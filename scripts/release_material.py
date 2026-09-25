#!/usr/bin/env python3
"""Package frozen release inputs and safely unpack them on every native runner."""

import argparse
import gzip
import hashlib
import io
from pathlib import Path, PurePosixPath
import re
import shutil
import tarfile


FILES = {
    "v1": (
        "v1/history-step.runtime",
        "v1/history-step-c00.field-r1cs.zst",
        "v1/history-step-c01.field-r1cs.zst",
        "pins.env",
    ),
    "v2": (
        "v2-runtime-metadata.bin",
        "v2-small.field-r1cs.zst",
        "v2-large.field-r1cs.zst",
        "pins.env",
        "retirement-keys/class-0.key",
        "retirement-keys/class-1.key",
    ),
}
PINS = {
    "v1": {
        "NOID_HISTORY_STEP_RUNTIME_METADATA_RELEASE_DIGEST": 64,
        "NOID_HISTORY_STEP_PACK_LEAF_DIGESTS": 128,
    },
    "v2": {
        "NOID_V2_RELEASE_BANK": 64,
        "NOID_RETIREMENT_KEY_0_PIN": 64,
        "NOID_RETIREMENT_KEY_1_PIN": 64,
    },
}


def digest(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def regular_file(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or not path.stat().st_size:
        raise ValueError(f"missing, empty or non-regular input: {path}")
    return path


def validate_pins(data, kind):
    pins = {}
    for line in data.decode("ascii").splitlines():
        if not line or line.startswith("#"):
            continue
        name, sep, value = line.partition("=")
        if name not in PINS[kind] or name in pins or not sep:
            raise ValueError("unexpected or duplicate release pin")
        if not re.fullmatch(r"[0-9a-f]{%d}" % PINS[kind][name], value):
            raise ValueError("malformed release pin")
        pins[name] = value
    if pins.keys() != PINS[kind].keys():
        raise ValueError("missing release pin")


def verify_manifest(root, kind):
    entries = {}
    for line in (root / "SHA256SUMS").read_text(encoding="ascii").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if not match or match[2] not in FILES[kind] or match[2] in entries:
            raise ValueError("invalid matrix pack SHA256SUMS")
        entries[match[2]] = match[1]
    if entries.keys() != set(FILES[kind]):
        raise ValueError("incomplete matrix pack SHA256SUMS")
    for name, expected in entries.items():
        if digest(root / name) != expected:
            raise ValueError(f"matrix pack digest mismatch: {name}")
    validate_pins((root / "pins.env").read_bytes(), kind)


def write_archive(kind, sources, output):
    root = f"history-step-pack-{kind}"
    sources = {name: regular_file(path) for name, path in sources.items()}
    validate_pins(sources["pins.env"].read_bytes(), kind)
    manifest = "".join(f"{digest(sources[name])}  {name}\n" for name in FILES[kind])
    # No source path, mtime, ownership or gzip filename enters the archive.
    with output.open("xb") as raw:
        with gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0) as gz:
            with tarfile.open(fileobj=gz, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                for name in (*FILES[kind], "SHA256SUMS"):
                    info = tarfile.TarInfo(f"{root}/{name}")
                    info.mode = 0o644
                    if name == "SHA256SUMS":
                        data = manifest.encode("ascii")
                        info.size = len(data)
                        archive.addfile(info, io.BytesIO(data))
                    else:
                        info.size = sources[name].stat().st_size
                        with sources[name].open("rb") as stream:
                            archive.addfile(info, stream)
    print(f"{digest(output)}  {output.name}")


def create(args):
    args.output.mkdir(parents=True, exist_ok=True)
    verify_manifest(args.legacy_pack, "v1")
    sources = {name: args.legacy_pack / name for name in FILES["v1"]}
    write_archive("v1", sources, args.output / "history-step-pack-v1.tar.gz")
    sources = {name: args.v2_pack / name for name in FILES["v2"]}
    sources["pins.env"] = args.v2_pins
    for index in range(2):
        sources[f"retirement-keys/class-{index}.key"] = args.retirement_keys / f"class-{index}.key"
    write_archive("v2", sources, args.output / "history-step-pack-v2.tar.gz")


def extract(args):
    if not re.fullmatch(r"[0-9a-f]{64}", args.sha256) or digest(args.archive) != args.sha256:
        raise ValueError("matrix archive SHA-256 mismatch")
    root_name = f"history-step-pack-{args.kind}"
    required = {f"{root_name}/{name}" for name in (*FILES[args.kind], "SHA256SUMS")}
    directories = {str(parent) for name in required for parent in PurePosixPath(name).parents if str(parent) != "."}
    root = args.output / root_name
    if root.exists() or root.is_symlink():
        raise ValueError(f"extraction destination already exists: {root}")
    with tarfile.open(args.archive, "r:gz") as archive:
        seen = set()
        total_size = 0
        for member in archive.getmembers():
            if member.name in seen:
                raise ValueError("duplicate archive member")
            seen.add(member.name)
            if member.isdir() and member.name in directories:
                continue
            if not member.isfile() or member.name not in required or member.size <= 0:
                raise ValueError(f"unexpected archive member: {member.name}")
            total_size += member.size
            if total_size > 128 * 1024 * 1024:
                raise ValueError("matrix archive exceeds input size limit")
        if seen - directories != required:
            raise ValueError("incomplete matrix archive")
        root.mkdir(parents=True)
        try:
            for member in archive.getmembers():
                if member.isdir():
                    continue
                destination = args.output / member.name
                destination.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(member) as source, destination.open("xb") as target:
                    shutil.copyfileobj(source, target)
            verify_manifest(root, args.kind)
        except Exception:
            shutil.rmtree(root)
            raise
    print(f"Verified {root_name}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    pack = commands.add_parser("create")
    for name in ("legacy-pack", "v2-pack", "v2-pins", "retirement-keys", "output"):
        pack.add_argument(f"--{name}", type=Path, required=True)
    unpack = commands.add_parser("extract")
    unpack.add_argument("--kind", choices=FILES, required=True)
    unpack.add_argument("--archive", type=Path, required=True)
    unpack.add_argument("--sha256", required=True)
    unpack.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        (create if args.command == "create" else extract)(args)
    except (OSError, ValueError, tarfile.TarError) as error:
        parser.exit(1, f"release material: {error}\n")


if __name__ == "__main__":
    main()
