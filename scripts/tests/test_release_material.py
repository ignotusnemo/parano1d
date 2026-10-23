#!/usr/bin/env python3
"""Exercise reproducible packing and rejection of damaged or unsafe inputs."""

import argparse
import contextlib
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "release_material.py"
spec = importlib.util.spec_from_file_location("material", SCRIPT)
material = importlib.util.module_from_spec(spec)
spec.loader.exec_module(material)


class ReleaseMaterialTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="release inputs ")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def archive(self, kind, retired_history=False):
        sources = {}
        for name in material.pack_files(kind, retired_history):
            path = self.root / "source" / kind / name
            path.parent.mkdir(parents=True, exist_ok=True)
            data = name.encode()
            if name == "pins.env":
                data = "".join(f"{key}={'a' * size}\r\n" for key, size in material.PINS[kind].items()).encode()
            path.write_bytes(data)
            sources[name] = path
        output = self.root / f"{kind}{'-retired' if retired_history else ''}.tar.gz"
        with contextlib.redirect_stdout(io.StringIO()):
            material.write_archive(kind, sources, output, retired_history=retired_history)
        return output, sources

    def extract(self, archive, kind, sha=None, retired_history=False):
        args = argparse.Namespace(archive=archive, kind=kind, sha256=sha or material.digest(archive),
                                  output=self.root / "unpack", retired_history=retired_history)
        with contextlib.redirect_stdout(io.StringIO()):
            material.extract(args)

    def test_all_packs_roundtrip_and_are_reproducible(self):
        for kind in ("v1", "v2", "v21"):
            archive, sources = self.archive(kind)
            second = self.root / f"second-{kind}.tar.gz"
            for source in sources.values():
                source.chmod(0o600)
            with contextlib.redirect_stdout(io.StringIO()):
                material.write_archive(kind, sources, second)
            self.assertEqual(archive.read_bytes(), second.read_bytes())
            self.extract(archive, kind)
            for name, source in sources.items():
                self.assertEqual(source.read_bytes(), (self.root / "unpack" / f"history-step-pack-{kind}" / name).read_bytes())

    def test_wrong_archive_digest_rejected_before_writing(self):
        archive, _ = self.archive("v2")
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            self.extract(archive, "v2", "0" * 64)
        self.assertFalse((self.root / "unpack").exists())

    def test_unsafe_members_duplicates_missing_and_corruption_rejected(self):
        original, _ = self.archive("v2")
        with tarfile.open(original) as archive:
            entries = [(member, archive.extractfile(member).read()) for member in archive.getmembers()]
        for mutation in ("traversal", "symlink", "hardlink", "duplicate", "missing", "corruption"):
            with self.subTest(mutation=mutation):
                changed = self.root / f"{mutation}.tar.gz"
                with tarfile.open(changed, "w:gz") as archive:
                    for index, (member, data) in enumerate(entries):
                        if mutation == "missing" and index == 0:
                            continue
                        if mutation == "corruption" and index == 0:
                            data = b"X" * len(data)
                        archive.addfile(member, io.BytesIO(data))
                    if mutation == "duplicate":
                        archive.addfile(entries[0][0], io.BytesIO(entries[0][1]))
                    elif mutation in ("traversal", "symlink", "hardlink"):
                        bad = tarfile.TarInfo("../outside" if mutation == "traversal" else "history-step-pack-v2/extra")
                        if mutation != "traversal":
                            bad.type = tarfile.SYMTYPE if mutation == "symlink" else tarfile.LNKTYPE
                            bad.linkname = "../../outside"
                        archive.addfile(bad)
                with self.assertRaises(ValueError):
                    self.extract(changed, "v2")
                self.assertFalse((self.root / "outside").exists())
                self.assertFalse((self.root / "unpack/history-step-pack-v2").exists())

    def test_pin_file_is_data_and_must_be_complete(self):
        for data in (b"NOID_V2_RELEASE_BANK=$(touch /tmp/unwanted)\n", b"", b"export NOID_V2_RELEASE_BANK=abc\n"):
            with self.assertRaises(ValueError):
                material.validate_pins(data, "v2")

    def test_source_symlink_rejected(self):
        archive, sources = self.archive("v2")
        alias = self.root / "alias"
        alias.symlink_to(sources["pins.env"])
        sources["pins.env"] = alias
        with self.assertRaises(ValueError):
            material.write_archive("v2", sources, self.root / "bad.tar.gz")

    def test_retired_pack_contains_only_pinned_metadata(self):
        archive, sources = self.archive("v1", retired_history=True)
        self.extract(archive, "v1", retired_history=True)
        root = self.root / "unpack/history-step-pack-v1"
        files = {str(p.relative_to(root)) for p in root.rglob("*") if p.is_file()}
        self.assertEqual(files, {"v1/history-step.runtime", "pins.env", "SHA256SUMS"})
        self.assertEqual((root / "v1/history-step.runtime").read_bytes(), sources["v1/history-step.runtime"].read_bytes())

    def test_transition_and_retired_archive_profiles_cannot_be_mixed(self):
        full, _ = self.archive("v1")
        retired, _ = self.archive("v1", retired_history=True)
        with self.assertRaises(ValueError):
            self.extract(full, "v1", retired_history=True)
        with self.assertRaises(ValueError):
            self.extract(retired, "v1")
        self.assertFalse((self.root / "unpack").exists())

    def test_retired_profile_cannot_omit_v2_matrices(self):
        archive, _ = self.archive("v2")
        with self.assertRaisesRegex(ValueError, "only to the legacy"):
            self.extract(archive, "v2", retired_history=True)
        self.assertFalse((self.root / "unpack").exists())

    def test_retired_creation_omits_rows_from_authenticated_full_source(self):
        legacy, _ = self.archive("v1")
        _, v2_sources = self.archive("v2")
        self.extract(legacy, "v1")
        legacy_root = self.root / "unpack/history-step-pack-v1"
        args = argparse.Namespace(legacy_pack=legacy_root, v2_pack=self.root / "source/v2",
                                  v2_pins=v2_sources["pins.env"], retirement_keys=self.root / "source/v2/retirement-keys",
                                  output=self.root / "created", retired_history=True)
        with contextlib.redirect_stdout(io.StringIO()):
            material.create(args)
        archive = args.output / "history-step-pack-v1.tar.gz"
        with tarfile.open(archive) as packed:
            self.assertEqual({member.name for member in packed.getmembers()},
                             {"history-step-pack-v1/" + name for name in
                              ("v1/history-step.runtime", "pins.env", "SHA256SUMS")})
        self.assertTrue((legacy_root / "v1/history-step-c00.field-r1cs.zst").is_file())

    def test_retired_archive_rejects_injected_legacy_rows(self):
        original, _ = self.archive("v1", retired_history=True)
        changed = self.root / "injected.tar.gz"
        with tarfile.open(original) as source, tarfile.open(changed, "w:gz") as target:
            for member in source.getmembers():
                target.addfile(member, source.extractfile(member))
            row = tarfile.TarInfo("history-step-pack-v1/v1/history-step-c00.field-r1cs.zst")
            row.size = 4
            target.addfile(row, io.BytesIO(b"rows"))
        with self.assertRaises(ValueError):
            self.extract(changed, "v1", retired_history=True)
        self.assertFalse((self.root / "unpack").exists())

    def test_retired_creation_accepts_metadata_only_source(self):
        legacy, _ = self.archive("v1", retired_history=True)
        _, v2_sources = self.archive("v2")
        self.extract(legacy, "v1", retired_history=True)
        args = argparse.Namespace(legacy_pack=self.root / "unpack/history-step-pack-v1",
                                  v2_pack=self.root / "source/v2", v2_pins=v2_sources["pins.env"],
                                  retirement_keys=self.root / "source/v2/retirement-keys",
                                  output=self.root / "created", retired_history=True)
        with contextlib.redirect_stdout(io.StringIO()):
            material.create(args)
        self.assertEqual((args.output / "history-step-pack-v1.tar.gz").read_bytes(), legacy.read_bytes())


if __name__ == "__main__":
    unittest.main()
