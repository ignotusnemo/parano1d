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

    def archive(self, kind):
        sources = {}
        for name in material.FILES[kind]:
            path = self.root / "source" / kind / name
            path.parent.mkdir(parents=True, exist_ok=True)
            data = name.encode()
            if name == "pins.env":
                data = "".join(f"{key}={'a' * size}\r\n" for key, size in material.PINS[kind].items()).encode()
            path.write_bytes(data)
            sources[name] = path
        output = self.root / f"{kind}.tar.gz"
        with contextlib.redirect_stdout(io.StringIO()):
            material.write_archive(kind, sources, output)
        return output, sources

    def extract(self, archive, kind, sha=None):
        args = argparse.Namespace(archive=archive, kind=kind, sha256=sha or material.digest(archive), output=self.root / "unpack")
        with contextlib.redirect_stdout(io.StringIO()):
            material.extract(args)

    def test_both_packs_roundtrip_and_are_reproducible(self):
        for kind in ("v1", "v2"):
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


if __name__ == "__main__":
    unittest.main()
