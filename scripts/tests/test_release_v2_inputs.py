#!/usr/bin/env python3
"""Exercise release input handling without compiling or packaging a binary.

The cargo stub captures the first build and deliberately fails. Semantic
matrix authentication belongs to the Rust build checks, not this shell test.
"""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'scripts/build_release.sh'


class ReleaseInputs(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='v2 release inputs ')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.legacy = self.root / 'legacy'
        self.v2 = self.root / 'v2'
        self.v21 = self.root / 'v21'
        self.keys = self.root / 'keys'
        self.bin = self.root / 'bin'
        for directory in (self.legacy / 'v1', self.v2, self.v21, self.keys, self.bin):
            directory.mkdir(parents=True)
        for name in ('history-step.runtime', 'history-step-c00.field-r1cs.zst',
                     'history-step-c01.field-r1cs.zst'):
            (self.legacy / 'v1' / name).write_bytes(b'layout fixture')
        (self.legacy / 'SHA256SUMS').write_text('layout fixture\n')
        (self.legacy / 'pins.env').write_text(
            'NOID_HISTORY_STEP_RUNTIME_METADATA_RELEASE_DIGEST=' + 'a1' * 32 + '\n'
            'NOID_HISTORY_STEP_PACK_LEAF_DIGESTS=' + 'a2' * 64 + '\n')
        for name in ('v2-runtime-metadata.bin', 'v2-small.field-r1cs.zst', 'v2-large.field-r1cs.zst'):
            (self.v2 / name).write_bytes(b'layout fixture')
        for name in ('v21-runtime-metadata.bin', 'v21-small.field-r1cs.zst',
                     'v21-large.field-r1cs.zst', 'v21-native.field-r1cs.zst'):
            (self.v21 / name).write_bytes(b'layout fixture')
        for name in ('class-0.key', 'class-1.key'):
            (self.keys / name).write_bytes(b'layout fixture')
        self.pins = self.root / 'pins.env'
        self.valid_pins = (
            'NOID_V2_RELEASE_BANK=' + 'b1' * 32 + '\n'
            'NOID_RETIREMENT_KEY_0_PIN=' + 'c0' * 32 + '\n'
            'NOID_RETIREMENT_KEY_1_PIN=' + 'c1' * 32 + '\n')
        self.pins.write_text(self.valid_pins)
        self.v21_pins = self.root / 'v21-pins.env'
        self.valid_v21_pins = 'NOID_V21_RELEASE_BANK=' + 'd1' * 32 + '\n'
        self.v21_pins.write_text(self.valid_v21_pins)
        cargo = self.bin / 'cargo'
        cargo.write_text('''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
if sys.argv[1] == 'pkgid':
    print('path+file:///fixture#' + sys.argv[-1] + '@1.1.0')
elif sys.argv[1] == '--version':
    print('cargo fixture')
elif sys.argv[1] == 'build':
    Path(os.environ['TEST_ENV_CAPTURE']).write_text(json.dumps({
        'args': sys.argv[1:],
        'env': {k: v for k, v in os.environ.items() if k.startswith('NOID_')}}))
    sys.exit(91)
else:
    sys.exit(92)
''')
        cargo.chmod(0o755)
        rustc = self.bin / 'rustc'
        rustc.write_text("#!/bin/sh\ncase \"$1\" in -vV) echo 'host: x86_64-unknown-linux-gnu';; *) echo 'rustc fixture';; esac\n")
        rustc.chmod(0o755)
        self.capture = self.root / 'captured.json'
        self.output = self.root / 'output'
        self.env = os.environ.copy()
        self.env.update(PATH=str(self.bin) + os.pathsep + self.env['PATH'],
            TEST_ENV_CAPTURE=str(self.capture), NOID_V2_PACK_DIR='/stale-v2',
            NOID_V2_RELEASE_BANK='stale-bank', NOID_RETIREMENT_KEYS_DIR='/stale-keys',
            NOID_RETIREMENT_KEY_0_PIN='stale-key0', NOID_RETIREMENT_KEY_1_PIN='stale-key1',
            NOID_V21_PACK_DIR='/stale-v21', NOID_V21_RELEASE_BANK='stale-v21-bank',
            NOID_AUTHORIZATION_PACK_DIR='/stale-pack', NOID_AUTHORIZATION_RELEASE_BANK='stale-pin',
            NOID_HISTORY_STEP_PACK_LEAF_DIGESTS='stale-leaves')

    def run_build(self, *extra):
        return subprocess.run(['bash', str(SCRIPT), '--pack', str(self.legacy),
            '--v2-pack', str(self.v2), '--v2-pins', str(self.pins),
            '--v21-pack', str(self.v21), '--v21-pins', str(self.v21_pins),
            '--retirement-keys', str(self.keys), '--output', str(self.output), *extra],
            cwd=ROOT, env=self.env, capture_output=True, text=True, timeout=30)

    def checked_capture(self, result):
        self.assertEqual(result.returncode, 91, result.stdout + result.stderr)
        captured = json.loads(self.capture.read_text())
        self.assertEqual(captured['env']['NOID_V2_PACK_DIR'], str(self.v2))
        self.assertEqual(captured['env']['NOID_V2_RELEASE_BANK'], 'b1' * 32)
        self.assertEqual(captured['env']['NOID_V21_PACK_DIR'], str(self.v21))
        self.assertEqual(captured['env']['NOID_V21_RELEASE_BANK'], 'd1' * 32)
        self.assertNotIn('NOID_AUTHORIZATION_PACK_DIR', captured['env'])
        self.assertNotIn('NOID_AUTHORIZATION_RELEASE_BANK', captured['env'])
        self.assertEqual(captured['env']['NOID_RETIREMENT_KEYS_DIR'], str(self.keys))
        self.assertEqual(captured['env']['NOID_RETIREMENT_KEY_0_PIN'], 'c0' * 32)
        self.assertEqual(captured['env']['NOID_RETIREMENT_KEY_1_PIN'], 'c1' * 32)
        self.assertEqual(captured['env']['NOID_HISTORY_STEP_PACK_DIR'], str(self.legacy))
        self.assertEqual(captured['env']['NOID_HISTORY_STEP_RUNTIME_METADATA_RELEASE_DIGEST'], 'a1' * 32)
        self.assertNotIn('NOID_HISTORY_STEP_PACK_LEAF_DIGESTS', captured['env'])
        self.assertIn(self.valid_pins, (self.output / 'proof-pins.env').read_text())
        self.assertIn(self.valid_v21_pins, (self.output / 'proof-pins.env').read_text())
        return captured

    def test_transition_uses_explicit_pins_and_keeps_both_legacy_classes(self):
        captured = self.checked_capture(self.run_build())
        self.assertNotIn('--features', captured['args'])
        self.assertIn('RETIRED_HISTORY=0\n', (self.output / 'proof-pins.env').read_text())

    def test_retired_profile_needs_no_old_matrix_files(self):
        for path in (self.legacy / 'v1').glob('*.zst'):
            path.unlink()
        captured = self.checked_capture(self.run_build('--retired-history'))
        self.assertEqual(captured['args'][-2:], ['--features', 'retired-history'])
        self.assertIn('RETIRED_HISTORY=1\n', (self.output / 'proof-pins.env').read_text())

    def test_windows_pin_line_endings_are_accepted(self):
        self.pins.write_bytes(self.valid_pins.replace('\n', '\r\n').encode())
        self.v21_pins.write_bytes(self.valid_v21_pins.replace('\n', '\r\n').encode())
        self.checked_capture(self.run_build())

    def test_transition_rejects_missing_legacy_class(self):
        (self.legacy / 'v1/history-step-c01.field-r1cs.zst').unlink()
        result = self.run_build()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('artifact is missing', result.stderr)
        self.assertFalse(self.capture.exists())

    def test_pin_file_is_data_and_rejects_ambiguous_assignments(self):
        marker = self.root / 'must-not-exist'
        cases = [
            self.valid_pins + self.valid_pins.splitlines()[0] + '\n',
            self.valid_pins.replace('NOID_RETIREMENT_KEY_1_PIN', 'UNRECOGNIZED_PIN'),
            '\n'.join(self.valid_pins.splitlines()[:2]) + '\n',
            self.valid_pins.replace('b1' * 32, '$(touch "' + str(marker) + '")'),
        ]
        for text in cases:
            with self.subTest(text=text):
                self.pins.write_text(text)
                result = self.run_build()
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.capture.exists())
                self.assertFalse(marker.exists())
                self.assertFalse(self.output.exists())

    def test_symlinked_key_is_rejected_before_cargo(self):
        path = self.keys / 'class-1.key'
        path.unlink()
        path.symlink_to(self.keys / 'class-0.key')
        result = self.run_build()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('symlink', result.stderr)
        self.assertFalse(self.capture.exists())


if __name__ == '__main__':
    unittest.main()
