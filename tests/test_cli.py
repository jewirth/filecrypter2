"""Black-box security and round-trip regression tests; no third-party packages."""
import os
import base64
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

EXE = str(Path(sys.argv.pop(1)).resolve())

class CLI(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def run_cli(self, *args, success=True, stdin=None):
        result = subprocess.run([EXE, *map(str, args)], input=stdin, capture_output=True)
        self.assertEqual(result.returncode == 0, success, result.stderr.decode())
        if not success:
            self.assertIn(b'Usage:', result.stderr)
        return result

    def test_usage(self):
        self.run_cli('--help')
        self.run_cli('-h')
        for args in [(), ('a',), ('a', 'b'), ('a', 'b', 'p', 'extra'),
                     ('--unknown', 'b', 'p'), ('a', 'b', '')]:
            self.run_cli(*args, success=False)
        self.run_cli(self.root/'absent', self.root/'out', 'pw', success=False)
        self.assertFalse((self.root/'out').exists())

    def test_round_trip_and_randomization(self):
        for size in (0, 1, 15, 16, 65535, 65536, 65537, 131089, 1048576):
            with self.subTest(size=size):
                src, enc, enc2, dst = [self.root/f'{size}-{n}' for n in range(4)]
                data = os.urandom(size)
                src.write_bytes(data)
                self.run_cli(src, enc, 'long unique test password')
                self.run_cli(src, enc2, 'long unique test password')
                self.assertNotEqual(enc.read_bytes(), enc2.read_bytes())
                self.run_cli('--decrypt', enc, dst, 'long unique test password')
                self.assertEqual(dst.read_bytes(), data)
                if os.name != 'nt':
                    self.assertEqual(enc.stat().st_mode & 0o777, 0o600)
                    self.assertEqual(dst.stat().st_mode & 0o777, 0o600)

    def test_authentication_and_truncation(self):
        src, enc, out = [self.root/n for n in ('src', 'enc', 'out')]
        src.write_bytes(os.urandom(70000))
        self.run_cli(src, enc, 'pw')
        self.run_cli('--decrypt', enc, out, 'wrong', success=False)
        self.assertFalse(out.exists())
        original = enc.read_bytes()
        variants = [original[:n] for n in (0, 7, 35, 36, 51, 52, 65536, len(original)-1)]
        variants += [original+b'x']
        for offset in (0, 8, 24, 36, len(original)-1):
            damaged = bytearray(original)
            damaged[offset] ^= 1
            variants.append(damaged)
        for data in variants:
            enc.write_bytes(data)
            self.run_cli('--decrypt', enc, out, 'pw', success=False)
            self.assertFalse(out.exists())

    def test_no_clobber_and_aliases(self):
        src, out = self.root/'src', self.root/'out'
        src.write_bytes(b'original')
        out.write_bytes(b'keep me')
        self.run_cli(src, out, 'pw', success=False)
        self.assertEqual(out.read_bytes(), b'keep me')
        self.run_cli(src, src, 'pw', success=False)
        self.assertEqual(src.read_bytes(), b'original')
        alias = self.root/'alias'
        try:
            os.link(src, alias)
        except OSError:
            pass
        else:
            self.run_cli(src, alias, 'pw', success=False)
            self.assertEqual(src.read_bytes(), b'original')
        if os.name != 'nt':
            link = self.root/'symlink'
            link.symlink_to(src)
            self.run_cli(src, link, 'pw', success=False)
            self.assertEqual(src.read_bytes(), b'original')

    def test_reject_special_and_oversized_inputs(self):
        out = self.root/'out'
        self.run_cli(self.root, out, 'pw', success=False)
        self.assertFalse(out.exists())
        if os.name != 'nt':
            fifo = self.root/'fifo'
            os.mkfifo(fifo)
            result = subprocess.run([EXE, str(fifo), str(out), 'pw'],
                                    capture_output=True, timeout=3)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b'Usage:', result.stderr)
            self.run_cli('/dev/null', out, 'pw', success=False)
            sparse = self.root/'oversized'
            with sparse.open('wb') as stream:
                stream.truncate((1 << 35) + 1)
            self.run_cli(sparse, out, 'pw', success=False)
            self.assertFalse(out.exists())

    def test_independently_generated_format_fixture(self):
        fixture_path = Path(__file__).parent/'fixtures'/'v1.json'
        fixture = json.loads(fixture_path.read_text())
        enc, out = self.root/'fixture.enc', self.root/'fixture.out'
        enc.write_bytes(base64.b64decode(fixture['ciphertext_base64']))
        self.run_cli('--decrypt', enc, out, fixture['password'])
        self.assertEqual(out.read_bytes(), base64.b64decode(fixture['plaintext_base64']))

    @unittest.skipIf(os.name == 'nt', 'requires POSIX file-size limits')
    def test_write_failure_removes_incomplete_output(self):
        import resource
        import signal
        src, out = self.root/'src', self.root/'out'
        src.write_bytes(os.urandom(4096))
        def limit_output():
            signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
            resource.setrlimit(resource.RLIMIT_FSIZE, (1024, 1024))
        result = subprocess.run([EXE, str(src), str(out), 'pw'], capture_output=True,
                                preexec_fn=limit_output, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'Usage:', result.stderr)
        self.assertFalse(out.exists())
        self.assertEqual(src.stat().st_size, 4096)

    def test_missing_output_directory(self):
        src = self.root/'src'
        src.write_bytes(b'data')
        result = self.run_cli(src, self.root/'missing'/'out', 'pw', success=False)
        self.assertIn(b'Cannot create output', result.stderr)
        self.assertEqual(src.read_bytes(), b'data')

    def test_password_stdin(self):
        src, enc, dst = [self.root/n for n in ('src', 'enc', 'dst')]
        src.write_bytes(b'private')
        self.run_cli(src, enc, '-', stdin=b'secret\n')
        self.run_cli('--decrypt', enc, dst, '-', stdin=b'secret\n')
        self.assertEqual(dst.read_bytes(), b'private')
        self.run_cli(src, self.root/'bad', '-', stdin=b'', success=False)

if __name__ == '__main__':
    unittest.main()
