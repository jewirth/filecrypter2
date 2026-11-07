"""Independent format check: pip install cryptography; python interop.py EXE.

Uses Python's hashlib.scrypt and cryptography's AESGCM rather than the C code's
stream framing, EVP calls and verification path. Can also regenerate the fixture
with --fixture. cryptography is a development-only optional dependency.
"""
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PASSWORD = 'independent interop password'
PLAINTEXT = bytes(range(256)) + b'\x00\r\nfilecrypter2\n'
HEADER = b'FCRYPT2\x01' + bytes(range(16)) + bytes(range(16, 28))


def derive(header):
    return hashlib.scrypt(PASSWORD.encode(), salt=header[8:24],
                          n=32768, r=8, p=1, maxmem=64*1024*1024, dklen=32)


def fixture():
    encrypted = HEADER + AESGCM(derive(HEADER)).encrypt(HEADER[24:36], PLAINTEXT, HEADER)
    return {'password': PASSWORD, 'plaintext_base64': base64.b64encode(PLAINTEXT).decode(),
            'ciphertext_base64': base64.b64encode(encrypted).decode()}


if __name__ == '__main__':
    if sys.argv[1:] == ['--fixture']:
        print(json.dumps(fixture(), indent=2))
    else:
        exe = str(Path(sys.argv[1]).resolve())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for size in (0, 1, 65535, 65536, 65537, 1048576):
                data = (PLAINTEXT * (size // len(PLAINTEXT) + 1))[:size]
                src, enc = root/'source', root/f'enc-{size}'
                src.write_bytes(data)
                subprocess.run([exe, str(src), str(enc), PASSWORD], check=True)
                encrypted = enc.read_bytes()
                header = encrypted[:36]
                assert header[:8] == b'FCRYPT2\x01'
                decoded = AESGCM(derive(header)).decrypt(header[24:36], encrypted[36:], header)
                assert decoded == data
        print('Independent AES-GCM/scrypt interoperability checks passed.')
