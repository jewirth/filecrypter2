# filecrypter2

Portable password-based file encryption in C, inspired by
[jewirth/filecrypter](https://github.com/jewirth/filecrypter).
This is a new implementation; it does not read the original XOR format.

Requires a C11 compiler, CMake >= 3.20 and OpenSSL >= 3.0.

```sh
cmake -S . -B build
cmake --build build --config Release
```

MIT licensed. OpenSSL is provided separately under its own license.

## Build on each platform

Linux (Debian/Ubuntu): install `build-essential cmake libssl-dev python3`.
macOS: install CMake and `openssl@3` with Homebrew, then configure with
`cmake -S . -B build -DOPENSSL_ROOT_DIR="$(brew --prefix openssl@3)"`.
Windows: use Visual Studio 2022's developer shell and vcpkg:

```powershell
vcpkg install openssl:x64-windows
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE="$env:VCPKG_INSTALLATION_ROOT/scripts/buildsystems/vcpkg.cmake" -DVCPKG_TARGET_TRIPLET=x64-windows
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

With a dynamic OpenSSL build, keep its DLLs available beside the executable or
on PATH. vcpkg normally copies runtime DLLs to the build output.
Python 3 is required for tests; use `-DBUILD_TESTING=OFF` for a production-only
build. On Unix run `ctest --test-dir build --output-on-failure`.

## Usage

```sh
./build/filecrypter2 input.txt input.enc 'a long unique password'
./build/filecrypter2 --decrypt input.enc restored.txt 'a long unique password'
./build/filecrypter2 --help
```

On Windows the executable is `build\Release\filecrypter2.exe`.
Arguments containing spaces must be quoted. Use `./-filename` for input names
starting with a dash. Output must not exist; the program never overwrites it.
All failures return exit code 1 and display usage; success returns 0.

A password argument may appear in process listings and shell history. Use `-`
as the password to read one line from stdin. For example, in Bash:

```bash
read -r -s -p 'Password: ' password; printf '\n'
printf '%s\n' "$password" | ./build/filecrypter2 input.txt input.enc -
unset password
```

Stdin passwords support up to 1022 bytes, without embedded NUL or newline.
The program itself does not disable terminal echo; use a hidden prompt as above.
The literal password `-` is reserved for stdin mode.

## Format and security

New files use format version 2 with OpenSSL AES-256-GCM, a random 16-byte salt and 12-byte nonce.
The key is derived with scrypt (N=131072, r=8, p=1; about 128 MiB working memory).
This increases the KDF work factor fourfold over the initial format. Decryption
also accepts version 1 (N=32768); encrypt again to migrate an older file.
Format: 8-byte magic (`FCRYPT2` plus version byte 2), 16-byte salt, 12-byte nonce,
ciphertext, 16-byte authentication tag. The complete 36-byte header is GCM
associated data. KDF parameters are fixed by the version, never file-controlled.
The seven ASCII characters plus version byte make up the eight-byte magic.
Unknown versions are rejected; the version byte is authenticated with the header.
Only regular files are accepted; pipes, devices and directories are rejected.
Files larger than 32 GiB of plaintext are rejected to remain below GCM limits.
Memory consumption stays bounded as file size grows.

After encryption, the program rereads the actual output through the decryption
path, verifies the GCM tag and compares SHA-256 of the decrypted content with
SHA-256 of the input bytes processed. Verification failure removes the output.
This checks the file through the OS cache, not power-loss durability on disk.

Decryption stages plaintext in an automatically deleted temporary file and
creates the requested output only after authentication succeeds. Allow enough
temporary disk space for the plaintext. Unix outputs are created with mode
0600; on Windows the parent directory's ACL determines access. Sensitive memory
buffers and derived keys are cleared where practical. Plaintext temporary data
may remain recoverable on storage or swap; secure deletion is not promised.

Use directories you control for input, output and temporary files. Concurrent
changes to input files and hostile users able to modify these directories are
outside this tool's threat model. A crash or full disk may leave an incomplete
new output; originals and existing destinations are never intentionally changed.
Weak passwords remain susceptible to offline guessing. Filenames, sizes and
filesystem metadata are not hidden. The original XOR format is incompatible.
This is a small implementation with regression tests, not an independent audit.


## Independent format checks

The regular regression suite decrypts fixed version 1 and version 2 fixtures
produced independently with Python hashlib.scrypt and cryptography AESGCM.
For an additional independent check of C-produced ciphertext, install the
optional development dependency `cryptography` in a virtual environment and run:

```sh
python tests/interop.py build/filecrypter2
```

`python tests/interop.py --fixture` regenerates the version 2 fixture. It uses
fixed salt and nonce only for a deterministic test vector; production encryption
always generates fresh random values. Tests also simulate a write failure under
POSIX and assert that the original survives and the incomplete output is removed.
