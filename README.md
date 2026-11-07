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
