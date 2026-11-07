# Security review

The first implementation was reviewed after the crypto and verification commits.
Concrete improvements made in the following security commit:

- Replaced truncating output creation with exclusive creation to prevent data
  loss and reject existing paths, symlinks and hardlink aliases.
- Restricted new Unix output files to owner read/write access.
- Bounded GCM message length and fixed versioned KDF parameters.
- Added stdin password input and cleared password/key/plaintext buffers.

A follow-up portability review replaced Windows root-directory temporary files
with exclusively created, random-named, delete-on-close files in the user temp
folder, removed flushing a stream after reading, and cleared copy buffers on
write errors. See README for the threat model and remaining limitations.

Tests cover empty/binary/large files and block boundaries; wrong passwords;
modified headers, payloads and tags; truncation and trailing bytes; argument
errors; existing destinations and filesystem aliases. CI builds and tests on
Linux, macOS and Windows. These checks are not a cryptographic security audit.

Report suspected vulnerabilities privately to the repository owner before
publishing exploit details. Never include real passwords or private files.
