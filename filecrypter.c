#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#ifdef _WIN32
#include <io.h>
#include <windows.h>
#else
#include <unistd.h>
#endif

#define MAX_PLAINTEXT UINT64_C(34359738368)
#define FORMAT_OVERHEAD 52

/* Validate an opened descriptor, not a path that could change before opening.
 * Nonblocking open prevents FIFOs from hanging before their type is checked. */
static FILE *open_input(const char *path, int decrypt)
{
    int fd;
    FILE *file;
    uint64_t limit = MAX_PLAINTEXT + (decrypt ? FORMAT_OVERHEAD : 0);
#ifdef _WIN32
    struct _stat64 info;
    fd = _open(path, _O_RDONLY | _O_BINARY);
    if (fd < 0) return NULL;
    if (_fstat64(fd, &info) != 0 || (info.st_mode & _S_IFMT) != _S_IFREG) {
        _close(fd); errno = EINVAL; return NULL;
    }
    if (info.st_size < 0 || (uint64_t)info.st_size > limit) {
        _close(fd); errno = EFBIG; return NULL;
    }
    file = _fdopen(fd, "rb");
    if (!file) _close(fd);
#else
    struct stat info;
    fd = open(path, O_RDONLY | O_NONBLOCK);
    if (fd < 0) return NULL;
    if (fstat(fd, &info) != 0 || !S_ISREG(info.st_mode)) {
        close(fd); errno = EINVAL; return NULL;
    }
    if (info.st_size < 0 || (uint64_t)info.st_size > limit) {
        close(fd); errno = EFBIG; return NULL;
    }
    file = fdopen(fd, "rb");
    if (!file) close(fd);
#endif
    return file;
}

/* Exclusive creation also rejects symlinks and input/output hardlink aliases. */
static FILE *create_output(const char *path)
{
    int fd;
    FILE *file;
#ifdef _WIN32
    fd = _open(path, _O_CREAT | _O_EXCL | _O_RDWR | _O_BINARY,
               _S_IREAD | _S_IWRITE);
    if (fd < 0) return NULL;
    file = _fdopen(fd, "w+b");
    if (!file) { _close(fd); remove(path); }
#else
    fd = open(path, O_CREAT | O_EXCL | O_RDWR, S_IRUSR | S_IWUSR);
    if (fd < 0) return NULL;
    file = fdopen(fd, "w+b");
    if (!file) { close(fd); remove(path); }
#endif
    return file;
}

/* Windows tmpfile() may require root-directory write access. Use the user's
 * temp directory, exclusive creation and automatic deletion instead. */
static FILE *private_temp(void)
{
#ifdef _WIN32
    char directory[MAX_PATH], path[MAX_PATH], suffix[33];
    unsigned char random[16];
    HANDLE handle;
    int fd;
    FILE *file;
    DWORD length = GetTempPathA(MAX_PATH, directory);
    if (!length || length >= MAX_PATH || RAND_bytes(random, sizeof random) != 1)
        return NULL;
    for (size_t i = 0; i < sizeof random; ++i)
        snprintf(suffix + i * 2, 3, "%02x", random[i]);
    if (snprintf(path, sizeof path, "%sfilecrypter2-%s.tmp", directory, suffix) >= MAX_PATH)
        return NULL;
    handle = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_NEW,
                         FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, NULL);
    if (handle == INVALID_HANDLE_VALUE) return NULL;
    fd = _open_osfhandle((intptr_t)handle, _O_RDWR | _O_BINARY);
    if (fd < 0) { CloseHandle(handle); return NULL; }
    file = _fdopen(fd, "w+b");
    if (!file) _close(fd);
    return file;
#else
    return tmpfile();
#endif
}

#define CHUNK 65536
#define HEADER 36
#define TAG 16
static const unsigned char magic[8] = {'F','C','R','Y','P','T','2',1};

static int put(FILE *out, const unsigned char *data, size_t n)
{
    return !out || fwrite(data, 1, n, out) == n;
}

/* The final 16 bytes are retained until EOF so truncation cannot be accepted. */
static int process_stream(FILE *in, FILE *out, const char *password, int decrypt,
                 unsigned char digest[32])
{
    unsigned char header[HEADER], key[32] = {0};
    unsigned char input[CHUNK + TAG], output[CHUNK + TAG], tag[TAG];
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    size_t n;
    uint64_t processed = 0;
    int count = 0, ok = 0;
    unsigned int digest_len;
    if (!ctx || !md) goto done;
    if (decrypt) {
        if (fread(header, 1, HEADER, in) != HEADER ||
            memcmp(header, magic, sizeof magic) != 0) goto done;
    } else {
        memcpy(header, magic, sizeof magic);
        if (RAND_bytes(header + 8, 28) != 1) goto done;
    }
    /* Fixed versioned KDF parameters prevent attacker-controlled resource costs. */
    if (EVP_PBE_scrypt(password, strlen(password), header + 8, 16,
                       32768, 8, 1, 64 * 1024 * 1024, key, sizeof key) != 1 ||
        EVP_DigestInit_ex(md, EVP_sha256(), NULL) != 1 ||
        EVP_CipherInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, header + 24, !decrypt) != 1 ||
        EVP_CipherUpdate(ctx, NULL, &count, header, HEADER) != 1) goto done;
    if (!decrypt && !put(out, header, HEADER)) goto done;
    n = fread(input, 1, decrypt ? CHUNK + TAG : CHUNK, in);
    for (;;) {
        size_t amount = decrypt ? (n > TAG ? n - TAG : 0) : n;
        if (ferror(in) || (decrypt && n < TAG)) goto done;
        if (amount) {
            /* Stay below GCM's per-nonce message bound (2^39 - 256 bits). */
            if (processed + amount > MAX_PLAINTEXT) goto done;
            processed += amount;
            if (EVP_CipherUpdate(ctx, output, &count, input, (int)amount) != 1 ||
                EVP_DigestUpdate(md, decrypt ? output : input, amount) != 1 ||
                !put(out, output, (size_t)count)) goto done;
        }
        if (decrypt) {
            memmove(input, input + amount, TAG);
            n = fread(input + TAG, 1, CHUNK, in);
            if (ferror(in)) goto done;
            if (n == 0) {
                if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG, input) != 1) goto done;
                break;
            }
            n += TAG;
        } else {
            n = fread(input, 1, CHUNK, in);
            if (n == 0) {
                if (ferror(in)) goto done;
                break;
            }
        }
    }
    if (EVP_CipherFinal_ex(ctx, output, &count) != 1 ||
        !put(out, output, (size_t)count)) goto done;
    if (!decrypt && (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG, tag) != 1 ||
                     !put(out, tag, TAG))) goto done;
    if (EVP_DigestFinal_ex(md, digest, &digest_len) != 1 || digest_len != 32) goto done;
    ok = 1;
done:
    OPENSSL_cleanse(key, sizeof key);
    OPENSSL_cleanse(input, sizeof input);
    OPENSSL_cleanse(output, sizeof output);
    EVP_MD_CTX_free(md);
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static int copy(FILE *in, FILE *out)
{
    unsigned char buffer[CHUNK];
    size_t n;
    int ok = 1;
    while ((n = fread(buffer, 1, sizeof buffer, in)) != 0)
        if (!put(out, buffer, n)) { ok = 0; break; }
    OPENSSL_cleanse(buffer, sizeof buffer);
    return ok && !ferror(in);
}

static void usage(FILE *stream)
{
    fputs("Usage: filecrypter2 [--decrypt] INPUT OUTPUT PASSWORD\n"
          "       filecrypter2 --help\n"
          "Encrypt by default; --decrypt decrypts a filecrypter2 file.\n"
          "Use PASSWORD - to read a password line from stdin.\n"
          "Use a long, unique password. Existing output files are refused.\n", stream);
}

int main(int argc, char **argv)
{
    int decrypt = argc > 1 && strcmp(argv[1], "--decrypt") == 0;
    int base = decrypt ? 2 : 1;
    FILE *in, *out = NULL, *plain = NULL;
    char secret[1024] = {0};
    const char *password;
    unsigned char digest[32], verified[32];
    int ok = 0;
    const char *error = "File operation failed.";
    if (argc == 2 && (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)) {
        usage(stdout);
        return 0;
    }
    if (argc != base + 3 || argv[base][0] == '\0' ||
        argv[base + 1][0] == '\0' || argv[base + 2][0] == '\0' ||
        (base == 1 && argv[1][0] == '-')) {
        fputs("Error: expected input, output and a nonempty password.\n", stderr);
        usage(stderr);
        return 1;
    }
    password = argv[base + 2];
    if (strcmp(password, "-") == 0) {
        size_t length;
        if (!fgets(secret, sizeof secret, stdin) ||
            !(length = strlen(secret)) || secret[length - 1] != '\n') {
            fputs("Error: stdin password must be a nonempty line shorter than 1023 bytes.\n", stderr);
            OPENSSL_cleanse(secret, sizeof secret);
            usage(stderr);
            return 1;
        }
        secret[--length] = 0;
        if (length && secret[length - 1] == '\r') secret[--length] = 0;
        if (!length) {
            OPENSSL_cleanse(secret, sizeof secret);
            usage(stderr);
            return 1;
        }
        password = secret;
    }
    in = open_input(argv[base], decrypt);
    if (!in) {
        OPENSSL_cleanse(secret, sizeof secret);
        perror("Error opening input");
        usage(stderr);
        return 1;
    }
    if (strcmp(argv[base], argv[base + 1]) == 0) {
        error = "Input and output must differ.";
        goto done;
    }
    if (decrypt) {
        plain = private_temp();
        error = "Cannot create a private temporary file.";
        if (!plain) goto done;
        error = "Decryption failed: wrong password, damaged file, or input/output error.";
        if (!process_stream(in, plain, password, 1, digest)) goto done;
        error = "Cannot prepare temporary plaintext for copying.";
        if (fflush(plain) != 0 || fseek(plain, 0, SEEK_SET) != 0) goto done;
        error = "Cannot create output: it must not exist and its directory must be writable.";
        out = create_output(argv[base + 1]);
        if (!out) goto done;
        error = "Cannot write decrypted output.";
        if (!copy(plain, out)) goto done;
    } else {
        error = "Cannot create output: it must not exist and its directory must be writable.";
        out = create_output(argv[base + 1]);
        if (!out) goto done;
        error = "Encryption failed: cryptographic operation or file read/write failed.";
        if (!process_stream(in, out, password, 0, digest)) goto done;
        error = "Cannot flush or rewind encrypted output for verification.";
        if (fflush(out) != 0 || fseek(out, 0, SEEK_SET) != 0) goto done;
        error = "Encryption verification failed: output is not correctly decryptable.";
        if (!process_stream(out, NULL, password, 1, verified) ||
            CRYPTO_memcmp(digest, verified, sizeof digest) != 0) goto done;
    }
    error = "Cannot flush decrypted output.";
    if (decrypt && fflush(out) != 0) goto done;
    ok = 1;
done:
    if (plain && fclose(plain) != 0) {
        if (ok) error = "Cannot close temporary plaintext.";
        ok = 0;
    }
    if (out && fclose(out) != 0) {
        if (ok) error = "Cannot close output.";
        ok = 0;
    }
    if (fclose(in) != 0) {
        if (ok) error = "Cannot close input.";
        ok = 0;
    }
    if (!ok) {
        if (out && remove(argv[base + 1]) != 0)
            perror("Error removing incomplete output");
        fprintf(stderr, "Error: %s\n", error);
        usage(stderr);
    }
    OPENSSL_cleanse(secret, sizeof secret);
    return ok ? 0 : 1;
}
