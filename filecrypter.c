#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

#define CHUNK 65536
#define HEADER 36
#define TAG 16
static const unsigned char magic[8] = {'F','C','R','Y','P','T','2',1};

static int put(FILE *out, const unsigned char *data, size_t n)
{
    return !out || fwrite(data, 1, n, out) == n;
}

/* The final 16 bytes are retained until EOF so truncation cannot be accepted. */
static int crypt(FILE *in, FILE *out, const char *password, int decrypt,
                 unsigned char digest[32])
{
    unsigned char header[HEADER], key[32] = {0};
    unsigned char input[CHUNK + TAG], output[CHUNK + TAG], tag[TAG];
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    size_t n;
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
    while ((n = fread(buffer, 1, sizeof buffer, in)) != 0)
        if (!put(out, buffer, n)) return 0;
    OPENSSL_cleanse(buffer, sizeof buffer);
    return !ferror(in);
}

static void usage(FILE *stream)
{
    fputs("Usage: filecrypter2 [--decrypt] INPUT OUTPUT PASSWORD\n"
          "       filecrypter2 --help\n"
          "Encrypt by default; --decrypt decrypts a filecrypter2 file.\n"
          "Use a long, unique password. Existing output files are refused.\n", stream);
}

int main(int argc, char **argv)
{
    int decrypt = argc > 1 && strcmp(argv[1], "--decrypt") == 0;
    int base = decrypt ? 2 : 1;
    FILE *in, *out = NULL, *plain = NULL;
    unsigned char digest[32];
    int ok = 0;
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
    in = fopen(argv[base], "rb");
    if (!in) {
        perror("Error opening input");
        usage(stderr);
        return 1;
    }
    if (strcmp(argv[base], argv[base + 1]) == 0) goto done;
    if (decrypt) {
        plain = tmpfile();
        if (!plain || !crypt(in, plain, argv[base + 2], 1, digest) ||
            fflush(plain) != 0 || fseek(plain, 0, SEEK_SET) != 0) goto done;
        out = fopen(argv[base + 1], "w+b");
        if (!out || !copy(plain, out)) goto done;
    } else {
        out = fopen(argv[base + 1], "w+b");
        if (!out || !crypt(in, out, argv[base + 2], 0, digest)) goto done;
    }
    if (fflush(out) != 0) goto done;
    ok = 1;
done:
    if (plain && fclose(plain) != 0) ok = 0;
    if (out && fclose(out) != 0) ok = 0;
    if (fclose(in) != 0) ok = 0;
    if (!ok) {
        if (out) remove(argv[base + 1]);
        fputs("Error: file operation failed, invalid format, wrong password or damaged ciphertext.\n", stderr);
        usage(stderr);
    }
    return ok ? 0 : 1;
}
