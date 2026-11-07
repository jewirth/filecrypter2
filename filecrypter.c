#include <stdio.h>
#include <string.h>

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
    FILE *in;
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
    fclose(in);
    fputs("Error: encryption backend is not yet implemented.\n", stderr);
    usage(stderr);
    return 1;
}
