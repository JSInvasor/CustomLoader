#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// XOR encode a .bin file with a given key
// Output: encoded .bin file ready for use with loader.c -x <key>

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("XOR Encoder for CustomLoader\n\n");
        printf("Usage: %s <input.bin> <output.bin> <key 0-255>\n", argv[0]);
        return 1;
    }

    const char *in_path = argv[1];
    const char *out_path = argv[2];
    unsigned char key = (unsigned char)atoi(argv[3]);

    FILE *fin = fopen(in_path, "rb");
    if (!fin) {
        printf("[-] Cannot open: %s\n", in_path);
        return 1;
    }

    fseek(fin, 0, SEEK_END);
    long len = ftell(fin);
    fseek(fin, 0, SEEK_SET);

    unsigned char *buf = (unsigned char *)malloc(len);
    fread(buf, 1, len, fin);
    fclose(fin);

    for (long i = 0; i < len; i++) {
        buf[i] ^= key;
    }

    FILE *fout = fopen(out_path, "wb");
    if (!fout) {
        printf("[-] Cannot write: %s\n", out_path);
        free(buf);
        return 1;
    }

    fwrite(buf, 1, len, fout);
    fclose(fout);
    free(buf);

    printf("[+] Encoded %ld bytes with key 0x%02X\n", len, key);
    printf("[+] Output: %s\n", out_path);
    printf("[+] Decode: loader.exe %s -x %d\n", out_path, key);
    return 0;
}
