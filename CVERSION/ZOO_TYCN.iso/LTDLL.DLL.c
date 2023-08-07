typedef unsigned char   undefined;

typedef unsigned long long    GUID;
typedef pointer32 ImageBaseOffset32;

typedef unsigned char    byte;
typedef unsigned int    dword;
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned char    undefined1;
typedef unsigned short    undefined2;
typedef unsigned int    undefined4;
typedef unsigned short    ushort;
typedef unsigned short    wchar16;
typedef short    wchar_t;
typedef unsigned short    word;
typedef struct CLIENT_ID CLIENT_ID, *PCLIENT_ID;

struct CLIENT_ID {
    void * UniqueProcess;
    void * UniqueThread;
};

typedef struct _cpinfo _cpinfo, *P_cpinfo;

typedef uint UINT;

typedef uchar BYTE;

struct _cpinfo {
    UINT MaxCharSize;
    BYTE DefaultChar[2];
    BYTE LeadByte[12];
};

typedef struct _cpinfo * LPCPINFO;

typedef ulong DWORD;

typedef DWORD LCTYPE;

typedef struct _OVERLAPPED _OVERLAPPED, *P_OVERLAPPED;

typedef ulong ULONG_PTR;

typedef union _union_518 _union_518, *P_union_518;

typedef void * HANDLE;

typedef struct _struct_519 _struct_519, *P_struct_519;

typedef void * PVOID;

struct _struct_519 {
    DWORD Offset;
    DWORD OffsetHigh;
};

union _union_518 {
    struct _struct_519 s;
    PVOID Pointer;
};

struct _OVERLAPPED {
    ULONG_PTR Internal;
    ULONG_PTR InternalHigh;
    union _union_518 u;
    HANDLE hEvent;
};

typedef struct _SECURITY_ATTRIBUTES _SECURITY_ATTRIBUTES, *P_SECURITY_ATTRIBUTES;

typedef void * LPVOID;

typedef int BOOL;

struct _SECURITY_ATTRIBUTES {
    DWORD nLength;
    LPVOID lpSecurityDescriptor;
    BOOL bInheritHandle;
};

typedef struct _WIN32_FIND_DATAA _WIN32_FIND_DATAA, *P_WIN32_FIND_DATAA;

typedef struct _FILETIME _FILETIME, *P_FILETIME;

typedef struct _FILETIME FILETIME;

typedef char CHAR;

struct _FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
};

struct _WIN32_FIND_DATAA {
    DWORD dwFileAttributes;
    FILETIME ftCreationTime;
    FILETIME ftLastAccessTime;
    FILETIME ftLastWriteTime;
    DWORD nFileSizeHigh;
    DWORD nFileSizeLow;
    DWORD dwReserved0;
    DWORD dwReserved1;
    CHAR cFileName[260];
    CHAR cAlternateFileName[14];
};

typedef struct _OVERLAPPED * LPOVERLAPPED;

typedef struct _SECURITY_ATTRIBUTES * LPSECURITY_ATTRIBUTES;

typedef struct _STARTUPINFOA _STARTUPINFOA, *P_STARTUPINFOA;

typedef CHAR * LPSTR;

typedef ushort WORD;

typedef BYTE * LPBYTE;

struct _STARTUPINFOA {
    DWORD cb;
    LPSTR lpReserved;
    LPSTR lpDesktop;
    LPSTR lpTitle;
    DWORD dwX;
    DWORD dwY;
    DWORD dwXSize;
    DWORD dwYSize;
    DWORD dwXCountChars;
    DWORD dwYCountChars;
    DWORD dwFillAttribute;
    DWORD dwFlags;
    WORD wShowWindow;
    WORD cbReserved2;
    LPBYTE lpReserved2;
    HANDLE hStdInput;
    HANDLE hStdOutput;
    HANDLE hStdError;
};

typedef struct _WIN32_FIND_DATAA * LPWIN32_FIND_DATAA;

typedef struct _STARTUPINFOA * LPSTARTUPINFOA;

typedef struct _RTL_CRITICAL_SECTION _RTL_CRITICAL_SECTION, *P_RTL_CRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION * PRTL_CRITICAL_SECTION;

typedef PRTL_CRITICAL_SECTION LPCRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION_DEBUG _RTL_CRITICAL_SECTION_DEBUG, *P_RTL_CRITICAL_SECTION_DEBUG;

typedef struct _RTL_CRITICAL_SECTION_DEBUG * PRTL_CRITICAL_SECTION_DEBUG;

typedef long LONG;

typedef struct _LIST_ENTRY _LIST_ENTRY, *P_LIST_ENTRY;

typedef struct _LIST_ENTRY LIST_ENTRY;

struct _RTL_CRITICAL_SECTION {
    PRTL_CRITICAL_SECTION_DEBUG DebugInfo;
    LONG LockCount;
    LONG RecursionCount;
    HANDLE OwningThread;
    HANDLE LockSemaphore;
    ULONG_PTR SpinCount;
};

struct _LIST_ENTRY {
    struct _LIST_ENTRY * Flink;
    struct _LIST_ENTRY * Blink;
};

struct _RTL_CRITICAL_SECTION_DEBUG {
    WORD Type;
    WORD CreatorBackTraceIndex;
    struct _RTL_CRITICAL_SECTION * CriticalSection;
    LIST_ENTRY ProcessLocksList;
    DWORD EntryCount;
    DWORD ContentionCount;
    DWORD Flags;
    WORD CreatorBackTraceIndexHigh;
    WORD SpareWORD;
};

typedef wchar_t WCHAR;

typedef WCHAR * LPWSTR;

typedef WCHAR * LPWCH;

typedef WCHAR * LPCWSTR;

typedef CHAR * LPCSTR;

typedef LONG * PLONG;

typedef CHAR * LPCH;

typedef struct _OSVERSIONINFOA _OSVERSIONINFOA, *P_OSVERSIONINFOA;

struct _OSVERSIONINFOA {
    DWORD dwOSVersionInfoSize;
    DWORD dwMajorVersion;
    DWORD dwMinorVersion;
    DWORD dwBuildNumber;
    DWORD dwPlatformId;
    CHAR szCSDVersion[128];
};

typedef struct _OSVERSIONINFOA * LPOSVERSIONINFOA;

typedef DWORD ACCESS_MASK;

typedef DWORD LCID;

typedef struct IMAGE_DOS_HEADER IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

struct IMAGE_DOS_HEADER {
    char e_magic[2]; // Magic number
    word e_cblp; // Bytes of last page
    word e_cp; // Pages in file
    word e_crlc; // Relocations
    word e_cparhdr; // Size of header in paragraphs
    word e_minalloc; // Minimum extra paragraphs needed
    word e_maxalloc; // Maximum extra paragraphs needed
    word e_ss; // Initial (relative) SS value
    word e_sp; // Initial SP value
    word e_csum; // Checksum
    word e_ip; // Initial IP value
    word e_cs; // Initial (relative) CS value
    word e_lfarlc; // File address of relocation table
    word e_ovno; // Overlay number
    word e_res[4][4]; // Reserved words
    word e_oemid; // OEM identifier (for e_oeminfo)
    word e_oeminfo; // OEM information; e_oemid specific
    word e_res2[10][10]; // Reserved words
    dword e_lfanew; // File address of new exe header
    byte e_program[64]; // Actual DOS program
};

typedef ULONG_PTR SIZE_T;

typedef struct HKEY__ HKEY__, *PHKEY__;

struct HKEY__ {
    int unused;
};

typedef DWORD * LPDWORD;

typedef struct _FILETIME * PFILETIME;

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

typedef struct HINSTANCE__ * HINSTANCE;

struct HINSTANCE__ {
    int unused;
};

typedef HINSTANCE HMODULE;

typedef struct _FILETIME * LPFILETIME;

typedef int (* FARPROC)(void);

typedef WORD * LPWORD;

typedef struct HKEY__ * HKEY;

typedef HKEY * PHKEY;

typedef BOOL * LPBOOL;

typedef void * LPCVOID;

typedef struct IMAGE_OPTIONAL_HEADER32 IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct IMAGE_DATA_DIRECTORY IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

struct IMAGE_DATA_DIRECTORY {
    ImageBaseOffset32 VirtualAddress;
    dword Size;
};

struct IMAGE_OPTIONAL_HEADER32 {
    word Magic;
    byte MajorLinkerVersion;
    byte MinorLinkerVersion;
    dword SizeOfCode;
    dword SizeOfInitializedData;
    dword SizeOfUninitializedData;
    ImageBaseOffset32 AddressOfEntryPoint;
    ImageBaseOffset32 BaseOfCode;
    ImageBaseOffset32 BaseOfData;
    pointer32 ImageBase;
    dword SectionAlignment;
    dword FileAlignment;
    word MajorOperatingSystemVersion;
    word MinorOperatingSystemVersion;
    word MajorImageVersion;
    word MinorImageVersion;
    word MajorSubsystemVersion;
    word MinorSubsystemVersion;
    dword Win32VersionValue;
    dword SizeOfImage;
    dword SizeOfHeaders;
    dword CheckSum;
    word Subsystem;
    word DllCharacteristics;
    dword SizeOfStackReserve;
    dword SizeOfStackCommit;
    dword SizeOfHeapReserve;
    dword SizeOfHeapCommit;
    dword LoaderFlags;
    dword NumberOfRvaAndSizes;
    struct IMAGE_DATA_DIRECTORY DataDirectory[16];
};

typedef struct IMAGE_SECTION_HEADER IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef union Misc Misc, *PMisc;

typedef enum SectionFlags {
    IMAGE_SCN_TYPE_NO_PAD=8,
    IMAGE_SCN_RESERVED_0001=16,
    IMAGE_SCN_CNT_CODE=32,
    IMAGE_SCN_CNT_INITIALIZED_DATA=64,
    IMAGE_SCN_CNT_UNINITIALIZED_DATA=128,
    IMAGE_SCN_LNK_OTHER=256,
    IMAGE_SCN_LNK_INFO=512,
    IMAGE_SCN_RESERVED_0040=1024,
    IMAGE_SCN_LNK_REMOVE=2048,
    IMAGE_SCN_LNK_COMDAT=4096,
    IMAGE_SCN_GPREL=32768,
    IMAGE_SCN_MEM_16BIT=131072,
    IMAGE_SCN_MEM_PURGEABLE=131072,
    IMAGE_SCN_MEM_LOCKED=262144,
    IMAGE_SCN_MEM_PRELOAD=524288,
    IMAGE_SCN_ALIGN_1BYTES=1048576,
    IMAGE_SCN_ALIGN_2BYTES=2097152,
    IMAGE_SCN_ALIGN_4BYTES=3145728,
    IMAGE_SCN_ALIGN_8BYTES=4194304,
    IMAGE_SCN_ALIGN_16BYTES=5242880,
    IMAGE_SCN_ALIGN_32BYTES=6291456,
    IMAGE_SCN_ALIGN_64BYTES=7340032,
    IMAGE_SCN_ALIGN_128BYTES=8388608,
    IMAGE_SCN_ALIGN_256BYTES=9437184,
    IMAGE_SCN_ALIGN_512BYTES=10485760,
    IMAGE_SCN_ALIGN_1024BYTES=11534336,
    IMAGE_SCN_ALIGN_2048BYTES=12582912,
    IMAGE_SCN_ALIGN_4096BYTES=13631488,
    IMAGE_SCN_ALIGN_8192BYTES=14680064,
    IMAGE_SCN_LNK_NRELOC_OVFL=16777216,
    IMAGE_SCN_MEM_DISCARDABLE=33554432,
    IMAGE_SCN_MEM_NOT_CACHED=67108864,
    IMAGE_SCN_MEM_NOT_PAGED=134217728,
    IMAGE_SCN_MEM_SHARED=268435456,
    IMAGE_SCN_MEM_EXECUTE=536870912,
    IMAGE_SCN_MEM_READ=1073741824,
    IMAGE_SCN_MEM_WRITE=2147483648
} SectionFlags;

union Misc {
    dword PhysicalAddress;
    dword VirtualSize;
};

struct IMAGE_SECTION_HEADER {
    char Name[8];
    union Misc Misc;
    ImageBaseOffset32 VirtualAddress;
    dword SizeOfRawData;
    dword PointerToRawData;
    dword PointerToRelocations;
    dword PointerToLinenumbers;
    word NumberOfRelocations;
    word NumberOfLinenumbers;
    enum SectionFlags Characteristics;
};

typedef struct IMAGE_DIRECTORY_ENTRY_EXPORT IMAGE_DIRECTORY_ENTRY_EXPORT, *PIMAGE_DIRECTORY_ENTRY_EXPORT;

struct IMAGE_DIRECTORY_ENTRY_EXPORT {
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    dword Name;
    dword Base;
    dword NumberOfFunctions;
    dword NumberOfNames;
    dword AddressOfFunctions;
    dword AddressOfNames;
    dword AddressOfNameOrdinals;
};

typedef struct IMAGE_FILE_HEADER IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

struct IMAGE_FILE_HEADER {
    word Machine; // 332
    word NumberOfSections;
    dword TimeDateStamp;
    dword PointerToSymbolTable;
    dword NumberOfSymbols;
    word SizeOfOptionalHeader;
    word Characteristics;
};

typedef struct IMAGE_NT_HEADERS32 IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

struct IMAGE_NT_HEADERS32 {
    char Signature[4];
    struct IMAGE_FILE_HEADER FileHeader;
    struct IMAGE_OPTIONAL_HEADER32 OptionalHeader;
};

typedef ACCESS_MASK REGSAM;

typedef LONG LSTATUS;

typedef uint size_t;




void FUN_10001000(int param_1)

{
  (*DAT_100127f8)(param_1);
  if (*(char *)(param_1 + 1) == '\0') {
    WaitForSingleObject(DAT_100127e0,0xffffffff);
  }
  return;
}



undefined FUN_10001120(undefined param_1,undefined param_2,uint *param_3,char *param_4)

{
  undefined uVar1;
  undefined4 *lpAddress;
  LPVOID pvVar2;
  BOOL BVar3;
  int iVar4;
  undefined4 *puVar5;
  
  lpAddress = (undefined4 *)VirtualAlloc((LPVOID)0x0,0x100,0x1000,4);
  puVar5 = lpAddress;
  for (iVar4 = 0x40; iVar4 != 0; iVar4 = iVar4 + -1) {
    *puVar5 = 0;
    puVar5 = puVar5 + 1;
  }
  *(undefined *)lpAddress = 2;
  *(undefined *)((int)lpAddress + 2) = param_1;
  *(undefined *)((int)lpAddress + 3) = 0x48;
  *(undefined *)(lpAddress + 2) = param_2;
  pvVar2 = VirtualAlloc((LPVOID)0x0,0x38,0x1000,4);
  lpAddress[4] = pvVar2;
  lpAddress[3] = 0x38;
  *(undefined *)(lpAddress + 5) = 0xe;
  *(undefined *)((int)lpAddress + 0x15) = 6;
  *(undefined *)(lpAddress + 0xc) = 0x12;
  *(undefined *)(lpAddress + 0xd) = 0x38;
  lpAddress[6] = DAT_100127e0;
  FUN_10001000(lpAddress);
  if (*(char *)((int)lpAddress + 1) == '\x01') {
    *param_3 = (uint)*(byte *)lpAddress[4];
    _strncpy(param_4,(char *)(lpAddress[4] + 8),0x1c);
    param_4[0x1c] = '\0';
  }
  uVar1 = *(undefined *)((int)lpAddress + 1);
  BVar3 = VirtualFree((LPVOID)lpAddress[4],0x38,0x4000);
  if (BVar3 != 0) {
    VirtualFree((LPVOID)lpAddress[4],0,0x8000);
  }
  BVar3 = VirtualFree(lpAddress,0x100,0x4000);
  if (BVar3 != 0) {
    VirtualFree(lpAddress,0,0x8000);
  }
  return uVar1;
}



char FUN_10001210(undefined4 param_1,undefined param_2,undefined param_3,undefined4 *param_4,
                 uint param_5)

{
  char cVar1;
  undefined4 *lpAddress;
  LPVOID pvVar2;
  BOOL BVar3;
  int iVar4;
  uint uVar5;
  undefined4 *puVar6;
  
  lpAddress = (undefined4 *)VirtualAlloc((LPVOID)0x0,0x100,0x1000,4);
  puVar6 = lpAddress;
  for (iVar4 = 0x40; iVar4 != 0; iVar4 = iVar4 + -1) {
    *puVar6 = 0;
    puVar6 = puVar6 + 1;
  }
  *(undefined *)lpAddress = 2;
  *(undefined *)((int)lpAddress + 2) = param_2;
  *(undefined *)((int)lpAddress + 3) = 0x48;
  *(undefined *)(lpAddress + 2) = param_3;
  pvVar2 = VirtualAlloc((LPVOID)0x0,param_5,0x1000,4);
  lpAddress[4] = pvVar2;
  *(char *)((int)lpAddress + 0x33) = (char)((uint)param_1 >> 0x10);
  lpAddress[3] = param_5;
  *(undefined *)(lpAddress + 5) = 0xe;
  *(undefined *)((int)lpAddress + 0x15) = 10;
  *(undefined *)(lpAddress + 0xc) = 0x28;
  *(char *)((int)lpAddress + 0x32) = (char)((uint)param_1 >> 0x18);
  *(char *)(lpAddress + 0xd) = (char)((uint)param_1 >> 8);
  *(char *)((int)lpAddress + 0x35) = (char)param_1;
  *(undefined *)(lpAddress + 0xe) = 1;
  lpAddress[6] = DAT_100127e0;
  FUN_10001000(lpAddress);
  cVar1 = *(char *)((int)lpAddress + 1);
  puVar6 = (undefined4 *)lpAddress[4];
  for (uVar5 = param_5 >> 2; uVar5 != 0; uVar5 = uVar5 - 1) {
    *param_4 = *puVar6;
    puVar6 = puVar6 + 1;
    param_4 = param_4 + 1;
  }
  for (uVar5 = param_5 & 3; uVar5 != 0; uVar5 = uVar5 - 1) {
    *(undefined *)param_4 = *(undefined *)puVar6;
    puVar6 = (undefined4 *)((int)puVar6 + 1);
    param_4 = (undefined4 *)((int)param_4 + 1);
  }
  if (cVar1 != '\x01') {
    DAT_10014049 = *(undefined *)(lpAddress + 0x13);
    DAT_10014048 = *(undefined *)((int)lpAddress + 0x4d);
    DAT_1001404a = cVar1;
  }
  BVar3 = VirtualFree((LPVOID)lpAddress[4],param_5,0x4000);
  if (BVar3 != 0) {
    VirtualFree((LPVOID)lpAddress[4],0,0x8000);
  }
  BVar3 = VirtualFree(lpAddress,0x100,0x4000);
  if (BVar3 != 0) {
    VirtualFree(lpAddress,0,0x8000);
  }
  return cVar1;
}



char FUN_10001330(undefined4 param_1,undefined param_2,undefined param_3,undefined4 *param_4,
                 uint param_5)

{
  char cVar1;
  undefined4 *lpAddress;
  LPVOID pvVar2;
  BOOL BVar3;
  int iVar4;
  uint uVar5;
  undefined4 *puVar6;
  
  lpAddress = (undefined4 *)VirtualAlloc((LPVOID)0x0,0x100,0x1000,4);
  puVar6 = lpAddress;
  for (iVar4 = 0x40; iVar4 != 0; iVar4 = iVar4 + -1) {
    *puVar6 = 0;
    puVar6 = puVar6 + 1;
  }
  *(undefined *)lpAddress = 2;
  *(undefined *)((int)lpAddress + 2) = param_2;
  *(undefined *)((int)lpAddress + 3) = 0x48;
  *(undefined *)(lpAddress + 2) = param_3;
  pvVar2 = VirtualAlloc((LPVOID)0x0,param_5,0x1000,4);
  lpAddress[4] = pvVar2;
  *(char *)((int)lpAddress + 0x33) = (char)((uint)param_1 >> 0x10);
  lpAddress[3] = param_5;
  *(undefined *)(lpAddress + 5) = 0xe;
  *(undefined *)((int)lpAddress + 0x15) = 10;
  *(undefined *)(lpAddress + 0xc) = 0xbe;
  *(char *)((int)lpAddress + 0x32) = (char)((uint)param_1 >> 0x18);
  *(char *)(lpAddress + 0xd) = (char)((uint)param_1 >> 8);
  *(char *)((int)lpAddress + 0x35) = (char)param_1;
  *(undefined *)(lpAddress + 0xe) = 1;
  *(undefined *)((int)lpAddress + 0x39) = 0xf8;
  lpAddress[6] = DAT_100127e0;
  FUN_10001000(lpAddress);
  cVar1 = *(char *)((int)lpAddress + 1);
  puVar6 = (undefined4 *)lpAddress[4];
  for (uVar5 = param_5 >> 2; uVar5 != 0; uVar5 = uVar5 - 1) {
    *param_4 = *puVar6;
    puVar6 = puVar6 + 1;
    param_4 = param_4 + 1;
  }
  for (uVar5 = param_5 & 3; uVar5 != 0; uVar5 = uVar5 - 1) {
    *(undefined *)param_4 = *(undefined *)puVar6;
    puVar6 = (undefined4 *)((int)puVar6 + 1);
    param_4 = (undefined4 *)((int)param_4 + 1);
  }
  if (cVar1 != '\x01') {
    DAT_10014049 = *(undefined *)(lpAddress + 0x13);
    DAT_10014048 = *(undefined *)((int)lpAddress + 0x4d);
    DAT_1001404a = cVar1;
  }
  BVar3 = VirtualFree((LPVOID)lpAddress[4],param_5,0x4000);
  if (BVar3 != 0) {
    VirtualFree((LPVOID)lpAddress[4],0,0x8000);
  }
  BVar3 = VirtualFree(lpAddress,0x100,0x4000);
  if (BVar3 != 0) {
    VirtualFree(lpAddress,0,0x8000);
  }
  return cVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_10001450(void)

{
  short sVar1;
  
  sVar1 = FUN_10003410(&DAT_100127e4);
  if (sVar1 != 0) {
    DAT_100127e0 = CreateEventA((LPSECURITY_ATTRIBUTES)0x0,0,0,(LPCSTR)0x0);
    if (DAT_100127e0 != (HANDLE)0x0) {
      _DAT_100127dc = (*DAT_100127fc)();
      DAT_100127d8 = (char)_DAT_100127dc;
      if ((DAT_100127d8 != '\0') && ((char)((uint)_DAT_100127dc >> 8) == '\x01')) {
        return 1;
      }
    }
  }
  return 0;
}



void FUN_100014a0(void)

{
  char cVar1;
  short sVar2;
  byte bVar3;
  int iVar4;
  undefined4 local_5c;
  undefined4 local_58;
  int local_54;
  undefined local_50 [80];
  
  sVar2 = FUN_10001450();
  if ((sVar2 != 0) && (local_5c = local_5c & 0xffffff00, DAT_100127d8 != 0)) {
    do {
      bVar3 = 0;
      local_58 = local_58 & 0xffffff00;
      iVar4 = 0;
      do {
        cVar1 = FUN_10001120(local_5c,local_58,&local_54,local_50);
        if ((cVar1 == '\x01') && (local_54 == 5)) {
          FUN_100020d0(local_50,local_5c & 0xff,iVar4);
        }
        bVar3 = bVar3 + 1;
        iVar4 = iVar4 + 1;
        local_58 = CONCAT31(local_58._1_3_,bVar3);
      } while (bVar3 < 8);
      bVar3 = (char)local_5c + 1;
      local_5c = CONCAT31(local_5c._1_3_,bVar3);
    } while (bVar3 < DAT_100127d8);
  }
  return;
}



LSTATUS FUN_10001670(HKEY param_1,HKEY param_2,LPBYTE param_3,LPDWORD param_4)

{
  LSTATUS LVar1;
  
  LVar1 = RegOpenKeyExA(param_1,(LPCSTR)param_2,0,0x20019,&param_2);
  if (LVar1 == 0) {
    LVar1 = RegQueryValueExA(param_2,s_HardWareKey_1000f09c,(LPDWORD)0x0,(LPDWORD)&param_1,param_3,
                             param_4);
    RegCloseKey(param_2);
  }
  return LVar1;
}



undefined4 FUN_100016d0(HKEY param_1)

{
  byte bVar1;
  LSTATUS LVar2;
  byte *pbVar3;
  int iVar4;
  byte *pbVar5;
  undefined4 uVar6;
  bool bVar7;
  DWORD local_54;
  byte local_50 [80];
  
  uVar6 = 0;
  local_54 = 0x50;
  LVar2 = RegQueryValueExA(param_1,s_Class_1000f0b0,(LPDWORD)0x0,(LPDWORD)&param_1,local_50,
                           &local_54);
  if ((LVar2 == 0) && (local_54 != 0)) {
    pbVar5 = &DAT_1000f0a8;
    pbVar3 = local_50;
    do {
      bVar1 = *pbVar3;
      bVar7 = bVar1 < *pbVar5;
      if (bVar1 != *pbVar5) {
LAB_1000173d:
        iVar4 = (1 - (uint)bVar7) - (uint)(bVar7 != 0);
        goto LAB_10001742;
      }
      if (bVar1 == 0) break;
      bVar1 = pbVar3[1];
      bVar7 = bVar1 < pbVar5[1];
      if (bVar1 != pbVar5[1]) goto LAB_1000173d;
      pbVar3 = pbVar3 + 2;
      pbVar5 = pbVar5 + 2;
    } while (bVar1 != 0);
    iVar4 = 0;
LAB_10001742:
    if (iVar4 == 0) {
      uVar6 = 1;
    }
  }
  return uVar6;
}



undefined4 FUN_10001760(HKEY param_1)

{
  LSTATUS LVar1;
  undefined4 uVar2;
  DWORD local_54;
  BYTE local_50 [80];
  
  local_54 = 0x50;
  uVar2 = 99;
  LVar1 = RegQueryValueExA(param_1,s_SCSILUN_1000f0b8,(LPDWORD)0x0,(LPDWORD)&param_1,local_50,
                           &local_54);
  if ((LVar1 == 0) && (param_1 == (HKEY)0x1)) {
    uVar2 = FUN_100057b0(local_50);
  }
  return uVar2;
}



undefined4 FUN_100017c0(HKEY param_1)

{
  LSTATUS LVar1;
  undefined4 uVar2;
  DWORD local_54;
  BYTE local_50 [80];
  
  local_54 = 0x50;
  uVar2 = 99;
  LVar1 = RegQueryValueExA(param_1,s_SCSITargetID_1000f0c0,(LPDWORD)0x0,(LPDWORD)&param_1,local_50,
                           &local_54);
  if ((LVar1 == 0) && (param_1 == (HKEY)0x1)) {
    uVar2 = FUN_100057b0(local_50);
  }
  return uVar2;
}



void FUN_10001820(undefined4 param_1,undefined4 *param_2,undefined2 *param_3)

{
  byte bVar1;
  undefined4 *puVar2;
  uint uVar3;
  byte *pbVar4;
  int iVar5;
  undefined4 uVar6;
  uint uVar7;
  undefined4 *puVar8;
  bool bVar9;
  undefined4 local_50;
  
  puVar8 = &local_50;
  puVar2 = (undefined4 *)_strchr((char *)param_2,0x5c);
  if (param_2 != puVar2) {
    uVar3 = (int)puVar2 - (int)param_2;
    puVar8 = &local_50;
    for (uVar7 = uVar3 >> 2; uVar7 != 0; uVar7 = uVar7 - 1) {
      *puVar8 = *param_2;
      param_2 = param_2 + 1;
      puVar8 = puVar8 + 1;
    }
    for (uVar7 = uVar3 & 3; uVar7 != 0; uVar7 = uVar7 - 1) {
      *(undefined *)puVar8 = *(undefined *)param_2;
      param_2 = (undefined4 *)((int)param_2 + 1);
      puVar8 = (undefined4 *)((int)puVar8 + 1);
    }
    puVar8 = (undefined4 *)((int)&local_50 + uVar3);
  }
  *(undefined *)puVar8 = 0;
  puVar8 = &local_50;
  pbVar4 = &DAT_1000f0d0;
  do {
    bVar1 = *pbVar4;
    bVar9 = bVar1 < *(byte *)puVar8;
    if (bVar1 != *(byte *)puVar8) {
LAB_1000188b:
      iVar5 = (1 - (uint)bVar9) - (uint)(bVar9 != 0);
      goto LAB_10001890;
    }
    if (bVar1 == 0) break;
    bVar1 = pbVar4[1];
    bVar9 = bVar1 < *(byte *)((int)puVar8 + 1);
    if (bVar1 != *(byte *)((int)puVar8 + 1)) goto LAB_1000188b;
    pbVar4 = pbVar4 + 2;
    puVar8 = (undefined4 *)((int)puVar8 + 2);
  } while (bVar1 != 0);
  iVar5 = 0;
LAB_10001890:
  if (iVar5 == 0) {
    *param_3 = 1;
    uVar6 = FUN_10001760(param_1);
    *(undefined4 *)(param_3 + 2) = uVar6;
    uVar6 = FUN_100017c0(param_1);
    *(undefined4 *)(param_3 + 4) = uVar6;
    return;
  }
  *param_3 = 0;
  *(undefined4 *)(param_3 + 2) = 99;
  *(undefined4 *)(param_3 + 4) = 99;
  return;
}



char FUN_100018e0(HKEY param_1)

{
  LSTATUS LVar1;
  DWORD local_54;
  byte local_50 [80];
  
  local_54 = 0x50;
  LVar1 = RegQueryValueExA(param_1,s_CurrentDriveLetterAssignment_1000f0d8,(LPDWORD)0x0,
                           (LPDWORD)&param_1,local_50,&local_54);
  if ((((LVar1 == 0) && (param_1 == (HKEY)0x1)) && (0x40 < local_50[0])) && (local_50[0] < 0x5b)) {
    return local_50[0] + 0xbf;
  }
  return 'c';
}



void FUN_10001940(HKEY param_1_00,undefined *param_1,undefined4 *param_3)

{
  char cVar1;
  LSTATUS LVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  DWORD dwIndex;
  uint uVar6;
  uint uVar7;
  undefined4 *puVar8;
  undefined4 *puVar9;
  uint local_210;
  uint uStack_20c;
  _FILETIME _Stack_208;
  undefined4 uStack_200;
  
  dwIndex = 0;
  local_210 = 0;
  do {
    uStack_20c = 0x200;
    LVar2 = RegEnumKeyExA(param_1_00,dwIndex,(LPSTR)&uStack_200,&uStack_20c,(LPDWORD)0x0,(LPSTR)0x0,
                          (LPDWORD)0x0,&_Stack_208);
    if (LVar2 != 0) {
      return;
    }
    uVar6 = 0;
    iVar3 = FUN_10005890(*param_1);
    iVar4 = FUN_10005890(uStack_200 & 0xff);
    uVar7 = uVar6;
    if (iVar3 == iVar4) {
      do {
        uVar7 = uVar6 + 1;
        iVar3 = FUN_10005890(param_1[uVar6 + 1]);
        iVar4 = FUN_10005890(*(undefined *)((int)&uStack_200 + uVar6 + 1));
        uVar6 = uVar7;
      } while (iVar3 == iVar4);
    }
    if ((uStack_20c == uVar7) && (local_210 < uVar7)) {
      uVar6 = 0xffffffff;
      puVar8 = &uStack_200;
      do {
        puVar9 = puVar8;
        if (uVar6 == 0) break;
        uVar6 = uVar6 - 1;
        puVar9 = (undefined4 *)((int)puVar8 + 1);
        cVar1 = *(char *)puVar8;
        puVar8 = puVar9;
      } while (cVar1 != '\0');
      uVar6 = ~uVar6;
      puVar8 = (undefined4 *)((int)puVar9 - uVar6);
      puVar9 = param_3;
      for (uVar5 = uVar6 >> 2; uVar5 != 0; uVar5 = uVar5 - 1) {
        *puVar9 = *puVar8;
        puVar8 = puVar8 + 1;
        puVar9 = puVar9 + 1;
      }
      for (uVar6 = uVar6 & 3; local_210 = uVar7, uVar6 != 0; uVar6 = uVar6 - 1) {
        *(undefined *)puVar9 = *(undefined *)puVar8;
        puVar8 = (undefined4 *)((int)puVar8 + 1);
        puVar9 = (undefined4 *)((int)puVar9 + 1);
      }
    }
    dwIndex = dwIndex + 1;
  } while( true );
}



void FUN_10001a40(char *param_1,LPBYTE param_2)

{
  char cVar1;
  char *pcVar2;
  LSTATUS LVar3;
  uint uVar4;
  int iVar5;
  uint uVar6;
  char *pcVar7;
  undefined4 *puVar8;
  char *pcVar9;
  undefined4 *puVar10;
  undefined4 *puVar11;
  HKEY local_40c;
  HKEY local_408;
  DWORD local_404;
  undefined4 local_400;
  undefined local_3fc;
  undefined4 local_200 [128];
  
  uVar4 = 0xffffffff;
  pcVar2 = param_1;
  do {
    if (uVar4 == 0) break;
    uVar4 = uVar4 - 1;
    cVar1 = *pcVar2;
    pcVar2 = pcVar2 + 1;
  } while (cVar1 != '\0');
  puVar8 = &local_400;
  for (iVar5 = 0x80; iVar5 != 0; iVar5 = iVar5 + -1) {
    *puVar8 = 0;
    puVar8 = puVar8 + 1;
  }
  pcVar7 = param_1 + (~uVar4 - 1);
  local_400 = DAT_1000f0f8;
  local_3fc = DAT_1000f0fc;
  pcVar2 = _strchr(param_1,0x5c);
  if ((pcVar2 != (char *)0x0) && (pcVar2 = _strchr(pcVar2 + 1,0x5c), pcVar2 != (char *)0x0)) {
    pcVar7 = pcVar2 + 1;
  }
  do {
    do {
      LVar3 = RegOpenKeyExA((HKEY)0x80000002,(LPCSTR)&local_400,0,0x20019,&local_40c);
    } while (LVar3 != 0);
    puVar8 = local_200;
    for (iVar5 = 0x80; iVar5 != 0; iVar5 = iVar5 + -1) {
      *puVar8 = 0;
      puVar8 = puVar8 + 1;
    }
    FUN_10001940(local_40c,pcVar7,local_200);
    RegCloseKey(local_40c);
    iVar5 = -1;
    puVar8 = local_200;
    do {
      if (iVar5 == 0) break;
      iVar5 = iVar5 + -1;
      cVar1 = *(char *)puVar8;
      puVar8 = (undefined4 *)((int)puVar8 + 1);
    } while (cVar1 != '\0');
    if (iVar5 == -2) {
      LVar3 = RegOpenKeyExA((HKEY)0x80000002,(LPCSTR)&local_400,0,0x20019,&local_408);
      if (LVar3 == 0) {
        RegQueryValueExA(local_408,s_Class_1000f0b0,(LPDWORD)0x0,&local_404,param_2,
                         (LPDWORD)&stack0x0000000c);
        RegCloseKey(local_408);
      }
      return;
    }
    uVar4 = 0xffffffff;
    pcVar2 = (char *)0x1000f030;
    do {
      pcVar9 = pcVar2;
      if (uVar4 == 0) break;
      uVar4 = uVar4 - 1;
      pcVar9 = pcVar2 + 1;
      cVar1 = *pcVar2;
      pcVar2 = pcVar9;
    } while (cVar1 != '\0');
    uVar4 = ~uVar4;
    iVar5 = -1;
    puVar8 = &local_400;
    do {
      puVar11 = puVar8;
      if (iVar5 == 0) break;
      iVar5 = iVar5 + -1;
      puVar11 = (undefined4 *)((int)puVar8 + 1);
      cVar1 = *(char *)puVar8;
      puVar8 = puVar11;
    } while (cVar1 != '\0');
    puVar8 = (undefined4 *)(pcVar9 + -uVar4);
    puVar11 = (undefined4 *)((int)puVar11 + -1);
    for (uVar6 = uVar4 >> 2; uVar6 != 0; uVar6 = uVar6 - 1) {
      *puVar11 = *puVar8;
      puVar8 = puVar8 + 1;
      puVar11 = puVar11 + 1;
    }
    for (uVar4 = uVar4 & 3; uVar4 != 0; uVar4 = uVar4 - 1) {
      *(undefined *)puVar11 = *(undefined *)puVar8;
      puVar8 = (undefined4 *)((int)puVar8 + 1);
      puVar11 = (undefined4 *)((int)puVar11 + 1);
    }
    uVar4 = 0xffffffff;
    puVar8 = local_200;
    do {
      puVar11 = puVar8;
      if (uVar4 == 0) break;
      uVar4 = uVar4 - 1;
      puVar11 = (undefined4 *)((int)puVar8 + 1);
      cVar1 = *(char *)puVar8;
      puVar8 = puVar11;
    } while (cVar1 != '\0');
    uVar4 = ~uVar4;
    iVar5 = -1;
    puVar8 = &local_400;
    do {
      puVar10 = puVar8;
      if (iVar5 == 0) break;
      iVar5 = iVar5 + -1;
      puVar10 = (undefined4 *)((int)puVar8 + 1);
      cVar1 = *(char *)puVar8;
      puVar8 = puVar10;
    } while (cVar1 != '\0');
    puVar8 = (undefined4 *)((int)puVar11 - uVar4);
    puVar11 = (undefined4 *)((int)puVar10 + -1);
    for (uVar6 = uVar4 >> 2; uVar6 != 0; uVar6 = uVar6 - 1) {
      *puVar11 = *puVar8;
      puVar8 = puVar8 + 1;
      puVar11 = puVar11 + 1;
    }
    for (uVar4 = uVar4 & 3; uVar4 != 0; uVar4 = uVar4 - 1) {
      *(undefined *)puVar11 = *(undefined *)puVar8;
      puVar8 = (undefined4 *)((int)puVar8 + 1);
      puVar11 = (undefined4 *)((int)puVar11 + 1);
    }
    uVar4 = 0xffffffff;
    puVar8 = local_200;
    do {
      if (uVar4 == 0) break;
      uVar4 = uVar4 - 1;
      cVar1 = *(char *)puVar8;
      puVar8 = (undefined4 *)((int)puVar8 + 1);
    } while (cVar1 != '\0');
    pcVar7 = pcVar7 + (~uVar4 - 1);
    if (*pcVar7 == '&') {
      pcVar7 = pcVar7 + 1;
    }
  } while( true );
}



void FUN_10001be0(HKEY param_1,LPBYTE param_2,DWORD param_3)

{
  LPBYTE pBVar1;
  LSTATUS LVar2;
  
  pBVar1 = param_2;
  *param_2 = '\0';
  LVar2 = RegQueryValueExA(param_1,s_DeviceDesc_1000f100,(LPDWORD)0x0,(LPDWORD)&param_2,param_2,
                           &param_3);
  if ((LVar2 == 0) && (param_2 != (LPBYTE)0x1)) {
    *pBVar1 = '\0';
  }
  return;
}



void FUN_10001c20(undefined4 param_1,undefined4 param_2)

{
  int iVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  undefined4 local_b8 [4];
  undefined local_a7;
  undefined local_a6 [82];
  undefined local_54 [84];
  
  puVar2 = local_b8;
  for (iVar1 = 0x2e; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  FUN_10001820(param_1,param_2,local_b8);
  local_a7 = FUN_100018e0(param_1);
  FUN_10001a40(param_2,local_54,0x50);
  FUN_10001be0(param_1,local_a6,0x50);
  puVar2 = local_b8;
  puVar3 = (undefined4 *)(&DAT_100131e4 + DAT_100131e0 * 0xb8);
  for (iVar1 = 0x2e; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  DAT_100131e0 = DAT_100131e0 + 1;
  return;
}



void FUN_10001cc0(void)

{
  byte bVar1;
  uint uVar2;
  byte *pbVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  byte *pbVar7;
  int *piVar8;
  bool bVar9;
  bool bVar10;
  int *local_10;
  int *local_8;
  
  uVar2 = DAT_100131e0;
  if ((1 < DAT_100131e0) && (DAT_100131e0 != 1)) {
    local_10 = &DAT_100131ec;
    local_8 = &DAT_100132a4;
    uVar5 = 1;
    do {
      bVar10 = false;
      if (uVar5 < uVar2) {
        iVar6 = uVar2 - uVar5;
        piVar8 = local_8;
        do {
          pbVar7 = (byte *)((int)piVar8 + 10);
          pbVar3 = (byte *)((int)local_10 + 10);
          do {
            bVar1 = *pbVar3;
            bVar9 = bVar1 < *pbVar7;
            if (bVar1 != *pbVar7) {
LAB_10001d34:
              iVar4 = (1 - (uint)bVar9) - (uint)(bVar9 != 0);
              goto LAB_10001d39;
            }
            if (bVar1 == 0) break;
            bVar1 = pbVar3[1];
            bVar9 = bVar1 < pbVar7[1];
            if (bVar1 != pbVar7[1]) goto LAB_10001d34;
            pbVar3 = pbVar3 + 2;
            pbVar7 = pbVar7 + 2;
          } while (bVar1 != 0);
          iVar4 = 0;
LAB_10001d39:
          if ((iVar4 == 0) && (*local_10 == *piVar8)) {
            *piVar8 = 99;
            bVar10 = true;
          }
          piVar8 = piVar8 + 0x2e;
          iVar6 = iVar6 + -1;
        } while (iVar6 != 0);
      }
      if (bVar10) {
        *local_10 = 99;
      }
      local_8 = local_8 + 0x2e;
      local_10 = local_10 + 0x2e;
      bVar10 = uVar5 < uVar2 - 1;
      uVar5 = uVar5 + 1;
    } while (bVar10);
  }
  return;
}



void FUN_10001db0(char *param_1)

{
  char cVar1;
  short sVar2;
  LSTATUS LVar3;
  uint uVar4;
  int iVar5;
  uint uVar6;
  undefined4 *puVar7;
  char *pcVar8;
  char *pcVar9;
  undefined4 *puVar10;
  HKEY local_204;
  undefined4 local_200;
  undefined local_1fc;
  
  local_200 = DAT_1000f0f8;
  local_1fc = DAT_1000f0fc;
  uVar4 = 0xffffffff;
  pcVar8 = (char *)0x1000f030;
  do {
    pcVar9 = pcVar8;
    if (uVar4 == 0) break;
    uVar4 = uVar4 - 1;
    pcVar9 = pcVar8 + 1;
    cVar1 = *pcVar8;
    pcVar8 = pcVar9;
  } while (cVar1 != '\0');
  uVar4 = ~uVar4;
  iVar5 = -1;
  puVar7 = &local_200;
  do {
    puVar10 = puVar7;
    if (iVar5 == 0) break;
    iVar5 = iVar5 + -1;
    puVar10 = (undefined4 *)((int)puVar7 + 1);
    cVar1 = *(char *)puVar7;
    puVar7 = puVar10;
  } while (cVar1 != '\0');
  puVar7 = (undefined4 *)(pcVar9 + -uVar4);
  puVar10 = (undefined4 *)((int)puVar10 + -1);
  for (uVar6 = uVar4 >> 2; uVar6 != 0; uVar6 = uVar6 - 1) {
    *puVar10 = *puVar7;
    puVar7 = puVar7 + 1;
    puVar10 = puVar10 + 1;
  }
  for (uVar4 = uVar4 & 3; uVar4 != 0; uVar4 = uVar4 - 1) {
    *(undefined *)puVar10 = *(undefined *)puVar7;
    puVar7 = (undefined4 *)((int)puVar7 + 1);
    puVar10 = (undefined4 *)((int)puVar10 + 1);
  }
  uVar4 = 0xffffffff;
  pcVar8 = param_1;
  do {
    pcVar9 = pcVar8;
    if (uVar4 == 0) break;
    uVar4 = uVar4 - 1;
    pcVar9 = pcVar8 + 1;
    cVar1 = *pcVar8;
    pcVar8 = pcVar9;
  } while (cVar1 != '\0');
  uVar4 = ~uVar4;
  iVar5 = -1;
  puVar7 = &local_200;
  do {
    puVar10 = puVar7;
    if (iVar5 == 0) break;
    iVar5 = iVar5 + -1;
    puVar10 = (undefined4 *)((int)puVar7 + 1);
    cVar1 = *(char *)puVar7;
    puVar7 = puVar10;
  } while (cVar1 != '\0');
  puVar7 = (undefined4 *)(pcVar9 + -uVar4);
  puVar10 = (undefined4 *)((int)puVar10 + -1);
  for (uVar6 = uVar4 >> 2; uVar6 != 0; uVar6 = uVar6 - 1) {
    *puVar10 = *puVar7;
    puVar7 = puVar7 + 1;
    puVar10 = puVar10 + 1;
  }
  for (uVar4 = uVar4 & 3; uVar4 != 0; uVar4 = uVar4 - 1) {
    *(undefined *)puVar10 = *(undefined *)puVar7;
    puVar7 = (undefined4 *)((int)puVar7 + 1);
    puVar10 = (undefined4 *)((int)puVar10 + 1);
  }
  LVar3 = RegOpenKeyExA((HKEY)0x80000002,(LPCSTR)&local_200,0,0x20019,&local_204);
  if (LVar3 == 0) {
    sVar2 = FUN_100016d0(local_204);
    if (sVar2 != 0) {
      FUN_10001c20(local_204,param_1);
      FUN_10001cc0();
    }
    RegCloseKey(local_204);
  }
  return;
}



void FUN_10001e90(HKEY param_1)

{
  LSTATUS LVar1;
  int iVar2;
  DWORD dwIndex;
  DWORD local_410;
  undefined4 local_40c;
  _FILETIME local_408;
  CHAR local_400 [512];
  undefined local_200 [512];
  
  dwIndex = 0;
  while( true ) {
    local_410 = 0x200;
    LVar1 = RegEnumKeyExA(param_1,dwIndex,local_400,&local_410,(LPDWORD)0x0,(LPSTR)0x0,(LPDWORD)0x0,
                          &local_408);
    if (LVar1 != 0) break;
    local_40c = 0x200;
    iVar2 = FUN_10001670(param_1,local_400,local_200,&local_40c);
    if (iVar2 == 0) {
      FUN_10001db0(local_200);
    }
    dwIndex = dwIndex + 1;
  }
  return;
}



void FUN_10001f10(undefined param_1)

{
  int iVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  undefined4 local_b8;
  undefined local_b4 [4];
  undefined local_b0 [4];
  undefined local_ac [4];
  undefined local_a8;
  undefined local_a7;
  undefined local_a6 [80];
  undefined2 local_56;
  undefined local_54 [80];
  undefined local_4 [4];
  
  local_a7 = param_1;
  local_56 = 0;
  FUN_10002460(param_1,local_b4,local_b0,local_ac,&local_a8,local_a6,local_4,&local_b8,local_54);
  puVar2 = &local_b8;
  puVar3 = (undefined4 *)(&DAT_100131e4 + DAT_100131e0 * 0xb8);
  for (iVar1 = 0x2e; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  DAT_100131e0 = DAT_100131e0 + 1;
  return;
}



void __fastcall FUN_10001fa0(undefined4 param_1)

{
  UINT UVar1;
  uint uVar2;
  undefined4 local_4;
  
  uVar2 = 0;
  local_4 = param_1;
  do {
    FUN_10005510(&local_4,&DAT_1000f094,uVar2 + 0x41);
    UVar1 = GetDriveTypeA((LPCSTR)&local_4);
    if (UVar1 == 5) {
      FUN_10001f10(uVar2);
    }
    uVar2 = uVar2 + 1;
  } while (uVar2 < 0x1a);
  return;
}



void FUN_10001fe0(void)

{
  short sVar1;
  LSTATUS LVar2;
  HKEY pHStack_4;
  
  sVar1 = FUN_100028f0();
  if (sVar1 == 0) {
    LVar2 = RegOpenKeyExA((HKEY)0x80000006,s_Config_Manager_Enum_1000f10c,0,0x20019,&pHStack_4);
    if (LVar2 == 0) {
      FUN_10001e90(pHStack_4);
      RegCloseKey(pHStack_4);
      return;
    }
  }
  else {
    FUN_10001fa0();
  }
  return;
}



int FUN_10002030(char *param_1,char *param_2)

{
  int iVar1;
  char cVar2;
  char *pcVar3;
  uint uVar4;
  
  iVar1 = 0;
  if ((param_1 == (char *)0x0) || (param_2 == (char *)0x0)) {
LAB_100020ba:
    iVar1 = 99;
  }
  else {
    uVar4 = 0;
    pcVar3 = param_1;
    do {
      if (param_1[uVar4] != ' ') {
        pcVar3 = param_1 + uVar4;
      }
      uVar4 = uVar4 + 1;
    } while (uVar4 < 8);
    cVar2 = *param_1;
    while( true ) {
      if (((cVar2 == '\0') || (*param_2 == '\0')) || (pcVar3 < param_1)) goto LAB_1000207d;
      if (*param_1 != *param_2) break;
      cVar2 = param_1[1];
      param_1 = param_1 + 1;
      param_2 = param_2 + 1;
    }
    iVar1 = 99;
LAB_1000207d:
    if (iVar1 == 0) {
      cVar2 = *param_1;
      while (cVar2 == ' ') {
        pcVar3 = param_1 + 1;
        param_1 = param_1 + 1;
        cVar2 = *pcVar3;
      }
      cVar2 = *param_2;
      while (cVar2 == ' ') {
        pcVar3 = param_2 + 1;
        param_2 = param_2 + 1;
        cVar2 = *pcVar3;
      }
      cVar2 = *param_1;
      if (cVar2 != '\0') {
        while (*param_2 != '\0') {
          if (cVar2 != *param_2) goto LAB_100020ba;
          cVar2 = param_1[1];
          param_1 = param_1 + 1;
          param_2 = param_2 + 1;
          if (cVar2 == '\0') {
            return 0;
          }
        }
      }
    }
  }
  return iVar1;
}



void FUN_100020d0(int param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  undefined *puVar2;
  uint uVar3;
  
  uVar3 = 0;
  puVar2 = &DAT_100131e4;
  if (DAT_100131e0 != 0) {
    while ((iVar1 = FUN_10002030(param_1,puVar2 + 0x12), iVar1 != 0 ||
           (*(int *)(puVar2 + 8) != param_3))) {
      uVar3 = uVar3 + 1;
      puVar2 = puVar2 + 0xb8;
      if (DAT_100131e0 <= uVar3) {
        return;
      }
    }
    *(int *)(puVar2 + 8) = param_3;
    *(undefined4 *)(puVar2 + 0xc) = param_2;
    *(undefined2 *)(puVar2 + 0x62) = 1;
    *(undefined4 *)(puVar2 + 0xb4) = *(undefined4 *)(param_1 + 0x18);
  }
  return;
}



void FUN_100022d0(char param_1,undefined2 *param_2_00,undefined4 *param_2)

{
  char cVar1;
  LSTATUS LVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  undefined4 *puVar6;
  char *pcVar7;
  char *pcVar8;
  undefined4 *puVar9;
  HKEY local_20c;
  DWORD local_208;
  undefined4 local_204;
  undefined4 local_200;
  
  puVar6 = &local_200;
  for (iVar3 = 0x80; iVar3 != 0; iVar3 = iVar3 + -1) {
    *puVar6 = 0;
    puVar6 = puVar6 + 1;
  }
  puVar6 = (undefined4 *)s_HARDWARE_DEVICEMAP_Scsi_Scsi_Por_1000f334;
  puVar9 = &local_200;
  for (iVar3 = 8; iVar3 != 0; iVar3 = iVar3 + -1) {
    *puVar9 = *puVar6;
    puVar6 = puVar6 + 1;
    puVar9 = puVar9 + 1;
  }
  uVar4 = 0xffffffff;
  *(undefined2 *)puVar9 = *(undefined2 *)puVar6;
  *(undefined *)((int)puVar9 + 2) = *(undefined *)((int)puVar6 + 2);
  puVar6 = &local_200;
  do {
    if (uVar4 == 0) break;
    uVar4 = uVar4 - 1;
    cVar1 = *(char *)puVar6;
    puVar6 = (undefined4 *)((int)puVar6 + 1);
  } while (cVar1 != '\0');
  local_208 = 0x20;
  *(char *)((int)&local_204 + ~uVar4 + 3) = param_1 + '0';
  LVar2 = RegOpenKeyExA((HKEY)0x80000002,(LPCSTR)&local_200,0,1,&local_20c);
  if (LVar2 == 0) {
    RegQueryValueExA(local_20c,s_Driver_1000f32c,(LPDWORD)0x0,&local_204,(LPBYTE)param_2,&local_208)
    ;
    RegCloseKey(local_20c);
  }
  else {
    *param_2 = s_Unknown_1000f324._0_4_;
    param_2[1] = s_Unknown_1000f324._4_4_;
  }
  uVar4 = 0xffffffff;
  pcVar7 = s__Scsi_Bus_0_Initiator_Id_255_1000f304;
  do {
    pcVar8 = pcVar7;
    if (uVar4 == 0) break;
    uVar4 = uVar4 - 1;
    pcVar8 = pcVar7 + 1;
    cVar1 = *pcVar7;
    pcVar7 = pcVar8;
  } while (cVar1 != '\0');
  uVar4 = ~uVar4;
  iVar3 = -1;
  puVar6 = &local_200;
  do {
    puVar9 = puVar6;
    if (iVar3 == 0) break;
    iVar3 = iVar3 + -1;
    puVar9 = (undefined4 *)((int)puVar6 + 1);
    cVar1 = *(char *)puVar6;
    puVar6 = puVar9;
  } while (cVar1 != '\0');
  puVar6 = (undefined4 *)(pcVar8 + -uVar4);
  puVar9 = (undefined4 *)((int)puVar9 + -1);
  for (uVar5 = uVar4 >> 2; uVar5 != 0; uVar5 = uVar5 - 1) {
    *puVar9 = *puVar6;
    puVar6 = puVar6 + 1;
    puVar9 = puVar9 + 1;
  }
  for (uVar4 = uVar4 & 3; uVar4 != 0; uVar4 = uVar4 - 1) {
    *(undefined *)puVar9 = *(undefined *)puVar6;
    puVar6 = (undefined4 *)((int)puVar6 + 1);
    puVar9 = (undefined4 *)((int)puVar9 + 1);
  }
  LVar2 = RegOpenKeyExA((HKEY)0x80000002,(LPCSTR)&local_200,0,1,&local_20c);
  if (LVar2 == 0) {
    RegCloseKey(local_20c);
    *param_2_00 = 0;
    return;
  }
  *param_2_00 = 1;
  return;
}



bool FUN_10002410(char param_1,HANDLE *param_2)

{
  HANDLE pvVar1;
  CHAR aCStack_c [12];
  
  FUN_10005510(aCStack_c,s______c__1000f358,(int)param_1);
  pvVar1 = CreateFileA(aCStack_c,0x80000000,3,(LPSECURITY_ATTRIBUTES)0x0,3,0x80,(HANDLE)0x0);
  *param_2 = pvVar1;
  return pvVar1 != (HANDLE)0xffffffff;
}



short FUN_10002460(HANDLE param_1,uint *param_2,uint *param_3,uint *param_4,undefined *param_5,
                  undefined4 param_6,undefined4 param_7,undefined4 param_8,undefined4 param_9)

{
  short sVar1;
  BOOL BVar2;
  DWORD local_10;
  undefined local_c [4];
  undefined2 uStack_8;
  undefined uStack_6;
  byte bStack_5;
  
  sVar1 = FUN_10002410((char)param_1 + 'A',&param_1);
  if (sVar1 == 0) {
    return 0;
  }
  BVar2 = DeviceIoControl(param_1,0x41018,(LPVOID)0x0,0,local_c,8,&local_10,(LPOVERLAPPED)0x0);
  if ((short)BVar2 == 0) {
    sVar1 = FUN_100025a0();
    if (sVar1 == 0) {
      CloseHandle(param_1);
      return 0;
    }
  }
  else {
    *param_2 = (uint)bStack_5;
    *param_3 = CONCAT11(bStack_5,uStack_6) & 0xff;
    *param_4 = CONCAT12(uStack_6,uStack_8) & 0xff;
    *param_5 = (char)((ushort)uStack_8 >> 8);
    FUN_100022d0(CONCAT13(bStack_5,CONCAT12(uStack_6,uStack_8)),param_8,param_9);
  }
  sVar1 = FUN_100025a0();
  if (sVar1 == 0) {
    sVar1 = FUN_100025c0(param_1,local_c,param_6,param_7);
    if (sVar1 == 0) {
      CloseHandle(param_1);
      return 0;
    }
  }
  else {
    sVar1 = FUN_10002960(param_1,param_6,param_7);
    if (sVar1 == 0) {
      CloseHandle(param_1);
      return 0;
    }
  }
  CloseHandle(param_1);
  return sVar1;
}



undefined2 FUN_100025a0(void)

{
  short sVar1;
  
  sVar1 = FUN_100028f0();
  if (sVar1 != 0) {
    sVar1 = FUN_10002920();
    if (sVar1 == 0) {
      return 1;
    }
  }
  return 0;
}



uint FUN_100025c0(uint param_1)

{
  undefined4 uVar1;
  uint uVar2;
  DWORD DVar3;
  int iVar4;
  uint uVar5;
  undefined4 *puVar6;
  uint *puVar7;
  undefined4 *puVar8;
  HANDLE in_stack_00001008;
  int in_stack_0000100c;
  undefined4 *in_stack_00001010;
  undefined4 *in_stack_00001014;
  
  FUN_10005ef0();
  puVar6 = &param_1;
  for (iVar4 = 0x400; iVar4 != 0; iVar4 = iVar4 + -1) {
    *puVar6 = 0;
    puVar6 = puVar6 + 1;
  }
  uVar2 = DeviceIoControl(in_stack_00001008,0x4100c,(LPVOID)0x0,0,&param_1,0x1000,
                          (LPDWORD)&stack0x00000000,(LPOVERLAPPED)0x0);
  if (uVar2 == 0) {
    DVar3 = GetLastError();
    return DVar3 & 0xffff0000;
  }
  uVar5 = 0;
  if ((param_1 & 0xff) == 0) {
    return uVar2 & 0xffff0000;
  }
  puVar7 = (uint *)&stack0x0000000c;
  do {
    uVar2 = *puVar7;
    if (uVar2 != 0) {
      do {
        if (((*(char *)((int)&param_1 + uVar2) == *(char *)(in_stack_0000100c + 5)) &&
            (*(char *)((int)&param_1 + uVar2 + 1) == *(char *)(in_stack_0000100c + 6))) &&
           (*(char *)((int)&param_1 + uVar2 + 2) == *(char *)(in_stack_0000100c + 7))) {
          puVar6 = (undefined4 *)(&stack0x00000018 + uVar2);
          puVar8 = in_stack_00001010;
          for (iVar4 = 6; iVar4 != 0; iVar4 = iVar4 + -1) {
            *puVar8 = *puVar6;
            puVar6 = puVar6 + 1;
            puVar8 = puVar8 + 1;
          }
          *(undefined *)(in_stack_00001010 + 6) = 0;
          uVar1 = *(undefined4 *)(&stack0x00000030 + uVar2);
          *in_stack_00001014 = uVar1;
          return CONCAT22((short)((uint)uVar1 >> 0x10),1);
        }
        uVar2 = *(uint *)(&stack0x0000000c + uVar2);
      } while (uVar2 != 0);
    }
    uVar5 = uVar5 + 1;
    puVar7 = puVar7 + 2;
    if ((param_1 & 0xff) <= uVar5) {
      return uVar2 & 0xffff0000;
    }
  } while( true );
}



bool FUN_100028f0(void)

{
  _OSVERSIONINFOA _Stack_94;
  
  _Stack_94.dwOSVersionInfoSize = 0x94;
  GetVersionExA(&_Stack_94);
  return _Stack_94.dwPlatformId == 2;
}



bool FUN_10002920(void)

{
  _OSVERSIONINFOA _Stack_94;
  
  if (DAT_1000f360 == 0xffffff9c) {
    _Stack_94.dwOSVersionInfoSize = 0x94;
    GetVersionExA(&_Stack_94);
    DAT_1000f360 = _Stack_94.dwMajorVersion;
  }
  return 4 < DAT_1000f360;
}



bool FUN_10002960(HANDLE param_1,undefined4 *param_2,undefined4 *param_3)

{
  BOOL BVar1;
  BOOL BVar2;
  int iVar3;
  undefined4 *puVar4;
  undefined4 *puVar5;
  DWORD DStack_54;
  undefined4 local_50;
  undefined local_4c;
  undefined local_4b;
  undefined local_4a;
  undefined local_49;
  undefined local_48;
  undefined4 local_44;
  undefined4 local_40;
  LPVOID pvStack_3c;
  undefined4 uStack_38;
  undefined uStack_34;
  undefined uStack_33;
  undefined uStack_32;
  undefined uStack_31;
  undefined uStack_30;
  undefined uStack_2f;
  
  puVar4 = &local_50;
  for (iVar3 = 0x14; iVar3 != 0; iVar3 = iVar3 + -1) {
    *puVar4 = 0;
    puVar4 = puVar4 + 1;
  }
  local_50._0_2_ = 0x2c;
  local_50._3_1_ = 0;
  local_4c = 0;
  local_4b = 0;
  local_4a = 6;
  local_48 = 1;
  local_49 = 0x18;
  local_44 = 0x38;
  local_40 = 10;
  pvStack_3c = VirtualAlloc((LPVOID)0x0,0x38,0x1000,4);
  uStack_38 = 0x30;
  uStack_34 = 0x12;
  uStack_33 = 0;
  uStack_32 = 0;
  uStack_31 = 0;
  uStack_30 = 0x38;
  uStack_2f = 0;
  BVar1 = DeviceIoControl(param_1,0x4d014,&local_50,0x50,&local_50,0x50,&DStack_54,(LPOVERLAPPED)0x0
                         );
  if ((char)BVar1 != '\0') {
    puVar4 = (undefined4 *)((int)pvStack_3c + 8);
    puVar5 = param_2;
    for (iVar3 = 6; iVar3 != 0; iVar3 = iVar3 + -1) {
      *puVar5 = *puVar4;
      puVar4 = puVar4 + 1;
      puVar5 = puVar5 + 1;
    }
    *(undefined *)(param_2 + 6) = 0;
    *param_3 = *(undefined4 *)((int)pvStack_3c + 0x20);
  }
  BVar2 = VirtualFree(pvStack_3c,0x38,0x4000);
  if (BVar2 != 0) {
    VirtualFree(pvStack_3c,0,0x8000);
  }
  return (char)BVar1 != '\0';
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_10003000(LPCSTR param_1)

{
  char cVar1;
  short sVar2;
  char *pcVar3;
  uint uVar4;
  uint uVar5;
  undefined4 *puVar6;
  LPCSTR pCVar7;
  undefined4 *puVar8;
  undefined4 local_104 [65];
  
  sVar2 = FUN_100028f0();
  if ((sVar2 == 0) && (DAT_100127f0 == (FARPROC)0x0)) {
    uVar4 = 0xffffffff;
    pCVar7 = param_1;
    do {
      pcVar3 = pCVar7;
      if (uVar4 == 0) break;
      uVar4 = uVar4 - 1;
      pcVar3 = pCVar7 + 1;
      cVar1 = *pCVar7;
      pCVar7 = pcVar3;
    } while (cVar1 != '\0');
    uVar4 = ~uVar4;
    puVar6 = (undefined4 *)(pcVar3 + -uVar4);
    puVar8 = local_104;
    for (uVar5 = uVar4 >> 2; uVar5 != 0; uVar5 = uVar5 - 1) {
      *puVar8 = *puVar6;
      puVar6 = puVar6 + 1;
      puVar8 = puVar8 + 1;
    }
    for (uVar4 = uVar4 & 3; uVar4 != 0; uVar4 = uVar4 - 1) {
      *(undefined *)puVar8 = *(undefined *)puVar6;
      puVar6 = (undefined4 *)((int)puVar6 + 1);
      puVar8 = (undefined4 *)((int)puVar8 + 1);
    }
    pcVar3 = _strrchr((char *)local_104,0x5c);
    if (pcVar3 != (char *)0x0) {
      if (pcVar3[-1] == ':') {
        pcVar3 = pcVar3 + 1;
      }
      *pcVar3 = '\0';
    }
    FUN_10004ed0(local_104);
    DAT_10014044 = LoadLibraryExA(param_1,(HANDLE)0x0,8);
    FUN_10005060();
    DAT_100127f0 = GetProcAddress(DAT_10014044,s__SetVectors_If32_16_1000f064);
    DAT_100127ec = GetProcAddress(DAT_10014044,s__GetV86Vector_If32_12_1000f04c);
    _DAT_100127e8 = GetProcAddress(DAT_10014044,s__SetV86Vector_If32_12_1000f034);
    if (((DAT_100127f0 == (FARPROC)0x0) || (DAT_100127ec == (FARPROC)0x0)) ||
       (_DAT_100127e8 == (FARPROC)0x0)) {
      if (DAT_10014044 != (HMODULE)0x0) {
        FreeLibrary(DAT_10014044);
      }
      return 100;
    }
  }
  return 0x65;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_10003120(undefined4 param_1)

{
  undefined4 uVar1;
  undefined4 uStack_108;
  undefined local_104 [260];
  
  if (_DAT_100127f4 == 0) {
    _DAT_100127f4 = 1;
    FUN_10005510(local_104,s__s_CLCD32_DLL_1000f078,param_1,s_clcd32_dll_1000f088);
    uVar1 = FUN_10003000(local_104);
    return uVar1;
  }
  return uStack_108;
}



bool FUN_10003410(HMODULE *param_1)

{
  HMODULE hModule;
  bool bVar1;
  
  hModule = LoadLibraryA(s_wnaspi32_dll_1000f160);
  *param_1 = hModule;
  if (hModule != (HMODULE)0x0) {
    DAT_100127fc = GetProcAddress(hModule,s_GetASPI32SupportInfo_1000f148);
    bVar1 = DAT_100127fc != (FARPROC)0x0;
    DAT_100127f8 = GetProcAddress(*param_1,s_SendASPI32Command_1000f134);
    if (DAT_100127f8 != (FARPROC)0x0) {
      return bVar1;
    }
  }
  return false;
}



undefined4 FUN_10003840(LPCSTR param_1,undefined4 param_2)

{
  LPVOID lpBuffer;
  HANDLE pvVar1;
  int iVar2;
  BOOL BVar3;
  DWORD DVar4;
  DWORD lDistanceToMove;
  DWORD DStack_30;
  undefined4 local_2c;
  undefined4 uStack_28;
  DWORD DStack_24;
  BOOL BStack_20;
  DWORD DStack_1c;
  _FILETIME _Stack_18;
  _FILETIME _Stack_10;
  _FILETIME _Stack_8;
  
  local_2c = 0x68;
  lDistanceToMove = 0;
  lpBuffer = (LPVOID)FUN_10005410(0x1000);
  if (lpBuffer == (LPVOID)0x0) {
    return 0xa1;
  }
  DStack_24 = GetFileAttributesA(param_1);
  if (DStack_24 == 0xffffffff) {
    FUN_100053a0(lpBuffer);
    return 0x9a;
  }
  pvVar1 = CreateFileA(param_1,0x80000000,0,(LPSECURITY_ATTRIBUTES)0x0,3,0x80,(HANDLE)0x0);
  if (pvVar1 != (HANDLE)0xffffffff) {
    BStack_20 = GetFileTime(pvVar1,&_Stack_8,&_Stack_10,&_Stack_18);
    CloseHandle(pvVar1);
  }
  if ((DStack_24 & 0xfffffffe) != DStack_24) {
    SetFileAttributesA(param_1,DStack_24 & 0xfffffffe);
  }
  iVar2 = FUN_1000c000(param_2,&uStack_28);
  if (iVar2 != 0x3e9) {
    FUN_100053a0(lpBuffer);
    return 0xa1;
  }
  pvVar1 = CreateFileA(param_1,0xc0000000,0,(LPSECURITY_ATTRIBUTES)0x0,3,0x80,(HANDLE)0x0);
  if (pvVar1 == (HANDLE)0xffffffff) {
    local_2c = 0xad;
  }
  else {
    BVar3 = ReadFile(pvVar1,lpBuffer,0x1000,&DStack_30,(LPOVERLAPPED)0x0);
    if (BVar3 == 0) {
LAB_100039f6:
      CloseHandle(pvVar1);
    }
    else {
      do {
        if (DStack_30 == 0) goto LAB_100039f6;
        FUN_1000c060(uStack_28,param_2,lDistanceToMove,lpBuffer,DStack_30);
        DVar4 = SetFilePointer(pvVar1,lDistanceToMove,(PLONG)0x0,0);
        if (DVar4 != lDistanceToMove) {
          local_2c = 0xab;
          CloseHandle(pvVar1);
          goto LAB_10003a07;
        }
        BVar3 = WriteFile(pvVar1,lpBuffer,DStack_30,&DStack_1c,(LPOVERLAPPED)0x0);
        if (BVar3 == 0) {
          local_2c = 0xac;
          goto LAB_100039f6;
        }
        lDistanceToMove = lDistanceToMove + DStack_30;
        BVar3 = ReadFile(pvVar1,lpBuffer,0x1000,&DStack_30,(LPOVERLAPPED)0x0);
      } while (BVar3 != 0);
      CloseHandle(pvVar1);
    }
  }
LAB_10003a07:
  FUN_100053a0(lpBuffer);
  FUN_100053a0(uStack_28);
  if (((short)BStack_20 != 0) &&
     (pvVar1 = CreateFileA(param_1,0xc0000000,0,(LPSECURITY_ATTRIBUTES)0x0,3,0x80,(HANDLE)0x0),
     pvVar1 != (HANDLE)0xffffffff)) {
    SetFileTime(pvVar1,&_Stack_8,&_Stack_10,&_Stack_18);
    CloseHandle(pvVar1);
  }
  SetFileAttributesA(param_1,DStack_24);
  return local_2c;
}



undefined4 FUN_10003dc0(void)

{
  return 0xbf16ef23;
}



undefined4 FUN_10003de0(void)

{
  return 0xc779bbe2;
}



undefined4 FUN_10003e00(char *param_1)

{
  char cVar1;
  char *pcVar2;
  char *pcVar3;
  uint uVar4;
  undefined2 uVar5;
  
  uVar5 = 0;
  pcVar2 = _strrchr(param_1,0x5c);
  uVar4 = 0xffffffff;
  pcVar3 = param_1;
  do {
    if (uVar4 == 0) break;
    uVar4 = uVar4 - 1;
    cVar1 = *pcVar3;
    pcVar3 = pcVar3 + 1;
  } while (cVar1 != '\0');
  pcVar3 = param_1 + (~uVar4 - 2);
  if (pcVar2 == pcVar3) {
    uVar5 = 1;
    do {
      uVar4 = 0xffffffff;
      pcVar3 = param_1;
      do {
        if (uVar4 == 0) break;
        uVar4 = uVar4 - 1;
        cVar1 = *pcVar3;
        pcVar3 = pcVar3 + 1;
      } while (cVar1 != '\0');
      param_1[~uVar4 - 2] = '\0';
      pcVar2 = _strrchr(param_1,0x5c);
      uVar4 = 0xffffffff;
      pcVar3 = param_1;
      do {
        if (uVar4 == 0) break;
        uVar4 = uVar4 - 1;
        cVar1 = *pcVar3;
        pcVar3 = pcVar3 + 1;
      } while (cVar1 != '\0');
      pcVar3 = param_1 + (~uVar4 - 2);
    } while (pcVar2 == pcVar3);
  }
  return CONCAT22((short)((uint)pcVar3 >> 0x10),uVar5);
}



undefined4 LTDLL_Initialise(int param_1)

{
                    // 0x3e70  3  LTDLL_Initialise
  if (param_1 == 1) {
    DAT_10012800 = 1;
    return 1;
  }
  return 0;
}



undefined4 LTDLL_Authenticate(void)

{
                    // 0x3e90  2  LTDLL_Authenticate
  return 1;
}



uint LTDLL_Unwrap(LPCSTR param_1,undefined4 param_2)

{
  uint uVar1;
  DWORD DVar2;
  undefined4 uVar3;
  int iVar4;
  
                    // 0x4030  4  LTDLL_Unwrap
  if (DAT_1000f2b8 != 0x68) {
    uVar1 = FUN_100040e0(DAT_1000f2b8,param_2);
    return uVar1 & 0xffff0000;
  }
  if (DAT_10012800 == 0) {
    uVar1 = FUN_100040e0(0xb5,param_2);
    return uVar1 & 0xffff0000;
  }
  if (param_1 == (LPCSTR)0x0) {
    uVar1 = FUN_100040e0(0xb3,param_2);
    return uVar1 & 0xffff0000;
  }
  DVar2 = GetFileAttributesA(param_1);
  if (DVar2 == 0xffffffff) {
    uVar1 = FUN_100040e0(0x9a,param_2);
    return uVar1 & 0xffff0000;
  }
  uVar3 = FUN_10003dc0();
  iVar4 = FUN_10003840(param_1,uVar3);
  FUN_100040e0(iVar4,param_2);
  return (uint)(iVar4 == 0x68);
}



void FUN_100040e0(undefined4 param_1,undefined4 *param_2)

{
  if (param_2 != (undefined4 *)0x0) {
    *param_2 = param_1;
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 _DllMain_12(HMODULE param_1,int param_2)

{
  short sVar1;
  char *pcVar2;
  int iVar3;
  CHAR local_104 [260];
  
                    // 0x40f0  1  _DllMain@12
  if ((param_2 != 0) && (param_2 == 1)) {
    _DAT_10012c08 = param_1;
    FUN_10001fe0();
    sVar1 = FUN_100028f0();
    if (sVar1 == 0) {
      FUN_100014a0();
      GetModuleFileNameA(param_1,local_104,0x104);
      pcVar2 = _strrchr(local_104,0x5c);
      if (pcVar2 != (char *)0x0) {
        *pcVar2 = '\0';
        sVar1 = FUN_100028f0();
        if (sVar1 == 0) {
          iVar3 = FUN_10003120(local_104);
          if (iVar3 != 0x65) {
            DAT_1000f2b8 = 0xa7;
          }
        }
      }
    }
  }
  return 1;
}



char FUN_10004180(int *param_1)

{
  int iVar1;
  
  if (*param_1 != 2) {
    return -0x62;
  }
  iVar1 = FUN_10003dc0();
  return (-(param_1[1] != iVar1) & 0x33U) + 0x6c;
}



uint FUN_10004ed0(char *param_1)

{
  char cVar1;
  DWORD DVar2;
  undefined4 *lpBuffer;
  int iVar3;
  uint uVar4;
  uint uVar5;
  undefined4 *puVar6;
  char *pcVar7;
  char *pcVar8;
  undefined4 *puVar9;
  CHAR local_1;
  
  if (param_1 == (char *)0x0) {
    return 0;
  }
  iVar3 = -1;
  pcVar7 = param_1;
  do {
    if (iVar3 == 0) break;
    iVar3 = iVar3 + -1;
    cVar1 = *pcVar7;
    pcVar7 = pcVar7 + 1;
  } while (cVar1 != '\0');
  if (iVar3 == -2) {
    return 0;
  }
  DVar2 = GetEnvironmentVariableA(&DAT_1000f368,&local_1,1);
  uVar4 = 0xffffffff;
  pcVar7 = param_1;
  do {
    if (uVar4 == 0) break;
    uVar4 = uVar4 - 1;
    cVar1 = *pcVar7;
    pcVar7 = pcVar7 + 1;
  } while (cVar1 != '\0');
  uVar4 = ~uVar4 + DVar2;
  if (uVar4 == 0) {
    return 0;
  }
  if (0x8000 < uVar4) {
    return 0;
  }
  lpBuffer = (undefined4 *)FUN_10005410(uVar4);
  if (lpBuffer == (undefined4 *)0x0) {
    return 0;
  }
  puVar6 = lpBuffer;
  for (uVar5 = uVar4 >> 2; uVar5 != 0; uVar5 = uVar5 - 1) {
    *puVar6 = 0;
    puVar6 = puVar6 + 1;
  }
  for (uVar5 = uVar4 & 3; uVar5 != 0; uVar5 = uVar5 - 1) {
    *(undefined *)puVar6 = 0;
    puVar6 = (undefined4 *)((int)puVar6 + 1);
  }
  GetEnvironmentVariableA(&DAT_1000f368,(LPSTR)lpBuffer,uVar4);
  if (DAT_10012c14 != (undefined4 *)0x0) {
    FUN_100053a0(DAT_10012c14);
  }
  uVar4 = DVar2 + 1;
  DAT_10012c14 = (undefined4 *)FUN_10005410(uVar4);
  if (DAT_10012c14 == (undefined4 *)0x0) {
    FUN_100053a0(lpBuffer);
    return 0;
  }
  puVar6 = DAT_10012c14;
  for (uVar5 = uVar4 >> 2; uVar5 != 0; uVar5 = uVar5 - 1) {
    *puVar6 = 0;
    puVar6 = puVar6 + 1;
  }
  for (uVar4 = uVar4 & 3; uVar4 != 0; uVar4 = uVar4 - 1) {
    *(undefined *)puVar6 = 0;
    puVar6 = (undefined4 *)((int)puVar6 + 1);
  }
  if (DVar2 != 0) {
    uVar4 = 0xffffffff;
    puVar6 = lpBuffer;
    do {
      puVar9 = puVar6;
      if (uVar4 == 0) break;
      uVar4 = uVar4 - 1;
      puVar9 = (undefined4 *)((int)puVar6 + 1);
      cVar1 = *(char *)puVar6;
      puVar6 = puVar9;
    } while (cVar1 != '\0');
    uVar4 = ~uVar4;
    puVar6 = (undefined4 *)((int)puVar9 - uVar4);
    puVar9 = DAT_10012c14;
    for (uVar5 = uVar4 >> 2; uVar5 != 0; uVar5 = uVar5 - 1) {
      *puVar9 = *puVar6;
      puVar6 = puVar6 + 1;
      puVar9 = puVar9 + 1;
    }
    for (uVar4 = uVar4 & 3; uVar4 != 0; uVar4 = uVar4 - 1) {
      *(undefined *)puVar9 = *(undefined *)puVar6;
      puVar6 = (undefined4 *)((int)puVar6 + 1);
      puVar9 = (undefined4 *)((int)puVar9 + 1);
    }
    uVar4 = 0xffffffff;
    pcVar7 = (char *)0x1000f364;
    do {
      pcVar8 = pcVar7;
      if (uVar4 == 0) break;
      uVar4 = uVar4 - 1;
      pcVar8 = pcVar7 + 1;
      cVar1 = *pcVar7;
      pcVar7 = pcVar8;
    } while (cVar1 != '\0');
    uVar4 = ~uVar4;
    iVar3 = -1;
    puVar6 = lpBuffer;
    do {
      puVar9 = puVar6;
      if (iVar3 == 0) break;
      iVar3 = iVar3 + -1;
      puVar9 = (undefined4 *)((int)puVar6 + 1);
      cVar1 = *(char *)puVar6;
      puVar6 = puVar9;
    } while (cVar1 != '\0');
    puVar6 = (undefined4 *)(pcVar8 + -uVar4);
    puVar9 = (undefined4 *)((int)puVar9 + -1);
    for (uVar5 = uVar4 >> 2; uVar5 != 0; uVar5 = uVar5 - 1) {
      *puVar9 = *puVar6;
      puVar6 = puVar6 + 1;
      puVar9 = puVar9 + 1;
    }
    for (uVar4 = uVar4 & 3; uVar4 != 0; uVar4 = uVar4 - 1) {
      *(undefined *)puVar9 = *(undefined *)puVar6;
      puVar6 = (undefined4 *)((int)puVar6 + 1);
      puVar9 = (undefined4 *)((int)puVar9 + 1);
    }
  }
  uVar4 = 0xffffffff;
  do {
    pcVar7 = param_1;
    if (uVar4 == 0) break;
    uVar4 = uVar4 - 1;
    pcVar7 = param_1 + 1;
    cVar1 = *param_1;
    param_1 = pcVar7;
  } while (cVar1 != '\0');
  uVar4 = ~uVar4;
  iVar3 = -1;
  puVar6 = lpBuffer;
  do {
    puVar9 = puVar6;
    if (iVar3 == 0) break;
    iVar3 = iVar3 + -1;
    puVar9 = (undefined4 *)((int)puVar6 + 1);
    cVar1 = *(char *)puVar6;
    puVar6 = puVar9;
  } while (cVar1 != '\0');
  puVar6 = (undefined4 *)(pcVar7 + -uVar4);
  puVar9 = (undefined4 *)((int)puVar9 + -1);
  for (uVar5 = uVar4 >> 2; uVar5 != 0; uVar5 = uVar5 - 1) {
    *puVar9 = *puVar6;
    puVar6 = puVar6 + 1;
    puVar9 = puVar9 + 1;
  }
  for (uVar4 = uVar4 & 3; uVar4 != 0; uVar4 = uVar4 - 1) {
    *(undefined *)puVar9 = *(undefined *)puVar6;
    puVar6 = (undefined4 *)((int)puVar6 + 1);
    puVar9 = (undefined4 *)((int)puVar9 + 1);
  }
  uVar4 = SetEnvironmentVariableA(&DAT_1000f368,(LPCSTR)lpBuffer);
  FUN_100053a0(lpBuffer);
  return uVar4 & 0xffff;
}



BOOL FUN_10005060(void)

{
  BOOL BVar1;
  
  BVar1 = 1;
  if (DAT_10012c14 != (LPCSTR)0x0) {
    BVar1 = SetEnvironmentVariableA(&DAT_1000f368,DAT_10012c14);
  }
  return BVar1;
}



// Library Function - Single Match
//  _strncpy
// 
// Libraries: Visual Studio 1998 Debug, Visual Studio 1998 Release

char * __cdecl _strncpy(char *_Dest,char *_Source,size_t _Count)

{
  uint uVar1;
  uint uVar2;
  char cVar3;
  uint uVar4;
  uint *puVar5;
  
  if (_Count == 0) {
    return _Dest;
  }
  puVar5 = (uint *)_Dest;
  if (((uint)_Source & 3) != 0) {
    while( true ) {
      cVar3 = *_Source;
      _Source = (char *)((int)_Source + 1);
      *(char *)puVar5 = cVar3;
      puVar5 = (uint *)((int)puVar5 + 1);
      _Count = _Count - 1;
      if (_Count == 0) {
        return _Dest;
      }
      if (cVar3 == '\0') break;
      if (((uint)_Source & 3) == 0) {
        uVar4 = _Count >> 2;
        goto joined_r0x100052de;
      }
    }
    do {
      if (((uint)puVar5 & 3) == 0) {
        uVar4 = _Count >> 2;
        cVar3 = '\0';
        if (uVar4 == 0) goto LAB_1000531b;
        goto LAB_10005389;
      }
      *(undefined *)puVar5 = 0;
      puVar5 = (uint *)((int)puVar5 + 1);
      _Count = _Count - 1;
    } while (_Count != 0);
    return _Dest;
  }
  uVar4 = _Count >> 2;
  if (uVar4 != 0) {
    do {
      uVar1 = *(uint *)_Source;
      uVar2 = *(uint *)_Source;
      _Source = (char *)((int)_Source + 4);
      if (((uVar1 ^ 0xffffffff ^ uVar1 + 0x7efefeff) & 0x81010100) != 0) {
        if ((char)uVar2 == '\0') {
          *puVar5 = 0;
joined_r0x10005385:
          while( true ) {
            uVar4 = uVar4 - 1;
            puVar5 = puVar5 + 1;
            if (uVar4 == 0) break;
LAB_10005389:
            *puVar5 = 0;
          }
          cVar3 = '\0';
          _Count = _Count & 3;
          if (_Count != 0) goto LAB_1000531b;
          return _Dest;
        }
        if ((char)(uVar2 >> 8) == '\0') {
          *puVar5 = uVar2 & 0xff;
          goto joined_r0x10005385;
        }
        if ((uVar2 & 0xff0000) == 0) {
          *puVar5 = uVar2 & 0xffff;
          goto joined_r0x10005385;
        }
        if ((uVar2 & 0xff000000) == 0) {
          *puVar5 = uVar2;
          goto joined_r0x10005385;
        }
      }
      *puVar5 = uVar2;
      puVar5 = puVar5 + 1;
      uVar4 = uVar4 - 1;
joined_r0x100052de:
    } while (uVar4 != 0);
    _Count = _Count & 3;
    if (_Count == 0) {
      return _Dest;
    }
  }
  do {
    cVar3 = *_Source;
    _Source = (char *)((int)_Source + 1);
    *(char *)puVar5 = cVar3;
    puVar5 = (uint *)((int)puVar5 + 1);
    if (cVar3 == '\0') {
      while (_Count = _Count - 1, _Count != 0) {
LAB_1000531b:
        *(char *)puVar5 = cVar3;
        puVar5 = (uint *)((int)puVar5 + 1);
      }
      return _Dest;
    }
    _Count = _Count - 1;
  } while (_Count != 0);
  return _Dest;
}



void FUN_100053a0(LPVOID param_1)

{
  LPVOID lpMem;
  int iVar1;
  undefined4 local_4;
  
  lpMem = param_1;
  if (param_1 != (LPVOID)0x0) {
    FUN_10006360(9);
    iVar1 = FUN_10006780(lpMem,&local_4,&param_1);
    if (iVar1 != 0) {
      FUN_100067e0(local_4,param_1,iVar1);
      FUN_100063e0(9);
      return;
    }
    FUN_100063e0(9);
    HeapFree(DAT_10015190,0,lpMem);
  }
  return;
}



void FUN_10005410(undefined4 param_1)

{
  FUN_10005430(param_1,DAT_10012cbc);
  return;
}



int FUN_10005430(uint param_1,int param_2)

{
  int iVar1;
  
  if (param_1 < 0xffffffe1) {
    if (param_1 == 0) {
      param_1 = 1;
    }
    do {
      if (param_1 < 0xffffffe1) {
        iVar1 = FUN_10005480(param_1);
      }
      else {
        iVar1 = 0;
      }
      if (iVar1 != 0) {
        return iVar1;
      }
      if (param_2 == 0) {
        return 0;
      }
      iVar1 = FUN_10006c00(param_1);
    } while (iVar1 != 0);
  }
  return 0;
}



LPVOID FUN_10005480(int param_1)

{
  LPVOID pvVar1;
  uint dwBytes;
  
  dwBytes = param_1 + 0xfU & 0xfffffff0;
  if (dwBytes <= DAT_1001147c) {
    FUN_10006360(9);
    pvVar1 = (LPVOID)FUN_10006840(param_1 + 0xfU >> 4);
    FUN_100063e0(9);
    if (pvVar1 != (LPVOID)0x0) {
      return pvVar1;
    }
  }
  pvVar1 = HeapAlloc(DAT_10015190,0,dwBytes);
  return pvVar1;
}



// Library Function - Single Match
//  _strrchr
// 
// Libraries: Visual Studio 1998 Debug, Visual Studio 1998 Release

char * __cdecl _strrchr(char *_Str,int _Ch)

{
  char cVar1;
  int iVar2;
  char *pcVar3;
  char *pcVar4;
  
  iVar2 = -1;
  do {
    pcVar4 = _Str;
    if (iVar2 == 0) break;
    iVar2 = iVar2 + -1;
    pcVar4 = _Str + 1;
    cVar1 = *_Str;
    _Str = pcVar4;
  } while (cVar1 != '\0');
  iVar2 = -(iVar2 + 1);
  pcVar4 = pcVar4 + -1;
  do {
    pcVar3 = pcVar4;
    if (iVar2 == 0) break;
    iVar2 = iVar2 + -1;
    pcVar3 = pcVar4 + -1;
    cVar1 = *pcVar4;
    pcVar4 = pcVar3;
  } while ((char)_Ch != cVar1);
  pcVar3 = pcVar3 + 1;
  if (*pcVar3 != (char)_Ch) {
    pcVar3 = (char *)0x0;
  }
  return pcVar3;
}



undefined4 FUN_10005510(undefined *param_1,undefined4 param_2)

{
  undefined4 uVar1;
  undefined *local_20;
  int local_1c;
  undefined *local_18;
  undefined4 local_14;
  
  local_18 = param_1;
  local_20 = param_1;
  local_14 = 0x42;
  local_1c = 0x7fffffff;
  uVar1 = FUN_10006d50(&local_20,param_2,&stack0x0000000c);
  local_1c = local_1c + -1;
  if (-1 < local_1c) {
    *local_20 = 0;
    return uVar1;
  }
  FUN_10006c20(0,&local_20);
  return uVar1;
}



int FUN_10005710(byte *param_1)

{
  byte bVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  byte *pbVar6;
  
  while( true ) {
    if (DAT_100117f4 < 2) {
      uVar2 = *(byte *)(DAT_100115e8 + (uint)*param_1 * 2) & 8;
    }
    else {
      uVar2 = FUN_10007a80(*param_1,8);
    }
    if (uVar2 == 0) break;
    param_1 = param_1 + 1;
  }
  uVar2 = (uint)*param_1;
  pbVar6 = param_1 + 1;
  if ((uVar2 == 0x2d) || (uVar4 = uVar2, uVar2 == 0x2b)) {
    uVar4 = (uint)*pbVar6;
    pbVar6 = param_1 + 2;
  }
  iVar5 = 0;
  while( true ) {
    if (DAT_100117f4 < 2) {
      uVar3 = *(byte *)(DAT_100115e8 + uVar4 * 2) & 4;
    }
    else {
      uVar3 = FUN_10007a80(uVar4,4);
    }
    if (uVar3 == 0) break;
    bVar1 = *pbVar6;
    pbVar6 = pbVar6 + 1;
    iVar5 = (uVar4 - 0x30) + iVar5 * 10;
    uVar4 = (uint)bVar1;
  }
  if (uVar2 == 0x2d) {
    iVar5 = -iVar5;
  }
  return iVar5;
}



void FUN_100057b0(undefined4 param_1)

{
  FUN_10005710(param_1);
  return;
}



// Library Function - Single Match
//  _strchr
// 
// Libraries: Visual Studio 1998 Debug, Visual Studio 1998 Release

char * __cdecl _strchr(char *_Str,int _Val)

{
  uint uVar1;
  char cVar2;
  uint uVar3;
  uint uVar4;
  uint *puVar5;
  
  uVar1 = (uint)_Str & 3;
  while (uVar1 != 0) {
    if (*_Str == (char)_Val) {
      return (char *)(uint *)_Str;
    }
    if (*_Str == '\0') {
      return (char *)0x0;
    }
    uVar1 = (uint)(uint *)((int)_Str + 1) & 3;
    _Str = (char *)(uint *)((int)_Str + 1);
  }
  while( true ) {
    while( true ) {
      uVar1 = *(uint *)_Str;
      uVar4 = uVar1 ^ CONCAT22(CONCAT11((char)_Val,(char)_Val),CONCAT11((char)_Val,(char)_Val));
      uVar3 = uVar1 ^ 0xffffffff ^ uVar1 + 0x7efefeff;
      puVar5 = (uint *)((int)_Str + 4);
      if (((uVar4 ^ 0xffffffff ^ uVar4 + 0x7efefeff) & 0x81010100) != 0) break;
      _Str = (char *)puVar5;
      if ((uVar3 & 0x81010100) != 0) {
        if ((uVar3 & 0x1010100) != 0) {
          return (char *)0x0;
        }
        if ((uVar1 + 0x7efefeff & 0x80000000) == 0) {
          return (char *)0x0;
        }
      }
    }
    uVar1 = *(uint *)_Str;
    if ((char)uVar1 == (char)_Val) {
      return (char *)(uint *)_Str;
    }
    if ((char)uVar1 == '\0') {
      return (char *)0x0;
    }
    cVar2 = (char)(uVar1 >> 8);
    if (cVar2 == (char)_Val) {
      return (char *)((int)_Str + 1);
    }
    if (cVar2 == '\0') break;
    cVar2 = (char)(uVar1 >> 0x10);
    if (cVar2 == (char)_Val) {
      return (char *)((int)_Str + 2);
    }
    if (cVar2 == '\0') {
      return (char *)0x0;
    }
    cVar2 = (char)(uVar1 >> 0x18);
    if (cVar2 == (char)_Val) {
      return (char *)((int)_Str + 3);
    }
    _Str = (char *)puVar5;
    if (cVar2 == '\0') {
      return (char *)0x0;
    }
  }
  return (char *)0x0;
}



int FUN_10005890(int param_1)

{
  bool bVar1;
  
  if (DAT_10012cd8 == 0) {
    if ((0x40 < param_1) && (param_1 < 0x5b)) {
      return param_1 + 0x20;
    }
  }
  else {
    InterlockedIncrement((LONG *)&DAT_1001518c);
    bVar1 = DAT_10015188 != 0;
    if (bVar1) {
      InterlockedDecrement((LONG *)&DAT_1001518c);
      FUN_10006360(0x13);
    }
    param_1 = FUN_10005920(param_1);
    if (bVar1) {
      FUN_100063e0(0x13);
      return param_1;
    }
    InterlockedDecrement((LONG *)&DAT_1001518c);
  }
  return param_1;
}



uint FUN_10005920(uint param_1)

{
  uint uVar1;
  uint uVar2;
  undefined4 uVar3;
  int iVar4;
  uint local_8 [2];
  
  uVar1 = param_1;
  if (DAT_10012cd8 == 0) {
    if ((0x40 < (int)param_1) && ((int)param_1 < 0x5b)) {
      return param_1 + 0x20;
    }
  }
  else {
    if ((int)param_1 < 0x100) {
      if (DAT_100117f4 < 2) {
        uVar2 = *(byte *)(DAT_100115e8 + param_1 * 2) & 1;
      }
      else {
        uVar2 = FUN_10007a80(param_1,1);
      }
      if (uVar2 == 0) {
        return uVar1;
      }
    }
    uVar2 = param_1;
    if ((*(byte *)(DAT_100115e8 + 1 + ((int)uVar1 >> 8 & 0xffU) * 2) & 0x80) == 0) {
      param_1._0_2_ = (ushort)(byte)uVar1;
      uVar3 = 1;
    }
    else {
      param_1._0_2_ = CONCAT11((byte)uVar1,(char)(uVar1 >> 8));
      param_1._0_3_ = (uint3)(ushort)param_1;
      uVar3 = 2;
    }
    iVar4 = FUN_10007820(DAT_10012cd8,0x100,&param_1,uVar3,local_8,3,0,1);
    if (iVar4 == 0) {
      return uVar1;
    }
    if (iVar4 == 1) {
      return local_8[0] & 0xff;
    }
    param_1 = (local_8[0] >> 8 & 0xff) << 8 | local_8[0] & 0xff;
  }
  return param_1;
}



// Library Function - Single Match
//  _strncmp
// 
// Libraries: Visual Studio 1998 Debug, Visual Studio 1998 Release

int __cdecl _strncmp(char *_Str1,char *_Str2,size_t _MaxCount)

{
  char cVar1;
  char cVar2;
  byte bVar3;
  size_t sVar4;
  int iVar5;
  uint uVar6;
  char *pcVar7;
  char *pcVar8;
  bool bVar9;
  
  sVar4 = _MaxCount;
  pcVar7 = _Str1;
  if (_MaxCount != 0) {
    do {
      if (sVar4 == 0) break;
      sVar4 = sVar4 - 1;
      cVar1 = *pcVar7;
      pcVar7 = pcVar7 + 1;
    } while (cVar1 != '\0');
    iVar5 = _MaxCount - sVar4;
    do {
      pcVar7 = _Str2;
      pcVar8 = _Str1;
      if (iVar5 == 0) break;
      iVar5 = iVar5 + -1;
      pcVar8 = _Str1 + 1;
      pcVar7 = _Str2 + 1;
      cVar1 = *_Str2;
      cVar2 = *_Str1;
      _Str2 = pcVar7;
      _Str1 = pcVar8;
    } while (cVar1 == cVar2);
    bVar3 = pcVar7[-1];
    uVar6 = 0;
    bVar9 = bVar3 == pcVar8[-1];
    if (bVar3 < (byte)pcVar8[-1] || bVar9) {
      if (bVar9) {
        return 0;
      }
      uVar6 = 0xfffffffe;
    }
    _MaxCount = ~uVar6;
  }
  return _MaxCount;
}



// WARNING: Unable to track spacebase fully for stack

void FUN_10005ef0(void)

{
  uint in_EAX;
  undefined *puVar1;
  undefined4 unaff_retaddr;
  
  puVar1 = &stack0x00000004;
  if (0xfff < in_EAX) {
    do {
      puVar1 = puVar1 + -0x1000;
      in_EAX = in_EAX - 0x1000;
    } while (0xfff < in_EAX);
  }
  *(undefined4 *)(puVar1 + (-4 - in_EAX)) = unaff_retaddr;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_10006020(undefined4 param_1_00,int param_1)

{
  int iVar1;
  
  if (param_1 != 1) {
    if (param_1 != 0) {
      if (param_1 == 3) {
        FUN_10008db0(0);
      }
      return 1;
    }
    if (0 < DAT_10012c44) {
      DAT_10012c44 = DAT_10012c44 + -1;
      if (DAT_10012f54 == 0) {
        FUN_10008b70();
      }
      FUN_10008ac0();
      FUN_10008ce0();
      FUN_10006270();
      return 1;
    }
    return 0;
  }
  DAT_10012f1c = GetVersion();
  iVar1 = FUN_10006230();
  if (iVar1 == 0) {
    return 0;
  }
  _DAT_10012f28 = DAT_10012f1c >> 8 & 0xff;
  _DAT_10012f24 = DAT_10012f1c & 0xff;
  _DAT_10012f20 = _DAT_10012f24 * 0x100 + _DAT_10012f28;
  DAT_10012f1c = DAT_10012f1c >> 0x10;
  iVar1 = FUN_10008c80();
  if (iVar1 == 0) {
    FUN_10006270();
    return 0;
  }
  DAT_10015194 = GetCommandLineA();
  DAT_10012c48 = FUN_10009200();
  if ((DAT_10015194 != (LPSTR)0x0) && (DAT_10012c48 != 0)) {
    FUN_100088b0();
    FUN_100080b0();
    FUN_10008f50();
    FUN_10008e60();
    FUN_10008b20();
    DAT_10012c44 = DAT_10012c44 + 1;
    return 1;
  }
  FUN_10008ce0();
  FUN_10006270();
  return 0;
}



int entry(undefined4 param_1,int param_2,undefined4 param_3)

{
  int iVar1;
  int iVar2;
  
  iVar1 = 1;
  if ((param_2 == 0) && (DAT_10012c44 == 0)) {
    return 0;
  }
  if ((param_2 != 1) && (param_2 != 2)) {
LAB_1000619e:
    iVar1 = _DllMain_12(param_1,param_2,param_3);
    if ((param_2 == 1) && (iVar1 == 0)) {
      FUN_10006020(param_1,0,param_3);
    }
    if ((param_2 == 0) || (param_2 == 3)) {
      iVar2 = FUN_10006020(param_1,param_2,param_3);
      if (iVar2 == 0) {
        iVar1 = 0;
      }
      if ((iVar1 != 0) && (DAT_10015198 != (code *)0x0)) {
        iVar1 = (*DAT_10015198)(param_1,param_2,param_3);
      }
    }
    return iVar1;
  }
  if (DAT_10015198 != (code *)0x0) {
    iVar1 = (*DAT_10015198)(param_1,param_2,param_3);
  }
  if (iVar1 != 0) {
    iVar1 = FUN_10006020(param_1,param_2,param_3);
    if (iVar1 != 0) goto LAB_1000619e;
  }
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __amsg_exit
// 
// Library: Visual Studio 1998 Release

void __cdecl __amsg_exit(int param_1)

{
  if ((DAT_10012c50 == 1) || ((DAT_10012c50 == 0 && (_DAT_10012c54 == 1)))) {
    FUN_10009360();
  }
  FUN_100093a0(param_1);
  (*DAT_1000f390)(0xff);
  return;
}



undefined4 FUN_10006230(void)

{
  int iVar1;
  
  DAT_10015190 = HeapCreate(0,0x1000,0);
  if (DAT_10015190 == (HANDLE)0x0) {
    return 0;
  }
  iVar1 = FUN_100064e0();
  if (iVar1 == 0) {
    HeapDestroy(DAT_10015190);
    return 0;
  }
  return 1;
}



void FUN_10006270(void)

{
  undefined4 *puVar1;
  
  puVar1 = &DAT_1000f458;
  do {
    if ((LPVOID)puVar1[4] != (LPVOID)0x0) {
      VirtualFree((LPVOID)puVar1[4],0,0x8000);
    }
    puVar1 = (undefined4 *)*puVar1;
  } while (puVar1 != &DAT_1000f458);
  HeapDestroy(DAT_10015190);
  return;
}



void FUN_100062b0(void)

{
  InitializeCriticalSection(DAT_1000f3dc);
  InitializeCriticalSection(DAT_1000f3cc);
  InitializeCriticalSection(DAT_1000f3bc);
  InitializeCriticalSection(DAT_1000f39c);
  return;
}



void FUN_100062e0(void)

{
  LPCRITICAL_SECTION *pp_Var1;
  
  pp_Var1 = (LPCRITICAL_SECTION *)&DAT_1000f398;
  do {
    if ((((*pp_Var1 != (LPCRITICAL_SECTION)0x0) && (pp_Var1 != &DAT_1000f3dc)) &&
        (pp_Var1 != &DAT_1000f3cc)) && ((pp_Var1 != &DAT_1000f3bc && (pp_Var1 != &DAT_1000f39c)))) {
      DeleteCriticalSection(*pp_Var1);
      FUN_100053a0(*pp_Var1);
    }
    pp_Var1 = pp_Var1 + 1;
  } while ((int)pp_Var1 < 0x1000f458);
  DeleteCriticalSection(DAT_1000f3bc);
  DeleteCriticalSection(DAT_1000f3cc);
  DeleteCriticalSection(DAT_1000f3dc);
  DeleteCriticalSection(DAT_1000f39c);
  return;
}



void FUN_10006360(int param_1)

{
  LPCRITICAL_SECTION lpCriticalSection;
  
  if ((&DAT_1000f398)[param_1] == 0) {
    lpCriticalSection = (LPCRITICAL_SECTION)FUN_10005410(0x18);
    if (lpCriticalSection == (LPCRITICAL_SECTION)0x0) {
      __amsg_exit(0x11);
    }
    FUN_10006360(0x11);
    if ((&DAT_1000f398)[param_1] == 0) {
      InitializeCriticalSection(lpCriticalSection);
      (&DAT_1000f398)[param_1] = lpCriticalSection;
    }
    else {
      FUN_100053a0();
    }
    FUN_100063e0(0x11);
  }
  EnterCriticalSection((LPCRITICAL_SECTION)(&DAT_1000f398)[param_1]);
  return;
}



void FUN_100063e0(int param_1)

{
  LeaveCriticalSection((LPCRITICAL_SECTION)(&DAT_1000f398)[param_1]);
  return;
}



void FUN_10006400(uint param_1)

{
  if ((0x10011b17 < param_1) && (param_1 < 0x10011d79)) {
    FUN_10006360(((int)(param_1 + 0xeffee4e8) >> 5) + 0x1c);
    return;
  }
  EnterCriticalSection((LPCRITICAL_SECTION)(param_1 + 0x20));
  return;
}



void FUN_10006440(int param_1,int param_2)

{
  if (param_1 < 0x14) {
    FUN_10006360(param_1 + 0x1c);
    return;
  }
  EnterCriticalSection((LPCRITICAL_SECTION)(param_2 + 0x20));
  return;
}



void FUN_10006470(uint param_1)

{
  if ((0x10011b17 < param_1) && (param_1 < 0x10011d79)) {
    FUN_100063e0(((int)(param_1 + 0xeffee4e8) >> 5) + 0x1c);
    return;
  }
  LeaveCriticalSection((LPCRITICAL_SECTION)(param_1 + 0x20));
  return;
}



void FUN_100064b0(int param_1,int param_2)

{
  if (param_1 < 0x14) {
    FUN_100063e0(param_1 + 0x1c);
    return;
  }
  LeaveCriticalSection((LPCRITICAL_SECTION)(param_2 + 0x20));
  return;
}



undefined4 * FUN_100064e0(void)

{
  bool bVar1;
  undefined4 *lpAddress;
  LPVOID pvVar2;
  int iVar3;
  int *piVar4;
  undefined4 *lpMem;
  undefined4 *puVar5;
  
  if (DAT_1000f468 == -1) {
    lpMem = &DAT_1000f458;
  }
  else {
    lpMem = (undefined4 *)HeapAlloc(DAT_10015190,0,0x2020);
    if (lpMem == (undefined4 *)0x0) {
      return (undefined4 *)0x0;
    }
  }
  lpAddress = (undefined4 *)VirtualAlloc((LPVOID)0x0,0x400000,0x2000,4);
  if (lpAddress != (undefined4 *)0x0) {
    pvVar2 = VirtualAlloc(lpAddress,0x10000,0x1000,4);
    if (pvVar2 != (LPVOID)0x0) {
      if ((undefined4 **)lpMem == &DAT_1000f458) {
        if (DAT_1000f458 == (undefined4 *)0x0) {
          DAT_1000f458 = &DAT_1000f458;
        }
        if (DAT_1000f45c == (undefined4 *)0x0) {
          DAT_1000f45c = &DAT_1000f458;
        }
      }
      else {
        *lpMem = &DAT_1000f458;
        lpMem[1] = DAT_1000f45c;
        DAT_1000f45c = lpMem;
        *(undefined4 **)lpMem[1] = lpMem;
      }
      lpMem[5] = lpAddress + 0x100000;
      lpMem[4] = lpAddress;
      lpMem[2] = lpMem + 6;
      lpMem[3] = lpMem + 0x26;
      iVar3 = 0;
      piVar4 = lpMem + 6;
      do {
        bVar1 = 0xf < iVar3;
        iVar3 = iVar3 + 1;
        *piVar4 = (bVar1 - 1 & 0xf1) - 1;
        piVar4[1] = 0xf1;
        piVar4 = piVar4 + 2;
      } while (iVar3 < 0x400);
      puVar5 = lpAddress;
      for (iVar3 = 0x4000; iVar3 != 0; iVar3 = iVar3 + -1) {
        *puVar5 = 0;
        puVar5 = puVar5 + 1;
      }
      if (lpAddress < (undefined4 *)(lpMem[4] + 0x10000)) {
        do {
          lpAddress[1] = 0xf0;
          *lpAddress = lpAddress + 2;
          *(undefined *)(lpAddress + 0x3e) = 0xff;
          lpAddress = lpAddress + 0x400;
        } while (lpAddress < (undefined4 *)(lpMem[4] + 0x10000));
      }
      return lpMem;
    }
    VirtualFree(lpAddress,0,0x8000);
  }
  if ((undefined4 **)lpMem != &DAT_1000f458) {
    HeapFree(DAT_10015190,0,lpMem);
  }
  return (undefined4 *)0x0;
}



void FUN_10006650(int *param_1)

{
  VirtualFree((LPVOID)param_1[4],0,0x8000);
  if (DAT_10011478 == param_1) {
    DAT_10011478 = (int *)param_1[1];
  }
  if (param_1 != &DAT_1000f458) {
    *(int *)param_1[1] = *param_1;
    *(int *)(*param_1 + 4) = param_1[1];
    HeapFree(DAT_10015190,0,param_1);
    return;
  }
  DAT_1000f468 = 0xffffffff;
  return;
}



void FUN_100066b0(int param_1)

{
  BOOL BVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  
  iVar5 = DAT_1000f45c;
  do {
    iVar3 = iVar5;
    if (*(int *)(iVar5 + 0x10) != -1) {
      iVar4 = 0;
      piVar2 = (int *)(iVar5 + 0x2010);
      iVar3 = 0x3ff000;
      do {
        if (*piVar2 == 0xf0) {
          BVar1 = VirtualFree((LPVOID)(*(int *)(iVar5 + 0x10) + iVar3),0x1000,0x4000);
          if (BVar1 != 0) {
            *piVar2 = -1;
            DAT_10012cb8 = DAT_10012cb8 + -1;
            if ((*(int **)(iVar5 + 0xc) == (int *)0x0) || (piVar2 < *(int **)(iVar5 + 0xc))) {
              *(int **)(iVar5 + 0xc) = piVar2;
            }
            iVar4 = iVar4 + 1;
            param_1 = param_1 + -1;
            if (param_1 == 0) break;
          }
        }
        iVar3 = iVar3 + -0x1000;
        piVar2 = piVar2 + -2;
      } while (-1 < iVar3);
      iVar3 = *(int *)(iVar5 + 4);
      if ((iVar4 != 0) && (*(int *)(iVar5 + 0x18) == -1)) {
        iVar4 = 1;
        piVar2 = (int *)(iVar5 + 0x20);
        do {
          if (*piVar2 != -1) break;
          iVar4 = iVar4 + 1;
          piVar2 = piVar2 + 2;
        } while (iVar4 < 0x400);
        if (iVar4 == 0x400) {
          FUN_10006650(iVar5);
        }
      }
    }
    if ((iVar3 == DAT_1000f45c) || (iVar5 = iVar3, param_1 < 1)) {
      return;
    }
  } while( true );
}



int FUN_10006780(uint param_1,undefined4 *param_2,uint *param_3)

{
  undefined4 *puVar1;
  uint uVar2;
  
  puVar1 = &DAT_1000f458;
  while ((param_1 < (uint)puVar1[4] || param_1 == puVar1[4] || ((uint)puVar1[5] <= param_1))) {
    puVar1 = (undefined4 *)*puVar1;
    if (puVar1 == &DAT_1000f458) {
      return 0;
    }
  }
  if ((param_1 & 0xf) != 0) {
    return 0;
  }
  if ((param_1 & 0xfff) < 0x100) {
    return 0;
  }
  *param_2 = puVar1;
  uVar2 = param_1 & 0xfffff000;
  *param_3 = uVar2;
  return ((int)((param_1 - uVar2) + -0x100) >> 4) + 8 + uVar2;
}



void FUN_100067e0(int param_1,int param_2,byte *param_3)

{
  int *piVar1;
  int iVar2;
  
  iVar2 = param_2 - *(int *)(param_1 + 0x10) >> 0xc;
  piVar1 = (int *)(param_1 + 0x18 + iVar2 * 8);
  *piVar1 = *(int *)(param_1 + 0x18 + iVar2 * 8) + (uint)*param_3;
  *param_3 = 0;
  piVar1[1] = 0xf1;
  if ((*piVar1 == 0xf0) && (DAT_10012cb8 = DAT_10012cb8 + 1, DAT_10012cb8 == 0x20)) {
    FUN_100066b0(0x10);
  }
  return;
}



int * FUN_10006840(uint param_1)

{
  int *piVar1;
  int *piVar2;
  int *piVar3;
  undefined4 *puVar4;
  int iVar5;
  int iVar6;
  int *piVar7;
  bool bVar8;
  int *local_4;
  
  local_4 = DAT_10011478;
  do {
    if (local_4[4] != -1) {
      piVar7 = (int *)local_4[2];
      iVar5 = ((int)piVar7 + (-0x18 - (int)local_4) >> 3) * 0x1000 + local_4[4];
      for (; piVar7 < local_4 + 0x806; piVar7 = piVar7 + 2) {
        if (((int)param_1 <= *piVar7) && (param_1 <= (uint)piVar7[1] && piVar7[1] != param_1)) {
          piVar1 = (int *)FUN_10006a80(iVar5,*piVar7,param_1);
          if (piVar1 != (int *)0x0) {
            DAT_10011478 = local_4;
            *piVar7 = *piVar7 - param_1;
            local_4[2] = (int)piVar7;
            return piVar1;
          }
          piVar7[1] = param_1;
        }
        iVar5 = iVar5 + 0x1000;
      }
      piVar1 = (int *)local_4[2];
      iVar5 = local_4[4];
      for (piVar7 = local_4 + 6; piVar7 < piVar1; piVar7 = piVar7 + 2) {
        if (((int)param_1 <= *piVar7) && (param_1 <= (uint)piVar7[1] && piVar7[1] != param_1)) {
          piVar2 = (int *)FUN_10006a80(iVar5,*piVar7,param_1);
          if (piVar2 != (int *)0x0) {
            DAT_10011478 = local_4;
            *piVar7 = *piVar7 - param_1;
            local_4[2] = (int)piVar7;
            return piVar2;
          }
          piVar7[1] = param_1;
        }
        iVar5 = iVar5 + 0x1000;
      }
    }
    local_4 = (int *)*local_4;
  } while (local_4 != DAT_10011478);
  puVar4 = &DAT_1000f458;
  while ((puVar4[4] == -1 || (puVar4[3] == 0))) {
    puVar4 = (undefined4 *)*puVar4;
    if (puVar4 == &DAT_1000f458) {
      iVar5 = FUN_100064e0();
      if (iVar5 == 0) {
        return (int *)0x0;
      }
      piVar7 = *(int **)(iVar5 + 0x10);
      *(char *)(piVar7 + 2) = (char)param_1;
      DAT_10011478 = (int *)iVar5;
      *piVar7 = (int)piVar7 + param_1 + 8;
      piVar7[1] = 0xf0 - param_1;
      *(uint *)(iVar5 + 0x18) = *(int *)(iVar5 + 0x18) - (param_1 & 0xff);
      return piVar7 + 0x40;
    }
  }
  piVar7 = (int *)puVar4[3];
  iVar5 = *piVar7;
  piVar2 = (int *)(((int)piVar7 + (-0x18 - (int)puVar4) >> 3) * 0x1000 + puVar4[4]);
  piVar1 = piVar7;
  for (iVar6 = 0; (iVar5 == -1 && (iVar6 < 0x10)); iVar6 = iVar6 + 1) {
    iVar5 = piVar1[2];
    piVar1 = piVar1 + 2;
  }
  piVar1 = (int *)VirtualAlloc(piVar2,iVar6 << 0xc,0x1000,4);
  if (piVar1 != piVar2) {
    return (int *)0x0;
  }
  piVar1 = piVar7;
  if (0 < iVar6) {
    piVar3 = piVar2 + 1;
    do {
      *piVar3 = 0xf0;
      piVar3[-1] = (int)(piVar3 + 1);
      *(undefined *)(piVar3 + 0x3d) = 0xff;
      *piVar1 = 0xf0;
      piVar1[1] = 0xf1;
      piVar3 = piVar3 + 0x400;
      piVar1 = piVar1 + 2;
      iVar6 = iVar6 + -1;
    } while (iVar6 != 0);
  }
  piVar3 = puVar4 + 0x806;
  bVar8 = piVar1 < piVar3;
  if (bVar8) {
    do {
      if (*piVar1 == -1) break;
      piVar1 = piVar1 + 2;
    } while (piVar1 < piVar3);
    bVar8 = piVar1 < piVar3;
  }
  DAT_10011478 = puVar4;
  puVar4[3] = -(uint)bVar8 & (uint)piVar1;
  *(char *)(piVar2 + 2) = (char)param_1;
  puVar4[2] = piVar7;
  *piVar7 = *piVar7 - param_1;
  piVar2[1] = piVar2[1] - param_1;
  *piVar2 = (int)piVar2 + param_1 + 8;
  return piVar2 + 0x40;
}



int FUN_10006a80(int **param_1,int *param_2,int *param_3)

{
  char cVar1;
  int **ppiVar2;
  int **ppiVar3;
  int **ppiVar4;
  int *piVar5;
  int **ppiVar6;
  
  ppiVar2 = (int **)*param_1;
  if (param_3 <= param_1[1]) {
    *(char *)ppiVar2 = (char)param_3;
    if ((int **)((int)ppiVar2 + (int)param_3) < param_1 + 0x3e) {
      *param_1 = (int *)((int)*param_1 + (int)param_3);
      param_1[1] = (int *)((int)param_1[1] - (int)param_3);
    }
    else {
      param_1[1] = (int *)0x0;
      *param_1 = (int *)(param_1 + 2);
    }
    return (int)(ppiVar2 + 2) * 0x10 + (int)param_1 * -0xf;
  }
  ppiVar3 = (int **)((int)param_1[1] + (int)ppiVar2);
  ppiVar6 = ppiVar2;
  if (*(char *)ppiVar3 != '\0') {
    ppiVar6 = ppiVar3;
  }
  if ((int **)((int)ppiVar6 + (int)param_3) < param_1 + 0x3e) {
    do {
      if (*(byte *)ppiVar6 == 0) {
        ppiVar3 = (int **)((int)ppiVar6 + 1);
        piVar5 = (int *)0x1;
        cVar1 = *(char *)((int)ppiVar6 + 1);
        while (cVar1 == '\0') {
          ppiVar3 = (int **)((int)ppiVar3 + 1);
          piVar5 = (int *)((int)piVar5 + 1);
          cVar1 = *(char *)ppiVar3;
        }
        if (param_3 <= piVar5) {
          if (param_1 + 0x3e <= (int **)((int)ppiVar6 + (int)param_3)) {
            *param_1 = (int *)(param_1 + 2);
            goto LAB_10006bcf;
          }
          *param_1 = (int *)(int **)((int)ppiVar6 + (int)param_3);
          param_1[1] = (int *)((int)piVar5 - (int)param_3);
          goto LAB_10006bd6;
        }
        if (ppiVar6 == ppiVar2) {
          param_1[1] = piVar5;
        }
        else {
          param_2 = (int *)((int)param_2 - (int)piVar5);
          if (param_2 < param_3) {
            return 0;
          }
        }
      }
      else {
        ppiVar3 = (int **)((int)ppiVar6 + (uint)*(byte *)ppiVar6);
      }
      ppiVar6 = ppiVar3;
    } while ((int **)((int)ppiVar3 + (int)param_3) < param_1 + 0x3e);
  }
  ppiVar3 = param_1 + 2;
  ppiVar6 = ppiVar3;
  if (ppiVar3 < ppiVar2) {
    while ((int **)((int)ppiVar6 + (int)param_3) < param_1 + 0x3e) {
      if (*(byte *)ppiVar6 == 0) {
        ppiVar4 = (int **)((int)ppiVar6 + 1);
        piVar5 = (int *)0x1;
        cVar1 = *(char *)((int)ppiVar6 + 1);
        while (cVar1 == '\0') {
          ppiVar4 = (int **)((int)ppiVar4 + 1);
          piVar5 = (int *)((int)piVar5 + 1);
          cVar1 = *(char *)ppiVar4;
        }
        if (param_3 <= piVar5) {
          if ((int **)((int)ppiVar6 + (int)param_3) < param_1 + 0x3e) {
            *param_1 = (int *)(int **)((int)ppiVar6 + (int)param_3);
            param_1[1] = (int *)((int)piVar5 - (int)param_3);
          }
          else {
            *param_1 = (int *)ppiVar3;
LAB_10006bcf:
            param_1[1] = (int *)0x0;
          }
LAB_10006bd6:
          *(char *)ppiVar6 = (char)param_3;
          return (int)(ppiVar6 + 2) * 0x10 + (int)param_1 * -0xf;
        }
        param_2 = (int *)((int)param_2 - (int)piVar5);
        if (param_2 < param_3) {
          return 0;
        }
      }
      else {
        ppiVar4 = (int **)((int)ppiVar6 + (uint)*(byte *)ppiVar6);
      }
      ppiVar6 = ppiVar4;
      if (ppiVar2 <= ppiVar4) {
        return 0;
      }
    }
  }
  return 0;
}



undefined4 FUN_10006c00(undefined4 param_1)

{
  int iVar1;
  
  if (DAT_10012cc0 != (code *)0x0) {
    iVar1 = (*DAT_10012cc0)(param_1);
    if (iVar1 != 0) {
      return 1;
    }
  }
  return 0;
}



uint FUN_10006c20(uint param_1,int *param_2)

{
  uint uVar1;
  uint uVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  
  piVar3 = param_2;
  uVar1 = param_2[3];
  uVar2 = param_2[4];
  if (((uVar1 & 0x82) == 0) || ((uVar1 & 0x40) != 0)) {
LAB_10006d43:
    param_2[3] = uVar1 | 0x20;
    return 0xffffffff;
  }
  iVar6 = 0;
  if ((uVar1 & 1) != 0) {
    param_2[1] = 0;
    if ((uVar1 & 0x10) == 0) goto LAB_10006d43;
    *param_2 = param_2[2];
    param_2[3] = uVar1 & 0xfffffffe;
  }
  uVar1 = param_2[3];
  param_2[1] = 0;
  param_2[3] = uVar1 & 0xffffffef | 2;
  if ((uVar1 & 0x10c) == 0) {
    if ((param_2 == (int *)0x10011b38) || (param_2 == (int *)0x10011b58)) {
      iVar4 = FUN_100096c0(uVar2);
      if (iVar4 != 0) goto LAB_10006c93;
    }
    FUN_10009660(piVar3);
  }
LAB_10006c93:
  if ((piVar3[3] & 0x108U) == 0) {
    iVar4 = 1;
    iVar6 = FUN_10008170(uVar2,&param_1,1);
  }
  else {
    iVar5 = piVar3[2];
    iVar4 = *piVar3 - iVar5;
    *piVar3 = iVar5 + 1;
    piVar3[1] = piVar3[6] + -1;
    if (iVar4 < 1) {
      if (uVar2 == 0xffffffff) {
        iVar5 = 0x10011a60;
      }
      else {
        iVar5 = (&DAT_10015080)[(int)uVar2 >> 5] + (uVar2 & 0x1f) * 0x24;
      }
      if ((*(byte *)(iVar5 + 4) & 0x20) != 0) {
        FUN_10008620(uVar2,0,2);
      }
      *(undefined *)piVar3[2] = (undefined)param_1;
    }
    else {
      iVar6 = FUN_10008170(uVar2,iVar5,iVar4);
      *(undefined *)piVar3[2] = (undefined)param_1;
    }
  }
  if (iVar6 != iVar4) {
    piVar3[3] = piVar3[3] | 0x20;
    return 0xffffffff;
  }
  return param_1 & 0xff;
}



int FUN_10006d50(undefined4 param_1,char *param_2,undefined4 *param_3)

{
  short sVar1;
  uint uVar2;
  undefined4 uVar3;
  int *piVar4;
  short *psVar5;
  int iVar6;
  char cVar7;
  undefined *puVar8;
  undefined *puVar9;
  int iVar10;
  ulonglong uVar11;
  longlong lVar12;
  uint local_24c;
  short *local_248;
  int local_244;
  int local_240;
  undefined local_23a;
  char local_239;
  int local_238;
  int local_234;
  int local_230;
  int local_22c;
  int local_228;
  int local_224;
  int local_220;
  undefined4 local_21c;
  undefined4 local_218;
  undefined local_214 [4];
  undefined4 local_210;
  undefined4 local_20c;
  int local_204;
  undefined local_200 [511];
  undefined local_1;
  
  local_220 = 0;
  puVar9 = (undefined *)0x0;
  local_240 = 0;
  cVar7 = *param_2;
  param_2 = param_2 + 1;
  local_21c = CONCAT31(local_21c._1_3_,cVar7);
  do {
    if ((cVar7 == '\0') || (local_240 < 0)) {
      return local_240;
    }
    if ((cVar7 < ' ') || ('x' < cVar7)) {
      uVar2 = 0;
    }
    else {
      uVar2 = *(byte *)((int)&GetStringTypeA_exref + (int)cVar7) & 0xf;
    }
    local_220 = (int)(char)(&DAT_1000d150)[uVar2 * 8 + local_220] >> 4;
    switch(local_220) {
    case 0:
switchD_10006dcd_caseD_0:
      local_230 = 0;
      if ((*(byte *)(DAT_100115e8 + 1 + (local_21c & 0xff) * 2) & 0x80) != 0) {
        FUN_100076e0((int)cVar7,param_1,&local_240);
        cVar7 = *param_2;
        param_2 = param_2 + 1;
      }
      FUN_100076e0((int)cVar7,param_1,&local_240);
      break;
    case 1:
      local_218 = 0;
      local_228 = 0;
      local_234 = 0;
      local_238 = 0;
      local_24c = 0;
      local_244 = -1;
      local_230 = 0;
      break;
    case 2:
      switch(cVar7) {
      case ' ':
        local_24c = local_24c | 2;
        break;
      case '#':
        local_24c = local_24c | 0x80;
        break;
      case '+':
        local_24c = local_24c | 1;
        break;
      case '-':
        local_24c = local_24c | 4;
        break;
      case '0':
        local_24c = local_24c | 8;
      }
      break;
    case 3:
      if (cVar7 == '*') {
        local_234 = FUN_100077b0(&param_3);
        if (local_234 < 0) {
          local_24c = local_24c | 4;
          local_234 = -local_234;
        }
      }
      else {
        local_234 = cVar7 + -0x30 + local_234 * 10;
      }
      break;
    case 4:
      local_244 = 0;
      break;
    case 5:
      if (cVar7 == '*') {
        local_244 = FUN_100077b0(&param_3);
        if (local_244 < 0) {
          local_244 = -1;
        }
      }
      else {
        local_244 = cVar7 + -0x30 + local_244 * 10;
      }
      break;
    case 6:
      switch(cVar7) {
      case 'I':
        if ((*param_2 != '6') || (param_2[1] != '4')) {
          local_220 = 0;
          goto switchD_10006dcd_caseD_0;
        }
        param_2 = param_2 + 2;
        local_24c = local_24c | 0x8000;
        break;
      case 'h':
        local_24c = local_24c | 0x20;
        break;
      case 'l':
        local_24c = local_24c | 0x10;
        break;
      case 'w':
        local_24c = local_24c | 0x800;
      }
      break;
    case 7:
      switch(cVar7) {
      case 'C':
        if ((local_24c & 0x830) == 0) {
          local_24c = local_24c | 0x800;
        }
      case 'c':
        if ((local_24c & 0x810) == 0) {
          local_200[0] = FUN_100077b0(&param_3);
          puVar9 = (undefined *)0x1;
        }
        else {
          uVar3 = FUN_100077f0(&param_3);
          puVar9 = (undefined *)FUN_100096f0(local_200,uVar3);
          if ((int)puVar9 < 0) {
            local_248 = (short *)local_200;
            local_228 = 1;
            break;
          }
        }
        local_248 = (short *)local_200;
        break;
      case 'E':
      case 'G':
        local_218 = 1;
        cVar7 = cVar7 + ' ';
      case 'e':
      case 'f':
      case 'g':
        local_248 = (short *)local_200;
        if (local_244 < 0) {
          local_244 = 6;
        }
        else if ((local_244 == 0) && (cVar7 == 'g')) {
          local_244 = 1;
        }
        local_210 = *param_3;
        local_20c = param_3[1];
        param_3 = param_3 + 2;
        (*DAT_10011d98)(&local_210,local_200,(int)cVar7,local_244,local_218);
        if (((local_24c & 0x80) != 0) && (local_244 == 0)) {
          (*DAT_10011da4)(local_200);
        }
        if ((cVar7 == 'g') && ((local_24c & 0x80) == 0)) {
          (*DAT_10011d9c)(local_200);
        }
        uVar2 = local_24c | 0x40;
        if (local_200[0] == '-') {
          local_248 = (short *)(local_200 + 1);
          uVar2 = local_24c | 0x140;
        }
        local_24c = uVar2;
        uVar2 = 0xffffffff;
        psVar5 = local_248;
        do {
          if (uVar2 == 0) break;
          uVar2 = uVar2 - 1;
          cVar7 = *(char *)psVar5;
          psVar5 = (short *)((int)psVar5 + 1);
        } while (cVar7 != '\0');
        puVar9 = (undefined *)(~uVar2 - 1);
        break;
      case 'S':
        if ((local_24c & 0x830) == 0) {
          local_24c = local_24c | 0x800;
        }
      case 's':
        iVar10 = 0x7fffffff;
        if (local_244 != -1) {
          iVar10 = local_244;
        }
        local_248 = (short *)FUN_100077b0(&param_3);
        if ((local_24c & 0x810) == 0) {
          psVar5 = local_248;
          if (local_248 == (short *)0x0) {
            psVar5 = DAT_10011480;
            local_248 = DAT_10011480;
          }
          for (; (iVar10 != 0 && (iVar10 = iVar10 + -1, *(char *)psVar5 != '\0'));
              psVar5 = (short *)((int)psVar5 + 1)) {
          }
          puVar9 = (undefined *)((int)psVar5 - (int)local_248);
        }
        else {
          if (local_248 == (short *)0x0) {
            local_248 = DAT_10011484;
          }
          local_230 = 1;
          for (psVar5 = local_248; (iVar10 != 0 && (iVar10 = iVar10 + -1, *psVar5 != 0));
              psVar5 = psVar5 + 1) {
          }
          puVar9 = (undefined *)((int)psVar5 - (int)local_248 >> 1);
        }
        break;
      case 'X':
        goto switchD_10006fe1_caseD_58;
      case 'Z':
        psVar5 = (short *)FUN_100077b0(&param_3);
        if ((psVar5 == (short *)0x0) ||
           (local_248 = *(short **)(psVar5 + 2), local_248 == (short *)0x0)) {
          uVar2 = 0xffffffff;
          local_248 = DAT_10011480;
          psVar5 = DAT_10011480;
          do {
            if (uVar2 == 0) break;
            uVar2 = uVar2 - 1;
            cVar7 = *(char *)psVar5;
            psVar5 = (short *)((int)psVar5 + 1);
          } while (cVar7 != '\0');
          puVar9 = (undefined *)(~uVar2 - 1);
        }
        else if ((local_24c & 0x800) == 0) {
          puVar9 = (undefined *)(int)*psVar5;
          local_230 = 0;
        }
        else {
          local_230 = 1;
          puVar9 = (undefined *)((uint)(int)*psVar5 >> 1);
        }
        break;
      case 'd':
      case 'i':
        local_22c = 10;
        local_24c = local_24c | 0x40;
        goto LAB_10007317;
      case 'n':
        piVar4 = (int *)FUN_100077b0(&param_3);
        if ((local_24c & 0x20) == 0) {
          local_228 = 1;
          *piVar4 = local_240;
        }
        else {
          local_228 = 1;
          *(undefined2 *)piVar4 = (undefined2)local_240;
        }
        break;
      case 'o':
        local_22c = 8;
        if ((local_24c & 0x80) != 0) {
          local_24c = local_24c | 0x200;
        }
        goto LAB_10007317;
      case 'p':
        local_244 = 8;
switchD_10006fe1_caseD_58:
        local_224 = 7;
LAB_100072d2:
        local_22c = 0x10;
        if ((local_24c & 0x80) != 0) {
          local_23a = 0x30;
          local_239 = (char)local_224 + 'Q';
          local_238 = 2;
        }
        goto LAB_10007317;
      case 'u':
        local_22c = 10;
LAB_10007317:
        if ((local_24c & 0x8000) == 0) {
          if ((local_24c & 0x20) == 0) {
            if ((local_24c & 0x40) == 0) {
              uVar2 = FUN_100077b0(&param_3);
              uVar11 = (ulonglong)uVar2;
            }
            else {
              iVar10 = FUN_100077b0(&param_3);
              uVar11 = (ulonglong)iVar10;
            }
          }
          else if ((local_24c & 0x40) == 0) {
            uVar2 = FUN_100077b0(&param_3);
            uVar11 = (ulonglong)(uVar2 & 0xffff);
          }
          else {
            sVar1 = FUN_100077b0(&param_3);
            uVar11 = (ulonglong)(int)sVar1;
          }
        }
        else {
          uVar11 = FUN_100077d0(&param_3);
        }
        if ((((local_24c & 0x40) != 0) && ((longlong)uVar11 < 0x100000000)) &&
           ((longlong)uVar11 < 0)) {
          uVar11 = CONCAT44(-((int)(uVar11 >> 0x20) + (uint)((int)uVar11 != 0)),-(int)uVar11);
          local_24c = local_24c | 0x100;
        }
        uVar2 = (uint)(uVar11 >> 0x20);
        if ((local_24c & 0x8000) == 0) {
          uVar2 = 0;
        }
        lVar12 = CONCAT44(uVar2,(uint)uVar11);
        if (local_244 < 0) {
          local_244 = 1;
        }
        else {
          local_24c = local_24c & 0xfffffff7;
        }
        if (((uint)uVar11 | uVar2) == 0) {
          local_238 = 0;
        }
        psVar5 = (short *)&local_1;
        iVar10 = local_244;
        while ((iVar6 = local_22c, local_244 = iVar10 + -1, 0 < iVar10 || (lVar12 != 0))) {
          local_204 = local_22c >> 0x1f;
          iVar10 = __aullrem(lVar12,local_22c,local_204);
          iVar10 = iVar10 + 0x30;
          lVar12 = __aulldiv(lVar12,iVar6,local_204);
          if (0x39 < iVar10) {
            iVar10 = iVar10 + local_224;
          }
          *(char *)psVar5 = (char)iVar10;
          psVar5 = (short *)((int)psVar5 + -1);
          iVar10 = local_244;
        }
        puVar9 = &local_1 + -(int)psVar5;
        local_248 = (short *)((int)psVar5 + 1);
        if (((local_24c & 0x200) != 0) &&
           ((*(char *)local_248 != '0' || (puVar9 == (undefined *)0x0)))) {
          puVar9 = &stack0x00000000 + -(int)psVar5;
          *(char *)psVar5 = '0';
          local_248 = psVar5;
        }
        break;
      case 'x':
        local_224 = 0x27;
        goto LAB_100072d2;
      }
      if (local_228 == 0) {
        if ((local_24c & 0x40) != 0) {
          if ((local_24c & 0x100) == 0) {
            if ((local_24c & 1) == 0) {
              if ((local_24c & 2) == 0) goto LAB_100074af;
              local_23a = 0x20;
            }
            else {
              local_23a = 0x2b;
            }
          }
          else {
            local_23a = 0x2d;
          }
          local_238 = 1;
        }
LAB_100074af:
        iVar10 = (local_234 - (int)puVar9) - local_238;
        if ((local_24c & 0xc) == 0) {
          FUN_10007730(0x20,iVar10,param_1,&local_240);
        }
        FUN_10007770(&local_23a,local_238,param_1,&local_240);
        if (((local_24c & 8) != 0) && ((local_24c & 4) == 0)) {
          FUN_10007730(0x30,iVar10,param_1,&local_240);
        }
        if ((local_230 == 0) || (psVar5 = local_248, puVar8 = puVar9, (int)puVar9 < 1)) {
          FUN_10007770(local_248,puVar9,param_1,&local_240);
        }
        else {
          do {
            puVar8 = puVar8 + -1;
            iVar6 = FUN_100096f0(local_214,*psVar5);
            if (iVar6 < 1) break;
            FUN_10007770(local_214,iVar6,param_1,&local_240);
            psVar5 = psVar5 + 1;
          } while (puVar8 != (undefined *)0x0);
        }
        if ((local_24c & 4) != 0) {
          FUN_10007730(0x20,iVar10,param_1,&local_240);
        }
      }
    }
    cVar7 = *param_2;
    param_2 = param_2 + 1;
    local_21c = CONCAT31(local_21c._1_3_,cVar7);
  } while( true );
}



void FUN_100076e0(uint param_1,int *param_2,int *param_3)

{
  int iVar1;
  
  iVar1 = param_2[1];
  param_2[1] = iVar1 + -1;
  if (iVar1 + -1 < 0) {
    param_1 = FUN_10006c20(param_1,param_2);
  }
  else {
    *(char *)*param_2 = (char)param_1;
    param_1 = param_1 & 0xff;
    *param_2 = *param_2 + 1;
  }
  if (param_1 == 0xffffffff) {
    *param_3 = -1;
    return;
  }
  *param_3 = *param_3 + 1;
  return;
}



void FUN_10007730(undefined4 param_1,int param_2,undefined4 param_3,int *param_4)

{
  if (0 < param_2) {
    do {
      param_2 = param_2 + -1;
      FUN_100076e0(param_1,param_3,param_4);
      if (*param_4 == -1) {
        return;
      }
    } while (0 < param_2);
  }
  return;
}



void FUN_10007770(char *param_1,int param_2,undefined4 param_3,int *param_4)

{
  char cVar1;
  
  if (0 < param_2) {
    do {
      param_2 = param_2 + -1;
      cVar1 = *param_1;
      param_1 = param_1 + 1;
      FUN_100076e0((int)cVar1,param_3,param_4);
      if (*param_4 == -1) {
        return;
      }
    } while (0 < param_2);
  }
  return;
}



undefined4 FUN_100077b0(int *param_1)

{
  undefined4 *puVar1;
  
  puVar1 = (undefined4 *)*param_1;
  *param_1 = (int)(puVar1 + 1);
  return *puVar1;
}



undefined8 FUN_100077d0(int *param_1)

{
  undefined8 *puVar1;
  
  puVar1 = (undefined8 *)*param_1;
  *param_1 = (int)(puVar1 + 1);
  return *puVar1;
}



undefined4 FUN_100077f0(undefined4 *param_1)

{
  undefined2 *puVar1;
  undefined2 *puVar2;
  
  puVar1 = (undefined2 *)*param_1;
  puVar2 = puVar1 + 2;
  *param_1 = puVar2;
  return CONCAT22((short)((uint)puVar2 >> 0x10),*puVar1);
}



int FUN_10007820(LCID param_1_00,uint param_2,LPCSTR param_3,LPCWSTR param_1,LPWSTR param_5,
                int param_6,UINT param_7,int param_8)

{
  int iVar1;
  int iVar2;
  LPCWSTR lpWideCharStr;
  
  if (DAT_10012cf0 == 0) {
    iVar1 = LCMapStringW(0,0x100,L"",1,(LPWSTR)0x0,0);
    if (iVar1 == 0) {
      iVar1 = LCMapStringA(0,0x100,"",1,(LPSTR)0x0,0);
      if (iVar1 == 0) {
        return 0;
      }
      DAT_10012cf0 = 2;
    }
    else {
      DAT_10012cf0 = 1;
    }
  }
  iVar1 = (int)param_1;
  if (0 < (int)param_1) {
    iVar1 = FUN_10007a50(param_3,param_1);
  }
  if (DAT_10012cf0 == 2) {
    iVar1 = LCMapStringA(param_1_00,param_2,param_3,iVar1,(LPSTR)param_5,param_6);
    return iVar1;
  }
  if (DAT_10012cf0 != 1) {
    return DAT_10012cf0;
  }
  param_1 = (LPCWSTR)0x0;
  if (param_7 == 0) {
    param_7 = DAT_10012ce8;
  }
  iVar2 = MultiByteToWideChar(param_7,(-(uint)(param_8 != 0) & 8) + 1,param_3,iVar1,(LPWSTR)0x0,0);
  if (iVar2 == 0) {
    return 0;
  }
  lpWideCharStr = (LPCWSTR)FUN_10005410(iVar2 * 2);
  if (lpWideCharStr == (LPCWSTR)0x0) {
    return 0;
  }
  iVar1 = MultiByteToWideChar(param_7,1,param_3,iVar1,lpWideCharStr,iVar2);
  if ((iVar1 != 0) &&
     (iVar1 = LCMapStringW(param_1_00,param_2,lpWideCharStr,iVar2,(LPWSTR)0x0,0), iVar1 != 0)) {
    if ((param_2 & 0x400) == 0) {
      param_1 = (LPCWSTR)FUN_10005410(iVar1 * 2);
      if ((param_1 == (LPCWSTR)0x0) ||
         (iVar2 = LCMapStringW(param_1_00,param_2,lpWideCharStr,iVar2,param_1,iVar1), iVar2 == 0))
      goto LAB_10007a28;
      if (param_6 == 0) {
        iVar1 = WideCharToMultiByte(param_7,0x220,param_1,iVar1,(LPSTR)0x0,0,(LPCSTR)0x0,(LPBOOL)0x0
                                   );
        iVar2 = iVar1;
      }
      else {
        iVar1 = WideCharToMultiByte(param_7,0x220,param_1,iVar1,(LPSTR)param_5,param_6,(LPCSTR)0x0,
                                    (LPBOOL)0x0);
        iVar2 = iVar1;
      }
    }
    else {
      if (param_6 == 0) goto LAB_1000798f;
      if (param_6 < iVar1) goto LAB_10007a28;
      iVar2 = LCMapStringW(param_1_00,param_2,lpWideCharStr,iVar2,param_5,param_6);
    }
    if (iVar2 != 0) {
LAB_1000798f:
      FUN_100053a0(lpWideCharStr);
      FUN_100053a0(param_1);
      return iVar1;
    }
  }
LAB_10007a28:
  FUN_100053a0(lpWideCharStr);
  FUN_100053a0(param_1);
  return 0;
}



int FUN_10007a50(char *param_1,int param_2)

{
  char *pcVar1;
  int iVar2;
  
  pcVar1 = param_1;
  iVar2 = param_2;
  if (param_2 != 0) {
    do {
      iVar2 = iVar2 + -1;
      if (*pcVar1 == '\0') break;
      pcVar1 = pcVar1 + 1;
    } while (iVar2 != 0);
  }
  if (*pcVar1 == '\0') {
    return (int)pcVar1 - (int)param_1;
  }
  return param_2;
}



uint FUN_10007a80(int param_1,uint param_2)

{
  undefined4 uVar1;
  int iVar2;
  uint local_4;
  
  iVar2 = param_1;
  if (param_1 + 1U < 0x101) {
    return *(ushort *)(DAT_100115e8 + param_1 * 2) & param_2;
  }
  if ((*(byte *)(DAT_100115e8 + 1 + (param_1 >> 8 & 0xffU) * 2) & 0x80) == 0) {
    param_1._0_2_ = (ushort)(byte)param_1;
    uVar1 = 1;
  }
  else {
    param_1._0_2_ = CONCAT11((byte)param_1,(char)((uint)param_1 >> 8));
    param_1._0_3_ = (uint3)(ushort)param_1;
    uVar1 = 2;
  }
  iVar2 = FUN_1000aa00(1,&param_1,uVar1,&local_4,0,0,1);
  if (iVar2 == 0) {
    return 0;
  }
  return local_4 & 0xffff & param_2;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_10007bb0(undefined4 param_1)

{
  BYTE *pBVar1;
  byte bVar2;
  byte bVar3;
  UINT CodePage;
  UINT *pUVar4;
  BOOL BVar5;
  uint uVar6;
  uint uVar7;
  int iVar8;
  int iVar9;
  BYTE *pBVar10;
  byte *pbVar11;
  byte *pbVar12;
  undefined4 *puVar13;
  _cpinfo local_14;
  
  FUN_10006360(0x19);
  CodePage = FUN_10007de0(param_1);
  if (CodePage == DAT_10012f00) {
    FUN_100063e0(0x19);
    return 0;
  }
  if (CodePage == 0) {
    FUN_10007e90();
    FUN_10007ed0();
    FUN_100063e0(0x19);
    return 0;
  }
  iVar9 = 0;
  pUVar4 = &DAT_10011808;
  do {
    if (*pUVar4 == CodePage) {
      puVar13 = (undefined4 *)&DAT_10012cf8;
      for (iVar8 = 0x40; iVar8 != 0; iVar8 = iVar8 + -1) {
        *puVar13 = 0;
        puVar13 = puVar13 + 1;
      }
      *(undefined *)puVar13 = 0;
      uVar6 = 0;
      pbVar11 = &DAT_10011818 + iVar9 * 0x30;
      do {
        bVar2 = *pbVar11;
        for (pbVar12 = pbVar11; (bVar2 != 0 && (bVar2 = pbVar12[1], bVar2 != 0));
            pbVar12 = pbVar12 + 2) {
          uVar7 = (uint)*pbVar12;
          if (uVar7 <= bVar2) {
            bVar3 = (&DAT_10011800)[uVar6];
            do {
              (&DAT_10012cf9)[uVar7] = (&DAT_10012cf9)[uVar7] | bVar3;
              uVar7 = uVar7 + 1;
            } while (uVar7 <= bVar2);
          }
          bVar2 = pbVar12[2];
        }
        uVar6 = uVar6 + 1;
        pbVar11 = pbVar11 + 8;
      } while (uVar6 < 4);
      _DAT_10015184 = 1;
      DAT_10012f00 = CodePage;
      DAT_10012f04 = FUN_10007e30(CodePage);
      _DAT_10012f08 = (&DAT_1001180c)[iVar9 * 0xc];
      _DAT_10012f0c = (&DAT_10011810)[iVar9 * 0xc];
      _DAT_10012f10 = (&DAT_10011814)[iVar9 * 0xc];
      goto LAB_10007d02;
    }
    pUVar4 = pUVar4 + 0xc;
    iVar9 = iVar9 + 1;
  } while (pUVar4 < &DAT_100118f8);
  BVar5 = GetCPInfo(CodePage,&local_14);
  if (BVar5 == 1) {
    puVar13 = (undefined4 *)&DAT_10012cf8;
    for (iVar9 = 0x40; iVar9 != 0; iVar9 = iVar9 + -1) {
      *puVar13 = 0;
      puVar13 = puVar13 + 1;
    }
    *(undefined *)puVar13 = 0;
    DAT_10012f04 = 0;
    if (local_14.MaxCharSize < 2) {
      _DAT_10015184 = 0;
      DAT_10012f00 = CodePage;
    }
    else {
      DAT_10012f00 = CodePage;
      if (local_14.LeadByte[0] != '\0') {
        pBVar10 = local_14.LeadByte + 1;
        do {
          bVar2 = *pBVar10;
          if (bVar2 == 0) break;
          for (uVar6 = (uint)pBVar10[-1]; uVar6 <= bVar2; uVar6 = uVar6 + 1) {
            (&DAT_10012cf9)[uVar6] = (&DAT_10012cf9)[uVar6] | 4;
          }
          pBVar1 = pBVar10 + 1;
          pBVar10 = pBVar10 + 2;
        } while (*pBVar1 != 0);
      }
      uVar6 = 1;
      do {
        (&DAT_10012cf9)[uVar6] = (&DAT_10012cf9)[uVar6] | 8;
        uVar6 = uVar6 + 1;
      } while (uVar6 < 0xff);
      DAT_10012f04 = FUN_10007e30(CodePage);
      _DAT_10015184 = 1;
    }
    _DAT_10012f08 = 0;
    _DAT_10012f0c = 0;
    _DAT_10012f10 = 0;
  }
  else {
    if (DAT_10012f14 == 0) {
      FUN_100063e0(0x19);
      return 0xffffffff;
    }
    FUN_10007e90();
  }
LAB_10007d02:
  FUN_10007ed0();
  FUN_100063e0(0x19);
  return 0;
}



int FUN_10007de0(int param_1)

{
  int iVar1;
  bool bVar2;
  
  if (param_1 == -2) {
    DAT_10012f14 = 1;
                    // WARNING: Could not recover jumptable at 0x10007dfd. Too many branches
                    // WARNING: Treating indirect jump as call
    iVar1 = GetOEMCP();
    return iVar1;
  }
  if (param_1 == -3) {
    DAT_10012f14 = 1;
                    // WARNING: Could not recover jumptable at 0x10007e12. Too many branches
                    // WARNING: Treating indirect jump as call
    iVar1 = GetACP();
    return iVar1;
  }
  bVar2 = param_1 == -4;
  if (bVar2) {
    param_1 = DAT_10012ce8;
  }
  DAT_10012f14 = (uint)bVar2;
  return param_1;
}



undefined4 FUN_10007e30(undefined4 param_1)

{
  switch(param_1) {
  case 0x3a4:
    return 0x411;
  default:
    return 0;
  case 0x3a8:
    return 0x804;
  case 0x3b5:
    return 0x412;
  case 0x3b6:
    return 0x404;
  }
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_10007e90(void)

{
  int iVar1;
  undefined4 *puVar2;
  
  puVar2 = (undefined4 *)&DAT_10012cf8;
  for (iVar1 = 0x40; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  *(undefined *)puVar2 = 0;
  DAT_10012f00 = 0;
  _DAT_10015184 = 0;
  DAT_10012f04 = 0;
  _DAT_10012f08 = 0;
  _DAT_10012f0c = 0;
  _DAT_10012f10 = 0;
  return;
}



void FUN_10007ed0(void)

{
  BOOL BVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  BYTE *pBVar5;
  ushort *puVar6;
  undefined4 *puVar7;
  _cpinfo _Stack_514;
  undefined4 auStack_500 [64];
  undefined auStack_400 [256];
  undefined auStack_300 [256];
  ushort auStack_200 [256];
  
  BVar1 = GetCPInfo(DAT_10012f00,&_Stack_514);
  if (BVar1 == 1) {
    uVar2 = 0;
    do {
      *(char *)((int)auStack_500 + uVar2) = (char)uVar2;
      uVar2 = uVar2 + 1;
    } while (uVar2 < 0x100);
    auStack_500[0]._0_1_ = 0x20;
    if (_Stack_514.LeadByte[0] != 0) {
      pBVar5 = _Stack_514.LeadByte + 1;
      do {
        uVar2 = (uint)_Stack_514.LeadByte[0];
        if (uVar2 <= *pBVar5) {
          uVar3 = (*pBVar5 - uVar2) + 1;
          puVar7 = (undefined4 *)((int)auStack_500 + uVar2);
          for (uVar4 = uVar3 >> 2; uVar4 != 0; uVar4 = uVar4 - 1) {
            *puVar7 = 0x20202020;
            puVar7 = puVar7 + 1;
          }
          for (uVar3 = uVar3 & 3; uVar3 != 0; uVar3 = uVar3 - 1) {
            *(undefined *)puVar7 = 0x20;
            puVar7 = (undefined4 *)((int)puVar7 + 1);
          }
        }
        _Stack_514.LeadByte[0] = pBVar5[1];
        pBVar5 = pBVar5 + 2;
      } while (_Stack_514.LeadByte[0] != 0);
    }
    FUN_1000aa00(1,auStack_500,0x100,auStack_200,DAT_10012f00,DAT_10012f04,0);
    FUN_10007820(DAT_10012f04,0x100,auStack_500,0x100,auStack_400,0x100,DAT_10012f00,0);
    FUN_10007820(DAT_10012f04,0x200,auStack_500,0x100,auStack_300,0x100,DAT_10012f00,0);
    uVar2 = 0;
    puVar6 = auStack_200;
    do {
      if ((*puVar6 & 1) == 0) {
        if ((*puVar6 & 2) == 0) {
          (&DAT_10012e00)[uVar2] = 0;
        }
        else {
          (&DAT_10012cf9)[uVar2] = (&DAT_10012cf9)[uVar2] | 0x20;
          (&DAT_10012e00)[uVar2] = auStack_300[uVar2];
        }
      }
      else {
        (&DAT_10012cf9)[uVar2] = (&DAT_10012cf9)[uVar2] | 0x10;
        (&DAT_10012e00)[uVar2] = auStack_400[uVar2];
      }
      uVar2 = uVar2 + 1;
      puVar6 = puVar6 + 1;
    } while (uVar2 < 0x100);
    return;
  }
  uVar2 = 0;
  do {
    if ((uVar2 < 0x41) || (0x5a < uVar2)) {
      if ((uVar2 < 0x61) || (0x7a < uVar2)) {
        (&DAT_10012e00)[uVar2] = 0;
      }
      else {
        (&DAT_10012cf9)[uVar2] = (&DAT_10012cf9)[uVar2] | 0x20;
        (&DAT_10012e00)[uVar2] = (char)uVar2 + -0x20;
      }
    }
    else {
      (&DAT_10012cf9)[uVar2] = (&DAT_10012cf9)[uVar2] | 0x10;
      (&DAT_10012e00)[uVar2] = (char)uVar2 + ' ';
    }
    uVar2 = uVar2 + 1;
  } while (uVar2 < 0x100);
  return;
}



void FUN_100080b0(void)

{
  FUN_10007bb0(0xfffffffd);
  return;
}



undefined4 FUN_10008170(uint param_1,undefined4 param_2,undefined4 param_3)

{
  undefined4 uVar1;
  undefined4 *puVar2;
  
  if ((param_1 < DAT_10015180) &&
     ((*(byte *)((&DAT_10015080)[(int)param_1 >> 5] + 4 + (param_1 & 0x1f) * 0x24) & 1) != 0)) {
    FUN_10008810(param_1);
    uVar1 = FUN_100081f0(param_1,param_2,param_3);
    FUN_10008880(param_1);
    return uVar1;
  }
  puVar2 = (undefined4 *)FUN_10008600();
  *puVar2 = 9;
  puVar2 = (undefined4 *)FUN_10008610();
  *puVar2 = 0;
  return 0xffffffff;
}



int FUN_100081f0(uint param_1,char *param_2,uint param_3)

{
  int *piVar1;
  char cVar2;
  char *pcVar3;
  BOOL BVar4;
  undefined4 *puVar5;
  int iVar6;
  char *pcVar7;
  DWORD local_41c;
  DWORD local_414;
  DWORD local_410;
  int local_40c;
  int *local_408;
  char local_404 [1028];
  
  local_41c = 0;
  local_40c = 0;
  if (param_3 == 0) {
    return 0;
  }
  piVar1 = &DAT_10015080 + ((int)param_1 >> 5);
  iVar6 = (param_1 & 0x1f) * 0x24;
  local_408 = piVar1;
  if ((*(byte *)(iVar6 + 4 + *piVar1) & 0x20) != 0) {
    FUN_100086a0(param_1,0,2);
  }
  if ((*(byte *)((HANDLE *)(*piVar1 + iVar6) + 1) & 0x80) == 0) {
    BVar4 = WriteFile(*(HANDLE *)(*piVar1 + iVar6),param_2,param_3,&local_410,(LPOVERLAPPED)0x0);
    if (BVar4 == 0) {
      local_414 = GetLastError();
    }
    else {
      local_41c = local_410;
      local_414 = 0;
    }
  }
  else {
    local_414 = 0;
    pcVar7 = param_2;
    if (param_3 != 0) {
      do {
        pcVar3 = local_404;
        do {
          if (param_3 <= (uint)((int)pcVar7 - (int)param_2)) break;
          cVar2 = *pcVar7;
          pcVar7 = pcVar7 + 1;
          if (cVar2 == '\n') {
            *pcVar3 = '\r';
            local_40c = local_40c + 1;
            pcVar3 = pcVar3 + 1;
          }
          *pcVar3 = cVar2;
          pcVar3 = pcVar3 + 1;
        } while ((int)pcVar3 - (int)local_404 < 0x400);
        BVar4 = WriteFile(*(HANDLE *)(iVar6 + *local_408),local_404,(int)pcVar3 - (int)local_404,
                          &local_410,(LPOVERLAPPED)0x0);
        if (BVar4 == 0) {
          local_414 = GetLastError();
          break;
        }
        local_41c = local_41c + local_410;
        if (((int)local_410 < (int)pcVar3 - (int)local_404) ||
           (param_3 <= (uint)((int)pcVar7 - (int)param_2))) break;
      } while( true );
    }
  }
  if (local_41c != 0) {
    return local_41c - local_40c;
  }
  if (local_414 == 0) {
    if (((*(byte *)(iVar6 + 4 + *local_408) & 0x40) != 0) && (*param_2 == '\x1a')) {
      return 0;
    }
    puVar5 = (undefined4 *)FUN_10008600();
    *puVar5 = 0x1c;
    puVar5 = (undefined4 *)FUN_10008610();
    *puVar5 = 0;
    return -1;
  }
  if (local_414 != 5) {
    FUN_10008580(local_414);
    return -1;
  }
  puVar5 = (undefined4 *)FUN_10008600();
  *puVar5 = 9;
  puVar5 = (undefined4 *)FUN_10008610();
  *puVar5 = 5;
  return -1;
}



void FUN_10008580(uint param_1)

{
  uint *puVar1;
  undefined4 *puVar2;
  int iVar3;
  
  puVar1 = (uint *)FUN_10008610();
  iVar3 = 0;
  *puVar1 = param_1;
  puVar1 = &DAT_100118f8;
  do {
    if (param_1 == *puVar1) {
      puVar2 = (undefined4 *)FUN_10008600();
      *puVar2 = (&DAT_100118fc)[iVar3 * 2];
      return;
    }
    puVar1 = puVar1 + 2;
    iVar3 = iVar3 + 1;
  } while (puVar1 < (uint *)0x10011a60);
  if ((0x12 < param_1) && (param_1 < 0x25)) {
    puVar2 = (undefined4 *)FUN_10008600();
    *puVar2 = 0xd;
    return;
  }
  if ((0xbb < param_1) && (param_1 < 0xcb)) {
    puVar2 = (undefined4 *)FUN_10008600();
    *puVar2 = 8;
    return;
  }
  puVar2 = (undefined4 *)FUN_10008600();
  *puVar2 = 0x16;
  return;
}



int FUN_10008600(void)

{
  int iVar1;
  
  iVar1 = FUN_10008d30();
  return iVar1 + 8;
}



int FUN_10008610(void)

{
  int iVar1;
  
  iVar1 = FUN_10008d30();
  return iVar1 + 0xc;
}



undefined4 FUN_10008620(uint param_1,undefined4 param_2,undefined4 param_3)

{
  undefined4 uVar1;
  undefined4 *puVar2;
  
  if ((param_1 < DAT_10015180) &&
     ((*(byte *)((&DAT_10015080)[(int)param_1 >> 5] + 4 + (param_1 & 0x1f) * 0x24) & 1) != 0)) {
    FUN_10008810(param_1);
    uVar1 = FUN_100086a0(param_1,param_2,param_3);
    FUN_10008880(param_1);
    return uVar1;
  }
  puVar2 = (undefined4 *)FUN_10008600();
  *puVar2 = 9;
  puVar2 = (undefined4 *)FUN_10008610();
  *puVar2 = 0;
  return 0xffffffff;
}



DWORD FUN_100086a0(uint param_1,LONG param_2,DWORD param_3)

{
  HANDLE hFile;
  undefined4 *puVar1;
  DWORD DVar2;
  DWORD DVar3;
  
  hFile = (HANDLE)FUN_100087c0(param_1);
  if (hFile == (HANDLE)0xffffffff) {
    puVar1 = (undefined4 *)FUN_10008600();
    *puVar1 = 9;
    return 0xffffffff;
  }
  DVar2 = SetFilePointer(hFile,param_2,(PLONG)0x0,param_3);
  if (DVar2 == 0xffffffff) {
    DVar3 = GetLastError();
  }
  else {
    DVar3 = 0;
  }
  if (DVar3 != 0) {
    FUN_10008580(DVar3);
    return 0xffffffff;
  }
  *(byte *)((&DAT_10015080)[(int)param_1 >> 5] + 4 + (param_1 & 0x1f) * 0x24) =
       *(byte *)((&DAT_10015080)[(int)param_1 >> 5] + 4 + (param_1 & 0x1f) * 0x24) & 0xfd;
  return DVar2;
}



undefined4 FUN_100087c0(uint param_1)

{
  undefined4 *puVar1;
  
  if ((param_1 < DAT_10015180) &&
     ((*(byte *)((&DAT_10015080)[(int)param_1 >> 5] + 4 + (param_1 & 0x1f) * 0x24) & 1) != 0)) {
    return *(undefined4 *)((&DAT_10015080)[(int)param_1 >> 5] + (param_1 & 0x1f) * 0x24);
  }
  puVar1 = (undefined4 *)FUN_10008600();
  *puVar1 = 9;
  puVar1 = (undefined4 *)FUN_10008610();
  *puVar1 = 0;
  return 0xffffffff;
}



void FUN_10008810(uint param_1)

{
  int iVar1;
  int iVar2;
  
  iVar2 = (param_1 & 0x1f) * 0x24;
  iVar1 = (&DAT_10015080)[(int)param_1 >> 5] + iVar2;
  if (*(int *)(iVar1 + 8) == 0) {
    FUN_10006360(0x11);
    if (*(int *)(iVar1 + 8) == 0) {
      InitializeCriticalSection((LPCRITICAL_SECTION)(iVar1 + 0xc));
      *(int *)(iVar1 + 8) = *(int *)(iVar1 + 8) + 1;
    }
    FUN_100063e0(0x11);
  }
  EnterCriticalSection((LPCRITICAL_SECTION)((&DAT_10015080)[(int)param_1 >> 5] + 0xc + iVar2));
  return;
}



void FUN_10008880(uint param_1)

{
  LeaveCriticalSection
            ((LPCRITICAL_SECTION)
             ((&DAT_10015080)[(int)param_1 >> 5] + 0xc + (param_1 & 0x1f) * 0x24));
  return;
}



void FUN_100088b0(void)

{
  HANDLE *ppvVar1;
  byte bVar2;
  undefined4 *puVar3;
  DWORD DVar4;
  HANDLE hFile;
  HANDLE *ppvVar5;
  int iVar6;
  int *piVar7;
  uint uVar8;
  UINT UStack_48;
  _STARTUPINFOA local_44;
  
  puVar3 = (undefined4 *)FUN_10005410(0x480);
  if (puVar3 == (undefined4 *)0x0) {
    __amsg_exit(0x1b);
  }
  DAT_10015180 = 0x20;
  DAT_10015080 = puVar3;
  if (puVar3 < puVar3 + 0x120) {
    do {
      *(undefined *)(puVar3 + 1) = 0;
      *puVar3 = 0xffffffff;
      *(undefined *)((int)puVar3 + 5) = 10;
      puVar3[2] = 0;
      puVar3 = puVar3 + 9;
    } while (puVar3 < DAT_10015080 + 0x120);
  }
  GetStartupInfoA(&local_44);
  if ((local_44.cbReserved2 != 0) && ((UINT *)local_44.lpReserved2 != (UINT *)0x0)) {
    UStack_48 = *(UINT *)local_44.lpReserved2;
    local_44.lpReserved2 = (LPBYTE)((int)local_44.lpReserved2 + 4);
    ppvVar5 = (HANDLE *)((int)local_44.lpReserved2 + UStack_48);
    if (0x7ff < (int)UStack_48) {
      UStack_48 = 0x800;
    }
    if ((int)DAT_10015180 < (int)UStack_48) {
      piVar7 = &DAT_10015084;
      do {
        puVar3 = (undefined4 *)FUN_10005410(0x480);
        if (puVar3 == (undefined4 *)0x0) {
          UStack_48 = DAT_10015180;
          break;
        }
        *piVar7 = (int)puVar3;
        DAT_10015180 = DAT_10015180 + 0x20;
        if (puVar3 < puVar3 + 0x120) {
          do {
            *(undefined *)(puVar3 + 1) = 0;
            *puVar3 = 0xffffffff;
            *(undefined *)((int)puVar3 + 5) = 10;
            puVar3[2] = 0;
            puVar3 = puVar3 + 9;
          } while (puVar3 < (undefined4 *)(*piVar7 + 0x480));
        }
        piVar7 = piVar7 + 1;
      } while ((int)DAT_10015180 < (int)UStack_48);
    }
    uVar8 = 0;
    if (0 < (int)UStack_48) {
      do {
        if (((*ppvVar5 != (HANDLE)0xffffffff) && ((*local_44.lpReserved2 & 1) != 0)) &&
           (((*local_44.lpReserved2 & 8) != 0 || (DVar4 = GetFileType(*ppvVar5), DVar4 != 0)))) {
          ppvVar1 = (HANDLE *)((int)(&DAT_10015080)[(int)uVar8 >> 5] + (uVar8 & 0x1f) * 0x24);
          *ppvVar1 = *ppvVar5;
          *(BYTE *)(ppvVar1 + 1) = *local_44.lpReserved2;
        }
        uVar8 = uVar8 + 1;
        local_44.lpReserved2 = (LPBYTE)((int)local_44.lpReserved2 + 1);
        ppvVar5 = ppvVar5 + 1;
      } while ((int)uVar8 < (int)UStack_48);
    }
  }
  iVar6 = 0;
  do {
    ppvVar5 = (HANDLE *)(DAT_10015080 + iVar6 * 9);
    if (DAT_10015080[iVar6 * 9] == -1) {
      *(undefined *)(ppvVar5 + 1) = 0x81;
      if (iVar6 == 0) {
        DVar4 = 0xfffffff6;
      }
      else {
        DVar4 = 0xfffffff5 - (iVar6 != 1);
      }
      hFile = GetStdHandle(DVar4);
      if ((hFile == (HANDLE)0xffffffff) || (DVar4 = GetFileType(hFile), DVar4 == 0)) {
        bVar2 = *(byte *)(ppvVar5 + 1) | 0x40;
        goto LAB_10008a9e;
      }
      *ppvVar5 = hFile;
      if ((DVar4 & 0xff) == 2) {
        bVar2 = *(byte *)(ppvVar5 + 1) | 0x40;
        goto LAB_10008a9e;
      }
      if ((DVar4 & 0xff) == 3) {
        bVar2 = *(byte *)(ppvVar5 + 1) | 8;
        goto LAB_10008a9e;
      }
    }
    else {
      bVar2 = *(byte *)(ppvVar5 + 1) | 0x80;
LAB_10008a9e:
      *(byte *)(ppvVar5 + 1) = bVar2;
    }
    iVar6 = iVar6 + 1;
    if (2 < iVar6) {
      SetHandleCount(DAT_10015180);
      return;
    }
  } while( true );
}



void FUN_10008ac0(void)

{
  uint *puVar1;
  uint uVar2;
  LPCRITICAL_SECTION lpCriticalSection;
  
  puVar1 = &DAT_10015080;
  do {
    uVar2 = *puVar1;
    if (uVar2 != 0) {
      if (uVar2 < uVar2 + 0x480) {
        lpCriticalSection = (LPCRITICAL_SECTION)(uVar2 + 0xc);
        do {
          if (lpCriticalSection[-1].SpinCount != 0) {
            DeleteCriticalSection(lpCriticalSection);
          }
          uVar2 = uVar2 + 0x24;
          lpCriticalSection = (LPCRITICAL_SECTION)&lpCriticalSection[1].OwningThread;
        } while (uVar2 < *puVar1 + 0x480);
      }
      FUN_100053a0(*puVar1);
      *puVar1 = 0;
    }
    puVar1 = puVar1 + 1;
  } while ((int)puVar1 < 0x10015180);
  return;
}



void FUN_10008b20(void)

{
  if (DAT_1001506c != (code *)0x0) {
    (*DAT_1001506c)();
  }
  FUN_10008c60(&DAT_1000f008,&DAT_1000f010);
  FUN_10008c60(&DAT_1000f000,&DAT_1000f004);
  return;
}



// Library Function - Single Match
//  __exit
// 
// Library: Visual Studio 1998 Release

void __cdecl __exit(int _Code)

{
  FUN_10008b80(_Code,1,0);
  return;
}



void FUN_10008b70(void)

{
  FUN_10008b80(0,0,1);
  return;
}



void FUN_10008b80(UINT param_1,int param_2,int param_3)

{
  HANDLE hProcess;
  code **ppcVar1;
  code **ppcVar2;
  UINT uExitCode;
  
  FUN_10008c40();
  if (DAT_10012f58 == 1) {
    uExitCode = param_1;
    hProcess = GetCurrentProcess();
    TerminateProcess(hProcess,uExitCode);
  }
  DAT_10012f54 = 1;
  DAT_10012f50 = (undefined)param_3;
  if (param_2 == 0) {
    if ((DAT_10015068 != (code **)0x0) &&
       (ppcVar2 = (code **)(DAT_10015064 + -4), ppcVar1 = DAT_10015068, DAT_10015068 <= ppcVar2)) {
      do {
        if (*ppcVar2 != (code *)0x0) {
          (**ppcVar2)();
          ppcVar1 = DAT_10015068;
        }
        ppcVar2 = ppcVar2 + -1;
      } while (ppcVar1 <= ppcVar2);
    }
    FUN_10008c60(&DAT_1000f014,&DAT_1000f01c);
  }
  FUN_10008c60(&DAT_1000f020,&DAT_1000f024);
  if (param_3 != 0) {
    FUN_10008c50();
    return;
  }
  DAT_10012f58 = 1;
                    // WARNING: Subroutine does not return
  ExitProcess(param_1);
}



void FUN_10008c40(void)

{
  FUN_10006360(0xd);
  return;
}



void FUN_10008c50(void)

{
  FUN_100063e0(0xd);
  return;
}



void FUN_10008c60(code **param_1,code **param_2)

{
  if (param_1 < param_2) {
    do {
      if (*param_1 != (code *)0x0) {
        (**param_1)();
      }
      param_1 = param_1 + 1;
    } while (param_1 < param_2);
  }
  return;
}



undefined4 FUN_10008c80(void)

{
  DWORD *lpTlsValue;
  BOOL BVar1;
  DWORD DVar2;
  
  FUN_100062b0();
  DAT_10011a84 = TlsAlloc();
  if (DAT_10011a84 != 0xffffffff) {
    lpTlsValue = (DWORD *)FUN_1000abe0(1,0x74);
    if (lpTlsValue != (DWORD *)0x0) {
      BVar1 = TlsSetValue(DAT_10011a84,lpTlsValue);
      if (BVar1 != 0) {
        FUN_10008d10(lpTlsValue);
        DVar2 = GetCurrentThreadId();
        *lpTlsValue = DVar2;
        lpTlsValue[1] = 0xffffffff;
        return 1;
      }
    }
  }
  return 0;
}



void FUN_10008ce0(void)

{
  FUN_100062e0();
  if (DAT_10011a84 != 0xffffffff) {
    TlsFree(DAT_10011a84);
    DAT_10011a84 = 0xffffffff;
  }
  return;
}



void FUN_10008d10(int param_1)

{
  *(undefined **)(param_1 + 0x50) = &DAT_10012530;
  *(undefined4 *)(param_1 + 0x14) = 1;
  return;
}



DWORD * FUN_10008d30(void)

{
  DWORD dwErrCode;
  DWORD *lpTlsValue;
  BOOL BVar1;
  DWORD DVar2;
  
  dwErrCode = GetLastError();
  lpTlsValue = (DWORD *)TlsGetValue(DAT_10011a84);
  if (lpTlsValue == (DWORD *)0x0) {
    lpTlsValue = (DWORD *)FUN_1000abe0(1,0x74);
    if (lpTlsValue != (DWORD *)0x0) {
      BVar1 = TlsSetValue(DAT_10011a84,lpTlsValue);
      if (BVar1 != 0) {
        FUN_10008d10(lpTlsValue);
        DVar2 = GetCurrentThreadId();
        *lpTlsValue = DVar2;
        lpTlsValue[1] = 0xffffffff;
        SetLastError(dwErrCode);
        return lpTlsValue;
      }
    }
    __amsg_exit(0x10);
  }
  SetLastError(dwErrCode);
  return lpTlsValue;
}



void FUN_10008db0(LPVOID param_1)

{
  if (DAT_10011a84 != 0xffffffff) {
    if ((param_1 != (LPVOID)0x0) || (param_1 = TlsGetValue(DAT_10011a84), param_1 != (LPVOID)0x0)) {
      if (*(int *)((int)param_1 + 0x24) != 0) {
        FUN_100053a0(*(int *)((int)param_1 + 0x24));
      }
      if (*(int *)((int)param_1 + 0x28) != 0) {
        FUN_100053a0(*(int *)((int)param_1 + 0x28));
      }
      if (*(int *)((int)param_1 + 0x30) != 0) {
        FUN_100053a0(*(int *)((int)param_1 + 0x30));
      }
      if (*(int *)((int)param_1 + 0x38) != 0) {
        FUN_100053a0(*(int *)((int)param_1 + 0x38));
      }
      if (*(int *)((int)param_1 + 0x40) != 0) {
        FUN_100053a0(*(int *)((int)param_1 + 0x40));
      }
      if (*(int *)((int)param_1 + 0x44) != 0) {
        FUN_100053a0(*(int *)((int)param_1 + 0x44));
      }
      if (*(undefined **)((int)param_1 + 0x50) != &DAT_10012530) {
        FUN_100053a0(*(undefined **)((int)param_1 + 0x50));
      }
      FUN_100053a0(param_1);
    }
    TlsSetValue(DAT_10011a84,(LPVOID)0x0);
    return;
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_10008e60(void)

{
  char cVar1;
  char cVar2;
  int *piVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  char *pcVar7;
  int iVar8;
  undefined4 *puVar9;
  char *pcVar10;
  char *pcVar11;
  undefined4 *puVar12;
  int *local_4;
  
  iVar8 = 0;
  cVar2 = *DAT_10012c48;
  pcVar7 = DAT_10012c48;
  while (cVar2 != '\0') {
    if (cVar2 != '=') {
      iVar8 = iVar8 + 1;
    }
    uVar4 = 0xffffffff;
    pcVar10 = pcVar7;
    do {
      if (uVar4 == 0) break;
      uVar4 = uVar4 - 1;
      cVar2 = *pcVar10;
      pcVar10 = pcVar10 + 1;
    } while (cVar2 != '\0');
    pcVar10 = pcVar7 + ~uVar4;
    pcVar7 = pcVar7 + ~uVar4;
    cVar2 = *pcVar10;
  }
  piVar3 = (int *)FUN_10005410(iVar8 * 4 + 4);
  _DAT_10012f38 = piVar3;
  if (piVar3 == (int *)0x0) {
    __amsg_exit(9);
  }
  cVar2 = *DAT_10012c48;
  local_4 = piVar3;
  pcVar7 = DAT_10012c48;
  do {
    if (cVar2 == '\0') {
      FUN_100053a0(DAT_10012c48);
      DAT_10012c48 = (char *)0x0;
      *piVar3 = 0;
      return;
    }
    uVar4 = 0xffffffff;
    pcVar10 = pcVar7;
    do {
      if (uVar4 == 0) break;
      uVar4 = uVar4 - 1;
      cVar1 = *pcVar10;
      pcVar10 = pcVar10 + 1;
    } while (cVar1 != '\0');
    uVar4 = ~uVar4;
    if (cVar2 != '=') {
      iVar8 = FUN_10005410(uVar4);
      *piVar3 = iVar8;
      if (iVar8 == 0) {
        __amsg_exit(9);
      }
      uVar5 = 0xffffffff;
      pcVar10 = pcVar7;
      do {
        pcVar11 = pcVar10;
        if (uVar5 == 0) break;
        uVar5 = uVar5 - 1;
        pcVar11 = pcVar10 + 1;
        cVar2 = *pcVar10;
        pcVar10 = pcVar11;
      } while (cVar2 != '\0');
      uVar5 = ~uVar5;
      puVar9 = (undefined4 *)(pcVar11 + -uVar5);
      puVar12 = (undefined4 *)*local_4;
      for (uVar6 = uVar5 >> 2; uVar6 != 0; uVar6 = uVar6 - 1) {
        *puVar12 = *puVar9;
        puVar9 = puVar9 + 1;
        puVar12 = puVar12 + 1;
      }
      piVar3 = local_4 + 1;
      for (uVar5 = uVar5 & 3; local_4 = piVar3, uVar5 != 0; uVar5 = uVar5 - 1) {
        *(undefined *)puVar12 = *(undefined *)puVar9;
        puVar9 = (undefined4 *)((int)puVar9 + 1);
        puVar12 = (undefined4 *)((int)puVar12 + 1);
      }
    }
    cVar2 = pcVar7[uVar4];
    pcVar7 = pcVar7 + uVar4;
  } while( true );
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_10008f50(void)

{
  int iVar1;
  char *pcVar2;
  int iStack_8;
  int iStack_4;
  
  GetModuleFileNameA((HMODULE)0x0,&DAT_10012f60,0x104);
  _DAT_10012f48 = &DAT_10012f60;
  pcVar2 = DAT_10015194;
  if (*DAT_10015194 == '\0') {
    pcVar2 = &DAT_10012f60;
  }
  FUN_10008ff0(pcVar2,0,0,&iStack_8,&iStack_4);
  iVar1 = FUN_10005410(iStack_4 + iStack_8 * 4);
  if (iVar1 == 0) {
    __amsg_exit(8);
  }
  FUN_10008ff0(pcVar2,iVar1,iVar1 + iStack_8 * 4,&iStack_8,&iStack_4);
  _DAT_10012f30 = iVar1;
  _DAT_10012f2c = iStack_8 + -1;
  return;
}



void FUN_10008ff0(byte *param_1,byte **param_2,byte *param_3,int *param_4,int *param_5)

{
  byte *pbVar1;
  byte bVar2;
  bool bVar3;
  bool bVar4;
  bool bVar5;
  int *piVar6;
  byte *pbVar7;
  uint uVar8;
  
  piVar6 = param_5;
  *param_5 = 0;
  *param_4 = 1;
  if (param_2 != (byte **)0x0) {
    *param_2 = param_3;
    param_2 = param_2 + 1;
  }
  if (*param_1 == 0x22) {
    pbVar7 = param_1 + 1;
    bVar2 = param_1[1];
    while ((bVar2 != 0x22 && (bVar2 != 0))) {
      if ((((&DAT_10012cf9)[bVar2] & 4) != 0) && (*param_5 = *param_5 + 1, param_3 != (byte *)0x0))
      {
        *param_3 = *pbVar7;
        param_3 = param_3 + 1;
        pbVar7 = pbVar7 + 1;
      }
      *param_5 = *param_5 + 1;
      if (param_3 != (byte *)0x0) {
        *param_3 = *pbVar7;
        param_3 = param_3 + 1;
      }
      pbVar1 = pbVar7 + 1;
      pbVar7 = pbVar7 + 1;
      bVar2 = *pbVar1;
    }
    *param_5 = *param_5 + 1;
    if (param_3 != (byte *)0x0) {
      *param_3 = 0;
      param_3 = param_3 + 1;
    }
    if (*pbVar7 == 0x22) {
      pbVar7 = pbVar7 + 1;
    }
  }
  else {
    do {
      *piVar6 = *piVar6 + 1;
      if (param_3 != (byte *)0x0) {
        *param_3 = *param_1;
        param_3 = param_3 + 1;
      }
      bVar2 = *param_1;
      pbVar7 = param_1 + 1;
      param_5 = (int *)(uint)bVar2;
      if (((&DAT_10012cf9)[(int)param_5] & 4) != 0) {
        *piVar6 = *piVar6 + 1;
        if (param_3 != (byte *)0x0) {
          *param_3 = *pbVar7;
          param_3 = param_3 + 1;
        }
        pbVar7 = param_1 + 2;
      }
      if (bVar2 == 0x20) break;
      if (bVar2 == 0) goto LAB_100090c9;
      param_1 = pbVar7;
    } while (bVar2 != 9);
    if (bVar2 == 0) {
LAB_100090c9:
      pbVar7 = pbVar7 + -1;
    }
    else if (param_3 != (byte *)0x0) {
      param_3[-1] = 0;
    }
  }
  bVar4 = false;
  bVar5 = false;
  while (*pbVar7 != 0) {
    for (; (*pbVar7 == 0x20 || (*pbVar7 == 9)); pbVar7 = pbVar7 + 1) {
    }
    if (*pbVar7 == 0) break;
    if (param_2 != (byte **)0x0) {
      *param_2 = param_3;
      param_2 = param_2 + 1;
    }
    *param_4 = *param_4 + 1;
    while( true ) {
      uVar8 = 0;
      bVar3 = true;
      bVar2 = *pbVar7;
      while (bVar2 == 0x5c) {
        pbVar1 = pbVar7 + 1;
        pbVar7 = pbVar7 + 1;
        uVar8 = uVar8 + 1;
        bVar2 = *pbVar1;
      }
      if (*pbVar7 == 0x22) {
        if ((uVar8 & 1) == 0) {
          if ((bVar4) && (pbVar7[1] == 0x22)) {
            pbVar7 = pbVar7 + 1;
          }
          else {
            bVar3 = false;
          }
          bVar4 = !bVar5;
          bVar5 = bVar4;
        }
        uVar8 = uVar8 >> 1;
      }
      for (; uVar8 != 0; uVar8 = uVar8 - 1) {
        if (param_3 != (byte *)0x0) {
          *param_3 = 0x5c;
          param_3 = param_3 + 1;
        }
        *piVar6 = *piVar6 + 1;
      }
      bVar2 = *pbVar7;
      if ((bVar2 == 0) || ((!bVar4 && ((bVar2 == 0x20 || (bVar2 == 9)))))) break;
      if (bVar3) {
        if (param_3 == (byte *)0x0) {
          if (((&DAT_10012cf9)[bVar2] & 4) != 0) {
            pbVar7 = pbVar7 + 1;
            *piVar6 = *piVar6 + 1;
          }
          *piVar6 = *piVar6 + 1;
          goto LAB_100091c5;
        }
        if (((&DAT_10012cf9)[bVar2] & 4) != 0) {
          *param_3 = bVar2;
          param_3 = param_3 + 1;
          pbVar7 = pbVar7 + 1;
          *piVar6 = *piVar6 + 1;
        }
        *param_3 = *pbVar7;
        param_3 = param_3 + 1;
        *piVar6 = *piVar6 + 1;
        pbVar7 = pbVar7 + 1;
      }
      else {
LAB_100091c5:
        pbVar7 = pbVar7 + 1;
      }
    }
    if (param_3 != (byte *)0x0) {
      *param_3 = 0;
      param_3 = param_3 + 1;
    }
    *piVar6 = *piVar6 + 1;
  }
  if (param_2 != (byte **)0x0) {
    *param_2 = (byte *)0x0;
  }
  *param_4 = *param_4 + 1;
  return;
}



undefined4 * FUN_10009200(void)

{
  char cVar1;
  WCHAR WVar2;
  WCHAR *pWVar3;
  int iVar5;
  int cbMultiByte;
  undefined4 *puVar6;
  uint uVar7;
  uint uVar8;
  undefined4 *puVar9;
  LPWCH lpWideCharStr;
  undefined4 *puVar10;
  undefined4 *puVar11;
  WCHAR *pWVar4;
  
  lpWideCharStr = (LPWCH)0x0;
  puVar9 = (undefined4 *)0x0;
  if (DAT_10013068 == 0) {
    lpWideCharStr = GetEnvironmentStringsW();
    if (lpWideCharStr == (LPWCH)0x0) {
      puVar9 = (undefined4 *)GetEnvironmentStrings();
      if (puVar9 == (undefined4 *)0x0) {
        return (undefined4 *)0x0;
      }
      DAT_10013068 = 2;
    }
    else {
      DAT_10013068 = 1;
    }
  }
  if (DAT_10013068 == 1) {
    if ((lpWideCharStr != (LPWCH)0x0) ||
       (lpWideCharStr = GetEnvironmentStringsW(), lpWideCharStr != (LPWCH)0x0)) {
      WVar2 = *lpWideCharStr;
      pWVar3 = lpWideCharStr;
      while (WVar2 != L'\0') {
        do {
          pWVar4 = pWVar3;
          pWVar3 = pWVar4 + 1;
        } while (*pWVar3 != L'\0');
        pWVar3 = pWVar4 + 2;
        WVar2 = *pWVar3;
      }
      iVar5 = ((int)pWVar3 - (int)lpWideCharStr >> 1) + 1;
      cbMultiByte = WideCharToMultiByte(0,0,lpWideCharStr,iVar5,(LPSTR)0x0,0,(LPCSTR)0x0,(LPBOOL)0x0
                                       );
      if ((cbMultiByte != 0) &&
         (puVar9 = (undefined4 *)FUN_10005410(cbMultiByte), puVar9 != (undefined4 *)0x0)) {
        iVar5 = WideCharToMultiByte(0,0,lpWideCharStr,iVar5,(LPSTR)puVar9,cbMultiByte,(LPCSTR)0x0,
                                    (LPBOOL)0x0);
        if (iVar5 == 0) {
          FUN_100053a0(puVar9);
          puVar9 = (undefined4 *)0x0;
        }
        FreeEnvironmentStringsW(lpWideCharStr);
        return puVar9;
      }
      FreeEnvironmentStringsW(lpWideCharStr);
      return (undefined4 *)0x0;
    }
  }
  else if ((DAT_10013068 == 2) &&
          ((puVar9 != (undefined4 *)0x0 ||
           (puVar9 = (undefined4 *)GetEnvironmentStrings(), puVar9 != (undefined4 *)0x0)))) {
    cVar1 = *(char *)puVar9;
    puVar6 = puVar9;
    while (cVar1 != '\0') {
      do {
        puVar10 = puVar6;
        puVar6 = (undefined4 *)((int)puVar10 + 1);
      } while (*(char *)((int)puVar10 + 1) != '\0');
      puVar6 = (undefined4 *)((int)puVar10 + 2);
      cVar1 = *(char *)((int)puVar10 + 2);
    }
    uVar7 = (int)puVar6 + (1 - (int)puVar9);
    puVar6 = (undefined4 *)FUN_10005410(uVar7);
    if (puVar6 != (undefined4 *)0x0) {
      puVar10 = puVar9;
      puVar11 = puVar6;
      for (uVar8 = uVar7 >> 2; uVar8 != 0; uVar8 = uVar8 - 1) {
        *puVar11 = *puVar10;
        puVar10 = puVar10 + 1;
        puVar11 = puVar11 + 1;
      }
      for (uVar7 = uVar7 & 3; uVar7 != 0; uVar7 = uVar7 - 1) {
        *(undefined *)puVar11 = *(undefined *)puVar10;
        puVar10 = (undefined4 *)((int)puVar10 + 1);
        puVar11 = (undefined4 *)((int)puVar11 + 1);
      }
      FreeEnvironmentStringsA((LPCH)puVar9);
      return puVar6;
    }
    FreeEnvironmentStringsA((LPCH)puVar9);
    return (undefined4 *)0x0;
  }
  return (undefined4 *)0x0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_10009360(void)

{
  if ((DAT_10012c50 == 1) || ((DAT_10012c50 == 0 && (_DAT_10012c54 == 1)))) {
    FUN_100093a0(0xfc);
    if (DAT_1001306c != (code *)0x0) {
      (*DAT_1001306c)();
    }
    FUN_100093a0(0xff);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_100093a0(int param_1)

{
  char cVar1;
  int *piVar2;
  DWORD DVar3;
  HANDLE hFile;
  int iVar4;
  uint uVar5;
  uint uVar6;
  undefined4 *puVar7;
  int iVar8;
  undefined4 *puVar9;
  undefined4 *puVar10;
  char *pcVar11;
  char *pcVar12;
  DWORD local_1a8;
  undefined4 auStack_1a4 [25];
  undefined4 auStack_140 [15];
  undefined4 local_104;
  
  piVar2 = &DAT_10011a88;
  iVar8 = 0;
  do {
    if (param_1 == *piVar2) break;
    piVar2 = piVar2 + 2;
    iVar8 = iVar8 + 1;
  } while (piVar2 < (int *)0x10011b18);
  if (param_1 == (&DAT_10011a88)[iVar8 * 2]) {
    if ((DAT_10012c50 == 1) || ((DAT_10012c50 == 0 && (_DAT_10012c54 == 1)))) {
      if ((DAT_10015080 == 0) ||
         (hFile = *(HANDLE *)(DAT_10015080 + 0x48), hFile == (HANDLE)0xffffffff)) {
        hFile = GetStdHandle(0xfffffff4);
      }
      pcVar11 = *(char **)(iVar8 * 8 + 0x10011a8c);
      uVar5 = 0xffffffff;
      pcVar12 = pcVar11;
      do {
        if (uVar5 == 0) break;
        uVar5 = uVar5 - 1;
        cVar1 = *pcVar12;
        pcVar12 = pcVar12 + 1;
      } while (cVar1 != '\0');
      WriteFile(hFile,pcVar11,~uVar5 - 1,&local_1a8,(LPOVERLAPPED)0x0);
    }
    else if (param_1 != 0xfc) {
      DVar3 = GetModuleFileNameA((HMODULE)0x0,(LPSTR)&local_104,0x104);
      if (DVar3 == 0) {
        puVar7 = (undefined4 *)"<program name unknown>";
        puVar9 = &local_104;
        for (iVar4 = 5; iVar4 != 0; iVar4 = iVar4 + -1) {
          *puVar9 = *puVar7;
          puVar7 = puVar7 + 1;
          puVar9 = puVar9 + 1;
        }
        *(undefined2 *)puVar9 = *(undefined2 *)puVar7;
        *(undefined *)((int)puVar9 + 2) = *(undefined *)((int)puVar7 + 2);
      }
      uVar5 = 0xffffffff;
      puVar7 = &local_104;
      puVar9 = &local_104;
      do {
        if (uVar5 == 0) break;
        uVar5 = uVar5 - 1;
        cVar1 = *(char *)puVar9;
        puVar9 = (undefined4 *)((int)puVar9 + 1);
      } while (cVar1 != '\0');
      if (0x3c < ~uVar5) {
        uVar5 = 0xffffffff;
        puVar7 = &local_104;
        do {
          if (uVar5 == 0) break;
          uVar5 = uVar5 - 1;
          cVar1 = *(char *)puVar7;
          puVar7 = (undefined4 *)((int)puVar7 + 1);
        } while (cVar1 != '\0');
        puVar7 = (undefined4 *)((int)auStack_140 + ~uVar5);
        _strncpy((char *)puVar7,"...",3);
      }
      puVar9 = (undefined4 *)"Runtime Error!\n\nProgram: ";
      puVar10 = auStack_1a4;
      for (iVar4 = 6; iVar4 != 0; iVar4 = iVar4 + -1) {
        *puVar10 = *puVar9;
        puVar9 = puVar9 + 1;
        puVar10 = puVar10 + 1;
      }
      *(undefined2 *)puVar10 = *(undefined2 *)puVar9;
      uVar5 = 0xffffffff;
      do {
        puVar9 = puVar7;
        if (uVar5 == 0) break;
        uVar5 = uVar5 - 1;
        puVar9 = (undefined4 *)((int)puVar7 + 1);
        cVar1 = *(char *)puVar7;
        puVar7 = puVar9;
      } while (cVar1 != '\0');
      uVar5 = ~uVar5;
      iVar4 = -1;
      puVar7 = auStack_1a4;
      do {
        puVar10 = puVar7;
        if (iVar4 == 0) break;
        iVar4 = iVar4 + -1;
        puVar10 = (undefined4 *)((int)puVar7 + 1);
        cVar1 = *(char *)puVar7;
        puVar7 = puVar10;
      } while (cVar1 != '\0');
      puVar7 = (undefined4 *)((int)puVar9 - uVar5);
      puVar9 = (undefined4 *)((int)puVar10 + -1);
      for (uVar6 = uVar5 >> 2; uVar6 != 0; uVar6 = uVar6 - 1) {
        *puVar9 = *puVar7;
        puVar7 = puVar7 + 1;
        puVar9 = puVar9 + 1;
      }
      for (uVar5 = uVar5 & 3; uVar5 != 0; uVar5 = uVar5 - 1) {
        *(undefined *)puVar9 = *(undefined *)puVar7;
        puVar7 = (undefined4 *)((int)puVar7 + 1);
        puVar9 = (undefined4 *)((int)puVar9 + 1);
      }
      uVar5 = 0xffffffff;
      pcVar11 = "\n\n";
      do {
        pcVar12 = pcVar11;
        if (uVar5 == 0) break;
        uVar5 = uVar5 - 1;
        pcVar12 = pcVar11 + 1;
        cVar1 = *pcVar11;
        pcVar11 = pcVar12;
      } while (cVar1 != '\0');
      uVar5 = ~uVar5;
      iVar4 = -1;
      puVar7 = auStack_1a4;
      do {
        puVar9 = puVar7;
        if (iVar4 == 0) break;
        iVar4 = iVar4 + -1;
        puVar9 = (undefined4 *)((int)puVar7 + 1);
        cVar1 = *(char *)puVar7;
        puVar7 = puVar9;
      } while (cVar1 != '\0');
      puVar7 = (undefined4 *)(pcVar12 + -uVar5);
      puVar9 = (undefined4 *)((int)puVar9 + -1);
      for (uVar6 = uVar5 >> 2; uVar6 != 0; uVar6 = uVar6 - 1) {
        *puVar9 = *puVar7;
        puVar7 = puVar7 + 1;
        puVar9 = puVar9 + 1;
      }
      for (uVar5 = uVar5 & 3; uVar5 != 0; uVar5 = uVar5 - 1) {
        *(undefined *)puVar9 = *(undefined *)puVar7;
        puVar7 = (undefined4 *)((int)puVar7 + 1);
        puVar9 = (undefined4 *)((int)puVar9 + 1);
      }
      uVar5 = 0xffffffff;
      pcVar11 = *(char **)(iVar8 * 8 + 0x10011a8c);
      do {
        pcVar12 = pcVar11;
        if (uVar5 == 0) break;
        uVar5 = uVar5 - 1;
        pcVar12 = pcVar11 + 1;
        cVar1 = *pcVar11;
        pcVar11 = pcVar12;
      } while (cVar1 != '\0');
      uVar5 = ~uVar5;
      iVar8 = -1;
      puVar7 = auStack_1a4;
      do {
        puVar9 = puVar7;
        if (iVar8 == 0) break;
        iVar8 = iVar8 + -1;
        puVar9 = (undefined4 *)((int)puVar7 + 1);
        cVar1 = *(char *)puVar7;
        puVar7 = puVar9;
      } while (cVar1 != '\0');
      puVar7 = (undefined4 *)(pcVar12 + -uVar5);
      puVar9 = (undefined4 *)((int)puVar9 + -1);
      for (uVar6 = uVar5 >> 2; uVar6 != 0; uVar6 = uVar6 - 1) {
        *puVar9 = *puVar7;
        puVar7 = puVar7 + 1;
        puVar9 = puVar9 + 1;
      }
      for (uVar5 = uVar5 & 3; uVar5 != 0; uVar5 = uVar5 - 1) {
        *(undefined *)puVar9 = *(undefined *)puVar7;
        puVar7 = (undefined4 *)((int)puVar7 + 1);
        puVar9 = (undefined4 *)((int)puVar9 + 1);
      }
      FUN_1000ac90(auStack_1a4,"Microsoft Visual C++ Runtime Library");
      return;
    }
  }
  return;
}



void FUN_10009660(int *param_1)

{
  int iVar1;
  
  DAT_10013070 = DAT_10013070 + 1;
  iVar1 = FUN_10005410(0x1000);
  param_1[2] = iVar1;
  if (iVar1 != 0) {
    param_1[3] = param_1[3] | 8;
    param_1[6] = 0x1000;
    *param_1 = param_1[2];
    param_1[1] = 0;
    return;
  }
  param_1[6] = 2;
  param_1[3] = param_1[3] | 4;
  param_1[2] = (int)(param_1 + 5);
  *param_1 = (int)(param_1 + 5);
  param_1[1] = 0;
  return;
}



byte FUN_100096c0(uint param_1)

{
  if (DAT_10015180 <= param_1) {
    return 0;
  }
  return *(byte *)((&DAT_10015080)[(int)param_1 >> 5] + 4 + (param_1 & 0x1f) * 0x24) & 0x40;
}



undefined4 FUN_100096f0(undefined4 param_1,undefined4 param_2)

{
  undefined4 uVar1;
  bool bVar2;
  
  InterlockedIncrement((LONG *)&DAT_1001518c);
  bVar2 = DAT_10015188 != 0;
  if (bVar2) {
    InterlockedDecrement((LONG *)&DAT_1001518c);
    FUN_10006360(0x13);
  }
  uVar1 = FUN_10009760(param_1,param_2);
  if (!bVar2) {
    InterlockedDecrement((LONG *)&DAT_1001518c);
    return uVar1;
  }
  FUN_100063e0(0x13);
  return uVar1;
}



LPSTR FUN_10009760(LPSTR param_1,WCHAR param_2)

{
  LPSTR pCVar1;
  undefined4 *puVar2;
  
  pCVar1 = param_1;
  if (param_1 == (LPSTR)0x0) {
    return param_1;
  }
  if (DAT_10012cd8 == 0) {
    if ((ushort)param_2 < 0x100) {
      *param_1 = (CHAR)param_2;
      return (LPSTR)0x1;
    }
  }
  else {
    param_1 = (LPSTR)0x0;
    pCVar1 = (LPSTR)WideCharToMultiByte(DAT_10012ce8,0x220,&param_2,1,pCVar1,DAT_100117f4,
                                        (LPCSTR)0x0,(LPBOOL)&param_1);
    if ((pCVar1 != (LPSTR)0x0) && (param_1 == (LPSTR)0x0)) {
      return pCVar1;
    }
  }
  puVar2 = (undefined4 *)FUN_10008600();
  *puVar2 = 0x2a;
  return (LPSTR)0xffffffff;
}



// Library Function - Single Match
//  __aulldiv
// 
// Library: Visual Studio

undefined8 __aulldiv(uint param_1,uint param_2,uint param_3,uint param_4)

{
  ulonglong uVar1;
  longlong lVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  
  uVar3 = param_1;
  uVar8 = param_4;
  uVar6 = param_2;
  uVar9 = param_3;
  if (param_4 == 0) {
    uVar3 = param_2 / param_3;
    iVar4 = (int)(((ulonglong)param_2 % (ulonglong)param_3 << 0x20 | (ulonglong)param_1) /
                 (ulonglong)param_3);
  }
  else {
    do {
      uVar5 = uVar8 >> 1;
      uVar9 = uVar9 >> 1 | (uint)((uVar8 & 1) != 0) << 0x1f;
      uVar7 = uVar6 >> 1;
      uVar3 = uVar3 >> 1 | (uint)((uVar6 & 1) != 0) << 0x1f;
      uVar8 = uVar5;
      uVar6 = uVar7;
    } while (uVar5 != 0);
    uVar1 = CONCAT44(uVar7,uVar3) / (ulonglong)uVar9;
    iVar4 = (int)uVar1;
    lVar2 = (ulonglong)param_3 * (uVar1 & 0xffffffff);
    uVar3 = (uint)((ulonglong)lVar2 >> 0x20);
    uVar8 = uVar3 + iVar4 * param_4;
    if (((CARRY4(uVar3,iVar4 * param_4)) || (param_2 < uVar8)) ||
       ((param_2 <= uVar8 && (param_1 < (uint)lVar2)))) {
      iVar4 = iVar4 + -1;
    }
    uVar3 = 0;
  }
  return CONCAT44(uVar3,iVar4);
}



// Library Function - Single Match
//  __aullrem
// 
// Library: Visual Studio

undefined8 __aullrem(uint param_1,uint param_2,uint param_3,uint param_4)

{
  ulonglong uVar1;
  longlong lVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  bool bVar11;
  
  uVar3 = param_1;
  uVar4 = param_4;
  uVar9 = param_2;
  uVar10 = param_3;
  if (param_4 == 0) {
    iVar6 = (int)(((ulonglong)param_2 % (ulonglong)param_3 << 0x20 | (ulonglong)param_1) %
                 (ulonglong)param_3);
    iVar7 = 0;
  }
  else {
    do {
      uVar5 = uVar4 >> 1;
      uVar10 = uVar10 >> 1 | (uint)((uVar4 & 1) != 0) << 0x1f;
      uVar8 = uVar9 >> 1;
      uVar3 = uVar3 >> 1 | (uint)((uVar9 & 1) != 0) << 0x1f;
      uVar4 = uVar5;
      uVar9 = uVar8;
    } while (uVar5 != 0);
    uVar1 = CONCAT44(uVar8,uVar3) / (ulonglong)uVar10;
    uVar3 = (int)uVar1 * param_4;
    lVar2 = (uVar1 & 0xffffffff) * (ulonglong)param_3;
    uVar9 = (uint)((ulonglong)lVar2 >> 0x20);
    uVar4 = (uint)lVar2;
    uVar10 = uVar9 + uVar3;
    if (((CARRY4(uVar9,uVar3)) || (param_2 < uVar10)) || ((param_2 <= uVar10 && (param_1 < uVar4))))
    {
      bVar11 = uVar4 < param_3;
      uVar4 = uVar4 - param_3;
      uVar10 = (uVar10 - param_4) - (uint)bVar11;
    }
    iVar6 = -(uVar4 - param_1);
    iVar7 = -(uint)(uVar4 - param_1 != 0) - ((uVar10 - param_2) - (uint)(uVar4 < param_1));
  }
  return CONCAT44(iVar7,iVar6);
}



uint FUN_10009980(int param_1)

{
  undefined2 uVar1;
  undefined2 uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  uint uVar11;
  uint uVar12;
  uint uVar13;
  uint uVar14;
  uint uVar15;
  uint uVar16;
  uint uVar17;
  uint uVar18;
  uint uVar19;
  uint uVar20;
  uint uVar21;
  uint uVar22;
  uint uVar23;
  uint uVar24;
  uint uVar25;
  uint uVar26;
  uint uVar27;
  uint uVar28;
  uint uVar29;
  uint uVar30;
  uint uVar31;
  uint uVar32;
  uint uVar33;
  uint uVar34;
  uint uVar35;
  uint uVar36;
  uint uVar37;
  uint uVar38;
  uint uVar39;
  uint uVar40;
  uint uVar41;
  uint uVar42;
  uint uVar43;
  uint uVar44;
  uint uVar45;
  
  uVar2 = DAT_100130b0;
  uVar1 = DAT_100130ae;
  if (param_1 == 0) {
    return 0xffffffff;
  }
  uVar3 = FUN_1000add0(1,DAT_100130ae,0x31,param_1 + 4);
  uVar4 = FUN_1000add0(1,uVar1,0x32,param_1 + 8);
  uVar5 = FUN_1000add0(1,uVar1,0x33,param_1 + 0xc);
  uVar6 = FUN_1000add0(1,uVar1,0x34,param_1 + 0x10);
  uVar7 = FUN_1000add0(1,uVar1,0x35,param_1 + 0x14);
  uVar8 = FUN_1000add0(1,uVar1,0x36,param_1 + 0x18);
  uVar9 = FUN_1000add0(1,uVar1,0x37,param_1);
  uVar10 = FUN_1000add0(1,uVar1,0x2a,param_1 + 0x20);
  uVar11 = FUN_1000add0(1,uVar1,0x2b,param_1 + 0x24);
  uVar12 = FUN_1000add0(1,uVar1,0x2c,param_1 + 0x28);
  uVar13 = FUN_1000add0(1,uVar1,0x2d,param_1 + 0x2c);
  uVar14 = FUN_1000add0(1,uVar1,0x2e,param_1 + 0x30);
  uVar15 = FUN_1000add0(1,uVar1,0x2f,param_1 + 0x34);
  uVar16 = FUN_1000add0(1,uVar1,0x30,param_1 + 0x1c);
  uVar17 = FUN_1000add0(1,uVar1,0x44,param_1 + 0x38);
  uVar18 = FUN_1000add0(1,uVar1,0x45,param_1 + 0x3c);
  uVar19 = FUN_1000add0(1,uVar1,0x46,param_1 + 0x40);
  uVar20 = FUN_1000add0(1,uVar1,0x47,param_1 + 0x44);
  uVar21 = FUN_1000add0(1,uVar1,0x48,param_1 + 0x48);
  uVar22 = FUN_1000add0(1,uVar1,0x49,param_1 + 0x4c);
  uVar23 = FUN_1000add0(1,uVar1,0x4a,param_1 + 0x50);
  uVar24 = FUN_1000add0(1,uVar1,0x4b,param_1 + 0x54);
  uVar25 = FUN_1000add0(1,uVar1,0x4c,param_1 + 0x58);
  uVar26 = FUN_1000add0(1,uVar1,0x4d,param_1 + 0x5c);
  uVar27 = FUN_1000add0(1,uVar1,0x4e,param_1 + 0x60);
  uVar28 = FUN_1000add0(1,uVar1,0x4f,param_1 + 100);
  uVar29 = FUN_1000add0(1,uVar1,0x38,param_1 + 0x68);
  uVar30 = FUN_1000add0(1,uVar1,0x39,param_1 + 0x6c);
  uVar31 = FUN_1000add0(1,uVar1,0x3a,param_1 + 0x70);
  uVar32 = FUN_1000add0(1,uVar1,0x3b,param_1 + 0x74);
  uVar33 = FUN_1000add0(1,uVar1,0x3c,param_1 + 0x78);
  uVar34 = FUN_1000add0(1,uVar1,0x3d,param_1 + 0x7c);
  uVar35 = FUN_1000add0(1,uVar1,0x3e,param_1 + 0x80);
  uVar36 = FUN_1000add0(1,uVar1,0x3f,param_1 + 0x84);
  uVar37 = FUN_1000add0(1,uVar1,0x40,param_1 + 0x88);
  uVar38 = FUN_1000add0(1,uVar1,0x41,param_1 + 0x8c);
  uVar39 = FUN_1000add0(1,uVar1,0x42,param_1 + 0x90);
  uVar40 = FUN_1000add0(1,uVar1,0x43,param_1 + 0x94);
  uVar41 = FUN_1000add0(1,uVar1,0x28,param_1 + 0x98);
  uVar42 = FUN_1000add0(1,uVar1,0x29,param_1 + 0x9c);
  uVar43 = FUN_1000add0(1,uVar2,0x1f,param_1 + 0xa0);
  uVar44 = FUN_1000add0(1,uVar2,0x20,param_1 + 0xa4);
  uVar45 = FUN_10009f40(uVar2,param_1);
  return uVar3 | uVar4 | uVar5 | uVar6 | uVar7 | uVar8 | uVar9 | uVar10 | uVar11 | uVar12 | uVar13 |
         uVar14 | uVar15 | uVar16 | uVar17 | uVar18 | uVar19 | uVar20 | uVar21 | uVar22 | uVar23 |
         uVar24 | uVar25 | uVar26 | uVar27 | uVar28 | uVar29 | uVar30 | uVar31 | uVar32 | uVar33 |
         uVar34 | uVar35 | uVar36 | uVar37 | uVar38 | uVar39 | uVar40 | uVar41 | uVar42 | uVar43 |
         uVar44 | uVar45;
}



void FUN_10009d00(undefined4 *param_1)

{
  if (param_1 != (undefined4 *)0x0) {
    FUN_100053a0(param_1[1]);
    FUN_100053a0(param_1[2]);
    FUN_100053a0(param_1[3]);
    FUN_100053a0(param_1[4]);
    FUN_100053a0(param_1[5]);
    FUN_100053a0(param_1[6]);
    FUN_100053a0(*param_1);
    FUN_100053a0(param_1[8]);
    FUN_100053a0(param_1[9]);
    FUN_100053a0(param_1[10]);
    FUN_100053a0(param_1[0xb]);
    FUN_100053a0(param_1[0xc]);
    FUN_100053a0(param_1[0xd]);
    FUN_100053a0(param_1[7]);
    FUN_100053a0(param_1[0xe]);
    FUN_100053a0(param_1[0xf]);
    FUN_100053a0(param_1[0x10]);
    FUN_100053a0(param_1[0x11]);
    FUN_100053a0(param_1[0x12]);
    FUN_100053a0(param_1[0x13]);
    FUN_100053a0(param_1[0x14]);
    FUN_100053a0(param_1[0x15]);
    FUN_100053a0(param_1[0x16]);
    FUN_100053a0(param_1[0x17]);
    FUN_100053a0(param_1[0x18]);
    FUN_100053a0(param_1[0x19]);
    FUN_100053a0(param_1[0x1a]);
    FUN_100053a0(param_1[0x1b]);
    FUN_100053a0(param_1[0x1c]);
    FUN_100053a0(param_1[0x1d]);
    FUN_100053a0(param_1[0x1e]);
    FUN_100053a0(param_1[0x1f]);
    FUN_100053a0(param_1[0x20]);
    FUN_100053a0(param_1[0x21]);
    FUN_100053a0(param_1[0x22]);
    FUN_100053a0(param_1[0x23]);
    FUN_100053a0(param_1[0x24]);
    FUN_100053a0(param_1[0x25]);
    FUN_100053a0(param_1[0x26]);
    FUN_100053a0(param_1[0x27]);
    FUN_100053a0(param_1[0x28]);
    FUN_100053a0(param_1[0x29]);
    FUN_100053a0(param_1[0x2a]);
  }
  return;
}



uint FUN_10009f40(char *param_1,int param_2)

{
  char *pcVar1;
  char cVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  undefined *puVar6;
  char *pcVar7;
  char *pcVar8;
  int local_8;
  int local_4;
  
  pcVar7 = param_1;
  local_4 = 0;
  local_8 = 0;
  uVar3 = FUN_1000add0(0,param_1,0x23,&local_4);
  uVar4 = FUN_1000add0(0,pcVar7,0x25,&local_8);
  uVar5 = FUN_1000add0(1,pcVar7,0x1e,&param_1);
  uVar5 = uVar3 | uVar4 | uVar5;
  if (uVar5 != 0) {
    return uVar5;
  }
  puVar6 = (undefined *)FUN_10005410(0xd);
  *(undefined **)(param_2 + 0xa8) = puVar6;
  if (local_4 == 0) {
    *puVar6 = 0x68;
    pcVar7 = puVar6 + 1;
    if (local_8 == 0) goto LAB_10009fdc;
    *pcVar7 = 'h';
  }
  else {
    *puVar6 = 0x48;
    pcVar7 = puVar6 + 1;
    if (local_8 == 0) goto LAB_10009fdc;
    *pcVar7 = 'H';
  }
  pcVar7 = puVar6 + 2;
LAB_10009fdc:
  cVar2 = *param_1;
  pcVar8 = param_1;
  while (cVar2 != '\0') {
    *pcVar7 = cVar2;
    pcVar1 = pcVar8 + 1;
    pcVar7 = pcVar7 + 1;
    pcVar8 = pcVar8 + 1;
    cVar2 = *pcVar1;
  }
  *pcVar7 = 'm';
  pcVar8 = pcVar7 + 1;
  if (local_8 != 0) {
    *pcVar8 = 'm';
    pcVar8 = pcVar7 + 2;
  }
  cVar2 = *param_1;
  pcVar7 = param_1;
  while (cVar2 != '\0') {
    *pcVar8 = cVar2;
    pcVar1 = pcVar7 + 1;
    pcVar8 = pcVar8 + 1;
    pcVar7 = pcVar7 + 1;
    cVar2 = *pcVar1;
  }
  *pcVar8 = 's';
  pcVar8[1] = 's';
  pcVar8[2] = '\0';
  FUN_100053a0(param_1);
  return 0;
}



uint FUN_1000a330(int param_1)

{
  undefined2 uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  uint uVar11;
  uint uVar12;
  uint uVar13;
  uint uVar14;
  uint uVar15;
  uint uVar16;
  
  uVar1 = DAT_100130a4;
  if (param_1 == 0) {
    return 0xffffffff;
  }
  uVar2 = FUN_1000add0(1,DAT_100130a4,0x15,param_1 + 0xc);
  uVar3 = FUN_1000add0(1,uVar1,0x14,param_1 + 0x10);
  uVar4 = FUN_1000add0(1,uVar1,0x16,param_1 + 0x14);
  uVar5 = FUN_1000add0(1,uVar1,0x17,param_1 + 0x18);
  uVar6 = FUN_1000add0(1,uVar1,0x18,(undefined4 *)(param_1 + 0x1c));
  FUN_1000a480(*(undefined4 *)(param_1 + 0x1c));
  uVar7 = FUN_1000add0(1,uVar1,0x50,param_1 + 0x20);
  uVar8 = FUN_1000add0(1,uVar1,0x51,param_1 + 0x24);
  uVar9 = FUN_1000add0(0,uVar1,0x1a,param_1 + 0x28);
  uVar10 = FUN_1000add0(0,uVar1,0x19,param_1 + 0x29);
  uVar11 = FUN_1000add0(0,uVar1,0x54,param_1 + 0x2a);
  uVar12 = FUN_1000add0(0,uVar1,0x55,param_1 + 0x2b);
  uVar13 = FUN_1000add0(0,uVar1,0x56,param_1 + 0x2c);
  uVar14 = FUN_1000add0(0,uVar1,0x57,param_1 + 0x2d);
  uVar15 = FUN_1000add0(0,uVar1,0x52,param_1 + 0x2e);
  uVar16 = FUN_1000add0(0,uVar1,0x53,param_1 + 0x2f);
  return uVar2 | uVar3 | uVar4 | uVar5 | uVar6 | uVar7 | uVar8 | uVar9 | uVar10 | uVar11 | uVar12 |
         uVar13 | uVar14 | uVar15 | uVar16;
}



void FUN_1000a480(char *param_1)

{
  char *pcVar1;
  char cVar2;
  char *pcVar3;
  
  cVar2 = *param_1;
  do {
    if (cVar2 == '\0') {
      return;
    }
    if ((cVar2 < '0') || ('9' < cVar2)) {
      pcVar3 = param_1;
      if (cVar2 != ';') goto LAB_1000a496;
      do {
        *pcVar3 = pcVar3[1];
        pcVar1 = pcVar3 + 1;
        pcVar3 = pcVar3 + 1;
      } while (*pcVar1 != '\0');
    }
    else {
      *param_1 = cVar2 + -0x30;
LAB_1000a496:
      param_1 = param_1 + 1;
    }
    cVar2 = *param_1;
  } while( true );
}



void FUN_1000a4c0(int param_1)

{
  if ((param_1 != 0) && (*(undefined **)(param_1 + 0xc) != &DAT_10013100)) {
    FUN_100053a0(*(undefined **)(param_1 + 0xc));
    FUN_100053a0(*(undefined4 *)(param_1 + 0x10));
    FUN_100053a0(*(undefined4 *)(param_1 + 0x14));
    FUN_100053a0(*(undefined4 *)(param_1 + 0x18));
    FUN_100053a0(*(undefined4 *)(param_1 + 0x1c));
    FUN_100053a0(*(undefined4 *)(param_1 + 0x20));
    FUN_100053a0(*(undefined4 *)(param_1 + 0x24));
  }
  return;
}



// Library Function - Single Match
//  _strcspn
// 
// Libraries: Visual Studio 1998 Debug, Visual Studio 1998 Release

size_t __cdecl _strcspn(char *_Str,char *_Control)

{
  byte bVar1;
  byte *pbVar2;
  size_t sVar3;
  undefined4 uStack_28;
  undefined4 uStack_24;
  undefined4 uStack_20;
  undefined4 uStack_1c;
  undefined4 uStack_18;
  undefined4 uStack_14;
  undefined4 uStack_10;
  undefined4 uStack_c;
  
  uStack_c = 0;
  uStack_10 = 0;
  uStack_14 = 0;
  uStack_18 = 0;
  uStack_1c = 0;
  uStack_20 = 0;
  uStack_24 = 0;
  uStack_28 = 0;
  while( true ) {
    bVar1 = *_Control;
    if (bVar1 == 0) break;
    _Control = (char *)((byte *)_Control + 1);
    pbVar2 = (byte *)((int)&uStack_28 + ((int)(uint)bVar1 >> 3));
    *pbVar2 = *pbVar2 | '\x01' << (bVar1 & 7);
  }
  sVar3 = 0xffffffff;
  do {
    sVar3 = sVar3 + 1;
    bVar1 = *_Str;
    if (bVar1 == 0) {
      return sVar3;
    }
    _Str = (char *)((byte *)_Str + 1);
  } while ((*(byte *)((int)&uStack_28 + ((int)(uint)bVar1 >> 3)) >> (bVar1 & 7) & 1) == 0);
  return sVar3;
}



// Library Function - Single Match
//  _strpbrk
// 
// Libraries: Visual Studio 1998 Debug, Visual Studio 1998 Release

char * __cdecl _strpbrk(char *_Str,char *_Control)

{
  byte bVar1;
  byte *pbVar2;
  undefined4 uStack_28;
  undefined4 uStack_24;
  undefined4 uStack_20;
  undefined4 uStack_1c;
  undefined4 uStack_18;
  undefined4 uStack_14;
  undefined4 uStack_10;
  undefined4 uStack_c;
  
  uStack_c = 0;
  uStack_10 = 0;
  uStack_14 = 0;
  uStack_18 = 0;
  uStack_1c = 0;
  uStack_20 = 0;
  uStack_24 = 0;
  uStack_28 = 0;
  while( true ) {
    bVar1 = *_Control;
    if (bVar1 == 0) break;
    _Control = (char *)((byte *)_Control + 1);
    pbVar2 = (byte *)((int)&uStack_28 + ((int)(uint)bVar1 >> 3));
    *pbVar2 = *pbVar2 | '\x01' << (bVar1 & 7);
  }
  do {
    pbVar2 = (byte *)_Str;
    bVar1 = *pbVar2;
    if (bVar1 == 0) {
      return (char *)(uint)bVar1;
    }
    _Str = (char *)(pbVar2 + 1);
  } while ((*(byte *)((int)&uStack_28 + ((int)(char *)(uint)bVar1 >> 3)) >> (bVar1 & 7) & 1) == 0);
  return (char *)pbVar2;
}



BOOL FUN_1000a870(DWORD param_1,LPCWSTR param_2,int param_3,LPWORD param_4,UINT param_5,LCID param_6
                 )

{
  BOOL BVar1;
  int cbMultiByte;
  LPCSTR lpMultiByteStr;
  int iVar2;
  LPWORD lpCharType;
  int local_4;
  
  lpCharType = (LPWORD)0x0;
  if (DAT_100130d8 == 0) {
    BVar1 = GetStringTypeW(1,L"",1,(LPWORD)&local_4);
    if (BVar1 == 0) {
      BVar1 = GetStringTypeA(0,1,"",1,(LPWORD)&local_4);
      if (BVar1 == 0) {
        return 0;
      }
      DAT_100130d8 = 2;
    }
    else {
      DAT_100130d8 = 1;
    }
  }
  if (DAT_100130d8 != 1) {
    local_4 = DAT_100130d8;
    if (DAT_100130d8 == 2) {
      local_4 = 0;
      if (param_5 == 0) {
        param_5 = DAT_10012ce8;
      }
      cbMultiByte = WideCharToMultiByte(param_5,0x220,param_2,param_3,(LPSTR)0x0,0,(LPCSTR)0x0,
                                        (LPBOOL)0x0);
      if (cbMultiByte == 0) {
        return 0;
      }
      lpMultiByteStr = (LPCSTR)FUN_1000abe0(1,cbMultiByte);
      if (lpMultiByteStr == (LPCSTR)0x0) {
        return 0;
      }
      iVar2 = WideCharToMultiByte(param_5,0x220,param_2,param_3,lpMultiByteStr,cbMultiByte,
                                  (LPCSTR)0x0,(LPBOOL)0x0);
      if ((iVar2 != 0) &&
         (lpCharType = (LPWORD)FUN_10005410(cbMultiByte * 2 + 2), lpCharType != (LPWORD)0x0)) {
        if (param_6 == 0) {
          param_6 = DAT_10012cd8;
        }
        lpCharType[param_3] = 0xffff;
        lpCharType[param_3 + -1] = 0xffff;
        local_4 = GetStringTypeA(param_6,param_1,lpMultiByteStr,cbMultiByte,lpCharType);
        if ((lpCharType[param_3 + -1] == 0xffff) || (lpCharType[param_3] != 0xffff)) {
          local_4 = 0;
        }
        else {
          FUN_1000b160(param_4,lpCharType,param_3 * 2);
        }
      }
      FUN_100053a0(lpMultiByteStr);
      FUN_100053a0(lpCharType);
    }
    return local_4;
  }
  BVar1 = GetStringTypeW(param_1,param_2,param_3,param_4);
  return BVar1;
}



BOOL FUN_1000aa00(DWORD param_1,LPCSTR param_2,int param_3,LPWORD param_4,UINT param_5,LCID param_6,
                 int param_7)

{
  BOOL BVar1;
  int iVar2;
  LPCWSTR lpWideCharStr;
  WORD local_2;
  
  lpWideCharStr = (LPCWSTR)0x0;
  if (DAT_100130dc == 0) {
    BVar1 = GetStringTypeW(1,L"",1,&local_2);
    if (BVar1 == 0) {
      BVar1 = GetStringTypeA(0,1,"",1,&local_2);
      if (BVar1 == 0) {
        return 0;
      }
      DAT_100130dc = 2;
    }
    else {
      DAT_100130dc = 1;
    }
  }
  if (DAT_100130dc == 2) {
    if (param_6 == 0) {
      param_6 = DAT_10012cd8;
    }
    BVar1 = GetStringTypeA(param_6,param_1,param_2,param_3,param_4);
    return BVar1;
  }
  param_6 = DAT_100130dc;
  if (DAT_100130dc == 1) {
    param_6 = 0;
    if (param_5 == 0) {
      param_5 = DAT_10012ce8;
    }
    iVar2 = MultiByteToWideChar(param_5,(-(uint)(param_7 != 0) & 8) + 1,param_2,param_3,(LPWSTR)0x0,
                                0);
    if (iVar2 != 0) {
      lpWideCharStr = (LPCWSTR)FUN_1000abe0(2,iVar2);
      if (lpWideCharStr != (LPCWSTR)0x0) {
        iVar2 = MultiByteToWideChar(param_5,1,param_2,param_3,lpWideCharStr,iVar2);
        if (iVar2 != 0) {
          BVar1 = GetStringTypeW(param_1,lpWideCharStr,iVar2,param_4);
          FUN_100053a0(lpWideCharStr);
          return BVar1;
        }
      }
    }
    FUN_100053a0(lpWideCharStr);
  }
  return param_6;
}



undefined4 * FUN_1000abe0(int param_1,int param_2)

{
  int iVar1;
  uint uVar2;
  uint dwBytes;
  undefined4 *puVar3;
  undefined4 *puVar4;
  
  dwBytes = param_2 * param_1;
  if (dwBytes < 0xffffffe1) {
    if (dwBytes == 0) {
      dwBytes = 0x10;
    }
    else {
      dwBytes = dwBytes + 0xf & 0xfffffff0;
    }
  }
  do {
    puVar3 = (undefined4 *)0x0;
    if (dwBytes < 0xffffffe1) {
      if (DAT_1001147c < dwBytes) {
LAB_1000ac54:
        if (puVar3 != (undefined4 *)0x0) {
          return puVar3;
        }
      }
      else {
        FUN_10006360(9);
        puVar3 = (undefined4 *)FUN_10006840(dwBytes >> 4);
        FUN_100063e0(9);
        if (puVar3 != (undefined4 *)0x0) {
          puVar4 = puVar3;
          for (uVar2 = dwBytes >> 2; uVar2 != 0; uVar2 = uVar2 - 1) {
            *puVar4 = 0;
            puVar4 = puVar4 + 1;
          }
          for (uVar2 = dwBytes & 3; uVar2 != 0; uVar2 = uVar2 - 1) {
            *(undefined *)puVar4 = 0;
            puVar4 = (undefined4 *)((int)puVar4 + 1);
          }
          goto LAB_1000ac54;
        }
      }
      puVar3 = (undefined4 *)HeapAlloc(DAT_10015190,8,dwBytes);
    }
    if ((puVar3 != (undefined4 *)0x0) || (DAT_10012cbc == 0)) {
      return puVar3;
    }
    iVar1 = FUN_10006c00(dwBytes);
    if (iVar1 == 0) {
      return (undefined4 *)0x0;
    }
  } while( true );
}



int FUN_1000ac90(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  HMODULE hModule;
  int iVar1;
  
  iVar1 = 0;
  if (DAT_100130e0 != (FARPROC)0x0) {
LAB_1000ace0:
    if (DAT_100130e4 != (FARPROC)0x0) {
      iVar1 = (*DAT_100130e4)();
    }
    if ((iVar1 != 0) && (DAT_100130e8 != (FARPROC)0x0)) {
      iVar1 = (*DAT_100130e8)(iVar1);
    }
    iVar1 = (*DAT_100130e0)(iVar1,param_1,param_2,param_3);
    return iVar1;
  }
  hModule = LoadLibraryA("user32.dll");
  if (hModule != (HMODULE)0x0) {
    DAT_100130e0 = GetProcAddress(hModule,"MessageBoxA");
    if (DAT_100130e0 != (FARPROC)0x0) {
      DAT_100130e4 = GetProcAddress(hModule,"GetActiveWindow");
      DAT_100130e8 = GetProcAddress(hModule,"GetLastActivePopup");
      goto LAB_1000ace0;
    }
  }
  return 0;
}



// Library Function - Single Match
//  __fptrap
// 
// Library: Visual Studio 1998 Release

void __cdecl __fptrap(void)

{
  __amsg_exit(2);
  return;
}



undefined4 FUN_1000add0(int param_1,undefined4 param_2,undefined4 param_3,char **param_4)

{
  byte bVar1;
  bool bVar2;
  size_t _Count;
  DWORD DVar3;
  int iVar4;
  char *_Source;
  char *_Dest;
  uint uVar5;
  byte *pbVar6;
  char local_80 [128];
  
  if (param_1 != 1) {
    if (param_1 != 0) {
      return 0xffffffff;
    }
    iVar4 = FUN_1000b550(param_2,param_3,&DAT_100130f8,4,0);
    if (iVar4 != 0) {
      pbVar6 = &DAT_100130f8;
      *(char *)param_4 = '\0';
      while( true ) {
        bVar1 = *pbVar6;
        if (DAT_100117f4 < 2) {
          uVar5 = *(byte *)(DAT_100115e8 + (uint)bVar1 * 2) & 4;
        }
        else {
          uVar5 = FUN_10007a80(bVar1,4);
        }
        if (uVar5 == 0) break;
        pbVar6 = pbVar6 + 2;
        *(byte *)param_4 = *(char *)param_4 * '\n' + bVar1 + -0x30;
        if (0x100130ff < (int)pbVar6) {
          return 0;
        }
      }
      return 0;
    }
    return 0xffffffff;
  }
  _Source = local_80;
  bVar2 = false;
  _Count = FUN_1000b680(param_2,param_3,local_80,0x80,0);
  if (_Count == 0) {
    DVar3 = GetLastError();
    if (((DVar3 != 0x7a) || (iVar4 = FUN_1000b680(param_2,param_3,0,0,0), iVar4 == 0)) ||
       (_Source = (char *)FUN_10005410(iVar4), _Source == (char *)0x0)) goto LAB_1000ae80;
    bVar2 = true;
    _Count = FUN_1000b680(param_2,param_3,_Source,iVar4,0);
    if (_Count == 0) goto LAB_1000ae80;
  }
  _Dest = (char *)FUN_10005410(_Count);
  *param_4 = _Dest;
  if (_Dest != (char *)0x0) {
    _strncpy(_Dest,_Source,_Count);
    if (!bVar2) {
      return 0;
    }
    FUN_100053a0(_Source);
    return 0;
  }
LAB_1000ae80:
  if (!bVar2) {
    return 0xffffffff;
  }
  FUN_100053a0(_Source);
  return 0xffffffff;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

byte FUN_1000af80(byte *param_1,byte *param_2)

{
  bool bVar1;
  int iVar2;
  byte bVar3;
  byte bVar4;
  byte bVar5;
  uint uVar6;
  
  iVar2 = _DAT_1001518c;
  if (DAT_10012cd8 == 0) {
    bVar5 = 0xff;
    do {
      do {
        if (bVar5 == 0) {
          return 0;
        }
        bVar5 = *param_2;
        param_2 = param_2 + 1;
        bVar4 = *param_1;
        param_1 = param_1 + 1;
      } while (bVar4 == bVar5);
      bVar3 = bVar5 + 0xbf + (-((byte)(bVar5 + 0xbf) < 0x1a) & 0x20U) + 0x41;
      bVar4 = bVar4 + 0xbf;
      bVar5 = bVar4 + (-(bVar4 < 0x1a) & 0x20U) + 0x41;
    } while (bVar5 == bVar3);
    bVar5 = (bVar5 < bVar3) * -2 + 1;
  }
  else {
    LOCK();
    _DAT_1001518c = _DAT_1001518c + 1;
    UNLOCK();
    bVar1 = 0 < DAT_10015188;
    if (bVar1) {
      LOCK();
      UNLOCK();
      _DAT_1001518c = iVar2;
      FUN_10006360(0x13);
    }
    uVar6 = (uint)bVar1;
    bVar5 = 0xff;
    do {
      do {
        if (bVar5 == 0) goto LAB_1000b02f;
        bVar5 = *param_2;
        param_2 = param_2 + 1;
        bVar4 = *param_1;
        param_1 = param_1 + 1;
      } while (bVar5 == bVar4);
      bVar4 = FUN_10005920(bVar4,bVar5);
      bVar5 = FUN_10005920();
    } while (bVar4 == bVar5);
    bVar5 = (bVar4 < bVar5) * -2 + 1;
LAB_1000b02f:
    if (uVar6 == 0) {
      LOCK();
      _DAT_1001518c = _DAT_1001518c + -1;
      UNLOCK();
    }
    else {
      FUN_100063e0(0x13);
    }
  }
  return bVar5;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_1000b050(byte *param_1,char *param_2,int param_3)

{
  char cVar1;
  int iVar2;
  byte bVar3;
  ushort uVar4;
  uint uVar5;
  uint uVar6;
  bool bVar7;
  uint uVar8;
  
  iVar2 = _DAT_1001518c;
  if (param_3 != 0) {
    if (DAT_10012cd8 == 0) {
      do {
        bVar3 = *param_1;
        cVar1 = *param_2;
        uVar4 = CONCAT11(bVar3,cVar1);
        if (bVar3 == 0) break;
        uVar4 = CONCAT11(bVar3,cVar1);
        uVar6 = (uint)uVar4;
        if (cVar1 == '\0') break;
        param_1 = param_1 + 1;
        param_2 = param_2 + 1;
        if ((0x40 < bVar3) && (bVar3 < 0x5b)) {
          uVar6 = (uint)CONCAT11(bVar3 + 0x20,cVar1);
        }
        uVar4 = (ushort)uVar6;
        bVar3 = (byte)uVar6;
        if ((0x40 < bVar3) && (bVar3 < 0x5b)) {
          uVar4 = (ushort)CONCAT31((int3)(uVar6 >> 8),bVar3 + 0x20);
        }
        bVar3 = (byte)(uVar4 >> 8);
        bVar7 = bVar3 < (byte)uVar4;
        if (bVar3 != (byte)uVar4) goto LAB_1000b0af;
        param_3 = param_3 + -1;
      } while (param_3 != 0);
      param_3 = 0;
      bVar3 = (byte)(uVar4 >> 8);
      bVar7 = bVar3 < (byte)uVar4;
      if (bVar3 != (byte)uVar4) {
LAB_1000b0af:
        param_3 = -1;
        if (!bVar7) {
          param_3 = 1;
        }
      }
    }
    else {
      LOCK();
      _DAT_1001518c = _DAT_1001518c + 1;
      UNLOCK();
      bVar7 = 0 < DAT_10015188;
      if (bVar7) {
        LOCK();
        UNLOCK();
        _DAT_1001518c = iVar2;
        FUN_10006360(0x13);
      }
      uVar8 = (uint)bVar7;
      uVar6 = 0;
      uVar5 = 0;
      do {
        uVar5 = CONCAT31((int3)(uVar5 >> 8),*param_1);
        uVar6 = CONCAT31((int3)(uVar6 >> 8),*param_2);
        if ((uVar5 == 0) || (uVar6 == 0)) break;
        param_1 = param_1 + 1;
        param_2 = param_2 + 1;
        uVar6 = FUN_10005920(uVar6,uVar5);
        uVar5 = FUN_10005920();
        bVar7 = uVar5 < uVar6;
        if (uVar5 != uVar6) goto LAB_1000b125;
        param_3 = param_3 + -1;
      } while (param_3 != 0);
      param_3 = 0;
      bVar7 = uVar5 < uVar6;
      if (uVar5 != uVar6) {
LAB_1000b125:
        param_3 = -1;
        if (!bVar7) {
          param_3 = 1;
        }
      }
      if (uVar8 == 0) {
        LOCK();
        _DAT_1001518c = _DAT_1001518c + -1;
        UNLOCK();
      }
      else {
        FUN_100063e0(0x13);
      }
    }
  }
  return param_3;
}



undefined4 * FUN_1000b160(undefined4 *param_1,undefined4 *param_2,uint param_3)

{
  uint uVar1;
  undefined4 *puVar2;
  
  if ((param_2 < param_1) && (param_1 < (undefined4 *)(param_3 + (int)param_2))) {
    param_2 = (undefined4 *)((param_3 - 4) + (int)param_2);
    puVar2 = (undefined4 *)((param_3 - 4) + (int)param_1);
    if (((uint)puVar2 & 3) == 0) {
      uVar1 = param_3 >> 2;
      param_3 = param_3 & 3;
      if (7 < uVar1) {
        for (; uVar1 != 0; uVar1 = uVar1 - 1) {
          *puVar2 = *param_2;
          param_2 = param_2 + -1;
          puVar2 = puVar2 + -1;
        }
        switch(param_3) {
        case 0:
          return param_1;
        case 2:
          goto switchD_1000b317_caseD_2;
        case 3:
          goto switchD_1000b317_caseD_3;
        }
        goto switchD_1000b317_caseD_1;
      }
    }
    else {
      switch(param_3) {
      case 0:
        goto switchD_1000b317_caseD_0;
      case 1:
        goto switchD_1000b317_caseD_1;
      case 2:
        goto switchD_1000b317_caseD_2;
      case 3:
        goto switchD_1000b317_caseD_3;
      default:
        uVar1 = param_3 - ((uint)puVar2 & 3);
        switch((uint)puVar2 & 3) {
        case 1:
          param_3 = uVar1 & 3;
          *(undefined *)((int)puVar2 + 3) = *(undefined *)((int)param_2 + 3);
          param_2 = (undefined4 *)((int)param_2 + -1);
          uVar1 = uVar1 >> 2;
          puVar2 = (undefined4 *)((int)puVar2 - 1);
          if (7 < uVar1) {
            for (; uVar1 != 0; uVar1 = uVar1 - 1) {
              *puVar2 = *param_2;
              param_2 = param_2 + -1;
              puVar2 = puVar2 + -1;
            }
            switch(param_3) {
            case 0:
              return param_1;
            case 2:
              goto switchD_1000b317_caseD_2;
            case 3:
              goto switchD_1000b317_caseD_3;
            }
            goto switchD_1000b317_caseD_1;
          }
          break;
        case 2:
          param_3 = uVar1 & 3;
          *(undefined *)((int)puVar2 + 3) = *(undefined *)((int)param_2 + 3);
          uVar1 = uVar1 >> 2;
          *(undefined *)((int)puVar2 + 2) = *(undefined *)((int)param_2 + 2);
          param_2 = (undefined4 *)((int)param_2 + -2);
          puVar2 = (undefined4 *)((int)puVar2 - 2);
          if (7 < uVar1) {
            for (; uVar1 != 0; uVar1 = uVar1 - 1) {
              *puVar2 = *param_2;
              param_2 = param_2 + -1;
              puVar2 = puVar2 + -1;
            }
            switch(param_3) {
            case 0:
              return param_1;
            case 2:
              goto switchD_1000b317_caseD_2;
            case 3:
              goto switchD_1000b317_caseD_3;
            }
            goto switchD_1000b317_caseD_1;
          }
          break;
        case 3:
          param_3 = uVar1 & 3;
          *(undefined *)((int)puVar2 + 3) = *(undefined *)((int)param_2 + 3);
          *(undefined *)((int)puVar2 + 2) = *(undefined *)((int)param_2 + 2);
          uVar1 = uVar1 >> 2;
          *(undefined *)((int)puVar2 + 1) = *(undefined *)((int)param_2 + 1);
          param_2 = (undefined4 *)((int)param_2 + -3);
          puVar2 = (undefined4 *)((int)puVar2 - 3);
          if (7 < uVar1) {
            for (; uVar1 != 0; uVar1 = uVar1 - 1) {
              *puVar2 = *param_2;
              param_2 = param_2 + -1;
              puVar2 = puVar2 + -1;
            }
            switch(param_3) {
            case 0:
              return param_1;
            case 2:
              goto switchD_1000b317_caseD_2;
            case 3:
              goto switchD_1000b317_caseD_3;
            }
            goto switchD_1000b317_caseD_1;
          }
        }
      }
    }
    switch(uVar1) {
    case 7:
      puVar2[7 - uVar1] = param_2[7 - uVar1];
    case 6:
      puVar2[6 - uVar1] = param_2[6 - uVar1];
    case 5:
      puVar2[5 - uVar1] = param_2[5 - uVar1];
    case 4:
      puVar2[4 - uVar1] = param_2[4 - uVar1];
    case 3:
      puVar2[3 - uVar1] = param_2[3 - uVar1];
    case 2:
      puVar2[2 - uVar1] = param_2[2 - uVar1];
    case 1:
      puVar2[1 - uVar1] = param_2[1 - uVar1];
      param_2 = param_2 + -uVar1;
      puVar2 = puVar2 + -uVar1;
    }
    switch(param_3) {
    case 1:
switchD_1000b317_caseD_1:
      *(undefined *)((int)puVar2 + 3) = *(undefined *)((int)param_2 + 3);
      return param_1;
    case 2:
switchD_1000b317_caseD_2:
      *(undefined *)((int)puVar2 + 3) = *(undefined *)((int)param_2 + 3);
      *(undefined *)((int)puVar2 + 2) = *(undefined *)((int)param_2 + 2);
      return param_1;
    case 3:
switchD_1000b317_caseD_3:
      *(undefined *)((int)puVar2 + 3) = *(undefined *)((int)param_2 + 3);
      *(undefined *)((int)puVar2 + 2) = *(undefined *)((int)param_2 + 2);
      *(undefined *)((int)puVar2 + 1) = *(undefined *)((int)param_2 + 1);
      return param_1;
    }
switchD_1000b317_caseD_0:
    return param_1;
  }
  puVar2 = param_1;
  if (((uint)param_1 & 3) == 0) {
    uVar1 = param_3 >> 2;
    param_3 = param_3 & 3;
    if (7 < uVar1) {
      for (; uVar1 != 0; uVar1 = uVar1 - 1) {
        *puVar2 = *param_2;
        param_2 = param_2 + 1;
        puVar2 = puVar2 + 1;
      }
      switch(param_3) {
      case 0:
        return param_1;
      case 2:
        goto switchD_1000b195_caseD_2;
      case 3:
        goto switchD_1000b195_caseD_3;
      }
      goto switchD_1000b195_caseD_1;
    }
  }
  else {
    switch(param_3) {
    case 0:
      goto switchD_1000b195_caseD_0;
    case 1:
      goto switchD_1000b195_caseD_1;
    case 2:
      goto switchD_1000b195_caseD_2;
    case 3:
      goto switchD_1000b195_caseD_3;
    default:
      uVar1 = (param_3 - 4) + ((uint)param_1 & 3);
      switch((uint)param_1 & 3) {
      case 1:
        param_3 = uVar1 & 3;
        *(undefined *)param_1 = *(undefined *)param_2;
        *(undefined *)((int)param_1 + 1) = *(undefined *)((int)param_2 + 1);
        uVar1 = uVar1 >> 2;
        *(undefined *)((int)param_1 + 2) = *(undefined *)((int)param_2 + 2);
        param_2 = (undefined4 *)((int)param_2 + 3);
        puVar2 = (undefined4 *)((int)param_1 + 3);
        if (7 < uVar1) {
          for (; uVar1 != 0; uVar1 = uVar1 - 1) {
            *puVar2 = *param_2;
            param_2 = param_2 + 1;
            puVar2 = puVar2 + 1;
          }
          switch(param_3) {
          case 0:
            return param_1;
          case 2:
            goto switchD_1000b195_caseD_2;
          case 3:
            goto switchD_1000b195_caseD_3;
          }
          goto switchD_1000b195_caseD_1;
        }
        break;
      case 2:
        param_3 = uVar1 & 3;
        *(undefined *)param_1 = *(undefined *)param_2;
        uVar1 = uVar1 >> 2;
        *(undefined *)((int)param_1 + 1) = *(undefined *)((int)param_2 + 1);
        param_2 = (undefined4 *)((int)param_2 + 2);
        puVar2 = (undefined4 *)((int)param_1 + 2);
        if (7 < uVar1) {
          for (; uVar1 != 0; uVar1 = uVar1 - 1) {
            *puVar2 = *param_2;
            param_2 = param_2 + 1;
            puVar2 = puVar2 + 1;
          }
          switch(param_3) {
          case 0:
            return param_1;
          case 2:
            goto switchD_1000b195_caseD_2;
          case 3:
            goto switchD_1000b195_caseD_3;
          }
          goto switchD_1000b195_caseD_1;
        }
        break;
      case 3:
        param_3 = uVar1 & 3;
        *(undefined *)param_1 = *(undefined *)param_2;
        param_2 = (undefined4 *)((int)param_2 + 1);
        uVar1 = uVar1 >> 2;
        puVar2 = (undefined4 *)((int)param_1 + 1);
        if (7 < uVar1) {
          for (; uVar1 != 0; uVar1 = uVar1 - 1) {
            *puVar2 = *param_2;
            param_2 = param_2 + 1;
            puVar2 = puVar2 + 1;
          }
          switch(param_3) {
          case 0:
            return param_1;
          case 2:
            goto switchD_1000b195_caseD_2;
          case 3:
            goto switchD_1000b195_caseD_3;
          }
          goto switchD_1000b195_caseD_1;
        }
      }
    }
  }
                    // WARNING: Could not find normalized switch variable to match jumptable
  switch(uVar1) {
  case 0x1c:
  case 0x1d:
  case 0x1e:
  case 0x1f:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar2[uVar1 - 7] = param_2[uVar1 - 7];
  case 0x18:
  case 0x19:
  case 0x1a:
  case 0x1b:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar2[uVar1 - 6] = param_2[uVar1 - 6];
  case 0x14:
  case 0x15:
  case 0x16:
  case 0x17:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar2[uVar1 - 5] = param_2[uVar1 - 5];
  case 0x10:
  case 0x11:
  case 0x12:
  case 0x13:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar2[uVar1 - 4] = param_2[uVar1 - 4];
  case 0xc:
  case 0xd:
  case 0xe:
  case 0xf:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar2[uVar1 - 3] = param_2[uVar1 - 3];
  case 8:
  case 9:
  case 10:
  case 0xb:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar2[uVar1 - 2] = param_2[uVar1 - 2];
  case 4:
  case 5:
  case 6:
  case 7:
    puVar2[uVar1 - 1] = param_2[uVar1 - 1];
    param_2 = param_2 + uVar1;
    puVar2 = puVar2 + uVar1;
  }
  switch(param_3) {
  case 1:
switchD_1000b195_caseD_1:
    *(undefined *)puVar2 = *(undefined *)param_2;
    return param_1;
  case 2:
switchD_1000b195_caseD_2:
    *(undefined *)puVar2 = *(undefined *)param_2;
    *(undefined *)((int)puVar2 + 1) = *(undefined *)((int)param_2 + 1);
    return param_1;
  case 3:
switchD_1000b195_caseD_3:
    *(undefined *)puVar2 = *(undefined *)param_2;
    *(undefined *)((int)puVar2 + 1) = *(undefined *)((int)param_2 + 1);
    *(undefined *)((int)puVar2 + 2) = *(undefined *)((int)param_2 + 2);
    return param_1;
  }
switchD_1000b195_caseD_0:
  return param_1;
}



int FUN_1000b550(LCID param_1,LCTYPE param_2,LPWSTR param_3,int param_4,UINT param_5)

{
  int iVar1;
  LPSTR lpLCData;
  
  if (DAT_100131c4 == 0) {
    iVar1 = GetLocaleInfoW(0,1,(LPWSTR)0x0,0);
    if (iVar1 == 0) {
      iVar1 = GetLocaleInfoA(0,1,(LPSTR)0x0,0);
      if (iVar1 == 0) {
        return 0;
      }
      DAT_100131c4 = 2;
    }
    else {
      DAT_100131c4 = 1;
    }
  }
  if (DAT_100131c4 == 1) {
    iVar1 = GetLocaleInfoW(param_1,param_2,param_3,param_4);
    return iVar1;
  }
  if (DAT_100131c4 != 2) {
    return DAT_100131c4;
  }
  if (param_5 == 0) {
    param_5 = DAT_10012ce8;
  }
  iVar1 = GetLocaleInfoA(param_1,param_2,(LPSTR)0x0,0);
  if (iVar1 != 0) {
    lpLCData = (LPSTR)FUN_10005410(iVar1);
    if (lpLCData == (LPSTR)0x0) {
      return 0;
    }
    iVar1 = GetLocaleInfoA(param_1,param_2,lpLCData,iVar1);
    if (iVar1 != 0) {
      if (param_4 == 0) {
        iVar1 = MultiByteToWideChar(param_5,1,lpLCData,-1,(LPWSTR)0x0,0);
        if (iVar1 != 0) {
          FUN_100053a0(lpLCData);
          return iVar1;
        }
      }
      else {
        iVar1 = MultiByteToWideChar(param_5,1,lpLCData,-1,param_3,param_4);
        if (iVar1 != 0) {
          FUN_100053a0(lpLCData);
          return iVar1;
        }
      }
    }
    FUN_100053a0(lpLCData);
    return 0;
  }
  return 0;
}



int FUN_1000b680(LCID param_1,LCTYPE param_2,LPSTR param_3,int param_4,UINT param_5)

{
  int iVar1;
  LPWSTR lpLCData;
  
  if (DAT_100131c8 == 0) {
    iVar1 = GetLocaleInfoW(0,1,(LPWSTR)0x0,0);
    if (iVar1 == 0) {
      iVar1 = GetLocaleInfoA(0,1,(LPSTR)0x0,0);
      if (iVar1 == 0) {
        return 0;
      }
      DAT_100131c8 = 2;
    }
    else {
      DAT_100131c8 = 1;
    }
  }
  if (DAT_100131c8 == 2) {
    iVar1 = GetLocaleInfoA(param_1,param_2,param_3,param_4);
    return iVar1;
  }
  if (DAT_100131c8 != 1) {
    return DAT_100131c8;
  }
  if (param_5 == 0) {
    param_5 = DAT_10012ce8;
  }
  iVar1 = GetLocaleInfoW(param_1,param_2,(LPWSTR)0x0,0);
  if (iVar1 != 0) {
    lpLCData = (LPWSTR)FUN_10005410(iVar1 * 2);
    if (lpLCData == (LPWSTR)0x0) {
      return 0;
    }
    iVar1 = GetLocaleInfoW(param_1,param_2,lpLCData,iVar1);
    if (iVar1 != 0) {
      if (param_4 == 0) {
        iVar1 = WideCharToMultiByte(param_5,0x220,lpLCData,-1,(LPSTR)0x0,0,(LPCSTR)0x0,(LPBOOL)0x0);
        if (iVar1 != 0) {
          FUN_100053a0(lpLCData);
          return iVar1;
        }
      }
      else {
        iVar1 = WideCharToMultiByte(param_5,0x220,lpLCData,-1,param_3,param_4,(LPCSTR)0x0,
                                    (LPBOOL)0x0);
        if (iVar1 != 0) {
          FUN_100053a0(lpLCData);
          return iVar1;
        }
      }
    }
    FUN_100053a0(lpLCData);
    return 0;
  }
  return 0;
}



undefined4 FUN_1000c000(undefined4 param_1,int *param_2)

{
  undefined *puVar1;
  undefined extraout_var;
  int iVar2;
  undefined local_4 [4];
  
  puVar1 = (undefined *)FUN_10005410(0x80);
  *param_2 = (int)puVar1;
  if (puVar1 == (undefined *)0x0) {
    return 0x3ea;
  }
  FUN_1000c0e0(param_1,local_4);
  iVar2 = 0x80;
  do {
    FUN_1000c0f0(local_4);
    *puVar1 = extraout_var;
    puVar1 = puVar1 + 1;
    iVar2 = iVar2 + -1;
  } while (iVar2 != 0);
  return 0x3e9;
}



undefined4 FUN_1000c060(int param_1,undefined4 param_2_00,uint param_2,int param_3,int param_4)

{
  uint uVar1;
  
  uVar1 = param_2;
  if (param_4 != 0) {
    param_3 = param_3 - param_2;
    param_2 = param_4;
    do {
      *(byte *)(uVar1 + param_3) =
           *(byte *)(uVar1 + param_3) ^
           (&DAT_1000f1a0)[*(byte *)(uVar1 % 0x7b + param_1) ^ *(byte *)(uVar1 % 0x7f + param_1)] ^
           *(byte *)((uVar1 & 0x7f) + param_1);
      uVar1 = uVar1 + 1;
      param_2 = param_2 + -1;
    } while (param_2 != 0);
  }
  return 0x3e9;
}



void FUN_1000c0e0(undefined4 param_1,undefined4 *param_2)

{
  *param_2 = param_1;
  return;
}



void FUN_1000c0f0(int *param_1)

{
  *param_1 = *param_1 * -0xd5acb1b + 0x361962e9;
  return;
}


