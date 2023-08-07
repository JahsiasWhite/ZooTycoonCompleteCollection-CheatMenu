typedef unsigned char   undefined;

typedef unsigned long long    GUID;
typedef pointer32 ImageBaseOffset32;

typedef unsigned char    bool;
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

typedef ushort WORD;

typedef ulong DWORD;

typedef int (* FARPROC)(void);

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

typedef struct HINSTANCE__ * HINSTANCE;

struct HINSTANCE__ {
    int unused;
};

typedef void * LPCVOID;

typedef void * LPVOID;

typedef int BOOL;

typedef HINSTANCE HMODULE;

typedef WORD * LPWORD;

typedef DWORD * LPDWORD;

typedef BOOL * LPBOOL;

typedef BYTE * LPBYTE;

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

typedef struct _STARTUPINFOA _STARTUPINFOA, *P_STARTUPINFOA;

typedef char CHAR;

typedef CHAR * LPSTR;

typedef void * HANDLE;

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

typedef struct _RTL_CRITICAL_SECTION _RTL_CRITICAL_SECTION, *P_RTL_CRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION * PRTL_CRITICAL_SECTION;

typedef PRTL_CRITICAL_SECTION LPCRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION_DEBUG _RTL_CRITICAL_SECTION_DEBUG, *P_RTL_CRITICAL_SECTION_DEBUG;

typedef struct _RTL_CRITICAL_SECTION_DEBUG * PRTL_CRITICAL_SECTION_DEBUG;

typedef long LONG;

typedef ulong ULONG_PTR;

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

typedef struct _STARTUPINFOA * LPSTARTUPINFOA;

typedef union _union_518 _union_518, *P_union_518;

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

typedef struct _OVERLAPPED _OVERLAPPED, *P_OVERLAPPED;

struct _OVERLAPPED {
    ULONG_PTR Internal;
    ULONG_PTR InternalHigh;
    union _union_518 u;
    HANDLE hEvent;
};

typedef struct _OVERLAPPED * LPOVERLAPPED;

typedef wchar_t WCHAR;

typedef CHAR * LPCSTR;

typedef LONG * PLONG;

typedef CHAR * LPCH;

typedef WCHAR * LPWSTR;

typedef WCHAR * LPWCH;

typedef WCHAR * LPCWSTR;

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

typedef uint size_t;




void _SetVectors_If32_16(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4
                        )

{
                    // 0x1000  10  _SetVectors_If32@16
  FUN_10001247((undefined2)param_1,param_2,param_3,(undefined2)param_4);
  return;
}



void _SetIDT_If32_8(undefined4 param_1,undefined4 param_2)

{
                    // 0x1020  8  _SetIDT_If32@8
  FUN_100011f5((undefined2)param_1);
  return;
}



void _GetIDT_If32_8(undefined4 param_1,undefined4 param_2)

{
                    // 0x1040  1  _GetIDT_If32@8
  FUN_100011f9((undefined2)param_1);
  return;
}



void _GetRMInts_If32_8(undefined4 param_1,undefined4 param_2)

{
                    // 0x1060  2  _GetRMInts_If32@8
  FUN_100011f1((undefined2)param_1);
  return;
}



void _GetV86Vector_If32_12(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
                    // 0x1080  3  _GetV86Vector_If32@12
  thunk_FUN_100011c3((undefined2)param_1);
  return;
}



void _SetV86Vector_If32_12(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
                    // 0x10a0  9  _SetV86Vector_If32@12
  FUN_100011c1((undefined2)param_1);
  return;
}



void _InitIV_32_12(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
                    // 0x10c0  5  _InitIV_32@12
  thunk_FUN_100011c3((undefined2)param_1);
  return;
}



void _GetVectors_If32_8(undefined4 param_1,undefined4 param_2)

{
                    // 0x10e0  4  _GetVectors_If32@8
  FUN_10001273();
  return;
}



void _InitVectors_32_8(undefined4 param_1,undefined4 param_2)

{
                    // 0x1100  6  _InitVectors_32@8
  FUN_1000129f(param_1);
  return;
}



void _IsLoadComplete_32_4(undefined4 param_1)

{
                    // 0x1120  7  _IsLoadComplete_32@4
  FUN_100012c3();
  return;
}



bool FUN_10001130(undefined4 param_1,undefined4 param_2)

{
  int iVar1;
  
  iVar1 = FUN_10001160();
  return iVar1 != 0;
}



void FUN_10001160(void)

{
  ThunkConnect32(&thk_ThunkData32);
  return;
}



void thunk_FUN_100011c3(undefined2 param_1)

{
  FUN_100011c3(param_1);
  return;
}



void thunk_FUN_100011c3(undefined2 param_1)

{
  FUN_100011c3(param_1);
  return;
}



void FUN_100011c1(undefined2 param_1)

{
  undefined4 uVar1;
  
  uVar1 = SMapLS_IP_EBP_12(param_1);
  uVar1 = SMapLS_IP_EBP_16(uVar1);
  FUN_1000606c();
  SUnMapLS_IP_EBP_12(uVar1);
  SUnMapLS_IP_EBP_16();
  return;
}



void FUN_100011c3(undefined2 param_1)

{
  undefined4 uVar1;
  
  uVar1 = SMapLS_IP_EBP_12(param_1);
  uVar1 = SMapLS_IP_EBP_16(uVar1);
  FUN_1000606c();
  SUnMapLS_IP_EBP_12(uVar1);
  SUnMapLS_IP_EBP_16();
  return;
}



void FUN_100011f1(undefined2 param_1)

{
  undefined4 uVar1;
  
  uVar1 = SMapLS_IP_EBP_12(param_1);
  FUN_1000606c();
  SUnMapLS_IP_EBP_12(uVar1);
  return;
}



void FUN_100011f5(undefined2 param_1)

{
  undefined4 uVar1;
  
  uVar1 = SMapLS_IP_EBP_12(param_1);
  FUN_1000606c();
  SUnMapLS_IP_EBP_12(uVar1);
  return;
}



void FUN_100011f9(undefined2 param_1)

{
  undefined4 uVar1;
  
  uVar1 = SMapLS_IP_EBP_12(param_1);
  FUN_1000606c();
  SUnMapLS_IP_EBP_12(uVar1);
  return;
}



void FUN_10001247(undefined2 param_1,undefined4 param_2,undefined4 param_3,undefined2 param_4)

{
  SMapLS_IP_EBP_16(param_2,param_1);
  FUN_1000606c();
  SUnMapLS_IP_EBP_16(param_4);
  return;
}



void FUN_10001273(void)

{
  undefined4 uVar1;
  
  uVar1 = SMapLS_IP_EBP_8();
  uVar1 = SMapLS_IP_EBP_12(uVar1);
  FUN_1000606c();
  SUnMapLS_IP_EBP_8(uVar1);
  SUnMapLS_IP_EBP_12();
  return;
}



void FUN_1000129f(undefined4 param_1)

{
  undefined4 uVar1;
  
  uVar1 = SMapLS_IP_EBP_12(param_1);
  FUN_1000606c();
  SUnMapLS_IP_EBP_12(uVar1);
  return;
}



void FUN_100012c3(void)

{
  undefined4 uVar1;
  
  uVar1 = SMapLS_IP_EBP_8();
  FUN_1000606c();
  SUnMapLS_IP_EBP_8(uVar1);
  return;
}



void SMapLS_IP_EBP_8(void)

{
                    // WARNING: Could not recover jumptable at 0x100012e4. Too many branches
                    // WARNING: Treating indirect jump as call
  SMapLS_IP_EBP_8();
  return;
}



void SUnMapLS_IP_EBP_8(void)

{
                    // WARNING: Could not recover jumptable at 0x100012ea. Too many branches
                    // WARNING: Treating indirect jump as call
  SUnMapLS_IP_EBP_8();
  return;
}



void SMapLS_IP_EBP_12(void)

{
                    // WARNING: Could not recover jumptable at 0x100012f0. Too many branches
                    // WARNING: Treating indirect jump as call
  SMapLS_IP_EBP_12();
  return;
}



void SUnMapLS_IP_EBP_12(void)

{
                    // WARNING: Could not recover jumptable at 0x100012f6. Too many branches
                    // WARNING: Treating indirect jump as call
  SUnMapLS_IP_EBP_12();
  return;
}



void SMapLS_IP_EBP_16(void)

{
                    // WARNING: Could not recover jumptable at 0x100012fc. Too many branches
                    // WARNING: Treating indirect jump as call
  SMapLS_IP_EBP_16();
  return;
}



void SUnMapLS_IP_EBP_16(void)

{
                    // WARNING: Could not recover jumptable at 0x10001302. Too many branches
                    // WARNING: Treating indirect jump as call
  SUnMapLS_IP_EBP_16();
  return;
}



void ThunkConnect32(void)

{
                    // WARNING: Could not recover jumptable at 0x10001314. Too many branches
                    // WARNING: Treating indirect jump as call
  ThunkConnect32();
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_10001320(undefined4 param_1,int param_2)

{
  int iVar1;
  
  if (param_2 != 1) {
    if (param_2 != 0) {
      if (param_2 == 3) {
        FUN_100017c0((undefined *)0x0);
      }
      return 1;
    }
    if (0 < DAT_100087c8) {
      DAT_100087c8 = DAT_100087c8 + -1;
      if (DAT_10008818 == 0) {
        FUN_10001580();
      }
      FUN_10001a80();
      FUN_100016f0();
      FUN_10002530();
      return 1;
    }
    return 0;
  }
  DAT_100087e0 = GetVersion();
  iVar1 = FUN_100024f0();
  if (iVar1 == 0) {
    return 0;
  }
  _DAT_100087ec = DAT_100087e0 >> 8 & 0xff;
  _DAT_100087e8 = DAT_100087e0 & 0xff;
  _DAT_100087e4 = _DAT_100087e8 * 0x100 + _DAT_100087ec;
  DAT_100087e0 = DAT_100087e0 >> 0x10;
  iVar1 = FUN_10001690();
  if (iVar1 == 0) {
    FUN_10002530();
    return 0;
  }
  DAT_10009d50 = GetCommandLineA();
  DAT_100087cc = FUN_10002390();
  if ((DAT_10009d50 != (LPSTR)0x0) && (DAT_100087cc != (undefined4 *)0x0)) {
    FUN_10001870();
    FUN_10002380();
    FUN_10001bd0();
    FUN_10001ae0();
    FUN_10001530();
    DAT_100087c8 = DAT_100087c8 + 1;
    return 1;
  }
  FUN_100016f0();
  FUN_10002530();
  return 0;
}



int entry(undefined4 param_1,int param_2,undefined4 param_3)

{
  bool bVar1;
  int iVar2;
  undefined3 extraout_var;
  int iVar3;
  
  iVar2 = 1;
  if ((param_2 == 0) && (DAT_100087c8 == 0)) {
    return 0;
  }
  if ((param_2 != 1) && (param_2 != 2)) {
LAB_1000149e:
    bVar1 = FUN_10001130(param_1,param_2);
    iVar2 = CONCAT31(extraout_var,bVar1);
    if ((param_2 == 1) && (iVar2 == 0)) {
      FUN_10001320(param_1,0);
    }
    if ((param_2 == 0) || (param_2 == 3)) {
      iVar3 = FUN_10001320(param_1,param_2);
      if (iVar3 == 0) {
        iVar2 = 0;
      }
      if ((iVar2 != 0) && (DAT_10009d54 != (code *)0x0)) {
        iVar2 = (*DAT_10009d54)(param_1,param_2,param_3);
      }
    }
    return iVar2;
  }
  if (DAT_10009d54 != (code *)0x0) {
    iVar2 = (*DAT_10009d54)(param_1,param_2,param_3);
  }
  if (iVar2 != 0) {
    iVar2 = FUN_10001320(param_1,param_2);
    if (iVar2 != 0) goto LAB_1000149e;
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
  if ((DAT_100087d4 == 1) || ((DAT_100087d4 == 0 && (_DAT_100087d8 == 1)))) {
    FUN_10002570();
  }
  FUN_100025b0(param_1);
  (*(code *)PTR___exit_100060ac)(0xff);
  return;
}



void FUN_10001530(void)

{
  if (DAT_10009d4c != (code *)0x0) {
    (*DAT_10009d4c)();
  }
  FUN_10001670((undefined **)&DAT_10006008,(undefined **)&DAT_10006010);
  FUN_10001670((undefined **)&DAT_10006000,(undefined **)&DAT_10006004);
  return;
}



// Library Function - Single Match
//  __exit
// 
// Library: Visual Studio 1998 Release

void __cdecl __exit(int _Code)

{
  FUN_10001590(_Code,1,0);
  return;
}



void FUN_10001580(void)

{
  FUN_10001590(0,0,1);
  return;
}



void __cdecl FUN_10001590(UINT param_1,int param_2,int param_3)

{
  HANDLE hProcess;
  code **ppcVar1;
  code **ppcVar2;
  UINT uExitCode;
  
  FUN_10001650();
  if (DAT_1000881c == 1) {
    uExitCode = param_1;
    hProcess = GetCurrentProcess();
    TerminateProcess(hProcess,uExitCode);
  }
  DAT_10008818 = 1;
  DAT_10008814 = (undefined)param_3;
  if (param_2 == 0) {
    if ((DAT_10009d48 != (code **)0x0) &&
       (ppcVar2 = (code **)(DAT_10009d44 + -4), ppcVar1 = DAT_10009d48, DAT_10009d48 <= ppcVar2)) {
      do {
        if (*ppcVar2 != (code *)0x0) {
          (**ppcVar2)();
          ppcVar1 = DAT_10009d48;
        }
        ppcVar2 = ppcVar2 + -1;
      } while (ppcVar1 <= ppcVar2);
    }
    FUN_10001670((undefined **)&DAT_10006014,(undefined **)&DAT_1000601c);
  }
  FUN_10001670((undefined **)&DAT_10006020,(undefined **)&DAT_10006024);
  if (param_3 != 0) {
    FUN_10001660();
    return;
  }
  DAT_1000881c = 1;
                    // WARNING: Subroutine does not return
  ExitProcess(param_1);
}



void FUN_10001650(void)

{
  FUN_10002840(0xd);
  return;
}



void FUN_10001660(void)

{
  FUN_100028c0(0xd);
  return;
}



void __cdecl FUN_10001670(undefined **param_1,undefined **param_2)

{
  if (param_1 < param_2) {
    do {
      if ((code *)*param_1 != (code *)0x0) {
        (*(code *)*param_1)();
      }
      param_1 = (code **)param_1 + 1;
    } while (param_1 < param_2);
  }
  return;
}



undefined4 FUN_10001690(void)

{
  DWORD *lpTlsValue;
  BOOL BVar1;
  DWORD DVar2;
  
  FUN_10002790();
  DAT_100060b0 = TlsAlloc();
  if (DAT_100060b0 != 0xffffffff) {
    lpTlsValue = (DWORD *)FUN_100029c0(1,0x74);
    if (lpTlsValue != (DWORD *)0x0) {
      BVar1 = TlsSetValue(DAT_100060b0,lpTlsValue);
      if (BVar1 != 0) {
        FUN_10001720((int)lpTlsValue);
        DVar2 = GetCurrentThreadId();
        *lpTlsValue = DVar2;
        lpTlsValue[1] = 0xffffffff;
        return 1;
      }
    }
  }
  return 0;
}



void FUN_100016f0(void)

{
  FUN_100027c0();
  if (DAT_100060b0 != 0xffffffff) {
    TlsFree(DAT_100060b0);
    DAT_100060b0 = 0xffffffff;
  }
  return;
}



void __cdecl FUN_10001720(int param_1)

{
  *(undefined **)(param_1 + 0x50) = &DAT_10006330;
  *(undefined4 *)(param_1 + 0x14) = 1;
  return;
}



void __cdecl FUN_100017c0(undefined *param_1)

{
  if (DAT_100060b0 != 0xffffffff) {
    if ((param_1 != (undefined *)0x0) ||
       (param_1 = (undefined *)TlsGetValue(DAT_100060b0), param_1 != (undefined *)0x0)) {
      if (*(undefined **)(param_1 + 0x24) != (undefined *)0x0) {
        FUN_10002a70(*(undefined **)(param_1 + 0x24));
      }
      if (*(undefined **)(param_1 + 0x28) != (undefined *)0x0) {
        FUN_10002a70(*(undefined **)(param_1 + 0x28));
      }
      if (*(undefined **)(param_1 + 0x30) != (undefined *)0x0) {
        FUN_10002a70(*(undefined **)(param_1 + 0x30));
      }
      if (*(undefined **)(param_1 + 0x38) != (undefined *)0x0) {
        FUN_10002a70(*(undefined **)(param_1 + 0x38));
      }
      if (*(undefined **)(param_1 + 0x40) != (undefined *)0x0) {
        FUN_10002a70(*(undefined **)(param_1 + 0x40));
      }
      if (*(undefined **)(param_1 + 0x44) != (undefined *)0x0) {
        FUN_10002a70(*(undefined **)(param_1 + 0x44));
      }
      if (*(undefined **)(param_1 + 0x50) != &DAT_10006330) {
        FUN_10002a70(*(undefined **)(param_1 + 0x50));
      }
      FUN_10002a70(param_1);
    }
    TlsSetValue(DAT_100060b0,(LPVOID)0x0);
    return;
  }
  return;
}



void FUN_10001870(void)

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
  
  puVar3 = (undefined4 *)FUN_10002ae0(0x480);
  if (puVar3 == (undefined4 *)0x0) {
    __amsg_exit(0x1b);
  }
  DAT_10009d40 = 0x20;
  DAT_10009c40 = puVar3;
  if (puVar3 < puVar3 + 0x120) {
    do {
      *(undefined *)(puVar3 + 1) = 0;
      *puVar3 = 0xffffffff;
      *(undefined *)((int)puVar3 + 5) = 10;
      puVar3[2] = 0;
      puVar3 = puVar3 + 9;
    } while (puVar3 < DAT_10009c40 + 0x120);
  }
  GetStartupInfoA(&local_44);
  if ((local_44.cbReserved2 != 0) && ((UINT *)local_44.lpReserved2 != (UINT *)0x0)) {
    UStack_48 = *(UINT *)local_44.lpReserved2;
    local_44.lpReserved2 = (LPBYTE)((int)local_44.lpReserved2 + 4);
    ppvVar5 = (HANDLE *)((int)local_44.lpReserved2 + UStack_48);
    if (0x7ff < (int)UStack_48) {
      UStack_48 = 0x800;
    }
    if ((int)DAT_10009d40 < (int)UStack_48) {
      piVar7 = &DAT_10009c44;
      do {
        puVar3 = (undefined4 *)FUN_10002ae0(0x480);
        if (puVar3 == (undefined4 *)0x0) {
          UStack_48 = DAT_10009d40;
          break;
        }
        *piVar7 = (int)puVar3;
        DAT_10009d40 = DAT_10009d40 + 0x20;
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
      } while ((int)DAT_10009d40 < (int)UStack_48);
    }
    uVar8 = 0;
    if (0 < (int)UStack_48) {
      do {
        if (((*ppvVar5 != (HANDLE)0xffffffff) && ((*local_44.lpReserved2 & 1) != 0)) &&
           (((*local_44.lpReserved2 & 8) != 0 || (DVar4 = GetFileType(*ppvVar5), DVar4 != 0)))) {
          ppvVar1 = (HANDLE *)((int)(&DAT_10009c40)[(int)uVar8 >> 5] + (uVar8 & 0x1f) * 0x24);
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
    ppvVar5 = (HANDLE *)(DAT_10009c40 + iVar6 * 9);
    if (DAT_10009c40[iVar6 * 9] == -1) {
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
        goto LAB_10001a5e;
      }
      *ppvVar5 = hFile;
      if ((DVar4 & 0xff) == 2) {
        bVar2 = *(byte *)(ppvVar5 + 1) | 0x40;
        goto LAB_10001a5e;
      }
      if ((DVar4 & 0xff) == 3) {
        bVar2 = *(byte *)(ppvVar5 + 1) | 8;
        goto LAB_10001a5e;
      }
    }
    else {
      bVar2 = *(byte *)(ppvVar5 + 1) | 0x80;
LAB_10001a5e:
      *(byte *)(ppvVar5 + 1) = bVar2;
    }
    iVar6 = iVar6 + 1;
    if (2 < iVar6) {
      SetHandleCount(DAT_10009d40);
      return;
    }
  } while( true );
}



void FUN_10001a80(void)

{
  uint *puVar1;
  uint uVar2;
  LPCRITICAL_SECTION lpCriticalSection;
  
  puVar1 = &DAT_10009c40;
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
      FUN_10002a70((undefined *)*puVar1);
      *puVar1 = 0;
    }
    puVar1 = puVar1 + 1;
  } while ((int)puVar1 < 0x10009d40);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_10001ae0(void)

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
  cVar2 = *DAT_100087cc;
  pcVar7 = DAT_100087cc;
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
  piVar3 = (int *)FUN_10002ae0(iVar8 * 4 + 4);
  _DAT_100087fc = piVar3;
  if (piVar3 == (int *)0x0) {
    __amsg_exit(9);
  }
  cVar2 = *DAT_100087cc;
  local_4 = piVar3;
  pcVar7 = DAT_100087cc;
  do {
    if (cVar2 == '\0') {
      FUN_10002a70(DAT_100087cc);
      DAT_100087cc = (char *)0x0;
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
      iVar8 = FUN_10002ae0(uVar4);
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

void FUN_10001bd0(void)

{
  byte **ppbVar1;
  byte *pbVar2;
  int iStack_8;
  int iStack_4;
  
  GetModuleFileNameA((HMODULE)0x0,&DAT_10008820,0x104);
  _DAT_1000880c = &DAT_10008820;
  pbVar2 = DAT_10009d50;
  if (*DAT_10009d50 == 0) {
    pbVar2 = &DAT_10008820;
  }
  FUN_10001c70(pbVar2,(byte **)0x0,(byte *)0x0,&iStack_8,&iStack_4);
  ppbVar1 = (byte **)FUN_10002ae0(iStack_4 + iStack_8 * 4);
  if (ppbVar1 == (byte **)0x0) {
    __amsg_exit(8);
  }
  FUN_10001c70(pbVar2,ppbVar1,(byte *)(ppbVar1 + iStack_8),&iStack_8,&iStack_4);
  _DAT_100087f4 = ppbVar1;
  _DAT_100087f0 = iStack_8 + -1;
  return;
}



void __cdecl FUN_10001c70(byte *param_1,byte **param_2,byte *param_3,int *param_4,int *param_5)

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
      if ((((&DAT_10008929)[bVar2] & 4) != 0) && (*param_5 = *param_5 + 1, param_3 != (byte *)0x0))
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
      if ((*(byte *)((int)param_5 + 0x10008929) & 4) != 0) {
        *piVar6 = *piVar6 + 1;
        if (param_3 != (byte *)0x0) {
          *param_3 = *pbVar7;
          param_3 = param_3 + 1;
        }
        pbVar7 = param_1 + 2;
      }
      if (bVar2 == 0x20) break;
      if (bVar2 == 0) goto LAB_10001d49;
      param_1 = pbVar7;
    } while (bVar2 != 9);
    if (bVar2 == 0) {
LAB_10001d49:
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
          if (((&DAT_10008929)[bVar2] & 4) != 0) {
            pbVar7 = pbVar7 + 1;
            *piVar6 = *piVar6 + 1;
          }
          *piVar6 = *piVar6 + 1;
          goto LAB_10001e45;
        }
        if (((&DAT_10008929)[bVar2] & 4) != 0) {
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
LAB_10001e45:
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



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 __cdecl FUN_10001e80(int param_1)

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
  
  FUN_10002840(0x19);
  CodePage = FUN_100020b0(param_1);
  if (CodePage == DAT_10008b30) {
    FUN_100028c0(0x19);
    return 0;
  }
  if (CodePage == 0) {
    FUN_10002160();
    FUN_100021a0();
    FUN_100028c0(0x19);
    return 0;
  }
  iVar9 = 0;
  pUVar4 = &DAT_100060e8;
  do {
    if (*pUVar4 == CodePage) {
      puVar13 = (undefined4 *)&DAT_10008928;
      for (iVar8 = 0x40; iVar8 != 0; iVar8 = iVar8 + -1) {
        *puVar13 = 0;
        puVar13 = puVar13 + 1;
      }
      *(undefined *)puVar13 = 0;
      uVar6 = 0;
      pbVar11 = &DAT_100060f8 + iVar9 * 0x30;
      do {
        bVar2 = *pbVar11;
        for (pbVar12 = pbVar11; (bVar2 != 0 && (bVar2 = pbVar12[1], bVar2 != 0));
            pbVar12 = pbVar12 + 2) {
          uVar7 = (uint)*pbVar12;
          if (uVar7 <= bVar2) {
            bVar3 = (&DAT_100060e0)[uVar6];
            do {
              (&DAT_10008929)[uVar7] = (&DAT_10008929)[uVar7] | bVar3;
              uVar7 = uVar7 + 1;
            } while (uVar7 <= bVar2);
          }
          bVar2 = pbVar12[2];
        }
        uVar6 = uVar6 + 1;
        pbVar11 = pbVar11 + 8;
      } while (uVar6 < 4);
      _DAT_10009c28 = 1;
      DAT_10008b30 = CodePage;
      DAT_10008b34 = FUN_10002100(CodePage);
      _DAT_10008b38 = (&DAT_100060ec)[iVar9 * 0xc];
      _DAT_10008b3c = (&DAT_100060f0)[iVar9 * 0xc];
      _DAT_10008b40 = (&DAT_100060f4)[iVar9 * 0xc];
      goto LAB_10001fd2;
    }
    pUVar4 = pUVar4 + 0xc;
    iVar9 = iVar9 + 1;
  } while (pUVar4 < &DAT_100061d8);
  BVar5 = GetCPInfo(CodePage,&local_14);
  if (BVar5 == 1) {
    puVar13 = (undefined4 *)&DAT_10008928;
    for (iVar9 = 0x40; iVar9 != 0; iVar9 = iVar9 + -1) {
      *puVar13 = 0;
      puVar13 = puVar13 + 1;
    }
    *(undefined *)puVar13 = 0;
    DAT_10008b34 = 0;
    if (local_14.MaxCharSize < 2) {
      _DAT_10009c28 = 0;
      DAT_10008b30 = CodePage;
    }
    else {
      DAT_10008b30 = CodePage;
      if (local_14.LeadByte[0] != '\0') {
        pBVar10 = local_14.LeadByte + 1;
        do {
          bVar2 = *pBVar10;
          if (bVar2 == 0) break;
          for (uVar6 = (uint)pBVar10[-1]; uVar6 <= bVar2; uVar6 = uVar6 + 1) {
            (&DAT_10008929)[uVar6] = (&DAT_10008929)[uVar6] | 4;
          }
          pBVar1 = pBVar10 + 1;
          pBVar10 = pBVar10 + 2;
        } while (*pBVar1 != 0);
      }
      uVar6 = 1;
      do {
        (&DAT_10008929)[uVar6] = (&DAT_10008929)[uVar6] | 8;
        uVar6 = uVar6 + 1;
      } while (uVar6 < 0xff);
      DAT_10008b34 = FUN_10002100(CodePage);
      _DAT_10009c28 = 1;
    }
    _DAT_10008b38 = 0;
    _DAT_10008b3c = 0;
    _DAT_10008b40 = 0;
  }
  else {
    if (DAT_10008b44 == 0) {
      FUN_100028c0(0x19);
      return 0xffffffff;
    }
    FUN_10002160();
  }
LAB_10001fd2:
  FUN_100021a0();
  FUN_100028c0(0x19);
  return 0;
}



int __cdecl FUN_100020b0(int param_1)

{
  int iVar1;
  bool bVar2;
  
  if (param_1 == -2) {
    DAT_10008b44 = 1;
                    // WARNING: Could not recover jumptable at 0x100020cd. Too many branches
                    // WARNING: Treating indirect jump as call
    iVar1 = GetOEMCP();
    return iVar1;
  }
  if (param_1 == -3) {
    DAT_10008b44 = 1;
                    // WARNING: Could not recover jumptable at 0x100020e2. Too many branches
                    // WARNING: Treating indirect jump as call
    iVar1 = GetACP();
    return iVar1;
  }
  bVar2 = param_1 == -4;
  if (bVar2) {
    param_1 = DAT_10008bd0;
  }
  DAT_10008b44 = (uint)bVar2;
  return param_1;
}



undefined4 __cdecl FUN_10002100(undefined4 param_1)

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

void FUN_10002160(void)

{
  int iVar1;
  undefined4 *puVar2;
  
  puVar2 = (undefined4 *)&DAT_10008928;
  for (iVar1 = 0x40; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  *(undefined *)puVar2 = 0;
  DAT_10008b30 = 0;
  _DAT_10009c28 = 0;
  DAT_10008b34 = 0;
  _DAT_10008b38 = 0;
  _DAT_10008b3c = 0;
  _DAT_10008b40 = 0;
  return;
}



void FUN_100021a0(void)

{
  BOOL BVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  BYTE *pBVar5;
  ushort *puVar6;
  undefined4 *puVar7;
  _cpinfo local_514;
  undefined4 auStack_500 [64];
  WCHAR aWStack_400 [128];
  WCHAR aWStack_300 [128];
  WORD aWStack_200 [256];
  
  BVar1 = GetCPInfo(DAT_10008b30,&local_514);
  if (BVar1 == 1) {
    uVar2 = 0;
    do {
      *(char *)((int)auStack_500 + uVar2) = (char)uVar2;
      uVar2 = uVar2 + 1;
    } while (uVar2 < 0x100);
    auStack_500[0]._0_1_ = 0x20;
    if (local_514.LeadByte[0] != 0) {
      pBVar5 = local_514.LeadByte + 1;
      do {
        uVar2 = (uint)local_514.LeadByte[0];
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
        local_514.LeadByte[0] = pBVar5[1];
        pBVar5 = pBVar5 + 2;
      } while (local_514.LeadByte[0] != 0);
    }
    FUN_10002e10(1,(LPCSTR)auStack_500,0x100,aWStack_200,DAT_10008b30,DAT_10008b34,0);
    FUN_10002bb0(DAT_10008b34,0x100,(char *)auStack_500,(LPCWSTR)0x100,aWStack_400,0x100,
                 DAT_10008b30,0);
    FUN_10002bb0(DAT_10008b34,0x200,(char *)auStack_500,(LPCWSTR)0x100,aWStack_300,0x100,
                 DAT_10008b30,0);
    uVar2 = 0;
    puVar6 = aWStack_200;
    do {
      if ((*puVar6 & 1) == 0) {
        if ((*puVar6 & 2) == 0) {
          (&DAT_10008a30)[uVar2] = 0;
        }
        else {
          (&DAT_10008929)[uVar2] = (&DAT_10008929)[uVar2] | 0x20;
          (&DAT_10008a30)[uVar2] = *(undefined *)((int)aWStack_300 + uVar2);
        }
      }
      else {
        (&DAT_10008929)[uVar2] = (&DAT_10008929)[uVar2] | 0x10;
        (&DAT_10008a30)[uVar2] = *(undefined *)((int)aWStack_400 + uVar2);
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
        (&DAT_10008a30)[uVar2] = 0;
      }
      else {
        (&DAT_10008929)[uVar2] = (&DAT_10008929)[uVar2] | 0x20;
        (&DAT_10008a30)[uVar2] = (char)uVar2 + -0x20;
      }
    }
    else {
      (&DAT_10008929)[uVar2] = (&DAT_10008929)[uVar2] | 0x10;
      (&DAT_10008a30)[uVar2] = (char)uVar2 + ' ';
    }
    uVar2 = uVar2 + 1;
  } while (uVar2 < 0x100);
  return;
}



void FUN_10002380(void)

{
  FUN_10001e80(-3);
  return;
}



undefined4 * FUN_10002390(void)

{
  char cVar1;
  WCHAR WVar2;
  WCHAR *pWVar3;
  int iVar5;
  uint uVar6;
  undefined4 *puVar7;
  uint uVar8;
  undefined4 *puVar9;
  LPWCH lpWideCharStr;
  undefined4 *puVar10;
  undefined4 *puVar11;
  WCHAR *pWVar4;
  
  lpWideCharStr = (LPWCH)0x0;
  puVar9 = (undefined4 *)0x0;
  if (DAT_10008b4c == 0) {
    lpWideCharStr = GetEnvironmentStringsW();
    if (lpWideCharStr == (LPWCH)0x0) {
      puVar9 = (undefined4 *)GetEnvironmentStrings();
      if (puVar9 == (undefined4 *)0x0) {
        return (undefined4 *)0x0;
      }
      DAT_10008b4c = 2;
    }
    else {
      DAT_10008b4c = 1;
    }
  }
  if (DAT_10008b4c == 1) {
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
      uVar6 = WideCharToMultiByte(0,0,lpWideCharStr,iVar5,(LPSTR)0x0,0,(LPCSTR)0x0,(LPBOOL)0x0);
      if ((uVar6 != 0) && (puVar9 = (undefined4 *)FUN_10002ae0(uVar6), puVar9 != (undefined4 *)0x0))
      {
        iVar5 = WideCharToMultiByte(0,0,lpWideCharStr,iVar5,(LPSTR)puVar9,uVar6,(LPCSTR)0x0,
                                    (LPBOOL)0x0);
        if (iVar5 == 0) {
          FUN_10002a70((undefined *)puVar9);
          puVar9 = (undefined4 *)0x0;
        }
        FreeEnvironmentStringsW(lpWideCharStr);
        return puVar9;
      }
      FreeEnvironmentStringsW(lpWideCharStr);
      return (undefined4 *)0x0;
    }
  }
  else if ((DAT_10008b4c == 2) &&
          ((puVar9 != (undefined4 *)0x0 ||
           (puVar9 = (undefined4 *)GetEnvironmentStrings(), puVar9 != (undefined4 *)0x0)))) {
    cVar1 = *(char *)puVar9;
    puVar7 = puVar9;
    while (cVar1 != '\0') {
      do {
        puVar10 = puVar7;
        puVar7 = (undefined4 *)((int)puVar10 + 1);
      } while (*(char *)((int)puVar10 + 1) != '\0');
      puVar7 = (undefined4 *)((int)puVar10 + 2);
      cVar1 = *(char *)((int)puVar10 + 2);
    }
    uVar6 = (int)puVar7 + (1 - (int)puVar9);
    puVar7 = (undefined4 *)FUN_10002ae0(uVar6);
    if (puVar7 != (undefined4 *)0x0) {
      puVar10 = puVar9;
      puVar11 = puVar7;
      for (uVar8 = uVar6 >> 2; uVar8 != 0; uVar8 = uVar8 - 1) {
        *puVar11 = *puVar10;
        puVar10 = puVar10 + 1;
        puVar11 = puVar11 + 1;
      }
      for (uVar6 = uVar6 & 3; uVar6 != 0; uVar6 = uVar6 - 1) {
        *(undefined *)puVar11 = *(undefined *)puVar10;
        puVar10 = (undefined4 *)((int)puVar10 + 1);
        puVar11 = (undefined4 *)((int)puVar11 + 1);
      }
      FreeEnvironmentStringsA((LPCH)puVar9);
      return puVar7;
    }
    FreeEnvironmentStringsA((LPCH)puVar9);
    return (undefined4 *)0x0;
  }
  return (undefined4 *)0x0;
}



undefined4 FUN_100024f0(void)

{
  undefined **ppuVar1;
  
  DAT_10009c24 = HeapCreate(0,0x1000,0);
  if (DAT_10009c24 == (HANDLE)0x0) {
    return 0;
  }
  ppuVar1 = FUN_10002f50();
  if (ppuVar1 == (undefined **)0x0) {
    HeapDestroy(DAT_10009c24);
    return 0;
  }
  return 1;
}



void FUN_10002530(void)

{
  undefined **ppuVar1;
  
  ppuVar1 = &PTR_LOOP_100063b8;
  do {
    if (ppuVar1[4] != (undefined *)0x0) {
      VirtualFree(ppuVar1[4],0,0x8000);
    }
    ppuVar1 = (undefined **)*ppuVar1;
  } while (ppuVar1 != &PTR_LOOP_100063b8);
  HeapDestroy(DAT_10009c24);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_10002570(void)

{
  if ((DAT_100087d4 == 1) || ((DAT_100087d4 == 0 && (_DAT_100087d8 == 1)))) {
    FUN_100025b0(0xfc);
    if (DAT_10008b50 != (code *)0x0) {
      (*DAT_10008b50)();
    }
    FUN_100025b0(0xff);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_100025b0(int param_1)

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
  
  piVar2 = &DAT_100061e0;
  iVar8 = 0;
  do {
    if (param_1 == *piVar2) break;
    piVar2 = piVar2 + 2;
    iVar8 = iVar8 + 1;
  } while (piVar2 < &DAT_10006270);
  if (param_1 == (&DAT_100061e0)[iVar8 * 2]) {
    if ((DAT_100087d4 == 1) || ((DAT_100087d4 == 0 && (_DAT_100087d8 == 1)))) {
      if ((DAT_10009c40 == 0) ||
         (hFile = *(HANDLE *)(DAT_10009c40 + 0x48), hFile == (HANDLE)0xffffffff)) {
        hFile = GetStdHandle(0xfffffff4);
      }
      pcVar11 = *(char **)(iVar8 * 8 + 0x100061e4);
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
      pcVar11 = *(char **)(iVar8 * 8 + 0x100061e4);
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
      FUN_10003670(auStack_1a4,"Microsoft Visual C++ Runtime Library",0x12010);
      return;
    }
  }
  return;
}



void FUN_10002790(void)

{
  InitializeCriticalSection((LPCRITICAL_SECTION)PTR_DAT_100062b4);
  InitializeCriticalSection((LPCRITICAL_SECTION)PTR_DAT_100062a4);
  InitializeCriticalSection((LPCRITICAL_SECTION)PTR_DAT_10006294);
  InitializeCriticalSection((LPCRITICAL_SECTION)PTR_DAT_10006274);
  return;
}



void FUN_100027c0(void)

{
  LPCRITICAL_SECTION *pp_Var1;
  
  pp_Var1 = (LPCRITICAL_SECTION *)&DAT_10006270;
  do {
    if ((((*pp_Var1 != (LPCRITICAL_SECTION)0x0) &&
         (pp_Var1 != (LPCRITICAL_SECTION *)&PTR_DAT_100062b4)) &&
        (pp_Var1 != (LPCRITICAL_SECTION *)&PTR_DAT_100062a4)) &&
       ((pp_Var1 != (LPCRITICAL_SECTION *)&PTR_DAT_10006294 &&
        (pp_Var1 != (LPCRITICAL_SECTION *)&PTR_DAT_10006274)))) {
      DeleteCriticalSection(*pp_Var1);
      FUN_10002a70((undefined *)*pp_Var1);
    }
    pp_Var1 = pp_Var1 + 1;
  } while ((int)pp_Var1 < 0x10006330);
  DeleteCriticalSection((LPCRITICAL_SECTION)PTR_DAT_10006294);
  DeleteCriticalSection((LPCRITICAL_SECTION)PTR_DAT_100062a4);
  DeleteCriticalSection((LPCRITICAL_SECTION)PTR_DAT_100062b4);
  DeleteCriticalSection((LPCRITICAL_SECTION)PTR_DAT_10006274);
  return;
}



void __cdecl FUN_10002840(int param_1)

{
  LPCRITICAL_SECTION lpCriticalSection;
  
  if ((&DAT_10006270)[param_1] == 0) {
    lpCriticalSection = (LPCRITICAL_SECTION)FUN_10002ae0(0x18);
    if (lpCriticalSection == (LPCRITICAL_SECTION)0x0) {
      __amsg_exit(0x11);
    }
    FUN_10002840(0x11);
    if ((&DAT_10006270)[param_1] == 0) {
      InitializeCriticalSection(lpCriticalSection);
      (&DAT_10006270)[param_1] = lpCriticalSection;
    }
    else {
      FUN_10002a70((undefined *)lpCriticalSection);
    }
    FUN_100028c0(0x11);
  }
  EnterCriticalSection((LPCRITICAL_SECTION)(&DAT_10006270)[param_1]);
  return;
}



void __cdecl FUN_100028c0(int param_1)

{
  LeaveCriticalSection((LPCRITICAL_SECTION)(&DAT_10006270)[param_1]);
  return;
}



void __cdecl FUN_100028e0(uint param_1)

{
  if ((0x100083df < param_1) && (param_1 < 0x10008641)) {
    FUN_10002840(((int)(param_1 + 0xefff7c20) >> 5) + 0x1c);
    return;
  }
  EnterCriticalSection((LPCRITICAL_SECTION)(param_1 + 0x20));
  return;
}



void __cdecl FUN_10002920(int param_1,int param_2)

{
  if (param_1 < 0x14) {
    FUN_10002840(param_1 + 0x1c);
    return;
  }
  EnterCriticalSection((LPCRITICAL_SECTION)(param_2 + 0x20));
  return;
}



void __cdecl FUN_10002950(uint param_1)

{
  if ((0x100083df < param_1) && (param_1 < 0x10008641)) {
    FUN_100028c0(((int)(param_1 + 0xefff7c20) >> 5) + 0x1c);
    return;
  }
  LeaveCriticalSection((LPCRITICAL_SECTION)(param_1 + 0x20));
  return;
}



void __cdecl FUN_10002990(int param_1,int param_2)

{
  if (param_1 < 0x14) {
    FUN_100028c0(param_1 + 0x1c);
    return;
  }
  LeaveCriticalSection((LPCRITICAL_SECTION)(param_2 + 0x20));
  return;
}



int * __cdecl FUN_100029c0(int param_1,int param_2)

{
  int iVar1;
  uint uVar2;
  uint dwBytes;
  int *piVar3;
  int *piVar4;
  
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
    piVar3 = (int *)0x0;
    if (dwBytes < 0xffffffe1) {
      if (DAT_100083dc < dwBytes) {
LAB_10002a34:
        if (piVar3 != (int *)0x0) {
          return piVar3;
        }
      }
      else {
        FUN_10002840(9);
        piVar3 = FUN_100032b0((int *)(dwBytes >> 4));
        FUN_100028c0(9);
        if (piVar3 != (int *)0x0) {
          piVar4 = piVar3;
          for (uVar2 = dwBytes >> 2; uVar2 != 0; uVar2 = uVar2 - 1) {
            *piVar4 = 0;
            piVar4 = piVar4 + 1;
          }
          for (uVar2 = dwBytes & 3; uVar2 != 0; uVar2 = uVar2 - 1) {
            *(undefined *)piVar4 = 0;
            piVar4 = (int *)((int)piVar4 + 1);
          }
          goto LAB_10002a34;
        }
      }
      piVar3 = (int *)HeapAlloc(DAT_10009c24,8,dwBytes);
    }
    if ((piVar3 != (int *)0x0) || (DAT_10008bfc == 0)) {
      return piVar3;
    }
    iVar1 = FUN_100038e0(dwBytes);
    if (iVar1 == 0) {
      return (int *)0x0;
    }
  } while( true );
}



void __cdecl FUN_10002a70(undefined *param_1)

{
  undefined *lpMem;
  byte *pbVar1;
  int *local_4;
  
  lpMem = param_1;
  if (param_1 != (undefined *)0x0) {
    FUN_10002840(9);
    pbVar1 = (byte *)FUN_100031f0(lpMem,&local_4,(uint *)&param_1);
    if (pbVar1 != (byte *)0x0) {
      FUN_10003250((int)local_4,(int)param_1,pbVar1);
      FUN_100028c0(9);
      return;
    }
    FUN_100028c0(9);
    HeapFree(DAT_10009c24,0,lpMem);
  }
  return;
}



void __cdecl FUN_10002ae0(uint param_1)

{
  FUN_10002b00(param_1,DAT_10008bfc);
  return;
}



int * __cdecl FUN_10002b00(uint param_1,int param_2)

{
  int *piVar1;
  int iVar2;
  
  if (param_1 < 0xffffffe1) {
    if (param_1 == 0) {
      param_1 = 1;
    }
    do {
      if (param_1 < 0xffffffe1) {
        piVar1 = FUN_10002b50(param_1);
      }
      else {
        piVar1 = (int *)0x0;
      }
      if (piVar1 != (int *)0x0) {
        return piVar1;
      }
      if (param_2 == 0) {
        return (int *)0x0;
      }
      iVar2 = FUN_100038e0(param_1);
    } while (iVar2 != 0);
  }
  return (int *)0x0;
}



int * __cdecl FUN_10002b50(int param_1)

{
  int *piVar1;
  uint dwBytes;
  
  dwBytes = param_1 + 0xfU & 0xfffffff0;
  if (dwBytes <= DAT_100083dc) {
    FUN_10002840(9);
    piVar1 = FUN_100032b0((int *)(param_1 + 0xfU >> 4));
    FUN_100028c0(9);
    if (piVar1 != (int *)0x0) {
      return piVar1;
    }
  }
  piVar1 = (int *)HeapAlloc(DAT_10009c24,0,dwBytes);
  return piVar1;
}



int __cdecl
FUN_10002bb0(LCID param_1,uint param_2,char *param_3,LPCWSTR param_4,LPWSTR param_5,int param_6,
            UINT param_7,int param_8)

{
  int iVar1;
  LPCWSTR cbMultiByte;
  LPCWSTR lpWideCharStr;
  int iVar2;
  
  if (DAT_10008bd8 == 0) {
    iVar1 = LCMapStringW(0,0x100,L"",1,(LPWSTR)0x0,0);
    if (iVar1 == 0) {
      iVar1 = LCMapStringA(0,0x100,"",1,(LPSTR)0x0,0);
      if (iVar1 == 0) {
        return 0;
      }
      DAT_10008bd8 = 2;
    }
    else {
      DAT_10008bd8 = 1;
    }
  }
  cbMultiByte = param_4;
  if (0 < (int)param_4) {
    cbMultiByte = (LPCWSTR)FUN_10002de0(param_3,(int)param_4);
  }
  if (DAT_10008bd8 == 2) {
    iVar1 = LCMapStringA(param_1,param_2,param_3,(int)cbMultiByte,(LPSTR)param_5,param_6);
    return iVar1;
  }
  if (DAT_10008bd8 != 1) {
    return DAT_10008bd8;
  }
  param_4 = (LPCWSTR)0x0;
  if (param_7 == 0) {
    param_7 = DAT_10008bd0;
  }
  iVar1 = MultiByteToWideChar(param_7,(-(uint)(param_8 != 0) & 8) + 1,param_3,(int)cbMultiByte,
                              (LPWSTR)0x0,0);
  if (iVar1 == 0) {
    return 0;
  }
  lpWideCharStr = (LPCWSTR)FUN_10002ae0(iVar1 * 2);
  if (lpWideCharStr == (LPCWSTR)0x0) {
    return 0;
  }
  iVar2 = MultiByteToWideChar(param_7,1,param_3,(int)cbMultiByte,lpWideCharStr,iVar1);
  if ((iVar2 != 0) &&
     (iVar2 = LCMapStringW(param_1,param_2,lpWideCharStr,iVar1,(LPWSTR)0x0,0), iVar2 != 0)) {
    if ((param_2 & 0x400) == 0) {
      param_4 = (LPCWSTR)FUN_10002ae0(iVar2 * 2);
      if ((param_4 == (LPCWSTR)0x0) ||
         (iVar1 = LCMapStringW(param_1,param_2,lpWideCharStr,iVar1,param_4,iVar2), iVar1 == 0))
      goto LAB_10002db8;
      if (param_6 == 0) {
        iVar2 = WideCharToMultiByte(param_7,0x220,param_4,iVar2,(LPSTR)0x0,0,(LPCSTR)0x0,(LPBOOL)0x0
                                   );
        iVar1 = iVar2;
      }
      else {
        iVar2 = WideCharToMultiByte(param_7,0x220,param_4,iVar2,(LPSTR)param_5,param_6,(LPCSTR)0x0,
                                    (LPBOOL)0x0);
        iVar1 = iVar2;
      }
    }
    else {
      if (param_6 == 0) goto LAB_10002d1f;
      if (param_6 < iVar2) goto LAB_10002db8;
      iVar1 = LCMapStringW(param_1,param_2,lpWideCharStr,iVar1,param_5,param_6);
    }
    if (iVar1 != 0) {
LAB_10002d1f:
      FUN_10002a70((undefined *)lpWideCharStr);
      FUN_10002a70((undefined *)param_4);
      return iVar2;
    }
  }
LAB_10002db8:
  FUN_10002a70((undefined *)lpWideCharStr);
  FUN_10002a70((undefined *)param_4);
  return 0;
}



int __cdecl FUN_10002de0(char *param_1,int param_2)

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



BOOL __cdecl
FUN_10002e10(DWORD param_1,LPCSTR param_2,int param_3,LPWORD param_4,UINT param_5,LCID param_6,
            int param_7)

{
  BOOL BVar1;
  int iVar2;
  int *lpWideCharStr;
  WORD local_2;
  
  lpWideCharStr = (int *)0x0;
  if (DAT_10008be0 == 0) {
    BVar1 = GetStringTypeW(1,L"",1,&local_2);
    if (BVar1 == 0) {
      BVar1 = GetStringTypeA(0,1,"",1,&local_2);
      if (BVar1 == 0) {
        return 0;
      }
      DAT_10008be0 = 2;
    }
    else {
      DAT_10008be0 = 1;
    }
  }
  if (DAT_10008be0 == 2) {
    if (param_6 == 0) {
      param_6 = DAT_10008bc0;
    }
    BVar1 = GetStringTypeA(param_6,param_1,param_2,param_3,param_4);
    return BVar1;
  }
  param_6 = DAT_10008be0;
  if (DAT_10008be0 == 1) {
    param_6 = 0;
    if (param_5 == 0) {
      param_5 = DAT_10008bd0;
    }
    iVar2 = MultiByteToWideChar(param_5,(-(uint)(param_7 != 0) & 8) + 1,param_2,param_3,(LPWSTR)0x0,
                                0);
    if (iVar2 != 0) {
      lpWideCharStr = FUN_100029c0(2,iVar2);
      if (lpWideCharStr != (int *)0x0) {
        iVar2 = MultiByteToWideChar(param_5,1,param_2,param_3,(LPWSTR)lpWideCharStr,iVar2);
        if (iVar2 != 0) {
          BVar1 = GetStringTypeW(param_1,(LPCWSTR)lpWideCharStr,iVar2,param_4);
          FUN_10002a70((undefined *)lpWideCharStr);
          return BVar1;
        }
      }
    }
    FUN_10002a70((undefined *)lpWideCharStr);
  }
  return param_6;
}



undefined ** FUN_10002f50(void)

{
  bool bVar1;
  undefined4 *lpAddress;
  LPVOID pvVar2;
  int iVar3;
  undefined **ppuVar4;
  undefined **lpMem;
  undefined4 *puVar5;
  
  if (DAT_100063c8 == -1) {
    lpMem = &PTR_LOOP_100063b8;
  }
  else {
    lpMem = (undefined **)HeapAlloc(DAT_10009c24,0,0x2020);
    if (lpMem == (undefined **)0x0) {
      return (undefined **)0x0;
    }
  }
  lpAddress = (undefined4 *)VirtualAlloc((LPVOID)0x0,0x400000,0x2000,4);
  if (lpAddress != (undefined4 *)0x0) {
    pvVar2 = VirtualAlloc(lpAddress,0x10000,0x1000,4);
    if (pvVar2 != (LPVOID)0x0) {
      if (lpMem == &PTR_LOOP_100063b8) {
        if (PTR_LOOP_100063b8 == (undefined *)0x0) {
          PTR_LOOP_100063b8 = (undefined *)&PTR_LOOP_100063b8;
        }
        if (PTR_LOOP_100063bc == (undefined *)0x0) {
          PTR_LOOP_100063bc = (undefined *)&PTR_LOOP_100063b8;
        }
      }
      else {
        *lpMem = (undefined *)&PTR_LOOP_100063b8;
        lpMem[1] = PTR_LOOP_100063bc;
        PTR_LOOP_100063bc = (undefined *)lpMem;
        *(undefined ***)lpMem[1] = lpMem;
      }
      lpMem[5] = (undefined *)(lpAddress + 0x100000);
      lpMem[4] = (undefined *)lpAddress;
      lpMem[2] = (undefined *)(lpMem + 6);
      lpMem[3] = (undefined *)(lpMem + 0x26);
      iVar3 = 0;
      ppuVar4 = lpMem + 6;
      do {
        bVar1 = 0xf < iVar3;
        iVar3 = iVar3 + 1;
        *ppuVar4 = (undefined *)((bVar1 - 1 & 0xf1) - 1);
        ppuVar4[1] = (undefined *)0xf1;
        ppuVar4 = ppuVar4 + 2;
      } while (iVar3 < 0x400);
      puVar5 = lpAddress;
      for (iVar3 = 0x4000; iVar3 != 0; iVar3 = iVar3 + -1) {
        *puVar5 = 0;
        puVar5 = puVar5 + 1;
      }
      if (lpAddress < lpMem[4] + 0x10000) {
        do {
          lpAddress[1] = 0xf0;
          *lpAddress = lpAddress + 2;
          *(undefined *)(lpAddress + 0x3e) = 0xff;
          lpAddress = lpAddress + 0x400;
        } while (lpAddress < lpMem[4] + 0x10000);
      }
      return lpMem;
    }
    VirtualFree(lpAddress,0,0x8000);
  }
  if (lpMem != &PTR_LOOP_100063b8) {
    HeapFree(DAT_10009c24,0,lpMem);
  }
  return (undefined **)0x0;
}



void __cdecl FUN_100030c0(undefined **param_1)

{
  VirtualFree(param_1[4],0,0x8000);
  if ((undefined **)PTR_LOOP_100083d8 == param_1) {
    PTR_LOOP_100083d8 = param_1[1];
  }
  if (param_1 != &PTR_LOOP_100063b8) {
    *(undefined **)param_1[1] = *param_1;
    *(undefined **)(*param_1 + 4) = param_1[1];
    HeapFree(DAT_10009c24,0,param_1);
    return;
  }
  DAT_100063c8 = 0xffffffff;
  return;
}



void __cdecl FUN_10003120(int param_1)

{
  BOOL BVar1;
  undefined **ppuVar2;
  int iVar3;
  int iVar4;
  undefined **ppuVar5;
  undefined **ppuVar6;
  
  ppuVar6 = (undefined **)PTR_LOOP_100063bc;
  do {
    ppuVar5 = ppuVar6;
    if (ppuVar6[4] != (undefined *)0xffffffff) {
      iVar4 = 0;
      ppuVar5 = ppuVar6 + 0x804;
      iVar3 = 0x3ff000;
      do {
        if (*ppuVar5 == (undefined *)0xf0) {
          BVar1 = VirtualFree(ppuVar6[4] + iVar3,0x1000,0x4000);
          if (BVar1 != 0) {
            *ppuVar5 = (undefined *)0xffffffff;
            DAT_10008be4 = DAT_10008be4 + -1;
            if (((undefined **)ppuVar6[3] == (undefined **)0x0) || (ppuVar5 < ppuVar6[3])) {
              ppuVar6[3] = (undefined *)ppuVar5;
            }
            iVar4 = iVar4 + 1;
            param_1 = param_1 + -1;
            if (param_1 == 0) break;
          }
        }
        iVar3 = iVar3 + -0x1000;
        ppuVar5 = ppuVar5 + -2;
      } while (-1 < iVar3);
      ppuVar5 = (undefined **)ppuVar6[1];
      if ((iVar4 != 0) && (ppuVar6[6] == (undefined *)0xffffffff)) {
        iVar3 = 1;
        ppuVar2 = ppuVar6 + 8;
        do {
          if (*ppuVar2 != (undefined *)0xffffffff) break;
          iVar3 = iVar3 + 1;
          ppuVar2 = ppuVar2 + 2;
        } while (iVar3 < 0x400);
        if (iVar3 == 0x400) {
          FUN_100030c0(ppuVar6);
        }
      }
    }
    if ((ppuVar5 == (undefined **)PTR_LOOP_100063bc) || (ppuVar6 = ppuVar5, param_1 < 1)) {
      return;
    }
  } while( true );
}



int __cdecl FUN_100031f0(undefined *param_1,int **param_2,uint *param_3)

{
  undefined **ppuVar1;
  uint uVar2;
  
  ppuVar1 = &PTR_LOOP_100063b8;
  while ((param_1 < ppuVar1[4] || param_1 == ppuVar1[4] || (ppuVar1[5] <= param_1))) {
    ppuVar1 = (undefined **)*ppuVar1;
    if (ppuVar1 == &PTR_LOOP_100063b8) {
      return 0;
    }
  }
  if (((uint)param_1 & 0xf) != 0) {
    return 0;
  }
  if (((uint)param_1 & 0xfff) < 0x100) {
    return 0;
  }
  *param_2 = (int *)ppuVar1;
  uVar2 = (uint)param_1 & 0xfffff000;
  *param_3 = uVar2;
  return ((int)(param_1 + (-0x100 - uVar2)) >> 4) + 8 + uVar2;
}



void __cdecl FUN_10003250(int param_1,int param_2,byte *param_3)

{
  int *piVar1;
  int iVar2;
  
  iVar2 = param_2 - *(int *)(param_1 + 0x10) >> 0xc;
  piVar1 = (int *)(param_1 + 0x18 + iVar2 * 8);
  *piVar1 = *(int *)(param_1 + 0x18 + iVar2 * 8) + (uint)*param_3;
  *param_3 = 0;
  piVar1[1] = 0xf1;
  if ((*piVar1 == 0xf0) && (DAT_10008be4 = DAT_10008be4 + 1, DAT_10008be4 == 0x20)) {
    FUN_10003120(0x10);
  }
  return;
}



int * __cdecl FUN_100032b0(int *param_1)

{
  undefined **ppuVar1;
  undefined **ppuVar2;
  undefined *puVar3;
  int *piVar4;
  int *piVar5;
  undefined **ppuVar6;
  undefined **ppuVar7;
  int **ppiVar8;
  int iVar9;
  int **ppiVar10;
  int **ppiVar11;
  bool bVar12;
  int *local_4;
  
  local_4 = (int *)PTR_LOOP_100083d8;
  do {
    if (local_4[4] != -1) {
      ppiVar10 = (int **)local_4[2];
      ppiVar8 = (int **)(((int)ppiVar10 + (-0x18 - (int)local_4) >> 3) * 0x1000 + local_4[4]);
      for (; ppiVar10 < local_4 + 0x806; ppiVar10 = ppiVar10 + 2) {
        if (((int)param_1 <= (int)*ppiVar10) && (param_1 <= ppiVar10[1] && ppiVar10[1] != param_1))
        {
          piVar4 = (int *)FUN_100034f0(ppiVar8,*ppiVar10,param_1);
          if (piVar4 != (int *)0x0) {
            PTR_LOOP_100083d8 = (undefined *)local_4;
            *ppiVar10 = (int *)((int)*ppiVar10 - (int)param_1);
            local_4[2] = (int)ppiVar10;
            return piVar4;
          }
          ppiVar10[1] = param_1;
        }
        ppiVar8 = ppiVar8 + 0x400;
      }
      ppiVar8 = (int **)local_4[2];
      ppiVar11 = (int **)local_4[4];
      for (ppiVar10 = (int **)(local_4 + 6); ppiVar10 < ppiVar8; ppiVar10 = ppiVar10 + 2) {
        if (((int)param_1 <= (int)*ppiVar10) && (param_1 <= ppiVar10[1] && ppiVar10[1] != param_1))
        {
          piVar4 = (int *)FUN_100034f0(ppiVar11,*ppiVar10,param_1);
          if (piVar4 != (int *)0x0) {
            PTR_LOOP_100083d8 = (undefined *)local_4;
            *ppiVar10 = (int *)((int)*ppiVar10 - (int)param_1);
            local_4[2] = (int)ppiVar10;
            return piVar4;
          }
          ppiVar10[1] = param_1;
        }
        ppiVar11 = ppiVar11 + 0x400;
      }
    }
    local_4 = (int *)*local_4;
  } while (local_4 != (int *)PTR_LOOP_100083d8);
  ppuVar7 = &PTR_LOOP_100063b8;
  while ((ppuVar7[4] == (undefined *)0xffffffff || (ppuVar7[3] == (undefined *)0x0))) {
    ppuVar7 = (undefined **)*ppuVar7;
    if (ppuVar7 == &PTR_LOOP_100063b8) {
      ppuVar7 = FUN_10002f50();
      if (ppuVar7 == (undefined **)0x0) {
        return (int *)0x0;
      }
      piVar4 = (int *)ppuVar7[4];
      *(char *)(piVar4 + 2) = (char)param_1;
      PTR_LOOP_100083d8 = (undefined *)ppuVar7;
      *piVar4 = (int)(piVar4 + 2) + (int)param_1;
      piVar4[1] = 0xf0 - (int)param_1;
      ppuVar7[6] = ppuVar7[6] + -((uint)param_1 & 0xff);
      return piVar4 + 0x40;
    }
  }
  ppuVar2 = (undefined **)ppuVar7[3];
  puVar3 = *ppuVar2;
  piVar4 = (int *)(ppuVar7[4] + ((int)ppuVar2 + (-0x18 - (int)ppuVar7) >> 3) * 0x1000);
  ppuVar6 = ppuVar2;
  for (iVar9 = 0; (puVar3 == (undefined *)0xffffffff && (iVar9 < 0x10)); iVar9 = iVar9 + 1) {
    puVar3 = ppuVar6[2];
    ppuVar6 = ppuVar6 + 2;
  }
  piVar5 = (int *)VirtualAlloc(piVar4,iVar9 << 0xc,0x1000,4);
  if (piVar5 != piVar4) {
    return (int *)0x0;
  }
  ppuVar6 = ppuVar2;
  if (0 < iVar9) {
    piVar5 = piVar4 + 1;
    do {
      *piVar5 = 0xf0;
      piVar5[-1] = (int)(piVar5 + 1);
      *(undefined *)(piVar5 + 0x3d) = 0xff;
      *ppuVar6 = (undefined *)0xf0;
      ppuVar6[1] = (undefined *)0xf1;
      piVar5 = piVar5 + 0x400;
      ppuVar6 = ppuVar6 + 2;
      iVar9 = iVar9 + -1;
    } while (iVar9 != 0);
  }
  ppuVar1 = ppuVar7 + 0x806;
  bVar12 = ppuVar6 < ppuVar1;
  if (bVar12) {
    do {
      if (*ppuVar6 == (undefined *)0xffffffff) break;
      ppuVar6 = ppuVar6 + 2;
    } while (ppuVar6 < ppuVar1);
    bVar12 = ppuVar6 < ppuVar1;
  }
  PTR_LOOP_100083d8 = (undefined *)ppuVar7;
  ppuVar7[3] = (undefined *)(-(uint)bVar12 & (uint)ppuVar6);
  *(char *)(piVar4 + 2) = (char)param_1;
  ppuVar7[2] = (undefined *)ppuVar2;
  *ppuVar2 = *ppuVar2 + -(int)param_1;
  piVar4[1] = piVar4[1] - (int)param_1;
  *piVar4 = (int)(piVar4 + 2) + (int)param_1;
  return piVar4 + 0x40;
}



int __cdecl FUN_100034f0(int **param_1,int *param_2,int *param_3)

{
  byte bVar1;
  int **ppiVar2;
  int **ppiVar3;
  int **ppiVar4;
  int *piVar5;
  int **ppiVar6;
  
  ppiVar2 = (int **)*param_1;
  if (param_3 <= param_1[1]) {
    *(byte *)ppiVar2 = (byte)param_3;
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
  if (*(byte *)ppiVar3 != 0) {
    ppiVar6 = ppiVar3;
  }
  if ((int **)((int)ppiVar6 + (int)param_3) < param_1 + 0x3e) {
    do {
      if (*(byte *)ppiVar6 == 0) {
        ppiVar3 = (int **)((int)ppiVar6 + 1);
        piVar5 = (int *)0x1;
        bVar1 = *(byte *)((int)ppiVar6 + 1);
        while (bVar1 == 0) {
          ppiVar3 = (int **)((int)ppiVar3 + 1);
          piVar5 = (int *)((int)piVar5 + 1);
          bVar1 = *(byte *)ppiVar3;
        }
        if (param_3 <= piVar5) {
          if (param_1 + 0x3e <= (int **)((int)ppiVar6 + (int)param_3)) {
            *param_1 = (int *)(param_1 + 2);
            goto LAB_1000363f;
          }
          *param_1 = (int *)(int **)((int)ppiVar6 + (int)param_3);
          param_1[1] = (int *)((int)piVar5 - (int)param_3);
          goto LAB_10003646;
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
        bVar1 = *(byte *)((int)ppiVar6 + 1);
        while (bVar1 == 0) {
          ppiVar4 = (int **)((int)ppiVar4 + 1);
          piVar5 = (int *)((int)piVar5 + 1);
          bVar1 = *(byte *)ppiVar4;
        }
        if (param_3 <= piVar5) {
          if ((int **)((int)ppiVar6 + (int)param_3) < param_1 + 0x3e) {
            *param_1 = (int *)(int **)((int)ppiVar6 + (int)param_3);
            param_1[1] = (int *)((int)piVar5 - (int)param_3);
          }
          else {
            *param_1 = (int *)ppiVar3;
LAB_1000363f:
            param_1[1] = (int *)0x0;
          }
LAB_10003646:
          *(byte *)ppiVar6 = (byte)param_3;
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



int __cdecl FUN_10003670(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  HMODULE hModule;
  int iVar1;
  
  iVar1 = 0;
  if (DAT_10008be8 != (FARPROC)0x0) {
LAB_100036c0:
    if (DAT_10008bec != (FARPROC)0x0) {
      iVar1 = (*DAT_10008bec)();
    }
    if ((iVar1 != 0) && (DAT_10008bf0 != (FARPROC)0x0)) {
      iVar1 = (*DAT_10008bf0)(iVar1);
    }
    iVar1 = (*DAT_10008be8)(iVar1,param_1,param_2,param_3);
    return iVar1;
  }
  hModule = LoadLibraryA("user32.dll");
  if (hModule != (HMODULE)0x0) {
    DAT_10008be8 = GetProcAddress(hModule,"MessageBoxA");
    if (DAT_10008be8 != (FARPROC)0x0) {
      DAT_10008bec = GetProcAddress(hModule,"GetActiveWindow");
      DAT_10008bf0 = GetProcAddress(hModule,"GetLastActivePopup");
      goto LAB_100036c0;
    }
  }
  return 0;
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
        goto joined_r0x1000373e;
      }
    }
    do {
      if (((uint)puVar5 & 3) == 0) {
        uVar4 = _Count >> 2;
        cVar3 = '\0';
        if (uVar4 == 0) goto LAB_1000377b;
        goto LAB_100037e9;
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
joined_r0x100037e5:
          while( true ) {
            uVar4 = uVar4 - 1;
            puVar5 = puVar5 + 1;
            if (uVar4 == 0) break;
LAB_100037e9:
            *puVar5 = 0;
          }
          cVar3 = '\0';
          _Count = _Count & 3;
          if (_Count != 0) goto LAB_1000377b;
          return _Dest;
        }
        if ((char)(uVar2 >> 8) == '\0') {
          *puVar5 = uVar2 & 0xff;
          goto joined_r0x100037e5;
        }
        if ((uVar2 & 0xff0000) == 0) {
          *puVar5 = uVar2 & 0xffff;
          goto joined_r0x100037e5;
        }
        if ((uVar2 & 0xff000000) == 0) {
          *puVar5 = uVar2;
          goto joined_r0x100037e5;
        }
      }
      *puVar5 = uVar2;
      puVar5 = puVar5 + 1;
      uVar4 = uVar4 - 1;
joined_r0x1000373e:
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
LAB_1000377b:
        *(char *)puVar5 = cVar3;
        puVar5 = (uint *)((int)puVar5 + 1);
      }
      return _Dest;
    }
    _Count = _Count - 1;
  } while (_Count != 0);
  return _Dest;
}



undefined4 __cdecl FUN_100038e0(undefined4 param_1)

{
  int iVar1;
  
  if (DAT_10008bf8 != (code *)0x0) {
    iVar1 = (*DAT_10008bf8)(param_1);
    if (iVar1 != 0) {
      return 1;
    }
  }
  return 0;
}



undefined4 * __cdecl FUN_10003900(undefined4 *param_1,undefined4 *param_2,uint param_3)

{
  uint uVar1;
  uint uVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  
  if ((param_2 < param_1) && (param_1 < (undefined4 *)(param_3 + (int)param_2))) {
    puVar3 = (undefined4 *)((param_3 - 4) + (int)param_2);
    puVar4 = (undefined4 *)((param_3 - 4) + (int)param_1);
    if (((uint)puVar4 & 3) == 0) {
      uVar1 = param_3 >> 2;
      uVar2 = param_3 & 3;
      if (7 < uVar1) {
        for (; uVar1 != 0; uVar1 = uVar1 - 1) {
          *puVar4 = *puVar3;
          puVar3 = puVar3 + -1;
          puVar4 = puVar4 + -1;
        }
        switch(uVar2) {
        case 0:
          return param_1;
        case 2:
          goto switchD_10003ab7_caseD_2;
        case 3:
          goto switchD_10003ab7_caseD_3;
        }
        goto switchD_10003ab7_caseD_1;
      }
    }
    else {
      switch(param_3) {
      case 0:
        goto switchD_10003ab7_caseD_0;
      case 1:
        goto switchD_10003ab7_caseD_1;
      case 2:
        goto switchD_10003ab7_caseD_2;
      case 3:
        goto switchD_10003ab7_caseD_3;
      default:
        uVar1 = param_3 - ((uint)puVar4 & 3);
        switch((uint)puVar4 & 3) {
        case 1:
          uVar2 = uVar1 & 3;
          *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar3 + 3);
          puVar3 = (undefined4 *)((int)puVar3 + -1);
          uVar1 = uVar1 >> 2;
          puVar4 = (undefined4 *)((int)puVar4 - 1);
          if (7 < uVar1) {
            for (; uVar1 != 0; uVar1 = uVar1 - 1) {
              *puVar4 = *puVar3;
              puVar3 = puVar3 + -1;
              puVar4 = puVar4 + -1;
            }
            switch(uVar2) {
            case 0:
              return param_1;
            case 2:
              goto switchD_10003ab7_caseD_2;
            case 3:
              goto switchD_10003ab7_caseD_3;
            }
            goto switchD_10003ab7_caseD_1;
          }
          break;
        case 2:
          uVar2 = uVar1 & 3;
          *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar3 + 3);
          uVar1 = uVar1 >> 2;
          *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar3 + 2);
          puVar3 = (undefined4 *)((int)puVar3 + -2);
          puVar4 = (undefined4 *)((int)puVar4 - 2);
          if (7 < uVar1) {
            for (; uVar1 != 0; uVar1 = uVar1 - 1) {
              *puVar4 = *puVar3;
              puVar3 = puVar3 + -1;
              puVar4 = puVar4 + -1;
            }
            switch(uVar2) {
            case 0:
              return param_1;
            case 2:
              goto switchD_10003ab7_caseD_2;
            case 3:
              goto switchD_10003ab7_caseD_3;
            }
            goto switchD_10003ab7_caseD_1;
          }
          break;
        case 3:
          uVar2 = uVar1 & 3;
          *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar3 + 3);
          *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar3 + 2);
          uVar1 = uVar1 >> 2;
          *(undefined *)((int)puVar4 + 1) = *(undefined *)((int)puVar3 + 1);
          puVar3 = (undefined4 *)((int)puVar3 + -3);
          puVar4 = (undefined4 *)((int)puVar4 - 3);
          if (7 < uVar1) {
            for (; uVar1 != 0; uVar1 = uVar1 - 1) {
              *puVar4 = *puVar3;
              puVar3 = puVar3 + -1;
              puVar4 = puVar4 + -1;
            }
            switch(uVar2) {
            case 0:
              return param_1;
            case 2:
              goto switchD_10003ab7_caseD_2;
            case 3:
              goto switchD_10003ab7_caseD_3;
            }
            goto switchD_10003ab7_caseD_1;
          }
        }
      }
    }
    switch(uVar1) {
    case 7:
      puVar4[7 - uVar1] = puVar3[7 - uVar1];
    case 6:
      puVar4[6 - uVar1] = puVar3[6 - uVar1];
    case 5:
      puVar4[5 - uVar1] = puVar3[5 - uVar1];
    case 4:
      puVar4[4 - uVar1] = puVar3[4 - uVar1];
    case 3:
      puVar4[3 - uVar1] = puVar3[3 - uVar1];
    case 2:
      puVar4[2 - uVar1] = puVar3[2 - uVar1];
    case 1:
      puVar4[1 - uVar1] = puVar3[1 - uVar1];
      puVar3 = puVar3 + -uVar1;
      puVar4 = puVar4 + -uVar1;
    }
    switch(uVar2) {
    case 1:
switchD_10003ab7_caseD_1:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar3 + 3);
      return param_1;
    case 2:
switchD_10003ab7_caseD_2:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar3 + 3);
      *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar3 + 2);
      return param_1;
    case 3:
switchD_10003ab7_caseD_3:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar3 + 3);
      *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar3 + 2);
      *(undefined *)((int)puVar4 + 1) = *(undefined *)((int)puVar3 + 1);
      return param_1;
    }
switchD_10003ab7_caseD_0:
    return param_1;
  }
  puVar3 = param_1;
  if (((uint)param_1 & 3) == 0) {
    uVar1 = param_3 >> 2;
    uVar2 = param_3 & 3;
    if (7 < uVar1) {
      for (; uVar1 != 0; uVar1 = uVar1 - 1) {
        *puVar3 = *param_2;
        param_2 = param_2 + 1;
        puVar3 = puVar3 + 1;
      }
      switch(uVar2) {
      case 0:
        return param_1;
      case 2:
        goto switchD_10003935_caseD_2;
      case 3:
        goto switchD_10003935_caseD_3;
      }
      goto switchD_10003935_caseD_1;
    }
  }
  else {
    switch(param_3) {
    case 0:
      goto switchD_10003935_caseD_0;
    case 1:
      goto switchD_10003935_caseD_1;
    case 2:
      goto switchD_10003935_caseD_2;
    case 3:
      goto switchD_10003935_caseD_3;
    default:
      uVar1 = (param_3 - 4) + ((uint)param_1 & 3);
      switch((uint)param_1 & 3) {
      case 1:
        uVar2 = uVar1 & 3;
        *(undefined *)param_1 = *(undefined *)param_2;
        *(undefined *)((int)param_1 + 1) = *(undefined *)((int)param_2 + 1);
        uVar1 = uVar1 >> 2;
        *(undefined *)((int)param_1 + 2) = *(undefined *)((int)param_2 + 2);
        param_2 = (undefined4 *)((int)param_2 + 3);
        puVar3 = (undefined4 *)((int)param_1 + 3);
        if (7 < uVar1) {
          for (; uVar1 != 0; uVar1 = uVar1 - 1) {
            *puVar3 = *param_2;
            param_2 = param_2 + 1;
            puVar3 = puVar3 + 1;
          }
          switch(uVar2) {
          case 0:
            return param_1;
          case 2:
            goto switchD_10003935_caseD_2;
          case 3:
            goto switchD_10003935_caseD_3;
          }
          goto switchD_10003935_caseD_1;
        }
        break;
      case 2:
        uVar2 = uVar1 & 3;
        *(undefined *)param_1 = *(undefined *)param_2;
        uVar1 = uVar1 >> 2;
        *(undefined *)((int)param_1 + 1) = *(undefined *)((int)param_2 + 1);
        param_2 = (undefined4 *)((int)param_2 + 2);
        puVar3 = (undefined4 *)((int)param_1 + 2);
        if (7 < uVar1) {
          for (; uVar1 != 0; uVar1 = uVar1 - 1) {
            *puVar3 = *param_2;
            param_2 = param_2 + 1;
            puVar3 = puVar3 + 1;
          }
          switch(uVar2) {
          case 0:
            return param_1;
          case 2:
            goto switchD_10003935_caseD_2;
          case 3:
            goto switchD_10003935_caseD_3;
          }
          goto switchD_10003935_caseD_1;
        }
        break;
      case 3:
        uVar2 = uVar1 & 3;
        *(undefined *)param_1 = *(undefined *)param_2;
        param_2 = (undefined4 *)((int)param_2 + 1);
        uVar1 = uVar1 >> 2;
        puVar3 = (undefined4 *)((int)param_1 + 1);
        if (7 < uVar1) {
          for (; uVar1 != 0; uVar1 = uVar1 - 1) {
            *puVar3 = *param_2;
            param_2 = param_2 + 1;
            puVar3 = puVar3 + 1;
          }
          switch(uVar2) {
          case 0:
            return param_1;
          case 2:
            goto switchD_10003935_caseD_2;
          case 3:
            goto switchD_10003935_caseD_3;
          }
          goto switchD_10003935_caseD_1;
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
    puVar3[uVar1 - 7] = param_2[uVar1 - 7];
  case 0x18:
  case 0x19:
  case 0x1a:
  case 0x1b:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar3[uVar1 - 6] = param_2[uVar1 - 6];
  case 0x14:
  case 0x15:
  case 0x16:
  case 0x17:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar3[uVar1 - 5] = param_2[uVar1 - 5];
  case 0x10:
  case 0x11:
  case 0x12:
  case 0x13:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar3[uVar1 - 4] = param_2[uVar1 - 4];
  case 0xc:
  case 0xd:
  case 0xe:
  case 0xf:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar3[uVar1 - 3] = param_2[uVar1 - 3];
  case 8:
  case 9:
  case 10:
  case 0xb:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar3[uVar1 - 2] = param_2[uVar1 - 2];
  case 4:
  case 5:
  case 6:
  case 7:
    puVar3[uVar1 - 1] = param_2[uVar1 - 1];
    param_2 = param_2 + uVar1;
    puVar3 = puVar3 + uVar1;
  }
  switch(uVar2) {
  case 1:
switchD_10003935_caseD_1:
    *(undefined *)puVar3 = *(undefined *)param_2;
    return param_1;
  case 2:
switchD_10003935_caseD_2:
    *(undefined *)puVar3 = *(undefined *)param_2;
    *(undefined *)((int)puVar3 + 1) = *(undefined *)((int)param_2 + 1);
    return param_1;
  case 3:
switchD_10003935_caseD_3:
    *(undefined *)puVar3 = *(undefined *)param_2;
    *(undefined *)((int)puVar3 + 1) = *(undefined *)((int)param_2 + 1);
    *(undefined *)((int)puVar3 + 2) = *(undefined *)((int)param_2 + 2);
    return param_1;
  }
switchD_10003935_caseD_0:
  return param_1;
}


