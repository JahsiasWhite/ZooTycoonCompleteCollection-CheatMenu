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
typedef unsigned long long    undefined8;
typedef unsigned short    ushort;
typedef unsigned short    wchar16;
typedef short    wchar_t;
typedef unsigned short    word;
typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion;

typedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct;

struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct {
    dword OffsetToDirectory;
    dword DataIsDirectory;
};

union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion {
    dword OffsetToData;
    struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct;
};

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

typedef struct _OVERLAPPED _OVERLAPPED, *P_OVERLAPPED;

typedef ulong ULONG_PTR;

typedef union _union_518 _union_518, *P_union_518;

typedef void * HANDLE;

typedef struct _struct_519 _struct_519, *P_struct_519;

typedef void * PVOID;

typedef ulong DWORD;

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

typedef struct _OVERLAPPED * LPOVERLAPPED;

typedef struct _SECURITY_ATTRIBUTES * LPSECURITY_ATTRIBUTES;

typedef struct _STARTUPINFOA _STARTUPINFOA, *P_STARTUPINFOA;

typedef char CHAR;

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

typedef struct _EXCEPTION_RECORD _EXCEPTION_RECORD, *P_EXCEPTION_RECORD;

struct _EXCEPTION_RECORD {
    DWORD ExceptionCode;
    DWORD ExceptionFlags;
    struct _EXCEPTION_RECORD * ExceptionRecord;
    PVOID ExceptionAddress;
    DWORD NumberParameters;
    ULONG_PTR ExceptionInformation[15];
};

typedef struct tagPDA tagPDA, *PtagPDA;

typedef struct HWND__ HWND__, *PHWND__;

typedef struct HWND__ * HWND;

typedef HANDLE HGLOBAL;

typedef struct HDC__ HDC__, *PHDC__;

typedef struct HDC__ * HDC;

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

typedef struct HINSTANCE__ * HINSTANCE;

typedef long LONG_PTR;

typedef LONG_PTR LPARAM;

typedef uint UINT_PTR;

typedef UINT_PTR WPARAM;

typedef UINT_PTR (* LPPRINTHOOKPROC)(HWND, UINT, WPARAM, LPARAM);

typedef UINT_PTR (* LPSETUPHOOKPROC)(HWND, UINT, WPARAM, LPARAM);

typedef CHAR * LPCSTR;

struct HDC__ {
    int unused;
};

struct tagPDA {
    DWORD lStructSize;
    HWND hwndOwner;
    HGLOBAL hDevMode;
    HGLOBAL hDevNames;
    HDC hDC;
    DWORD Flags;
    WORD nFromPage;
    WORD nToPage;
    WORD nMinPage;
    WORD nMaxPage;
    WORD nCopies;
    HINSTANCE hInstance;
    LPARAM lCustData;
    LPPRINTHOOKPROC lpfnPrintHook;
    LPSETUPHOOKPROC lpfnSetupHook;
    LPCSTR lpPrintTemplateName;
    LPCSTR lpSetupTemplateName;
    HGLOBAL hPrintTemplate;
    HGLOBAL hSetupTemplate;
};

struct HINSTANCE__ {
    int unused;
};

struct HWND__ {
    int unused;
};

typedef struct tagPDA * LPPRINTDLGA;

typedef uint size_t;

typedef int errno_t;

typedef struct tagMSG tagMSG, *PtagMSG;

typedef struct tagMSG MSG;

typedef struct tagPOINT tagPOINT, *PtagPOINT;

typedef struct tagPOINT POINT;

struct tagPOINT {
    LONG x;
    LONG y;
};

struct tagMSG {
    HWND hwnd;
    UINT message;
    WPARAM wParam;
    LPARAM lParam;
    DWORD time;
    POINT pt;
};

typedef struct tagMSG * LPMSG;

typedef int INT_PTR;

typedef INT_PTR (* DLGPROC)(HWND, UINT, WPARAM, LPARAM);

typedef struct _DOCINFOA _DOCINFOA, *P_DOCINFOA;

typedef struct _DOCINFOA DOCINFOA;

struct _DOCINFOA {
    int cbSize;
    LPCSTR lpszDocName;
    LPCSTR lpszOutput;
    LPCSTR lpszDatatype;
    DWORD fwType;
};

typedef struct _EXCEPTION_RECORD EXCEPTION_RECORD;

typedef EXCEPTION_RECORD * PEXCEPTION_RECORD;

typedef wchar_t WCHAR;

typedef WCHAR * LPWSTR;

typedef WCHAR * LPWCH;

typedef WCHAR * LPCWSTR;

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

typedef HINSTANCE HMODULE;

typedef int (* FARPROC)(void);

typedef struct HICON__ HICON__, *PHICON__;

struct HICON__ {
    int unused;
};

typedef WORD * LPWORD;

typedef struct HKEY__ * HKEY;

typedef HKEY * PHKEY;

typedef LONG_PTR LRESULT;

typedef BOOL * LPBOOL;

typedef struct HICON__ * HICON;

typedef void * LPCVOID;

typedef HICON HCURSOR;

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

typedef struct Var Var, *PVar;

struct Var {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;

struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct {
    dword NameOffset;
    dword NameIsString;
};

typedef struct IMAGE_DEBUG_DIRECTORY IMAGE_DEBUG_DIRECTORY, *PIMAGE_DEBUG_DIRECTORY;

struct IMAGE_DEBUG_DIRECTORY {
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    dword Type;
    dword SizeOfData;
    dword AddressOfRawData;
    dword PointerToRawData;
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

typedef struct StringFileInfo StringFileInfo, *PStringFileInfo;

struct StringFileInfo {
    word wLength;
    word wValueLength;
    word wType;
};

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY IMAGE_RESOURCE_DIRECTORY_ENTRY, *PIMAGE_RESOURCE_DIRECTORY_ENTRY;

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion;

union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion {
    struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;
    dword Name;
    word Id;
};

union IMAGE_RESOURCE_DIRECTORY_ENTRY {
    union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion NameUnion;
    union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion DirectoryUnion;
};

typedef struct StringTable StringTable, *PStringTable;

struct StringTable {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct IMAGE_RESOURCE_DIR_STRING_U_18 IMAGE_RESOURCE_DIR_STRING_U_18, *PIMAGE_RESOURCE_DIR_STRING_U_18;

struct IMAGE_RESOURCE_DIR_STRING_U_18 {
    word Length;
    wchar16 NameString[9];
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

typedef struct VS_VERSION_INFO VS_VERSION_INFO, *PVS_VERSION_INFO;

struct VS_VERSION_INFO {
    word StructLength;
    word ValueLength;
    word StructType;
    wchar16 Info[16];
    byte Padding[2];
    dword Signature;
    word StructVersion[2];
    word FileVersion[4];
    word ProductVersion[4];
    dword FileFlagsMask[2];
    dword FileFlags;
    dword FileOS;
    dword FileType;
    dword FileSubtype;
    dword FileTimestamp;
};

typedef struct IMAGE_RESOURCE_DATA_ENTRY IMAGE_RESOURCE_DATA_ENTRY, *PIMAGE_RESOURCE_DATA_ENTRY;

struct IMAGE_RESOURCE_DATA_ENTRY {
    dword OffsetToData;
    dword Size;
    dword CodePage;
    dword Reserved;
};

typedef struct VarFileInfo VarFileInfo, *PVarFileInfo;

struct VarFileInfo {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct IMAGE_RESOURCE_DIRECTORY IMAGE_RESOURCE_DIRECTORY, *PIMAGE_RESOURCE_DIRECTORY;

struct IMAGE_RESOURCE_DIRECTORY {
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    word NumberOfNamedEntries;
    word NumberOfIdEntries;
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

typedef struct StringInfo StringInfo, *PStringInfo;

struct StringInfo {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct IMAGE_RESOURCE_DIR_STRING_U_24 IMAGE_RESOURCE_DIR_STRING_U_24, *PIMAGE_RESOURCE_DIR_STRING_U_24;

struct IMAGE_RESOURCE_DIR_STRING_U_24 {
    word Length;
    wchar16 NameString[12];
};

typedef ACCESS_MASK REGSAM;

typedef LONG LSTATUS;




undefined4 FUN_10001000(undefined4 param_1,int param_2)

{
  if (param_2 == 1) {
    DAT_1000be18 = param_1;
  }
  return 1;
}



void FUN_10001020(HWND param_1)

{
  LRESULT LVar1;
  LRESULT LVar2;
  WPARAM wParam;
  
  LVar1 = SendMessageA(param_1,0x146,0,0);
  wParam = 0;
  if (0 < LVar1) {
    do {
      LVar2 = SendMessageA(param_1,0x150,wParam,0);
      if (LVar2 != 0) {
        FUN_100025a6(LVar2);
      }
      wParam = wParam + 1;
    } while ((int)wParam < LVar1);
  }
  return;
}



void FUN_10001870(HWND param_1,undefined4 param_2)

{
  undefined4 uStack_c;
  undefined4 local_8;
  undefined4 local_4;
  
  uStack_c = 0;
  local_8 = 0xffffffff;
  local_4 = param_2;
  SendMessageA(param_1,0x438,0,(LPARAM)&uStack_c);
  return;
}



undefined4 FUN_100018b0(undefined4 param_1,HWND param_2,undefined4 *param_3,undefined4 *param_4)

{
  LRESULT LVar1;
  WPARAM wParam;
  LRESULT LVar2;
  undefined4 uVar3;
  
  LVar1 = SendMessageA(param_2,0x146,0,0);
  wParam = SendMessageA(param_2,0x147,0,0);
  LVar2 = SendMessageA(param_2,0x150,wParam,0);
  uVar3 = FUN_10001870(param_1,LVar2);
  *param_3 = uVar3;
  if ((int)(wParam + 1) < LVar1) {
    LVar1 = SendMessageA(param_2,0x150,wParam + 1,0);
    uVar3 = FUN_10001870(param_1,LVar1);
    *param_4 = uVar3;
    return 1;
  }
  *param_4 = 0xffffffff;
  return 1;
}



undefined4 FUN_10001940(HWND param_1,undefined4 param_2)

{
  WPARAM wParam;
  LRESULT LVar1;
  undefined4 uVar2;
  undefined4 local_c;
  undefined4 local_8;
  undefined4 local_4;
  
  local_c = 0;
  local_4 = param_2;
  local_8 = 0xffffffff;
  wParam = SendMessageA(param_1,0x438,0,(LPARAM)&local_c);
  if (-1 < (int)wParam) {
    LVar1 = SendMessageA(param_1,0xc9,wParam,0);
    SendMessageA(param_1,0xb1,0xffffffff,0);
    uVar2 = FUN_100019b0(param_1,LVar1);
    return uVar2;
  }
  return 0;
}



void FUN_100019b0(HWND param_1,int param_2)

{
  LRESULT LVar1;
  
  LVar1 = SendMessageA(param_1,0xce,0,0);
  SendMessageA(param_1,0xb6,0,param_2 - LVar1);
  return;
}



undefined4 FUN_100019e0(HKEY param_1,LPCSTR param_2,undefined4 param_3)

{
  LSTATUS LVar1;
  undefined4 local_8;
  DWORD local_4;
  
  local_4 = 4;
  local_8 = 0;
  LVar1 = RegOpenKeyExA((HKEY)0x80000001,(LPCSTR)param_1,0,0x20019,&param_1);
  if (LVar1 == 0) {
    LVar1 = RegQueryValueExA(param_1,param_2,(LPDWORD)0x0,(LPDWORD)0x0,(LPBYTE)&local_8,&local_4);
    if (LVar1 == 0) {
      RegCloseKey(param_1);
      return local_8;
    }
  }
  return param_3;
}



undefined4 FUN_10001a50(HKEY param_1,LPCSTR param_2)

{
  LSTATUS LVar1;
  DWORD DStack_4;
  
  LVar1 = RegCreateKeyExA((HKEY)0x80000001,(LPCSTR)param_1,0,&DAT_1000bee0,0,0x20006,
                          (LPSECURITY_ATTRIBUTES)0x0,&param_1,&DStack_4);
  if (LVar1 == 0) {
    LVar1 = RegSetValueExA(param_1,param_2,0,4,&stack0x0000000c,4);
    if (LVar1 == 0) {
      RegCloseKey(param_1);
      return 1;
    }
  }
  return 0;
}



undefined4 FUN_10001ac0(HWND param_1_00,LPSTR param_1)

{
  HANDLE hFile;
  LPCSTR pCVar1;
  LPSTR lpString1;
  DWORD DVar2;
  BOOL BVar3;
  size_t _MaxCount;
  int iVar4;
  WPARAM wParam;
  DWORD *lpNumberOfBytesRead;
  LPOVERLAPPED lpOverlapped;
  HANDLE pvStack_11c;
  undefined4 uStack_118;
  undefined *puStack_114;
  char acStack_110 [8];
  DWORD local_108;
  CHAR local_104 [260];
  
  wParam = 1;
  hFile = CreateFileA(param_1,0x80000000,1,(LPSECURITY_ATTRIBUTES)0x0,3,0x80,(HANDLE)0x0);
  if (hFile == (HANDLE)0xffffffff) {
    pCVar1 = (LPCSTR)FUN_100022d0(param_1);
    if (pCVar1 != (LPCSTR)0x0) {
      param_1 = CharNextA(pCVar1);
    }
    GetModuleFileNameA((HMODULE)0x0,local_104,0x104);
    pCVar1 = (LPCSTR)FUN_100022d0(local_104);
    lpString1 = CharNextA(pCVar1);
    lstrcpyA(lpString1,param_1);
    hFile = CreateFileA(local_104,0x80000000,1,(LPSECURITY_ATTRIBUTES)0x0,3,0x80,(HANDLE)0x0);
    if (hFile == (HANDLE)0xffffffff) {
      return 0;
    }
  }
  lpNumberOfBytesRead = &local_108;
  lpOverlapped = (LPOVERLAPPED)0x0;
  DVar2 = lstrlenA(s___rtf1_10009030);
  BVar3 = ReadFile(hFile,acStack_110,DVar2,lpNumberOfBytesRead,lpOverlapped);
  if (BVar3 != 0) {
    _MaxCount = lstrlenA(s___rtf1_10009030);
    iVar4 = _strncmp(acStack_110,s___rtf1_10009030,_MaxCount);
    wParam = 2 - (iVar4 != 0);
    SetFilePointer(hFile,0,(PLONG)0x0,0);
  }
  DVar2 = GetFileSize(hFile,(LPDWORD)0x0);
  if (DVar2 == 0xffffffff) {
    DVar2 = 0x7fff;
  }
  SendMessageA(param_1_00,0x435,0,DVar2);
  uStack_118 = 0;
  puStack_114 = &LAB_10001c20;
  pvStack_11c = hFile;
  SendMessageA(param_1_00,0x449,wParam,(LPARAM)&pvStack_11c);
  CloseHandle(hFile);
  return 1;
}



undefined4 FUN_10001c50(void)

{
  int iVar1;
  tagMSG local_1c;
  
  iVar1 = PeekMessageA(&local_1c,(HWND)0x0,0,0,1);
  while( true ) {
    if (iVar1 == 0) {
      return 1;
    }
    if ((((local_1c.message == 0x12) || (local_1c.message == 0x10)) || (local_1c.message == 0x112))
       || (local_1c.message == 2)) break;
    TranslateMessage(&local_1c);
    DispatchMessageA(&local_1c);
    iVar1 = PeekMessageA(&local_1c,(HWND)0x0,0,0,1);
  }
  PostMessageA(local_1c.hwnd,local_1c.message,local_1c.wParam,local_1c.lParam);
  return 0;
}



void FUN_10001cf0(HWND param_1,undefined4 param_2)

{
  BOOL BVar1;
  HCURSOR pHVar2;
  int iVar3;
  int iVar4;
  tagPDA *ptVar5;
  HDC *ppHVar6;
  HDC apHStack_88 [2];
  int iStack_80;
  int iStack_7c;
  int iStack_78;
  int iStack_74;
  int iStack_70;
  int iStack_6c;
  int iStack_68;
  int iStack_64;
  int iStack_60;
  int iStack_5c;
  DOCINFOA DStack_58;
  tagPDA local_44;
  
  ptVar5 = &local_44;
  for (iVar4 = 0x10; iVar4 != 0; iVar4 = iVar4 + -1) {
    ptVar5->lStructSize = 0;
    ptVar5 = (tagPDA *)&ptVar5->hwndOwner;
  }
  *(undefined2 *)&ptVar5->lStructSize = 0;
  local_44.lStructSize = 0x42;
  local_44.hwndOwner = DAT_1000be1c;
  local_44.hInstance = DAT_1000be18;
  local_44.Flags = 0x14c;
  BVar1 = PrintDlgA(&local_44);
  if (BVar1 == 1) {
    DAT_1000bed4 = 0;
    DAT_1000bec8 = CreateDialogParamA(DAT_1000be18,(LPCSTR)0x64,DAT_1000be1c,(DLGPROC)&LAB_10001ff0,
                                      0);
    pHVar2 = LoadCursorA((HINSTANCE)0x0,(LPCSTR)0x7f8a);
    pHVar2 = SetCursor(pHVar2);
    FUN_10001c50();
    ppHVar6 = apHStack_88;
    for (iVar4 = 0xc; iVar4 != 0; iVar4 = iVar4 + -1) {
      *ppHVar6 = (HDC)0x0;
      ppHVar6 = ppHVar6 + 1;
    }
    apHStack_88[1] = local_44.hDC;
    apHStack_88[0] = local_44.hDC;
    FUN_100018b0(param_1,param_2,&iStack_60,&iStack_5c);
    if (iStack_60 == -1) {
      iStack_60 = 0;
    }
    if (iStack_5c <= iStack_60) {
      iStack_5c = -1;
    }
    SetMapMode(local_44.hDC,1);
    GetDeviceCaps(local_44.hDC,0x58);
    GetDeviceCaps(local_44.hDC,0x5a);
    GetDeviceCaps(local_44.hDC,0x70);
    iStack_78 = __ftol();
    iStack_80 = iStack_78 + 0x2d0;
    iStack_70 = iStack_80;
    GetDeviceCaps(local_44.hDC,0x71);
    iStack_74 = __ftol();
    iStack_7c = iStack_74 + 0x2d0;
    iStack_6c = iStack_7c;
    GetDeviceCaps(local_44.hDC,8);
    iVar4 = __ftol();
    iStack_78 = -iVar4 - iStack_78;
    iStack_68 = iStack_78;
    GetDeviceCaps(local_44.hDC,10);
    iVar4 = __ftol();
    iStack_74 = -iVar4 - iStack_74;
    DStack_58.cbSize = 0x14;
    DStack_58.lpszDatatype = (LPCSTR)0x0;
    DStack_58.lpszDocName = &DAT_1000be28;
    DStack_58.fwType = 0;
    DStack_58.lpszOutput = (LPCSTR)0x0;
    iStack_64 = iStack_74;
    StartDocA(local_44.hDC,&DStack_58);
    StartPage(local_44.hDC);
    iVar4 = iStack_60;
    iVar3 = iStack_5c;
    if (iStack_5c == -1) {
      iVar3 = SendMessageA(param_1,0xe,0,0);
    }
    while ((iVar4 < iVar3 && (DAT_1000bed4 == 0))) {
      FUN_10001c50();
      iVar4 = SendMessageA(param_1,0x439,0,(LPARAM)apHStack_88);
      SendMessageA(param_1,0x433,0,(LPARAM)&iStack_80);
      if (iVar4 < iVar3) {
        EndPage(local_44.hDC);
        StartPage(local_44.hDC);
        iStack_60 = iVar4;
      }
      FUN_10001c50();
    }
    SendMessageA(param_1,0x439,1,0);
    EndPage(local_44.hDC);
    EndDoc(local_44.hDC);
    DeleteDC(local_44.hDC);
    if (DAT_1000bed4 == 0) {
      DestroyWindow(DAT_1000bec8);
    }
    SetCursor(pHVar2);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

INT_PTR EBUEula(LPCSTR param_1,LPCSTR param_2,LPCSTR param_3,int param_4)

{
  LPCSTR lpsz;
  LPSTR pCVar1;
  int iVar2;
  HWND pHVar3;
  INT_PTR IVar4;
  LPCSTR lpsz_00;
  DLGPROC pDVar5;
  LPCSTR *ppCVar6;
  CHAR *local_318;
  CHAR *local_314;
  int local_310;
  char local_30c [260];
  CHAR aCStack_208 [260];
  CHAR aCStack_104 [260];
  
                    // 0x2050  1  EBUEula
  lpsz_00 = (LPCSTR)0x0;
  if (param_1 != (LPCSTR)0x0) {
    for (; (*param_1 == '\\' || (*param_1 == '/')); param_1 = CharNextA(param_1)) {
    }
    lstrcpyA(local_30c,param_1);
    lpsz = local_30c;
    if (local_30c[0] != '\0') {
      do {
        if ((local_30c[0] != '\\') && (local_30c[0] != '/')) {
          lpsz_00 = lpsz;
        }
        lpsz = CharNextA(lpsz);
        local_30c[0] = *lpsz;
      } while (local_30c[0] != '\0');
      if ((lpsz_00 != (LPCSTR)0x0) && (*lpsz_00 != '\0')) {
        pCVar1 = CharNextA(lpsz_00);
        *pCVar1 = '\0';
      }
    }
  }
  local_310 = param_4;
  local_318 = param_2;
  local_314 = param_3;
  if (((param_3 == (LPCSTR)0x0) || (iVar2 = lstrlenA(param_3), iVar2 == 0)) &&
     (iVar2 = LoadStringA(DAT_1000be18,4000,aCStack_208,0x104), iVar2 != 0)) {
    local_314 = aCStack_208;
  }
  if (((local_318 == (LPCSTR)0x0) || (iVar2 = lstrlenA(local_318), iVar2 == 0)) &&
     (iVar2 = LoadStringA(DAT_1000be18,0xfa1,aCStack_104,0x104), iVar2 != 0)) {
    local_318 = aCStack_104;
  }
  LoadStringA(DAT_1000be18,3,&DAT_1000be28,0x80);
  _DAT_1000bed0 = LoadLibraryA(s_RICHED32_DLL_10009044);
  if (param_4 != 0) {
    iVar2 = FUN_100019e0(local_30c,s_FIRSTRUN_10009038,0);
    if (iVar2 != 0) {
      return 1;
    }
    ppCVar6 = &local_318;
    pDVar5 = (DLGPROC)&LAB_10001070;
    pHVar3 = GetDesktopWindow();
    IVar4 = DialogBoxParamA(DAT_1000be18,(LPCSTR)0xc8,pHVar3,pDVar5,(LPARAM)ppCVar6);
    if (IVar4 == -1) {
      ppCVar6 = &local_318;
      pDVar5 = (DLGPROC)&LAB_10001400;
      pHVar3 = GetDesktopWindow();
      IVar4 = DialogBoxParamA(DAT_1000be18,(LPCSTR)0x67,pHVar3,pDVar5,(LPARAM)ppCVar6);
      if (IVar4 == -1) {
        return -1;
      }
    }
    FUN_10001a50(local_30c,s_FIRSTRUN_10009038,IVar4);
    return IVar4;
  }
  ppCVar6 = &local_318;
  pDVar5 = (DLGPROC)&LAB_10001070;
  pHVar3 = GetDesktopWindow();
  IVar4 = DialogBoxParamA(DAT_1000be18,(LPCSTR)0xc8,pHVar3,pDVar5,(LPARAM)ppCVar6);
  if (IVar4 == -1) {
    ppCVar6 = &local_318;
    pDVar5 = (DLGPROC)&LAB_10001400;
    pHVar3 = GetDesktopWindow();
    DialogBoxParamA(DAT_1000be18,(LPCSTR)0x67,pHVar3,pDVar5,(LPARAM)ppCVar6);
  }
  return 1;
}



void FUN_10002260(HWND param_1)

{
  int iVar1;
  int iVar2;
  CHAR aCStack_100 [256];
  
  lstrcpyA(aCStack_100,&DAT_1000be28);
  lstrcatA(aCStack_100,&DAT_10009054);
  iVar1 = lstrlenA(aCStack_100);
  iVar1 = 0x100 - iVar1;
  iVar2 = lstrlenA(aCStack_100);
  GetWindowTextA(param_1,aCStack_100 + iVar2,iVar1);
  SetWindowTextA(param_1,aCStack_100);
  return;
}



LPCSTR FUN_100022d0(LPCSTR param_1)

{
  char cVar1;
  LPCSTR pCVar2;
  
  pCVar2 = (LPCSTR)0x0;
  cVar1 = *param_1;
  if (cVar1 == '\0') {
    return (LPCSTR)0x0;
  }
  do {
    if (cVar1 == '\\') {
      pCVar2 = param_1;
    }
    param_1 = CharNextA(param_1);
    cVar1 = *param_1;
  } while (cVar1 != '\0');
  return pCVar2;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_10002300(void)

{
  if (DAT_1000bf1c == 0) {
    LoadStringA(DAT_1000be18,1,&DAT_1000befc,5);
    LoadStringA(DAT_1000be18,2,&DAT_1000bf0c,5);
    DAT_1000bf1c = 1;
    DAT_1000bf18 = LoadLibraryA(s_IMM32_DLL_100090f0);
    if (DAT_1000bf18 == (HMODULE)0x0) {
      DAT_1000bf14 = DAT_1000bf18;
      return;
    }
    DAT_1000bee4 = GetProcAddress(DAT_1000bf18,s_ImmCreateContext_100090dc);
    DAT_1000bef0 = GetProcAddress(DAT_1000bf18,s_ImmAssociateContext_100090c8);
    DAT_1000bef8 = GetProcAddress(DAT_1000bf18,s_ImmDestroyContext_100090b4);
    DAT_1000beec = GetProcAddress(DAT_1000bf18,s_ImmGetContext_100090a4);
    DAT_1000bee8 = GetProcAddress(DAT_1000bf18,s_ImmSetOpenStatus_10009090);
    DAT_1000bf04 = GetProcAddress(DAT_1000bf18,s_ImmReleaseContext_1000907c);
    DAT_1000bef4 = GetProcAddress(DAT_1000bf18,s_ImmNotifyIME_1000906c);
    _DAT_1000bf08 = GetProcAddress(DAT_1000bf18,s_ImmGetDefaultIMEWnd_10009058);
    if (((((DAT_1000bee4 == (FARPROC)0x0) || (DAT_1000bef0 == (FARPROC)0x0)) ||
         (DAT_1000bef8 == (FARPROC)0x0)) ||
        ((DAT_1000beec == (FARPROC)0x0 || (DAT_1000bee8 == (FARPROC)0x0)))) ||
       ((DAT_1000bf04 == (FARPROC)0x0 ||
        ((DAT_1000bef4 == (FARPROC)0x0 || (_DAT_1000bf08 == (FARPROC)0x0)))))) {
      FUN_10002450();
    }
    DAT_1000bf14 = (HMODULE)0x1;
  }
  return;
}



void FUN_10002450(void)

{
  if (DAT_1000bf18 != (HMODULE)0x0) {
    FreeLibrary(DAT_1000bf18);
    DAT_1000bf18 = (HMODULE)0x0;
  }
  DAT_1000bf14 = 0;
  DAT_1000bf1c = 0;
  return;
}



void FUN_10002480(undefined4 param_1,undefined4 param_2)

{
  int local_4;
  
  local_4 = 0;
  FUN_100024c0(param_1,&local_4,param_2);
  if (local_4 != 0) {
    (*DAT_1000bef8)(local_4);
  }
  return;
}



void FUN_100024c0(int param_1,int *param_2,uint param_3)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 *unaff_retaddr;
  
  if (DAT_1000bf1c == 0) {
    FUN_10002300();
  }
  if ((param_1 != 0) && (DAT_1000bf14 != 0)) {
    iVar1 = FUN_10002590();
    if (iVar1 == 0) {
      param_3 = 0;
    }
    if ((param_3 & 0x8000) != 0) {
      if (*param_2 == 0) {
        uVar2 = (*DAT_1000bee4)();
        iVar1 = (*DAT_1000bef0)(param_1,uVar2);
        if (iVar1 != 0) {
          (*DAT_1000bef8)(iVar1);
        }
      }
      else {
        (*DAT_1000bef0)(param_1,*param_2);
        *param_2 = 0;
      }
      iVar1 = (*DAT_1000beec)(param_1);
      if (iVar1 == 0) {
        uVar2 = (*DAT_1000bee4)();
        (*DAT_1000bef0)(param_1,uVar2);
        iVar1 = (*DAT_1000beec)(param_1);
        if (iVar1 == 0) {
          return;
        }
      }
      (*DAT_1000bee8)(iVar1,param_3 >> 0xe & 1);
      (*DAT_1000bf04)(param_1,iVar1);
      return;
    }
    uVar2 = (*DAT_1000bef0)(param_1,0);
    *unaff_retaddr = uVar2;
  }
  return;
}



bool FUN_10002590(void)

{
  return DAT_1000bf0c == '1';
}



BOOL PrintDlgA(LPPRINTDLGA pPD)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x100025a0. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = PrintDlgA(pPD);
  return BVar1;
}



void FUN_100025a6(LPVOID param_1)

{
  int iVar1;
  undefined4 local_2c;
  int local_28;
  undefined4 local_24;
  int local_20;
  void *local_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &DAT_100081b8;
  puStack_10 = &LAB_10003dac;
  local_14 = ExceptionList;
  if (param_1 == (LPVOID)0x0) {
    return;
  }
  if (DAT_1000c614 == 3) {
    ExceptionList = &local_14;
    FUN_10003c3c(9);
    local_8 = 0;
    local_20 = FUN_10002d7a(param_1);
    if (local_20 != 0) {
      FUN_10002da5(local_20,param_1);
    }
    local_8 = 0xffffffff;
    FUN_10002610();
    iVar1 = local_20;
  }
  else {
    ExceptionList = &local_14;
    if (DAT_1000c614 != 2) goto LAB_10002672;
    ExceptionList = &local_14;
    FUN_10003c3c(9);
    local_8 = 1;
    local_28 = FUN_100037df(param_1,&local_2c,&local_24);
    if (local_28 != 0) {
      FUN_10003836(local_2c,local_24,local_28);
    }
    local_8 = 0xffffffff;
    FUN_10002668();
    iVar1 = local_28;
  }
  if (iVar1 != 0) {
    ExceptionList = local_14;
    return;
  }
LAB_10002672:
  HeapFree(DAT_1000c610,0,param_1);
  ExceptionList = local_14;
  return;
}



void FUN_10002610(void)

{
  FUN_10003c9d(9);
  return;
}



void FUN_10002668(void)

{
  FUN_10003c9d(9);
  return;
}



// Library Function - Single Match
//  _malloc
// 
// Library: Visual Studio 2003 Release

void * __cdecl _malloc(size_t _Size)

{
  void *pvVar1;
  
  pvVar1 = __nh_malloc(_Size,DAT_1000bfa0);
  return pvVar1;
}



// Library Function - Single Match
//  __nh_malloc
// 
// Library: Visual Studio 2003 Release

void * __cdecl __nh_malloc(size_t _Size,int _NhFlag)

{
  void *pvVar1;
  int iVar2;
  
  if (_Size < 0xffffffe1) {
    do {
      pvVar1 = (void *)FUN_100026cd(_Size);
      if (pvVar1 != (void *)0x0) {
        return pvVar1;
      }
      if (_NhFlag == 0) {
        return (void *)0x0;
      }
      iVar2 = FUN_10003e84(_Size);
    } while (iVar2 != 0);
  }
  return (void *)0x0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_100026cd(uint param_1)

{
  int iVar1;
  uint dwBytes;
  void *local_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &DAT_100081d0;
  puStack_10 = &LAB_10003dac;
  local_14 = ExceptionList;
  if (DAT_1000c614 == 3) {
    ExceptionList = &local_14;
    if (param_1 <= _DAT_1000c60c) {
      ExceptionList = &local_14;
      FUN_10003c3c(9);
      local_8 = 0;
      iVar1 = FUN_100030ce(param_1);
      local_8 = 0xffffffff;
      FUN_10002734();
      if (iVar1 != 0) {
        ExceptionList = local_14;
        return;
      }
    }
  }
  else {
    ExceptionList = &local_14;
    if (DAT_1000c614 == 2) {
      if (param_1 == 0) {
        dwBytes = 0x10;
      }
      else {
        dwBytes = param_1 + 0xf & 0xfffffff0;
      }
      ExceptionList = &local_14;
      if (dwBytes <= _DAT_1000b144) {
        ExceptionList = &local_14;
        FUN_10003c3c(9);
        local_8 = 1;
        iVar1 = FUN_1000387b(dwBytes >> 4);
        local_8 = 0xffffffff;
        FUN_10002793();
        if (iVar1 != 0) {
          ExceptionList = local_14;
          return;
        }
      }
      goto LAB_100027ac;
    }
  }
  if (param_1 == 0) {
    param_1 = 1;
  }
  dwBytes = param_1 + 0xf & 0xfffffff0;
LAB_100027ac:
  HeapAlloc(DAT_1000c610,0,dwBytes);
  ExceptionList = local_14;
  return;
}



void FUN_10002734(void)

{
  FUN_10003c9d(9);
  return;
}



void FUN_10002793(void)

{
  FUN_10003c9d(9);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_100027c9(byte *param_1)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  byte *pbVar5;
  
  while( true ) {
    if (_DAT_1000b424 < 2) {
      uVar1 = *(byte *)(DAT_1000b218 + (uint)*param_1 * 2) & 8;
    }
    else {
      uVar1 = FUN_10003e9f(*param_1,8);
    }
    if (uVar1 == 0) break;
    param_1 = param_1 + 1;
  }
  uVar1 = (uint)*param_1;
  pbVar5 = param_1 + 1;
  if ((uVar1 == 0x2d) || (uVar4 = uVar1, uVar1 == 0x2b)) {
    uVar4 = (uint)*pbVar5;
    pbVar5 = param_1 + 2;
  }
  iVar3 = 0;
  while( true ) {
    if (_DAT_1000b424 < 2) {
      uVar2 = *(byte *)(DAT_1000b218 + uVar4 * 2) & 4;
    }
    else {
      uVar2 = FUN_10003e9f(uVar4,4);
    }
    if (uVar2 == 0) break;
    iVar3 = (uVar4 - 0x30) + iVar3 * 10;
    uVar4 = (uint)*pbVar5;
    pbVar5 = pbVar5 + 1;
  }
  if (uVar1 == 0x2d) {
    iVar3 = -iVar3;
  }
  return iVar3;
}



void FUN_10002854(undefined4 param_1)

{
  FUN_100027c9(param_1);
  return;
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



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_10002898(void)

{
  FUN_100028b0();
  _DAT_1000bf24 = FUN_10003fa4();
  FUN_10003f54();
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_100028b0(void)

{
  _DAT_1000b434 = &UNK_10004027;
  _DAT_1000b430 = __cfltcvt;
  _DAT_1000b438 = __fassign;
  _DAT_1000b43c = FUN_10003fcd;
  _DAT_1000b440 = &UNK_10004075;
  _DAT_1000b444 = __cfltcvt;
  return;
}



// Library Function - Single Match
//  __ftol
// 
// Library: Visual Studio

longlong __ftol(void)

{
  float10 in_ST0;
  
  return (longlong)ROUND(in_ST0);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_1000290f(undefined4 param_1_00,int param_1)

{
  int iVar1;
  undefined4 uVar2;
  
  if (param_1 == 1) {
    DAT_1000bfac = GetVersion();
    iVar1 = FUN_10002c2d(1);
    if (iVar1 != 0) {
      _DAT_1000bfb8 = DAT_1000bfac >> 8 & 0xff;
      _DAT_1000bfb4 = DAT_1000bfac & 0xff;
      DAT_1000bfac = DAT_1000bfac >> 0x10;
      _DAT_1000bfb0 = _DAT_1000bfb4 * 0x100 + _DAT_1000bfb8;
      iVar1 = FUN_10004511();
      if (iVar1 != 0) {
        DAT_1000c618 = GetCommandLineA();
        DAT_1000bf2c = FUN_10004bb3();
        FUN_1000469d();
        FUN_10004966();
        FUN_100048ad();
        FUN_100043f3();
        _DAT_1000bf28 = _DAT_1000bf28 + 1;
        goto LAB_100029e2;
      }
      FUN_10002c8a();
    }
LAB_1000296f:
    uVar2 = 0;
  }
  else {
    if (param_1 == 0) {
      if (_DAT_1000bf28 < 1) goto LAB_1000296f;
      _DAT_1000bf28 = _DAT_1000bf28 + -1;
      if (_DAT_1000bfe4 == 0) {
        FUN_10004431();
      }
      FUN_10004859();
      FUN_10004565();
      FUN_10002c8a();
    }
    else if (param_1 == 3) {
      FUN_100045fd(0);
    }
LAB_100029e2:
    uVar2 = 1;
  }
  return uVar2;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int entry(undefined4 param_1,int param_2,undefined4 param_3)

{
  int iVar1;
  int iVar2;
  int iVar3;
  
  iVar1 = param_2;
  iVar2 = _DAT_1000bf28;
  if (param_2 != 0) {
    if ((param_2 != 1) && (param_2 != 2)) goto LAB_10002a30;
    if ((DAT_1000c61c != (code *)0x0) &&
       (iVar2 = (*DAT_1000c61c)(param_1,param_2,param_3), iVar2 == 0)) {
      return 0;
    }
    iVar2 = FUN_1000290f(param_1,param_2,param_3);
  }
  if (iVar2 == 0) {
    return 0;
  }
LAB_10002a30:
  iVar2 = FUN_10001000(param_1,param_2,param_3);
  if (param_2 == 1) {
    if (iVar2 != 0) {
      return iVar2;
    }
    FUN_1000290f(param_1,0,param_3);
  }
  if ((param_2 != 0) && (param_2 != 3)) {
    return iVar2;
  }
  iVar3 = FUN_1000290f(param_1,param_2,param_3);
  param_2 = iVar2;
  if (iVar3 == 0) {
    param_2 = 0;
  }
  if (param_2 != 0) {
    if (DAT_1000c61c != (code *)0x0) {
      iVar2 = (*DAT_1000c61c)(param_1,iVar1,param_3);
      return iVar2;
    }
    return param_2;
  }
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __amsg_exit
// 
// Library: Visual Studio 2003 Release

void __cdecl __amsg_exit(int param_1)

{
  if ((DAT_1000bf34 == 1) || ((DAT_1000bf34 == 0 && (_DAT_1000bf38 == 1)))) {
    FUN_10004ce5();
  }
  FUN_10004d1e(param_1);
  (*DAT_10009114)(0xff);
  return;
}



void FUN_10002ab8(undefined4 *param_1)

{
  int iVar1;
  HMODULE pHVar2;
  
  *param_1 = 0;
  pHVar2 = GetModuleHandleA((LPCSTR)0x0);
  if ((*(short *)&pHVar2->unused == 0x5a4d) && (iVar1 = pHVar2[0xf].unused, iVar1 != 0)) {
    *(undefined *)param_1 = *(undefined *)((int)&pHVar2[6].unused + iVar1 + 2);
    *(undefined *)((int)param_1 + 1) = *(undefined *)((int)&pHVar2[6].unused + iVar1 + 3);
  }
  return;
}



int FUN_10002ae5(void)

{
  char cVar1;
  BOOL BVar2;
  int iVar3;
  DWORD DVar4;
  char *pcVar5;
  undefined4 unaff_EBX;
  char local_1230 [4240];
  char local_1a0 [260];
  DWORD local_9c;
  uint local_98;
  DWORD local_8c;
  undefined4 uStackY_18;
  byte bVar6;
  
  bVar6 = (byte)unaff_EBX;
  FUN_100051e0();
  local_9c = 0x94;
  BVar2 = GetVersionExA((LPOSVERSIONINFOA)&local_9c);
  if (((BVar2 == 0) || (local_8c != 2)) || (local_98 < 5)) {
    uStackY_18._0_1_ = '?';
    uStackY_18._1_1_ = '+';
    uStackY_18._2_1_ = '\0';
    uStackY_18._3_1_ = '\x10';
    DVar4 = GetEnvironmentVariableA("__MSVCRT_HEAP_SELECT",local_1230,0x1090);
    if (DVar4 != 0) {
      pcVar5 = local_1230;
      while (local_1230[0] != '\0') {
        cVar1 = *pcVar5;
        if (('`' < cVar1) && (cVar1 < '{')) {
          *pcVar5 = cVar1 + -0x20;
        }
        pcVar5 = pcVar5 + 1;
        local_1230[0] = *pcVar5;
      }
      uStackY_18._0_1_ = '}';
      uStackY_18._1_1_ = '+';
      uStackY_18._2_1_ = '\0';
      uStackY_18._3_1_ = '\x10';
      iVar3 = _strncmp("__GLOBAL_HEAP_SELECTED",local_1230,0x16);
      if (iVar3 == 0) {
        pcVar5 = local_1230;
      }
      else {
        uStackY_18._0_1_ = -0x61;
        uStackY_18._1_1_ = '+';
        uStackY_18._2_1_ = '\0';
        uStackY_18._3_1_ = '\x10';
        GetModuleFileNameA((HMODULE)0x0,local_1a0,0x104);
        pcVar5 = local_1a0;
        while (local_1a0[0] != '\0') {
          cVar1 = *pcVar5;
          if (('`' < cVar1) && (cVar1 < '{')) {
            *pcVar5 = cVar1 + -0x20;
          }
          bVar6 = (byte)unaff_EBX;
          pcVar5 = pcVar5 + 1;
          local_1a0[0] = *pcVar5;
        }
        pcVar5 = _strstr(local_1230,local_1a0);
      }
      if ((pcVar5 != (char *)0x0) && (pcVar5 = _strchr(pcVar5,0x2c), pcVar5 != (char *)0x0)) {
        pcVar5 = pcVar5 + 1;
        cVar1 = *pcVar5;
        while (cVar1 != '\0') {
          if (*pcVar5 == ';') {
            *pcVar5 = '\0';
          }
          else {
            pcVar5 = pcVar5 + 1;
          }
          cVar1 = *pcVar5;
        }
        uStackY_18._0_1_ = '\x05';
        uStackY_18._1_1_ = ',';
        uStackY_18._2_1_ = '\0';
        uStackY_18._3_1_ = '\x10';
        iVar3 = FUN_10004e71();
        if (iVar3 == 2) {
          return 2;
        }
        if (iVar3 == 3) {
          return 3;
        }
        if (iVar3 == 1) {
          return 1;
        }
      }
    }
    FUN_10002ab8();
    iVar3 = 3 - (uint)(bVar6 < 6);
  }
  else {
    iVar3 = 1;
  }
  return iVar3;
}



undefined4 FUN_10002c2d(int param_1)

{
  int iVar1;
  
  DAT_1000c610 = HeapCreate((uint)(param_1 == 0),0x1000,0);
  if (DAT_1000c610 != (HANDLE)0x0) {
    DAT_1000c614 = FUN_10002ae5();
    if (DAT_1000c614 == 3) {
      iVar1 = FUN_10002d32(0x3f8);
    }
    else {
      if (DAT_1000c614 != 2) {
        return 1;
      }
      iVar1 = FUN_10003583();
    }
    if (iVar1 != 0) {
      return 1;
    }
    HeapDestroy(DAT_1000c610);
  }
  return 0;
}



void FUN_10002c8a(void)

{
  int iVar1;
  LPVOID *ppvVar2;
  undefined4 *puVar3;
  
  if (DAT_1000c614 == 3) {
    iVar1 = 0;
    if (0 < DAT_1000c604) {
      ppvVar2 = (LPVOID *)((int)DAT_1000c608 + 0xc);
      do {
        VirtualFree(*ppvVar2,0x100000,0x4000);
        VirtualFree(*ppvVar2,0,0x8000);
        HeapFree(DAT_1000c610,0,ppvVar2[1]);
        ppvVar2 = ppvVar2 + 5;
        iVar1 = iVar1 + 1;
      } while (iVar1 < DAT_1000c604);
    }
    HeapFree(DAT_1000c610,0,DAT_1000c608);
  }
  else if (DAT_1000c614 == 2) {
    puVar3 = &DAT_10009120;
    do {
      if ((LPVOID)puVar3[4] != (LPVOID)0x0) {
        VirtualFree((LPVOID)puVar3[4],0,0x8000);
      }
      puVar3 = (undefined4 *)*puVar3;
    } while (puVar3 != &DAT_10009120);
  }
  HeapDestroy(DAT_1000c610);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_10002d32(undefined4 param_1)

{
  DAT_1000c608 = HeapAlloc(DAT_1000c610,0,0x140);
  if (DAT_1000c608 == (LPVOID)0x0) {
    return 0;
  }
  DAT_1000c600 = 0;
  DAT_1000c604 = 0;
  DAT_1000c5fc = DAT_1000c608;
  _DAT_1000c60c = param_1;
  DAT_1000c5f4 = 0x10;
  return 1;
}



uint FUN_10002d7a(int param_1)

{
  uint uVar1;
  
  uVar1 = DAT_1000c608;
  while( true ) {
    if (DAT_1000c608 + DAT_1000c604 * 0x14 <= uVar1) {
      return 0;
    }
    if ((uint)(param_1 - *(int *)(uVar1 + 0xc)) < 0x100000) break;
    uVar1 = uVar1 + 0x14;
  }
  return uVar1;
}



void FUN_10002da5(uint *param_1,int param_2)

{
  char *pcVar1;
  uint *puVar2;
  int *piVar3;
  char cVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  byte bVar8;
  uint uVar9;
  uint *puVar10;
  uint *puVar11;
  uint *puVar12;
  uint uVar13;
  uint uVar14;
  uint local_8;
  
  uVar5 = param_1[4];
  puVar12 = (uint *)(param_2 + -4);
  uVar14 = param_2 - param_1[3] >> 0xf;
  piVar3 = (int *)(uVar14 * 0x204 + 0x144 + uVar5);
  uVar13 = *puVar12;
  local_8 = uVar13 - 1;
  if ((local_8 & 1) == 0) {
    uVar6 = *(uint *)(local_8 + (int)puVar12);
    uVar7 = *(uint *)(param_2 + -8);
    if ((uVar6 & 1) == 0) {
      uVar9 = ((int)uVar6 >> 4) - 1;
      if (0x3f < uVar9) {
        uVar9 = 0x3f;
      }
      if (*(int *)((int)puVar12 + uVar13 + 3) == *(int *)((int)puVar12 + uVar13 + 7)) {
        if (uVar9 < 0x20) {
          pcVar1 = (char *)(uVar9 + 4 + uVar5);
          uVar9 = ~(0x80000000U >> ((byte)uVar9 & 0x1f));
          puVar10 = (uint *)(uVar5 + 0x44 + uVar14 * 4);
          *puVar10 = *puVar10 & uVar9;
          *pcVar1 = *pcVar1 + -1;
          if (*pcVar1 == '\0') {
            *param_1 = *param_1 & uVar9;
          }
        }
        else {
          pcVar1 = (char *)(uVar9 + 4 + uVar5);
          uVar9 = ~(0x80000000U >> ((byte)uVar9 - 0x20 & 0x1f));
          puVar10 = (uint *)(uVar5 + 0xc4 + uVar14 * 4);
          *puVar10 = *puVar10 & uVar9;
          *pcVar1 = *pcVar1 + -1;
          if (*pcVar1 == '\0') {
            param_1[1] = param_1[1] & uVar9;
          }
        }
      }
      local_8 = local_8 + uVar6;
      *(undefined4 *)(*(int *)((int)puVar12 + uVar13 + 7) + 4) =
           *(undefined4 *)((int)puVar12 + uVar13 + 3);
      *(undefined4 *)(*(int *)((int)puVar12 + uVar13 + 3) + 8) =
           *(undefined4 *)((int)puVar12 + uVar13 + 7);
    }
    puVar10 = (uint *)(((int)local_8 >> 4) + -1);
    if ((uint *)0x3f < puVar10) {
      puVar10 = (uint *)0x3f;
    }
    puVar11 = param_1;
    if ((uVar7 & 1) == 0) {
      puVar12 = (uint *)((int)puVar12 - uVar7);
      puVar11 = (uint *)(((int)uVar7 >> 4) + -1);
      if ((uint *)0x3f < puVar11) {
        puVar11 = (uint *)0x3f;
      }
      local_8 = local_8 + uVar7;
      puVar10 = (uint *)(((int)local_8 >> 4) + -1);
      if ((uint *)0x3f < puVar10) {
        puVar10 = (uint *)0x3f;
      }
      if (puVar11 != puVar10) {
        if (puVar12[1] == puVar12[2]) {
          if (puVar11 < (uint *)0x20) {
            uVar13 = ~(0x80000000U >> ((byte)puVar11 & 0x1f));
            puVar2 = (uint *)(uVar5 + 0x44 + uVar14 * 4);
            *puVar2 = *puVar2 & uVar13;
            pcVar1 = (char *)((int)puVar11 + uVar5 + 4);
            *pcVar1 = *pcVar1 + -1;
            if (*pcVar1 == '\0') {
              *param_1 = *param_1 & uVar13;
            }
          }
          else {
            uVar13 = ~(0x80000000U >> ((byte)puVar11 - 0x20 & 0x1f));
            puVar2 = (uint *)(uVar5 + 0xc4 + uVar14 * 4);
            *puVar2 = *puVar2 & uVar13;
            pcVar1 = (char *)((int)puVar11 + uVar5 + 4);
            *pcVar1 = *pcVar1 + -1;
            if (*pcVar1 == '\0') {
              param_1[1] = param_1[1] & uVar13;
            }
          }
        }
        *(uint *)(puVar12[2] + 4) = puVar12[1];
        *(uint *)(puVar12[1] + 8) = puVar12[2];
      }
    }
    if (((uVar7 & 1) != 0) || (puVar11 != puVar10)) {
      puVar12[1] = piVar3[(int)puVar10 * 2 + 1];
      puVar12[2] = (uint)(piVar3 + (int)puVar10 * 2);
      (piVar3 + (int)puVar10 * 2)[1] = (int)puVar12;
      *(uint **)(puVar12[1] + 8) = puVar12;
      if (puVar12[1] == puVar12[2]) {
        cVar4 = *(char *)((int)puVar10 + uVar5 + 4);
        *(char *)((int)puVar10 + uVar5 + 4) = cVar4 + '\x01';
        bVar8 = (byte)puVar10;
        if (puVar10 < (uint *)0x20) {
          if (cVar4 == '\0') {
            *param_1 = *param_1 | 0x80000000U >> (bVar8 & 0x1f);
          }
          puVar10 = (uint *)(uVar5 + 0x44 + uVar14 * 4);
          *puVar10 = *puVar10 | 0x80000000U >> (bVar8 & 0x1f);
        }
        else {
          if (cVar4 == '\0') {
            param_1[1] = param_1[1] | 0x80000000U >> (bVar8 - 0x20 & 0x1f);
          }
          puVar10 = (uint *)(uVar5 + 0xc4 + uVar14 * 4);
          *puVar10 = *puVar10 | 0x80000000U >> (bVar8 - 0x20 & 0x1f);
        }
      }
    }
    *puVar12 = local_8;
    *(uint *)((local_8 - 4) + (int)puVar12) = local_8;
    *piVar3 = *piVar3 + -1;
    if (*piVar3 == 0) {
      if (DAT_1000c600 != (uint *)0x0) {
        VirtualFree((LPVOID)(DAT_1000c5f8 * 0x8000 + DAT_1000c600[3]),0x8000,0x4000);
        DAT_1000c600[2] = DAT_1000c600[2] | 0x80000000U >> ((byte)DAT_1000c5f8 & 0x1f);
        *(undefined4 *)(DAT_1000c600[4] + 0xc4 + DAT_1000c5f8 * 4) = 0;
        *(char *)(DAT_1000c600[4] + 0x43) = *(char *)(DAT_1000c600[4] + 0x43) + -1;
        if (*(char *)(DAT_1000c600[4] + 0x43) == '\0') {
          DAT_1000c600[1] = DAT_1000c600[1] & 0xfffffffe;
        }
        if (DAT_1000c600[2] == 0xffffffff) {
          VirtualFree((LPVOID)DAT_1000c600[3],0,0x8000);
          HeapFree(DAT_1000c610,0,(LPVOID)DAT_1000c600[4]);
          FUN_10005210(DAT_1000c600,DAT_1000c600 + 5,
                       (DAT_1000c604 * 0x14 - (int)DAT_1000c600) + -0x14 + DAT_1000c608);
          DAT_1000c604 = DAT_1000c604 + -1;
          if (DAT_1000c600 < param_1) {
            param_1 = param_1 + -5;
          }
          DAT_1000c5fc = DAT_1000c608;
        }
      }
      DAT_1000c600 = param_1;
      DAT_1000c5f8 = uVar14;
    }
  }
  return;
}



int * FUN_100030ce(uint *param_1)

{
  char *pcVar1;
  int *piVar2;
  char cVar3;
  int *piVar4;
  undefined4 uVar5;
  byte bVar6;
  uint uVar7;
  int iVar8;
  uint *puVar9;
  int iVar10;
  uint uVar11;
  int *piVar12;
  uint *puVar13;
  uint *puVar14;
  int iVar15;
  uint local_10;
  uint local_c;
  int local_8;
  
  puVar9 = DAT_1000c608 + DAT_1000c604 * 5;
  uVar7 = (int)param_1 + 0x17U & 0xfffffff0;
  iVar8 = ((int)((int)param_1 + 0x17U) >> 4) + -1;
  bVar6 = (byte)iVar8;
  if (iVar8 < 0x20) {
    local_10 = 0xffffffff >> (bVar6 & 0x1f);
    local_c = 0xffffffff;
  }
  else {
    local_c = 0xffffffff >> (bVar6 - 0x20 & 0x1f);
    local_10 = 0;
  }
  param_1 = DAT_1000c5fc;
  if (DAT_1000c5fc < puVar9) {
    do {
      if ((param_1[1] & local_c | *param_1 & local_10) != 0) break;
      param_1 = param_1 + 5;
    } while (param_1 < puVar9);
  }
  puVar13 = DAT_1000c608;
  if (param_1 == puVar9) {
    for (; (puVar13 < DAT_1000c5fc && ((puVar13[1] & local_c | *puVar13 & local_10) == 0));
        puVar13 = puVar13 + 5) {
    }
    param_1 = puVar13;
    if (puVar13 == DAT_1000c5fc) {
      for (; (puVar13 < puVar9 && (puVar13[2] == 0)); puVar13 = puVar13 + 5) {
      }
      puVar14 = DAT_1000c608;
      param_1 = puVar13;
      if (puVar13 == puVar9) {
        for (; (puVar14 < DAT_1000c5fc && (puVar14[2] == 0)); puVar14 = puVar14 + 5) {
        }
        param_1 = puVar14;
        if ((puVar14 == DAT_1000c5fc) && (param_1 = (uint *)FUN_100033d7(), param_1 == (uint *)0x0))
        {
          return (int *)0x0;
        }
      }
      uVar5 = FUN_10003488(param_1);
      *(undefined4 *)param_1[4] = uVar5;
      if (*(int *)param_1[4] == -1) {
        return (int *)0x0;
      }
    }
  }
  piVar4 = (int *)param_1[4];
  local_8 = *piVar4;
  if ((local_8 == -1) ||
     ((piVar4[local_8 + 0x31] & local_c | piVar4[local_8 + 0x11] & local_10) == 0)) {
    local_8 = 0;
    puVar9 = (uint *)(piVar4 + 0x11);
    uVar11 = piVar4[0x31] & local_c | piVar4[0x11] & local_10;
    while (uVar11 == 0) {
      puVar13 = puVar9 + 0x21;
      local_8 = local_8 + 1;
      puVar9 = puVar9 + 1;
      uVar11 = *puVar13 & local_c | local_10 & *puVar9;
    }
  }
  iVar8 = 0;
  piVar2 = piVar4 + local_8 * 0x81 + 0x51;
  local_10 = piVar4[local_8 + 0x11] & local_10;
  if (local_10 == 0) {
    local_10 = piVar4[local_8 + 0x31] & local_c;
    iVar8 = 0x20;
  }
  for (; -1 < (int)local_10; local_10 = local_10 << 1) {
    iVar8 = iVar8 + 1;
  }
  piVar12 = (int *)piVar2[iVar8 * 2 + 1];
  iVar10 = *piVar12 - uVar7;
  iVar15 = (iVar10 >> 4) + -1;
  if (0x3f < iVar15) {
    iVar15 = 0x3f;
  }
  DAT_1000c5fc = param_1;
  if (iVar15 != iVar8) {
    if (piVar12[1] == piVar12[2]) {
      if (iVar8 < 0x20) {
        pcVar1 = (char *)((int)piVar4 + iVar8 + 4);
        uVar11 = ~(0x80000000U >> ((byte)iVar8 & 0x1f));
        piVar4[local_8 + 0x11] = uVar11 & piVar4[local_8 + 0x11];
        *pcVar1 = *pcVar1 + -1;
        if (*pcVar1 == '\0') {
          *param_1 = *param_1 & uVar11;
        }
      }
      else {
        pcVar1 = (char *)((int)piVar4 + iVar8 + 4);
        uVar11 = ~(0x80000000U >> ((byte)iVar8 - 0x20 & 0x1f));
        piVar4[local_8 + 0x31] = piVar4[local_8 + 0x31] & uVar11;
        *pcVar1 = *pcVar1 + -1;
        if (*pcVar1 == '\0') {
          param_1[1] = param_1[1] & uVar11;
        }
      }
    }
    *(int *)(piVar12[2] + 4) = piVar12[1];
    *(int *)(piVar12[1] + 8) = piVar12[2];
    if (iVar10 == 0) goto LAB_10003394;
    piVar12[1] = piVar2[iVar15 * 2 + 1];
    piVar12[2] = (int)(piVar2 + iVar15 * 2);
    (piVar2 + iVar15 * 2)[1] = (int)piVar12;
    *(int **)(piVar12[1] + 8) = piVar12;
    if (piVar12[1] == piVar12[2]) {
      cVar3 = *(char *)(iVar15 + 4 + (int)piVar4);
      bVar6 = (byte)iVar15;
      if (iVar15 < 0x20) {
        *(char *)(iVar15 + 4 + (int)piVar4) = cVar3 + '\x01';
        if (cVar3 == '\0') {
          *param_1 = *param_1 | 0x80000000U >> (bVar6 & 0x1f);
        }
        piVar4[local_8 + 0x11] = piVar4[local_8 + 0x11] | 0x80000000U >> (bVar6 & 0x1f);
      }
      else {
        *(char *)(iVar15 + 4 + (int)piVar4) = cVar3 + '\x01';
        if (cVar3 == '\0') {
          param_1[1] = param_1[1] | 0x80000000U >> (bVar6 - 0x20 & 0x1f);
        }
        piVar4[local_8 + 0x31] = piVar4[local_8 + 0x31] | 0x80000000U >> (bVar6 - 0x20 & 0x1f);
      }
    }
  }
  if (iVar10 != 0) {
    *piVar12 = iVar10;
    *(int *)(iVar10 + -4 + (int)piVar12) = iVar10;
  }
LAB_10003394:
  piVar12 = (int *)((int)piVar12 + iVar10);
  *piVar12 = uVar7 + 1;
  *(uint *)((int)piVar12 + (uVar7 - 4)) = uVar7 + 1;
  iVar8 = *piVar2;
  *piVar2 = iVar8 + 1;
  if (((iVar8 == 0) && (param_1 == DAT_1000c600)) && (local_8 == DAT_1000c5f8)) {
    DAT_1000c600 = (uint *)0x0;
  }
  *piVar4 = local_8;
  return piVar12 + 1;
}



undefined4 * FUN_100033d7(void)

{
  undefined4 *puVar1;
  LPVOID pvVar2;
  
  if (DAT_1000c604 == DAT_1000c5f4) {
    pvVar2 = HeapReAlloc(DAT_1000c610,0,DAT_1000c608,(DAT_1000c5f4 * 5 + 0x50) * 4);
    if (pvVar2 == (LPVOID)0x0) {
      return (undefined4 *)0x0;
    }
    DAT_1000c5f4 = DAT_1000c5f4 + 0x10;
    DAT_1000c608 = pvVar2;
  }
  puVar1 = (undefined4 *)((int)DAT_1000c608 + DAT_1000c604 * 0x14);
  pvVar2 = HeapAlloc(DAT_1000c610,8,0x41c4);
  puVar1[4] = pvVar2;
  if (pvVar2 != (LPVOID)0x0) {
    pvVar2 = VirtualAlloc((LPVOID)0x0,0x100000,0x2000,4);
    puVar1[3] = pvVar2;
    if (pvVar2 != (LPVOID)0x0) {
      puVar1[2] = 0xffffffff;
      *puVar1 = 0;
      puVar1[1] = 0;
      DAT_1000c604 = DAT_1000c604 + 1;
      *(undefined4 *)puVar1[4] = 0xffffffff;
      return puVar1;
    }
    HeapFree(DAT_1000c610,0,(LPVOID)puVar1[4]);
  }
  return (undefined4 *)0x0;
}



int FUN_10003488(int param_1)

{
  int *piVar1;
  char cVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  LPVOID pvVar6;
  int *piVar7;
  int iVar8;
  int iVar9;
  int *lpAddress;
  
  iVar3 = *(int *)(param_1 + 0x10);
  iVar9 = 0;
  for (iVar4 = *(int *)(param_1 + 8); -1 < iVar4; iVar4 = iVar4 << 1) {
    iVar9 = iVar9 + 1;
  }
  iVar8 = 0x3f;
  iVar4 = iVar9 * 0x204 + 0x144 + iVar3;
  iVar5 = iVar4;
  do {
    *(int *)(iVar5 + 8) = iVar5;
    *(int *)(iVar5 + 4) = iVar5;
    iVar5 = iVar5 + 8;
    iVar8 = iVar8 + -1;
  } while (iVar8 != 0);
  lpAddress = (int *)(iVar9 * 0x8000 + *(int *)(param_1 + 0xc));
  pvVar6 = VirtualAlloc(lpAddress,0x8000,0x1000,4);
  if (pvVar6 == (LPVOID)0x0) {
    iVar9 = -1;
  }
  else {
    if (lpAddress <= lpAddress + 0x1c00) {
      piVar7 = lpAddress + 4;
      do {
        piVar7[-2] = -1;
        piVar7[0x3fb] = -1;
        piVar7[-1] = 0xff0;
        *piVar7 = (int)(piVar7 + 0x3ff);
        piVar7[1] = (int)(piVar7 + -0x401);
        piVar7[0x3fa] = 0xff0;
        piVar1 = piVar7 + 0x3fc;
        piVar7 = piVar7 + 0x400;
      } while (piVar1 <= lpAddress + 0x1c00);
    }
    *(int **)(iVar4 + 0x1fc) = lpAddress + 3;
    lpAddress[5] = iVar4 + 0x1f8;
    *(int **)(iVar4 + 0x200) = lpAddress + 0x1c03;
    lpAddress[0x1c04] = iVar4 + 0x1f8;
    *(undefined4 *)(iVar3 + 0x44 + iVar9 * 4) = 0;
    *(undefined4 *)(iVar3 + 0xc4 + iVar9 * 4) = 1;
    cVar2 = *(char *)(iVar3 + 0x43);
    *(char *)(iVar3 + 0x43) = cVar2 + '\x01';
    if (cVar2 == '\0') {
      *(uint *)(param_1 + 4) = *(uint *)(param_1 + 4) | 1;
    }
    *(uint *)(param_1 + 8) = *(uint *)(param_1 + 8) & ~(0x80000000U >> ((byte)iVar9 & 0x1f));
  }
  return iVar9;
}



undefined4 * FUN_10003583(void)

{
  bool bVar1;
  int *lpAddress;
  LPVOID pvVar2;
  int *piVar3;
  int iVar4;
  undefined4 *lpMem;
  
  if (DAT_10009130 == -1) {
    lpMem = &DAT_10009120;
  }
  else {
    lpMem = (undefined4 *)HeapAlloc(DAT_1000c610,0,0x2020);
    if (lpMem == (undefined4 *)0x0) {
      return (undefined4 *)0x0;
    }
  }
  lpAddress = (int *)VirtualAlloc((LPVOID)0x0,0x400000,0x2000,4);
  if (lpAddress != (int *)0x0) {
    pvVar2 = VirtualAlloc(lpAddress,0x10000,0x1000,4);
    if (pvVar2 != (LPVOID)0x0) {
      if ((undefined4 **)lpMem == &DAT_10009120) {
        if (DAT_10009120 == (undefined4 *)0x0) {
          DAT_10009120 = &DAT_10009120;
        }
        if (DAT_10009124 == (undefined4 *)0x0) {
          DAT_10009124 = &DAT_10009120;
        }
      }
      else {
        *lpMem = &DAT_10009120;
        lpMem[1] = DAT_10009124;
        DAT_10009124 = lpMem;
        *(undefined4 **)lpMem[1] = lpMem;
      }
      lpMem[5] = lpAddress + 0x100000;
      piVar3 = lpMem + 6;
      lpMem[3] = lpMem + 0x26;
      lpMem[4] = lpAddress;
      lpMem[2] = piVar3;
      iVar4 = 0;
      do {
        bVar1 = 0xf < iVar4;
        iVar4 = iVar4 + 1;
        *piVar3 = (bVar1 - 1 & 0xf1) - 1;
        piVar3[1] = 0xf1;
        piVar3 = piVar3 + 2;
      } while (iVar4 < 0x400);
      _memset(lpAddress,0,0x10000);
      for (; lpAddress < (int *)(lpMem[4] + 0x10000); lpAddress = lpAddress + 0x400) {
        *(undefined *)(lpAddress + 0x3e) = 0xff;
        *lpAddress = (int)(lpAddress + 2);
        lpAddress[1] = 0xf0;
      }
      return lpMem;
    }
    VirtualFree(lpAddress,0,0x8000);
  }
  if ((undefined4 **)lpMem != &DAT_10009120) {
    HeapFree(DAT_1000c610,0,lpMem);
  }
  return (undefined4 *)0x0;
}



void FUN_100036c7(int *param_1)

{
  VirtualFree((LPVOID)param_1[4],0,0x8000);
  if (DAT_1000b140 == param_1) {
    DAT_1000b140 = (int *)param_1[1];
  }
  if (param_1 != &DAT_10009120) {
    *(int *)param_1[1] = *param_1;
    *(int *)(*param_1 + 4) = param_1[1];
    HeapFree(DAT_1000c610,0,param_1);
    return;
  }
  DAT_10009130 = 0xffffffff;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_1000371d(int param_1)

{
  BOOL BVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int local_8;
  
  iVar5 = DAT_10009124;
  do {
    iVar4 = iVar5;
    if (*(int *)(iVar5 + 0x10) != -1) {
      local_8 = 0;
      piVar2 = (int *)(iVar5 + 0x2010);
      iVar4 = 0x3ff000;
      do {
        if (*piVar2 == 0xf0) {
          BVar1 = VirtualFree((LPVOID)(iVar4 + *(int *)(iVar5 + 0x10)),0x1000,0x4000);
          if (BVar1 != 0) {
            *piVar2 = -1;
            _DAT_1000bf3c = _DAT_1000bf3c + -1;
            if ((*(int **)(iVar5 + 0xc) == (int *)0x0) || (piVar2 < *(int **)(iVar5 + 0xc))) {
              *(int **)(iVar5 + 0xc) = piVar2;
            }
            local_8 = local_8 + 1;
            param_1 = param_1 + -1;
            if (param_1 == 0) break;
          }
        }
        iVar4 = iVar4 + -0x1000;
        piVar2 = piVar2 + -2;
      } while (-1 < iVar4);
      iVar4 = *(int *)(iVar5 + 4);
      if ((local_8 != 0) && (*(int *)(iVar5 + 0x18) == -1)) {
        piVar2 = (int *)(iVar5 + 0x20);
        iVar3 = 1;
        do {
          if (*piVar2 != -1) break;
          iVar3 = iVar3 + 1;
          piVar2 = piVar2 + 2;
        } while (iVar3 < 0x400);
        if (iVar3 == 0x400) {
          FUN_100036c7(iVar5);
        }
      }
    }
    if ((iVar4 == DAT_10009124) || (iVar5 = iVar4, param_1 < 1)) {
      return;
    }
  } while( true );
}



int FUN_100037df(uint param_1,undefined4 *param_2,uint *param_3)

{
  undefined4 *puVar1;
  uint uVar2;
  
  puVar1 = &DAT_10009120;
  while ((param_1 < (uint)puVar1[4] || param_1 == puVar1[4] || ((uint)puVar1[5] <= param_1))) {
    puVar1 = (undefined4 *)*puVar1;
    if (puVar1 == &DAT_10009120) {
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



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_10003836(int param_1,int param_2,byte *param_3)

{
  int *piVar1;
  int iVar2;
  
  piVar1 = (int *)(param_1 + 0x18 + (param_2 - *(int *)(param_1 + 0x10) >> 0xc) * 8);
  *piVar1 = *piVar1 + (uint)*param_3;
  *param_3 = 0;
  piVar1[1] = 0xf1;
  iVar2 = _DAT_1000bf3c;
  if ((*piVar1 == 0xf0) && (_DAT_1000bf3c = _DAT_1000bf3c + 1, iVar2 == 0x1f)) {
    FUN_1000371d(0x10);
  }
  return;
}



// WARNING: Type propagation algorithm not settling

int * FUN_1000387b(uint param_1)

{
  int *piVar1;
  int *piVar2;
  int *piVar3;
  int iVar4;
  int *piVar5;
  undefined4 *puVar6;
  int local_8;
  
  piVar5 = DAT_1000b140;
  do {
    if (piVar5[4] != -1) {
      piVar2 = (int *)piVar5[2];
      iVar4 = piVar5[4] + ((int)piVar2 + (-0x18 - (int)piVar5) >> 3) * 0x1000;
      if (piVar2 < piVar5 + 0x806) {
        do {
          if (((int)param_1 <= *piVar2) && (param_1 <= (uint)piVar2[1] && piVar2[1] != param_1)) {
            piVar1 = (int *)FUN_10003a83(iVar4,*piVar2,param_1);
            if (piVar1 != (int *)0x0) goto LAB_10003946;
            piVar2[1] = param_1;
          }
          piVar2 = piVar2 + 2;
          iVar4 = iVar4 + 0x1000;
        } while (piVar2 < piVar5 + 0x806);
      }
      piVar3 = (int *)piVar5[2];
      iVar4 = piVar5[4];
      for (piVar2 = piVar5 + 6; piVar2 < piVar3; piVar2 = piVar2 + 2) {
        if (((int)param_1 <= *piVar2) && (param_1 <= (uint)piVar2[1] && piVar2[1] != param_1)) {
          piVar1 = (int *)FUN_10003a83(iVar4,*piVar2,param_1);
          if (piVar1 != (int *)0x0) {
LAB_10003946:
            DAT_1000b140 = piVar5;
            *piVar2 = *piVar2 - param_1;
            piVar5[2] = (int)piVar2;
            return piVar1;
          }
          piVar2[1] = param_1;
        }
        iVar4 = iVar4 + 0x1000;
      }
    }
    piVar5 = (int *)*piVar5;
    if (piVar5 == DAT_1000b140) {
      puVar6 = &DAT_10009120;
      while ((puVar6[4] == -1 || (puVar6[3] == 0))) {
        puVar6 = (undefined4 *)*puVar6;
        if (puVar6 == &DAT_10009120) {
          iVar4 = FUN_10003583();
          if (iVar4 == 0) {
            return (int *)0x0;
          }
          piVar5 = *(int **)(iVar4 + 0x10);
          *(char *)(piVar5 + 2) = (char)param_1;
          DAT_1000b140 = (int *)iVar4;
          *piVar5 = (int)(piVar5 + 2) + param_1;
          piVar5[1] = 0xf0 - param_1;
          *(int *)(iVar4 + 0x18) = *(int *)(iVar4 + 0x18) - (param_1 & 0xff);
          return piVar5 + 0x40;
        }
      }
      piVar5 = (int *)puVar6[3];
      local_8 = 0;
      piVar1 = (int *)(puVar6[4] + ((int)piVar5 + (-0x18 - (int)puVar6) >> 3) * 0x1000);
      iVar4 = *piVar5;
      piVar2 = piVar5;
      for (; (iVar4 == -1 && (local_8 < 0x10)); local_8 = local_8 + 1) {
        piVar2 = piVar2 + 2;
        iVar4 = *piVar2;
      }
      piVar2 = (int *)VirtualAlloc(piVar1,local_8 << 0xc,0x1000,4);
      if (piVar2 != piVar1) {
        return (int *)0;
      }
      _memset(piVar1,local_8 << 0xc,0);
      piVar2 = piVar5;
      if (0 < local_8) {
        piVar3 = piVar1 + 1;
        do {
          *(undefined *)(piVar3 + 0x3d) = 0xff;
          piVar3[-1] = (int)(piVar3 + 1);
          *piVar3 = 0xf0;
          *piVar2 = 0xf0;
          piVar2[1] = 0xf1;
          piVar3 = piVar3 + 0x400;
          piVar2 = piVar2 + 2;
          local_8 = local_8 + -1;
        } while (local_8 != 0);
      }
      for (; (piVar2 < puVar6 + 0x806 && (*piVar2 != -1)); piVar2 = piVar2 + 2) {
      }
      DAT_1000b140 = puVar6;
      puVar6[3] = -(uint)(piVar2 < puVar6 + 0x806) & (uint)piVar2;
      *(char *)(piVar1 + 2) = (char)param_1;
      puVar6[2] = piVar5;
      *piVar5 = *piVar5 - param_1;
      piVar1[1] = piVar1[1] - param_1;
      *piVar1 = (int)(piVar1 + 2) + param_1;
      return piVar1 + 0x40;
    }
  } while( true );
}



int FUN_10003a83(int **param_1,int *param_2,int *param_3)

{
  int **ppiVar1;
  int **ppiVar2;
  undefined uVar3;
  int **ppiVar4;
  int *piVar5;
  int **ppiVar6;
  
  ppiVar2 = (int **)*param_1;
  ppiVar1 = param_1 + 0x3e;
  uVar3 = SUB41(param_3,0);
  if (param_1[1] < param_3) {
    ppiVar4 = (int **)((int)param_1[1] + (int)ppiVar2);
    ppiVar6 = ppiVar2;
    if (*(char *)ppiVar4 != '\0') {
      ppiVar6 = ppiVar4;
    }
    while( true ) {
      while( true ) {
        if (ppiVar1 <= (int **)((int)ppiVar6 + (int)param_3)) {
          ppiVar6 = param_1 + 2;
          while( true ) {
            while( true ) {
              if (ppiVar2 <= ppiVar6) {
                return 0;
              }
              if (ppiVar1 <= (int **)((int)ppiVar6 + (int)param_3)) {
                return 0;
              }
              if (*(byte *)ppiVar6 == 0) break;
              ppiVar6 = (int **)((int)ppiVar6 + (uint)*(byte *)ppiVar6);
            }
            piVar5 = (int *)0x1;
            ppiVar4 = ppiVar6;
            while (ppiVar4 = (int **)((int)ppiVar4 + 1), *(char *)ppiVar4 == '\0') {
              piVar5 = (int *)((int)piVar5 + 1);
            }
            if (param_3 <= piVar5) break;
            param_2 = (int *)((int)param_2 - (int)piVar5);
            ppiVar6 = ppiVar4;
            if (param_2 < param_3) {
              return 0;
            }
          }
          if ((int **)((int)ppiVar6 + (int)param_3) < ppiVar1) {
            *param_1 = (int *)(int **)((int)ppiVar6 + (int)param_3);
            param_1[1] = (int *)((int)piVar5 - (int)param_3);
          }
          else {
            param_1[1] = (int *)0x0;
            *param_1 = (int *)(param_1 + 2);
          }
          *(undefined *)ppiVar6 = uVar3;
          ppiVar2 = ppiVar6 + 2;
          goto LAB_10003b96;
        }
        if (*(byte *)ppiVar6 == 0) break;
        ppiVar6 = (int **)((int)ppiVar6 + (uint)*(byte *)ppiVar6);
      }
      piVar5 = (int *)0x1;
      ppiVar4 = ppiVar6;
      while (ppiVar4 = (int **)((int)ppiVar4 + 1), *(char *)ppiVar4 == '\0') {
        piVar5 = (int *)((int)piVar5 + 1);
      }
      if (param_3 <= piVar5) break;
      if (ppiVar6 == ppiVar2) {
        param_1[1] = piVar5;
        ppiVar6 = ppiVar4;
      }
      else {
        param_2 = (int *)((int)param_2 - (int)piVar5);
        ppiVar6 = ppiVar4;
        if (param_2 < param_3) {
          return 0;
        }
      }
    }
    if ((int **)((int)ppiVar6 + (int)param_3) < ppiVar1) {
      *param_1 = (int *)(int **)((int)ppiVar6 + (int)param_3);
      param_1[1] = (int *)((int)piVar5 - (int)param_3);
    }
    else {
      param_1[1] = (int *)0x0;
      *param_1 = (int *)(param_1 + 2);
    }
    *(undefined *)ppiVar6 = uVar3;
    ppiVar2 = ppiVar6 + 2;
  }
  else {
    *(undefined *)ppiVar2 = uVar3;
    if ((int **)((int)ppiVar2 + (int)param_3) < ppiVar1) {
      *param_1 = (int *)((int)*param_1 + (int)param_3);
      param_1[1] = (int *)((int)param_1[1] - (int)param_3);
    }
    else {
      param_1[1] = (int *)0x0;
      *param_1 = (int *)(param_1 + 2);
    }
    ppiVar2 = ppiVar2 + 2;
  }
LAB_10003b96:
  return (int)ppiVar2 * 0x10 + (int)param_1 * -0xf;
}



void FUN_10003ba7(void)

{
  InitializeCriticalSection(DAT_1000b18c);
  InitializeCriticalSection(DAT_1000b17c);
  InitializeCriticalSection(DAT_1000b16c);
  InitializeCriticalSection(DAT_1000b14c);
  return;
}



void FUN_10003bd0(void)

{
  LPCRITICAL_SECTION *pp_Var1;
  
  pp_Var1 = (LPCRITICAL_SECTION *)&DAT_1000b148;
  do {
    if ((((*pp_Var1 != (LPCRITICAL_SECTION)0x0) && (pp_Var1 != &DAT_1000b18c)) &&
        (pp_Var1 != &DAT_1000b17c)) && ((pp_Var1 != &DAT_1000b16c && (pp_Var1 != &DAT_1000b14c)))) {
      DeleteCriticalSection(*pp_Var1);
      FUN_100025a6(*pp_Var1);
    }
    pp_Var1 = pp_Var1 + 1;
  } while ((int)pp_Var1 < 0x1000b208);
  DeleteCriticalSection(DAT_1000b16c);
  DeleteCriticalSection(DAT_1000b17c);
  DeleteCriticalSection(DAT_1000b18c);
  DeleteCriticalSection(DAT_1000b14c);
  return;
}



void FUN_10003c3c(int param_1)

{
  LPCRITICAL_SECTION *pp_Var1;
  LPCRITICAL_SECTION lpCriticalSection;
  
  pp_Var1 = (LPCRITICAL_SECTION *)(&DAT_1000b148 + param_1);
  if ((&DAT_1000b148)[param_1] == 0) {
    lpCriticalSection = (LPCRITICAL_SECTION)_malloc(0x18);
    if (lpCriticalSection == (LPCRITICAL_SECTION)0x0) {
      __amsg_exit(0x11);
    }
    FUN_10003c3c(0x11);
    if (*pp_Var1 == (LPCRITICAL_SECTION)0x0) {
      InitializeCriticalSection(lpCriticalSection);
      *pp_Var1 = lpCriticalSection;
    }
    else {
      FUN_100025a6();
    }
    FUN_10003c9d(0x11);
  }
  EnterCriticalSection(*pp_Var1);
  return;
}



void FUN_10003c9d(int param_1)

{
  LeaveCriticalSection((LPCRITICAL_SECTION)(&DAT_1000b148)[param_1]);
  return;
}



// Library Function - Single Match
//  __global_unwind2
// 
// Library: Visual Studio

void __global_unwind2(PVOID param_1)

{
  RtlUnwind(param_1,(PVOID)0x10003ccc,(PEXCEPTION_RECORD)0x0,(PVOID)0x0);
  return;
}



// Library Function - Single Match
//  __local_unwind2
// 
// Libraries: Visual Studio 1998 Debug, Visual Studio 1998 Release, Visual Studio 2003 Debug, Visual
// Studio 2003 Release

void __local_unwind2(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  void *pvStack_1c;
  undefined *puStack_18;
  undefined4 local_14;
  int iStack_10;
  
  iStack_10 = param_1;
  puStack_18 = &LAB_10003cd4;
  pvStack_1c = ExceptionList;
  ExceptionList = &pvStack_1c;
  while( true ) {
    iVar1 = *(int *)(param_1 + 8);
    iVar2 = *(int *)(param_1 + 0xc);
    if ((iVar2 == -1) || (iVar2 == param_2)) break;
    local_14 = *(undefined4 *)(iVar1 + iVar2 * 0xc);
    *(undefined4 *)(param_1 + 0xc) = local_14;
    if (*(int *)(iVar1 + 4 + iVar2 * 0xc) == 0) {
      FUN_10003d8a(0x101);
      (**(code **)(iVar1 + 8 + iVar2 * 0xc))();
    }
  }
  ExceptionList = pvStack_1c;
  return;
}



void FUN_10003d8a(void)

{
  undefined4 in_EAX;
  int unaff_EBP;
  
  DAT_1000b210 = *(undefined4 *)(unaff_EBP + 8);
  DAT_1000b20c = in_EAX;
  DAT_1000b214 = unaff_EBP;
  return;
}



void FUN_10003e69(int param_1)

{
  __local_unwind2(*(undefined4 *)(param_1 + 0x18),*(undefined4 *)(param_1 + 0x1c));
  return;
}



undefined4 FUN_10003e84(undefined4 param_1)

{
  int iVar1;
  
  if (DAT_1000bfa4 != (code *)0x0) {
    iVar1 = (*DAT_1000bfa4)(param_1);
    if (iVar1 != 0) {
      return 1;
    }
  }
  return 0;
}



uint __thiscall FUN_10003e9f(undefined4 param_1_00,int param_1,uint param_2)

{
  int iVar1;
  undefined4 uVar2;
  uint local_8;
  
  if (param_1 + 1U < 0x101) {
    param_1._2_2_ = *(ushort *)(DAT_1000b218 + param_1 * 2);
  }
  else {
    if ((*(byte *)(DAT_1000b218 + 1 + (param_1 >> 8 & 0xffU) * 2) & 0x80) == 0) {
      local_8 = CONCAT31((int3)((uint)param_1_00 >> 8),(char)param_1) & 0xffff00ff;
      uVar2 = 1;
    }
    else {
      local_8._0_2_ = CONCAT11((char)param_1,(char)((uint)param_1 >> 8));
      local_8 = CONCAT22((short)((uint)param_1_00 >> 0x10),(undefined2)local_8) & 0xff00ffff;
      uVar2 = 2;
    }
    iVar1 = FUN_100055a8(1,&local_8,uVar2,(int)&param_1 + 2,0,0,1);
    if (iVar1 == 0) {
      return 0;
    }
  }
  return param_1._2_2_ & param_2;
}



void FUN_10003f54(void)

{
  FUN_10005726(0x10000,0x30000);
  return;
}



// WARNING: Removing unreachable block (ram,0x10003f9b)

undefined4 FUN_10003f66(void)

{
  return 0;
}



void FUN_10003fa4(void)

{
  HMODULE hModule;
  FARPROC pFVar1;
  
  hModule = GetModuleHandleA("KERNEL32");
  if (hModule != (HMODULE)0x0) {
    pFVar1 = GetProcAddress(hModule,"IsProcessorFeaturePresent");
    if (pFVar1 != (FARPROC)0x0) {
      (*pFVar1)(0);
      return;
    }
  }
  FUN_10003f66();
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_10003fcd(char *param_1)

{
  char cVar1;
  char cVar2;
  int iVar3;
  uint uVar4;
  
  iVar3 = FUN_10005857((int)*param_1);
  if (iVar3 != 0x65) {
    do {
      param_1 = param_1 + 1;
      if (_DAT_1000b424 < 2) {
        uVar4 = *(byte *)(DAT_1000b218 + *param_1 * 2) & 4;
      }
      else {
        uVar4 = FUN_10003e9f((int)*param_1,4);
      }
    } while (uVar4 != 0);
  }
  cVar2 = *param_1;
  *param_1 = DAT_1000b428;
  do {
    param_1 = param_1 + 1;
    cVar1 = *param_1;
    *param_1 = cVar2;
    cVar2 = cVar1;
  } while (*param_1 != '\0');
  return;
}



// Library Function - Single Match
//  __fassign
// 
// Library: Visual Studio 2003 Release

void __cdecl __fassign(int flag,char *argument,char *number)

{
  undefined4 uStack_c;
  undefined4 uStack_8;
  
  if (flag != 0) {
    FUN_10005d23(&uStack_c);
    *(undefined4 *)argument = uStack_c;
    *(undefined4 *)(argument + 4) = uStack_8;
    return;
  }
  FUN_10005d50(&number,number);
  *(char **)argument = number;
  return;
}



int FUN_100040cb(undefined8 *param_1,int param_2,int param_3,undefined4 param_4)

{
  undefined local_2c [24];
  int local_14 [4];
  
  FUN_10005df4(*param_1,local_14,local_2c);
  FUN_10005d7d((uint)(0 < param_3) + param_2 + (uint)(local_14[0] == 0x2d),param_3 + 1,local_14);
  FUN_1000412c(param_2,param_3,param_4,local_14,0);
  return param_2;
}



undefined * FUN_1000412c(undefined *param_1,int param_2,int param_3,int *param_4,char param_5)

{
  undefined *puVar1;
  undefined *puVar2;
  char *pcVar3;
  int iVar4;
  
  if (param_5 != '\0') {
    FUN_100043ce(param_1 + (*param_4 == 0x2d),0 < param_2);
  }
  puVar1 = param_1;
  if (*param_4 == 0x2d) {
    *param_1 = 0x2d;
    puVar1 = param_1 + 1;
  }
  puVar2 = puVar1;
  if (0 < param_2) {
    puVar2 = puVar1 + 1;
    *puVar1 = puVar1[1];
    *puVar2 = DAT_1000b428;
  }
  pcVar3 = FID_conflict___mbscpy(puVar2 + param_2 + (uint)(param_5 == '\0'),"e+000");
  if (param_3 != 0) {
    *pcVar3 = 'E';
  }
  if (*(char *)param_4[3] != '0') {
    iVar4 = param_4[1] + -1;
    if (iVar4 < 0) {
      iVar4 = -iVar4;
      pcVar3[1] = '-';
    }
    if (99 < iVar4) {
      pcVar3[2] = pcVar3[2] + (char)(iVar4 / 100);
      iVar4 = iVar4 % 100;
    }
    if (9 < iVar4) {
      pcVar3[3] = pcVar3[3] + (char)(iVar4 / 10);
      iVar4 = iVar4 % 10;
    }
    pcVar3[4] = pcVar3[4] + (char)iVar4;
  }
  return param_1;
}



int FUN_100041ee(undefined8 *param_1,int param_2,int param_3)

{
  undefined local_2c [24];
  int local_14;
  int local_10;
  
  FUN_10005df4(*param_1,&local_14,local_2c);
  FUN_10005d7d((uint)(local_14 == 0x2d) + param_2,local_10 + param_3,&local_14);
  FUN_10004243(param_2,param_3,&local_14,0);
  return param_2;
}



undefined * FUN_10004243(undefined *param_1,size_t param_2,int *param_3,char param_4)

{
  int iVar1;
  int iVar2;
  undefined *puVar3;
  
  iVar1 = param_3[1];
  if ((param_4 != '\0') && (iVar1 - 1U == param_2)) {
    iVar2 = *param_3;
    param_1[(uint)(iVar2 == 0x2d) + (iVar1 - 1U)] = 0x30;
    (param_1 + (uint)(iVar2 == 0x2d) + (iVar1 - 1U))[1] = 0;
  }
  puVar3 = param_1;
  if (*param_3 == 0x2d) {
    *param_1 = 0x2d;
    puVar3 = param_1 + 1;
  }
  if (param_3[1] < 1) {
    FUN_100043ce(puVar3,1);
    *puVar3 = 0x30;
    puVar3 = puVar3 + 1;
  }
  else {
    puVar3 = puVar3 + param_3[1];
  }
  if (0 < (int)param_2) {
    FUN_100043ce(puVar3,1);
    *puVar3 = DAT_1000b428;
    iVar1 = param_3[1];
    if (iVar1 < 0) {
      if ((param_4 != '\0') || (SBORROW4(param_2,-iVar1) == (int)(param_2 + iVar1) < 0)) {
        param_2 = -iVar1;
      }
      FUN_100043ce(puVar3 + 1,param_2);
      _memset(puVar3 + 1,0x30,param_2);
    }
  }
  return param_1;
}



void FUN_100042ea(undefined8 *param_1,int param_2,int param_3,undefined4 param_4)

{
  int iVar1;
  char *pcVar2;
  char *pcVar3;
  undefined local_2c [24];
  int local_14;
  int local_10;
  
  FUN_10005df4(*param_1,&local_14,local_2c);
  iVar1 = local_10 + -1;
  pcVar2 = (char *)((uint)(local_14 == 0x2d) + param_2);
  FUN_10005d7d(pcVar2,param_3,&local_14);
  local_10 = local_10 + -1;
  if ((local_10 < -4) || (param_3 <= local_10)) {
    FUN_1000412c(param_2,param_3,param_4,&local_14,1);
  }
  else {
    if (iVar1 < local_10) {
      do {
        pcVar3 = pcVar2;
        pcVar2 = pcVar3 + 1;
      } while (*pcVar3 != '\0');
      pcVar3[-1] = '\0';
    }
    FUN_10004243(param_2,param_3,&local_14,1);
  }
  return;
}



// Library Function - Single Match
//  __cfltcvt
// 
// Library: Visual Studio 2003 Release

errno_t __cdecl
__cfltcvt(double *arg,char *buffer,size_t sizeInBytes,int format,int precision,int caps)

{
  errno_t eVar1;
  
  if ((sizeInBytes == 0x65) || (sizeInBytes == 0x45)) {
    eVar1 = FUN_100040cb(arg,buffer,format,precision);
  }
  else {
    if (sizeInBytes == 0x66) {
      eVar1 = FUN_100041ee(arg,buffer,format);
      return eVar1;
    }
    eVar1 = FUN_100042ea(arg,buffer,format,precision);
  }
  return eVar1;
}



void FUN_100043ce(char *param_1,int param_2)

{
  size_t sVar1;
  
  if (param_2 != 0) {
    sVar1 = _strlen(param_1);
    FUN_10005210(param_1 + param_2,param_1,sVar1 + 1);
  }
  return;
}



void FUN_100043f3(void)

{
  if (DAT_10009108 != (code *)0x0) {
    (*DAT_10009108)();
  }
  FUN_100044f7(&DAT_10009008,&DAT_10009010);
  FUN_100044f7(&DAT_10009000,&DAT_10009004);
  return;
}



// Library Function - Single Match
//  __exit
// 
// Library: Visual Studio 2003 Release

void __cdecl __exit(int _Code)

{
  FUN_10004440(_Code,1,0);
  return;
}



void FUN_10004431(void)

{
  FUN_10004440(0,0,1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_10004440(UINT param_1,int param_2,int param_3)

{
  HANDLE hProcess;
  code **ppcVar1;
  UINT uExitCode;
  
  FUN_100044e5();
  if (_DAT_1000bfe8 == 1) {
    uExitCode = param_1;
    hProcess = GetCurrentProcess();
    TerminateProcess(hProcess,uExitCode);
  }
  _DAT_1000bfe4 = 1;
  DAT_1000bfe0 = (undefined)param_3;
  if (param_2 == 0) {
    if ((DAT_1000c5f0 != (code **)0x0) &&
       (ppcVar1 = (code **)(DAT_1000c5ec - 4), DAT_1000c5f0 <= ppcVar1)) {
      do {
        if (*ppcVar1 != (code *)0x0) {
          (**ppcVar1)();
        }
        ppcVar1 = ppcVar1 + -1;
      } while (DAT_1000c5f0 <= ppcVar1);
    }
    FUN_100044f7(&DAT_10009014,&DAT_10009018);
  }
  FUN_100044f7(&DAT_1000901c,&DAT_10009020);
  if (param_3 == 0) {
    _DAT_1000bfe8 = 1;
                    // WARNING: Subroutine does not return
    ExitProcess(param_1);
  }
  FUN_100044ee();
  return;
}



void FUN_100044e5(void)

{
  FUN_10003c3c(0xd);
  return;
}



void FUN_100044ee(void)

{
  FUN_10003c9d(0xd);
  return;
}



void FUN_100044f7(code **param_1,code **param_2)

{
  for (; param_1 < param_2; param_1 = param_1 + 1) {
    if (*param_1 != (code *)0x0) {
      (**param_1)();
    }
  }
  return;
}



undefined4 FUN_10004511(void)

{
  DWORD *lpTlsValue;
  BOOL BVar1;
  DWORD DVar2;
  
  FUN_10003ba7();
  DAT_1000b448 = TlsAlloc();
  if (DAT_1000b448 != 0xffffffff) {
    lpTlsValue = (DWORD *)FUN_10006084(1,0x74);
    if (lpTlsValue != (DWORD *)0x0) {
      BVar1 = TlsSetValue(DAT_1000b448,lpTlsValue);
      if (BVar1 != 0) {
        FUN_10004583(lpTlsValue);
        DVar2 = GetCurrentThreadId();
        lpTlsValue[1] = 0xffffffff;
        *lpTlsValue = DVar2;
        return 1;
      }
    }
  }
  return 0;
}



void FUN_10004565(void)

{
  FUN_10003bd0();
  if (DAT_1000b448 != 0xffffffff) {
    TlsFree(DAT_1000b448);
    DAT_1000b448 = 0xffffffff;
  }
  return;
}



void FUN_10004583(int param_1)

{
  *(undefined **)(param_1 + 0x50) = &DAT_1000b540;
  *(undefined4 *)(param_1 + 0x14) = 1;
  return;
}



DWORD * FUN_10004596(void)

{
  DWORD dwErrCode;
  DWORD *lpTlsValue;
  BOOL BVar1;
  DWORD DVar2;
  
  dwErrCode = GetLastError();
  lpTlsValue = (DWORD *)TlsGetValue(DAT_1000b448);
  if (lpTlsValue == (DWORD *)0x0) {
    lpTlsValue = (DWORD *)FUN_10006084(1,0x74);
    if (lpTlsValue != (DWORD *)0x0) {
      BVar1 = TlsSetValue(DAT_1000b448,lpTlsValue);
      if (BVar1 != 0) {
        FUN_10004583(lpTlsValue);
        DVar2 = GetCurrentThreadId();
        lpTlsValue[1] = 0xffffffff;
        *lpTlsValue = DVar2;
        goto LAB_100045f1;
      }
    }
    __amsg_exit(0x10);
  }
LAB_100045f1:
  SetLastError(dwErrCode);
  return lpTlsValue;
}



void FUN_100045fd(LPVOID param_1)

{
  if (DAT_1000b448 != 0xffffffff) {
    if ((param_1 != (LPVOID)0x0) || (param_1 = TlsGetValue(DAT_1000b448), param_1 != (LPVOID)0x0)) {
      if (*(int *)((int)param_1 + 0x24) != 0) {
        FUN_100025a6(*(int *)((int)param_1 + 0x24));
      }
      if (*(int *)((int)param_1 + 0x28) != 0) {
        FUN_100025a6(*(int *)((int)param_1 + 0x28));
      }
      if (*(int *)((int)param_1 + 0x30) != 0) {
        FUN_100025a6(*(int *)((int)param_1 + 0x30));
      }
      if (*(int *)((int)param_1 + 0x38) != 0) {
        FUN_100025a6(*(int *)((int)param_1 + 0x38));
      }
      if (*(int *)((int)param_1 + 0x40) != 0) {
        FUN_100025a6(*(int *)((int)param_1 + 0x40));
      }
      if (*(int *)((int)param_1 + 0x44) != 0) {
        FUN_100025a6(*(int *)((int)param_1 + 0x44));
      }
      if (*(undefined **)((int)param_1 + 0x50) != &DAT_1000b540) {
        FUN_100025a6(*(undefined **)((int)param_1 + 0x50));
      }
      FUN_100025a6(param_1);
    }
    TlsSetValue(DAT_1000b448,(LPVOID)0x0);
    return;
  }
  return;
}



void FUN_1000469d(void)

{
  HANDLE *ppvVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  DWORD DVar5;
  HANDLE hFile;
  int iVar6;
  uint uVar7;
  UINT UVar8;
  UINT UVar9;
  _STARTUPINFOA local_4c;
  HANDLE *local_8;
  
  puVar3 = (undefined4 *)_malloc(0x480);
  if (puVar3 == (undefined4 *)0x0) {
    __amsg_exit(0x1b);
  }
  DAT_1000c5e0 = 0x20;
  DAT_1000c4e0 = puVar3;
  for (; puVar3 < DAT_1000c4e0 + 0x120; puVar3 = puVar3 + 9) {
    *(undefined *)(puVar3 + 1) = 0;
    *puVar3 = 0xffffffff;
    puVar3[2] = 0;
    *(undefined *)((int)puVar3 + 5) = 10;
  }
  GetStartupInfoA(&local_4c);
  if ((local_4c.cbReserved2 != 0) && ((UINT *)local_4c.lpReserved2 != (UINT *)0x0)) {
    UVar8 = *(UINT *)local_4c.lpReserved2;
    local_4c.lpReserved2 = (LPBYTE)((int)local_4c.lpReserved2 + 4);
    local_8 = (HANDLE *)((int)local_4c.lpReserved2 + UVar8);
    if (0x7ff < (int)UVar8) {
      UVar8 = 0x800;
    }
    UVar9 = UVar8;
    if ((int)DAT_1000c5e0 < (int)UVar8) {
      puVar3 = &DAT_1000c4e4;
      do {
        puVar4 = (undefined4 *)_malloc(0x480);
        UVar9 = DAT_1000c5e0;
        if (puVar4 == (undefined4 *)0x0) break;
        DAT_1000c5e0 = DAT_1000c5e0 + 0x20;
        *puVar3 = puVar4;
        puVar2 = puVar4;
        for (; puVar4 < puVar2 + 0x120; puVar4 = puVar4 + 9) {
          *(undefined *)(puVar4 + 1) = 0;
          *puVar4 = 0xffffffff;
          puVar4[2] = 0;
          *(undefined *)((int)puVar4 + 5) = 10;
          puVar2 = (undefined4 *)*puVar3;
        }
        puVar3 = puVar3 + 1;
        UVar9 = UVar8;
      } while ((int)DAT_1000c5e0 < (int)UVar8);
    }
    uVar7 = 0;
    if (0 < (int)UVar9) {
      do {
        if (((*local_8 != (HANDLE)0xffffffff) && ((*local_4c.lpReserved2 & 1) != 0)) &&
           (((*local_4c.lpReserved2 & 8) != 0 || (DVar5 = GetFileType(*local_8), DVar5 != 0)))) {
          ppvVar1 = (HANDLE *)((int)(&DAT_1000c4e0)[(int)uVar7 >> 5] + (uVar7 & 0x1f) * 0x24);
          *ppvVar1 = *local_8;
          *(BYTE *)(ppvVar1 + 1) = *local_4c.lpReserved2;
        }
        local_8 = local_8 + 1;
        uVar7 = uVar7 + 1;
        local_4c.lpReserved2 = (LPBYTE)((int)local_4c.lpReserved2 + 1);
      } while ((int)uVar7 < (int)UVar9);
    }
  }
  iVar6 = 0;
  do {
    ppvVar1 = (HANDLE *)(DAT_1000c4e0 + iVar6 * 9);
    if (DAT_1000c4e0[iVar6 * 9] == -1) {
      *(undefined *)(ppvVar1 + 1) = 0x81;
      if (iVar6 == 0) {
        DVar5 = 0xfffffff6;
      }
      else {
        DVar5 = 0xfffffff5 - (iVar6 != 1);
      }
      hFile = GetStdHandle(DVar5);
      if ((hFile != (HANDLE)0xffffffff) && (DVar5 = GetFileType(hFile), DVar5 != 0)) {
        *ppvVar1 = hFile;
        if ((DVar5 & 0xff) != 2) {
          if ((DVar5 & 0xff) == 3) {
            *(byte *)(ppvVar1 + 1) = *(byte *)(ppvVar1 + 1) | 8;
          }
          goto LAB_10004842;
        }
      }
      *(byte *)(ppvVar1 + 1) = *(byte *)(ppvVar1 + 1) | 0x40;
    }
    else {
      *(byte *)(ppvVar1 + 1) = *(byte *)(ppvVar1 + 1) | 0x80;
    }
LAB_10004842:
    iVar6 = iVar6 + 1;
    if (2 < iVar6) {
      SetHandleCount(DAT_1000c5e0);
      return;
    }
  } while( true );
}



void FUN_10004859(void)

{
  LPCRITICAL_SECTION lpCriticalSection;
  uint *puVar1;
  uint uVar2;
  
  puVar1 = &DAT_1000c4e0;
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
      FUN_100025a6(*puVar1);
      *puVar1 = 0;
    }
    puVar1 = puVar1 + 1;
  } while ((int)puVar1 < 0x1000c5e0);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_100048ad(void)

{
  char cVar1;
  size_t sVar2;
  char **ppcVar3;
  char *pcVar4;
  int iVar5;
  char *pcVar6;
  
  if (_DAT_1000c5e8 == 0) {
    FUN_10006599();
  }
  iVar5 = 0;
  for (pcVar6 = DAT_1000bf2c; *pcVar6 != '\0'; pcVar6 = pcVar6 + sVar2 + 1) {
    if (*pcVar6 != '=') {
      iVar5 = iVar5 + 1;
    }
    sVar2 = _strlen(pcVar6);
  }
  ppcVar3 = (char **)_malloc(iVar5 * 4 + 4);
  _DAT_1000bfc8 = ppcVar3;
  if (ppcVar3 == (char **)0x0) {
    __amsg_exit(9);
  }
  cVar1 = *DAT_1000bf2c;
  pcVar6 = DAT_1000bf2c;
  while (cVar1 != '\0') {
    sVar2 = _strlen(pcVar6);
    if (*pcVar6 != '=') {
      pcVar4 = (char *)_malloc(sVar2 + 1);
      *ppcVar3 = pcVar4;
      if (pcVar4 == (char *)0x0) {
        __amsg_exit(9);
      }
      FID_conflict___mbscpy(*ppcVar3,pcVar6);
      ppcVar3 = ppcVar3 + 1;
    }
    pcVar6 = pcVar6 + sVar2 + 1;
    cVar1 = *pcVar6;
  }
  FUN_100025a6(DAT_1000bf2c);
  DAT_1000bf2c = (char *)0x0;
  *ppcVar3 = (char *)0x0;
  _DAT_1000c5e4 = 1;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_10004966(void)

{
  void *pvVar1;
  char *pcVar2;
  int local_c;
  int local_8;
  
  if (_DAT_1000c5e8 == 0) {
    FUN_10006599();
  }
  GetModuleFileNameA((HMODULE)0x0,&DAT_1000bfec,0x104);
  _DAT_1000bfd8 = &DAT_1000bfec;
  pcVar2 = &DAT_1000bfec;
  if (*DAT_1000c618 != '\0') {
    pcVar2 = DAT_1000c618;
  }
  FUN_100049ff(pcVar2,0,0,&local_8,&local_c);
  pvVar1 = _malloc(local_c + local_8 * 4);
  if (pvVar1 == (void *)0x0) {
    __amsg_exit(8);
  }
  FUN_100049ff(pcVar2,pvVar1,(void *)((int)pvVar1 + local_8 * 4),&local_8,&local_c);
  _DAT_1000bfc0 = pvVar1;
  _DAT_1000bfbc = local_8 + -1;
  return;
}



void FUN_100049ff(byte *param_1,byte **param_2,byte *param_3,int *param_4,int *param_5)

{
  byte bVar1;
  bool bVar2;
  bool bVar3;
  byte *pbVar4;
  byte *pbVar5;
  uint uVar6;
  byte **ppbVar7;
  
  *param_5 = 0;
  *param_4 = 1;
  if (param_2 != (byte **)0x0) {
    *param_2 = param_3;
    param_2 = param_2 + 1;
  }
  if (*param_1 == 0x22) {
    while( true ) {
      bVar1 = param_1[1];
      pbVar4 = param_1 + 1;
      if ((bVar1 == 0x22) || (bVar1 == 0)) break;
      if ((((&DAT_1000c3c1)[bVar1] & 4) != 0) && (*param_5 = *param_5 + 1, param_3 != (byte *)0x0))
      {
        *param_3 = *pbVar4;
        param_3 = param_3 + 1;
        pbVar4 = param_1 + 2;
      }
      *param_5 = *param_5 + 1;
      param_1 = pbVar4;
      if (param_3 != (byte *)0x0) {
        *param_3 = *pbVar4;
        param_3 = param_3 + 1;
      }
    }
    *param_5 = *param_5 + 1;
    if (param_3 != (byte *)0x0) {
      *param_3 = 0;
      param_3 = param_3 + 1;
    }
    if (*pbVar4 == 0x22) {
      pbVar4 = param_1 + 2;
    }
  }
  else {
    do {
      *param_5 = *param_5 + 1;
      if (param_3 != (byte *)0x0) {
        *param_3 = *param_1;
        param_3 = param_3 + 1;
      }
      bVar1 = *param_1;
      pbVar4 = param_1 + 1;
      if (((&DAT_1000c3c1)[bVar1] & 4) != 0) {
        *param_5 = *param_5 + 1;
        if (param_3 != (byte *)0x0) {
          *param_3 = *pbVar4;
          param_3 = param_3 + 1;
        }
        pbVar4 = param_1 + 2;
      }
      if (bVar1 == 0x20) break;
      if (bVar1 == 0) goto LAB_10004aaa;
      param_1 = pbVar4;
    } while (bVar1 != 9);
    if (bVar1 == 0) {
LAB_10004aaa:
      pbVar4 = pbVar4 + -1;
    }
    else if (param_3 != (byte *)0x0) {
      param_3[-1] = 0;
    }
  }
  bVar2 = false;
  ppbVar7 = param_2;
  while (*pbVar4 != 0) {
    for (; (*pbVar4 == 0x20 || (*pbVar4 == 9)); pbVar4 = pbVar4 + 1) {
    }
    if (*pbVar4 == 0) break;
    if (ppbVar7 != (byte **)0x0) {
      *ppbVar7 = param_3;
      ppbVar7 = ppbVar7 + 1;
      param_2 = ppbVar7;
    }
    *param_4 = *param_4 + 1;
    while( true ) {
      bVar3 = true;
      uVar6 = 0;
      for (; *pbVar4 == 0x5c; pbVar4 = pbVar4 + 1) {
        uVar6 = uVar6 + 1;
      }
      if (*pbVar4 == 0x22) {
        pbVar5 = pbVar4;
        if ((uVar6 & 1) == 0) {
          if ((!bVar2) || (pbVar5 = pbVar4 + 1, pbVar4[1] != 0x22)) {
            bVar3 = false;
            pbVar5 = pbVar4;
          }
          bVar2 = !bVar2;
          ppbVar7 = param_2;
        }
        uVar6 = uVar6 >> 1;
        pbVar4 = pbVar5;
      }
      for (; uVar6 != 0; uVar6 = uVar6 - 1) {
        if (param_3 != (byte *)0x0) {
          *param_3 = 0x5c;
          param_3 = param_3 + 1;
        }
        *param_5 = *param_5 + 1;
      }
      bVar1 = *pbVar4;
      if ((bVar1 == 0) || ((!bVar2 && ((bVar1 == 0x20 || (bVar1 == 9)))))) break;
      if (bVar3) {
        if (param_3 == (byte *)0x0) {
          if (((&DAT_1000c3c1)[bVar1] & 4) != 0) {
            pbVar4 = pbVar4 + 1;
            *param_5 = *param_5 + 1;
          }
        }
        else {
          if (((&DAT_1000c3c1)[bVar1] & 4) != 0) {
            *param_3 = bVar1;
            param_3 = param_3 + 1;
            pbVar4 = pbVar4 + 1;
            *param_5 = *param_5 + 1;
          }
          *param_3 = *pbVar4;
          param_3 = param_3 + 1;
        }
        *param_5 = *param_5 + 1;
      }
      pbVar4 = pbVar4 + 1;
    }
    if (param_3 != (byte *)0x0) {
      *param_3 = 0;
      param_3 = param_3 + 1;
    }
    *param_5 = *param_5 + 1;
  }
  if (ppbVar7 != (byte **)0x0) {
    *ppbVar7 = (byte *)0x0;
  }
  *param_4 = *param_4 + 1;
  return;
}



LPSTR FUN_10004bb3(void)

{
  char cVar1;
  WCHAR WVar2;
  WCHAR *pWVar3;
  WCHAR *pWVar4;
  int iVar5;
  size_t _Size;
  LPSTR pCVar6;
  char *pcVar7;
  LPWCH lpWideCharStr;
  LPCH pCVar9;
  LPSTR local_8;
  char *pcVar8;
  
  lpWideCharStr = (LPWCH)0x0;
  pCVar9 = (LPCH)0x0;
  if (DAT_1000c0f0 == 0) {
    lpWideCharStr = GetEnvironmentStringsW();
    if (lpWideCharStr != (LPWCH)0x0) {
      DAT_1000c0f0 = 1;
LAB_10004c0a:
      if ((lpWideCharStr == (LPWCH)0x0) &&
         (lpWideCharStr = GetEnvironmentStringsW(), lpWideCharStr == (LPWCH)0x0)) {
        return (LPSTR)0x0;
      }
      WVar2 = *lpWideCharStr;
      pWVar4 = lpWideCharStr;
      while (WVar2 != L'\0') {
        do {
          pWVar3 = pWVar4;
          pWVar4 = pWVar3 + 1;
        } while (*pWVar4 != L'\0');
        pWVar4 = pWVar3 + 2;
        WVar2 = *pWVar4;
      }
      iVar5 = ((int)pWVar4 - (int)lpWideCharStr >> 1) + 1;
      _Size = WideCharToMultiByte(0,0,lpWideCharStr,iVar5,(LPSTR)0x0,0,(LPCSTR)0x0,(LPBOOL)0x0);
      local_8 = (LPSTR)0x0;
      if (((_Size != 0) && (pCVar6 = (LPSTR)_malloc(_Size), pCVar6 != (LPSTR)0x0)) &&
         (iVar5 = WideCharToMultiByte(0,0,lpWideCharStr,iVar5,pCVar6,_Size,(LPCSTR)0x0,(LPBOOL)0x0),
         local_8 = pCVar6, iVar5 == 0)) {
        FUN_100025a6(pCVar6);
        local_8 = (LPSTR)0x0;
      }
      FreeEnvironmentStringsW(lpWideCharStr);
      return local_8;
    }
    pCVar9 = GetEnvironmentStrings();
    if (pCVar9 == (LPCH)0x0) {
      return (LPSTR)0x0;
    }
    DAT_1000c0f0 = 2;
  }
  else {
    if (DAT_1000c0f0 == 1) goto LAB_10004c0a;
    if (DAT_1000c0f0 != 2) {
      return (LPSTR)0x0;
    }
  }
  if ((pCVar9 == (LPCH)0x0) && (pCVar9 = GetEnvironmentStrings(), pCVar9 == (LPCH)0x0)) {
    return (LPSTR)0x0;
  }
  cVar1 = *pCVar9;
  pcVar7 = pCVar9;
  while (cVar1 != '\0') {
    do {
      pcVar8 = pcVar7;
      pcVar7 = pcVar8 + 1;
    } while (*pcVar7 != '\0');
    pcVar7 = pcVar8 + 2;
    cVar1 = *pcVar7;
  }
  pCVar6 = (LPSTR)_malloc((size_t)(pcVar7 + (1 - (int)pCVar9)));
  if (pCVar6 == (LPSTR)0x0) {
    pCVar6 = (LPSTR)0x0;
  }
  else {
    FUN_100065c0(pCVar6,pCVar9,pcVar7 + (1 - (int)pCVar9));
  }
  FreeEnvironmentStringsA(pCVar9);
  return pCVar6;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_10004ce5(void)

{
  if ((DAT_1000bf34 == 1) || ((DAT_1000bf34 == 0 && (_DAT_1000bf38 == 1)))) {
    FUN_10004d1e(0xfc);
    if (DAT_1000c0f4 != (code *)0x0) {
      (*DAT_1000c0f4)();
    }
    FUN_10004d1e(0xff);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_10004d1e(DWORD param_1)

{
  char **ppcVar1;
  DWORD *pDVar2;
  DWORD DVar3;
  size_t sVar4;
  HANDLE hFile;
  int iVar5;
  CHAR *_Dest;
  char acStackY_1e3 [3];
  undefined4 uStackY_1e0;
  char *pcStackY_1dc;
  char *pcStackY_1d8;
  undefined4 uStackY_1d4;
  char *lpBuffer;
  LPDWORD lpNumberOfBytesWritten;
  LPOVERLAPPED lpOverlapped;
  CHAR local_1a8 [260];
  char local_a4 [160];
  
  iVar5 = 0;
  pDVar2 = &DAT_1000b478;
  do {
    if (param_1 == *pDVar2) break;
    pDVar2 = pDVar2 + 2;
    iVar5 = iVar5 + 1;
  } while ((int)pDVar2 < 0x1000b508);
  if (param_1 == (&DAT_1000b478)[iVar5 * 2]) {
    if ((DAT_1000bf34 == 1) || ((DAT_1000bf34 == 0 && (_DAT_1000bf38 == 1)))) {
      lpNumberOfBytesWritten = &param_1;
      ppcVar1 = (char **)(iVar5 * 8 + 0x1000b47c);
      lpOverlapped = (LPOVERLAPPED)0x0;
      sVar4 = _strlen(*ppcVar1);
      lpBuffer = *ppcVar1;
      hFile = GetStdHandle(0xfffffff4);
      WriteFile(hFile,lpBuffer,sVar4,lpNumberOfBytesWritten,lpOverlapped);
    }
    else if (param_1 != 0xfc) {
      DVar3 = GetModuleFileNameA((HMODULE)0x0,local_1a8,0x104);
      if (DVar3 == 0) {
        FID_conflict___mbscpy(local_1a8,"<program name unknown>");
      }
      _Dest = local_1a8;
      sVar4 = _strlen(local_1a8);
      if (0x3c < sVar4 + 1) {
        sVar4 = _strlen(local_1a8);
        _Dest = acStackY_1e3 + sVar4;
        _strncpy(_Dest,"...",3);
      }
      FID_conflict___mbscpy(local_a4,"Runtime Error!\n\nProgram: ");
      FID_conflict__strcat(local_a4,_Dest);
      FID_conflict__strcat(local_a4,"\n\n");
      uStackY_1d4 = 0x10004e2c;
      FID_conflict__strcat(local_a4,*(char **)(iVar5 * 8 + 0x1000b47c));
      uStackY_1d4 = 0x12010;
      pcStackY_1dc = local_a4;
      pcStackY_1d8 = "Microsoft Visual C++ Runtime Library";
      uStackY_1e0 = 0x10004e42;
      FUN_100068f5();
    }
  }
  return;
}



void FUN_10004e71(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  FUN_10004e88(param_1,param_2,param_3,0);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

uint FUN_10004e88(byte *param_1,byte **param_2,uint param_3,uint param_4)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  undefined4 *puVar4;
  byte bVar5;
  uint uVar6;
  uint local_c;
  byte *local_8;
  
  local_c = 0;
  bVar5 = *param_1;
  local_8 = param_1 + 1;
  while( true ) {
    if (_DAT_1000b424 < 2) {
      uVar1 = *(byte *)(DAT_1000b218 + (uint)bVar5 * 2) & 8;
    }
    else {
      uVar1 = FUN_10003e9f(bVar5,8);
    }
    if (uVar1 == 0) break;
    bVar5 = *local_8;
    local_8 = local_8 + 1;
  }
  if (bVar5 == 0x2d) {
    param_4 = param_4 | 2;
LAB_10004ee3:
    bVar5 = *local_8;
    local_8 = local_8 + 1;
  }
  else if (bVar5 == 0x2b) goto LAB_10004ee3;
  if ((((int)param_3 < 0) || (param_3 == 1)) || (0x24 < (int)param_3)) {
    if (param_2 != (byte **)0x0) {
      *param_2 = param_1;
    }
    return 0;
  }
  if (param_3 == 0) {
    if (bVar5 != 0x30) {
      param_3 = 10;
      goto LAB_10004f4d;
    }
    if ((*local_8 != 0x78) && (*local_8 != 0x58)) {
      param_3 = 8;
      goto LAB_10004f4d;
    }
    param_3 = 0x10;
  }
  if (((param_3 == 0x10) && (bVar5 == 0x30)) && ((*local_8 == 0x78 || (*local_8 == 0x58)))) {
    bVar5 = local_8[1];
    local_8 = local_8 + 2;
  }
LAB_10004f4d:
  uVar1 = (uint)(0xffffffff / (ulonglong)param_3);
  do {
    uVar6 = (uint)bVar5;
    if (_DAT_1000b424 < 2) {
      uVar2 = *(byte *)(DAT_1000b218 + uVar6 * 2) & 4;
    }
    else {
      uVar2 = FUN_10003e9f(uVar6,4);
    }
    if (uVar2 == 0) {
      if (_DAT_1000b424 < 2) {
        uVar6 = *(ushort *)(DAT_1000b218 + uVar6 * 2) & 0x103;
      }
      else {
        uVar6 = FUN_10003e9f(uVar6,0x103);
      }
      if (uVar6 == 0) {
LAB_10004ff9:
        local_8 = local_8 + -1;
        if ((param_4 & 8) == 0) {
          if (param_2 != (byte **)0x0) {
            local_8 = param_1;
          }
          local_c = 0;
        }
        else if (((param_4 & 4) != 0) ||
                (((param_4 & 1) == 0 &&
                 ((((param_4 & 2) != 0 && (0x80000000 < local_c)) ||
                  (((param_4 & 2) == 0 && (0x7fffffff < local_c)))))))) {
          puVar4 = (undefined4 *)FUN_10006a7e();
          *puVar4 = 0x22;
          if ((param_4 & 1) == 0) {
            local_c = ((param_4 & 2) != 0) + 0x7fffffff;
          }
          else {
            local_c = 0xffffffff;
          }
        }
        if (param_2 != (byte **)0x0) {
          *param_2 = local_8;
        }
        if ((param_4 & 2) == 0) {
          return local_c;
        }
        return -local_c;
      }
      iVar3 = FUN_10006a87((int)(char)bVar5);
      uVar6 = iVar3 - 0x37;
    }
    else {
      uVar6 = (int)(char)bVar5 - 0x30;
    }
    if (param_3 <= uVar6) goto LAB_10004ff9;
    if ((local_c < uVar1) ||
       ((local_c == uVar1 && (uVar6 <= (uint)(0xffffffff % (ulonglong)param_3))))) {
      local_c = local_c * param_3 + uVar6;
      param_4 = param_4 | 8;
    }
    else {
      param_4 = param_4 | 0xc;
    }
    bVar5 = *local_8;
    local_8 = local_8 + 1;
  } while( true );
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



// Library Function - Single Match
//  _strstr
// 
// Libraries: Visual Studio 1998 Debug, Visual Studio 1998 Release

char * __cdecl _strstr(char *_Str,char *_SubStr)

{
  char *pcVar1;
  char *pcVar2;
  char cVar3;
  uint uVar4;
  char cVar5;
  uint uVar6;
  uint uVar7;
  char *pcVar8;
  uint *puVar9;
  char *pcVar10;
  
  cVar3 = *_SubStr;
  if (cVar3 == '\0') {
    return _Str;
  }
  if (_SubStr[1] == '\0') {
    uVar4 = (uint)_Str & 3;
    while (uVar4 != 0) {
      if (*_Str == cVar3) {
        return (char *)(uint *)_Str;
      }
      if (*_Str == '\0') {
        return (char *)0x0;
      }
      uVar4 = (uint)(uint *)((int)_Str + 1) & 3;
      _Str = (char *)(uint *)((int)_Str + 1);
    }
    while( true ) {
      while( true ) {
        uVar4 = *(uint *)_Str;
        uVar7 = uVar4 ^ CONCAT22(CONCAT11(cVar3,cVar3),CONCAT11(cVar3,cVar3));
        uVar6 = uVar4 ^ 0xffffffff ^ uVar4 + 0x7efefeff;
        puVar9 = (uint *)((int)_Str + 4);
        if (((uVar7 ^ 0xffffffff ^ uVar7 + 0x7efefeff) & 0x81010100) != 0) break;
        _Str = (char *)puVar9;
        if ((uVar6 & 0x81010100) != 0) {
          if ((uVar6 & 0x1010100) != 0) {
            return (char *)0x0;
          }
          if ((uVar4 + 0x7efefeff & 0x80000000) == 0) {
            return (char *)0x0;
          }
        }
      }
      uVar4 = *(uint *)_Str;
      if ((char)uVar4 == cVar3) {
        return (char *)(uint *)_Str;
      }
      if ((char)uVar4 == '\0') {
        return (char *)0x0;
      }
      cVar5 = (char)(uVar4 >> 8);
      if (cVar5 == cVar3) {
        return (char *)((int)_Str + 1);
      }
      if (cVar5 == '\0') break;
      cVar5 = (char)(uVar4 >> 0x10);
      if (cVar5 == cVar3) {
        return (char *)((int)_Str + 2);
      }
      if (cVar5 == '\0') {
        return (char *)0x0;
      }
      cVar5 = (char)(uVar4 >> 0x18);
      if (cVar5 == cVar3) {
        return (char *)((int)_Str + 3);
      }
      _Str = (char *)puVar9;
      if (cVar5 == '\0') {
        return (char *)0x0;
      }
    }
    return (char *)0x0;
  }
  do {
    cVar5 = *_Str;
    do {
      while (_Str = _Str + 1, cVar5 != cVar3) {
        if (cVar5 == '\0') {
          return (char *)0x0;
        }
        cVar5 = *_Str;
      }
      cVar5 = *_Str;
      pcVar10 = _Str + 1;
      pcVar8 = _SubStr;
    } while (cVar5 != _SubStr[1]);
    do {
      if (pcVar8[2] == '\0') {
LAB_100051d3:
        return _Str + -1;
      }
      if (*pcVar10 != pcVar8[2]) break;
      pcVar1 = pcVar8 + 3;
      if (*pcVar1 == '\0') goto LAB_100051d3;
      pcVar2 = pcVar10 + 1;
      pcVar8 = pcVar8 + 2;
      pcVar10 = pcVar10 + 2;
    } while (*pcVar1 == *pcVar2);
  } while( true );
}



// WARNING: Unable to track spacebase fully for stack

void FUN_100051e0(void)

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



undefined4 * FUN_10005210(undefined4 *param_1,undefined4 *param_2,uint param_3)

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
          goto switchD_100053c7_caseD_2;
        case 3:
          goto switchD_100053c7_caseD_3;
        }
        goto switchD_100053c7_caseD_1;
      }
    }
    else {
      switch(param_3) {
      case 0:
        goto switchD_100053c7_caseD_0;
      case 1:
        goto switchD_100053c7_caseD_1;
      case 2:
        goto switchD_100053c7_caseD_2;
      case 3:
        goto switchD_100053c7_caseD_3;
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
              goto switchD_100053c7_caseD_2;
            case 3:
              goto switchD_100053c7_caseD_3;
            }
            goto switchD_100053c7_caseD_1;
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
              goto switchD_100053c7_caseD_2;
            case 3:
              goto switchD_100053c7_caseD_3;
            }
            goto switchD_100053c7_caseD_1;
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
              goto switchD_100053c7_caseD_2;
            case 3:
              goto switchD_100053c7_caseD_3;
            }
            goto switchD_100053c7_caseD_1;
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
switchD_100053c7_caseD_1:
      *(undefined *)((int)puVar2 + 3) = *(undefined *)((int)param_2 + 3);
      return param_1;
    case 2:
switchD_100053c7_caseD_2:
      *(undefined *)((int)puVar2 + 3) = *(undefined *)((int)param_2 + 3);
      *(undefined *)((int)puVar2 + 2) = *(undefined *)((int)param_2 + 2);
      return param_1;
    case 3:
switchD_100053c7_caseD_3:
      *(undefined *)((int)puVar2 + 3) = *(undefined *)((int)param_2 + 3);
      *(undefined *)((int)puVar2 + 2) = *(undefined *)((int)param_2 + 2);
      *(undefined *)((int)puVar2 + 1) = *(undefined *)((int)param_2 + 1);
      return param_1;
    }
switchD_100053c7_caseD_0:
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
        goto switchD_10005245_caseD_2;
      case 3:
        goto switchD_10005245_caseD_3;
      }
      goto switchD_10005245_caseD_1;
    }
  }
  else {
    switch(param_3) {
    case 0:
      goto switchD_10005245_caseD_0;
    case 1:
      goto switchD_10005245_caseD_1;
    case 2:
      goto switchD_10005245_caseD_2;
    case 3:
      goto switchD_10005245_caseD_3;
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
            goto switchD_10005245_caseD_2;
          case 3:
            goto switchD_10005245_caseD_3;
          }
          goto switchD_10005245_caseD_1;
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
            goto switchD_10005245_caseD_2;
          case 3:
            goto switchD_10005245_caseD_3;
          }
          goto switchD_10005245_caseD_1;
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
            goto switchD_10005245_caseD_2;
          case 3:
            goto switchD_10005245_caseD_3;
          }
          goto switchD_10005245_caseD_1;
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
switchD_10005245_caseD_1:
    *(undefined *)puVar2 = *(undefined *)param_2;
    return param_1;
  case 2:
switchD_10005245_caseD_2:
    *(undefined *)puVar2 = *(undefined *)param_2;
    *(undefined *)((int)puVar2 + 1) = *(undefined *)((int)param_2 + 1);
    return param_1;
  case 3:
switchD_10005245_caseD_3:
    *(undefined *)puVar2 = *(undefined *)param_2;
    *(undefined *)((int)puVar2 + 1) = *(undefined *)((int)param_2 + 1);
    *(undefined *)((int)puVar2 + 2) = *(undefined *)((int)param_2 + 2);
    return param_1;
  }
switchD_10005245_caseD_0:
  return param_1;
}



// Library Function - Single Match
//  _memset
// 
// Libraries: Visual Studio 1998 Debug, Visual Studio 1998 Release

void * __cdecl _memset(void *_Dst,int _Val,size_t _Size)

{
  uint uVar1;
  uint uVar2;
  size_t sVar3;
  uint *puVar4;
  
  if (_Size == 0) {
    return _Dst;
  }
  uVar1 = _Val & 0xff;
  puVar4 = (uint *)_Dst;
  if (3 < _Size) {
    uVar2 = -(int)_Dst & 3;
    sVar3 = _Size;
    if (uVar2 != 0) {
      sVar3 = _Size - uVar2;
      do {
        *(undefined *)puVar4 = (undefined)_Val;
        puVar4 = (uint *)((int)puVar4 + 1);
        uVar2 = uVar2 - 1;
      } while (uVar2 != 0);
    }
    uVar1 = uVar1 * 0x1010101;
    _Size = sVar3 & 3;
    uVar2 = sVar3 >> 2;
    if (uVar2 != 0) {
      for (; uVar2 != 0; uVar2 = uVar2 - 1) {
        *puVar4 = uVar1;
        puVar4 = puVar4 + 1;
      }
      if (_Size == 0) {
        return _Dst;
      }
    }
  }
  do {
    *(char *)puVar4 = (char)uVar1;
    puVar4 = (uint *)((int)puVar4 + 1);
    _Size = _Size - 1;
  } while (_Size != 0);
  return _Dst;
}



BOOL FUN_100055a8(DWORD param_1,LPCSTR param_2,int param_3,LPWORD param_4,UINT param_5,LCID param_6,
                 int param_7)

{
  undefined *puVar1;
  BOOL BVar2;
  int iVar3;
  WORD local_20 [2];
  undefined *local_1c;
  void *local_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &DAT_10008560;
  puStack_10 = &LAB_10003dac;
  local_14 = ExceptionList;
  local_1c = &stack0xffffffc8;
  iVar3 = DAT_1000c0f8;
  ExceptionList = &local_14;
  puVar1 = &stack0xffffffc8;
  if (DAT_1000c0f8 == 0) {
    ExceptionList = &local_14;
    BVar2 = GetStringTypeW(1,L"",1,local_20);
    iVar3 = 1;
    puVar1 = local_1c;
    if (BVar2 == 0) {
      BVar2 = GetStringTypeA(0,1,"",1,local_20);
      if (BVar2 == 0) {
        ExceptionList = local_14;
        return 0;
      }
      iVar3 = 2;
      puVar1 = local_1c;
    }
  }
  local_1c = puVar1;
  DAT_1000c0f8 = iVar3;
  if (DAT_1000c0f8 != 2) {
    if (DAT_1000c0f8 == 1) {
      if (param_5 == 0) {
        param_5 = DAT_1000c124;
      }
      iVar3 = MultiByteToWideChar(param_5,(-(uint)(param_7 != 0) & 8) + 1,param_2,param_3,
                                  (LPWSTR)0x0,0);
      if (iVar3 != 0) {
        local_8 = 0;
        FUN_100051e0();
        local_1c = &stack0xffffffc8;
        _memset(&stack0xffffffc8,0,iVar3 * 2);
        local_8 = 0xffffffff;
        if ((&stack0x00000000 != (undefined *)0x38) &&
           (iVar3 = MultiByteToWideChar(param_5,1,param_2,param_3,(LPWSTR)&stack0xffffffc8,iVar3),
           iVar3 != 0)) {
          BVar2 = GetStringTypeW(param_1,(LPCWSTR)&stack0xffffffc8,iVar3,param_4);
          ExceptionList = local_14;
          return BVar2;
        }
      }
    }
    ExceptionList = local_14;
    return 0;
  }
  if (param_6 == 0) {
    param_6 = DAT_1000c114;
  }
  BVar2 = GetStringTypeA(param_6,param_1,param_2,param_3,param_4);
  ExceptionList = local_14;
  return BVar2;
}



uint FUN_100056f1(uint param_1,uint param_2)

{
  uint uVar1;
  
  uVar1 = FUN_1000573c();
  uVar1 = uVar1 & ~param_2 | param_1 & param_2;
  FUN_100057ce(uVar1);
  return uVar1;
}



void FUN_10005726(undefined4 param_1,uint param_2)

{
  FUN_100056f1(param_1,param_2 & 0xfff7ffff);
  return;
}



uint FUN_1000573c(uint param_1)

{
  uint uVar1;
  uint uVar2;
  
  uVar1 = 0;
  if ((param_1 & 1) != 0) {
    uVar1 = 0x10;
  }
  if ((param_1 & 4) != 0) {
    uVar1 = uVar1 | 8;
  }
  if ((param_1 & 8) != 0) {
    uVar1 = uVar1 | 4;
  }
  if ((param_1 & 0x10) != 0) {
    uVar1 = uVar1 | 2;
  }
  if ((param_1 & 0x20) != 0) {
    uVar1 = uVar1 | 1;
  }
  if ((param_1 & 2) != 0) {
    uVar1 = uVar1 | 0x80000;
  }
  uVar2 = param_1 & 0xc00;
  if (uVar2 != 0) {
    if (uVar2 == 0x400) {
      uVar1 = uVar1 | 0x100;
    }
    else if (uVar2 == 0x800) {
      uVar1 = uVar1 | 0x200;
    }
    else if (uVar2 == 0xc00) {
      uVar1 = uVar1 | 0x300;
    }
  }
  if ((param_1 & 0x300) == 0) {
    uVar1 = uVar1 | 0x20000;
  }
  else if ((param_1 & 0x300) == 0x200) {
    uVar1 = uVar1 | 0x10000;
  }
  if ((param_1 & 0x1000) != 0) {
    uVar1 = uVar1 | 0x40000;
  }
  return uVar1;
}



uint FUN_100057ce(uint param_1)

{
  uint uVar1;
  uint uVar2;
  
  uVar1 = (uint)((param_1 & 0x10) != 0);
  if ((param_1 & 8) != 0) {
    uVar1 = uVar1 | 4;
  }
  if ((param_1 & 4) != 0) {
    uVar1 = uVar1 | 8;
  }
  if ((param_1 & 2) != 0) {
    uVar1 = uVar1 | 0x10;
  }
  if ((param_1 & 1) != 0) {
    uVar1 = uVar1 | 0x20;
  }
  if ((param_1 & 0x80000) != 0) {
    uVar1 = uVar1 | 2;
  }
  uVar2 = param_1 & 0x300;
  if (uVar2 != 0) {
    if (uVar2 == 0x100) {
      uVar1 = uVar1 | 0x400;
    }
    else if (uVar2 == 0x200) {
      uVar1 = uVar1 | 0x800;
    }
    else if (uVar2 == 0x300) {
      uVar1 = uVar1 | 0xc00;
    }
  }
  if ((param_1 & 0x30000) == 0) {
    uVar1 = uVar1 | 0x300;
  }
  else if ((param_1 & 0x30000) == 0x10000) {
    uVar1 = uVar1 | 0x200;
  }
  if ((param_1 & 0x40000) != 0) {
    uVar1 = uVar1 | 0x1000;
  }
  return uVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_10005857(int param_1)

{
  bool bVar1;
  
  if (DAT_1000c114 == 0) {
    if ((0x40 < param_1) && (param_1 < 0x5b)) {
      return param_1 + 0x20;
    }
  }
  else {
    InterlockedIncrement((LONG *)&DAT_1000c294);
    bVar1 = _DAT_1000c290 != 0;
    if (bVar1) {
      InterlockedDecrement((LONG *)&DAT_1000c294);
      FUN_10003c3c(0x13);
    }
    param_1 = FUN_100058c6(param_1);
    if (bVar1) {
      FUN_10003c9d(0x13);
    }
    else {
      InterlockedDecrement((LONG *)&DAT_1000c294);
    }
  }
  return param_1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

uint FUN_100058c6(uint param_1)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  undefined4 uVar4;
  uint local_8;
  
  uVar1 = param_1;
  if (DAT_1000c114 == 0) {
    if ((0x40 < (int)param_1) && ((int)param_1 < 0x5b)) {
      uVar1 = param_1 + 0x20;
    }
  }
  else {
    uVar4 = 1;
    if ((int)param_1 < 0x100) {
      if (_DAT_1000b424 < 2) {
        uVar2 = *(byte *)(DAT_1000b218 + param_1 * 2) & 1;
      }
      else {
        uVar2 = FUN_10003e9f(param_1,1);
      }
      if (uVar2 == 0) {
        return uVar1;
      }
    }
    if ((*(byte *)(DAT_1000b218 + 1 + ((int)uVar1 >> 8 & 0xffU) * 2) & 0x80) == 0) {
      param_1 = CONCAT31((int3)(param_1 >> 8),(char)uVar1) & 0xffff00ff;
    }
    else {
      uVar2 = param_1 >> 0x10;
      param_1._0_2_ = CONCAT11((char)uVar1,(char)(uVar1 >> 8));
      param_1 = CONCAT22((short)uVar2,(undefined2)param_1) & 0xff00ffff;
      uVar4 = 2;
    }
    iVar3 = FUN_10006bc2(DAT_1000c114,0x100,&param_1,uVar4,&local_8,3,0,1);
    if (iVar3 != 0) {
      if (iVar3 == 1) {
        uVar1 = local_8 & 0xff;
      }
      else {
        uVar1 = local_8 & 0xffff;
      }
    }
  }
  return uVar1;
}



undefined4 FUN_10005991(int param_1,int param_2)

{
  int *piVar1;
  int iVar2;
  
  if ((*(uint *)(param_1 + (param_2 / 0x20) * 4) & ~(-1 << (0x1fU - (char)(param_2 % 0x20) & 0x1f)))
      != 0) {
    return 0;
  }
  iVar2 = param_2 / 0x20 + 1;
  if (iVar2 < 3) {
    piVar1 = (int *)(param_1 + iVar2 * 4);
    do {
      if (*piVar1 != 0) {
        return 0;
      }
      iVar2 = iVar2 + 1;
      piVar1 = piVar1 + 1;
    } while (iVar2 < 3);
  }
  return 1;
}



void FUN_100059da(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  undefined4 *puVar3;
  
  puVar3 = (undefined4 *)(param_1 + (param_2 / 0x20) * 4);
  iVar1 = FUN_10006e11(*puVar3,1 << (0x1fU - (char)(param_2 % 0x20) & 0x1f),puVar3);
  iVar2 = param_2 / 0x20 + -1;
  if (-1 < iVar2) {
    puVar3 = (undefined4 *)(param_1 + iVar2 * 4);
    do {
      if (iVar1 == 0) {
        return;
      }
      iVar1 = FUN_10006e11(*puVar3,1,puVar3);
      iVar2 = iVar2 + -1;
      puVar3 = puVar3 + -1;
    } while (-1 < iVar2);
  }
  return;
}



undefined4 FUN_10005a30(int param_1,int param_2)

{
  uint *puVar1;
  int iVar2;
  byte bVar3;
  int iVar4;
  undefined4 *puVar5;
  undefined4 local_8;
  
  local_8 = 0;
  puVar1 = (uint *)(param_1 + (param_2 / 0x20) * 4);
  bVar3 = 0x1f - (char)(param_2 % 0x20);
  if (((*puVar1 & 1 << (bVar3 & 0x1f)) != 0) &&
     (iVar2 = FUN_10005991(param_1,param_2 + 1), iVar2 == 0)) {
    local_8 = FUN_100059da(param_1,param_2 + -1);
  }
  *puVar1 = *puVar1 & -1 << (bVar3 & 0x1f);
  iVar2 = param_2 / 0x20 + 1;
  if (iVar2 < 3) {
    puVar5 = (undefined4 *)(param_1 + iVar2 * 4);
    for (iVar4 = 3 - iVar2; iVar4 != 0; iVar4 = iVar4 + -1) {
      *puVar5 = 0;
      puVar5 = puVar5 + 1;
    }
  }
  return local_8;
}



void FUN_10005abc(int param_1,undefined4 *param_2)

{
  int iVar1;
  
  param_1 = param_1 - (int)param_2;
  iVar1 = 3;
  do {
    *(undefined4 *)(param_1 + (int)param_2) = *param_2;
    param_2 = param_2 + 1;
    iVar1 = iVar1 + -1;
  } while (iVar1 != 0);
  return;
}



void FUN_10005ad7(undefined4 *param_1)

{
  *param_1 = 0;
  param_1[1] = 0;
  param_1[2] = 0;
  return;
}



undefined4 FUN_10005ae3(int *param_1)

{
  int iVar1;
  
  iVar1 = 0;
  do {
    if (*param_1 != 0) {
      return 0;
    }
    iVar1 = iVar1 + 1;
    param_1 = param_1 + 1;
  } while (iVar1 < 3);
  return 1;
}



void FUN_10005afe(uint *param_1,uint param_2)

{
  uint uVar1;
  int iVar2;
  byte bVar3;
  int iVar4;
  int iVar5;
  uint *puVar6;
  int local_8;
  
  local_8 = 3;
  iVar2 = (int)param_2 / 0x20;
  iVar4 = (int)param_2 % 0x20;
  param_2 = 0;
  bVar3 = (byte)iVar4;
  puVar6 = param_1;
  do {
    uVar1 = *puVar6;
    *puVar6 = uVar1 >> (bVar3 & 0x1f) | param_2;
    puVar6 = puVar6 + 1;
    param_2 = (uVar1 & ~(-1 << (bVar3 & 0x1f))) << (0x20 - bVar3 & 0x1f);
    local_8 = local_8 + -1;
  } while (local_8 != 0);
  iVar5 = 2;
  iVar4 = 8;
  do {
    if (iVar5 < iVar2) {
      *(undefined4 *)(iVar4 + (int)param_1) = 0;
    }
    else {
      *(undefined4 *)(iVar4 + (int)param_1) = *(undefined4 *)(iVar4 + iVar2 * -4 + (int)param_1);
    }
    iVar5 = iVar5 + -1;
    iVar4 = iVar4 + -4;
  } while (-1 < iVar4);
  return;
}



undefined4 FUN_10005b8b(ushort *param_1,uint *param_2,int *param_3)

{
  ushort uVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  undefined4 uVar5;
  undefined local_1c [12];
  uint local_10;
  uint local_c;
  int local_8;
  
  uVar1 = param_1[5];
  local_10 = *(uint *)(param_1 + 3);
  local_c = *(uint *)(param_1 + 1);
  uVar3 = uVar1 & 0x7fff;
  iVar4 = uVar3 - 0x3fff;
  local_8 = (uint)*param_1 << 0x10;
  if (iVar4 == -0x3fff) {
    iVar4 = 0;
    iVar2 = FUN_10005ae3(&local_10);
    if (iVar2 != 0) {
LAB_10005cb7:
      uVar5 = 0;
      goto LAB_10005cb9;
    }
    FUN_10005ad7(&local_10);
  }
  else {
    FUN_10005abc(local_1c,&local_10);
    iVar2 = FUN_10005a30(&local_10,param_3[2]);
    if (iVar2 != 0) {
      iVar4 = uVar3 - 0x3ffe;
    }
    iVar2 = param_3[1];
    if (iVar4 < iVar2 - param_3[2]) {
      FUN_10005ad7(&local_10);
    }
    else {
      if (iVar2 < iVar4) {
        if (*param_3 <= iVar4) {
          FUN_10005ad7(&local_10);
          local_10 = local_10 | 0x80000000;
          FUN_10005afe(&local_10,param_3[3]);
          iVar4 = param_3[5] + *param_3;
          uVar5 = 1;
          goto LAB_10005cb9;
        }
        local_10 = local_10 & 0x7fffffff;
        iVar4 = param_3[5] + iVar4;
        FUN_10005afe(&local_10,param_3[3]);
        goto LAB_10005cb7;
      }
      FUN_10005abc(&local_10,local_1c);
      FUN_10005afe(&local_10,iVar2 - iVar4);
      FUN_10005a30(&local_10,param_3[2]);
      FUN_10005afe(&local_10,param_3[3] + 1);
    }
  }
  iVar4 = 0;
  uVar5 = 2;
LAB_10005cb9:
  local_10 = iVar4 << (0x1fU - (char)param_3[3] & 0x1f) |
             -(uint)((uVar1 & 0x8000) != 0) & 0x80000000 | local_10;
  if (param_3[4] == 0x40) {
    param_2[1] = local_10;
    *param_2 = local_c;
  }
  else if (param_3[4] == 0x20) {
    *param_2 = local_10;
  }
  return uVar5;
}



void FUN_10005cf7(undefined4 param_1,undefined4 param_2)

{
  FUN_10005b8b(param_1,param_2,&DAT_1000b510);
  return;
}



void FUN_10005d0d(undefined4 param_1,undefined4 param_2)

{
  FUN_10005b8b(param_1,param_2,&DAT_1000b528);
  return;
}



void FUN_10005d23(undefined4 param_1,undefined4 param_2)

{
  undefined local_10 [12];
  
  FUN_10006fb2(local_10,&param_2,param_2,0,0,0,0);
  FUN_10005cf7(local_10,param_1);
  return;
}



void FUN_10005d50(undefined4 param_1,undefined4 param_2)

{
  undefined local_10 [12];
  
  FUN_10006fb2(local_10,&param_2,param_2,0,0,0,0);
  FUN_10005d0d(local_10,param_1);
  return;
}



void FUN_10005d7d(char *param_1,int param_2,int param_3)

{
  char *_Str;
  char *pcVar1;
  char *pcVar2;
  size_t sVar3;
  char *pcVar4;
  char cVar5;
  
  pcVar1 = param_1;
  pcVar4 = *(char **)(param_3 + 0xc);
  _Str = param_1 + 1;
  *param_1 = '0';
  pcVar2 = _Str;
  if (0 < param_2) {
    param_1 = (char *)param_2;
    param_2 = 0;
    do {
      cVar5 = *pcVar4;
      if (cVar5 == '\0') {
        cVar5 = '0';
      }
      else {
        pcVar4 = pcVar4 + 1;
      }
      *pcVar2 = cVar5;
      pcVar2 = pcVar2 + 1;
      param_1 = (char *)((int)param_1 + -1);
    } while (param_1 != (char *)0x0);
  }
  *pcVar2 = '\0';
  if ((-1 < param_2) && ('4' < *pcVar4)) {
    while (pcVar2 = pcVar2 + -1, *pcVar2 == '9') {
      *pcVar2 = '0';
    }
    *pcVar2 = *pcVar2 + '\x01';
  }
  if (*pcVar1 == '1') {
    *(int *)(param_3 + 4) = *(int *)(param_3 + 4) + 1;
  }
  else {
    sVar3 = _strlen(_Str);
    FUN_10005210(pcVar1,_Str,sVar3 + 1);
  }
  return;
}



int * FUN_10005df4(undefined4 param_1,undefined4 param_2_00,int *param_2,char *param_3)

{
  int *piVar1;
  char *pcVar2;
  int iVar3;
  short local_2c;
  char local_2a;
  char local_28 [24];
  undefined4 local_10;
  undefined4 uStack_c;
  undefined2 uStack_8;
  
  FUN_10005e50(&local_10,&param_1);
  iVar3 = FUN_10007483(local_10,uStack_c,uStack_8,0x11,0,&local_2c);
  pcVar2 = param_3;
  piVar1 = param_2;
  param_2[2] = iVar3;
  *param_2 = (int)local_2a;
  param_2[1] = (int)local_2c;
  FID_conflict___mbscpy(param_3,local_28);
  piVar1[3] = (int)pcVar2;
  return piVar1;
}



void FUN_10005e50(uint *param_1,uint *param_2)

{
  ushort uVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  uint local_8;
  
  uVar1 = *(ushort *)((int)param_2 + 6);
  uVar3 = (uVar1 & 0x7ff0) >> 4;
  uVar2 = *param_2;
  local_8 = 0x80000000;
  if (uVar3 == 0) {
    if (((param_2[1] & 0xfffff) == 0) && (uVar2 == 0)) {
      param_1[1] = 0;
      *param_1 = 0;
      *(undefined2 *)(param_1 + 2) = 0;
      return;
    }
    iVar4 = 0x3c01;
    local_8 = 0;
  }
  else if (uVar3 == 0x7ff) {
    iVar4 = 0x7fff;
  }
  else {
    iVar4 = uVar3 + 0x3c00;
  }
  local_8 = uVar2 >> 0x15 | (param_2[1] & 0xfffff) << 0xb | local_8;
  param_1[1] = local_8;
  *param_1 = uVar2 << 0xb;
  while ((local_8 & 0x80000000) == 0) {
    local_8 = *param_1 >> 0x1f | local_8 * 2;
    *param_1 = *param_1 * 2;
    param_1[1] = local_8;
    iVar4 = iVar4 + 0xffff;
  }
  *(ushort *)(param_1 + 2) = uVar1 & 0x8000 | (ushort)iVar4;
  return;
}



// Library Function - Multiple Matches With Different Base Names
//  __mbscpy
//  _strcpy
// 
// Libraries: Visual Studio 1998 Debug, Visual Studio 1998 Release

char * __cdecl FID_conflict___mbscpy(char *_Dest,char *_Source)

{
  byte bVar1;
  uint uVar2;
  uint uVar3;
  uint *puVar4;
  
  uVar3 = (uint)_Source & 3;
  puVar4 = (uint *)_Dest;
  while (uVar3 != 0) {
    bVar1 = *_Source;
    uVar3 = (uint)bVar1;
    _Source = (char *)((int)_Source + 1);
    if (bVar1 == 0) goto LAB_10005ff8;
    *(byte *)puVar4 = bVar1;
    puVar4 = (uint *)((int)puVar4 + 1);
    uVar3 = (uint)_Source & 3;
  }
  do {
    uVar2 = *(uint *)_Source;
    uVar3 = *(uint *)_Source;
    _Source = (char *)((int)_Source + 4);
    if (((uVar2 ^ 0xffffffff ^ uVar2 + 0x7efefeff) & 0x81010100) != 0) {
      if ((char)uVar3 == '\0') {
LAB_10005ff8:
        *(byte *)puVar4 = (byte)uVar3;
        return _Dest;
      }
      if ((char)(uVar3 >> 8) == '\0') {
        *(short *)puVar4 = (short)uVar3;
        return _Dest;
      }
      if ((uVar3 & 0xff0000) == 0) {
        *(short *)puVar4 = (short)uVar3;
        *(byte *)((int)puVar4 + 2) = 0;
        return _Dest;
      }
      if ((uVar3 & 0xff000000) == 0) {
        *puVar4 = uVar3;
        return _Dest;
      }
    }
    *puVar4 = uVar3;
    puVar4 = puVar4 + 1;
  } while( true );
}



// Library Function - Multiple Matches With Different Base Names
//  __mbscat
//  _strcat
// 
// Libraries: Visual Studio 1998 Debug, Visual Studio 1998 Release

char * __cdecl FID_conflict__strcat(char *_Dest,char *_Source)

{
  byte bVar1;
  uint uVar2;
  uint *puVar3;
  uint uVar4;
  uint *puVar5;
  
  uVar4 = (uint)_Dest & 3;
  puVar3 = (uint *)_Dest;
  while (uVar4 != 0) {
    bVar1 = *(byte *)puVar3;
    puVar3 = (uint *)((int)puVar3 + 1);
    if (bVar1 == 0) goto LAB_10005f6f;
    uVar4 = (uint)puVar3 & 3;
  }
  do {
    do {
      puVar5 = puVar3;
      puVar3 = puVar5 + 1;
    } while (((*puVar5 ^ 0xffffffff ^ *puVar5 + 0x7efefeff) & 0x81010100) == 0);
    uVar4 = *puVar5;
    if ((char)uVar4 == '\0') goto LAB_10005f81;
    if ((char)(uVar4 >> 8) == '\0') {
      puVar5 = (uint *)((int)puVar5 + 1);
      goto LAB_10005f81;
    }
    if ((uVar4 & 0xff0000) == 0) {
      puVar5 = (uint *)((int)puVar5 + 2);
      goto LAB_10005f81;
    }
  } while ((uVar4 & 0xff000000) != 0);
LAB_10005f6f:
  puVar5 = (uint *)((int)puVar3 + -1);
LAB_10005f81:
  uVar4 = (uint)_Source & 3;
  while (uVar4 != 0) {
    bVar1 = *_Source;
    uVar4 = (uint)bVar1;
    _Source = (char *)((int)_Source + 1);
    if (bVar1 == 0) goto LAB_10005ff8;
    *(byte *)puVar5 = bVar1;
    puVar5 = (uint *)((int)puVar5 + 1);
    uVar4 = (uint)_Source & 3;
  }
  do {
    uVar2 = *(uint *)_Source;
    uVar4 = *(uint *)_Source;
    _Source = (char *)((int)_Source + 4);
    if (((uVar2 ^ 0xffffffff ^ uVar2 + 0x7efefeff) & 0x81010100) != 0) {
      if ((char)uVar4 == '\0') {
LAB_10005ff8:
        *(byte *)puVar5 = (byte)uVar4;
        return _Dest;
      }
      if ((char)(uVar4 >> 8) == '\0') {
        *(short *)puVar5 = (short)uVar4;
        return _Dest;
      }
      if ((uVar4 & 0xff0000) == 0) {
        *(short *)puVar5 = (short)uVar4;
        *(byte *)((int)puVar5 + 2) = 0;
        return _Dest;
      }
      if ((uVar4 & 0xff000000) == 0) {
        *puVar5 = uVar4;
        return _Dest;
      }
    }
    *puVar5 = uVar4;
    puVar5 = puVar5 + 1;
  } while( true );
}



// Library Function - Single Match
//  _strlen
// 
// Libraries: Visual Studio 1998 Debug, Visual Studio 1998 Release

size_t __cdecl _strlen(char *_Str)

{
  char cVar1;
  uint uVar2;
  uint *puVar3;
  uint *puVar4;
  
  uVar2 = (uint)_Str & 3;
  puVar3 = (uint *)_Str;
  while (uVar2 != 0) {
    cVar1 = *(char *)puVar3;
    puVar3 = (uint *)((int)puVar3 + 1);
    if (cVar1 == '\0') goto LAB_10006053;
    uVar2 = (uint)puVar3 & 3;
  }
  do {
    do {
      puVar4 = puVar3;
      puVar3 = puVar4 + 1;
    } while (((*puVar4 ^ 0xffffffff ^ *puVar4 + 0x7efefeff) & 0x81010100) == 0);
    uVar2 = *puVar4;
    if ((char)uVar2 == '\0') {
      return (int)puVar4 - (int)_Str;
    }
    if ((char)(uVar2 >> 8) == '\0') {
      return (size_t)((int)puVar4 + (1 - (int)_Str));
    }
    if ((uVar2 & 0xff0000) == 0) {
      return (size_t)((int)puVar4 + (2 - (int)_Str));
    }
  } while ((uVar2 & 0xff000000) != 0);
LAB_10006053:
  return (size_t)((int)puVar3 + (-1 - (int)_Str));
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

LPVOID FUN_10006084(int param_1,int param_2)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  uint _Size;
  void *local_24;
  void *local_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &DAT_10008570;
  puStack_10 = &LAB_10003dac;
  local_14 = ExceptionList;
  uVar2 = param_1 * param_2;
  uVar3 = uVar2;
  ExceptionList = &local_14;
  if (uVar2 < 0xffffffe1) {
    if (uVar2 == 0) {
      uVar3 = 1;
    }
    uVar3 = uVar3 + 0xf & 0xfffffff0;
    ExceptionList = &local_14;
  }
  do {
    local_24 = (LPVOID)0x0;
    if (uVar3 < 0xffffffe1) {
      if (DAT_1000c614 == 3) {
        if (uVar2 <= _DAT_1000c60c) {
          FUN_10003c3c(9);
          local_8 = 0;
          local_24 = (void *)FUN_100030ce(uVar2);
          local_8 = 0xffffffff;
          FUN_1000611d();
          _Size = uVar2;
          if (local_24 == (void *)0x0) goto LAB_10006171;
LAB_10006160:
          _memset(local_24,0,_Size);
        }
LAB_1000616c:
        if (local_24 != (LPVOID)0x0) {
          ExceptionList = local_14;
          return local_24;
        }
      }
      else {
        if ((DAT_1000c614 != 2) || (_DAT_1000b144 < uVar3)) goto LAB_1000616c;
        FUN_10003c3c(9);
        local_8 = 1;
        local_24 = (void *)FUN_1000387b(uVar3 >> 4);
        local_8 = 0xffffffff;
        FUN_100061a6();
        _Size = uVar3;
        if (local_24 != (void *)0x0) goto LAB_10006160;
      }
LAB_10006171:
      local_24 = HeapAlloc(DAT_1000c610,8,uVar3);
    }
    if (local_24 != (LPVOID)0x0) {
      ExceptionList = local_14;
      return local_24;
    }
    if (DAT_1000bfa0 == 0) {
      ExceptionList = local_14;
      return (LPVOID)0x0;
    }
    iVar1 = FUN_10003e84(uVar3);
    if (iVar1 == 0) {
      ExceptionList = local_14;
      return (LPVOID)0x0;
    }
  } while( true );
}



void FUN_1000611d(void)

{
  FUN_10003c9d(9);
  return;
}



void FUN_100061a6(void)

{
  FUN_10003c9d(9);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_100061c1(undefined4 param_1)

{
  BYTE *pBVar1;
  byte bVar2;
  byte bVar3;
  UINT CodePage;
  UINT *pUVar4;
  BOOL BVar5;
  uint uVar6;
  BYTE *pBVar7;
  int iVar8;
  byte *pbVar9;
  int iVar10;
  byte *pbVar11;
  undefined4 uVar12;
  uint uVar13;
  undefined4 *puVar14;
  _cpinfo local_1c;
  uint local_8;
  
  FUN_10003c3c(0x19);
  CodePage = FUN_1000636e(param_1);
  if (CodePage != DAT_1000c298) {
    if (CodePage != 0) {
      iVar10 = 0;
      pUVar4 = &DAT_1000b5d0;
LAB_100061fe:
      if (*pUVar4 != CodePage) goto code_r0x10006202;
      local_8 = 0;
      puVar14 = (undefined4 *)&DAT_1000c3c0;
      for (iVar8 = 0x40; iVar8 != 0; iVar8 = iVar8 + -1) {
        *puVar14 = 0;
        puVar14 = puVar14 + 1;
      }
      *(undefined *)puVar14 = 0;
      pbVar11 = &DAT_1000b5e0 + iVar10 * 0x30;
      do {
        bVar2 = *pbVar11;
        pbVar9 = pbVar11;
        while ((bVar2 != 0 && (bVar2 = pbVar9[1], bVar2 != 0))) {
          uVar13 = (uint)*pbVar9;
          if (uVar13 <= bVar2) {
            bVar3 = (&DAT_1000b5c8)[local_8];
            do {
              (&DAT_1000c3c1)[uVar13] = (&DAT_1000c3c1)[uVar13] | bVar3;
              uVar13 = uVar13 + 1;
            } while (uVar13 <= bVar2);
          }
          pbVar9 = pbVar9 + 2;
          bVar2 = *pbVar9;
        }
        local_8 = local_8 + 1;
        pbVar11 = pbVar11 + 8;
      } while (local_8 < 4);
      _DAT_1000c2ac = 1;
      DAT_1000c298 = CodePage;
      DAT_1000c4c4 = FUN_100063b8(CodePage);
      DAT_1000c2a0 = (&DAT_1000b5d4)[iVar10 * 0xc];
      DAT_1000c2a4 = (&DAT_1000b5d8)[iVar10 * 0xc];
      DAT_1000c2a8 = (&DAT_1000b5dc)[iVar10 * 0xc];
      goto LAB_10006352;
    }
    goto LAB_1000634d;
  }
  goto LAB_100061e8;
code_r0x10006202:
  pUVar4 = pUVar4 + 0xc;
  iVar10 = iVar10 + 1;
  if (0x1000b6bf < (int)pUVar4) goto code_r0x1000620d;
  goto LAB_100061fe;
code_r0x1000620d:
  BVar5 = GetCPInfo(CodePage,&local_1c);
  uVar13 = 1;
  if (BVar5 == 1) {
    DAT_1000c4c4 = 0;
    puVar14 = (undefined4 *)&DAT_1000c3c0;
    for (iVar10 = 0x40; iVar10 != 0; iVar10 = iVar10 + -1) {
      *puVar14 = 0;
      puVar14 = puVar14 + 1;
    }
    *(undefined *)puVar14 = 0;
    if (local_1c.MaxCharSize < 2) {
      _DAT_1000c2ac = 0;
      DAT_1000c298 = CodePage;
    }
    else {
      DAT_1000c298 = CodePage;
      if (local_1c.LeadByte[0] != '\0') {
        pBVar7 = local_1c.LeadByte + 1;
        do {
          bVar2 = *pBVar7;
          if (bVar2 == 0) break;
          for (uVar6 = (uint)pBVar7[-1]; uVar6 <= bVar2; uVar6 = uVar6 + 1) {
            (&DAT_1000c3c1)[uVar6] = (&DAT_1000c3c1)[uVar6] | 4;
          }
          pBVar1 = pBVar7 + 1;
          pBVar7 = pBVar7 + 2;
        } while (*pBVar1 != 0);
      }
      do {
        (&DAT_1000c3c1)[uVar13] = (&DAT_1000c3c1)[uVar13] | 8;
        uVar13 = uVar13 + 1;
      } while (uVar13 < 0xff);
      DAT_1000c4c4 = FUN_100063b8(CodePage);
      _DAT_1000c2ac = 1;
    }
    DAT_1000c2a0 = 0;
    DAT_1000c2a4 = 0;
    DAT_1000c2a8 = 0;
  }
  else {
    if (_DAT_1000c0fc == 0) {
      uVar12 = 0xffffffff;
      goto LAB_1000635f;
    }
LAB_1000634d:
    FUN_100063eb();
  }
LAB_10006352:
  FUN_10006414();
LAB_100061e8:
  uVar12 = 0;
LAB_1000635f:
  FUN_10003c9d(0x19);
  return uVar12;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_1000636e(int param_1)

{
  int iVar1;
  bool bVar2;
  
  if (param_1 == -2) {
    _DAT_1000c0fc = 1;
                    // WARNING: Could not recover jumptable at 0x10006388. Too many branches
                    // WARNING: Treating indirect jump as call
    iVar1 = GetOEMCP();
    return iVar1;
  }
  if (param_1 == -3) {
    _DAT_1000c0fc = 1;
                    // WARNING: Could not recover jumptable at 0x1000639d. Too many branches
                    // WARNING: Treating indirect jump as call
    iVar1 = GetACP();
    return iVar1;
  }
  bVar2 = param_1 == -4;
  if (bVar2) {
    param_1 = DAT_1000c124;
  }
  _DAT_1000c0fc = (uint)bVar2;
  return param_1;
}



undefined4 FUN_100063b8(int param_1)

{
  if (param_1 == 0x3a4) {
    return 0x411;
  }
  if (param_1 == 0x3a8) {
    return 0x804;
  }
  if (param_1 == 0x3b5) {
    return 0x412;
  }
  if (param_1 != 0x3b6) {
    return 0;
  }
  return 0x404;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_100063eb(void)

{
  int iVar1;
  undefined4 *puVar2;
  
  puVar2 = (undefined4 *)&DAT_1000c3c0;
  for (iVar1 = 0x40; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  *(undefined *)puVar2 = 0;
  DAT_1000c298 = 0;
  _DAT_1000c2ac = 0;
  DAT_1000c4c4 = 0;
  DAT_1000c2a0 = 0;
  DAT_1000c2a4 = 0;
  DAT_1000c2a8 = 0;
  return;
}



void FUN_10006414(void)

{
  BOOL BVar1;
  uint uVar2;
  char cVar3;
  uint uVar4;
  uint uVar5;
  ushort *puVar6;
  undefined uVar7;
  BYTE *pBVar8;
  undefined4 *puVar9;
  ushort local_518 [256];
  undefined local_318 [256];
  undefined local_218 [256];
  undefined4 local_118 [64];
  _cpinfo local_18;
  
  BVar1 = GetCPInfo(DAT_1000c298,&local_18);
  if (BVar1 == 1) {
    uVar2 = 0;
    do {
      *(char *)((int)local_118 + uVar2) = (char)uVar2;
      uVar2 = uVar2 + 1;
    } while (uVar2 < 0x100);
    local_118[0]._0_1_ = 0x20;
    if (local_18.LeadByte[0] != 0) {
      pBVar8 = local_18.LeadByte + 1;
      do {
        uVar2 = (uint)local_18.LeadByte[0];
        if (uVar2 <= *pBVar8) {
          uVar4 = (*pBVar8 - uVar2) + 1;
          puVar9 = (undefined4 *)((int)local_118 + uVar2);
          for (uVar5 = uVar4 >> 2; uVar5 != 0; uVar5 = uVar5 - 1) {
            *puVar9 = 0x20202020;
            puVar9 = puVar9 + 1;
          }
          for (uVar4 = uVar4 & 3; uVar4 != 0; uVar4 = uVar4 - 1) {
            *(undefined *)puVar9 = 0x20;
            puVar9 = (undefined4 *)((int)puVar9 + 1);
          }
        }
        local_18.LeadByte[0] = pBVar8[1];
        pBVar8 = pBVar8 + 2;
      } while (local_18.LeadByte[0] != 0);
    }
    FUN_100055a8(1,local_118,0x100,local_518,DAT_1000c298,DAT_1000c4c4,0);
    FUN_10006bc2(DAT_1000c4c4,0x100,local_118,0x100,local_218,0x100,DAT_1000c298,0);
    FUN_10006bc2(DAT_1000c4c4,0x200,local_118,0x100,local_318,0x100,DAT_1000c298,0);
    uVar2 = 0;
    puVar6 = local_518;
    do {
      if ((*puVar6 & 1) == 0) {
        if ((*puVar6 & 2) != 0) {
          (&DAT_1000c3c1)[uVar2] = (&DAT_1000c3c1)[uVar2] | 0x20;
          uVar7 = local_318[uVar2];
          goto LAB_10006520;
        }
        (&DAT_1000c2c0)[uVar2] = 0;
      }
      else {
        (&DAT_1000c3c1)[uVar2] = (&DAT_1000c3c1)[uVar2] | 0x10;
        uVar7 = local_218[uVar2];
LAB_10006520:
        (&DAT_1000c2c0)[uVar2] = uVar7;
      }
      uVar2 = uVar2 + 1;
      puVar6 = puVar6 + 1;
    } while (uVar2 < 0x100);
  }
  else {
    uVar2 = 0;
    do {
      if ((uVar2 < 0x41) || (0x5a < uVar2)) {
        if ((0x60 < uVar2) && (uVar2 < 0x7b)) {
          (&DAT_1000c3c1)[uVar2] = (&DAT_1000c3c1)[uVar2] | 0x20;
          cVar3 = (char)uVar2 + -0x20;
          goto LAB_1000656a;
        }
        (&DAT_1000c2c0)[uVar2] = 0;
      }
      else {
        (&DAT_1000c3c1)[uVar2] = (&DAT_1000c3c1)[uVar2] | 0x10;
        cVar3 = (char)uVar2 + ' ';
LAB_1000656a:
        (&DAT_1000c2c0)[uVar2] = cVar3;
      }
      uVar2 = uVar2 + 1;
    } while (uVar2 < 0x100);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_10006599(void)

{
  if (_DAT_1000c5e8 == 0) {
    FUN_100061c1(0xfffffffd);
    _DAT_1000c5e8 = 1;
  }
  return;
}



undefined4 * FUN_100065c0(undefined4 *param_1,undefined4 *param_2,uint param_3)

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
          goto switchD_10006777_caseD_2;
        case 3:
          goto switchD_10006777_caseD_3;
        }
        goto switchD_10006777_caseD_1;
      }
    }
    else {
      switch(param_3) {
      case 0:
        goto switchD_10006777_caseD_0;
      case 1:
        goto switchD_10006777_caseD_1;
      case 2:
        goto switchD_10006777_caseD_2;
      case 3:
        goto switchD_10006777_caseD_3;
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
              goto switchD_10006777_caseD_2;
            case 3:
              goto switchD_10006777_caseD_3;
            }
            goto switchD_10006777_caseD_1;
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
              goto switchD_10006777_caseD_2;
            case 3:
              goto switchD_10006777_caseD_3;
            }
            goto switchD_10006777_caseD_1;
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
              goto switchD_10006777_caseD_2;
            case 3:
              goto switchD_10006777_caseD_3;
            }
            goto switchD_10006777_caseD_1;
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
switchD_10006777_caseD_1:
      *(undefined *)((int)puVar2 + 3) = *(undefined *)((int)param_2 + 3);
      return param_1;
    case 2:
switchD_10006777_caseD_2:
      *(undefined *)((int)puVar2 + 3) = *(undefined *)((int)param_2 + 3);
      *(undefined *)((int)puVar2 + 2) = *(undefined *)((int)param_2 + 2);
      return param_1;
    case 3:
switchD_10006777_caseD_3:
      *(undefined *)((int)puVar2 + 3) = *(undefined *)((int)param_2 + 3);
      *(undefined *)((int)puVar2 + 2) = *(undefined *)((int)param_2 + 2);
      *(undefined *)((int)puVar2 + 1) = *(undefined *)((int)param_2 + 1);
      return param_1;
    }
switchD_10006777_caseD_0:
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
        goto switchD_100065f5_caseD_2;
      case 3:
        goto switchD_100065f5_caseD_3;
      }
      goto switchD_100065f5_caseD_1;
    }
  }
  else {
    switch(param_3) {
    case 0:
      goto switchD_100065f5_caseD_0;
    case 1:
      goto switchD_100065f5_caseD_1;
    case 2:
      goto switchD_100065f5_caseD_2;
    case 3:
      goto switchD_100065f5_caseD_3;
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
            goto switchD_100065f5_caseD_2;
          case 3:
            goto switchD_100065f5_caseD_3;
          }
          goto switchD_100065f5_caseD_1;
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
            goto switchD_100065f5_caseD_2;
          case 3:
            goto switchD_100065f5_caseD_3;
          }
          goto switchD_100065f5_caseD_1;
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
            goto switchD_100065f5_caseD_2;
          case 3:
            goto switchD_100065f5_caseD_3;
          }
          goto switchD_100065f5_caseD_1;
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
switchD_100065f5_caseD_1:
    *(undefined *)puVar2 = *(undefined *)param_2;
    return param_1;
  case 2:
switchD_100065f5_caseD_2:
    *(undefined *)puVar2 = *(undefined *)param_2;
    *(undefined *)((int)puVar2 + 1) = *(undefined *)((int)param_2 + 1);
    return param_1;
  case 3:
switchD_100065f5_caseD_3:
    *(undefined *)puVar2 = *(undefined *)param_2;
    *(undefined *)((int)puVar2 + 1) = *(undefined *)((int)param_2 + 1);
    *(undefined *)((int)puVar2 + 2) = *(undefined *)((int)param_2 + 2);
    return param_1;
  }
switchD_100065f5_caseD_0:
  return param_1;
}



int FUN_100068f5(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  HMODULE hModule;
  int iVar1;
  
  iVar1 = 0;
  if (DAT_1000c100 == (FARPROC)0x0) {
    hModule = LoadLibraryA("user32.dll");
    if (hModule != (HMODULE)0x0) {
      DAT_1000c100 = GetProcAddress(hModule,"MessageBoxA");
      if (DAT_1000c100 != (FARPROC)0x0) {
        DAT_1000c104 = GetProcAddress(hModule,"GetActiveWindow");
        DAT_1000c108 = GetProcAddress(hModule,"GetLastActivePopup");
        goto LAB_10006944;
      }
    }
    iVar1 = 0;
  }
  else {
LAB_10006944:
    if (DAT_1000c104 != (FARPROC)0x0) {
      iVar1 = (*DAT_1000c104)();
      if ((iVar1 != 0) && (DAT_1000c108 != (FARPROC)0x0)) {
        iVar1 = (*DAT_1000c108)(iVar1);
      }
    }
    iVar1 = (*DAT_1000c100)(iVar1,param_1,param_2,param_3);
  }
  return iVar1;
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
        goto joined_r0x100069be;
      }
    }
    do {
      if (((uint)puVar5 & 3) == 0) {
        uVar4 = _Count >> 2;
        cVar3 = '\0';
        if (uVar4 == 0) goto LAB_100069fb;
        goto LAB_10006a69;
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
joined_r0x10006a65:
          while( true ) {
            uVar4 = uVar4 - 1;
            puVar5 = puVar5 + 1;
            if (uVar4 == 0) break;
LAB_10006a69:
            *puVar5 = 0;
          }
          cVar3 = '\0';
          _Count = _Count & 3;
          if (_Count != 0) goto LAB_100069fb;
          return _Dest;
        }
        if ((char)(uVar2 >> 8) == '\0') {
          *puVar5 = uVar2 & 0xff;
          goto joined_r0x10006a65;
        }
        if ((uVar2 & 0xff0000) == 0) {
          *puVar5 = uVar2 & 0xffff;
          goto joined_r0x10006a65;
        }
        if ((uVar2 & 0xff000000) == 0) {
          *puVar5 = uVar2;
          goto joined_r0x10006a65;
        }
      }
      *puVar5 = uVar2;
      puVar5 = puVar5 + 1;
      uVar4 = uVar4 - 1;
joined_r0x100069be:
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
LAB_100069fb:
        *(char *)puVar5 = cVar3;
        puVar5 = (uint *)((int)puVar5 + 1);
      }
      return _Dest;
    }
    _Count = _Count - 1;
  } while (_Count != 0);
  return _Dest;
}



int FUN_10006a7e(void)

{
  int iVar1;
  
  iVar1 = FUN_10004596();
  return iVar1 + 8;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_10006a87(int param_1)

{
  bool bVar1;
  
  if (DAT_1000c114 == 0) {
    if ((0x60 < param_1) && (param_1 < 0x7b)) {
      return param_1 + -0x20;
    }
  }
  else {
    InterlockedIncrement((LONG *)&DAT_1000c294);
    bVar1 = _DAT_1000c290 != 0;
    if (bVar1) {
      InterlockedDecrement((LONG *)&DAT_1000c294);
      FUN_10003c3c(0x13);
    }
    param_1 = FUN_10006af6(param_1);
    if (bVar1) {
      FUN_10003c9d(0x13);
    }
    else {
      InterlockedDecrement((LONG *)&DAT_1000c294);
    }
  }
  return param_1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

uint FUN_10006af6(uint param_1)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  undefined4 uVar4;
  uint local_8;
  
  uVar1 = param_1;
  if (DAT_1000c114 == 0) {
    if ((0x60 < (int)param_1) && ((int)param_1 < 0x7b)) {
      uVar1 = param_1 - 0x20;
    }
  }
  else {
    if ((int)param_1 < 0x100) {
      if (_DAT_1000b424 < 2) {
        uVar2 = *(byte *)(DAT_1000b218 + param_1 * 2) & 2;
      }
      else {
        uVar2 = FUN_10003e9f(param_1,2);
      }
      if (uVar2 == 0) {
        return uVar1;
      }
    }
    if ((*(byte *)(DAT_1000b218 + 1 + ((int)uVar1 >> 8 & 0xffU) * 2) & 0x80) == 0) {
      param_1 = CONCAT31((int3)(param_1 >> 8),(char)uVar1) & 0xffff00ff;
      uVar4 = 1;
    }
    else {
      uVar2 = param_1 >> 0x10;
      param_1._0_2_ = CONCAT11((char)uVar1,(char)(uVar1 >> 8));
      param_1 = CONCAT22((short)uVar2,(undefined2)param_1) & 0xff00ffff;
      uVar4 = 2;
    }
    iVar3 = FUN_10006bc2(DAT_1000c114,0x200,&param_1,uVar4,&local_8,3,0,1);
    if (iVar3 != 0) {
      if (iVar3 == 1) {
        uVar1 = local_8 & 0xff;
      }
      else {
        uVar1 = local_8 & 0xffff;
      }
    }
  }
  return uVar1;
}



int FUN_10006bc2(LCID param_1,uint param_2,LPCSTR param_3,int param_4,LPWSTR param_5,int param_6,
                UINT param_7,int param_8)

{
  int iVar1;
  int iVar2;
  void *local_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &DAT_100085c8;
  puStack_10 = &LAB_10003dac;
  local_14 = ExceptionList;
  ExceptionList = &local_14;
  if (DAT_1000c14c == 0) {
    ExceptionList = &local_14;
    iVar1 = LCMapStringW(0,0x100,L"",1,(LPWSTR)0x0,0);
    if (iVar1 == 0) {
      iVar1 = LCMapStringA(0,0x100,"",1,(LPSTR)0x0,0);
      if (iVar1 == 0) {
        ExceptionList = local_14;
        return 0;
      }
      DAT_1000c14c = 2;
    }
    else {
      DAT_1000c14c = 1;
    }
  }
  if (0 < param_4) {
    param_4 = FUN_10006de6(param_3,param_4);
  }
  if (DAT_1000c14c == 2) {
    iVar1 = LCMapStringA(param_1,param_2,param_3,param_4,(LPSTR)param_5,param_6);
    ExceptionList = local_14;
    return iVar1;
  }
  if (DAT_1000c14c == 1) {
    if (param_7 == 0) {
      param_7 = DAT_1000c124;
    }
    iVar1 = MultiByteToWideChar(param_7,(-(uint)(param_8 != 0) & 8) + 1,param_3,param_4,(LPWSTR)0x0,
                                0);
    if (iVar1 != 0) {
      local_8 = 0;
      FUN_100051e0();
      local_8 = 0xffffffff;
      if ((&stack0x00000000 != (undefined *)0x3c) &&
         (iVar2 = MultiByteToWideChar(param_7,1,param_3,param_4,(LPWSTR)&stack0xffffffc4,iVar1),
         iVar2 != 0)) {
        iVar2 = LCMapStringW(param_1,param_2,(LPCWSTR)&stack0xffffffc4,iVar1,(LPWSTR)0x0,0);
        if (iVar2 != 0) {
          if ((param_2 & 0x400) == 0) {
            local_8 = 1;
            FUN_100051e0();
            local_8 = 0xffffffff;
            if (&stack0x00000000 == (undefined *)0x3c) {
              ExceptionList = local_14;
              return 0;
            }
            iVar1 = LCMapStringW(param_1,param_2,(LPCWSTR)&stack0xffffffc4,iVar1,
                                 (LPWSTR)&stack0xffffffc4,iVar2);
            if (iVar1 == 0) {
              ExceptionList = local_14;
              return 0;
            }
            if (param_6 == 0) {
              param_6 = 0;
              param_5 = (LPWSTR)0x0;
            }
            iVar2 = WideCharToMultiByte(param_7,0x220,(LPCWSTR)&stack0xffffffc4,iVar2,(LPSTR)param_5
                                        ,param_6,(LPCSTR)0x0,(LPBOOL)0x0);
            iVar1 = iVar2;
          }
          else {
            if (param_6 == 0) {
              ExceptionList = local_14;
              return iVar2;
            }
            if (param_6 < iVar2) {
              ExceptionList = local_14;
              return 0;
            }
            iVar1 = LCMapStringW(param_1,param_2,(LPCWSTR)&stack0xffffffc4,iVar1,param_5,param_6);
          }
          if (iVar1 != 0) {
            ExceptionList = local_14;
            return iVar2;
          }
        }
      }
    }
  }
  ExceptionList = local_14;
  return 0;
}



int FUN_10006de6(char *param_1,int param_2)

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



undefined4 FUN_10006e11(uint param_1,uint param_2,uint *param_3)

{
  uint uVar1;
  undefined4 uVar2;
  
  uVar2 = 0;
  uVar1 = param_1 + param_2;
  if ((uVar1 < param_1) || (uVar1 < param_2)) {
    uVar2 = 1;
  }
  *param_3 = uVar1;
  return uVar2;
}



// Library Function - Single Match
//  ___add_12
// 
// Library: Visual Studio 2003 Release

void ___add_12(undefined4 *param_1,undefined4 *param_2)

{
  int iVar1;
  
  iVar1 = FUN_10006e11(*param_1,*param_2,param_1);
  if (iVar1 != 0) {
    iVar1 = FUN_10006e11(param_1[1],1,param_1 + 1);
    if (iVar1 != 0) {
      param_1[2] = param_1[2] + 1;
    }
  }
  iVar1 = FUN_10006e11(param_1[1],param_2[1],param_1 + 1);
  if (iVar1 != 0) {
    param_1[2] = param_1[2] + 1;
  }
  FUN_10006e11(param_1[2],param_2[2],param_1 + 2);
  return;
}



void FUN_10006e90(uint *param_1)

{
  uint uVar1;
  uint uVar2;
  
  uVar1 = *param_1;
  uVar2 = param_1[1];
  *param_1 = uVar1 * 2;
  param_1[1] = uVar2 * 2 | uVar1 >> 0x1f;
  param_1[2] = param_1[2] << 1 | uVar2 >> 0x1f;
  return;
}



void FUN_10006ebe(uint *param_1)

{
  uint uVar1;
  
  uVar1 = param_1[1];
  param_1[1] = uVar1 >> 1 | param_1[2] << 0x1f;
  param_1[2] = param_1[2] >> 1;
  *param_1 = *param_1 >> 1 | uVar1 << 0x1f;
  return;
}



void FUN_10006eeb(char *param_1,int param_2,uint *param_3)

{
  uint *puVar1;
  uint local_14;
  uint local_10;
  uint local_c;
  int local_8;
  
  puVar1 = param_3;
  local_8 = 0x404e;
  *param_3 = 0;
  param_3[1] = 0;
  param_3[2] = 0;
  if (param_2 != 0) {
    param_3 = (uint *)param_2;
    do {
      local_14 = *puVar1;
      local_10 = puVar1[1];
      local_c = puVar1[2];
      FUN_10006e90(puVar1);
      FUN_10006e90(puVar1);
      ___add_12(puVar1,&local_14);
      FUN_10006e90(puVar1);
      local_10 = 0;
      local_c = 0;
      local_14 = (uint)*param_1;
      ___add_12(puVar1,&local_14);
      param_1 = param_1 + 1;
      param_3 = (uint *)((int)param_3 + -1);
    } while (param_3 != (uint *)0x0);
  }
  while (puVar1[2] == 0) {
    puVar1[2] = puVar1[1] >> 0x10;
    local_8 = local_8 + 0xfff0;
    puVar1[1] = *puVar1 >> 0x10 | puVar1[1] << 0x10;
    *puVar1 = *puVar1 << 0x10;
  }
  while ((puVar1[2] & 0x8000) == 0) {
    FUN_10006e90(puVar1);
    local_8 = local_8 + 0xffff;
  }
  *(undefined2 *)((int)puVar1 + 10) = (undefined2)local_8;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4
FUN_10006fb2(ushort *param_1,byte **param_2,byte *param_3,undefined4 param_4,int param_5,int param_6
            ,int param_7)

{
  int iVar1;
  uint uVar2;
  char *pcVar3;
  int iVar4;
  int iVar5;
  byte bVar6;
  int iVar7;
  byte *pbVar8;
  byte *pbVar9;
  byte *pbVar10;
  char local_60 [23];
  char local_49;
  ushort local_44;
  undefined2 uStack_42;
  undefined2 uStack_40;
  byte *local_3e;
  undefined4 local_3a;
  int local_34;
  int local_30;
  undefined4 local_2c;
  int local_28;
  int local_24;
  int local_20;
  int local_1c;
  undefined4 local_18;
  int local_14;
  char *local_10;
  int local_c;
  uint local_8;
  
  local_10 = local_60;
  local_2c = 0;
  local_1c = 1;
  local_8 = 0;
  local_14 = 0;
  local_28 = 0;
  local_24 = 0;
  local_30 = 0;
  local_34 = 0;
  local_20 = 0;
  local_c = 0;
  local_18 = 0;
  for (pbVar8 = param_3;
      (((bVar6 = *pbVar8, bVar6 == 0x20 || (bVar6 == 9)) || (bVar6 == 10)) || (bVar6 == 0xd));
      pbVar8 = pbVar8 + 1) {
  }
  iVar7 = 4;
  iVar4 = 0;
  iVar5 = local_14;
LAB_10007009:
  local_14 = iVar5;
  iVar5 = 1;
  bVar6 = *pbVar8;
  pbVar9 = pbVar8 + 1;
  pbVar10 = param_3;
  iVar1 = local_14;
  switch(iVar4) {
  case 0:
    if (('0' < (char)bVar6) && ((char)bVar6 < ':')) {
LAB_10007026:
      local_14 = iVar1;
      iVar4 = 3;
      goto LAB_1000724b;
    }
    if (bVar6 == DAT_1000b428) goto LAB_10007035;
    if (bVar6 == 0x2b) {
      local_2c = 0;
      iVar4 = 2;
      pbVar8 = pbVar9;
      iVar5 = local_14;
    }
    else if (bVar6 == 0x2d) {
      local_2c = 0x8000;
      iVar4 = 2;
      pbVar8 = pbVar9;
      iVar5 = local_14;
    }
    else {
      iVar4 = iVar5;
      pbVar8 = pbVar9;
      iVar5 = local_14;
      if (bVar6 != 0x30) goto LAB_10007325;
    }
    goto LAB_10007009;
  case 1:
    local_14 = 1;
    if (('0' < (char)bVar6) && (iVar1 = iVar5, (char)bVar6 < ':')) goto LAB_10007026;
    iVar4 = iVar7;
    pbVar8 = pbVar9;
    if (bVar6 != DAT_1000b428) {
      iVar4 = iVar5;
      if ((bVar6 == 0x2b) || (iVar4 = local_14, bVar6 == 0x2d)) goto LAB_100070ba;
      iVar4 = iVar5;
      local_14 = iVar5;
      if (bVar6 != 0x30) goto LAB_10007093;
    }
    goto LAB_10007009;
  case 2:
    if (('0' < (char)bVar6) && ((char)bVar6 < ':')) goto LAB_10007026;
    if (bVar6 == DAT_1000b428) {
LAB_10007035:
      iVar4 = 5;
      pbVar8 = pbVar9;
      iVar5 = local_14;
    }
    else {
      iVar4 = iVar5;
      pbVar8 = pbVar9;
      iVar5 = local_14;
      if (bVar6 != 0x30) goto LAB_1000732a;
    }
    goto LAB_10007009;
  case 3:
    local_14 = iVar5;
    while( true ) {
      if (_DAT_1000b424 < 2) {
        uVar2 = *(byte *)(DAT_1000b218 + (uint)bVar6 * 2) & 4;
      }
      else {
        uVar2 = FUN_10003e9f(bVar6,4);
      }
      if (uVar2 == 0) break;
      if (local_8 < 0x19) {
        local_8 = local_8 + 1;
        pcVar3 = local_10 + 1;
        *local_10 = bVar6 - 0x30;
        local_10 = pcVar3;
      }
      else {
        local_c = local_c + 1;
      }
      bVar6 = *pbVar9;
      pbVar9 = pbVar9 + 1;
    }
    iVar4 = iVar7;
    pbVar8 = pbVar9;
    iVar5 = local_14;
    if (bVar6 != DAT_1000b428) goto LAB_100071a7;
    goto LAB_10007009;
  case 4:
    local_14 = 1;
    local_28 = 1;
    iVar4 = iVar5;
    if (local_8 == 0) {
      while (iVar5 = local_28, iVar4 = local_14, bVar6 == 0x30) {
        local_c = local_c + -1;
        bVar6 = *pbVar9;
        pbVar9 = pbVar9 + 1;
      }
    }
    while( true ) {
      local_14 = iVar4;
      local_28 = iVar5;
      if (_DAT_1000b424 < 2) {
        uVar2 = *(byte *)(DAT_1000b218 + (uint)bVar6 * 2) & 4;
      }
      else {
        uVar2 = FUN_10003e9f(bVar6,4);
      }
      if (uVar2 == 0) break;
      if (local_8 < 0x19) {
        local_8 = local_8 + 1;
        local_c = local_c + -1;
        pcVar3 = local_10 + 1;
        *local_10 = bVar6 - 0x30;
        local_10 = pcVar3;
      }
      bVar6 = *pbVar9;
      pbVar9 = pbVar9 + 1;
      iVar5 = local_28;
      iVar4 = local_14;
    }
LAB_100071a7:
    iVar4 = local_14;
    if ((bVar6 == 0x2b) || (bVar6 == 0x2d)) {
LAB_100070ba:
      local_14 = iVar4;
      iVar4 = 0xb;
      pbVar8 = pbVar9 + -1;
      iVar5 = local_14;
    }
    else {
LAB_10007093:
      if (((char)bVar6 < 'D') ||
         (('E' < (char)bVar6 && (((char)bVar6 < 'd' || ('e' < (char)bVar6)))))) goto LAB_10007325;
      iVar4 = 6;
      pbVar8 = pbVar9;
      iVar5 = local_14;
    }
    goto LAB_10007009;
  case 5:
    local_28 = iVar5;
    if (_DAT_1000b424 < 2) {
      uVar2 = *(byte *)(DAT_1000b218 + (uint)bVar6 * 2) & 4;
    }
    else {
      uVar2 = FUN_10003e9f(bVar6,4);
    }
    iVar4 = iVar7;
    if (uVar2 != 0) goto LAB_1000724b;
    goto LAB_1000732a;
  case 6:
    param_3 = pbVar8 + -1;
    if (((char)bVar6 < '1') || ('9' < (char)bVar6)) {
      if (bVar6 == 0x2b) goto LAB_10007280;
      if (bVar6 == 0x2d) goto LAB_10007274;
      pbVar10 = param_3;
      if (bVar6 != 0x30) goto LAB_1000732a;
LAB_10007219:
      iVar4 = 8;
      pbVar8 = pbVar9;
      iVar5 = local_14;
      goto LAB_10007009;
    }
    break;
  case 7:
    if (((char)bVar6 < '1') || ('9' < (char)bVar6)) {
      if (bVar6 == 0x30) goto LAB_10007219;
      goto LAB_1000732a;
    }
    break;
  case 8:
    local_24 = 1;
    while (bVar6 == 0x30) {
      bVar6 = *pbVar9;
      pbVar9 = pbVar9 + 1;
    }
    if (((char)bVar6 < '1') || ('9' < (char)bVar6)) goto LAB_10007325;
    break;
  case 9:
    local_24 = 1;
    iVar4 = 0;
    goto LAB_100072ab;
  default:
    goto switchD_10007015_caseD_a;
  case 0xb:
    if (param_7 != 0) {
      param_3 = pbVar8;
      if (bVar6 == 0x2b) {
LAB_10007280:
        iVar4 = 7;
        pbVar8 = pbVar9;
        iVar5 = local_14;
      }
      else {
        pbVar10 = pbVar8;
        if (bVar6 != 0x2d) goto LAB_1000732a;
LAB_10007274:
        local_1c = -1;
        iVar4 = 7;
        pbVar8 = pbVar9;
        iVar5 = local_14;
      }
      goto LAB_10007009;
    }
    iVar4 = 10;
    pbVar9 = pbVar8;
switchD_10007015_caseD_a:
    pbVar8 = pbVar9;
    pbVar10 = pbVar9;
    iVar5 = local_14;
    if (iVar4 != 10) goto LAB_10007009;
    goto LAB_1000732a;
  }
  iVar4 = 9;
LAB_1000724b:
  pbVar8 = pbVar9 + -1;
  iVar5 = local_14;
  goto LAB_10007009;
LAB_100072ab:
  if (_DAT_1000b424 < 2) {
    uVar2 = *(byte *)(DAT_1000b218 + (uint)bVar6 * 2) & 4;
  }
  else {
    uVar2 = FUN_10003e9f(bVar6,4);
  }
  if (uVar2 == 0) goto LAB_100072f5;
  iVar4 = (char)bVar6 + -0x30 + iVar4 * 10;
  if (0x1450 < iVar4) goto LAB_100072ed;
  bVar6 = *pbVar9;
  pbVar9 = pbVar9 + 1;
  goto LAB_100072ab;
LAB_100072ed:
  iVar4 = 0x1451;
LAB_100072f5:
  while( true ) {
    local_20 = iVar4;
    if (_DAT_1000b424 < 2) {
      uVar2 = *(byte *)(DAT_1000b218 + (uint)bVar6 * 2) & 4;
    }
    else {
      uVar2 = FUN_10003e9f(bVar6,4);
    }
    if (uVar2 == 0) break;
    bVar6 = *pbVar9;
    pbVar9 = pbVar9 + 1;
    iVar4 = local_20;
  }
LAB_10007325:
  pbVar10 = pbVar9 + -1;
LAB_1000732a:
  *param_2 = pbVar10;
  if (local_14 == 0) {
    local_44 = 0;
    local_3a._0_2_ = 0;
    local_3e = (byte *)0x0;
    param_3 = (byte *)0x0;
    local_18 = 4;
    goto LAB_10007438;
  }
  pcVar3 = local_10;
  if (0x18 < local_8) {
    if ('\x04' < local_49) {
      local_49 = local_49 + '\x01';
    }
    local_8 = 0x18;
    local_c = local_c + 1;
    pcVar3 = local_10 + -1;
  }
  if (local_8 == 0) {
    local_44 = 0;
    local_3a._0_2_ = 0;
    local_3e = (byte *)0x0;
    param_3 = (byte *)0x0;
  }
  else {
    while (pcVar3 = pcVar3 + -1, *pcVar3 == '\0') {
      local_8 = local_8 - 1;
      local_c = local_c + 1;
    }
    FUN_10006eeb(local_60,local_8,&local_44);
    iVar4 = local_20;
    if (local_1c < 0) {
      iVar4 = -local_20;
    }
    iVar4 = iVar4 + local_c;
    if (local_24 == 0) {
      iVar4 = iVar4 + param_5;
    }
    if (local_28 == 0) {
      iVar4 = iVar4 - param_6;
    }
    if (iVar4 < 0x1451) {
      if (-0x1451 < iVar4) {
        FUN_10007a4a(&local_44,iVar4,param_4);
        param_3 = (byte *)CONCAT22(uStack_40,uStack_42);
        goto LAB_100073bd;
      }
      local_34 = 1;
    }
    else {
      local_30 = 1;
    }
    local_3a._0_2_ = (ushort)param_3;
    local_3e = param_3;
    local_44 = (ushort)local_3a;
  }
LAB_100073bd:
  if (local_30 == 0) {
    if (local_34 != 0) {
      local_44 = 0;
      local_3a._0_2_ = 0;
      local_3e = (byte *)0x0;
      param_3 = (byte *)0x0;
      local_18 = 1;
    }
  }
  else {
    param_3 = (byte *)0x0;
    local_3a._0_2_ = 0x7fff;
    local_3e = (byte *)0x80000000;
    local_44 = 0;
    local_18 = 2;
  }
LAB_10007438:
  *(byte **)(param_1 + 3) = local_3e;
  *(byte **)(param_1 + 1) = param_3;
  param_1[5] = (ushort)local_3a | (ushort)local_2c;
  *param_1 = local_44;
  return local_18;
}



undefined4
FUN_10007483(int param_1,uint param_2,uint param_3,int param_4,byte param_5,short *param_6)

{
  short *psVar1;
  short *psVar2;
  char cVar3;
  uint uVar4;
  short *psVar5;
  short *psVar6;
  short sVar7;
  int iVar8;
  int iVar9;
  char *pcVar10;
  undefined local_20;
  undefined local_1f;
  undefined local_1e;
  undefined local_1d;
  undefined local_1c;
  undefined local_1b;
  undefined local_1a;
  undefined local_19;
  undefined local_18;
  undefined local_17;
  undefined local_16;
  undefined local_15;
  undefined2 local_14;
  undefined2 local_12;
  undefined2 uStack_10;
  undefined2 local_e;
  undefined2 uStack_c;
  undefined local_a;
  char cStack_9;
  undefined4 local_8;
  
  psVar2 = param_6;
  uVar4 = param_3 & 0x7fff;
  local_20 = 0xcc;
  local_1f = 0xcc;
  local_1e = 0xcc;
  local_1d = 0xcc;
  local_1c = 0xcc;
  local_1b = 0xcc;
  local_1a = 0xcc;
  local_19 = 0xcc;
  local_18 = 0xcc;
  local_17 = 0xcc;
  local_16 = 0xfb;
  local_15 = 0x3f;
  local_8 = 1;
  if ((param_3 & 0x8000) == 0) {
    *(undefined *)(param_6 + 1) = 0x20;
  }
  else {
    *(undefined *)(param_6 + 1) = 0x2d;
  }
  if ((((short)uVar4 != 0) || (param_2 != 0)) || (param_1 != 0)) {
    if ((short)uVar4 == 0x7fff) {
      *param_6 = 1;
      if (((param_2 == 0x80000000) && (param_1 == 0)) || ((param_2 & 0x40000000) != 0)) {
        if (((param_3 & 0x8000) == 0) || (param_2 != 0xc0000000)) {
          if ((param_2 != 0x80000000) || (param_1 != 0)) goto LAB_10007578;
          pcVar10 = "1#INF";
        }
        else {
          if (param_1 != 0) {
LAB_10007578:
            pcVar10 = "1#QNAN";
            goto LAB_1000757d;
          }
          pcVar10 = "1#IND";
        }
        FID_conflict___mbscpy((char *)(param_6 + 2),pcVar10);
        *(undefined *)((int)psVar2 + 3) = 5;
      }
      else {
        pcVar10 = "1#SNAN";
LAB_1000757d:
        FID_conflict___mbscpy((char *)(param_6 + 2),pcVar10);
        *(undefined *)((int)psVar2 + 3) = 6;
      }
      return 0;
    }
    local_14 = 0;
    local_a = (undefined)uVar4;
    cStack_9 = (char)(uVar4 >> 8);
    local_e = (undefined2)param_2;
    uStack_c = (undefined2)(param_2 >> 0x10);
    local_12 = (undefined2)param_1;
    uStack_10 = (undefined2)((uint)param_1 >> 0x10);
    sVar7 = (short)(((uVar4 >> 8) + (param_2 >> 0x18) * 2) * 0x4d + -0x134312f4 + uVar4 * 0x4d10 >>
                   0x10);
    FUN_10007a4a(&local_14,-(int)sVar7,1);
    if (0x3ffe < CONCAT11(cStack_9,local_a)) {
      sVar7 = sVar7 + 1;
      FUN_1000782a(&local_14,&local_20);
    }
    *psVar2 = sVar7;
    iVar9 = param_4;
    if (((param_5 & 1) == 0) || (iVar9 = param_4 + sVar7, 0 < param_4 + sVar7)) {
      if (0x15 < iVar9) {
        iVar9 = 0x15;
      }
      iVar8 = CONCAT11(cStack_9,local_a) - 0x3ffe;
      local_a = 0;
      cStack_9 = '\0';
      param_6 = (short *)0x8;
      do {
        FUN_10006e90(&local_14);
        param_6 = (short *)((int)param_6 + -1);
      } while (param_6 != (short *)0x0);
      if (iVar8 < 0) {
        param_6 = (short *)0x0;
        for (uVar4 = -iVar8 & 0xff; uVar4 != 0; uVar4 = uVar4 - 1) {
          FUN_10006ebe(&local_14);
        }
      }
      param_4 = iVar9 + 1;
      psVar5 = psVar2 + 2;
      param_6 = psVar5;
      if (0 < param_4) {
        do {
          param_1 = CONCAT22(local_12,local_14);
          param_2 = CONCAT22(local_e,uStack_10);
          param_3 = CONCAT13(cStack_9,CONCAT12(local_a,uStack_c));
          FUN_10006e90(&local_14);
          FUN_10006e90(&local_14);
          ___add_12(&local_14,&param_1);
          FUN_10006e90(&local_14);
          cVar3 = cStack_9;
          cStack_9 = '\0';
          psVar5 = (short *)((int)param_6 + 1);
          param_4 = param_4 + -1;
          *(char *)param_6 = cVar3 + '0';
          param_6 = psVar5;
        } while (param_4 != 0);
      }
      psVar6 = psVar5 + -1;
      psVar1 = psVar2 + 2;
      if ('4' < *(char *)((int)psVar5 + -1)) {
        for (; psVar1 <= psVar6; psVar6 = (short *)((int)psVar6 + -1)) {
          if (*(char *)psVar6 != '9') {
            if (psVar1 <= psVar6) goto LAB_100076d5;
            break;
          }
          *(undefined *)psVar6 = 0x30;
        }
        psVar6 = (short *)((int)psVar6 + 1);
        *psVar2 = *psVar2 + 1;
LAB_100076d5:
        *(char *)psVar6 = *(char *)psVar6 + '\x01';
LAB_100076d7:
        cVar3 = ((char)psVar6 - (char)psVar2) + -3;
        *(char *)((int)psVar2 + 3) = cVar3;
        *(undefined *)(cVar3 + 4 + (int)psVar2) = 0;
        return local_8;
      }
      for (; psVar1 <= psVar6; psVar6 = (short *)((int)psVar6 + -1)) {
        if (*(char *)psVar6 != '0') {
          if (psVar1 <= psVar6) goto LAB_100076d7;
          break;
        }
      }
      *psVar2 = 0;
      *(undefined *)(psVar2 + 1) = 0x20;
      *(undefined *)((int)psVar2 + 3) = 1;
      *(undefined *)psVar1 = 0x30;
      goto LAB_1000770d;
    }
  }
  *psVar2 = 0;
  *(undefined *)(psVar2 + 1) = 0x20;
  *(undefined *)((int)psVar2 + 3) = 1;
  *(undefined *)(psVar2 + 2) = 0x30;
LAB_1000770d:
  *(undefined *)((int)psVar2 + 5) = 0;
  return 1;
}



int FUN_100077b0(byte *param_1,byte *param_2)

{
  byte bVar1;
  byte *pbVar2;
  int iVar3;
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
    bVar1 = *param_2;
    if (bVar1 == 0) break;
    param_2 = param_2 + 1;
    pbVar2 = (byte *)((int)&uStack_28 + ((int)(uint)bVar1 >> 3));
    *pbVar2 = *pbVar2 | '\x01' << (bVar1 & 7);
  }
  iVar3 = -1;
  do {
    iVar3 = iVar3 + 1;
    bVar1 = *param_1;
    if (bVar1 == 0) {
      return iVar3;
    }
    param_1 = param_1 + 1;
  } while ((*(byte *)((int)&uStack_28 + ((int)(uint)bVar1 >> 3)) >> (bVar1 & 7) & 1) == 0);
  return iVar3;
}



byte * FUN_100077f0(byte *param_1,byte *param_2)

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
    bVar1 = *param_2;
    if (bVar1 == 0) break;
    param_2 = param_2 + 1;
    pbVar2 = (byte *)((int)&uStack_28 + ((int)(uint)bVar1 >> 3));
    *pbVar2 = *pbVar2 | '\x01' << (bVar1 & 7);
  }
  do {
    pbVar2 = param_1;
    bVar1 = *pbVar2;
    if (bVar1 == 0) {
      return (byte *)(uint)bVar1;
    }
    param_1 = pbVar2 + 1;
  } while ((*(byte *)((int)&uStack_28 + ((int)(byte *)(uint)bVar1 >> 3)) >> (bVar1 & 7) & 1) == 0);
  return pbVar2;
}



void FUN_1000782a(int *param_1,int *param_2)

{
  short sVar1;
  int iVar2;
  ushort uVar3;
  int *piVar4;
  int *piVar5;
  ushort uVar6;
  int iVar7;
  ushort uVar8;
  ushort uVar9;
  byte local_28;
  undefined uStack_27;
  undefined2 uStack_26;
  short local_24;
  undefined2 uStack_22;
  undefined2 local_20;
  undefined uStack_1e;
  byte bStack_1d;
  int local_1c;
  int local_18;
  int local_14;
  int *local_10;
  ushort *local_c;
  short *local_8;
  
  piVar5 = param_2;
  piVar4 = param_1;
  local_18 = 0;
  local_28 = 0;
  uStack_27 = 0;
  uStack_26 = 0;
  local_24 = 0;
  uStack_22 = 0;
  local_20 = 0;
  uStack_1e = 0;
  bStack_1d = 0;
  uVar6 = *(ushort *)((int)param_1 + 10) & 0x7fff;
  uVar8 = *(ushort *)((int)param_2 + 10) & 0x7fff;
  uVar9 = (*(ushort *)((int)param_2 + 10) ^ *(ushort *)((int)param_1 + 10)) & 0x8000;
  uVar3 = uVar8 + uVar6;
  if (((uVar6 < 0x7fff) && (uVar8 < 0x7fff)) && (uVar3 < 0xbffe)) {
    if (uVar3 < 0x3fc0) {
LAB_100078cd:
      param_1[2] = 0;
      param_1[1] = 0;
      *param_1 = 0;
      return;
    }
    if (((uVar6 != 0) || (uVar3 = uVar3 + 1, (param_1[2] & 0x7fffffffU) != 0)) ||
       ((uVar6 = 0, param_1[1] != 0 || (*param_1 != 0)))) {
      if (((uVar8 == 0) && (uVar3 = uVar3 + 1, (param_2[2] & 0x7fffffffU) == 0)) &&
         ((param_2[1] == 0 && (*param_2 == 0)))) goto LAB_100078cd;
      local_14 = 0;
      local_8 = &local_24;
      param_2 = (int *)0x5;
      do {
        if (0 < (int)param_2) {
          local_c = (ushort *)(local_14 * 2 + (int)param_1);
          local_10 = piVar5 + 2;
          local_1c = (int)param_2;
          do {
            iVar7 = FUN_10006e11(*(undefined4 *)(local_8 + -2),
                                 (uint)*local_c * (uint)*(ushort *)local_10,local_8 + -2);
            if (iVar7 != 0) {
              *local_8 = *local_8 + 1;
            }
            local_c = local_c + 1;
            local_10 = (int *)((int)local_10 + -2);
            local_1c = local_1c + -1;
          } while (local_1c != 0);
        }
        local_8 = local_8 + 1;
        local_14 = local_14 + 1;
        param_2 = (int *)((int)param_2 + -1);
      } while (0 < (int)param_2);
      param_1._0_2_ = uVar3 + 0xc002;
      if ((short)(ushort)param_1 < 1) {
LAB_10007981:
        param_1._0_2_ = (ushort)param_1 - 1;
        if ((short)(ushort)param_1 < 0) {
          iVar7 = -(int)(short)(ushort)param_1;
          param_1._0_2_ = (ushort)param_1 + (short)iVar7;
          do {
            if ((local_28 & 1) != 0) {
              local_18 = local_18 + 1;
            }
            FUN_10006ebe(&local_28);
            iVar7 = iVar7 + -1;
          } while (iVar7 != 0);
          if (local_18 != 0) {
            local_28 = local_28 | 1;
          }
        }
      }
      else {
        do {
          if ((bStack_1d & 0x80) != 0) break;
          FUN_10006e90(&local_28);
          param_1._0_2_ = (ushort)param_1 - 1;
        } while (0 < (short)(ushort)param_1);
        if ((short)(ushort)param_1 < 1) goto LAB_10007981;
      }
      if ((0x8000 < CONCAT11(uStack_27,local_28)) ||
         (sVar1 = CONCAT11(bStack_1d,uStack_1e), iVar2 = CONCAT22(local_20,uStack_22),
         iVar7 = CONCAT22(local_24,uStack_26),
         (CONCAT22(uStack_26,CONCAT11(uStack_27,local_28)) & 0x1ffff) == 0x18000)) {
        if (CONCAT22(local_24,uStack_26) == -1) {
          iVar7 = 0;
          if (CONCAT22(local_20,uStack_22) == -1) {
            if (CONCAT11(bStack_1d,uStack_1e) == -1) {
              param_1._0_2_ = (ushort)param_1 + 1;
              sVar1 = -0x8000;
              iVar2 = 0;
              iVar7 = 0;
            }
            else {
              sVar1 = CONCAT11(bStack_1d,uStack_1e) + 1;
              iVar2 = 0;
              iVar7 = 0;
            }
          }
          else {
            sVar1 = CONCAT11(bStack_1d,uStack_1e);
            iVar2 = CONCAT22(local_20,uStack_22) + 1;
          }
        }
        else {
          iVar7 = CONCAT22(local_24,uStack_26) + 1;
          sVar1 = CONCAT11(bStack_1d,uStack_1e);
          iVar2 = CONCAT22(local_20,uStack_22);
        }
      }
      local_24 = (short)((uint)iVar7 >> 0x10);
      uStack_26 = (undefined2)iVar7;
      local_20 = (undefined2)((uint)iVar2 >> 0x10);
      uStack_22 = (undefined2)iVar2;
      bStack_1d = (byte)((ushort)sVar1 >> 8);
      uStack_1e = (undefined)sVar1;
      if (0x7ffe < (ushort)param_1) goto LAB_10007a2a;
      uVar6 = (ushort)param_1 | uVar9;
      *(undefined2 *)piVar4 = uStack_26;
      *(uint *)((int)piVar4 + 2) = CONCAT22(uStack_22,local_24);
      *(uint *)((int)piVar4 + 6) = CONCAT13(bStack_1d,CONCAT12(uStack_1e,local_20));
    }
    *(ushort *)((int)piVar4 + 10) = uVar6;
  }
  else {
LAB_10007a2a:
    piVar4[1] = 0;
    *piVar4 = 0;
    piVar4[2] = (-(uint)(uVar9 != 0) & 0x80000000) + 0x7fff8000;
  }
  return;
}



void FUN_10007a4a(undefined2 *param_1,uint param_2,int param_3)

{
  uint uVar1;
  uint uVar2;
  undefined **ppuVar3;
  undefined **ppuVar4;
  undefined2 local_10;
  undefined4 local_e;
  undefined2 uStack_a;
  undefined *puStack_8;
  
  ppuVar3 = &PTR_DAT_1000b9e0;
  if (param_2 != 0) {
    if ((int)param_2 < 0) {
      param_2 = -param_2;
      ppuVar3 = (undefined **)0x1000bb40;
    }
    if (param_3 == 0) {
      *param_1 = 0;
    }
    while (param_2 != 0) {
      ppuVar3 = ppuVar3 + 0x15;
      uVar1 = (int)param_2 >> 3;
      uVar2 = param_2 & 7;
      param_2 = uVar1;
      if (uVar2 != 0) {
        ppuVar4 = ppuVar3 + uVar2 * 3;
        if (0x7fff < *(ushort *)(ppuVar3 + uVar2 * 3)) {
          local_10 = SUB42(*ppuVar4,0);
          local_e._0_2_ = (undefined2)((uint)*ppuVar4 >> 0x10);
          local_e._2_2_ = SUB42(ppuVar4[1],0);
          uStack_a = (undefined2)((uint)ppuVar4[1] >> 0x10);
          puStack_8 = ppuVar4[2];
          local_e = CONCAT22(local_e._2_2_,(undefined2)local_e) + -1;
          ppuVar4 = (undefined **)&local_10;
        }
        FUN_1000782a(param_1,ppuVar4);
      }
    }
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

byte FUN_10007ad0(byte *param_1,byte *param_2)

{
  bool bVar1;
  int iVar2;
  byte bVar3;
  byte bVar4;
  byte bVar5;
  uint uVar6;
  
  iVar2 = _DAT_1000c294;
  if (DAT_1000c114 == 0) {
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
    _DAT_1000c294 = _DAT_1000c294 + 1;
    UNLOCK();
    bVar1 = 0 < _DAT_1000c290;
    if (bVar1) {
      LOCK();
      UNLOCK();
      _DAT_1000c294 = iVar2;
      FUN_10003c3c(0x13);
    }
    uVar6 = (uint)bVar1;
    bVar5 = 0xff;
    do {
      do {
        if (bVar5 == 0) goto LAB_10007b7f;
        bVar5 = *param_2;
        param_2 = param_2 + 1;
        bVar4 = *param_1;
        param_1 = param_1 + 1;
      } while (bVar5 == bVar4);
      bVar4 = FUN_100058c6(bVar4,bVar5);
      bVar5 = FUN_100058c6();
    } while (bVar4 == bVar5);
    bVar5 = (bVar4 < bVar5) * -2 + 1;
LAB_10007b7f:
    if (uVar6 == 0) {
      LOCK();
      _DAT_1000c294 = _DAT_1000c294 + -1;
      UNLOCK();
    }
    else {
      FUN_10003c9d(0x13);
    }
  }
  return bVar5;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_10007ba0(byte *param_1,char *param_2,int param_3)

{
  char cVar1;
  int iVar2;
  byte bVar3;
  ushort uVar4;
  uint uVar5;
  uint uVar6;
  bool bVar7;
  uint uVar8;
  
  iVar2 = _DAT_1000c294;
  if (param_3 != 0) {
    if (DAT_1000c114 == 0) {
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
        if (bVar3 != (byte)uVar4) goto LAB_10007bff;
        param_3 = param_3 + -1;
      } while (param_3 != 0);
      param_3 = 0;
      bVar3 = (byte)(uVar4 >> 8);
      bVar7 = bVar3 < (byte)uVar4;
      if (bVar3 != (byte)uVar4) {
LAB_10007bff:
        param_3 = -1;
        if (!bVar7) {
          param_3 = 1;
        }
      }
    }
    else {
      LOCK();
      _DAT_1000c294 = _DAT_1000c294 + 1;
      UNLOCK();
      bVar7 = 0 < _DAT_1000c290;
      if (bVar7) {
        LOCK();
        UNLOCK();
        _DAT_1000c294 = iVar2;
        FUN_10003c3c(0x13);
      }
      uVar8 = (uint)bVar7;
      uVar5 = 0;
      uVar6 = 0;
      do {
        uVar5 = CONCAT31((int3)(uVar5 >> 8),*param_1);
        uVar6 = CONCAT31((int3)(uVar6 >> 8),*param_2);
        if ((uVar5 == 0) || (uVar6 == 0)) break;
        param_1 = param_1 + 1;
        param_2 = param_2 + 1;
        uVar6 = FUN_100058c6(uVar6,uVar5);
        uVar5 = FUN_100058c6();
        bVar7 = uVar5 < uVar6;
        if (uVar5 != uVar6) goto LAB_10007c75;
        param_3 = param_3 + -1;
      } while (param_3 != 0);
      param_3 = 0;
      bVar7 = uVar5 < uVar6;
      if (uVar5 != uVar6) {
LAB_10007c75:
        param_3 = -1;
        if (!bVar7) {
          param_3 = 1;
        }
      }
      if (uVar8 == 0) {
        LOCK();
        _DAT_1000c294 = _DAT_1000c294 + -1;
        UNLOCK();
      }
      else {
        FUN_10003c9d(0x13);
      }
    }
  }
  return param_3;
}



void RtlUnwind(PVOID TargetFrame,PVOID TargetIp,PEXCEPTION_RECORD ExceptionRecord,PVOID ReturnValue)

{
                    // WARNING: Could not recover jumptable at 0x10007d96. Too many branches
                    // WARNING: Treating indirect jump as call
  RtlUnwind(TargetFrame,TargetIp,ExceptionRecord,ReturnValue);
  return;
}


