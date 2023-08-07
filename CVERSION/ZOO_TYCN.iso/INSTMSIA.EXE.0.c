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
typedef unsigned long long    undefined8;
typedef unsigned short    ushort;
typedef unsigned short    wchar16;
typedef unsigned short    word;
typedef struct CLIENT_ID CLIENT_ID, *PCLIENT_ID;

struct CLIENT_ID {
    void * UniqueProcess;
    void * UniqueThread;
};

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

typedef struct DLGTEMPLATE DLGTEMPLATE, *PDLGTEMPLATE;

typedef struct DLGTEMPLATE * LPCDLGTEMPLATEA;

typedef ulong DWORD;

typedef ushort WORD;

struct DLGTEMPLATE {
    DWORD style;
    DWORD dwExtendedStyle;
    WORD cdit;
    short x;
    short y;
    short cx;
    short cy;
};

typedef struct tagMSG tagMSG, *PtagMSG;

typedef struct tagMSG MSG;

typedef struct HWND__ HWND__, *PHWND__;

typedef struct HWND__ * HWND;

typedef uint UINT;

typedef uint UINT_PTR;

typedef UINT_PTR WPARAM;

typedef long LONG_PTR;

typedef LONG_PTR LPARAM;

typedef struct tagPOINT tagPOINT, *PtagPOINT;

typedef struct tagPOINT POINT;

typedef long LONG;

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

struct HWND__ {
    int unused;
};

typedef int INT_PTR;

typedef INT_PTR (* DLGPROC)(HWND, UINT, WPARAM, LPARAM);

typedef LONG_PTR LRESULT;

typedef LRESULT (* WNDPROC)(HWND, UINT, WPARAM, LPARAM);

typedef struct tagMSG * LPMSG;

typedef uchar BYTE;

typedef struct HKEY__ HKEY__, *PHKEY__;

struct HKEY__ {
    int unused;
};

typedef DWORD * LPDWORD;

typedef DWORD * PDWORD;

typedef struct _FILETIME _FILETIME, *P_FILETIME;

typedef struct _FILETIME FILETIME;

struct _FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
};

typedef struct HDC__ HDC__, *PHDC__;

struct HDC__ {
    int unused;
};

typedef uint * PUINT;

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

typedef struct HINSTANCE__ * HINSTANCE;

struct HINSTANCE__ {
    int unused;
};

typedef struct _FILETIME * PFILETIME;

typedef void * LPVOID;

typedef struct HRSRC__ HRSRC__, *PHRSRC__;

struct HRSRC__ {
    int unused;
};

typedef HINSTANCE HMODULE;

typedef void * HANDLE;

typedef HANDLE HLOCAL;

typedef BYTE * LPBYTE;

typedef struct _FILETIME * LPFILETIME;

typedef int (* FARPROC)(void);

typedef struct HDC__ * HDC;

typedef struct tagRECT tagRECT, *PtagRECT;

struct tagRECT {
    LONG left;
    LONG top;
    LONG right;
    LONG bottom;
};

typedef int INT;

typedef struct HKEY__ * HKEY;

typedef HKEY * PHKEY;

typedef int HFILE;

typedef struct tagRECT * LPRECT;

typedef HANDLE HGLOBAL;

typedef void * LPCVOID;

typedef struct HRSRC__ * HRSRC;

typedef int BOOL;

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

typedef struct IMAGE_RESOURCE_DIR_STRING_U_14 IMAGE_RESOURCE_DIR_STRING_U_14, *PIMAGE_RESOURCE_DIR_STRING_U_14;

struct IMAGE_RESOURCE_DIR_STRING_U_14 {
    word Length;
    wchar16 NameString[7];
};

typedef struct IMAGE_RESOURCE_DIR_STRING_U_10 IMAGE_RESOURCE_DIR_STRING_U_10, *PIMAGE_RESOURCE_DIR_STRING_U_10;

struct IMAGE_RESOURCE_DIR_STRING_U_10 {
    word Length;
    wchar16 NameString[5];
};

typedef struct IMAGE_RESOURCE_DIR_STRING_U_12 IMAGE_RESOURCE_DIR_STRING_U_12, *PIMAGE_RESOURCE_DIR_STRING_U_12;

struct IMAGE_RESOURCE_DIR_STRING_U_12 {
    word Length;
    wchar16 NameString[6];
};

typedef struct StringTable StringTable, *PStringTable;

struct StringTable {
    word wLength;
    word wValueLength;
    word wType;
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

typedef struct IMAGE_DATA_DIRECTORY IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

struct IMAGE_DATA_DIRECTORY {
    ImageBaseOffset32 VirtualAddress;
    dword Size;
};

typedef struct IMAGE_RESOURCE_DIR_STRING_U_6 IMAGE_RESOURCE_DIR_STRING_U_6, *PIMAGE_RESOURCE_DIR_STRING_U_6;

struct IMAGE_RESOURCE_DIR_STRING_U_6 {
    word Length;
    wchar16 NameString[3];
};

typedef struct IMAGE_RESOURCE_DATA_ENTRY IMAGE_RESOURCE_DATA_ENTRY, *PIMAGE_RESOURCE_DATA_ENTRY;

struct IMAGE_RESOURCE_DATA_ENTRY {
    dword OffsetToData;
    dword Size;
    dword CodePage;
    dword Reserved;
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

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion;

union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion {
    struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;
    dword Name;
    word Id;
};

typedef struct IMAGE_OPTIONAL_HEADER32 IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

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

union IMAGE_RESOURCE_DIRECTORY_ENTRY {
    union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion NameUnion;
    union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion DirectoryUnion;
};

typedef struct IMAGE_RESOURCE_DIR_STRING_U_18 IMAGE_RESOURCE_DIR_STRING_U_18, *PIMAGE_RESOURCE_DIR_STRING_U_18;

struct IMAGE_RESOURCE_DIR_STRING_U_18 {
    word Length;
    wchar16 NameString[9];
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

typedef struct VarFileInfo VarFileInfo, *PVarFileInfo;

struct VarFileInfo {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct IMAGE_RESOURCE_DIR_STRING_U_20 IMAGE_RESOURCE_DIR_STRING_U_20, *PIMAGE_RESOURCE_DIR_STRING_U_20;

struct IMAGE_RESOURCE_DIR_STRING_U_20 {
    word Length;
    wchar16 NameString[10];
};

typedef struct StringInfo StringInfo, *PStringInfo;

struct StringInfo {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct IMAGE_RESOURCE_DIR_STRING_U_26 IMAGE_RESOURCE_DIR_STRING_U_26, *PIMAGE_RESOURCE_DIR_STRING_U_26;

struct IMAGE_RESOURCE_DIR_STRING_U_26 {
    word Length;
    wchar16 NameString[13];
};

typedef struct IMAGE_RESOURCE_DIR_STRING_U_28 IMAGE_RESOURCE_DIR_STRING_U_28, *PIMAGE_RESOURCE_DIR_STRING_U_28;

struct IMAGE_RESOURCE_DIR_STRING_U_28 {
    word Length;
    wchar16 NameString[14];
};

typedef struct _SYSTEM_INFO _SYSTEM_INFO, *P_SYSTEM_INFO;

typedef struct _SYSTEM_INFO * LPSYSTEM_INFO;

typedef union _union_530 _union_530, *P_union_530;

typedef ulong ULONG_PTR;

typedef ULONG_PTR DWORD_PTR;

typedef struct _struct_531 _struct_531, *P_struct_531;

struct _struct_531 {
    WORD wProcessorArchitecture;
    WORD wReserved;
};

union _union_530 {
    DWORD dwOemId;
    struct _struct_531 s;
};

struct _SYSTEM_INFO {
    union _union_530 u;
    DWORD dwPageSize;
    LPVOID lpMinimumApplicationAddress;
    LPVOID lpMaximumApplicationAddress;
    DWORD_PTR dwActiveProcessorMask;
    DWORD dwNumberOfProcessors;
    DWORD dwProcessorType;
    DWORD dwAllocationGranularity;
    WORD wProcessorLevel;
    WORD wProcessorRevision;
};

typedef struct _OVERLAPPED _OVERLAPPED, *P_OVERLAPPED;

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

struct _OVERLAPPED {
    ULONG_PTR Internal;
    ULONG_PTR InternalHigh;
    union _union_518 u;
    HANDLE hEvent;
};

typedef struct _SECURITY_ATTRIBUTES _SECURITY_ATTRIBUTES, *P_SECURITY_ATTRIBUTES;

struct _SECURITY_ATTRIBUTES {
    DWORD nLength;
    LPVOID lpSecurityDescriptor;
    BOOL bInheritHandle;
};

typedef struct _WIN32_FIND_DATAA _WIN32_FIND_DATAA, *P_WIN32_FIND_DATAA;

typedef char CHAR;

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

typedef DWORD (* PTHREAD_START_ROUTINE)(LPVOID);

typedef PTHREAD_START_ROUTINE LPTHREAD_START_ROUTINE;

typedef struct _OVERLAPPED * LPOVERLAPPED;

typedef struct _SECURITY_ATTRIBUTES * LPSECURITY_ATTRIBUTES;

typedef struct _STARTUPINFOA _STARTUPINFOA, *P_STARTUPINFOA;

typedef CHAR * LPSTR;

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

typedef struct _PROCESS_INFORMATION _PROCESS_INFORMATION, *P_PROCESS_INFORMATION;

struct _PROCESS_INFORMATION {
    HANDLE hProcess;
    HANDLE hThread;
    DWORD dwProcessId;
    DWORD dwThreadId;
};

typedef struct _WIN32_FIND_DATAA * LPWIN32_FIND_DATAA;

typedef struct _STARTUPINFOA * LPSTARTUPINFOA;

typedef struct _PROCESS_INFORMATION * LPPROCESS_INFORMATION;

typedef LONG LSTATUS;

typedef DWORD ACCESS_MASK;

typedef ACCESS_MASK REGSAM;

typedef CHAR * LPCSTR;

typedef struct _LUID _LUID, *P_LUID;

typedef struct _LUID LUID;

struct _LUID {
    DWORD LowPart;
    LONG HighPart;
};

typedef LONG * PLONG;

typedef struct _LUID_AND_ATTRIBUTES _LUID_AND_ATTRIBUTES, *P_LUID_AND_ATTRIBUTES;

struct _LUID_AND_ATTRIBUTES {
    LUID Luid;
    DWORD Attributes;
};

typedef struct _TOKEN_PRIVILEGES _TOKEN_PRIVILEGES, *P_TOKEN_PRIVILEGES;

typedef struct _LUID_AND_ATTRIBUTES LUID_AND_ATTRIBUTES;

struct _TOKEN_PRIVILEGES {
    DWORD PrivilegeCount;
    LUID_AND_ATTRIBUTES Privileges[1];
};

typedef struct _OSVERSIONINFOA _OSVERSIONINFOA, *P_OSVERSIONINFOA;

struct _OSVERSIONINFOA {
    DWORD dwOSVersionInfoSize;
    DWORD dwMajorVersion;
    DWORD dwMinorVersion;
    DWORD dwBuildNumber;
    DWORD dwPlatformId;
    CHAR szCSDVersion[128];
};

typedef enum _TOKEN_INFORMATION_CLASS {
    TokenUser=1,
    TokenGroups=2,
    TokenPrivileges=3,
    TokenOwner=4,
    TokenPrimaryGroup=5,
    TokenDefaultDacl=6,
    TokenSource=7,
    TokenType=8,
    TokenImpersonationLevel=9,
    TokenStatistics=10,
    TokenRestrictedSids=11,
    TokenSessionId=12,
    TokenGroupsAndPrivileges=13,
    TokenSessionReference=14,
    TokenSandBoxInert=15,
    TokenAuditPolicy=16,
    TokenOrigin=17,
    TokenElevationType=18,
    TokenLinkedToken=19,
    TokenElevation=20,
    TokenHasRestrictions=21,
    TokenAccessInformation=22,
    TokenVirtualizationAllowed=23,
    TokenVirtualizationEnabled=24,
    TokenIntegrityLevel=25,
    TokenUIAccess=26,
    TokenMandatoryPolicy=27,
    TokenLogonSid=28,
    MaxTokenInfoClass=29
} _TOKEN_INFORMATION_CLASS;

typedef struct _OSVERSIONINFOA * LPOSVERSIONINFOA;

typedef PVOID PSID;

typedef struct _TOKEN_PRIVILEGES * PTOKEN_PRIVILEGES;

typedef struct _SID_IDENTIFIER_AUTHORITY _SID_IDENTIFIER_AUTHORITY, *P_SID_IDENTIFIER_AUTHORITY;

struct _SID_IDENTIFIER_AUTHORITY {
    BYTE Value[6];
};

typedef struct _SID_IDENTIFIER_AUTHORITY * PSID_IDENTIFIER_AUTHORITY;

typedef struct _LUID * PLUID;

typedef enum _TOKEN_INFORMATION_CLASS TOKEN_INFORMATION_CLASS;

typedef HANDLE * PHANDLE;

typedef char * va_list;

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




int FUN_01001600(void)

{
  HANDLE ProcessHandle;
  int iVar1;
  BOOL BVar2;
  uint *TokenInformation;
  PSID *ppvVar3;
  DWORD DVar4;
  HANDLE *TokenHandle;
  _SID_IDENTIFIER_AUTHORITY local_20;
  int local_18;
  PSID local_14;
  HANDLE local_10;
  uint local_c;
  SIZE_T local_8;
  
  TokenInformation = (uint *)0x0;
  local_20.Value[0] = '\0';
  local_20.Value[1] = '\0';
  local_20.Value[2] = '\0';
  local_20.Value[3] = '\0';
  local_20.Value[4] = '\0';
  local_20.Value[5] = '\x05';
  local_18 = 0;
  iVar1 = DAT_0100a21c;
  if (DAT_0100a21c == 2) {
    TokenHandle = &local_10;
    DVar4 = 8;
    ProcessHandle = GetCurrentProcess();
    iVar1 = OpenProcessToken(ProcessHandle,DVar4,TokenHandle);
    if (iVar1 != 0) {
      BVar2 = GetTokenInformation(local_10,TokenGroups,(LPVOID)0x0,0,&local_8);
      if ((BVar2 == 0) && (DVar4 = GetLastError(), DVar4 == 0x7a)) {
        TokenInformation = (uint *)LocalAlloc(0,local_8);
      }
      if (((TokenInformation != (uint *)0x0) &&
          (BVar2 = GetTokenInformation(local_10,TokenGroups,TokenInformation,local_8,&local_8),
          BVar2 != 0)) &&
         (BVar2 = AllocateAndInitializeSid(&local_20,'\x02',0x20,0x220,0,0,0,0,0,0,&local_14),
         BVar2 != 0)) {
        local_c = 0;
        if (*TokenInformation != 0) {
          ppvVar3 = (PSID *)(TokenInformation + 1);
          do {
            BVar2 = EqualSid(*ppvVar3,local_14);
            if (BVar2 != 0) {
              DAT_0100a21c = 1;
              local_18 = 1;
              break;
            }
            local_c = local_c + 1;
            ppvVar3 = ppvVar3 + 2;
          } while (local_c < *TokenInformation);
        }
        FreeSid(local_14);
      }
      CloseHandle(local_10);
      iVar1 = local_18;
      if (TokenInformation != (uint *)0x0) {
        LocalFree(TokenInformation);
        iVar1 = local_18;
      }
    }
  }
  return iVar1;
}



undefined4 FUN_0100170a(HWND param_1,int param_2,uint param_3,UINT param_4)

{
  HWND pHVar1;
  CHAR local_204 [512];
  
  if (param_2 == 0x110) {
    pHVar1 = GetDesktopWindow();
    FUN_01003bed(param_1,pHVar1);
    local_204[0] = '\0';
    LoadStringA(DAT_0100b6dc,param_4,local_204,0x200);
    SetDlgItemTextA(param_1,0x83f,local_204);
    MessageBeep(0xffffffff);
  }
  else {
    if (((param_2 != 0x111) || (param_3 < 0x83d)) || (0x83e < param_3)) {
      return 0;
    }
    EndDialog(param_1,param_3);
  }
  return 1;
}



char * FUN_01001799(char **param_1,short *param_2)

{
  char cVar1;
  short *psVar2;
  char *pcVar3;
  char *pcVar4;
  int iVar5;
  
  pcVar4 = *param_1;
  iVar5 = 0;
  while( true ) {
    psVar2 = FUN_010059cd(param_2,(short)*pcVar4);
    if (psVar2 == (short *)0x0) {
      *param_1 = pcVar4;
      cVar1 = *pcVar4;
      for (; (psVar2 = FUN_010059cd(param_2,(short)cVar1), psVar2 == (short *)0x0 &&
             (pcVar4[iVar5] != '\0')); iVar5 = iVar5 + 1) {
        cVar1 = pcVar4[iVar5 + 1];
      }
      pcVar3 = pcVar4 + iVar5;
      if (pcVar4[iVar5] != '\0') {
        *pcVar3 = '\0';
        pcVar3 = pcVar3 + 1;
      }
      return pcVar3;
    }
    if (*pcVar4 == '\0') break;
    pcVar4 = pcVar4 + 1;
  }
  return (char *)0x0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_010017f8(LPSTR param_1,BYTE **param_2,undefined4 *param_3)

{
  int iVar1;
  short *psVar2;
  uint uVar3;
  char *pcVar4;
  DWORD DVar5;
  int iVar6;
  UINT UVar7;
  CHAR *pCVar8;
  short *psVar9;
  BYTE local_614 [1024];
  undefined local_214 [260];
  CHAR local_110 [260];
  BYTE *local_c;
  short *local_8;
  
  lstrcpyA(local_214,param_1);
  if (local_214[0] == '\"') {
    local_8 = (short *)(local_214 + 1);
    psVar9 = (short *)&DAT_010012e4;
  }
  else {
    local_8 = (short *)local_214;
    psVar9 = (short *)&DAT_010012e0;
  }
  psVar9 = (short *)FUN_01001799((char **)&local_8,psVar9);
  iVar1 = FUN_010020bc((LPCSTR)local_8);
  if (iVar1 == 0) {
    lstrcpyA(local_110,&DAT_0100ae84);
    FUN_01005a4d(local_110,(LPCSTR)local_8);
  }
  else {
    lstrcpyA(local_110,(LPCSTR)local_8);
  }
  psVar2 = FUN_01005a1b(local_8,0x2e);
  if ((psVar2 == (short *)0x0) || (iVar1 = lstrcmpiA((LPCSTR)psVar2,".INF"), iVar1 != 0)) {
    psVar2 = FUN_01005a1b(local_8,0x2e);
    if ((psVar2 == (short *)0x0) || (iVar1 = lstrcmpiA((LPCSTR)psVar2,".BAT"), iVar1 != 0)) {
      local_c = (BYTE *)LocalAlloc(0x40,0x400);
      if (local_c != (BYTE *)0x0) {
        DVar5 = GetFileAttributesA(local_110);
        if ((DVar5 == 0xffffffff) || ((DVar5 & 0x10) != 0)) {
          lstrcpyA((LPSTR)local_614,param_1);
        }
        else {
          lstrcpyA((LPSTR)local_614,local_110);
          if ((psVar9 != (short *)0x0) && (*(char *)psVar9 != '\0')) {
            lstrcatA((LPSTR)local_614," ");
            lstrcatA((LPSTR)local_614,(LPCSTR)psVar9);
          }
        }
        FUN_0100263b(local_614,local_c);
LAB_01001b15:
        *param_2 = local_c;
        return 1;
      }
      pCVar8 = (LPCSTR)0x0;
      UVar7 = 0x4b5;
      local_c = (BYTE *)0x0;
    }
    else {
      iVar1 = lstrlenA(local_110);
      iVar6 = lstrlenA(s_Command_com__c__s_0100a208);
      local_c = (BYTE *)LocalAlloc(0x40,iVar1 + 8 + iVar6);
      if (local_c != (BYTE *)0x0) {
        wsprintfA((LPSTR)local_c,s_Command_com__c__s_0100a208,local_110);
        goto LAB_01001b15;
      }
      pCVar8 = (LPCSTR)0x0;
      UVar7 = 0x4b5;
      local_c = (BYTE *)0x0;
    }
  }
  else {
    uVar3 = FUN_010059fd(local_110);
    if (uVar3 == 0) {
      pCVar8 = local_110;
      UVar7 = 0x525;
    }
    else {
      local_8 = psVar9;
      psVar9 = (short *)FUN_01001799((char **)&local_8,(short *)&DAT_010012d4);
      lstrlenA(s_DefaultInstall_0100a0b8);
      if (psVar9 != (short *)0x0) {
        if (*(char *)psVar9 != '\0') {
          local_8 = psVar9;
        }
        FUN_01001799((char **)&local_8,(short *)&DAT_010012d0);
        if (*(char *)local_8 != '\0') {
          lstrlenA((LPCSTR)local_8);
        }
      }
      local_c = (BYTE *)LocalAlloc(0x40,0x200);
      if (local_c != (BYTE *)0x0) {
        pcVar4 = (char *)local_8;
        if (*(char *)local_8 == '\0') {
          pcVar4 = s_DefaultInstall_0100a0b8;
        }
        _DAT_0100b824 = GetPrivateProfileIntA(pcVar4,"Reboot",0,local_110);
        *param_3 = 1;
        DVar5 = GetPrivateProfileStringA("Version","AdvancedINF","",(LPSTR)local_c,8,local_110);
        if (DVar5 == 0) {
          _DAT_0100b6d4 = _DAT_0100b6d4 & 0xfffffffb;
          if (DAT_0100bc04 == 0) {
            pcVar4 = "setupx.dll";
            GetShortPathNameA(local_110,local_110,0x104);
          }
          else {
            pcVar4 = "setupapi.dll";
          }
          psVar9 = (short *)s_DefaultInstall_0100a0b8;
          if (*(char *)local_8 != '\0') {
            psVar9 = local_8;
          }
          wsprintfA((LPSTR)local_c,s_rundll32_exe__s_InstallHinfSecti_0100a018,pcVar4,psVar9,
                    local_110);
        }
        else {
          _DAT_0100b6d4 = _DAT_0100b6d4 | 4;
          psVar9 = (short *)s_DefaultInstall_0100a0b8;
          if (*(char *)local_8 != '\0') {
            psVar9 = local_8;
          }
          lstrcpyA(param_1,(LPCSTR)psVar9);
          lstrcpyA((LPSTR)local_c,local_110);
        }
        goto LAB_01001b15;
      }
      pCVar8 = (LPCSTR)0x0;
      UVar7 = 0x4b5;
      local_c = (BYTE *)0x0;
    }
  }
  FUN_01003cb8((HWND)0x0,UVar7,pCVar8,(LPCSTR)0x0,0x10,0);
  return 0;
}



void FUN_01001b27(void)

{
  FUN_01003cb8((HWND)0x0,0x521,"",(LPCSTR)0x0,0x40,0);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_01001b3e(void)

{
  bool bVar1;
  undefined3 extraout_var;
  
  if ((_DAT_0100b824 == 0) &&
     (bVar1 = FUN_01002231(DAT_0100bc08,DAT_0100bc04), CONCAT31(extraout_var,bVar1) == 0)) {
    return 0xffffffff;
  }
  return 2;
}



undefined4 FUN_01001b68(void)

{
  HANDLE ProcessHandle;
  BOOL BVar1;
  UINT UVar2;
  DWORD DesiredAccess;
  HANDLE *TokenHandle;
  _TOKEN_PRIVILEGES local_18;
  HANDLE local_8;
  
  TokenHandle = &local_8;
  DesiredAccess = 0x28;
  ProcessHandle = GetCurrentProcess();
  BVar1 = OpenProcessToken(ProcessHandle,DesiredAccess,TokenHandle);
  if (BVar1 == 0) {
    UVar2 = 0x4f5;
  }
  else {
    LookupPrivilegeValueA((LPCSTR)0x0,"SeShutdownPrivilege",&local_18.Privileges[0].Luid);
    local_18.PrivilegeCount = 1;
    local_18.Privileges[0].Attributes = 2;
    BVar1 = AdjustTokenPrivileges(local_8,0,&local_18,0,(PTOKEN_PRIVILEGES)0x0,(PDWORD)0x0);
    if (BVar1 == 0) {
      UVar2 = 0x4f6;
    }
    else {
      BVar1 = ExitWindowsEx(2,0);
      if (BVar1 != 0) {
        return 1;
      }
      UVar2 = 0x4f7;
    }
  }
  FUN_01003cb8((HWND)0x0,UVar2,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
  return 0;
}



void FUN_01001bfb(byte param_1)

{
  int iVar1;
  
  if ((param_1 & 2) == 0) {
    iVar1 = FUN_01001b3e();
  }
  else {
    iVar1 = 2;
  }
  if (iVar1 == 2) {
    if ((param_1 & 4) == 0) {
      iVar1 = FUN_01003cb8((HWND)0x0,0x522,"",(LPCSTR)0x0,0x40,4);
    }
    else {
      iVar1 = 6;
    }
    if (iVar1 == 6) {
      if (DAT_0100bc04 == 0) {
        ExitWindowsEx(2,0);
      }
      else {
        FUN_01001b68();
      }
    }
  }
  return;
}



void FUN_01001c57(void)

{
  LSTATUS LVar1;
  HKEY local_8;
  
  if (DAT_0100a300 != '\0') {
    LVar1 = RegOpenKeyExA((HKEY)0x80000002,s_Software_Microsoft_Windows_Curre_0100a0d8,0,0x20006,
                          &local_8);
    if (LVar1 == 0) {
      RegDeleteValueA(local_8,&DAT_0100a300);
      RegCloseKey(local_8);
    }
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_01001c9c(void)

{
  LSTATUS LVar1;
  FARPROC pFVar2;
  UINT UVar3;
  DWORD DVar4;
  int iVar5;
  BYTE *lpData;
  char *pcVar6;
  int iVar7;
  undefined4 *puVar8;
  CHAR local_220;
  undefined4 local_21f;
  CHAR local_11c;
  undefined4 local_11b;
  DWORD local_18;
  DWORD local_14;
  uint local_10;
  HKEY local_c;
  HMODULE local_8;
  
  local_11c = '\0';
  puVar8 = &local_11b;
  for (iVar7 = 0x40; iVar7 != 0; iVar7 = iVar7 + -1) {
    *puVar8 = 0;
    puVar8 = puVar8 + 1;
  }
  *(undefined2 *)puVar8 = 0;
  *(undefined *)((int)puVar8 + 2) = 0;
  local_220 = '\0';
  puVar8 = &local_21f;
  for (iVar7 = 0x40; iVar7 != 0; iVar7 = iVar7 + -1) {
    *puVar8 = 0;
    puVar8 = puVar8 + 1;
  }
  *(undefined2 *)puVar8 = 0;
  *(undefined *)((int)puVar8 + 2) = 0;
  local_10 = 0;
  LVar1 = RegCreateKeyExA((HKEY)0x80000002,s_Software_Microsoft_Windows_Curre_0100a0d8,0,(LPSTR)0x0,
                          0,0x2001f,(LPSECURITY_ATTRIBUTES)0x0,&local_c,&local_14);
  if (LVar1 != 0) {
    return;
  }
  local_8 = (HMODULE)0x0;
  do {
    wsprintfA(&DAT_0100a300,s_wextract_cleanup_d_0100a1b0,local_8);
    LVar1 = RegQueryValueExA(local_c,&DAT_0100a300,(LPDWORD)0x0,(LPDWORD)0x0,(LPBYTE)0x0,&local_18);
    if (LVar1 != 0) break;
    local_8 = (HMODULE)((int)local_8 + 1);
  } while ((int)local_8 < 200);
  if (local_8 == (HMODULE)0xc8) {
    RegCloseKey(local_c);
    DAT_0100a300 = 0;
    return;
  }
  GetSystemDirectoryA(&local_220,0x104);
  FUN_01005a4d(&local_220,"advpack.dll");
  local_8 = LoadLibraryA(&local_220);
  if (local_8 != (HMODULE)0x0) {
    pFVar2 = GetProcAddress(local_8,"DelNodeRunDLL32");
    local_10 = (uint)(pFVar2 != (FARPROC)0x0);
    FreeLibrary(local_8);
  }
  if (local_10 == 0) {
    DVar4 = GetModuleFileNameA(DAT_0100b6dc,&local_11c,0x104);
    if (DVar4 == 0) goto LAB_01001e29;
  }
  else {
    UVar3 = GetSystemDirectoryA(&local_11c,0x104);
    if (UVar3 != 0) {
      FUN_01005a4d(&local_11c,"");
    }
  }
  iVar7 = lstrlenA(&local_11c);
  iVar5 = lstrlenA(&DAT_0100ae84);
  lpData = (BYTE *)LocalAlloc(0x40,iVar7 + 0x50 + iVar5);
  if (lpData != (BYTE *)0x0) {
    _DAT_0100a350 = (uint)(local_10 == 0);
    pcVar6 = s_rundll32_exe__sadvpack_dll_DelNo_0100a1d8;
    if (local_10 == 0) {
      pcVar6 = s__s__D__s_0100a1c8;
    }
    wsprintfA((LPSTR)lpData,pcVar6,&local_11c,&DAT_0100ae84);
    iVar7 = lstrlenA((LPCSTR)lpData);
    RegSetValueExA(local_c,&DAT_0100a300,0,1,lpData,iVar7 + 1);
    RegCloseKey(local_c);
    LocalFree(lpData);
    return;
  }
  FUN_01003cb8((HWND)0x0,0x4b5,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
LAB_01001e29:
  RegCloseKey(local_c);
  return;
}



void FUN_01001e91(void)

{
  LSTATUS LVar1;
  UINT UVar2;
  int iVar3;
  undefined4 *puVar4;
  BYTE local_348 [568];
  CHAR local_110;
  undefined4 local_10f;
  DWORD local_c;
  HKEY local_8;
  
  if (DAT_0100a300 != '\0') {
    LVar1 = RegOpenKeyExA((HKEY)0x80000002,s_Software_Microsoft_Windows_Curre_0100a0d8,0,0x2001f,
                          &local_8);
    if (LVar1 == 0) {
      local_c = 0x238;
      LVar1 = RegQueryValueExA(local_8,&DAT_0100a300,(LPDWORD)0x0,(LPDWORD)0x0,local_348,&local_c);
      if (LVar1 == 0) {
        local_110 = '\0';
        puVar4 = &local_10f;
        for (iVar3 = 0x40; iVar3 != 0; iVar3 = iVar3 + -1) {
          *puVar4 = 0;
          puVar4 = puVar4 + 1;
        }
        *(undefined2 *)puVar4 = 0;
        *(undefined *)((int)puVar4 + 2) = 0;
        UVar2 = GetSystemDirectoryA(&local_110,0x104);
        if (UVar2 != 0) {
          FUN_01005a4d(&local_110,"");
        }
        wsprintfA((LPSTR)local_348,s_rundll32_exe__sadvpack_dll_DelNo_0100a1d8,&local_110,
                  &DAT_0100ae84);
        iVar3 = lstrlenA((LPCSTR)local_348);
        RegSetValueExA(local_8,&DAT_0100a300,0,1,local_348,iVar3 + 1);
      }
      RegCloseKey(local_8);
    }
  }
  return;
}



void FUN_01001f8c(LPCSTR param_1)

{
  HANDLE hFindFile;
  int iVar1;
  BOOL BVar2;
  byte local_248;
  CHAR local_21c [276];
  CHAR local_108 [260];
  
  if ((param_1 != (LPCSTR)0x0) && (*param_1 != '\0')) {
    lstrcpyA(local_108,param_1);
    lstrcatA(local_108,"*");
    hFindFile = FindFirstFileA(local_108,(LPWIN32_FIND_DATAA)&local_248);
    if (hFindFile != (HANDLE)0xffffffff) {
      do {
        lstrcpyA(local_108,param_1);
        if ((local_248 & 0x10) == 0) {
          lstrcatA(local_108,local_21c);
          SetFileAttributesA(local_108,0x80);
          DeleteFileA(local_108);
        }
        else {
          iVar1 = lstrcmpA(local_21c,".");
          if (iVar1 != 0) {
            iVar1 = lstrcmpA(local_21c,"..");
            if (iVar1 != 0) {
              lstrcatA(local_108,local_21c);
              FUN_01005a4d(local_108,"");
              FUN_01001f8c(local_108);
            }
          }
        }
        BVar2 = FindNextFileA(hFindFile,(LPWIN32_FIND_DATAA)&local_248);
      } while (BVar2 != 0);
      FindClose(hFindFile);
      RemoveDirectoryA(param_1);
    }
  }
  return;
}



undefined4 FUN_010020bc(LPCSTR param_1)

{
  int iVar1;
  
  if (((param_1 != (LPCSTR)0x0) && (iVar1 = lstrlenA(param_1), 2 < iVar1)) &&
     (((param_1[1] == ':' && (param_1[2] == '\\')) || ((*param_1 == '\\' && (param_1[1] == '\\')))))
     ) {
    return 1;
  }
  return 0;
}



LONG FUN_010020f2(void)

{
  UINT UVar1;
  HFILE hFile;
  LONG LVar2;
  CHAR local_108 [260];
  
  LVar2 = 0;
  UVar1 = GetWindowsDirectoryA(local_108,0x104);
  if (UVar1 != 0) {
    FUN_01005a4d(local_108,"wininit.ini");
    hFile = _lopen(local_108,0x40);
    if (hFile != -1) {
      LVar2 = _llseek(hFile,0,2);
      _lclose(hFile);
    }
  }
  return LVar2;
}



DWORD FUN_01002155(HKEY param_1,LPCSTR param_2)

{
  LSTATUS LVar1;
  DWORD local_8;
  
  local_8 = 0;
  LVar1 = RegOpenKeyExA((HKEY)0x80000002,(LPCSTR)param_1,0,0x20019,&param_1);
  if (LVar1 == 0) {
    LVar1 = RegQueryValueExA(param_1,param_2,(LPDWORD)0x0,(LPDWORD)0x0,(LPBYTE)0x0,&local_8);
    if (LVar1 != 0) {
      local_8 = 0;
    }
    RegCloseKey(param_1);
  }
  return local_8;
}



DWORD FUN_010021a6(HKEY param_1)

{
  LSTATUS LVar1;
  DWORD local_8;
  
  local_8 = 0;
  LVar1 = RegOpenKeyExA((HKEY)0x80000002,(LPCSTR)param_1,0,0x20019,&param_1);
  if (LVar1 == 0) {
    LVar1 = RegQueryInfoKeyA(param_1,(LPSTR)0x0,(LPDWORD)0x0,(LPDWORD)0x0,(LPDWORD)0x0,(LPDWORD)0x0,
                             (LPDWORD)0x0,&local_8,(LPDWORD)0x0,(LPDWORD)0x0,(LPDWORD)0x0,
                             (PFILETIME)0x0);
    if (LVar1 != 0) {
      local_8 = 0;
    }
    RegCloseKey(param_1);
  }
  return local_8;
}



void FUN_010021fb(short param_1)

{
  if (param_1 == 0) {
    FUN_010020f2();
  }
  else if (param_1 == 1) {
    FUN_010021a6((HKEY)s_System_CurrentControlSet_Control_0100a168);
  }
  else if (param_1 == 2) {
    FUN_01002155((HKEY)s_System_CurrentControlSet_Control_0100a110,
                 s_PendingFileRenameOperations_0100a148);
  }
  return;
}



bool FUN_01002231(int param_1,short param_2)

{
  int iVar1;
  
  iVar1 = FUN_010021fb(param_2);
  return param_1 != iVar1;
}



uint FUN_01002248(LPCSTR param_1)

{
  DWORD DVar1;
  uint uVar2;
  
  DVar1 = GetFileAttributesA(param_1);
  if (DVar1 == 0xffffffff) {
    uVar2 = CreateDirectoryA(param_1,(LPSECURITY_ATTRIBUTES)0x0);
  }
  else {
    uVar2 = DVar1 & 0x10;
  }
  return uVar2;
}



bool FUN_0100226b(char *param_1)

{
  UINT UVar1;
  char local_108 [260];
  
  UVar1 = GetWindowsDirectoryA(local_108,0x104);
  if (UVar1 == 0) {
    FUN_01003cb8((HWND)0x0,0x4f0,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
  }
  return *param_1 == local_108[0];
}



LPSTR FUN_010022ae(undefined4 param_1,LPSTR param_2)

{
  wsprintfA(param_2,"%lu",param_1);
  return param_2;
}



bool FUN_010022cb(int param_1,int param_2,int param_3,LPCSTR param_4)

{
  LPSTR pCVar1;
  int iVar2;
  char cVar3;
  LPCSTR pCVar4;
  UINT UVar5;
  uint uVar6;
  CHAR local_10 [12];
  
  cVar3 = '\0';
  DAT_0100b704 = 0x70;
  if (param_1 == 1) {
    uVar6 = 0;
    UVar5 = 0x10;
    pCVar4 = (LPCSTR)0x0;
    pCVar1 = FUN_010022ae(param_3 + param_2,local_10);
    FUN_01003cb8((HWND)0x0,0x4fa,pCVar1,pCVar4,UVar5,uVar6);
  }
  else if (param_1 == 4) {
    uVar6 = 5;
    UVar5 = 0x20;
    pCVar4 = (LPCSTR)0x0;
    pCVar1 = FUN_010022ae(param_3 + param_2,local_10);
    iVar2 = FUN_01003cb8((HWND)0x0,0x4bd,pCVar1,pCVar4,UVar5,uVar6);
    cVar3 = '\x01' - (iVar2 != 4);
  }
  else if (param_1 == 2) {
    uVar6 = 0x104;
    UVar5 = 0x40;
    pCVar1 = FUN_010022ae(param_3,local_10);
    iVar2 = FUN_01003cb8((HWND)0x0,0x4cc,pCVar1,param_4,UVar5,uVar6);
    if (iVar2 == 6) {
      DAT_0100b704 = 0;
      cVar3 = '\x01';
    }
  }
  return (bool)cVar3;
}



undefined4 FUN_0100237e(LPBYTE param_1,HKEY param_2,char *param_3)

{
  LPBYTE lpData;
  LPSTR pCVar1;
  LPSTR lpsz;
  char *pcVar2;
  LSTATUS LVar3;
  LPCSTR lpsz_00;
  CHAR local_10c [260];
  int local_8;
  
  lpData = param_1;
  local_8 = 0;
  *param_1 = '\0';
  pcVar2 = param_3;
  if (*param_3 == '#') {
    lpsz_00 = param_3 + 1;
    pCVar1 = CharUpperA((LPSTR)(int)param_3[1]);
    lpsz = CharNextA(lpsz_00);
    pcVar2 = CharNextA(lpsz);
    if ((char)pCVar1 != 'S') {
      if ((char)pCVar1 == 'W') {
        GetWindowsDirectoryA((LPSTR)lpData,(UINT)param_2);
      }
      else {
        param_1 = (LPBYTE)0x104;
        lstrcpyA(local_10c,"Software\\Microsoft\\Windows\\CurrentVersion\\App Paths");
        FUN_01005a4d(local_10c,pcVar2);
        LVar3 = RegOpenKeyExA((HKEY)0x80000002,local_10c,0,0x20019,&param_2);
        if (LVar3 == 0) {
          LVar3 = RegQueryValueExA(param_2,"",(LPDWORD)0x0,(LPDWORD)0x0,lpData,(LPDWORD)&param_1);
          if (LVar3 == 0) {
            local_8 = 1;
          }
          RegCloseKey(param_2);
        }
      }
      goto LAB_01002454;
    }
  }
  GetSystemDirectoryA((LPSTR)lpData,(UINT)param_2);
LAB_01002454:
  if (local_8 == 0) {
    FUN_01005a4d((LPCSTR)lpData,pcVar2);
  }
  return 1;
}



undefined4 FUN_0100246b(int param_1,LPBYTE param_2,HKEY param_3,int *param_4)

{
  int iVar1;
  int iVar2;
  int iVar3;
  LPVOID lpData;
  BOOL BVar4;
  uint uVar5;
  uint uVar6;
  int *piVar7;
  uint *puVar8;
  uint local_34 [5];
  DWORD local_20;
  DWORD local_1c;
  undefined4 local_18;
  LPVOID local_14;
  int local_10;
  int local_c;
  HGLOBAL local_8;
  
  iVar2 = param_1;
  local_8 = (HGLOBAL)0x0;
  local_18 = 0;
  local_c = 0;
  if (0 < *(int *)(param_1 + 0x7c)) {
    local_10 = 0;
    param_1 = 0;
    do {
      iVar1 = param_1 + iVar2 + 0x84 + *(int *)(iVar2 + 0x80);
      iVar3 = FUN_0100237e(param_2,param_3,
                           (char *)(*(int *)(param_1 + iVar2 + 0xbc + *(int *)(iVar2 + 0x80)) + 0x84
                                   + iVar2));
      if (iVar3 == 0) goto LAB_010025d7;
      local_1c = GetFileVersionInfoSizeA((LPCSTR)param_2,&local_20);
      if (local_1c == 0) {
        piVar7 = (int *)(local_10 + iVar1);
        if ((((*piVar7 != 0) || (piVar7[1] != 0)) || (piVar7[3] != 0)) || (piVar7[4] != 0))
        goto LAB_010025d7;
      }
      else {
        local_8 = GlobalAlloc(0x42,local_1c);
        if ((local_8 == (HGLOBAL)0x0) || (lpData = GlobalLock(local_8), lpData == (LPVOID)0x0))
        goto LAB_010025d7;
        BVar4 = GetFileVersionInfoA((LPCSTR)param_2,local_20,local_1c,lpData);
        if ((BVar4 != 0) &&
           ((BVar4 = VerQueryValueA(lpData,"\\",&local_14,local_34 + 4), BVar4 != 0 &&
            (iVar3 = 0, local_34[4] != 0)))) {
          puVar8 = (uint *)(iVar1 + 0x10);
          do {
            uVar5 = FUN_01002614(*(uint *)((int)local_14 + 8),*(uint *)((int)local_14 + 0xc),
                                 puVar8[-4],puVar8[-3]);
            uVar6 = *puVar8;
            *(uint *)((int)local_34 + iVar3 + 8) = uVar5;
            uVar6 = FUN_01002614(*(uint *)((int)local_14 + 8),*(uint *)((int)local_14 + 0xc),
                                 puVar8[-1],uVar6);
            *(uint *)((int)local_34 + iVar3) = uVar6;
            iVar3 = iVar3 + 4;
            puVar8 = puVar8 + 6;
          } while (iVar3 < 8);
          if ((((int)local_34[2] < 0) || (0 < (int)local_34[0])) &&
             (((int)local_34[3] < 0 || (0 < (int)local_34[1])))) {
            GlobalUnlock(local_8);
            goto LAB_010025d7;
          }
        }
        GlobalUnlock(local_8);
      }
      local_c = local_c + 1;
      param_1 = param_1 + 0x3c;
      local_10 = local_10 + 0x18;
    } while (local_c < *(int *)(iVar2 + 0x7c));
  }
  local_18 = 1;
LAB_010025d7:
  *param_4 = local_c;
  if (local_8 != (HGLOBAL)0x0) {
    GlobalFree(local_8);
  }
  return local_18;
}



uint FUN_010025f7(uint param_1)

{
  uint uVar1;
  
  if ((param_1 & 1) == 0) {
    uVar1 = -(uint)((param_1 & 2) != 0) & 0x101;
  }
  else {
    uVar1 = 0x104;
  }
  return uVar1;
}



uint FUN_01002614(uint param_1,uint param_2,uint param_3,uint param_4)

{
  if (param_3 <= param_1) {
    if (param_3 < param_1) {
      return 1;
    }
    if (param_4 <= param_2) {
      return (uint)(param_4 < param_2);
    }
  }
  return 0xffffffff;
}



void FUN_0100263b(BYTE *param_1,BYTE *param_2)

{
  BYTE TestChar;
  BOOL BVar1;
  LPSTR pCVar2;
  int iVar3;
  CHAR local_104 [260];
  
  *param_2 = '\0';
  if ((param_1 != (BYTE *)0x0) && (*param_1 != '\0')) {
    GetModuleFileNameA(DAT_0100b6dc,local_104,0x104);
    TestChar = *param_1;
    while (TestChar != '\0') {
      BVar1 = IsDBCSLeadByte(TestChar);
      *param_2 = *param_1;
      if (BVar1 != 0) {
        param_2[1] = param_1[1];
      }
      if (*param_1 == '#') {
        param_1 = (BYTE *)CharNextA((LPCSTR)param_1);
        pCVar2 = CharUpperA((LPSTR)(int)(char)*param_1);
        if ((char)pCVar2 == 'D') {
          FUN_01005a8c(local_104);
          iVar3 = lstrlenA(local_104);
          pCVar2 = CharPrevA(local_104,local_104 + iVar3);
          if ((pCVar2 != (LPSTR)0x0) && (*pCVar2 == '\\')) {
            *pCVar2 = '\0';
          }
        }
        else {
          pCVar2 = CharUpperA((LPSTR)(int)(char)*param_1);
          if ((char)pCVar2 != 'E') {
            if (*param_1 == '#') goto LAB_01002719;
            goto LAB_0100271e;
          }
        }
        lstrcpyA((LPSTR)param_2,local_104);
        iVar3 = lstrlenA(local_104);
        param_2 = param_2 + iVar3;
      }
      else {
LAB_01002719:
        param_2 = (BYTE *)CharNextA((LPCSTR)param_2);
      }
LAB_0100271e:
      param_1 = (BYTE *)CharNextA((LPCSTR)param_1);
      TestChar = *param_1;
    }
    *param_2 = '\0';
  }
  return;
}



void entry(void)

{
  char cVar1;
  char *pcVar2;
  HMODULE pHVar3;
  UINT uExitCode;
  char *pcVar4;
  undefined4 uVar5;
  _STARTUPINFOA local_48;
  
  pcVar2 = GetCommandLineA();
  cVar1 = *pcVar2;
  if (cVar1 == '\"') {
    do {
      pcVar4 = pcVar2;
      pcVar2 = pcVar4 + 1;
      if (pcVar4[1] == '\0') break;
    } while (pcVar4[1] != '\"');
    if (*pcVar2 == '\"') {
      pcVar2 = pcVar4 + 2;
    }
  }
  else {
    while (' ' < cVar1) {
      pcVar2 = pcVar2 + 1;
      cVar1 = *pcVar2;
    }
  }
  for (; (*pcVar2 != '\0' && (*pcVar2 < '!')); pcVar2 = pcVar2 + 1) {
  }
  local_48.dwFlags = 0;
  GetStartupInfoA(&local_48);
  uVar5 = 0;
  pHVar3 = GetModuleHandleA((LPCSTR)0x0);
  uExitCode = FUN_010027ba(pHVar3,uVar5,pcVar2);
                    // WARNING: Subroutine does not return
  ExitProcess(uExitCode);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_010027ba(HMODULE param_1,undefined4 param_2,char *param_3)

{
  int iVar1;
  int iVar2;
  
  iVar2 = 0;
  DAT_0100b704 = 0;
  iVar1 = FUN_01002819(param_1,param_3);
  if (iVar1 != 0) {
    iVar2 = FUN_01002a51();
    thunk_FUN_0100499a();
  }
  if (((iVar2 != 0) && (DAT_0100aaba == '\0')) && ((_DAT_0100b6cc & 1) != 0)) {
    FUN_01001bfb((byte)_DAT_0100b6cc);
  }
  if (DAT_0100aa80 != (HANDLE)0x0) {
    CloseHandle(DAT_0100aa80);
  }
  return DAT_0100b704;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_01002819(HMODULE param_1,char *param_2)

{
  bool bVar1;
  DWORD DVar2;
  HRSRC hResInfo;
  undefined3 extraout_var;
  int iVar3;
  undefined4 *puVar4;
  UINT UVar5;
  undefined4 local_10c [65];
  HGLOBAL local_8;
  
  DAT_0100b6dc = param_1;
  puVar4 = &DAT_0100ade0;
  for (iVar3 = 0x23f; iVar3 != 0; iVar3 = iVar3 + -1) {
    *puVar4 = 0;
    puVar4 = puVar4 + 1;
  }
  puVar4 = &DAT_0100aaa0;
  for (iVar3 = 0xcb; iVar3 != 0; iVar3 = iVar3 + -1) {
    *puVar4 = 0;
    puVar4 = puVar4 + 1;
  }
  puVar4 = &DAT_0100b720;
  for (iVar3 = 0x41; iVar3 != 0; iVar3 = iVar3 + -1) {
    *puVar4 = 0;
    puVar4 = puVar4 + 1;
  }
  local_8 = (HGLOBAL)0x0;
  _DAT_0100b08c = 1;
  DVar2 = FUN_01003e0b("TITLE",(undefined4 *)&DAT_0100adf4,0x7f);
  if ((DVar2 == 0) || (0x80 < DVar2)) {
    UVar5 = 0x4b1;
  }
  else {
    DAT_0100aa7c = CreateEventA((LPSECURITY_ATTRIBUTES)0x0,1,1,(LPCSTR)0x0);
    SetEvent(DAT_0100aa7c);
    DVar2 = FUN_01003e0b("EXTRACTOPT",(undefined4 *)&DAT_0100b6d4,4);
    if (DVar2 == 0) {
LAB_010028d6:
      FUN_01003cb8((HWND)0x0,0x4b1,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
      DAT_0100b704 = 0x80070714;
      return 0;
    }
    if ((DAT_0100b6d4 & 0xc0) != 0) {
      DVar2 = FUN_01003e0b("INSTANCECHECK",local_10c,0x104);
      if (DVar2 == 0) goto LAB_010028d6;
      DAT_0100aa80 = CreateMutexA((LPSECURITY_ATTRIBUTES)0x0,1,(LPCSTR)local_10c);
      if ((DAT_0100aa80 != (HANDLE)0x0) && (DVar2 = GetLastError(), DVar2 == 0xb7)) {
        if ((DAT_0100b6d4 & 0x80) != 0) {
          FUN_01003cb8((HWND)0x0,0x54b,&DAT_0100adf4,(LPCSTR)0x0,0x10,0);
LAB_0100294b:
          CloseHandle(DAT_0100aa80);
          DAT_0100b704 = 0x800700b7;
          return 0;
        }
        iVar3 = FUN_01003cb8((HWND)0x0,0x524,&DAT_0100adf4,(LPCSTR)0x0,0x20,4);
        if (iVar3 != 6) goto LAB_0100294b;
      }
    }
    _DAT_0100b824 = 0;
    iVar3 = FUN_010051f9(param_2);
    if (iVar3 != 0) {
      if (DAT_0100aaba != '\0') {
        FUN_01001f8c(&DAT_0100aaba);
        return 0;
      }
      hResInfo = FindResourceA(param_1,"VERCHECK",(LPCSTR)0xa);
      if (hResInfo != (HRSRC)0x0) {
        local_8 = LoadResource(param_1,hResInfo);
      }
      if (DAT_0100a2f8 != 0) {
        InitCommonControls();
      }
      if (_DAT_0100aaa4 != 0) {
        return 1;
      }
      bVar1 = FUN_0100313c((int)local_8);
      if (CONCAT31(extraout_var,bVar1) == 0) {
        return 0;
      }
      if ((DAT_0100bc04 != 1) && (DAT_0100bc04 != 2)) {
        return 1;
      }
      if ((DAT_0100b6d5 & 1) == 0) {
        return 1;
      }
      if (((byte)DAT_0100aab8 & 1) != 0) {
        return 1;
      }
      iVar3 = FUN_01001600();
      if (iVar3 != 0) {
        return 1;
      }
      iVar3 = FUN_0100592b(DAT_0100b6dc,(LPCSTR)0x7d6,(HWND)0x0,FUN_0100170a,0x547,0x83e);
      if (iVar3 != 0x83d) {
        return 0;
      }
      return 1;
    }
    UVar5 = 0x520;
  }
  FUN_01003cb8((HWND)0x0,UVar5,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_01002a51(void)

{
  bool bVar1;
  int iVar2;
  undefined3 extraout_var;
  BOOL BVar3;
  
  if (DAT_0100aab8 == 0) {
    if ((_DAT_0100aaa4 == 0) && (iVar2 = FUN_010048d4(), iVar2 == 0)) {
      return 0;
    }
    if ((DAT_0100aab8 == 0) && (iVar2 = FUN_010033e8(), iVar2 == 0)) {
      return 0;
    }
  }
  iVar2 = FUN_0100484b();
  if ((iVar2 != 0) && (iVar2 = FUN_01004c18(), iVar2 != 0)) {
    if ((_DAT_0100aaa4 == 0) &&
       ((_DAT_0100b6d0 == 0 && (bVar1 = FUN_010056af(), CONCAT31(extraout_var,bVar1) == 0)))) {
      return 0;
    }
    BVar3 = SetCurrentDirectoryA(&DAT_0100ae84);
    if (BVar3 != 0) {
      if ((_DAT_0100aaac == 0) && (iVar2 = FUN_010034c7(), iVar2 == 0)) {
        return 0;
      }
      if ((DAT_0100adc8 & 0xc0) == 0) {
        DAT_0100bc08 = FUN_010021fb(DAT_0100bc04);
      }
      else {
        DAT_0100bc08 = 0;
      }
      if (((_DAT_0100aaa4 == 0) && (_DAT_0100b6d0 == 0)) && (iVar2 = FUN_01003545(), iVar2 == 0)) {
        return 0;
      }
      if ((DAT_0100aab8 == 0) && (_DAT_0100aaa4 == 0)) {
        FUN_01003a1a();
      }
      return 1;
    }
    FUN_01003cb8((HWND)0x0,0x4bc,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
    DAT_0100b704 = FUN_010056fe();
  }
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void thunk_FUN_0100499a(void)

{
  LPCSTR *ppCVar1;
  LPCSTR *hMem;
  CHAR aCStack_104 [260];
  
  hMem = DAT_0100ae80;
  if (DAT_0100ae80 != (LPCSTR *)0x0) {
    do {
      if ((_DAT_0100aaa4 == 0) && (_DAT_0100b6d0 == 0)) {
        SetFileAttributesA(*hMem,0x80);
        DeleteFileA(*hMem);
      }
      ppCVar1 = (LPCSTR *)hMem[1];
      LocalFree(*hMem);
      LocalFree(hMem);
      hMem = ppCVar1;
    } while (ppCVar1 != (LPCSTR *)0x0);
  }
  if (((DAT_0100aaa0 != 0) && (_DAT_0100aaa4 == 0)) && (_DAT_0100b6d0 == 0)) {
    lstrcpyA(aCStack_104,&DAT_0100ae84);
    if ((DAT_0100b6d4 & 0x20) != 0) {
      FUN_01005a8c(aCStack_104);
    }
    SetCurrentDirectoryA("..");
    FUN_01001f8c(aCStack_104);
  }
  if ((DAT_0100bc04 != 1) && (DAT_0100aaa0 != 0)) {
    FUN_01001c57();
  }
  DAT_0100aaa0 = 0;
  return;
}



void FUN_01002b56(HWND param_1,LONG param_2)

{
  DAT_0100b708 = GetWindowLongA(param_1,-4);
  SetWindowLongA(param_1,-4,param_2);
  return;
}



LRESULT FUN_01002b7a(HWND param_1,UINT param_2,WPARAM param_3,int param_4)

{
  LRESULT LVar1;
  
  if (((param_2 == 0xb1) && (param_3 == 0)) && (param_4 == -2)) {
    LVar1 = 0;
  }
  else {
    LVar1 = CallWindowProcA(DAT_0100b708,param_1,param_2,param_3,param_4);
  }
  return LVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_01002bb2(HWND param_1,int param_2,int param_3)

{
  undefined4 uVar1;
  HWND pHVar2;
  INT_PTR nResult;
  code *pcVar3;
  
  if (param_2 == 0xf) {
    if (_DAT_0100aa84 == 0) {
      _DAT_0100a870 = SendDlgItemMessageA(param_1,0x834,0xb1,0xffffffff,0);
      _DAT_0100aa84 = 1;
    }
LAB_01002c1b:
    uVar1 = 0;
  }
  else {
    if (param_2 == 0x10) {
LAB_01002bdc:
      nResult = 0;
LAB_01002bde:
      EndDialog(param_1,nResult);
    }
    else if (param_2 == 0x110) {
      pHVar2 = GetDesktopWindow();
      FUN_01003bed(param_1,pHVar2);
      SetDlgItemTextA(param_1,0x834,DAT_0100bc00);
      SetWindowTextA(param_1,&DAT_0100adf4);
      SetForegroundWindow(param_1);
      pcVar3 = FUN_01002b7a;
      pHVar2 = GetDlgItem(param_1,0x834);
      FUN_01002b56(pHVar2,(LONG)pcVar3);
    }
    else {
      if (param_2 != 0x111) goto LAB_01002c1b;
      if (param_3 == 6) {
        nResult = 1;
        goto LAB_01002bde;
      }
      if (param_3 == 7) goto LAB_01002bdc;
    }
    uVar1 = 1;
  }
  return uVar1;
}



undefined4 FUN_01002c71(LPCSTR param_1)

{
  int iVar1;
  
  if (((param_1 != (LPCSTR)0x0) && (iVar1 = lstrlenA(param_1), 2 < iVar1)) &&
     ((param_1[1] == ':' || ((*param_1 == '\\' && (param_1[1] == '\\')))))) {
    return 1;
  }
  return 0;
}



undefined4 FUN_01002ca1(HWND param_1,int param_2,int param_3)

{
  bool bVar1;
  int iVar2;
  undefined3 extraout_var;
  BOOL BVar3;
  UINT UVar4;
  DWORD DVar5;
  undefined3 extraout_var_00;
  HWND pHVar6;
  uint uVar7;
  LPCSTR pCVar8;
  
  if (param_2 != 0x10) {
    if (param_2 == 0x110) {
      pHVar6 = GetDesktopWindow();
      FUN_01003bed(param_1,pHVar6);
      SetWindowTextA(param_1,&DAT_0100adf4);
      SendDlgItemMessageA(param_1,0x835,0xc5,0x103,0);
      if (DAT_0100bc04 != 1) {
        return 1;
      }
      BVar3 = 0;
      pHVar6 = GetDlgItem(param_1,0x836);
      EnableWindow(pHVar6,BVar3);
      return 1;
    }
    if (param_2 != 0x111) {
      return 0;
    }
    if (param_3 == 1) {
      UVar4 = GetDlgItemTextA(param_1,0x835,&DAT_0100ae84,0x104);
      if ((UVar4 == 0) || (iVar2 = FUN_01002c71(&DAT_0100ae84), iVar2 == 0)) {
        pCVar8 = (LPCSTR)0x0;
        UVar4 = 0x4bf;
      }
      else {
        DVar5 = GetFileAttributesA(&DAT_0100ae84);
        if (DVar5 == 0xffffffff) {
          iVar2 = FUN_01003cb8(param_1,0x54a,&DAT_0100ae84,(LPCSTR)0x0,0x20,4);
          if (iVar2 != 6) {
            return 1;
          }
          BVar3 = CreateDirectoryA(&DAT_0100ae84,(LPSECURITY_ATTRIBUTES)0x0);
          if (BVar3 == 0) {
            pCVar8 = &DAT_0100ae84;
            UVar4 = 0x4cb;
            goto LAB_01002e4a;
          }
        }
        FUN_01005a4d(&DAT_0100ae84,"");
        iVar2 = FUN_01004ee3(&DAT_0100ae84);
        if (iVar2 != 0) {
          if ((DAT_0100ae84 != '\\') || (uVar7 = 0, DAT_0100ae85 != '\\')) {
            uVar7 = 1;
          }
          bVar1 = FUN_01004f82(&DAT_0100ae84,uVar7,1);
          if (CONCAT31(extraout_var_00,bVar1) != 0) {
            EndDialog(param_1,1);
          }
          return 1;
        }
        pCVar8 = (LPCSTR)0x0;
        UVar4 = 0x4be;
      }
LAB_01002e4a:
      FUN_01003cb8(param_1,UVar4,pCVar8,(LPCSTR)0x0,0x10,0);
      return 1;
    }
    if (param_3 == 2) {
      EndDialog(param_1,0);
      DAT_0100b704 = 0x800704c7;
      return 1;
    }
    if (param_3 != 0x836) {
      return 1;
    }
    iVar2 = LoadStringA(DAT_0100b6dc,1000,&DAT_0100a670,0x200);
    if (iVar2 == 0) {
      FUN_01003cb8(param_1,0x4b1,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
    }
    else {
      bVar1 = FUN_01003ab8(param_1,&DAT_0100a670,&DAT_0100a360);
      if (CONCAT31(extraout_var,bVar1) == 0) {
        return 1;
      }
      BVar3 = SetDlgItemTextA(param_1,0x835,&DAT_0100a360);
      if (BVar3 != 0) {
        return 1;
      }
      FUN_01003cb8(param_1,0x4c0,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
    }
  }
  EndDialog(param_1,0);
  return 1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_01002ec0(HWND param_1,int param_2,uint param_3)

{
  HWND pHVar1;
  
  if (param_2 == 0x10) {
    EndDialog(param_1,2);
  }
  else if (param_2 == 0x110) {
    pHVar1 = GetDesktopWindow();
    FUN_01003bed(param_1,pHVar1);
    SetWindowTextA(param_1,&DAT_0100adf4);
    SetDlgItemTextA(param_1,0x838,DAT_0100b0a4);
    SetForegroundWindow(param_1);
  }
  else {
    if (param_2 != 0x111) {
      return 0;
    }
    if (5 < param_3) {
      if (7 < param_3) {
        if (param_3 != 0x839) {
          return 1;
        }
        _DAT_0100ae7c = 1;
      }
      EndDialog(param_1,param_3);
      return 1;
    }
  }
  return 1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_01002f4f(HWND param_1,int param_2,int param_3)

{
  int iVar1;
  HWND pHVar2;
  UINT UVar3;
  WPARAM WVar4;
  LPARAM LVar5;
  
  if (param_2 != 0x10) {
    if (param_2 != 0x102) {
      if (param_2 == 0x110) {
        DAT_0100aa78 = param_1;
        pHVar2 = GetDesktopWindow();
        FUN_01003bed(param_1,pHVar2);
        if (DAT_0100a2f8 != 0) {
          LVar5 = 0xbb9;
          WVar4 = 0;
          UVar3 = 0x464;
          pHVar2 = GetDlgItem(param_1,0x83b);
          SendMessageA(pHVar2,UVar3,WVar4,LVar5);
          LVar5 = -0x10000;
          WVar4 = 0xffffffff;
          UVar3 = 0x465;
          pHVar2 = GetDlgItem(param_1,0x83b);
          SendMessageA(pHVar2,UVar3,WVar4,LVar5);
        }
        SetWindowTextA(param_1,&DAT_0100adf4);
        DAT_0100a358 = CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,FUN_010046cc,(LPVOID)0x0,0,
                                    (LPDWORD)&DAT_0100a668);
        if (DAT_0100a358 != (HANDLE)0x0) {
          return 1;
        }
        FUN_01003cb8(param_1,0x4b8,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
        param_3 = 0;
LAB_010030a7:
        EndDialog(param_1,param_3);
        return 1;
      }
      if (param_2 != 0x111) {
        if (param_2 != 0xfa1) {
          return 0;
        }
        TerminateThread(DAT_0100a358,0);
        goto LAB_010030a7;
      }
      if (param_3 != 2) {
        return 1;
      }
      ResetEvent(DAT_0100aa7c);
      iVar1 = FUN_01003cb8(DAT_0100aa78,0x4b2,"",(LPCSTR)0x0,0x20,4);
      if ((iVar1 != 6) && (iVar1 != 1)) {
        SetEvent(DAT_0100aa7c);
        return 1;
      }
      _DAT_0100ae78 = 1;
      SetEvent(DAT_0100aa7c);
      FUN_010030da((char)DAT_0100a358);
      goto LAB_010030c6;
    }
    if (param_3 != 0x1b) {
      return 1;
    }
  }
  _DAT_0100ae78 = 1;
LAB_010030c6:
  EndDialog(param_1,0);
  return 1;
}



void FUN_010030da(undefined param_1)

{
  int iVar1;
  DWORD DVar2;
  BOOL BVar3;
  tagMSG local_24;
  int local_8;
  
  local_8 = 0;
  do {
    DVar2 = MsgWaitForMultipleObjects(1,(HANDLE *)&param_1,0,0xffffffff,0xff);
    iVar1 = local_8;
    if (DVar2 == 0) {
      local_8 = 1;
    }
    else {
      while (local_8 = iVar1, BVar3 = PeekMessageA(&local_24,(HWND)0x0,0,0,1), BVar3 != 0) {
        iVar1 = 1;
        if (local_24.message != 0x12) {
          DispatchMessageA(&local_24);
          iVar1 = local_8;
        }
      }
    }
  } while (local_8 == 0);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

bool FUN_0100313c(int param_1)

{
  uint *puVar1;
  short sVar2;
  BOOL BVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  bool bVar8;
  bool bVar9;
  LPCSTR pCVar10;
  BYTE *pBVar11;
  UINT UVar12;
  BYTE local_1b4 [260];
  _OSVERSIONINFOA local_b0;
  uint auStack_1c [3];
  BYTE *local_10;
  int local_c;
  UINT local_8;
  
  local_8 = 0;
  local_b0.dwOSVersionInfoSize = 0x94;
  BVar3 = GetVersionExA(&local_b0);
  iVar7 = local_c;
  iVar5 = param_1;
  if (BVar3 == 0) {
    local_8 = 0x4b4;
  }
  else {
    if (local_b0.dwPlatformId == 1) {
      DAT_0100bc04 = 0;
      DAT_0100a2f8 = 1;
      _DAT_0100a2fc = 1;
      sVar2 = DAT_0100bc04;
    }
    else {
      if (local_b0.dwPlatformId != 2) {
        local_8 = 0x4ca;
        goto LAB_01003179;
      }
      DAT_0100bc04 = 2;
      DAT_0100a2f8 = 1;
      _DAT_0100a2fc = 1;
      sVar2 = DAT_0100bc04;
      if (local_b0.dwMajorVersion < 4) {
        DAT_0100bc04 = 1;
        if ((local_b0.dwMajorVersion < 3) ||
           ((sVar2 = 1, local_b0.dwMajorVersion == 3 && (local_b0.dwMinorVersion < 0x33)))) {
          DAT_0100a2f8 = 0;
          _DAT_0100a2fc = 0;
          sVar2 = DAT_0100bc04;
        }
      }
    }
    DAT_0100bc04 = sVar2;
    if ((_DAT_0100aab4 == 0) && (param_1 != 0)) {
      if (DAT_0100bc04 == 0) {
        iVar5 = param_1 + 0x40;
      }
      else {
        iVar5 = param_1 + 4;
      }
      local_c = 0;
      do {
        uVar4 = FUN_01002614(local_b0.dwMajorVersion,local_b0.dwMinorVersion,
                             *(uint *)(iVar5 + local_c * 0x18),*(uint *)(iVar5 + 4 + local_c * 0x18)
                            );
        iVar7 = local_c;
        auStack_1c[local_c + 2] = uVar4;
        uVar4 = FUN_01002614(local_b0.dwMajorVersion,local_b0.dwMinorVersion,
                             *(uint *)(iVar5 + iVar7 * 0x18 + 0xc),
                             *(uint *)(iVar5 + 0x10 + iVar7 * 0x18));
        iVar7 = local_c;
        iVar6 = local_c + 2;
        auStack_1c[local_c] = uVar4;
        if (((int)auStack_1c[iVar6] < 0) || (0 < (int)uVar4)) {
          if (iVar7 == 1) goto LAB_0100339e;
        }
        else {
          if (auStack_1c[iVar6] == 0) {
            if (uVar4 == 0) {
              uVar4 = local_b0.dwBuildNumber & 0xffff;
              if (*(uint *)(iVar5 + 8 + iVar7 * 0x18) <= uVar4) {
                puVar1 = (uint *)(iVar5 + iVar7 * 0x18 + 0x14);
                bVar8 = uVar4 < *puVar1;
                bVar9 = uVar4 == *puVar1;
                goto LAB_01003383;
              }
            }
            else if (*(uint *)(iVar5 + 8 + iVar7 * 0x18) <= (local_b0.dwBuildNumber & 0xffff))
            break;
          }
          else {
            if (uVar4 != 0) break;
            puVar1 = (uint *)(iVar5 + 0x14 + iVar7 * 0x18);
            bVar8 = (local_b0.dwBuildNumber & 0xffff) < *puVar1;
            bVar9 = (local_b0.dwBuildNumber & 0xffff) == *puVar1;
LAB_01003383:
            if (bVar8 || bVar9) break;
          }
          if (iVar7 != 0) {
LAB_0100339e:
            local_8 = 0x54c;
            break;
          }
        }
        iVar7 = iVar7 + 1;
        local_c = iVar7;
      } while (iVar7 < 2);
      if (((local_8 == 0) && (*(int *)(param_1 + 0x7c) != 0)) &&
         (iVar6 = FUN_0100246b(param_1,local_1b4,(HKEY)0x104,&local_c), iVar7 = local_c, iVar6 == 0)
         ) {
        local_8 = 0x54d;
      }
    }
  }
LAB_01003179:
  if ((local_8 == 0x54d) || (local_8 == 0x54c)) {
    local_10 = (BYTE *)0x0;
    if (local_8 == 0x54d) {
      iVar5 = iVar7 * 0x3c + *(int *)(param_1 + 0x80) + 0x84 + param_1;
      local_10 = local_1b4;
    }
    pCVar10 = (LPCSTR)(*(int *)(iVar5 + 0x34) + 0x84 + param_1);
    uVar4 = FUN_010025f7(*(uint *)(iVar5 + 0x30));
    if ((((byte)DAT_0100aab8 & 1) == 0) && (*pCVar10 != '\0')) {
      MessageBeep(0);
      iVar5 = MessageBoxA((HWND)0x0,pCVar10,&DAT_0100adf4,uVar4 | 0x30);
      if ((uVar4 & 4) == 0) {
        if ((uVar4 & 1) == 0) goto LAB_01003238;
        bVar8 = iVar5 == 1;
      }
      else {
        bVar8 = iVar5 == 6;
      }
      if (bVar8) {
        local_8 = 0;
      }
      goto LAB_01003238;
    }
    UVar12 = 0x30;
    pCVar10 = &DAT_0100adf4;
    pBVar11 = local_10;
  }
  else {
    if (local_8 == 0) goto LAB_01003238;
    UVar12 = 0x10;
    pCVar10 = (LPCSTR)0x0;
    pBVar11 = (BYTE *)0x0;
  }
  FUN_01003cb8((HWND)0x0,local_8,pCVar10,(LPCSTR)pBVar11,UVar12,0);
LAB_01003238:
  return local_8 == 0;
}



undefined4 FUN_010033e8(void)

{
  DWORD DVar1;
  int iVar2;
  
  DVar1 = FUN_01003e0b("LICENSE",(undefined4 *)0x0,0);
  DAT_0100bc00 = (undefined4 *)LocalAlloc(0x40,DVar1 + 1);
  if (DAT_0100bc00 == (undefined4 *)0x0) {
    FUN_01003cb8((HWND)0x0,0x4b5,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
    DAT_0100b704 = FUN_010056fe();
  }
  else {
    DVar1 = FUN_01003e0b("LICENSE",DAT_0100bc00,DVar1);
    if (DVar1 != 0) {
      iVar2 = lstrcmpA((LPCSTR)DAT_0100bc00,"<None>");
      if (iVar2 == 0) {
        LocalFree(DAT_0100bc00);
      }
      else {
        iVar2 = FUN_0100592b(DAT_0100b6dc,(LPCSTR)0x7d1,(HWND)0x0,FUN_01002bb2,0,0);
        LocalFree(DAT_0100bc00);
        if (iVar2 == 0) {
          DAT_0100b704 = 0x800704c7;
          return 0;
        }
      }
      DAT_0100b704 = 0;
      return 1;
    }
    FUN_01003cb8((HWND)0x0,0x4b1,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
    LocalFree(DAT_0100bc00);
    DAT_0100b704 = 0x80070714;
  }
  return 0;
}



undefined4 FUN_010034c7(void)

{
  undefined4 *puVar1;
  WPARAM WVar2;
  int iVar3;
  
  puVar1 = &DAT_0100b840;
  do {
    *puVar1 = 1;
    puVar1 = puVar1 + 6;
  } while (puVar1 < &DAT_0100bc00);
  if ((((byte)DAT_0100aab8 & 1) == 0) && ((DAT_0100b6d4 & 1) == 0)) {
    WVar2 = FUN_0100592b(DAT_0100b6dc,(LPCSTR)(0x7d5 - (uint)(DAT_0100a2f8 != 0)),(HWND)0x0,
                         FUN_01002f4f,0,0);
  }
  else {
    WVar2 = FUN_010046cc();
  }
  if (WVar2 == 0) {
    DAT_0100b704 = 0x8007042b;
  }
  else {
    iVar3 = FUN_0100571d(FUN_01005830);
    if (iVar3 != 0) {
      DAT_0100b704 = 0;
      return 1;
    }
  }
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_01003545(void)

{
  DWORD DVar1;
  HMODULE hModule;
  FARPROC pFVar2;
  undefined4 uVar3;
  int iVar4;
  _STARTUPINFOA *p_Var5;
  undefined4 local_188 [65];
  _STARTUPINFOA local_84;
  undefined4 local_40;
  undefined *local_3c;
  BYTE *local_38;
  undefined *local_34;
  undefined4 *local_30;
  short local_2c;
  uint local_28;
  undefined4 local_24;
  int local_20;
  int local_1c;
  char *local_18;
  int local_14;
  uint local_10;
  int local_c;
  BYTE *local_8;
  
  local_c = 0;
  local_1c = 0;
  local_20 = 0;
  DAT_0100b704 = 0;
  if ((_DAT_0100aaa8 == 0) &&
     ((DVar1 = FUN_01003e0b("REBOOT",(undefined4 *)&DAT_0100b6cc,4), DVar1 == 0 || (4 < DVar1)))) {
LAB_01003850:
    FUN_01003cb8((HWND)0x0,0x4b1,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
    DAT_0100b704 = 0x80070714;
LAB_010038da:
    uVar3 = 0;
  }
  else {
    local_10 = 0;
    do {
      local_c = 0;
      p_Var5 = &local_84;
      for (iVar4 = 0x11; iVar4 != 0; iVar4 = iVar4 + -1) {
        p_Var5->cb = 0;
        p_Var5 = (_STARTUPINFOA *)&p_Var5->lpReserved;
      }
      local_84.cb = 0x44;
      if (DAT_0100acc2 == '\0') {
        DVar1 = FUN_01003e0b("SHOWWINDOW",&local_14,4);
        if ((DVar1 == 0) || (4 < DVar1)) goto LAB_01003850;
        if (local_14 == 1) {
          local_84.dwFlags = 1;
          local_84.wShowWindow = 0;
        }
        else if (local_14 == 2) {
          local_84.dwFlags = 1;
          local_84.wShowWindow = 6;
        }
        else if (local_14 == 3) {
          local_84.dwFlags = 1;
          local_84.wShowWindow = 3;
        }
        if (local_10 == 0) {
          if (DAT_0100aab8 != 0) {
            if ((DAT_0100aab8 & 1) == 0) {
              if ((DAT_0100aab8 & 2) != 0) {
                local_18 = "USRQCMD";
              }
            }
            else {
              local_18 = "ADMQCMD";
            }
            DVar1 = FUN_01003e0b(local_18,local_188,0x104);
            if (DVar1 == 0) goto LAB_01003850;
            iVar4 = lstrcmpiA((LPCSTR)local_188,"<None>");
            if (iVar4 != 0) {
              local_1c = 1;
            }
          }
          if ((local_1c == 0) && (DVar1 = FUN_01003e0b("RUNPROGRAM",local_188,0x104), DVar1 == 0))
          goto LAB_01003850;
        }
      }
      else {
        lstrcpyA((LPSTR)local_188,&DAT_0100acc2);
      }
      if (local_10 == 1) {
        DVar1 = FUN_01003e0b("POSTRUNPROGRAM",local_188,0x104);
        if (DVar1 == 0) goto LAB_01003850;
        if ((DAT_0100acc2 != '\0') || (iVar4 = lstrcmpiA((LPCSTR)local_188,"<None>"), iVar4 == 0))
        break;
      }
      iVar4 = FUN_010017f8((LPSTR)local_188,&local_8,&local_c);
      if (iVar4 == 0) goto LAB_010038da;
      if (((local_20 == 0) && (DAT_0100bc04 != 1)) && (DAT_0100aaa0 != 0)) {
        if (local_c == 0) {
          local_20 = 1;
          FUN_01001c9c();
          goto LAB_0100372a;
        }
LAB_01003733:
        if (_DAT_0100a2fc == 0) {
          FUN_01003cb8((HWND)0x0,0x4c7,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
          LocalFree(local_8);
          DAT_0100b704 = 0x8007042b;
        }
        else {
          if ((local_c == 0) || ((DAT_0100b6d4 & 4) == 0)) goto LAB_01003813;
          hModule = (HMODULE)FUN_010058cb("advpack.dll");
          if (hModule == (HMODULE)0x0) {
            FUN_01003cb8((HWND)0x0,0x4c8,"advpack.dll",(LPCSTR)0x0,0x10,0);
          }
          else {
            pFVar2 = GetProcAddress(hModule,s_DoInfInstall_0100a2e8);
            if (pFVar2 != (FARPROC)0x0) {
              local_38 = local_8;
              local_30 = local_188;
              local_2c = DAT_0100bc04;
              local_40 = 0;
              local_28 = (uint)DAT_0100aab8;
              local_3c = &DAT_0100adf4;
              local_34 = &DAT_0100ae84;
              if (_DAT_0100aab0 != 0) {
                local_28 = (uint)CONCAT12(1,DAT_0100aab8);
              }
              if ((DAT_0100b6d4 & 8) != 0) {
                local_28 = local_28 | 0x20000;
              }
              if ((DAT_0100b6d4 & 0x10) != 0) {
                local_28 = local_28 | 0x40000;
              }
              if ((DAT_0100adc8 & 0x40) != 0) {
                local_28 = local_28 | 0x80000;
              }
              if ((DAT_0100adc8 & 0x80) != 0) {
                local_28 = local_28 | 0x100000;
              }
              local_24 = DAT_0100b6d8;
              DAT_0100b704 = (*pFVar2)(&local_40);
              if ((int)DAT_0100b704 < 0) {
                FreeLibrary(hModule);
                goto LAB_010038d5;
              }
              FreeLibrary(hModule);
              goto LAB_01003827;
            }
            FUN_01003cb8((HWND)0x0,0x4c9,s_DoInfInstall_0100a2e8,(LPCSTR)0x0,0x10,0);
            FreeLibrary(hModule);
          }
          LocalFree(local_8);
          DAT_0100b704 = FUN_010056fe();
        }
        goto LAB_010038da;
      }
LAB_0100372a:
      if (local_c != 0) goto LAB_01003733;
LAB_01003813:
      iVar4 = FUN_010038e1((LPSTR)local_8,&local_84);
      if (iVar4 == 0) {
LAB_010038d5:
        LocalFree(local_8);
        goto LAB_010038da;
      }
LAB_01003827:
      LocalFree(local_8);
      local_10 = local_10 + 1;
    } while (local_10 < 2);
    uVar3 = 1;
    if (_DAT_0100a350 != 0) {
      FUN_01001e91();
    }
  }
  return uVar3;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_010038e1(LPSTR param_1,LPSTARTUPINFOA param_2)

{
  BOOL BVar1;
  DWORD dwMessageId;
  DWORD dwLanguageId;
  CHAR *lpBuffer;
  DWORD nSize;
  va_list *Arguments;
  CHAR local_214 [512];
  _PROCESS_INFORMATION local_14;
  
  if (param_1 != (LPSTR)0x0) {
    local_14.hProcess = (HANDLE)0x0;
    local_14.hThread = (HANDLE)0x0;
    local_14.dwProcessId = 0;
    local_14.dwThreadId = 0;
    BVar1 = CreateProcessA((LPCSTR)0x0,param_1,(LPSECURITY_ATTRIBUTES)0x0,(LPSECURITY_ATTRIBUTES)0x0
                           ,0,0x20,(LPVOID)0x0,(LPCSTR)0x0,param_2,&local_14);
    if (BVar1 == 0) {
      DAT_0100b704 = FUN_010056fe();
      Arguments = (va_list *)0x0;
      lpBuffer = local_214;
      nSize = 0x200;
      dwLanguageId = 0;
      dwMessageId = GetLastError();
      FormatMessageA(0x1000,(LPCVOID)0x0,dwMessageId,dwLanguageId,lpBuffer,nSize,Arguments);
      FUN_01003cb8((HWND)0x0,0x4c4,param_1,local_214,0x10,0);
    }
    else {
      WaitForSingleObject(local_14.hProcess,0xffffffff);
      GetExitCodeProcess(local_14.hProcess,(LPDWORD)&param_2);
      if ((((_DAT_0100aaa8 == 0) && (((uint)_DAT_0100b6cc & 1) != 0)) &&
          (((uint)_DAT_0100b6cc & 2) == 0)) && (((uint)param_2 & 0xff000000) == 0xaa000000)) {
        _DAT_0100b6cc = param_2;
      }
      FUN_010039db((uint)param_2);
      CloseHandle(local_14.hThread);
      CloseHandle(local_14.hProcess);
      if ((DAT_0100b6d5 & 4) == 0) {
        return 1;
      }
      if (-1 < (int)param_2) {
        return 1;
      }
    }
  }
  return 0;
}



void FUN_010039db(uint param_1)

{
  int iVar1;
  
  iVar1 = FUN_01001b3e();
  if ((iVar1 == 2) || (((param_1 & 0xff000000) == 0xaa000000 && ((param_1 & 1) != 0)))) {
    DAT_0100b704 = 0xbc2;
  }
  else if ((DAT_0100b6d5 & 2) != 0) {
    DAT_0100b704 = param_1;
  }
  return;
}



void FUN_01003a1a(void)

{
  DWORD DVar1;
  undefined4 *lpString1;
  int iVar2;
  UINT UVar3;
  undefined4 *puVar4;
  UINT UVar5;
  
  DVar1 = FUN_01003e0b("FINISHMSG",(undefined4 *)0x0,0);
  lpString1 = (undefined4 *)LocalAlloc(0x40,DVar1 + 1);
  if (lpString1 == (undefined4 *)0x0) {
    FUN_01003cb8((HWND)0x0,0x4b5,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
    return;
  }
  DVar1 = FUN_01003e0b("FINISHMSG",lpString1,DVar1);
  if (DVar1 == 0) {
    UVar5 = 0x10;
    UVar3 = 0x4b1;
    puVar4 = (undefined4 *)0x0;
  }
  else {
    iVar2 = lstrcmpA((LPCSTR)lpString1,"<None>");
    if (iVar2 == 0) goto LAB_01003a8b;
    UVar5 = 0x40;
    UVar3 = 0x3e9;
    puVar4 = lpString1;
  }
  FUN_01003cb8((HWND)0x0,UVar3,(LPCSTR)puVar4,(LPCSTR)0x0,UVar5,0);
LAB_01003a8b:
  LocalFree(lpString1);
  return;
}



bool FUN_01003ab8(HWND param_1,undefined4 param_2,LPSTR param_3)

{
  HMODULE hModule;
  int iVar1;
  LPSTR pCVar2;
  UINT UVar3;
  HWND local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined *local_24;
  undefined4 *local_20;
  HMODULE local_18;
  FARPROC local_14;
  FARPROC local_10;
  FARPROC local_c;
  LPSTR local_8;
  
  hModule = LoadLibraryA(s_SHELL32_DLL_0100a268);
  local_18 = hModule;
  if (hModule == (HMODULE)0x0) {
    UVar3 = 0x4c2;
  }
  else {
    local_c = GetProcAddress(hModule,s_SHBrowseForFolder_0100a298);
    if (((local_c != (FARPROC)0x0) &&
        (local_14 = GetProcAddress(hModule,(LPCSTR)0xc3), local_14 != (FARPROC)0x0)) &&
       (local_10 = GetProcAddress(hModule,s_SHGetPathFromIDList_0100a2b0), local_10 != (FARPROC)0x0)
       ) {
      if ((char)DAT_0100b720 == '\0') {
        GetTempPathA(0x104,(LPSTR)&DAT_0100b720);
        iVar1 = lstrlenA((LPCSTR)&DAT_0100b720);
        local_8 = CharPrevA((LPCSTR)&DAT_0100b720,(LPCSTR)((int)&DAT_0100b720 + iVar1));
        if ((*local_8 == '\\') &&
           (pCVar2 = CharPrevA((LPCSTR)&DAT_0100b720,local_8), *pCVar2 != ':')) {
          *local_8 = '\0';
        }
      }
      local_38 = param_1;
      local_2c = param_2;
      *param_3 = '\0';
      local_34 = 0;
      local_30 = 0;
      local_28 = 1;
      local_24 = &LAB_01003a97;
      local_20 = &DAT_0100b720;
      iVar1 = (*local_c)(&local_38);
      if (iVar1 != 0) {
        (*local_10)(iVar1,&DAT_0100b720);
        if ((char)DAT_0100b720 != '\0') {
          lstrcpyA(param_3,(LPCSTR)&DAT_0100b720);
        }
        (*local_14)(iVar1);
      }
      FreeLibrary(local_18);
      return *param_3 != '\0';
    }
    FreeLibrary(hModule);
    UVar3 = 0x4c1;
  }
  FUN_01003cb8(param_1,UVar3,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
  return false;
}



void FUN_01003bed(HWND param_1,HWND param_2)

{
  HDC hdc;
  tagRECT local_30;
  tagRECT local_20;
  int local_10;
  int local_c;
  int local_8;
  
  GetWindowRect(param_1,&local_30);
  local_30.right = local_30.right - local_30.left;
  local_30.bottom = local_30.bottom - local_30.top;
  GetWindowRect(param_2,&local_20);
  local_c = local_20.bottom - local_20.top;
  local_20.right = local_20.right - local_20.left;
  hdc = GetDC(param_1);
  local_8 = GetDeviceCaps(hdc,8);
  local_10 = GetDeviceCaps(hdc,10);
  ReleaseDC(param_1,hdc);
  local_20.left = (local_20.right - local_30.right) / 2 + local_20.left;
  if (local_20.left < 0) {
    local_20.left = 0;
  }
  else if (local_8 < local_20.left + local_30.right) {
    local_20.left = local_8 - local_30.right;
  }
  local_20.top = (local_c - local_30.bottom) / 2 + local_20.top;
  if (local_20.top < 0) {
    local_20.top = 0;
  }
  else if (local_10 < local_20.top + local_30.bottom) {
    local_20.top = local_10 - local_30.bottom;
  }
  SetWindowPos(param_1,(HWND)0x0,local_20.left,local_20.top,0,0,5);
  return;
}



int FUN_01003cb8(HWND param_1,UINT param_2,LPCSTR param_3,LPCSTR param_4,UINT param_5,uint param_6)

{
  int iVar1;
  int iVar2;
  LPSTR lpString1;
  int iVar3;
  undefined4 *puVar4;
  undefined4 *puVar5;
  char local_23c [512];
  undefined4 local_3c [14];
  
  puVar4 = (undefined4 *)"LoadString() Error.  Could not load string resource.";
  puVar5 = local_3c;
  for (iVar3 = 0xd; iVar3 != 0; iVar3 = iVar3 + -1) {
    *puVar5 = *puVar4;
    puVar4 = puVar4 + 1;
    puVar5 = puVar5 + 1;
  }
  *(undefined *)puVar5 = *(undefined *)puVar4;
  if (((byte)DAT_0100aab8 & 1) != 0) {
    return 1;
  }
  FUN_01003e7d(param_2,local_23c,0x200);
  if (local_23c[0] == '\0') {
    MessageBoxA(param_1,(LPCSTR)local_3c,&DAT_0100adf4,0x10010);
  }
  else if (param_4 == (LPCSTR)0x0) {
    if (param_3 == (LPCSTR)0x0) {
      iVar3 = lstrlenA(local_23c);
      lpString1 = (LPSTR)LocalAlloc(0x40,iVar3 + 1);
      if (lpString1 != (LPSTR)0x0) {
        lstrcpyA(lpString1,local_23c);
        goto LAB_01003dd6;
      }
    }
    else {
      iVar3 = lstrlenA(local_23c);
      iVar1 = lstrlenA(param_3);
      lpString1 = (LPSTR)LocalAlloc(0x40,iVar3 + 100 + iVar1);
      if (lpString1 != (LPSTR)0x0) {
        wsprintfA(lpString1,local_23c,param_3);
LAB_01003dd6:
        MessageBeep(param_5);
        iVar3 = MessageBoxA(param_1,lpString1,&DAT_0100adf4,param_6 | param_5 | 0x10000);
        LocalFree(lpString1);
        return iVar3;
      }
    }
  }
  else {
    iVar3 = lstrlenA(local_23c);
    iVar1 = lstrlenA(param_3);
    iVar2 = lstrlenA(param_4);
    lpString1 = (LPSTR)LocalAlloc(0x40,iVar3 + iVar1 + 100 + iVar2);
    if (lpString1 != (LPSTR)0x0) {
      wsprintfA(lpString1,local_23c,param_3,param_4);
      goto LAB_01003dd6;
    }
  }
  return -1;
}



DWORD FUN_01003e0b(LPCSTR param_1,undefined4 *param_2,uint param_3)

{
  HRSRC pHVar1;
  DWORD DVar2;
  HGLOBAL hResData;
  undefined4 *hResData_00;
  uint uVar3;
  undefined4 *puVar4;
  
  pHVar1 = FindResourceA((HMODULE)0x0,param_1,(LPCSTR)0xa);
  DVar2 = SizeofResource((HMODULE)0x0,pHVar1);
  if ((DVar2 <= param_3) && (param_2 != (undefined4 *)0x0)) {
    if (DVar2 != 0) {
      pHVar1 = FindResourceA((HMODULE)0x0,param_1,(LPCSTR)0xa);
      hResData = LoadResource((HMODULE)0x0,pHVar1);
      hResData_00 = (undefined4 *)LockResource(hResData);
      if (hResData_00 != (undefined4 *)0x0) {
        puVar4 = hResData_00;
        for (uVar3 = DVar2 >> 2; uVar3 != 0; uVar3 = uVar3 - 1) {
          *param_2 = *puVar4;
          puVar4 = puVar4 + 1;
          param_2 = param_2 + 1;
        }
        for (uVar3 = DVar2 & 3; uVar3 != 0; uVar3 = uVar3 - 1) {
          *(undefined *)param_2 = *(undefined *)puVar4;
          puVar4 = (undefined4 *)((int)puVar4 + 1);
          param_2 = (undefined4 *)((int)param_2 + 1);
        }
        FreeResource(hResData_00);
        return DVar2;
      }
    }
    DVar2 = 0;
  }
  return DVar2;
}



LPSTR FUN_01003e7d(UINT param_1,LPSTR param_2,int param_3)

{
  if (param_2 != (LPSTR)0x0) {
    *param_2 = '\0';
    LoadStringA(DAT_0100b6dc,param_1,param_2,param_3);
  }
  return param_2;
}



undefined4 FUN_01003ea4(LPSTR param_1,int param_2,LPCSTR param_3,LPCSTR param_4)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  
  iVar1 = lstrlenA(param_4);
  iVar2 = lstrlenA(param_3);
  if (iVar1 + 1 + iVar2 < param_2) {
    lstrcpyA(param_1,param_3);
    iVar1 = lstrlenA(param_1);
    if (param_1[iVar1 + -1] != '\\') {
      iVar1 = lstrlenA(param_1);
      if (param_1[iVar1 + -1] != '/') {
        iVar1 = lstrlenA(param_1);
        param_1[iVar1] = '\\';
        iVar1 = lstrlenA(param_1);
        param_1[iVar1 + 1] = '\0';
      }
    }
    lstrcatA(param_1,param_4);
    uVar3 = 1;
  }
  else {
    uVar3 = 0;
  }
  return uVar3;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_01003f0b(LPCSTR param_1)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = 1;
  uVar1 = FUN_010059fd(param_1);
  if (uVar1 != 0) {
    if ((_DAT_0100ae7c == 0) && (((byte)DAT_0100aab8 & 1) == 0)) {
      DAT_0100b0a4 = param_1;
      iVar2 = FUN_0100592b(DAT_0100b6dc,(LPCSTR)0x7d3,DAT_0100aa78,FUN_01002ec0,0,6);
      if (iVar2 != 6) {
        if (iVar2 == 7) {
          iVar3 = 0;
        }
        else if (iVar2 == 0x839) {
          _DAT_0100ae7c = 1;
        }
      }
    }
    if (iVar3 != 0) {
      SetFileAttributesA(param_1,0x80);
    }
  }
  return iVar3;
}



undefined4 FUN_01003f8e(LPCSTR param_1)

{
  LPSTR *hMem;
  int iVar1;
  LPSTR lpString1;
  
  hMem = (LPSTR *)LocalAlloc(0x40,8);
  if (hMem == (LPSTR *)0x0) {
    FUN_01003cb8(DAT_0100aa78,0x4b5,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
  }
  else {
    iVar1 = lstrlenA(param_1);
    lpString1 = (LPSTR)LocalAlloc(0x40,iVar1 + 1);
    *hMem = lpString1;
    if (lpString1 != (LPSTR)0x0) {
      lstrcpyA(lpString1,param_1);
      hMem[1] = (LPSTR)DAT_0100ae80;
      DAT_0100ae80 = hMem;
      return 1;
    }
    FUN_01003cb8(DAT_0100aa78,0x4b5,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
    LocalFree(hMem);
  }
  return 0;
}



HANDLE FUN_01004014(LPCSTR param_1,uint param_2)

{
  uint uVar1;
  uint uVar2;
  HANDLE pvVar3;
  DWORD dwCreationDisposition;
  
  uVar2 = param_2;
  if ((param_2 & 8) == 0) {
    uVar1 = param_2 & 3;
    param_2 = 0x80000000;
    if (uVar1 != 0) {
      param_2 = 0x40000000;
    }
    if ((uVar2 & 0x100) == 0) {
      dwCreationDisposition = (-(uint)((uVar2 & 0x200) != 0) & 2) + 3;
    }
    else if ((uVar2 & 0x400) == 0) {
      dwCreationDisposition = (-(uint)((uVar2 & 0x200) != 0) & 0xfffffffe) + 4;
    }
    else {
      dwCreationDisposition = 1;
    }
    pvVar3 = CreateFileA(param_1,param_2,0,(LPSECURITY_ATTRIBUTES)0x0,dwCreationDisposition,0x80,
                         (HANDLE)0xffffffff);
    if ((pvVar3 == (HANDLE)0xffffffff) && (dwCreationDisposition != 3)) {
      FUN_010040b0(param_1);
      pvVar3 = CreateFileA(param_1,param_2,0,(LPSECURITY_ATTRIBUTES)0x0,dwCreationDisposition,0x80,
                           (HANDLE)0xffffffff);
    }
  }
  else {
    pvVar3 = (HANDLE)0xffffffff;
  }
  return pvVar3;
}



void FUN_010040b0(LPCSTR param_1)

{
  LPCSTR lpsz;
  int iVar1;
  
  if (*param_1 != '\0') {
    lpsz = param_1 + 1;
    iVar1 = 0;
    if ((param_1[1] == ':') && (param_1[2] == '\\')) {
      lpsz = param_1 + 3;
    }
    else if ((*param_1 == '\\') && (param_1[1] == '\\')) {
      lpsz = param_1 + 2;
      iVar1 = 2;
    }
    for (; *lpsz != '\0'; lpsz = CharNextA(lpsz)) {
      if ((*lpsz == '\\') && (lpsz[-1] != ':')) {
        if (iVar1 == 0) {
          *lpsz = '\0';
          CreateDirectoryA(param_1,(LPSECURITY_ATTRIBUTES)0x0);
          *lpsz = '\\';
        }
        else {
          iVar1 = iVar1 + -1;
        }
      }
    }
  }
  return;
}



int __cdecl FUN_0100411a(LPCSTR param_1,uint param_2)

{
  undefined4 uVar1;
  int *piVar2;
  int iVar3;
  HANDLE pvVar4;
  int iVar5;
  
  iVar5 = 0;
  piVar2 = &DAT_0100b840;
  do {
    if (*piVar2 == 1) break;
    piVar2 = piVar2 + 6;
    iVar5 = iVar5 + 1;
  } while ((int)piVar2 < 0x100bc00);
  if (iVar5 == 0x28) {
    FUN_01003cb8(DAT_0100aa78,0x4bb,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
  }
  else {
    iVar3 = lstrcmpA(param_1,s__MEMCAB_0100a230);
    uVar1 = DAT_0100ade0;
    if (iVar3 == 0) {
      if (((param_2 & 0x100) == 0) && ((param_2 & 0xb) == 0)) {
        iVar3 = iVar5 * 0x18;
        (&DAT_0100b840)[iVar5 * 6] = 0;
        *(undefined4 *)(&DAT_0100b844 + iVar3) = 1;
        *(undefined4 *)(&DAT_0100b848 + iVar3) = uVar1;
        *(undefined4 *)(&DAT_0100b850 + iVar3) = DAT_0100ade4;
        *(undefined4 *)(&DAT_0100b84c + iVar3) = 0;
        return iVar5;
      }
    }
    else {
      pvVar4 = FUN_01004014(param_1,param_2);
      *(HANDLE *)(&DAT_0100b854 + iVar5 * 0x18) = pvVar4;
      if (pvVar4 != (HANDLE)0xffffffff) {
        (&DAT_0100b840)[iVar5 * 6] = 0;
        *(undefined4 *)(&DAT_0100b844 + iVar5 * 0x18) = 0;
        return iVar5;
      }
    }
  }
  return -1;
}



uint __cdecl FUN_010041df(int param_1,undefined4 *param_2,uint param_3)

{
  int iVar1;
  BOOL BVar2;
  uint uVar3;
  undefined4 *puVar4;
  
  iVar1 = param_1 * 0x18;
  if (*(int *)(&DAT_0100b844 + iVar1) == 0) {
    BVar2 = ReadFile(*(HANDLE *)(&DAT_0100b854 + iVar1),param_2,param_3,&param_3,(LPOVERLAPPED)0x0);
    if (BVar2 == 0) {
      param_3 = 0xffffffff;
    }
  }
  else if (*(int *)(&DAT_0100b844 + iVar1) == 1) {
    uVar3 = *(int *)(&DAT_0100b850 + iVar1) - *(int *)(&DAT_0100b84c + iVar1);
    if (param_3 < uVar3) {
      uVar3 = param_3;
    }
    param_3 = uVar3;
    puVar4 = (undefined4 *)(*(int *)(&DAT_0100b848 + iVar1) + *(int *)(&DAT_0100b84c + iVar1));
    for (uVar3 = param_3 >> 2; uVar3 != 0; uVar3 = uVar3 - 1) {
      *param_2 = *puVar4;
      puVar4 = puVar4 + 1;
      param_2 = param_2 + 1;
    }
    for (uVar3 = param_3 & 3; uVar3 != 0; uVar3 = uVar3 - 1) {
      *(undefined *)param_2 = *(undefined *)puVar4;
      puVar4 = (undefined4 *)((int)puVar4 + 1);
      param_2 = (undefined4 *)((int)param_2 + 1);
    }
    *(uint *)(&DAT_0100b84c + iVar1) = *(int *)(&DAT_0100b84c + iVar1) + param_3;
  }
  return param_3;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

DWORD __cdecl FUN_01004265(int param_1,LPCVOID param_2,DWORD param_3)

{
  BOOL BVar1;
  DWORD DVar2;
  
  FUN_010030da((char)DAT_0100aa7c);
  if (_DAT_0100ae78 == 0) {
    BVar1 = WriteFile(*(HANDLE *)(&DAT_0100b854 + param_1 * 0x18),param_2,param_3,&param_3,
                      (LPOVERLAPPED)0x0);
    DVar2 = param_3;
    if (BVar1 == 0) {
      DVar2 = 0xffffffff;
    }
    if (((DVar2 != 0xffffffff) && (DAT_0100b0a0 = DAT_0100b0a0 + DVar2, DAT_0100a2f8 != 0)) &&
       (DAT_0100aa78 != (HWND)0x0)) {
      SendDlgItemMessageA(DAT_0100aa78,0x83a,0x402,(uint)(DAT_0100b0a0 * 100) / DAT_0100b098,0);
    }
    return DVar2;
  }
  return 0xffffffff;
}



undefined4 __cdecl FUN_010042f4(int param_1)

{
  undefined4 uVar1;
  BOOL BVar2;
  int iVar3;
  
  iVar3 = param_1 * 0x18;
  if (*(int *)(&DAT_0100b844 + iVar3) == 1) {
    uVar1 = 0;
    (&DAT_0100b840)[param_1 * 6] = 1;
    *(undefined4 *)(&DAT_0100b848 + iVar3) = 0;
    *(undefined4 *)(&DAT_0100b850 + iVar3) = 0;
    *(undefined4 *)(&DAT_0100b84c + iVar3) = 0;
  }
  else {
    BVar2 = CloseHandle(*(HANDLE *)(&DAT_0100b854 + iVar3));
    if (BVar2 == 0) {
      uVar1 = 0xffffffff;
    }
    else {
      uVar1 = 0;
      (&DAT_0100b840)[param_1 * 6] = 1;
    }
  }
  return uVar1;
}



DWORD __cdecl FUN_01004347(int param_1,DWORD param_2,int param_3)

{
  int iVar1;
  DWORD DVar2;
  
  iVar1 = param_1 * 0x18;
  if (*(int *)(&DAT_0100b844 + iVar1) != 1) {
    if (param_3 == 0) {
      DVar2 = 0;
    }
    else if (param_3 == 1) {
      DVar2 = 1;
    }
    else {
      DVar2 = param_2;
      if (param_3 == 2) {
        DVar2 = 2;
      }
    }
    DVar2 = SetFilePointer(*(HANDLE *)(&DAT_0100b854 + iVar1),param_2,(PLONG)0x0,DVar2);
    if (DVar2 == 0xffffffff) {
      return 0xffffffff;
    }
    return DVar2;
  }
  if (param_3 != 0) {
    if (param_3 == 1) {
      *(DWORD *)(&DAT_0100b84c + iVar1) = *(int *)(&DAT_0100b84c + iVar1) + param_2;
      goto LAB_01004389;
    }
    if (param_3 != 2) {
      return 0xffffffff;
    }
    param_2 = *(int *)(&DAT_0100b850 + iVar1) + param_2;
  }
  *(DWORD *)(&DAT_0100b84c + iVar1) = param_2;
LAB_01004389:
  return *(DWORD *)(&DAT_0100b84c + iVar1);
}



bool FUN_010043c8(int param_1,WORD param_2,WORD param_3)

{
  BOOL BVar1;
  _FILETIME local_14;
  _FILETIME local_c;
  
  if (((*(int *)(&DAT_0100b844 + param_1 * 0x18) != 1) &&
      (BVar1 = DosDateTimeToFileTime(param_2,param_3,&local_14), BVar1 != 0)) &&
     (BVar1 = LocalFileTimeToFileTime(&local_14,&local_c), BVar1 != 0)) {
    BVar1 = SetFileTime(*(HANDLE *)(&DAT_0100b854 + param_1 * 0x18),&local_c,&local_c,&local_c);
    return BVar1 != 0;
  }
  return false;
}



ushort FUN_0100442e(ushort param_1)

{
  ushort uVar1;
  
  if (param_1 == 0) {
    uVar1 = 0x80;
  }
  else {
    uVar1 = param_1 & 0x27;
  }
  return uVar1;
}



undefined4 FUN_0100445c(void)

{
  return 0xffffffff;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int __cdecl FUN_01004460(int param_1,int param_2)

{
  bool bVar1;
  ushort uVar2;
  int iVar3;
  undefined3 extraout_var;
  undefined2 extraout_var_00;
  BOOL BVar4;
  int iVar5;
  CHAR local_108 [260];
  
  if (_DAT_0100ae78 == 0) {
    if (param_1 == 0) {
      iVar3 = FUN_010045c5(param_2);
      return iVar3;
    }
    if (param_1 == 1) {
      return 0;
    }
    if (param_1 == 2) {
      if (DAT_0100aa78 != (HWND)0x0) {
        SetDlgItemTextA(DAT_0100aa78,0x837,*(LPCSTR *)(param_2 + 4));
      }
      iVar3 = FUN_01003ea4(local_108,0x104,&DAT_0100ae84,*(LPCSTR *)(param_2 + 4));
      if (iVar3 != 0) {
        iVar3 = FUN_01003f0b(local_108);
        if (iVar3 == 0) {
          return 0;
        }
        iVar3 = FUN_0100411a(local_108,0x8302);
        if ((iVar3 != -1) && (iVar5 = FUN_01003f8e(local_108), iVar5 != 0)) {
          _DAT_0100b094 = _DAT_0100b094 + 1;
          return iVar3;
        }
      }
    }
    else {
      if (param_1 != 3) {
        if (param_1 != 4) {
          return 0;
        }
        iVar3 = FUN_0100445c();
        return iVar3;
      }
      iVar3 = FUN_01003ea4(local_108,0x104,&DAT_0100ae84,*(LPCSTR *)(param_2 + 4));
      if ((iVar3 != 0) &&
         (bVar1 = FUN_010043c8(*(int *)(param_2 + 0x14),*(WORD *)(param_2 + 0x18),
                               *(WORD *)(param_2 + 0x1a)), CONCAT31(extraout_var,bVar1) != 0)) {
        FUN_010042f4(*(int *)(param_2 + 0x14));
        uVar2 = FUN_0100442e(*(ushort *)(param_2 + 0x1c));
        BVar4 = SetFileAttributesA(local_108,CONCAT22(extraout_var_00,uVar2));
        return (-(uint)(BVar4 != 0) & 2) - 1;
      }
    }
  }
  else if (param_1 == 3) {
    FUN_010042f4(*(int *)(param_2 + 0x14));
  }
  return -1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_010045c5(int param_1)

{
  int iVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  
  puVar2 = &DAT_0100b3bc;
  puVar3 = &DAT_0100b0ac;
  for (iVar1 = 0xc4; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  lstrcpyA((LPSTR)&DAT_0100b3bc,*(LPCSTR *)(param_1 + 0xc));
  lstrcpyA(&DAT_0100b4c0,*(LPCSTR *)(param_1 + 4));
  lstrcpyA(&DAT_0100b5c4,*(LPCSTR *)(param_1 + 8));
  _DAT_0100b6c8 = *(undefined2 *)(param_1 + 0x1e);
  _DAT_0100b6ca = *(undefined2 *)(param_1 + 0x20);
  return 0;
}



bool FUN_01004619(void)

{
  undefined4 *puVar1;
  int iVar2;
  int iVar3;
  int *piVar4;
  int local_28 [4];
  int local_18;
  int local_14;
  undefined4 local_10 [3];
  
  piVar4 = local_28;
  for (iVar3 = 6; iVar3 != 0; iVar3 = iVar3 + -1) {
    *piVar4 = 0;
    piVar4 = piVar4 + 1;
  }
  puVar1 = FUN_01005ba0(&LAB_01004444,&LAB_01004451,FUN_0100411a,FUN_010041df,FUN_01004265,
                        FUN_010042f4,FUN_01004347,1,local_10);
  if ((((puVar1 != (undefined4 *)0x0) &&
       (iVar3 = FUN_0100411a(s__MEMCAB_0100a230,0x8000), iVar3 != -1)) &&
      (iVar2 = FUN_01005cb0(puVar1,iVar3,local_28), iVar2 != 0)) &&
     (((local_28[0] == DAT_0100ade4 && (local_18 == 0)) &&
      ((local_14 == 0 && (iVar3 = FUN_010042f4(iVar3), iVar3 != -1)))))) {
    iVar3 = FUN_01005c40(puVar1);
    return iVar3 != 0;
  }
  return false;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

WPARAM FUN_010046cc(void)

{
  bool bVar1;
  undefined3 extraout_var;
  HWND pHVar2;
  undefined3 extraout_var_00;
  int **ppiVar3;
  WPARAM wParam;
  UINT UVar4;
  int iVar5;
  
  bVar1 = FUN_0100480b();
  if (CONCAT31(extraout_var,bVar1) == 0) {
    return 0;
  }
  if (DAT_0100aa78 != (HWND)0x0) {
    iVar5 = 0;
    pHVar2 = GetDlgItem(DAT_0100aa78,0x842);
    ShowWindow(pHVar2,iVar5);
    iVar5 = 5;
    pHVar2 = GetDlgItem(DAT_0100aa78,0x841);
    ShowWindow(pHVar2,iVar5);
  }
  bVar1 = FUN_01004619();
  if (CONCAT31(extraout_var_00,bVar1) == 0) {
    UVar4 = 0x4ba;
  }
  else {
    ppiVar3 = (int **)FUN_01005ba0(&LAB_01004444,&LAB_01004451,FUN_0100411a,FUN_010041df,
                                   FUN_01004265,FUN_010042f4,FUN_01004347,1,&DAT_0100ade8);
    if (ppiVar3 != (int **)0x0) {
      wParam = FUN_01005d80(ppiVar3,s__MEMCAB_0100a230,"",0,(int *)FUN_01004460,(int *)0x0,
                            (int *)&DAT_0100ade0);
      if (wParam == 0) goto LAB_010047ae;
      iVar5 = FUN_01005c40(ppiVar3);
      if (iVar5 != 0) goto LAB_010047ae;
    }
    UVar4 = DAT_0100ade8 + 0x514;
  }
  FUN_01003cb8(DAT_0100aa78,UVar4,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
  wParam = 0;
LAB_010047ae:
  if (DAT_0100ade0 != (HGLOBAL)0x0) {
    FreeResource(DAT_0100ade0);
    DAT_0100ade0 = (HGLOBAL)0x0;
  }
  if ((wParam == 0) && (_DAT_0100ae78 == 0)) {
    FUN_01003cb8((HWND)0x0,0x4f8,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
  }
  if ((((byte)DAT_0100aab8 & 1) == 0) && ((DAT_0100b6d4 & 1) == 0)) {
    SendMessageA(DAT_0100aa78,0xfa1,wParam,0);
  }
  return wParam;
}



bool FUN_0100480b(void)

{
  HRSRC hResInfo;
  HGLOBAL hResData;
  
  DAT_0100ade4 = FUN_01003e0b("CABINET",(undefined4 *)0x0,0);
  hResInfo = FindResourceA((HMODULE)0x0,"CABINET",(LPCSTR)0xa);
  hResData = LoadResource((HMODULE)0x0,hResInfo);
  DAT_0100ade0 = LockResource(hResData);
  return DAT_0100ade0 != (LPVOID)0x0;
}



undefined4 FUN_0100484b(void)

{
  DWORD DVar1;
  int iVar2;
  UINT UVar3;
  
  DVar1 = FUN_01003e0b("FILESIZES",&DAT_0100b6e0,0x24);
  if (DVar1 == 0x24) {
    DAT_0100b098 = DAT_0100b700;
    if (DAT_0100b700 != 0) {
      FUN_01003e0b("PACKINSTSPACE",&DAT_0100b6d8,4);
      iVar2 = FUN_0100571d(&LAB_010057f0);
      if (iVar2 == 0) {
        FUN_01003cb8((HWND)0x0,0x4c6,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
        return 0;
      }
      return 1;
    }
    UVar3 = 0x4c6;
  }
  else {
    UVar3 = 0x4b1;
  }
  FUN_01003cb8((HWND)0x0,UVar3,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
  DAT_0100b704 = 0x80070714;
  return 0;
}



undefined4 FUN_010048d4(void)

{
  DWORD DVar1;
  undefined4 *lpString1;
  int iVar2;
  
  DVar1 = FUN_01003e0b("UPROMPT",(undefined4 *)0x0,0);
  lpString1 = (undefined4 *)LocalAlloc(0x40,DVar1 + 1);
  if (lpString1 == (undefined4 *)0x0) {
    FUN_01003cb8((HWND)0x0,0x4b5,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
    DAT_0100b704 = FUN_010056fe();
  }
  else {
    DVar1 = FUN_01003e0b("UPROMPT",lpString1,DVar1);
    if (DVar1 != 0) {
      iVar2 = lstrcmpA((LPCSTR)lpString1,"<None>");
      if (iVar2 == 0) {
        LocalFree(lpString1);
      }
      else {
        iVar2 = FUN_01003cb8((HWND)0x0,0x3e9,(LPCSTR)lpString1,(LPCSTR)0x0,0x20,4);
        LocalFree(lpString1);
        if (iVar2 != 6) {
          DAT_0100b704 = 0x800704c7;
          return 0;
        }
        DAT_0100b704 = 0;
      }
      return 1;
    }
    FUN_01003cb8((HWND)0x0,0x4b1,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
    LocalFree(lpString1);
    DAT_0100b704 = 0x80070714;
  }
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0100499a(void)

{
  LPCSTR *ppCVar1;
  LPCSTR *hMem;
  CHAR local_104 [260];
  
  hMem = DAT_0100ae80;
  if (DAT_0100ae80 != (LPCSTR *)0x0) {
    do {
      if ((_DAT_0100aaa4 == 0) && (_DAT_0100b6d0 == 0)) {
        SetFileAttributesA(*hMem,0x80);
        DeleteFileA(*hMem);
      }
      ppCVar1 = (LPCSTR *)hMem[1];
      LocalFree(*hMem);
      LocalFree(hMem);
      hMem = ppCVar1;
    } while (ppCVar1 != (LPCSTR *)0x0);
  }
  if (((DAT_0100aaa0 != 0) && (_DAT_0100aaa4 == 0)) && (_DAT_0100b6d0 == 0)) {
    lstrcpyA(local_104,&DAT_0100ae84);
    if ((DAT_0100b6d4 & 0x20) != 0) {
      FUN_01005a8c(local_104);
    }
    SetCurrentDirectoryA("..");
    FUN_01001f8c(local_104);
  }
  if ((DAT_0100bc04 != 1) && (DAT_0100aaa0 != 0)) {
    FUN_01001c57();
  }
  DAT_0100aaa0 = 0;
  return;
}



int FUN_01004a65(LPCSTR param_1,LPSTR param_2)

{
  DWORD DVar1;
  BOOL BVar2;
  UINT UVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  CHAR local_104 [260];
  
  iVar4 = 0;
  iVar5 = 0;
  do {
    iVar6 = iVar5 + 1;
    wsprintfA(local_104,"IXP%03d.TMP",iVar5);
    lstrcpyA(param_2,param_1);
    FUN_01005a4d(param_2,local_104);
    RemoveDirectoryA(param_2);
    DVar1 = GetFileAttributesA(param_2);
    if (DVar1 == 0xffffffff) {
      iVar4 = 0;
      BVar2 = CreateDirectoryA(param_2,(LPSECURITY_ATTRIBUTES)0x0);
      if (BVar2 != 0) {
        iVar4 = 1;
        DAT_0100aaa0 = 1;
      }
      break;
    }
    iVar5 = iVar6;
  } while (iVar6 < 400);
  if ((iVar4 == 0) && (UVar3 = GetTempFileNameA(param_1,"IXP",0,param_2), UVar3 != 0)) {
    iVar4 = 1;
    DeleteFileA(param_2);
    CreateDirectoryA(param_2,(LPSECURITY_ATTRIBUTES)0x0);
  }
  return iVar4;
}



undefined4 FUN_01004b1a(LPCSTR param_1,int param_2,uint param_3)

{
  bool bVar1;
  int iVar2;
  BOOL BVar3;
  undefined3 extraout_var;
  char *pcVar4;
  CHAR local_12c [260];
  _SYSTEM_INFO local_28;
  
  if (param_2 == 0) {
    lstrcpyA(&DAT_0100ae84,param_1);
    goto LAB_01004bb6;
  }
  iVar2 = FUN_01004a65(param_1,local_12c);
  if (iVar2 == 0) {
    return 0;
  }
  lstrcpyA(&DAT_0100ae84,local_12c);
  if ((DAT_0100b6d4 & 0x20) != 0) {
    GetSystemInfo(&local_28);
    if (local_28.u.s.wProcessorArchitecture == 0) {
      pcVar4 = "i386";
    }
    else if (local_28.u.s.wProcessorArchitecture == 1) {
      pcVar4 = "mips";
    }
    else if (local_28.u.s.wProcessorArchitecture == 2) {
      pcVar4 = "alpha";
    }
    else {
      if (local_28.u.s.wProcessorArchitecture != 3) goto LAB_01004b9a;
      pcVar4 = "ppc";
    }
    FUN_01005a4d(&DAT_0100ae84,pcVar4);
  }
LAB_01004b9a:
  FUN_01005a4d(&DAT_0100ae84,"");
LAB_01004bb6:
  iVar2 = FUN_01004ee3(&DAT_0100ae84);
  if (iVar2 == 0) {
    BVar3 = CreateDirectoryA(&DAT_0100ae84,(LPSECURITY_ATTRIBUTES)0x0);
    if (BVar3 == 0) {
      DAT_0100b704 = FUN_010056fe();
      return 0;
    }
    DAT_0100aaa0 = 1;
  }
  bVar1 = FUN_01004f82(&DAT_0100ae84,param_3,0);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    if (DAT_0100aaa0 != 0) {
      DAT_0100aaa0 = 0;
      RemoveDirectoryA(&DAT_0100ae84);
    }
    return 0;
  }
  DAT_0100b704 = 0;
  return 1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_01004c18(void)

{
  bool bVar1;
  DWORD DVar2;
  undefined4 *lpString1;
  int iVar3;
  undefined3 extraout_var;
  UINT UVar4;
  undefined3 extraout_var_00;
  undefined3 extraout_var_01;
  undefined3 extraout_var_02;
  undefined3 extraout_var_03;
  undefined3 extraout_var_04;
  uint uVar5;
  char local_108 [3];
  undefined local_105;
  
  DVar2 = FUN_01003e0b("RUNPROGRAM",(undefined4 *)0x0,0);
  lpString1 = (undefined4 *)LocalAlloc(0x40,DVar2 + 1);
  if (lpString1 == (undefined4 *)0x0) {
    FUN_01003cb8((HWND)0x0,0x4b5,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
    DAT_0100b704 = FUN_010056fe();
  }
  else {
    DVar2 = FUN_01003e0b("RUNPROGRAM",lpString1,DVar2);
    if (DVar2 == 0) {
      FUN_01003cb8((HWND)0x0,0x4b1,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
      LocalFree(lpString1);
      DAT_0100b704 = 0x80070714;
    }
    else {
      iVar3 = lstrcmpA((LPCSTR)lpString1,"<None>");
      uVar5 = 1;
      if (iVar3 == 0) {
        _DAT_0100b6d0 = 1;
      }
      LocalFree(lpString1);
      if (DAT_0100abbe == '\0') {
        if ((_DAT_0100aaa4 != 0) || (_DAT_0100b6d0 != 0)) {
          iVar3 = FUN_0100592b(DAT_0100b6dc,(LPCSTR)0x7d2,(HWND)0x0,FUN_01002ca1,0,0);
          return iVar3;
        }
        DVar2 = GetTempPathA(0x104,&DAT_0100ae84);
        if (DVar2 != 0) {
          iVar3 = FUN_01004b1a(&DAT_0100ae84,1,3);
          if (iVar3 != 0) {
            return 1;
          }
          bVar1 = FUN_0100226b(&DAT_0100ae84);
          if ((CONCAT31(extraout_var,bVar1) == 0) &&
             (iVar3 = FUN_01004b1a(&DAT_0100ae84,1,1), iVar3 != 0)) {
            return 1;
          }
        }
        do {
          lstrcpyA(local_108,"A:\\");
          while (local_108[0] < '[') {
            UVar4 = GetDriveTypeA(local_108);
            if (((((UVar4 == 6) || (UVar4 == 3)) &&
                 (DVar2 = GetFileAttributesA(local_108), DVar2 != 0xffffffff)) ||
                (((UVar4 == 2 && (local_108[0] != 'A')) &&
                 ((local_108[0] != 'B' &&
                  ((uVar5 = FUN_01005ae5(local_108), uVar5 != 0 && (0x18fff < uVar5)))))))) &&
               ((bVar1 = FUN_01004f82(local_108,3,0), CONCAT31(extraout_var_00,bVar1) != 0 ||
                ((bVar1 = FUN_0100226b(local_108), CONCAT31(extraout_var_01,bVar1) == 0 &&
                 (bVar1 = FUN_01004f82(local_108,1,0), CONCAT31(extraout_var_02,bVar1) != 0)))))) {
              bVar1 = FUN_0100226b(local_108);
              if (CONCAT31(extraout_var_03,bVar1) != 0) {
                GetWindowsDirectoryA(local_108,0x104);
              }
              FUN_01005a4d(local_108,"msdownld.tmp");
              uVar5 = FUN_01002248(local_108);
              if (uVar5 == 0) {
                local_108[0] = local_108[0] + '\x01';
                local_105 = 0;
              }
              else {
                SetFileAttributesA(local_108,2);
                lstrcpyA(&DAT_0100ae84,local_108);
                iVar3 = FUN_01004b1a(&DAT_0100ae84,1,0);
                if (iVar3 != 0) {
                  return 1;
                }
              }
            }
            else {
              local_108[0] = local_108[0] + '\x01';
            }
          }
          GetWindowsDirectoryA(local_108,0x104);
          bVar1 = FUN_01004f82(local_108,3,4);
        } while (CONCAT31(extraout_var_04,bVar1) != 0);
      }
      else {
        if ((DAT_0100abbe == '\\') && (DAT_0100abbf == '\\')) {
          uVar5 = 0;
        }
        iVar3 = FUN_01004b1a(&DAT_0100abbe,0,uVar5);
        if (iVar3 != 0) {
          return 1;
        }
        FUN_01003cb8((HWND)0x0,0x4be,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
      }
    }
  }
  return 0;
}



undefined4 FUN_01004ee3(LPCSTR param_1)

{
  int iVar1;
  LPSTR lpString1;
  HANDLE hObject;
  DWORD DVar2;
  
  iVar1 = lstrlenA(param_1);
  lpString1 = (LPSTR)LocalAlloc(0x40,iVar1 + 0x14);
  if (lpString1 == (LPSTR)0x0) {
    FUN_01003cb8((HWND)0x0,0x4b5,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
  }
  else {
    lstrcpyA(lpString1,param_1);
    FUN_01005a4d(lpString1,"TMP4351$.TMP");
    hObject = CreateFileA(lpString1,0x40000000,0,(LPSECURITY_ATTRIBUTES)0x0,1,0x4000080,(HANDLE)0x0)
    ;
    LocalFree(lpString1);
    if (hObject != (HANDLE)0xffffffff) {
      CloseHandle(hObject);
      DVar2 = GetFileAttributesA(param_1);
      if ((DVar2 != 0xffffffff) && ((DVar2 & 0x10) != 0)) {
        DAT_0100b704 = 0;
        return 1;
      }
    }
  }
  DAT_0100b704 = FUN_010056fe();
  return 0;
}



bool FUN_01004f82(LPCSTR param_1,uint param_2,int param_3)

{
  ushort uVar1;
  BOOL BVar2;
  uint uVar3;
  DWORD DVar4;
  uint uVar5;
  int iVar6;
  uint uVar7;
  undefined4 *puVar8;
  bool bVar9;
  bool bVar10;
  UINT UVar11;
  DWORD DVar12;
  CHAR *pCVar13;
  DWORD DVar14;
  va_list *ppcVar15;
  CHAR local_31c;
  undefined4 local_31b;
  CHAR local_11c [260];
  DWORD local_18;
  undefined4 local_14;
  CHAR local_10 [8];
  int local_8;
  
  local_8 = 0;
  if (param_2 == 0) {
    return true;
  }
  GetCurrentDirectoryA(0x104,local_11c);
  BVar2 = SetCurrentDirectoryA(param_1);
  if (BVar2 == 0) {
    FUN_01003cb8((HWND)0x0,0x4bc,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
    DAT_0100b704 = FUN_010056fe();
  }
  else {
    uVar3 = FUN_01005b39((LPCSTR)0x0,&local_8);
    if (uVar3 == 0) {
      local_31c = '\0';
      puVar8 = &local_31b;
      for (iVar6 = 0x7f; iVar6 != 0; iVar6 = iVar6 + -1) {
        *puVar8 = 0;
        puVar8 = puVar8 + 1;
      }
      *(undefined2 *)puVar8 = 0;
      *(undefined *)((int)puVar8 + 2) = 0;
      DAT_0100b704 = FUN_010056fe();
      ppcVar15 = (va_list *)0x0;
      pCVar13 = &local_31c;
      DVar14 = 0x200;
      DVar12 = 0;
      DVar4 = GetLastError();
      FormatMessageA(0x1000,(LPCVOID)0x0,DVar4,DVar12,pCVar13,DVar14,ppcVar15);
      UVar11 = 0x4b0;
    }
    else {
      BVar2 = GetVolumeInformationA
                        ((LPCSTR)0x0,(LPSTR)0x0,0,(LPDWORD)0x0,&local_18,&local_14,(LPSTR)0x0,0);
      if (BVar2 != 0) {
        SetCurrentDirectoryA(local_11c);
        lstrcpynA(local_10,param_1,3);
        iVar6 = 0x200;
        uVar1 = 0;
        do {
          if (local_8 == iVar6) break;
          iVar6 = iVar6 << 1;
          uVar1 = uVar1 + 1;
        } while (uVar1 < 8);
        if (uVar1 == 8) {
          FUN_01003cb8((HWND)0x0,0x4c5,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
          return false;
        }
        if (((DAT_0100b6d4 & 8) == 0) || ((local_14._1_1_ & 0x80) == 0)) {
          uVar5 = (&DAT_0100b6e0)[uVar1];
          uVar7 = DAT_0100b6d8;
        }
        else {
          uVar5 = (&DAT_0100b6e0)[uVar1] << 1;
          uVar7 = (DAT_0100b6d8 >> 2) + DAT_0100b6d8;
        }
        if (((param_2 & 1) == 0) || ((param_2 & 2) == 0)) {
          if ((param_2 & 1) == 0) {
            bVar9 = uVar7 < uVar3;
            bVar10 = uVar7 == uVar3;
          }
          else {
            bVar9 = uVar5 < uVar3;
            bVar10 = uVar5 == uVar3;
          }
        }
        else {
          bVar9 = uVar7 + uVar5 < uVar3;
          bVar10 = uVar7 + uVar5 == uVar3;
        }
        if (bVar9 || bVar10) {
          DAT_0100b704 = 0;
          return true;
        }
        bVar9 = FUN_010022cb(param_3,uVar5,uVar7,local_10);
        return bVar9;
      }
      local_31c = '\0';
      puVar8 = &local_31b;
      for (iVar6 = 0x7f; iVar6 != 0; iVar6 = iVar6 + -1) {
        *puVar8 = 0;
        puVar8 = puVar8 + 1;
      }
      *(undefined2 *)puVar8 = 0;
      *(undefined *)((int)puVar8 + 2) = 0;
      DAT_0100b704 = FUN_010056fe();
      ppcVar15 = (va_list *)0x0;
      pCVar13 = &local_31c;
      DVar14 = 0x200;
      DVar12 = 0;
      DVar4 = GetLastError();
      FormatMessageA(0x1000,(LPCVOID)0x0,DVar4,DVar12,pCVar13,DVar14,ppcVar15);
      UVar11 = 0x4f9;
    }
    FUN_01003cb8((HWND)0x0,UVar11,param_1,&local_31c,0x10,0);
    SetCurrentDirectoryA(local_11c);
  }
  return false;
}



undefined4 FUN_0100517d(char *param_1,int *param_2)

{
  char cVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  
  iVar4 = 0;
  cVar1 = *param_1;
  while ((cVar1 != '\0' &&
         ((((cVar1 == ' ' || (cVar1 == '\t')) || (cVar1 == '\r')) ||
          (((cVar1 == '\n' || (cVar1 == '\v')) || (cVar1 == '\f'))))))) {
    iVar3 = iVar4 + 1;
    iVar4 = iVar4 + 1;
    cVar1 = param_1[iVar3];
  }
  if (param_1[iVar4] == '\0') {
    uVar2 = 0;
  }
  else {
    iVar3 = lstrlenA(param_1 + iVar4);
    do {
      iVar3 = iVar3 + -1;
      if (iVar3 < 0) break;
      cVar1 = (param_1 + iVar4)[iVar3];
    } while (((cVar1 == ' ') || (cVar1 == '\t')) ||
            ((cVar1 == '\r' || (((cVar1 == '\n' || (cVar1 == '\v')) || (cVar1 == '\f'))))));
    param_1[iVar3 + iVar4 + 1] = '\0';
    *param_2 = iVar4;
    uVar2 = 1;
  }
  return uVar2;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_010051f9(char *param_1)

{
  char cVar1;
  char *pcVar2;
  LPSTR pCVar3;
  int iVar4;
  short *psVar5;
  DWORD DVar6;
  short *psVar7;
  int iVar8;
  uint uVar9;
  uint uVar10;
  uint uVar11;
  char *lpString1;
  uint uVar12;
  bool bVar13;
  char local_110 [3];
  undefined2 local_10d;
  int local_c;
  int local_8;
  
  local_8 = 1;
  if ((param_1 == (char *)0x0) || (uVar9 = _DAT_0100aaa4, uVar10 = _DAT_0100aaac, *param_1 == '\0'))
  {
    return 1;
  }
LAB_01005223:
  _DAT_0100aaac = uVar10;
  _DAT_0100aaa4 = uVar9;
  uVar12 = 1;
  if ((*param_1 == '\0') || (local_8 == 0)) goto LAB_01005666;
  for (; ((cVar1 = *param_1, cVar1 == ' ' ||
          (((cVar1 == '\t' || (cVar1 == '\r')) || (cVar1 == '\n')))) ||
         ((cVar1 == '\v' || (cVar1 == '\f')))); param_1 = CharNextA(param_1)) {
  }
  if (*param_1 == '\0') goto LAB_01005666;
  iVar8 = 0;
  uVar9 = 0;
  uVar10 = 0;
  do {
    if (uVar9 == 0) {
      cVar1 = *param_1;
      if (((cVar1 == ' ') || (cVar1 == '\t')) ||
         ((cVar1 == '\r' || (((cVar1 == '\n' || (cVar1 == '\v')) || (cVar1 == '\f')))))) break;
    }
    else if (uVar10 != 0) break;
    uVar11 = uVar10;
    if (*param_1 == '\"') {
      pcVar2 = param_1 + 1;
      if (*pcVar2 == '\"') {
        local_110[iVar8] = '\"';
        iVar8 = iVar8 + 1;
        param_1 = param_1 + 2;
      }
      else {
        uVar11 = uVar12;
        param_1 = pcVar2;
        if (uVar9 == 0) {
          uVar9 = uVar12;
          uVar11 = uVar10;
        }
      }
    }
    else {
      local_110[iVar8] = *param_1;
      iVar8 = iVar8 + 1;
      param_1 = param_1 + 1;
    }
    uVar10 = uVar11;
  } while (*param_1 != '\0');
  local_110[iVar8] = '\0';
  if (uVar9 == 0) {
LAB_010052f3:
    if (uVar10 != 0) {
LAB_01005663:
      local_8 = 0;
LAB_01005666:
      if (_DAT_0100aaac == 0) {
        return local_8;
      }
      if (DAT_0100abbe == '\0') {
        DVar6 = GetModuleFileNameA(DAT_0100b6dc,&DAT_0100abbe,0x104);
        if (DVar6 == 0) {
          return 0;
        }
        psVar7 = FUN_01005a1b((short *)&DAT_0100abbe,0x5c);
        *(undefined *)((int)psVar7 + 1) = 0;
        return local_8;
      }
      return local_8;
    }
  }
  else if (uVar10 == 0) {
    if (uVar9 == 0) goto LAB_010052f3;
    goto LAB_01005663;
  }
  if ((local_110[0] != '/') && (local_110[0] != '-')) {
    return 0;
  }
  pCVar3 = CharUpperA((LPSTR)(int)local_110[1]);
  cVar1 = (char)pCVar3;
  if (cVar1 == '?') {
    FUN_01001b27();
    if (DAT_0100aa80 != (HANDLE)0x0) {
      CloseHandle(DAT_0100aa80);
    }
                    // WARNING: Subroutine does not return
    ExitProcess(0);
  }
  uVar10 = _DAT_0100aaac;
  if (cVar1 == 'C') {
    uVar9 = uVar12;
    if (local_110[2] == '\0') goto LAB_01005223;
    if (local_110[2] == ':') {
      iVar8 = ((char)local_10d == '\"') + 3;
      psVar7 = (short *)(local_110 + ((char)local_10d == '\"') + 3);
      iVar4 = lstrlenA((LPCSTR)psVar7);
      if ((((iVar4 == 0) ||
           ((psVar5 = FUN_010059cd(psVar7,0x5b), psVar5 != (short *)0x0 &&
            (psVar5 = FUN_010059cd(psVar7,0x5d), psVar5 == (short *)0x0)))) ||
          ((psVar5 = FUN_010059cd(psVar7,0x5d), psVar5 != (short *)0x0 &&
           (psVar5 = FUN_010059cd(psVar7,0x5b), psVar5 == (short *)0x0)))) ||
         (local_c = iVar8, iVar4 = FUN_0100517d((char *)psVar7,&local_c), iVar4 == 0)) {
LAB_01005616:
        local_8 = 0;
        uVar9 = _DAT_0100aaa4;
        uVar10 = _DAT_0100aaac;
      }
      else {
        lstrcpyA(&DAT_0100acc2,local_110 + local_c + iVar8);
        uVar9 = _DAT_0100aaa4;
        uVar10 = _DAT_0100aaac;
      }
      goto LAB_01005223;
    }
  }
  else {
    if (cVar1 == 'D') {
LAB_010054ed:
      if (local_110[2] != ':') goto LAB_01005654;
      bVar13 = (char)local_10d == '\"';
      iVar8 = bVar13 + 3;
      iVar4 = lstrlenA(local_110 + bVar13 + 3);
      if ((iVar4 == 0) ||
         (local_c = iVar8, iVar4 = FUN_0100517d(local_110 + bVar13 + 3,&local_c), iVar4 == 0))
      goto LAB_01005616;
      pCVar3 = CharUpperA((LPSTR)(int)local_110[1]);
      if ((char)pCVar3 == 'T') {
        lpString1 = &DAT_0100abbe;
        pcVar2 = local_110 + local_c + iVar8;
      }
      else {
        lpString1 = &DAT_0100aaba;
        pcVar2 = local_110 + local_c + iVar8;
      }
      lstrcpyA(lpString1,pcVar2);
      FUN_01005a4d(lpString1,"");
      iVar8 = FUN_01002c71(lpString1);
      uVar9 = _DAT_0100aaa4;
      uVar10 = _DAT_0100aaac;
      if (iVar8 == 0) {
        return 0;
      }
      goto LAB_01005223;
    }
    uVar9 = _DAT_0100aaa4;
    if (cVar1 == 'N') {
      uVar10 = uVar12;
      if (local_110[2] == '\0') goto LAB_01005223;
      if (local_110[2] == ':') {
        uVar10 = _DAT_0100aaac;
        if ((char)local_10d != '\0') {
          pcVar2 = local_110 + 3;
          do {
            cVar1 = *pcVar2;
            pcVar2 = pcVar2 + 1;
            pCVar3 = CharUpperA((LPSTR)(int)cVar1);
            cVar1 = (char)pCVar3;
            uVar9 = uVar12;
            uVar10 = _DAT_0100aab0;
            uVar11 = _DAT_0100aab4;
            if (((cVar1 != 'E') && (uVar9 = _DAT_0100aaac, uVar10 = uVar12, cVar1 != 'G')) &&
               (uVar10 = _DAT_0100aab0, uVar11 = uVar12, cVar1 != 'V')) {
              local_8 = 0;
              uVar11 = _DAT_0100aab4;
            }
            _DAT_0100aab4 = uVar11;
            _DAT_0100aab0 = uVar10;
            _DAT_0100aaac = uVar9;
            uVar9 = _DAT_0100aaa4;
            uVar10 = _DAT_0100aaac;
          } while (*pcVar2 != '\0');
        }
        goto LAB_01005223;
      }
    }
    else {
      if (cVar1 == 'Q') {
        if (local_110[2] != '\0') {
          if (local_110[2] != ':') goto LAB_01005654;
          pCVar3 = CharUpperA((LPSTR)(int)(char)local_10d);
          cVar1 = (char)pCVar3;
          if (cVar1 != '1') {
            if (cVar1 == 'A') {
              DAT_0100aab8 = 1;
              uVar9 = _DAT_0100aaa4;
              uVar10 = _DAT_0100aaac;
              goto LAB_01005223;
            }
            if (cVar1 != 'U') goto LAB_01005654;
          }
        }
        DAT_0100aab8 = 2;
        uVar9 = _DAT_0100aaa4;
        uVar10 = _DAT_0100aaac;
        goto LAB_01005223;
      }
      if (cVar1 != 'R') {
        if (cVar1 == 'T') goto LAB_010054ed;
        goto LAB_01005654;
      }
      if (local_110[2] == '\0') {
        _DAT_0100b6cc = 3;
        _DAT_0100aaa8 = uVar12;
        goto LAB_01005223;
      }
      if (local_110[2] == ':') {
        _DAT_0100b6cc = uVar12;
        if ((char)local_10d != '\0') {
          pcVar2 = local_110 + 3;
          do {
            cVar1 = *pcVar2;
            pcVar2 = pcVar2 + 1;
            pCVar3 = CharUpperA((LPSTR)(int)cVar1);
            cVar1 = (char)pCVar3;
            if (cVar1 == 'A') {
              _DAT_0100b6cc = _DAT_0100b6cc | 2;
              _DAT_0100aaa8 = uVar12;
            }
            else if (cVar1 == 'D') {
              _DAT_0100adc8 = _DAT_0100adc8 | 0x40;
            }
            else if (cVar1 == 'I') {
              _DAT_0100b6cc = _DAT_0100b6cc & 0xfffffffd;
              _DAT_0100aaa8 = uVar12;
            }
            else if (cVar1 == 'N') {
              _DAT_0100b6cc = _DAT_0100b6cc & 0xfffffffe;
              _DAT_0100aaa8 = uVar12;
            }
            else if (cVar1 == 'P') {
              _DAT_0100adc8 = _DAT_0100adc8 | 0x80;
            }
            else if (cVar1 == 'S') {
              _DAT_0100b6cc = _DAT_0100b6cc | 4;
              _DAT_0100aaa8 = uVar12;
            }
            else {
              local_8 = 0;
            }
            uVar9 = _DAT_0100aaa4;
            uVar10 = _DAT_0100aaac;
          } while (*pcVar2 != '\0');
        }
        goto LAB_01005223;
      }
      iVar8 = lstrcmpiA("RegServer",local_110 + 1);
      uVar9 = _DAT_0100aaa4;
      uVar10 = _DAT_0100aaac;
      if (iVar8 == 0) goto LAB_01005223;
    }
  }
LAB_01005654:
  local_8 = 0;
  uVar9 = _DAT_0100aaa4;
  uVar10 = _DAT_0100aaac;
  goto LAB_01005223;
}



bool FUN_010056af(void)

{
  bool bVar1;
  UINT UVar2;
  CHAR local_108 [260];
  
  UVar2 = GetWindowsDirectoryA(local_108,0x104);
  if (UVar2 == 0) {
    FUN_01003cb8((HWND)0x0,0x4f0,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
    DAT_0100b704 = FUN_010056fe();
    return false;
  }
  bVar1 = FUN_01004f82(local_108,2,2);
  return bVar1;
}



DWORD FUN_010056fe(void)

{
  DWORD DVar1;
  
  DVar1 = GetLastError();
  if ((int)DVar1 < 1) {
    DVar1 = GetLastError();
    return DVar1;
  }
  DVar1 = GetLastError();
  return DVar1 & 0xffff | 0x80070000;
}



undefined4 FUN_0100571d(undefined *param_1)

{
  undefined4 *lpString;
  HRSRC hResInfo;
  HGLOBAL hResData;
  undefined4 *hResData_00;
  int iVar1;
  CHAR local_28 [20];
  undefined4 local_14;
  undefined4 local_10;
  undefined4 local_c;
  int local_8;
  
  local_c = 1;
  local_8 = 0;
  wsprintfA(local_28,"UPDFILE%lu",0);
  hResInfo = FindResourceA((HMODULE)0x0,local_28,(LPCSTR)0xa);
  while( true ) {
    if (hResInfo == (HRSRC)0x0) {
      return local_c;
    }
    hResData = LoadResource((HMODULE)0x0,hResInfo);
    hResData_00 = (undefined4 *)LockResource(hResData);
    if (hResData_00 == (undefined4 *)0x0) break;
    local_14 = *hResData_00;
    lpString = hResData_00 + 2;
    local_10 = hResData_00[1];
    iVar1 = lstrlenA((LPCSTR)lpString);
    iVar1 = (*(code *)param_1)(local_14,local_10,lpString,(LPCSTR)(iVar1 + 1 + (int)lpString));
    if (iVar1 == 0) {
      local_c = 0;
      FreeResource(hResData_00);
      return local_c;
    }
    FreeResource(hResData_00);
    local_8 = local_8 + 1;
    wsprintfA(local_28,"UPDFILE%lu",local_8);
    hResInfo = FindResourceA((HMODULE)0x0,local_28,(LPCSTR)0xa);
  }
  DAT_0100b704 = 0x80070714;
  return 0;
}



undefined4 FUN_01005830(DWORD param_1,undefined4 param_2,LPCSTR param_3,LPCVOID param_4)

{
  HANDLE hFile;
  BOOL BVar1;
  CHAR local_110 [260];
  DWORD local_c;
  undefined4 local_8;
  
  local_8 = 1;
  local_c = 0;
  lstrcpyA(local_110,&DAT_0100ae84);
  FUN_01005a4d(local_110,param_3);
  hFile = CreateFileA(local_110,0x40000000,0,(LPSECURITY_ATTRIBUTES)0x0,2,0x80,(HANDLE)0x0);
  if (hFile != (HANDLE)0xffffffff) {
    BVar1 = WriteFile(hFile,param_4,param_1,&local_c,(LPOVERLAPPED)0x0);
    if ((BVar1 != 0) && (param_1 == local_c)) goto LAB_010058b5;
  }
  DAT_0100b704 = 0x80070052;
  local_8 = 0;
LAB_010058b5:
  if (hFile != (HANDLE)0xffffffff) {
    CloseHandle(hFile);
  }
  return local_8;
}



void FUN_010058cb(LPCSTR param_1)

{
  DWORD DVar1;
  CHAR local_108 [260];
  
  lstrcpyA(local_108,&DAT_0100ae84);
  FUN_01005a4d(local_108,param_1);
  DVar1 = GetFileAttributesA(local_108);
  if ((DVar1 == 0xffffffff) || ((DVar1 & 0x10) != 0)) {
    LoadLibraryA(param_1);
  }
  else {
    LoadLibraryExA(local_108,(HANDLE)0x0,8);
  }
  return;
}



int FUN_0100592b(HMODULE param_1,LPCSTR param_2,HWND param_3,DLGPROC param_4,int param_5,int param_6
                )

{
  HRSRC hResInfo;
  LPCDLGTEMPLATEA hDialogTemplate;
  int iVar1;
  
  iVar1 = -1;
  hResInfo = FindResourceA(param_1,param_2,(LPCSTR)0x5);
  if ((hResInfo != (HRSRC)0x0) &&
     (hDialogTemplate = (LPCDLGTEMPLATEA)LoadResource(param_1,hResInfo),
     hDialogTemplate != (LPCDLGTEMPLATEA)0x0)) {
    if (param_5 == 0) {
      param_5 = 0;
    }
    iVar1 = DialogBoxIndirectParamA(param_1,hDialogTemplate,param_3,param_4,param_5);
    FreeResource(hDialogTemplate);
  }
  if (iVar1 == -1) {
    FUN_01003cb8((HWND)0x0,0x4fb,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
    iVar1 = param_6;
  }
  return iVar1;
}



undefined4 FUN_0100599c(void)

{
  return 0;
}



void FUN_0100599f(void)

{
  return;
}



bool FUN_010059a0(short param_1,short param_2)

{
  BOOL BVar1;
  bool bVar2;
  
  if ((BYTE)param_1 == (BYTE)param_2) {
    BVar1 = IsDBCSLeadByte((BYTE)param_1);
    if (BVar1 == 0) {
      bVar2 = false;
    }
    else {
      bVar2 = param_1 != param_2;
    }
  }
  else {
    bVar2 = true;
  }
  return bVar2;
}



short * FUN_010059cd(short *param_1,short param_2)

{
  bool bVar1;
  undefined3 extraout_var;
  
  while( true ) {
    if (*(char *)param_1 == '\0') {
      return (short *)0x0;
    }
    bVar1 = FUN_010059a0(*param_1,param_2);
    if (CONCAT31(extraout_var,bVar1) == 0) break;
    param_1 = (short *)CharNextA((LPCSTR)param_1);
  }
  return param_1;
}



uint FUN_010059fd(LPCSTR param_1)

{
  DWORD DVar1;
  uint uVar2;
  
  DVar1 = GetFileAttributesA(param_1);
  if (DVar1 == 0xffffffff) {
    uVar2 = 0;
  }
  else {
    uVar2 = ~DVar1 >> 4 & 1;
  }
  return uVar2;
}



short * FUN_01005a1b(short *param_1,short param_2)

{
  bool bVar1;
  undefined3 extraout_var;
  short *psVar2;
  
  psVar2 = (short *)0x0;
  for (; *(char *)param_1 != '\0'; param_1 = (short *)CharNextA((LPCSTR)param_1)) {
    bVar1 = FUN_010059a0(*param_1,param_2);
    if (CONCAT31(extraout_var,bVar1) == 0) {
      psVar2 = param_1;
    }
  }
  return psVar2;
}



void FUN_01005a4d(LPCSTR param_1,LPCSTR param_2)

{
  int iVar1;
  LPSTR pCVar2;
  LPSTR lpszCurrent;
  
  iVar1 = lstrlenA(param_1);
  lpszCurrent = param_1 + iVar1;
  if ((param_1 < lpszCurrent) && (pCVar2 = CharPrevA(param_1,lpszCurrent), *pCVar2 != '\\')) {
    *lpszCurrent = '\\';
    lpszCurrent = lpszCurrent + 1;
  }
  for (; *param_2 == ' '; param_2 = param_2 + 1) {
  }
  lstrcpyA(lpszCurrent,param_2);
  return;
}



undefined4 FUN_01005a8c(LPCSTR param_1)

{
  int iVar1;
  LPSTR lpszCurrent;
  LPSTR pCVar2;
  
  iVar1 = lstrlenA(param_1);
  lpszCurrent = CharPrevA(param_1,param_1 + iVar1);
  do {
    lpszCurrent = CharPrevA(param_1,lpszCurrent);
    if (lpszCurrent <= param_1) {
      if (*lpszCurrent != '\\') {
        return 0;
      }
      break;
    }
  } while (*lpszCurrent != '\\');
  if ((lpszCurrent == param_1) || (pCVar2 = CharPrevA(param_1,lpszCurrent), *pCVar2 == ':')) {
    lpszCurrent = CharNextA(lpszCurrent);
  }
  *lpszCurrent = '\0';
  return 1;
}



int FUN_01005ae5(LPCSTR param_1)

{
  BOOL BVar1;
  int iVar2;
  DWORD local_14;
  DWORD local_10;
  DWORD local_c;
  DWORD local_8;
  
  local_10 = 0;
  local_c = 0;
  local_8 = 0;
  local_14 = 0;
  if ((*param_1 != '\0') &&
     (BVar1 = GetDiskFreeSpaceA(param_1,&local_10,&local_c,&local_8,&local_14), BVar1 != 0)) {
    iVar2 = MulDiv(local_c * local_10,local_8,0x400);
    return iVar2;
  }
  return 0;
}



void FUN_01005b39(LPCSTR param_1,int *param_2)

{
  BOOL BVar1;
  int nNumber;
  DWORD local_14;
  DWORD local_10;
  DWORD local_c;
  DWORD local_8;
  
  local_c = 0;
  local_8 = 0;
  local_10 = 0;
  local_14 = 0;
  BVar1 = GetDiskFreeSpaceA(param_1,&local_c,&local_8,&local_10,&local_14);
  if (BVar1 != 0) {
    nNumber = local_8 * local_c;
    MulDiv(nNumber,local_10,0x400);
    if (param_2 != (int *)0x0) {
      *param_2 = nNumber;
    }
  }
  return;
}



undefined4 * __cdecl
FUN_01005ba0(undefined *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,undefined4 param_7,undefined4 param_8,
            undefined4 *param_9)

{
  undefined4 *puVar1;
  
  puVar1 = (undefined4 *)(*(code *)param_1)(0x804);
  if (puVar1 == (undefined4 *)0x0) {
    FUN_01007480(param_9,5,0);
    return (undefined4 *)0x0;
  }
  puVar1[1] = param_2;
  puVar1[2] = param_1;
  puVar1[3] = param_3;
  puVar1[4] = param_4;
  puVar1[5] = param_5;
  puVar1[6] = param_6;
  puVar1[7] = param_7;
  puVar1[8] = param_8;
  *puVar1 = param_9;
  *(undefined2 *)((int)puVar1 + 0xb2) = 0xf;
  puVar1[0x12] = 0;
  puVar1[0x11] = 0;
  puVar1[0x13] = 0;
  puVar1[0x28] = 0xffff;
  puVar1[0x2a] = 0xffff;
  puVar1[0x29] = 0xffff;
  puVar1[0x22] = 0xffffffff;
  puVar1[0x21] = 0xffffffff;
  return puVar1;
}



undefined4 __cdecl FUN_01005c40(undefined4 *param_1)

{
  FUN_01006e10(0xf,param_1);
  if (param_1[0x13] != 0) {
    (*(code *)param_1[1])(param_1[0x13]);
  }
  if (param_1[0x11] != 0) {
    (*(code *)param_1[1])(param_1[0x11]);
  }
  if (param_1[0x12] != 0) {
    (*(code *)param_1[1])(param_1[0x12]);
  }
  if (param_1[0x22] != -1) {
    (*(code *)param_1[6])(param_1[0x22]);
  }
  if (param_1[0x21] != -1) {
    (*(code *)param_1[6])(param_1[0x21]);
  }
  (*(code *)param_1[1])(param_1);
  return 1;
}



undefined4 __cdecl FUN_01005cb0(undefined4 *param_1,undefined4 param_2,undefined4 *param_3)

{
  int iVar1;
  int local_24 [2];
  undefined4 uStack_1c;
  undefined4 uStack_c;
  undefined2 uStack_8;
  ushort uStack_6;
  undefined2 uStack_4;
  undefined2 uStack_2;
  
  iVar1 = (*(code *)param_1[4])(param_2,local_24,0x24);
  if (iVar1 != 0x24) {
    return 0;
  }
  if (local_24[0] != 0x4643534d) {
    return 0;
  }
  if ((short)uStack_c != 0x103) {
    FUN_01007480((undefined4 *)*param_1,3,uStack_c & 0xffff);
    return 0;
  }
  *(undefined2 *)(param_3 + 1) = uStack_c._2_2_;
  *param_3 = uStack_1c;
  *(undefined2 *)((int)param_3 + 6) = uStack_8;
  *(undefined2 *)(param_3 + 2) = uStack_4;
  *(undefined2 *)((int)param_3 + 10) = uStack_2;
  param_3[3] = (uint)((uStack_6 & 4) != 0);
  param_3[4] = uStack_6 & 1;
  param_3[5] = uStack_6 & 2;
  return 1;
}



undefined4 __cdecl
FUN_01005d80(int **param_1,char *param_2,char *param_3,undefined4 param_4,int *param_5,int *param_6,
            int *param_7)

{
  int **ppiVar1;
  char cVar2;
  short sVar3;
  bool bVar4;
  undefined3 extraout_var;
  int iVar5;
  int *piVar6;
  uint uVar7;
  uint uVar8;
  undefined4 *puVar9;
  char *pcVar10;
  char *pcVar11;
  undefined4 *puVar12;
  undefined4 local_4;
  
  local_4 = 0;
  ppiVar1 = param_1 + 0x1ef;
  param_1[0xe] = param_7;
  param_1[9] = param_5;
  uVar7 = 0xffffffff;
  param_1[10] = param_6;
  *(undefined2 *)((int)param_1 + 0xae) = 0;
  pcVar11 = param_3;
  do {
    pcVar10 = pcVar11;
    if (uVar7 == 0) break;
    uVar7 = uVar7 - 1;
    pcVar10 = pcVar11 + 1;
    cVar2 = *pcVar11;
    pcVar11 = pcVar10;
  } while (cVar2 != '\0');
  uVar7 = ~uVar7;
  puVar9 = (undefined4 *)(pcVar10 + -uVar7);
  puVar12 = (undefined4 *)((int)param_1 + 0x5b9);
  for (uVar8 = uVar7 >> 2; uVar8 != 0; uVar8 = uVar8 - 1) {
    *puVar12 = *puVar9;
    puVar9 = puVar9 + 1;
    puVar12 = puVar12 + 1;
  }
  for (uVar7 = uVar7 & 3; uVar7 != 0; uVar7 = uVar7 - 1) {
    *(undefined *)puVar12 = *(undefined *)puVar9;
    puVar9 = (undefined4 *)((int)puVar9 + 1);
    puVar12 = (undefined4 *)((int)puVar12 + 1);
  }
  bVar4 = FUN_01006030(param_1,param_2,0,-1);
  if (CONCAT31(extraout_var,bVar4) != 0) {
    uVar7 = 0xffffffff;
    param_1[0x27] = (int *)0x0;
    param_1[0x24] = (int *)0xffff;
    do {
      pcVar11 = param_3;
      if (uVar7 == 0) break;
      uVar7 = uVar7 - 1;
      pcVar11 = param_3 + 1;
      cVar2 = *param_3;
      param_3 = pcVar11;
    } while (cVar2 != '\0');
    uVar7 = ~uVar7;
    puVar9 = (undefined4 *)(pcVar11 + -uVar7);
    puVar12 = (undefined4 *)((int)param_1 + 0x5b9);
    for (uVar8 = uVar7 >> 2; uVar8 != 0; uVar8 = uVar8 - 1) {
      *puVar12 = *puVar9;
      puVar9 = puVar9 + 1;
      puVar12 = puVar12 + 1;
    }
    for (uVar7 = uVar7 & 3; uVar7 != 0; uVar7 = uVar7 - 1) {
      *(undefined *)puVar12 = *(undefined *)puVar9;
      puVar9 = (undefined4 *)((int)puVar9 + 1);
      puVar12 = (undefined4 *)((int)puVar12 + 1);
    }
    iVar5 = FUN_01006d40(param_1);
    while (iVar5 != 0) {
      do {
        sVar3 = *(short *)(param_1 + 0x2b);
        *(short *)(param_1 + 0x2b) = sVar3 + -1;
        if (sVar3 == 0) {
          local_4 = 1;
          goto LAB_01005fde;
        }
        iVar5 = FUN_01006ac0(param_1);
        if (iVar5 == 0) goto LAB_01005fde;
        param_1[0x1f0] = (int *)(param_1 + 0x2d);
        *ppiVar1 = param_1[0x1d];
        param_1[0x1f1] = (int *)((int)param_1 + 0x1b5);
        param_1[0x1f2] = (int *)((int)param_1 + 0x2b6);
        *(undefined2 *)(param_1 + 0x1f5) = *(undefined2 *)((int)param_1 + 0x7e);
        *(undefined2 *)((int)param_1 + 0x7d6) = *(undefined2 *)(param_1 + 0x20);
        *(undefined2 *)(param_1 + 0x1f6) = *(undefined2 *)((int)param_1 + 0x82);
        param_1[499] = param_1[0xe];
        *(undefined2 *)((int)param_1 + 0x7de) = *(undefined2 *)(param_1 + 0x1f);
        if ((*(ushort *)(param_1 + 0x1f) & 0xfffd) == 0xfffd) {
          if (param_1[0x27] == (int *)0x0) {
            iVar5 = (*(code *)param_5)(1,ppiVar1);
            if (iVar5 == -1) {
              FUN_01007480(*param_1,0xb,0);
              goto LAB_01005fde;
            }
          }
          else {
            piVar6 = (int *)(*(code *)param_5)(2);
            param_1[0x23] = piVar6;
            if (piVar6 == (int *)0xffffffff) {
              FUN_01007480(*param_1,0xb,0);
              goto LAB_01005fde;
            }
            if (piVar6 == (int *)0x0) {
              if ((*(ushort *)(param_1 + 0x1f) & 0xfffe) == 0xfffe) {
                *(short *)((int)param_1 + 0xae) = *(short *)((int)param_1 + 0xae) + 1;
              }
            }
            else {
              iVar5 = FUN_01006470(param_1);
joined_r0x01005f6f:
              if (iVar5 == 0) goto LAB_01005fde;
            }
          }
        }
        else if (param_1[0x27] == (int *)0x0) {
          piVar6 = (int *)(*(code *)param_5)(2,ppiVar1);
          param_1[0x23] = piVar6;
          if (piVar6 == (int *)0xffffffff) {
            FUN_01007480(*param_1,0xb,0);
            goto LAB_01005fde;
          }
          if (piVar6 != (int *)0x0) {
            iVar5 = FUN_01006470(param_1);
            goto joined_r0x01005f6f;
          }
          if ((*(ushort *)(param_1 + 0x1f) & 0xfffe) == 0xfffe) {
            *(short *)((int)param_1 + 0xae) = *(short *)((int)param_1 + 0xae) + 1;
          }
        }
        else {
          *(undefined2 *)(param_1 + 0x2b) = 0;
        }
      } while (*(short *)(param_1 + 0x2b) != 0);
      iVar5 = FUN_01006d40(param_1);
    }
  }
LAB_01005fde:
  if (param_1[0x22] != (int *)0xffffffff) {
    (*(code *)param_1[6])(param_1[0x22]);
  }
  if (param_1[0x21] != (int *)0xffffffff) {
    (*(code *)param_1[6])(param_1[0x21]);
  }
  param_1[0x22] = (int *)0xffffffff;
  param_1[0x21] = (int *)0xffffffff;
  return local_4;
}



bool __cdecl FUN_01006030(undefined4 *param_1,char *param_2,short param_3,short param_4)

{
  undefined4 *puVar1;
  char cVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  int iVar6;
  undefined4 *puVar7;
  int *piVar8;
  char *pcVar9;
  char *pcVar10;
  undefined4 *puVar11;
  int *piVar12;
  uint uStack_28;
  int aiStack_24 [6];
  uint uStack_c;
  short sStack_4;
  short sStack_2;
  
  uVar4 = 0xffffffff;
  puVar1 = (undefined4 *)((int)param_1 + 0x6ba);
  pcVar10 = (char *)((int)param_1 + 0x5b9);
  do {
    pcVar9 = pcVar10;
    if (uVar4 == 0) break;
    uVar4 = uVar4 - 1;
    pcVar9 = pcVar10 + 1;
    cVar2 = *pcVar10;
    pcVar10 = pcVar9;
  } while (cVar2 != '\0');
  uVar4 = ~uVar4;
  puVar7 = (undefined4 *)(pcVar9 + -uVar4);
  puVar11 = puVar1;
  for (uVar5 = uVar4 >> 2; uVar5 != 0; uVar5 = uVar5 - 1) {
    *puVar11 = *puVar7;
    puVar7 = puVar7 + 1;
    puVar11 = puVar11 + 1;
  }
  for (uVar4 = uVar4 & 3; uVar4 != 0; uVar4 = uVar4 - 1) {
    *(undefined *)puVar11 = *(undefined *)puVar7;
    puVar7 = (undefined4 *)((int)puVar7 + 1);
    puVar11 = (undefined4 *)((int)puVar11 + 1);
  }
  uVar4 = 0xffffffff;
  do {
    pcVar10 = param_2;
    if (uVar4 == 0) break;
    uVar4 = uVar4 - 1;
    pcVar10 = param_2 + 1;
    cVar2 = *param_2;
    param_2 = pcVar10;
  } while (cVar2 != '\0');
  uVar4 = ~uVar4;
  iVar6 = -1;
  puVar7 = puVar1;
  do {
    puVar11 = puVar7;
    if (iVar6 == 0) break;
    iVar6 = iVar6 + -1;
    puVar11 = (undefined4 *)((int)puVar7 + 1);
    cVar2 = *(char *)puVar7;
    puVar7 = puVar11;
  } while (cVar2 != '\0');
  puVar7 = (undefined4 *)(pcVar10 + -uVar4);
  puVar11 = (undefined4 *)((int)puVar11 + -1);
  for (uVar5 = uVar4 >> 2; uVar5 != 0; uVar5 = uVar5 - 1) {
    *puVar11 = *puVar7;
    puVar7 = puVar7 + 1;
    puVar11 = puVar11 + 1;
  }
  for (uVar4 = uVar4 & 3; uVar4 != 0; uVar4 = uVar4 - 1) {
    *(undefined *)puVar11 = *(undefined *)puVar7;
    puVar7 = (undefined4 *)((int)puVar7 + 1);
    puVar11 = (undefined4 *)((int)puVar11 + 1);
  }
  iVar6 = (*(code *)param_1[3])(puVar1,0x8000,0x180);
  param_1[0x22] = iVar6;
  if (iVar6 != -1) {
    iVar6 = (*(code *)param_1[3])(puVar1,0x8000,0x180);
    param_1[0x21] = iVar6;
    if (iVar6 != -1) {
      iVar6 = (*(code *)param_1[4])(param_1[0x22],aiStack_24,0x24);
      if (iVar6 != 0x24) {
        FUN_01007480((undefined4 *)*param_1,2,0);
        return false;
      }
      if (aiStack_24[0] != 0x4643534d) {
        FUN_01007480((undefined4 *)*param_1,2,0);
        return false;
      }
      if ((short)uStack_c != 0x103) {
        FUN_01007480((undefined4 *)*param_1,3,uStack_c & 0xffff);
        return false;
      }
      if ((param_4 != -1) && ((sStack_4 != param_3 || (sStack_2 != param_4)))) {
        FUN_01007480((undefined4 *)*param_1,10,0);
        return false;
      }
      piVar8 = aiStack_24;
      piVar12 = param_1 + 0x14;
      for (iVar6 = 9; iVar6 != 0; iVar6 = iVar6 + -1) {
        *piVar12 = *piVar8;
        piVar8 = piVar8 + 1;
        piVar12 = piVar12 + 1;
      }
      uStack_28 = 0;
      if ((*(byte *)((int)param_1 + 0x6e) & 4) != 0) {
        iVar6 = (*(code *)param_1[4])(param_1[0x22],&uStack_28,4);
        if (iVar6 != 4) {
          FUN_01007480((undefined4 *)*param_1,2,0);
          return false;
        }
        if (param_1[0x28] == 0xffff) {
          uVar4 = uStack_28 & 0xffff;
          param_1[0x28] = uVar4;
          if (uVar4 != 0) {
            iVar6 = (*(code *)param_1[2])(uVar4);
            param_1[0x13] = iVar6;
            if (iVar6 == 0) {
              FUN_01007480((undefined4 *)*param_1,5,0);
              return false;
            }
          }
        }
        iVar6 = param_1[0x28];
        if ((iVar6 != 0) &&
           (iVar3 = (*(code *)param_1[4])(param_1[0x22],param_1[0x13],iVar6), iVar3 != iVar6)) {
          FUN_01007480((undefined4 *)*param_1,2,0);
          return false;
        }
      }
      iVar6 = (uStack_28 >> 0x10 & 0xff) + 8;
      if (param_1[0x11] == 0) {
        param_1[0x29] = iVar6;
        iVar6 = (*(code *)param_1[2])(iVar6);
        param_1[0x11] = iVar6;
        if (iVar6 == 0) {
          FUN_01007480((undefined4 *)*param_1,5,0);
          return false;
        }
      }
      else if (param_1[0x29] != iVar6) {
        FUN_01007480((undefined4 *)*param_1,9,0);
        return false;
      }
      iVar6 = (uStack_28 >> 0x18) + 8;
      if (param_1[0x12] == 0) {
        param_1[0x2a] = iVar6;
        iVar6 = (*(code *)param_1[2])(iVar6);
        param_1[0x12] = iVar6;
        if (iVar6 == 0) {
          FUN_01007480((undefined4 *)*param_1,5,0);
          return false;
        }
      }
      else if (param_1[0x2a] != iVar6) {
        FUN_01007480((undefined4 *)*param_1,9,0);
        return false;
      }
      if ((*(byte *)((int)param_1 + 0x6e) & 1) == 0) {
        *(undefined *)((int)param_1 + 0x1b5) = 0;
        *(undefined *)((int)param_1 + 0x2b6) = 0;
      }
      else {
        iVar6 = FUN_01006c80((char *)((int)param_1 + 0x1b5),0x100,param_1);
        if (iVar6 == 0) {
          return false;
        }
        iVar6 = FUN_01006c80((char *)((int)param_1 + 0x2b6),0x100,param_1);
        if (iVar6 == 0) {
          return false;
        }
      }
      if ((*(byte *)((int)param_1 + 0x6e) & 2) == 0) {
        *(undefined *)((int)param_1 + 0x3b7) = 0;
        *(undefined *)(param_1 + 0x12e) = 0;
      }
      else {
        iVar6 = FUN_01006c80((char *)((int)param_1 + 0x3b7),0x100,param_1);
        if ((iVar6 == 0) ||
           (iVar6 = FUN_01006c80((char *)(param_1 + 0x12e),0x100,param_1), iVar6 == 0)) {
          return false;
        }
      }
      iVar6 = (*(code *)param_1[7])(param_1[0x22],0,1);
      param_1[0xb] = iVar6;
      if (iVar6 == -1) {
        FUN_01007480((undefined4 *)*param_1,4,0);
        return false;
      }
      iVar6 = (*(code *)param_1[7])(param_1[0x22],param_1[0x18]);
      if (iVar6 != -1) {
        *(undefined2 *)(param_1 + 0x2b) = *(undefined2 *)(param_1 + 0x1b);
        iVar6 = FUN_01006860(param_1);
        return (bool)('\x01' - (iVar6 == 0));
      }
      FUN_01007480((undefined4 *)*param_1,4,0);
      return false;
    }
  }
  FUN_01007480((undefined4 *)*param_1,1,0);
  return false;
}



undefined4 __cdecl FUN_01006470(int **param_1)

{
  int **ppiVar1;
  int iVar2;
  int *piVar3;
  int *piVar4;
  int *piVar5;
  int *piVar6;
  undefined4 uVar7;
  
  piVar4 = param_1[0x1d];
  if (piVar4 == (int *)0x0) {
LAB_0100651c:
    ppiVar1 = param_1 + 0x1ef;
    param_1[0x1f0] = (int *)(param_1 + 0x2d);
    param_1[500] = param_1[0x23];
    *(undefined2 *)(param_1 + 0x1f5) = *(undefined2 *)((int)param_1 + 0x7e);
    *(undefined2 *)((int)param_1 + 0x7d6) = *(undefined2 *)(param_1 + 0x20);
    *(undefined2 *)(param_1 + 0x1f6) = *(undefined2 *)((int)param_1 + 0x82);
    param_1[499] = param_1[0xe];
    *(undefined2 *)((int)param_1 + 0x7de) = *(undefined2 *)(param_1 + 0x1f);
    *ppiVar1 = (int *)0x0;
    if ((*(byte *)(param_1 + 0x1f6) & 0x40) != 0) {
      *ppiVar1 = (int *)0x1;
      *(ushort *)(param_1 + 0x1f6) = *(ushort *)(param_1 + 0x1f6) & 0xffbf;
    }
    iVar2 = (*(code *)param_1[9])(3,ppiVar1);
    if (iVar2 != -1) {
      param_1[0x23] = (int *)0xffffffff;
      if (iVar2 == 0) {
        FUN_01007480(*param_1,8,0);
        return 0;
      }
      return 1;
    }
    uVar7 = 0xb;
LAB_0100658a:
    FUN_01007480(*param_1,uVar7,0);
  }
  else {
    piVar6 = param_1[0x1e];
    if (piVar6 <= param_1[0xc] && param_1[0xc] != piVar6) {
      param_1[0x24] = (int *)0xffff;
    }
    iVar2 = FUN_01006920(param_1,(int *)(uint)*(ushort *)(param_1 + 0x1f));
    while (iVar2 != 0) {
      if (piVar6 < (int *)((uint)*(ushort *)((int)param_1[0x12] + 6) + (int)param_1[0xc]))
      goto LAB_010064cf;
      iVar2 = FUN_010065f0(param_1);
    }
  }
  goto LAB_01006595;
  while( true ) {
    piVar5 = (int *)((uint)*(ushort *)((int)param_1[0x12] + 6) - ((int)piVar6 - (int)param_1[0xc]));
    if (piVar4 < piVar5) {
      piVar5 = piVar4;
    }
    piVar3 = (int *)(*(code *)param_1[5])
                              (param_1[0x23],(int)param_1[0x10] + ((int)piVar6 - (int)param_1[0xc]),
                               piVar5);
    if (piVar3 != piVar5) {
      uVar7 = 8;
      goto LAB_0100658a;
    }
    piVar6 = (int *)((int)piVar6 + (int)piVar5);
    piVar4 = (int *)((int)piVar4 - (int)piVar5);
    if ((piVar4 != (int *)0x0) && (iVar2 = FUN_010065f0(param_1), iVar2 == 0)) break;
LAB_010064cf:
    if (piVar4 == (int *)0x0) goto LAB_0100651c;
  }
LAB_01006595:
  if (param_1[0x23] != (int *)0xffffffff) {
    (*(code *)param_1[6])(param_1[0x23]);
    param_1[0x23] = (int *)0xffffffff;
  }
  return 0;
}



undefined4 __cdecl FUN_010065f0(int **param_1)

{
  int iVar1;
  ushort local_2;
  
  param_1[0xc] = (int *)((int)param_1[0xc] + (uint)*(ushort *)((int)param_1[0x12] + 6));
  if (*(short *)(param_1 + 0x2c) == 0) {
    iVar1 = FUN_010066d0(param_1);
    if (iVar1 == 0) {
      return 0;
    }
  }
  *(short *)(param_1 + 0x2c) = *(short *)(param_1 + 0x2c) + -1;
  iVar1 = FUN_01006b10(param_1,0);
  if (iVar1 == 0) {
    return 0;
  }
  if (*(short *)((int)param_1[0x12] + 6) == 0) {
    iVar1 = FUN_010066d0(param_1);
    if (iVar1 != 0) {
      iVar1 = FUN_01006b10(param_1,(uint)*(ushort *)(param_1[0x12] + 1));
      if (iVar1 != 0) {
        *(short *)(param_1 + 0x2c) = *(short *)(param_1 + 0x2c) + -1;
        goto LAB_01006674;
      }
    }
    return 0;
  }
LAB_01006674:
  local_2 = *(ushort *)((int)param_1[0x12] + 6);
  iVar1 = FUN_010072f0(param_1,&local_2);
  if (iVar1 == 0) {
    return 0;
  }
  if (*(ushort *)((int)param_1[0x12] + 6) != local_2) {
    FUN_01007480(*param_1,7,0);
    return 0;
  }
  return 1;
}



undefined4 __cdecl FUN_010066d0(int **param_1)

{
  short sVar1;
  bool bVar2;
  bool bVar3;
  int iVar4;
  undefined3 extraout_var;
  short sVar5;
  
  sVar1 = *(short *)(param_1 + 0x1c);
  sVar5 = *(short *)((int)param_1 + 0x72) + 1;
  param_1[0x1f0] = (int *)((int)param_1 + 0x3b7);
  param_1[0x1f1] = (int *)(param_1 + 0x12e);
  param_1[0x1f2] = (int *)((int)param_1 + 0x5b9);
  param_1[499] = param_1[0xe];
  *(short *)((int)param_1 + 0x7da) = sVar1;
  *(short *)(param_1 + 0x1f7) = sVar5;
  param_1[0x1f8] = (int *)0x0;
  do {
    bVar2 = false;
    if (param_1[0x21] != (int *)0xffffffff) {
      iVar4 = (*(code *)param_1[6])(param_1[0x21]);
      if (iVar4 != 0) goto LAB_01006803;
    }
    if (param_1[0x22] != (int *)0xffffffff) {
      iVar4 = (*(code *)param_1[6])(param_1[0x22]);
      if (iVar4 != 0) {
LAB_01006803:
        FUN_01007480(*param_1,4,0);
        return 0;
      }
    }
    param_1[0x22] = (int *)0xffffffff;
    param_1[0x21] = (int *)0xffffffff;
    iVar4 = (*(code *)param_1[9])(4,param_1 + 0x1ef);
    if (iVar4 == -1) {
      FUN_01007480(*param_1,0xb,0);
      return 0;
    }
    bVar3 = FUN_01006030(param_1,(char *)((int)param_1 + 0x3b7),sVar1,sVar5);
    if (CONCAT31(extraout_var,bVar3) == 0) {
LAB_010067aa:
      if (**param_1 == 0xb) {
        return 0;
      }
      bVar2 = true;
    }
    else {
      iVar4 = FUN_010069a0(param_1,0);
      if (iVar4 == 0) goto LAB_010067aa;
    }
    param_1[0x1f8] = (int *)**param_1;
    if (!bVar2) {
      *(short *)((int)param_1 + 0xae) = *(short *)((int)param_1 + 0xae) + 1;
      do {
        if (*(short *)((int)param_1 + 0xae) == 0) {
          param_1[0x27] = (int *)0x1;
          return 1;
        }
        *(short *)(param_1 + 0x2b) = *(short *)(param_1 + 0x2b) + -1;
        *(short *)((int)param_1 + 0xae) = *(short *)((int)param_1 + 0xae) + -1;
        iVar4 = FUN_01006ac0(param_1);
      } while (iVar4 != 0);
      return 0;
    }
  } while( true );
}



undefined4 __cdecl FUN_01006860(undefined4 *param_1)

{
  int iVar1;
  
  param_1[0x1f0] = (int)param_1 + 0x3b7;
  param_1[0x1f1] = param_1 + 0x12e;
  param_1[0x1f2] = (int)param_1 + 0x5b9;
  param_1[499] = param_1[0xe];
  *(undefined2 *)((int)param_1 + 0x7da) = *(undefined2 *)(param_1 + 0x1c);
  *(undefined2 *)(param_1 + 0x1f7) = *(undefined2 *)((int)param_1 + 0x72);
  iVar1 = (*(code *)param_1[9])(0,param_1 + 0x1ef);
  if (iVar1 == -1) {
    FUN_01007480((undefined4 *)*param_1,0xb,0);
    return 0;
  }
  if (param_1[10] != 0) {
    param_1[0x1f9] = 0;
    param_1[0x1fa] = param_1[0xe];
    param_1[0x1fb] = param_1[0x13];
    *(short *)(param_1 + 0x1fc) = (short)param_1[0x28];
    *(undefined2 *)((int)param_1 + 0x7f2) = *(undefined2 *)(param_1 + 0x1c);
    param_1[0x1fd] = (uint)*(ushort *)((int)param_1 + 0x72);
    iVar1 = (*(code *)param_1[10])(param_1 + 0x1f9);
    if (iVar1 == -1) {
      FUN_01007480((undefined4 *)*param_1,0xb,0);
      return 0;
    }
  }
  return 1;
}



undefined4 __cdecl FUN_01006920(int **param_1,int *param_2)

{
  int iVar1;
  
  if (param_1[0x27] != (int *)0x0) {
    return 1;
  }
  if (((uint)param_2 & 0xfffe) == 0xfffe) {
    param_2 = (int *)(*(ushort *)((int)param_1 + 0x6a) - 1);
  }
  if (param_1[0x24] == param_2) {
    return 1;
  }
  iVar1 = FUN_01007220(param_1);
  if ((iVar1 != 0) && (iVar1 = FUN_010069a0(param_1,(int)param_2), iVar1 != 0)) {
    iVar1 = FUN_010065f0(param_1);
    if (iVar1 != 0) {
      param_1[0xc] = (int *)0x0;
      return 1;
    }
    return 0;
  }
  return 0;
}



undefined4 __cdecl FUN_010069a0(undefined4 *param_1,int param_2)

{
  bool bVar1;
  short sVar2;
  int iVar3;
  int iVar4;
  undefined3 extraout_var;
  
  param_1[0x24] = param_2;
  iVar3 = (*(code *)param_1[7])(param_1[0x21],param_1[0x29] * param_2 + param_1[0xb],0);
  if (iVar3 != -1) {
    iVar3 = param_1[0x29];
    iVar4 = (*(code *)param_1[4])(param_1[0x21],param_1[0x11],iVar3);
    if (iVar4 == iVar3) {
      iVar3 = (*(code *)param_1[7])(param_1[0x21],*(undefined4 *)param_1[0x11],0);
      if (iVar3 != -1) {
        *(undefined2 *)(param_1 + 0x2c) = *(undefined2 *)(param_1[0x11] + 4);
        bVar1 = FUN_01006e10(*(short *)(param_1[0x11] + 6),param_1);
        if (CONCAT31(extraout_var,bVar1) == 0) {
          return 0;
        }
        if (param_1[10] != 0) {
          param_1[0x1f9] = 1;
          param_1[0x1fa] = param_1[0xe];
          sVar2 = (short)param_1[0x29] + -8;
          *(short *)(param_1 + 0x1fc) = sVar2;
          if (sVar2 == 0) {
            param_1[0x1fb] = 0;
          }
          else {
            param_1[0x1fb] = param_1[0x11] + 8;
          }
          *(short *)((int)param_1 + 0x7f2) = (short)param_2;
          iVar3 = (*(code *)param_1[10])(param_1 + 0x1f9);
          if (iVar3 == -1) {
            FUN_01007480((undefined4 *)*param_1,0xb,0);
            return 0;
          }
        }
        return 1;
      }
    }
  }
  FUN_01007480((undefined4 *)*param_1,4,0);
  return 0;
}



undefined4 __cdecl FUN_01006ac0(undefined4 *param_1)

{
  int iVar1;
  
  iVar1 = (*(code *)param_1[4])(param_1[0x22],param_1 + 0x1d,0x10);
  if (iVar1 == 0x10) {
    iVar1 = FUN_01006c80((char *)(param_1 + 0x2d),0x100,param_1);
    if (iVar1 != 0) {
      return 1;
    }
  }
  FUN_01007480((undefined4 *)*param_1,4,0);
  return 0;
}



undefined4 __cdecl FUN_01006b10(undefined4 *param_1,int param_2)

{
  short sVar1;
  int iVar2;
  int iVar3;
  undefined4 extraout_ECX;
  undefined4 extraout_ECX_00;
  undefined4 uVar4;
  uint uVar5;
  uint *puVar6;
  undefined8 uVar7;
  
  iVar3 = param_1[0x2a];
  iVar2 = (*(code *)param_1[4])(param_1[0x21],param_1[0x12],iVar3);
  if (iVar2 == iVar3) {
    uVar5 = (uint)*(ushort *)(param_1[0x12] + 4);
    if (uVar5 + param_2 < (uint)param_1[0x26] || uVar5 + param_2 == param_1[0x26]) {
      uVar7 = (*(code *)param_1[4])(param_1[0x21],param_1[0xf] + param_2,uVar5);
      if ((uint)uVar7 == uVar5) {
        if (*(int *)param_1[0x12] != 0) {
          puVar6 = (uint *)((int *)param_1[0x12] + 1);
          uVar7 = FUN_0100749c(extraout_ECX,(int)((ulonglong)uVar7 >> 0x20),
                               (uint *)(param_1[0xf] + param_2),(uint)*(ushort *)puVar6,0);
          uVar7 = FUN_0100749c(extraout_ECX_00,(int)((ulonglong)uVar7 >> 0x20),puVar6,
                               param_1[0x2a] - 4,(uint)uVar7);
          if (*(int *)param_1[0x12] != (int)uVar7) {
            FUN_01007480((undefined4 *)*param_1,4,0);
            return 0;
          }
        }
        *(short *)(param_1[0x12] + 4) = *(short *)(param_1[0x12] + 4) + (short)param_2;
        if ((param_2 != 0) || (uVar4 = 0, *(short *)(param_1[0x12] + 6) == 0)) {
          uVar4 = 1;
        }
        if (param_1[10] != 0) {
          param_1[0x1f9] = 2;
          param_1[0x1fa] = param_1[0xe];
          sVar1 = (short)param_1[0x2a] + -8;
          *(short *)(param_1 + 0x1fc) = sVar1;
          if (sVar1 == 0) {
            param_1[0x1fb] = 0;
          }
          else {
            param_1[0x1fb] = param_1[0x12] + 8;
          }
          param_1[0x1fd] = param_1[0xf] + param_2;
          *(undefined2 *)(param_1 + 0x1fe) = *(undefined2 *)(param_1[0x12] + 4);
          param_1[0x1ff] = uVar4;
          *(short *)(param_1 + 0x200) = (short)param_2;
          iVar3 = (*(code *)param_1[10])(param_1 + 0x1f9);
          if (iVar3 == -1) {
            FUN_01007480((undefined4 *)*param_1,0xb,0);
            return 0;
          }
        }
        return 1;
      }
    }
  }
  FUN_01007480((undefined4 *)*param_1,4,0);
  return 0;
}



undefined4 __cdecl FUN_01006c80(char *param_1,int param_2,undefined4 *param_3)

{
  char cVar1;
  char cVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  
  iVar3 = (*(code *)param_3[7])(param_3[0x22],0,1);
  iVar4 = (*(code *)param_3[4])(param_3[0x22],param_1,param_2);
  if (iVar4 < 1) {
    FUN_01007480((undefined4 *)*param_3,4,0);
    return 0;
  }
  uVar5 = 0xffffffff;
  cVar2 = param_1[param_2 + -1];
  param_1[param_2 + -1] = '\0';
  do {
    if (uVar5 == 0) break;
    uVar5 = uVar5 - 1;
    cVar1 = *param_1;
    param_1 = param_1 + 1;
  } while (cVar1 != '\0');
  if ((param_2 <= (int)~uVar5) && (cVar2 != '\0')) {
    FUN_01007480((undefined4 *)*param_3,4,0);
    return 0;
  }
  iVar3 = (*(code *)param_3[7])(param_3[0x22],~uVar5 + iVar3,0);
  if (iVar3 == -1) {
    FUN_01007480((undefined4 *)*param_3,4,0);
    return 0;
  }
  return 1;
}



undefined4 __cdecl FUN_01006d40(undefined4 *param_1)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  
  iVar2 = (*(code *)param_1[7])(param_1[0x22],0,1);
  if (iVar2 == -1) {
    FUN_01007480((undefined4 *)*param_1,4,0);
    return 0;
  }
  piVar1 = param_1 + 0x1ef;
  *(undefined2 *)((int)param_1 + 0x7de) = *(undefined2 *)(param_1 + 0x2b);
  *(undefined2 *)((int)param_1 + 0x7da) = *(undefined2 *)(param_1 + 0x1c);
  *piVar1 = iVar2;
  param_1[499] = param_1[0xe];
  iVar3 = (*(code *)param_1[9])(5,piVar1);
  if (iVar3 == -1) {
    FUN_01007480((undefined4 *)*param_1,0xb,0);
    return 0;
  }
  *(short *)(param_1 + 0x2b) = *(short *)((int)param_1 + 0x7de);
  if ((*(short *)((int)param_1 + 0x7de) != 0) && (*piVar1 != iVar2)) {
    iVar2 = (*(code *)param_1[7])(param_1[0x22],*piVar1,0);
    if (iVar2 == -1) {
      FUN_01007480((undefined4 *)*param_1,0xb,0);
      return 0;
    }
  }
  return 1;
}



bool __cdecl FUN_01006e10(short param_1,undefined4 *param_2)

{
  int iVar1;
  
  if (*(short *)((int)param_2 + 0xb2) == param_1) {
    return true;
  }
  iVar1 = FUN_01006e70(param_2);
  if (iVar1 == 0) {
    FUN_01007480((undefined4 *)*param_2,7,0);
    return false;
  }
  *(short *)((int)param_2 + 0xb2) = param_1;
  iVar1 = FUN_01006f60(param_2);
  return (bool)('\x01' - (iVar1 == 0));
}



undefined4 __cdecl FUN_01006e70(undefined4 *param_1)

{
  int iVar1;
  
  switch(*(ushort *)((int)param_1 + 0xb2) & 0xf) {
  case 0:
    break;
  case 1:
    iVar1 = FUN_0100599f();
    if (iVar1 != 0) {
      FUN_01007480((undefined4 *)*param_1,7,0);
      return 0;
    }
    break;
  case 2:
    iVar1 = FUN_0100599f();
    if (iVar1 != 0) {
      FUN_01007480((undefined4 *)*param_1,7,0);
      return 0;
    }
    break;
  case 3:
    iVar1 = FUN_010076d0((int *)param_1[0xd]);
    if (iVar1 != 0) {
      FUN_01007480((undefined4 *)*param_1,7,0);
      return 0;
    }
    break;
  default:
    FUN_01007480((undefined4 *)*param_1,6,0);
    return 0;
  case 0xf:
    return 1;
  }
  (*(code *)param_1[1])(param_1[0xf]);
  (*(code *)param_1[1])(param_1[0x10]);
  return 1;
}



undefined4 __cdecl FUN_01006f60(undefined4 *param_1)

{
  int *piVar1;
  ushort uVar2;
  int iVar3;
  int iVar4;
  uint local_8 [2];
  
  iVar4 = 0;
  piVar1 = param_1 + 0x25;
  *piVar1 = 0x8000;
  switch(*(ushort *)((int)param_1 + 0xb2) & 0xf) {
  case 0:
    param_1[0x26] = 0x8000;
    break;
  case 1:
    iVar3 = FUN_0100599c();
    if (iVar3 == 0) break;
    goto LAB_01007052;
  case 2:
    iVar3 = FUN_0100599c();
    goto joined_r0x01007050;
  case 3:
    local_8[0] = 1 << ((byte)(*(ushort *)((int)param_1 + 0xb2) >> 8) & 0x1f);
    iVar3 = FUN_01007520(piVar1,local_8,(undefined *)0x0,(undefined *)0x0,param_1 + 0x26,
                         (undefined4 *)0x0,0,0,0,0,0);
joined_r0x01007050:
    if (iVar3 != 0) {
LAB_01007052:
      iVar4 = 7;
    }
    break;
  default:
    iVar4 = 6;
    break;
  case 0xf:
    return 1;
  }
  if (iVar4 != 0) {
    FUN_01007480((undefined4 *)*param_1,iVar4,0);
    *(undefined2 *)((int)param_1 + 0xb2) = 0xf;
    return 0;
  }
  iVar4 = (*(code *)param_1[2])(param_1[0x26]);
  param_1[0xf] = iVar4;
  if (iVar4 == 0) {
    FUN_01007480((undefined4 *)*param_1,5,0);
    *(undefined2 *)((int)param_1 + 0xb2) = 0xf;
    return 0;
  }
  iVar4 = (*(code *)param_1[2])(*piVar1);
  param_1[0x10] = iVar4;
  if (iVar4 == 0) {
    (*(code *)param_1[1])(param_1[0xf]);
    FUN_01007480((undefined4 *)*param_1,5,0);
    *(undefined2 *)((int)param_1 + 0xb2) = 0xf;
    return 0;
  }
  uVar2 = *(ushort *)((int)param_1 + 0xb2) & 0xf;
  iVar4 = 0;
  if (uVar2 == 1) {
    iVar3 = FUN_0100599c();
  }
  else if (uVar2 == 2) {
    iVar3 = FUN_0100599c();
  }
  else {
    if (uVar2 != 3) goto LAB_010071a1;
    iVar3 = FUN_01007520(piVar1,local_8,(undefined *)param_1[2],(undefined *)param_1[1],
                         param_1 + 0x26,param_1 + 0xd,param_1[3],param_1[4],param_1[5],param_1[6],
                         param_1[7]);
  }
  if (iVar3 != 0) {
    iVar4 = (-(uint)(iVar3 == 1) & 0xfffffffe) + 7;
  }
LAB_010071a1:
  if (iVar4 != 0) {
    (*(code *)param_1[1])(param_1[0xf]);
    (*(code *)param_1[1])(param_1[0x10]);
    FUN_01007480((undefined4 *)*param_1,iVar4,0);
    *(undefined2 *)((int)param_1 + 0xb2) = 0xf;
    return 0;
  }
  return 1;
}



undefined4 __cdecl FUN_01007220(undefined4 *param_1)

{
  int iVar1;
  
  switch(*(ushort *)((int)param_1 + 0xb2) & 0xf) {
  case 0:
  case 0xf:
    break;
  case 1:
    iVar1 = FUN_0100599f();
    if (iVar1 != 0) {
      FUN_01007480((undefined4 *)*param_1,7,0);
      return 0;
    }
    break;
  case 2:
    iVar1 = FUN_0100599f();
    if (iVar1 != 0) {
      FUN_01007480((undefined4 *)*param_1,7,0);
      return 0;
    }
    break;
  case 3:
    iVar1 = FUN_010076a0((int *)param_1[0xd]);
    if (iVar1 != 0) {
      FUN_01007480((undefined4 *)*param_1,7,0);
      return 0;
    }
    break;
  default:
    FUN_01007480((undefined4 *)*param_1,6,0);
    return 0;
  }
  return 1;
}



undefined4 __cdecl FUN_010072f0(undefined4 *param_1,ushort *param_2)

{
  ushort uVar1;
  byte bVar2;
  int iVar3;
  undefined3 extraout_var;
  uint uVar4;
  undefined *puVar5;
  undefined *puVar6;
  uint local_4;
  
  switch(*(ushort *)((int)param_1 + 0xb2) & 0xf) {
  case 0:
    uVar1 = *(ushort *)(param_1[0x12] + 4);
    *param_2 = uVar1;
    puVar5 = (undefined *)param_1[0xf];
    puVar6 = (undefined *)param_1[0x10];
    for (uVar4 = (uint)uVar1; uVar4 != 0; uVar4 = uVar4 - 1) {
      *puVar6 = *puVar5;
      puVar5 = puVar5 + 1;
      puVar6 = puVar6 + 1;
    }
    return 1;
  case 1:
    break;
  case 2:
    local_4 = (uint)*param_2;
    iVar3 = FUN_0100599f();
    if (iVar3 == 0) {
      *param_2 = (ushort)local_4;
      return 1;
    }
    FUN_01007480((undefined4 *)*param_1,7,0);
    return 0;
  case 3:
    local_4 = (uint)*param_2;
    bVar2 = FUN_01007620((int *)param_1[0xd],param_1[0xf],(uint)*(ushort *)(param_1[0x12] + 4),
                         param_1[0x10],&local_4);
    if (CONCAT31(extraout_var,bVar2) == 0) {
      *param_2 = (ushort)local_4;
      return 1;
    }
    FUN_01007480((undefined4 *)*param_1,7,0);
    return 0;
  default:
    FUN_01007480((undefined4 *)*param_1,6,0);
    return 0;
  }
  local_4 = param_1[0x25];
  iVar3 = FUN_0100599f();
  if (iVar3 == 0) {
    *param_2 = (ushort)local_4;
    return 1;
  }
  FUN_01007480((undefined4 *)*param_1,7,0);
  return 0;
}



void __cdecl FUN_01007480(undefined4 *param_1,undefined4 param_2,undefined4 param_3)

{
  *param_1 = param_2;
  param_1[2] = 1;
  param_1[1] = param_3;
  return;
}



undefined8 __fastcall
FUN_0100749c(undefined4 param_1,undefined4 param_2,uint *param_3,uint param_4,uint param_5)

{
  uint *puVar1;
  uint *puVar2;
  uint *puVar3;
  byte bVar4;
  uint uVar5;
  uint uVar6;
  
  if (3 < (int)param_4) {
    if (0xf < (int)param_4) {
      uVar6 = param_4 >> 4;
      do {
        uVar5 = *param_3;
        puVar1 = param_3 + 1;
        puVar2 = param_3 + 2;
        puVar3 = param_3 + 3;
        param_3 = param_3 + 4;
        param_5 = param_5 ^ uVar5 ^ *puVar2 ^ *puVar1 ^ *puVar3;
        uVar6 = uVar6 - 1;
      } while (uVar6 != 0);
    }
    for (uVar6 = param_4 >> 2 & 3; uVar6 != 0; uVar6 = uVar6 - 1) {
      param_5 = param_5 ^ *param_3;
      param_3 = param_3 + 1;
    }
  }
  uVar6 = param_4 & 3;
  if (uVar6 == 3) {
    bVar4 = *(byte *)param_3;
    param_3 = (uint *)((int)param_3 + 1);
    param_5 = param_5 ^ (uint)bVar4 << 0x10;
LAB_010074fc:
    bVar4 = *(byte *)param_3;
    param_3 = (uint *)((int)param_3 + 1);
    param_5 = param_5 ^ (uint)bVar4 << 8;
  }
  else {
    if (uVar6 == 2) goto LAB_010074fc;
    if (uVar6 != 1) goto LAB_01007513;
  }
  param_5 = param_5 ^ *(byte *)param_3;
LAB_01007513:
  return CONCAT44(param_2,param_5);
}



undefined4 __cdecl
FUN_01007520(int *param_1,uint *param_2,undefined *param_3,undefined *param_4,int *param_5,
            undefined4 *param_6,int param_7,int param_8,int param_9,int param_10,int param_11)

{
  undefined4 *puVar1;
  int iVar2;
  
  *param_5 = *param_1 + 0x1800;
  if (param_6 == (undefined4 *)0x0) {
    return 0;
  }
  *param_6 = 0;
  puVar1 = (undefined4 *)(*(code *)param_3)(0x2c);
  if (puVar1 == (undefined4 *)0x0) {
    return 1;
  }
  iVar2 = (*(code *)param_3)(0x2efc);
  puVar1[10] = iVar2;
  if (iVar2 == 0) {
    (*(code *)param_4)(puVar1);
    return 1;
  }
  puVar1[1] = param_3;
  puVar1[2] = param_4;
  puVar1[3] = param_7;
  puVar1[4] = param_8;
  puVar1[5] = param_9;
  puVar1[6] = param_10;
  puVar1[7] = param_11;
  puVar1[8] = *param_1;
  puVar1[9] = param_2[1];
  *puVar1 = 0x4349444c;
  iVar2 = FUN_01007710((int *)puVar1[10],*param_2,(int)param_3,(int)param_4,param_7,param_8,param_9,
                       param_10,param_11);
  if (iVar2 == 0) {
    (*(code *)param_4)(puVar1);
    return 1;
  }
  *param_6 = puVar1;
  return 0;
}



byte __cdecl FUN_01007620(int *param_1,int param_2,int param_3,int param_4,uint *param_5)

{
  uint uVar1;
  int iVar2;
  uint local_4;
  
  local_4 = 0;
  if (*param_1 != 0x4349444c) {
    return 2;
  }
  uVar1 = *param_5;
  if ((uint)param_1[8] < uVar1) {
    return 3;
  }
  iVar2 = FUN_010077e0((int *)param_1[10],uVar1,param_2,param_3,param_4,uVar1,&local_4);
  *param_5 = local_4;
  return (iVar2 == 0) - 1U & 4;
}



undefined4 __cdecl FUN_010076a0(int *param_1)

{
  if (*param_1 != 0x4349444c) {
    return 2;
  }
  FUN_010077b0(param_1[10]);
  return 0;
}



undefined4 __cdecl FUN_010076d0(int *param_1)

{
  if (*param_1 != 0x4349444c) {
    return 2;
  }
  FUN_010077a0((int *)param_1[10]);
  *param_1 = 0;
  (*(code *)param_1[2])(param_1[10]);
  (*(code *)param_1[2])(param_1);
  return 0;
}



undefined4 __cdecl
FUN_01007710(int *param_1,uint param_2,int param_3,int param_4,int param_5,int param_6,int param_7,
            int param_8,int param_9)

{
  bool bVar1;
  undefined3 extraout_var;
  
  param_1[3000] = param_3;
  param_1[0xbb9] = param_4;
  param_1[0xbba] = param_5;
  param_1[0xbbb] = param_6;
  param_1[0xbbc] = param_7;
  param_1[0xbbd] = param_8;
  param_1[0xbbe] = param_9;
  param_1[1] = param_2;
  param_1[2] = param_2 - 1;
  if ((param_2 & param_2 - 1) != 0) {
    return 0;
  }
  bVar1 = FUN_01007850(param_1);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    return 0;
  }
  FUN_010077b0((int)param_1);
  return 1;
}



void __cdecl FUN_010077a0(int *param_1)

{
  FUN_010078b0(param_1);
  return;
}



void __cdecl FUN_010077b0(int param_1)

{
  FUN_010078d0(param_1);
  FUN_01007930(param_1);
  FUN_01007980(param_1);
  *(undefined4 *)(param_1 + 0x2ecc) = 0;
  return;
}



undefined4 __cdecl
FUN_010077e0(int *param_1,int param_2,int param_3,int param_4,int param_5,undefined4 param_6,
            uint *param_7)

{
  uint uVar1;
  
  param_1[0xac1] = param_3;
  param_1[0xac3] = param_5;
  param_1[0xac2] = param_3 + param_4 + 4;
  FUN_01007ce0((int)param_1);
  uVar1 = FUN_010079c0(param_1,param_2);
  param_1[0xbb3] = param_1[0xbb3] + 1;
  if ((int)uVar1 < 0) {
    *param_7 = 0;
    return 1;
  }
  *param_7 = uVar1;
  param_1[0xac4] = param_1[0xac4] + uVar1;
  return 0;
}



bool __cdecl FUN_01007850(int *param_1)

{
  byte bVar1;
  int iVar2;
  uint uVar3;
  
  uVar3 = 4;
  *(undefined *)((int)param_1 + 0x2eb5) = 4;
  do {
    bVar1 = *(byte *)((int)param_1 + 0x2eb5);
    *(byte *)((int)param_1 + 0x2eb5) = bVar1 + 1;
    uVar3 = uVar3 + (1 << ((&DAT_010014c8)[bVar1] & 0x1f));
  } while (uVar3 < (uint)param_1[1]);
  iVar2 = (*(code *)param_1[3000])(param_1[1] + 0x105);
  *param_1 = iVar2;
  return (bool)('\x01' - (iVar2 == 0));
}



void __cdecl FUN_010078b0(int *param_1)

{
  if (*param_1 != 0) {
    (*(code *)param_1[0xbb9])(*param_1);
    *param_1 = 0;
  }
  return;
}



void __cdecl FUN_010078d0(int param_1)

{
  uint uVar1;
  int iVar2;
  undefined4 *puVar3;
  
  puVar3 = (undefined4 *)(param_1 + 0xa18);
  for (uVar1 = (uint)*(byte *)(param_1 + 0x2eb5) * 8 + 0x100 >> 2; uVar1 != 0; uVar1 = uVar1 - 1) {
    *puVar3 = 0;
    puVar3 = puVar3 + 1;
  }
  puVar3 = (undefined4 *)(param_1 + 0x2b14);
  for (uVar1 = (uint)*(byte *)(param_1 + 0x2eb5) * 8 + 0x100 >> 2; uVar1 != 0; uVar1 = uVar1 - 1) {
    *puVar3 = 0;
    puVar3 = puVar3 + 1;
  }
  puVar3 = (undefined4 *)(param_1 + 0xcb8);
  for (iVar2 = 0x3e; iVar2 != 0; iVar2 = iVar2 + -1) {
    *puVar3 = 0;
    puVar3 = puVar3 + 1;
  }
  *(undefined *)puVar3 = 0;
  puVar3 = (undefined4 *)(param_1 + 0x2db4);
  for (iVar2 = 0x3e; iVar2 != 0; iVar2 = iVar2 + -1) {
    *puVar3 = 0;
    puVar3 = puVar3 + 1;
  }
  *(undefined *)puVar3 = 0;
  return;
}



void __cdecl FUN_01007930(int param_1)

{
  *(undefined4 *)(param_1 + 0xc) = 1;
  *(undefined4 *)(param_1 + 0x10) = 1;
  *(undefined4 *)(param_1 + 0x14) = 1;
  *(undefined4 *)(param_1 + 0x2ec0) = 0;
  *(undefined4 *)(param_1 + 0x2b10) = 0;
  *(undefined4 *)(param_1 + 0x2edc) = 1;
  *(undefined4 *)(param_1 + 0x2ed4) = 0;
  *(undefined4 *)(param_1 + 0x2ed8) = 0;
  *(undefined4 *)(param_1 + 0x2eb8) = 1;
  *(undefined4 *)(param_1 + 0x2ec4) = 0;
  *(undefined4 *)(param_1 + 0x2ebc) = 0;
  return;
}



void __cdecl FUN_01007980(int param_1)

{
  *(undefined4 *)(param_1 + 0x2ec8) = 0;
  return;
}



void __cdecl FUN_01007990(int param_1,undefined4 param_2,int param_3)

{
  undefined8 uVar1;
  
  uVar1 = FUN_01007de4(param_2,*(undefined4 *)(param_1 + 0x2ec4),*(char **)(param_1 + 0x2ec8),
                       *(undefined4 *)(param_1 + 0x2ec4),(char *)param_2,param_3);
  *(int *)(param_1 + 0x2ec8) = (int)uVar1;
  return;
}



uint __cdecl FUN_010079c0(int *param_1,int param_2)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  int *piVar6;
  int *piVar7;
  uint local_4;
  
  local_4 = 0;
  if (0 < param_2) {
    do {
      if (param_1[2999] == 1) {
        if (param_1[0xbae] != 0) {
          param_1[0xbae] = 0;
          uVar1 = FUN_01007dc0((int)param_1,1);
          if (uVar1 == 0) {
            param_1[0xbb1] = 0;
          }
          else {
            uVar1 = FUN_01007dc0((int)param_1,0x10);
            uVar2 = FUN_01007dc0((int)param_1,0x10);
            param_1[0xbb1] = uVar1 << 0x10 | uVar2;
          }
        }
        if (param_1[0xbb6] == 3) {
          if (((*(byte *)(param_1 + 0xbb4) & 1) != 0) &&
             (uVar1 = param_1[0xac1], uVar1 <= (uint)param_1[0xac2] && param_1[0xac2] != uVar1)) {
            param_1[0xac1] = uVar1 + 1;
          }
          param_1[0xbb6] = 0;
          FUN_01007c90((int)param_1);
        }
        uVar1 = FUN_01007dc0((int)param_1,3);
        param_1[0xbb6] = uVar1;
        uVar1 = FUN_01007dc0((int)param_1,8);
        uVar2 = FUN_01007dc0((int)param_1,8);
        uVar3 = FUN_01007dc0((int)param_1,8);
        iVar4 = uVar3 + (uVar1 * 0x100 + uVar2) * 0x100;
        param_1[0xbb4] = iVar4;
        param_1[0xbb5] = iVar4;
        if (param_1[0xbb6] == 2) {
          FUN_01008250((int)param_1);
        }
        iVar4 = param_1[0xbb6];
        if ((iVar4 == 1) || (iVar4 == 2)) {
          piVar6 = param_1 + 0x286;
          piVar7 = param_1 + 0xac5;
          for (uVar1 = (uint)*(byte *)((int)param_1 + 0x2eb5) * 8 + 0x100 >> 2; uVar1 != 0;
              uVar1 = uVar1 - 1) {
            *piVar7 = *piVar6;
            piVar6 = piVar6 + 1;
            piVar7 = piVar7 + 1;
          }
          piVar6 = param_1 + 0x32e;
          piVar7 = param_1 + 0xb6d;
          for (iVar4 = 0x3e; iVar4 != 0; iVar4 = iVar4 + -1) {
            *piVar7 = *piVar6;
            piVar6 = piVar6 + 1;
            piVar7 = piVar7 + 1;
          }
          *(undefined *)piVar7 = *(undefined *)piVar6;
          FUN_01007f00((int)param_1);
        }
        else {
          if (iVar4 != 3) {
            return 0xffffffff;
          }
          iVar4 = FUN_01008320((int)param_1);
          if (iVar4 == 0) {
            return 0xffffffff;
          }
        }
        param_1[2999] = 2;
      }
      iVar4 = param_1[0xbb5];
      if (0 < iVar4) {
        do {
          if (param_2 < 1) break;
          iVar4 = param_1[0xbb5];
          if (param_2 <= param_1[0xbb5]) {
            iVar4 = param_2;
          }
          if (iVar4 == 0) {
            return 0xffffffff;
          }
          iVar5 = FUN_01007c20(param_1,param_1[0xbb6],param_1[0xbb0],iVar4);
          if (iVar5 != 0) {
            return 0xffffffff;
          }
          iVar5 = param_1[0xbb5];
          param_2 = param_2 - iVar4;
          local_4 = local_4 + iVar4;
          param_1[0xbb5] = iVar5 - iVar4;
        } while (0 < iVar5 - iVar4);
        iVar4 = param_1[0xbb5];
      }
      if (iVar4 == 0) {
        param_1[2999] = 1;
      }
      if (param_2 == 0) {
        FUN_01007c90((int)param_1);
      }
    } while (0 < param_2);
  }
  iVar4 = param_1[0xbb0];
  if (iVar4 == 0) {
    iVar4 = param_1[1];
  }
  FUN_01007eb0((int)param_1,local_4,(undefined4 *)((iVar4 - local_4) + *param_1));
  return local_4;
}



int __cdecl FUN_01007c20(int *param_1,int param_2,uint param_3,int param_4)

{
  int iVar1;
  
  if (param_2 == 2) {
    iVar1 = FUN_01008a00(param_1,param_3,param_4);
    return iVar1;
  }
  if (param_2 == 1) {
    iVar1 = FUN_01008390(param_3,param_1,param_1,param_3,param_4);
    return iVar1;
  }
  if (param_2 == 3) {
    iVar1 = FUN_010082a0(param_1,param_3,param_4);
    return iVar1;
  }
  return -1;
}



void __cdecl FUN_01007c90(int param_1)

{
  byte bVar1;
  byte bVar2;
  byte bVar3;
  byte bVar4;
  byte *pbVar5;
  
  if (*(int *)(param_1 + 0x2ed8) != 3) {
    pbVar5 = *(byte **)(param_1 + 0x2b04);
    bVar1 = pbVar5[1];
    bVar2 = pbVar5[3];
    bVar3 = pbVar5[2];
    bVar4 = *pbVar5;
    *(byte **)(param_1 + 0x2b04) = pbVar5 + 4;
    *(undefined *)(param_1 + 0x2eb4) = 0x10;
    *(uint *)(param_1 + 0x2eb0) =
         ((uint)bVar1 << 0x10 | (uint)bVar2) << 8 | (uint)bVar3 | (uint)bVar4 << 0x10;
  }
  return;
}



void __cdecl FUN_01007ce0(int param_1)

{
  FUN_01007c90(param_1);
  return;
}



void __cdecl FUN_01007cf0(int param_1,byte param_2)

{
  ushort *puVar1;
  ushort uVar2;
  char cVar3;
  char cVar4;
  uint uVar5;
  ushort *puVar6;
  
  uVar5 = *(int *)(param_1 + 0x2eb0) << (param_2 & 0x1f);
  cVar3 = *(char *)(param_1 + 0x2eb4) - param_2;
  *(uint *)(param_1 + 0x2eb0) = uVar5;
  *(char *)(param_1 + 0x2eb4) = cVar3;
  if (cVar3 < '\x01') {
    puVar1 = *(ushort **)(param_1 + 0x2b04);
    if (*(ushort **)(param_1 + 0x2b08) <= puVar1) {
      *(undefined4 *)(param_1 + 0x2ebc) = 1;
      return;
    }
    uVar2 = *puVar1;
    puVar6 = puVar1 + 1;
    *(ushort **)(param_1 + 0x2b04) = puVar6;
    cVar4 = cVar3 + '\x10';
    uVar5 = (uint)uVar2 << (-cVar3 & 0x1fU) | uVar5;
    *(char *)(param_1 + 0x2eb4) = cVar4;
    *(uint *)(param_1 + 0x2eb0) = uVar5;
    if (cVar4 < '\x01') {
      if (*(ushort **)(param_1 + 0x2b08) <= puVar6) {
        *(undefined4 *)(param_1 + 0x2ebc) = 1;
        return;
      }
      uVar2 = *puVar6;
      *(ushort **)(param_1 + 0x2b04) = puVar1 + 2;
      *(char *)(param_1 + 0x2eb4) = cVar3 + ' ';
      *(uint *)(param_1 + 0x2eb0) = (uint)uVar2 << (-cVar4 & 0x1fU) | uVar5;
    }
  }
  return;
}



uint __cdecl FUN_01007dc0(int param_1,byte param_2)

{
  uint uVar1;
  
  uVar1 = *(uint *)(param_1 + 0x2eb0);
  FUN_01007cf0(param_1,param_2);
  return uVar1 >> (0x20 - param_2 & 0x1f);
}



undefined8 __fastcall
FUN_01007de4(undefined4 param_1,undefined4 param_2,char *param_3,uint param_4,char *param_5,
            int param_6)

{
  undefined2 uVar1;
  undefined4 uVar2;
  uint uVar3;
  undefined4 *puVar4;
  char *pcVar5;
  char *pcVar6;
  char *pcVar7;
  char *pcVar8;
  
  if (param_6 < 6) {
    return CONCAT44(param_2,param_3 + param_6);
  }
  pcVar8 = param_3 + param_6;
  puVar4 = (undefined4 *)(param_5 + param_6 + -6);
  uVar2 = *puVar4;
  uVar1 = *(undefined2 *)(param_5 + param_6 + -2);
  *puVar4 = 0xe8e8e8e8;
  *(undefined2 *)(param_5 + param_6 + -2) = 0xe8e8;
  pcVar6 = param_5;
  pcVar5 = param_5;
  do {
    while (*pcVar5 == -0x18) {
LAB_01007e63:
      pcVar7 = pcVar5 + ((int)param_3 - (int)pcVar6);
      if ((int)(pcVar8 + -6) <= (int)pcVar7) {
        *puVar4 = uVar2;
        *(undefined2 *)(param_5 + param_6 + -2) = uVar1;
        return CONCAT44(param_2,pcVar8);
      }
      uVar3 = *(uint *)(pcVar5 + 1);
      pcVar6 = pcVar5 + 5;
      if (uVar3 < param_4) {
        *(int *)(pcVar5 + 1) = *(int *)(pcVar5 + 1) - (int)pcVar7;
        param_3 = pcVar7 + 5;
        pcVar5 = pcVar6;
      }
      else {
        if ((char *)-uVar3 < pcVar7 || -(int)pcVar7 == uVar3) {
          *(uint *)(pcVar5 + 1) = *(int *)(pcVar5 + 1) + param_4;
        }
        param_3 = pcVar7 + 5;
        pcVar5 = pcVar6;
      }
    }
    if (pcVar5[1] == -0x18) {
      pcVar5 = pcVar5 + 1;
      goto LAB_01007e63;
    }
    if (pcVar5[2] == -0x18) {
      pcVar5 = pcVar5 + 2;
      goto LAB_01007e63;
    }
    if (pcVar5[3] == -0x18) {
      pcVar5 = pcVar5 + 3;
      goto LAB_01007e63;
    }
    pcVar5 = pcVar5 + 4;
  } while( true );
}



void __cdecl FUN_01007eb0(int param_1,uint param_2,undefined4 *param_3)

{
  uint uVar1;
  undefined4 *puVar2;
  
  puVar2 = *(undefined4 **)(param_1 + 0x2b0c);
  for (uVar1 = param_2 >> 2; uVar1 != 0; uVar1 = uVar1 - 1) {
    *puVar2 = *param_3;
    param_3 = param_3 + 1;
    puVar2 = puVar2 + 1;
  }
  for (uVar1 = param_2 & 3; uVar1 != 0; uVar1 = uVar1 - 1) {
    *(undefined *)puVar2 = *(undefined *)param_3;
    param_3 = (undefined4 *)((int)param_3 + 1);
    puVar2 = (undefined4 *)((int)puVar2 + 1);
  }
  if ((*(int *)(param_1 + 0x2ec4) != 0) && (*(uint *)(param_1 + 0x2ecc) < 0x8000)) {
    FUN_01007990(param_1,*(undefined4 *)(param_1 + 0x2b0c),param_2);
  }
  return;
}



bool __cdecl FUN_01007f00(int param_1)

{
  int iVar1;
  bool bVar2;
  undefined3 extraout_var;
  undefined3 extraout_var_00;
  undefined3 extraout_var_01;
  undefined4 extraout_EDX;
  undefined4 extraout_EDX_00;
  undefined8 uVar3;
  
  bVar2 = FUN_01007fe0(param_1,0x100,param_1 + 0x2b14,param_1 + 0xa18);
  if (CONCAT31(extraout_var,bVar2) == 0) {
    return false;
  }
  bVar2 = FUN_01007fe0(param_1,(uint)*(byte *)(param_1 + 0x2eb5) << 3,param_1 + 0x2c14,
                       param_1 + 0xb18);
  if (CONCAT31(extraout_var_00,bVar2) == 0) {
    return false;
  }
  iVar1 = (uint)*(byte *)(param_1 + 0x2eb5) * 8 + 0x100;
  uVar3 = FUN_01008dbc(iVar1,extraout_EDX,param_1,iVar1,param_1 + 0xa18,10,
                       (undefined4 *)(param_1 + 0x18),param_1 + 0xe3c);
  if ((int)uVar3 == 0) {
    return false;
  }
  bVar2 = FUN_01007fe0(param_1,0xf9,param_1 + 0x2db4,param_1 + 0xcb8);
  if (CONCAT31(extraout_var_01,bVar2) == 0) {
    return false;
  }
  uVar3 = FUN_01008dbc(param_1 + 0x818,extraout_EDX_00,param_1,0xf9,param_1 + 0xcb8,8,
                       (undefined4 *)(param_1 + 0x818),param_1 + 0x233c);
  return (bool)('\x01' - ((int)uVar3 == 0));
}



bool __cdecl FUN_01007fe0(int param_1,int param_2,int param_3,int param_4)

{
  undefined uVar1;
  uint uVar2;
  short sVar3;
  int iVar4;
  int iVar5;
  byte local_2d4 [24];
  short local_2bc [94];
  short local_200 [256];
  
  iVar5 = 0;
  do {
    iVar4 = iVar5 + 1;
    uVar2 = FUN_01007dc0(param_1,4);
    local_2d4[iVar5] = (byte)uVar2;
    iVar5 = iVar4;
  } while (iVar4 < 0x14);
  if (*(int *)(param_1 + 0x2ebc) != 0) {
    return false;
  }
  iVar5 = 0;
  FUN_01008dbc(local_200,local_2d4,param_1,0x14,(int)local_2d4,8,(undefined4 *)local_200,
               (int)local_2bc);
  if (0 < param_2) {
    do {
      sVar3 = *(short *)((int)local_200 + ((*(uint *)(param_1 + 0x2eb0) & 0xff7fffff) >> 0x17));
      if (sVar3 < 0) {
        uVar2 = 0x800000;
        do {
          if ((uVar2 & *(uint *)(param_1 + 0x2eb0)) == 0) {
            sVar3 = local_2bc[-sVar3 * 2];
          }
          else {
            sVar3 = local_2bc[-sVar3 * 2 + 1];
          }
          uVar2 = uVar2 >> 1;
        } while (sVar3 < 0);
      }
      FUN_01007cf0(param_1,local_2d4[sVar3]);
      if (*(int *)(param_1 + 0x2ebc) != 0) {
        return false;
      }
      if (sVar3 == 0x11) {
        uVar2 = FUN_01007dc0(param_1,4);
        iVar4 = (uVar2 & 0xff) + 4;
        if (param_2 <= (int)(iVar5 + 4 + (uVar2 & 0xff))) {
          iVar4 = param_2 - iVar5;
        }
        for (; 0 < iVar4; iVar4 = iVar4 + -1) {
          *(undefined *)(iVar5 + param_4) = 0;
          iVar5 = iVar5 + 1;
        }
        iVar5 = iVar5 + -1;
      }
      else if (sVar3 == 0x12) {
        uVar2 = FUN_01007dc0(param_1,5);
        iVar4 = (uVar2 & 0xff) + 0x14;
        if (param_2 <= (int)(iVar5 + 0x14 + (uVar2 & 0xff))) {
          iVar4 = param_2 - iVar5;
        }
        for (; 0 < iVar4; iVar4 = iVar4 + -1) {
          *(undefined *)(iVar5 + param_4) = 0;
          iVar5 = iVar5 + 1;
        }
        iVar5 = iVar5 + -1;
      }
      else if (sVar3 == 0x13) {
        uVar2 = FUN_01007dc0(param_1,1);
        iVar4 = (uVar2 & 0xff) + 4;
        if (param_2 <= (int)(iVar5 + 4 + (uVar2 & 0xff))) {
          iVar4 = param_2 - iVar5;
        }
        sVar3 = *(short *)((int)local_200 + ((*(uint *)(param_1 + 0x2eb0) & 0xff7fffff) >> 0x17));
        if (sVar3 < 0) {
          uVar2 = 0x800000;
          do {
            if ((uVar2 & *(uint *)(param_1 + 0x2eb0)) == 0) {
              sVar3 = local_2bc[-sVar3 * 2];
            }
            else {
              sVar3 = local_2bc[-sVar3 * 2 + 1];
            }
            uVar2 = uVar2 >> 1;
          } while (sVar3 < 0);
        }
        FUN_01007cf0(param_1,local_2d4[sVar3]);
        uVar1 = (&DAT_010015e1)[(uint)*(byte *)(iVar5 + param_3) - (int)sVar3];
        for (; 0 < iVar4; iVar4 = iVar4 + -1) {
          *(undefined *)(iVar5 + param_4) = uVar1;
          iVar5 = iVar5 + 1;
        }
        iVar5 = iVar5 + -1;
      }
      else {
        *(undefined *)(iVar5 + param_4) =
             (&DAT_010015e1)[(uint)*(byte *)(iVar5 + param_3) - (int)sVar3];
      }
      iVar5 = iVar5 + 1;
    } while (iVar5 < param_2);
  }
  return *(int *)(param_1 + 0x2ebc) == 0;
}



bool __cdecl FUN_01008250(int param_1)

{
  uint uVar1;
  int iVar2;
  
  iVar2 = 0;
  do {
    iVar2 = iVar2 + 1;
    uVar1 = FUN_01007dc0(param_1,3);
    *(char *)(param_1 + 0xe33 + iVar2) = (char)uVar1;
  } while (iVar2 < 8);
  if (*(int *)(param_1 + 0x2ebc) != 0) {
    return false;
  }
  iVar2 = FUN_01009040(param_1,param_1 + 0xe34,(undefined4 *)(param_1 + 0xdb4));
  return (bool)('\x01' - (iVar2 == 0));
}



int __cdecl FUN_010082a0(int *param_1,uint param_2,int param_3)

{
  undefined uVar1;
  uint uVar2;
  undefined *puVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  
  uVar2 = param_3 + param_2;
  puVar3 = (undefined *)param_1[0xac1];
  uVar5 = param_2;
  if ((int)param_2 < (int)uVar2) {
    do {
      if ((undefined *)param_1[0xac2] < puVar3 || (undefined *)param_1[0xac2] == puVar3) {
        return -1;
      }
      uVar1 = *puVar3;
      puVar3 = puVar3 + 1;
      uVar5 = uVar5 + 1;
      *(undefined *)(*param_1 + -1 + uVar5) = uVar1;
    } while ((int)uVar5 < (int)uVar2);
  }
  param_1[0xac1] = (int)puVar3;
  uVar4 = uVar2;
  if (0x100 < (int)uVar2) {
    uVar4 = 0x101;
  }
  if (param_2 < uVar4) {
    do {
      uVar6 = param_2 + 1;
      *(undefined *)(param_1[1] + *param_1 + -1 + uVar6) = *(undefined *)(param_2 + *param_1);
      param_2 = uVar6;
    } while (uVar6 < uVar4);
  }
  param_1[0xbb0] = uVar5 & param_1[2];
  return uVar5 - uVar2;
}



undefined4 __cdecl FUN_01008320(int param_1)

{
  byte *pbVar1;
  uint *puVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0x2b04);
  *(int *)(param_1 + 0x2b04) = iVar3 + -2;
  if (*(uint *)(param_1 + 0x2b08) <= iVar3 + 2U) {
    return 0;
  }
  iVar3 = 3;
  puVar2 = (uint *)(param_1 + 0xc);
  do {
    pbVar1 = *(byte **)(param_1 + 0x2b04);
    *puVar2 = ((uint)pbVar1[3] << 0x10 | (uint)pbVar1[1]) << 8 | (uint)pbVar1[2] << 0x10 |
              (uint)*pbVar1;
    *(int *)(param_1 + 0x2b04) = *(int *)(param_1 + 0x2b04) + 4;
    iVar3 = iVar3 + -1;
    puVar2 = puVar2 + 1;
  } while (iVar3 != 0);
  return 1;
}



int __fastcall
FUN_01008390(undefined4 param_1,undefined4 param_2,int *param_3,uint param_4,int param_5)

{
  int iVar1;
  uint uVar2;
  undefined4 extraout_ECX;
  undefined4 extraout_EDX;
  undefined8 uVar3;
  
  if ((int)param_4 < 0x101) {
    iVar1 = 0x101 - param_4;
    if (param_5 <= (int)(0x101 - param_4)) {
      iVar1 = param_5;
    }
    uVar2 = FUN_010083f0(param_3,param_4,iVar1);
    param_5 = (param_5 - uVar2) + param_4;
    param_3[0xbb0] = uVar2;
    param_1 = extraout_ECX;
    param_2 = extraout_EDX;
    param_4 = uVar2;
    if (param_5 < 1) {
      return param_5;
    }
  }
  uVar3 = FUN_010091d3(param_1,param_2,param_3,param_4,param_5);
  return (int)uVar3;
}



int __cdecl FUN_010083f0(int *param_1,int param_2,int param_3)

{
  char cVar1;
  short sVar2;
  ushort *puVar3;
  ushort uVar4;
  byte bVar5;
  int iVar6;
  uint uVar7;
  char cVar8;
  int iVar9;
  ushort *puVar10;
  ushort *puVar11;
  uint uVar12;
  int iVar13;
  char local_11;
  uint local_10;
  
  local_11 = *(char *)(param_1 + 0xbad);
  local_10 = param_1[0xbac];
  puVar11 = (ushort *)param_1[0xac1];
  puVar3 = (ushort *)param_1[0xac2];
  iVar6 = param_3 + param_2;
  if (param_2 < iVar6) {
    do {
      iVar9 = (int)*(short *)(((local_10 & 0xffdfffff) >> 0x15) + 0x18 + (int)param_1);
      if (iVar9 < 0) {
        uVar7 = 0x200000;
        do {
          if ((local_10 & uVar7) == 0) {
            sVar2 = *(short *)(param_1 + (0x38f - iVar9));
          }
          else {
            sVar2 = *(short *)((int)param_1 + iVar9 * -4 + 0xe3e);
          }
          iVar9 = (int)sVar2;
          uVar7 = uVar7 >> 1;
        } while (iVar9 < 0);
      }
      if (puVar3 <= puVar11) {
        return -1;
      }
      bVar5 = *(byte *)(iVar9 + 0xa18 + (int)param_1);
      local_10 = local_10 << (bVar5 & 0x1f);
      local_11 = local_11 - bVar5;
      if (local_11 < '\x01') {
        uVar4 = *puVar11;
        puVar11 = puVar11 + 1;
        bVar5 = -local_11;
        local_11 = local_11 + '\x10';
        local_10 = local_10 | (uint)uVar4 << (bVar5 & 0x1f);
      }
      uVar7 = iVar9 - 0x100;
      if ((int)uVar7 < 0) {
        param_2 = param_2 + 1;
        *(char *)(*param_1 + -1 + param_2) = (char)uVar7;
        *(char *)(param_1[1] + *param_1 + -1 + param_2) = (char)uVar7;
      }
      else {
        uVar12 = uVar7 & 7;
        if (uVar12 == 7) {
          iVar9 = (int)*(short *)(((local_10 & 0xff7fffff) >> 0x17) + 0x818 + (int)param_1);
          if (iVar9 < 0) {
            uVar12 = 0x800000;
            do {
              if ((local_10 & uVar12) == 0) {
                sVar2 = *(short *)(param_1 + (0x8cf - iVar9));
              }
              else {
                sVar2 = *(short *)((int)param_1 + iVar9 * -4 + 0x233e);
              }
              iVar9 = (int)sVar2;
              uVar12 = uVar12 >> 1;
            } while (iVar9 < 0);
          }
          bVar5 = *(byte *)(iVar9 + 0xcb8 + (int)param_1);
          local_10 = local_10 << (bVar5 & 0x1f);
          local_11 = local_11 - bVar5;
          if (local_11 < '\x01') {
            uVar4 = *puVar11;
            puVar11 = puVar11 + 1;
            bVar5 = -local_11;
            local_11 = local_11 + '\x10';
            local_10 = local_10 | (uint)uVar4 << (bVar5 & 0x1f);
          }
          uVar12 = iVar9 + 7;
        }
        cVar8 = (char)((int)uVar7 >> 3);
        if (cVar8 < '\x03') {
          iVar9 = param_1[cVar8 + 3];
          if (cVar8 != '\0') {
            param_1[cVar8 + 3] = param_1[3];
            goto LAB_01008612;
          }
        }
        else {
          if (cVar8 < '\x04') {
            iVar9 = 1;
          }
          else {
            bVar5 = (&DAT_010014c8)[cVar8];
            cVar1 = local_11 - bVar5;
            uVar7 = local_10 >> (0x20 - bVar5 & 0x1f);
            local_10 = local_10 << (bVar5 & 0x1f);
            puVar10 = puVar11;
            local_11 = cVar1;
            if (cVar1 < '\x01') {
              puVar10 = puVar11 + 1;
              local_11 = cVar1 + '\x10';
              local_10 = local_10 | (uint)*puVar11 << (-cVar1 & 0x1fU);
              if (local_11 < '\x01') {
                uVar4 = *puVar10;
                puVar10 = puVar11 + 2;
                bVar5 = -local_11;
                local_11 = cVar1 + ' ';
                local_10 = local_10 | (uint)uVar4 << (bVar5 & 0x1f);
              }
            }
            iVar9 = uVar7 + *(int *)(&DAT_01001500 + cVar8 * 4);
            puVar11 = puVar10;
          }
          param_1[5] = param_1[4];
          param_1[4] = param_1[3];
LAB_01008612:
          param_1[3] = iVar9;
        }
        iVar13 = uVar12 + 2;
        do {
          *(undefined *)(*param_1 + param_2) =
               *(undefined *)((param_2 - iVar9 & param_1[2]) + *param_1);
          if (param_2 < 0x101) {
            *(undefined *)(param_1[1] + *param_1 + param_2) = *(undefined *)(*param_1 + param_2);
          }
          param_2 = param_2 + 1;
          iVar13 = iVar13 + -1;
        } while (0 < iVar13);
      }
    } while (param_2 < iVar6);
  }
  *(char *)(param_1 + 0xbad) = local_11;
  param_1[0xbac] = local_10;
  param_1[0xac1] = (int)puVar11;
  return param_2;
}



int __cdecl FUN_01008680(int *param_1,uint param_2,int param_3)

{
  short sVar1;
  ushort *puVar2;
  int iVar3;
  ushort uVar4;
  int iVar5;
  int iVar6;
  byte bVar7;
  uint uVar8;
  char cVar9;
  char cVar10;
  uint uVar11;
  uint local_20;
  ushort *local_1c;
  int local_14;
  uint local_10;
  
  cVar9 = *(char *)(param_1 + 0xbad);
  local_20 = param_1[0xbac];
  local_1c = (ushort *)param_1[0xac1];
  puVar2 = (ushort *)param_1[0xac2];
  iVar3 = *param_1;
  iVar5 = param_3 + param_2;
  if ((int)param_2 < iVar5) {
    do {
      iVar6 = (int)*(short *)(((local_20 & 0xffdfffff) >> 0x15) + 0x18 + (int)param_1);
      if (iVar6 < 0) {
        uVar8 = 0x200000;
        do {
          if ((local_20 & uVar8) == 0) {
            sVar1 = *(short *)(param_1 + (0x38f - iVar6));
          }
          else {
            sVar1 = *(short *)((int)param_1 + iVar6 * -4 + 0xe3e);
          }
          iVar6 = (int)sVar1;
          uVar8 = uVar8 >> 1;
        } while (iVar6 < 0);
      }
      if (puVar2 <= local_1c) {
        return -1;
      }
      bVar7 = *(byte *)(iVar6 + 0xa18 + (int)param_1);
      local_20 = local_20 << (bVar7 & 0x1f);
      cVar9 = cVar9 - bVar7;
      if (cVar9 < '\x01') {
        bVar7 = -cVar9;
        cVar9 = cVar9 + '\x10';
        local_20 = local_20 | (uint)*local_1c << (bVar7 & 0x1f);
        local_1c = local_1c + 1;
      }
      uVar8 = iVar6 - 0x100;
      if ((int)uVar8 < 0) {
        *(char *)(iVar3 + param_2) = (char)uVar8;
        param_2 = param_2 + 1;
      }
      else {
        uVar11 = uVar8 & 7;
        if (uVar11 == 7) {
          iVar6 = (int)*(short *)(((local_20 & 0xff7fffff) >> 0x17) + 0x818 + (int)param_1);
          if (iVar6 < 0) {
            uVar11 = 0x800000;
            do {
              if ((local_20 & uVar11) == 0) {
                sVar1 = *(short *)(param_1 + (0x8cf - iVar6));
              }
              else {
                sVar1 = *(short *)((int)param_1 + iVar6 * -4 + 0x233e);
              }
              iVar6 = (int)sVar1;
              uVar11 = uVar11 >> 1;
            } while (iVar6 < 0);
          }
          bVar7 = *(byte *)(iVar6 + 0xcb8 + (int)param_1);
          local_20 = local_20 << (bVar7 & 0x1f);
          cVar9 = cVar9 - bVar7;
          if (cVar9 < '\x01') {
            uVar4 = *local_1c;
            bVar7 = -cVar9;
            cVar9 = cVar9 + '\x10';
            local_1c = local_1c + 1;
            local_20 = local_20 | (uint)uVar4 << (bVar7 & 0x1f);
          }
          uVar11 = iVar6 + 7;
        }
        cVar10 = (char)((int)uVar8 >> 3);
        if (cVar10 < '\x03') {
          local_14 = param_1[cVar10 + 3];
          if (cVar10 != '\0') {
            param_1[cVar10 + 3] = param_1[3];
            param_1[3] = local_14;
          }
        }
        else {
          iVar6 = (int)cVar10;
          bVar7 = (&DAT_010014c8)[iVar6];
          if (bVar7 < 3) {
            if (bVar7 == 0) {
              local_14 = *(int *)(&DAT_01001500 + iVar6 * 4);
            }
            else {
              cVar9 = cVar9 - bVar7;
              uVar8 = local_20 >> (0x20 - bVar7 & 0x1f);
              local_20 = local_20 << (bVar7 & 0x1f);
              if (cVar9 < '\x01') {
                bVar7 = -cVar9;
                cVar9 = cVar9 + '\x10';
                local_20 = local_20 | (uint)*local_1c << (bVar7 & 0x1f);
                local_1c = local_1c + 1;
              }
              local_14 = uVar8 + *(int *)(&DAT_01001500 + iVar6 * 4);
            }
          }
          else {
            if (bVar7 == 3) {
              local_10 = 0;
            }
            else {
              cVar10 = cVar9 - bVar7;
              local_10 = local_20 >> (0x23 - bVar7 & 0x1f);
              cVar9 = cVar10 + '\x03';
              local_20 = local_20 << (bVar7 - 3 & 0x1f);
              if (cVar9 < '\x01') {
                bVar7 = -cVar9;
                cVar9 = cVar10 + '\x13';
                local_20 = local_20 | (uint)*local_1c << (bVar7 & 0x1f);
                local_1c = local_1c + 1;
              }
            }
            local_14 = (int)*(char *)((local_20 >> 0x19) + 0xdb4 + (int)param_1);
            bVar7 = *(byte *)(local_14 + 0xe34 + (int)param_1);
            local_20 = local_20 << (bVar7 & 0x1f);
            cVar9 = cVar9 - bVar7;
            if (cVar9 < '\x01') {
              bVar7 = -cVar9;
              cVar9 = cVar9 + '\x10';
              local_20 = local_20 | (uint)*local_1c << (bVar7 & 0x1f);
              local_1c = local_1c + 1;
            }
            local_14 = *(int *)(&DAT_01001500 + iVar6 * 4) + local_10 * 8 + local_14;
          }
          param_1[5] = param_1[4];
          param_1[4] = param_1[3];
          param_1[3] = local_14;
        }
        iVar6 = uVar11 + 2;
        uVar8 = param_2 - local_14 & param_1[2];
        do {
          uVar8 = uVar8 + 1;
          iVar6 = iVar6 + -1;
          uVar11 = param_2 + 1;
          *(undefined *)(iVar3 + param_2) = *(undefined *)(iVar3 + -1 + uVar8);
          param_2 = uVar11;
        } while (0 < iVar6);
      }
    } while ((int)param_2 < iVar5);
  }
  *(char *)(param_1 + 0xbad) = cVar9;
  param_1[0xbac] = local_20;
  param_1[0xac1] = (int)local_1c;
  param_1[0xbb0] = param_2 & param_1[2];
  return param_2 - iVar5;
}



int __cdecl FUN_01008a00(int *param_1,uint param_2,int param_3)

{
  uint uVar1;
  int iVar2;
  
  if ((int)param_2 < 0x101) {
    iVar2 = 0x101 - param_2;
    if (param_3 <= (int)(0x101 - param_2)) {
      iVar2 = param_3;
    }
    uVar1 = FUN_01008a60(param_1,param_2,iVar2);
    param_3 = (param_3 - uVar1) + param_2;
    param_1[0xbb0] = uVar1;
    param_2 = uVar1;
    if (param_3 < 1) {
      return param_3;
    }
  }
  iVar2 = FUN_01008680(param_1,param_2,param_3);
  return iVar2;
}



int __cdecl FUN_01008a60(int *param_1,int param_2,int param_3)

{
  undefined uVar1;
  short sVar2;
  ushort *puVar3;
  int iVar4;
  ushort uVar5;
  byte bVar6;
  int iVar7;
  uint uVar8;
  char cVar9;
  char cVar10;
  int iVar11;
  ushort *puVar12;
  uint uVar13;
  uint local_1c;
  uint local_18;
  int local_14;
  
  cVar10 = *(char *)(param_1 + 0xbad);
  local_18 = param_1[0xbac];
  puVar12 = (ushort *)param_1[0xac1];
  puVar3 = (ushort *)param_1[0xac2];
  iVar4 = *param_1;
  iVar7 = param_3 + param_2;
  if (param_2 < iVar7) {
    do {
      iVar11 = (int)*(short *)(((local_18 & 0xffdfffff) >> 0x15) + 0x18 + (int)param_1);
      if (iVar11 < 0) {
        uVar8 = 0x200000;
        do {
          if ((local_18 & uVar8) == 0) {
            sVar2 = *(short *)(param_1 + (0x38f - iVar11));
          }
          else {
            sVar2 = *(short *)((int)param_1 + iVar11 * -4 + 0xe3e);
          }
          iVar11 = (int)sVar2;
          uVar8 = uVar8 >> 1;
        } while (iVar11 < 0);
      }
      if (puVar3 <= puVar12) {
        return -1;
      }
      bVar6 = *(byte *)(iVar11 + 0xa18 + (int)param_1);
      local_18 = local_18 << (bVar6 & 0x1f);
      cVar9 = cVar10 - bVar6;
      cVar10 = cVar9;
      if (cVar9 < '\x01') {
        uVar5 = *puVar12;
        puVar12 = puVar12 + 1;
        cVar10 = cVar9 + '\x10';
        local_18 = local_18 | (uint)uVar5 << (-cVar9 & 0x1fU);
      }
      uVar8 = iVar11 - 0x100;
      if ((int)uVar8 < 0) {
        *(char *)(iVar4 + param_2) = (char)uVar8;
        iVar11 = param_1[1] + param_2;
        param_2 = param_2 + 1;
        *(char *)(iVar11 + iVar4) = (char)uVar8;
      }
      else {
        uVar13 = uVar8 & 7;
        if (uVar13 == 7) {
          iVar11 = (int)*(short *)(((local_18 & 0xff7fffff) >> 0x17) + 0x818 + (int)param_1);
          if (iVar11 < 0) {
            uVar13 = 0x800000;
            do {
              if ((local_18 & uVar13) == 0) {
                sVar2 = *(short *)(param_1 + (0x8cf - iVar11));
              }
              else {
                sVar2 = *(short *)((int)param_1 + iVar11 * -4 + 0x233e);
              }
              iVar11 = (int)sVar2;
              uVar13 = uVar13 >> 1;
            } while (iVar11 < 0);
          }
          bVar6 = *(byte *)(iVar11 + 0xcb8 + (int)param_1);
          local_18 = local_18 << (bVar6 & 0x1f);
          cVar9 = cVar10 - bVar6;
          cVar10 = cVar9;
          if (cVar9 < '\x01') {
            uVar5 = *puVar12;
            puVar12 = puVar12 + 1;
            cVar10 = cVar9 + '\x10';
            local_18 = local_18 | (uint)uVar5 << (-cVar9 & 0x1fU);
          }
          uVar13 = iVar11 + 7;
        }
        cVar9 = (char)((int)uVar8 >> 3);
        iVar11 = (int)cVar9;
        if (cVar9 < '\x03') {
          local_14 = param_1[iVar11 + 3];
          if (cVar9 != '\0') {
            param_1[iVar11 + 3] = param_1[3];
            param_1[3] = local_14;
          }
        }
        else {
          bVar6 = (&DAT_010014c8)[iVar11];
          if (bVar6 < 3) {
            if (bVar6 == 0) {
              local_14 = 1;
            }
            else {
              cVar10 = cVar10 - bVar6;
              uVar8 = local_18 >> (0x20 - bVar6 & 0x1f);
              local_18 = local_18 << (bVar6 & 0x1f);
              if (cVar10 < '\x01') {
                uVar5 = *puVar12;
                puVar12 = puVar12 + 1;
                bVar6 = -cVar10;
                cVar10 = cVar10 + '\x10';
                local_18 = local_18 | (uint)uVar5 << (bVar6 & 0x1f);
              }
              local_14 = uVar8 + *(int *)(&DAT_01001500 + iVar11 * 4);
            }
          }
          else {
            if (bVar6 == 3) {
              local_1c = 0;
            }
            else {
              cVar9 = cVar10 - bVar6;
              local_1c = local_18 >> (0x23 - bVar6 & 0x1f);
              cVar10 = cVar9 + '\x03';
              local_18 = local_18 << (bVar6 - 3 & 0x1f);
              if (cVar10 < '\x01') {
                uVar5 = *puVar12;
                puVar12 = puVar12 + 1;
                bVar6 = -cVar10;
                cVar10 = cVar9 + '\x13';
                local_18 = local_18 | (uint)uVar5 << (bVar6 & 0x1f);
              }
            }
            local_14 = (int)*(char *)((local_18 >> 0x19) + 0xdb4 + (int)param_1);
            bVar6 = *(byte *)(local_14 + 0xe34 + (int)param_1);
            local_18 = local_18 << (bVar6 & 0x1f);
            cVar10 = cVar10 - bVar6;
            if (cVar10 < '\x01') {
              uVar5 = *puVar12;
              puVar12 = puVar12 + 1;
              bVar6 = -cVar10;
              cVar10 = cVar10 + '\x10';
              local_18 = local_18 | (uint)uVar5 << (bVar6 & 0x1f);
            }
            local_14 = *(int *)(&DAT_01001500 + iVar11 * 4) + local_1c * 8 + local_14;
          }
          param_1[5] = param_1[4];
          param_1[4] = param_1[3];
          param_1[3] = local_14;
        }
        iVar11 = uVar13 + 2;
        do {
          uVar1 = *(undefined *)((param_2 - local_14 & param_1[2]) + iVar4);
          *(undefined *)(iVar4 + param_2) = uVar1;
          if (param_2 < 0x101) {
            *(undefined *)(param_1[1] + iVar4 + param_2) = uVar1;
          }
          param_2 = param_2 + 1;
          iVar11 = iVar11 + -1;
        } while (0 < iVar11);
      }
    } while (param_2 < iVar7);
  }
  *(char *)(param_1 + 0xbad) = cVar10;
  param_1[0xbac] = local_18;
  param_1[0xac1] = (int)puVar12;
  return param_2;
}



undefined8 __fastcall
FUN_01008dbc(undefined4 param_1,undefined4 param_2,undefined4 param_3,uint param_4,int param_5,
            uint param_6,undefined4 *param_7,int param_8)

{
  char cVar1;
  short *psVar2;
  undefined4 uVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  uint uVar7;
  uint uVar8;
  uint *puVar9;
  int *piVar10;
  undefined2 *puVar11;
  bool bVar12;
  uint auStack_118 [17];
  uint local_d4 [19];
  int aiStack_88 [18];
  uint local_40;
  int local_3c;
  int local_34;
  uint local_30;
  uint local_2c;
  undefined4 *local_28;
  uint local_24;
  int local_20;
  undefined4 local_1c;
  undefined4 uStack_c;
  
  local_40 = param_4 & 0xffff;
  local_1c = param_3;
  local_3c = param_5;
  local_24 = param_6 & 0xff;
  local_28 = param_7;
  local_34 = param_8;
  piVar10 = aiStack_88;
  uStack_c = param_2;
  for (iVar4 = 0x10; iVar6 = local_3c, piVar10 = piVar10 + 1, uVar5 = local_40, iVar4 != 0;
      iVar4 = iVar4 + -1) {
    *piVar10 = 0;
  }
  do {
    uVar5 = uVar5 - 1;
    aiStack_88[*(byte *)(uVar5 + iVar6)] = aiStack_88[*(byte *)(uVar5 + iVar6)] + 1;
  } while (0 < (int)uVar5);
  puVar9 = auStack_118 + 1;
  piVar10 = aiStack_88;
  uVar5 = 0;
  auStack_118[1] = 0;
  iVar4 = 0xf;
  do {
    piVar10 = piVar10 + 1;
    puVar9 = puVar9 + 1;
    uVar5 = (*piVar10 << ((byte)iVar4 & 0x1f)) + uVar5;
    *puVar9 = uVar5;
    uVar8 = local_24;
    bVar12 = 0 < iVar4;
    iVar4 = iVar4 + -1;
  } while (bVar12);
  if (local_d4[0] == 0x10000) {
    iVar4 = 1;
    uVar5 = 1 << ((byte)(local_24 - 1) & 0x1f);
    iVar6 = CONCAT31((int3)(local_24 - 1 >> 8),0x10) - local_24;
    local_20 = iVar6;
    do {
      auStack_118[iVar4] = auStack_118[iVar4] >> ((byte)iVar6 & 0x1f);
      local_d4[iVar4 + 1] = uVar5;
      uVar5 = uVar5 >> 1;
      iVar4 = iVar4 + 1;
    } while (iVar4 <= (int)uVar8);
    cVar1 = (char)iVar4;
    while (cVar1 < '\x11') {
      cVar1 = (char)iVar4;
      iVar4 = iVar4 + 1;
      local_d4[iVar4] = 1 << (0x10U - cVar1 & 0x1f);
      cVar1 = (char)iVar4;
    }
    uVar5 = auStack_118[local_24 + 1] >> ((byte)local_20 & 0x1f);
    if (uVar5 != 0x10000) {
      puVar11 = (undefined2 *)((int)local_28 + uVar5 * 2);
      for (iVar4 = (1 << ((byte)local_24 & 0x1f)) - uVar5; iVar4 != 0; iVar4 = iVar4 + -1) {
        *puVar11 = 0;
        puVar11 = puVar11 + 1;
      }
    }
    iVar4 = 0;
    local_30 = local_40;
LAB_01008f27:
    do {
      uVar5 = (uint)*(byte *)(iVar4 + local_3c);
      if (uVar5 != 0) {
        local_2c = auStack_118[uVar5];
        uVar8 = local_2c + local_d4[uVar5 + 1];
        if ((int)uVar5 <= (int)local_24) {
          if (1 << ((byte)local_24 & 0x1f) < (int)uVar8) {
            uVar3 = 0;
            goto LAB_01009001;
          }
          iVar6 = uVar8 - local_2c;
          psVar2 = (short *)(local_2c * 2 + (int)local_28);
          auStack_118[uVar5] = uVar8;
          do {
            *psVar2 = (short)iVar4;
            psVar2 = psVar2 + 1;
            iVar6 = iVar6 + -1;
          } while (iVar6 != 0);
          iVar4 = iVar4 + 1;
          if ((int)local_40 <= iVar4) {
            uVar3 = 1;
            goto LAB_01009001;
          }
          goto LAB_01008f27;
        }
        iVar6 = uVar5 - local_24;
        uVar7 = local_2c << ((byte)local_24 + 0x10 & 0x1f);
        auStack_118[uVar5] = uVar8;
        psVar2 = (short *)((int)local_28 + (local_2c >> ((byte)local_20 & 0x1f)) * 2);
        do {
          if (*psVar2 == 0) {
            *psVar2 = (short)local_30;
            *(undefined4 *)(local_34 + local_30 * 4) = 0;
            local_30 = local_30 + 1;
            *psVar2 = -*psVar2;
          }
          psVar2 = (short *)(local_34 + *psVar2 * -4);
          bVar12 = CARRY4(uVar7,uVar7);
          uVar7 = uVar7 * 2;
          if (bVar12) {
            psVar2 = psVar2 + 1;
          }
          iVar6 = iVar6 + -1;
        } while (iVar6 != 0);
        *psVar2 = (short)iVar4;
      }
      iVar4 = iVar4 + 1;
    } while (iVar4 < (int)local_40);
    uVar3 = 1;
  }
  else if (local_d4[0] == 0) {
    for (iVar4 = 1 << ((char)local_24 - 1U & 0x1f); iVar4 != 0; iVar4 = iVar4 + -1) {
      *local_28 = 0;
      local_28 = local_28 + 1;
    }
    uVar3 = 1;
  }
  else {
    uVar3 = 0;
  }
LAB_01009001:
  return CONCAT44(uStack_c,uVar3);
}



undefined4 __cdecl FUN_01009040(undefined4 param_1,int param_2,undefined4 *param_3)

{
  byte bVar1;
  ushort uVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  byte bVar6;
  ushort uVar7;
  undefined4 *puVar8;
  ushort auStack_48 [17];
  short local_26;
  short asStack_24 [18];
  
  uVar4 = 1;
  do {
    uVar2 = (short)uVar4 + 1;
    asStack_24[uVar4] = 0;
    uVar4 = (uint)uVar2;
  } while (uVar2 < 0x11);
  uVar4 = 0;
  do {
    uVar2 = (short)uVar4 + 1;
    asStack_24[*(byte *)(uVar4 + param_2)] = asStack_24[*(byte *)(uVar4 + param_2)] + 1;
    uVar4 = (uint)uVar2;
  } while (uVar2 < 8);
  auStack_48[1] = 0;
  uVar4 = 1;
  do {
    uVar2 = (short)uVar4 + 1;
    auStack_48[uVar4 + 1] = (asStack_24[uVar4] << (0x10U - (char)uVar4 & 0x1f)) + auStack_48[uVar4];
    uVar4 = (uint)uVar2;
  } while (uVar2 < 0x11);
  if (local_26 != 0) {
    return 0;
  }
  uVar4 = 1;
  do {
    uVar2 = (short)uVar4 + 1;
    uVar5 = (uint)uVar2;
    auStack_48[uVar4] = auStack_48[uVar4] >> 9;
    asStack_24[uVar4] = 1 << (7U - (char)uVar4 & 0x1f);
    uVar4 = uVar5;
  } while (uVar2 < 8);
  while (uVar2 < 0x11) {
    uVar2 = (short)uVar5 + 1;
    asStack_24[uVar5] = 1 << (0x10U - (char)uVar5 & 0x1f);
    uVar5 = (uint)uVar2;
  }
  bVar6 = 0;
  puVar8 = param_3;
  for (iVar3 = 0x20; iVar3 != 0; iVar3 = iVar3 + -1) {
    *puVar8 = 0;
    puVar8 = puVar8 + 1;
  }
  do {
    bVar1 = *(byte *)((uint)bVar6 + param_2);
    if (bVar1 != 0) {
      uVar2 = auStack_48[bVar1];
      uVar7 = asStack_24[bVar1] + uVar2;
      if (0x80 < uVar7) {
        return 0;
      }
      if (uVar2 < uVar7) {
        puVar8 = (undefined4 *)((int)param_3 + (uint)uVar2);
        for (uVar4 = (uint)((ushort)(uVar7 - uVar2) >> 2); uVar4 != 0; uVar4 = uVar4 - 1) {
          *puVar8 = CONCAT22(CONCAT11(bVar6,bVar6),CONCAT11(bVar6,bVar6));
          puVar8 = puVar8 + 1;
        }
        for (uVar4 = (ushort)(uVar7 - uVar2) & 3; uVar4 != 0; uVar4 = uVar4 - 1) {
          *(byte *)puVar8 = bVar6;
          puVar8 = (undefined4 *)((int)puVar8 + 1);
        }
      }
      auStack_48[bVar1] = uVar7;
    }
    bVar6 = bVar6 + 1;
  } while (bVar6 < 8);
  return 1;
}



undefined8 __fastcall
FUN_010091d3(undefined4 param_1,undefined4 param_2,int *param_3,uint param_4,int param_5)

{
  int iVar1;
  int iVar2;
  ushort uVar3;
  uint uVar4;
  uint uVar5;
  undefined4 uVar6;
  byte bVar7;
  byte bVar8;
  char cVar9;
  byte bVar10;
  int iVar11;
  uint uVar12;
  uint uVar13;
  ushort *puVar14;
  ushort *puVar15;
  uint uVar16;
  bool bVar17;
  uint local_38;
  int local_28 [4];
  undefined4 uStack_4;
  
  puVar15 = (ushort *)param_3[0xac1];
  uVar4 = param_5 + param_4;
  iVar1 = *param_3;
  local_38 = param_3[0xbac];
  local_28[0] = param_3[3];
  local_28[1] = param_3[4];
  local_28[2] = param_3[5];
  local_28[3] = (int)*(byte *)(param_3 + 0xbad);
  uStack_4 = param_2;
  do {
    iVar2 = local_28[1];
    puVar14 = (ushort *)param_3[0xac2];
    uVar16 = param_4;
    while( true ) {
      iVar11 = (int)*(short *)((int)param_3 + (local_38 >> 0x16) * 2 + 0x18);
      if (iVar11 < 0) {
        uVar12 = local_38 << 10;
        do {
          bVar17 = CARRY4(uVar12,uVar12);
          uVar12 = uVar12 * 2;
          iVar11 = (int)*(short *)((int)param_3 + (iVar11 * -2 + (uint)bVar17) * 2 + 0xe3c);
        } while (iVar11 < 0);
      }
      if (puVar14 <= puVar15) {
        return CONCAT44(uStack_4,0xffffffff);
      }
      bVar10 = *(byte *)((int)param_3 + iVar11 + 0xa18);
      local_38 = local_38 << (bVar10 & 0x1f);
      bVar7 = (char)local_28[3] - bVar10;
      if (bVar7 == 0 || (char)local_28[3] < (char)bVar10) {
        uVar3 = *puVar15;
        puVar15 = puVar15 + 1;
        local_38 = (uint)uVar3 << ((bVar7 ^ 0xff) + 1 & 0x1f) | local_38;
        bVar7 = bVar7 + 0x10;
      }
      local_28[3] = (int)bVar7;
      uVar12 = iVar11 - 0x100;
      if (-1 < (int)uVar12) break;
      param_4 = uVar16 + 1;
      *(char *)(uVar16 + iVar1) = (char)uVar12;
      puVar14 = (ushort *)param_3[0xac2];
      uVar16 = param_4;
      if (uVar4 <= param_4) goto LAB_01009414;
    }
    uVar13 = uVar12 >> 3;
    uVar12 = uVar12 & 7;
    if (uVar12 == 7) {
      iVar11 = (int)*(short *)((int)param_3 + (local_38 >> 0x18) * 2 + 0x818);
      if (iVar11 < 0) {
        uVar12 = local_38 << 8;
        do {
          bVar17 = CARRY4(uVar12,uVar12);
          uVar12 = uVar12 * 2;
          iVar11 = (int)*(short *)((int)param_3 + (iVar11 * -2 + (uint)bVar17) * 2 + 0x233c);
        } while (iVar11 < 0);
      }
      bVar10 = *(byte *)(iVar11 + 0xcb8 + (int)param_3);
      uVar12 = iVar11 + 7;
      local_38 = local_38 << (bVar10 & 0x1f);
      bVar8 = bVar7 - bVar10;
      local_28[3] = (int)bVar8;
      if (bVar8 == 0 || (char)bVar7 < (char)bVar10) {
        local_38 = (uint)*puVar15 << ((bVar8 ^ 0xff) + 1 & 0x1f) | local_38;
        local_28[3] = (int)(byte)(bVar8 + 0x10);
        puVar15 = puVar15 + 1;
      }
    }
    uVar5 = uVar13 & 0xff;
    puVar14 = puVar15;
    if ((char)uVar13 < '\x04') {
      if (uVar13 != 0) {
        if ((char)uVar13 == '\x03') {
          iVar11 = 1;
          goto LAB_010093d3;
        }
        iVar2 = local_28[uVar13];
        local_28[uVar13] = local_28[0];
        local_28[0] = iVar2;
      }
    }
    else {
      iVar11 = (local_38 >> ((&DAT_010091a0)[uVar5] & 0x1f)) + *(int *)(&DAT_01001500 + uVar5 * 4);
      bVar10 = (&DAT_010014c8)[uVar5];
      local_38 = local_38 << (bVar10 & 0x1f);
      cVar9 = (char)local_28[3];
      bVar7 = cVar9 - bVar10;
      local_28[3] = (int)bVar7;
      if (bVar7 == 0 || cVar9 < (char)bVar10) {
        local_38 = (uint)*puVar15 << ((bVar7 ^ 0xff) + 1 & 0x1f) | local_38;
        bVar10 = bVar7 + 0x10;
        local_28[3] = (int)bVar10;
        puVar14 = puVar15 + 1;
        if (bVar10 == 0 || SCARRY1(bVar7,'\x10') != (char)bVar10 < '\0') {
          local_38 = (uint)puVar15[1] << ((bVar10 ^ 0xff) + 1 & 0x1f) | local_38;
          local_28[3] = (int)(byte)(bVar7 + 0x20);
          puVar14 = puVar15 + 2;
        }
      }
LAB_010093d3:
      local_28[1] = local_28[0];
      local_28[2] = iVar2;
      puVar15 = puVar14;
      local_28[0] = iVar11;
    }
    bVar7 = (byte)local_28[3];
    uVar13 = uVar16 - local_28[0] & param_3[2];
    iVar2 = *param_3;
    *(undefined *)(uVar16 + iVar2) = *(undefined *)(uVar13 + iVar2);
    uVar16 = uVar16 + 1;
    do {
      uVar13 = uVar13 + 1;
      param_4 = uVar16 + 1;
      *(undefined *)(uVar16 + iVar2) = *(undefined *)(uVar13 + iVar2);
      bVar17 = 0 < (int)uVar12;
      uVar12 = uVar12 - 1;
      uVar16 = param_4;
    } while (bVar17);
    if (uVar4 <= param_4) {
LAB_01009414:
      uVar6 = 0;
      if (param_4 != uVar4) {
        uVar6 = 0xffffffff;
      }
      *(byte *)(param_3 + 0xbad) = bVar7;
      param_3[0xbb0] = param_4 & param_3[2];
      param_3[0xac1] = (int)puVar15;
      param_3[3] = local_28[0];
      param_3[4] = local_28[1];
      param_3[5] = local_28[2];
      param_3[0xbac] = local_38;
      return CONCAT44(uStack_4,uVar6);
    }
  } while( true );
}



BOOL VerQueryValueA(LPCVOID pBlock,LPCSTR lpSubBlock,LPVOID *lplpBuffer,PUINT puLen)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x01009462. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = VerQueryValueA(pBlock,lpSubBlock,lplpBuffer,puLen);
  return BVar1;
}



BOOL GetFileVersionInfoA(LPCSTR lptstrFilename,DWORD dwHandle,DWORD dwLen,LPVOID lpData)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x01009468. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = GetFileVersionInfoA(lptstrFilename,dwHandle,dwLen,lpData);
  return BVar1;
}



DWORD GetFileVersionInfoSizeA(LPCSTR lptstrFilename,LPDWORD lpdwHandle)

{
  DWORD DVar1;
  
                    // WARNING: Could not recover jumptable at 0x0100946e. Too many branches
                    // WARNING: Treating indirect jump as call
  DVar1 = GetFileVersionInfoSizeA(lptstrFilename,lpdwHandle);
  return DVar1;
}


