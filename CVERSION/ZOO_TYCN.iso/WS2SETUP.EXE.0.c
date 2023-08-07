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
typedef unsigned long long    undefined5;
typedef unsigned long long    undefined8;
typedef unsigned short    ushort;
typedef unsigned short    wchar16;
typedef short    wchar_t;
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

typedef struct tagMSG tagMSG, *PtagMSG;

typedef struct tagMSG MSG;

typedef struct HWND__ HWND__, *PHWND__;

typedef struct HWND__ * HWND;

typedef uint UINT;

typedef uint UINT_PTR;

typedef UINT_PTR WPARAM;

typedef long LONG_PTR;

typedef LONG_PTR LPARAM;

typedef ulong DWORD;

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

typedef struct _cpinfo _cpinfo, *P_cpinfo;

typedef uchar BYTE;

struct _cpinfo {
    UINT MaxCharSize;
    BYTE DefaultChar[2];
    BYTE LeadByte[12];
};

typedef struct _cpinfo * LPCPINFO;

typedef DWORD LCTYPE;

typedef struct _STARTUPINFOA _STARTUPINFOA, *P_STARTUPINFOA;

typedef char CHAR;

typedef CHAR * LPSTR;

typedef ushort WORD;

typedef BYTE * LPBYTE;

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

typedef struct _PROCESS_INFORMATION _PROCESS_INFORMATION, *P_PROCESS_INFORMATION;

struct _PROCESS_INFORMATION {
    HANDLE hProcess;
    HANDLE hThread;
    DWORD dwProcessId;
    DWORD dwThreadId;
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

typedef struct _WIN32_FIND_DATAA * LPWIN32_FIND_DATAA;

typedef struct _FILETIME _FILETIME, *P_FILETIME;

typedef struct _FILETIME FILETIME;

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

typedef struct _STARTUPINFOA * LPSTARTUPINFOA;

typedef struct _OVERLAPPED _OVERLAPPED, *P_OVERLAPPED;

typedef ulong ULONG_PTR;

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

typedef struct _PROCESS_INFORMATION * LPPROCESS_INFORMATION;

typedef struct _RTL_CRITICAL_SECTION _RTL_CRITICAL_SECTION, *P_RTL_CRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION * PRTL_CRITICAL_SECTION;

typedef PRTL_CRITICAL_SECTION LPCRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION_DEBUG _RTL_CRITICAL_SECTION_DEBUG, *P_RTL_CRITICAL_SECTION_DEBUG;

typedef struct _RTL_CRITICAL_SECTION_DEBUG * PRTL_CRITICAL_SECTION_DEBUG;

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

typedef DWORD (* PTHREAD_START_ROUTINE)(LPVOID);

typedef PTHREAD_START_ROUTINE LPTHREAD_START_ROUTINE;

typedef struct _OVERLAPPED * LPOVERLAPPED;

typedef struct _SECURITY_ATTRIBUTES * LPSECURITY_ATTRIBUTES;

typedef struct _CONTEXT _CONTEXT, *P_CONTEXT;

typedef struct _CONTEXT CONTEXT;

typedef struct _FLOATING_SAVE_AREA _FLOATING_SAVE_AREA, *P_FLOATING_SAVE_AREA;

typedef struct _FLOATING_SAVE_AREA FLOATING_SAVE_AREA;

struct _FLOATING_SAVE_AREA {
    DWORD ControlWord;
    DWORD StatusWord;
    DWORD TagWord;
    DWORD ErrorOffset;
    DWORD ErrorSelector;
    DWORD DataOffset;
    DWORD DataSelector;
    BYTE RegisterArea[80];
    DWORD Cr0NpxState;
};

struct _CONTEXT {
    DWORD ContextFlags;
    DWORD Dr0;
    DWORD Dr1;
    DWORD Dr2;
    DWORD Dr3;
    DWORD Dr6;
    DWORD Dr7;
    FLOATING_SAVE_AREA FloatSave;
    DWORD SegGs;
    DWORD SegFs;
    DWORD SegEs;
    DWORD SegDs;
    DWORD Edi;
    DWORD Esi;
    DWORD Ebx;
    DWORD Edx;
    DWORD Ecx;
    DWORD Eax;
    DWORD Ebp;
    DWORD Eip;
    DWORD SegCs;
    DWORD EFlags;
    DWORD Esp;
    DWORD SegSs;
    BYTE ExtendedRegisters[512];
};

typedef struct _EXCEPTION_RECORD _EXCEPTION_RECORD, *P_EXCEPTION_RECORD;

typedef struct _EXCEPTION_RECORD EXCEPTION_RECORD;

typedef EXCEPTION_RECORD * PEXCEPTION_RECORD;

struct _EXCEPTION_RECORD {
    DWORD ExceptionCode;
    DWORD ExceptionFlags;
    struct _EXCEPTION_RECORD * ExceptionRecord;
    PVOID ExceptionAddress;
    DWORD NumberParameters;
    ULONG_PTR ExceptionInformation[15];
};

typedef struct _TOKEN_PRIVILEGES _TOKEN_PRIVILEGES, *P_TOKEN_PRIVILEGES;

typedef struct _LUID_AND_ATTRIBUTES _LUID_AND_ATTRIBUTES, *P_LUID_AND_ATTRIBUTES;

typedef struct _LUID_AND_ATTRIBUTES LUID_AND_ATTRIBUTES;

typedef struct _LUID _LUID, *P_LUID;

typedef struct _LUID LUID;

struct _LUID {
    DWORD LowPart;
    LONG HighPart;
};

struct _LUID_AND_ATTRIBUTES {
    LUID Luid;
    DWORD Attributes;
};

struct _TOKEN_PRIVILEGES {
    DWORD PrivilegeCount;
    LUID_AND_ATTRIBUTES Privileges[1];
};

typedef wchar_t WCHAR;

typedef WCHAR * LPWSTR;

typedef WCHAR * LPWCH;

typedef struct _SID_IDENTIFIER_AUTHORITY _SID_IDENTIFIER_AUTHORITY, *P_SID_IDENTIFIER_AUTHORITY;

typedef struct _SID_IDENTIFIER_AUTHORITY * PSID_IDENTIFIER_AUTHORITY;

struct _SID_IDENTIFIER_AUTHORITY {
    BYTE Value[6];
};

typedef WCHAR * LPCWSTR;

typedef struct _LUID * PLUID;

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

typedef CONTEXT * PCONTEXT;

typedef struct _TOKEN_PRIVILEGES * PTOKEN_PRIVILEGES;

typedef DWORD ACCESS_MASK;

typedef DWORD LCID;

typedef enum _TOKEN_INFORMATION_CLASS TOKEN_INFORMATION_CLASS;

typedef HANDLE * PHANDLE;

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

typedef struct _EXCEPTION_POINTERS _EXCEPTION_POINTERS, *P_EXCEPTION_POINTERS;

struct _EXCEPTION_POINTERS {
    PEXCEPTION_RECORD ExceptionRecord;
    PCONTEXT ContextRecord;
};

typedef struct HKEY__ HKEY__, *PHKEY__;

struct HKEY__ {
    int unused;
};

typedef DWORD * LPDWORD;

typedef DWORD * PDWORD;

typedef struct HDC__ HDC__, *PHDC__;

struct HDC__ {
    int unused;
};

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

typedef struct HINSTANCE__ * HINSTANCE;

struct HINSTANCE__ {
    int unused;
};

typedef struct _FILETIME * PFILETIME;

typedef struct HRSRC__ HRSRC__, *PHRSRC__;

struct HRSRC__ {
    int unused;
};

typedef HINSTANCE HMODULE;

typedef HANDLE HLOCAL;

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

typedef struct HKEY__ * HKEY;

typedef HKEY * PHKEY;

typedef WORD * LPWORD;

typedef int INT;

typedef int HFILE;

typedef struct tagRECT * LPRECT;

typedef HANDLE HGLOBAL;

typedef BOOL * LPBOOL;

typedef void * LPCVOID;

typedef struct HRSRC__ * HRSRC;

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

typedef LONG LSTATUS;

typedef ACCESS_MASK REGSAM;

typedef char * va_list;

typedef uint size_t;




int FUN_01001eb0(void)

{
  HANDLE ProcessHandle;
  BOOL BVar1;
  int iVar2;
  int iVar3;
  uint *TokenInformation;
  uint uVar4;
  DWORD DVar5;
  HANDLE *TokenHandle;
  PSID *local_1c;
  PSID local_18;
  SIZE_T local_14;
  HANDLE local_10;
  _SID_IDENTIFIER_AUTHORITY local_c;
  
  iVar3 = 0;
  local_c.Value[0] = '\0';
  local_c.Value[1] = '\0';
  TokenInformation = (uint *)0x0;
  local_c.Value[2] = '\0';
  local_c.Value[3] = '\0';
  local_c.Value[4] = '\0';
  local_c.Value[5] = '\x05';
  iVar2 = DAT_010102d0;
  if (DAT_010102d0 == 2) {
    TokenHandle = &local_10;
    DVar5 = 8;
    ProcessHandle = GetCurrentProcess();
    BVar1 = OpenProcessToken(ProcessHandle,DVar5,TokenHandle);
    if (BVar1 == 0) {
      iVar2 = 0;
    }
    else {
      BVar1 = GetTokenInformation(local_10,TokenGroups,(LPVOID)0x0,0,&local_14);
      if ((BVar1 == 0) && (DVar5 = GetLastError(), DVar5 == 0x7a)) {
        TokenInformation = (uint *)LocalAlloc(0,local_14);
      }
      if (((TokenInformation != (uint *)0x0) &&
          (BVar1 = GetTokenInformation(local_10,TokenGroups,TokenInformation,local_14,&local_14),
          BVar1 != 0)) &&
         (BVar1 = AllocateAndInitializeSid(&local_c,'\x02',0x20,0x220,0,0,0,0,0,0,&local_18),
         BVar1 != 0)) {
        uVar4 = 0;
        if (*TokenInformation != 0) {
          local_1c = (PSID *)(TokenInformation + 1);
          do {
            BVar1 = EqualSid(*local_1c,local_18);
            if (BVar1 != 0) {
              iVar3 = 1;
              DAT_010102d0 = 1;
              break;
            }
            local_1c = local_1c + 2;
            uVar4 = uVar4 + 1;
          } while (uVar4 <= *TokenInformation && *TokenInformation != uVar4);
        }
        FreeSid(local_18);
      }
      CloseHandle(local_10);
      iVar2 = iVar3;
      if (TokenInformation != (uint *)0x0) {
        LocalFree(TokenInformation);
      }
    }
  }
  return iVar2;
}



undefined4 FUN_01001fcb(HWND param_1,int param_2,uint param_3,UINT param_4)

{
  HWND pHVar1;
  CHAR local_204 [512];
  
  if (param_2 == 0x110) {
    pHVar1 = GetDesktopWindow();
    FUN_01003d7d(param_1,pHVar1);
    local_204[0] = '\0';
    LoadStringA(DAT_01016700,param_4,local_204,0x200);
    SetDlgItemTextA(param_1,0x83f,local_204);
    MessageBeep(0xffffffff);
  }
  else {
    if (param_2 != 0x111) {
      return 0;
    }
    if ((param_3 < 0x83d) || (0x83e < param_3)) {
      return 0;
    }
    EndDialog(param_1,param_3);
  }
  return 1;
}



char * FUN_01002066(char **param_1,char *param_2)

{
  char *pcVar1;
  char *pcVar2;
  int iVar3;
  
  iVar3 = 0;
  pcVar2 = *param_1;
  pcVar1 = _strchr(param_2,(int)*pcVar2);
  while( true ) {
    if (pcVar1 == (char *)0x0) {
      *param_1 = pcVar2;
      pcVar1 = _strchr(param_2,(int)*pcVar2);
      while ((pcVar1 == (char *)0x0 && (pcVar2[iVar3] != '\0'))) {
        iVar3 = iVar3 + 1;
        pcVar1 = _strchr(param_2,(int)pcVar2[iVar3]);
      }
      pcVar2 = pcVar2 + iVar3;
      if (*pcVar2 != '\0') {
        *pcVar2 = '\0';
        pcVar2 = pcVar2 + 1;
      }
      return pcVar2;
    }
    if (*pcVar2 == '\0') break;
    pcVar2 = pcVar2 + 1;
    pcVar1 = _strchr(param_2,(int)*pcVar2);
  }
  return (char *)0x0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_010020e1(CHAR *param_1,LPSTR *param_2,undefined4 *param_3)

{
  int iVar1;
  char *pcVar2;
  LPSTR lpString1;
  DWORD DVar3;
  int iVar4;
  char *pcVar5;
  char local_210;
  CHAR local_20f [259];
  CHAR local_10c [260];
  CHAR *local_8;
  
  lstrcpyA(&local_210,param_1);
  if (local_210 == '\"') {
    local_8 = local_20f;
    pcVar5 = "\"";
  }
  else {
    local_8 = &local_210;
    pcVar5 = " ";
  }
  pcVar5 = FUN_01002066(&local_8,pcVar5);
  iVar1 = FUN_01002822(local_8);
  if (iVar1 == 0) {
    lstrcpyA(local_10c,&DAT_01015774);
    FUN_010027e1(local_10c,local_8);
  }
  else {
    lstrcpyA(local_10c,local_8);
  }
  pcVar2 = _strrchr(local_8,0x2e);
  if ((pcVar2 == (char *)0x0) || (iVar1 = lstrcmpiA(pcVar2,".INF"), iVar1 != 0)) {
    pcVar2 = _strrchr(local_8,0x2e);
    if ((pcVar2 != (char *)0x0) && (iVar1 = lstrcmpiA(pcVar2,".BAT"), iVar1 == 0)) {
      iVar1 = lstrlenA(local_10c);
      iVar4 = lstrlenA(s_Command_com__c__s_01010288);
      lpString1 = (LPSTR)LocalAlloc(0x40,iVar1 + iVar4 + 8);
      if (lpString1 == (LPSTR)0x0) {
        FUN_01003e4b((HWND)0x0,0x4b5,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
        return 0;
      }
      wsprintfA(lpString1,s_Command_com__c__s_01010288,local_10c);
      goto LAB_010023ce;
    }
    iVar1 = lstrlenA(local_10c);
    iVar4 = lstrlenA(param_1);
    lpString1 = (LPSTR)LocalAlloc(0x40,iVar1 + iVar4 + 10);
    if (lpString1 == (LPSTR)0x0) {
      FUN_01003e4b((HWND)0x0,0x4b5,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
      return 0;
    }
    DVar3 = GetFileAttributesA(local_10c);
    if ((DVar3 != 0xffffffff) && ((DVar3 & 0x10) == 0)) {
      lstrcpyA(lpString1,local_10c);
      if ((pcVar5 != (char *)0x0) && (*pcVar5 != '\0')) {
        lstrcatA(lpString1," ");
        lstrcatA(lpString1,pcVar5);
      }
      goto LAB_010023ce;
    }
  }
  else {
    local_8 = pcVar5;
    pcVar5 = FUN_01002066(&local_8,"[");
    lstrlenA(s_DefaultInstall_01010168);
    if (pcVar5 != (char *)0x0) {
      if (*pcVar5 != '\0') {
        local_8 = pcVar5;
      }
      FUN_01002066(&local_8,"]");
      if (*local_8 != '\0') {
        lstrlenA(local_8);
      }
    }
    lpString1 = (LPSTR)LocalAlloc(0x40,0x200);
    if (lpString1 == (LPSTR)0x0) {
      FUN_01003e4b((HWND)0x0,0x4b5,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
      return 0;
    }
    pcVar5 = local_8;
    if (*local_8 == '\0') {
      pcVar5 = s_DefaultInstall_01010168;
    }
    _DAT_01015fd0 = GetPrivateProfileIntA(pcVar5,"Reboot",0,local_10c);
    *param_3 = 1;
    DVar3 = GetPrivateProfileStringA("Version","AdvancedINF","",lpString1,8,local_10c);
    if (DVar3 == 0) {
      DAT_01015fc4 = DAT_01015fc4 & 0xfb;
      pcVar5 = local_8;
      if (*local_8 == '\0') {
        pcVar5 = s_DefaultInstall_01010168;
      }
      pcVar2 = "setupx.dll";
      if (DAT_01016704 != 0) {
        pcVar2 = "setupapi.dll";
      }
      wsprintfA(lpString1,s_rundll32_exe__s_InstallHinfSecti_010100c8,pcVar2,pcVar5,local_10c);
      goto LAB_010023ce;
    }
    DAT_01015fc4 = DAT_01015fc4 | 4;
    pcVar5 = local_8;
    if (*local_8 == '\0') {
      pcVar5 = s_DefaultInstall_01010168;
    }
    lstrcpyA(param_1,pcVar5);
    param_1 = local_10c;
  }
  lstrcpyA(lpString1,param_1);
LAB_010023ce:
  *param_2 = lpString1;
  return 1;
}



void FUN_010023e1(void)

{
  FUN_01003e4b((HWND)0x0,0x521,"",(LPCSTR)0x0,0x40,0);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_010023f8(void)

{
  bool bVar1;
  undefined3 extraout_var;
  
  if ((_DAT_01015fd0 == 0) &&
     (bVar1 = FUN_01002997(DAT_01015fd4,DAT_01016704), CONCAT31(extraout_var,bVar1) == 0)) {
    return 0xffffffff;
  }
  return 2;
}



undefined4 FUN_01002426(void)

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
  FUN_01003e4b((HWND)0x0,UVar2,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
  return 0;
}



void FUN_010024bf(byte param_1)

{
  int iVar1;
  
  iVar1 = 2;
  if ((param_1 & 2) == 0) {
    iVar1 = FUN_010023f8();
  }
  if (iVar1 == 2) {
    iVar1 = 6;
    if ((param_1 & 4) == 0) {
      iVar1 = FUN_01003e4b((HWND)0x0,0x522,"",(LPCSTR)0x0,0x40,4);
    }
    if (iVar1 == 6) {
      if (DAT_01016704 == 0) {
        ExitWindowsEx(2,0);
      }
      else {
        FUN_01002426();
      }
    }
  }
  return;
}



void FUN_01002524(void)

{
  LSTATUS LVar1;
  HKEY local_4;
  
  if (DAT_010102a0 != '\0') {
    LVar1 = RegOpenKeyExA((HKEY)0x80000002,s_Software_Microsoft_Windows_Curre_01010188,0,0xf003f,
                          &local_4);
    if (LVar1 == 0) {
      RegDeleteValueA(local_4,&DAT_010102a0);
      RegCloseKey(local_4);
    }
  }
  return;
}



void FUN_0100256d(void)

{
  LSTATUS LVar1;
  DWORD DVar2;
  int iVar3;
  BYTE *lpData;
  int iVar4;
  CHAR local_114 [260];
  DWORD local_10;
  DWORD local_c;
  HKEY local_8;
  
  iVar4 = 0;
  LVar1 = RegCreateKeyExA((HKEY)0x80000002,s_Software_Microsoft_Windows_Curre_01010188,0,(LPSTR)0x0,
                          0,0xf003f,(LPSECURITY_ATTRIBUTES)0x0,&local_8,&local_c);
  if (LVar1 == 0) {
    do {
      wsprintfA(&DAT_010102a0,s_wextract_cleanup_d_01010260,iVar4);
      LVar1 = RegQueryValueExA(local_8,&DAT_010102a0,(LPDWORD)0x0,(LPDWORD)0x0,(LPBYTE)0x0,&local_10
                              );
      if (LVar1 != 0) break;
      iVar4 = iVar4 + 1;
    } while (iVar4 < 200);
    if (iVar4 == 200) {
      RegCloseKey(local_8);
      DAT_010102a0 = 0;
    }
    else {
      DVar2 = GetModuleFileNameA(DAT_01016700,local_114,0x104);
      if (DVar2 == 0) {
        RegCloseKey(local_8);
      }
      else {
        iVar4 = lstrlenA(local_114);
        iVar3 = lstrlenA(&DAT_01015774);
        lpData = (BYTE *)LocalAlloc(0x40,iVar4 + iVar3 + 0x30);
        if (lpData == (BYTE *)0x0) {
          FUN_01003e4b((HWND)0x0,0x4b5,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
          RegCloseKey(local_8);
        }
        else {
          wsprintfA((LPSTR)lpData,s__s__D__s_01010278,local_114,&DAT_01015774);
          iVar4 = lstrlenA((LPCSTR)lpData);
          RegSetValueExA(local_8,&DAT_010102a0,0,1,lpData,iVar4 + 1);
          RegCloseKey(local_8);
          LocalFree(lpData);
        }
      }
    }
  }
  return;
}



void FUN_010026b2(LPCSTR param_1)

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
          iVar1 = lstrcmpA(local_21c,(LPCSTR)&DAT_01001374);
          if (iVar1 != 0) {
            iVar1 = lstrcmpA(local_21c,"..");
            if (iVar1 != 0) {
              lstrcatA(local_108,local_21c);
              FUN_010027e1(local_108,"");
              FUN_010026b2(local_108);
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



void FUN_010027e1(LPCSTR param_1,LPCSTR param_2)

{
  char cVar1;
  int iVar2;
  LPSTR pCVar3;
  LPCSTR lpszCurrent;
  
  iVar2 = lstrlenA(param_1);
  lpszCurrent = param_1 + iVar2;
  if ((param_1 < lpszCurrent) && (pCVar3 = CharPrevA(param_1,lpszCurrent), *pCVar3 != '\\')) {
    *lpszCurrent = '\\';
    lpszCurrent = lpszCurrent + 1;
  }
  cVar1 = *param_2;
  while (cVar1 == ' ') {
    param_2 = param_2 + 1;
    cVar1 = *param_2;
  }
  lstrcpyA(lpszCurrent,param_2);
  return;
}



undefined4 FUN_01002822(LPCSTR param_1)

{
  int iVar1;
  
  if (((param_1 != (LPCSTR)0x0) && (iVar1 = lstrlenA(param_1), 2 < iVar1)) &&
     (((param_1[1] == ':' && (param_1[2] == '\\')) || ((*param_1 == '\\' && (param_1[1] == '\\')))))
     ) {
    return 1;
  }
  return 0;
}



LONG FUN_0100285a(void)

{
  UINT UVar1;
  HFILE hFile;
  LONG LVar2;
  CHAR local_104 [260];
  
  LVar2 = 0;
  UVar1 = GetWindowsDirectoryA(local_104,0x104);
  if (UVar1 != 0) {
    FUN_010027e1(local_104,"wininit.ini");
    hFile = _lopen(local_104,0x40);
    if (hFile != -1) {
      LVar2 = _llseek(hFile,0,2);
      _lclose(hFile);
    }
  }
  return LVar2;
}



DWORD FUN_010028b9(LPCSTR param_1,LPCSTR param_2)

{
  LSTATUS LVar1;
  HKEY local_c;
  DWORD local_8;
  
  local_8 = 0;
  LVar1 = RegOpenKeyA((HKEY)0x80000002,param_1,&local_c);
  if (LVar1 == 0) {
    LVar1 = RegQueryValueExA(local_c,param_2,(LPDWORD)0x0,(LPDWORD)0x0,(LPBYTE)0x0,&local_8);
    if (LVar1 != 0) {
      local_8 = 0;
    }
    RegCloseKey(local_c);
  }
  return local_8;
}



DWORD FUN_01002908(LPCSTR param_1)

{
  LSTATUS LVar1;
  HKEY local_c;
  DWORD local_8;
  
  local_8 = 0;
  LVar1 = RegOpenKeyA((HKEY)0x80000002,param_1,&local_c);
  if (LVar1 == 0) {
    LVar1 = RegQueryInfoKeyA(local_c,(LPSTR)0x0,(LPDWORD)0x0,(LPDWORD)0x0,(LPDWORD)0x0,(LPDWORD)0x0,
                             (LPDWORD)0x0,&local_8,(LPDWORD)0x0,(LPDWORD)0x0,(LPDWORD)0x0,
                             (PFILETIME)0x0);
    if (LVar1 != 0) {
      local_8 = 0;
    }
    RegCloseKey(local_c);
  }
  return local_8;
}



DWORD FUN_0100295b(short param_1)

{
  DWORD DVar1;
  
  DVar1 = 0;
  if (param_1 == 0) {
    DVar1 = FUN_0100285a();
  }
  else if (param_1 == 1) {
    DVar1 = FUN_01002908(s_System_CurrentControlSet_Control_01010218);
  }
  else if (param_1 == 2) {
    DVar1 = FUN_010028b9(s_System_CurrentControlSet_Control_010101c0,
                         s_PendingFileRenameOperations_010101f8);
  }
  return DVar1;
}



bool FUN_01002997(DWORD param_1,short param_2)

{
  DWORD DVar1;
  
  DVar1 = FUN_0100295b(param_2);
  return (bool)('\x01' - (DVar1 == param_1));
}



uint FUN_010029ad(LPCSTR param_1)

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



bool FUN_010029d0(char *param_1)

{
  UINT UVar1;
  char local_104 [260];
  
  UVar1 = GetWindowsDirectoryA(local_104,0x104);
  if (UVar1 == 0) {
    FUN_01003e4b((HWND)0x0,0x4f0,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
  }
  return *param_1 == local_104[0];
}



bool FUN_01002a18(int param_1,int param_2,uint param_3,LPCSTR param_4)

{
  char *pcVar1;
  int iVar2;
  bool bVar3;
  LPCSTR pCVar4;
  uint uVar5;
  uint uVar6;
  char local_10 [12];
  
  DAT_01015fcc = 0x70;
  bVar3 = false;
  if (param_1 == 1) {
    uVar6 = 0;
    uVar5 = 0x10;
    pCVar4 = (LPCSTR)0x0;
    pcVar1 = FUN_01005fc4((param_3 + param_2) / 1000,local_10,10);
    FUN_01003e4b((HWND)0x0,0x4fa,pcVar1,pCVar4,uVar5,uVar6);
  }
  else if (param_1 == 4) {
    uVar6 = 5;
    uVar5 = 0x20;
    pCVar4 = (LPCSTR)0x0;
    pcVar1 = FUN_01005fc4((param_3 + param_2) / 1000,local_10,10);
    iVar2 = FUN_01003e4b((HWND)0x0,0x4bd,pcVar1,pCVar4,uVar5,uVar6);
    bVar3 = iVar2 == 4;
  }
  else if (param_1 == 2) {
    uVar6 = 0x104;
    uVar5 = 0x40;
    pcVar1 = FUN_01005fc4(param_3 / 1000,local_10,10);
    iVar2 = FUN_01003e4b((HWND)0x0,0x4cc,pcVar1,param_4,uVar5,uVar6);
    if (iVar2 == 6) {
      bVar3 = true;
      DAT_01015fcc = 0;
    }
  }
  return bVar3;
}



undefined4 FUN_01002afc(HINSTANCE param_1,undefined4 param_2,char *param_3)

{
  int iVar1;
  int iVar2;
  
  iVar2 = 0;
  DAT_01015fcc = 0;
  iVar1 = FUN_01002b5b(param_1,param_3);
  if (iVar1 != 0) {
    iVar2 = FUN_01002d3f();
    thunk_FUN_01004b89();
  }
  if (((iVar2 != 0) && (DAT_01015ff6 == '\0')) && ((DAT_01015fbc & 1) != 0)) {
    FUN_010024bf((byte)DAT_01015fbc);
  }
  InterlockedDecrement((LONG *)&DAT_01019000);
  return DAT_01015fcc;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_01002b5b(HINSTANCE param_1,char *param_2)

{
  DWORD DVar1;
  LONG LVar2;
  int iVar3;
  INT_PTR IVar4;
  UINT UVar5;
  LPCSTR pCVar6;
  
  DAT_01016700 = param_1;
  _DAT_0101597c = 1;
  _DAT_01015768 = 0;
  _DAT_0101576c = 0;
  _DAT_01015998 = 0;
  _DAT_01015980 = 0;
  DAT_01015770 = 0;
  _DAT_01015984 = 0;
  DAT_01015988 = 0;
  DAT_010156d0 = 0;
  DAT_010156d4 = 0;
  _DAT_01015fc0 = 0;
  DAT_01015fbc = 0;
  _DAT_01015fc4 = 0;
  DAT_01015fc8 = 0;
  DVar1 = FUN_01003f90(s_TITLE_010102d8,(undefined4 *)&DAT_010156e4,0x7f);
  if ((DVar1 == 0) || (0x80 < DVar1)) {
    pCVar6 = (LPCSTR)0x0;
    UVar5 = 0x4b1;
  }
  else {
    LVar2 = InterlockedIncrement((LONG *)&DAT_01019000);
    if (LVar2 == 0) {
      DAT_0101046c = CreateEventA((LPSECURITY_ATTRIBUTES)0x0,1,1,(LPCSTR)0x0);
      SetEvent(DAT_0101046c);
      DVar1 = FUN_01003f90(s_EXTRACTOPT_01010368,(undefined4 *)&DAT_01015fc4,4);
      if (DVar1 == 0) {
        FUN_01003e4b((HWND)0x0,0x4b1,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
        DAT_01015fcc = 0x80070714;
        return 0;
      }
      iVar3 = FUN_01003497();
      if (iVar3 == 0) {
        return 0;
      }
      if (_DAT_01010460 != 0) {
        InitCommonControls();
      }
      _DAT_01015fe4 = 0;
      _DAT_01015fe0 = 0;
      DAT_01015ff4 = 0;
      _DAT_01015fe8 = 0;
      _DAT_01015fec = 0;
      _DAT_01015ff0 = 0;
      DAT_010160fa = 0;
      DAT_010161fe = 0;
      DAT_01015ff6 = 0;
      _DAT_01015fd0 = 0;
      iVar3 = FUN_010054fc(param_2);
      if (iVar3 != 0) {
        if (((DAT_01015ff4 == 0) &&
            (((DAT_01016704 == 1 || (DAT_01016704 == 2)) && (iVar3 = FUN_01001eb0(), iVar3 == 0))))
           && (IVar4 = DialogBoxParamA(DAT_01016700,(LPCSTR)0x7d6,(HWND)0x0,FUN_01001fcb,0x547),
              IVar4 != 0x83d)) {
          return 0;
        }
        return 1;
      }
      pCVar6 = (LPCSTR)0x0;
      UVar5 = 0x520;
    }
    else {
      DAT_01015fcc = 0x800700b7;
      pCVar6 = &DAT_010156e4;
      UVar5 = 0x54b;
    }
  }
  FUN_01003e4b((HWND)0x0,UVar5,pCVar6,(LPCSTR)0x0,0x10,0);
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_01002d3f(void)

{
  bool bVar1;
  int iVar2;
  INT_PTR IVar3;
  undefined3 extraout_var;
  BOOL BVar4;
  undefined3 extraout_var_00;
  
  if (DAT_01015ff6 == '\0') {
    if ((DAT_01015ff4 == 0) &&
       ((iVar2 = FUN_01004ab4(), iVar2 == 0 || (iVar2 = FUN_0100355d(), iVar2 == 0)))) {
      return 0;
    }
    iVar2 = FUN_01004a17();
    if (iVar2 == 0) {
      return 0;
    }
    IVar3 = FUN_01004d94();
    if (IVar3 == 0) {
      return 0;
    }
    bVar1 = FUN_01005a08();
    if (CONCAT31(extraout_var,bVar1) == 0) {
      return 0;
    }
    BVar4 = SetCurrentDirectoryA(&DAT_01015774);
    if (BVar4 == 0) {
      FUN_01003e4b((HWND)0x0,0x4bc,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
      DAT_01015fcc = FUN_01005aa0();
      return 0;
    }
    if ((_DAT_01015fec == 0) && (bVar1 = FUN_01003653(), CONCAT31(extraout_var_00,bVar1) == 0)) {
      return 0;
    }
    DAT_01015fd4 = FUN_0100295b(DAT_01016704);
    if (((_DAT_01015fe4 == 0) && (_DAT_01015fc0 == 0)) && (iVar2 = FUN_010036eb(), iVar2 == 0)) {
      return 0;
    }
    if (DAT_01015ff4 == 0) {
      FUN_01003b9b();
    }
  }
  else {
    FUN_010026b2(&DAT_01015ff6);
  }
  return 1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void thunk_FUN_01004b89(void)

{
  LPCSTR *ppCVar1;
  LPCSTR *hMem;
  
  hMem = DAT_01015770;
  if (DAT_01015770 != (LPCSTR *)0x0) {
    do {
      if ((_DAT_01015fe4 == 0) && (_DAT_01015fc0 == 0)) {
        SetFileAttributesA(*hMem,0x80);
        DeleteFileA(*hMem);
      }
      ppCVar1 = (LPCSTR *)hMem[1];
      LocalFree(*hMem);
      LocalFree(hMem);
      hMem = ppCVar1;
    } while (ppCVar1 != (LPCSTR *)0x0);
  }
  if ((DAT_01016704 != 1) && (_DAT_01015fe0 != 0)) {
    FUN_01002524();
  }
  if (((_DAT_01015fe0 != 0) && (_DAT_01015fe4 == 0)) && (_DAT_01015fc0 == 0)) {
    _DAT_01015fe0 = 0;
    SetCurrentDirectoryA("..");
    FUN_010026b2(&DAT_01015774);
  }
  return;
}



void FUN_01002e39(HWND param_1,LONG param_2)

{
  DAT_0101670c = GetWindowLongA(param_1,-4);
  SetWindowLongA(param_1,-4,param_2);
  return;
}



LRESULT FUN_01002e5d(HWND param_1,UINT param_2,WPARAM param_3,int param_4)

{
  LRESULT LVar1;
  
  if (((param_2 != 0xb1) || (param_3 != 0)) || (LVar1 = 0, param_4 != -2)) {
    LVar1 = CallWindowProcA(DAT_0101670c,param_1,param_2,param_3,param_4);
  }
  return LVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_01002e97(HWND param_1,int param_2,int param_3)

{
  HWND pHVar1;
  code *pcVar2;
  INT_PTR nResult;
  
  if (param_2 == 0xf) {
    if (_DAT_01010470 == 0) {
      _DAT_01011f14 = SendDlgItemMessageA(param_1,0x834,0xb1,0xffffffff,0);
      _DAT_01010470 = 1;
    }
    return 0;
  }
  if (param_2 != 0x10) {
    if (param_2 == 0x110) {
      pHVar1 = GetDesktopWindow();
      FUN_01003d7d(param_1,pHVar1);
      SetDlgItemTextA(param_1,0x834,DAT_01016708);
      SetWindowTextA(param_1,&DAT_010156e4);
      SetForegroundWindow(param_1);
      pcVar2 = FUN_01002e5d;
      pHVar1 = GetDlgItem(param_1,0x834);
      FUN_01002e39(pHVar1,(LONG)pcVar2);
      return 1;
    }
    if (param_2 != 0x111) {
      return 0;
    }
    if (param_3 == 6) {
      nResult = 1;
      goto LAB_01002f5d;
    }
    if (param_3 != 7) {
      return 1;
    }
  }
  nResult = 0;
LAB_01002f5d:
  EndDialog(param_1,nResult);
  return 1;
}



undefined4 FUN_01002f70(LPCSTR param_1)

{
  int iVar1;
  
  if (((param_1 != (LPCSTR)0x0) && (iVar1 = lstrlenA(param_1), 2 < iVar1)) &&
     ((param_1[1] == ':' || ((*param_1 == '\\' && (param_1[1] == '\\')))))) {
    return 1;
  }
  return 0;
}



undefined4 FUN_01002fa2(HWND param_1,int param_2,int param_3)

{
  bool bVar1;
  HWND pHVar2;
  DWORD DVar3;
  uint uVar4;
  undefined3 extraout_var;
  int iVar5;
  undefined3 extraout_var_00;
  BOOL BVar6;
  UINT UVar7;
  INT_PTR nResult;
  
  if (param_2 == 0x10) {
    nResult = 0;
  }
  else {
    if (param_2 == 0x110) {
      pHVar2 = GetDesktopWindow();
      FUN_01003d7d(param_1,pHVar2);
      SetWindowTextA(param_1,&DAT_010156e4);
      if ((DAT_01016704 != 1) && (DAT_01016704 != 2)) {
        return 1;
      }
      BVar6 = 0;
      pHVar2 = GetDlgItem(param_1,0x836);
      EnableWindow(pHVar2,BVar6);
      return 1;
    }
    if (param_2 != 0x111) {
      return 0;
    }
    if (param_3 == 1) {
      UVar7 = GetDlgItemTextA(param_1,0x835,&DAT_01015774,0x104);
      if ((UVar7 == 0) || (iVar5 = FUN_01002f70(&DAT_01015774), iVar5 == 0)) {
        FUN_01003e4b(param_1,0x4bf,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
        return 1;
      }
      DVar3 = GetFileAttributesA(&DAT_01015774);
      if (DVar3 == 0xffffffff) {
        iVar5 = FUN_01003e4b(param_1,0x54a,&DAT_01015774,(LPCSTR)0x0,0x20,4);
        if (iVar5 != 6) {
          return 1;
        }
        BVar6 = CreateDirectoryA(&DAT_01015774,(LPSECURITY_ATTRIBUTES)0x0);
        if (BVar6 == 0) {
          FUN_01003e4b(param_1,0x4cb,&DAT_01015774,(LPCSTR)0x0,0x10,0);
          return 1;
        }
      }
      FUN_010027e1(&DAT_01015774,"");
      iVar5 = FUN_010050dd(&DAT_01015774);
      if (iVar5 == 0) {
        FUN_01003e4b(param_1,0x4be,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
        return 1;
      }
      if ((DAT_01015774 != '\\') || (uVar4 = 0, DAT_01015775 != '\\')) {
        uVar4 = 1;
      }
      bVar1 = FUN_010051cf(&DAT_01015774,uVar4,1);
      if (CONCAT31(extraout_var,bVar1) == 0) {
        return 1;
      }
      nResult = 1;
    }
    else {
      if (param_3 == 2) {
        EndDialog(param_1,0);
        DAT_01015fcc = 0x800704c7;
        return 1;
      }
      if (param_3 != 0x836) {
        return 1;
      }
      iVar5 = LoadStringA(DAT_01016700,1000,&DAT_01012120,0x200);
      if (iVar5 == 0) {
        UVar7 = 0x4b1;
      }
      else {
        bVar1 = FUN_01003c1d(param_1,&DAT_01012120,&DAT_01011e10);
        if (CONCAT31(extraout_var_00,bVar1) == 0) {
          return 1;
        }
        BVar6 = SetDlgItemTextA(param_1,0x835,&DAT_01011e10);
        if (BVar6 != 0) {
          return 1;
        }
        UVar7 = 0x4c0;
      }
      FUN_01003e4b(param_1,UVar7,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
      nResult = 0;
    }
  }
  EndDialog(param_1,nResult);
  return 1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_010031db(HWND param_1,int param_2,uint param_3)

{
  HWND pHVar1;
  
  if (param_2 == 0x10) {
    param_3 = 2;
  }
  else {
    if (param_2 == 0x110) {
      pHVar1 = GetDesktopWindow();
      FUN_01003d7d(param_1,pHVar1);
      SetWindowTextA(param_1,&DAT_010156e4);
      SetDlgItemTextA(param_1,0x838,DAT_01015994);
      SetForegroundWindow(param_1);
      return 1;
    }
    if (param_2 != 0x111) {
      return 0;
    }
    if (param_3 < 6) {
      return 1;
    }
    if (7 < param_3) {
      if (param_3 != 0x839) {
        return 1;
      }
      _DAT_0101576c = 1;
    }
  }
  EndDialog(param_1,param_3);
  return 1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0100326c(HWND param_1,int param_2,int param_3)

{
  HWND pHVar1;
  int iVar2;
  UINT UVar3;
  WPARAM WVar4;
  LPARAM LVar5;
  
  if (param_2 == 0x10) {
    _DAT_01015768 = 1;
    EndDialog(param_1,0);
    return 1;
  }
  if (param_2 == 0x102) {
    if (param_3 != 0x1b) {
      return 1;
    }
    _DAT_01015768 = 1;
    param_3 = 0;
  }
  else if (param_2 == 0x110) {
    DAT_01010468 = param_1;
    pHVar1 = GetDesktopWindow();
    FUN_01003d7d(param_1,pHVar1);
    if (_DAT_01010460 != 0) {
      LVar5 = 0xbb9;
      WVar4 = 0;
      UVar3 = 0x464;
      pHVar1 = GetDlgItem(param_1,0x83b);
      SendMessageA(pHVar1,UVar3,WVar4,LVar5);
      LVar5 = -0x10000;
      WVar4 = 0xffffffff;
      UVar3 = 0x465;
      pHVar1 = GetDlgItem(param_1,0x83b);
      SendMessageA(pHVar1,UVar3,WVar4,LVar5);
    }
    SetWindowTextA(param_1,&DAT_010156e4);
    DAT_01011f18 = CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,FUN_01004856,(LPVOID)0x0,0,
                                (LPDWORD)&DAT_01012520);
    if (DAT_01011f18 != (HANDLE)0xffffffff) {
      return 1;
    }
    FUN_01003e4b(param_1,0x4b8,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
    param_3 = 0;
  }
  else {
    if (param_2 == 0x111) {
      if (param_3 != 2) {
        return 1;
      }
      ResetEvent(DAT_0101046c);
      iVar2 = FUN_01003e4b(DAT_01010468,0x4b2,"",(LPCSTR)0x0,0x20,4);
      if ((iVar2 != 6) && (iVar2 != 1)) {
        SetEvent(DAT_0101046c);
        return 1;
      }
      _DAT_01015768 = 1;
      SetEvent(DAT_0101046c);
      FUN_01003423((char)DAT_01011f18);
      EndDialog(param_1,0);
      return 1;
    }
    if (param_2 != 0xfa1) {
      return 0;
    }
    TerminateThread(DAT_01011f18,0);
  }
  EndDialog(param_1,param_3);
  return 1;
}



void FUN_01003423(undefined param_1)

{
  bool bVar1;
  DWORD DVar2;
  int iVar3;
  tagMSG local_20;
  
  bVar1 = false;
  do {
    DVar2 = MsgWaitForMultipleObjects(1,(HANDLE *)&param_1,0,0xffffffff,0xff);
    if (DVar2 == 0) {
      bVar1 = true;
    }
    else {
      iVar3 = PeekMessageA(&local_20,(HWND)0x0,0,0,1);
      while (iVar3 != 0) {
        if (local_20.message == 0x12) {
          bVar1 = true;
        }
        else {
          DispatchMessageA(&local_20);
        }
        iVar3 = PeekMessageA(&local_20,(HWND)0x0,0,0,1);
      }
    }
  } while (!bVar1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_01003497(void)

{
  BOOL BVar1;
  undefined4 uVar2;
  _OSVERSIONINFOA local_98;
  
  local_98.dwOSVersionInfoSize = 0x94;
  BVar1 = GetVersionExA(&local_98);
  if (BVar1 == 0) {
    FUN_01003e4b((HWND)0x0,0x4b4,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
    uVar2 = 0;
  }
  else if (local_98.dwPlatformId == 1) {
    DAT_01016704 = 0;
    uVar2 = 1;
    _DAT_01010460 = 1;
    _DAT_01010464 = 1;
  }
  else if (local_98.dwPlatformId == 2) {
    DAT_01016704 = 2;
    _DAT_01010460 = 1;
    _DAT_01010464 = 1;
    if ((local_98.dwMajorVersion < 4) &&
       ((DAT_01016704 = 1, local_98.dwMajorVersion < 3 ||
        ((local_98.dwMajorVersion == 3 && (local_98.dwMinorVersion < 0x33)))))) {
      _DAT_01010460 = 0;
      _DAT_01010464 = 0;
    }
    uVar2 = 1;
  }
  else {
    FUN_01003e4b((HWND)0x0,0x4ca,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
    uVar2 = 0;
  }
  return uVar2;
}



undefined4 FUN_0100355d(void)

{
  DWORD DVar1;
  undefined4 uVar2;
  int iVar3;
  INT_PTR IVar4;
  
  DVar1 = FUN_01003f90(s_LICENSE_010102e0,(undefined4 *)0x0,0);
  DAT_01016708 = (undefined4 *)LocalAlloc(0x40,DVar1 + 1);
  if (DAT_01016708 == (undefined4 *)0x0) {
    FUN_01003e4b((HWND)0x0,0x4b5,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
    DAT_01015fcc = FUN_01005aa0();
    uVar2 = 0;
  }
  else {
    DVar1 = FUN_01003f90(s_LICENSE_010102e0,DAT_01016708,DVar1);
    if (DVar1 == 0) {
      FUN_01003e4b((HWND)0x0,0x4b1,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
      LocalFree(DAT_01016708);
      DAT_01015fcc = 0x80070714;
      uVar2 = 0;
    }
    else {
      iVar3 = lstrcmpA((LPCSTR)DAT_01016708,s_<None>_01010338);
      if (iVar3 == 0) {
        LocalFree(DAT_01016708);
      }
      else {
        IVar4 = DialogBoxParamA(DAT_01016700,(LPCSTR)0x7d1,(HWND)0x0,FUN_01002e97,0);
        LocalFree(DAT_01016708);
        if (IVar4 == 0) {
          DAT_01015fcc = 0x800704c7;
          return 0;
        }
      }
      DAT_01015fcc = 0;
      uVar2 = 1;
    }
  }
  return uVar2;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

bool FUN_01003653(void)

{
  undefined4 *puVar1;
  INT_PTR IVar2;
  WPARAM WVar3;
  int iVar4;
  
  puVar1 = &DAT_01016340;
  do {
    *puVar1 = 1;
    puVar1 = puVar1 + 6;
  } while (puVar1 < &DAT_01016700);
  if ((((byte)DAT_01015ff4 & 1) == 0) && ((DAT_01015fc4 & 1) == 0)) {
    IVar2 = DialogBoxParamA(DAT_01016700,(LPCSTR)((_DAT_01010460 == 0) + 0x7d4),(HWND)0x0,
                            FUN_0100326c,0);
    if (IVar2 == 0) {
      DAT_01015fcc = 0x8007042b;
      return false;
    }
  }
  else {
    WVar3 = FUN_01004856();
    if (WVar3 == 0) {
      DAT_01015fcc = 0x8007042b;
      return false;
    }
  }
  iVar4 = FUN_01005ac0(FUN_01005baf);
  if (iVar4 != 0) {
    DAT_01015fcc = 0;
  }
  return iVar4 != 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_010036eb(void)

{
  DWORD DVar1;
  HMODULE hModule;
  FARPROC pFVar2;
  int iVar3;
  _STARTUPINFOA *p_Var4;
  CHAR local_37c [512];
  undefined4 local_17c [65];
  _STARTUPINFOA local_78;
  undefined4 local_34;
  undefined *local_30;
  LPSTR local_2c;
  undefined *local_28;
  undefined4 *local_24;
  short local_20;
  uint local_1c;
  undefined4 local_18;
  int local_14;
  uint local_10;
  int local_c;
  LPSTR local_8;
  
  local_c = 0;
  if ((_DAT_01015fe8 == 0) &&
     ((DVar1 = FUN_01003f90(s_REBOOT_01010360,&DAT_01015fbc,4), DVar1 == 0 || (4 < DVar1)))) {
    FUN_01003e4b((HWND)0x0,0x4b1,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
    DAT_01015fcc = 0x80070714;
    return 0;
  }
  local_10 = 0;
  do {
    local_c = 0;
    p_Var4 = &local_78;
    for (iVar3 = 0x11; iVar3 != 0; iVar3 = iVar3 + -1) {
      p_Var4->cb = 0;
      p_Var4 = (_STARTUPINFOA *)&p_Var4->lpReserved;
    }
    local_78.cb = 0x44;
    if (DAT_010161fe == '\0') {
      DVar1 = FUN_01003f90(s_SHOWWINDOW_010102e8,&local_14,4);
      if ((DVar1 == 0) || (4 < DVar1)) {
        FUN_01003e4b((HWND)0x0,0x4b1,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
        DAT_01015fcc = 0x80070714;
        return 0;
      }
      if (local_14 == 1) {
        local_78.wShowWindow = 0;
        local_78.dwFlags = 1;
      }
      else if (local_14 == 2) {
        local_78.wShowWindow = 6;
        local_78.dwFlags = 1;
      }
      else if (local_14 == 3) {
        local_78.wShowWindow = 3;
        local_78.dwFlags = 1;
      }
    }
    if (local_10 == 0) {
      if (DAT_010161fe == '\0') {
        DVar1 = FUN_01003f90(s_RUNPROGRAM_01010308,local_17c,0x104);
        if (DVar1 == 0) {
          FUN_01003e4b((HWND)0x0,0x4b1,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
          DAT_01015fcc = 0x80070714;
          return 0;
        }
      }
      else {
        lstrcpyA((LPSTR)local_17c,&DAT_010161fe);
      }
    }
    if (local_10 == 1) {
      DVar1 = FUN_01003f90(s_POSTRUNPROGRAM_01010318,local_17c,0x104);
      if (DVar1 == 0) {
        FUN_01003e4b((HWND)0x0,0x4b1,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
        DAT_01015fcc = 0x80070714;
        return 0;
      }
      if (DAT_010161fe != '\0') {
        return 1;
      }
      iVar3 = lstrcmpiA((LPCSTR)local_17c,s_<None>_01010338);
      if (iVar3 == 0) {
        return 1;
      }
    }
    iVar3 = FUN_010020e1((CHAR *)local_17c,&local_8,&local_c);
    if (iVar3 == 0) {
      return 0;
    }
    if ((DAT_01016704 == 1) || (_DAT_01015fe0 == 0)) {
LAB_01003898:
      if (local_c != 0) goto LAB_010038a1;
LAB_0100396d:
      iVar3 = FUN_01003ae2(local_8,&local_78);
      if (iVar3 == 0) {
        DVar1 = GetLastError();
        FormatMessageA(0x1000,(LPCVOID)0x0,DVar1,0,local_37c,0x200,(va_list *)0x0);
        FUN_01003e4b((HWND)0x0,0x4c4,local_8,local_37c,0x10,0);
        LocalFree(local_8);
        return 0;
      }
    }
    else {
      if (local_c == 0) {
        FUN_0100256d();
        goto LAB_01003898;
      }
LAB_010038a1:
      if (_DAT_01010464 == 0) {
        FUN_01003e4b((HWND)0x0,0x4c7,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
        LocalFree(local_8);
        DAT_01015fcc = 0x8007042b;
        return 0;
      }
      if ((local_c == 0) || ((DAT_01015fc4 & 4) == 0)) goto LAB_0100396d;
      hModule = (HMODULE)FUN_01005c49("advpack.dll");
      if (hModule == (HMODULE)0x0) {
        FUN_01003e4b((HWND)0x0,0x4c8,"advpack.dll",(LPCSTR)0x0,0x10,0);
        LocalFree(local_8);
        DAT_01015fcc = FUN_01005aa0();
        return 0;
      }
      pFVar2 = GetProcAddress(hModule,s_DoInfInstall_01010450);
      if (pFVar2 == (FARPROC)0x0) {
        FUN_01003e4b((HWND)0x0,0x4c9,s_DoInfInstall_01010450,(LPCSTR)0x0,0x10,0);
        FreeLibrary(hModule);
        LocalFree(local_8);
        DAT_01015fcc = FUN_01005aa0();
        return 0;
      }
      local_20 = DAT_01016704;
      local_34 = 0;
      local_2c = local_8;
      local_24 = local_17c;
      local_1c = (uint)DAT_01015ff4;
      local_30 = &DAT_010156e4;
      local_28 = &DAT_01015774;
      if (_DAT_01015ff0 != 0) {
        local_1c = (uint)CONCAT12(1,DAT_01015ff4);
      }
      if ((DAT_01015fc4 & 8) != 0) {
        local_1c = local_1c | 0x20000;
      }
      if ((DAT_01015fc4 & 0x10) != 0) {
        local_1c = local_1c | 0x40000;
      }
      local_18 = DAT_01015fc8;
      iVar3 = (*pFVar2)(&local_34);
      if (iVar3 == 0) {
        FreeLibrary(hModule);
        LocalFree(local_8);
        DAT_01015fcc = 0x8007042b;
        return 0;
      }
      FreeLibrary(hModule);
      FUN_01005a57(0,1);
    }
    LocalFree(local_8);
    local_10 = local_10 + 1;
    if (1 < local_10) {
      return 1;
    }
  } while( true );
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_01003ae2(LPSTR param_1,LPSTARTUPINFOA param_2)

{
  BOOL BVar1;
  _PROCESS_INFORMATION local_18;
  uint local_8;
  
  if (param_1 != (LPSTR)0x0) {
    local_18.hProcess = (HANDLE)0x0;
    local_18.hThread = (HANDLE)0x0;
    local_18.dwProcessId = 0;
    local_18.dwThreadId = 0;
    BVar1 = CreateProcessA((LPCSTR)0x0,param_1,(LPSECURITY_ATTRIBUTES)0x0,(LPSECURITY_ATTRIBUTES)0x0
                           ,0,0x20,(LPVOID)0x0,(LPCSTR)0x0,param_2,&local_18);
    if (BVar1 != 0) {
      WaitForSingleObject(local_18.hProcess,0xffffffff);
      GetExitCodeProcess(local_18.hProcess,&local_8);
      if ((((_DAT_01015fe8 == 0) && ((DAT_01015fbc & 1) != 0)) && ((DAT_01015fbc & 2) == 0)) &&
         ((local_8 & 0xff000000) == 0xaa000000)) {
        DAT_01015fbc = local_8;
      }
      FUN_01005a57(local_8,0);
      CloseHandle(local_18.hThread);
      CloseHandle(local_18.hProcess);
      return 1;
    }
    DAT_01015fcc = FUN_01005aa0();
  }
  return 0;
}



void FUN_01003b9b(void)

{
  DWORD DVar1;
  undefined4 *lpString1;
  int iVar2;
  UINT UVar3;
  undefined4 *puVar4;
  uint uVar5;
  
  DVar1 = FUN_01003f90(s_FINISHMSG_010102f8,(undefined4 *)0x0,0);
  lpString1 = (undefined4 *)LocalAlloc(0x40,DVar1 + 1);
  if (lpString1 == (undefined4 *)0x0) {
    FUN_01003e4b((HWND)0x0,0x4b5,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
    return;
  }
  DVar1 = FUN_01003f90(s_FINISHMSG_010102f8,lpString1,DVar1);
  if (DVar1 == 0) {
    uVar5 = 0x10;
    UVar3 = 0x4b1;
    puVar4 = (undefined4 *)0x0;
  }
  else {
    iVar2 = lstrcmpA((LPCSTR)lpString1,s_<None>_01010338);
    if (iVar2 == 0) goto LAB_01003c12;
    uVar5 = 0x40;
    UVar3 = 0x3e9;
    puVar4 = lpString1;
  }
  FUN_01003e4b((HWND)0x0,UVar3,(LPCSTR)puVar4,(LPCSTR)0x0,uVar5,0);
LAB_01003c12:
  LocalFree(lpString1);
  return;
}



bool FUN_01003c1d(HWND param_1,undefined4 param_2,LPSTR param_3)

{
  LPCSTR lpString2;
  HMODULE hModule;
  UINT UVar1;
  HWND local_38;
  int local_34;
  LPCSTR local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  FARPROC local_18;
  FARPROC local_14;
  FARPROC local_10;
  int local_c;
  FARPROC local_8;
  
  local_c = 0;
  lpString2 = (LPCSTR)LocalAlloc(0x40,0x104);
  if (lpString2 == (LPCSTR)0x0) {
    UVar1 = 0x4b5;
  }
  else {
    hModule = LoadLibraryA(s_SHELL32_DLL_010103d0);
    if (hModule == (HMODULE)0x0) {
      LocalFree(lpString2);
      UVar1 = 0x4c2;
    }
    else {
      local_18 = GetProcAddress(hModule,s_SHGetSpecialFolderLocation_010103e0);
      if ((((local_18 != (FARPROC)0x0) &&
           (local_8 = GetProcAddress(hModule,s_SHBrowseForFolder_01010400), local_8 != (FARPROC)0x0)
           ) && (local_10 = GetProcAddress(hModule,(LPCSTR)0xc3), local_10 != (FARPROC)0x0)) &&
         (local_14 = GetProcAddress(hModule,s_SHGetPathFromIDList_01010418),
         local_14 != (FARPROC)0x0)) {
        (*local_18)(param_1,0x11,&local_c);
        local_38 = param_1;
        *param_3 = '\0';
        local_34 = local_c;
        local_2c = param_2;
        local_24 = 0;
        local_28 = 1;
        local_20 = 0;
        local_30 = lpString2;
        local_8 = (FARPROC)(*local_8)(&local_38);
        if (local_8 != (FARPROC)0x0) {
          (*local_14)(local_8,lpString2);
          if (*lpString2 != '\0') {
            lstrcpyA(param_3,lpString2);
          }
          (*local_10)(local_8);
        }
        if (local_c != 0) {
          (*local_10)(local_c);
        }
        FreeLibrary(hModule);
        LocalFree(lpString2);
        return (bool)('\x01' - (*param_3 == '\0'));
      }
      FreeLibrary(hModule);
      LocalFree(lpString2);
      UVar1 = 0x4c1;
    }
  }
  FUN_01003e4b(param_1,UVar1,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
  return false;
}



void FUN_01003d7d(HWND param_1,HWND param_2)

{
  tagRECT local_34;
  tagRECT local_24;
  int local_14;
  int local_10;
  int local_c;
  HDC local_8;
  
  GetWindowRect(param_1,&local_34);
  local_34.right = local_34.right - local_34.left;
  local_34.bottom = local_34.bottom - local_34.top;
  GetWindowRect(param_2,&local_24);
  local_24.right = local_24.right - local_24.left;
  local_14 = local_24.bottom - local_24.top;
  local_8 = GetDC(param_1);
  local_10 = GetDeviceCaps(local_8,8);
  local_c = GetDeviceCaps(local_8,10);
  ReleaseDC(param_1,local_8);
  local_24.left = local_24.left + (local_24.right - local_34.right) / 2;
  if (local_24.left < 0) {
    local_24.left = 0;
  }
  else if (local_10 < local_24.left + local_34.right) {
    local_24.left = local_10 - local_34.right;
  }
  local_24.top = local_24.top + (local_14 - local_34.bottom) / 2;
  if (local_24.top < 0) {
    local_24.top = 0;
  }
  else if (local_c < local_24.top + local_34.bottom) {
    local_24.top = local_c - local_34.bottom;
  }
  SetWindowPos(param_1,(HWND)0x0,local_24.left,local_24.top,0,0,5);
  return;
}



int FUN_01003e4b(HWND param_1,UINT param_2,LPCSTR param_3,LPCSTR param_4,uint param_5,uint param_6)

{
  int iVar1;
  int iVar2;
  int iVar3;
  byte *lpString1;
  CHAR local_204 [512];
  
  if (((byte)DAT_01015ff4 & 1) == 0) {
    FUN_01004007(param_2,local_204,0x200);
    if (param_4 == (LPCSTR)0x0) {
      if (param_3 == (LPCSTR)0x0) {
        iVar1 = lstrlenA(local_204);
        lpString1 = (byte *)LocalAlloc(0x40,iVar1 + 1);
        if (lpString1 == (byte *)0x0) {
          return -1;
        }
        lstrcpyA((LPSTR)lpString1,local_204);
      }
      else {
        iVar1 = lstrlenA(param_3);
        iVar2 = lstrlenA(local_204);
        lpString1 = (byte *)LocalAlloc(0x40,iVar1 + iVar2 + 100);
        if (lpString1 == (byte *)0x0) {
          return -1;
        }
        FUN_01005fdf(lpString1,local_204);
      }
    }
    else {
      iVar1 = lstrlenA(param_4);
      iVar2 = lstrlenA(param_3);
      iVar3 = lstrlenA(local_204);
      lpString1 = (byte *)LocalAlloc(0x40,iVar1 + iVar2 + iVar3 + 100);
      if (lpString1 == (byte *)0x0) {
        return -1;
      }
      FUN_01005fdf(lpString1,local_204);
    }
    MessageBeep(param_5);
    iVar1 = MessageBoxA(param_1,(LPCSTR)lpString1,&DAT_010156e4,param_5 | param_6 | 0x10000);
    LocalFree(lpString1);
  }
  else {
    iVar1 = 1;
  }
  return iVar1;
}



DWORD FUN_01003f90(LPCSTR param_1,undefined4 *param_2,uint param_3)

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
    if (DVar2 == 0) {
      DVar2 = 0;
    }
    else {
      pHVar1 = FindResourceA((HMODULE)0x0,param_1,(LPCSTR)0xa);
      hResData = LoadResource((HMODULE)0x0,pHVar1);
      hResData_00 = (undefined4 *)LockResource(hResData);
      if (hResData_00 == (undefined4 *)0x0) {
        DVar2 = 0;
      }
      else {
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
      }
    }
  }
  return DVar2;
}



LPSTR FUN_01004007(UINT param_1,LPSTR param_2,int param_3)

{
  if (param_2 != (LPSTR)0x0) {
    *param_2 = '\0';
    LoadStringA(DAT_01016700,param_1,param_2,param_3);
  }
  return param_2;
}



undefined4 FUN_0100402e(LPSTR param_1,int param_2,LPCSTR param_3,LPCSTR param_4)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  
  iVar1 = lstrlenA(param_4);
  iVar2 = lstrlenA(param_3);
  if (iVar1 + iVar2 + 1 < param_2) {
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



bool FUN_01004096(LPCSTR param_1)

{
  HANDLE hObject;
  
  hObject = CreateFileA(param_1,0x80000000,0,(LPSECURITY_ATTRIBUTES)0x0,3,0x80,(HANDLE)0xffffffff);
  if (hObject != (HANDLE)0xffffffff) {
    CloseHandle(hObject);
  }
  return hObject != (HANDLE)0xffffffff;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_010040ca(LPCSTR param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  INT_PTR IVar2;
  
  bVar1 = FUN_01004096(param_1);
  if (((CONCAT31(extraout_var,bVar1) != 0) && (((byte)DAT_01015ff4 & 1) == 0)) &&
     (_DAT_0101576c == 0)) {
    DAT_01015994 = param_1;
    IVar2 = DialogBoxParamA(DAT_01016700,(LPCSTR)0x7d3,DAT_01010468,FUN_010031db,0);
    if (IVar2 != 6) {
      if (IVar2 == 7) {
        return 0;
      }
      if (IVar2 == 0x839) {
        _DAT_0101576c = 1;
        return 1;
      }
    }
  }
  return 1;
}



undefined4 FUN_0100413b(LPCSTR param_1)

{
  LPSTR *hMem;
  undefined4 uVar1;
  int iVar2;
  LPSTR lpString1;
  
  hMem = (LPSTR *)LocalAlloc(0x40,8);
  if (hMem == (LPSTR *)0x0) {
    FUN_01003e4b(DAT_01010468,0x4b5,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
    uVar1 = 0;
  }
  else {
    iVar2 = lstrlenA(param_1);
    lpString1 = (LPSTR)LocalAlloc(0x40,iVar2 + 1);
    *hMem = lpString1;
    if (lpString1 == (LPSTR)0x0) {
      FUN_01003e4b(DAT_01010468,0x4b5,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
      LocalFree(hMem);
      uVar1 = 0;
    }
    else {
      lstrcpyA(lpString1,param_1);
      uVar1 = 1;
      hMem[1] = (LPSTR)DAT_01015770;
      DAT_01015770 = hMem;
    }
  }
  return uVar1;
}



HANDLE FUN_010041c8(LPCSTR param_1,uint param_2)

{
  HANDLE pvVar1;
  DWORD dwCreationDisposition;
  DWORD dwDesiredAccess;
  
  if ((param_2 & 8) == 0) {
    dwDesiredAccess = 0x80000000;
    if ((param_2 & 3) != 0) {
      dwDesiredAccess = 0x40000000;
    }
    if ((param_2 & 0x100) == 0) {
      dwCreationDisposition = (-(uint)((param_2 & 0x200) == 0) & 0xfffffffe) + 5;
    }
    else if ((param_2 & 0x400) == 0) {
      dwCreationDisposition = (-(uint)((param_2 & 0x200) == 0) & 2) + 2;
    }
    else {
      dwCreationDisposition = 1;
    }
    pvVar1 = CreateFileA(param_1,dwDesiredAccess,0,(LPSECURITY_ATTRIBUTES)0x0,dwCreationDisposition,
                         0x80,(HANDLE)0xffffffff);
  }
  else {
    pvVar1 = (HANDLE)0xffffffff;
  }
  return pvVar1;
}



int __cdecl FUN_01004231(LPCSTR param_1,uint param_2)

{
  undefined4 uVar1;
  undefined4 uVar2;
  int *piVar3;
  int iVar4;
  HANDLE pvVar5;
  int iVar6;
  
  piVar3 = &DAT_01016340;
  iVar6 = 0;
  do {
    if (*piVar3 == 1) break;
    piVar3 = piVar3 + 6;
    iVar6 = iVar6 + 1;
  } while (piVar3 < &DAT_01016700);
  if (iVar6 == 0x28) {
    FUN_01003e4b(DAT_01010468,0x4bb,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
    iVar6 = -1;
  }
  else {
    iVar4 = lstrcmpA(param_1,s__MEMCAB_01010398);
    uVar2 = DAT_010156d4;
    uVar1 = DAT_010156d0;
    if (iVar4 == 0) {
      if ((param_2 & 0x10b) == 0) {
        iVar4 = iVar6 * 0x18;
        (&DAT_01016340)[iVar6 * 6] = 0;
        *(undefined4 *)(&DAT_01016344 + iVar4) = 1;
        *(undefined4 *)(&DAT_01016348 + iVar4) = uVar1;
        *(undefined4 *)(&DAT_01016350 + iVar4) = uVar2;
        *(undefined4 *)(&DAT_0101634c + iVar4) = 0;
      }
      else {
        iVar6 = -1;
      }
    }
    else {
      pvVar5 = FUN_010041c8(param_1,param_2);
      *(HANDLE *)(&DAT_01016354 + iVar6 * 0x18) = pvVar5;
      if (pvVar5 == (HANDLE)0xffffffff) {
        iVar6 = -1;
      }
      else {
        (&DAT_01016340)[iVar6 * 6] = 0;
        *(undefined4 *)(&DAT_01016344 + iVar6 * 0x18) = 0;
      }
    }
  }
  return iVar6;
}



uint __cdecl FUN_01004306(int param_1,undefined4 *param_2,uint param_3)

{
  int *piVar1;
  BOOL BVar2;
  int iVar3;
  uint uVar4;
  undefined4 *puVar5;
  uint local_8;
  
  iVar3 = param_1 * 0x18;
  if (*(int *)(&DAT_01016344 + iVar3) == 0) {
    BVar2 = ReadFile(*(HANDLE *)(&DAT_01016354 + iVar3),param_2,param_3,&param_3,(LPOVERLAPPED)0x0);
    local_8 = param_3;
    if (BVar2 == 0) {
      local_8 = 0xffffffff;
    }
  }
  else if (*(int *)(&DAT_01016344 + iVar3) == 1) {
    piVar1 = (int *)(&DAT_0101634c + iVar3);
    local_8 = *(int *)(&DAT_01016350 + iVar3) - *piVar1;
    if (param_3 <= local_8) {
      local_8 = param_3;
    }
    puVar5 = (undefined4 *)(*piVar1 + *(int *)(&DAT_01016348 + iVar3));
    for (uVar4 = local_8 >> 2; uVar4 != 0; uVar4 = uVar4 - 1) {
      *param_2 = *puVar5;
      puVar5 = puVar5 + 1;
      param_2 = param_2 + 1;
    }
    for (uVar4 = local_8 & 3; uVar4 != 0; uVar4 = uVar4 - 1) {
      *(undefined *)param_2 = *(undefined *)puVar5;
      puVar5 = (undefined4 *)((int)puVar5 + 1);
      param_2 = (undefined4 *)((int)param_2 + 1);
    }
    *piVar1 = *piVar1 + local_8;
  }
  return local_8;
}



undefined4 __cdecl FUN_01004419(int param_1)

{
  undefined4 uVar1;
  BOOL BVar2;
  int iVar3;
  
  iVar3 = param_1 * 0x18;
  if (*(int *)(&DAT_01016344 + iVar3) == 1) {
    (&DAT_01016340)[param_1 * 6] = 1;
    uVar1 = 0;
    *(undefined4 *)(&DAT_01016348 + iVar3) = 0;
    *(undefined4 *)(&DAT_01016350 + iVar3) = 0;
    *(undefined4 *)(&DAT_0101634c + iVar3) = 0;
  }
  else {
    BVar2 = CloseHandle(*(HANDLE *)(&DAT_01016354 + iVar3));
    uVar1 = 0xffffffff;
    if (BVar2 != 0) {
      (&DAT_01016340)[param_1 * 6] = 1;
      uVar1 = 0;
    }
  }
  return uVar1;
}



DWORD __cdecl FUN_0100446d(int param_1,int param_2,int param_3)

{
  DWORD DVar1;
  int iVar2;
  DWORD local_8;
  
  iVar2 = param_1 * 0x18;
  if (*(int *)(&DAT_01016344 + iVar2) != 1) {
    if (param_3 == 0) {
      local_8 = 0;
    }
    else if (param_3 == 1) {
      local_8 = 1;
    }
    else if (param_3 == 2) {
      local_8 = 2;
    }
    DVar1 = SetFilePointer(*(HANDLE *)(&DAT_01016354 + iVar2),param_2,(PLONG)0x0,local_8);
    if (DVar1 == 0xffffffff) {
      return 0xffffffff;
    }
    return DVar1;
  }
  if (param_3 != 0) {
    if (param_3 == 1) {
      *(int *)(&DAT_0101634c + iVar2) = *(int *)(&DAT_0101634c + iVar2) + param_2;
      goto LAB_010044c0;
    }
    if (param_3 != 2) {
      return 0xffffffff;
    }
    param_2 = *(int *)(&DAT_01016350 + iVar2) + param_2;
  }
  *(int *)(&DAT_0101634c + iVar2) = param_2;
LAB_010044c0:
  return *(DWORD *)(&DAT_0101634c + iVar2);
}



bool FUN_01004507(int param_1,WORD param_2,WORD param_3)

{
  char cVar1;
  BOOL BVar2;
  _FILETIME local_14;
  _FILETIME local_c;
  
  if (*(int *)(&DAT_01016344 + param_1 * 0x18) == 1) {
    cVar1 = '\0';
  }
  else {
    BVar2 = DosDateTimeToFileTime(param_2,param_3,&local_14);
    if (BVar2 == 0) {
      cVar1 = '\0';
    }
    else {
      BVar2 = LocalFileTimeToFileTime(&local_14,&local_c);
      cVar1 = '\0';
      if (BVar2 != 0) {
        BVar2 = SetFileTime(*(HANDLE *)(&DAT_01016354 + param_1 * 0x18),&local_c,&local_c,&local_c);
        cVar1 = '\x01' - (BVar2 == 0);
      }
    }
  }
  return (bool)cVar1;
}



ushort FUN_0100456f(ushort param_1)

{
  ushort uVar1;
  
  uVar1 = 0x80;
  if (param_1 != 0) {
    uVar1 = param_1 & 0x27;
  }
  return uVar1;
}



undefined4 FUN_010045a1(void)

{
  return 0xffffffff;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int __cdecl FUN_010045a7(int param_1,int param_2)

{
  bool bVar1;
  ushort uVar2;
  int iVar3;
  int iVar4;
  undefined3 extraout_var;
  undefined2 extraout_var_00;
  BOOL BVar5;
  CHAR local_108 [260];
  
  if (_DAT_01015768 == 0) {
    if (param_1 == 0) {
      iVar3 = FUN_01004746(param_2);
    }
    else if (param_1 == 1) {
      iVar3 = 0;
    }
    else if (param_1 == 2) {
      if (DAT_01010468 != (HWND)0x0) {
        SetDlgItemTextA(DAT_01010468,0x837,*(LPCSTR *)(param_2 + 4));
      }
      iVar3 = FUN_0100402e(local_108,0x104,&DAT_01015774,*(LPCSTR *)(param_2 + 4));
      if (iVar3 == 0) {
        iVar3 = -1;
      }
      else {
        iVar3 = FUN_010040ca(local_108);
        if (iVar3 == 0) {
          iVar3 = 0;
        }
        else {
          iVar3 = FUN_01004231(local_108,0x8302);
          if (iVar3 == -1) {
            iVar3 = -1;
          }
          else {
            iVar4 = FUN_0100413b(local_108);
            if (iVar4 == 0) {
              iVar3 = -1;
            }
            else {
              _DAT_01015984 = _DAT_01015984 + 1;
            }
          }
        }
      }
    }
    else if (param_1 == 3) {
      iVar3 = FUN_0100402e(local_108,0x104,&DAT_01015774,*(LPCSTR *)(param_2 + 4));
      if (iVar3 == 0) {
        iVar3 = -1;
      }
      else {
        bVar1 = FUN_01004507(*(int *)(param_2 + 0x14),*(WORD *)(param_2 + 0x18),
                             *(WORD *)(param_2 + 0x1a));
        if (CONCAT31(extraout_var,bVar1) == 0) {
          iVar3 = -1;
        }
        else {
          FUN_01004419(*(int *)(param_2 + 0x14));
          uVar2 = FUN_0100456f(*(ushort *)(param_2 + 0x1c));
          BVar5 = SetFileAttributesA(local_108,CONCAT22(extraout_var_00,uVar2));
          iVar3 = (-(uint)(BVar5 == 0) & 0xfffffffe) + 1;
        }
      }
    }
    else if (param_1 == 4) {
      iVar3 = FUN_010045a1();
    }
    else {
      iVar3 = 0;
    }
  }
  else {
    if (param_1 == 3) {
      FUN_01004419(*(int *)(param_2 + 0x14));
    }
    iVar3 = -1;
  }
  return iVar3;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_01004746(int param_1)

{
  int iVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  
  puVar2 = &DAT_01015cac;
  puVar3 = &DAT_0101599c;
  for (iVar1 = 0xc4; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  lstrcpyA((LPSTR)&DAT_01015cac,*(LPCSTR *)(param_1 + 0xc));
  lstrcpyA(&DAT_01015db0,*(LPCSTR *)(param_1 + 4));
  lstrcpyA(&DAT_01015eb4,*(LPCSTR *)(param_1 + 8));
  _DAT_01015fb8 = *(undefined2 *)(param_1 + 0x1e);
  _DAT_01015fba = *(undefined2 *)(param_1 + 0x20);
  return 0;
}



bool FUN_0100479b(void)

{
  undefined4 *puVar1;
  int iVar2;
  int iVar3;
  int *piVar4;
  undefined4 local_28 [3];
  int local_1c [4];
  int local_c;
  int local_8;
  
  piVar4 = local_1c;
  for (iVar3 = 6; iVar3 != 0; iVar3 = iVar3 + -1) {
    *piVar4 = 0;
    piVar4 = piVar4 + 1;
  }
  puVar1 = FUN_0100a970(&LAB_01004589,&LAB_01004596,FUN_01004231,FUN_01004306,&LAB_01004389,
                        FUN_01004419,FUN_0100446d,1,local_28);
  if ((((puVar1 != (undefined4 *)0x0) &&
       (iVar3 = FUN_01004231(s__MEMCAB_01010398,0x8000), iVar3 != -1)) &&
      (iVar2 = FUN_0100aa80(puVar1,iVar3,local_1c), iVar2 != 0)) &&
     (((DAT_010156d4 == local_1c[0] && (local_c == 0)) &&
      ((local_8 == 0 && (iVar3 = FUN_01004419(iVar3), iVar3 != -1)))))) {
    iVar3 = FUN_0100aa10(puVar1);
    return (bool)('\x01' - (iVar3 == 0));
  }
  return false;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

WPARAM FUN_01004856(void)

{
  bool bVar1;
  undefined3 extraout_var;
  WPARAM wParam;
  HWND pHVar2;
  undefined3 extraout_var_00;
  int **ppiVar3;
  int iVar4;
  
  bVar1 = FUN_010049da();
  if (CONCAT31(extraout_var,bVar1) == 0) {
    wParam = 0;
  }
  else {
    if (DAT_01010468 != (HWND)0x0) {
      iVar4 = 0;
      pHVar2 = GetDlgItem(DAT_01010468,0x842);
      ShowWindow(pHVar2,iVar4);
      iVar4 = 5;
      pHVar2 = GetDlgItem(DAT_01010468,0x841);
      ShowWindow(pHVar2,iVar4);
    }
    bVar1 = FUN_0100479b();
    if (CONCAT31(extraout_var_00,bVar1) == 0) {
      wParam = 0;
      FUN_01003e4b(DAT_01010468,0x4ba,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
    }
    else {
      wParam = 0;
      ppiVar3 = (int **)FUN_0100a970(&LAB_01004589,&LAB_01004596,FUN_01004231,FUN_01004306,
                                     &LAB_01004389,FUN_01004419,FUN_0100446d,1,&DAT_010156d8);
      if (ppiVar3 == (int **)0x0) {
        FUN_01003e4b(DAT_01010468,DAT_010156d8 + 0x514,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
      }
      else {
        wParam = FUN_0100ab40(ppiVar3,s__MEMCAB_01010398,"",0,(int *)FUN_010045a7,(int *)0x0,
                              (int *)&DAT_010156d0);
        if ((wParam != 0) && (iVar4 = FUN_0100aa10(ppiVar3), iVar4 == 0)) {
          wParam = 0;
          FUN_01003e4b(DAT_01010468,DAT_010156d8 + 0x514,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
        }
      }
    }
    if (DAT_010156d0 != (HGLOBAL)0x0) {
      FreeResource(DAT_010156d0);
      DAT_010156d0 = (HGLOBAL)0x0;
    }
    if ((wParam == 0) && (_DAT_01015768 == 0)) {
      FUN_01003e4b((HWND)0x0,0x4f8,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
    }
    if ((((byte)DAT_01015ff4 & 1) == 0) && ((DAT_01015fc4 & 1) == 0)) {
      SendMessageA(DAT_01010468,0xfa1,wParam,0);
    }
  }
  return wParam;
}



bool FUN_010049da(void)

{
  HRSRC hResInfo;
  HGLOBAL hResData;
  
  DAT_010156d4 = FUN_01003f90(s_CABINET_01010328,(undefined4 *)0x0,0);
  hResInfo = FindResourceA((HMODULE)0x0,s_CABINET_01010328,(LPCSTR)0xa);
  hResData = LoadResource((HMODULE)0x0,hResInfo);
  DAT_010156d0 = LockResource(hResData);
  return (bool)('\x01' - (DAT_010156d0 == (LPVOID)0x0));
}



undefined4 FUN_01004a17(void)

{
  DWORD DVar1;
  int iVar2;
  
  DVar1 = FUN_01003f90(s_FILESIZES_01010350,&DAT_01016310,0x24);
  if (DVar1 == 0x24) {
    DAT_01015988 = DAT_01016330;
    if (DAT_01016330 == 0) {
      FUN_01003e4b((HWND)0x0,0x4c6,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
      DAT_01015fcc = 0x80070714;
    }
    else {
      FUN_01003f90(s_PACKINSTSPACE_01010378,&DAT_01015fc8,4);
      iVar2 = FUN_01005ac0(&LAB_01005b68);
      if (iVar2 != 0) {
        return 1;
      }
      FUN_01003e4b((HWND)0x0,0x4c6,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
    }
  }
  else {
    FUN_01003e4b((HWND)0x0,0x4b1,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
    DAT_01015fcc = 0x80070714;
  }
  return 0;
}



undefined4 FUN_01004ab4(void)

{
  DWORD DVar1;
  undefined4 *lpString1;
  int iVar2;
  
  DVar1 = FUN_01003f90(s_UPROMPT_01010330,(undefined4 *)0x0,0);
  lpString1 = (undefined4 *)LocalAlloc(0x40,DVar1 + 1);
  if (lpString1 == (undefined4 *)0x0) {
    FUN_01003e4b((HWND)0x0,0x4b5,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
    DAT_01015fcc = FUN_01005aa0();
  }
  else {
    DVar1 = FUN_01003f90(s_UPROMPT_01010330,lpString1,DVar1);
    if (DVar1 == 0) {
      FUN_01003e4b((HWND)0x0,0x4b1,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
      LocalFree(lpString1);
      DAT_01015fcc = 0x80070714;
    }
    else {
      iVar2 = lstrcmpA((LPCSTR)lpString1,s_<None>_01010338);
      if (iVar2 == 0) {
        LocalFree(lpString1);
        return 1;
      }
      iVar2 = FUN_01003e4b((HWND)0x0,0x3e9,(LPCSTR)lpString1,(LPCSTR)0x0,0x20,4);
      LocalFree(lpString1);
      if (iVar2 == 6) {
        DAT_01015fcc = 0;
        return 1;
      }
      DAT_01015fcc = 0x800704c7;
    }
  }
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_01004b89(void)

{
  LPCSTR *ppCVar1;
  LPCSTR *hMem;
  
  hMem = DAT_01015770;
  if (DAT_01015770 != (LPCSTR *)0x0) {
    do {
      if ((_DAT_01015fe4 == 0) && (_DAT_01015fc0 == 0)) {
        SetFileAttributesA(*hMem,0x80);
        DeleteFileA(*hMem);
      }
      ppCVar1 = (LPCSTR *)hMem[1];
      LocalFree(*hMem);
      LocalFree(hMem);
      hMem = ppCVar1;
    } while (ppCVar1 != (LPCSTR *)0x0);
  }
  if ((DAT_01016704 != 1) && (_DAT_01015fe0 != 0)) {
    FUN_01002524();
  }
  if (((_DAT_01015fe0 != 0) && (_DAT_01015fe4 == 0)) && (_DAT_01015fc0 == 0)) {
    _DAT_01015fe0 = 0;
    SetCurrentDirectoryA("..");
    FUN_010026b2(&DAT_01015774);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_01004c25(LPCSTR param_1,LPSTR param_2)

{
  DWORD DVar1;
  BOOL BVar2;
  UINT UVar3;
  int iVar4;
  int iVar5;
  CHAR local_108 [260];
  
  iVar5 = 0;
  iVar4 = 0;
  do {
    if (399 < iVar4) goto LAB_01004c99;
    wsprintfA(local_108,"MSE%03d",iVar4);
    lstrcpyA(param_2,param_1);
    FUN_010027e1(param_2,local_108);
    DVar1 = GetFileAttributesA(param_2);
    iVar4 = iVar4 + 1;
  } while (DVar1 != 0xffffffff);
  iVar5 = 0;
  BVar2 = CreateDirectoryA(param_2,(LPSECURITY_ATTRIBUTES)0x0);
  if (BVar2 != 0) {
    iVar5 = 1;
    _DAT_01015fe0 = 1;
  }
LAB_01004c99:
  if (iVar5 == 0) {
    UVar3 = GetTempFileNameA(param_1,"MSE",0,param_2);
    if (UVar3 != 0) {
      iVar5 = 1;
      DeleteFileA(param_2);
    }
  }
  return iVar5;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_01004cc9(LPCSTR param_1,int param_2,uint param_3)

{
  bool bVar1;
  int iVar2;
  BOOL BVar3;
  undefined3 extraout_var;
  CHAR local_108 [260];
  
  if (param_2 == 0) {
    lstrcpyA(&DAT_01015774,param_1);
  }
  else {
    iVar2 = FUN_01004c25(param_1,local_108);
    if (iVar2 == 0) {
      return 0;
    }
    lstrcpyA(&DAT_01015774,local_108);
    FUN_010027e1(&DAT_01015774,"");
  }
  iVar2 = FUN_010050dd(&DAT_01015774);
  if (iVar2 == 0) {
    BVar3 = CreateDirectoryA(&DAT_01015774,(LPSECURITY_ATTRIBUTES)0x0);
    if (BVar3 == 0) {
      DAT_01015fcc = FUN_01005aa0();
      return 0;
    }
    _DAT_01015fe0 = 1;
  }
  bVar1 = FUN_010051cf(&DAT_01015774,param_3,0);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    if (_DAT_01015fe0 != 0) {
      _DAT_01015fe0 = 0;
      RemoveDirectoryA(&DAT_01015774);
    }
    return 0;
  }
  DAT_01015fcc = 0;
  return 1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

INT_PTR FUN_01004d94(void)

{
  char cVar1;
  bool bVar2;
  DWORD DVar3;
  undefined4 *lpString1;
  INT_PTR IVar4;
  int iVar5;
  uint uVar6;
  undefined3 extraout_var;
  undefined3 extraout_var_00;
  UINT UVar7;
  undefined3 extraout_var_01;
  undefined3 extraout_var_02;
  undefined3 extraout_var_03;
  undefined3 extraout_var_04;
  char local_108 [3];
  undefined local_105;
  
  DVar3 = FUN_01003f90(s_RUNPROGRAM_01010308,(undefined4 *)0x0,0);
  lpString1 = (undefined4 *)LocalAlloc(0x40,DVar3 + 1);
  if (lpString1 == (undefined4 *)0x0) {
    FUN_01003e4b((HWND)0x0,0x4b5,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
    DAT_01015fcc = FUN_01005aa0();
    IVar4 = 0;
  }
  else {
    DVar3 = FUN_01003f90(s_RUNPROGRAM_01010308,lpString1,DVar3);
    if (DVar3 == 0) {
      FUN_01003e4b((HWND)0x0,0x4b1,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
      LocalFree(lpString1);
      DAT_01015fcc = 0x80070714;
      IVar4 = 0;
    }
    else {
      iVar5 = lstrcmpA((LPCSTR)lpString1,s_<None>_01010338);
      if (iVar5 == 0) {
        _DAT_01015fc0 = 1;
      }
      LocalFree(lpString1);
      if (DAT_010160fa == '\0') {
        if ((_DAT_01015fe4 == 0) && (_DAT_01015fc0 == 0)) {
          DVar3 = GetTempPathA(0x104,&DAT_01015774);
          if (DVar3 != 0) {
            iVar5 = FUN_01004cc9(&DAT_01015774,1,3);
            if (iVar5 != 0) {
              return 1;
            }
            bVar2 = FUN_010029d0(&DAT_01015774);
            if ((CONCAT31(extraout_var,bVar2) == 0) &&
               (iVar5 = FUN_01004cc9(&DAT_01015774,1,1), iVar5 != 0)) {
              return 1;
            }
          }
          DVar3 = GetModuleFileNameA(DAT_01016700,&DAT_01015774,0x104);
          if ((DVar3 != 0) && (DAT_01015775 != '\\')) {
            iVar5 = lstrlenA(&DAT_01015774);
            cVar1 = *(char *)((int)&DAT_01015770 + iVar5 + 3);
            while (cVar1 != '\\') {
              cVar1 = *(char *)((int)&DAT_01015770 + iVar5 + 2);
              iVar5 = iVar5 + -1;
            }
            (&DAT_01015774)[iVar5] = 0;
            iVar5 = FUN_01004cc9(&DAT_01015774,1,3);
            if (iVar5 != 0) {
              return 1;
            }
            bVar2 = FUN_010029d0(&DAT_01015774);
            if ((CONCAT31(extraout_var_00,bVar2) == 0) &&
               (iVar5 = FUN_01004cc9(&DAT_01015774,1,1), iVar5 != 0)) {
              return 1;
            }
          }
          do {
            lstrcpyA(local_108,"A:\\");
            while (local_108[0] < '[') {
              UVar7 = GetDriveTypeA(local_108);
              if ((((UVar7 == 6) || (UVar7 == 3)) &&
                  (DVar3 = GetFileAttributesA(local_108), DVar3 != 0xffffffff)) &&
                 ((bVar2 = FUN_010051cf(local_108,3,0), CONCAT31(extraout_var_01,bVar2) != 0 ||
                  ((bVar2 = FUN_010029d0(local_108), CONCAT31(extraout_var_02,bVar2) == 0 &&
                   (bVar2 = FUN_010051cf(local_108,1,0), CONCAT31(extraout_var_03,bVar2) != 0))))))
              {
                FUN_010027e1(local_108,"msdownld.tmp");
                uVar6 = FUN_010029ad(local_108);
                if (uVar6 == 0) {
                  local_108[0] = local_108[0] + '\x01';
                  local_105 = 0;
                }
                else {
                  SetFileAttributesA(local_108,2);
                  lstrcpyA(&DAT_01015774,local_108);
                  iVar5 = FUN_01004cc9(&DAT_01015774,1,0);
                  if (iVar5 != 0) {
                    return 1;
                  }
                }
              }
              else {
                local_108[0] = local_108[0] + '\x01';
              }
            }
            GetWindowsDirectoryA(local_108,0x104);
            bVar2 = FUN_010051cf(local_108,3,4);
          } while (CONCAT31(extraout_var_04,bVar2) != 0);
          IVar4 = 0;
        }
        else {
          IVar4 = DialogBoxParamA(DAT_01016700,(LPCSTR)0x7d2,(HWND)0x0,FUN_01002fa2,0);
        }
      }
      else {
        if ((DAT_010160fa != '\\') || (uVar6 = 0, DAT_010160fb != '\\')) {
          uVar6 = 1;
        }
        iVar5 = FUN_01004cc9(&DAT_010160fa,0,uVar6);
        if (iVar5 == 0) {
          FUN_01003e4b((HWND)0x0,0x4be,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
          IVar4 = 0;
        }
        else {
          IVar4 = 1;
        }
      }
    }
  }
  return IVar4;
}



undefined4 FUN_010050dd(LPCSTR param_1)

{
  char cVar1;
  undefined4 *lpFileName;
  HANDLE hObject;
  DWORD DVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  undefined4 *puVar6;
  LPCSTR pCVar7;
  char *pcVar8;
  char *pcVar9;
  undefined4 *puVar10;
  
  uVar3 = 0xffffffff;
  pCVar7 = param_1;
  do {
    if (uVar3 == 0) break;
    uVar3 = uVar3 - 1;
    cVar1 = *pCVar7;
    pCVar7 = pCVar7 + 1;
  } while (cVar1 != '\0');
  lpFileName = (undefined4 *)LocalAlloc(0x40,~uVar3 + 0x13);
  if (lpFileName == (undefined4 *)0x0) {
    FUN_01003e4b((HWND)0x0,0x4b5,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
  }
  else {
    uVar3 = 0xffffffff;
    pCVar7 = param_1;
    do {
      pcVar8 = pCVar7;
      if (uVar3 == 0) break;
      uVar3 = uVar3 - 1;
      pcVar8 = pCVar7 + 1;
      cVar1 = *pCVar7;
      pCVar7 = pcVar8;
    } while (cVar1 != '\0');
    uVar3 = ~uVar3;
    puVar6 = (undefined4 *)(pcVar8 + -uVar3);
    puVar10 = lpFileName;
    for (uVar4 = uVar3 >> 2; uVar4 != 0; uVar4 = uVar4 - 1) {
      *puVar10 = *puVar6;
      puVar6 = puVar6 + 1;
      puVar10 = puVar10 + 1;
    }
    for (uVar3 = uVar3 & 3; uVar3 != 0; uVar3 = uVar3 - 1) {
      *(undefined *)puVar10 = *(undefined *)puVar6;
      puVar6 = (undefined4 *)((int)puVar6 + 1);
      puVar10 = (undefined4 *)((int)puVar10 + 1);
    }
    uVar3 = 0xffffffff;
    pcVar8 = "~TMP4352.TMP";
    do {
      pcVar9 = pcVar8;
      if (uVar3 == 0) break;
      uVar3 = uVar3 - 1;
      pcVar9 = pcVar8 + 1;
      cVar1 = *pcVar8;
      pcVar8 = pcVar9;
    } while (cVar1 != '\0');
    uVar3 = ~uVar3;
    iVar5 = -1;
    puVar6 = lpFileName;
    do {
      puVar10 = puVar6;
      if (iVar5 == 0) break;
      iVar5 = iVar5 + -1;
      puVar10 = (undefined4 *)((int)puVar6 + 1);
      cVar1 = *(char *)puVar6;
      puVar6 = puVar10;
    } while (cVar1 != '\0');
    puVar6 = (undefined4 *)(pcVar9 + -uVar3);
    puVar10 = (undefined4 *)((int)puVar10 + -1);
    for (uVar4 = uVar3 >> 2; uVar4 != 0; uVar4 = uVar4 - 1) {
      *puVar10 = *puVar6;
      puVar6 = puVar6 + 1;
      puVar10 = puVar10 + 1;
    }
    for (uVar3 = uVar3 & 3; uVar3 != 0; uVar3 = uVar3 - 1) {
      *(undefined *)puVar10 = *(undefined *)puVar6;
      puVar6 = (undefined4 *)((int)puVar6 + 1);
      puVar10 = (undefined4 *)((int)puVar10 + 1);
    }
    hObject = CreateFileA((LPCSTR)lpFileName,0x40000000,0,(LPSECURITY_ATTRIBUTES)0x0,1,0x4000080,
                          (HANDLE)0x0);
    LocalFree(lpFileName);
    if (hObject != (HANDLE)0xffffffff) {
      CloseHandle(hObject);
      DVar2 = GetFileAttributesA(param_1);
      if ((DVar2 != 0xffffffff) && ((DVar2 & 0x10) != 0)) {
        DAT_01015fcc = 0;
        return 1;
      }
    }
  }
  DAT_01015fcc = FUN_01005aa0();
  return 0;
}



bool FUN_010051cf(LPCSTR param_1,uint param_2,int param_3)

{
  bool bVar1;
  BOOL BVar2;
  DWORD DVar3;
  int iVar4;
  uint uVar5;
  ushort uVar6;
  uint uVar7;
  uint uVar8;
  undefined4 *puVar9;
  DWORD DVar10;
  CHAR *pCVar11;
  DWORD DVar12;
  va_list *ppcVar13;
  CHAR local_328 [260];
  CHAR local_224;
  undefined4 local_223;
  DWORD local_24;
  DWORD local_20;
  undefined4 local_1c;
  CHAR local_18 [8];
  DWORD local_10;
  DWORD local_c;
  DWORD local_8;
  
  local_c = 0;
  local_10 = 0;
  local_8 = 0;
  local_20 = 0;
  if (param_2 != 0) {
    GetCurrentDirectoryA(0x104,local_328);
    BVar2 = SetCurrentDirectoryA(param_1);
    if (BVar2 == 0) {
      FUN_01003e4b((HWND)0x0,0x4bc,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
      DAT_01015fcc = FUN_01005aa0();
      return false;
    }
    BVar2 = GetDiskFreeSpaceA((LPCSTR)0x0,&local_c,&local_10,&local_8,&local_20);
    if (BVar2 == 0) {
      local_224 = '\0';
      puVar9 = &local_223;
      for (iVar4 = 0x7f; iVar4 != 0; iVar4 = iVar4 + -1) {
        *puVar9 = 0;
        puVar9 = puVar9 + 1;
      }
      *(undefined2 *)puVar9 = 0;
      *(undefined *)((int)puVar9 + 2) = 0;
      DAT_01015fcc = FUN_01005aa0();
      ppcVar13 = (va_list *)0x0;
      DVar12 = 0x200;
      pCVar11 = &local_224;
      DVar10 = 0;
      DVar3 = GetLastError();
      FormatMessageA(0x1000,(LPCVOID)0x0,DVar3,DVar10,pCVar11,DVar12,ppcVar13);
      FUN_01003e4b((HWND)0x0,0x4b0,param_1,&local_224,0x10,0);
      SetCurrentDirectoryA(local_328);
      return false;
    }
    BVar2 = GetVolumeInformationA
                      ((LPCSTR)0x0,(LPSTR)0x0,0,(LPDWORD)0x0,&local_24,&local_1c,(LPSTR)0x0,0);
    if (BVar2 == 0) {
      local_224 = '\0';
      puVar9 = &local_223;
      for (iVar4 = 0x7f; iVar4 != 0; iVar4 = iVar4 + -1) {
        *puVar9 = 0;
        puVar9 = puVar9 + 1;
      }
      *(undefined2 *)puVar9 = 0;
      *(undefined *)((int)puVar9 + 2) = 0;
      DAT_01015fcc = FUN_01005aa0();
      ppcVar13 = (va_list *)0x0;
      DVar12 = 0x200;
      pCVar11 = &local_224;
      DVar10 = 0;
      DVar3 = GetLastError();
      FormatMessageA(0x1000,(LPCVOID)0x0,DVar3,DVar10,pCVar11,DVar12,ppcVar13);
      FUN_01003e4b((HWND)0x0,0x4f9,param_1,&local_224,0x10,0);
      SetCurrentDirectoryA(local_328);
      return false;
    }
    SetCurrentDirectoryA(local_328);
    iVar4 = 0x200;
    lstrcpynA(local_18,param_1,3);
    uVar6 = 0;
    uVar5 = local_8 * local_10 * local_c;
    do {
      if (iVar4 == local_10 * local_c) break;
      uVar6 = uVar6 + 1;
      iVar4 = iVar4 * 2;
    } while (uVar6 < 8);
    if (uVar6 == 8) {
      FUN_01003e4b((HWND)0x0,0x4c5,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
      return false;
    }
    if (((DAT_01015fc4 & 8) == 0) || ((local_1c._1_1_ & 0x80) == 0)) {
      uVar7 = (&DAT_01016310)[uVar6];
      uVar8 = DAT_01015fc8;
    }
    else {
      uVar7 = (&DAT_01016310)[uVar6] * 2;
      uVar8 = (DAT_01015fc8 >> 2) + DAT_01015fc8;
    }
    if (((param_2 & 1) == 0) || ((param_2 & 2) == 0)) {
      if ((param_2 & 1) == 0) {
        if (uVar5 < uVar8) {
          bVar1 = FUN_01002a18(param_3,uVar7,uVar8,local_18);
          return bVar1;
        }
      }
      else if (uVar5 < uVar7) {
        bVar1 = FUN_01002a18(param_3,uVar7,uVar8,local_18);
        return bVar1;
      }
    }
    else if (uVar5 < uVar7 + uVar8) {
      bVar1 = FUN_01002a18(param_3,uVar7,uVar8,local_18);
      return bVar1;
    }
    DAT_01015fcc = 0;
  }
  return true;
}



undefined4 FUN_0100544a(char *param_1,int *param_2)

{
  char cVar1;
  int iVar2;
  ushort uVar3;
  undefined2 extraout_var;
  undefined4 uVar4;
  int iVar5;
  undefined2 extraout_var_00;
  uint uVar6;
  int iVar7;
  
  iVar7 = 0;
  cVar1 = *param_1;
  while (cVar1 != '\0') {
    if (DAT_0101069c < 2) {
      uVar6 = *(ushort *)(PTR_DAT_01010490 + param_1[iVar7] * 2) & 8;
    }
    else {
      uVar3 = FUN_01006038((int)param_1[iVar7],8);
      uVar6 = CONCAT22(extraout_var,uVar3);
    }
    if (uVar6 == 0) break;
    iVar7 = iVar7 + 1;
    cVar1 = param_1[iVar7];
  }
  if (param_1[iVar7] == '\0') {
    uVar4 = 0;
  }
  else {
    iVar5 = lstrlenA(param_1 + iVar7);
    do {
      iVar2 = iVar5;
      iVar5 = iVar2 + -1;
      if (iVar5 < 0) break;
      if (DAT_0101069c < 2) {
        uVar6 = *(ushort *)(PTR_DAT_01010490 + param_1[iVar7 + iVar5] * 2) & 8;
      }
      else {
        uVar3 = FUN_01006038((int)param_1[iVar7 + iVar5],8);
        uVar6 = CONCAT22(extraout_var_00,uVar3);
      }
    } while (uVar6 != 0);
    param_1[iVar7 + iVar2] = '\0';
    *param_2 = iVar7;
    uVar4 = 1;
  }
  return uVar4;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_010054fc(char *param_1)

{
  char cVar1;
  ushort uVar2;
  undefined2 extraout_var;
  undefined2 extraout_var_00;
  uint uVar3;
  DWORD DVar4;
  char *pcVar5;
  int iVar6;
  int iVar7;
  LPCSTR pCVar8;
  bool bVar9;
  char local_114 [260];
  int local_10;
  int local_c;
  int local_8;
  
  iVar7 = 1;
  if ((param_1 == (char *)0x0) || (*param_1 == '\0')) {
    iVar7 = 1;
  }
  else {
    do {
      if (iVar7 == 0) break;
      while( true ) {
        if (DAT_0101069c < 2) {
          uVar3 = *(ushort *)(PTR_DAT_01010490 + *param_1 * 2) & 8;
        }
        else {
          uVar2 = FUN_01006038((int)*param_1,8);
          uVar3 = CONCAT22(extraout_var,uVar2);
        }
        if (uVar3 == 0) break;
        param_1 = CharNextA(param_1);
      }
      if (*param_1 == '\0') break;
      iVar6 = 0;
      local_8 = 0;
      local_10 = 0;
      pCVar8 = param_1;
      do {
        param_1 = pCVar8;
        if (local_8 == 0) {
          if (DAT_0101069c < 2) {
            uVar3 = *(ushort *)(PTR_DAT_01010490 + *pCVar8 * 2) & 8;
          }
          else {
            uVar2 = FUN_01006038((int)*pCVar8,8);
            uVar3 = CONCAT22(extraout_var_00,uVar2);
          }
          if (uVar3 != 0) {
            if (local_8 != 0) goto LAB_010055b1;
            break;
          }
        }
        else {
LAB_010055b1:
          if (local_10 != 0) break;
        }
        if (*pCVar8 == '\"') {
          param_1 = pCVar8 + 1;
          if (*param_1 == '\"') {
            local_114[iVar6] = '\"';
            iVar6 = iVar6 + 1;
            param_1 = pCVar8 + 2;
          }
          else if (local_8 == 0) {
            local_8 = 1;
          }
          else {
            local_10 = 1;
          }
        }
        else {
          local_114[iVar6] = *pCVar8;
          param_1 = pCVar8 + 1;
          iVar6 = iVar6 + 1;
        }
        pCVar8 = param_1;
      } while (*param_1 != '\0');
      local_114[iVar6] = '\0';
      if (local_8 == 0) {
LAB_01005619:
        if (local_10 != 0) {
LAB_010059b4:
          iVar7 = 0;
          break;
        }
      }
      else if (local_10 == 0) {
        if (local_8 == 0) goto LAB_01005619;
        goto LAB_010059b4;
      }
      if ((local_114[0] != '/') && (local_114[0] != '-')) {
        return 0;
      }
      uVar3 = FUN_010060b3((int)local_114[1]);
      if (uVar3 == 0x3f) {
        FUN_010023e1();
        FUN_01006220(0);
      }
      else if (uVar3 == 0x43) {
        if (local_114[2] != '\0') {
          if (local_114[2] == ':') {
            local_8 = (local_114[3] == '\"') + 3;
            pCVar8 = local_114 + (local_114[3] == '\"') + 3;
            iVar6 = lstrlenA(pCVar8);
            if (((iVar6 != 0) &&
                ((pcVar5 = _strchr(pCVar8,0x5b), pcVar5 == (char *)0x0 ||
                 (pcVar5 = _strchr(pCVar8,0x5d), pcVar5 != (char *)0x0)))) &&
               ((pcVar5 = _strchr(pCVar8,0x5d), pcVar5 == (char *)0x0 ||
                (pcVar5 = _strchr(pCVar8,0x5b), pcVar5 != (char *)0x0)))) {
              local_c = local_8;
              iVar6 = FUN_0100544a(pCVar8,&local_c);
              if (iVar6 != 0) {
                lstrcpyA(&DAT_010161fe,local_114 + local_c + local_8);
                goto LAB_010059a5;
              }
            }
          }
          goto LAB_010059a3;
        }
        _DAT_01015fe4 = 1;
      }
      else if (uVar3 == 0x44) {
LAB_01005763:
        if (local_114[2] == ':') {
          bVar9 = local_114[3] == '\"';
          local_8 = bVar9 + 3;
          iVar6 = lstrlenA(local_114 + bVar9 + 3);
          if (iVar6 != 0) {
            local_c = local_8;
            iVar6 = FUN_0100544a(local_114 + bVar9 + 3,&local_c);
            if (iVar6 != 0) {
              uVar3 = FUN_010060b3((int)local_114[1]);
              if (uVar3 == 0x54) {
                lstrcpyA(&DAT_010160fa,local_114 + local_c + local_8);
                FUN_010027e1(&DAT_010160fa,"");
              }
              else {
                lstrcpyA(&DAT_01015ff6,local_114 + local_c + local_8);
                FUN_010027e1(&DAT_01015ff6,"");
              }
              goto LAB_010059a5;
            }
          }
        }
LAB_010059a3:
        iVar7 = 0;
      }
      else if (uVar3 == 0x4e) {
        if (local_114[2] == '\0') {
          _DAT_01015fec = 1;
        }
        else {
          if (local_114[2] != ':') goto LAB_010059a3;
          iVar6 = 3;
          cVar1 = local_114[3];
          while (cVar1 != '\0') {
            uVar3 = FUN_010060b3((int)local_114[iVar6]);
            if (uVar3 == 0x45) {
              _DAT_01015fec = 1;
            }
            else if (uVar3 == 0x47) {
              _DAT_01015ff0 = 1;
            }
            else {
              iVar7 = 0;
            }
            cVar1 = local_114[iVar6 + 1];
            iVar6 = iVar6 + 1;
          }
        }
      }
      else if (uVar3 == 0x51) {
        if (local_114[2] == '\0') {
          DAT_01015ff4._0_1_ = (byte)DAT_01015ff4 | 1;
        }
        else {
          if (local_114[2] != ':') goto LAB_010059a3;
          iVar6 = 3;
          cVar1 = local_114[3];
          while (cVar1 != '\0') {
            if (local_114[iVar6] == '1') {
              DAT_01015ff4._0_1_ = (byte)DAT_01015ff4 | 2;
            }
            else {
              iVar7 = 0;
            }
            cVar1 = local_114[iVar6 + 1];
            iVar6 = iVar6 + 1;
          }
        }
      }
      else {
        if (uVar3 != 0x52) {
          if (uVar3 == 0x54) goto LAB_01005763;
          goto LAB_010059a3;
        }
        if (local_114[2] == '\0') {
          DAT_01015fbc = 3;
        }
        else {
          if (local_114[2] != ':') {
            iVar6 = lstrcmpiA("RegServer",local_114 + 1);
            if (iVar6 == 0) goto LAB_010059a5;
            goto LAB_010059a3;
          }
          DAT_01015fbc = 1;
          iVar6 = 3;
          cVar1 = local_114[3];
          while (cVar1 != '\0') {
            uVar3 = FUN_010060b3((int)local_114[iVar6]);
            if (uVar3 == 0x41) {
              DAT_01015fbc = DAT_01015fbc | 2;
            }
            else if (uVar3 == 0x49) {
              DAT_01015fbc = DAT_01015fbc & 0xfffffffd;
            }
            else if (uVar3 == 0x4e) {
              DAT_01015fbc = DAT_01015fbc & 0xfffffffe;
            }
            else if (uVar3 == 0x53) {
              DAT_01015fbc = DAT_01015fbc | 4;
            }
            cVar1 = local_114[iVar6 + 1];
            iVar6 = iVar6 + 1;
          }
        }
        _DAT_01015fe8 = 1;
      }
LAB_010059a5:
    } while (*param_1 != '\0');
    if ((_DAT_01015fec != 0) && (DAT_010160fa == '\0')) {
      DVar4 = GetModuleFileNameA(DAT_01016700,&DAT_010160fa,0x104);
      if (DVar4 == 0) {
        iVar7 = 0;
      }
      else {
        pcVar5 = _strrchr(&DAT_010160fa,0x5c);
        pcVar5[1] = '\0';
      }
    }
  }
  return iVar7;
}



bool FUN_01005a08(void)

{
  bool bVar1;
  UINT UVar2;
  CHAR local_104 [260];
  
  UVar2 = GetWindowsDirectoryA(local_104,0x104);
  if (UVar2 == 0) {
    FUN_01003e4b((HWND)0x0,0x4f0,(LPCSTR)0x0,(LPCSTR)0x0,0x10,0);
    DAT_01015fcc = FUN_01005aa0();
    bVar1 = false;
  }
  else {
    bVar1 = FUN_010051cf(local_104,2,2);
  }
  return bVar1;
}



void FUN_01005a57(uint param_1,int param_2)

{
  int iVar1;
  
  if (param_2 == 0) {
    if (((param_1 & 0xff000000) == 0xaa000000) && ((param_1 & 1) != 0)) {
      DAT_01015fcc = 0xbc2;
    }
    else {
      DAT_01015fcc = param_1;
    }
  }
  else {
    iVar1 = FUN_010023f8();
    if (iVar1 == 2) {
      DAT_01015fcc = 0xbc2;
    }
  }
  return;
}



uint FUN_01005aa0(void)

{
  DWORD DVar1;
  uint uVar2;
  
  DVar1 = GetLastError();
  uVar2 = 0;
  if (DVar1 != 0) {
    DVar1 = GetLastError();
    uVar2 = DVar1 & 0xffff | 0x80070000;
  }
  return uVar2;
}



undefined4 FUN_01005ac0(undefined *param_1)

{
  HRSRC hResInfo;
  HGLOBAL hResData;
  undefined4 *hResData_00;
  int iVar1;
  CHAR local_24 [20];
  undefined4 local_10;
  undefined4 local_c;
  int local_8;
  
  local_8 = 0;
  while( true ) {
    wsprintfA(local_24,"UPDFILE%lu",local_8);
    hResInfo = FindResourceA((HMODULE)0x0,local_24,(LPCSTR)0xa);
    if (hResInfo == (HRSRC)0x0) {
      return 1;
    }
    hResData = LoadResource((HMODULE)0x0,hResInfo);
    hResData_00 = (undefined4 *)LockResource(hResData);
    if (hResData_00 == (undefined4 *)0x0) break;
    local_c = *hResData_00;
    local_10 = hResData_00[1];
    iVar1 = lstrlenA((LPCSTR)(hResData_00 + 2));
    iVar1 = (*(code *)param_1)(local_c,local_10,hResData_00 + 2,(int)hResData_00 + iVar1 + 9);
    if (iVar1 == 0) {
      FreeResource(hResData_00);
      return 0;
    }
    FreeResource(hResData_00);
    local_8 = local_8 + 1;
  }
  DAT_01015fcc = 0x80070714;
  return 0;
}



undefined4 FUN_01005baf(DWORD param_1,undefined4 param_2,LPCSTR param_3,LPCVOID param_4)

{
  HANDLE hFile;
  BOOL BVar1;
  undefined4 uVar2;
  CHAR local_10c [260];
  DWORD local_8;
  
  uVar2 = 1;
  local_8 = 0;
  lstrcpyA(local_10c,&DAT_01015774);
  FUN_010027e1(local_10c,param_3);
  hFile = CreateFileA(local_10c,0x40000000,0,(LPSECURITY_ATTRIBUTES)0x0,2,0x80,(HANDLE)0x0);
  if (hFile != (HANDLE)0xffffffff) {
    BVar1 = WriteFile(hFile,param_4,param_1,&local_8,(LPOVERLAPPED)0x0);
    if ((BVar1 != 0) && (local_8 == param_1)) goto LAB_01005c32;
  }
  DAT_01015fcc = 0x80070052;
  uVar2 = 0;
LAB_01005c32:
  if (hFile != (HANDLE)0xffffffff) {
    CloseHandle(hFile);
  }
  return uVar2;
}



void FUN_01005c49(LPCSTR param_1)

{
  DWORD DVar1;
  CHAR local_108 [260];
  
  lstrcpyA(local_108,&DAT_01015774);
  FUN_010027e1(local_108,param_1);
  DVar1 = GetFileAttributesA(local_108);
  if ((DVar1 == 0xffffffff) || ((DVar1 & 0x10) != 0)) {
    LoadLibraryA(param_1);
  }
  else {
    LoadLibraryExA(local_108,(HANDLE)0x0,8);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void entry(void)

{
  byte bVar1;
  DWORD DVar2;
  int iVar3;
  HMODULE pHVar4;
  UINT UVar5;
  byte *pbVar6;
  undefined4 uVar7;
  _STARTUPINFOA local_70;
  uint local_28;
  undefined *local_1c;
  void *local_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &DAT_010013e0;
  puStack_10 = &LAB_01006ff0;
  local_14 = ExceptionList;
  local_1c = &stack0xffffff84;
  ExceptionList = &local_14;
  DVar2 = GetVersion();
  _DAT_010106b8 = DVar2 >> 8 & 0xff;
  DAT_010106ac = DVar2 >> 0x10;
  _DAT_010106b4 = DVar2 & 0xff;
  _DAT_010106b0 = _DAT_010106b4 * 0x100 + _DAT_010106b8;
  FUN_01006fc4();
  iVar3 = FUN_01006ee6();
  if (iVar3 == 0) {
    FUN_01005e3c(0x10);
  }
  local_8 = 0;
  FUN_01006d16();
  FUN_01006d0b();
  DAT_0101783c = (byte *)GetCommandLineA();
  DAT_01010474 = FUN_01006923();
  if ((DAT_01010474 == (undefined4 *)0x0) || (DAT_0101783c == (byte *)0x0)) {
    FUN_01006220(0xffffffff);
  }
  FUN_010066bf();
  FUN_010065d0();
  FUN_010061f0();
  bVar1 = *DAT_0101783c;
  pbVar6 = DAT_0101783c;
  if (bVar1 == 0x22) {
    pbVar6 = DAT_0101783c + 1;
    if (*pbVar6 != 0x22) {
      do {
        if (*pbVar6 == 0) break;
        iVar3 = FUN_01006588(*pbVar6);
        if (iVar3 != 0) {
          pbVar6 = pbVar6 + 1;
        }
        pbVar6 = pbVar6 + 1;
      } while (*pbVar6 != 0x22);
      if (*pbVar6 != 0x22) goto LAB_01005dad;
    }
    pbVar6 = pbVar6 + 1;
  }
  else {
    while (0x20 < bVar1) {
      bVar1 = pbVar6[1];
      pbVar6 = pbVar6 + 1;
    }
  }
LAB_01005dad:
  bVar1 = *pbVar6;
  while ((bVar1 != 0 && (*pbVar6 < 0x21))) {
    pbVar6 = pbVar6 + 1;
    bVar1 = *pbVar6;
  }
  local_70.dwFlags = 0;
  GetStartupInfoA(&local_70);
  if ((local_70.dwFlags & 1) == 0) {
    local_28 = 10;
  }
  else {
    local_28 = (uint)local_70.wShowWindow;
  }
  uVar7 = 0;
  pHVar4 = GetModuleHandleA((LPCSTR)0x0);
  UVar5 = FUN_01002afc(pHVar4,uVar7,(char *)pbVar6);
  FUN_01006220(UVar5);
  ExceptionList = local_14;
  return;
}



void __cdecl FUN_01005e3c(int param_1)

{
  if (DAT_01010480 == 1) {
    __FF_MSGBANNER();
  }
  FUN_01007105(param_1);
  (*(code *)PTR_FUN_0101047c)(0xff);
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



void __cdecl FUN_01005f67(uint param_1,char *param_2,uint param_3,int param_4)

{
  ulonglong uVar1;
  char *pcVar2;
  char *pcVar3;
  char cVar4;
  
  pcVar2 = param_2;
  if (param_4 != 0) {
    *param_2 = '-';
    param_1 = -param_1;
    param_2 = param_2 + 1;
    pcVar2 = param_2;
  }
  do {
    pcVar3 = pcVar2;
    uVar1 = (ulonglong)param_1;
    param_1 = param_1 / param_3;
    cVar4 = (char)(uVar1 % (ulonglong)param_3);
    if ((uint)(uVar1 % (ulonglong)param_3) < 10) {
      cVar4 = cVar4 + '0';
    }
    else {
      cVar4 = cVar4 + 'W';
    }
    *pcVar3 = cVar4;
    pcVar2 = pcVar3 + 1;
  } while (param_1 != 0);
  pcVar3[1] = '\0';
  do {
    cVar4 = *pcVar3;
    *pcVar3 = *param_2;
    pcVar3 = pcVar3 + -1;
    *param_2 = cVar4;
    param_2 = param_2 + 1;
  } while (param_2 < pcVar3);
  return;
}



char * __cdecl FUN_01005fc4(uint param_1,char *param_2,uint param_3)

{
  FUN_01005f67(param_1,param_2,param_3,0);
  return param_2;
}



int __cdecl FUN_01005fdf(byte *param_1,char *param_2)

{
  int iVar1;
  byte *local_24;
  int local_20;
  byte *local_1c;
  undefined4 local_18;
  
  local_18 = 0x42;
  local_1c = param_1;
  local_24 = param_1;
  local_20 = 0x7fffffff;
  iVar1 = FUN_010074f5(&local_24,param_2,(undefined4 *)&stack0x0000000c);
  local_20 = local_20 + -1;
  if (local_20 < 0) {
    FUN_010073c5(0,(int *)&local_24);
  }
  else {
    *local_24 = 0;
  }
  return iVar1;
}



ushort __cdecl FUN_01006038(int param_1,ushort param_2)

{
  int iVar1;
  byte local_c;
  byte local_b;
  undefined local_a;
  ushort local_6;
  
  if (param_1 + 1U < 0x101) {
    local_6 = *(ushort *)(PTR_DAT_01010490 + param_1 * 2);
  }
  else {
    local_c = (byte)((uint)param_1 >> 8);
    if ((PTR_DAT_01010490[(uint)local_c * 2 + 1] & 0x80) == 0) {
      local_b = 0;
      iVar1 = 1;
      local_c = (byte)param_1;
    }
    else {
      local_a = 0;
      iVar1 = 2;
      local_b = (byte)param_1;
    }
    iVar1 = FUN_01007fbe(1,(LPCSTR)&local_c,iVar1,&local_6,0,0);
    if (iVar1 == 0) {
      return 0;
    }
  }
  return local_6 & param_2;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

uint __cdecl FUN_010060b3(uint param_1)

{
  bool bVar1;
  
  if (DAT_01010cb8 == 0) {
    if ((0x60 < (int)param_1) && ((int)param_1 < 0x7b)) {
      param_1 = param_1 - 0x20;
    }
  }
  else {
    bVar1 = _DAT_01017724 == 0;
    if (bVar1) {
      _DAT_01017720 = _DAT_01017720 + 1;
    }
    else {
      FUN_010080e9(0x13);
    }
    param_1 = FUN_01006121(param_1);
    if (bVar1) {
      _DAT_01017720 = _DAT_01017720 + -1;
    }
    else {
      FUN_0100814c(0x13);
    }
  }
  return param_1;
}



uint __cdecl FUN_01006121(uint param_1)

{
  ushort uVar1;
  undefined2 extraout_var;
  uint uVar2;
  int iVar3;
  WCHAR local_c [2];
  byte local_8;
  byte local_7;
  undefined local_6;
  
  if (DAT_01010cb8 == 0) {
    if ((0x60 < (int)param_1) && ((int)param_1 < 0x7b)) {
      param_1 = param_1 - 0x20;
    }
  }
  else {
    if ((int)param_1 < 0x100) {
      if (DAT_0101069c < 2) {
        uVar2 = *(ushort *)(PTR_DAT_01010490 + param_1 * 2) & 2;
      }
      else {
        uVar1 = FUN_01006038(param_1,2);
        uVar2 = CONCAT22(extraout_var,uVar1);
      }
      if (uVar2 == 0) {
        return param_1;
      }
    }
    local_8 = (byte)(param_1 >> 8);
    if ((PTR_DAT_01010490[(uint)local_8 * 2 + 1] & 0x80) == 0) {
      iVar3 = 1;
      local_7 = 0;
      local_8 = (byte)param_1;
    }
    else {
      iVar3 = 2;
      local_6 = 0;
      local_7 = (byte)param_1;
    }
    iVar3 = FUN_0100820e(DAT_01010cb8,0x200,(char *)&local_8,iVar3,local_c,3,0);
    if (iVar3 != 0) {
      if (iVar3 == 1) {
        param_1 = (uint)(byte)local_c[0];
      }
      else {
        param_1 = (uint)(ushort)local_c[0];
      }
    }
  }
  return param_1;
}



void FUN_010061f0(void)

{
  if (DAT_01017834 != (code *)0x0) {
    (*DAT_01017834)();
  }
  FUN_01006307((undefined **)&DAT_01001008,(undefined **)&DAT_01001010);
  FUN_01006307((undefined **)&DAT_01001000,(undefined **)&DAT_01001004);
  return;
}



void __cdecl FUN_01006220(UINT param_1)

{
  FUN_01006242(param_1,0,0);
  return;
}



void __cdecl FUN_01006231(UINT param_1)

{
  FUN_01006242(param_1,1,0);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_01006242(UINT param_1,int param_2,int param_3)

{
  HANDLE hProcess;
  code **ppcVar1;
  UINT uExitCode;
  
  FUN_010062f1();
  if (_DAT_010106e8 == 1) {
    uExitCode = param_1;
    hProcess = GetCurrentProcess();
    TerminateProcess(hProcess,uExitCode);
  }
  _DAT_010106e4 = 1;
  DAT_010106e0 = (undefined)param_3;
  if (param_2 == 0) {
    if ((_DAT_01017838 != (code **)0x0) &&
       (ppcVar1 = (code **)(DAT_01017830 + -4), _DAT_01017838 <= ppcVar1)) {
      do {
        if (*ppcVar1 != (code *)0x0) {
          (**ppcVar1)();
        }
        ppcVar1 = ppcVar1 + -1;
      } while (_DAT_01017838 <= ppcVar1);
    }
    FUN_01006307((undefined **)&DAT_01001014,(undefined **)&DAT_0100101c);
  }
  FUN_01006307((undefined **)&DAT_01001020,(undefined **)&DAT_01001024);
  if (param_3 != 0) {
    FUN_010062fc();
    return;
  }
  _DAT_010106e8 = 1;
                    // WARNING: Subroutine does not return
  ExitProcess(param_1);
}



void FUN_010062f1(void)

{
  FUN_010080e9(0xd);
  return;
}



void FUN_010062fc(void)

{
  FUN_0100814c(0xd);
  return;
}



void __cdecl FUN_01006307(undefined **param_1,undefined **param_2)

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



// Library Function - Single Match
//  __global_unwind2
// 
// Library: Visual Studio

void __cdecl __global_unwind2(PVOID param_1)

{
  RtlUnwind(param_1,(PVOID)0x1006340,(PEXCEPTION_RECORD)0x0,(PVOID)0x0);
  return;
}



// Library Function - Single Match
//  __local_unwind2
// 
// Libraries: Visual Studio 1998 Debug, Visual Studio 1998 Release, Visual Studio 2003 Debug, Visual
// Studio 2003 Release

void __cdecl __local_unwind2(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  void *pvStack_1c;
  undefined *puStack_18;
  undefined4 local_14;
  int iStack_10;
  
  iStack_10 = param_1;
  puStack_18 = &LAB_01006348;
  pvStack_1c = ExceptionList;
  ExceptionList = &pvStack_1c;
  while( true ) {
    iVar1 = *(int *)(param_1 + 8);
    iVar2 = *(int *)(param_1 + 0xc);
    if ((iVar2 == -1) || (iVar2 == param_2)) break;
    local_14 = *(undefined4 *)(iVar1 + iVar2 * 0xc);
    *(undefined4 *)(param_1 + 0xc) = local_14;
    if (*(int *)(iVar1 + 4 + iVar2 * 0xc) == 0) {
      FUN_010063fe();
      (**(code **)(iVar1 + 8 + iVar2 * 0xc))();
    }
  }
  ExceptionList = pvStack_1c;
  return;
}



void FUN_010063fe(void)

{
  undefined4 in_EAX;
  int unaff_EBP;
  
  DAT_010106f4 = *(undefined4 *)(unaff_EBP + 8);
  DAT_010106f0 = in_EAX;
  DAT_010106f8 = unaff_EBP;
  return;
}



LONG __cdecl FUN_01006416(int param_1,_EXCEPTION_POINTERS *param_2)

{
  code **ppcVar1;
  DWORD *pDVar2;
  code *pcVar3;
  DWORD DVar4;
  DWORD DVar5;
  DWORD *pDVar6;
  int *piVar7;
  LONG LVar8;
  int iVar9;
  int iVar10;
  
  pDVar6 = FUN_01006f55();
  piVar7 = (int *)FUN_0100655d(param_1,(int *)pDVar6[0x14]);
  if (piVar7 != (int *)0x0) {
    ppcVar1 = (code **)(piVar7 + 2);
    pcVar3 = *ppcVar1;
    if (pcVar3 != (code *)0x0) {
      if (pcVar3 == (code *)0x5) {
        *ppcVar1 = (code *)0x0;
        return 1;
      }
      if (pcVar3 == (code *)0x1) {
        return -1;
      }
      DVar4 = pDVar6[0x15];
      pDVar6[0x15] = (DWORD)param_2;
      if (piVar7[1] == 8) {
        if (DAT_01010778 < DAT_0101077c + DAT_01010778) {
          iVar9 = DAT_01010778 * 0xc;
          iVar10 = DAT_01010778;
          do {
            iVar9 = iVar9 + 0xc;
            iVar10 = iVar10 + 1;
            *(undefined4 *)((pDVar6[0x14] - 4) + iVar9) = 0;
          } while (iVar10 < DAT_0101077c + DAT_01010778);
        }
        pDVar2 = pDVar6 + 0x16;
        iVar10 = *piVar7;
        DVar5 = *pDVar2;
        if (iVar10 == -0x3fffff72) {
          *pDVar2 = 0x83;
        }
        else if (iVar10 == -0x3fffff70) {
          *pDVar2 = 0x81;
        }
        else if (iVar10 == -0x3fffff6f) {
          *pDVar2 = 0x84;
        }
        else if (iVar10 == -0x3fffff6d) {
          *pDVar2 = 0x85;
        }
        else if (iVar10 == -0x3fffff73) {
          *pDVar2 = 0x82;
        }
        else if (iVar10 == -0x3fffff71) {
          *pDVar2 = 0x86;
        }
        else if (iVar10 == -0x3fffff6e) {
          *pDVar2 = 0x8a;
        }
        (*pcVar3)(8,*pDVar2);
        *pDVar2 = DVar5;
      }
      else {
        *ppcVar1 = (code *)0x0;
        (*pcVar3)(piVar7[1]);
      }
      pDVar6[0x15] = DVar4;
      return -1;
    }
  }
  LVar8 = UnhandledExceptionFilter(param_2);
  return LVar8;
}



uint __cdecl FUN_0100655d(int param_1,int *param_2)

{
  int *piVar1;
  
  piVar1 = param_2;
  do {
    if (*piVar1 == param_1) break;
    piVar1 = piVar1 + 3;
  } while (piVar1 < param_2 + DAT_01010784 * 3);
  return -(uint)(*piVar1 == param_1) & (uint)piVar1;
}



void __cdecl FUN_01006588(byte param_1)

{
  FUN_01006599(param_1,0,4);
  return;
}



undefined4 __cdecl FUN_01006599(byte param_1,uint param_2,byte param_3)

{
  uint uVar1;
  
  if ((param_3 & (&DAT_01010791)[param_1]) == 0) {
    if (param_2 == 0) {
      uVar1 = 0;
    }
    else {
      uVar1 = *(ushort *)(&DAT_0101049a + (uint)param_1 * 2) & param_2;
    }
    if (uVar1 == 0) {
      return 0;
    }
  }
  return 1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_010065d0(void)

{
  char cVar1;
  int *piVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  char *pcVar6;
  int iVar7;
  undefined4 *puVar8;
  char *pcVar9;
  char *pcVar10;
  undefined4 *puVar11;
  
  iVar7 = 0;
  if (DAT_01010474 == (char *)0x0) {
    _DAT_010106c8 = (int *)0x0;
  }
  else {
    cVar1 = *DAT_01010474;
    pcVar6 = DAT_01010474;
    while (cVar1 != '\0') {
      if (*pcVar6 != '=') {
        iVar7 = iVar7 + 1;
      }
      uVar3 = 0xffffffff;
      pcVar9 = pcVar6;
      do {
        if (uVar3 == 0) break;
        uVar3 = uVar3 - 1;
        cVar1 = *pcVar9;
        pcVar9 = pcVar9 + 1;
      } while (cVar1 != '\0');
      pcVar6 = pcVar6 + ~uVar3;
      cVar1 = *pcVar6;
    }
    piVar2 = (int *)FUN_01008440(iVar7 * 4 + 4);
    _DAT_010106c8 = piVar2;
    if (piVar2 == (int *)0x0) {
      FUN_01005e3c(9);
    }
    cVar1 = *DAT_01010474;
    pcVar6 = DAT_01010474;
    while (cVar1 != '\0') {
      uVar3 = 0xffffffff;
      pcVar9 = pcVar6;
      do {
        if (uVar3 == 0) break;
        uVar3 = uVar3 - 1;
        cVar1 = *pcVar9;
        pcVar9 = pcVar9 + 1;
      } while (cVar1 != '\0');
      if (*pcVar6 != '=') {
        iVar7 = FUN_01008440(~uVar3);
        *piVar2 = iVar7;
        if (iVar7 == 0) {
          FUN_01005e3c(9);
        }
        uVar4 = 0xffffffff;
        pcVar9 = pcVar6;
        do {
          pcVar10 = pcVar9;
          if (uVar4 == 0) break;
          uVar4 = uVar4 - 1;
          pcVar10 = pcVar9 + 1;
          cVar1 = *pcVar9;
          pcVar9 = pcVar10;
        } while (cVar1 != '\0');
        uVar4 = ~uVar4;
        puVar8 = (undefined4 *)(pcVar10 + -uVar4);
        puVar11 = (undefined4 *)*piVar2;
        for (uVar5 = uVar4 >> 2; uVar5 != 0; uVar5 = uVar5 - 1) {
          *puVar11 = *puVar8;
          puVar8 = puVar8 + 1;
          puVar11 = puVar11 + 1;
        }
        piVar2 = piVar2 + 1;
        for (uVar4 = uVar4 & 3; uVar4 != 0; uVar4 = uVar4 - 1) {
          *(undefined *)puVar11 = *(undefined *)puVar8;
          puVar8 = (undefined4 *)((int)puVar8 + 1);
          puVar11 = (undefined4 *)((int)puVar11 + 1);
        }
      }
      pcVar6 = pcVar6 + ~uVar3;
      cVar1 = *pcVar6;
    }
    FUN_01008428(DAT_01010474);
    *piVar2 = 0;
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_010066bf(void)

{
  byte **ppbVar1;
  byte *pbVar2;
  int local_c;
  int local_8;
  
  GetModuleFileNameA((HMODULE)0x0,&DAT_01012528,0x104);
  _DAT_010106d8 = &DAT_01012528;
  pbVar2 = &DAT_01012528;
  if (*DAT_0101783c != 0) {
    pbVar2 = DAT_0101783c;
  }
  FUN_01006755(pbVar2,(byte **)0x0,(byte *)0x0,&local_8,&local_c);
  ppbVar1 = (byte **)FUN_01008440(local_8 * 4 + local_c);
  if (ppbVar1 == (byte **)0x0) {
    FUN_01005e3c(8);
  }
  FUN_01006755(pbVar2,ppbVar1,(byte *)(ppbVar1 + local_8),&local_8,&local_c);
  _DAT_010106c0 = ppbVar1;
  _DAT_010106bc = local_8 + -1;
  return;
}



void __cdecl FUN_01006755(byte *param_1,byte **param_2,byte *param_3,int *param_4,int *param_5)

{
  byte bVar1;
  bool bVar2;
  bool bVar3;
  uint uVar4;
  byte *pbVar5;
  
  *param_5 = 0;
  *param_4 = 1;
  if (param_2 != (byte **)0x0) {
    *param_2 = param_3;
    param_2 = param_2 + 1;
  }
  if (*param_1 == 0x22) {
    pbVar5 = param_1 + 1;
    bVar1 = *pbVar5;
    while ((bVar1 != 0x22 && (*pbVar5 != 0))) {
      if ((((&DAT_01010791)[*pbVar5] & 4) != 0) && (*param_5 = *param_5 + 1, param_3 != (byte *)0x0)
         ) {
        bVar1 = *pbVar5;
        pbVar5 = pbVar5 + 1;
        *param_3 = bVar1;
        param_3 = param_3 + 1;
      }
      *param_5 = *param_5 + 1;
      if (param_3 != (byte *)0x0) {
        *param_3 = *pbVar5;
        param_3 = param_3 + 1;
      }
      pbVar5 = pbVar5 + 1;
      bVar1 = *pbVar5;
    }
    *param_5 = *param_5 + 1;
    if (param_3 != (byte *)0x0) {
      *param_3 = 0;
      param_3 = param_3 + 1;
    }
    if (*pbVar5 == 0x22) {
      pbVar5 = pbVar5 + 1;
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
      pbVar5 = param_1 + 1;
      if (((&DAT_01010791)[bVar1] & 4) != 0) {
        *param_5 = *param_5 + 1;
        if (param_3 != (byte *)0x0) {
          *param_3 = *pbVar5;
          param_3 = param_3 + 1;
        }
        pbVar5 = param_1 + 2;
      }
      if (bVar1 == 0x20) break;
      if (bVar1 == 0) goto LAB_010067c0;
      param_1 = pbVar5;
    } while (bVar1 != 9);
    if (bVar1 == 0) {
LAB_010067c0:
      pbVar5 = pbVar5 + -1;
    }
    else if (param_3 != (byte *)0x0) {
      param_3[-1] = 0;
    }
  }
  bVar3 = false;
  while (*pbVar5 != 0) {
    for (; (*pbVar5 == 0x20 || (*pbVar5 == 9)); pbVar5 = pbVar5 + 1) {
    }
    if (*pbVar5 == 0) break;
    if (param_2 != (byte **)0x0) {
      *param_2 = param_3;
      param_2 = param_2 + 1;
    }
    *param_4 = *param_4 + 1;
    while( true ) {
      bVar2 = true;
      uVar4 = 0;
      bVar1 = *pbVar5;
      while (bVar1 == 0x5c) {
        pbVar5 = pbVar5 + 1;
        uVar4 = uVar4 + 1;
        bVar1 = *pbVar5;
      }
      if (*pbVar5 == 0x22) {
        if ((uVar4 & 1) == 0) {
          if ((bVar3) && (pbVar5[1] == 0x22)) {
            pbVar5 = pbVar5 + 1;
          }
          else {
            bVar2 = false;
          }
          bVar3 = !bVar3;
        }
        uVar4 = uVar4 >> 1;
      }
      while (uVar4 != 0) {
        uVar4 = uVar4 - 1;
        if (param_3 != (byte *)0x0) {
          *param_3 = 0x5c;
          param_3 = param_3 + 1;
        }
        *param_5 = *param_5 + 1;
      }
      bVar1 = *pbVar5;
      if ((bVar1 == 0) || ((!bVar3 && ((bVar1 == 0x20 || (bVar1 == 9)))))) break;
      if (bVar2) {
        if (param_3 == (byte *)0x0) {
          if (((&DAT_01010791)[bVar1] & 4) != 0) {
            pbVar5 = pbVar5 + 1;
            *param_5 = *param_5 + 1;
          }
        }
        else {
          if (((&DAT_01010791)[bVar1] & 4) != 0) {
            pbVar5 = pbVar5 + 1;
            *param_3 = bVar1;
            param_3 = param_3 + 1;
            *param_5 = *param_5 + 1;
          }
          *param_3 = *pbVar5;
          param_3 = param_3 + 1;
        }
        *param_5 = *param_5 + 1;
      }
      pbVar5 = pbVar5 + 1;
    }
    if (param_3 != (byte *)0x0) {
      *param_3 = 0;
      param_3 = param_3 + 1;
    }
    *param_5 = *param_5 + 1;
  }
  if (param_2 != (byte **)0x0) {
    *param_2 = (byte *)0x0;
  }
  *param_4 = *param_4 + 1;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 * FUN_01006923(void)

{
  char cVar1;
  short sVar2;
  undefined4 *puVar3;
  SIZE_T cbMultiByte;
  uint uVar4;
  uint uVar5;
  undefined4 *puVar6;
  int iVar7;
  undefined4 *puVar8;
  undefined4 *local_4;
  
  puVar3 = local_4;
  if (_DAT_0101078c == 0) {
    puVar3 = (undefined4 *)GetEnvironmentStringsW();
    if (puVar3 == (undefined4 *)0x0) {
      local_4 = (undefined4 *)GetEnvironmentStrings();
      if (local_4 == (undefined4 *)0x0) {
        return (undefined4 *)0x0;
      }
      _DAT_0101078c = 2;
    }
    else {
      _DAT_0101078c = 1;
    }
  }
  if (_DAT_0101078c == 1) {
    if ((puVar3 != (undefined4 *)0x0) ||
       (puVar3 = (undefined4 *)GetEnvironmentStringsW(), puVar3 != (undefined4 *)0x0)) {
      sVar2 = *(short *)puVar3;
      puVar6 = puVar3;
      while (sVar2 != 0) {
        do {
          puVar8 = puVar6;
          puVar6 = (undefined4 *)((int)puVar8 + 2);
        } while (*(short *)puVar6 != 0);
        puVar6 = puVar8 + 1;
        sVar2 = *(short *)puVar6;
      }
      iVar7 = ((int)puVar6 - (int)puVar3 >> 1) + 1;
      cbMultiByte = WideCharToMultiByte(0,0,(LPCWSTR)puVar3,iVar7,(LPSTR)0x0,0,(LPCSTR)0x0,
                                        (LPBOOL)0x0);
      if ((cbMultiByte != 0) &&
         (puVar6 = (undefined4 *)FUN_01008440(cbMultiByte), puVar6 != (undefined4 *)0x0)) {
        iVar7 = WideCharToMultiByte(0,0,(LPCWSTR)puVar3,iVar7,(LPSTR)puVar6,cbMultiByte,(LPCSTR)0x0,
                                    (LPBOOL)0x0);
        if (iVar7 == 0) {
          FUN_01008428(puVar6);
          puVar6 = (undefined4 *)0x0;
        }
        FreeEnvironmentStringsW((LPWCH)puVar3);
        return puVar6;
      }
      FreeEnvironmentStringsW((LPWCH)puVar3);
    }
  }
  else if ((_DAT_0101078c == 2) &&
          ((local_4 != (undefined4 *)0x0 ||
           (local_4 = (undefined4 *)GetEnvironmentStrings(), local_4 != (undefined4 *)0x0)))) {
    cVar1 = *(char *)local_4;
    puVar3 = local_4;
    while (cVar1 != '\0') {
      do {
        puVar6 = puVar3;
        puVar3 = (undefined4 *)((int)puVar6 + 1);
      } while (*(char *)puVar3 != '\0');
      puVar3 = (undefined4 *)((int)puVar6 + 2);
      cVar1 = *(char *)puVar3;
    }
    uVar5 = (int)puVar3 + (1 - (int)local_4);
    puVar3 = (undefined4 *)FUN_01008440(uVar5);
    if (puVar3 != (undefined4 *)0x0) {
      puVar6 = local_4;
      puVar8 = puVar3;
      for (uVar4 = uVar5 >> 2; uVar4 != 0; uVar4 = uVar4 - 1) {
        *puVar8 = *puVar6;
        puVar6 = puVar6 + 1;
        puVar8 = puVar8 + 1;
      }
      for (uVar5 = uVar5 & 3; uVar5 != 0; uVar5 = uVar5 - 1) {
        *(undefined *)puVar8 = *(undefined *)puVar6;
        puVar6 = (undefined4 *)((int)puVar6 + 1);
        puVar8 = (undefined4 *)((int)puVar8 + 1);
      }
      FreeEnvironmentStringsA((LPCH)local_4);
      return puVar3;
    }
    FreeEnvironmentStringsA((LPCH)local_4);
  }
  return (undefined4 *)0x0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 __cdecl FUN_01006a80(UINT param_1)

{
  byte bVar1;
  UINT CodePage;
  undefined4 uVar2;
  UINT *pUVar3;
  BOOL BVar4;
  BYTE *pBVar5;
  int iVar6;
  uint uVar7;
  uint uVar8;
  int iVar9;
  undefined4 *puVar10;
  byte *pbVar11;
  _cpinfo local_14;
  
  FUN_010080e9(0x19);
  CodePage = FUN_01006c57(param_1);
  if (CodePage == _DAT_01010894) {
    FUN_0100814c(0x19);
    uVar2 = 0;
  }
  else if (CodePage == 0) {
    FUN_01006ce7();
    FUN_0100814c(0x19);
    uVar2 = 0;
  }
  else {
    iVar9 = 0;
    pUVar3 = &DAT_010108b8;
    do {
      if (*pUVar3 == CodePage) {
        uVar7 = 0;
        puVar10 = (undefined4 *)&DAT_01010790;
        for (iVar6 = 0x40; iVar6 != 0; iVar6 = iVar6 + -1) {
          *puVar10 = 0;
          puVar10 = puVar10 + 1;
        }
        *(undefined *)puVar10 = 0;
        do {
          pbVar11 = &DAT_010108c8 + (uVar7 + iVar9 * 6) * 8;
          bVar1 = *pbVar11;
          while ((bVar1 != 0 && (pbVar11[1] != 0))) {
            uVar8 = (uint)*pbVar11;
            if (uVar8 <= pbVar11[1]) {
              do {
                (&DAT_01010791)[uVar8] = (&DAT_01010791)[uVar8] | (&DAT_010108b0)[uVar7];
                uVar8 = uVar8 + 1;
              } while (uVar8 <= pbVar11[1]);
            }
            pbVar11 = pbVar11 + 2;
            bVar1 = *pbVar11;
          }
          uVar7 = uVar7 + 1;
        } while (uVar7 < 4);
        _DAT_01010894 = CodePage;
        _DAT_01010898 = FUN_01006ca8(CodePage);
        DAT_010108a0 = (&DAT_010108bc)[iVar9 * 0xc];
        DAT_010108a4 = (&DAT_010108c0)[iVar9 * 0xc];
        DAT_010108a8 = (&DAT_010108c4)[iVar9 * 0xc];
        FUN_0100814c(0x19);
        return 0;
      }
      pUVar3 = pUVar3 + 0xc;
      iVar9 = iVar9 + 1;
    } while (pUVar3 < &DAT_010109a8);
    BVar4 = GetCPInfo(CodePage,&local_14);
    if (BVar4 == 1) {
      puVar10 = (undefined4 *)&DAT_01010790;
      for (iVar9 = 0x40; iVar9 != 0; iVar9 = iVar9 + -1) {
        *puVar10 = 0;
        puVar10 = puVar10 + 1;
      }
      *(undefined *)puVar10 = 0;
      if (local_14.MaxCharSize < 2) {
        _DAT_01010898 = 0;
        _DAT_01010894 = 0;
      }
      else {
        pBVar5 = local_14.LeadByte;
        while ((local_14.LeadByte[0] != 0 && (pBVar5[1] != 0))) {
          uVar7 = (uint)*pBVar5;
          if (uVar7 <= pBVar5[1]) {
            do {
              (&DAT_01010791)[uVar7] = (&DAT_01010791)[uVar7] | 4;
              uVar7 = uVar7 + 1;
            } while (uVar7 <= pBVar5[1]);
          }
          pBVar5 = pBVar5 + 2;
          local_14.LeadByte[0] = *pBVar5;
        }
        uVar7 = 1;
        do {
          (&DAT_01010791)[uVar7] = (&DAT_01010791)[uVar7] | 8;
          uVar7 = uVar7 + 1;
        } while (uVar7 < 0xff);
        _DAT_01010894 = CodePage;
        _DAT_01010898 = FUN_01006ca8(CodePage);
      }
      DAT_010108a0 = 0;
      DAT_010108a4 = 0;
      DAT_010108a8 = 0;
      FUN_0100814c(0x19);
      uVar2 = 0;
    }
    else if (_DAT_010108ac == 0) {
      FUN_0100814c(0x19);
      uVar2 = 0xffffffff;
    }
    else {
      FUN_01006ce7();
      FUN_0100814c(0x19);
      uVar2 = 0;
    }
  }
  return uVar2;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

UINT __cdecl FUN_01006c57(UINT param_1)

{
  _DAT_010108ac = 0;
  if (param_1 == 0xfffffffe) {
    _DAT_010108ac = 1;
    param_1 = GetOEMCP();
  }
  else if (param_1 == 0xfffffffd) {
    _DAT_010108ac = 1;
    param_1 = GetACP();
  }
  else if (param_1 == 0xfffffffc) {
    _DAT_010108ac = 1;
    param_1 = DAT_01010cc8;
  }
  return param_1;
}



undefined4 __cdecl FUN_01006ca8(int param_1)

{
  undefined4 uVar1;
  
  if (param_1 == 0x3a4) {
    uVar1 = 0x411;
  }
  else if (param_1 == 0x3a8) {
    uVar1 = 0x804;
  }
  else if (param_1 == 0x3b5) {
    uVar1 = 0x412;
  }
  else if (param_1 == 0x3b6) {
    uVar1 = 0x404;
  }
  else {
    uVar1 = 0;
  }
  return uVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_01006ce7(void)

{
  int iVar1;
  undefined4 *puVar2;
  
  puVar2 = (undefined4 *)&DAT_01010790;
  for (iVar1 = 0x40; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  *(undefined *)puVar2 = 0;
  _DAT_01010894 = 0;
  _DAT_01010898 = 0;
  DAT_010108a0 = 0;
  DAT_010108a4 = 0;
  DAT_010108a8 = 0;
  return;
}



void FUN_01006d0b(void)

{
  FUN_01006a80(0xfffffffd);
  return;
}



void FUN_01006d16(void)

{
  undefined4 *puVar1;
  DWORD DVar2;
  HANDLE hFile;
  HANDLE *ppvVar3;
  HANDLE *ppvVar4;
  undefined4 *puVar5;
  UINT UVar6;
  UINT UVar7;
  int iVar8;
  int *piVar9;
  uint uVar10;
  int iVar11;
  _STARTUPINFOA local_44;
  
  puVar1 = (undefined4 *)FUN_01008440(0x480);
  if (puVar1 == (undefined4 *)0x0) {
    FUN_01005e3c(0x1b);
  }
  DAT_0101772c = 0x20;
  DAT_01017730 = puVar1;
  if (puVar1 < puVar1 + 0x120) {
    do {
      *(undefined *)(puVar1 + 1) = 0;
      *puVar1 = 0xffffffff;
      puVar5 = puVar1 + 9;
      *(undefined *)((int)puVar1 + 5) = 10;
      puVar1[2] = 0;
      puVar1 = puVar5;
    } while (puVar5 < DAT_01017730 + 0x120);
  }
  GetStartupInfoA(&local_44);
  if ((local_44.cbReserved2 != 0) && ((UINT *)local_44.lpReserved2 != (UINT *)0x0)) {
    UVar6 = *(UINT *)local_44.lpReserved2;
    local_44.lpReserved2 = (LPBYTE)((int)local_44.lpReserved2 + 4);
    ppvVar4 = (HANDLE *)(UVar6 + (int)local_44.lpReserved2);
    if (0x7ff < (int)UVar6) {
      UVar6 = 0x800;
    }
    UVar7 = UVar6;
    if ((int)DAT_0101772c < (int)UVar6) {
      piVar9 = &DAT_01017734;
      do {
        puVar1 = (undefined4 *)FUN_01008440(0x480);
        UVar7 = DAT_0101772c;
        if (puVar1 == (undefined4 *)0x0) break;
        *piVar9 = (int)puVar1;
        DAT_0101772c = DAT_0101772c + 0x20;
        if (puVar1 < puVar1 + 0x120) {
          do {
            *(undefined *)(puVar1 + 1) = 0;
            *puVar1 = 0xffffffff;
            puVar5 = puVar1 + 9;
            *(undefined *)((int)puVar1 + 5) = 10;
            puVar1[2] = 0;
            puVar1 = puVar5;
          } while (puVar5 < (undefined4 *)(*piVar9 + 0x480));
        }
        piVar9 = piVar9 + 1;
        UVar7 = UVar6;
      } while ((int)DAT_0101772c < (int)UVar6);
    }
    uVar10 = 0;
    if (0 < (int)UVar7) {
      do {
        if (((*ppvVar4 != (HANDLE)0xffffffff) && ((*local_44.lpReserved2 & 1) != 0)) &&
           (DVar2 = GetFileType(*ppvVar4), DVar2 != 0)) {
          ppvVar3 = (HANDLE *)
                    ((uVar10 & 0x1f) * 0x24 +
                    *(int *)((int)&DAT_01017730 + ((int)(uVar10 & 0xffffffe7) >> 3)));
          *ppvVar3 = *ppvVar4;
          *(BYTE *)(ppvVar3 + 1) = *local_44.lpReserved2;
        }
        uVar10 = uVar10 + 1;
        local_44.lpReserved2 = (LPBYTE)((int)local_44.lpReserved2 + 1);
        ppvVar4 = ppvVar4 + 1;
      } while ((int)uVar10 < (int)UVar7);
    }
  }
  iVar11 = 0;
  iVar8 = 0;
  do {
    ppvVar4 = (HANDLE *)((int)DAT_01017730 + iVar8);
    if (*ppvVar4 == (HANDLE)0xffffffff) {
      DVar2 = 0xfffffff6;
      *(undefined *)(ppvVar4 + 1) = 0x81;
      if (iVar8 != 0) {
        DVar2 = (iVar11 == 1) - 0xc;
      }
      hFile = GetStdHandle(DVar2);
      if ((hFile == (HANDLE)0xffffffff) || (DVar2 = GetFileType(hFile), DVar2 == 0)) {
        *(byte *)(ppvVar4 + 1) = *(byte *)(ppvVar4 + 1) | 0x40;
      }
      else {
        *ppvVar4 = hFile;
        if ((DVar2 & 0xff) == 2) {
          *(byte *)(ppvVar4 + 1) = *(byte *)(ppvVar4 + 1) | 0x40;
        }
        else if ((DVar2 & 0xff) == 3) {
          *(byte *)(ppvVar4 + 1) = *(byte *)(ppvVar4 + 1) | 8;
        }
      }
    }
    else {
      *(byte *)(ppvVar4 + 1) = *(byte *)(ppvVar4 + 1) | 0x80;
    }
    iVar8 = iVar8 + 0x24;
    iVar11 = iVar11 + 1;
  } while (iVar8 < 0x6c);
  SetHandleCount(DAT_0101772c);
  return;
}



undefined4 FUN_01006ee6(void)

{
  DWORD *lpTlsValue;
  BOOL BVar1;
  DWORD DVar2;
  
  FUN_010080c0();
  DAT_010109cc = TlsAlloc();
  if (((DAT_010109cc != 0xffffffff) &&
      (lpTlsValue = (DWORD *)FUN_0100849e(1,0x74), lpTlsValue != (DWORD *)0x0)) &&
     (BVar1 = TlsSetValue(DAT_010109cc,lpTlsValue), BVar1 != 0)) {
    FUN_01006f42((int)lpTlsValue);
    DVar2 = GetCurrentThreadId();
    *lpTlsValue = DVar2;
    lpTlsValue[1] = 0xffffffff;
    return 1;
  }
  return 0;
}



void __cdecl FUN_01006f42(int param_1)

{
  *(undefined **)(param_1 + 0x50) = &DAT_01010700;
  *(undefined4 *)(param_1 + 0x14) = 1;
  return;
}



DWORD * FUN_01006f55(void)

{
  DWORD dwErrCode;
  DWORD *lpTlsValue;
  BOOL BVar1;
  DWORD DVar2;
  
  dwErrCode = GetLastError();
  lpTlsValue = (DWORD *)TlsGetValue(DAT_010109cc);
  if (lpTlsValue == (DWORD *)0x0) {
    lpTlsValue = (DWORD *)FUN_0100849e(1,0x74);
    if (lpTlsValue != (DWORD *)0x0) {
      BVar1 = TlsSetValue(DAT_010109cc,lpTlsValue);
      if (BVar1 != 0) {
        FUN_01006f42((int)lpTlsValue);
        DVar2 = GetCurrentThreadId();
        *lpTlsValue = DVar2;
        lpTlsValue[1] = 0xffffffff;
        goto LAB_01006fb8;
      }
    }
    FUN_01005e3c(0x10);
  }
LAB_01006fb8:
  SetLastError(dwErrCode);
  return lpTlsValue;
}



void FUN_01006fc4(void)

{
  DAT_01017728 = HeapCreate(0,0x1000,0);
  if (DAT_01017728 == (HANDLE)0x0) {
                    // WARNING: Subroutine does not return
    ExitProcess(0xffffffff);
  }
  return;
}



void FUN_010070ad(int param_1)

{
  __local_unwind2(*(int *)(param_1 + 0x18),*(int *)(param_1 + 0x1c));
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __FF_MSGBANNER
// 
// Library: Visual Studio 1998 Release

void __cdecl __FF_MSGBANNER(void)

{
  if ((DAT_01010480 == 1) || ((DAT_01010480 == 0 && (_DAT_01010484 == 1)))) {
    FUN_01007105(0xfc);
    if (DAT_01010a60 != (code *)0x0) {
      (*DAT_01010a60)();
    }
    FUN_01007105(0xff);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_01007105(int param_1)

{
  char cVar1;
  int *piVar2;
  DWORD DVar3;
  HANDLE hFile;
  int iVar4;
  uint uVar5;
  uint uVar6;
  undefined4 *puVar7;
  undefined4 *puVar8;
  undefined4 *puVar9;
  char *pcVar10;
  char *pcVar11;
  undefined4 auStackY_1ec [6];
  undefined4 uStackY_1d4;
  undefined4 local_1b0;
  undefined4 local_ac [40];
  DWORD local_c;
  int local_8;
  
  piVar2 = &DAT_010109d8;
  local_8 = 0;
  do {
    if (*piVar2 == param_1) break;
    piVar2 = piVar2 + 2;
    local_8 = local_8 + 1;
  } while (piVar2 < &DAT_01010a60);
  if ((&DAT_010109d8)[local_8 * 2] == param_1) {
    if ((DAT_01010480 == 1) || ((DAT_01010480 == 0 && (_DAT_01010484 == 1)))) {
      hFile = *(HANDLE *)(DAT_01017730 + 0x48);
      if (hFile == (HANDLE)0xffffffff) {
        hFile = GetStdHandle(0xfffffff4);
      }
      uVar5 = 0xffffffff;
      pcVar10 = (&PTR_s_R6002___floating_point_not_loade_010109dc)[local_8 * 2];
      do {
        if (uVar5 == 0) break;
        uVar5 = uVar5 - 1;
        cVar1 = *pcVar10;
        pcVar10 = pcVar10 + 1;
      } while (cVar1 != '\0');
      uStackY_1d4 = 0x10072d9;
      WriteFile(hFile,(&PTR_s_R6002___floating_point_not_loade_010109dc)[local_8 * 2],~uVar5 - 1,
                &local_c,(LPOVERLAPPED)0x0);
    }
    else if (param_1 != 0xfc) {
      DVar3 = GetModuleFileNameA((HMODULE)0x0,(LPSTR)&local_1b0,0x104);
      if (DVar3 == 0) {
        puVar7 = (undefined4 *)"<program name unknown>";
        puVar8 = &local_1b0;
        for (iVar4 = 5; iVar4 != 0; iVar4 = iVar4 + -1) {
          *puVar8 = *puVar7;
          puVar7 = puVar7 + 1;
          puVar8 = puVar8 + 1;
        }
        *(undefined2 *)puVar8 = *(undefined2 *)puVar7;
        *(undefined *)((int)puVar8 + 2) = *(undefined *)((int)puVar7 + 2);
      }
      puVar7 = &local_1b0;
      uVar5 = 0xffffffff;
      puVar8 = puVar7;
      do {
        if (uVar5 == 0) break;
        uVar5 = uVar5 - 1;
        cVar1 = *(char *)puVar8;
        puVar8 = (undefined4 *)((int)puVar8 + 1);
      } while (cVar1 != '\0');
      if (0x3c < ~uVar5) {
        uVar5 = 0xffffffff;
        do {
          if (uVar5 == 0) break;
          uVar5 = uVar5 - 1;
          cVar1 = *(char *)puVar7;
          puVar7 = (undefined4 *)((int)puVar7 + 1);
        } while (cVar1 != '\0');
        puVar7 = (undefined4 *)((int)auStackY_1ec + ~uVar5);
        _strncpy((char *)puVar7,"...",3);
      }
      puVar8 = (undefined4 *)"Runtime Error!\n\nProgram: ";
      puVar9 = local_ac;
      for (iVar4 = 6; iVar4 != 0; iVar4 = iVar4 + -1) {
        *puVar9 = *puVar8;
        puVar8 = puVar8 + 1;
        puVar9 = puVar9 + 1;
      }
      *(undefined2 *)puVar9 = *(undefined2 *)puVar8;
      uVar5 = 0xffffffff;
      do {
        puVar8 = puVar7;
        if (uVar5 == 0) break;
        uVar5 = uVar5 - 1;
        puVar8 = (undefined4 *)((int)puVar7 + 1);
        cVar1 = *(char *)puVar7;
        puVar7 = puVar8;
      } while (cVar1 != '\0');
      uVar5 = ~uVar5;
      iVar4 = -1;
      puVar7 = local_ac;
      do {
        puVar9 = puVar7;
        if (iVar4 == 0) break;
        iVar4 = iVar4 + -1;
        puVar9 = (undefined4 *)((int)puVar7 + 1);
        cVar1 = *(char *)puVar7;
        puVar7 = puVar9;
      } while (cVar1 != '\0');
      puVar7 = (undefined4 *)((int)puVar8 - uVar5);
      puVar8 = (undefined4 *)((int)puVar9 + -1);
      for (uVar6 = uVar5 >> 2; uVar6 != 0; uVar6 = uVar6 - 1) {
        *puVar8 = *puVar7;
        puVar7 = puVar7 + 1;
        puVar8 = puVar8 + 1;
      }
      for (uVar5 = uVar5 & 3; uVar5 != 0; uVar5 = uVar5 - 1) {
        *(undefined *)puVar8 = *(undefined *)puVar7;
        puVar7 = (undefined4 *)((int)puVar7 + 1);
        puVar8 = (undefined4 *)((int)puVar8 + 1);
      }
      uVar5 = 0xffffffff;
      pcVar10 = "\n\n";
      do {
        pcVar11 = pcVar10;
        if (uVar5 == 0) break;
        uVar5 = uVar5 - 1;
        pcVar11 = pcVar10 + 1;
        cVar1 = *pcVar10;
        pcVar10 = pcVar11;
      } while (cVar1 != '\0');
      uVar5 = ~uVar5;
      iVar4 = -1;
      puVar7 = local_ac;
      do {
        puVar8 = puVar7;
        if (iVar4 == 0) break;
        iVar4 = iVar4 + -1;
        puVar8 = (undefined4 *)((int)puVar7 + 1);
        cVar1 = *(char *)puVar7;
        puVar7 = puVar8;
      } while (cVar1 != '\0');
      puVar7 = (undefined4 *)(pcVar11 + -uVar5);
      puVar8 = (undefined4 *)((int)puVar8 + -1);
      for (uVar6 = uVar5 >> 2; uVar6 != 0; uVar6 = uVar6 - 1) {
        *puVar8 = *puVar7;
        puVar7 = puVar7 + 1;
        puVar8 = puVar8 + 1;
      }
      for (uVar5 = uVar5 & 3; uVar5 != 0; uVar5 = uVar5 - 1) {
        *(undefined *)puVar8 = *(undefined *)puVar7;
        puVar7 = (undefined4 *)((int)puVar7 + 1);
        puVar8 = (undefined4 *)((int)puVar8 + 1);
      }
      uVar5 = 0xffffffff;
      pcVar10 = (&PTR_s_R6002___floating_point_not_loade_010109dc)[local_8 * 2];
      do {
        pcVar11 = pcVar10;
        if (uVar5 == 0) break;
        uVar5 = uVar5 - 1;
        pcVar11 = pcVar10 + 1;
        cVar1 = *pcVar10;
        pcVar10 = pcVar11;
      } while (cVar1 != '\0');
      uVar5 = ~uVar5;
      iVar4 = -1;
      puVar7 = local_ac;
      do {
        puVar8 = puVar7;
        if (iVar4 == 0) break;
        iVar4 = iVar4 + -1;
        puVar8 = (undefined4 *)((int)puVar7 + 1);
        cVar1 = *(char *)puVar7;
        puVar7 = puVar8;
      } while (cVar1 != '\0');
      puVar7 = (undefined4 *)(pcVar11 + -uVar5);
      puVar8 = (undefined4 *)((int)puVar8 + -1);
      for (uVar6 = uVar5 >> 2; uVar6 != 0; uVar6 = uVar6 - 1) {
        *puVar8 = *puVar7;
        puVar7 = puVar7 + 1;
        puVar8 = puVar8 + 1;
      }
      for (uVar5 = uVar5 & 3; uVar5 != 0; uVar5 = uVar5 - 1) {
        *(undefined *)puVar8 = *(undefined *)puVar7;
        puVar7 = (undefined4 *)((int)puVar7 + 1);
        puVar8 = (undefined4 *)((int)puVar8 + 1);
      }
      FUN_010084e8(local_ac,"Microsoft Visual C++ Runtime Library",0x12010);
    }
  }
  return;
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



uint __cdecl FUN_010073c5(uint param_1,int *param_2)

{
  uint uVar1;
  int *piVar2;
  byte bVar3;
  uint uVar4;
  undefined3 extraout_var;
  undefined *puVar5;
  uint uVar6;
  uint uVar7;
  uint local_8;
  
  piVar2 = param_2;
  uVar1 = param_2[4];
  uVar6 = param_2[3];
  if (((uVar6 & 0x82) == 0) || ((uVar6 & 0x40) != 0)) {
LAB_010074e4:
    param_2[3] = uVar6 | 0x20;
  }
  else {
    if ((uVar6 & 1) != 0) {
      param_2[1] = 0;
      uVar6 = param_2[3];
      if ((uVar6 & 0x10) == 0) goto LAB_010074e4;
      *param_2 = param_2[2];
      *(byte *)(param_2 + 3) = *(byte *)(param_2 + 3) & 0xfe;
    }
    uVar6 = param_2[3];
    uVar7 = 0;
    uVar4 = uVar6 | 2;
    param_2[3] = uVar4;
    param_2[3] = CONCAT31((int3)(uVar6 >> 8),(char)uVar4) & 0xffffffef;
    param_2[1] = 0;
    if (((param_2[3] & 0x10cU) == 0) &&
       (((param_2 != (int *)&DAT_01010d00 && (param_2 != (int *)&DAT_01010d20)) ||
        (bVar3 = FUN_010089b1(uVar1), CONCAT31(extraout_var,bVar3) == 0)))) {
      FUN_01008965(piVar2);
    }
    if ((piVar2[3] & 0x108U) == 0) {
      local_8 = 1;
      uVar7 = FUN_0100867e(uVar1,(char *)&param_1,1);
    }
    else {
      local_8 = *piVar2 - piVar2[2];
      *piVar2 = piVar2[2] + 1;
      piVar2[1] = piVar2[6] + -1;
      if ((int)local_8 < 1) {
        puVar5 = &DAT_010109a8;
        if (uVar1 != 0xffffffff) {
          puVar5 = (undefined *)
                   (*(int *)((int)&DAT_01017730 + ((int)(uVar1 & 0xffffffe7) >> 3)) +
                   (uVar1 & 0x1f) * 0x24);
        }
        if ((puVar5[4] & 0x20) != 0) {
          FUN_0100887a(uVar1,0,2);
        }
      }
      else {
        uVar7 = FUN_0100867e(uVar1,(char *)piVar2[2],local_8);
      }
      *(undefined *)piVar2[2] = (undefined)param_1;
    }
    if (uVar7 == local_8) {
      return param_1 & 0xff;
    }
    *(byte *)(piVar2 + 3) = *(byte *)(piVar2 + 3) | 0x20;
  }
  return 0xffffffff;
}



int __cdecl FUN_010074f5(byte **param_1,char *param_2,undefined4 *param_3)

{
  char *pcVar1;
  char *pcVar2;
  char cVar3;
  bool bVar4;
  WCHAR *pWVar5;
  WCHAR WVar6;
  uint uVar7;
  short *psVar8;
  int *piVar9;
  undefined4 uVar10;
  int iVar11;
  char *pcVar12;
  char *pcVar13;
  char *pcVar14;
  undefined8 uVar15;
  char local_258;
  char local_257 [510];
  char local_59;
  undefined4 uStack_58;
  undefined4 local_54;
  undefined4 local_50;
  char *local_4c;
  uint local_48;
  int local_44;
  int local_40;
  int local_3c;
  int local_38;
  int local_34;
  int local_30;
  undefined8 local_2c;
  int local_24;
  undefined8 local_20;
  char *local_18;
  char *local_14;
  undefined4 local_10;
  CHAR local_c [4];
  CHAR local_8 [2];
  char local_6;
  char local_5;
  
  local_24 = 0;
  cVar3 = *param_2;
  local_3c = 0;
  local_10 = (char *)CONCAT13(cVar3,(undefined3)local_10);
  param_2 = param_2 + 1;
  pcVar12 = local_10;
  pcVar14 = local_10;
  pcVar13 = local_10;
  do {
    if ((cVar3 == '\0') || (local_24 < 0)) {
      return local_24;
    }
    local_10._3_1_ = (byte)((uint)pcVar13 >> 0x18);
    if (((char)local_10._3_1_ < ' ') || ('x' < (char)local_10._3_1_)) {
      uVar7 = 0;
    }
    else {
      uVar7 = (byte)"<program name unknown>"[(char)local_10._3_1_ + 0x14] & 0xf;
    }
    local_3c = (int)((char)(&DAT_010016d0)[uVar7 * 8 + local_3c] >> 4);
    local_10 = pcVar13;
    switch(local_3c) {
    case 0:
switchD_01007568_caseD_0:
      local_38 = 0;
      if ((PTR_DAT_01010490[(uint)local_10._3_1_ * 2 + 1] & 0x80) != 0) {
        uVar7 = (uint)(char)local_10._3_1_;
        FUN_01007d63(uVar7,param_1,&local_24);
        local_10 = (char *)CONCAT13(*param_2,(undefined3)local_10);
        param_2 = param_2 + 1;
        pcVar13 = local_10;
      }
      local_10 = pcVar13;
      FUN_01007d63((int)(char)local_10._3_1_,param_1,&local_24);
      pcVar13 = local_10;
      break;
    case 1:
      pcVar12 = (char *)0x0;
      local_50 = 0;
      local_40 = 0;
      local_34 = 0;
      local_30 = 0;
      local_38 = 0;
      local_18 = (char *)0xffffffff;
      break;
    case 2:
      if (local_10._3_1_ == 0x20) {
        pcVar12 = (char *)((uint)pcVar12 | 2);
      }
      else if (local_10._3_1_ == 0x23) {
        pcVar12 = (char *)((uint)pcVar12 | 0x80);
      }
      else if (local_10._3_1_ == 0x2b) {
        pcVar12 = (char *)((uint)pcVar12 | 1);
      }
      else if (local_10._3_1_ == 0x2d) {
        pcVar12 = (char *)((uint)pcVar12 | 4);
      }
      else if (local_10._3_1_ == 0x30) {
        pcVar12 = (char *)((uint)pcVar12 | 8);
      }
      break;
    case 3:
      if (local_10._3_1_ == 0x2a) {
        local_34 = FUN_01007dfb((int *)&param_3);
        pcVar13 = local_10;
        if (local_34 < 0) {
          local_34 = -local_34;
          pcVar12 = (char *)((uint)pcVar12 | 4);
        }
      }
      else {
        local_34 = (char)local_10._3_1_ + -0x30 + local_34 * 10;
      }
      break;
    case 4:
      local_18 = (char *)0x0;
      break;
    case 5:
      if (local_10._3_1_ == 0x2a) {
        local_18 = (char *)FUN_01007dfb((int *)&param_3);
        pcVar13 = local_10;
        if ((int)local_18 < 0) {
          local_18 = (char *)0xffffffff;
        }
      }
      else {
        local_18 = (char *)((char)local_10._3_1_ + -0x30 + (int)local_18 * 10);
      }
      break;
    case 6:
      if (local_10._3_1_ == 0x49) {
        if ((*param_2 != '6') || (param_2[1] != '4')) {
          local_3c = 0;
          goto switchD_01007568_caseD_0;
        }
        param_2 = param_2 + 2;
        pcVar12 = (char *)((uint)pcVar12 | 0x8000);
      }
      else if (local_10._3_1_ == 0x68) {
        pcVar12 = (char *)((uint)pcVar12 | 0x20);
      }
      else if (local_10._3_1_ == 0x6c) {
        pcVar12 = (char *)((uint)pcVar12 | 0x10);
      }
      else if (local_10._3_1_ == 0x77) {
        pcVar12 = (char *)((uint)pcVar12 | 0x800);
      }
      break;
    case 7:
      pcVar2 = local_14;
      switch(local_10._3_1_) {
      case 0x43:
        if (((uint)pcVar12 & 0x830) == 0) {
          pcVar12 = (char *)((uint)pcVar12 | 0x800);
        }
      case 99:
        if (((uint)pcVar12 & 0x810) == 0) {
          pcVar14 = (char *)0x1;
          uVar10 = FUN_01007dfb((int *)&param_3);
          local_258 = (char)uVar10;
        }
        else {
          WVar6 = FUN_01007e1e(&param_3);
          pcVar14 = (char *)FUN_01008ab7(&local_258,WVar6);
          if ((int)pcVar14 < 0) {
            local_40 = 1;
          }
        }
        pcVar2 = &local_258;
        pcVar13 = local_10;
        break;
      case 0x45:
      case 0x47:
        local_50 = 1;
        local_10._0_3_ = SUB43(pcVar13,0);
        local_10 = (char *)CONCAT13(local_10._3_1_ + 0x20,(undefined3)local_10);
        pcVar13 = local_10;
      case 0x65:
      case 0x66:
      case 0x67:
        local_10 = pcVar13;
        pcVar13 = (char *)((uint)pcVar12 | 0x40);
        local_14 = &local_258;
        if ((int)local_18 < 0) {
          local_18 = (char *)0x6;
        }
        else if ((local_18 == (char *)0x0) && (local_10._3_1_ == 'g')) {
          local_18 = (char *)0x1;
        }
        uStack_58 = *param_3;
        local_54 = param_3[1];
        param_3 = param_3 + 2;
        (*(code *)PTR_FUN_01010f68)
                  (&uStack_58,&local_258,(int)(char)local_10._3_1_,local_18,local_50);
        if ((((uint)pcVar12 & 0x80) != 0) && (local_18 == (char *)0x0)) {
          (*(code *)PTR_FUN_01010f74)(&local_258);
        }
        if ((local_10._3_1_ == 'g') && (((uint)pcVar12 & 0x80) == 0)) {
          (*(code *)PTR_FUN_01010f6c)(&local_258);
        }
        if (local_258 == '-') {
          pcVar13 = (char *)((uint)pcVar12 | 0x140);
          local_14 = local_257;
        }
        uVar7 = 0xffffffff;
        pcVar14 = local_14;
        do {
          if (uVar7 == 0) break;
          uVar7 = uVar7 - 1;
          cVar3 = *pcVar14;
          pcVar14 = pcVar14 + 1;
        } while (cVar3 != '\0');
        pcVar14 = (char *)(~uVar7 - 1);
        pcVar12 = pcVar13;
        pcVar2 = local_14;
        pcVar13 = local_10;
        break;
      case 0x53:
        if (((uint)pcVar12 & 0x830) == 0) {
          pcVar12 = (char *)((uint)pcVar12 | 0x800);
        }
      case 0x73:
        local_10 = (char *)0x7fffffff;
        if (local_18 != (char *)0xffffffff) {
          local_10 = local_18;
        }
        local_14 = (char *)FUN_01007dfb((int *)&param_3);
        if (((uint)pcVar12 & 0x810) == 0) {
          pcVar14 = local_14;
          if (local_14 == (char *)0x0) {
            local_14 = PTR_DAT_01010a70;
            pcVar14 = PTR_DAT_01010a70;
          }
          for (; (bVar4 = local_10 != (char *)0x0, local_10 = local_10 + -1, bVar4 &&
                 (*pcVar14 != '\0')); pcVar14 = pcVar14 + 1) {
          }
          pcVar14 = pcVar14 + -(int)local_14;
          pcVar2 = local_14;
          pcVar13 = local_10;
        }
        else {
          if (local_14 == (char *)0x0) {
            local_14 = PTR_DAT_01010a74;
          }
          pcVar14 = (char *)0x0;
          local_20 = CONCAT44(local_14,(int)local_20);
          local_38 = 1;
          pcVar2 = local_14;
          pcVar13 = local_10;
          if (0 < (int)local_10) {
            do {
              pcVar2 = local_14;
              pcVar13 = local_10;
              if ((*local_20._4_4_ == L'\0') ||
                 (iVar11 = FUN_01008ab7(local_8,*local_20._4_4_), pcVar2 = local_14,
                 pcVar13 = local_10, iVar11 == 0)) break;
              local_20 = CONCAT44((int)local_20._4_4_ + 2,(int)local_20);
              pcVar14 = pcVar14 + iVar11;
            } while ((int)pcVar14 < (int)local_10);
          }
        }
        break;
      case 0x5a:
        psVar8 = (short *)FUN_01007dfb((int *)&param_3);
        if ((psVar8 == (short *)0x0) || (pcVar2 = *(char **)(psVar8 + 2), pcVar2 == (char *)0x0)) {
          uVar7 = 0xffffffff;
          local_14 = PTR_DAT_01010a70;
          pcVar14 = PTR_DAT_01010a70;
          do {
            if (uVar7 == 0) break;
            uVar7 = uVar7 - 1;
            cVar3 = *pcVar14;
            pcVar14 = pcVar14 + 1;
          } while (cVar3 != '\0');
          pcVar14 = (char *)(~uVar7 - 1);
          pcVar2 = local_14;
          pcVar13 = local_10;
        }
        else if (((uint)pcVar12 & 0x800) == 0) {
          local_38 = 0;
          pcVar14 = (char *)(int)*psVar8;
          pcVar13 = local_10;
        }
        else {
          local_38 = 1;
          pcVar14 = (char *)((uint)(int)*psVar8 >> 1);
          pcVar13 = local_10;
        }
        break;
      case 100:
      case 0x69:
        local_10 = (char *)0xa;
        pcVar12 = (char *)((uint)pcVar12 | 0x40);
        goto LAB_0100791c;
      case 0x6e:
        piVar9 = (int *)FUN_01007dfb((int *)&param_3);
        if (((uint)pcVar12 & 0x20) == 0) {
          *piVar9 = local_24;
        }
        else {
          *(short *)piVar9 = (short)local_24;
        }
        local_40 = 1;
        pcVar2 = local_14;
        pcVar13 = local_10;
        break;
      case 0x6f:
        local_10 = (char *)0x8;
        if (((uint)pcVar12 & 0x80) != 0) {
          pcVar12 = (char *)((uint)pcVar12 | 0x200);
        }
        goto LAB_0100791c;
      case 0x70:
        local_18 = (char *)0x8;
      case 0x58:
        local_44 = 7;
        goto LAB_010078fa;
      case 0x75:
        local_10 = (char *)0xa;
        goto LAB_0100791c;
      case 0x78:
        local_44 = 0x27;
LAB_010078fa:
        local_10 = (char *)0x10;
        if (((uint)pcVar12 & 0x80) != 0) {
          local_6 = '0';
          local_30 = 2;
          local_5 = (char)local_44 + 'Q';
        }
LAB_0100791c:
        if (((uint)pcVar12 & 0x8000) == 0) {
          if (((uint)pcVar12 & 0x20) == 0) {
            if (((uint)pcVar12 & 0x40) == 0) {
              uVar7 = FUN_01007dfb((int *)&param_3);
              goto LAB_010079a4;
            }
            iVar11 = FUN_01007dfb((int *)&param_3);
            local_20 = (ulonglong)iVar11;
          }
          else if (((uint)pcVar12 & 0x40) == 0) {
            uVar7 = FUN_01007dfb((int *)&param_3);
            uVar7 = uVar7 & 0xffff;
LAB_010079a4:
            local_20 = (ulonglong)uVar7;
          }
          else {
            uVar10 = FUN_01007dfb((int *)&param_3);
            local_20 = (ulonglong)(int)(short)uVar10;
          }
        }
        else {
          local_20 = FUN_01007e0a((int *)&param_3);
        }
        if (((((uint)pcVar12 & 0x40) == 0) || (0 < (int)local_20._4_4_)) ||
           (-1 < (longlong)local_20)) {
          local_2c = local_20;
        }
        else {
          pcVar12 = (char *)((uint)pcVar12 | 0x100);
          local_2c = CONCAT44(-((int)local_20._4_4_ + (uint)((int)local_20 != 0)),-(int)local_20);
        }
        if (((uint)pcVar12 & 0x8000) == 0) {
          local_2c = local_2c & 0xffffffff;
        }
        if ((int)local_18 < 0) {
          local_18 = (char *)0x1;
        }
        else {
          pcVar12 = (char *)((uint)pcVar12 & 0xfffffff7);
        }
        if ((local_2c._4_4_ == (WCHAR *)0x0) && ((uint)local_2c == 0)) {
          local_30 = 0;
        }
        local_14 = &local_59;
        while( true ) {
          pcVar1 = local_18 + -1;
          if ((((int)local_18 < 1) && (local_2c._4_4_ == (WCHAR *)0x0)) && ((uint)local_2c == 0))
          break;
          local_48 = (int)local_10 >> 0x1f;
          local_4c = local_10;
          local_18 = pcVar1;
          uVar15 = __aullrem((uint)local_2c,(uint)local_2c._4_4_,(uint)local_10,local_48);
          local_20 = CONCAT44((int)uVar15 + 0x30,(int)local_20);
          local_2c = __aulldiv((uint)local_2c,(uint)local_2c._4_4_,(uint)local_4c,local_48);
          if (0x39 < (int)local_20._4_4_) {
            local_20 = CONCAT44((int)local_20._4_4_ + local_44,(int)local_20);
          }
          pcVar14 = local_14 + -1;
          *local_14 = local_20._4_1_;
          local_14 = pcVar14;
        }
        pcVar14 = &local_59 + -(int)local_14;
        pcVar2 = local_14 + 1;
        local_18 = pcVar1;
        pcVar13 = local_10;
        if ((((uint)pcVar12 & 0x200) != 0) && ((*pcVar2 != '0' || (pcVar14 == (char *)0x0)))) {
          pcVar14 = (char *)((int)&uStack_58 + -(int)local_14);
          *local_14 = '0';
          pcVar2 = local_14;
          pcVar13 = local_10;
        }
      }
      local_10 = pcVar13;
      local_14 = pcVar2;
      pcVar13 = local_10;
      if (local_40 == 0) {
        if (((uint)pcVar12 & 0x40) != 0) {
          if (((uint)pcVar12 & 0x100) == 0) {
            if (((uint)pcVar12 & 1) == 0) {
              if (((uint)pcVar12 & 2) == 0) goto LAB_01007be0;
              local_6 = ' ';
            }
            else {
              local_6 = '+';
            }
          }
          else {
            local_6 = '-';
          }
          local_30 = 1;
        }
LAB_01007be0:
        local_10 = (char *)((local_34 - (int)pcVar14) - local_30);
        if (((uint)pcVar12 & 0xc) == 0) {
          FUN_01007da4(0x20,(int)local_10,param_1,&local_24);
        }
        FUN_01007dcc(&local_6,local_30,param_1,&local_24);
        if ((((uint)pcVar12 & 8) != 0) && (((uint)pcVar12 & 4) == 0)) {
          FUN_01007da4(0x30,(int)local_10,param_1,&local_24);
        }
        if ((local_38 == 0) || ((int)pcVar14 < 1)) {
          FUN_01007dcc(local_14,(int)pcVar14,param_1,&local_24);
        }
        else {
          local_2c = CONCAT44(local_14,(uint)local_2c);
          local_20 = CONCAT44(pcVar14 + -1,(int)local_20);
          do {
            pWVar5 = local_2c._4_4_;
            local_2c = CONCAT44(local_2c._4_4_ + 1,(uint)local_2c);
            iVar11 = FUN_01008ab7(local_c,*pWVar5);
            if (iVar11 < 1) break;
            FUN_01007dcc(local_c,iVar11,param_1,&local_24);
            iVar11 = (int)local_20._4_4_;
            local_20 = CONCAT44((int)local_20._4_4_ + -1,(int)local_20);
          } while (iVar11 != 0);
        }
        pcVar13 = local_10;
        if (((uint)pcVar12 & 4) != 0) {
          FUN_01007da4(0x20,(int)local_10,param_1,&local_24);
          pcVar13 = local_10;
        }
      }
    }
    local_10 = pcVar13;
    cVar3 = *param_2;
    local_10 = (char *)CONCAT13(cVar3,(undefined3)local_10);
    param_2 = param_2 + 1;
    pcVar13 = local_10;
  } while( true );
}



void __cdecl FUN_01007d63(uint param_1,byte **param_2,int *param_3)

{
  byte *pbVar1;
  uint uVar2;
  
  pbVar1 = param_2[1];
  param_2[1] = pbVar1 + -1;
  if ((int)(pbVar1 + -1) < 0) {
    uVar2 = FUN_010073c5(param_1,(int *)param_2);
  }
  else {
    **param_2 = (byte)param_1;
    uVar2 = (uint)**param_2;
    *param_2 = *param_2 + 1;
  }
  if (uVar2 == 0xffffffff) {
    *param_3 = -1;
  }
  else {
    *param_3 = *param_3 + 1;
  }
  return;
}



void __cdecl FUN_01007da4(uint param_1,int param_2,byte **param_3,int *param_4)

{
  do {
    if (param_2 < 1) {
      return;
    }
    FUN_01007d63(param_1,param_3,param_4);
    param_2 = param_2 + -1;
  } while (*param_4 != -1);
  return;
}



void __cdecl FUN_01007dcc(char *param_1,int param_2,byte **param_3,int *param_4)

{
  char cVar1;
  
  do {
    if (param_2 < 1) {
      return;
    }
    cVar1 = *param_1;
    param_1 = param_1 + 1;
    FUN_01007d63((int)cVar1,param_3,param_4);
    param_2 = param_2 + -1;
  } while (*param_4 != -1);
  return;
}



undefined4 __cdecl FUN_01007dfb(int *param_1)

{
  undefined4 *puVar1;
  
  puVar1 = (undefined4 *)*param_1;
  *param_1 = (int)(puVar1 + 1);
  return *puVar1;
}



undefined8 __cdecl FUN_01007e0a(int *param_1)

{
  undefined8 *puVar1;
  
  puVar1 = (undefined8 *)*param_1;
  *param_1 = (int)(puVar1 + 1);
  return *puVar1;
}



undefined2 __cdecl FUN_01007e1e(undefined4 *param_1)

{
  undefined2 *puVar1;
  
  puVar1 = (undefined2 *)*param_1;
  *param_1 = puVar1 + 2;
  return *puVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl
FUN_01007e2e(DWORD param_1,LPCWSTR param_2,int param_3,LPWORD param_4,UINT param_5,LCID param_6)

{
  LPWORD pWVar1;
  BOOL BVar2;
  int cbMultiByte;
  int iVar3;
  LPWORD lpCharType;
  undefined4 local_8;
  
  if (_DAT_01010a78 == 0) {
    BVar2 = GetStringTypeW(1,L"",1,(LPWORD)((int)&local_8 + 2));
    if (BVar2 == 0) {
      BVar2 = GetStringTypeA(0,1,"",1,(LPWORD)((int)&local_8 + 2));
      if (BVar2 == 0) {
        return;
      }
      _DAT_01010a78 = 2;
    }
    else {
      _DAT_01010a78 = 1;
    }
  }
  if (_DAT_01010a78 == 1) {
    GetStringTypeW(param_1,param_2,param_3,param_4);
  }
  else if (_DAT_01010a78 == 2) {
    lpCharType = (LPWORD)0x0;
    if (param_5 == 0) {
      param_5 = DAT_01010cc8;
    }
    cbMultiByte = WideCharToMultiByte(param_5,0x220,param_2,param_3,(LPSTR)0x0,0,(LPCSTR)0x0,
                                      (LPBOOL)0x0);
    if ((cbMultiByte != 0) && (local_8 = (LPSTR)FUN_0100849e(1,cbMultiByte), local_8 != (LPSTR)0x0))
    {
      iVar3 = WideCharToMultiByte(param_5,0x220,param_2,param_3,local_8,cbMultiByte,(LPCSTR)0x0,
                                  (LPBOOL)0x0);
      if ((iVar3 != 0) &&
         (lpCharType = (LPWORD)FUN_01008440(cbMultiByte * 2 + 2), lpCharType != (LPWORD)0x0)) {
        if (param_6 == 0) {
          param_6 = DAT_01010cb8;
        }
        pWVar1 = lpCharType + param_3;
        *pWVar1 = 0xffff;
        pWVar1[-1] = 0xffff;
        GetStringTypeA(param_6,param_1,local_8,cbMultiByte,lpCharType);
        if ((pWVar1[-1] != 0xffff) && (*pWVar1 == 0xffff)) {
          FID_conflict__memcpy(param_4,lpCharType,param_3 * 2);
        }
      }
      FUN_01008428(local_8);
      FUN_01008428(lpCharType);
    }
  }
  return;
}



void __cdecl
FUN_01007fbe(DWORD param_1,LPCSTR param_2,int param_3,LPWORD param_4,UINT param_5,LCID param_6)

{
  BOOL BVar1;
  int iVar2;
  LPCWSTR lpWideCharStr;
  undefined4 local_8;
  
  iVar2 = DAT_01010a7c;
  if (DAT_01010a7c == 0) {
    BVar1 = GetStringTypeA(0,1,"",1,(LPWORD)((int)&local_8 + 2));
    if (BVar1 == 0) {
      iVar2 = 1;
      BVar1 = GetStringTypeW(1,L"",1,(LPWORD)((int)&local_8 + 2));
      if (BVar1 == 0) {
        return;
      }
    }
    else {
      iVar2 = 2;
    }
  }
  DAT_01010a7c = iVar2;
  if (iVar2 == 2) {
    if (param_6 == 0) {
      param_6 = DAT_01010cb8;
    }
    GetStringTypeA(param_6,param_1,param_2,param_3,param_4);
  }
  else if (iVar2 == 1) {
    lpWideCharStr = (LPCWSTR)0x0;
    if (param_5 == 0) {
      param_5 = DAT_01010cc8;
    }
    local_8 = MultiByteToWideChar(param_5,9,param_2,param_3,(LPWSTR)0x0,0);
    if (((local_8 != 0) &&
        (lpWideCharStr = (LPCWSTR)FUN_0100849e(2,local_8), lpWideCharStr != (LPCWSTR)0x0)) &&
       (iVar2 = MultiByteToWideChar(param_5,1,param_2,param_3,lpWideCharStr,local_8), iVar2 != 0)) {
      GetStringTypeW(param_1,lpWideCharStr,iVar2,param_4);
    }
    FUN_01008428(lpWideCharStr);
  }
  return;
}



void FUN_010080c0(void)

{
  InitializeCriticalSection((LPCRITICAL_SECTION)PTR_DAT_01010c34);
  InitializeCriticalSection((LPCRITICAL_SECTION)PTR_DAT_01010c24);
  InitializeCriticalSection((LPCRITICAL_SECTION)PTR_DAT_01010c14);
  InitializeCriticalSection((LPCRITICAL_SECTION)PTR_DAT_01010bf4);
  return;
}



void __cdecl FUN_010080e9(int param_1)

{
  LPCRITICAL_SECTION *pp_Var1;
  LPCRITICAL_SECTION lpCriticalSection;
  
  pp_Var1 = (LPCRITICAL_SECTION *)(&DAT_01010bf0 + param_1 * 4);
  if (*pp_Var1 == (LPCRITICAL_SECTION)0x0) {
    lpCriticalSection = (LPCRITICAL_SECTION)FUN_01008440(0x18);
    if (lpCriticalSection == (LPCRITICAL_SECTION)0x0) {
      FUN_01005e3c(0x11);
    }
    FUN_010080e9(0x11);
    if (*pp_Var1 == (LPCRITICAL_SECTION)0x0) {
      InitializeCriticalSection(lpCriticalSection);
      *pp_Var1 = lpCriticalSection;
    }
    else {
      FUN_01008428(lpCriticalSection);
    }
    FUN_0100814c(0x11);
  }
  EnterCriticalSection(*pp_Var1);
  return;
}



void __cdecl FUN_0100814c(int param_1)

{
  LeaveCriticalSection(*(LPCRITICAL_SECTION *)(&DAT_01010bf0 + param_1 * 4));
  return;
}



void __cdecl FUN_0100815e(undefined **param_1)

{
  if ((param_1 < &PTR_DAT_01010ce0) || (&DAT_01010f40 < param_1)) {
    EnterCriticalSection((LPCRITICAL_SECTION)(param_1 + 8));
  }
  else {
    FUN_010080e9(((int)(param_1 + -0x404338) >> 5) + 0x1c);
  }
  return;
}



void __cdecl FUN_01008190(int param_1,int param_2)

{
  if (param_1 < 0x14) {
    FUN_010080e9(param_1 + 0x1c);
  }
  else {
    EnterCriticalSection((LPCRITICAL_SECTION)(param_2 + 0x20));
  }
  return;
}



void __cdecl FUN_010081b6(undefined **param_1)

{
  if ((param_1 < &PTR_DAT_01010ce0) || (&DAT_01010f40 < param_1)) {
    LeaveCriticalSection((LPCRITICAL_SECTION)(param_1 + 8));
  }
  else {
    FUN_0100814c(((int)(param_1 + -0x404338) >> 5) + 0x1c);
  }
  return;
}



void __cdecl FUN_010081e8(int param_1,int param_2)

{
  if (param_1 < 0x14) {
    FUN_0100814c(param_1 + 0x1c);
  }
  else {
    LeaveCriticalSection((LPCRITICAL_SECTION)(param_2 + 0x20));
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int __cdecl
FUN_0100820e(LCID param_1,uint param_2,char *param_3,int param_4,LPWSTR param_5,int param_6,
            UINT param_7)

{
  int iVar1;
  LPCWSTR lpWideCharStr;
  int iVar2;
  LPCWSTR lpDestStr;
  
  iVar1 = 0;
  if (_DAT_01010cd0 == 0) {
    iVar1 = LCMapStringA(0,0x100,"",1,(LPSTR)0x0,0);
    if (iVar1 == 0) {
      iVar1 = LCMapStringW(0,0x100,L"",1,(LPWSTR)0x0,0);
      if (iVar1 == 0) {
        return 0;
      }
      _DAT_01010cd0 = 1;
    }
    else {
      _DAT_01010cd0 = 2;
    }
  }
  if (0 < param_4) {
    iVar1 = FUN_010083fe(param_3,param_4);
    param_4 = iVar1;
  }
  if (_DAT_01010cd0 == 2) {
    iVar1 = LCMapStringA(param_1,param_2,param_3,param_4,(LPSTR)param_5,param_6);
    return iVar1;
  }
  if (_DAT_01010cd0 != 1) {
    return iVar1;
  }
  lpDestStr = (LPCWSTR)0x0;
  if (param_7 == 0) {
    param_7 = DAT_01010cc8;
  }
  iVar1 = MultiByteToWideChar(param_7,9,param_3,param_4,(LPWSTR)0x0,0);
  if (iVar1 == 0) {
    return 0;
  }
  lpWideCharStr = (LPCWSTR)FUN_01008440(iVar1 * 2);
  if (lpWideCharStr == (LPCWSTR)0x0) {
    return 0;
  }
  iVar2 = MultiByteToWideChar(param_7,1,param_3,param_4,lpWideCharStr,iVar1);
  if ((iVar2 != 0) &&
     (iVar2 = LCMapStringW(param_1,param_2,lpWideCharStr,iVar1,(LPWSTR)0x0,0), iVar2 != 0)) {
    if ((param_2 & 0x400) == 0) {
      lpDestStr = (LPCWSTR)FUN_01008440(iVar2 * 2);
      if ((lpDestStr == (LPCWSTR)0x0) ||
         (iVar1 = LCMapStringW(param_1,param_2,lpWideCharStr,iVar1,lpDestStr,iVar2), iVar1 == 0))
      goto LAB_0100835a;
      if (param_6 == 0) {
        iVar2 = WideCharToMultiByte(param_7,0x220,lpDestStr,iVar2,(LPSTR)0x0,0,(LPCSTR)0x0,
                                    (LPBOOL)0x0);
        iVar1 = iVar2;
      }
      else {
        iVar2 = WideCharToMultiByte(param_7,0x220,lpDestStr,iVar2,(LPSTR)param_5,param_6,(LPCSTR)0x0
                                    ,(LPBOOL)0x0);
        iVar1 = iVar2;
      }
    }
    else {
      if (param_6 == 0) goto LAB_010083e5;
      if (param_6 < iVar2) goto LAB_0100835a;
      iVar1 = LCMapStringW(param_1,param_2,lpWideCharStr,iVar1,param_5,param_6);
    }
    if (iVar1 != 0) {
LAB_010083e5:
      FUN_01008428(lpWideCharStr);
      FUN_01008428(lpDestStr);
      return iVar2;
    }
  }
LAB_0100835a:
  FUN_01008428(lpWideCharStr);
  FUN_01008428(lpDestStr);
  return 0;
}



int __cdecl FUN_010083fe(char *param_1,int param_2)

{
  int iVar1;
  char *pcVar2;
  
  pcVar2 = param_1;
  iVar1 = param_2;
  if (param_2 != 0) {
    do {
      iVar1 = iVar1 + -1;
      if (*pcVar2 == '\0') goto LAB_01008420;
      pcVar2 = pcVar2 + 1;
    } while (iVar1 != 0);
  }
  if (*pcVar2 == '\0') {
LAB_01008420:
    param_2 = (int)pcVar2 - (int)param_1;
  }
  return param_2;
}



void __cdecl FUN_01008428(LPVOID param_1)

{
  if (param_1 != (LPVOID)0x0) {
    HeapFree(DAT_01017728,0,param_1);
  }
  return;
}



void __cdecl FUN_01008440(SIZE_T param_1)

{
  FUN_01008453(param_1,DAT_010117bc);
  return;
}



int __cdecl FUN_01008453(SIZE_T param_1,int param_2)

{
  int iVar1;
  
  if (param_1 < 0xffffffe1) {
    if (param_1 == 0) {
      param_1 = 1;
    }
    do {
      iVar1 = FUN_0100848b(param_1);
      if (iVar1 != 0) {
        return iVar1;
      }
      if (param_2 == 0) {
        return 0;
      }
      iVar1 = FUN_01009c0a(param_1);
    } while (iVar1 != 0);
  }
  return 0;
}



void __cdecl FUN_0100848b(SIZE_T param_1)

{
  HeapAlloc(DAT_01017728,0,param_1);
  return;
}



LPVOID __cdecl FUN_0100849e(int param_1,int param_2)

{
  LPVOID pvVar1;
  int iVar2;
  uint dwBytes;
  
  dwBytes = param_2 * param_1;
  if (dwBytes == 0) {
    dwBytes = 1;
  }
  do {
    pvVar1 = (LPVOID)0x0;
    if (dwBytes < 0xffffffe1) {
      pvVar1 = HeapAlloc(DAT_01017728,8,dwBytes);
    }
    if (pvVar1 != (LPVOID)0x0) {
      return pvVar1;
    }
    if (DAT_010117bc == 0) {
      return (LPVOID)0x0;
    }
    iVar2 = FUN_01009c0a(dwBytes);
  } while (iVar2 != 0);
  return (LPVOID)0x0;
}



int __cdecl FUN_010084e8(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  HMODULE hModule;
  int iVar1;
  
  iVar1 = 0;
  if (DAT_01010cd4 == (FARPROC)0x0) {
    hModule = LoadLibraryA("user32.dll");
    if (hModule != (HMODULE)0x0) {
      DAT_01010cd4 = GetProcAddress(hModule,"MessageBoxA");
      if (DAT_01010cd4 != (FARPROC)0x0) {
        DAT_01010cd8 = GetProcAddress(hModule,"GetActiveWindow");
        DAT_01010cdc = GetProcAddress(hModule,"GetLastActivePopup");
        goto LAB_01008537;
      }
    }
    iVar1 = 0;
  }
  else {
LAB_01008537:
    if (DAT_01010cd8 != (FARPROC)0x0) {
      iVar1 = (*DAT_01010cd8)();
    }
    if ((iVar1 != 0) && (DAT_01010cdc != (FARPROC)0x0)) {
      iVar1 = (*DAT_01010cdc)(iVar1);
    }
    iVar1 = (*DAT_01010cd4)(iVar1,param_1,param_2,param_3);
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
        goto joined_r0x010085be;
      }
    }
    do {
      if (((uint)puVar5 & 3) == 0) {
        uVar4 = _Count >> 2;
        cVar3 = '\0';
        if (uVar4 == 0) goto LAB_010085fb;
        goto LAB_01008669;
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
joined_r0x01008665:
          while( true ) {
            uVar4 = uVar4 - 1;
            puVar5 = puVar5 + 1;
            if (uVar4 == 0) break;
LAB_01008669:
            *puVar5 = 0;
          }
          cVar3 = '\0';
          _Count = _Count & 3;
          if (_Count != 0) goto LAB_010085fb;
          return _Dest;
        }
        if ((char)(uVar2 >> 8) == '\0') {
          *puVar5 = uVar2 & 0xff;
          goto joined_r0x01008665;
        }
        if ((uVar2 & 0xff0000) == 0) {
          *puVar5 = uVar2 & 0xffff;
          goto joined_r0x01008665;
        }
        if ((uVar2 & 0xff000000) == 0) {
          *puVar5 = uVar2;
          goto joined_r0x01008665;
        }
      }
      *puVar5 = uVar2;
      puVar5 = puVar5 + 1;
      uVar4 = uVar4 - 1;
joined_r0x010085be:
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
LAB_010085fb:
        *(char *)puVar5 = cVar3;
        puVar5 = (uint *)((int)puVar5 + 1);
      }
      return _Dest;
    }
    _Count = _Count - 1;
  } while (_Count != 0);
  return _Dest;
}



int __cdecl FUN_0100867e(uint param_1,char *param_2,uint param_3)

{
  int iVar1;
  DWORD *pDVar2;
  
  if ((param_1 < DAT_0101772c) &&
     ((*(byte *)(*(int *)((int)&DAT_01017730 + ((int)(param_1 & 0xffffffe7) >> 3)) + 4 +
                (param_1 & 0x1f) * 0x24) & 1) != 0)) {
    FUN_01009da0(param_1);
    iVar1 = FUN_010086ef(param_1,param_2,param_3);
    FUN_01009e01(param_1);
  }
  else {
    pDVar2 = FUN_01009cbb();
    *pDVar2 = 9;
    pDVar2 = FUN_01009cc4();
    *pDVar2 = 0;
    iVar1 = -1;
  }
  return iVar1;
}



int __cdecl FUN_010086ef(uint param_1,char *param_2,uint param_3)

{
  char *pcVar1;
  char cVar2;
  BOOL BVar3;
  DWORD *pDVar4;
  char *pcVar5;
  DWORD DVar6;
  int iVar7;
  char local_41c [1028];
  int local_18;
  char *local_14;
  DWORD local_10;
  int *local_c;
  undefined *local_8;
  
  DVar6 = 0;
  local_18 = 0;
  if (param_3 == 0) {
    local_18 = 0;
  }
  else {
    local_c = (int *)((int)&DAT_01017730 + ((int)(param_1 & 0xffffffe7) >> 3));
    iVar7 = (param_1 & 0x1f) * 0x24;
    if ((*(byte *)(*local_c + 4 + iVar7) & 0x20) != 0) {
      FUN_010088eb(param_1,0,2);
    }
    if ((*(byte *)((HANDLE *)(*local_c + iVar7) + 1) & 0x80) == 0) {
      BVar3 = WriteFile(*(HANDLE *)(*local_c + iVar7),param_2,param_3,&local_10,(LPOVERLAPPED)0x0);
      if (BVar3 == 0) {
LAB_010087f7:
        local_8 = (undefined *)GetLastError();
      }
      else {
        local_8 = (undefined *)0x0;
        DVar6 = local_10;
      }
    }
    else {
      local_8 = (undefined *)0x0;
      local_14 = param_2;
      do {
        if (param_3 <= (uint)((int)local_14 - (int)param_2)) break;
        pcVar5 = local_41c;
        do {
          if (param_3 <= (uint)((int)local_14 - (int)param_2)) break;
          pcVar1 = local_14 + 1;
          cVar2 = *local_14;
          local_14 = pcVar1;
          if (cVar2 == '\n') {
            local_18 = local_18 + 1;
            *pcVar5 = '\r';
            pcVar5 = pcVar5 + 1;
          }
          *pcVar5 = cVar2;
          pcVar5 = pcVar5 + 1;
        } while ((int)pcVar5 - (int)local_41c < 0x400);
        BVar3 = WriteFile(*(HANDLE *)(*local_c + iVar7),local_41c,(int)pcVar5 - (int)local_41c,
                          &local_10,(LPOVERLAPPED)0x0);
        if (BVar3 == 0) goto LAB_010087f7;
        DVar6 = DVar6 + local_10;
      } while ((int)pcVar5 - (int)local_41c <= (int)local_10);
    }
    if (DVar6 == 0) {
      if (local_8 == (undefined *)0x0) {
        if (((*(byte *)(*local_c + 4 + iVar7) & 0x40) == 0) || (*param_2 != '\x1a')) {
          pDVar4 = FUN_01009cbb();
          *pDVar4 = 0x1c;
          pDVar4 = FUN_01009cc4();
          *pDVar4 = 0;
          local_18 = -1;
        }
        else {
          local_18 = 0;
        }
      }
      else {
        if (local_8 == (undefined *)0x5) {
          pDVar4 = FUN_01009cbb();
          *pDVar4 = 9;
          pDVar4 = FUN_01009cc4();
          *pDVar4 = (DWORD)local_8;
        }
        else {
          FUN_01009c48(local_8);
        }
        local_18 = -1;
      }
    }
    else {
      local_18 = DVar6 - local_18;
    }
  }
  return local_18;
}



DWORD __cdecl FUN_0100887a(uint param_1,LONG param_2,DWORD param_3)

{
  DWORD DVar1;
  DWORD *pDVar2;
  
  if ((param_1 < DAT_0101772c) &&
     ((*(byte *)(*(int *)((int)&DAT_01017730 + ((int)(param_1 & 0xffffffe7) >> 3)) + 4 +
                (param_1 & 0x1f) * 0x24) & 1) != 0)) {
    FUN_01009da0(param_1);
    DVar1 = FUN_010088eb(param_1,param_2,param_3);
    FUN_01009e01(param_1);
  }
  else {
    pDVar2 = FUN_01009cbb();
    *pDVar2 = 9;
    pDVar2 = FUN_01009cc4();
    *pDVar2 = 0;
    DVar1 = 0xffffffff;
  }
  return DVar1;
}



DWORD __cdecl FUN_010088eb(uint param_1,LONG param_2,DWORD param_3)

{
  byte *pbVar1;
  HANDLE hFile;
  DWORD *pDVar2;
  DWORD DVar3;
  undefined *puVar4;
  
  hFile = (HANDLE)FUN_01009d59(param_1);
  if (hFile == (HANDLE)0xffffffff) {
    pDVar2 = FUN_01009cbb();
    *pDVar2 = 9;
    DVar3 = 0xffffffff;
  }
  else {
    DVar3 = SetFilePointer(hFile,param_2,(PLONG)0x0,param_3);
    puVar4 = (undefined *)0x0;
    if (DVar3 == 0xffffffff) {
      puVar4 = (undefined *)GetLastError();
    }
    if (puVar4 == (undefined *)0x0) {
      pbVar1 = (byte *)(*(int *)((int)&DAT_01017730 + ((int)(param_1 & 0xffffffe7) >> 3)) + 4 +
                       (param_1 & 0x1f) * 0x24);
      *pbVar1 = *pbVar1 & 0xfd;
    }
    else {
      FUN_01009c48(puVar4);
      DVar3 = 0xffffffff;
    }
  }
  return DVar3;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_01008965(int *param_1)

{
  int **ppiVar1;
  int *piVar2;
  
  _DAT_01010f60 = _DAT_01010f60 + 1;
  piVar2 = (int *)FUN_01008440(0x1000);
  ppiVar1 = (int **)(param_1 + 2);
  *ppiVar1 = piVar2;
  if (piVar2 == (int *)0x0) {
    *(byte *)(param_1 + 3) = *(byte *)(param_1 + 3) | 4;
    *ppiVar1 = param_1 + 5;
    param_1[6] = 2;
  }
  else {
    *(byte *)(param_1 + 3) = *(byte *)(param_1 + 3) | 8;
    param_1[6] = 0x1000;
  }
  *param_1 = (int)*ppiVar1;
  param_1[1] = 0;
  return;
}



byte __cdecl FUN_010089b1(uint param_1)

{
  byte bVar1;
  
  bVar1 = 0;
  if (param_1 < DAT_0101772c) {
    bVar1 = *(byte *)(*(int *)((int)&DAT_01017730 + ((int)(param_1 & 0xffffffe7) >> 3)) + 4 +
                     (param_1 & 0x1f) * 0x24) & 0x40;
  }
  return bVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int __cdecl FUN_01008ab7(LPSTR param_1,WCHAR param_2)

{
  int iVar1;
  bool bVar2;
  
  bVar2 = _DAT_01017724 == 0;
  if (bVar2) {
    _DAT_01017720 = _DAT_01017720 + 1;
  }
  else {
    FUN_010080e9(0x13);
  }
  iVar1 = FUN_01008b08(param_1,param_2);
  if (bVar2) {
    _DAT_01017720 = _DAT_01017720 + -1;
  }
  else {
    FUN_0100814c(0x13);
  }
  return iVar1;
}



int __cdecl FUN_01008b08(LPSTR param_1,WCHAR param_2)

{
  int iVar1;
  DWORD *pDVar2;
  int local_8;
  
  if (param_1 == (LPSTR)0x0) {
    iVar1 = 0;
  }
  else {
    if (DAT_01010cb8 == 0) {
      if ((ushort)param_2 < 0x100) {
        *param_1 = (CHAR)param_2;
        return 1;
      }
    }
    else {
      local_8 = 0;
      iVar1 = WideCharToMultiByte(DAT_01010cc8,0x220,&param_2,1,param_1,DAT_0101069c,(LPCSTR)0x0,
                                  &local_8);
      if ((iVar1 != 0) && (local_8 == 0)) {
        return iVar1;
      }
    }
    pDVar2 = FUN_01009cbb();
    *pDVar2 = 0x2a;
    iVar1 = -1;
  }
  return iVar1;
}



// Library Function - Multiple Matches With Different Base Names
//  _memcpy
//  _memmove
// 
// Libraries: Visual Studio 1998 Debug, Visual Studio 1998 Release

void * __cdecl FID_conflict__memcpy(void *_Dst,void *_Src,size_t _Size)

{
  uint uVar1;
  int in_EDX;
  uint uVar2;
  undefined4 *puVar3;
  undefined *puVar4;
  undefined4 *puVar5;
  undefined *puVar6;
  
  if ((_Src < _Dst) && (_Dst < (void *)((int)_Src + _Size))) {
    puVar3 = (undefined4 *)((int)_Src + _Size);
    puVar5 = (undefined4 *)((int)_Dst + _Size);
    if (((uint)puVar5 & 3) == 0) {
      uVar1 = _Size >> 2;
      while( true ) {
        puVar5 = puVar5 + -1;
        puVar3 = puVar3 + -1;
        if (uVar1 == 0) break;
        uVar1 = uVar1 - 1;
        *puVar5 = *puVar3;
      }
      switch(_Size & 3) {
      case 1:
switchD_01008c49_caseD_1:
        *(undefined *)((int)puVar5 + 3) = *(undefined *)((int)puVar3 + 3);
        return _Dst;
      case 2:
switchD_01008c49_caseD_2:
        *(undefined2 *)((int)puVar5 + 2) = *(undefined2 *)((int)puVar3 + 2);
        return _Dst;
      case 3:
switchD_01008c49_caseD_3:
        *(undefined2 *)((int)puVar5 + 2) = *(undefined2 *)((int)puVar3 + 2);
        *(undefined *)((int)puVar5 + 1) = *(undefined *)((int)puVar3 + 1);
        return _Dst;
      }
    }
    else {
      puVar4 = (undefined *)((int)puVar3 + -1);
      puVar6 = (undefined *)((int)puVar5 + -1);
      if (_Size < 0xd) {
        for (; _Size != 0; _Size = _Size - 1) {
          *puVar6 = *puVar4;
          puVar4 = puVar4 + -1;
          puVar6 = puVar6 + -1;
        }
        return _Dst;
      }
      uVar2 = -in_EDX & 3;
      uVar1 = _Size - uVar2;
      for (; uVar2 != 0; uVar2 = uVar2 - 1) {
        *puVar6 = *puVar4;
        puVar4 = puVar4 + -1;
        puVar6 = puVar6 + -1;
      }
      puVar3 = (undefined4 *)(puVar4 + -3);
      puVar5 = (undefined4 *)(puVar6 + -3);
      for (uVar2 = uVar1 >> 2; uVar2 != 0; uVar2 = uVar2 - 1) {
        *puVar5 = *puVar3;
        puVar3 = puVar3 + -1;
        puVar5 = puVar5 + -1;
      }
      switch(uVar1 & 3) {
      case 1:
        goto switchD_01008c49_caseD_1;
      case 2:
        goto switchD_01008c49_caseD_2;
      case 3:
        goto switchD_01008c49_caseD_3;
      }
    }
    return _Dst;
  }
  puVar3 = (undefined4 *)_Dst;
  if (((uint)_Dst & 3) == 0) {
                    // WARNING: Load size is inaccurate
    for (uVar1 = _Size >> 2; uVar1 != 0; uVar1 = uVar1 - 1) {
      *puVar3 = *_Src;
      _Src = (undefined4 *)((int)_Src + 4);
      puVar3 = puVar3 + 1;
    }
    switch(_Size & 3) {
    case 1:
switchD_01008bb0_caseD_1:
                    // WARNING: Load size is inaccurate
      *(undefined *)puVar3 = *_Src;
      return _Dst;
    case 2:
switchD_01008bb0_caseD_2:
                    // WARNING: Load size is inaccurate
      *(undefined2 *)puVar3 = *_Src;
      return _Dst;
    case 3:
switchD_01008bb0_caseD_3:
                    // WARNING: Load size is inaccurate
      *(undefined2 *)puVar3 = *_Src;
      *(undefined *)((int)puVar3 + 2) = *(undefined *)((int)_Src + 2);
      return _Dst;
    }
  }
  else {
    puVar4 = (undefined *)_Dst;
    if (_Size < 0xd) {
                    // WARNING: Load size is inaccurate
      for (; _Size != 0; _Size = _Size - 1) {
        *puVar4 = *_Src;
        _Src = (undefined *)((int)_Src + 1);
        puVar4 = puVar4 + 1;
      }
      return _Dst;
    }
    uVar2 = -(int)_Dst & 3;
    uVar1 = _Size - uVar2;
                    // WARNING: Load size is inaccurate
    for (; uVar2 != 0; uVar2 = uVar2 - 1) {
      *(undefined *)puVar3 = *_Src;
      _Src = (undefined4 *)((int)_Src + 1);
      puVar3 = (undefined4 *)((int)puVar3 + 1);
    }
                    // WARNING: Load size is inaccurate
    for (uVar2 = uVar1 >> 2; uVar2 != 0; uVar2 = uVar2 - 1) {
      *puVar3 = *_Src;
      _Src = (undefined4 *)((int)_Src + 4);
      puVar3 = puVar3 + 1;
    }
    switch(uVar1 & 3) {
    case 1:
      goto switchD_01008bb0_caseD_1;
    case 2:
      goto switchD_01008bb0_caseD_2;
    case 3:
      goto switchD_01008bb0_caseD_3;
    }
  }
  return _Dst;
}



uint __cdecl FUN_01008d7b(char **param_1)

{
  uint uVar1;
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
  
  uVar1 = (uint)DAT_01010fc0;
  uVar2 = 0xffffffff;
  uVar44 = (uint)DAT_01010fbe;
  if (param_1 != (char **)0x0) {
    uVar3 = FUN_0100a029(1,uVar44,0x31,param_1 + 1);
    uVar4 = FUN_0100a029(1,uVar44,0x32,param_1 + 2);
    uVar5 = FUN_0100a029(1,uVar44,0x33,param_1 + 3);
    uVar6 = FUN_0100a029(1,uVar44,0x34,param_1 + 4);
    uVar7 = FUN_0100a029(1,uVar44,0x35,param_1 + 5);
    uVar8 = FUN_0100a029(1,uVar44,0x36,param_1 + 6);
    uVar9 = FUN_0100a029(1,uVar44,0x37,param_1);
    uVar10 = FUN_0100a029(1,uVar44,0x2a,param_1 + 8);
    uVar11 = FUN_0100a029(1,uVar44,0x2b,param_1 + 9);
    uVar12 = FUN_0100a029(1,uVar44,0x2c,param_1 + 10);
    uVar13 = FUN_0100a029(1,uVar44,0x2d,param_1 + 0xb);
    uVar14 = FUN_0100a029(1,uVar44,0x2e,param_1 + 0xc);
    uVar15 = FUN_0100a029(1,uVar44,0x2f,param_1 + 0xd);
    uVar16 = FUN_0100a029(1,uVar44,0x30,param_1 + 7);
    uVar17 = FUN_0100a029(1,uVar44,0x44,param_1 + 0xe);
    uVar18 = FUN_0100a029(1,uVar44,0x45,param_1 + 0xf);
    uVar19 = FUN_0100a029(1,uVar44,0x46,param_1 + 0x10);
    uVar20 = FUN_0100a029(1,uVar44,0x47,param_1 + 0x11);
    uVar21 = FUN_0100a029(1,uVar44,0x48,param_1 + 0x12);
    uVar22 = FUN_0100a029(1,uVar44,0x49,param_1 + 0x13);
    uVar23 = FUN_0100a029(1,uVar44,0x4a,param_1 + 0x14);
    uVar24 = FUN_0100a029(1,uVar44,0x4b,param_1 + 0x15);
    uVar25 = FUN_0100a029(1,uVar44,0x4c,param_1 + 0x16);
    uVar26 = FUN_0100a029(1,uVar44,0x4d,param_1 + 0x17);
    uVar27 = FUN_0100a029(1,uVar44,0x4e,param_1 + 0x18);
    uVar28 = FUN_0100a029(1,uVar44,0x4f,param_1 + 0x19);
    uVar29 = FUN_0100a029(1,uVar44,0x38,param_1 + 0x1a);
    uVar30 = FUN_0100a029(1,uVar44,0x39,param_1 + 0x1b);
    uVar31 = FUN_0100a029(1,uVar44,0x3a,param_1 + 0x1c);
    uVar32 = FUN_0100a029(1,uVar44,0x3b,param_1 + 0x1d);
    uVar33 = FUN_0100a029(1,uVar44,0x3c,param_1 + 0x1e);
    uVar34 = FUN_0100a029(1,uVar44,0x3d,param_1 + 0x1f);
    uVar35 = FUN_0100a029(1,uVar44,0x3e,param_1 + 0x20);
    uVar36 = FUN_0100a029(1,uVar44,0x3f,param_1 + 0x21);
    uVar37 = FUN_0100a029(1,uVar44,0x40,param_1 + 0x22);
    uVar38 = FUN_0100a029(1,uVar44,0x41,param_1 + 0x23);
    uVar39 = FUN_0100a029(1,uVar44,0x42,param_1 + 0x24);
    uVar40 = FUN_0100a029(1,uVar44,0x43,param_1 + 0x25);
    uVar41 = FUN_0100a029(1,uVar44,0x28,param_1 + 0x26);
    uVar44 = FUN_0100a029(1,uVar44,0x29,param_1 + 0x27);
    uVar42 = FUN_0100a029(1,uVar1,0x1f,param_1 + 0x28);
    uVar43 = FUN_0100a029(1,uVar1,0x20,param_1 + 0x29);
    uVar2 = FUN_010092e0(uVar1,(int)param_1);
    uVar2 = uVar3 | uVar4 | uVar5 | uVar6 | uVar7 | uVar8 | uVar9 | uVar10 | uVar11 | uVar12 |
            uVar13 | uVar14 | uVar15 | uVar16 | uVar17 | uVar18 | uVar19 | uVar20 | uVar21 | uVar22
            | uVar23 | uVar24 | uVar25 | uVar26 | uVar27 | uVar28 | uVar29 | uVar30 | uVar31 |
            uVar32 | uVar33 | uVar34 | uVar35 | uVar36 | uVar37 | uVar38 | uVar39 | uVar40 | uVar41
            | uVar44 | uVar42 | uVar43 | uVar2;
  }
  return uVar2;
}



void __cdecl FUN_010090d8(LPVOID *param_1)

{
  if (param_1 != (LPVOID *)0x0) {
    FUN_01008428(param_1[1]);
    FUN_01008428(param_1[2]);
    FUN_01008428(param_1[3]);
    FUN_01008428(param_1[4]);
    FUN_01008428(param_1[5]);
    FUN_01008428(param_1[6]);
    FUN_01008428(*param_1);
    FUN_01008428(param_1[8]);
    FUN_01008428(param_1[9]);
    FUN_01008428(param_1[10]);
    FUN_01008428(param_1[0xb]);
    FUN_01008428(param_1[0xc]);
    FUN_01008428(param_1[0xd]);
    FUN_01008428(param_1[7]);
    FUN_01008428(param_1[0xe]);
    FUN_01008428(param_1[0xf]);
    FUN_01008428(param_1[0x10]);
    FUN_01008428(param_1[0x11]);
    FUN_01008428(param_1[0x12]);
    FUN_01008428(param_1[0x13]);
    FUN_01008428(param_1[0x14]);
    FUN_01008428(param_1[0x15]);
    FUN_01008428(param_1[0x16]);
    FUN_01008428(param_1[0x17]);
    FUN_01008428(param_1[0x18]);
    FUN_01008428(param_1[0x19]);
    FUN_01008428(param_1[0x1a]);
    FUN_01008428(param_1[0x1b]);
    FUN_01008428(param_1[0x1c]);
    FUN_01008428(param_1[0x1d]);
    FUN_01008428(param_1[0x1e]);
    FUN_01008428(param_1[0x1f]);
    FUN_01008428(param_1[0x20]);
    FUN_01008428(param_1[0x21]);
    FUN_01008428(param_1[0x22]);
    FUN_01008428(param_1[0x23]);
    FUN_01008428(param_1[0x24]);
    FUN_01008428(param_1[0x25]);
    FUN_01008428(param_1[0x26]);
    FUN_01008428(param_1[0x27]);
    FUN_01008428(param_1[0x28]);
    FUN_01008428(param_1[0x29]);
    FUN_01008428(param_1[0x2a]);
  }
  return;
}



uint __cdecl FUN_010092e0(LCID param_1,int param_2)

{
  char cVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  undefined *puVar5;
  char *pcVar6;
  char *pcVar7;
  char *local_10;
  char *local_c;
  char *local_8;
  
  local_10 = (char *)0x0;
  local_c = (char *)0x0;
  uVar2 = FUN_0100a029(0,param_1,0x23,&local_10);
  uVar3 = FUN_0100a029(0,param_1,0x25,&local_c);
  uVar4 = FUN_0100a029(1,param_1,0x1e,&local_8);
  uVar4 = uVar2 | uVar3 | uVar4;
  if (uVar4 != 0) {
    return uVar4;
  }
  puVar5 = (undefined *)FUN_01008440(0xd);
  *(undefined **)(param_2 + 0xa8) = puVar5;
  if (local_10 == (char *)0x0) {
    *puVar5 = 0x68;
    pcVar7 = puVar5 + 1;
    if (local_c == (char *)0x0) goto LAB_01009369;
    *pcVar7 = 'h';
  }
  else {
    *puVar5 = 0x48;
    pcVar7 = puVar5 + 1;
    if (local_c == (char *)0x0) goto LAB_01009369;
    *pcVar7 = 'H';
  }
  pcVar7 = puVar5 + 2;
LAB_01009369:
  cVar1 = *local_8;
  pcVar6 = local_8;
  while (cVar1 != '\0') {
    cVar1 = *pcVar6;
    pcVar6 = pcVar6 + 1;
    *pcVar7 = cVar1;
    pcVar7 = pcVar7 + 1;
    cVar1 = *pcVar6;
  }
  *pcVar7 = 'm';
  pcVar6 = pcVar7 + 1;
  if (local_c != (char *)0x0) {
    *pcVar6 = 'm';
    pcVar6 = pcVar7 + 2;
  }
  cVar1 = *local_8;
  pcVar7 = local_8;
  while (cVar1 != '\0') {
    cVar1 = *pcVar7;
    pcVar7 = pcVar7 + 1;
    *pcVar6 = cVar1;
    pcVar6 = pcVar6 + 1;
    cVar1 = *pcVar7;
  }
  *pcVar6 = 's';
  pcVar6[1] = 's';
  pcVar6[2] = '\0';
  FUN_01008428(local_8);
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_010093bc(void)

{
  uint uVar1;
  uint uVar2;
  undefined4 uVar3;
  uint uVar4;
  
  uVar4 = (uint)DAT_01010fba;
  if (_DAT_01010cc0 == 0) {
    FUN_01008428(DAT_01010f84);
    FUN_01008428(DAT_01010f88);
    FUN_01008428(DAT_01010f8c);
    DAT_01010f84 = (LPVOID)0x0;
    DAT_01010f88 = (LPVOID)0x0;
    DAT_01010f8c = (char *)0x0;
    uVar3 = FUN_01008440(2);
    *(undefined4 *)PTR_PTR_DAT_01011a18 = uVar3;
    if (*(undefined2 **)PTR_PTR_DAT_01011a18 == (undefined2 *)0x0) {
      return 0xffffffff;
    }
    **(undefined2 **)PTR_PTR_DAT_01011a18 = 0x2e;
    uVar3 = FUN_01008440(2);
    *(undefined4 *)(PTR_PTR_DAT_01011a18 + 4) = uVar3;
    if (*(undefined **)(PTR_PTR_DAT_01011a18 + 4) == (undefined *)0x0) {
      return 0xffffffff;
    }
    **(undefined **)(PTR_PTR_DAT_01011a18 + 4) = 0;
    uVar3 = FUN_01008440(2);
    *(undefined4 *)(PTR_PTR_DAT_01011a18 + 8) = uVar3;
    if (*(undefined **)(PTR_PTR_DAT_01011a18 + 8) == (undefined *)0x0) {
      return 0xffffffff;
    }
    **(undefined **)(PTR_PTR_DAT_01011a18 + 8) = 0;
    DAT_010106a0 = **(undefined **)PTR_PTR_DAT_01011a18;
  }
  else {
    uVar1 = FUN_0100a029(1,uVar4,0xe,(char **)&DAT_01010f84);
    uVar2 = FUN_0100a029(1,uVar4,0xf,(char **)&DAT_01010f88);
    uVar4 = FUN_0100a029(1,uVar4,0x10,&DAT_01010f8c);
    FUN_010095bb(DAT_01010f8c);
    if ((uVar1 | uVar2 | uVar4) != 0) {
      FUN_01008428(DAT_01010f84);
      FUN_01008428(DAT_01010f88);
      FUN_01008428(DAT_01010f8c);
      DAT_01010f84 = (LPVOID)0x0;
      DAT_01010f88 = (LPVOID)0x0;
      DAT_01010f8c = (char *)0x0;
      return 0xffffffff;
    }
    if (*(undefined **)PTR_PTR_DAT_01011a18 != &DAT_010119e0) {
      FUN_01008428(*(undefined **)PTR_PTR_DAT_01011a18);
      FUN_01008428(*(LPVOID *)(PTR_PTR_DAT_01011a18 + 4));
      FUN_01008428(*(LPVOID *)(PTR_PTR_DAT_01011a18 + 8));
    }
    *(LPVOID *)PTR_PTR_DAT_01011a18 = DAT_01010f84;
    *(LPVOID *)(PTR_PTR_DAT_01011a18 + 4) = DAT_01010f88;
    *(char **)(PTR_PTR_DAT_01011a18 + 8) = DAT_01010f8c;
    DAT_010106a0 = **(undefined **)PTR_PTR_DAT_01011a18;
  }
  _DAT_010106a4 = 1;
  return 0;
}



void __cdecl FUN_010095bb(char *param_1)

{
  char *pcVar1;
  char cVar2;
  char *pcVar3;
  
  cVar2 = *param_1;
  do {
    if (cVar2 == '\0') {
      return;
    }
    cVar2 = *param_1;
    if ((cVar2 < '0') || ('9' < cVar2)) {
      pcVar3 = param_1;
      if (cVar2 != ';') goto LAB_010095eb;
      do {
        pcVar1 = pcVar3 + 1;
        *pcVar3 = *pcVar1;
        pcVar3 = pcVar1;
      } while (*pcVar1 != '\0');
    }
    else {
      *param_1 = cVar2 + -0x30;
LAB_010095eb:
      param_1 = param_1 + 1;
    }
    cVar2 = *param_1;
  } while( true );
}



undefined4 FUN_010098bd(void)

{
  byte bVar1;
  int iVar2;
  LPCWSTR pWVar3;
  LPCSTR pCVar4;
  BOOL BVar5;
  uint uVar6;
  LPCWSTR pWVar7;
  undefined4 uVar8;
  BYTE *pBVar9;
  int iVar10;
  LPCSTR pCVar11;
  _cpinfo local_24;
  LPWORD local_10;
  undefined2 *local_c;
  LPCWSTR local_8;
  
  pCVar11 = (LPCSTR)0x0;
  local_8 = (LPCWSTR)0x0;
  if (DAT_01010cb8 == 0) {
    PTR_DAT_01010490 = &DAT_0101049a;
    PTR_DAT_01010494 = &DAT_0101049a;
    FUN_01008428(DAT_01010f94);
    FUN_01008428(DAT_01010f98);
    uVar8 = 0;
    DAT_01010f94 = (LPCWSTR)0x0;
    DAT_01010f98 = (undefined2 *)0x0;
  }
  else {
    if ((DAT_01010cc8 != 0) ||
       (iVar2 = FUN_0100a029(0,(uint)DAT_01010fac,0xb,(char **)&DAT_01010cc8), pWVar3 = local_8,
       iVar2 == 0)) {
      pWVar3 = (LPCWSTR)FUN_01008440(0x202);
      local_c = (undefined2 *)FUN_01008440(0x202);
      pCVar11 = (LPCSTR)FUN_01008440(0x101);
      local_8 = (LPCWSTR)FUN_01008440(0x202);
      if ((pWVar3 != (LPCWSTR)0x0) &&
         (((local_c != (undefined2 *)0x0 && (pCVar11 != (LPCSTR)0x0)) && (local_8 != (LPCWSTR)0x0)))
         ) {
        iVar2 = 0;
        pCVar4 = pCVar11;
        do {
          *pCVar4 = (CHAR)iVar2;
          pCVar4 = pCVar4 + 1;
          iVar2 = iVar2 + 1;
        } while (iVar2 < 0x100);
        BVar5 = GetCPInfo(DAT_01010cc8,&local_24);
        if ((BVar5 != 0) && (local_24.MaxCharSize < 3)) {
          DAT_0101069c = local_24.MaxCharSize & 0xffff;
          if (1 < DAT_0101069c) {
            pBVar9 = local_24.LeadByte;
            bVar1 = local_24.LeadByte[0];
            while ((bVar1 != 0 && (pBVar9[1] != 0))) {
              uVar6 = (uint)*pBVar9;
              if (uVar6 <= pBVar9[1]) {
                do {
                  pCVar11[uVar6] = '\0';
                  uVar6 = uVar6 + 1;
                } while ((int)uVar6 <= (int)(uint)pBVar9[1]);
              }
              pBVar9 = pBVar9 + 2;
              bVar1 = *pBVar9;
            }
          }
          iVar10 = 0;
          iVar2 = FUN_01007fbe(1,pCVar11,0x100,(LPWORD)(pWVar3 + 1),0,0);
          if (iVar2 != 0) {
            *pWVar3 = L'\0';
            pWVar7 = local_8;
            do {
              *pWVar7 = (WCHAR)iVar10;
              pWVar7 = pWVar7 + 1;
              iVar10 = iVar10 + 1;
            } while (iVar10 < 0x100);
            local_10 = local_c + 1;
            iVar2 = FUN_01007e2e(1,local_8,0x100,local_10,0,0);
            if (iVar2 != 0) {
              *local_c = 0;
              if (1 < (int)DAT_0101069c) {
                pBVar9 = local_24.LeadByte;
                while ((local_24.LeadByte[0] != 0 && (pBVar9[1] != 0))) {
                  uVar6 = (uint)*pBVar9;
                  if (uVar6 <= pBVar9[1]) {
                    pWVar7 = pWVar3 + uVar6 + 1;
                    do {
                      *pWVar7 = L'è€€';
                      uVar6 = uVar6 + 1;
                      pWVar7 = pWVar7 + 1;
                    } while ((int)uVar6 <= (int)(uint)pBVar9[1]);
                  }
                  pBVar9 = pBVar9 + 2;
                  local_24.LeadByte[0] = *pBVar9;
                }
              }
              PTR_DAT_01010490 = (undefined *)(pWVar3 + 1);
              PTR_DAT_01010494 = (undefined *)local_10;
              if (DAT_01010f94 != (LPCWSTR)0x0) {
                FUN_01008428(DAT_01010f94);
              }
              DAT_01010f94 = pWVar3;
              if (DAT_01010f98 != (undefined2 *)0x0) {
                FUN_01008428(DAT_01010f98);
              }
              DAT_01010f98 = local_c;
              FUN_01008428(pCVar11);
              FUN_01008428(local_8);
              return 0;
            }
          }
        }
      }
    }
    FUN_01008428(pWVar3);
    FUN_01008428(local_c);
    FUN_01008428(pCVar11);
    FUN_01008428(local_8);
    uVar8 = 1;
  }
  return uVar8;
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



undefined4 __cdecl FUN_01009c0a(undefined4 param_1)

{
  int iVar1;
  
  FUN_010080e9(9);
  if ((DAT_01012690 != (code *)0x0) && (iVar1 = (*DAT_01012690)(param_1), iVar1 != 0)) {
    FUN_0100814c(9);
    return 1;
  }
  FUN_0100814c(9);
  return 0;
}



void __cdecl FUN_01009c48(undefined *param_1)

{
  DWORD *pDVar1;
  undefined **ppuVar2;
  int iVar3;
  
  pDVar1 = FUN_01009cc4();
  iVar3 = 0;
  *pDVar1 = (DWORD)param_1;
  ppuVar2 = (undefined **)&DAT_010117c0;
  do {
    if (*ppuVar2 == param_1) {
      pDVar1 = FUN_01009cbb();
      *pDVar1 = (&DAT_010117c4)[iVar3 * 2];
      return;
    }
    ppuVar2 = ppuVar2 + 2;
    iVar3 = iVar3 + 1;
  } while (ppuVar2 < &PTR_DAT_01011928);
  if ((param_1 < (undefined *)0x13) || ((undefined *)0x24 < param_1)) {
    if ((param_1 < (undefined *)0xbc) || ((undefined *)0xca < param_1)) {
      pDVar1 = FUN_01009cbb();
      *pDVar1 = 0x16;
    }
    else {
      pDVar1 = FUN_01009cbb();
      *pDVar1 = 8;
    }
  }
  else {
    pDVar1 = FUN_01009cbb();
    *pDVar1 = 0xd;
  }
  return;
}



DWORD * FUN_01009cbb(void)

{
  DWORD *pDVar1;
  
  pDVar1 = FUN_01006f55();
  return pDVar1 + 2;
}



DWORD * FUN_01009cc4(void)

{
  DWORD *pDVar1;
  
  pDVar1 = FUN_01006f55();
  return pDVar1 + 3;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 __cdecl FUN_01009ccd(uint param_1)

{
  int *piVar1;
  int *piVar2;
  DWORD *pDVar3;
  int iVar4;
  DWORD nStdHandle;
  
  if (param_1 < DAT_0101772c) {
    iVar4 = (param_1 & 0x1f) * 0x24;
    piVar1 = (int *)((int)&DAT_01017730 + ((int)(param_1 & 0xffffffe7) >> 3));
    piVar2 = (int *)(*piVar1 + iVar4);
    if (((*(byte *)(piVar2 + 1) & 1) != 0) && (*piVar2 != -1)) {
      if (_DAT_01010484 == 1) {
        if (param_1 == 0) {
          nStdHandle = 0xfffffff6;
        }
        else if (param_1 == 1) {
          nStdHandle = 0xfffffff5;
        }
        else {
          if (param_1 != 2) goto LAB_01009d2e;
          nStdHandle = 0xfffffff4;
        }
        SetStdHandle(nStdHandle,(HANDLE)0x0);
      }
LAB_01009d2e:
      *(undefined4 *)(*piVar1 + iVar4) = 0xffffffff;
      return 0;
    }
  }
  pDVar3 = FUN_01009cbb();
  *pDVar3 = 9;
  pDVar3 = FUN_01009cc4();
  *pDVar3 = 0;
  return 0xffffffff;
}



undefined4 __cdecl FUN_01009d59(uint param_1)

{
  undefined4 *puVar1;
  DWORD *pDVar2;
  undefined4 uVar3;
  
  if ((param_1 < DAT_0101772c) &&
     (puVar1 = (undefined4 *)
               (*(int *)((int)&DAT_01017730 + ((int)(param_1 & 0xffffffe7) >> 3)) +
               (param_1 & 0x1f) * 0x24), (*(byte *)(puVar1 + 1) & 1) != 0)) {
    uVar3 = *puVar1;
  }
  else {
    pDVar2 = FUN_01009cbb();
    *pDVar2 = 9;
    pDVar2 = FUN_01009cc4();
    *pDVar2 = 0;
    uVar3 = 0xffffffff;
  }
  return uVar3;
}



void __cdecl FUN_01009da0(uint param_1)

{
  int *piVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  
  piVar2 = (int *)((int)&DAT_01017730 + ((int)(param_1 & 0xffffffe7) >> 3));
  iVar4 = (param_1 & 0x1f) * 0x24;
  iVar3 = *piVar2 + iVar4;
  piVar1 = (int *)(iVar3 + 8);
  if (*piVar1 == 0) {
    FUN_010080e9(0x11);
    if (*piVar1 == 0) {
      InitializeCriticalSection((LPCRITICAL_SECTION)(iVar3 + 0xc));
      *piVar1 = *piVar1 + 1;
    }
    FUN_0100814c(0x11);
  }
  EnterCriticalSection((LPCRITICAL_SECTION)(*piVar2 + iVar4 + 0xc));
  return;
}



void __cdecl FUN_01009e01(uint param_1)

{
  LeaveCriticalSection
            ((LPCRITICAL_SECTION)
             (*(int *)((int)&DAT_01017730 + ((int)(param_1 & 0xffffffe7) >> 3)) +
              (param_1 & 0x1f) * 0x24 + 0xc));
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_01009e27(void)

{
  undefined **ppuVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  
  iVar3 = 3;
  iVar5 = 0;
  FUN_010080e9(2);
  if (3 < _DAT_01016710) {
    iVar4 = 0xc;
    do {
      ppuVar1 = *(undefined ***)(DAT_01016714 + iVar4);
      if (ppuVar1 != (undefined **)0x0) {
        if ((*(byte *)(ppuVar1 + 3) & 0x83) != 0) {
          iVar2 = FUN_0100a467(ppuVar1);
          if (iVar2 != -1) {
            iVar5 = iVar5 + 1;
          }
        }
        if (0x4f < iVar4) {
          DeleteCriticalSection((LPCRITICAL_SECTION)(*(int *)(DAT_01016714 + iVar4) + 0x20));
          FUN_01008428(*(LPVOID *)(DAT_01016714 + iVar4));
          *(undefined4 *)(DAT_01016714 + iVar4) = 0;
        }
      }
      iVar4 = iVar4 + 4;
      iVar3 = iVar3 + 1;
    } while (iVar3 < _DAT_01016710);
  }
  FUN_0100814c(2);
  return iVar5;
}



int __cdecl FUN_01009eba(int *param_1)

{
  int iVar1;
  DWORD DVar2;
  
  iVar1 = FUN_01009ef6(param_1);
  if (iVar1 == 0) {
    iVar1 = 0;
    if ((*(byte *)((int)param_1 + 0xd) & 0x40) != 0) {
      DVar2 = FUN_0100a500(param_1[4]);
      iVar1 = (DVar2 == 0) - 1;
    }
  }
  else {
    iVar1 = -1;
  }
  return iVar1;
}



undefined4 __cdecl FUN_01009ef6(int *param_1)

{
  uint *puVar1;
  uint uVar2;
  uint uVar3;
  undefined4 uVar4;
  
  uVar4 = 0;
  puVar1 = (uint *)(param_1 + 3);
  if ((((byte)*puVar1 & 3) == 2) && ((*puVar1 & 0x108) != 0)) {
    uVar3 = *param_1 - (int)(char *)param_1[2];
    if (0 < (int)uVar3) {
      uVar2 = FUN_0100867e(param_1[4],(char *)param_1[2],uVar3);
      if (uVar2 == uVar3) {
        if ((*puVar1 & 0x80) != 0) {
          *puVar1 = *puVar1 & 0xfffffffd;
        }
      }
      else {
        uVar4 = 0xffffffff;
        *(byte *)puVar1 = *(byte *)puVar1 | 0x20;
      }
    }
  }
  *param_1 = param_1[2];
  param_1[1] = 0;
  return uVar4;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int __cdecl FUN_01009f63(int param_1)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  
  iVar3 = 0;
  iVar6 = 0;
  iVar5 = 0;
  FUN_010080e9(2);
  if (0 < _DAT_01016710) {
    iVar4 = 0;
    do {
      iVar2 = *(int *)(DAT_01016714 + iVar4);
      if ((iVar2 != 0) && ((*(byte *)(iVar2 + 0xc) & 0x83) != 0)) {
        FUN_01008190(iVar5,iVar2);
        piVar1 = *(int **)(DAT_01016714 + iVar4);
        if ((piVar1[3] & 0x83U) != 0) {
          if (param_1 == 1) {
            iVar2 = FUN_01009eba(piVar1);
            if (iVar2 != -1) {
              iVar6 = iVar6 + 1;
            }
          }
          else if ((param_1 == 0) && ((piVar1[3] & 2U) != 0)) {
            iVar2 = FUN_01009eba(piVar1);
            if (iVar2 == -1) {
              iVar3 = -1;
            }
          }
        }
        FUN_010081e8(iVar5,*(int *)(DAT_01016714 + iVar4));
      }
      iVar4 = iVar4 + 4;
      iVar5 = iVar5 + 1;
    } while (iVar5 < _DAT_01016710);
  }
  FUN_0100814c(2);
  if (param_1 != 1) {
    iVar6 = iVar3;
  }
  return iVar6;
}



void FUN_0100a01e(void)

{
  FUN_01005e3c(2);
  return;
}



undefined4 __cdecl FUN_0100a029(int param_1,LCID param_2,LCTYPE param_3,char **param_4)

{
  byte bVar1;
  bool bVar2;
  ushort uVar3;
  DWORD DVar4;
  SIZE_T SVar5;
  LPSTR _Source;
  char *_Dest;
  int iVar6;
  undefined2 extraout_var;
  uint uVar7;
  byte *pbVar8;
  CHAR local_88 [128];
  undefined4 local_8;
  
  if (param_1 != 1) {
    if (param_1 != 0) {
      return 0xffffffff;
    }
    iVar6 = FUN_0100a186(param_2,param_3,(LPWSTR)&DAT_01012698,4,0);
    if (iVar6 == 0) {
      return 0xffffffff;
    }
    pbVar8 = &DAT_01012698;
    *(undefined *)param_4 = 0;
    while( true ) {
      bVar1 = *pbVar8;
      local_8 = CONCAT13(bVar1,(undefined3)local_8);
      if (DAT_0101069c < 2) {
        uVar7 = *(ushort *)(PTR_DAT_01010490 + (uint)bVar1 * 2) & 4;
      }
      else {
        uVar3 = FUN_01006038((uint)bVar1,4);
        uVar7 = CONCAT22(extraout_var,uVar3);
      }
      if (uVar7 == 0) break;
      pbVar8 = pbVar8 + 2;
      *(char *)param_4 = local_8._3_1_ + *(char *)param_4 * '\n' + -0x30;
      if (&DAT_010126a0 <= pbVar8) {
        return 0;
      }
    }
    return 0;
  }
  _Source = local_88;
  bVar2 = false;
  local_8 = FUN_0100a282(param_2,param_3,_Source,0x80,0);
  if (local_8 == 0) {
    DVar4 = GetLastError();
    if (((DVar4 != 0x7a) || (SVar5 = FUN_0100a282(param_2,param_3,(LPSTR)0x0,0,0), SVar5 == 0)) ||
       (_Source = (LPSTR)FUN_01008440(SVar5), _Source == (LPSTR)0x0)) goto LAB_0100a0ea;
    bVar2 = true;
    local_8 = FUN_0100a282(param_2,param_3,_Source,SVar5,0);
    if (local_8 == 0) goto LAB_0100a0ea;
  }
  _Dest = (char *)FUN_01008440(local_8);
  *param_4 = _Dest;
  if (_Dest != (char *)0x0) {
    _strncpy(_Dest,_Source,local_8);
    if (bVar2) {
      FUN_01008428(_Source);
    }
    return 0;
  }
LAB_0100a0ea:
  if (bVar2) {
    FUN_01008428(_Source);
  }
  return 0xffffffff;
}



int __cdecl FUN_0100a186(LCID param_1,LCTYPE param_2,LPWSTR param_3,int param_4,UINT param_5)

{
  int iVar1;
  SIZE_T cchData;
  LPSTR lpLCData;
  
  if (DAT_01011a1c == 0) {
    iVar1 = GetLocaleInfoW(0,1,(LPWSTR)0x0,0);
    if (iVar1 == 0) {
      iVar1 = GetLocaleInfoA(0,1,(LPSTR)0x0,0);
      if (iVar1 == 0) {
        return 0;
      }
      DAT_01011a1c = 2;
    }
    else {
      DAT_01011a1c = 1;
    }
  }
  if (DAT_01011a1c != 1) {
    if (DAT_01011a1c != 2) {
      return DAT_01011a1c;
    }
    if (param_5 == 0) {
      param_5 = DAT_01010cc8;
    }
    cchData = GetLocaleInfoA(param_1,param_2,(LPSTR)0x0,0);
    if ((cchData != 0) && (lpLCData = (LPSTR)FUN_01008440(cchData), lpLCData != (LPSTR)0x0)) {
      iVar1 = GetLocaleInfoA(param_1,param_2,lpLCData,cchData);
      if (iVar1 != 0) {
        if (param_4 == 0) {
          iVar1 = MultiByteToWideChar(param_5,1,lpLCData,-1,(LPWSTR)0x0,0);
        }
        else {
          iVar1 = MultiByteToWideChar(param_5,1,lpLCData,-1,param_3,param_4);
        }
        if (iVar1 != 0) {
          FUN_01008428(lpLCData);
          return iVar1;
        }
      }
      FUN_01008428(lpLCData);
    }
    return 0;
  }
  iVar1 = GetLocaleInfoW(param_1,param_2,param_3,param_4);
  return iVar1;
}



int __cdecl FUN_0100a282(LCID param_1,LCTYPE param_2,LPSTR param_3,int param_4,UINT param_5)

{
  int iVar1;
  LPWSTR lpLCData;
  
  if (DAT_01011a20 == 0) {
    iVar1 = GetLocaleInfoA(0,1,(LPSTR)0x0,0);
    if (iVar1 == 0) {
      iVar1 = GetLocaleInfoW(0,1,(LPWSTR)0x0,0);
      if (iVar1 == 0) {
        return 0;
      }
      DAT_01011a20 = 1;
    }
    else {
      DAT_01011a20 = 2;
    }
  }
  if (DAT_01011a20 != 2) {
    if (DAT_01011a20 != 1) {
      return DAT_01011a20;
    }
    if (param_5 == 0) {
      param_5 = DAT_01010cc8;
    }
    iVar1 = GetLocaleInfoW(param_1,param_2,(LPWSTR)0x0,0);
    if ((iVar1 != 0) && (lpLCData = (LPWSTR)FUN_01008440(iVar1 * 2), lpLCData != (LPWSTR)0x0)) {
      iVar1 = GetLocaleInfoW(param_1,param_2,lpLCData,iVar1);
      if (iVar1 != 0) {
        if (param_4 == 0) {
          iVar1 = WideCharToMultiByte(param_5,0x220,lpLCData,-1,(LPSTR)0x0,0,(LPCSTR)0x0,(LPBOOL)0x0
                                     );
        }
        else {
          iVar1 = WideCharToMultiByte(param_5,0x220,lpLCData,-1,param_3,param_4,(LPCSTR)0x0,
                                      (LPBOOL)0x0);
        }
        if (iVar1 != 0) {
          FUN_01008428(lpLCData);
          return iVar1;
        }
      }
      FUN_01008428(lpLCData);
    }
    return 0;
  }
  iVar1 = GetLocaleInfoA(param_1,param_2,param_3,param_4);
  return iVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __strcmpi
// 
// Libraries: Visual Studio 1998 Debug, Visual Studio 1998 Release

int __cdecl __strcmpi(char *_Str1,char *_Str2)

{
  char cVar1;
  char cVar2;
  bool bVar3;
  byte bVar4;
  byte bVar5;
  byte bVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  
  if (DAT_01010cb8 == 0) {
    bVar6 = 0xff;
    do {
      do {
        if (bVar6 == 0) goto LAB_0100a3ee;
        bVar6 = *_Str2;
        _Str2 = (char *)((byte *)_Str2 + 1);
        bVar5 = *_Str1;
        _Str1 = (char *)((byte *)_Str1 + 1);
      } while (bVar5 == bVar6);
      bVar4 = bVar6 + 0xbf + (-((byte)(bVar6 + 0xbf) < 0x1a) & 0x20U) + 0x41;
      bVar5 = bVar5 + 0xbf;
      bVar6 = bVar5 + (-(bVar5 < 0x1a) & 0x20U) + 0x41;
    } while (bVar6 == bVar4);
    bVar6 = (bVar6 < bVar4) * -2 + 1;
LAB_0100a3ee:
    uVar7 = (uint)(char)bVar6;
  }
  else {
    bVar3 = 0 < _DAT_01017724;
    if (bVar3) {
      FUN_010080e9(0x13);
    }
    else {
      _DAT_01017720 = _DAT_01017720 + 1;
    }
    uVar9 = (uint)bVar3;
    uVar7 = 0xff;
    uVar8 = 0;
    do {
      do {
        if ((char)uVar7 == '\0') goto LAB_0100a447;
        cVar1 = *_Str2;
        uVar7 = CONCAT31((int3)(uVar7 >> 8),cVar1);
        _Str2 = _Str2 + 1;
        cVar2 = *_Str1;
        uVar8 = CONCAT31((int3)(uVar8 >> 8),cVar2);
        _Str1 = _Str1 + 1;
      } while (cVar1 == cVar2);
      uVar8 = FUN_0100a5d4(uVar8);
      uVar7 = FUN_0100a5d4(uVar7);
    } while ((byte)uVar8 == (byte)uVar7);
    uVar8 = (uint)((byte)uVar8 < (byte)uVar7);
    uVar7 = (1 - uVar8) - (uint)(uVar8 != 0);
LAB_0100a447:
    if (uVar9 == 0) {
      _DAT_01017720 = _DAT_01017720 + -1;
    }
    else {
      FUN_0100814c(0x13);
    }
  }
  return uVar7;
}



undefined4 __cdecl FUN_0100a467(undefined **param_1)

{
  undefined4 uVar1;
  
  uVar1 = 0xffffffff;
  if ((*(byte *)(param_1 + 3) & 0x40) == 0) {
    FUN_0100815e(param_1);
    uVar1 = FUN_0100a4a3((int *)param_1);
    FUN_010081b6(param_1);
  }
  else {
    param_1[3] = (undefined *)0x0;
  }
  return uVar1;
}



undefined4 __cdecl FUN_0100a4a3(int *param_1)

{
  int iVar1;
  undefined4 uVar2;
  
  uVar2 = 0xffffffff;
  if ((*(byte *)(param_1 + 3) & 0x83) != 0) {
    uVar2 = FUN_01009ef6(param_1);
    FUN_0100a790(param_1);
    iVar1 = FUN_0100a6a3(param_1[4]);
    if (iVar1 < 0) {
      uVar2 = 0xffffffff;
    }
    else if ((LPVOID)param_1[7] != (LPVOID)0x0) {
      FUN_01008428((LPVOID)param_1[7]);
      param_1[7] = 0;
    }
  }
  param_1[3] = 0;
  return uVar2;
}



DWORD __cdecl FUN_0100a500(uint param_1)

{
  int *piVar1;
  HANDLE hFile;
  BOOL BVar2;
  DWORD *pDVar3;
  int iVar4;
  DWORD DVar5;
  
  if (DAT_0101772c <= param_1) {
LAB_0100a588:
    pDVar3 = FUN_01009cbb();
    *pDVar3 = 9;
    return 0xffffffff;
  }
  iVar4 = (param_1 & 0x1f) * 0x24;
  piVar1 = (int *)((int)&DAT_01017730 + ((int)(param_1 & 0xffffffe7) >> 3));
  if ((*(byte *)(*piVar1 + 4 + iVar4) & 1) == 0) goto LAB_0100a588;
  FUN_01009da0(param_1);
  if ((*(byte *)(*piVar1 + 4 + iVar4) & 1) != 0) {
    DVar5 = 0;
    hFile = (HANDLE)FUN_01009d59(param_1);
    BVar2 = FlushFileBuffers(hFile);
    if (BVar2 == 0) {
      DVar5 = GetLastError();
    }
    if (DVar5 == 0) goto LAB_0100a57b;
    pDVar3 = FUN_01009cc4();
    *pDVar3 = DVar5;
  }
  DVar5 = 0xffffffff;
  pDVar3 = FUN_01009cbb();
  *pDVar3 = 9;
LAB_0100a57b:
  FUN_01009e01(param_1);
  return DVar5;
}



uint __cdecl FUN_0100a5d4(uint param_1)

{
  ushort uVar1;
  undefined2 extraout_var;
  uint uVar2;
  int iVar3;
  WCHAR local_c [2];
  byte local_8;
  byte local_7;
  undefined local_6;
  
  if (DAT_01010cb8 == 0) {
    if ((0x40 < (int)param_1) && ((int)param_1 < 0x5b)) {
      param_1 = param_1 + 0x20;
    }
  }
  else {
    if ((int)param_1 < 0x100) {
      if (DAT_0101069c < 2) {
        uVar2 = *(ushort *)(PTR_DAT_01010490 + param_1 * 2) & 1;
      }
      else {
        uVar1 = FUN_01006038(param_1,1);
        uVar2 = CONCAT22(extraout_var,uVar1);
      }
      if (uVar2 == 0) {
        return param_1;
      }
    }
    local_8 = (byte)(param_1 >> 8);
    if ((PTR_DAT_01010490[(uint)local_8 * 2 + 1] & 0x80) == 0) {
      iVar3 = 1;
      local_7 = 0;
      local_8 = (byte)param_1;
    }
    else {
      iVar3 = 2;
      local_6 = 0;
      local_7 = (byte)param_1;
    }
    iVar3 = FUN_0100820e(DAT_01010cb8,0x100,(char *)&local_8,iVar3,local_c,3,0);
    if (iVar3 != 0) {
      if (iVar3 == 1) {
        param_1 = (uint)(byte)local_c[0];
      }
      else {
        param_1 = (uint)(ushort)local_c[0];
      }
    }
  }
  return param_1;
}



undefined4 __cdecl FUN_0100a6a3(uint param_1)

{
  undefined4 uVar1;
  DWORD *pDVar2;
  
  if ((param_1 < DAT_0101772c) &&
     ((*(byte *)(*(int *)((int)&DAT_01017730 + ((int)(param_1 & 0xffffffe7) >> 3)) + 4 +
                (param_1 & 0x1f) * 0x24) & 1) != 0)) {
    FUN_01009da0(param_1);
    uVar1 = FUN_0100a70c(param_1);
    FUN_01009e01(param_1);
  }
  else {
    pDVar2 = FUN_01009cbb();
    *pDVar2 = 9;
    pDVar2 = FUN_01009cc4();
    *pDVar2 = 0;
    uVar1 = 0xffffffff;
  }
  return uVar1;
}



undefined4 __cdecl FUN_0100a70c(uint param_1)

{
  int iVar1;
  int iVar2;
  HANDLE hObject;
  BOOL BVar3;
  undefined *puVar4;
  undefined4 uVar5;
  
  if ((param_1 == 1) || (param_1 == 2)) {
    iVar1 = FUN_01009d59(2);
    iVar2 = FUN_01009d59(1);
    if (iVar1 != iVar2) goto LAB_0100a736;
  }
  else {
LAB_0100a736:
    hObject = (HANDLE)FUN_01009d59(param_1);
    BVar3 = CloseHandle(hObject);
    if (BVar3 == 0) {
      puVar4 = (undefined *)GetLastError();
      goto LAB_0100a756;
    }
  }
  puVar4 = (undefined *)0x0;
LAB_0100a756:
  FUN_01009ccd(param_1);
  if (puVar4 == (undefined *)0x0) {
    uVar5 = 0;
    *(undefined *)
     (*(int *)((int)&DAT_01017730 + ((int)(param_1 & 0xffffffe7) >> 3)) + 4 +
     (param_1 & 0x1f) * 0x24) = 0;
  }
  else {
    FUN_01009c48(puVar4);
    uVar5 = 0xffffffff;
  }
  return uVar5;
}



void __cdecl FUN_0100a790(undefined4 *param_1)

{
  if (((param_1[3] & 0x83) != 0) && ((param_1[3] & 8) != 0)) {
    FUN_01008428((LPVOID)param_1[2]);
    *param_1 = 0;
    param_1[2] = 0;
    param_1[3] = param_1[3] & 0xfffffbf7;
    param_1[1] = 0;
  }
  return;
}



void __cdecl FUN_0100a7c0(char *param_1)

{
  size_t sVar1;
  char *_Dest;
  
  sVar1 = _strlen(param_1);
  _Dest = (char *)FUN_01008440(sVar1 + 1);
  if (_Dest != (char *)0x0) {
    FID_conflict___mbscpy(_Dest,param_1);
  }
  return;
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
    if (cVar1 == '\0') goto LAB_0100a843;
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
LAB_0100a843:
  return (size_t)((int)puVar3 + (-1 - (int)_Str));
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
    if (bVar1 == 0) goto LAB_0100a958;
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
LAB_0100a958:
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



void RtlUnwind(PVOID TargetFrame,PVOID TargetIp,PEXCEPTION_RECORD ExceptionRecord,PVOID ReturnValue)

{
                    // WARNING: Could not recover jumptable at 0x0100a960. Too many branches
                    // WARNING: Treating indirect jump as call
  RtlUnwind(TargetFrame,TargetIp,ExceptionRecord,ReturnValue);
  return;
}



undefined4 * __cdecl
FUN_0100a970(undefined *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,undefined4 param_7,undefined4 param_8,
            undefined4 *param_9)

{
  undefined4 *puVar1;
  
  puVar1 = (undefined4 *)(*(code *)param_1)(0x804);
  if (puVar1 == (undefined4 *)0x0) {
    FUN_0100bfe0(param_9,5,0);
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



undefined4 __cdecl FUN_0100aa10(undefined4 *param_1)

{
  FUN_0100bab0(0xf,param_1);
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



undefined4 __cdecl FUN_0100aa80(undefined4 *param_1,undefined4 param_2,undefined4 *param_3)

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
    FUN_0100bfe0((undefined4 *)*param_1,3,uStack_c & 0xffff);
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
FUN_0100ab40(int **param_1,char *param_2,char *param_3,undefined4 param_4,int *param_5,int *param_6,
            int *param_7)

{
  int **ppiVar1;
  char cVar2;
  short sVar3;
  ushort uVar4;
  bool bVar5;
  undefined3 extraout_var;
  int iVar6;
  int *piVar7;
  uint uVar8;
  uint uVar9;
  undefined4 *puVar10;
  char *pcVar11;
  char *pcVar12;
  undefined4 *puVar13;
  undefined4 local_4;
  
  local_4 = 0;
  ppiVar1 = param_1 + 0x1ef;
  param_1[0xe] = param_7;
  param_1[9] = param_5;
  uVar8 = 0xffffffff;
  param_1[10] = param_6;
  *(undefined2 *)((int)param_1 + 0xae) = 0;
  pcVar12 = param_3;
  do {
    pcVar11 = pcVar12;
    if (uVar8 == 0) break;
    uVar8 = uVar8 - 1;
    pcVar11 = pcVar12 + 1;
    cVar2 = *pcVar12;
    pcVar12 = pcVar11;
  } while (cVar2 != '\0');
  uVar8 = ~uVar8;
  puVar10 = (undefined4 *)(pcVar11 + -uVar8);
  puVar13 = (undefined4 *)((int)param_1 + 0x5b9);
  for (uVar9 = uVar8 >> 2; uVar9 != 0; uVar9 = uVar9 - 1) {
    *puVar13 = *puVar10;
    puVar10 = puVar10 + 1;
    puVar13 = puVar13 + 1;
  }
  for (uVar8 = uVar8 & 3; uVar8 != 0; uVar8 = uVar8 - 1) {
    *(undefined *)puVar13 = *(undefined *)puVar10;
    puVar10 = (undefined4 *)((int)puVar10 + 1);
    puVar13 = (undefined4 *)((int)puVar13 + 1);
  }
  bVar5 = FUN_0100adb0(param_1,param_2,0,-1);
  if (CONCAT31(extraout_var,bVar5) != 0) {
    uVar8 = 0xffffffff;
    param_1[0x27] = (int *)0x0;
    param_1[0x24] = (int *)0xffff;
    do {
      pcVar12 = param_3;
      if (uVar8 == 0) break;
      uVar8 = uVar8 - 1;
      pcVar12 = param_3 + 1;
      cVar2 = *param_3;
      param_3 = pcVar12;
    } while (cVar2 != '\0');
    uVar8 = ~uVar8;
    puVar10 = (undefined4 *)(pcVar12 + -uVar8);
    puVar13 = (undefined4 *)((int)param_1 + 0x5b9);
    for (uVar9 = uVar8 >> 2; uVar9 != 0; uVar9 = uVar9 - 1) {
      *puVar13 = *puVar10;
      puVar10 = puVar10 + 1;
      puVar13 = puVar13 + 1;
    }
    for (uVar8 = uVar8 & 3; uVar8 != 0; uVar8 = uVar8 - 1) {
      *(undefined *)puVar13 = *(undefined *)puVar10;
      puVar10 = (undefined4 *)((int)puVar10 + 1);
      puVar13 = (undefined4 *)((int)puVar13 + 1);
    }
    sVar3 = *(short *)(param_1 + 0x2b);
    *(short *)(param_1 + 0x2b) = sVar3 + -1;
    while (sVar3 != 0) {
      iVar6 = FUN_0100b830(param_1);
      if (iVar6 == 0) goto LAB_0100ad49;
      param_1[0x1f0] = (int *)(param_1 + 0x2d);
      *ppiVar1 = param_1[0x1d];
      param_1[0x1f1] = (int *)((int)param_1 + 0x1b5);
      param_1[0x1f2] = (int *)((int)param_1 + 0x2b6);
      *(undefined2 *)(param_1 + 0x1f5) = *(undefined2 *)((int)param_1 + 0x7e);
      *(undefined2 *)((int)param_1 + 0x7d6) = *(undefined2 *)(param_1 + 0x20);
      *(undefined2 *)(param_1 + 0x1f6) = *(undefined2 *)((int)param_1 + 0x82);
      param_1[499] = param_1[0xe];
      if ((*(ushort *)(param_1 + 0x1f) & 0xfffd) == 0xfffd) {
        if (param_1[0x27] == (int *)0x0) {
          iVar6 = (*(code *)param_5)(1,ppiVar1);
          if (iVar6 == -1) {
            FUN_0100bfe0(*param_1,0xb,0);
            goto LAB_0100ad49;
          }
        }
        else {
          piVar7 = (int *)(*(code *)param_5)(2);
          param_1[0x23] = piVar7;
          if (piVar7 == (int *)0xffffffff) {
            FUN_0100bfe0(*param_1,0xb,0);
            goto LAB_0100ad49;
          }
          if (piVar7 != (int *)0x0) {
            iVar6 = FUN_0100b1f0(param_1);
            goto joined_r0x0100ad0e;
          }
          uVar4 = *(ushort *)(param_1 + 0x1f);
joined_r0x0100ad1e:
          if ((uVar4 & 0xfffe) == 0xfffe) {
            *(short *)((int)param_1 + 0xae) = *(short *)((int)param_1 + 0xae) + 1;
          }
        }
      }
      else if (param_1[0x27] == (int *)0x0) {
        piVar7 = (int *)(*(code *)param_5)(2,ppiVar1);
        param_1[0x23] = piVar7;
        if (piVar7 == (int *)0xffffffff) {
          FUN_0100bfe0(*param_1,0xb,0);
          goto LAB_0100ad49;
        }
        if (piVar7 == (int *)0x0) {
          uVar4 = *(ushort *)(param_1 + 0x1f);
          goto joined_r0x0100ad1e;
        }
        iVar6 = FUN_0100b1f0(param_1);
joined_r0x0100ad0e:
        if (iVar6 == 0) goto LAB_0100ad49;
      }
      sVar3 = *(short *)(param_1 + 0x2b);
      *(short *)(param_1 + 0x2b) = sVar3 + -1;
    }
    local_4 = 1;
  }
LAB_0100ad49:
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



bool __cdecl FUN_0100adb0(undefined4 *param_1,char *param_2,short param_3,short param_4)

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
        FUN_0100bfe0((undefined4 *)*param_1,2,0);
        return false;
      }
      if (aiStack_24[0] != 0x4643534d) {
        FUN_0100bfe0((undefined4 *)*param_1,2,0);
        return false;
      }
      if ((short)uStack_c != 0x103) {
        FUN_0100bfe0((undefined4 *)*param_1,3,uStack_c & 0xffff);
        return false;
      }
      if ((param_4 != -1) && ((sStack_4 != param_3 || (sStack_2 != param_4)))) {
        FUN_0100bfe0((undefined4 *)*param_1,10,0);
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
          FUN_0100bfe0((undefined4 *)*param_1,2,0);
          return false;
        }
        if (param_1[0x28] == 0xffff) {
          uVar4 = uStack_28 & 0xffff;
          param_1[0x28] = uVar4;
          if (uVar4 != 0) {
            iVar6 = (*(code *)param_1[2])(uVar4);
            param_1[0x13] = iVar6;
            if (iVar6 == 0) {
              FUN_0100bfe0((undefined4 *)*param_1,5,0);
              return false;
            }
          }
        }
        iVar6 = param_1[0x28];
        if ((iVar6 != 0) &&
           (iVar3 = (*(code *)param_1[4])(param_1[0x22],param_1[0x13],iVar6), iVar3 != iVar6)) {
          FUN_0100bfe0((undefined4 *)*param_1,2,0);
          return false;
        }
      }
      iVar6 = (uStack_28 >> 0x10 & 0xff) + 8;
      if (param_1[0x11] == 0) {
        param_1[0x29] = iVar6;
        iVar6 = (*(code *)param_1[2])(iVar6);
        param_1[0x11] = iVar6;
        if (iVar6 == 0) {
          FUN_0100bfe0((undefined4 *)*param_1,5,0);
          return false;
        }
      }
      else if (param_1[0x29] != iVar6) {
        FUN_0100bfe0((undefined4 *)*param_1,9,0);
        return false;
      }
      iVar6 = (uStack_28 >> 0x18) + 8;
      if (param_1[0x12] == 0) {
        param_1[0x2a] = iVar6;
        iVar6 = (*(code *)param_1[2])(iVar6);
        param_1[0x12] = iVar6;
        if (iVar6 == 0) {
          FUN_0100bfe0((undefined4 *)*param_1,5,0);
          return false;
        }
      }
      else if (param_1[0x2a] != iVar6) {
        FUN_0100bfe0((undefined4 *)*param_1,9,0);
        return false;
      }
      if ((*(byte *)((int)param_1 + 0x6e) & 1) == 0) {
        *(undefined *)((int)param_1 + 0x1b5) = 0;
        *(undefined *)((int)param_1 + 0x2b6) = 0;
      }
      else {
        iVar6 = FUN_0100b9f0((char *)((int)param_1 + 0x1b5),0x100,param_1);
        if (iVar6 == 0) {
          return false;
        }
        iVar6 = FUN_0100b9f0((char *)((int)param_1 + 0x2b6),0x100,param_1);
        if (iVar6 == 0) {
          return false;
        }
      }
      if ((*(byte *)((int)param_1 + 0x6e) & 2) == 0) {
        *(undefined *)((int)param_1 + 0x3b7) = 0;
        *(undefined *)(param_1 + 0x12e) = 0;
      }
      else {
        iVar6 = FUN_0100b9f0((char *)((int)param_1 + 0x3b7),0x100,param_1);
        if ((iVar6 == 0) ||
           (iVar6 = FUN_0100b9f0((char *)(param_1 + 0x12e),0x100,param_1), iVar6 == 0)) {
          return false;
        }
      }
      iVar6 = (*(code *)param_1[7])(param_1[0x22],0,1);
      param_1[0xb] = iVar6;
      if (iVar6 == -1) {
        FUN_0100bfe0((undefined4 *)*param_1,4,0);
        return false;
      }
      iVar6 = (*(code *)param_1[7])(param_1[0x22],param_1[0x18]);
      if (iVar6 != -1) {
        *(undefined2 *)(param_1 + 0x2b) = *(undefined2 *)(param_1 + 0x1b);
        iVar6 = FUN_0100b5d0(param_1);
        return (bool)('\x01' - (iVar6 == 0));
      }
      FUN_0100bfe0((undefined4 *)*param_1,4,0);
      return false;
    }
  }
  FUN_0100bfe0((undefined4 *)*param_1,1,0);
  return false;
}



undefined4 __cdecl FUN_0100b1f0(int **param_1)

{
  int **ppiVar1;
  int iVar2;
  int *piVar3;
  int *piVar4;
  int *piVar5;
  int *piVar6;
  
  iVar2 = FUN_0100b690(param_1,(int *)(uint)*(ushort *)(param_1 + 0x1f));
  if (iVar2 != 0) {
    piVar6 = param_1[0x1e];
    piVar4 = param_1[0x1d];
    if (piVar4 == (int *)0x0) {
LAB_0100b2b2:
      ppiVar1 = param_1 + 0x1ef;
      param_1[0x1f0] = (int *)(param_1 + 0x2d);
      param_1[500] = param_1[0x23];
      *(undefined2 *)(param_1 + 0x1f5) = *(undefined2 *)((int)param_1 + 0x7e);
      *(undefined2 *)((int)param_1 + 0x7d6) = *(undefined2 *)(param_1 + 0x20);
      *(undefined2 *)(param_1 + 0x1f6) = *(undefined2 *)((int)param_1 + 0x82);
      param_1[499] = param_1[0xe];
      *ppiVar1 = (int *)0x0;
      if ((*(byte *)(param_1 + 0x1f6) & 0x40) != 0) {
        *ppiVar1 = (int *)0x1;
        *(ushort *)(param_1 + 0x1f6) = *(ushort *)(param_1 + 0x1f6) & 0xffbf;
      }
      iVar2 = (*(code *)param_1[9])(3,ppiVar1);
      if (iVar2 != -1) {
        param_1[0x23] = (int *)0xffffffff;
        if (iVar2 != 0) {
          return 1;
        }
        FUN_0100bfe0(*param_1,8,0);
        return 0;
      }
      FUN_0100bfe0(*param_1,0xb,0);
    }
    else {
      do {
        if (piVar6 < (int *)((uint)*(ushort *)((int)param_1[0x12] + 6) + (int)param_1[0xc]))
        goto LAB_0100b25a;
        iVar2 = FUN_0100b360(param_1);
      } while (iVar2 != 0);
    }
  }
  goto LAB_0100b237;
  while( true ) {
    piVar6 = (int *)((int)piVar6 + (int)piVar5);
    piVar4 = (int *)((int)piVar4 - (int)piVar5);
    if ((piVar4 != (int *)0x0) && (iVar2 = FUN_0100b360(param_1), iVar2 == 0)) break;
LAB_0100b25a:
    if (piVar4 == (int *)0x0) goto LAB_0100b2b2;
    piVar5 = (int *)((uint)*(ushort *)((int)param_1[0x12] + 6) - ((int)piVar6 - (int)param_1[0xc]));
    if (piVar4 < piVar5) {
      piVar5 = piVar4;
    }
    piVar3 = (int *)(*(code *)param_1[5])
                              (param_1[0x23],(int)param_1[0x10] + ((int)piVar6 - (int)param_1[0xc]),
                               piVar5);
    if (piVar3 != piVar5) {
      FUN_0100bfe0(*param_1,8,0);
      break;
    }
  }
LAB_0100b237:
  if (param_1[0x23] != (int *)0xffffffff) {
    (*(code *)param_1[6])(param_1[0x23]);
    param_1[0x23] = (int *)0xffffffff;
  }
  return 0;
}



undefined4 __cdecl FUN_0100b360(int **param_1)

{
  int iVar1;
  ushort local_2;
  
  param_1[0xc] = (int *)((int)param_1[0xc] + (uint)*(ushort *)((int)param_1[0x12] + 6));
  if (*(short *)(param_1 + 0x2c) == 0) {
    iVar1 = FUN_0100b440(param_1);
    if (iVar1 == 0) {
      return 0;
    }
  }
  *(short *)(param_1 + 0x2c) = *(short *)(param_1 + 0x2c) + -1;
  iVar1 = FUN_0100b880(param_1,0);
  if (iVar1 == 0) {
    return 0;
  }
  if (*(short *)((int)param_1[0x12] + 6) == 0) {
    iVar1 = FUN_0100b440(param_1);
    if (iVar1 != 0) {
      iVar1 = FUN_0100b880(param_1,(uint)*(ushort *)(param_1[0x12] + 1));
      if (iVar1 != 0) goto LAB_0100b3e4;
    }
    return 0;
  }
LAB_0100b3e4:
  local_2 = *(ushort *)((int)param_1[0x12] + 6);
  iVar1 = FUN_0100bec0(param_1,&local_2);
  if (iVar1 == 0) {
    return 0;
  }
  if (*(ushort *)((int)param_1[0x12] + 6) != local_2) {
    FUN_0100bfe0(*param_1,7,0);
    return 0;
  }
  return 1;
}



undefined4 __cdecl FUN_0100b440(int **param_1)

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
      if (iVar4 != 0) goto LAB_0100b573;
    }
    if (param_1[0x22] != (int *)0xffffffff) {
      iVar4 = (*(code *)param_1[6])(param_1[0x22]);
      if (iVar4 != 0) {
LAB_0100b573:
        FUN_0100bfe0(*param_1,4,0);
        return 0;
      }
    }
    param_1[0x22] = (int *)0xffffffff;
    param_1[0x21] = (int *)0xffffffff;
    iVar4 = (*(code *)param_1[9])(4,param_1 + 0x1ef);
    if (iVar4 == -1) {
      FUN_0100bfe0(*param_1,0xb,0);
      return 0;
    }
    bVar3 = FUN_0100adb0(param_1,(char *)((int)param_1 + 0x3b7),sVar1,sVar5);
    if (CONCAT31(extraout_var,bVar3) == 0) {
LAB_0100b51a:
      if (**param_1 == 0xb) {
        return 0;
      }
      bVar2 = true;
    }
    else {
      iVar4 = FUN_0100b710(param_1,0);
      if (iVar4 == 0) goto LAB_0100b51a;
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
        iVar4 = FUN_0100b830(param_1);
      } while (iVar4 != 0);
      return 0;
    }
  } while( true );
}



undefined4 __cdecl FUN_0100b5d0(undefined4 *param_1)

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
    FUN_0100bfe0((undefined4 *)*param_1,0xb,0);
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
      FUN_0100bfe0((undefined4 *)*param_1,0xb,0);
      return 0;
    }
  }
  return 1;
}



undefined4 __cdecl FUN_0100b690(int **param_1,int *param_2)

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
  iVar1 = FUN_0100be10(param_1);
  if ((iVar1 != 0) && (iVar1 = FUN_0100b710(param_1,(int)param_2), iVar1 != 0)) {
    iVar1 = FUN_0100b360(param_1);
    if (iVar1 != 0) {
      param_1[0xc] = (int *)0x0;
      return 1;
    }
    return 0;
  }
  return 0;
}



undefined4 __cdecl FUN_0100b710(undefined4 *param_1,int param_2)

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
        bVar1 = FUN_0100bab0(*(short *)(param_1[0x11] + 6),param_1);
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
            FUN_0100bfe0((undefined4 *)*param_1,0xb,0);
            return 0;
          }
        }
        return 1;
      }
    }
  }
  FUN_0100bfe0((undefined4 *)*param_1,4,0);
  return 0;
}



undefined4 __cdecl FUN_0100b830(undefined4 *param_1)

{
  int iVar1;
  
  iVar1 = (*(code *)param_1[4])(param_1[0x22],param_1 + 0x1d,0x10);
  if (iVar1 == 0x10) {
    iVar1 = FUN_0100b9f0((char *)(param_1 + 0x2d),0x100,param_1);
    if (iVar1 != 0) {
      return 1;
    }
  }
  FUN_0100bfe0((undefined4 *)*param_1,4,0);
  return 0;
}



undefined4 __cdecl FUN_0100b880(undefined4 *param_1,int param_2)

{
  short sVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  undefined4 uVar6;
  uint *puVar7;
  
  iVar5 = param_1[0x2a];
  iVar2 = (*(code *)param_1[4])(param_1[0x21],param_1[0x12],iVar5);
  if (iVar2 == iVar5) {
    uVar4 = (uint)*(ushort *)(param_1[0x12] + 4);
    if (param_2 + uVar4 < (uint)param_1[0x26] || param_2 + uVar4 == param_1[0x26]) {
      uVar3 = (*(code *)param_1[4])(param_1[0x21],param_1[0xf] + param_2,uVar4);
      if (uVar3 == uVar4) {
        if (*(int *)param_1[0x12] != 0) {
          puVar7 = (uint *)((int *)param_1[0x12] + 1);
          uVar4 = FUN_0100c000((uint *)(param_1[0xf] + param_2),(uint)*(ushort *)puVar7,0);
          uVar4 = FUN_0100c000(puVar7,param_1[0x2a] - 4,uVar4);
          if (*(uint *)param_1[0x12] != uVar4) {
            FUN_0100bfe0((undefined4 *)*param_1,4,0);
            return 0;
          }
        }
        *(short *)(param_1[0x12] + 4) = *(short *)(param_1[0x12] + 4) + (short)param_2;
        if ((param_2 != 0) || (uVar6 = 0, *(short *)(param_1[0x12] + 6) == 0)) {
          uVar6 = 1;
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
          param_1[0x1ff] = uVar6;
          *(short *)(param_1 + 0x200) = (short)param_2;
          iVar5 = (*(code *)param_1[10])(param_1 + 0x1f9);
          if (iVar5 == -1) {
            FUN_0100bfe0((undefined4 *)*param_1,0xb,0);
            return 0;
          }
        }
        return 1;
      }
    }
  }
  FUN_0100bfe0((undefined4 *)*param_1,4,0);
  return 0;
}



undefined4 __cdecl FUN_0100b9f0(char *param_1,int param_2,undefined4 *param_3)

{
  char cVar1;
  char cVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  
  iVar3 = (*(code *)param_3[7])(param_3[0x22],0,1);
  iVar4 = (*(code *)param_3[4])(param_3[0x22],param_1,param_2);
  if (iVar4 < 1) {
    FUN_0100bfe0((undefined4 *)*param_3,4,0);
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
    FUN_0100bfe0((undefined4 *)*param_3,4,0);
    return 0;
  }
  iVar3 = (*(code *)param_3[7])(param_3[0x22],~uVar5 + iVar3,0);
  if (iVar3 == -1) {
    FUN_0100bfe0((undefined4 *)*param_3,4,0);
    return 0;
  }
  return 1;
}



bool __cdecl FUN_0100bab0(short param_1,undefined4 *param_2)

{
  int iVar1;
  
  if (*(short *)((int)param_2 + 0xb2) == param_1) {
    return true;
  }
  iVar1 = FUN_0100bb10(param_2);
  if (iVar1 == 0) {
    FUN_0100bfe0((undefined4 *)*param_2,7,0);
    return false;
  }
  *(short *)((int)param_2 + 0xb2) = param_1;
  iVar1 = FUN_0100bbe0(param_2);
  return (bool)('\x01' - (iVar1 == 0));
}



undefined4 __cdecl FUN_0100bb10(undefined4 *param_1)

{
  int iVar1;
  
  switch(*(ushort *)((int)param_1 + 0xb2) & 0xf) {
  case 0:
    break;
  case 1:
    iVar1 = FUN_0100c350((int *)param_1[0xd]);
    if (iVar1 != 0) {
      FUN_0100bfe0((undefined4 *)*param_1,7,0);
      return 0;
    }
    break;
  case 2:
    iVar1 = FUN_0100c1f0((int *)param_1[0xd]);
    if (iVar1 != 0) {
      FUN_0100bfe0((undefined4 *)*param_1,7,0);
      return 0;
    }
    break;
  default:
    FUN_0100bfe0((undefined4 *)*param_1,6,0);
    return 0;
  case 0xf:
    return 1;
  }
  (*(code *)param_1[1])(param_1[0xf]);
  (*(code *)param_1[1])(param_1[0x10]);
  return 1;
}



undefined4 __cdecl FUN_0100bbe0(undefined4 *param_1)

{
  uint *puVar1;
  int *piVar2;
  ushort uVar3;
  int iVar4;
  int iVar5;
  uint local_8;
  undefined4 local_4;
  
  iVar5 = 0;
  puVar1 = param_1 + 0x25;
  *puVar1 = 0x8000;
  switch(*(ushort *)((int)param_1 + 0xb2) & 0xf) {
  case 0:
    param_1[0x26] = 0x8000;
    break;
  case 1:
    iVar4 = FUN_0100c260(puVar1,(undefined *)0x0,0,param_1 + 0x26,(undefined4 *)0x0);
    goto joined_r0x0100bc87;
  case 2:
    local_4 = param_1[8];
    local_8 = (uint)((*(ushort *)((int)param_1 + 0xb2) & 0x1f00) >> 8);
    iVar4 = FUN_0100c080(puVar1,(int *)&local_8,(undefined *)0x0,(undefined *)0x0,param_1 + 0x26,
                         (undefined4 *)0x0,0,0,0,0,0);
joined_r0x0100bc87:
    if (iVar4 != 0) {
      iVar5 = 7;
    }
    break;
  default:
    iVar5 = 6;
    break;
  case 0xf:
    return 1;
  }
  if (iVar5 != 0) {
    FUN_0100bfe0((undefined4 *)*param_1,iVar5,0);
    *(undefined2 *)((int)param_1 + 0xb2) = 0xf;
    return 0;
  }
  piVar2 = param_1 + 0x26;
  iVar5 = (*(code *)param_1[2])(*piVar2);
  param_1[0xf] = iVar5;
  if (iVar5 == 0) {
    FUN_0100bfe0((undefined4 *)*param_1,5,0);
    *(undefined2 *)((int)param_1 + 0xb2) = 0xf;
    return 0;
  }
  iVar5 = (*(code *)param_1[2])(*puVar1);
  param_1[0x10] = iVar5;
  if (iVar5 == 0) {
    (*(code *)param_1[1])(param_1[0xf]);
    FUN_0100bfe0((undefined4 *)*param_1,5,0);
    *(undefined2 *)((int)param_1 + 0xb2) = 0xf;
    return 0;
  }
  uVar3 = *(ushort *)((int)param_1 + 0xb2) & 0xf;
  iVar5 = 0;
  if (uVar3 == 1) {
    iVar4 = FUN_0100c260(puVar1,(undefined *)param_1[2],param_1[1],piVar2,param_1 + 0xd);
  }
  else {
    if (uVar3 != 2) goto LAB_0100bd99;
    iVar4 = FUN_0100c080(puVar1,(int *)&local_8,(undefined *)param_1[2],(undefined *)param_1[1],
                         piVar2,param_1 + 0xd,param_1[3],param_1[4],param_1[5],param_1[6],param_1[7]
                        );
  }
  if (iVar4 != 0) {
    iVar5 = (-(uint)(iVar4 == 1) & 0xfffffffe) + 7;
  }
LAB_0100bd99:
  if (iVar5 != 0) {
    (*(code *)param_1[1])(param_1[0xf]);
    (*(code *)param_1[1])(param_1[0x10]);
    FUN_0100bfe0((undefined4 *)*param_1,iVar5,0);
    *(undefined2 *)((int)param_1 + 0xb2) = 0xf;
    return 0;
  }
  return 1;
}



undefined4 __cdecl FUN_0100be10(undefined4 *param_1)

{
  byte bVar1;
  undefined3 extraout_var;
  int iVar2;
  
  switch(*(ushort *)((int)param_1 + 0xb2) & 0xf) {
  case 0:
  case 0xf:
    break;
  case 1:
    bVar1 = FUN_0100c330((int *)param_1[0xd]);
    if (CONCAT31(extraout_var,bVar1) != 0) {
      FUN_0100bfe0((undefined4 *)*param_1,7,0);
      return 0;
    }
    break;
  case 2:
    iVar2 = FUN_0100c1d0((int *)param_1[0xd]);
    if (iVar2 != 0) {
      FUN_0100bfe0((undefined4 *)*param_1,7,0);
      return 0;
    }
    break;
  default:
    FUN_0100bfe0((undefined4 *)*param_1,6,0);
    return 0;
  }
  return 1;
}



undefined4 __cdecl FUN_0100bec0(undefined4 *param_1,ushort *param_2)

{
  byte bVar1;
  ushort uVar2;
  undefined3 extraout_var;
  undefined3 extraout_var_00;
  uint uVar3;
  undefined *puVar4;
  undefined *puVar5;
  uint local_4;
  
  uVar2 = *(ushort *)((int)param_1 + 0xb2) & 0xf;
  if ((*(ushort *)((int)param_1 + 0xb2) & 0xf) == 0) {
    uVar2 = *(ushort *)(param_1[0x12] + 4);
    *param_2 = uVar2;
    puVar4 = (undefined *)param_1[0xf];
    puVar5 = (undefined *)param_1[0x10];
    for (uVar3 = (uint)uVar2; uVar3 != 0; uVar3 = uVar3 - 1) {
      *puVar5 = *puVar4;
      puVar4 = puVar4 + 1;
      puVar5 = puVar5 + 1;
    }
    return 1;
  }
  if (uVar2 == 1) {
    local_4 = param_1[0x25];
    bVar1 = FUN_0100c2d0((int *)param_1[0xd],(short *)param_1[0xf],
                         (uint)*(ushort *)(param_1[0x12] + 4),param_1[0x10],&local_4);
    if (CONCAT31(extraout_var,bVar1) != 0) {
      FUN_0100bfe0((undefined4 *)*param_1,7,0);
      return 0;
    }
    *param_2 = (ushort)local_4;
    return 1;
  }
  if (uVar2 != 2) {
    FUN_0100bfe0((undefined4 *)*param_1,6,0);
    return 0;
  }
  local_4 = (uint)*param_2;
  bVar1 = FUN_0100c170((int *)param_1[0xd],param_1[0xf],(uint)*(ushort *)(param_1[0x12] + 4),
                       param_1[0x10],&local_4);
  if (CONCAT31(extraout_var_00,bVar1) != 0) {
    FUN_0100bfe0((undefined4 *)*param_1,7,0);
    return 0;
  }
  *param_2 = (ushort)local_4;
  return 1;
}



void __cdecl FUN_0100bfe0(undefined4 *param_1,undefined4 param_2,undefined4 param_3)

{
  *param_1 = param_2;
  param_1[2] = 1;
  param_1[1] = param_3;
  return;
}



uint __cdecl FUN_0100c000(uint *param_1,uint param_2,uint param_3)

{
  byte bVar1;
  uint uVar2;
  uint *puVar3;
  uint uVar4;
  
  uVar2 = param_2 >> 2;
  puVar3 = param_1;
  if (uVar2 != 0) {
    do {
      uVar2 = uVar2 - 1;
      param_1 = puVar3 + 1;
      param_3 = param_3 ^ *puVar3;
      puVar3 = param_1;
    } while (0 < (int)uVar2);
  }
  uVar2 = 0;
  uVar4 = param_2 & 3;
  if (uVar4 != 1) {
    if (uVar4 != 2) {
      if (uVar4 != 3) goto LAB_0100c075;
      bVar1 = *(byte *)param_1;
      param_1 = (uint *)((int)param_1 + 1);
      uVar2 = (uint)bVar1 << 0x10;
    }
    bVar1 = *(byte *)param_1;
    param_1 = (uint *)((int)param_1 + 1);
    uVar2 = uVar2 | (uint)bVar1 << 8;
  }
  uVar2 = uVar2 | *(byte *)param_1;
LAB_0100c075:
  return param_3 ^ uVar2;
}



undefined4 __cdecl
FUN_0100c080(uint *param_1,int *param_2,undefined *param_3,undefined *param_4,int *param_5,
            undefined4 *param_6,undefined4 param_7,undefined4 param_8,undefined4 param_9,
            undefined4 param_10,undefined4 param_11)

{
  undefined4 *puVar1;
  int iVar2;
  
  if ((*param_2 < 10) || (0x15 < *param_2)) {
    return 5;
  }
  if ((*param_1 == 0) || (0x8000 < *param_1)) {
    *param_1 = 0x8000;
  }
  *param_5 = *param_1 + 0x2800;
  if (param_6 == (undefined4 *)0x0) {
    return 0;
  }
  *param_6 = 0;
  puVar1 = (undefined4 *)(*(code *)param_3)(0x28);
  if (puVar1 == (undefined4 *)0x0) {
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
  *puVar1 = 0x43494451;
  DAT_01018c38 = puVar1;
  iVar2 = FUN_0100c380((byte)*param_2);
  if (iVar2 != 0) {
    (*(code *)param_4)(puVar1);
    return 1;
  }
  *param_6 = puVar1;
  return 0;
}



byte __cdecl
FUN_0100c170(int *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,uint *param_5)

{
  uint uVar1;
  
  if (*param_1 != 0x43494451) {
    return 2;
  }
  DAT_01018c38 = param_1;
  if ((uint)param_1[8] < *param_5) {
    return 3;
  }
  uVar1 = FUN_0100c540(param_2,param_3,param_4,(short)*param_5);
  return ((uVar1 & 0xffff) == 0) - 1U & 4;
}



undefined4 __cdecl FUN_0100c1d0(int *param_1)

{
  if (*param_1 != 0x43494451) {
    return 2;
  }
  DAT_01018c38 = param_1;
  FUN_0100c600();
  return 0;
}



undefined4 __cdecl FUN_0100c1f0(int *param_1)

{
  if (*param_1 != 0x43494451) {
    return 2;
  }
  DAT_01018c38 = param_1;
  FUN_0100c5d0();
  *param_1 = 0;
  (*(code *)param_1[2])(param_1);
  return 0;
}



void __cdecl FUN_0100c220(undefined4 param_1)

{
  (**(code **)(DAT_01018c38 + 4))(param_1);
  return;
}



void __cdecl FUN_0100c240(undefined4 param_1)

{
  (**(code **)(DAT_01018c38 + 8))(param_1);
  return;
}



undefined4 __cdecl
FUN_0100c260(uint *param_1,undefined *param_2,undefined4 param_3,int *param_4,undefined4 *param_5)

{
  undefined4 *puVar1;
  
  if ((*param_1 == 0) || (0x8000 < *param_1)) {
    *param_1 = 0x8000;
  }
  *param_4 = *param_1 + 0xc;
  if (param_5 == (undefined4 *)0x0) {
    return 0;
  }
  *param_5 = 0;
  puVar1 = (undefined4 *)(*(code *)param_2)(0xc);
  if (puVar1 == (undefined4 *)0x0) {
    return 1;
  }
  puVar1[1] = param_3;
  puVar1[2] = *param_1;
  *puVar1 = 0x4349444d;
  *param_5 = puVar1;
  return 0;
}



byte __cdecl FUN_0100c2d0(int *param_1,short *param_2,uint param_3,undefined4 param_4,uint *param_5)

{
  int iVar1;
  
  if (*param_1 != 0x4349444d) {
    return 2;
  }
  if (param_1[2] + 0xcU < param_3) {
    return 3;
  }
  iVar1 = FUN_0100e080(param_2,param_3,param_4,param_1[2]);
  if (iVar1 == 0) {
    iVar1 = FUN_0100e110(param_5);
  }
  return (iVar1 == 0) - 1U & 4;
}



byte __cdecl FUN_0100c330(int *param_1)

{
  return (*param_1 == 0x4349444d) - 1U & 2;
}



undefined4 __cdecl FUN_0100c350(int *param_1)

{
  if (*param_1 != 0x4349444d) {
    return 2;
  }
  *param_1 = 0;
  (*(code *)param_1[1])(param_1);
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 __cdecl FUN_0100c380(byte param_1)

{
  int iVar1;
  
  DAT_01018c0c = 0;
  _DAT_01018c28 = 0;
  DAT_01018c24 = param_1;
  DAT_01018c14 = 1 << (param_1 & 0x1f);
  _DAT_01018c10 = DAT_01018c14 + -1;
  DAT_01018c00 = FUN_0100c220(DAT_01018c14);
  if (DAT_01018c00 == 0) {
    iVar1 = FUN_0100c640();
    if (iVar1 == 0) {
      return 1;
    }
    DAT_01018c34 = &LAB_0100c7f0;
    DAT_01018bf8 = &LAB_0100c9a0;
  }
  else {
    DAT_01018c34 = &LAB_0100c430;
    DAT_01018bf8 = &LAB_0100c4f0;
    _DAT_01018c04 = DAT_01018c14 + DAT_01018c00;
    DAT_01018c08 = DAT_01018c00;
  }
  FUN_0100e1e0(param_1);
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int __cdecl FUN_0100c540(undefined4 param_1,undefined4 param_2,undefined4 param_3,short param_4)

{
  ushort extraout_var;
  
  DAT_01018c18 = param_4;
  DAT_01018c1c = param_3;
  _DAT_01018c20 = 0;
  DAT_01018c2c = param_1;
  _DAT_01018c30 = param_2;
  _DAT_01018bf4 = 0;
  FUN_0100eac0();
  while ((DAT_01018c18 != 0 && (_DAT_01018bf4 == 0))) {
    FUN_0100e4a0();
  }
  FUN_0100ec40();
  if (((_DAT_01018bf4 == 0) && (_DAT_01018c20 == 0)) && (_DAT_01018c28 == 0)) {
    return (uint)extraout_var << 0x10;
  }
  return CONCAT22(extraout_var,1);
}



void FUN_0100c5d0(void)

{
  if (DAT_01018c00 == 0) {
    FUN_0100cbe0();
    FUN_0100e3b0();
    return;
  }
  FUN_0100c240(DAT_01018c00);
  FUN_0100e3b0();
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0100c600(void)

{
  FUN_0100e3b0();
  DAT_01018c0c = 0;
  DAT_01018c08 = DAT_01018c00;
  _DAT_01018c28 = 0;
  if (DAT_01018c00 == 0) {
    FUN_0100c770();
  }
  FUN_0100e1e0(DAT_01018c24);
  return;
}



undefined4 FUN_0100c640(void)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  int iVar3;
  undefined local_8;
  undefined local_7;
  int local_6;
  
  if (*(code **)(DAT_01018c38 + 0xc) == (code *)0x0) {
    return 0;
  }
  local_6 = DAT_01018c14;
  local_8 = 0x2a;
  local_7 = 0;
  DAT_01012758 = (**(code **)(DAT_01018c38 + 0xc))(&local_8,0x8102,0x180);
  if (DAT_01012758 == -1) {
    return 0;
  }
  DAT_01012768 = (int)(DAT_01018c14 + (DAT_01018c14 >> 0x1f & 0xfffU)) >> 0xc;
  if (DAT_01012768 < 3) {
    DAT_01012768 = 3;
  }
  DAT_01012774 = FUN_0100c220(DAT_01012768 << 3);
  if (DAT_01012774 == 0) {
    (**(code **)(DAT_01018c38 + 0x18))(DAT_01012758);
    return 0;
  }
  iVar3 = 0;
  DAT_0101276c = (undefined4 *)0x0;
  if (0 < DAT_01012768) {
    do {
      puVar2 = (undefined4 *)FUN_0100c220(0x1010);
      if (puVar2 == (undefined4 *)0x0) {
        if (iVar3 < 3) {
          FUN_0100cbe0();
          return 0;
        }
        break;
      }
      *puVar2 = 0;
      puVar2[1] = DAT_0101276c;
      puVar1 = puVar2;
      if (DAT_0101276c != (undefined4 *)0x0) {
        *DAT_0101276c = puVar2;
        puVar1 = DAT_01012770;
      }
      DAT_01012770 = puVar1;
      iVar3 = iVar3 + 1;
      DAT_0101276c = puVar2;
    } while (iVar3 < DAT_01012768);
  }
  FUN_0100c770();
  return 1;
}



void FUN_0100c770(void)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  
  iVar2 = DAT_0101276c;
  if (DAT_0101276c != 0) {
    do {
      *(undefined4 *)(iVar2 + 8) = 0xffffffff;
      *(undefined4 *)(iVar2 + 0xc) = 0;
      piVar1 = (int *)(iVar2 + 4);
      iVar2 = *piVar1;
    } while (*piVar1 != 0);
  }
  iVar2 = 0;
  if (0 < DAT_01012768) {
    iVar3 = 0;
    do {
      iVar3 = iVar3 + 8;
      iVar2 = iVar2 + 1;
      *(undefined4 *)(DAT_01012774 + -8 + iVar3) = 0;
      *(undefined4 *)(DAT_01012774 + -4 + iVar3) = 0;
    } while (iVar2 < DAT_01012768);
  }
  DAT_0101275c = FUN_0100ca30(0,1);
  if (DAT_0101275c != (int *)0x0) {
    DAT_01012760 = DAT_0101275c + 4;
    DAT_01012764 = DAT_0101275c + 0x404;
  }
  return;
}



int * __cdecl FUN_0100ca30(int param_1,uint param_2)

{
  int *piVar1;
  int **ppiVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  
  piVar3 = DAT_01012770;
  ppiVar2 = *(int ***)(DAT_01012774 + param_1 * 8);
  if (ppiVar2 != (int **)0x0) {
    if (DAT_0101276c != ppiVar2) {
      *(int **)((int)*ppiVar2 + 4) = ppiVar2[1];
      if (ppiVar2[1] == (int *)0x0) {
        DAT_01012770 = *ppiVar2;
      }
      else {
        *ppiVar2[1] = (int)*ppiVar2;
      }
      *DAT_0101276c = (int *)ppiVar2;
      *ppiVar2 = (int *)0x0;
      ppiVar2[1] = (int *)DAT_0101276c;
      DAT_0101276c = ppiVar2;
    }
    ppiVar2[3] = (int *)((uint)ppiVar2[3] | param_2);
    return (int *)ppiVar2;
  }
  if (DAT_0101275c == DAT_01012770) {
    return (int *)0x0;
  }
  piVar1 = DAT_01012770 + 2;
  if ((*piVar1 != -1) && (*(undefined4 *)(DAT_01012774 + *piVar1 * 8) = 0, piVar3[3] != 0)) {
    iVar5 = *piVar1;
    iVar4 = (**(code **)(DAT_01018c38 + 0x1c))(DAT_01012758,iVar5 << 0xc,0);
    if (iVar4 != iVar5 << 0xc) {
      return (int *)0x0;
    }
    iVar5 = (**(code **)(DAT_01018c38 + 0x14))(DAT_01012758,piVar3 + 4,0x1000);
    if (iVar5 != 0x1000) {
      return (int *)0x0;
    }
    *(undefined4 *)(DAT_01012774 + 4 + *piVar1 * 8) = 1;
  }
  DAT_01012770 = (int *)*DAT_01012770;
  *(undefined4 *)((int)DAT_01012770 + 4) = 0;
  *DAT_0101276c = piVar3;
  *piVar3 = 0;
  piVar3[1] = (int)DAT_0101276c;
  DAT_0101276c = (int **)piVar3;
  *(int **)(DAT_01012774 + param_1 * 8) = piVar3;
  if (*(int *)(DAT_01012774 + 4 + param_1 * 8) == 0) {
    if (param_2 == 0) {
      return (int *)0x0;
    }
  }
  else {
    iVar5 = (**(code **)(DAT_01018c38 + 0x1c))(DAT_01012758,param_1 << 0xc,0);
    if (iVar5 != param_1 << 0xc) {
      return (int *)0x0;
    }
    iVar5 = (**(code **)(DAT_01018c38 + 0x10))(DAT_01012758,piVar3 + 4,0x1000);
    if (iVar5 != 0x1000) {
      return (int *)0x0;
    }
  }
  piVar3[3] = param_2;
  *piVar1 = param_1;
  return piVar3;
}



void FUN_0100cbe0(void)

{
  int iVar1;
  int iVar2;
  
  FUN_0100c240(DAT_01012774);
  iVar2 = DAT_0101276c;
  while (iVar2 != 0) {
    iVar1 = *(int *)(iVar2 + 4);
    FUN_0100c240(iVar2);
    iVar2 = iVar1;
  }
  (**(code **)(DAT_01018c38 + 0x18))(DAT_01012758);
  return;
}



undefined4 __cdecl
FUN_0100cc20(int *param_1,uint param_2,uint param_3,int param_4,int param_5,int param_6,uint param_7
            ,uint *param_8)

{
  uint *puVar1;
  uint uVar2;
  uint *puVar3;
  int iVar4;
  int *piVar5;
  uint uVar6;
  uint uVar7;
  byte bVar8;
  uint uVar9;
  uint uVar10;
  int iVar11;
  undefined4 *puVar12;
  int iVar13;
  uint uVar14;
  uint uVar15;
  uint local_584;
  uint local_580;
  int local_57c;
  uint local_578;
  char local_574;
  int local_570;
  uint local_56c;
  uint *local_560;
  int local_554;
  undefined4 local_550;
  undefined4 local_54c;
  int local_548 [16];
  uint local_508 [17];
  uint local_4c4 [305];
  
  local_578 = 0;
  puVar3 = local_4c4;
  for (iVar4 = 0x11; uVar2 = param_2, piVar5 = param_1, iVar4 != 0; iVar4 = iVar4 + -1) {
    *puVar3 = 0;
    puVar3 = puVar3 + 1;
  }
  do {
    local_4c4[*piVar5] = local_4c4[*piVar5] + 1;
    uVar2 = uVar2 - 1;
    piVar5 = piVar5 + 1;
  } while (uVar2 != 0);
  if (local_4c4[0] == param_2) {
    *param_8 = 0;
    return 0;
  }
  uVar2 = 1;
  puVar3 = local_4c4 + 1;
  do {
    if (*puVar3 != 0) break;
    puVar3 = puVar3 + 1;
    uVar2 = uVar2 + 1;
  } while (puVar3 <= local_4c4 + 0x10);
  uVar9 = *param_8;
  if (*param_8 < uVar2) {
    uVar9 = uVar2;
  }
  uVar14 = 0x10;
  puVar3 = local_4c4 + 0x10;
  do {
    if (*puVar3 != 0) break;
    puVar3 = puVar3 + -1;
    uVar14 = uVar14 - 1;
  } while (puVar3 != local_4c4);
  if (uVar14 < uVar9) {
    uVar9 = uVar14;
  }
  *param_8 = uVar9;
  local_554 = 1 << ((byte)uVar2 & 0x1f);
  if (uVar2 < uVar14) {
    puVar3 = local_4c4 + uVar2;
    uVar6 = uVar2;
    do {
      uVar15 = *puVar3;
      if ((int)(local_554 - uVar15) < 0) {
        return 2;
      }
      puVar3 = puVar3 + 1;
      uVar6 = uVar6 + 1;
      local_554 = (local_554 - uVar15) * 2;
    } while (uVar6 < uVar14);
  }
  uVar6 = local_4c4[uVar14];
  local_554 = local_554 - uVar6;
  if (local_554 < 0) {
    return 2;
  }
  puVar1 = local_4c4;
  local_4c4[uVar14] = uVar6 + local_554;
  uVar6 = 0;
  puVar3 = local_508 + 2;
  local_508[1] = 0;
  uVar15 = uVar14;
  while (puVar1 = puVar1 + 1, uVar15 = uVar15 - 1, uVar15 != 0) {
    uVar6 = uVar6 + *puVar1;
    *puVar3 = uVar6;
    puVar3 = puVar3 + 1;
  }
  uVar6 = 0;
  do {
    iVar4 = *param_1;
    param_1 = param_1 + 1;
    if (iVar4 != 0) {
      uVar15 = local_508[iVar4];
      local_508[iVar4] = uVar15 + 1;
      local_4c4[uVar15 + 0x11] = uVar6;
    }
    uVar6 = uVar6 + 1;
  } while (uVar6 < param_2);
  local_560 = local_4c4 + 0x11;
  local_584 = 0;
  local_508[0] = 0;
  local_548[0] = 0;
  local_57c = 0;
  iVar4 = -uVar9;
  local_580 = 0;
  local_570 = -1;
  do {
    if ((int)uVar14 < (int)uVar2) {
      if ((local_554 != 0) && (uVar14 != 1)) {
        return 1;
      }
      return 0;
    }
    local_56c = local_4c4[uVar2];
    while( true ) {
      uVar6 = local_56c - 1;
      if (local_56c == 0) break;
      if ((int)(uVar9 + iVar4) < (int)uVar2) {
        iVar13 = local_570 << 2;
        do {
          iVar4 = iVar4 + uVar9;
          local_570 = local_570 + 1;
          uVar15 = (uVar14 & 0xffff) - iVar4;
          if (uVar9 < uVar15) {
            uVar15 = uVar9 & 0xffff;
          }
          uVar7 = uVar2 - iVar4;
          uVar10 = 1 << ((byte)uVar7 & 0x1f);
          if (local_56c < uVar10) {
            iVar11 = uVar10 - local_56c;
            puVar3 = local_4c4 + uVar2;
            while (uVar7 = uVar7 + 1, uVar7 < uVar15) {
              uVar10 = iVar11 * 2;
              puVar3 = puVar3 + 1;
              if (uVar10 < *puVar3 || uVar10 == *puVar3) break;
              iVar11 = uVar10 - *puVar3;
            }
          }
          local_580 = 1 << ((byte)uVar7 & 0x1f);
          local_57c = param_6 + local_578 * 8;
          local_578 = local_578 + local_580;
          if (param_7 < local_578) {
            return 3;
          }
          *(int *)((int)local_548 + iVar13 + 4) = local_57c;
          if (iVar13 + 4 != 0) {
            *(uint *)((int)local_508 + iVar13 + 4) = local_584;
            local_550 = CONCAT31(CONCAT21(local_550._2_2_,(char)uVar9),(byte)uVar7 + 0x10);
            puVar12 = (undefined4 *)
                      ((local_584 >> ((char)iVar4 - (char)uVar9 & 0x1fU)) * 8 +
                      *(int *)((int)local_548 + iVar13));
            *puVar12 = local_550;
            puVar12[1] = local_57c;
            local_54c = local_57c;
          }
          iVar13 = iVar13 + 4;
        } while ((int)(uVar9 + iVar4) < (int)uVar2);
      }
      local_574 = (char)uVar2;
      bVar8 = (byte)iVar4;
      if (local_560 < local_4c4 + param_2 + 0x11) {
        uVar15 = *local_560;
        if (uVar15 < param_3) {
          local_550._0_1_ = (uVar15 < 0x100) + '\x0f';
        }
        else {
          iVar13 = (uVar15 - param_3) * 2;
          local_550._0_1_ = *(char *)(iVar13 + param_5);
          uVar15 = (uint)*(ushort *)(iVar13 + param_4);
        }
        local_560 = local_560 + 1;
        local_54c = CONCAT22(local_54c._2_2_,(short)uVar15);
      }
      else {
        local_550._0_1_ = 'c';
      }
      local_550 = CONCAT31(CONCAT21(local_550._2_2_,local_574 - bVar8),(char)local_550);
      iVar13 = 1 << (local_574 - bVar8 & 0x1f);
      uVar15 = local_584 >> (bVar8 & 0x1f);
      if (uVar15 < local_580) {
        puVar12 = (undefined4 *)(local_57c + uVar15 * 8);
        do {
          uVar15 = uVar15 + iVar13;
          *puVar12 = local_550;
          puVar12[1] = local_54c;
          puVar12 = puVar12 + iVar13 * 2;
        } while (uVar15 < local_580);
      }
      uVar7 = 1 << (local_574 - 1U & 0x1f);
      uVar15 = local_584 & uVar7;
      while (uVar15 != 0) {
        local_584 = local_584 ^ uVar7;
        uVar7 = uVar7 >> 1;
        uVar15 = local_584 & uVar7;
      }
      local_584 = local_584 ^ uVar7;
      puVar3 = local_508 + local_570;
      local_56c = uVar6;
      if (((1 << (bVar8 & 0x1f)) - 1U & local_584) != *puVar3) {
        do {
          puVar3 = puVar3 + -1;
          iVar4 = iVar4 - uVar9;
          local_570 = local_570 + -1;
        } while (((1 << ((byte)iVar4 & 0x1f)) - 1U & local_584) != *puVar3);
      }
    }
    uVar2 = uVar2 + 1;
  } while( true );
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 __cdecl FUN_0100d070(int param_1,int param_2,uint param_3,uint param_4,short param_5)

{
  uint uVar1;
  int iVar2;
  ushort uVar3;
  ushort uVar4;
  byte *pbVar5;
  byte bVar6;
  byte bVar7;
  uint uVar8;
  uint local_1c;
  uint local_14;
  int local_10;
  byte *local_c;
  
  local_14 = DAT_0101455c;
  local_1c = DAT_01014560;
  uVar3 = *(ushort *)(&DAT_01011cd0 + param_3 * 2);
  uVar4 = *(ushort *)(&DAT_01011cd0 + param_4 * 2);
  uVar1 = DAT_01014560;
  if (param_5 == 0) goto joined_r0x0100d698;
  if (_DAT_0101277c == 0) goto joined_r0x0100d698;
  local_c = DAT_01012780;
  local_10 = DAT_01014538;
  while( true ) {
    while (iVar2 = local_10 + -1, uVar1 = local_1c, local_10 != 0) {
      pbVar5 = local_c + 1;
      *DAT_010156b0 = *local_c;
      DAT_010156b0 = DAT_010156b0 + 1;
      local_c = pbVar5;
      if ((int)DAT_01014540 - (int)pbVar5 == -0x8000) {
        local_c = DAT_01014540;
      }
      DAT_01014554 = DAT_01014554 + -1;
      local_10 = iVar2;
      if (DAT_01014554 == 0) {
        DAT_01014568 = param_1;
        DAT_01014564 = param_2;
        DAT_01014550 = param_3;
        DAT_0101454c = param_4;
        DAT_01014544 = 2;
        DAT_01014538 = iVar2;
        DAT_01012780 = local_c;
        _DAT_0101277c = 1;
        DAT_0101455c = local_14;
        DAT_01014560 = local_1c;
        return 0;
      }
    }
joined_r0x0100d698:
    while( true ) {
      for (; uVar1 < param_3; uVar1 = uVar1 + 8) {
        if (DAT_010156b4 < DAT_010156c0) {
          bVar7 = *(byte *)(DAT_01014548 + DAT_010156b4);
          DAT_010156b4 = DAT_010156b4 + 1;
        }
        else if (DAT_010156b4 == DAT_010156c0) {
          bVar7 = 0;
        }
        else {
          bVar7 = 0;
          _DAT_01012778 = 1;
        }
        local_1c._0_1_ = (byte)uVar1;
        local_14 = local_14 | (uint)bVar7 << ((byte)local_1c & 0x1f);
      }
      if (_DAT_01012778 != 0) {
        return 1;
      }
      pbVar5 = (byte *)((local_14 & uVar3) * 8 + param_1);
      bVar7 = *pbVar5;
      while (uVar8 = (uint)bVar7, 0x10 < uVar8) {
        _DAT_01012778 = 0;
        if (uVar8 == 99) {
          return 1;
        }
        local_14 = local_14 >> (pbVar5[1] & 0x1f);
        for (uVar1 = uVar1 - pbVar5[1]; uVar1 < uVar8 - 0x10; uVar1 = uVar1 + 8) {
          if (DAT_010156b4 < DAT_010156c0) {
            bVar7 = *(byte *)(DAT_01014548 + DAT_010156b4);
            DAT_010156b4 = DAT_010156b4 + 1;
          }
          else if (DAT_010156b4 == DAT_010156c0) {
            bVar7 = 0;
          }
          else {
            bVar7 = 0;
            _DAT_01012778 = 1;
          }
          local_1c._0_1_ = (byte)uVar1;
          local_14 = local_14 | (uint)bVar7 << ((byte)local_1c & 0x1f);
        }
        if (_DAT_01012778 != 0) {
          return 1;
        }
        pbVar5 = (byte *)((*(ushort *)(&DAT_01011cd0 + (uVar8 - 0x10) * 2) & local_14) * 8 +
                         *(int *)(pbVar5 + 4));
        bVar7 = *pbVar5;
      }
      _DAT_01012778 = 0;
      local_14 = local_14 >> (pbVar5[1] & 0x1f);
      uVar1 = uVar1 - pbVar5[1];
      if (uVar8 != 0x10) break;
      *DAT_010156b0 = pbVar5[4];
      DAT_010156b0 = DAT_010156b0 + 1;
      DAT_01014554 = DAT_01014554 + -1;
      if (DAT_01014554 == 0) {
        _DAT_0101277c = 0;
        DAT_01014544 = 2;
        DAT_0101454c = param_4;
        DAT_01014550 = param_3;
        DAT_0101455c = local_14;
        DAT_01014560 = uVar1;
        DAT_01014564 = param_2;
        DAT_01014568 = param_1;
        return 0;
      }
    }
    if (uVar8 == 0xf) {
      _DAT_01012778 = 0;
      DAT_0101455c = local_14;
      DAT_01014560 = uVar1;
      return 0;
    }
    for (; uVar1 < uVar8; uVar1 = uVar1 + 8) {
      if (DAT_010156b4 < DAT_010156c0) {
        bVar6 = *(byte *)(DAT_01014548 + DAT_010156b4);
        DAT_010156b4 = DAT_010156b4 + 1;
      }
      else if (DAT_010156b4 == DAT_010156c0) {
        bVar6 = 0;
      }
      else {
        bVar6 = 0;
        _DAT_01012778 = 1;
      }
      local_1c._0_1_ = (byte)uVar1;
      local_14 = local_14 | (uint)bVar6 << ((byte)local_1c & 0x1f);
    }
    if (_DAT_01012778 != 0) break;
    local_10 = (*(ushort *)(&DAT_01011cd0 + uVar8 * 2) & local_14) + (uint)*(ushort *)(pbVar5 + 4);
    local_14 = local_14 >> (bVar7 & 0x1f);
    _DAT_01012778 = 0;
    for (local_1c = uVar1 - uVar8; local_1c < param_4; local_1c = local_1c + 8) {
      if (DAT_010156b4 < DAT_010156c0) {
        bVar7 = *(byte *)(DAT_01014548 + DAT_010156b4);
        DAT_010156b4 = DAT_010156b4 + 1;
      }
      else if (DAT_010156b4 == DAT_010156c0) {
        bVar7 = 0;
      }
      else {
        bVar7 = 0;
        _DAT_01012778 = 1;
      }
      local_14 = local_14 | (uint)bVar7 << ((byte)local_1c & 0x1f);
    }
    if (_DAT_01012778 != 0) {
      return 1;
    }
    pbVar5 = (byte *)((local_14 & uVar4) * 8 + param_2);
    bVar7 = *pbVar5;
    while (uVar1 = (uint)bVar7, 0x10 < uVar1) {
      _DAT_01012778 = 0;
      if (uVar1 == 99) {
        return 1;
      }
      local_14 = local_14 >> (pbVar5[1] & 0x1f);
      for (local_1c = local_1c - pbVar5[1]; local_1c < uVar1 - 0x10; local_1c = local_1c + 8) {
        if (DAT_010156b4 < DAT_010156c0) {
          bVar7 = *(byte *)(DAT_01014548 + DAT_010156b4);
          DAT_010156b4 = DAT_010156b4 + 1;
        }
        else if (DAT_010156b4 == DAT_010156c0) {
          bVar7 = 0;
        }
        else {
          bVar7 = 0;
          _DAT_01012778 = 1;
        }
        local_14 = local_14 | (uint)bVar7 << ((byte)local_1c & 0x1f);
      }
      if (_DAT_01012778 != 0) {
        return 1;
      }
      pbVar5 = (byte *)((*(ushort *)(&DAT_01011cd0 + (uVar1 - 0x10) * 2) & local_14) * 8 +
                       *(int *)(pbVar5 + 4));
      bVar7 = *pbVar5;
    }
    _DAT_01012778 = 0;
    local_14 = local_14 >> (pbVar5[1] & 0x1f);
    for (local_1c = local_1c - pbVar5[1]; local_1c < uVar1; local_1c = local_1c + 8) {
      if (DAT_010156b4 < DAT_010156c0) {
        bVar6 = *(byte *)(DAT_01014548 + DAT_010156b4);
        DAT_010156b4 = DAT_010156b4 + 1;
      }
      else if (DAT_010156b4 == DAT_010156c0) {
        bVar6 = 0;
      }
      else {
        bVar6 = 0;
        _DAT_01012778 = 1;
      }
      local_14 = local_14 | (uint)bVar6 << ((byte)local_1c & 0x1f);
    }
    if (_DAT_01012778 != 0) {
      return 1;
    }
    uVar8 = (*(ushort *)(&DAT_01011cd0 + uVar1 * 2) & local_14) + (uint)*(ushort *)(pbVar5 + 4);
    local_1c = local_1c - uVar1;
    local_14 = local_14 >> (bVar7 & 0x1f);
    _DAT_01012778 = 0;
    if ((uint)((int)DAT_010156b0 - (int)DAT_01014540) < uVar8) {
      local_c = DAT_010156b0 + (0x8000 - uVar8);
    }
    else {
      local_c = DAT_010156b0 + -uVar8;
    }
  }
  return 1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_0100d6d0(void)

{
  byte bVar1;
  int iVar2;
  uint uVar3;
  byte bVar4;
  uint *puVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  int *piVar11;
  bool bVar12;
  uint local_508;
  uint local_504;
  uint local_500;
  uint local_4fc;
  uint local_4f8;
  uint local_4f4;
  uint local_4f0 [316];
  
  uVar8 = DAT_01014560;
  uVar9 = DAT_0101455c;
  if (DAT_01014560 < 5) {
    do {
      if (DAT_010156b4 < DAT_010156c0) {
        bVar4 = *(byte *)(DAT_01014548 + DAT_010156b4);
        DAT_010156b4 = DAT_010156b4 + 1;
      }
      else if (DAT_010156b4 == DAT_010156c0) {
        bVar4 = 0;
      }
      else {
        bVar4 = 0;
        _DAT_01012778 = 1;
      }
      uVar9 = uVar9 | (uint)bVar4 << ((byte)uVar8 & 0x1f);
      uVar8 = uVar8 + 8;
    } while (uVar8 < 5);
  }
  uVar10 = uVar9 >> 5;
  local_500 = (uVar9 & 0x1f) + 0x101;
  for (uVar8 = uVar8 - 5; uVar8 < 5; uVar8 = uVar8 + 8) {
    if (DAT_010156b4 < DAT_010156c0) {
      bVar4 = *(byte *)(DAT_01014548 + DAT_010156b4);
      DAT_010156b4 = DAT_010156b4 + 1;
    }
    else if (DAT_010156b4 == DAT_010156c0) {
      bVar4 = 0;
    }
    else {
      bVar4 = 0;
      _DAT_01012778 = 1;
    }
    uVar10 = uVar10 | (uint)bVar4 << ((byte)uVar8 & 0x1f);
  }
  uVar9 = uVar10 >> 5;
  local_4fc = (uVar10 & 0x1f) + 1;
  for (uVar8 = uVar8 - 5; uVar8 < 4; uVar8 = uVar8 + 8) {
    if (DAT_010156b4 < DAT_010156c0) {
      bVar4 = *(byte *)(DAT_01014548 + DAT_010156b4);
      DAT_010156b4 = DAT_010156b4 + 1;
    }
    else if (DAT_010156b4 == DAT_010156c0) {
      bVar4 = 0;
    }
    else {
      bVar4 = 0;
      _DAT_01012778 = 1;
    }
    uVar9 = uVar9 | (uint)bVar4 << ((byte)uVar8 & 0x1f);
  }
  uVar8 = uVar8 - 4;
  uVar10 = uVar9 >> 4;
  uVar9 = (uVar9 & 0xf) + 4;
  if (((_DAT_01012778 == 0) && (local_500 < 0x11f)) && (local_4fc < 0x1f)) {
    local_4f8 = 0;
    if (uVar9 != 0) {
      piVar11 = &DAT_01011b80;
      uVar3 = uVar10;
      uVar6 = uVar9;
      do {
        for (; uVar8 < 3; uVar8 = uVar8 + 8) {
          if (DAT_010156b4 < DAT_010156c0) {
            bVar4 = *(byte *)(DAT_01014548 + DAT_010156b4);
            DAT_010156b4 = DAT_010156b4 + 1;
          }
          else if (DAT_010156b4 == DAT_010156c0) {
            bVar4 = 0;
          }
          else {
            _DAT_01012778 = 1;
            bVar4 = 0;
          }
          bVar1 = (byte)uVar8;
          uVar3 = uVar3 | (uint)bVar4 << (bVar1 & 0x1f);
        }
        iVar2 = *piVar11;
        uVar10 = uVar3 >> 3;
        uVar8 = uVar8 - 3;
        piVar11 = piVar11 + 1;
        uVar6 = uVar6 - 1;
        local_4f0[iVar2] = uVar3 & 7;
        local_4f8 = uVar9;
        uVar3 = uVar10;
      } while (uVar6 != 0);
    }
    if (local_4f8 < 0x13) {
      piVar11 = &DAT_01011b80 + local_4f8;
      do {
        iVar2 = *piVar11;
        piVar11 = piVar11 + 1;
        local_4f0[iVar2] = 0;
      } while (piVar11 < &DAT_01011bcc);
    }
    if (_DAT_01012778 != 0) {
      return 1;
    }
    local_508 = 7;
    iVar2 = FUN_0100cc20((int *)local_4f0,0x13,0x13,0,0,(int)&DAT_01012c38,800,&local_508);
    if (iVar2 == 0) {
      local_504 = local_500 + local_4fc;
      local_4f8 = (uint)*(ushort *)(&DAT_01011cd0 + local_508 * 2);
      uVar9 = 0;
      uVar3 = 0;
      if (local_504 != 0) {
        do {
          for (; uVar8 < local_508; uVar8 = uVar8 + 8) {
            if (DAT_010156b4 < DAT_010156c0) {
              bVar4 = *(byte *)(DAT_01014548 + DAT_010156b4);
              DAT_010156b4 = DAT_010156b4 + 1;
            }
            else if (DAT_010156b4 == DAT_010156c0) {
              bVar4 = 0;
            }
            else {
              _DAT_01012778 = 1;
              bVar4 = 0;
            }
            uVar10 = uVar10 | (uint)bVar4 << ((byte)uVar8 & 0x1f);
          }
          if (_DAT_01012778 != 0) {
            return 1;
          }
          iVar2 = (uVar10 & local_4f8) * 8;
          uVar10 = uVar10 >> ((&DAT_01012c39)[iVar2] & 0x1f);
          uVar8 = uVar8 - (byte)(&DAT_01012c39)[iVar2];
          uVar6 = (uint)*(ushort *)(&DAT_01012c3c + iVar2);
          if (uVar6 < 0x10) {
            local_4f0[uVar3] = uVar6;
            uVar3 = uVar3 + 1;
            uVar9 = uVar6;
          }
          else {
            uVar7 = uVar10;
            if (uVar6 == 0x10) {
              for (; uVar8 < 2; uVar8 = uVar8 + 8) {
                if (DAT_010156b4 < DAT_010156c0) {
                  bVar4 = *(byte *)(DAT_01014548 + DAT_010156b4);
                  DAT_010156b4 = DAT_010156b4 + 1;
                }
                else if (DAT_010156b4 == DAT_010156c0) {
                  bVar4 = 0;
                }
                else {
                  _DAT_01012778 = 1;
                  bVar4 = 0;
                }
                bVar1 = (byte)uVar8;
                uVar7 = uVar7 | (uint)bVar4 << (bVar1 & 0x1f);
              }
              if (_DAT_01012778 != 0) {
                return 1;
              }
              uVar8 = uVar8 - 2;
              uVar10 = uVar7 >> 2;
              uVar7 = uVar7 & 3;
              if (local_504 < uVar3 + 3 + uVar7) goto LAB_0100dbad;
              if (uVar7 != 0xfffffffd) {
                puVar5 = local_4f0 + uVar3;
                iVar2 = uVar7 + 2;
                do {
                  *puVar5 = uVar9;
                  puVar5 = puVar5 + 1;
                  uVar3 = uVar3 + 1;
                  bVar12 = iVar2 != 0;
                  iVar2 = iVar2 + -1;
                } while (bVar12);
              }
            }
            else {
              uVar9 = uVar10;
              if (uVar6 == 0x11) {
                for (; uVar8 < 3; uVar8 = uVar8 + 8) {
                  if (DAT_010156b4 < DAT_010156c0) {
                    bVar4 = *(byte *)(DAT_01014548 + DAT_010156b4);
                    DAT_010156b4 = DAT_010156b4 + 1;
                  }
                  else if (DAT_010156b4 == DAT_010156c0) {
                    bVar4 = 0;
                  }
                  else {
                    bVar4 = 0;
                    _DAT_01012778 = 1;
                  }
                  bVar1 = (byte)uVar8;
                  uVar9 = uVar9 | (uint)bVar4 << (bVar1 & 0x1f);
                }
                if (_DAT_01012778 != 0) {
                  return 1;
                }
                uVar8 = uVar8 - 3;
                uVar10 = uVar9 >> 3;
                uVar9 = uVar9 & 7;
                if (local_504 < uVar3 + 3 + uVar9) {
LAB_0100dbad:
                  _DAT_01012778 = 2;
                  break;
                }
                if (uVar9 != 0xfffffffd) {
                  puVar5 = local_4f0 + uVar3;
                  iVar2 = uVar9 + 2;
                  do {
                    *puVar5 = 0;
                    puVar5 = puVar5 + 1;
                    uVar3 = uVar3 + 1;
                    bVar12 = iVar2 != 0;
                    iVar2 = iVar2 + -1;
                  } while (bVar12);
                }
                uVar9 = 0;
              }
              else {
                for (; uVar8 < 7; uVar8 = uVar8 + 8) {
                  if (DAT_010156b4 < DAT_010156c0) {
                    bVar4 = *(byte *)(DAT_01014548 + DAT_010156b4);
                    DAT_010156b4 = DAT_010156b4 + 1;
                  }
                  else if (DAT_010156b4 == DAT_010156c0) {
                    bVar4 = 0;
                  }
                  else {
                    bVar4 = 0;
                    _DAT_01012778 = 1;
                  }
                  bVar1 = (byte)uVar8;
                  uVar9 = uVar9 | (uint)bVar4 << (bVar1 & 0x1f);
                }
                if (_DAT_01012778 != 0) {
                  return 1;
                }
                uVar8 = uVar8 - 7;
                uVar10 = uVar9 >> 7;
                uVar9 = uVar9 & 0x7f;
                if (local_504 < uVar3 + 0xb + uVar9) goto LAB_0100dbad;
                if (uVar9 != 0xfffffff5) {
                  puVar5 = local_4f0 + uVar3;
                  iVar2 = uVar9 + 10;
                  do {
                    *puVar5 = 0;
                    puVar5 = puVar5 + 1;
                    uVar3 = uVar3 + 1;
                    bVar12 = iVar2 != 0;
                    iVar2 = iVar2 + -1;
                  } while (bVar12);
                }
                uVar9 = 0;
              }
            }
          }
        } while (uVar3 < local_504);
      }
      if (_DAT_01012778 != 0) {
        return 1;
      }
      local_508 = 9;
      DAT_0101455c = uVar10;
      DAT_01014560 = uVar8;
      iVar2 = FUN_0100cc20((int *)local_4f0,local_500,0x101,(int)&DAT_01011bd0,(int)&DAT_01011c10,
                           (int)&DAT_01012c38,800,&local_508);
      if (iVar2 == 0) {
        local_4f4 = 6;
        iVar2 = FUN_0100cc20((int *)(local_4f0 + local_500),local_4fc,0,(int)&DAT_01011c50,
                             (int)&DAT_01011c90,(int)&DAT_01012788,0x96,&local_4f4);
        if (iVar2 == 0) {
          iVar2 = FUN_0100d070((int)&DAT_01012c38,(int)&DAT_01012788,local_508,local_4f4,0);
          return iVar2;
        }
      }
    }
  }
  else {
    iVar2 = 1;
  }
  return iVar2;
}



int FUN_0100dc90(void)

{
  int iVar1;
  undefined4 *puVar2;
  int *piVar3;
  int local_480 [144];
  undefined4 local_240 [112];
  undefined4 local_80 [24];
  undefined4 local_20 [8];
  
  piVar3 = local_480;
  for (iVar1 = 0x90; iVar1 != 0; iVar1 = iVar1 + -1) {
    *piVar3 = 8;
    piVar3 = piVar3 + 1;
  }
  puVar2 = local_240;
  for (iVar1 = 0x70; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = 9;
    puVar2 = puVar2 + 1;
  }
  puVar2 = local_80;
  for (iVar1 = 0x18; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = 7;
    puVar2 = puVar2 + 1;
  }
  puVar2 = local_20;
  for (iVar1 = 8; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = 8;
    puVar2 = puVar2 + 1;
  }
  iVar1 = FUN_0100cc20(local_480,0x120,0x101,(int)&DAT_01011bd0,(int)&DAT_01011c10,
                       (int)&DAT_01014670,0x208,&DAT_01011b74);
  if (iVar1 == 0) {
    piVar3 = local_480;
    for (iVar1 = 0x1e; iVar1 != 0; iVar1 = iVar1 + -1) {
      *piVar3 = 5;
      piVar3 = piVar3 + 1;
    }
    iVar1 = FUN_0100cc20(local_480,0x1e,0,(int)&DAT_01011c50,(int)&DAT_01011c90,(int)&DAT_01014570,
                         0x20,&DAT_01011b78);
    if (iVar1 < 2) {
      iVar1 = 0;
    }
  }
  return iVar1;
}



void FUN_0100dd60(void)

{
  FUN_0100d070((int)&DAT_01014670,(int)&DAT_01014570,DAT_01011b74,DAT_01011b78,0);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 __cdecl FUN_0100dd90(short param_1)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  undefined4 *puVar5;
  uint uVar6;
  undefined4 *puVar7;
  undefined4 *puVar8;
  
  uVar3 = DAT_01014554;
  if (param_1 == 0) {
    uVar6 = DAT_0101455c >> (sbyte)(DAT_01014560 & 7);
    for (uVar4 = DAT_01014560 - (DAT_01014560 & 7); uVar4 < 0x10; uVar4 = uVar4 + 8) {
      if (DAT_010156b4 < DAT_010156c0) {
        uVar1 = (uint)*(byte *)(DAT_01014548 + DAT_010156b4);
        DAT_010156b4 = DAT_010156b4 + 1;
      }
      else if (DAT_010156b4 == DAT_010156c0) {
        uVar1 = 0;
      }
      else {
        uVar1 = 0;
        _DAT_01012778 = 1;
      }
      uVar6 = uVar6 | uVar1 << ((byte)uVar4 & 0x1f);
    }
    uVar1 = uVar6 >> 0x10;
    uVar6 = uVar6 & 0xffff;
    for (uVar4 = uVar4 - 0x10; uVar4 < 0x10; uVar4 = uVar4 + 8) {
      if (DAT_010156b4 < DAT_010156c0) {
        uVar2 = (uint)*(byte *)(DAT_01014548 + DAT_010156b4);
        DAT_010156b4 = DAT_010156b4 + 1;
      }
      else if (DAT_010156b4 == DAT_010156c0) {
        uVar2 = 0;
      }
      else {
        uVar2 = 0;
        _DAT_01012778 = 1;
      }
      uVar1 = uVar1 | uVar2 << ((byte)uVar4 & 0x1f);
    }
    if ((~uVar1 & 0xffff) != uVar6) {
      return 1;
    }
    if ((_DAT_01012778 != 0) || (uVar4 != 0x10)) {
      return 1;
    }
    DAT_01014560 = 0;
    puVar5 = (undefined4 *)(DAT_01014548 + DAT_010156b4);
    DAT_0101455c = 0;
    DAT_010156b4 = DAT_010156b4 + uVar6;
    _DAT_01012778 = 0;
  }
  else {
    DAT_01014544 = 0;
    uVar6 = DAT_010156bc;
    puVar5 = DAT_01014558;
  }
  if (uVar6 <= DAT_01014554) {
    DAT_01014554 = DAT_01014554 - uVar6;
    puVar7 = DAT_010156b0;
    for (uVar3 = uVar6 >> 2; uVar3 != 0; uVar3 = uVar3 - 1) {
      *puVar7 = *puVar5;
      puVar5 = puVar5 + 1;
      puVar7 = puVar7 + 1;
    }
    for (uVar3 = uVar6 & 3; uVar3 != 0; uVar3 = uVar3 - 1) {
      *(undefined *)puVar7 = *(undefined *)puVar5;
      puVar5 = (undefined4 *)((int)puVar5 + 1);
      puVar7 = (undefined4 *)((int)puVar7 + 1);
    }
    DAT_010156b0 = (undefined4 *)((int)DAT_010156b0 + uVar6);
    return 0;
  }
  puVar7 = puVar5;
  puVar8 = DAT_010156b0;
  for (uVar4 = DAT_01014554 >> 2; uVar4 != 0; uVar4 = uVar4 - 1) {
    *puVar8 = *puVar7;
    puVar7 = puVar7 + 1;
    puVar8 = puVar8 + 1;
  }
  for (uVar3 = uVar3 & 3; uVar3 != 0; uVar3 = uVar3 - 1) {
    *(undefined *)puVar8 = *(undefined *)puVar7;
    puVar7 = (undefined4 *)((int)puVar7 + 1);
    puVar8 = (undefined4 *)((int)puVar8 + 1);
  }
  DAT_01014544 = 1;
  DAT_010156b0 = (undefined4 *)((int)DAT_010156b0 + DAT_01014554);
  DAT_010156bc = uVar6 - DAT_01014554;
  DAT_01014558 = (undefined4 *)(DAT_01014554 + (int)puVar5);
  DAT_01014554 = 0;
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_0100df60(void)

{
  byte bVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  
  if (DAT_01014560 == 0) {
    DAT_01014560 = 0;
    do {
      if (DAT_010156b4 < DAT_010156c0) {
        bVar1 = *(byte *)(DAT_01014548 + DAT_010156b4);
        DAT_010156b4 = DAT_010156b4 + 1;
      }
      else if (DAT_010156b4 == DAT_010156c0) {
        bVar1 = 0;
      }
      else {
        bVar1 = 0;
        _DAT_01012778 = 1;
      }
      DAT_0101455c = DAT_0101455c | (uint)bVar1 << ((byte)DAT_01014560 & 0x1f);
      DAT_01014560 = DAT_01014560 + 8;
    } while (DAT_01014560 == 0);
  }
  uVar4 = DAT_0101455c >> 1;
  _DAT_0101453c = DAT_0101455c & 1;
  for (uVar3 = DAT_01014560 - 1; uVar3 < 2; uVar3 = uVar3 + 8) {
    if (DAT_010156b4 < DAT_010156c0) {
      bVar1 = *(byte *)(DAT_01014548 + DAT_010156b4);
      DAT_010156b4 = DAT_010156b4 + 1;
    }
    else if (DAT_010156b4 == DAT_010156c0) {
      bVar1 = 0;
    }
    else {
      bVar1 = 0;
      _DAT_01012778 = 1;
    }
    uVar4 = uVar4 | (uint)bVar1 << ((byte)uVar3 & 0x1f);
  }
  DAT_01014560 = uVar3 - 2;
  DAT_0101455c = uVar4 >> 2;
  uVar4 = uVar4 & 3;
  if (_DAT_01012778 != 0) {
    return 1;
  }
  if (uVar4 == 0) {
    iVar2 = FUN_0100dd90(0);
    return iVar2;
  }
  if (uVar4 != 1) {
    if (uVar4 != 2) {
      return 2;
    }
    iVar2 = FUN_0100d6d0();
    return iVar2;
  }
  iVar2 = FUN_0100dd60();
  return iVar2;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 __cdecl FUN_0100e080(short *param_1,int param_2,undefined4 param_3,undefined4 param_4)

{
  int iVar1;
  
  if (_DAT_01011b70 == 0) {
    iVar1 = FUN_0100dc90();
    if (iVar1 != 0) {
      return 2;
    }
    _DAT_01011b70 = 1;
  }
  if (*param_1 != 0x4b43) {
    return 3;
  }
  DAT_01014548 = param_1 + 1;
  DAT_010156b4 = 0;
  DAT_01014560 = 0;
  DAT_010156c0 = param_2 + -2;
  DAT_0101455c = 0;
  DAT_010156b8 = param_4;
  DAT_010156b0 = param_3;
  DAT_01014540 = param_3;
  _DAT_0101453c = 0;
  _DAT_01012778 = 0;
  DAT_01014544 = 0;
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int __cdecl FUN_0100e110(uint *param_1)

{
  uint uVar1;
  int iVar2;
  
  DAT_01014554 = *param_1;
  if (DAT_010156b8 < DAT_01014554) {
    DAT_01014554 = DAT_010156b8;
  }
  uVar1 = DAT_01014554;
  if (DAT_01014554 == 0) {
LAB_0100e1be:
    *param_1 = (uint)(ushort)((short)uVar1 - (short)DAT_01014554);
    return 0;
  }
  switch(DAT_01014544) {
  case 0:
    break;
  case 1:
    FUN_0100dd90(1);
    break;
  case 2:
    FUN_0100d070(DAT_01014568,DAT_01014564,DAT_01014550,DAT_0101454c,1);
    break;
  case 3:
    *param_1 = 0;
    return 0;
  default:
    return 3;
  }
  do {
    if ((_DAT_0101453c != 0) || (DAT_01014554 == 0)) goto LAB_0100e1be;
    iVar2 = FUN_0100df60();
    if (iVar2 != 0) {
      return 3 - (uint)(iVar2 == 3);
    }
  } while( true );
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_0100e1e0(byte param_1)

{
  byte *pbVar1;
  int *piVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  
  iVar4 = 0;
  iVar5 = 0;
  do {
    *(int *)((int)&DAT_01018ae0 + iVar4) = iVar5;
    if (0 < 1 << ((&DAT_01011cf8)[iVar4] & 0x1f)) {
      iVar5 = iVar5 + (1 << ((&DAT_01011cf8)[iVar4] & 0x1f));
    }
    iVar4 = iVar4 + 4;
  } while (iVar4 < 0x6c);
  iVar4 = 0;
  iVar6 = 0;
  iVar5 = 0;
  do {
    if (iVar5 < 1 << (param_1 & 0x1f)) {
      DAT_010184b0 = iVar6 + 1;
      if (iVar5 < 0x1000) {
        DAT_010186c0 = DAT_010184b0;
      }
      if (iVar5 < 0x40000) {
        DAT_010188d0 = DAT_010184b0;
      }
    }
    pbVar1 = &DAT_01011d68 + iVar4;
    *(int *)((int)&DAT_01018b4c + iVar4) = iVar5;
    iVar4 = iVar4 + 4;
    iVar5 = iVar5 + (1 << (*pbVar1 & 0x1f));
    iVar6 = iVar6 + 1;
  } while (iVar4 < 0xa8);
  iVar4 = 0;
  _DAT_01017850 = 7;
  _DAT_01017854 = 4;
  piVar3 = &DAT_01017858;
  do {
    piVar2 = piVar3 + 2;
    *piVar3 = 7 - iVar4;
    piVar3[1] = iVar4;
    iVar4 = iVar4 + 1;
    piVar3 = piVar2;
  } while (piVar2 < (int *)0x1017891);
  _DAT_01018090 = 0x40;
  _DAT_01017e80 = 0x40;
  _DAT_01017c70 = 0x40;
  _DAT_01017a60 = 0x40;
  _DAT_01018094 = 4;
  _DAT_01017e84 = 4;
  _DAT_01017c74 = 4;
  _DAT_01017a64 = 4;
  iVar4 = 0;
  piVar3 = &DAT_01017a68;
  do {
    piVar2 = piVar3 + 2;
    iVar5 = 0x40 - iVar4;
    *piVar3 = iVar5;
    piVar3[0x84] = iVar5;
    piVar3[0x108] = iVar5;
    piVar3[0x18c] = iVar5;
    piVar3[1] = iVar4;
    piVar3[0x85] = iVar4;
    piVar3[0x109] = iVar4;
    piVar3[0x18d] = iVar4;
    iVar4 = iVar4 + 1;
    piVar3 = piVar2;
  } while (piVar2 < (int *)0x1017c69);
  iVar4 = 0;
  _DAT_010182a0 = 0x1b;
  _DAT_010182a4 = 4;
  piVar3 = &DAT_010182a8;
  do {
    piVar2 = piVar3 + 2;
    *piVar3 = 0x1b - iVar4;
    piVar3[1] = iVar4;
    iVar4 = iVar4 + 1;
    piVar3 = piVar2;
  } while (piVar2 < (int *)0x1018381);
  iVar4 = 0;
  _DAT_010184b4 = 4;
  _DAT_010186c4 = 4;
  _DAT_010188d4 = 4;
  piVar3 = &DAT_010184b8;
  do {
    piVar2 = piVar3 + 2;
    *piVar3 = DAT_010184b0 - iVar4;
    piVar3[0x84] = DAT_010186c0 - iVar4;
    piVar3[0x108] = DAT_010188d0 - iVar4;
    piVar3[1] = iVar4;
    piVar3[0x85] = iVar4;
    piVar3[0x109] = iVar4;
    iVar4 = iVar4 + 1;
    piVar3 = piVar2;
  } while (piVar2 < (int *)0x1018609);
  return;
}



void FUN_0100e3b0(void)

{
  return;
}



void __cdecl FUN_0100e3c0(int *param_1)

{
  int iVar1;
  uint *puVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  uint *puVar6;
  int iVar7;
  uint uVar8;
  uint *puVar9;
  
  iVar7 = *param_1;
  iVar5 = param_1[1];
  puVar6 = (uint *)(param_1 + 2);
  param_1[1] = iVar5 + -1;
  if (iVar5 + -1 == 0) {
    param_1[1] = 0x32;
    iVar5 = iVar7;
    puVar9 = puVar6;
    if (0 < iVar7) {
      do {
        uVar8 = *puVar9;
        *puVar9 = uVar8 - puVar9[2];
        uVar8 = (uVar8 - puVar9[2]) + 1;
        *puVar9 = uVar8;
        iVar5 = iVar5 + -1;
        *puVar9 = uVar8 >> 1;
        puVar9 = puVar9 + 2;
      } while (iVar5 != 0);
    }
    iVar5 = 0;
    if (0 < iVar7) {
      do {
        iVar1 = iVar5 + 1;
        if (iVar1 < iVar7) {
          puVar9 = puVar6 + iVar1 * 2;
          puVar2 = puVar6 + iVar5 * 2;
          iVar5 = iVar7 - iVar1;
          do {
            uVar8 = *puVar2;
            if (uVar8 <= *puVar9 && *puVar9 != uVar8) {
              uVar3 = puVar2[1];
              uVar4 = puVar9[1];
              *puVar2 = *puVar9;
              puVar2[1] = uVar4;
              *puVar9 = uVar8;
              puVar9[1] = uVar3;
            }
            puVar9 = puVar9 + 2;
            iVar5 = iVar5 + -1;
          } while (iVar5 != 0);
        }
        iVar5 = iVar1;
      } while (iVar1 < iVar7);
    }
    iVar7 = iVar7 + -1;
    if (-1 < iVar7) {
      puVar6 = puVar6 + iVar7 * 2;
      do {
        *puVar6 = *puVar6 + puVar6[2];
        puVar6 = puVar6 + -2;
        iVar7 = iVar7 + -1;
      } while (-1 < iVar7);
      return;
    }
  }
  else {
    iVar7 = iVar7 + -1;
    if (-1 < iVar7) {
      puVar6 = puVar6 + iVar7 * 2;
      do {
        uVar8 = *puVar6;
        *puVar6 = uVar8 >> 1;
        if (uVar8 >> 1 <= puVar6[2]) {
          *puVar6 = puVar6[2] + 1;
        }
        puVar6 = puVar6 + -2;
        iVar7 = iVar7 + -1;
      } while (-1 < iVar7);
    }
  }
  return;
}



void FUN_0100e4a0(void)

{
  undefined4 uVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  uint *puVar5;
  int *piVar6;
  int iVar7;
  bool bVar8;
  undefined4 local_c;
  
  local_c = CONCAT22(local_c._2_2_,(short)DAT_01017858);
  iVar7 = 0;
  uVar3 = FUN_0100ec10(local_c);
  if (uVar3 < DAT_01017860) {
    puVar5 = &DAT_01017860;
    do {
      puVar5 = puVar5 + 2;
      iVar7 = iVar7 + 1;
    } while (uVar3 <= *puVar5 && *puVar5 != uVar3);
  }
  uVar1 = (&DAT_0101785c)[iVar7 * 2];
  FUN_0100ec50(CONCAT22((short)(&DAT_01017858)[iVar7 * 2],(short)(&DAT_01017860)[iVar7 * 2]),local_c
              );
  piVar6 = (int *)&DAT_01017858;
  do {
    *piVar6 = *piVar6 + 8;
    piVar6 = piVar6 + 2;
    bVar8 = iVar7 != 0;
    iVar7 = iVar7 + -1;
  } while (bVar8);
  if (0xed8 < DAT_01017858) {
    FUN_0100e3c0((int *)&DAT_01017850);
  }
  switch(uVar1) {
  case 0:
    iVar7 = 0;
    local_c = CONCAT22(local_c._2_2_,(short)DAT_01017a68);
    uVar3 = FUN_0100ec10(local_c);
    if (uVar3 < DAT_01017a70) {
      puVar5 = &DAT_01017a70;
      do {
        puVar5 = puVar5 + 2;
        iVar7 = iVar7 + 1;
      } while (uVar3 <= *puVar5 && *puVar5 != uVar3);
    }
    FUN_0100ec50(CONCAT22((short)(&DAT_01017a68)[iVar7 * 2],(short)(&DAT_01017a70)[iVar7 * 2]),
                 local_c);
    piVar6 = (int *)&DAT_01017a68;
    do {
      *piVar6 = *piVar6 + 8;
      piVar6 = piVar6 + 2;
      bVar8 = iVar7 != 0;
      iVar7 = iVar7 + -1;
    } while (bVar8);
    if (0xed8 < DAT_01017a68) {
      FUN_0100e3c0((int *)&DAT_01017a60);
    }
    (*DAT_01018bf8)();
    return;
  case 1:
    iVar7 = 0;
    local_c = CONCAT22(local_c._2_2_,(short)DAT_01017c78);
    uVar3 = FUN_0100ec10(local_c);
    if (uVar3 < DAT_01017c80) {
      puVar5 = &DAT_01017c80;
      do {
        puVar5 = puVar5 + 2;
        iVar7 = iVar7 + 1;
      } while (uVar3 <= *puVar5 && *puVar5 != uVar3);
    }
    FUN_0100ec50(CONCAT22((short)(&DAT_01017c78)[iVar7 * 2],(short)(&DAT_01017c80)[iVar7 * 2]),
                 local_c);
    piVar6 = (int *)&DAT_01017c78;
    do {
      *piVar6 = *piVar6 + 8;
      piVar6 = piVar6 + 2;
      bVar8 = iVar7 != 0;
      iVar7 = iVar7 + -1;
    } while (bVar8);
    if (0xed8 < DAT_01017c78) {
      FUN_0100e3c0((int *)&DAT_01017c70);
    }
    (*DAT_01018bf8)();
    return;
  case 2:
    iVar7 = 0;
    local_c = CONCAT22(local_c._2_2_,(short)DAT_01017e88);
    uVar3 = FUN_0100ec10(local_c);
    if (uVar3 < DAT_01017e90) {
      puVar5 = &DAT_01017e90;
      do {
        puVar5 = puVar5 + 2;
        iVar7 = iVar7 + 1;
      } while (uVar3 <= *puVar5 && *puVar5 != uVar3);
    }
    FUN_0100ec50(CONCAT22((short)(&DAT_01017e88)[iVar7 * 2],(short)(&DAT_01017e90)[iVar7 * 2]),
                 local_c);
    piVar6 = (int *)&DAT_01017e88;
    do {
      *piVar6 = *piVar6 + 8;
      piVar6 = piVar6 + 2;
      bVar8 = iVar7 != 0;
      iVar7 = iVar7 + -1;
    } while (bVar8);
    if (0xed8 < DAT_01017e88) {
      FUN_0100e3c0((int *)&DAT_01017e80);
    }
    (*DAT_01018bf8)();
    return;
  case 3:
    iVar7 = 0;
    local_c = CONCAT22(local_c._2_2_,(short)DAT_01018098);
    uVar3 = FUN_0100ec10(local_c);
    if (uVar3 < DAT_010180a0) {
      puVar5 = &DAT_010180a0;
      do {
        puVar5 = puVar5 + 2;
        iVar7 = iVar7 + 1;
      } while (uVar3 <= *puVar5 && *puVar5 != uVar3);
    }
    FUN_0100ec50(CONCAT22((short)(&DAT_01018098)[iVar7 * 2],(short)(&DAT_010180a0)[iVar7 * 2]),
                 local_c);
    piVar6 = (int *)&DAT_01018098;
    do {
      *piVar6 = *piVar6 + 8;
      piVar6 = piVar6 + 2;
      bVar8 = iVar7 != 0;
      iVar7 = iVar7 + -1;
    } while (bVar8);
    if (0xed8 < DAT_01018098) {
      FUN_0100e3c0((int *)&DAT_01018090);
    }
    (*DAT_01018bf8)();
    return;
  case 4:
    iVar7 = 0;
    local_c = CONCAT22(local_c._2_2_,(short)DAT_010186c8);
    uVar3 = FUN_0100ec10(local_c);
    if (uVar3 < DAT_010186d0) {
      puVar5 = &DAT_010186d0;
      do {
        puVar5 = puVar5 + 2;
        iVar7 = iVar7 + 1;
      } while (uVar3 <= *puVar5 && *puVar5 != uVar3);
    }
    iVar2 = (&DAT_010186cc)[iVar7 * 2];
    FUN_0100ec50(CONCAT22((short)(&DAT_010186c8)[iVar7 * 2],(short)(&DAT_010186d0)[iVar7 * 2]),
                 local_c);
    piVar6 = (int *)&DAT_010186c8;
    do {
      *piVar6 = *piVar6 + 8;
      piVar6 = piVar6 + 2;
      bVar8 = iVar7 != 0;
      iVar7 = iVar7 + -1;
    } while (bVar8);
    if (0xed8 < DAT_010186c8) {
      FUN_0100e3c0(&DAT_010186c0);
    }
    uVar3 = FUN_0100eb70(*(int *)(&DAT_01011d68 + iVar2 * 4));
    (*DAT_01018c34)(3,(&DAT_01018b4c)[iVar2] + uVar3 + 1);
    return;
  case 5:
    iVar7 = 0;
    local_c = CONCAT22(local_c._2_2_,(short)DAT_010188d8);
    uVar3 = FUN_0100ec10(local_c);
    if (uVar3 < DAT_010188e0) {
      puVar5 = &DAT_010188e0;
      do {
        puVar5 = puVar5 + 2;
        iVar7 = iVar7 + 1;
      } while (uVar3 <= *puVar5 && *puVar5 != uVar3);
    }
    iVar2 = (&DAT_010188dc)[iVar7 * 2];
    FUN_0100ec50(CONCAT22((short)(&DAT_010188d8)[iVar7 * 2],(short)(&DAT_010188e0)[iVar7 * 2]),
                 local_c);
    piVar6 = (int *)&DAT_010188d8;
    do {
      *piVar6 = *piVar6 + 8;
      piVar6 = piVar6 + 2;
      bVar8 = iVar7 != 0;
      iVar7 = iVar7 + -1;
    } while (bVar8);
    if (0xed8 < DAT_010188d8) {
      FUN_0100e3c0(&DAT_010188d0);
    }
    uVar3 = FUN_0100eb70(*(int *)(&DAT_01011d68 + iVar2 * 4));
    (*DAT_01018c34)(4,(&DAT_01018b4c)[iVar2] + uVar3 + 1);
    return;
  case 6:
    iVar7 = 0;
    local_c = CONCAT22(local_c._2_2_,(short)DAT_010182a8);
    uVar3 = FUN_0100ec10(local_c);
    if (uVar3 < DAT_010182b0) {
      puVar5 = &DAT_010182b0;
      do {
        puVar5 = puVar5 + 2;
        iVar7 = iVar7 + 1;
      } while (uVar3 <= *puVar5 && *puVar5 != uVar3);
    }
    iVar2 = (&DAT_010182ac)[iVar7 * 2];
    FUN_0100ec50(CONCAT22((short)(&DAT_010182a8)[iVar7 * 2],(short)(&DAT_010182b0)[iVar7 * 2]),
                 local_c);
    piVar6 = (int *)&DAT_010182a8;
    do {
      *piVar6 = *piVar6 + 8;
      piVar6 = piVar6 + 2;
      bVar8 = iVar7 != 0;
      iVar7 = iVar7 + -1;
    } while (bVar8);
    if (0xed8 < DAT_010182a8) {
      FUN_0100e3c0((int *)&DAT_010182a0);
    }
    uVar3 = FUN_0100eb70(*(int *)(&DAT_01011cf8 + iVar2 * 4));
    uVar1 = (&DAT_01018ae0)[iVar2];
    iVar7 = 0;
    local_c = CONCAT22(local_c._2_2_,(short)DAT_010184b8);
    uVar4 = FUN_0100ec10(local_c);
    if (uVar4 < DAT_010184c0) {
      puVar5 = &DAT_010184c0;
      do {
        puVar5 = puVar5 + 2;
        iVar7 = iVar7 + 1;
      } while (uVar4 <= *puVar5 && *puVar5 != uVar4);
    }
    iVar2 = (&DAT_010184bc)[iVar7 * 2];
    FUN_0100ec50(CONCAT22((short)(&DAT_010184b8)[iVar7 * 2],(short)(&DAT_010184c0)[iVar7 * 2]),
                 local_c);
    piVar6 = (int *)&DAT_010184b8;
    do {
      *piVar6 = *piVar6 + 8;
      piVar6 = piVar6 + 2;
      bVar8 = iVar7 != 0;
      iVar7 = iVar7 + -1;
    } while (bVar8);
    if (0xed8 < DAT_010184b8) {
      FUN_0100e3c0(&DAT_010184b0);
    }
    uVar4 = FUN_0100eb70(*(int *)(&DAT_01011d68 + iVar2 * 4));
    (*DAT_01018c34)((short)uVar1 + (short)uVar3 + 5,(&DAT_01018b4c)[iVar2] + uVar4 + 1);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0100eac0(void)

{
  char cVar1;
  uint uVar2;
  int iVar3;
  
  iVar3 = 0x10;
  _DAT_010156c4 = 0;
  do {
    DAT_01017844 = DAT_01017844 << 1;
    if (_DAT_010156c4 == 0) {
      if (_DAT_01018c30 == 0) {
        uVar2 = 0;
        _DAT_01018bf4 = 1;
      }
      else {
        _DAT_010156c4 = 7;
        _DAT_01018c30 = _DAT_01018c30 + -1;
        cVar1 = *DAT_01018c2c;
        DAT_01018c2c = DAT_01018c2c + 1;
        DAT_010156c8 = (int)cVar1 << 1;
        uVar2 = DAT_010156c8 & 0x100;
      }
    }
    else {
      DAT_010156c8 = DAT_010156c8 << 1;
      _DAT_010156c4 = _DAT_010156c4 + -1;
      uVar2 = DAT_010156c8 & 0x100;
    }
    if (uVar2 != 0) {
      DAT_01017844 = DAT_01017844 | 1;
    }
    iVar3 = iVar3 + -1;
  } while (iVar3 != 0);
  DAT_01017840 = 0;
  DAT_01017842 = 0xffff;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

uint __cdecl FUN_0100eb70(int param_1)

{
  char cVar1;
  uint uVar2;
  uint uVar3;
  
  uVar2 = 0;
  if (param_1 != 0) {
    do {
      param_1 = param_1 + -1;
      uVar2 = uVar2 * 2;
      if (_DAT_010156c4 == 0) {
        if (_DAT_01018c30 == 0) {
          uVar3 = 0;
          _DAT_01018bf4 = 1;
        }
        else {
          _DAT_010156c4 = 7;
          _DAT_01018c30 = _DAT_01018c30 + -1;
          cVar1 = *DAT_01018c2c;
          DAT_01018c2c = DAT_01018c2c + 1;
          DAT_010156c8 = (int)cVar1 << 1;
          uVar3 = DAT_010156c8 & 0x100;
        }
      }
      else {
        DAT_010156c8 = DAT_010156c8 << 1;
        _DAT_010156c4 = _DAT_010156c4 + -1;
        uVar3 = DAT_010156c8 & 0x100;
      }
      if (uVar3 != 0) {
        uVar2 = uVar2 | 1;
      }
    } while (param_1 != 0);
  }
  return uVar2;
}



int __fastcall FUN_0100ec10(uint param_1)

{
  return (int)(short)(((((uint)DAT_01017844 - (uint)DAT_01017840) + 1) * (param_1 & 0xffff) - 1) /
                     (((uint)DAT_01017842 - (uint)DAT_01017840) + 1));
}



void FUN_0100ec40(void)

{
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0100ec50(uint param_1,uint param_2)

{
  char cVar1;
  uint uVar2;
  int iVar3;
  
  iVar3 = ((uint)DAT_01017842 - (uint)DAT_01017840) + 1;
  DAT_01017842 = (DAT_01017840 + (short)(((param_1 >> 0x10) * iVar3) / (param_2 & 0xffff))) - 1;
  DAT_01017840 = DAT_01017840 + (short)(((param_1 & 0xffff) * iVar3) / (param_2 & 0xffff));
  do {
    if (((DAT_01017842 ^ DAT_01017840) & 0x8000) != 0) {
      if (((DAT_01017840 & 0x4000) == 0) || ((DAT_01017842 & 0x4000) != 0)) {
        return;
      }
      DAT_01017844 = DAT_01017844 ^ 0x4000;
      DAT_01017840 = DAT_01017840 & 0x3fff;
      DAT_01017842 = DAT_01017842 | 0x4000;
    }
    DAT_01017840 = DAT_01017840 << 1;
    DAT_01017842 = DAT_01017842 << 1;
    DAT_01017844 = DAT_01017844 << 1;
    DAT_01017842 = DAT_01017842 | 1;
    if (_DAT_010156c4 == 0) {
      if (_DAT_01018c30 == 0) {
        uVar2 = 0;
        _DAT_01018bf4 = 1;
      }
      else {
        _DAT_010156c4 = 7;
        _DAT_01018c30 = _DAT_01018c30 + -1;
        cVar1 = *DAT_01018c2c;
        DAT_01018c2c = DAT_01018c2c + 1;
        DAT_010156c8 = (int)cVar1 << 1;
        uVar2 = DAT_010156c8 & 0x100;
      }
    }
    else {
      DAT_010156c8 = DAT_010156c8 << 1;
      _DAT_010156c4 = _DAT_010156c4 + -1;
      uVar2 = DAT_010156c8 & 0x100;
    }
    if (uVar2 != 0) {
      DAT_01017844 = DAT_01017844 | 1;
    }
  } while( true );
}


