typedef unsigned char   undefined;

typedef pointer32 ImageBaseOffset32;

typedef unsigned char    bool;
typedef unsigned char    byte;
typedef unsigned int    dword;
float10
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned char    undefined1;
typedef unsigned short    undefined2;
typedef unsigned int    undefined4;
typedef unsigned long long    undefined8;
typedef unsigned short    ushort;
typedef short    wchar_t;
typedef unsigned short    word;
typedef unsigned short    wchar16;
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

typedef struct _ITEMIDLIST _ITEMIDLIST, *P_ITEMIDLIST;

typedef struct _SHITEMID _SHITEMID, *P_SHITEMID;

typedef struct _SHITEMID SHITEMID;

typedef ushort USHORT;

typedef uchar BYTE;

struct _SHITEMID {
    USHORT cb;
    BYTE abID[1];
};

struct _ITEMIDLIST {
    SHITEMID mkid;
};

typedef struct _ITEMIDLIST ITEMIDLIST;

typedef ITEMIDLIST * LPCITEMIDLIST;

typedef ITEMIDLIST * LPITEMIDLIST;

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

typedef struct tagMSG * LPMSG;

typedef LPCDLGTEMPLATEA LPCDLGTEMPLATE;

typedef void (* TIMERPROC)(HWND, UINT, UINT_PTR, DWORD);

typedef struct _cpinfo _cpinfo, *P_cpinfo;

struct _cpinfo {
    UINT MaxCharSize;
    BYTE DefaultChar[2];
    BYTE LeadByte[12];
};

typedef struct _cpinfo * LPCPINFO;

typedef struct tagLOGFONTA tagLOGFONTA, *PtagLOGFONTA;

typedef char CHAR;

struct tagLOGFONTA {
    LONG lfHeight;
    LONG lfWidth;
    LONG lfEscapement;
    LONG lfOrientation;
    LONG lfWeight;
    BYTE lfItalic;
    BYTE lfUnderline;
    BYTE lfStrikeOut;
    BYTE lfCharSet;
    BYTE lfOutPrecision;
    BYTE lfClipPrecision;
    BYTE lfQuality;
    BYTE lfPitchAndFamily;
    CHAR lfFaceName[32];
};

typedef struct tagLOGFONTA LOGFONTA;

typedef struct _STARTUPINFOA _STARTUPINFOA, *P_STARTUPINFOA;

typedef CHAR * LPSTR;

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

typedef struct _OFSTRUCT _OFSTRUCT, *P_OFSTRUCT;

struct _OFSTRUCT {
    BYTE cBytes;
    BYTE fFixedDisk;
    WORD nErrCode;
    WORD Reserved1;
    WORD Reserved2;
    CHAR szPathName[128];
};

typedef struct _OFSTRUCT * LPOFSTRUCT;

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

typedef wchar_t WCHAR;

typedef CHAR * LPCSTR;

typedef LONG * PLONG;

typedef CHAR * LPCH;

typedef WCHAR * LPWSTR;

typedef CONTEXT * PCONTEXT;

typedef WCHAR * LPWCH;

typedef DWORD ACCESS_MASK;

typedef WCHAR * LPCWSTR;

typedef DWORD LCID;

typedef CHAR * PCNZCH;

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

typedef LPCDLGTEMPLATE PROPSHEETPAGE_RESOURCE;

typedef struct _PSP _PSP, *P_PSP;

struct _PSP {
};

typedef struct _PROPSHEETPAGEA _PROPSHEETPAGEA, *P_PROPSHEETPAGEA;

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

typedef struct HINSTANCE__ * HINSTANCE;

typedef union _union_1933 _union_1933, *P_union_1933;

typedef union _union_1934 _union_1934, *P_union_1934;

typedef UINT (* LPFNPSPCALLBACKA)(HWND, UINT, struct _PROPSHEETPAGEA *);

typedef union _union_1935 _union_1935, *P_union_1935;

typedef struct HICON__ HICON__, *PHICON__;

typedef struct HICON__ * HICON;

typedef struct HBITMAP__ HBITMAP__, *PHBITMAP__;

typedef struct HBITMAP__ * HBITMAP;

struct HBITMAP__ {
    int unused;
};

union _union_1934 {
    HICON hIcon;
    LPCSTR pszIcon;
};

union _union_1935 {
    HBITMAP hbmHeader;
    LPCSTR pszbmHeader;
};

struct HICON__ {
    int unused;
};

union _union_1933 {
    LPCSTR pszTemplate;
    PROPSHEETPAGE_RESOURCE pResource;
};

struct _PROPSHEETPAGEA {
    DWORD dwSize;
    DWORD dwFlags;
    HINSTANCE hInstance;
    union _union_1933 u;
    union _union_1934 u2;
    LPCSTR pszTitle;
    DLGPROC pfnDlgProc;
    LPARAM lParam;
    LPFNPSPCALLBACKA pfnCallback;
    UINT * pcRefParent;
    LPCSTR pszHeaderTitle;
    LPCSTR pszHeaderSubTitle;
    HANDLE hActCtx;
    union _union_1935 u3;
};

struct HINSTANCE__ {
    int unused;
};

typedef struct _PSP * HPROPSHEETPAGE;

typedef struct _PROPSHEETHEADERA_V2 _PROPSHEETHEADERA_V2, *P_PROPSHEETHEADERA_V2;

typedef struct _PROPSHEETHEADERA_V2 PROPSHEETHEADERA_V2;

typedef PROPSHEETHEADERA_V2 * LPCPROPSHEETHEADERA_V2;

typedef LPCPROPSHEETHEADERA_V2 LPCPROPSHEETHEADERA;

typedef union _union_1954 _union_1954, *P_union_1954;

typedef union _union_1955 _union_1955, *P_union_1955;

typedef union _union_1956 _union_1956, *P_union_1956;

typedef int (* PFNPROPSHEETCALLBACK)(HWND, UINT, LPARAM);

typedef union _union_1957 _union_1957, *P_union_1957;

typedef struct HPALETTE__ HPALETTE__, *PHPALETTE__;

typedef struct HPALETTE__ * HPALETTE;

typedef union _union_1958 _union_1958, *P_union_1958;

typedef struct _PROPSHEETPAGEA PROPSHEETPAGEA_V4;

typedef PROPSHEETPAGEA_V4 * LPCPROPSHEETPAGEA_V4;

typedef LPCPROPSHEETPAGEA_V4 LPCPROPSHEETPAGEA;

union _union_1956 {
    LPCPROPSHEETPAGEA ppsp;
    HPROPSHEETPAGE * phpage;
};

union _union_1957 {
    HBITMAP hbmWatermark;
    LPCSTR pszbmWatermark;
};

struct HPALETTE__ {
    int unused;
};

union _union_1958 {
    HBITMAP hbmHeader;
    LPCSTR pszbmHeader;
};

union _union_1954 {
    HICON hIcon;
    LPCSTR pszIcon;
};

union _union_1955 {
    UINT nStartPage;
    LPCSTR pStartPage;
};

struct _PROPSHEETHEADERA_V2 {
    DWORD dwSize;
    DWORD dwFlags;
    HWND hwndParent;
    HINSTANCE hInstance;
    union _union_1954 u;
    LPCSTR pszCaption;
    UINT nPages;
    union _union_1955 u2;
    union _union_1956 u3;
    PFNPROPSHEETCALLBACK pfnCallback;
    union _union_1957 u4;
    HPALETTE hplWatermark;
    union _union_1958 u5;
};

typedef struct HFONT__ HFONT__, *PHFONT__;

typedef struct HFONT__ * HFONT;

struct HFONT__ {
    int unused;
};

typedef struct tagPOINT * LPPOINT;

typedef struct HKEY__ HKEY__, *PHKEY__;

struct HKEY__ {
    int unused;
};

typedef DWORD * LPDWORD;

typedef struct HDC__ HDC__, *PHDC__;

struct HDC__ {
    int unused;
};

typedef struct tagSIZE tagSIZE, *PtagSIZE;

struct tagSIZE {
    LONG cx;
    LONG cy;
};

typedef struct HRSRC__ HRSRC__, *PHRSRC__;

struct HRSRC__ {
    int unused;
};

typedef HINSTANCE HMODULE;

typedef struct tagSIZE * LPSIZE;

typedef struct HMENU__ HMENU__, *PHMENU__;

typedef struct HMENU__ * HMENU;

struct HMENU__ {
    int unused;
};

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

typedef WORD * LPWORD;

typedef struct HKEY__ * HKEY;

typedef HKEY * PHKEY;

typedef LONG_PTR LRESULT;

typedef struct tagRECT * LPRECT;

typedef HANDLE HGLOBAL;

typedef BOOL * LPBOOL;

typedef void * HGDIOBJ;

typedef void * LPCVOID;

typedef struct HRSRC__ * HRSRC;

typedef DWORD COLORREF;

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

typedef struct StringInfo StringInfo, *PStringInfo;

struct StringInfo {
    word wLength;
    word wValueLength;
    word wType;
};

typedef LONG LSTATUS;

typedef ACCESS_MASK REGSAM;

typedef char * va_list;

typedef struct _browseinfoA _browseinfoA, *P_browseinfoA;

typedef struct _browseinfoA * LPBROWSEINFOA;

typedef int (* BFFCALLBACK)(HWND, UINT, LPARAM, LPARAM);

struct _browseinfoA {
    HWND hwndOwner;
    LPCITEMIDLIST pidlRoot;
    LPSTR pszDisplayName;
    LPCSTR lpszTitle;
    UINT ulFlags;
    BFFCALLBACK lpfn;
    LPARAM lParam;
    int iImage;
};

typedef uint size_t;




undefined4 __cdecl FUN_00401000(int param_1)

{
  int iVar1;
  undefined4 local_8;
  
  iVar1 = 0;
  local_8 = 0x4643534d;
  do {
    if ((uint)(((char *)((int)&local_8 + iVar1))[param_1 - (int)&local_8] == '\0') ==
        (int)*(char *)((int)&local_8 + iVar1)) {
      return 0;
    }
    iVar1 = iVar1 + 1;
  } while (iVar1 < 4);
  return 1;
}



int __cdecl FUN_00401050(int *param_1,uint param_2)

{
  char *pcVar1;
  char cVar2;
  int iVar3;
  uint uVar4;
  int *piVar5;
  
  iVar3 = 0;
  for (uVar4 = param_2 & 0xffff; uVar4 != 0; uVar4 = uVar4 - 1) {
    piVar5 = param_1 + 4;
    iVar3 = iVar3 + *param_1;
    cVar2 = *(char *)(param_1 + 4);
    while (cVar2 != '\0') {
      pcVar1 = (char *)((int)piVar5 + 1);
      piVar5 = (int *)((int)piVar5 + 1);
      cVar2 = *pcVar1;
    }
    param_1 = (int *)((int)piVar5 + 1);
  }
  return iVar3;
}



int __cdecl FUN_00401090(LPCSTR param_1,undefined4 *param_2)

{
  LPCSTR lpFileName;
  DWORD DVar1;
  HANDLE hFile;
  HANDLE hFileMappingObject;
  LPVOID lpBaseAddress;
  int iVar2;
  int local_8;
  
  lpFileName = param_1;
  local_8 = -1;
  *param_2 = 0xfffffff6;
  if (param_1 != (LPCSTR)0x0) {
    DVar1 = GetFileAttributesA(param_1);
    if (DVar1 != 0xffffffff) {
      hFile = CreateFileA(lpFileName,0xc0000000,1,(LPSECURITY_ATTRIBUTES)0x0,3,0x80,(HANDLE)0x0);
      if (hFile != (HANDLE)0xffffffff) {
        param_1 = (LPCSTR)0x0;
        DVar1 = GetFileSize(hFile,(LPDWORD)&param_1);
        hFileMappingObject =
             CreateFileMappingA(hFile,(LPSECURITY_ATTRIBUTES)0x0,8,(DWORD)param_1,DVar1,(LPCSTR)0x0)
        ;
        if (hFileMappingObject != (HANDLE)0x0) {
          lpBaseAddress = MapViewOfFile(hFileMappingObject,1,0,0,0);
          if (lpBaseAddress != (LPVOID)0x0) {
            iVar2 = FUN_00401000((int)lpBaseAddress);
            if (iVar2 != 0) {
              local_8 = FUN_00401050((int *)(*(int *)((int)lpBaseAddress + 0x10) +
                                            (int)lpBaseAddress),
                                     CONCAT22((short)((uint)iVar2 >> 0x10),
                                              *(undefined2 *)((int)lpBaseAddress + 0x1c)));
            }
            UnmapViewOfFile(lpBaseAddress);
            *param_2 = 0;
          }
          CloseHandle(hFileMappingObject);
        }
        CloseHandle(hFile);
      }
    }
  }
  return local_8;
}



int __cdecl FUN_00401170(LPCSTR param_1)

{
  byte bVar1;
  int iVar2;
  DWORD DVar3;
  CHAR local_108;
  char local_107;
  
  bVar1 = 0;
  lstrcpyA(&local_108,param_1);
  FUN_004053a0(&local_108);
  FUN_004053e0(&local_108);
  iVar2 = lstrlenA(&local_108);
  if (((iVar2 == 3) || (iVar2 == 2)) && (local_107 == ':')) {
    bVar1 = 1;
    FUN_00401380(&local_108);
    lstrcatA(&local_108,&DAT_00413030);
  }
  DVar3 = GetFileAttributesA(&local_108);
  if (DVar3 == 0xffffffff) {
    return bVar1 - 2;
  }
  return 2 - (uint)bVar1;
}



bool __cdecl FUN_00401220(LPCSTR param_1,uint param_2)

{
  HANDLE hFindFile;
  bool bVar1;
  _WIN32_FIND_DATAA local_144;
  
  hFindFile = FindFirstFileA(param_1,&local_144);
  bVar1 = hFindFile != (HANDLE)0xffffffff;
  if ((param_2 != 0) && (bVar1)) {
    bVar1 = (local_144.dwFileAttributes & param_2) != 0;
  }
  FindClose(hFindFile);
  return bVar1;
}



int __cdecl FUN_00401270(LPCSTR param_1)

{
  BOOL BVar1;
  DWORD local_10;
  DWORD local_c;
  DWORD local_8;
  
  BVar1 = GetDiskFreeSpaceA(param_1,&local_c,&local_8,(LPDWORD)&param_1,&local_10);
  if (BVar1 != 0) {
    return (int)param_1 * local_8 * local_c;
  }
  return 0;
}



uint __cdecl FUN_004012b0(char *param_1)

{
  char cVar1;
  uint uVar2;
  
  uVar2 = 0xf143ac;
  cVar1 = *param_1;
  while (cVar1 != '\0') {
    param_1 = param_1 + 1;
    uVar2 = uVar2 + cVar1 * 2;
    cVar1 = *param_1;
  }
  return uVar2 ^ 0x51993;
}



void __cdecl FUN_004012e0(LPCSTR param_1)

{
  int iVar1;
  
  iVar1 = lstrlenA(param_1);
  if (param_1[iVar1 + -1] == '\\') {
    param_1[iVar1 + -1] = '\0';
  }
  return;
}



void __cdecl FUN_00401300(int param_1)

{
  int iVar1;
  bool bVar2;
  tagMSG local_20;
  
  do {
    iVar1 = PeekMessageA(&local_20,(HWND)0x0,0,0,1);
    while (iVar1 != 0) {
      TranslateMessage(&local_20);
      DispatchMessageA(&local_20);
      iVar1 = PeekMessageA(&local_20,(HWND)0x0,0,0,1);
    }
    if (param_1 != 0) {
      Sleep(1000);
    }
    bVar2 = param_1 != 0;
    param_1 = param_1 + -1;
  } while (bVar2);
  return;
}



void __cdecl FUN_00401380(LPCSTR param_1)

{
  int iVar1;
  
  iVar1 = lstrlenA(param_1);
  if (param_1[iVar1 + -1] != '\\') {
    param_1[iVar1] = '\\';
    param_1[iVar1 + 1] = '\0';
  }
  return;
}



void __cdecl FUN_004013b0(uint param_1)

{
  FUN_0040ba70(param_1);
  return;
}



void __cdecl FUN_004013d0(undefined *param_1)

{
  FUN_0040bb20(param_1);
  return;
}



undefined * FUN_004013f0(void)

{
  DWORD DVar1;
  uint uVar2;
  
  DVar1 = GetLastError();
  DVar1 = FormatMessageA(0x1000,(LPCVOID)0x0,DVar1,0x409,&DAT_00416118,0xff,(va_list *)0x0);
  if (DVar1 != 0) {
    while (DVar1 - 1 != 0) {
      if (DAT_0041379c < 2) {
        uVar2 = (byte)PTR_DAT_00413590[(char)(&DAT_00416117)[DVar1] * 2] & 8;
      }
      else {
        uVar2 = FUN_0040bb70((int)(char)(&DAT_00416117)[DVar1],8);
      }
      if (uVar2 == 0) break;
      (&DAT_00416117)[DVar1] = 0;
      DVar1 = DVar1 - 1;
    }
  }
  return &DAT_00416118;
}



HANDLE __cdecl FUN_00401470(LPCSTR param_1,uint param_2)

{
  int iVar1;
  HANDLE pvVar2;
  LPCSTR lpText;
  DWORD dwDesiredAccess;
  DWORD dwCreationDisposition;
  UINT uType;
  
  dwDesiredAccess = 0xc0000000;
  dwCreationDisposition = 4;
  if (param_2 == 0) {
    dwDesiredAccess = 0x80000000;
  }
  else if (param_2 == 2) {
    dwDesiredAccess = 0xc0000000;
    dwCreationDisposition = 4;
  }
  else if (param_2 == 1) {
    dwDesiredAccess = 0x40000000;
    dwCreationDisposition = 2;
  }
  if ((param_2 & 0x300) != 0) {
    dwCreationDisposition = 2;
  }
  if (param_1 != (LPCSTR)0x0) {
    iVar1 = lstrlenA(param_1);
    if ((((3 < iVar1) && (param_1[1] == ':')) && (param_1[2] == '\\')) && (param_1[3] == '\\')) {
      lstrcpyA(param_1 + 3,param_1 + 4);
    }
  }
  pvVar2 = CreateFileA(param_1,dwDesiredAccess,3,(LPSECURITY_ATTRIBUTES)0x0,dwCreationDisposition,
                       0x80,(HANDLE)0x0);
  if (pvVar2 == (HANDLE)0xffffffff) {
    uType = 0;
    lpText = FUN_004013f0();
    MessageBoxA((HWND)0x0,lpText,param_1,uType);
    pvVar2 = (HANDLE)0xffffffff;
  }
  return pvVar2;
}



DWORD __cdecl FUN_00401520(HANDLE param_1,LPVOID param_2,DWORD param_3)

{
  ReadFile(param_1,param_2,param_3,&param_3,(LPOVERLAPPED)0x0);
  return param_3;
}



DWORD __cdecl FUN_00401540(HANDLE param_1,LPCVOID param_2,DWORD param_3)

{
  WriteFile(param_1,param_2,param_3,&param_3,(LPOVERLAPPED)0x0);
  return param_3;
}



void __cdecl FUN_00401560(HANDLE param_1)

{
  CloseHandle(param_1);
  return;
}



void __cdecl FUN_00401570(HANDLE param_1,LONG param_2,DWORD param_3)

{
  SetFilePointer(param_1,param_2,(PLONG)0x0,param_3);
  return;
}



int __cdecl FUN_00401590(HANDLE param_1)

{
  int iVar1;
  ushort uVar2;
  undefined local_130 [6];
  ushort local_12a;
  uint local_11c;
  undefined local_6c [60];
  LONG local_30;
  undefined local_2c [16];
  int local_1c;
  int local_18;
  
  if (param_1 != (HANDLE)0xffffffff) {
    iVar1 = 0;
    FUN_00401520(param_1,local_6c,0x40);
    FUN_00401570(param_1,local_30,0);
    FUN_00401520(param_1,local_130,0x18);
    FUN_00401570(param_1,local_11c & 0xffff,1);
    uVar2 = 0;
    if (local_12a != 0) {
      do {
        FUN_00401520(param_1,local_2c,0x28);
        if (uVar2 == 0) {
          iVar1 = local_18;
        }
        iVar1 = iVar1 + local_1c;
        uVar2 = uVar2 + 1;
      } while (uVar2 < local_12a);
    }
    return iVar1;
  }
  return 0;
}



bool __cdecl FUN_00401640(LPSTR param_1,char *param_2)

{
  char *pcVar1;
  char *pcVar2;
  
  pcVar1 = _strpbrk(param_2,&DAT_00413034);
  if (pcVar1 != (char *)0x0) {
    lstrcpyA(param_1,param_2);
    pcVar2 = _strrchr(param_1,0x5c);
    pcVar1 = _strrchr(param_1,0x2f);
    if (pcVar1 < pcVar2) {
      pcVar1 = pcVar2;
    }
    *pcVar1 = '\0';
    return pcVar1[-1] != ':';
  }
  return false;
}



undefined __cdecl FUN_004016a0(LPCSTR param_1)

{
  bool bVar1;
  BOOL BVar2;
  DWORD DVar3;
  undefined3 extraout_var;
  int iVar4;
  CHAR local_108 [260];
  
  BVar2 = CreateDirectoryA(param_1,(LPSECURITY_ATTRIBUTES)0x0);
  if (BVar2 == 0) {
    DVar3 = GetLastError();
    if (DVar3 != 0xb7) {
      if (DVar3 == 5) {
        return 7;
      }
      bVar1 = FUN_00401640(local_108,param_1);
      if (CONCAT31(extraout_var,bVar1) != 0) {
        iVar4 = FUN_004016a0(local_108);
        if (iVar4 == 0) {
          BVar2 = CreateDirectoryA(param_1,(LPSECURITY_ATTRIBUTES)0x0);
          return BVar2 == 0;
        }
      }
      return true;
    }
  }
  return false;
}



LPSTR __cdecl FUN_00401730(LPSTR param_1,LPCSTR param_2,LPCSTR param_3)

{
  bool bVar1;
  char *pcVar2;
  undefined3 extraout_var;
  CHAR *lpString2;
  CHAR local_108 [260];
  
  lstrcpyA(local_108,param_3);
  pcVar2 = _strrchr(local_108,0x5c);
  if (pcVar2 == (char *)0x0) {
    lpString2 = local_108;
  }
  else {
    *pcVar2 = '\0';
    lpString2 = pcVar2 + 1;
  }
  lstrcpyA(param_1,param_2);
  if ((DAT_0041774c != 0) && ((DAT_00417758 & 1) != 0)) {
    if (lpString2 != local_108) {
      lstrcatA(param_1,local_108);
      FUN_00404fe0(param_1,(int)param_1,'\\');
    }
    bVar1 = FUN_00401220(param_1,0x10);
    if (CONCAT31(extraout_var,bVar1) == 0) {
      FUN_004016a0(param_1);
    }
    FUN_00401380(param_1);
  }
  lstrcatA(param_1,lpString2);
  return param_1;
}



DWORD __cdecl FUN_004017f0(LPCSTR param_1,undefined4 param_2,LPSTR param_3,DWORD param_4)

{
  DWORD DVar1;
  CHAR local_c [8];
  
  if (DAT_00417734 != (LPCSTR)0x0) {
    wsprintfA(local_c,&DAT_00413038,param_2);
    DVar1 = GetPrivateProfileStringA(param_1,local_c,&DAT_00416254,param_3,param_4,DAT_00417734);
    return DVar1;
  }
  return 0;
}



undefined4 __cdecl FUN_00401850(HWND param_1,undefined4 param_2,int param_3)

{
  HWND hWnd;
  DWORD DVar1;
  HWND hWnd_00;
  LONG LVar2;
  UINT Msg;
  WPARAM wParam;
  LPSTR lParam;
  char local_11c [260];
  CHAR local_18 [20];
  
  hWnd = GetWindow(param_1,5);
  wsprintfA(local_18,s_Dialog_d_0041303c,param_2);
  DVar1 = FUN_004017f0(local_18,0,local_11c,0x104);
  if (DVar1 == 0) {
    GetWindowTextA(param_1,local_11c,0x104);
  }
  if ((local_11c[0] != '\0') && (SetWindowTextA(param_1,local_11c), param_3 != 0)) {
    lParam = local_11c;
    if (DAT_0041776c != 0) {
      wsprintfA(DAT_00417768,s__s____s_00413048,DAT_0041776c);
      lParam = DAT_00417768;
    }
    wParam = 0;
    Msg = 0x46f;
    hWnd_00 = GetParent(param_1);
    SendMessageA(hWnd_00,Msg,wParam,(LPARAM)lParam);
  }
  for (; hWnd != (HWND)0x0; hWnd = GetWindow(hWnd,2)) {
    LVar2 = GetWindowLongA(hWnd,-0xc);
    FUN_00404e50(param_1,LVar2);
    DVar1 = FUN_004017f0(local_18,LVar2,DAT_00417768,0x104);
    if (DVar1 != 0) {
      SetWindowTextA(hWnd,DAT_00417768);
    }
  }
  return 0;
}



undefined4 FUN_00401970(HWND param_1,int param_2,INT_PTR param_3,LPCSTR param_4)

{
  if (param_2 == 0x110) {
    FUN_00401850(param_1,0x3ec,0);
    SetDlgItemTextA(param_1,0x3f8,param_4);
  }
  else if (param_2 == 0x111) {
    EndDialog(param_1,param_3);
    return 1;
  }
  return 0;
}



void __cdecl FUN_004019d0(LPSTR param_1)

{
  char *pcVar1;
  DWORD DVar2;
  CHAR local_38 [52];
  
  if ((DAT_0041772c == (HWND)0x0) || (DAT_0041621c != 0)) goto LAB_00401a85;
  pcVar1 = _strrchr(param_1,0x5c);
  if (pcVar1 != (char *)0x0) {
    param_1 = CharNextA(pcVar1);
  }
  if (DAT_00417734 == 0) {
LAB_00401a3c:
    pcVar1 = s_Unpacking___s__0041305c;
  }
  else {
    DVar2 = FUN_004017f0(s_Dialog1005_00413050,0,local_38,0x32);
    if (DVar2 == 0) goto LAB_00401a3c;
    pcVar1 = local_38;
  }
  wsprintfA(DAT_00417768,pcVar1,param_1);
  SetDlgItemTextA(DAT_0041772c,0x405,DAT_00417768);
  SendDlgItemMessageA(DAT_0041772c,0x3f0,0x405,0,0);
LAB_00401a85:
  DAT_00417764 = DAT_00417764 + 1;
  return;
}



undefined __cdecl FUN_00401a90(LPARAM param_1,undefined4 *param_2)

{
  INT_PTR IVar1;
  undefined4 uVar2;
  
  IVar1 = DialogBoxParamA(DAT_004177c8,(LPCSTR)0x3ec,DAT_0041772c,FUN_00401970,param_1);
  *param_2 = 0;
  if (IVar1 == 2) {
    DAT_0041621c = 1;
  }
  else {
    if ((IVar1 < 0x6e) || (IVar1 == 0x6f)) {
      uVar2 = 1;
    }
    else {
      uVar2 = 0;
    }
    *param_2 = uVar2;
  }
  if (IVar1 == 0x6f) {
    return 2;
  }
  return IVar1 == 0x70;
}



undefined4 __cdecl FUN_00401b00(LPCSTR param_1,int param_2)

{
  HANDLE hFile;
  BOOL BVar1;
  _FILETIME local_14;
  _FILETIME local_c;
  
  hFile = FUN_00401470(param_1,0x8000);
  if (hFile != (HANDLE)0xffffffff) {
    BVar1 = DosDateTimeToFileTime(*(WORD *)(param_2 + 0x18),*(WORD *)(param_2 + 0x1a),&local_14);
    if (BVar1 != 0) {
      BVar1 = LocalFileTimeToFileTime(&local_14,&local_c);
      if (BVar1 != 0) {
        SetFileTime(hFile,&local_c,(FILETIME *)0x0,&local_c);
      }
    }
    CloseHandle(hFile);
  }
  SetFileAttributesA(param_1,*(byte *)(param_2 + 0x1c) & 0x27);
  return 0;
}



HANDLE __cdecl FUN_00401b90(undefined4 param_1,uint *param_2)

{
  bool bVar1;
  uint uVar2;
  LPSTR pCVar3;
  HANDLE pvVar4;
  undefined3 extraout_var;
  DWORD DVar5;
  CHAR local_10c [260];
  int local_8;
  
  FUN_00401300(0);
  switch(param_1) {
  case 1:
    DAT_0041622c = 0x133;
    return (HANDLE)0xffffffff;
  case 2:
    break;
  case 3:
    FUN_004019d0((LPSTR)param_2[1]);
    FUN_00401730(local_10c,DAT_0041779c,(LPCSTR)param_2[1]);
    FUN_00401560((HANDLE)param_2[5]);
    FUN_00401b00(local_10c,(int)param_2);
    return (HANDLE)0x1;
  case 4:
    wsprintfA((LPSTR)param_2[3],s__spftw_d_pkg_0041306c,DAT_00417738,(uint)*(ushort *)(param_2 + 8))
    ;
    return (HANDLE)0x0;
  default:
    return (HANDLE)0x64;
  }
  if (((*DAT_004177d8 != '\0') && (uVar2 = FUN_00401270(DAT_004177d8), uVar2 != 0)) &&
     (uVar2 < *param_2)) {
    DAT_0041622c = 0x22;
    return (HANDLE)0xffffffff;
  }
  pCVar3 = FUN_00401730(local_10c,DAT_0041779c,(LPCSTR)param_2[1]);
  if (pCVar3 == (LPSTR)0x0) {
    DAT_0041622c = 0x2c;
    return (HANDLE)0xffffffff;
  }
  if ((DAT_00416248 != (code *)0x0) &&
     (pvVar4 = (HANDLE)(*DAT_00416248)(local_10c), pvVar4 != (HANDLE)0x1)) {
    return pvVar4;
  }
  bVar1 = FUN_00401220(local_10c,0);
  if (CONCAT31(extraout_var,bVar1) != 0) {
    if (DAT_00417728 == 0) {
      DAT_00417728 = FUN_00401a90((LPARAM)local_10c,&local_8);
      if (DAT_0041621c != 0) {
        return (HANDLE)0xffffffff;
      }
      if (local_8 == 0) {
        return (HANDLE)0x0;
      }
    }
    else if (DAT_00417728 == 1) {
      return (HANDLE)0x0;
    }
  }
  if (DAT_0041621c != 0) {
    return (HANDLE)0xffffffff;
  }
  DVar5 = GetFileAttributesA(local_10c);
  SetFileAttributesA(local_10c,DVar5 & 0xfffffffe);
  pvVar4 = FUN_00401470(local_10c,0x8101);
  return pvVar4;
}



undefined4 __cdecl FUN_00401d90(char *param_1)

{
  char *pcVar1;
  char cVar2;
  uint uVar3;
  char *pcVar4;
  char *pcVar5;
  
  pcVar5 = (char *)0x0;
  cVar2 = *param_1;
  do {
    if (cVar2 == '\0') {
      if (pcVar5 != (char *)0x0) {
        *pcVar5 = '\0';
      }
      return 0;
    }
    if (((pcVar5 == (char *)0x0) && (cVar2 == '/')) || (pcVar4 = param_1, cVar2 == '-')) {
      pcVar4 = param_1 + 1;
      switch(param_1[1]) {
      case 'A':
      case 'a':
        pcVar5 = (char *)FUN_0040ba70(0x104);
        pcVar4 = param_1 + 2;
        cVar2 = *pcVar4;
        DAT_0041773c = pcVar5;
        while (cVar2 != '\0') {
          if (DAT_0041379c < 2) {
            uVar3 = (byte)PTR_DAT_00413590[cVar2 * 2] & 8;
          }
          else {
            uVar3 = FUN_0040bb70((int)cVar2,8);
          }
          if (uVar3 == 0) break;
          pcVar1 = pcVar4 + 1;
          pcVar4 = pcVar4 + 1;
          cVar2 = *pcVar1;
        }
        break;
      case 'S':
      case 's':
        DAT_00416220 = 1;
        DAT_00417728 = 2;
      }
    }
    if (pcVar5 != (char *)0x0) {
      *pcVar5 = *pcVar4;
      pcVar5 = pcVar5 + 1;
    }
    cVar2 = pcVar4[1];
    param_1 = pcVar4 + 1;
  } while( true );
}



void __cdecl FUN_00401ea0(undefined4 *param_1,uint param_2)

{
  undefined4 *puVar1;
  uint uVar2;
  undefined4 *puVar3;
  
  puVar1 = (undefined4 *)FUN_0040ba70(param_2 + 1);
  puVar3 = puVar1;
  for (uVar2 = param_2 >> 2; uVar2 != 0; uVar2 = uVar2 - 1) {
    *puVar3 = *param_1;
    param_1 = param_1 + 1;
    puVar3 = puVar3 + 1;
  }
  for (uVar2 = param_2 & 3; uVar2 != 0; uVar2 = uVar2 - 1) {
    *(undefined *)puVar3 = *(undefined *)param_1;
    param_1 = (undefined4 *)((int)param_1 + 1);
    puVar3 = (undefined4 *)((int)puVar3 + 1);
  }
  *(undefined *)((int)puVar1 + param_2) = 0;
  return;
}



undefined4 __cdecl FUN_00401ee0(byte param_1)

{
  if ((((DAT_00416240 != (HMODULE)0x0) &&
       (((param_1 & 1) == 0 ||
        (DAT_00416244 = GetProcAddress(DAT_00416240,s_PackageStartup_0041307c),
        DAT_00416244 != (FARPROC)0x0)))) &&
      (((param_1 & 2) == 0 ||
       (DAT_00416248 = GetProcAddress(DAT_00416240,s_UnpackFile_0041308c),
       DAT_00416248 != (FARPROC)0x0)))) &&
     (((param_1 & 4) == 0 ||
      (DAT_0041624c = GetProcAddress(DAT_00416240,s_PackageShutdown_00413098),
      DAT_0041624c != (FARPROC)0x0)))) {
    return 0;
  }
  return 0x30;
}



undefined4 FUN_00401f60(void)

{
  if (DAT_00416240 != (HMODULE)0x0) {
    if (DAT_0041624c != (code *)0x0) {
      (*DAT_0041624c)();
    }
    FreeLibrary(DAT_00416240);
    DeleteFileA(DAT_0041623c);
  }
  return 0;
}



LONG __cdecl FUN_00401f90(LPSTR param_1,LPCVOID param_2,DWORD param_3)

{
  HANDLE pvVar1;
  INT hfSource;
  INT hfDest;
  LONG LVar2;
  _OFSTRUCT local_218;
  _OFSTRUCT local_190;
  CHAR local_108 [260];
  
  GetTempFileNameA(DAT_00417794,&DAT_004130a8,0,local_108);
  pvVar1 = FUN_00401470(local_108,0x8101);
  if (pvVar1 != (HANDLE)0xffffffff) {
    FUN_00401540(pvVar1,param_2,param_3);
    FUN_00401560(pvVar1);
    hfSource = LZOpenFileA(local_108,&local_218,0);
    hfDest = LZOpenFileA(param_1,&local_190,0x1001);
    LVar2 = LZCopy(hfSource,hfDest);
    LZClose(hfSource);
    LZClose(hfDest);
    DeleteFileA(local_108);
    return LVar2;
  }
  return 0;
}



bool __cdecl FUN_00402060(LPCVOID param_1,DWORD param_2)

{
  LONG LVar1;
  
  DAT_0041623c = (LPSTR)FUN_0040ba70(0x104);
  lstrcpyA(DAT_0041623c,DAT_00417794);
  lstrcatA(DAT_0041623c,s_ext_dll_004130ac);
  LVar1 = FUN_00401f90(DAT_0041623c,param_1,param_2);
  if (LVar1 != 0) {
    DAT_00416240 = LoadLibraryA(DAT_0041623c);
  }
  return DAT_00416240 == (HMODULE)0x0;
}



undefined4 __cdecl FUN_004020d0(LPCVOID param_1,DWORD param_2)

{
  DWORD DVar1;
  HANDLE pvVar2;
  CHAR local_108 [260];
  
  GetTempFileNameA(DAT_00417794,s_welcome_004130b4,0,local_108);
  DVar1 = FUN_00401f90(local_108,param_1,param_2);
  if (0 < (int)DVar1) {
    pvVar2 = FUN_00401470(local_108,0x8000);
    DAT_00417724 = (LPVOID)FUN_0040ba70(DVar1 + 1);
    FUN_00401520(pvVar2,DAT_00417724,DVar1);
    FUN_00401560(pvVar2);
    DeleteFileA(local_108);
    return 0;
  }
  return 0xffffffff;
}



undefined4 __cdecl FUN_00402170(LPCVOID param_1,DWORD param_2)

{
  LONG LVar1;
  
  DAT_00417734 = (LPSTR)FUN_0040ba70(0x104);
  GetTempFileNameA(DAT_00417794,&DAT_004130bc,0,DAT_00417734);
  LVar1 = FUN_00401f90(DAT_00417734,param_1,param_2);
  if (LVar1 == 0) {
    MessageBoxA((HWND)0x0,s_LoadLanguage_Failed_004130c8,s_Error_004130c0,0);
    FUN_0040bb20(DAT_00417734);
    DAT_00417734 = (LPSTR)0x0;
  }
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_004021f0(void)

{
  char cVar1;
  bool bVar2;
  LSTATUS LVar3;
  uint uVar4;
  DWORD DVar5;
  undefined3 extraout_var;
  int iVar6;
  undefined4 *puVar7;
  undefined4 *puVar8;
  DWORD local_10;
  HKEY local_c;
  DWORD local_8;
  
  LVar3 = RegOpenKeyExA((HKEY)0x80000002,s_SOFTWARE_Microsoft_Windows_Curre_004130dc,0,0x20019,
                        &local_c);
  if (LVar3 == 0) {
    local_8 = 0x104;
    local_10 = 1;
    RegQueryValueExA(local_c,s_ProgramFilesDir_00413108,(LPDWORD)0x0,&local_10,(LPBYTE)DAT_00417768,
                     &local_8);
    uVar4 = lstrlenA((LPCSTR)DAT_00417768);
    _DAT_00417780 = FUN_00401ea0(DAT_00417768,uVar4);
    local_8 = 0x104;
    RegQueryValueExA(local_c,s_CommonFilesDir_00413118,(LPDWORD)0x0,&local_10,(LPBYTE)DAT_00417768,
                     &local_8);
    uVar4 = lstrlenA((LPCSTR)DAT_00417768);
    _DAT_00417784 = FUN_00401ea0(DAT_00417768,uVar4);
    RegCloseKey(local_c);
  }
  GetLastError();
  GetWindowsDirectoryA((LPSTR)DAT_00417768,0x104);
  uVar4 = lstrlenA((LPCSTR)DAT_00417768);
  DAT_00417788 = (LPCSTR)FUN_00401ea0(DAT_00417768,uVar4);
  iVar6 = -1;
  puVar7 = DAT_00417768;
  do {
    puVar8 = puVar7;
    if (iVar6 == 0) break;
    iVar6 = iVar6 + -1;
    puVar8 = (undefined4 *)((int)puVar7 + 1);
    cVar1 = *(char *)puVar7;
    puVar7 = puVar8;
  } while (cVar1 != '\0');
  *(undefined4 *)((int)puVar8 + -1) = s__SYSTEM32_00413128._0_4_;
  *(undefined4 *)((int)puVar8 + 3) = s__SYSTEM32_00413128._4_4_;
  *(undefined2 *)((int)puVar8 + 7) = s__SYSTEM32_00413128._8_2_;
  uVar4 = lstrlenA((LPCSTR)DAT_00417768);
  _DAT_00417790 = FUN_00401ea0(DAT_00417768,uVar4);
  GetSystemDirectoryA((LPSTR)DAT_00417768,0x104);
  uVar4 = lstrlenA((LPCSTR)DAT_00417768);
  _DAT_0041778c = FUN_00401ea0(DAT_00417768,uVar4);
  DVar5 = GetTempPathA(0x104,(LPSTR)DAT_00417768);
  if (*(char *)((DVar5 - 1) + (int)DAT_00417768) == '\\') {
    *(undefined *)((DVar5 - 1) + (int)DAT_00417768) = 0;
  }
  bVar2 = FUN_00401220((LPCSTR)DAT_00417768,0x10);
  if (CONCAT31(extraout_var,bVar2) != 0) {
    uVar4 = lstrlenA((LPCSTR)DAT_00417768);
    DAT_00417794 = FUN_00401ea0(DAT_00417768,uVar4);
    return;
  }
  lstrcpyA((LPSTR)DAT_00417768,DAT_00417788);
  lstrcatA((LPSTR)DAT_00417768,s__TEMP_00413134);
  uVar4 = lstrlenA((LPCSTR)DAT_00417768);
  DAT_00417794 = FUN_00401ea0(DAT_00417768,uVar4);
  FUN_004016a0((LPCSTR)DAT_00417768);
  return;
}



void __cdecl FUN_00402420(byte *param_1,int param_2)

{
  byte bVar1;
  byte bVar2;
  
  bVar1 = 0x61;
  if (param_2 != 0) {
    do {
      bVar2 = *param_1 ^ bVar1;
      bVar1 = bVar1 + 1;
      *param_1 = bVar2;
      param_1 = param_1 + 1;
      if ('z' < (char)bVar1) {
        bVar1 = 0x61;
      }
      param_2 = param_2 + -1;
    } while (param_2 != 0);
  }
  return;
}



void __cdecl FUN_00402450(char *param_1,undefined4 *param_2)

{
  char cVar1;
  uint uVar2;
  undefined4 *puVar3;
  uint uVar4;
  char *pcVar5;
  char *pcVar6;
  char *pcVar7;
  undefined4 *puVar8;
  undefined4 *local_8;
  
  cVar1 = *param_1;
  puVar3 = param_2;
  local_8 = param_2;
  do {
    if (cVar1 == '\0') {
      do {
        do {
          *(undefined *)puVar3 = 0;
          cVar1 = *(char *)((int)puVar3 + -1);
          puVar3 = (undefined4 *)((int)puVar3 + -1);
        } while (cVar1 == '\\');
        if (DAT_0041379c < 2) {
          uVar2 = (byte)PTR_DAT_00413590[cVar1 * 2] & 8;
        }
        else {
          uVar2 = FUN_0040bb70((int)cVar1,8);
        }
      } while (uVar2 != 0);
      cVar1 = *(char *)param_2;
      while (cVar1 != '\0') {
        if ((*(char *)param_2 == '\\') && (*(char *)((int)param_2 + 1) == '\\')) {
          lstrcpyA((LPSTR)param_2,(LPCSTR)((int)param_2 + 1));
        }
        pcVar5 = (char *)((int)param_2 + 1);
        param_2 = (undefined4 *)((int)param_2 + 1);
        cVar1 = *pcVar5;
      }
      return;
    }
    pcVar5 = param_1;
    if (cVar1 == '%') {
      if (DAT_0041379c < 2) {
        uVar2 = (byte)PTR_DAT_00413590[param_1[1] * 2] & 4;
      }
      else {
        uVar2 = FUN_0040bb70((int)param_1[1],4);
      }
      if (uVar2 != 0) {
        pcVar5 = *(char **)(&DAT_004176bc + param_1[1] * 4);
        if (pcVar5 != (char *)0x0) {
          uVar2 = 0xffffffff;
          pcVar6 = pcVar5;
          do {
            pcVar7 = pcVar6;
            if (uVar2 == 0) break;
            uVar2 = uVar2 - 1;
            pcVar7 = pcVar6 + 1;
            cVar1 = *pcVar6;
            pcVar6 = pcVar7;
          } while (cVar1 != '\0');
          uVar2 = ~uVar2;
          puVar3 = (undefined4 *)(pcVar7 + -uVar2);
          puVar8 = local_8;
          for (uVar4 = uVar2 >> 2; uVar4 != 0; uVar4 = uVar4 - 1) {
            *puVar8 = *puVar3;
            puVar3 = puVar3 + 1;
            puVar8 = puVar8 + 1;
          }
          for (uVar2 = uVar2 & 3; uVar2 != 0; uVar2 = uVar2 - 1) {
            *(undefined *)puVar8 = *(undefined *)puVar3;
            puVar3 = (undefined4 *)((int)puVar3 + 1);
            puVar8 = (undefined4 *)((int)puVar8 + 1);
          }
          uVar2 = 0xffffffff;
          do {
            if (uVar2 == 0) break;
            uVar2 = uVar2 - 1;
            cVar1 = *pcVar5;
            pcVar5 = pcVar5 + 1;
          } while (cVar1 != '\0');
          puVar3 = (undefined4 *)((int)local_8 + (~uVar2 - 1));
          local_8 = puVar3;
        }
        pcVar5 = param_1 + 1;
        if (param_1[2] == '%') {
          pcVar5 = param_1 + 2;
        }
      }
    }
    else {
      *(char *)puVar3 = cVar1;
      puVar3 = (undefined4 *)((int)puVar3 + 1);
      local_8 = puVar3;
    }
    cVar1 = pcVar5[1];
    param_1 = pcVar5 + 1;
  } while( true );
}



undefined4 __cdecl FUN_00402580(int param_1,char *param_2,int param_3)

{
  int iVar1;
  int iVar2;
  
  iVar1 = 0;
  if (param_3 < 1) {
    return 0;
  }
  iVar2 = param_1 - (int)param_2;
  do {
    if (param_2[iVar2] != *param_2) {
      return 1;
    }
    iVar1 = iVar1 + 1;
    param_2 = param_2 + 1;
  } while (iVar1 < param_3);
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 __cdecl FUN_004025c0(int param_1,int param_2)

{
  byte bVar1;
  bool bVar2;
  int iVar3;
  undefined3 extraout_var;
  DWORD DVar4;
  uint uVar5;
  uint uVar6;
  undefined4 *puVar7;
  undefined4 *puVar8;
  char *pcVar9;
  undefined *puVar10;
  CHAR local_40 [52];
  uint local_c;
  undefined4 local_8;
  
  local_8 = 0;
  iVar3 = FUN_00402580(param_1,&DAT_0041313c,3);
  if (iVar3 == 0) {
    DAT_004177a4 = (uint)*(byte *)(param_1 + 3);
    puVar7 = (undefined4 *)(param_1 + 4);
    DAT_0041775c = 0;
    DAT_00416238 = FUN_0040ba70(DAT_004177a4 << 2);
    iVar3 = 0;
    puVar8 = puVar7;
    if (0 < (int)DAT_004177a4) {
      do {
        puVar7 = puVar8 + 1;
        *(undefined4 *)(DAT_00416238 + iVar3 * 4) = *puVar8;
        DAT_0041775c = DAT_0041775c + *(int *)(DAT_00416238 + iVar3 * 4);
        iVar3 = iVar3 + 1;
        puVar8 = puVar7;
      } while (iVar3 < (int)DAT_004177a4);
    }
    iVar3 = (int)puVar7 - param_1;
    while (iVar3 < param_2) {
      bVar1 = *(byte *)puVar7;
      uVar6 = bVar1 & 0x80;
      if ((bVar1 & 0x80) == 0) {
        uVar5 = (uint)*(ushort *)((int)puVar7 + 1);
        puVar7 = (undefined4 *)((int)puVar7 + 3);
      }
      else {
        uVar5 = (uint)*(byte *)(ushort *)((int)puVar7 + 1);
        puVar7 = (undefined4 *)((int)puVar7 + 2);
      }
      local_c = uVar6;
      switch((uint)bVar1) {
      case 1:
        DAT_004177dc = FUN_00401ea0(puVar7,uVar5);
        break;
      case 2:
        DAT_004177c4 = FUN_00401ea0(puVar7,uVar5);
        break;
      case 3:
        DAT_00417760 = FUN_00401ea0(puVar7,uVar5);
        break;
      case 4:
        DAT_0041776c = (undefined *)FUN_00401ea0(puVar7,uVar5);
        break;
      case 5:
        DAT_00417750 = FUN_00401ea0(puVar7,uVar5);
        break;
      case 6:
        DAT_00417748 = FUN_00401ea0(puVar7,uVar5);
        break;
      case 7:
        DAT_0041771c = FUN_00401ea0(puVar7,uVar5);
        break;
      case 8:
        DAT_004177ac = FUN_00401ea0(puVar7,uVar5);
        break;
      case 9:
        pcVar9 = (char *)FUN_00401ea0(puVar7,uVar5);
        DAT_004177d4 = (undefined4 *)FUN_0040ba70(0x104);
        *(undefined *)DAT_004177d4 = 0;
        FUN_00402450(pcVar9,DAT_004177d4);
        FUN_0040bb20(pcVar9);
        uVar6 = local_c;
        break;
      case 10:
        DAT_004177b0 = FUN_00401ea0(puVar7,uVar5);
        break;
      case 0xb:
        DAT_00417744 = FUN_00401ea0(puVar7,uVar5);
        break;
      case 0xc:
        DAT_00417798 = (byte *)FUN_00401ea0(puVar7,uVar5);
        DAT_00416234 = FUN_0040bf10(DAT_00417798,(byte **)0x0,0x10);
        break;
      case 0xd:
        DAT_0041774c = FUN_00401ea0(puVar7,uVar5);
        break;
      case 0xe:
        bVar2 = FUN_00402060(puVar7,uVar5);
        local_8 = CONCAT31(extraout_var,bVar2);
        break;
      case 0xf:
        FUN_00402170(puVar7,uVar5);
        break;
      case 0x10:
        local_8 = FUN_004020d0(puVar7,uVar5);
        break;
      case 0x11:
        DAT_004177a0 = FUN_00401ea0(puVar7,uVar5);
        break;
      case 0x94:
        DAT_00417730 = uVar5;
        break;
      case 0x95:
        _DAT_00417758 = uVar5;
        break;
      case 0x96:
        DAT_004177b8 = uVar5;
        break;
      case 0x97:
        DAT_004177b4 = uVar5;
        break;
      case 0x98:
        local_8 = FUN_00401ee0((byte)uVar5);
      }
      if (uVar6 == 0) {
        puVar7 = (undefined4 *)((int)puVar7 + uVar5);
      }
      iVar3 = (int)puVar7 - param_1;
    }
    if (((DAT_0041776c == (undefined *)0x0) || (DAT_00417734 == 0)) ||
       (DVar4 = FUN_004017f0(s_Strings_00413140,0x32,local_40,0x32), DVar4 == 0)) {
      if (DAT_0041776c == (undefined *)0x0) {
        puVar10 = &DAT_00416258;
        pcVar9 = &DAT_00413158;
      }
      else {
        pcVar9 = s_Unpacking__s____00413148;
        puVar10 = DAT_0041776c;
      }
    }
    else {
      pcVar9 = local_40;
      puVar10 = DAT_0041776c;
    }
    wsprintfA(DAT_00417768,pcVar9,puVar10);
    SetWindowTextA(DAT_0041772c,DAT_00417768);
    return local_8;
  }
  return 0xe;
}



HWND __cdecl FUN_00402a00(HWND param_1)

{
  HWND hWnd;
  int iVar1;
  CHAR local_18 [20];
  
  hWnd = GetWindow(param_1,5);
  while ((hWnd != (HWND)0x0 &&
         ((iVar1 = GetClassNameA(hWnd,local_18,0x14), iVar1 == 0 ||
          (iVar1 = lstrcmpA(local_18,s_Static_0041315c), iVar1 != 0))))) {
    hWnd = GetWindow(hWnd,2);
  }
  return hWnd;
}



void __cdecl FUN_00402a60(int param_1)

{
  int iVar1;
  LOGFONTA *pLVar2;
  LOGFONTA local_40;
  
  pLVar2 = &local_40;
  for (iVar1 = 0xf; iVar1 != 0; iVar1 = iVar1 + -1) {
    pLVar2->lfHeight = 0;
    pLVar2 = (LOGFONTA *)&pLVar2->lfWidth;
  }
  local_40.lfWeight = -(uint)(param_1 != 0) & 700;
  local_40.lfHeight = 0xd;
  local_40.lfItalic = '\0';
  local_40.lfPitchAndFamily = ' ';
  CreateFontIndirectA(&local_40);
  return;
}



void FUN_00402aa0(undefined4 param_1,int param_2,undefined4 param_3,int param_4)

{
  HDC hdc;
  HINSTANCE pHVar1;
  HGDIOBJ pvVar2;
  DWORD DVar3;
  
  if (param_2 == 0x2b) {
    hdc = *(HDC *)(param_4 + 0x18);
    SetBkMode(hdc,2);
    pvVar2 = (HGDIOBJ)FUN_00402a60(0);
    pvVar2 = SelectObject(hdc,pvVar2);
    DVar3 = GetSysColor(0x14);
    SetTextColor(hdc,DVar3);
    TextOutA(hdc,5,1,s_InstallShield_00413164,0xd);
    SetBkMode(hdc,1);
    DVar3 = GetSysColor(0x10);
    SetTextColor(hdc,DVar3);
    TextOutA(hdc,4,0,s_InstallShield_00413174,0xd);
    pvVar2 = SelectObject(hdc,pvVar2);
    DeleteObject(pvVar2);
  }
  else if ((param_2 == 0x111) && ((short)param_3 == 0x3ff)) {
    LoadStringA(DAT_004177c8,0x13,DAT_00417768,0x104);
    pHVar1 = ShellExecuteA((HWND)0x0,&DAT_00413184,DAT_00417768,&DAT_00416260,&DAT_0041625c,1);
    if ((int)pHVar1 < 0x21) {
      MessageBeep(0xffffffff);
    }
  }
  (*DAT_00416230)(param_1,param_2,param_3,param_4);
  return;
}



void __cdecl FUN_00402bc0(HWND param_1)

{
  HWND hWnd;
  uint uVar1;
  HWND hWnd_00;
  int iVar2;
  int iVar3;
  tagRECT local_38;
  tagRECT local_28;
  tagRECT local_18;
  uint local_8;
  
  local_8 = GetWindowLongA(param_1,-0x10);
  local_8 = local_8 & 0x40000000;
  if (local_8 == 0) {
    hWnd = GetWindow(param_1,4);
  }
  else {
    hWnd = GetParent(param_1);
  }
  GetWindowRect(param_1,&local_38);
  if (local_8 == 0) {
    if ((hWnd != (HWND)0x0) &&
       ((uVar1 = GetWindowLongA(hWnd,-0x10), (uVar1 & 0x10000000) == 0 ||
        ((uVar1 & 0x20000000) != 0)))) {
      hWnd = (HWND)0x0;
    }
    SystemParametersInfoA(0x30,0,&local_28,0);
    if (hWnd == (HWND)0x0) {
      local_18.left = local_28.left;
      local_18.top = local_28.top;
      local_18.right = local_28.right;
      local_18.bottom = local_28.bottom;
    }
    else {
      GetWindowRect(hWnd,&local_18);
    }
  }
  else {
    hWnd_00 = GetParent(param_1);
    GetClientRect(hWnd_00,&local_28);
    GetClientRect(hWnd,&local_18);
    MapWindowPoints(hWnd,hWnd_00,(LPPOINT)&local_18,2);
  }
  iVar2 = (local_18.left + local_18.right) / 2 - (local_38.right - local_38.left) / 2;
  iVar3 = (local_18.top + local_18.bottom) / 2 - (local_38.bottom - local_38.top) / 2;
  if ((local_28.left <= iVar2) &&
     (local_28.left = iVar2, local_28.right < (iVar2 + local_38.right) - local_38.left)) {
    local_28.left = (local_28.right + local_38.left) - local_38.right;
  }
  if ((local_28.top <= iVar3) &&
     (local_28.top = iVar3, local_28.bottom < (iVar3 + local_38.bottom) - local_38.top)) {
    local_28.top = (local_28.bottom + local_38.top) - local_38.bottom;
  }
  SetWindowPos(param_1,(HWND)0x0,local_28.left,local_28.top,-1,-1,0x15);
  return;
}



void __cdecl FUN_00402d20(HWND param_1)

{
  HWND hWnd;
  HDC hdc;
  HGDIOBJ pvVar1;
  HWND pHVar2;
  tagRECT *lpRect;
  undefined4 local_48;
  undefined4 local_44;
  HWND local_40;
  HWND local_3c;
  tagRECT local_38;
  LPSTR local_24;
  tagRECT local_1c;
  tagSIZE local_c;
  
  hWnd = GetParent(param_1);
  hdc = GetDC(hWnd);
  pvVar1 = (HGDIOBJ)FUN_00402a60(0);
  pvVar1 = SelectObject(hdc,pvVar1);
  GetTextExtentPointA(hdc,s_InstallShield_0041318c,0xd,&local_c);
  pvVar1 = SelectObject(hdc,pvVar1);
  DeleteObject(pvVar1);
  ReleaseDC(hWnd,hdc);
  lpRect = &local_1c;
  pHVar2 = FUN_00402a00(hWnd);
  GetWindowRect(pHVar2,lpRect);
  local_1c.top = local_1c.top - local_c.cy / 2;
  ScreenToClient(hWnd,(LPPOINT)&local_1c);
  local_1c.right = local_c.cx + 10;
  local_1c.bottom = local_c.cy + local_1c.top;
  local_1c.left = 5;
  DAT_00416230 = GetWindowLongA(hWnd,-4);
  SetWindowLongA(hWnd,-4,(LONG)FUN_00402aa0);
  local_3c = CreateWindowExA(0,s_BUTTON_004131a4,s_ISGlyph_0041319c,0x5000800b,local_1c.left,
                             local_1c.top,local_1c.right,local_1c.bottom,hWnd,(HMENU)0x3ff,
                             DAT_004177c8,(LPVOID)0x0);
  pHVar2 = CreateWindowExA(0x88,s_tooltips_class32_004131ac,&DAT_00416264,0x80000001,-0x80000000,
                           -0x80000000,-0x80000000,-0x80000000,hWnd,(HMENU)0x0,DAT_004177c8,
                           (LPVOID)0x0);
  LoadStringA(DAT_004177c8,0x13,DAT_00417768,0x104);
  GetClientRect(local_3c,&local_38);
  local_48 = 0x2c;
  local_44 = 0x11;
  local_24 = DAT_00417768;
  local_40 = hWnd;
  SendMessageA(pHVar2,0x404,0,(LPARAM)&local_48);
  SendMessageA(pHVar2,0x401,1,0);
  FUN_00402bc0(hWnd);
  return;
}



int __cdecl FUN_00402ed0(HWND param_1,UINT param_2,UINT param_3,UINT param_4)

{
  int iVar1;
  CHAR local_b8 [128];
  CHAR local_38 [52];
  
  if (DAT_00416220 == 0) {
    local_38[0] = '\0';
    local_b8[0] = '\0';
    if (DAT_00417734 == 0) {
      LoadStringA(DAT_004177c8,param_2,local_b8,0x80);
      LoadStringA(DAT_004177c8,param_3,local_38,0x32);
    }
    else {
      FUN_004017f0(s_Strings_004131c0,param_2,local_b8,0x80);
      FUN_004017f0(s_Strings_004131c8,param_3,local_38,0x32);
    }
    iVar1 = MessageBoxA(param_1,local_b8,local_38,param_4);
    return iVar1;
  }
  return 0;
}



undefined4 FUN_00402f90(HWND param_1,int param_2,short param_3)

{
  int iVar1;
  HWND hWnd;
  DWORD DVar2;
  char *pcVar3;
  undefined *puVar4;
  CHAR local_38 [52];
  
  if (param_2 != 0x110) {
    if (param_2 != 0x111) {
      return 0;
    }
    if (param_3 != 2) {
      return 0;
    }
    iVar1 = FUN_00402ed0(param_1,0x20,4,4);
    if (iVar1 != 6) {
      return 0;
    }
    DAT_0041621c = 1;
    return 0;
  }
  FUN_00401850(param_1,0x3ed,0);
  hWnd = GetDlgItem(param_1,0x3f2);
  SendMessageA(hWnd,0x464,0,0x66);
  SendMessageA(hWnd,0x465,1,0x270027);
  if (DAT_0041776c != (undefined *)0x0) {
    if ((DAT_00417734 != 0) &&
       (DVar2 = FUN_004017f0(s_Dialog1005_004131d0,0,local_38,0x32), DVar2 != 0)) {
      pcVar3 = local_38;
      puVar4 = DAT_0041776c;
      goto LAB_0040308f;
    }
    if (DAT_0041776c != (undefined *)0x0) {
      pcVar3 = s_Unpacking__s____004131dc;
      puVar4 = DAT_0041776c;
      goto LAB_0040308f;
    }
  }
  puVar4 = &DAT_00416268;
  pcVar3 = &DAT_004131ec;
LAB_0040308f:
  wsprintfA(DAT_00417768,pcVar3,puVar4);
  SetWindowTextA(param_1,DAT_00417768);
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int __cdecl FUN_004030c0(HWND param_1)

{
  char cVar1;
  HWND hDlg;
  bool bVar2;
  char *pcVar3;
  undefined3 extraout_var;
  HANDLE pvVar4;
  int iVar5;
  undefined3 extraout_var_00;
  uint uVar6;
  uint uVar7;
  undefined4 *puVar8;
  char *pcVar9;
  undefined4 *puVar10;
  CHAR local_134 [260];
  undefined4 local_30;
  uint local_2a;
  int local_18 [3];
  int **local_c;
  int local_8;
  
  hDlg = param_1;
  local_8 = 0;
  puVar10 = DAT_0041779c;
  if (DAT_004177d4 == (char *)0x0) {
    uVar6 = 0xffffffff;
    pcVar3 = DAT_00417738;
    do {
      pcVar9 = pcVar3;
      if (uVar6 == 0) break;
      uVar6 = uVar6 - 1;
      pcVar9 = pcVar3 + 1;
      cVar1 = *pcVar3;
      pcVar3 = pcVar9;
    } while (cVar1 != '\0');
    uVar6 = ~uVar6;
    puVar8 = (undefined4 *)(pcVar9 + -uVar6);
    for (uVar7 = uVar6 >> 2; uVar7 != 0; uVar7 = uVar7 - 1) {
      *puVar10 = *puVar8;
      puVar8 = puVar8 + 1;
      puVar10 = puVar10 + 1;
    }
  }
  else {
    uVar6 = 0xffffffff;
    pcVar3 = DAT_004177d4;
    do {
      pcVar9 = pcVar3;
      if (uVar6 == 0) break;
      uVar6 = uVar6 - 1;
      pcVar9 = pcVar3 + 1;
      cVar1 = *pcVar3;
      pcVar3 = pcVar9;
    } while (cVar1 != '\0');
    uVar6 = ~uVar6;
    puVar8 = (undefined4 *)(pcVar9 + -uVar6);
    for (uVar7 = uVar6 >> 2; uVar7 != 0; uVar7 = uVar7 - 1) {
      *puVar10 = *puVar8;
      puVar8 = puVar8 + 1;
      puVar10 = puVar10 + 1;
    }
  }
  for (uVar6 = uVar6 & 3; uVar6 != 0; uVar6 = uVar6 - 1) {
    *(undefined *)puVar10 = *(undefined *)puVar8;
    puVar8 = (undefined4 *)((int)puVar8 + 1);
    puVar10 = (undefined4 *)((int)puVar10 + 1);
  }
  FUN_004016a0((LPCSTR)DAT_0041779c);
  FUN_00401380((LPCSTR)DAT_0041779c);
  *DAT_004177d8 = '\0';
  pcVar3 = _strchr((char *)DAT_0041779c,0x3a);
  if (pcVar3 != (char *)0x0) {
    lstrcpynA(DAT_004177d8,(LPCSTR)DAT_0041779c,(int)(pcVar3 + (2 - (int)DAT_0041779c)));
    lstrcatA(DAT_004177d8,&DAT_004131f0);
  }
  local_c = (int **)FUN_00405420(FUN_004013b0,FUN_004013d0,FUN_00401470,FUN_00401520,FUN_00401540,
                                 FUN_00401560,FUN_00401570,1,local_18);
  if (local_c == (int **)0x0) {
    return 9;
  }
  if ((*DAT_004177d8 != '\0') && (uVar6 = FUN_00405040(DAT_004177d8,param_1,1), uVar6 == 0)) {
    return -10;
  }
  DAT_0041621c = 0;
  param_1 = (HWND)0x1;
  wsprintfA(local_134,s__spftw_d_pkg_004131f4,DAT_00417738,1);
  bVar2 = FUN_00401220(local_134,0);
  iVar5 = CONCAT31(extraout_var,bVar2);
  while (iVar5 != 0) {
    pvVar4 = FUN_00401470(local_134,0x8000);
    if ((pvVar4 == (HANDLE)0xffffffff) ||
       (iVar5 = FUN_00405530(local_c,pvVar4,&local_30), iVar5 == 0)) {
      FUN_00401560(pvVar4);
      return 10;
    }
    _DAT_00417754 = local_2a & 0xffff;
    if (hDlg != (HWND)0x0) {
      SendDlgItemMessageA(hDlg,0x3f0,0x401,0,_DAT_00417754 << 0x10);
      SendDlgItemMessageA(hDlg,0x3f0,0x404,1,0);
      SendDlgItemMessageA(hDlg,0x3f0,0x402,0,0);
    }
    wsprintfA(local_134,s_pftw_d_pkg_00413204,param_1);
    iVar5 = FUN_00405600(local_c,local_134,DAT_00417738,0,(int *)FUN_00401b90,(int *)0x0,(int *)0x0)
    ;
    if (iVar5 == 0) {
      local_8 = DAT_0041622c;
      if (DAT_0041622c == 0) {
        local_8 = local_18[0] + 300;
      }
      FUN_00401560(pvVar4);
    }
    param_1 = (HWND)((int)&param_1->unused + 1);
    FUN_00401560(pvVar4);
    if ((DAT_0041621c != 0) || (local_8 != 0)) break;
    wsprintfA(local_134,s__spftw_d_pkg_004131f4,DAT_00417738,param_1);
    bVar2 = FUN_00401220(local_134,0);
    iVar5 = CONCAT31(extraout_var_00,bVar2);
  }
  FUN_004054c0(local_c);
  DestroyWindow(DAT_0041772c);
  return local_8;
}



void __cdecl FUN_004033b0(char *param_1,char param_2,char param_3)

{
  char cVar1;
  
  cVar1 = *param_1;
  while (cVar1 != '\0') {
    if (*param_1 == param_2) {
      *param_1 = param_3;
    }
    param_1 = param_1 + 1;
    cVar1 = *param_1;
  }
  return;
}



undefined4 __cdecl FUN_004033e0(HWND param_1)

{
  HANDLE pvVar1;
  undefined *puVar2;
  HWND hWnd;
  DWORD DVar3;
  DWORD DVar4;
  int iVar5;
  undefined4 *puVar6;
  uint uVar7;
  char *lpString;
  CHAR local_320 [260];
  CHAR local_21c [260];
  CHAR local_118;
  undefined4 local_117;
  int local_14;
  HANDLE local_10;
  int local_c;
  HANDLE local_8;
  
  GetTempFileNameA(DAT_00417794,&DAT_00413210,0,DAT_00417738);
  DeleteFileA(DAT_00417738);
  FUN_004033b0(DAT_00417738,'.','~');
  FUN_004016a0(DAT_00417738);
  lstrcatA(DAT_00417738,&DAT_00413218);
  FUN_00405020(local_320,0x104);
  pvVar1 = FUN_00401470(local_320,0);
  if (pvVar1 == (HANDLE)0xffffffff) {
    return 5;
  }
  local_8 = pvVar1;
  puVar2 = (undefined *)FUN_0040ba70(0x40000);
  FUN_00401570(pvVar1,DAT_004177a8,0);
  if (param_1 != (HWND)0x0) {
    local_118 = '\0';
    puVar6 = &local_117;
    for (iVar5 = 0x40; iVar5 != 0; iVar5 = iVar5 + -1) {
      *puVar6 = 0;
      puVar6 = puVar6 + 1;
    }
    *(undefined2 *)puVar6 = 0;
    *(undefined *)((int)puVar6 + 2) = 0;
    hWnd = GetDlgItem(param_1,0x405);
    wsprintfA(&local_118,&DAT_0041321c,hWnd);
    if (hWnd != (HWND)0x0) {
      if ((DAT_00417734 == 0) ||
         (DVar3 = FUN_004017f0(s_Dialog1005_00413220,0x405,&local_118,0x104), DVar3 == 0)) {
        lpString = s_Reading_package____0041322c;
      }
      else {
        lpString = &local_118;
      }
      SetWindowTextA(hWnd,lpString);
    }
    SendDlgItemMessageA(param_1,0x3f0,0x401,0,(DAT_0041775c >> 0x12) << 0x10);
    SendDlgItemMessageA(param_1,0x3f0,0x404,1,0);
  }
  iVar5 = 0;
  if (0 < DAT_004177a4) {
    do {
      local_14 = iVar5 + 1;
      wsprintfA(local_21c,s__spftw_d_pkg_00413240,DAT_00417738,local_14);
      local_10 = FUN_00401470(local_21c,0x101);
      if (local_10 == (HANDLE)0xffffffff) {
        DeleteFileA(local_21c);
        FUN_00401560(local_8);
        return 6;
      }
      local_c = 0;
      uVar7 = *(uint *)(DAT_00416238 + iVar5 * 4);
      while ((uVar7 != 0 && (DAT_0041621c == 0))) {
        DVar3 = 0x40000;
        if (uVar7 < 0x40001) {
          DVar3 = uVar7;
        }
        DVar4 = FUN_00401520(local_8,puVar2,DVar3);
        FUN_00401540(local_10,puVar2,DVar4);
        FUN_00401300(0);
        local_c = local_c + DVar3;
        uVar7 = uVar7 - DVar3;
        SendDlgItemMessageA(param_1,0x3f0,0x405,0,0);
      }
      FUN_00401560(local_10);
      iVar5 = local_14;
    } while (local_14 < DAT_004177a4);
  }
  FUN_00401560(local_8);
  FUN_0040bb20(puVar2);
  return 0;
}



void __cdecl FUN_004036a0(HWND param_1)

{
  uint uVar1;
  HWND hWnd;
  UINT Msg;
  WPARAM wParam;
  LPARAM lParam;
  
  if (DAT_00417798 != 0) {
    uVar1 = FUN_004012b0(DAT_004177d0);
    if (uVar1 != DAT_00416234) {
      DAT_00416228 = 0x23;
      return;
    }
  }
  if (DAT_00416220 == 0) {
    DAT_0041772c = CreateDialogParamA(DAT_004177c8,(LPCSTR)0x3ed,param_1,FUN_00402f90,0);
  }
  else {
    DAT_0041772c = (HWND)0x0;
  }
  DAT_00416228 = FUN_004033e0(DAT_0041772c);
  if (DAT_00416228 == 0) {
    if (DAT_0041772c != (HWND)0x0) {
      lParam = -0x10000;
      wParam = 0xffffffff;
      Msg = 0x465;
      hWnd = GetDlgItem(DAT_0041772c,0x3f2);
      SendMessageA(hWnd,Msg,wParam,lParam);
    }
    if (DAT_0041621c == 0) {
      DAT_00416228 = FUN_004030c0(DAT_0041772c);
    }
  }
  if (DAT_00416228 == -10) {
    DAT_00416224 = 1;
  }
  return;
}



LPVOID __cdecl FUN_00403770(uint param_1)

{
  HRSRC hResInfo;
  HGLOBAL hResData;
  LPVOID pvVar1;
  
  hResInfo = FindResourceA(DAT_004177c8,(LPCSTR)(param_1 & 0xffff),&DAT_00413250);
  if (hResInfo != (HRSRC)0x0) {
    hResData = LoadResource(DAT_004177c8,hResInfo);
    if (hResData != (HGLOBAL)0x0) {
      pvVar1 = LockResource(hResData);
      return pvVar1;
    }
  }
  return (LPVOID)0x0;
}



undefined4 FUN_004037c0(int param_1,undefined4 *param_2,uint param_3,uint *param_4)

{
  uint uVar1;
  uint uVar2;
  undefined4 *puVar3;
  
  uVar1 = *(uint *)(param_1 + 8);
  if (param_3 <= *(uint *)(param_1 + 8)) {
    uVar1 = param_3;
  }
  if (uVar1 != 0) {
    puVar3 = *(undefined4 **)(param_1 + 4);
    for (uVar2 = uVar1 >> 2; uVar2 != 0; uVar2 = uVar2 - 1) {
      *param_2 = *puVar3;
      puVar3 = puVar3 + 1;
      param_2 = param_2 + 1;
    }
    for (uVar2 = uVar1 & 3; uVar2 != 0; uVar2 = uVar2 - 1) {
      *(undefined *)param_2 = *(undefined *)puVar3;
      puVar3 = (undefined4 *)((int)puVar3 + 1);
      param_2 = (undefined4 *)((int)param_2 + 1);
    }
    *(uint *)(param_1 + 8) = *(int *)(param_1 + 8) - uVar1;
    *(uint *)(param_1 + 4) = *(int *)(param_1 + 4) + uVar1;
  }
  *param_4 = uVar1;
  return 0;
}



void __cdecl FUN_00403810(HWND param_1,LPCSTR param_2)

{
  uint uVar1;
  int iVar2;
  LPCSTR *local_1c [2];
  code *local_14;
  LPCSTR local_10;
  LPCSTR local_c;
  int local_8;
  
  uVar1 = GetWindowLongA(param_1,-0x10);
  SetWindowLongA(param_1,-0x10,uVar1 & 0xfffff7ff);
  local_10 = param_2;
  local_8 = lstrlenA(param_2);
  local_1c[0] = &local_10;
  local_c = param_2;
  local_14 = FUN_004037c0;
  iVar2 = FUN_00402580((int)param_2,s___rtf1_00413254,6);
  SendMessageA(param_1,0x449,2 - (iVar2 != 0),(LPARAM)local_1c);
  SetWindowLongA(param_1,-0x10,uVar1 | 0x800);
  SendMessageA(param_1,0xb1,0xffffffff,0);
  SetFocus(param_1);
  return;
}



undefined4 FUN_004038b0(void)

{
  LPCSTR pCVar1;
  LPSTR pCVar2;
  undefined *puVar3;
  undefined *puVar4;
  undefined *local_1c;
  undefined *local_18;
  undefined *local_14;
  undefined *local_10;
  undefined *local_c;
  undefined *local_8;
  
  pCVar1 = (LPCSTR)FUN_00403770(0x6a);
  if (pCVar1 != (LPCSTR)0x0) {
    pCVar2 = (LPSTR)FUN_0040ba70(0x6d6);
    puVar3 = &DAT_0041626c;
    if (DAT_004177b4 == 0) {
      puVar3 = &DAT_0041325c;
    }
    local_8 = DAT_00417744;
    if (DAT_00417744 == (undefined *)0x0) {
      local_8 = &DAT_00416270;
    }
    local_c = DAT_004177a0;
    if (DAT_004177a0 == (undefined *)0x0) {
      local_c = &DAT_00416274;
    }
    local_10 = DAT_00417748;
    if (DAT_00417748 == (undefined *)0x0) {
      local_10 = &DAT_00416278;
    }
    local_14 = DAT_004177b0;
    if (DAT_004177b0 == (undefined *)0x0) {
      local_14 = &DAT_0041627c;
    }
    local_18 = DAT_00417760;
    if (DAT_00417760 == (undefined *)0x0) {
      local_18 = &DAT_00416280;
    }
    local_1c = DAT_00417750;
    if (DAT_00417750 == (undefined *)0x0) {
      local_1c = &DAT_00416284;
    }
    puVar4 = DAT_0041776c;
    if (DAT_0041776c == (undefined *)0x0) {
      puVar4 = &DAT_00416288;
    }
    wsprintfA(pCVar2,pCVar1,puVar4,local_1c,local_18,local_14,local_10,local_c,local_8,
              DAT_004177b8 / 10,DAT_004177b8 % 10,puVar3);
    FUN_00403810(DAT_00417720,pCVar2);
    FUN_0040bb20(pCVar2);
  }
  return 0;
}



undefined4 FUN_004039e0(HWND param_1,int param_2,undefined4 param_3,int param_4)

{
  HWND hWnd;
  LPARAM lParam;
  
  hWnd = GetParent(param_1);
  if (param_2 == 0x4e) {
    switch(*(undefined4 *)(param_4 + 8)) {
    case 0xffffff30:
      FUN_004036a0(param_1);
      break;
    case 0xffffff35:
    case 0xffffff37:
      SetWindowLongA(param_1,0,0);
      return 1;
    case 0xffffff38:
      if (DAT_004177bc == 1) {
        lParam = 4;
      }
      else {
        lParam = 2;
      }
      PostMessageA(hWnd,0x470,0,lParam);
      FUN_00404f10(param_1,1000);
      return 0;
    }
  }
  else if (param_2 == 0x110) {
    FUN_00401850(param_1,1000,1);
    DAT_00417720 = GetDlgItem(param_1,0x3fd);
    SendMessageA(DAT_00417720,0x443,0,0xffffff);
    if (DAT_00417724 == (LPCSTR)0x0) {
      FUN_004038b0();
    }
    else {
      FUN_00403810(DAT_00417720,DAT_00417724);
    }
    if (DAT_00416230 != 0) {
      return 1;
    }
    FUN_00402d20(param_1);
    return 1;
  }
  return 0;
}



bool __cdecl FUN_00403b10(HWND param_1)

{
  HWND hWnd;
  uint uVar1;
  
  hWnd = GetDlgItem(param_1,0x404);
  if (hWnd != (HWND)0x0) {
    GetWindowTextA(hWnd,DAT_004177d0,0x80);
    uVar1 = FUN_004012b0(DAT_004177d0);
    return uVar1 == DAT_00416234;
  }
  return false;
}



undefined4 FUN_00403b60(HWND param_1,undefined4 param_2,UINT_PTR param_3,int param_4)

{
  bool bVar1;
  short sVar2;
  HWND pHVar3;
  HWND hWnd;
  undefined3 extraout_var;
  undefined3 extraout_var_00;
  undefined3 extraout_var_01;
  uint uVar4;
  undefined3 extraout_var_02;
  
  pHVar3 = GetParent(param_1);
  switch(param_2) {
  case 0x2b:
  case 0x110:
    FUN_00401850(param_1,0x3eb,1);
    if (DAT_00416230 != 0) {
      return 1;
    }
    FUN_00402d20(param_1);
    return 1;
  case 0x4e:
    if (*(int *)(param_4 + 8) == -0xd0) {
      bVar1 = FUN_00403b10(param_1);
      if (CONCAT31(extraout_var_02,bVar1) != 0) {
        FUN_004036a0(param_1);
        return 1;
      }
      PostMessageA(pHVar3,0x470,0,8);
      SetWindowLongA(param_1,0,0);
    }
    else if (*(int *)(param_4 + 8) == -200) {
      uVar4 = (uint)(((byte)DAT_004177bc & 1) != 0);
      if (((byte)DAT_004177bc & 0xc) == 0) {
        DAT_00416250 = 1;
        uVar4 = uVar4 | 8;
      }
      else {
        uVar4 = uVar4 | 2;
      }
      PostMessageA(pHVar3,0x470,0,uVar4);
      SetTimer(param_1,1,0x32,(TIMERPROC)0x0);
      FUN_00404f10(param_1,0x3eb);
      return 1;
    }
    break;
  case 0x111:
    if (((short)param_3 == 0x404) &&
       ((sVar2 = (short)(param_3 >> 0x10), sVar2 == 0x300 || (sVar2 == 0x100)))) {
      if (DAT_00416250 != 0) {
        bVar1 = FUN_00403b10(param_1);
        if (CONCAT31(extraout_var_00,bVar1) == 0) {
          PostMessageA(pHVar3,0x470,0,8);
          return 0;
        }
        PostMessageA(pHVar3,0x470,0,0x3025);
        return 0;
      }
      pHVar3 = GetDlgItem(pHVar3,0x3024);
      if (pHVar3 != (HWND)0x0) {
        bVar1 = FUN_00403b10(param_1);
        EnableWindow(pHVar3,CONCAT31(extraout_var_01,bVar1));
        return 0;
      }
    }
    break;
  case 0x113:
    KillTimer(param_1,param_3);
    hWnd = GetDlgItem(pHVar3,0x3024);
    if ((hWnd == (HWND)0x0) && (hWnd = GetDlgItem(pHVar3,0x3025), hWnd == (HWND)0x0)) {
      return 1;
    }
    bVar1 = FUN_00403b10(param_1);
    EnableWindow(hWnd,CONCAT31(extraout_var,bVar1));
    return 1;
  }
  return 0;
}



bool __cdecl FUN_00403e70(HWND param_1,int param_2)

{
  LPITEMIDLIST pidl;
  _browseinfoA local_24;
  
  GetDlgItemTextA(param_1,param_2,DAT_00417768,0x104);
  local_24.hwndOwner = param_1;
  local_24.pidlRoot = (LPCITEMIDLIST)0x0;
  local_24.pszDisplayName = DAT_00417768;
  local_24.lpszTitle = (LPCSTR)0x0;
  local_24.ulFlags = 1;
  local_24.lpfn = (BFFCALLBACK)0x0;
  local_24.lParam = 0;
  pidl = SHBrowseForFolderA(&local_24);
  if (pidl != (LPITEMIDLIST)0x0) {
    SHGetPathFromIDListA(pidl,DAT_00417768);
    SetDlgItemTextA(param_1,param_2,DAT_00417768);
  }
  return pidl != (LPITEMIDLIST)0x0;
}



undefined4 FUN_00403ef0(HWND param_1,int param_2,short param_3,int param_4)

{
  uint uVar1;
  bool bVar2;
  bool bVar3;
  HWND hWnd;
  int iVar4;
  LPARAM lParam;
  
  hWnd = GetParent(param_1);
  if (param_2 != 0x4e) {
    if (param_2 == 0x110) {
      FUN_00401850(param_1,0x3ea,1);
      if (DAT_004177d4 != (LPCSTR)0x0) {
        SetDlgItemTextA(param_1,1000,DAT_004177d4);
      }
      if (DAT_00416230 == 0) {
        FUN_00402d20(param_1);
      }
    }
    else {
      if (param_2 != 0x111) {
        return 0;
      }
      if (param_3 == 0x67) {
        FUN_00403e70(param_1,1000);
        return 1;
      }
    }
    return 1;
  }
  uVar1 = *(uint *)(param_4 + 8);
  if (0xffffff2f < uVar1) {
    if (uVar1 < 0xffffff32) {
      bVar3 = false;
      bVar2 = false;
      if (DAT_004177d4 == (LPCSTR)0x0) {
        DAT_004177d4 = (LPCSTR)FUN_0040ba70(0x104);
      }
      GetDlgItemTextA(param_1,1000,DAT_004177d4,0x104);
      iVar4 = FUN_00401170(DAT_004177d4);
      if (iVar4 == -2) {
        iVar4 = FUN_00402ed0(param_1,0x1d,4,4);
        if (iVar4 != 6) {
          SetWindowLongA(param_1,0,-1);
          return 0xffffffff;
        }
        bVar2 = true;
      }
      else {
        if (iVar4 == -1) {
          FUN_00402ed0(param_1,0x34,4,0x10);
          SetWindowLongA(param_1,0,-1);
          return 0xffffffff;
        }
        bVar3 = true;
      }
      if ((bVar2) && (iVar4 = FUN_004016a0(DAT_004177d4), iVar4 == 0)) {
        bVar3 = true;
      }
      if (!bVar3) {
        FUN_00402ed0(param_1,0x138,4,0);
        SetWindowLongA(param_1,0,-1);
        return 0xffffffff;
      }
      FUN_004036a0(param_1);
      return 0;
    }
    if (uVar1 == 0xffffff38) {
      lParam = 4;
      if (DAT_004177bc != 8) {
        lParam = 5;
      }
      PostMessageA(hWnd,0x470,0,lParam);
      FUN_00404f10(param_1,0x3ea);
      return 0;
    }
  }
  return 0;
}



undefined4 FUN_004040f0(HWND param_1,int param_2,undefined4 param_3,int param_4)

{
  HWND hWnd;
  HWND hWnd_00;
  uint uVar1;
  
  hWnd = GetParent(param_1);
  hWnd_00 = GetDlgItem(param_1,0x3ea);
  if (param_2 == 0x4e) {
    if (*(int *)(param_4 + 8) == -0xd0) {
      FUN_004036a0(param_1);
    }
    else if (*(int *)(param_4 + 8) == -200) {
      uVar1 = (uint)((DAT_004177bc & 3) != 0);
      if ((DAT_004177bc & 8) == 0) {
        uVar1 = uVar1 | 4;
      }
      else {
        uVar1 = uVar1 | 2;
      }
      PostMessageA(hWnd,0x470,0,uVar1);
      FUN_00404f10(param_1,0x3e9);
      return 0;
    }
  }
  else if (param_2 == 0x110) {
    FUN_00401850(param_1,0x3e9,1);
    SendMessageA(hWnd_00,0x443,0,0xffffff);
    if (DAT_004177c4 != (LPCSTR)0x0) {
      FUN_00403810(hWnd_00,DAT_004177c4);
    }
    if (DAT_00416230 == 0) {
      FUN_00402d20(param_1);
    }
    return 1;
  }
  return 0;
}



undefined4 __cdecl FUN_004041f0(char *param_1)

{
  char *lpString1;
  int iVar1;
  
  lpString1 = _strrchr(param_1,0x2e);
  if (lpString1 == (char *)0x0) {
    return 0;
  }
  iVar1 = CompareStringA(0x400,1,lpString1,-1,&DAT_00413264,-1);
  if (((iVar1 != 2) && (iVar1 = CompareStringA(0x400,1,lpString1,-1,&DAT_0041326c,-1), iVar1 != 2))
     && (iVar1 = CompareStringA(0x400,1,lpString1,-1,&DAT_00413274,-1), iVar1 != 2)) {
    return 0;
  }
  return 1;
}



undefined4 FUN_00404270(void)

{
  bool bVar1;
  undefined3 extraout_var;
  int iVar2;
  HINSTANCE hHandle;
  DWORD DVar3;
  BOOL BVar4;
  LPCSTR lpString2;
  CHAR local_3c8 [260];
  CHAR local_2c4 [100];
  CHAR local_260 [260];
  CHAR local_15c [260];
  _STARTUPINFOA local_58;
  _PROCESS_INFORMATION local_14;
  
  local_58.cb = 0x44;
  GetStartupInfoA(&local_58);
  if ((DAT_00417730 != 3) && (local_58.dwFlags = local_58.dwFlags | 1, DAT_00417730 < 4)) {
    switch(DAT_00417730) {
    case 0:
      local_58._48_4_ = CONCAT22(local_58.cbReserved2,5);
      break;
    case 1:
      local_58._48_4_ = CONCAT22(local_58.cbReserved2,6);
      break;
    case 2:
      local_58._48_4_ = CONCAT22(local_58.cbReserved2,3);
    }
  }
  if (DAT_00416224 == 0) {
    lpString2 = DAT_00417738;
    if (DAT_004177d4 != (LPCSTR)0x0) {
      lpString2 = DAT_004177d4;
    }
    lstrcpyA(local_260,lpString2);
    lstrcpyA(local_15c,local_260);
    FUN_00401380(local_15c);
    lstrcatA(local_15c,DAT_0041771c);
    bVar1 = FUN_00401220(local_15c,0);
    if (CONCAT31(extraout_var,bVar1) == 0) {
      lstrcpyA(local_15c,DAT_0041771c);
    }
    FUN_004012e0(local_260);
    iVar2 = FUN_004041f0(local_15c);
    if (iVar2 == 0) {
      hHandle = ShellExecuteA((HWND)0x0,&DAT_0041327c,local_15c,DAT_004177ac,local_260,
                              local_58._48_4_ & 0xffff);
      if (hHandle != (HINSTANCE)0x0) {
        do {
          FUN_00401300(0);
          DVar3 = WaitForSingleObject(hHandle,100);
        } while (DVar3 == 0x102);
        return 0;
      }
    }
    else {
      lstrcpyA(local_3c8,local_15c);
      wsprintfA(local_15c,&DAT_00413284,local_3c8);
      if (DAT_004177ac != (LPCSTR)0x0) {
        lstrcatA(local_15c,&DAT_0041328c);
        lstrcatA(local_15c,DAT_004177ac);
      }
      if (DAT_0041773c != (LPCSTR)0x0) {
        lstrcatA(local_15c,&DAT_00413290);
        lstrcatA(local_15c,DAT_0041773c);
      }
      BVar4 = CreateProcessA((LPCSTR)0x0,local_15c,(LPSECURITY_ATTRIBUTES)0x0,
                             (LPSECURITY_ATTRIBUTES)0x0,0,0,(LPVOID)0x0,local_260,&local_58,
                             &local_14);
      if (BVar4 != 0) {
        do {
          FUN_00401300(0);
          DVar3 = WaitForSingleObject(local_14.hProcess,100);
        } while (DVar3 == 0x102);
        CloseHandle(local_14.hProcess);
        return 0;
      }
      if ((DAT_00417734 != 0) &&
         (DVar3 = FUN_004017f0(s_Strings_00413294,0x31,local_2c4,100), DVar3 != 0)) {
        MessageBoxA((HWND)0x0,local_15c,local_2c4,0);
        return 0xc;
      }
      MessageBoxA((HWND)0x0,local_15c,s_Unable_to_Execute__0041329c,0);
    }
    return 0xc;
  }
  return 0;
}



int __cdecl FUN_00404530(LPCSTR param_1)

{
  char cVar1;
  HANDLE hFindFile;
  BOOL BVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  undefined4 *puVar6;
  LPCSTR pCVar7;
  char *pcVar8;
  char *pcVar9;
  undefined4 *puVar10;
  byte local_24c;
  char local_220 [275];
  undefined uStack_10d;
  undefined4 local_10c [65];
  int local_8;
  
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
  local_8 = 0;
  puVar6 = (undefined4 *)(pcVar8 + -uVar3);
  puVar10 = local_10c;
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
  iVar5 = -1;
  puVar6 = local_10c;
  do {
    puVar10 = puVar6;
    if (iVar5 == 0) break;
    iVar5 = iVar5 + -1;
    puVar10 = (undefined4 *)((int)puVar6 + 1);
    cVar1 = *(char *)puVar6;
    puVar6 = puVar10;
  } while (cVar1 != '\0');
  *(undefined4 *)((int)puVar10 + -1) = DAT_004132b0;
  if (DAT_00417734 != (LPCSTR)0x0) {
    DeleteFileA(DAT_00417734);
  }
  hFindFile = FindFirstFileA((LPCSTR)local_10c,(LPWIN32_FIND_DATAA)&local_24c);
  if (hFindFile != (HANDLE)0xffffffff) {
    do {
      if ((local_24c & 0x10) == 0) {
        lstrcpyA((LPSTR)local_10c,param_1);
        lstrcatA((LPSTR)local_10c,local_220);
        BVar2 = DeleteFileA((LPCSTR)local_10c);
        if (BVar2 == 0) {
          local_8 = local_8 + 1;
        }
      }
      else if (local_220[0] != '.') {
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
        puVar10 = local_10c;
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
        pcVar8 = local_220;
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
        puVar6 = local_10c;
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
        iVar5 = -1;
        puVar6 = local_10c;
        do {
          puVar10 = puVar6;
          if (iVar5 == 0) break;
          iVar5 = iVar5 + -1;
          puVar10 = (undefined4 *)((int)puVar6 + 1);
          cVar1 = *(char *)puVar6;
          puVar6 = puVar10;
        } while (cVar1 != '\0');
        *(undefined2 *)((int)puVar10 + -1) = DAT_004132b4;
        local_8 = FUN_00404530((LPCSTR)local_10c);
      }
      BVar2 = FindNextFileA(hFindFile,(LPWIN32_FIND_DATAA)&local_24c);
    } while (BVar2 != 0);
    FindClose(hFindFile);
  }
  uVar3 = 0xffffffff;
  do {
    pcVar8 = param_1;
    if (uVar3 == 0) break;
    uVar3 = uVar3 - 1;
    pcVar8 = param_1 + 1;
    cVar1 = *param_1;
    param_1 = pcVar8;
  } while (cVar1 != '\0');
  uVar3 = ~uVar3;
  puVar6 = (undefined4 *)(pcVar8 + -uVar3);
  puVar10 = local_10c;
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
  iVar5 = lstrlenA((LPCSTR)local_10c);
  *(undefined *)((int)local_10c + iVar5 + -1) = 0;
  RemoveDirectoryA((LPCSTR)local_10c);
  return local_8;
}



void __cdecl FUN_00404700(undefined4 *param_1,uint param_2,undefined4 param_3,undefined4 param_4)

{
  param_1[2] = param_4;
  *param_1 = 0x28;
  param_1[1] = 8;
  param_1[3] = param_2 & 0xffff;
  param_1[6] = param_3;
  param_1[5] = 0;
  param_1[4] = 0;
  param_1[7] = 0;
  return;
}



int FUN_00404740(void)

{
  int iVar1;
  LPSTR lpCaption;
  HWND hWnd;
  uint uVar2;
  int iVar3;
  UINT UVar4;
  DWORD *pDVar5;
  LPCSTR lpText;
  UINT uType;
  undefined4 local_cc [40];
  DWORD local_2c;
  DWORD local_28;
  HWND local_24;
  LPCSTR local_18;
  UINT local_14;
  _union_1956 local_c;
  
  local_2c = 0;
  pDVar5 = &local_28;
  for (iVar3 = 9; iVar3 != 0; iVar3 = iVar3 + -1) {
    *pDVar5 = 0;
    pDVar5 = pDVar5 + 1;
  }
  UVar4 = 0;
  iVar3 = 0;
  InitCommonControls();
  if (DAT_00416244 != (code *)0x0) {
    iVar1 = (*DAT_00416244)();
    if (iVar1 != 0) {
      return -1;
    }
  }
  if (DAT_00416220 == 0) {
    if (DAT_004177dc != (LPCSTR)0x0) {
      lpCaption = DAT_0041776c;
      if (DAT_0041776c == (LPSTR)0x0) {
        LoadStringA(DAT_004177c8,4,DAT_00417768,0x104);
        lpCaption = DAT_00417768;
      }
      uType = 4;
      lpText = DAT_004177dc;
      hWnd = GetDesktopWindow();
      iVar1 = MessageBoxA(hWnd,lpText,lpCaption,uType);
      if (iVar1 != 6) {
        return 0;
      }
    }
    if ((((((DAT_00417724 != 0) || (DAT_00417760 != 0)) || (DAT_004177b0 != 0)) ||
         ((DAT_00417748 != 0 || (DAT_00417744 != 0)))) ||
        ((DAT_00417750 != 0 || (DAT_004177a0 != 0)))) && ((DAT_00417758 & 2) == 0)) {
      UVar4 = 1;
      FUN_00404700(local_cc,1000,FUN_004039e0,DAT_004177c8);
      DAT_004177bc = DAT_004177bc | 1;
    }
    if (DAT_00417798 != 0) {
      iVar1 = UVar4 * 10;
      UVar4 = UVar4 + 1;
      FUN_00404700(local_cc + iVar1,0x3eb,FUN_00403b60,DAT_004177c8);
      DAT_004177bc = DAT_004177bc | 2;
    }
    if (DAT_004177c4 != 0) {
      iVar1 = UVar4 * 10;
      UVar4 = UVar4 + 1;
      FUN_00404700(local_cc + iVar1,0x3e9,FUN_004040f0,DAT_004177c8);
      DAT_004177bc = DAT_004177bc | 4;
    }
    if (DAT_004177d4 != 0) {
      iVar1 = UVar4 * 10;
      UVar4 = UVar4 + 1;
      FUN_00404700(local_cc + iVar1,0x3ea,FUN_00403ef0,DAT_004177c8);
      DAT_004177bc = DAT_004177bc | 8;
    }
  }
  if (UVar4 == 0) {
    iVar3 = FUN_004036a0((HWND)0x0);
    uVar2 = (uint)(iVar3 == 0);
  }
  else {
    local_c.ppsp = (LPCPROPSHEETPAGEA)local_cc;
    local_2c = 0x28;
    local_28 = 0xa8;
    local_24 = (HWND)0x0;
    local_18 = &DAT_0041628c;
    local_14 = UVar4;
    uVar2 = PropertySheetA((LPCPROPSHEETHEADERA)&local_2c);
  }
  if (((uVar2 != 0) && (DAT_0041621c == 0)) && (DAT_0041622c == 0)) {
    if (DAT_0041771c != 0) {
      iVar3 = FUN_00404270();
      return iVar3;
    }
    if ((DAT_00417764 != 0) && (DAT_00416220 == 0)) {
      FUN_00402ed0((HWND)0x0,0x21,4,0);
    }
  }
  return iVar3;
}



int __cdecl FUN_004049b0(LPCSTR param_1)

{
  HANDLE hFile;
  DWORD DVar1;
  DWORD DVar2;
  byte *pbVar3;
  int iVar4;
  
  hFile = FUN_00401470(param_1,0);
  if (hFile == (HANDLE)0xffffffff) {
    iVar4 = 3;
  }
  else {
    DVar1 = GetFileSize(hFile,(LPDWORD)0x0);
    DVar2 = FUN_00401590(hFile);
    if (DVar2 == DVar1) {
      return 0xd;
    }
    FUN_00401570(hFile,DVar2,0);
    FUN_00401520(hFile,&DAT_004177c0,4);
    pbVar3 = (byte *)FUN_0040ba70(DAT_004177c0);
    FUN_00401520(hFile,pbVar3,DAT_004177c0);
    FUN_00402420(pbVar3,DAT_004177c0);
    iVar4 = FUN_004025c0((int)pbVar3,DAT_004177c0);
    if (iVar4 == 0) {
      DAT_004177a8 = DVar2 + 4 + DAT_004177c0;
      FUN_0040bb20(pbVar3);
      FUN_00401560(hFile);
      return 0;
    }
  }
  return iVar4;
}



int __cdecl FUN_00404a90(undefined4 param_1,char *param_2,undefined4 param_3)

{
  LPSTR pCVar1;
  int iVar2;
  
  DAT_00417768 = FUN_0040ba70(0x122);
  DAT_004177d0 = (undefined *)FUN_0040ba70(0x80);
  DAT_00417738 = (undefined *)FUN_0040ba70(0x104);
  DAT_0041779c = FUN_0040ba70(0x104);
  DAT_004177d8 = FUN_0040ba70(0x104);
  if ((((DAT_00417768 != 0) && (DAT_004177d0 != (undefined *)0x0)) &&
      (DAT_00417738 != (undefined *)0x0)) && ((DAT_0041779c != 0 && (DAT_004177d8 != 0)))) {
    *DAT_004177d0 = 0;
    DAT_004177c8 = param_1;
    FUN_004021f0();
    DAT_0041621c = 0;
    DAT_00417720 = 0;
    DAT_004177cc = LoadLibraryA(s_RICHED32_DLL_004132b8);
    *DAT_00417738 = 0;
    DAT_004177bc = 0;
    DAT_00417760 = 0;
    DAT_004177dc = 0;
    DAT_00417798 = 0;
    DAT_004177c4 = 0;
    DAT_004177b0 = 0;
    DAT_00417744 = 0;
    DAT_0041776c = 0;
    DAT_004177a0 = 0;
    DAT_00417750 = 0;
    DAT_00417748 = 0;
    DAT_0041771c = 0;
    DAT_004177ac = 0;
    DAT_004177d4 = 0;
    DAT_0041774c = 0;
    DAT_0041623c = 0;
    DAT_00417734 = 0;
    DAT_0041773c = 0;
    DAT_00417730 = param_3;
    pCVar1 = (LPSTR)FUN_0040ba70(0x104);
    if (pCVar1 != (LPSTR)0x0) {
      FUN_00405020(pCVar1,0x104);
      iVar2 = FUN_004049b0(pCVar1);
      if (iVar2 != 0) {
        FUN_0040bb20(pCVar1);
        return iVar2;
      }
      FUN_0040bb20(pCVar1);
      DAT_00417728 = 0;
      DAT_00417764 = 0;
      DAT_00416220 = 0;
      if ((param_2 != (char *)0x0) && (*param_2 != '\0')) {
        iVar2 = FUN_00401d90(param_2);
        return iVar2;
      }
      return 0;
    }
  }
  return 0x26;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_00404c60(void)

{
  if (DAT_004177cc != (HMODULE)0x0) {
    FreeLibrary(DAT_004177cc);
  }
  if (*DAT_00417738 != '\0') {
    FUN_00401300(7);
    FUN_00404530(DAT_00417738);
  }
  FUN_00401f60();
  FUN_0040bb20(DAT_00417768);
  FUN_0040bb20(DAT_004177d0);
  FUN_0040bb20(DAT_00417738);
  FUN_0040bb20(DAT_0041779c);
  FUN_0040bb20(DAT_004177d8);
  FUN_0040bb20(DAT_004177dc);
  FUN_0040bb20(DAT_00417798);
  FUN_0040bb20(DAT_004177c4);
  FUN_0040bb20(DAT_00417760);
  FUN_0040bb20(DAT_004177b0);
  FUN_0040bb20(DAT_00417744);
  FUN_0040bb20(DAT_0041776c);
  FUN_0040bb20(DAT_004177a0);
  FUN_0040bb20(DAT_00417750);
  FUN_0040bb20(DAT_00417748);
  FUN_0040bb20(DAT_0041771c);
  FUN_0040bb20(DAT_004177ac);
  FUN_0040bb20(DAT_004177d4);
  FUN_0040bb20(DAT_0041774c);
  _DAT_00417740 = 0;
  return 0;
}



void FUN_00404dc0(undefined4 param_1,undefined4 param_2,char *param_3,undefined4 param_4)

{
  HWND pHVar1;
  bool bVar2;
  UINT UVar3;
  UINT UVar4;
  UINT UVar5;
  
  DAT_00416228 = FUN_00404a90(param_1,param_3,param_4);
  bVar2 = DAT_00416228 == 0;
  if (bVar2) {
    DAT_00416228 = FUN_00404740();
    bVar2 = DAT_00416228 == 0;
    if (bVar2) {
      DAT_00416228 = FUN_00404c60();
      if (DAT_00416228 != 0) {
        UVar5 = 0x30;
        UVar4 = 1;
        UVar3 = DAT_00416228;
        pHVar1 = GetDesktopWindow();
        FUN_00402ed0(pHVar1,UVar3,UVar4,UVar5);
      }
                    // WARNING: Subroutine does not return
      ExitProcess(DAT_00416228);
    }
  }
  if (!bVar2 && -1 < (int)DAT_00416228) {
    UVar5 = 0x30;
    UVar4 = 1;
    UVar3 = DAT_00416228;
    pHVar1 = GetDesktopWindow();
    FUN_00402ed0(pHVar1,UVar3,UVar4,UVar5);
  }
  FUN_00404c60();
                    // WARNING: Subroutine does not return
  ExitProcess(DAT_00416228);
}



undefined4 __cdecl FUN_00404e50(HWND param_1,int param_2)

{
  LCID LVar1;
  HANDLE h;
  HDC hdc;
  int nNumerator;
  HFONT wParam;
  int nDenominator;
  LOGFONTA local_40;
  
  LVar1 = GetSystemDefaultLCID();
  if (LVar1 == 0x411) {
    h = (HANDLE)SendDlgItemMessageA(param_1,param_2,0x31,0,0);
    if (h == (HANDLE)0x0) {
      return 0;
    }
    GetObjectA(h,0x3c,&local_40);
    local_40.lfCharSet = '\x01';
    hdc = GetDC(param_1);
    nDenominator = 0x48;
    nNumerator = GetDeviceCaps(hdc,0x5a);
    local_40.lfHeight = MulDiv(9,nNumerator,nDenominator);
    local_40.lfHeight = -local_40.lfHeight;
    ReleaseDC(param_1,hdc);
    lstrcpyA(local_40.lfFaceName,&DAT_004132c8);
    wParam = CreateFontIndirectA(&local_40);
    if (wParam == (HFONT)0x0) {
      return 0;
    }
    SendDlgItemMessageA(param_1,param_2,0x30,(WPARAM)wParam,0);
  }
  return 1;
}



undefined4 __cdecl FUN_00404f10(HWND param_1,undefined4 param_2)

{
  DWORD DVar1;
  HWND hWnd;
  undefined4 uVar2;
  UINT Msg;
  WPARAM wParam;
  char *lParam;
  char local_11c [260];
  CHAR local_18 [20];
  
  uVar2 = 0;
  GetWindow(param_1,5);
  wsprintfA(local_18,s_Dialog_d_004132d8,param_2);
  DVar1 = FUN_004017f0(local_18,0,local_11c,0x104);
  if (DVar1 == 0) {
    GetWindowTextA(param_1,local_11c,0x104);
  }
  if (local_11c[0] != '\0') {
    SetWindowTextA(param_1,local_11c);
    lParam = local_11c;
    if (DAT_0041776c != 0) {
      wsprintfA(DAT_00417768,s__s____s_004132e4,DAT_0041776c);
      lParam = DAT_00417768;
    }
    wParam = 0;
    Msg = 0x46f;
    hWnd = GetParent(param_1);
    SendMessageA(hWnd,Msg,wParam,(LPARAM)lParam);
    uVar2 = 1;
  }
  return uVar2;
}



void __cdecl FUN_00404fe0(char *param_1,int param_2,char param_3)

{
  char *pcVar1;
  char cVar2;
  char cVar3;
  int iVar4;
  
  cVar3 = '\0';
  iVar4 = 0;
  cVar2 = *param_1;
  while (cVar2 != '\0') {
    cVar2 = *param_1;
    if ((param_3 != cVar2) || (cVar3 != cVar2)) {
      *(char *)(iVar4 + param_2) = cVar2;
      iVar4 = iVar4 + 1;
    }
    cVar3 = *param_1;
    pcVar1 = param_1 + 1;
    param_1 = param_1 + 1;
    cVar2 = *pcVar1;
  }
  *(undefined *)(iVar4 + param_2) = 0;
  return;
}



void __cdecl FUN_00405020(LPSTR param_1,DWORD param_2)

{
  GetModuleFileNameA((HMODULE)0x0,param_1,param_2);
  return;
}



uint __cdecl FUN_00405040(LPCSTR param_1,HWND param_2,int param_3)

{
  bool bVar1;
  undefined3 extraout_var;
  int iVar2;
  undefined3 extraout_var_00;
  uint uVar3;
  uint uVar4;
  int iVar5;
  float10 fVar6;
  CHAR local_4c4 [260];
  CHAR local_3c0 [260];
  CHAR local_2bc [128];
  CHAR local_23c [260];
  char local_138 [260];
  CHAR local_34 [32];
  double local_14;
  int local_c;
  uint local_8;
  
  iVar5 = 1;
  uVar4 = 0;
  local_8 = 0;
  local_c = 0;
  wsprintfA(local_23c,s__spftw_d_pkg_004132ec,DAT_00417738,1);
  bVar1 = FUN_00401220(local_23c,0);
  iVar2 = CONCAT31(extraout_var,bVar1);
  do {
    if (iVar2 == 0) {
LAB_004050ed:
      if (local_c == -10) {
        return 0;
      }
      iVar5 = 4;
      do {
        uVar3 = FUN_00401270(param_1);
        if (uVar3 != 0) {
          local_8 = (uint)(uVar4 <= uVar3);
        }
        if ((local_8 == 0) && (param_3 != 0)) {
          fVar6 = FUN_004052a0(uVar4,local_34,0x1e);
          local_14 = (double)fVar6;
          LoadStringA(DAT_004177c8,0x13a,local_2bc,0x104);
          FUN_0040c000(local_138,local_2bc);
          iVar5 = MessageBoxA(param_2,local_138,DAT_0041776c,0x15);
        }
      } while ((iVar5 == 4) && (local_8 == 0));
      return local_8;
    }
    iVar2 = FUN_00401090(local_23c,&local_c);
    if (iVar2 == 0) {
      if (param_3 == 0) {
        return 0;
      }
      LoadStringA(DAT_004177c8,0x139,local_3c0,0x104);
      LoadStringA(DAT_004177c8,1,local_138,0x104);
      MessageBoxA(param_2,local_3c0,local_138,0x10);
      return 0;
    }
    if ((local_c < 0) || (uVar4 = uVar4 + iVar2, local_c < 0)) {
      if (local_c == -10) {
        LoadStringA(DAT_004177c8,0x13e,local_3c0,0x104);
        GetSystemDirectoryA(local_4c4,0x104);
        lstrcpynA(local_4c4,local_4c4,4);
        wsprintfA(local_138,local_3c0,local_4c4);
        MessageBoxA(param_2,local_138,DAT_0041776c,0x10);
        goto LAB_004050ed;
      }
    }
    else {
      iVar5 = iVar5 + 1;
    }
    wsprintfA(local_23c,s__spftw_d_pkg_004132ec,DAT_00417738,iVar5);
    bVar1 = FUN_00401220(local_23c,0);
    iVar2 = CONCAT31(extraout_var_00,bVar1);
  } while( true );
}



float10 __cdecl FUN_004052a0(uint param_1,LPSTR param_2,int param_3)

{
  UINT uID;
  double local_c;
  
  local_c = (double)(ulonglong)param_1;
  local_c = (double)(longlong)local_c;
  if (param_1 < 0x400) {
    uID = 0x13d;
  }
  else if (param_1 < 0x100000) {
    local_c = local_c * 0.0009765625;
    uID = 0x13c;
  }
  else {
    local_c = local_c * 9.5367431640625e-07;
    uID = 0x13b;
  }
  LoadStringA(DAT_004177c8,uID,param_2,param_3);
  return (float10)local_c;
}



int __cdecl FUN_00405310(int param_1,int param_2)

{
  BOOL BVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int local_8;
  
  iVar4 = 0;
  iVar3 = param_2 + -1;
  local_8 = 0;
  if (iVar3 < 0) {
    return 0;
  }
  do {
    BVar1 = IsCharAlphaA(*(CHAR *)(iVar3 + param_1));
    if (BVar1 != 0) {
      return 0;
    }
    iVar2 = FUN_00405380(10,iVar4);
    local_8 = local_8 + (*(char *)(iVar3 + param_1) + -0x30) * iVar2;
    iVar3 = iVar3 + -1;
    iVar4 = iVar4 + 1;
  } while (-1 < iVar3);
  return local_8;
}



int __cdecl FUN_00405380(int param_1,int param_2)

{
  int iVar1;
  
  iVar1 = 1;
  if (0 < param_2) {
    do {
      iVar1 = iVar1 * param_1;
      param_2 = param_2 + -1;
    } while (param_2 != 0);
  }
  return iVar1;
}



void __cdecl FUN_004053a0(LPSTR param_1)

{
  char cVar1;
  uint uVar2;
  LPCSTR lpString2;
  
  cVar1 = *param_1;
  lpString2 = param_1;
  while ((cVar1 != '\0' && (uVar2 = FUN_0040c0e0((int)cVar1), uVar2 != 0))) {
    cVar1 = lpString2[1];
    lpString2 = lpString2 + 1;
  }
  if ((param_1 != lpString2) && (*lpString2 != '\0')) {
    lstrcpyA(param_1,lpString2);
  }
  return;
}



void __cdecl FUN_004053e0(char *param_1)

{
  char *pcVar1;
  char cVar2;
  uint uVar3;
  char *pcVar4;
  
  pcVar4 = (char *)0x0;
  cVar2 = *param_1;
  while (cVar2 != '\0') {
    uVar3 = FUN_0040c0e0((int)*param_1);
    if (uVar3 == 0) {
      pcVar4 = (char *)0x0;
    }
    else if (pcVar4 == (char *)0x0) {
      pcVar4 = param_1;
    }
    pcVar1 = param_1 + 1;
    param_1 = param_1 + 1;
    cVar2 = *pcVar1;
  }
  if (pcVar4 != (char *)0x0) {
    *pcVar4 = '\0';
  }
  return;
}



undefined4 * __cdecl
FUN_00405420(undefined *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,undefined4 param_7,undefined4 param_8,
            undefined4 *param_9)

{
  undefined4 *puVar1;
  
  puVar1 = (undefined4 *)(*(code *)param_1)(0x804);
  if (puVar1 == (undefined4 *)0x0) {
    FUN_00406d00(param_9,5,0);
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



undefined4 __cdecl FUN_004054c0(undefined4 *param_1)

{
  FUN_00406690(0xf,param_1);
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



undefined4 __cdecl FUN_00405530(undefined4 *param_1,undefined4 param_2,undefined4 *param_3)

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
    FUN_00406d00((undefined4 *)*param_1,3,uStack_c & 0xffff);
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
FUN_00405600(int **param_1,char *param_2,char *param_3,undefined4 param_4,int *param_5,int *param_6,
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
  bVar4 = FUN_004058b0(param_1,param_2,0,-1);
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
    iVar5 = FUN_004065c0(param_1);
    while (iVar5 != 0) {
      do {
        sVar3 = *(short *)(param_1 + 0x2b);
        *(short *)(param_1 + 0x2b) = sVar3 + -1;
        if (sVar3 == 0) {
          local_4 = 1;
          goto LAB_0040585e;
        }
        iVar5 = FUN_00406340(param_1);
        if (iVar5 == 0) goto LAB_0040585e;
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
              FUN_00406d00(*param_1,0xb,0);
              goto LAB_0040585e;
            }
          }
          else {
            piVar6 = (int *)(*(code *)param_5)(2);
            param_1[0x23] = piVar6;
            if (piVar6 == (int *)0xffffffff) {
              FUN_00406d00(*param_1,0xb,0);
              goto LAB_0040585e;
            }
            if (piVar6 == (int *)0x0) {
              if ((*(ushort *)(param_1 + 0x1f) & 0xfffe) == 0xfffe) {
                *(short *)((int)param_1 + 0xae) = *(short *)((int)param_1 + 0xae) + 1;
              }
            }
            else {
              iVar5 = FUN_00405cf0(param_1);
joined_r0x004057ef:
              if (iVar5 == 0) goto LAB_0040585e;
            }
          }
        }
        else if (param_1[0x27] == (int *)0x0) {
          piVar6 = (int *)(*(code *)param_5)(2,ppiVar1);
          param_1[0x23] = piVar6;
          if (piVar6 == (int *)0xffffffff) {
            FUN_00406d00(*param_1,0xb,0);
            goto LAB_0040585e;
          }
          if (piVar6 != (int *)0x0) {
            iVar5 = FUN_00405cf0(param_1);
            goto joined_r0x004057ef;
          }
          if ((*(ushort *)(param_1 + 0x1f) & 0xfffe) == 0xfffe) {
            *(short *)((int)param_1 + 0xae) = *(short *)((int)param_1 + 0xae) + 1;
          }
        }
        else {
          *(undefined2 *)(param_1 + 0x2b) = 0;
        }
      } while (*(short *)(param_1 + 0x2b) != 0);
      iVar5 = FUN_004065c0(param_1);
    }
  }
LAB_0040585e:
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



bool __cdecl FUN_004058b0(undefined4 *param_1,char *param_2,short param_3,short param_4)

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
        FUN_00406d00((undefined4 *)*param_1,2,0);
        return false;
      }
      if (aiStack_24[0] != 0x4643534d) {
        FUN_00406d00((undefined4 *)*param_1,2,0);
        return false;
      }
      if ((short)uStack_c != 0x103) {
        FUN_00406d00((undefined4 *)*param_1,3,uStack_c & 0xffff);
        return false;
      }
      if ((param_4 != -1) && ((sStack_4 != param_3 || (sStack_2 != param_4)))) {
        FUN_00406d00((undefined4 *)*param_1,10,0);
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
          FUN_00406d00((undefined4 *)*param_1,2,0);
          return false;
        }
        if (param_1[0x28] == 0xffff) {
          uVar4 = uStack_28 & 0xffff;
          param_1[0x28] = uVar4;
          if (uVar4 != 0) {
            iVar6 = (*(code *)param_1[2])(uVar4);
            param_1[0x13] = iVar6;
            if (iVar6 == 0) {
              FUN_00406d00((undefined4 *)*param_1,5,0);
              return false;
            }
          }
        }
        iVar6 = param_1[0x28];
        if ((iVar6 != 0) &&
           (iVar3 = (*(code *)param_1[4])(param_1[0x22],param_1[0x13],iVar6), iVar3 != iVar6)) {
          FUN_00406d00((undefined4 *)*param_1,2,0);
          return false;
        }
      }
      iVar6 = (uStack_28 >> 0x10 & 0xff) + 8;
      if (param_1[0x11] == 0) {
        param_1[0x29] = iVar6;
        iVar6 = (*(code *)param_1[2])(iVar6);
        param_1[0x11] = iVar6;
        if (iVar6 == 0) {
          FUN_00406d00((undefined4 *)*param_1,5,0);
          return false;
        }
      }
      else if (param_1[0x29] != iVar6) {
        FUN_00406d00((undefined4 *)*param_1,9,0);
        return false;
      }
      iVar6 = (uStack_28 >> 0x18) + 8;
      if (param_1[0x12] == 0) {
        param_1[0x2a] = iVar6;
        iVar6 = (*(code *)param_1[2])(iVar6);
        param_1[0x12] = iVar6;
        if (iVar6 == 0) {
          FUN_00406d00((undefined4 *)*param_1,5,0);
          return false;
        }
      }
      else if (param_1[0x2a] != iVar6) {
        FUN_00406d00((undefined4 *)*param_1,9,0);
        return false;
      }
      if ((*(byte *)((int)param_1 + 0x6e) & 1) == 0) {
        *(undefined *)((int)param_1 + 0x1b5) = 0;
        *(undefined *)((int)param_1 + 0x2b6) = 0;
      }
      else {
        iVar6 = FUN_00406500((char *)((int)param_1 + 0x1b5),0x100,param_1);
        if (iVar6 == 0) {
          return false;
        }
        iVar6 = FUN_00406500((char *)((int)param_1 + 0x2b6),0x100,param_1);
        if (iVar6 == 0) {
          return false;
        }
      }
      if ((*(byte *)((int)param_1 + 0x6e) & 2) == 0) {
        *(undefined *)((int)param_1 + 0x3b7) = 0;
        *(undefined *)(param_1 + 0x12e) = 0;
      }
      else {
        iVar6 = FUN_00406500((char *)((int)param_1 + 0x3b7),0x100,param_1);
        if ((iVar6 == 0) ||
           (iVar6 = FUN_00406500((char *)(param_1 + 0x12e),0x100,param_1), iVar6 == 0)) {
          return false;
        }
      }
      iVar6 = (*(code *)param_1[7])(param_1[0x22],0,1);
      param_1[0xb] = iVar6;
      if (iVar6 == -1) {
        FUN_00406d00((undefined4 *)*param_1,4,0);
        return false;
      }
      iVar6 = (*(code *)param_1[7])(param_1[0x22],param_1[0x18]);
      if (iVar6 != -1) {
        *(undefined2 *)(param_1 + 0x2b) = *(undefined2 *)(param_1 + 0x1b);
        iVar6 = FUN_004060e0(param_1);
        return (bool)('\x01' - (iVar6 == 0));
      }
      FUN_00406d00((undefined4 *)*param_1,4,0);
      return false;
    }
  }
  FUN_00406d00((undefined4 *)*param_1,1,0);
  return false;
}



undefined4 __cdecl FUN_00405cf0(int **param_1)

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
LAB_00405d9c:
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
        FUN_00406d00(*param_1,8,0);
        return 0;
      }
      return 1;
    }
    uVar7 = 0xb;
LAB_00405e0a:
    FUN_00406d00(*param_1,uVar7,0);
  }
  else {
    piVar6 = param_1[0x1e];
    if (piVar6 <= param_1[0xc] && param_1[0xc] != piVar6) {
      param_1[0x24] = (int *)0xffff;
    }
    iVar2 = FUN_004061a0(param_1,(int *)(uint)*(ushort *)(param_1 + 0x1f));
    while (iVar2 != 0) {
      if (piVar6 < (int *)((uint)*(ushort *)((int)param_1[0x12] + 6) + (int)param_1[0xc]))
      goto LAB_00405d4f;
      iVar2 = FUN_00405e70(param_1);
    }
  }
  goto LAB_00405e15;
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
      goto LAB_00405e0a;
    }
    piVar6 = (int *)((int)piVar6 + (int)piVar5);
    piVar4 = (int *)((int)piVar4 - (int)piVar5);
    if ((piVar4 != (int *)0x0) && (iVar2 = FUN_00405e70(param_1), iVar2 == 0)) break;
LAB_00405d4f:
    if (piVar4 == (int *)0x0) goto LAB_00405d9c;
  }
LAB_00405e15:
  if (param_1[0x23] != (int *)0xffffffff) {
    (*(code *)param_1[6])(param_1[0x23]);
    param_1[0x23] = (int *)0xffffffff;
  }
  return 0;
}



undefined4 __cdecl FUN_00405e70(int **param_1)

{
  int iVar1;
  ushort local_2;
  
  param_1[0xc] = (int *)((int)param_1[0xc] + (uint)*(ushort *)((int)param_1[0x12] + 6));
  if (*(short *)(param_1 + 0x2c) == 0) {
    iVar1 = FUN_00405f50(param_1);
    if (iVar1 == 0) {
      return 0;
    }
  }
  *(short *)(param_1 + 0x2c) = *(short *)(param_1 + 0x2c) + -1;
  iVar1 = FUN_00406390(param_1,0);
  if (iVar1 == 0) {
    return 0;
  }
  if (*(short *)((int)param_1[0x12] + 6) == 0) {
    iVar1 = FUN_00405f50(param_1);
    if (iVar1 != 0) {
      iVar1 = FUN_00406390(param_1,(uint)*(ushort *)(param_1[0x12] + 1));
      if (iVar1 != 0) {
        *(short *)(param_1 + 0x2c) = *(short *)(param_1 + 0x2c) + -1;
        goto LAB_00405ef4;
      }
    }
    return 0;
  }
LAB_00405ef4:
  local_2 = *(ushort *)((int)param_1[0x12] + 6);
  iVar1 = FUN_00406b70(param_1,&local_2);
  if (iVar1 == 0) {
    return 0;
  }
  if (*(ushort *)((int)param_1[0x12] + 6) != local_2) {
    FUN_00406d00(*param_1,7,0);
    return 0;
  }
  return 1;
}



undefined4 __cdecl FUN_00405f50(int **param_1)

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
      if (iVar4 != 0) goto LAB_00406083;
    }
    if (param_1[0x22] != (int *)0xffffffff) {
      iVar4 = (*(code *)param_1[6])(param_1[0x22]);
      if (iVar4 != 0) {
LAB_00406083:
        FUN_00406d00(*param_1,4,0);
        return 0;
      }
    }
    param_1[0x22] = (int *)0xffffffff;
    param_1[0x21] = (int *)0xffffffff;
    iVar4 = (*(code *)param_1[9])(4,param_1 + 0x1ef);
    if (iVar4 == -1) {
      FUN_00406d00(*param_1,0xb,0);
      return 0;
    }
    bVar3 = FUN_004058b0(param_1,(char *)((int)param_1 + 0x3b7),sVar1,sVar5);
    if (CONCAT31(extraout_var,bVar3) == 0) {
LAB_0040602a:
      if (**param_1 == 0xb) {
        return 0;
      }
      bVar2 = true;
    }
    else {
      iVar4 = FUN_00406220(param_1,0);
      if (iVar4 == 0) goto LAB_0040602a;
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
        iVar4 = FUN_00406340(param_1);
      } while (iVar4 != 0);
      return 0;
    }
  } while( true );
}



undefined4 __cdecl FUN_004060e0(undefined4 *param_1)

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
    FUN_00406d00((undefined4 *)*param_1,0xb,0);
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
      FUN_00406d00((undefined4 *)*param_1,0xb,0);
      return 0;
    }
  }
  return 1;
}



undefined4 __cdecl FUN_004061a0(int **param_1,int *param_2)

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
  iVar1 = FUN_00406aa0(param_1);
  if ((iVar1 != 0) && (iVar1 = FUN_00406220(param_1,(int)param_2), iVar1 != 0)) {
    iVar1 = FUN_00405e70(param_1);
    if (iVar1 != 0) {
      param_1[0xc] = (int *)0x0;
      return 1;
    }
    return 0;
  }
  return 0;
}



undefined4 __cdecl FUN_00406220(undefined4 *param_1,int param_2)

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
        bVar1 = FUN_00406690(*(short *)(param_1[0x11] + 6),param_1);
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
            FUN_00406d00((undefined4 *)*param_1,0xb,0);
            return 0;
          }
        }
        return 1;
      }
    }
  }
  FUN_00406d00((undefined4 *)*param_1,4,0);
  return 0;
}



undefined4 __cdecl FUN_00406340(undefined4 *param_1)

{
  int iVar1;
  
  iVar1 = (*(code *)param_1[4])(param_1[0x22],param_1 + 0x1d,0x10);
  if (iVar1 == 0x10) {
    iVar1 = FUN_00406500((char *)(param_1 + 0x2d),0x100,param_1);
    if (iVar1 != 0) {
      return 1;
    }
  }
  FUN_00406d00((undefined4 *)*param_1,4,0);
  return 0;
}



undefined4 __cdecl FUN_00406390(undefined4 *param_1,int param_2)

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
          uVar7 = FUN_00406d1c(extraout_ECX,(int)((ulonglong)uVar7 >> 0x20),
                               (uint *)(param_1[0xf] + param_2),(uint)*(ushort *)puVar6,0);
          uVar7 = FUN_00406d1c(extraout_ECX_00,(int)((ulonglong)uVar7 >> 0x20),puVar6,
                               param_1[0x2a] - 4,(uint)uVar7);
          if (*(int *)param_1[0x12] != (int)uVar7) {
            FUN_00406d00((undefined4 *)*param_1,4,0);
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
            FUN_00406d00((undefined4 *)*param_1,0xb,0);
            return 0;
          }
        }
        return 1;
      }
    }
  }
  FUN_00406d00((undefined4 *)*param_1,4,0);
  return 0;
}



undefined4 __cdecl FUN_00406500(char *param_1,int param_2,undefined4 *param_3)

{
  char cVar1;
  char cVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  
  iVar3 = (*(code *)param_3[7])(param_3[0x22],0,1);
  iVar4 = (*(code *)param_3[4])(param_3[0x22],param_1,param_2);
  if (iVar4 < 1) {
    FUN_00406d00((undefined4 *)*param_3,4,0);
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
    FUN_00406d00((undefined4 *)*param_3,4,0);
    return 0;
  }
  iVar3 = (*(code *)param_3[7])(param_3[0x22],~uVar5 + iVar3,0);
  if (iVar3 == -1) {
    FUN_00406d00((undefined4 *)*param_3,4,0);
    return 0;
  }
  return 1;
}



undefined4 __cdecl FUN_004065c0(undefined4 *param_1)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  
  iVar2 = (*(code *)param_1[7])(param_1[0x22],0,1);
  if (iVar2 == -1) {
    FUN_00406d00((undefined4 *)*param_1,4,0);
    return 0;
  }
  piVar1 = param_1 + 0x1ef;
  *(undefined2 *)((int)param_1 + 0x7de) = *(undefined2 *)(param_1 + 0x2b);
  *(undefined2 *)((int)param_1 + 0x7da) = *(undefined2 *)(param_1 + 0x1c);
  *piVar1 = iVar2;
  param_1[499] = param_1[0xe];
  iVar3 = (*(code *)param_1[9])(5,piVar1);
  if (iVar3 == -1) {
    FUN_00406d00((undefined4 *)*param_1,0xb,0);
    return 0;
  }
  *(short *)(param_1 + 0x2b) = *(short *)((int)param_1 + 0x7de);
  if ((*(short *)((int)param_1 + 0x7de) != 0) && (*piVar1 != iVar2)) {
    iVar2 = (*(code *)param_1[7])(param_1[0x22],*piVar1,0);
    if (iVar2 == -1) {
      FUN_00406d00((undefined4 *)*param_1,0xb,0);
      return 0;
    }
  }
  return 1;
}



bool __cdecl FUN_00406690(short param_1,undefined4 *param_2)

{
  int iVar1;
  
  if (*(short *)((int)param_2 + 0xb2) == param_1) {
    return true;
  }
  iVar1 = FUN_004066f0(param_2);
  if (iVar1 == 0) {
    FUN_00406d00((undefined4 *)*param_2,7,0);
    return false;
  }
  *(short *)((int)param_2 + 0xb2) = param_1;
  iVar1 = FUN_004067e0(param_2);
  return (bool)('\x01' - (iVar1 == 0));
}



undefined4 __cdecl FUN_004066f0(undefined4 *param_1)

{
  int iVar1;
  
  switch(*(ushort *)((int)param_1 + 0xb2) & 0xf) {
  case 0:
    break;
  case 1:
    iVar1 = FUN_004072a0((int *)param_1[0xd]);
    if (iVar1 != 0) {
      FUN_00406d00((undefined4 *)*param_1,7,0);
      return 0;
    }
    break;
  case 2:
    iVar1 = FUN_00407100((int *)param_1[0xd]);
    if (iVar1 != 0) {
      FUN_00406d00((undefined4 *)*param_1,7,0);
      return 0;
    }
    break;
  case 3:
    iVar1 = FUN_00406f50((int *)param_1[0xd]);
    if (iVar1 != 0) {
      FUN_00406d00((undefined4 *)*param_1,7,0);
      return 0;
    }
    break;
  default:
    FUN_00406d00((undefined4 *)*param_1,6,0);
    return 0;
  case 0xf:
    return 1;
  }
  (*(code *)param_1[1])(param_1[0xf]);
  (*(code *)param_1[1])(param_1[0x10]);
  return 1;
}



undefined4 __cdecl FUN_004067e0(undefined4 *param_1)

{
  uint *puVar1;
  int *piVar2;
  ushort uVar3;
  int iVar4;
  int iVar5;
  uint local_10;
  undefined4 local_c;
  uint local_8 [2];
  
  uVar3 = *(ushort *)((int)param_1 + 0xb2);
  iVar5 = 0;
  puVar1 = param_1 + 0x25;
  *puVar1 = 0x8000;
  switch(uVar3 & 0xf) {
  case 0:
    param_1[0x26] = 0x8000;
    break;
  case 1:
    iVar4 = FUN_00407170(puVar1,(undefined *)0x0,(undefined *)0x0,param_1 + 0x26,(undefined4 *)0x0);
    if (iVar4 == 0) break;
    goto LAB_004068d2;
  case 2:
    local_c = param_1[8];
    local_10 = (uint)((uVar3 & 0x1f00) >> 8);
    iVar4 = FUN_00406f90(puVar1,(int *)&local_10,(undefined *)0x0,(undefined *)0x0,param_1 + 0x26,
                         (undefined4 *)0x0,0,0,0,0,0);
    goto joined_r0x004068d0;
  case 3:
    local_8[0] = 1 << ((byte)(uVar3 >> 8) & 0x1f);
    iVar4 = FUN_00406da0((int *)puVar1,local_8,(undefined *)0x0,(undefined *)0x0,param_1 + 0x26,
                         (undefined4 *)0x0,0,0,0,0,0);
joined_r0x004068d0:
    if (iVar4 != 0) {
LAB_004068d2:
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
    FUN_00406d00((undefined4 *)*param_1,iVar5,0);
    *(undefined2 *)((int)param_1 + 0xb2) = 0xf;
    return 0;
  }
  piVar2 = param_1 + 0x26;
  iVar5 = (*(code *)param_1[2])(*piVar2);
  param_1[0xf] = iVar5;
  if (iVar5 == 0) {
    FUN_00406d00((undefined4 *)*param_1,5,0);
    *(undefined2 *)((int)param_1 + 0xb2) = 0xf;
    return 0;
  }
  iVar5 = (*(code *)param_1[2])(*puVar1);
  param_1[0x10] = iVar5;
  if (iVar5 == 0) {
    (*(code *)param_1[1])(param_1[0xf]);
    FUN_00406d00((undefined4 *)*param_1,5,0);
    *(undefined2 *)((int)param_1 + 0xb2) = 0xf;
    return 0;
  }
  uVar3 = *(ushort *)((int)param_1 + 0xb2) & 0xf;
  iVar5 = 0;
  if (uVar3 == 1) {
    iVar4 = FUN_00407170(puVar1,(undefined *)param_1[2],(undefined *)param_1[1],piVar2,param_1 + 0xd
                        );
  }
  else if (uVar3 == 2) {
    iVar4 = FUN_00406f90(puVar1,(int *)&local_10,(undefined *)param_1[2],(undefined *)param_1[1],
                         piVar2,param_1 + 0xd,param_1[3],param_1[4],param_1[5],param_1[6],param_1[7]
                        );
  }
  else {
    if (uVar3 != 3) goto LAB_00406a21;
    iVar4 = FUN_00406da0((int *)puVar1,local_8,(undefined *)param_1[2],(undefined *)param_1[1],
                         piVar2,param_1 + 0xd,param_1[3],param_1[4],param_1[5],param_1[6],param_1[7]
                        );
  }
  if (iVar4 != 0) {
    iVar5 = (-(uint)(iVar4 == 1) & 0xfffffffe) + 7;
  }
LAB_00406a21:
  if (iVar5 != 0) {
    (*(code *)param_1[1])(param_1[0xf]);
    (*(code *)param_1[1])(param_1[0x10]);
    FUN_00406d00((undefined4 *)*param_1,iVar5,0);
    *(undefined2 *)((int)param_1 + 0xb2) = 0xf;
    return 0;
  }
  return 1;
}



undefined4 __cdecl FUN_00406aa0(undefined4 *param_1)

{
  byte bVar1;
  undefined3 extraout_var;
  int iVar2;
  
  switch(*(ushort *)((int)param_1 + 0xb2) & 0xf) {
  case 0:
  case 0xf:
    break;
  case 1:
    bVar1 = FUN_00407280((int *)param_1[0xd]);
    if (CONCAT31(extraout_var,bVar1) != 0) {
      FUN_00406d00((undefined4 *)*param_1,7,0);
      return 0;
    }
    break;
  case 2:
    iVar2 = FUN_004070e0((int *)param_1[0xd]);
    if (iVar2 != 0) {
      FUN_00406d00((undefined4 *)*param_1,7,0);
      return 0;
    }
    break;
  case 3:
    iVar2 = FUN_00406f20((int *)param_1[0xd]);
    if (iVar2 != 0) {
      FUN_00406d00((undefined4 *)*param_1,7,0);
      return 0;
    }
    break;
  default:
    FUN_00406d00((undefined4 *)*param_1,6,0);
    return 0;
  }
  return 1;
}



undefined4 __cdecl FUN_00406b70(undefined4 *param_1,ushort *param_2)

{
  ushort uVar1;
  byte bVar2;
  undefined3 extraout_var;
  undefined3 extraout_var_00;
  undefined3 extraout_var_01;
  uint uVar3;
  undefined *puVar4;
  undefined *puVar5;
  uint local_4;
  
  switch(*(ushort *)((int)param_1 + 0xb2) & 0xf) {
  case 0:
    uVar1 = *(ushort *)(param_1[0x12] + 4);
    *param_2 = uVar1;
    puVar4 = (undefined *)param_1[0xf];
    puVar5 = (undefined *)param_1[0x10];
    for (uVar3 = (uint)uVar1; uVar3 != 0; uVar3 = uVar3 - 1) {
      *puVar5 = *puVar4;
      puVar4 = puVar4 + 1;
      puVar5 = puVar5 + 1;
    }
    return 1;
  case 1:
    break;
  case 2:
    local_4 = (uint)*param_2;
    bVar2 = FUN_00407080((int *)param_1[0xd],param_1[0xf],(uint)*(ushort *)(param_1[0x12] + 4),
                         param_1[0x10],&local_4);
    if (CONCAT31(extraout_var_00,bVar2) == 0) {
      *param_2 = (ushort)local_4;
      return 1;
    }
    FUN_00406d00((undefined4 *)*param_1,7,0);
    return 0;
  case 3:
    local_4 = (uint)*param_2;
    bVar2 = FUN_00406ea0((int *)param_1[0xd],param_1[0xf],(uint)*(ushort *)(param_1[0x12] + 4),
                         param_1[0x10],&local_4);
    if (CONCAT31(extraout_var_01,bVar2) == 0) {
      *param_2 = (ushort)local_4;
      return 1;
    }
    FUN_00406d00((undefined4 *)*param_1,7,0);
    return 0;
  default:
    FUN_00406d00((undefined4 *)*param_1,6,0);
    return 0;
  }
  local_4 = param_1[0x25];
  bVar2 = FUN_00407210((int *)param_1[0xd],(char *)param_1[0xf],(uint)*(ushort *)(param_1[0x12] + 4)
                       ,param_1[0x10],&local_4);
  if (CONCAT31(extraout_var,bVar2) == 0) {
    *param_2 = (ushort)local_4;
    return 1;
  }
  FUN_00406d00((undefined4 *)*param_1,7,0);
  return 0;
}



void __cdecl FUN_00406d00(undefined4 *param_1,undefined4 param_2,undefined4 param_3)

{
  *param_1 = param_2;
  param_1[2] = 1;
  param_1[1] = param_3;
  return;
}



undefined8 __fastcall
FUN_00406d1c(undefined4 param_1,undefined4 param_2,uint *param_3,uint param_4,uint param_5)

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
LAB_00406d7c:
    bVar4 = *(byte *)param_3;
    param_3 = (uint *)((int)param_3 + 1);
    param_5 = param_5 ^ (uint)bVar4 << 8;
  }
  else {
    if (uVar6 == 2) goto LAB_00406d7c;
    if (uVar6 != 1) goto LAB_00406d93;
  }
  param_5 = param_5 ^ *(byte *)param_3;
LAB_00406d93:
  return CONCAT44(param_2,param_5);
}



undefined4 __cdecl
FUN_00406da0(int *param_1,uint *param_2,undefined *param_3,undefined *param_4,int *param_5,
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
  iVar2 = FUN_004072e0((int *)puVar1[10],*param_2,(int)param_3,(int)param_4,param_7,param_8,param_9,
                       param_10,param_11);
  if (iVar2 == 0) {
    (*(code *)param_4)(puVar1);
    return 1;
  }
  *param_6 = puVar1;
  return 0;
}



byte __cdecl FUN_00406ea0(int *param_1,int param_2,int param_3,int param_4,uint *param_5)

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
  iVar2 = FUN_004073b0((int *)param_1[10],uVar1,param_2,param_3,param_4,uVar1,&local_4);
  *param_5 = local_4;
  return (iVar2 == 0) - 1U & 4;
}



undefined4 __cdecl FUN_00406f20(int *param_1)

{
  if (*param_1 != 0x4349444c) {
    return 2;
  }
  FUN_00407380(param_1[10]);
  return 0;
}



undefined4 __cdecl FUN_00406f50(int *param_1)

{
  if (*param_1 != 0x4349444c) {
    return 2;
  }
  FUN_00407370((int *)param_1[10]);
  *param_1 = 0;
  (*(code *)param_1[2])(param_1[10]);
  (*(code *)param_1[2])(param_1);
  return 0;
}



undefined4 __cdecl
FUN_00406f90(uint *param_1,int *param_2,undefined *param_3,undefined *param_4,int *param_5,
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
  DAT_00418bf4 = puVar1;
  iVar2 = FUN_00407420((byte)*param_2);
  if (iVar2 != 0) {
    (*(code *)param_4)(puVar1);
    return 1;
  }
  *param_6 = puVar1;
  return 0;
}



byte __cdecl
FUN_00407080(int *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,uint *param_5)

{
  uint uVar1;
  
  if (*param_1 != 0x43494451) {
    return 2;
  }
  DAT_00418bf4 = param_1;
  if ((uint)param_1[8] < *param_5) {
    return 3;
  }
  uVar1 = FUN_004075e0(param_2,param_3,param_4,(short)*param_5);
  return ((uVar1 & 0xffff) == 0) - 1U & 4;
}



undefined4 __cdecl FUN_004070e0(int *param_1)

{
  if (*param_1 != 0x43494451) {
    return 2;
  }
  DAT_00418bf4 = param_1;
  FUN_004076a0();
  return 0;
}



undefined4 __cdecl FUN_00407100(int *param_1)

{
  if (*param_1 != 0x43494451) {
    return 2;
  }
  DAT_00418bf4 = param_1;
  FUN_00407670();
  *param_1 = 0;
  (*(code *)param_1[2])(param_1);
  return 0;
}



void __cdecl FUN_00407130(undefined4 param_1)

{
  (**(code **)(DAT_00418bf4 + 4))(param_1);
  return;
}



void __cdecl FUN_00407150(undefined4 param_1)

{
  (**(code **)(DAT_00418bf4 + 8))(param_1);
  return;
}



undefined4 __cdecl
FUN_00407170(uint *param_1,undefined *param_2,undefined *param_3,int *param_4,undefined4 *param_5)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  
  if ((*param_1 == 0) || (0x8000 < *param_1)) {
    *param_1 = 0x8000;
  }
  *param_4 = *param_1 + 0xc;
  if (param_5 == (undefined4 *)0x0) {
    return 0;
  }
  *param_5 = 0;
  puVar1 = (undefined4 *)(*(code *)param_2)(0x10);
  if (puVar1 == (undefined4 *)0x0) {
    return 1;
  }
  puVar2 = FUN_00409100(param_2);
  puVar1[3] = puVar2;
  if (puVar2 == (undefined4 *)0x0) {
    (*(code *)param_3)(puVar1);
    return 1;
  }
  puVar1[1] = param_3;
  puVar1[2] = *param_1;
  *puVar1 = 0x4349444d;
  *param_5 = puVar1;
  return 0;
}



byte __cdecl FUN_00407210(int *param_1,char *param_2,uint param_3,undefined4 param_4,uint *param_5)

{
  int iVar1;
  
  if (*param_1 != 0x4349444d) {
    return 2;
  }
  if (param_1[2] + 0xcU < param_3) {
    return 3;
  }
  iVar1 = FUN_00407cc0((undefined4 *)param_1[3],param_2,param_3,param_4,param_1[2]);
  if (iVar1 == 0) {
    iVar1 = FUN_00407d10((uint *)param_1[3],param_5);
  }
  return (iVar1 == 0) - 1U & 4;
}



byte __cdecl FUN_00407280(int *param_1)

{
  return (*param_1 == 0x4349444d) - 1U & 2;
}



undefined4 __cdecl FUN_004072a0(int *param_1)

{
  if (*param_1 != 0x4349444d) {
    return 2;
  }
  *param_1 = 0;
  FUN_00409270(param_1[3],(undefined *)param_1[1]);
  (*(code *)param_1[1])(param_1);
  return 0;
}



undefined4 __cdecl
FUN_004072e0(int *param_1,uint param_2,int param_3,int param_4,int param_5,int param_6,int param_7,
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
  bVar1 = FUN_00409280(param_1);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    return 0;
  }
  FUN_00407380((int)param_1);
  return 1;
}



void __cdecl FUN_00407370(int *param_1)

{
  FUN_004092e0(param_1);
  return;
}



void __cdecl FUN_00407380(int param_1)

{
  FUN_00409300(param_1);
  FUN_00409360(param_1);
  FUN_004093b0(param_1);
  *(undefined4 *)(param_1 + 0x2ecc) = 0;
  return;
}



undefined4 __cdecl
FUN_004073b0(int *param_1,int param_2,int param_3,int param_4,int param_5,undefined4 param_6,
            uint *param_7)

{
  uint uVar1;
  
  param_1[0xac1] = param_3;
  param_1[0xac3] = param_5;
  param_1[0xac2] = param_3 + param_4 + 4;
  FUN_00409710((int)param_1);
  uVar1 = FUN_004093f0(param_1,param_2);
  param_1[0xbb3] = param_1[0xbb3] + 1;
  if ((int)uVar1 < 0) {
    *param_7 = 0;
    return 1;
  }
  *param_7 = uVar1;
  param_1[0xac4] = param_1[0xac4] + uVar1;
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 __cdecl FUN_00407420(byte param_1)

{
  int iVar1;
  
  DAT_00418bcc = 0;
  _DAT_00418be8 = 0;
  DAT_00418be4 = param_1;
  DAT_00418bd4 = 1 << (param_1 & 0x1f);
  _DAT_00418bd0 = DAT_00418bd4 + -1;
  DAT_00418bc0 = FUN_00407130(DAT_00418bd4);
  if (DAT_00418bc0 == 0) {
    iVar1 = FUN_004076e0();
    if (iVar1 == 0) {
      return 1;
    }
    DAT_00418bb8 = &LAB_00407890;
    DAT_00418bf0 = &LAB_00407a40;
  }
  else {
    DAT_00418bb8 = &LAB_004074d0;
    DAT_00418bf0 = &LAB_00407590;
    _DAT_00418bc4 = DAT_00418bd4 + DAT_00418bc0;
    DAT_00418bc8 = DAT_00418bc0;
  }
  FUN_00409820(param_1);
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int __cdecl FUN_004075e0(undefined4 param_1,undefined4 param_2,undefined4 param_3,short param_4)

{
  ushort extraout_var;
  
  DAT_00418bd8 = param_4;
  DAT_00418bdc = param_3;
  _DAT_00418be0 = 0;
  DAT_00418bb0 = param_1;
  _DAT_00418bec = param_2;
  _DAT_00418bb4 = 0;
  FUN_0040a0f0();
  while ((DAT_00418bd8 != 0 && (_DAT_00418bb4 == 0))) {
    FUN_00409ad0();
  }
  FUN_0040a270();
  if (((_DAT_00418bb4 == 0) && (_DAT_00418be0 == 0)) && (_DAT_00418be8 == 0)) {
    return (uint)extraout_var << 0x10;
  }
  return CONCAT22(extraout_var,1);
}



void FUN_00407670(void)

{
  if (DAT_00418bc0 == 0) {
    FUN_00407c80();
    FUN_0040a270();
    return;
  }
  FUN_00407150(DAT_00418bc0);
  FUN_0040a270();
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_004076a0(void)

{
  FUN_0040a270();
  DAT_00418bcc = 0;
  DAT_00418bc8 = DAT_00418bc0;
  _DAT_00418be8 = 0;
  if (DAT_00418bc0 == 0) {
    FUN_00407810();
  }
  FUN_00409820(DAT_00418be4);
  return;
}



undefined4 FUN_004076e0(void)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  int iVar3;
  undefined local_8;
  undefined local_7;
  int local_6;
  
  if (*(code **)(DAT_00418bf4 + 0xc) == (code *)0x0) {
    return 0;
  }
  local_6 = DAT_00418bd4;
  local_8 = 0x2a;
  local_7 = 0;
  DAT_00416290 = (**(code **)(DAT_00418bf4 + 0xc))(&local_8,0x8102,0x180);
  if (DAT_00416290 == -1) {
    return 0;
  }
  DAT_004162a0 = (int)(DAT_00418bd4 + (DAT_00418bd4 >> 0x1f & 0xfffU)) >> 0xc;
  if (DAT_004162a0 < 3) {
    DAT_004162a0 = 3;
  }
  DAT_004162ac = FUN_00407130(DAT_004162a0 << 3);
  if (DAT_004162ac == 0) {
    (**(code **)(DAT_00418bf4 + 0x18))(DAT_00416290);
    return 0;
  }
  iVar3 = 0;
  DAT_004162a4 = (undefined4 *)0x0;
  if (0 < DAT_004162a0) {
    do {
      puVar2 = (undefined4 *)FUN_00407130(0x1010);
      if (puVar2 == (undefined4 *)0x0) {
        if (iVar3 < 3) {
          FUN_00407c80();
          return 0;
        }
        break;
      }
      *puVar2 = 0;
      puVar2[1] = DAT_004162a4;
      puVar1 = puVar2;
      if (DAT_004162a4 != (undefined4 *)0x0) {
        *DAT_004162a4 = puVar2;
        puVar1 = DAT_004162a8;
      }
      DAT_004162a8 = puVar1;
      iVar3 = iVar3 + 1;
      DAT_004162a4 = puVar2;
    } while (iVar3 < DAT_004162a0);
  }
  FUN_00407810();
  return 1;
}



void FUN_00407810(void)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  
  iVar2 = DAT_004162a4;
  if (DAT_004162a4 != 0) {
    do {
      *(undefined4 *)(iVar2 + 8) = 0xffffffff;
      *(undefined4 *)(iVar2 + 0xc) = 0;
      piVar1 = (int *)(iVar2 + 4);
      iVar2 = *piVar1;
    } while (*piVar1 != 0);
  }
  iVar2 = 0;
  if (0 < DAT_004162a0) {
    iVar3 = 0;
    do {
      iVar3 = iVar3 + 8;
      iVar2 = iVar2 + 1;
      *(undefined4 *)(DAT_004162ac + -8 + iVar3) = 0;
      *(undefined4 *)(DAT_004162ac + -4 + iVar3) = 0;
    } while (iVar2 < DAT_004162a0);
  }
  DAT_00416294 = FUN_00407ad0(0,1);
  if (DAT_00416294 != (int *)0x0) {
    DAT_00416298 = DAT_00416294 + 4;
    DAT_0041629c = DAT_00416294 + 0x404;
  }
  return;
}



int * __cdecl FUN_00407ad0(int param_1,uint param_2)

{
  int *piVar1;
  int **ppiVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  
  piVar3 = DAT_004162a8;
  ppiVar2 = *(int ***)(DAT_004162ac + param_1 * 8);
  if (ppiVar2 != (int **)0x0) {
    if (DAT_004162a4 != ppiVar2) {
      *(int **)((int)*ppiVar2 + 4) = ppiVar2[1];
      if (ppiVar2[1] == (int *)0x0) {
        DAT_004162a8 = *ppiVar2;
      }
      else {
        *ppiVar2[1] = (int)*ppiVar2;
      }
      *DAT_004162a4 = (int *)ppiVar2;
      *ppiVar2 = (int *)0x0;
      ppiVar2[1] = (int *)DAT_004162a4;
      DAT_004162a4 = ppiVar2;
    }
    ppiVar2[3] = (int *)((uint)ppiVar2[3] | param_2);
    return (int *)ppiVar2;
  }
  if (DAT_00416294 == DAT_004162a8) {
    return (int *)0x0;
  }
  piVar1 = DAT_004162a8 + 2;
  if ((*piVar1 != -1) && (*(undefined4 *)(DAT_004162ac + *piVar1 * 8) = 0, piVar3[3] != 0)) {
    iVar5 = *piVar1;
    iVar4 = (**(code **)(DAT_00418bf4 + 0x1c))(DAT_00416290,iVar5 << 0xc,0);
    if (iVar4 != iVar5 << 0xc) {
      return (int *)0x0;
    }
    iVar5 = (**(code **)(DAT_00418bf4 + 0x14))(DAT_00416290,piVar3 + 4,0x1000);
    if (iVar5 != 0x1000) {
      return (int *)0x0;
    }
    *(undefined4 *)(DAT_004162ac + 4 + *piVar1 * 8) = 1;
  }
  DAT_004162a8 = (int *)*DAT_004162a8;
  *(undefined4 *)((int)DAT_004162a8 + 4) = 0;
  *DAT_004162a4 = piVar3;
  *piVar3 = 0;
  piVar3[1] = (int)DAT_004162a4;
  DAT_004162a4 = (int **)piVar3;
  *(int **)(DAT_004162ac + param_1 * 8) = piVar3;
  if (*(int *)(DAT_004162ac + 4 + param_1 * 8) == 0) {
    if (param_2 == 0) {
      return (int *)0x0;
    }
  }
  else {
    iVar5 = (**(code **)(DAT_00418bf4 + 0x1c))(DAT_00416290,param_1 << 0xc,0);
    if (iVar5 != param_1 << 0xc) {
      return (int *)0x0;
    }
    iVar5 = (**(code **)(DAT_00418bf4 + 0x10))(DAT_00416290,piVar3 + 4,0x1000);
    if (iVar5 != 0x1000) {
      return (int *)0x0;
    }
  }
  piVar3[3] = param_2;
  *piVar1 = param_1;
  return piVar3;
}



void FUN_00407c80(void)

{
  int iVar1;
  int iVar2;
  
  FUN_00407150(DAT_004162ac);
  iVar2 = DAT_004162a4;
  while (iVar2 != 0) {
    iVar1 = *(int *)(iVar2 + 4);
    FUN_00407150(iVar2);
    iVar2 = iVar1;
  }
  (**(code **)(DAT_00418bf4 + 0x18))(DAT_00416290);
  return;
}



undefined4 __cdecl
FUN_00407cc0(undefined4 *param_1,char *param_2,int param_3,undefined4 param_4,undefined4 param_5)

{
  if ((*param_2 == 'C') && (param_2[1] == 'K')) {
    param_1[2] = param_2 + 2;
    param_1[5] = param_3 + -2;
    param_1[6] = 0;
    param_1[10] = 0;
    param_1[9] = 0;
    param_1[3] = param_4;
    param_1[4] = param_4;
    param_1[8] = param_5;
    *param_1 = 0;
    param_1[1] = 0;
    param_1[0xb] = 0;
    return 0;
  }
  return 3;
}



int __cdecl FUN_00407d10(uint *param_1,uint *param_2)

{
  uint uVar1;
  int iVar2;
  
  uVar1 = *param_2;
  param_1[7] = uVar1;
  if (param_1[8] < uVar1) {
    param_1[7] = param_1[8];
  }
  uVar1 = param_1[7];
  if (uVar1 == 0) {
LAB_00407da4:
    *param_2 = (uint)(ushort)((short)uVar1 - *(short *)(param_1 + 7));
    return 0;
  }
  switch(param_1[0xb]) {
  case 0:
    break;
  case 1:
    FUN_00408480((int)param_1,1);
    break;
  case 2:
    FUN_00407dd0((int)param_1,param_1[0xe],param_1[0xf],param_1[0x10],param_1[0x11],1);
    break;
  case 3:
    *param_2 = 0;
    return 0;
  default:
    return 3;
  }
  do {
    if ((*param_1 != 0) || (param_1[7] == 0)) goto LAB_00407da4;
    iVar2 = FUN_00408620(param_1);
    if (iVar2 != 0) {
      return 3 - (uint)(iVar2 == 3);
    }
  } while( true );
}



undefined4 __cdecl
FUN_00407dd0(int param_1,int param_2,int param_3,uint param_4,uint param_5,short param_6)

{
  undefined *puVar1;
  ushort uVar2;
  ushort uVar3;
  uint uVar4;
  byte *pbVar5;
  int iVar6;
  int *piVar7;
  int iVar8;
  byte bVar9;
  byte bVar10;
  uint uVar11;
  uint local_2c;
  uint local_20;
  undefined *local_18;
  int local_c;
  
  local_20 = *(uint *)(param_1 + 0x24);
  local_2c = *(uint *)(param_1 + 0x28);
  uVar2 = *(ushort *)(&DAT_00413450 + param_4 * 2);
  uVar3 = *(ushort *)(&DAT_00413450 + param_5 * 2);
  if (param_6 == 0) goto LAB_00407e33;
  if (*(short *)(param_1 + 0x48) == 0) goto LAB_00407e33;
  local_18 = *(undefined **)(param_1 + 0x4c);
  local_c = *(int *)(param_1 + 0x50);
  do {
    piVar7 = (int *)(param_1 + 0xc);
    while (iVar6 = local_c + -1, local_c != 0) {
      puVar1 = local_18 + 1;
      *(undefined *)*piVar7 = *local_18;
      *piVar7 = *piVar7 + 1;
      local_18 = puVar1;
      if ((int)*(undefined **)(param_1 + 0x10) - (int)puVar1 == -0x8000) {
        local_18 = *(undefined **)(param_1 + 0x10);
      }
      iVar8 = *(int *)(param_1 + 0x1c) + -1;
      *(int *)(param_1 + 0x1c) = iVar8;
      local_c = iVar6;
      if (iVar8 == 0) {
        *(undefined2 *)(param_1 + 0x48) = 1;
        *(int *)(param_1 + 0x38) = param_2;
        *(int *)(param_1 + 0x3c) = param_3;
        *(uint *)(param_1 + 0x40) = param_4;
        *(uint *)(param_1 + 0x44) = param_5;
        *(undefined **)(param_1 + 0x4c) = local_18;
        *(undefined4 *)(param_1 + 0x2c) = 2;
        *(int *)(param_1 + 0x50) = iVar6;
        goto LAB_0040845c;
      }
    }
LAB_00407e33:
    while( true ) {
      if (local_2c < param_4) {
        do {
          uVar4 = *(uint *)(param_1 + 0x18);
          if (uVar4 < *(uint *)(param_1 + 0x14)) {
            bVar9 = *(byte *)(*(int *)(param_1 + 8) + -1 + uVar4 + 1);
            *(uint *)(param_1 + 0x18) = uVar4 + 1;
          }
          else if (*(uint *)(param_1 + 0x14) == uVar4) {
            bVar9 = 0;
          }
          else {
            bVar9 = 0;
            *(undefined4 *)(param_1 + 4) = 1;
          }
          local_20 = local_20 | (uint)bVar9 << ((byte)local_2c & 0x1f);
          local_2c = local_2c + 8;
        } while (local_2c < param_4);
      }
      piVar7 = (int *)(param_1 + 4);
      if (*piVar7 != 0) {
        return 1;
      }
      pbVar5 = (byte *)((local_20 & uVar2) * 8 + param_2);
      bVar9 = *pbVar5;
      while (uVar4 = (uint)bVar9, 0x10 < uVar4) {
        if (uVar4 == 99) {
          return 1;
        }
        uVar4 = uVar4 - 0x10;
        local_20 = local_20 >> (pbVar5[1] & 0x1f);
        local_2c = local_2c - pbVar5[1];
        if (local_2c < uVar4) {
          do {
            uVar11 = *(uint *)(param_1 + 0x18);
            if (uVar11 < *(uint *)(param_1 + 0x14)) {
              bVar9 = *(byte *)(*(int *)(param_1 + 8) + -1 + uVar11 + 1);
              *(uint *)(param_1 + 0x18) = uVar11 + 1;
            }
            else if (*(uint *)(param_1 + 0x14) == uVar11) {
              bVar9 = 0;
            }
            else {
              *piVar7 = 1;
              bVar9 = 0;
            }
            local_20 = local_20 | (uint)bVar9 << ((byte)local_2c & 0x1f);
            local_2c = local_2c + 8;
          } while (local_2c < uVar4);
        }
        if (*piVar7 != 0) {
          return 1;
        }
        pbVar5 = (byte *)((*(ushort *)(&DAT_00413450 + uVar4 * 2) & local_20) * 8 +
                         *(int *)(pbVar5 + 4));
        bVar9 = *pbVar5;
      }
      local_20 = local_20 >> (pbVar5[1] & 0x1f);
      local_2c = local_2c - pbVar5[1];
      if (uVar4 != 0x10) break;
      **(byte **)(param_1 + 0xc) = pbVar5[4];
      *(int *)(param_1 + 0xc) = *(int *)(param_1 + 0xc) + 1;
      iVar6 = *(int *)(param_1 + 0x1c) + -1;
      *(int *)(param_1 + 0x1c) = iVar6;
      if (iVar6 == 0) {
        *(undefined2 *)(param_1 + 0x48) = 0;
        *(int *)(param_1 + 0x38) = param_2;
        *(int *)(param_1 + 0x3c) = param_3;
        *(uint *)(param_1 + 0x40) = param_4;
        *(undefined4 *)(param_1 + 0x2c) = 2;
        *(uint *)(param_1 + 0x44) = param_5;
        goto LAB_0040845c;
      }
    }
    if (uVar4 == 0xf) {
LAB_0040845c:
      *(uint *)(param_1 + 0x24) = local_20;
      *(uint *)(param_1 + 0x28) = local_2c;
      return 0;
    }
    if (local_2c < uVar4) {
      do {
        uVar11 = *(uint *)(param_1 + 0x18);
        if (uVar11 < *(uint *)(param_1 + 0x14)) {
          bVar10 = *(byte *)(*(int *)(param_1 + 8) + -1 + uVar11 + 1);
          *(uint *)(param_1 + 0x18) = uVar11 + 1;
        }
        else if (*(uint *)(param_1 + 0x14) == uVar11) {
          bVar10 = 0;
        }
        else {
          bVar10 = 0;
          *piVar7 = 1;
        }
        local_20 = local_20 | (uint)bVar10 << ((byte)local_2c & 0x1f);
        local_2c = local_2c + 8;
      } while (local_2c < uVar4);
    }
    if (*piVar7 != 0) {
      return 1;
    }
    local_c = (*(ushort *)(&DAT_00413450 + uVar4 * 2) & local_20) + (uint)*(ushort *)(pbVar5 + 4);
    local_2c = local_2c - uVar4;
    local_20 = local_20 >> (bVar9 & 0x1f);
    if (local_2c < param_5) {
      do {
        uVar4 = *(uint *)(param_1 + 0x18);
        if (uVar4 < *(uint *)(param_1 + 0x14)) {
          bVar9 = *(byte *)(*(int *)(param_1 + 8) + -1 + uVar4 + 1);
          *(uint *)(param_1 + 0x18) = uVar4 + 1;
        }
        else if (*(uint *)(param_1 + 0x14) == uVar4) {
          bVar9 = 0;
        }
        else {
          bVar9 = 0;
          *piVar7 = 1;
        }
        local_20 = local_20 | (uint)bVar9 << ((byte)local_2c & 0x1f);
        local_2c = local_2c + 8;
      } while (local_2c < param_5);
    }
    if (*piVar7 != 0) {
      return 1;
    }
    pbVar5 = (byte *)((local_20 & uVar3) * 8 + param_3);
    bVar9 = *pbVar5;
    while (uVar4 = (uint)bVar9, 0x10 < uVar4) {
      if (uVar4 == 99) {
        return 1;
      }
      uVar4 = uVar4 - 0x10;
      local_20 = local_20 >> (pbVar5[1] & 0x1f);
      local_2c = local_2c - pbVar5[1];
      if (local_2c < uVar4) {
        do {
          uVar11 = *(uint *)(param_1 + 0x18);
          if (uVar11 < *(uint *)(param_1 + 0x14)) {
            bVar9 = *(byte *)(*(int *)(param_1 + 8) + -1 + uVar11 + 1);
            *(uint *)(param_1 + 0x18) = uVar11 + 1;
          }
          else if (*(uint *)(param_1 + 0x14) == uVar11) {
            bVar9 = 0;
          }
          else {
            *piVar7 = 1;
            bVar9 = 0;
          }
          local_20 = local_20 | (uint)bVar9 << ((byte)local_2c & 0x1f);
          local_2c = local_2c + 8;
        } while (local_2c < uVar4);
      }
      if (*piVar7 != 0) {
        return 1;
      }
      pbVar5 = (byte *)((*(ushort *)(&DAT_00413450 + uVar4 * 2) & local_20) * 8 +
                       *(int *)(pbVar5 + 4));
      bVar9 = *pbVar5;
    }
    local_20 = local_20 >> (pbVar5[1] & 0x1f);
    local_2c = local_2c - pbVar5[1];
    if (local_2c < uVar4) {
      do {
        uVar11 = *(uint *)(param_1 + 0x18);
        if (uVar11 < *(uint *)(param_1 + 0x14)) {
          bVar10 = *(byte *)(*(int *)(param_1 + 8) + -1 + uVar11 + 1);
          *(uint *)(param_1 + 0x18) = uVar11 + 1;
        }
        else if (*(uint *)(param_1 + 0x14) == uVar11) {
          bVar10 = 0;
        }
        else {
          bVar10 = 0;
          *piVar7 = 1;
        }
        local_20 = local_20 | (uint)bVar10 << ((byte)local_2c & 0x1f);
        local_2c = local_2c + 8;
      } while (local_2c < uVar4);
    }
    if (*piVar7 != 0) {
      return 1;
    }
    uVar11 = *(ushort *)(&DAT_00413450 + uVar4 * 2) & local_20;
    local_20 = local_20 >> (bVar9 & 0x1f);
    uVar11 = uVar11 + *(ushort *)(pbVar5 + 4);
    local_2c = local_2c - uVar4;
    iVar6 = *(int *)(param_1 + 0xc);
    if ((uint)(iVar6 - *(int *)(param_1 + 0x10)) < uVar11) {
      local_18 = (undefined *)((iVar6 - uVar11) + 0x8000);
    }
    else {
      local_18 = (undefined *)(iVar6 - uVar11);
    }
  } while( true );
}



undefined4 __cdecl FUN_00408480(int param_1,short param_2)

{
  uint uVar1;
  int iVar2;
  byte bVar3;
  ushort uVar4;
  uint uVar5;
  uint uVar6;
  undefined4 *puVar7;
  undefined4 *puVar8;
  undefined4 *puVar9;
  uint local_4;
  
  if (param_2 == 0) {
    uVar4 = (ushort)*(int *)(param_1 + 0x28) & 7;
    local_4 = *(uint *)(param_1 + 0x24) >> (sbyte)uVar4;
    uVar5 = *(int *)(param_1 + 0x28) - (uint)uVar4;
    if (uVar5 < 0x10) {
      do {
        uVar6 = *(uint *)(param_1 + 0x18);
        if (uVar6 < *(uint *)(param_1 + 0x14)) {
          bVar3 = *(byte *)(*(int *)(param_1 + 8) + uVar6);
          *(uint *)(param_1 + 0x18) = uVar6 + 1;
        }
        else if (*(uint *)(param_1 + 0x14) == uVar6) {
          bVar3 = 0;
        }
        else {
          *(undefined4 *)(param_1 + 4) = 1;
          bVar3 = 0;
        }
        local_4 = local_4 | (uint)bVar3 << ((byte)uVar5 & 0x1f);
        uVar5 = uVar5 + 8;
      } while (uVar5 < 0x10);
    }
    uVar5 = uVar5 - 0x10;
    uVar6 = local_4 >> 0x10;
    local_4 = local_4 & 0xffff;
    if (uVar5 < 0x10) {
      do {
        uVar1 = *(uint *)(param_1 + 0x18);
        if (uVar1 < *(uint *)(param_1 + 0x14)) {
          bVar3 = *(byte *)(*(int *)(param_1 + 8) + uVar1);
          *(uint *)(param_1 + 0x18) = uVar1 + 1;
        }
        else if (*(uint *)(param_1 + 0x14) == uVar1) {
          bVar3 = 0;
        }
        else {
          *(undefined4 *)(param_1 + 4) = 1;
          bVar3 = 0;
        }
        uVar6 = uVar6 | (uint)bVar3 << ((byte)uVar5 & 0x1f);
        uVar5 = uVar5 + 8;
      } while (uVar5 < 0x10);
    }
    if ((~uVar6 & 0xffff) != local_4) {
      return 1;
    }
    if ((*(int *)(param_1 + 4) != 0) || (uVar5 != 0x10)) {
      return 1;
    }
    *(undefined4 *)(param_1 + 0x28) = 0;
    *(undefined4 *)(param_1 + 0x24) = 0;
    puVar7 = (undefined4 *)(*(int *)(param_1 + 8) + *(int *)(param_1 + 0x18));
    *(uint *)(param_1 + 0x18) = *(int *)(param_1 + 0x18) + local_4;
  }
  else {
    puVar7 = *(undefined4 **)(param_1 + 0x34);
    local_4 = *(uint *)(param_1 + 0x30);
    *(undefined4 *)(param_1 + 0x2c) = 0;
  }
  uVar5 = *(uint *)(param_1 + 0x1c);
  if (local_4 <= uVar5) {
    *(uint *)(param_1 + 0x1c) = uVar5 - local_4;
    puVar8 = *(undefined4 **)(param_1 + 0xc);
    for (uVar5 = local_4 >> 2; uVar5 != 0; uVar5 = uVar5 - 1) {
      *puVar8 = *puVar7;
      puVar7 = puVar7 + 1;
      puVar8 = puVar8 + 1;
    }
    for (uVar5 = local_4 & 3; uVar5 != 0; uVar5 = uVar5 - 1) {
      *(undefined *)puVar8 = *(undefined *)puVar7;
      puVar7 = (undefined4 *)((int)puVar7 + 1);
      puVar8 = (undefined4 *)((int)puVar8 + 1);
    }
    *(int *)(param_1 + 0xc) = *(int *)(param_1 + 0xc) + local_4;
    return 0;
  }
  puVar8 = puVar7;
  puVar9 = *(undefined4 **)(param_1 + 0xc);
  for (uVar6 = uVar5 >> 2; uVar6 != 0; uVar6 = uVar6 - 1) {
    *puVar9 = *puVar8;
    puVar8 = puVar8 + 1;
    puVar9 = puVar9 + 1;
  }
  for (uVar5 = uVar5 & 3; uVar5 != 0; uVar5 = uVar5 - 1) {
    *(undefined *)puVar9 = *(undefined *)puVar8;
    puVar8 = (undefined4 *)((int)puVar8 + 1);
    puVar9 = (undefined4 *)((int)puVar9 + 1);
  }
  iVar2 = *(int *)(param_1 + 0x1c);
  *(int *)(param_1 + 0xc) = *(int *)(param_1 + 0xc) + iVar2;
  *(uint *)(param_1 + 0x30) = local_4 - iVar2;
  *(undefined **)(param_1 + 0x34) = (undefined *)(iVar2 + (int)puVar7);
  *(undefined4 *)(param_1 + 0x2c) = 1;
  *(undefined4 *)(param_1 + 0x1c) = 0;
  return 0;
}



int __cdecl FUN_00408620(uint *param_1)

{
  int iVar1;
  uint uVar2;
  byte bVar3;
  uint uVar4;
  uint uVar5;
  
  uVar4 = param_1[9];
  uVar2 = param_1[10];
  if (uVar2 == 0) {
    uVar2 = 0;
    do {
      uVar5 = param_1[6];
      if (uVar5 < param_1[5]) {
        bVar3 = *(byte *)(param_1[2] + uVar5);
        param_1[6] = uVar5 + 1;
      }
      else if (param_1[5] == uVar5) {
        bVar3 = 0;
      }
      else {
        param_1[1] = 1;
        bVar3 = 0;
      }
      uVar4 = uVar4 | (uint)bVar3 << ((byte)uVar2 & 0x1f);
      uVar2 = uVar2 + 8;
    } while (uVar2 == 0);
  }
  uVar2 = uVar2 - 1;
  uVar5 = uVar4 >> 1;
  *param_1 = uVar4 & 1;
  if (uVar2 < 2) {
    do {
      uVar4 = param_1[6];
      if (uVar4 < param_1[5]) {
        bVar3 = *(byte *)(param_1[2] + uVar4);
        param_1[6] = uVar4 + 1;
      }
      else if (param_1[5] == uVar4) {
        bVar3 = 0;
      }
      else {
        param_1[1] = 1;
        bVar3 = 0;
      }
      uVar5 = uVar5 | (uint)bVar3 << ((byte)uVar2 & 0x1f);
      uVar2 = uVar2 + 8;
    } while (uVar2 < 2);
  }
  uVar4 = uVar5 & 3;
  param_1[9] = uVar5 >> 2;
  param_1[10] = uVar2 - 2;
  if (param_1[1] != 0) {
    return 1;
  }
  if (uVar4 == 0) {
    iVar1 = FUN_00408480((int)param_1,0);
    return iVar1;
  }
  if (uVar4 != 1) {
    if (uVar4 != 2) {
      return 2;
    }
    iVar1 = FUN_00408720((int)param_1);
    return iVar1;
  }
  iVar1 = FUN_004090e0((int)param_1);
  return iVar1;
}



int __cdecl FUN_00408720(int param_1)

{
  uint uVar1;
  int *piVar2;
  int iVar3;
  uint uVar4;
  uint *puVar5;
  byte bVar6;
  uint uVar7;
  uint uVar8;
  byte bVar9;
  uint uVar10;
  bool bVar11;
  uint local_510;
  uint local_50c;
  int *local_508;
  uint local_504;
  uint local_500;
  uint local_4fc;
  uint local_4f8;
  uint local_4f4;
  uint local_4f0 [316];
  
  local_510 = *(uint *)(param_1 + 0x24);
  uVar10 = *(uint *)(param_1 + 0x28);
  if (uVar10 < 5) {
    do {
      uVar7 = *(uint *)(param_1 + 0x18);
      if (uVar7 < *(uint *)(param_1 + 0x14)) {
        bVar6 = *(byte *)(*(int *)(param_1 + 8) + uVar7);
        *(uint *)(param_1 + 0x18) = uVar7 + 1;
      }
      else if (*(uint *)(param_1 + 0x14) == uVar7) {
        bVar6 = 0;
      }
      else {
        *(undefined4 *)(param_1 + 4) = 1;
        bVar6 = 0;
      }
      bVar9 = (byte)uVar10;
      uVar10 = uVar10 + 8;
      local_510 = local_510 | (uint)bVar6 << (bVar9 & 0x1f);
    } while (uVar10 < 5);
  }
  uVar10 = uVar10 - 5;
  uVar7 = local_510 >> 5;
  local_500 = (local_510 & 0x1f) + 0x101;
  local_510 = uVar7;
  if (uVar10 < 5) {
    do {
      uVar7 = *(uint *)(param_1 + 0x18);
      if (uVar7 < *(uint *)(param_1 + 0x14)) {
        bVar6 = *(byte *)(*(int *)(param_1 + 8) + uVar7);
        *(uint *)(param_1 + 0x18) = uVar7 + 1;
      }
      else if (*(uint *)(param_1 + 0x14) == uVar7) {
        bVar6 = 0;
      }
      else {
        *(undefined4 *)(param_1 + 4) = 1;
        bVar6 = 0;
      }
      bVar9 = (byte)uVar10;
      uVar10 = uVar10 + 8;
      local_510 = local_510 | (uint)bVar6 << (bVar9 & 0x1f);
    } while (uVar10 < 5);
  }
  uVar10 = uVar10 - 5;
  uVar7 = local_510 >> 5;
  local_4f8 = (local_510 & 0x1f) + 1;
  local_510 = uVar7;
  if (uVar10 < 4) {
    do {
      uVar7 = *(uint *)(param_1 + 0x18);
      if (uVar7 < *(uint *)(param_1 + 0x14)) {
        bVar6 = *(byte *)(*(int *)(param_1 + 8) + uVar7);
        *(uint *)(param_1 + 0x18) = uVar7 + 1;
      }
      else if (*(uint *)(param_1 + 0x14) == uVar7) {
        bVar6 = 0;
      }
      else {
        *(undefined4 *)(param_1 + 4) = 1;
        bVar6 = 0;
      }
      bVar9 = (byte)uVar10;
      uVar10 = uVar10 + 8;
      local_510 = local_510 | (uint)bVar6 << (bVar9 & 0x1f);
    } while (uVar10 < 4);
  }
  uVar10 = uVar10 - 4;
  uVar7 = local_510 >> 4;
  uVar1 = (local_510 & 0xf) + 4;
  if (((*(int *)(param_1 + 4) == 0) && (local_500 < 0x11f)) && (local_4f8 < 0x1f)) {
    local_50c = 0;
    local_510 = uVar7;
    if (uVar1 != 0) {
      local_508 = &DAT_00413300;
      local_4fc = uVar1;
      do {
        if (uVar10 < 3) {
          do {
            uVar7 = *(uint *)(param_1 + 0x18);
            if (uVar7 < *(uint *)(param_1 + 0x14)) {
              bVar6 = *(byte *)(*(int *)(param_1 + 8) + uVar7);
              *(uint *)(param_1 + 0x18) = uVar7 + 1;
            }
            else if (*(uint *)(param_1 + 0x14) == uVar7) {
              bVar6 = 0;
            }
            else {
              *(undefined4 *)(param_1 + 4) = 1;
              bVar6 = 0;
            }
            bVar9 = (byte)uVar10;
            uVar10 = uVar10 + 8;
            local_510 = local_510 | (uint)bVar6 << (bVar9 & 0x1f);
          } while (uVar10 < 3);
        }
        uVar7 = local_510 & 7;
        uVar10 = uVar10 - 3;
        local_510 = local_510 >> 3;
        local_4fc = local_4fc - 1;
        local_4f0[*local_508] = uVar7;
        local_50c = uVar1;
        local_508 = local_508 + 1;
      } while (local_4fc != 0);
    }
    if (local_50c < 0x13) {
      piVar2 = &DAT_00413300 + local_50c;
      do {
        iVar3 = *piVar2;
        piVar2 = piVar2 + 1;
        local_4f0[iVar3] = 0;
      } while (piVar2 < &DAT_0041334c);
    }
    if (*(int *)(param_1 + 4) != 0) {
      return 1;
    }
    local_504 = 7;
    iVar3 = FUN_00408ca0((int *)local_4f0,0x13,0x13,0,0,param_1 + 0x54,800,&local_504);
    if (iVar3 == 0) {
      uVar7 = local_500 + local_4f8;
      local_4fc = (uint)*(ushort *)(&DAT_00413450 + local_504 * 2);
      uVar1 = 0;
      local_508 = (int *)0x0;
      if (uVar7 != 0) {
        do {
          if (uVar10 < local_504) {
            do {
              uVar4 = *(uint *)(param_1 + 0x18);
              if (uVar4 < *(uint *)(param_1 + 0x14)) {
                bVar6 = *(byte *)(*(int *)(param_1 + 8) + uVar4);
                *(uint *)(param_1 + 0x18) = uVar4 + 1;
              }
              else if (*(uint *)(param_1 + 0x14) == uVar4) {
                bVar6 = 0;
              }
              else {
                *(undefined4 *)(param_1 + 4) = 1;
                bVar6 = 0;
              }
              bVar9 = (byte)uVar10;
              uVar10 = uVar10 + 8;
              local_510 = local_510 | (uint)bVar6 << (bVar9 & 0x1f);
            } while (uVar10 < local_504);
          }
          if (*(int *)(param_1 + 4) != 0) {
            return 1;
          }
          uVar4 = local_510 & local_4fc;
          bVar6 = *(byte *)(param_1 + 0x55 + uVar4 * 8);
          uVar10 = uVar10 - bVar6;
          local_510 = local_510 >> (bVar6 & 0x1f);
          uVar4 = (uint)*(ushort *)(param_1 + uVar4 * 8 + 0x58);
          if (uVar4 < 0x10) {
            local_4f0[uVar1] = uVar4;
            uVar1 = uVar1 + 1;
            local_508 = (int *)uVar4;
          }
          else if (uVar4 == 0x10) {
            if (uVar10 < 2) {
              do {
                uVar4 = *(uint *)(param_1 + 0x18);
                if (uVar4 < *(uint *)(param_1 + 0x14)) {
                  bVar6 = *(byte *)(*(int *)(param_1 + 8) + uVar4);
                  *(uint *)(param_1 + 0x18) = uVar4 + 1;
                }
                else if (*(uint *)(param_1 + 0x14) == uVar4) {
                  bVar6 = 0;
                }
                else {
                  *(undefined4 *)(param_1 + 4) = 1;
                  bVar6 = 0;
                }
                bVar9 = (byte)uVar10;
                uVar10 = uVar10 + 8;
                local_510 = local_510 | (uint)bVar6 << (bVar9 & 0x1f);
              } while (uVar10 < 2);
            }
            if (*(int *)(param_1 + 4) != 0) {
              return 1;
            }
            uVar10 = uVar10 - 2;
            uVar4 = local_510 >> 2;
            uVar8 = local_510 & 3;
            local_510 = uVar4;
            if (uVar7 < uVar1 + 3 + uVar8) goto LAB_00408bbd;
            if (uVar8 != 0xfffffffd) {
              iVar3 = uVar8 + 2;
              puVar5 = local_4f0 + uVar1;
              do {
                uVar1 = uVar1 + 1;
                *puVar5 = (uint)local_508;
                bVar11 = iVar3 != 0;
                iVar3 = iVar3 + -1;
                puVar5 = puVar5 + 1;
              } while (bVar11);
            }
          }
          else if (uVar4 == 0x11) {
            if (uVar10 < 3) {
              do {
                uVar4 = *(uint *)(param_1 + 0x18);
                if (uVar4 < *(uint *)(param_1 + 0x14)) {
                  bVar6 = *(byte *)(*(int *)(param_1 + 8) + uVar4);
                  *(uint *)(param_1 + 0x18) = uVar4 + 1;
                }
                else if (*(uint *)(param_1 + 0x14) == uVar4) {
                  bVar6 = 0;
                }
                else {
                  *(undefined4 *)(param_1 + 4) = 1;
                  bVar6 = 0;
                }
                bVar9 = (byte)uVar10;
                uVar10 = uVar10 + 8;
                local_510 = local_510 | (uint)bVar6 << (bVar9 & 0x1f);
              } while (uVar10 < 3);
            }
            if (*(int *)(param_1 + 4) != 0) {
              return 1;
            }
            uVar10 = uVar10 - 3;
            uVar4 = local_510 >> 3;
            uVar8 = local_510 & 7;
            local_510 = uVar4;
            if (uVar7 < uVar1 + 3 + uVar8) {
LAB_00408bbd:
              *(undefined4 *)(param_1 + 4) = 2;
              break;
            }
            if (uVar8 != 0xfffffffd) {
              puVar5 = local_4f0 + uVar1;
              iVar3 = uVar8 + 2;
              do {
                *puVar5 = 0;
                puVar5 = puVar5 + 1;
                uVar1 = uVar1 + 1;
                bVar11 = iVar3 != 0;
                iVar3 = iVar3 + -1;
              } while (bVar11);
            }
            local_508 = (int *)0x0;
          }
          else {
            if (uVar10 < 7) {
              do {
                uVar4 = *(uint *)(param_1 + 0x18);
                if (uVar4 < *(uint *)(param_1 + 0x14)) {
                  bVar6 = *(byte *)(*(int *)(param_1 + 8) + uVar4);
                  *(uint *)(param_1 + 0x18) = uVar4 + 1;
                }
                else if (*(uint *)(param_1 + 0x14) == uVar4) {
                  bVar6 = 0;
                }
                else {
                  *(undefined4 *)(param_1 + 4) = 1;
                  bVar6 = 0;
                }
                bVar9 = (byte)uVar10;
                uVar10 = uVar10 + 8;
                local_510 = local_510 | (uint)bVar6 << (bVar9 & 0x1f);
              } while (uVar10 < 7);
            }
            if (*(int *)(param_1 + 4) != 0) {
              return 1;
            }
            uVar10 = uVar10 - 7;
            uVar4 = local_510 >> 7;
            uVar8 = local_510 & 0x7f;
            local_510 = uVar4;
            if (uVar7 < uVar1 + 0xb + uVar8) goto LAB_00408bbd;
            if (uVar8 != 0xfffffff5) {
              puVar5 = local_4f0 + uVar1;
              iVar3 = uVar8 + 10;
              do {
                *puVar5 = 0;
                puVar5 = puVar5 + 1;
                uVar1 = uVar1 + 1;
                bVar11 = iVar3 != 0;
                iVar3 = iVar3 + -1;
              } while (bVar11);
            }
            local_508 = (int *)0x0;
          }
        } while (uVar1 < uVar7);
      }
      if (*(int *)(param_1 + 4) != 0) {
        return 1;
      }
      *(uint *)(param_1 + 0x24) = local_510;
      *(uint *)(param_1 + 0x28) = uVar10;
      local_504 = 9;
      iVar3 = FUN_00408ca0((int *)local_4f0,local_500,0x101,(int)&DAT_00413350,(int)&DAT_00413390,
                           param_1 + 0x54,800,&local_504);
      if (iVar3 == 0) {
        local_4f4 = 6;
        iVar3 = FUN_00408ca0((int *)(local_4f0 + local_500),local_4f8,0,(int)&DAT_004133d0,
                             (int)&DAT_00413410,param_1 + 0x1954,0x96,&local_4f4);
        if (iVar3 == 0) {
          iVar3 = FUN_00407dd0(param_1,param_1 + 0x54,param_1 + 0x1954,local_504,local_4f4,0);
          return iVar3;
        }
      }
    }
  }
  else {
    iVar3 = 1;
  }
  return iVar3;
}



undefined4 __cdecl
FUN_00408ca0(int *param_1,uint param_2,uint param_3,int param_4,int param_5,int param_6,uint param_7
            ,uint *param_8)

{
  uint *puVar1;
  uint uVar2;
  uint *puVar3;
  uint uVar4;
  int iVar5;
  int *piVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  byte bVar10;
  uint uVar11;
  uint uVar12;
  int iVar13;
  undefined4 *puVar14;
  int iVar15;
  uint local_584;
  char local_57c;
  int local_578;
  undefined4 local_574;
  undefined4 local_570;
  uint local_568;
  uint *local_564;
  int local_560;
  uint local_55c;
  int local_558;
  uint local_554;
  uint local_548 [34];
  int local_4c0 [15];
  uint auStack_484 [289];
  
  local_554 = 0;
  puVar3 = local_548;
  for (iVar5 = 0x11; uVar2 = param_2, piVar6 = param_1, iVar5 != 0; iVar5 = iVar5 + -1) {
    *puVar3 = 0;
    puVar3 = puVar3 + 1;
  }
  do {
    local_548[*piVar6] = local_548[*piVar6] + 1;
    uVar2 = uVar2 - 1;
    piVar6 = piVar6 + 1;
  } while (uVar2 != 0);
  if (local_548[0] == param_2) {
    *param_8 = 0;
    return 0;
  }
  uVar2 = 1;
  puVar3 = local_548 + 1;
  do {
    if (*puVar3 != 0) break;
    puVar3 = puVar3 + 1;
    uVar2 = uVar2 + 1;
  } while (puVar3 <= local_548 + 0x10);
  uVar9 = *param_8;
  if (*param_8 < uVar2) {
    uVar9 = uVar2;
  }
  uVar11 = 0x10;
  puVar3 = local_548 + 0x10;
  do {
    if (*puVar3 != 0) break;
    puVar3 = puVar3 + -1;
    uVar11 = uVar11 - 1;
  } while (puVar3 != local_548);
  if (uVar11 < uVar9) {
    uVar9 = uVar11;
  }
  *param_8 = uVar9;
  local_578 = 1 << ((byte)uVar2 & 0x1f);
  if (uVar2 < uVar11) {
    puVar3 = local_548 + uVar2;
    uVar7 = uVar2;
    do {
      uVar4 = *puVar3;
      if ((int)(local_578 - uVar4) < 0) {
        return 2;
      }
      puVar3 = puVar3 + 1;
      uVar7 = uVar7 + 1;
      local_578 = (local_578 - uVar4) * 2;
    } while (uVar7 < uVar11);
  }
  uVar7 = local_548[uVar11];
  local_578 = local_578 - uVar7;
  if (local_578 < 0) {
    return 2;
  }
  puVar3 = local_548 + 0x13;
  local_548[uVar11] = uVar7 + local_578;
  uVar7 = 0;
  puVar1 = local_548;
  local_548[18] = 0;
  uVar4 = uVar11;
  while (puVar1 = puVar1 + 1, uVar4 = uVar4 - 1, uVar4 != 0) {
    uVar7 = uVar7 + *puVar1;
    *puVar3 = uVar7;
    puVar3 = puVar3 + 1;
  }
  uVar7 = 0;
  do {
    iVar5 = *param_1;
    param_1 = param_1 + 1;
    if (iVar5 != 0) {
      uVar4 = local_548[iVar5 + 0x11] + 1;
      local_548[iVar5 + 0x11] = uVar4;
      auStack_484[uVar4] = uVar7;
    }
    uVar7 = uVar7 + 1;
  } while (uVar7 < param_2);
  local_564 = auStack_484 + 1;
  local_584 = 0;
  local_548[17] = 0;
  local_4c0[0] = 0;
  local_560 = 0;
  iVar5 = -uVar9;
  local_55c = 0;
  local_558 = -1;
  do {
    if ((int)uVar11 < (int)uVar2) {
      if ((local_578 != 0) && (uVar11 != 1)) {
        return 1;
      }
      return 0;
    }
    local_568 = local_548[uVar2];
    while( true ) {
      uVar7 = local_568 - 1;
      if (local_568 == 0) break;
      if ((int)(uVar9 + iVar5) < (int)uVar2) {
        iVar15 = local_558 << 2;
        do {
          iVar5 = iVar5 + uVar9;
          local_558 = local_558 + 1;
          uVar4 = (uVar11 & 0xffff) - iVar5;
          if (uVar9 < uVar4) {
            uVar4 = uVar9 & 0xffff;
          }
          uVar8 = uVar2 - iVar5;
          uVar12 = 1 << ((byte)uVar8 & 0x1f);
          if (local_568 < uVar12) {
            iVar13 = uVar12 - local_568;
            puVar3 = local_548 + uVar2;
            while (uVar8 = uVar8 + 1, uVar8 < uVar4) {
              uVar12 = iVar13 * 2;
              puVar3 = puVar3 + 1;
              if (uVar12 < *puVar3 || uVar12 == *puVar3) break;
              iVar13 = uVar12 - *puVar3;
            }
          }
          local_55c = 1 << ((byte)uVar8 & 0x1f);
          local_560 = param_6 + local_554 * 8;
          local_554 = local_554 + local_55c;
          if (param_7 < local_554) {
            return 3;
          }
          *(int *)((int)local_4c0 + iVar15 + 4) = local_560;
          if (iVar15 + 4 != 0) {
            *(uint *)((int)local_548 + iVar15 + 0x48) = local_584;
            local_574 = CONCAT31(CONCAT21(local_574._2_2_,(char)uVar9),(byte)uVar8 + 0x10);
            puVar14 = (undefined4 *)
                      ((local_584 >> ((char)iVar5 - (char)uVar9 & 0x1fU)) * 8 +
                      *(int *)((int)local_4c0 + iVar15));
            *puVar14 = local_574;
            puVar14[1] = local_560;
            local_570 = local_560;
          }
          iVar15 = iVar15 + 4;
        } while ((int)(uVar9 + iVar5) < (int)uVar2);
      }
      local_57c = (char)uVar2;
      bVar10 = (byte)iVar5;
      if (local_564 < auStack_484 + param_2 + 1) {
        uVar4 = *local_564;
        if (uVar4 < param_3) {
          local_574._0_1_ = (uVar4 < 0x100) + '\x0f';
        }
        else {
          iVar15 = (uVar4 - param_3) * 2;
          local_574._0_1_ = *(char *)(iVar15 + param_5);
          uVar4 = (uint)*(ushort *)(param_4 + iVar15);
        }
        local_564 = local_564 + 1;
        local_570 = CONCAT22(local_570._2_2_,(short)uVar4);
      }
      else {
        local_574._0_1_ = 'c';
      }
      local_574 = CONCAT31(CONCAT21(local_574._2_2_,local_57c - bVar10),(char)local_574);
      iVar15 = 1 << (local_57c - bVar10 & 0x1f);
      uVar4 = local_584 >> (bVar10 & 0x1f);
      if (uVar4 < local_55c) {
        puVar14 = (undefined4 *)(local_560 + uVar4 * 8);
        do {
          uVar4 = uVar4 + iVar15;
          *puVar14 = local_574;
          puVar14[1] = local_570;
          puVar14 = puVar14 + iVar15 * 2;
        } while (uVar4 < local_55c);
      }
      uVar8 = 1 << (local_57c - 1U & 0x1f);
      uVar4 = local_584 & uVar8;
      while (uVar4 != 0) {
        local_584 = local_584 ^ uVar8;
        uVar8 = uVar8 >> 1;
        uVar4 = local_584 & uVar8;
      }
      local_584 = local_584 ^ uVar8;
      puVar3 = local_548 + local_558 + 0x11;
      local_568 = uVar7;
      if (((1 << (bVar10 & 0x1f)) - 1U & local_584) != *puVar3) {
        do {
          puVar3 = puVar3 + -1;
          iVar5 = iVar5 - uVar9;
          local_558 = local_558 + -1;
        } while (((1 << ((byte)iVar5 & 0x1f)) - 1U & local_584) != *puVar3);
      }
    }
    uVar2 = uVar2 + 1;
  } while( true );
}



void __cdecl FUN_004090e0(int param_1)

{
  FUN_00407dd0(param_1,(int)&DAT_004163b0,(int)&DAT_004162b0,9,5,0);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 * __cdecl FUN_00409100(undefined *param_1)

{
  undefined4 *puVar1;
  int iVar2;
  undefined4 *puVar3;
  
  puVar1 = (undefined4 *)(*(code *)param_1)(0x1e04);
  if (puVar1 != (undefined4 *)0x0) {
    puVar3 = puVar1;
    for (iVar2 = 0x781; iVar2 != 0; iVar2 = iVar2 + -1) {
      *puVar3 = 0;
      puVar3 = puVar3 + 1;
    }
    if (_DAT_00413474 == 0) {
      FUN_00409140();
      _DAT_00413474 = 1;
    }
  }
  return puVar1;
}



int FUN_00409140(void)

{
  uint uVar1;
  int iVar2;
  uint local_484;
  int local_480 [280];
  int aiStack_20 [8];
  
  local_484 = 0;
  do {
    uVar1 = local_484 + 1;
    local_480[local_484] = 8;
    local_484 = uVar1;
  } while ((int)uVar1 < 0x90);
  for (; (int)uVar1 < 0x100; uVar1 = uVar1 + 1) {
    local_480[uVar1] = 9;
  }
  for (; (int)uVar1 < 0x118; uVar1 = uVar1 + 1) {
    local_480[uVar1] = 7;
  }
  for (; (int)uVar1 < 0x120; uVar1 = uVar1 + 1) {
    local_480[uVar1] = 8;
  }
  local_484 = 9;
  iVar2 = FUN_00408ca0(local_480,0x120,0x101,(int)&DAT_00413350,(int)&DAT_00413390,
                       (int)&DAT_004163b0,0x208,&local_484);
  if (iVar2 == 0) {
    local_484 = 0;
    do {
      uVar1 = local_484 + 1;
      local_480[local_484] = 5;
      local_484 = uVar1;
    } while ((int)uVar1 < 0x1e);
    local_484 = 5;
    iVar2 = FUN_00408ca0(local_480,0x1e,0,(int)&DAT_004133d0,(int)&DAT_00413410,(int)&DAT_004162b0,
                         0x20,&local_484);
    if (iVar2 < 2) {
      iVar2 = 0;
    }
  }
  return iVar2;
}



void __cdecl FUN_00409270(undefined4 param_1,undefined *param_2)

{
  (*(code *)param_2)(param_1);
  return;
}



bool __cdecl FUN_00409280(int *param_1)

{
  byte bVar1;
  int iVar2;
  uint uVar3;
  
  uVar3 = 4;
  *(undefined *)((int)param_1 + 0x2eb5) = 4;
  do {
    bVar1 = *(byte *)((int)param_1 + 0x2eb5);
    *(byte *)((int)param_1 + 0x2eb5) = bVar1 + 1;
    uVar3 = uVar3 + (1 << ((&DAT_00412010)[bVar1] & 0x1f));
  } while (uVar3 < (uint)param_1[1]);
  iVar2 = (*(code *)param_1[3000])(param_1[1] + 0x105);
  *param_1 = iVar2;
  return (bool)('\x01' - (iVar2 == 0));
}



void __cdecl FUN_004092e0(int *param_1)

{
  if (*param_1 != 0) {
    (*(code *)param_1[0xbb9])(*param_1);
    *param_1 = 0;
  }
  return;
}



void __cdecl FUN_00409300(int param_1)

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



void __cdecl FUN_00409360(int param_1)

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



void __cdecl FUN_004093b0(int param_1)

{
  *(undefined4 *)(param_1 + 0x2ec8) = 0;
  return;
}



void __cdecl FUN_004093c0(int param_1,undefined4 param_2,int param_3)

{
  undefined8 uVar1;
  
  uVar1 = FUN_0040a3cc(param_2,*(undefined4 *)(param_1 + 0x2ec4),*(char **)(param_1 + 0x2ec8),
                       *(undefined4 *)(param_1 + 0x2ec4),(char *)param_2,param_3);
  *(int *)(param_1 + 0x2ec8) = (int)uVar1;
  return;
}



uint __cdecl FUN_004093f0(int *param_1,int param_2)

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
          uVar1 = FUN_004097f0((int)param_1,1);
          if (uVar1 == 0) {
            param_1[0xbb1] = 0;
          }
          else {
            uVar1 = FUN_004097f0((int)param_1,0x10);
            uVar2 = FUN_004097f0((int)param_1,0x10);
            param_1[0xbb1] = uVar1 << 0x10 | uVar2;
          }
        }
        if (param_1[0xbb6] == 3) {
          if (((*(byte *)(param_1 + 0xbb4) & 1) != 0) &&
             (uVar1 = param_1[0xac1], uVar1 <= (uint)param_1[0xac2] && param_1[0xac2] != uVar1)) {
            param_1[0xac1] = uVar1 + 1;
          }
          param_1[0xbb6] = 0;
          FUN_004096c0((int)param_1);
        }
        uVar1 = FUN_004097f0((int)param_1,3);
        param_1[0xbb6] = uVar1;
        uVar1 = FUN_004097f0((int)param_1,8);
        uVar2 = FUN_004097f0((int)param_1,8);
        uVar3 = FUN_004097f0((int)param_1,8);
        iVar4 = uVar3 + (uVar1 * 0x100 + uVar2) * 0x100;
        param_1[0xbb4] = iVar4;
        param_1[0xbb5] = iVar4;
        if (param_1[0xbb6] == 2) {
          FUN_0040a840((int)param_1);
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
          FUN_0040a4f0((int)param_1);
        }
        else {
          if (iVar4 != 3) {
            return 0xffffffff;
          }
          iVar4 = FUN_0040a910((int)param_1);
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
          iVar5 = FUN_00409650(param_1,param_1[0xbb6],param_1[0xbb0],iVar4);
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
        FUN_004096c0((int)param_1);
      }
    } while (0 < param_2);
  }
  iVar4 = param_1[0xbb0];
  if (iVar4 == 0) {
    iVar4 = param_1[1];
  }
  FUN_0040a4a0((int)param_1,local_4,(undefined4 *)((iVar4 - local_4) + *param_1));
  return local_4;
}



int __cdecl FUN_00409650(int *param_1,int param_2,uint param_3,int param_4)

{
  int iVar1;
  
  if (param_2 == 2) {
    iVar1 = FUN_0040aff0(param_1,param_3,param_4);
    return iVar1;
  }
  if (param_2 == 1) {
    iVar1 = FUN_0040a980(param_3,param_1,param_1,param_3,param_4);
    return iVar1;
  }
  if (param_2 == 3) {
    iVar1 = FUN_0040a890(param_1,param_3,param_4);
    return iVar1;
  }
  return -1;
}



void __cdecl FUN_004096c0(int param_1)

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



void __cdecl FUN_00409710(int param_1)

{
  FUN_004096c0(param_1);
  return;
}



void __cdecl FUN_00409720(int param_1,byte param_2)

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



uint __cdecl FUN_004097f0(int param_1,byte param_2)

{
  uint uVar1;
  
  uVar1 = *(uint *)(param_1 + 0x2eb0);
  FUN_00409720(param_1,param_2);
  return uVar1 >> (0x20 - param_2 & 0x1f);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_00409820(byte param_1)

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
    *(int *)((int)&DAT_00417800 + iVar4) = iVar5;
    if (0 < 1 << ((&DAT_00413478)[iVar4] & 0x1f)) {
      iVar5 = iVar5 + (1 << ((&DAT_00413478)[iVar4] & 0x1f));
    }
    iVar4 = iVar4 + 4;
  } while (iVar4 < 0x6c);
  iVar4 = 0;
  iVar6 = 0;
  iVar5 = 0;
  do {
    if (iVar5 < 1 << (param_1 & 0x1f)) {
      DAT_00418580 = iVar6 + 1;
      if (iVar5 < 0x1000) {
        DAT_00418790 = DAT_00418580;
      }
      if (iVar5 < 0x40000) {
        DAT_004189a0 = DAT_00418580;
      }
    }
    pbVar1 = &DAT_004134e8 + iVar4;
    *(int *)((int)&DAT_0041786c + iVar4) = iVar5;
    iVar4 = iVar4 + 4;
    iVar5 = iVar5 + (1 << (*pbVar1 & 0x1f));
    iVar6 = iVar6 + 1;
  } while (iVar4 < 0xa8);
  iVar4 = 0;
  _DAT_00417920 = 7;
  _DAT_00417924 = 4;
  piVar2 = &DAT_00417928;
  do {
    piVar3 = piVar2 + 2;
    *piVar2 = 7 - iVar4;
    piVar2[1] = iVar4;
    iVar4 = iVar4 + 1;
    piVar2 = piVar3;
  } while (piVar3 < (int *)0x417961);
  _DAT_00418160 = 0x40;
  _DAT_00417f50 = 0x40;
  _DAT_00417d40 = 0x40;
  _DAT_00417b30 = 0x40;
  iVar4 = 0;
  _DAT_00418164 = 4;
  _DAT_00417f54 = 4;
  _DAT_00417d44 = 4;
  _DAT_00417b34 = 4;
  piVar2 = &DAT_00417b38;
  do {
    piVar3 = piVar2 + 2;
    iVar5 = 0x40 - iVar4;
    *piVar2 = iVar5;
    piVar2[0x84] = iVar5;
    piVar2[0x108] = iVar5;
    piVar2[0x18c] = iVar5;
    piVar2[1] = iVar4;
    piVar2[0x85] = iVar4;
    piVar2[0x109] = iVar4;
    piVar2[0x18d] = iVar4;
    iVar4 = iVar4 + 1;
    piVar2 = piVar3;
  } while (piVar3 < (int *)0x417d39);
  iVar4 = 0;
  _DAT_00418370 = 0x1b;
  _DAT_00418374 = 4;
  piVar2 = &DAT_00418378;
  do {
    piVar3 = piVar2 + 2;
    *piVar2 = 0x1b - iVar4;
    piVar2[1] = iVar4;
    iVar4 = iVar4 + 1;
    piVar2 = piVar3;
  } while (piVar3 < (int *)0x418451);
  iVar4 = 0;
  _DAT_00418584 = 4;
  _DAT_00418794 = 4;
  _DAT_004189a4 = 4;
  piVar2 = &DAT_00418588;
  do {
    piVar3 = piVar2 + 2;
    *piVar2 = DAT_00418580 - iVar4;
    piVar2[0x84] = DAT_00418790 - iVar4;
    piVar2[0x108] = DAT_004189a0 - iVar4;
    piVar2[1] = iVar4;
    piVar2[0x85] = iVar4;
    piVar2[0x109] = iVar4;
    iVar4 = iVar4 + 1;
    piVar2 = piVar3;
  } while (piVar3 < (int *)0x4186d9);
  return;
}



void __cdecl FUN_004099f0(int *param_1)

{
  int iVar1;
  uint *puVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  uint *puVar6;
  int iVar7;
  uint uVar8;
  int iVar9;
  uint *puVar10;
  
  iVar7 = *param_1;
  puVar6 = (uint *)(param_1 + 2);
  iVar5 = param_1[1];
  param_1[1] = iVar5 + -1;
  if (iVar5 + -1 == 0) {
    param_1[1] = 0x32;
    iVar5 = iVar7;
    puVar10 = puVar6;
    if (0 < iVar7) {
      do {
        uVar8 = *puVar10;
        *puVar10 = uVar8 - puVar10[2];
        uVar8 = (uVar8 - puVar10[2]) + 1;
        *puVar10 = uVar8;
        iVar5 = iVar5 + -1;
        *puVar10 = uVar8 >> 1;
        puVar10 = puVar10 + 2;
      } while (iVar5 != 0);
    }
    iVar5 = 0;
    if (0 < iVar7) {
      do {
        iVar1 = iVar5 + 1;
        if (iVar1 < iVar7) {
          iVar9 = iVar7 - iVar1;
          puVar10 = puVar6 + iVar1 * 2;
          puVar2 = puVar6 + iVar5 * 2;
          do {
            uVar8 = *puVar2;
            if (uVar8 <= *puVar10 && *puVar10 != uVar8) {
              uVar3 = puVar2[1];
              uVar4 = puVar10[1];
              *puVar2 = *puVar10;
              puVar2[1] = uVar4;
              *puVar10 = uVar8;
              puVar10[1] = uVar3;
            }
            puVar10 = puVar10 + 2;
            iVar9 = iVar9 + -1;
          } while (iVar9 != 0);
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



void FUN_00409ad0(void)

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
  
  local_c = CONCAT22(local_c._2_2_,(short)DAT_00417928);
  iVar7 = 0;
  uVar3 = FUN_0040a240(local_c);
  if (uVar3 < DAT_00417930) {
    puVar5 = &DAT_00417930;
    do {
      puVar5 = puVar5 + 2;
      iVar7 = iVar7 + 1;
    } while (uVar3 <= *puVar5 && *puVar5 != uVar3);
  }
  uVar1 = (&DAT_0041792c)[iVar7 * 2];
  FUN_0040a280(CONCAT22((short)(&DAT_00417928)[iVar7 * 2],(short)(&DAT_00417930)[iVar7 * 2]),local_c
              );
  piVar6 = (int *)&DAT_00417928;
  do {
    *piVar6 = *piVar6 + 8;
    piVar6 = piVar6 + 2;
    bVar8 = iVar7 != 0;
    iVar7 = iVar7 + -1;
  } while (bVar8);
  if (0xed8 < DAT_00417928) {
    FUN_004099f0((int *)&DAT_00417920);
  }
  switch(uVar1) {
  case 0:
    iVar7 = 0;
    local_c = CONCAT22(local_c._2_2_,(short)DAT_00417b38);
    uVar3 = FUN_0040a240(local_c);
    if (uVar3 < DAT_00417b40) {
      puVar5 = &DAT_00417b40;
      do {
        puVar5 = puVar5 + 2;
        iVar7 = iVar7 + 1;
      } while (uVar3 <= *puVar5 && *puVar5 != uVar3);
    }
    FUN_0040a280(CONCAT22((short)(&DAT_00417b38)[iVar7 * 2],(short)(&DAT_00417b40)[iVar7 * 2]),
                 local_c);
    piVar6 = (int *)&DAT_00417b38;
    do {
      *piVar6 = *piVar6 + 8;
      piVar6 = piVar6 + 2;
      bVar8 = iVar7 != 0;
      iVar7 = iVar7 + -1;
    } while (bVar8);
    if (0xed8 < DAT_00417b38) {
      FUN_004099f0((int *)&DAT_00417b30);
    }
    (*DAT_00418bf0)();
    return;
  case 1:
    iVar7 = 0;
    local_c = CONCAT22(local_c._2_2_,(short)DAT_00417d48);
    uVar3 = FUN_0040a240(local_c);
    if (uVar3 < DAT_00417d50) {
      puVar5 = &DAT_00417d50;
      do {
        puVar5 = puVar5 + 2;
        iVar7 = iVar7 + 1;
      } while (uVar3 <= *puVar5 && *puVar5 != uVar3);
    }
    FUN_0040a280(CONCAT22((short)(&DAT_00417d48)[iVar7 * 2],(short)(&DAT_00417d50)[iVar7 * 2]),
                 local_c);
    piVar6 = (int *)&DAT_00417d48;
    do {
      *piVar6 = *piVar6 + 8;
      piVar6 = piVar6 + 2;
      bVar8 = iVar7 != 0;
      iVar7 = iVar7 + -1;
    } while (bVar8);
    if (0xed8 < DAT_00417d48) {
      FUN_004099f0((int *)&DAT_00417d40);
    }
    (*DAT_00418bf0)();
    return;
  case 2:
    iVar7 = 0;
    local_c = CONCAT22(local_c._2_2_,(short)DAT_00417f58);
    uVar3 = FUN_0040a240(local_c);
    if (uVar3 < DAT_00417f60) {
      puVar5 = &DAT_00417f60;
      do {
        puVar5 = puVar5 + 2;
        iVar7 = iVar7 + 1;
      } while (uVar3 <= *puVar5 && *puVar5 != uVar3);
    }
    FUN_0040a280(CONCAT22((short)(&DAT_00417f58)[iVar7 * 2],(short)(&DAT_00417f60)[iVar7 * 2]),
                 local_c);
    piVar6 = (int *)&DAT_00417f58;
    do {
      *piVar6 = *piVar6 + 8;
      piVar6 = piVar6 + 2;
      bVar8 = iVar7 != 0;
      iVar7 = iVar7 + -1;
    } while (bVar8);
    if (0xed8 < DAT_00417f58) {
      FUN_004099f0((int *)&DAT_00417f50);
    }
    (*DAT_00418bf0)();
    return;
  case 3:
    iVar7 = 0;
    local_c = CONCAT22(local_c._2_2_,(short)DAT_00418168);
    uVar3 = FUN_0040a240(local_c);
    if (uVar3 < DAT_00418170) {
      puVar5 = &DAT_00418170;
      do {
        puVar5 = puVar5 + 2;
        iVar7 = iVar7 + 1;
      } while (uVar3 <= *puVar5 && *puVar5 != uVar3);
    }
    FUN_0040a280(CONCAT22((short)(&DAT_00418168)[iVar7 * 2],(short)(&DAT_00418170)[iVar7 * 2]),
                 local_c);
    piVar6 = (int *)&DAT_00418168;
    do {
      *piVar6 = *piVar6 + 8;
      piVar6 = piVar6 + 2;
      bVar8 = iVar7 != 0;
      iVar7 = iVar7 + -1;
    } while (bVar8);
    if (0xed8 < DAT_00418168) {
      FUN_004099f0((int *)&DAT_00418160);
    }
    (*DAT_00418bf0)();
    return;
  case 4:
    iVar7 = 0;
    local_c = CONCAT22(local_c._2_2_,(short)DAT_00418798);
    uVar3 = FUN_0040a240(local_c);
    if (uVar3 < DAT_004187a0) {
      puVar5 = &DAT_004187a0;
      do {
        puVar5 = puVar5 + 2;
        iVar7 = iVar7 + 1;
      } while (uVar3 <= *puVar5 && *puVar5 != uVar3);
    }
    iVar2 = (&DAT_0041879c)[iVar7 * 2];
    FUN_0040a280(CONCAT22((short)(&DAT_00418798)[iVar7 * 2],(short)(&DAT_004187a0)[iVar7 * 2]),
                 local_c);
    piVar6 = (int *)&DAT_00418798;
    do {
      *piVar6 = *piVar6 + 8;
      piVar6 = piVar6 + 2;
      bVar8 = iVar7 != 0;
      iVar7 = iVar7 + -1;
    } while (bVar8);
    if (0xed8 < DAT_00418798) {
      FUN_004099f0(&DAT_00418790);
    }
    uVar3 = FUN_0040a1a0(*(int *)(&DAT_004134e8 + iVar2 * 4));
    (*DAT_00418bb8)(3,(&DAT_0041786c)[iVar2] + uVar3 + 1);
    return;
  case 5:
    iVar7 = 0;
    local_c = CONCAT22(local_c._2_2_,(short)DAT_004189a8);
    uVar3 = FUN_0040a240(local_c);
    if (uVar3 < DAT_004189b0) {
      puVar5 = &DAT_004189b0;
      do {
        puVar5 = puVar5 + 2;
        iVar7 = iVar7 + 1;
      } while (uVar3 <= *puVar5 && *puVar5 != uVar3);
    }
    iVar2 = (&DAT_004189ac)[iVar7 * 2];
    FUN_0040a280(CONCAT22((short)(&DAT_004189a8)[iVar7 * 2],(short)(&DAT_004189b0)[iVar7 * 2]),
                 local_c);
    piVar6 = (int *)&DAT_004189a8;
    do {
      *piVar6 = *piVar6 + 8;
      piVar6 = piVar6 + 2;
      bVar8 = iVar7 != 0;
      iVar7 = iVar7 + -1;
    } while (bVar8);
    if (0xed8 < DAT_004189a8) {
      FUN_004099f0(&DAT_004189a0);
    }
    uVar3 = FUN_0040a1a0(*(int *)(&DAT_004134e8 + iVar2 * 4));
    (*DAT_00418bb8)(4,(&DAT_0041786c)[iVar2] + uVar3 + 1);
    return;
  case 6:
    iVar7 = 0;
    local_c = CONCAT22(local_c._2_2_,(short)DAT_00418378);
    uVar3 = FUN_0040a240(local_c);
    if (uVar3 < DAT_00418380) {
      puVar5 = &DAT_00418380;
      do {
        puVar5 = puVar5 + 2;
        iVar7 = iVar7 + 1;
      } while (uVar3 <= *puVar5 && *puVar5 != uVar3);
    }
    iVar2 = (&DAT_0041837c)[iVar7 * 2];
    FUN_0040a280(CONCAT22((short)(&DAT_00418378)[iVar7 * 2],(short)(&DAT_00418380)[iVar7 * 2]),
                 local_c);
    piVar6 = (int *)&DAT_00418378;
    do {
      *piVar6 = *piVar6 + 8;
      piVar6 = piVar6 + 2;
      bVar8 = iVar7 != 0;
      iVar7 = iVar7 + -1;
    } while (bVar8);
    if (0xed8 < DAT_00418378) {
      FUN_004099f0((int *)&DAT_00418370);
    }
    uVar3 = FUN_0040a1a0(*(int *)(&DAT_00413478 + iVar2 * 4));
    uVar1 = (&DAT_00417800)[iVar2];
    iVar7 = 0;
    local_c = CONCAT22(local_c._2_2_,(short)DAT_00418588);
    uVar4 = FUN_0040a240(local_c);
    if (uVar4 < DAT_00418590) {
      puVar5 = &DAT_00418590;
      do {
        puVar5 = puVar5 + 2;
        iVar7 = iVar7 + 1;
      } while (uVar4 <= *puVar5 && *puVar5 != uVar4);
    }
    iVar2 = (&DAT_0041858c)[iVar7 * 2];
    FUN_0040a280(CONCAT22((short)(&DAT_00418588)[iVar7 * 2],(short)(&DAT_00418590)[iVar7 * 2]),
                 local_c);
    piVar6 = (int *)&DAT_00418588;
    do {
      *piVar6 = *piVar6 + 8;
      piVar6 = piVar6 + 2;
      bVar8 = iVar7 != 0;
      iVar7 = iVar7 + -1;
    } while (bVar8);
    if (0xed8 < DAT_00418588) {
      FUN_004099f0(&DAT_00418580);
    }
    uVar4 = FUN_0040a1a0(*(int *)(&DAT_004134e8 + iVar2 * 4));
    (*DAT_00418bb8)((short)uVar1 + (short)uVar3 + 5,(&DAT_0041786c)[iVar2] + uVar4 + 1);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0040a0f0(void)

{
  char cVar1;
  uint uVar2;
  int iVar3;
  
  iVar3 = 0x10;
  _DAT_004173f4 = 0;
  do {
    DAT_004177e4 = DAT_004177e4 << 1;
    if (_DAT_004173f4 == 0) {
      if (_DAT_00418bec == 0) {
        uVar2 = 0;
        _DAT_00418bb4 = 1;
      }
      else {
        _DAT_004173f4 = 7;
        _DAT_00418bec = _DAT_00418bec + -1;
        cVar1 = *DAT_00418bb0;
        DAT_00418bb0 = DAT_00418bb0 + 1;
        DAT_004173f0 = (int)cVar1 << 1;
        uVar2 = DAT_004173f0 & 0x100;
      }
    }
    else {
      DAT_004173f0 = DAT_004173f0 << 1;
      _DAT_004173f4 = _DAT_004173f4 + -1;
      uVar2 = DAT_004173f0 & 0x100;
    }
    if (uVar2 != 0) {
      DAT_004177e4 = DAT_004177e4 | 1;
    }
    iVar3 = iVar3 + -1;
  } while (iVar3 != 0);
  DAT_004177e0 = 0;
  DAT_004177e2 = 0xffff;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

uint __cdecl FUN_0040a1a0(int param_1)

{
  char cVar1;
  uint uVar2;
  uint uVar3;
  
  uVar2 = 0;
  if (param_1 != 0) {
    do {
      param_1 = param_1 + -1;
      uVar2 = uVar2 * 2;
      if (_DAT_004173f4 == 0) {
        if (_DAT_00418bec == 0) {
          uVar3 = 0;
          _DAT_00418bb4 = 1;
        }
        else {
          _DAT_004173f4 = 7;
          _DAT_00418bec = _DAT_00418bec + -1;
          cVar1 = *DAT_00418bb0;
          DAT_00418bb0 = DAT_00418bb0 + 1;
          DAT_004173f0 = (int)cVar1 << 1;
          uVar3 = DAT_004173f0 & 0x100;
        }
      }
      else {
        DAT_004173f0 = DAT_004173f0 << 1;
        _DAT_004173f4 = _DAT_004173f4 + -1;
        uVar3 = DAT_004173f0 & 0x100;
      }
      if (uVar3 != 0) {
        uVar2 = uVar2 | 1;
      }
    } while (param_1 != 0);
  }
  return uVar2;
}



int __fastcall FUN_0040a240(uint param_1)

{
  return (int)(short)(((((uint)DAT_004177e4 - (uint)DAT_004177e0) + 1) * (param_1 & 0xffff) - 1) /
                     (((uint)DAT_004177e2 - (uint)DAT_004177e0) + 1));
}



void FUN_0040a270(void)

{
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0040a280(uint param_1,uint param_2)

{
  char cVar1;
  uint uVar2;
  int iVar3;
  
  iVar3 = ((uint)DAT_004177e2 - (uint)DAT_004177e0) + 1;
  DAT_004177e2 = (DAT_004177e0 + (short)(((param_1 >> 0x10) * iVar3) / (param_2 & 0xffff))) - 1;
  DAT_004177e0 = DAT_004177e0 + (short)(((param_1 & 0xffff) * iVar3) / (param_2 & 0xffff));
  do {
    if (((DAT_004177e2 ^ DAT_004177e0) & 0x8000) != 0) {
      if (((DAT_004177e0 & 0x4000) == 0) || ((DAT_004177e2 & 0x4000) != 0)) {
        return;
      }
      DAT_004177e4 = DAT_004177e4 ^ 0x4000;
      DAT_004177e0 = DAT_004177e0 & 0x3fff;
      DAT_004177e2 = DAT_004177e2 | 0x4000;
    }
    DAT_004177e0 = DAT_004177e0 << 1;
    DAT_004177e2 = DAT_004177e2 << 1;
    DAT_004177e4 = DAT_004177e4 << 1;
    DAT_004177e2 = DAT_004177e2 | 1;
    if (_DAT_004173f4 == 0) {
      if (_DAT_00418bec == 0) {
        uVar2 = 0;
        _DAT_00418bb4 = 1;
      }
      else {
        _DAT_004173f4 = 7;
        _DAT_00418bec = _DAT_00418bec + -1;
        cVar1 = *DAT_00418bb0;
        DAT_00418bb0 = DAT_00418bb0 + 1;
        DAT_004173f0 = (int)cVar1 << 1;
        uVar2 = DAT_004173f0 & 0x100;
      }
    }
    else {
      DAT_004173f0 = DAT_004173f0 << 1;
      _DAT_004173f4 = _DAT_004173f4 + -1;
      uVar2 = DAT_004173f0 & 0x100;
    }
    if (uVar2 != 0) {
      DAT_004177e4 = DAT_004177e4 | 1;
    }
  } while( true );
}



undefined8 __fastcall
FUN_0040a3cc(undefined4 param_1,undefined4 param_2,char *param_3,uint param_4,char *param_5,
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
LAB_0040a44b:
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
      goto LAB_0040a44b;
    }
    if (pcVar5[2] == -0x18) {
      pcVar5 = pcVar5 + 2;
      goto LAB_0040a44b;
    }
    if (pcVar5[3] == -0x18) {
      pcVar5 = pcVar5 + 3;
      goto LAB_0040a44b;
    }
    pcVar5 = pcVar5 + 4;
  } while( true );
}



void __cdecl FUN_0040a4a0(int param_1,uint param_2,undefined4 *param_3)

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
    FUN_004093c0(param_1,*(undefined4 *)(param_1 + 0x2b0c),param_2);
  }
  return;
}



bool __cdecl FUN_0040a4f0(int param_1)

{
  int iVar1;
  bool bVar2;
  undefined3 extraout_var;
  undefined3 extraout_var_00;
  undefined3 extraout_var_01;
  undefined4 extraout_EDX;
  undefined4 extraout_EDX_00;
  undefined8 uVar3;
  
  bVar2 = FUN_0040a5d0(param_1,0x100,param_1 + 0x2b14,param_1 + 0xa18);
  if (CONCAT31(extraout_var,bVar2) == 0) {
    return false;
  }
  bVar2 = FUN_0040a5d0(param_1,(uint)*(byte *)(param_1 + 0x2eb5) << 3,param_1 + 0x2c14,
                       param_1 + 0xb18);
  if (CONCAT31(extraout_var_00,bVar2) == 0) {
    return false;
  }
  iVar1 = (uint)*(byte *)(param_1 + 0x2eb5) * 8 + 0x100;
  uVar3 = FUN_0040b3ac(iVar1,extraout_EDX,param_1,iVar1,param_1 + 0xa18,10,
                       (undefined4 *)(param_1 + 0x18),param_1 + 0xe3c);
  if ((int)uVar3 == 0) {
    return false;
  }
  bVar2 = FUN_0040a5d0(param_1,0xf9,param_1 + 0x2db4,param_1 + 0xcb8);
  if (CONCAT31(extraout_var_01,bVar2) == 0) {
    return false;
  }
  uVar3 = FUN_0040b3ac(param_1 + 0x818,extraout_EDX_00,param_1,0xf9,param_1 + 0xcb8,8,
                       (undefined4 *)(param_1 + 0x818),param_1 + 0x233c);
  return (bool)('\x01' - ((int)uVar3 == 0));
}



bool __cdecl FUN_0040a5d0(int param_1,int param_2,int param_3,int param_4)

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
    uVar2 = FUN_004097f0(param_1,4);
    local_2d4[iVar5] = (byte)uVar2;
    iVar5 = iVar4;
  } while (iVar4 < 0x14);
  if (*(int *)(param_1 + 0x2ebc) != 0) {
    return false;
  }
  iVar5 = 0;
  FUN_0040b3ac(local_200,local_2d4,param_1,0x14,(int)local_2d4,8,(undefined4 *)local_200,
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
      FUN_00409720(param_1,local_2d4[sVar3]);
      if (*(int *)(param_1 + 0x2ebc) != 0) {
        return false;
      }
      if (sVar3 == 0x11) {
        uVar2 = FUN_004097f0(param_1,4);
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
        uVar2 = FUN_004097f0(param_1,5);
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
        uVar2 = FUN_004097f0(param_1,1);
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
        FUN_00409720(param_1,local_2d4[sVar3]);
        uVar1 = (&DAT_00412129)[(uint)*(byte *)(iVar5 + param_3) - (int)sVar3];
        for (; 0 < iVar4; iVar4 = iVar4 + -1) {
          *(undefined *)(iVar5 + param_4) = uVar1;
          iVar5 = iVar5 + 1;
        }
        iVar5 = iVar5 + -1;
      }
      else {
        *(undefined *)(iVar5 + param_4) =
             (&DAT_00412129)[(uint)*(byte *)(iVar5 + param_3) - (int)sVar3];
      }
      iVar5 = iVar5 + 1;
    } while (iVar5 < param_2);
  }
  return *(int *)(param_1 + 0x2ebc) == 0;
}



bool __cdecl FUN_0040a840(int param_1)

{
  uint uVar1;
  int iVar2;
  
  iVar2 = 0;
  do {
    iVar2 = iVar2 + 1;
    uVar1 = FUN_004097f0(param_1,3);
    *(char *)(param_1 + 0xe33 + iVar2) = (char)uVar1;
  } while (iVar2 < 8);
  if (*(int *)(param_1 + 0x2ebc) != 0) {
    return false;
  }
  iVar2 = FUN_0040b630(param_1,param_1 + 0xe34,(undefined4 *)(param_1 + 0xdb4));
  return (bool)('\x01' - (iVar2 == 0));
}



int __cdecl FUN_0040a890(int *param_1,uint param_2,int param_3)

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



undefined4 __cdecl FUN_0040a910(int param_1)

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
FUN_0040a980(undefined4 param_1,undefined4 param_2,int *param_3,uint param_4,int param_5)

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
    uVar2 = FUN_0040a9e0(param_3,param_4,iVar1);
    param_5 = (param_5 - uVar2) + param_4;
    param_3[0xbb0] = uVar2;
    param_1 = extraout_ECX;
    param_2 = extraout_EDX;
    param_4 = uVar2;
    if (param_5 < 1) {
      return param_5;
    }
  }
  uVar3 = FUN_0040b7c3(param_1,param_2,param_3,param_4,param_5);
  return (int)uVar3;
}



int __cdecl FUN_0040a9e0(int *param_1,int param_2,int param_3)

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
            goto LAB_0040ac02;
          }
        }
        else {
          if (cVar8 < '\x04') {
            iVar9 = 1;
          }
          else {
            bVar5 = (&DAT_00412010)[cVar8];
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
            iVar9 = uVar7 + *(int *)(&DAT_00412048 + cVar8 * 4);
            puVar11 = puVar10;
          }
          param_1[5] = param_1[4];
          param_1[4] = param_1[3];
LAB_0040ac02:
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



int __cdecl FUN_0040ac70(int *param_1,uint param_2,int param_3)

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
          bVar7 = (&DAT_00412010)[iVar6];
          if (bVar7 < 3) {
            if (bVar7 == 0) {
              local_14 = *(int *)(&DAT_00412048 + iVar6 * 4);
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
              local_14 = uVar8 + *(int *)(&DAT_00412048 + iVar6 * 4);
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
            local_14 = *(int *)(&DAT_00412048 + iVar6 * 4) + local_10 * 8 + local_14;
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



int __cdecl FUN_0040aff0(int *param_1,uint param_2,int param_3)

{
  uint uVar1;
  int iVar2;
  
  if ((int)param_2 < 0x101) {
    iVar2 = 0x101 - param_2;
    if (param_3 <= (int)(0x101 - param_2)) {
      iVar2 = param_3;
    }
    uVar1 = FUN_0040b050(param_1,param_2,iVar2);
    param_3 = (param_3 - uVar1) + param_2;
    param_1[0xbb0] = uVar1;
    param_2 = uVar1;
    if (param_3 < 1) {
      return param_3;
    }
  }
  iVar2 = FUN_0040ac70(param_1,param_2,param_3);
  return iVar2;
}



int __cdecl FUN_0040b050(int *param_1,int param_2,int param_3)

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
          bVar6 = (&DAT_00412010)[iVar11];
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
              local_14 = uVar8 + *(int *)(&DAT_00412048 + iVar11 * 4);
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
            local_14 = *(int *)(&DAT_00412048 + iVar11 * 4) + local_1c * 8 + local_14;
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
FUN_0040b3ac(undefined4 param_1,undefined4 param_2,undefined4 param_3,uint param_4,int param_5,
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
LAB_0040b517:
    do {
      uVar5 = (uint)*(byte *)(iVar4 + local_3c);
      if (uVar5 != 0) {
        local_2c = auStack_118[uVar5];
        uVar8 = local_2c + local_d4[uVar5 + 1];
        if ((int)uVar5 <= (int)local_24) {
          if (1 << ((byte)local_24 & 0x1f) < (int)uVar8) {
            uVar3 = 0;
            goto LAB_0040b5f1;
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
            goto LAB_0040b5f1;
          }
          goto LAB_0040b517;
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
LAB_0040b5f1:
  return CONCAT44(uStack_c,uVar3);
}



undefined4 __cdecl FUN_0040b630(undefined4 param_1,int param_2,undefined4 *param_3)

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
FUN_0040b7c3(undefined4 param_1,undefined4 param_2,int *param_3,uint param_4,int param_5)

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
      if (uVar4 <= param_4) goto LAB_0040ba04;
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
          goto LAB_0040b9c3;
        }
        iVar2 = local_28[uVar13];
        local_28[uVar13] = local_28[0];
        local_28[0] = iVar2;
      }
    }
    else {
      iVar11 = (local_38 >> ((&DAT_0040b790)[uVar5] & 0x1f)) + *(int *)(&DAT_00412048 + uVar5 * 4);
      bVar10 = (&DAT_00412010)[uVar5];
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
LAB_0040b9c3:
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
LAB_0040ba04:
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



void LZClose(INT hFile)

{
                    // WARNING: Could not recover jumptable at 0x0040ba52. Too many branches
                    // WARNING: Treating indirect jump as call
  LZClose(hFile);
  return;
}



LONG LZCopy(INT hfSource,INT hfDest)

{
  LONG LVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040ba58. Too many branches
                    // WARNING: Treating indirect jump as call
  LVar1 = LZCopy(hfSource,hfDest);
  return LVar1;
}



INT LZOpenFileA(LPSTR lpFileName,LPOFSTRUCT lpReOpenBuf,WORD wStyle)

{
  INT IVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040ba5e. Too many branches
                    // WARNING: Treating indirect jump as call
  IVar1 = LZOpenFileA(lpFileName,lpReOpenBuf,wStyle);
  return IVar1;
}



void __cdecl FUN_0040ba70(uint param_1)

{
  FUN_0040ba90(param_1,DAT_0041740c);
  return;
}



int __cdecl FUN_0040ba90(uint param_1,int param_2)

{
  int iVar1;
  
  if (param_1 < 0xffffffe1) {
    if (param_1 == 0) {
      param_1 = 1;
    }
    do {
      if (param_1 < 0xffffffe1) {
        iVar1 = FUN_0040bae0(param_1);
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
      iVar1 = FUN_0040c2e0(param_1);
    } while (iVar1 != 0);
  }
  return 0;
}



void __cdecl FUN_0040bae0(int param_1)

{
  int *piVar1;
  uint dwBytes;
  
  dwBytes = param_1 + 0xfU & 0xfffffff0;
  if ((dwBytes <= DAT_004157f4) &&
     (piVar1 = FUN_0040c6a0((int *)(param_1 + 0xfU >> 4)), piVar1 != (int *)0x0)) {
    return;
  }
  HeapAlloc(DAT_00419d2c,0,dwBytes);
  return;
}



void __cdecl FUN_0040bb20(undefined *param_1)

{
  undefined *lpMem;
  byte *pbVar1;
  int *local_4;
  
  lpMem = param_1;
  if (param_1 != (undefined *)0x0) {
    pbVar1 = (byte *)FUN_0040c5e0(param_1,&local_4,(uint *)&param_1);
    if (pbVar1 != (byte *)0x0) {
      FUN_0040c640((int)local_4,(int)param_1,pbVar1);
      return;
    }
    HeapFree(DAT_00419d2c,0,lpMem);
  }
  return;
}



uint __cdecl FUN_0040bb70(int param_1,uint param_2)

{
  int iVar1;
  BOOL BVar2;
  uint local_4;
  
  iVar1 = param_1;
  if (param_1 + 1U < 0x101) {
    return *(ushort *)(PTR_DAT_00413590 + param_1 * 2) & param_2;
  }
  if ((PTR_DAT_00413590[(param_1 >> 8 & 0xffU) * 2 + 1] & 0x80) == 0) {
    param_1._0_2_ = (ushort)(byte)param_1;
    iVar1 = 1;
  }
  else {
    param_1._0_2_ = CONCAT11((byte)param_1,(char)((uint)param_1 >> 8));
    param_1._0_3_ = (uint3)(ushort)param_1;
    iVar1 = 2;
  }
  BVar2 = FUN_0040ca60(1,(LPCSTR)&param_1,iVar1,(LPWORD)&local_4,0,0);
  if (BVar2 == 0) {
    return 0;
  }
  return local_4 & 0xffff & param_2;
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



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

uint __cdecl FUN_0040bc80(byte *param_1,byte **param_2,uint param_3,uint param_4)

{
  uint uVar1;
  uint uVar2;
  byte bVar3;
  uint local_c;
  byte *local_8;
  uint local_4;
  
  local_4 = 0;
  bVar3 = *param_1;
  local_8 = param_1 + 1;
  while( true ) {
    local_c = (uint)bVar3;
    if (DAT_0041379c < 2) {
      uVar1 = (byte)PTR_DAT_00413590[local_c * 2] & 8;
    }
    else {
      uVar1 = FUN_0040bb70(local_c,8);
    }
    if (uVar1 == 0) break;
    bVar3 = *local_8;
    local_8 = local_8 + 1;
  }
  if (bVar3 == 0x2d) {
    param_4 = param_4 | 2;
  }
  else if (bVar3 != 0x2b) goto LAB_0040bd0b;
  bVar3 = *local_8;
  local_8 = local_8 + 1;
  local_c = (uint)bVar3;
LAB_0040bd0b:
  if ((((int)param_3 < 0) || (param_3 == 1)) || (0x24 < (int)param_3)) {
    if (param_2 != (byte **)0x0) {
      *param_2 = param_1;
    }
    return 0;
  }
  if (param_3 == 0) {
    if (bVar3 == 0x30) {
      if ((*local_8 == 0x78) || (param_3 = 8, *local_8 == 0x58)) {
        param_3 = 0x10;
      }
    }
    else {
      param_3 = 10;
    }
  }
  if (((param_3 == 0x10) && (bVar3 == 0x30)) && ((*local_8 == 0x78 || (*local_8 == 0x58)))) {
    bVar3 = local_8[1];
    local_c = (uint)bVar3;
    local_8 = local_8 + 2;
  }
  uVar1 = (uint)(0xffffffff / (ulonglong)param_3);
  do {
    if (DAT_0041379c < 2) {
      uVar2 = (byte)PTR_DAT_00413590[local_c * 2] & 4;
    }
    else {
      uVar2 = FUN_0040bb70(local_c,4);
    }
    if (uVar2 == 0) {
      if (DAT_0041379c < 2) {
        uVar2 = *(ushort *)(PTR_DAT_00413590 + local_c * 2) & 0x103;
      }
      else {
        uVar2 = FUN_0040bb70(local_c,0x103);
      }
      if (uVar2 == 0) {
LAB_0040be44:
        local_8 = local_8 + -1;
        if ((param_4 & 8) == 0) {
          if (param_2 != (byte **)0x0) {
            local_8 = param_1;
          }
          local_4 = 0;
        }
        else if (((param_4 & 4) != 0) ||
                (((param_4 & 1) == 0 &&
                 ((((param_4 & 2) != 0 && (0x80000000 < local_4)) ||
                  (((param_4 & 2) == 0 && (0x7fffffff < local_4)))))))) {
          _DAT_00417420 = 0x22;
          if ((param_4 & 1) == 0) {
            local_4 = ((param_4 & 2) != 0) + 0x7fffffff;
          }
          else {
            local_4 = 0xffffffff;
          }
        }
        if (param_2 != (byte **)0x0) {
          *param_2 = local_8;
        }
        if ((param_4 & 2) != 0) {
          local_4 = -local_4;
        }
        return local_4;
      }
      uVar2 = FUN_0040ccd0((int)(char)bVar3);
      uVar2 = uVar2 - 0x37;
    }
    else {
      uVar2 = (int)(char)bVar3 - 0x30;
    }
    if (param_3 <= uVar2) goto LAB_0040be44;
    if ((local_4 < uVar1) ||
       ((local_4 == uVar1 && (uVar2 <= (uint)(0xffffffff % (ulonglong)param_3))))) {
      local_4 = local_4 * param_3 + uVar2;
      param_4 = param_4 | 8;
    }
    else {
      param_4 = param_4 | 0xc;
    }
    bVar3 = *local_8;
    local_8 = local_8 + 1;
    local_c = (uint)bVar3;
  } while( true );
}



void __cdecl FUN_0040bf10(byte *param_1,byte **param_2,uint param_3)

{
  FUN_0040bc80(param_1,param_2,param_3,1);
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



int __cdecl FUN_0040c000(char *param_1,char *param_2)

{
  int iVar1;
  char *local_20;
  int local_1c;
  char *local_18;
  undefined4 local_14;
  
  local_18 = param_1;
  local_20 = param_1;
  local_14 = 0x42;
  local_1c = 0x7fffffff;
  iVar1 = FUN_0040cf00(&local_20,param_2,(undefined4 *)&stack0x0000000c);
  local_1c = local_1c + -1;
  if (-1 < local_1c) {
    *local_20 = '\0';
    return iVar1;
  }
  FUN_0040cdd0(0,&local_20);
  return iVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __fpmath
// 
// Library: Visual Studio 1998 Release

void __cdecl __fpmath(int param_1)

{
  FUN_0040c0a0();
  _DAT_004173fc = FUN_0040da30();
  __setdefaultprecision();
  return;
}



void FUN_0040c0a0(void)

{
  PTR_FUN_00415804 = &LAB_0040dac0;
  PTR_FUN_00415800 = &LAB_0040df00;
  PTR_FUN_00415808 = &LAB_0040db50;
  PTR_FUN_0041580c = FUN_0040da60;
  PTR_FUN_00415810 = &LAB_0040db30;
  PTR_FUN_00415814 = &LAB_0040df00;
  return;
}



uint __cdecl FUN_0040c0e0(int param_1)

{
  uint uVar1;
  
  if (1 < DAT_0041379c) {
    uVar1 = FUN_0040bb70(param_1,8);
    return uVar1;
  }
  return (byte)PTR_DAT_00413590[param_1 * 2] & 8;
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
  undefined4 *unaff_FS_OFFSET;
  undefined4 uVar8;
  _STARTUPINFOA local_60;
  undefined *local_1c;
  undefined4 local_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  byte *pbVar7;
  
  local_8 = 0xffffffff;
  puStack_c = &DAT_00412140;
  puStack_10 = &LAB_0040ec68;
  local_14 = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_14;
  local_1c = &stack0xffffff88;
  DVar2 = GetVersion();
  _DAT_00417438 = DVar2 >> 8 & 0xff;
  _DAT_00417434 = DVar2 & 0xff;
  _DAT_00417430 = _DAT_00417434 * 0x100 + _DAT_00417438;
  _DAT_0041742c = DVar2 >> 0x10;
  iVar3 = FUN_0040c300();
  if (iVar3 == 0) {
    __amsg_exit(0x1c);
  }
  local_8 = 0;
  FUN_0040e970();
  FUN_0040e960();
  DAT_00419d30 = (byte *)GetCommandLineA();
  DAT_00417400 = FUN_0040e530();
  if ((DAT_00417400 == (undefined4 *)0x0) || (DAT_00419d30 == (byte *)0x0)) {
    FUN_0040cbc0(0xffffffff);
  }
  FUN_0040e280();
  FUN_0040e190();
  FUN_0040cb90();
  pbVar6 = DAT_00419d30;
  if (*DAT_00419d30 == 0x22) {
    while( true ) {
      pbVar7 = pbVar6;
      pbVar6 = pbVar7 + 1;
      bVar1 = *pbVar6;
      if ((bVar1 == 0x22) || (bVar1 == 0)) break;
      iVar3 = FUN_0040e130((uint)bVar1);
      if (iVar3 != 0) {
        pbVar6 = pbVar7 + 2;
      }
    }
    if (*pbVar6 == 0x22) {
      pbVar6 = pbVar7 + 2;
    }
  }
  else {
    for (; 0x20 < *pbVar6; pbVar6 = pbVar6 + 1) {
    }
  }
  for (; (*pbVar6 != 0 && (*pbVar6 < 0x21)); pbVar6 = pbVar6 + 1) {
  }
  local_60.dwFlags = 0;
  GetStartupInfoA(&local_60);
  if ((local_60.dwFlags & 1) == 0) {
    local_60._48_4_ = 10;
  }
  else {
    local_60._48_4_ = local_60._48_4_ & 0xffff;
  }
  uVar8 = 0;
  pHVar4 = GetModuleHandleA((LPCSTR)0x0);
  UVar5 = FUN_00404dc0(pHVar4,uVar8,(char *)pbVar6,local_60._48_4_);
  FUN_0040cbc0(UVar5);
  *unaff_FS_OFFSET = local_14;
  return;
}



// Library Function - Single Match
//  __amsg_exit
// 
// Library: Visual Studio 1998 Release

void __cdecl __amsg_exit(int param_1)

{
  if (DAT_00417408 == 1) {
    FUN_0040ed40();
  }
  FUN_0040ed80((undefined *)param_1);
  (*(code *)PTR___exit_004137c4)(0xff);
  return;
}



undefined4 __cdecl FUN_0040c2e0(undefined4 param_1)

{
  int iVar1;
  
  if (DAT_00417410 != (code *)0x0) {
    iVar1 = (*DAT_00417410)(param_1);
    if (iVar1 != 0) {
      return 1;
    }
  }
  return 0;
}



undefined4 FUN_0040c300(void)

{
  undefined **ppuVar1;
  
  DAT_00419d2c = HeapCreate(1,0x1000,0);
  if (DAT_00419d2c == (HANDLE)0x0) {
    return 0;
  }
  ppuVar1 = FUN_0040c340();
  if (ppuVar1 == (undefined **)0x0) {
    HeapDestroy(DAT_00419d2c);
    return 0;
  }
  return 1;
}



undefined ** FUN_0040c340(void)

{
  bool bVar1;
  undefined4 *lpAddress;
  LPVOID pvVar2;
  int iVar3;
  undefined **ppuVar4;
  undefined **lpMem;
  undefined4 *puVar5;
  
  if (DAT_004137e0 == -1) {
    lpMem = &PTR_LOOP_004137d0;
  }
  else {
    lpMem = (undefined **)HeapAlloc(DAT_00419d2c,0,0x2020);
    if (lpMem == (undefined **)0x0) {
      return (undefined **)0x0;
    }
  }
  lpAddress = (undefined4 *)VirtualAlloc((LPVOID)0x0,0x400000,0x2000,4);
  if (lpAddress != (undefined4 *)0x0) {
    pvVar2 = VirtualAlloc(lpAddress,0x10000,0x1000,4);
    if (pvVar2 != (LPVOID)0x0) {
      if (lpMem == &PTR_LOOP_004137d0) {
        if (PTR_LOOP_004137d0 == (undefined *)0x0) {
          PTR_LOOP_004137d0 = (undefined *)&PTR_LOOP_004137d0;
        }
        if (PTR_LOOP_004137d4 == (undefined *)0x0) {
          PTR_LOOP_004137d4 = (undefined *)&PTR_LOOP_004137d0;
        }
      }
      else {
        *lpMem = (undefined *)&PTR_LOOP_004137d0;
        lpMem[1] = PTR_LOOP_004137d4;
        PTR_LOOP_004137d4 = (undefined *)lpMem;
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
  if (lpMem != &PTR_LOOP_004137d0) {
    HeapFree(DAT_00419d2c,0,lpMem);
  }
  return (undefined **)0x0;
}



void __cdecl FUN_0040c4b0(undefined **param_1)

{
  VirtualFree(param_1[4],0,0x8000);
  if ((undefined **)PTR_LOOP_004157f0 == param_1) {
    PTR_LOOP_004157f0 = param_1[1];
  }
  if (param_1 != &PTR_LOOP_004137d0) {
    *(undefined **)param_1[1] = *param_1;
    *(undefined **)(*param_1 + 4) = param_1[1];
    HeapFree(DAT_00419d2c,0,param_1);
    return;
  }
  DAT_004137e0 = 0xffffffff;
  return;
}



void __cdecl FUN_0040c510(int param_1)

{
  BOOL BVar1;
  undefined **ppuVar2;
  int iVar3;
  int iVar4;
  undefined **ppuVar5;
  undefined **ppuVar6;
  
  ppuVar6 = (undefined **)PTR_LOOP_004137d4;
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
            DAT_00417414 = DAT_00417414 + -1;
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
          FUN_0040c4b0(ppuVar6);
        }
      }
    }
    if ((ppuVar5 == (undefined **)PTR_LOOP_004137d4) || (ppuVar6 = ppuVar5, param_1 < 1)) {
      return;
    }
  } while( true );
}



int __cdecl FUN_0040c5e0(undefined *param_1,int **param_2,uint *param_3)

{
  undefined **ppuVar1;
  uint uVar2;
  
  ppuVar1 = &PTR_LOOP_004137d0;
  while ((param_1 < ppuVar1[4] || param_1 == ppuVar1[4] || (ppuVar1[5] <= param_1))) {
    ppuVar1 = (undefined **)*ppuVar1;
    if (ppuVar1 == &PTR_LOOP_004137d0) {
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



void __cdecl FUN_0040c640(int param_1,int param_2,byte *param_3)

{
  int *piVar1;
  int iVar2;
  
  iVar2 = param_2 - *(int *)(param_1 + 0x10) >> 0xc;
  piVar1 = (int *)(param_1 + 0x18 + iVar2 * 8);
  *piVar1 = *(int *)(param_1 + 0x18 + iVar2 * 8) + (uint)*param_3;
  *param_3 = 0;
  piVar1[1] = 0xf1;
  if ((*piVar1 == 0xf0) && (DAT_00417414 = DAT_00417414 + 1, DAT_00417414 == 0x20)) {
    FUN_0040c510(0x10);
  }
  return;
}



int * __cdecl FUN_0040c6a0(int *param_1)

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
  
  local_4 = (int *)PTR_LOOP_004157f0;
  do {
    if (local_4[4] != -1) {
      ppiVar10 = (int **)local_4[2];
      ppiVar8 = (int **)(((int)ppiVar10 + (-0x18 - (int)local_4) >> 3) * 0x1000 + local_4[4]);
      for (; ppiVar10 < local_4 + 0x806; ppiVar10 = ppiVar10 + 2) {
        if (((int)param_1 <= (int)*ppiVar10) && (param_1 <= ppiVar10[1] && ppiVar10[1] != param_1))
        {
          piVar4 = (int *)FUN_0040c8e0(ppiVar8,*ppiVar10,param_1);
          if (piVar4 != (int *)0x0) {
            PTR_LOOP_004157f0 = (undefined *)local_4;
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
          piVar4 = (int *)FUN_0040c8e0(ppiVar11,*ppiVar10,param_1);
          if (piVar4 != (int *)0x0) {
            PTR_LOOP_004157f0 = (undefined *)local_4;
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
  } while (local_4 != (int *)PTR_LOOP_004157f0);
  ppuVar7 = &PTR_LOOP_004137d0;
  while ((ppuVar7[4] == (undefined *)0xffffffff || (ppuVar7[3] == (undefined *)0x0))) {
    ppuVar7 = (undefined **)*ppuVar7;
    if (ppuVar7 == &PTR_LOOP_004137d0) {
      ppuVar7 = FUN_0040c340();
      if (ppuVar7 == (undefined **)0x0) {
        return (int *)0x0;
      }
      piVar4 = (int *)ppuVar7[4];
      *(char *)(piVar4 + 2) = (char)param_1;
      PTR_LOOP_004157f0 = (undefined *)ppuVar7;
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
  PTR_LOOP_004157f0 = (undefined *)ppuVar7;
  ppuVar7[3] = (undefined *)(-(uint)bVar12 & (uint)ppuVar6);
  *(char *)(piVar4 + 2) = (char)param_1;
  ppuVar7[2] = (undefined *)ppuVar2;
  *ppuVar2 = *ppuVar2 + -(int)param_1;
  piVar4[1] = piVar4[1] - (int)param_1;
  *piVar4 = (int)(piVar4 + 2) + (int)param_1;
  return piVar4 + 0x40;
}



int __cdecl FUN_0040c8e0(int **param_1,int *param_2,int *param_3)

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
            goto LAB_0040ca2f;
          }
          *param_1 = (int *)(int **)((int)ppiVar6 + (int)param_3);
          param_1[1] = (int *)((int)piVar5 - (int)param_3);
          goto LAB_0040ca36;
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
LAB_0040ca2f:
            param_1[1] = (int *)0x0;
          }
LAB_0040ca36:
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



BOOL __cdecl
FUN_0040ca60(DWORD param_1,LPCSTR param_2,int param_3,LPWORD param_4,UINT param_5,LCID param_6)

{
  BOOL BVar1;
  int iVar2;
  int *lpWideCharStr;
  WORD local_2;
  
  lpWideCharStr = (int *)0x0;
  if (DAT_0041741c == 0) {
    BVar1 = GetStringTypeA(0,1,"",1,&local_2);
    if (BVar1 == 0) {
      BVar1 = GetStringTypeW(1,L"",1,&local_2);
      if (BVar1 == 0) {
        return 0;
      }
      DAT_0041741c = 1;
    }
    else {
      DAT_0041741c = 2;
    }
  }
  if (DAT_0041741c == 2) {
    if (param_6 == 0) {
      param_6 = DAT_004176c0;
    }
    BVar1 = GetStringTypeA(param_6,param_1,param_2,param_3,param_4);
    return BVar1;
  }
  param_6 = DAT_0041741c;
  if (DAT_0041741c == 1) {
    param_6 = 0;
    if (param_5 == 0) {
      param_5 = DAT_004176d0;
    }
    iVar2 = MultiByteToWideChar(param_5,9,param_2,param_3,(LPWSTR)0x0,0);
    if (iVar2 != 0) {
      lpWideCharStr = FUN_0040f2a0(2,iVar2);
      if (lpWideCharStr != (int *)0x0) {
        iVar2 = MultiByteToWideChar(param_5,1,param_2,param_3,(LPWSTR)lpWideCharStr,iVar2);
        if (iVar2 != 0) {
          BVar1 = GetStringTypeW(param_1,(LPCWSTR)lpWideCharStr,iVar2,param_4);
          FUN_0040bb20((undefined *)lpWideCharStr);
          return BVar1;
        }
      }
    }
    FUN_0040bb20((undefined *)lpWideCharStr);
  }
  return param_6;
}



void FUN_0040cb90(void)

{
  if (PTR___fpmath_004137b8 != (undefined *)0x0) {
    (*(code *)PTR___fpmath_004137b8)();
  }
  FUN_0040ccb0((undefined **)&DAT_00413008,(undefined **)&DAT_00413010);
  FUN_0040ccb0((undefined **)&DAT_00413000,(undefined **)&DAT_00413004);
  return;
}



void __cdecl FUN_0040cbc0(UINT param_1)

{
  FUN_0040cc00(param_1,0,0);
  return;
}



// Library Function - Single Match
//  __exit
// 
// Library: Visual Studio 1998 Release

void __cdecl __exit(int _Code)

{
  FUN_0040cc00(_Code,1,0);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_0040cc00(UINT param_1,int param_2,int param_3)

{
  HANDLE hProcess;
  code **ppcVar1;
  code **ppcVar2;
  UINT uExitCode;
  
  if (DAT_00417468 == 1) {
    uExitCode = param_1;
    hProcess = GetCurrentProcess();
    TerminateProcess(hProcess,uExitCode);
  }
  _DAT_00417464 = 1;
  DAT_00417460 = (undefined)param_3;
  if (param_2 == 0) {
    if ((DAT_00419d28 != (code **)0x0) &&
       (ppcVar2 = (code **)(DAT_00419d24 + -4), ppcVar1 = DAT_00419d28, DAT_00419d28 <= ppcVar2)) {
      do {
        if (*ppcVar2 != (code *)0x0) {
          (**ppcVar2)();
          ppcVar1 = DAT_00419d28;
        }
        ppcVar2 = ppcVar2 + -1;
      } while (ppcVar1 <= ppcVar2);
    }
    FUN_0040ccb0((undefined **)&DAT_00413014,(undefined **)&DAT_0041301c);
  }
  FUN_0040ccb0((undefined **)&DAT_00413020,(undefined **)&DAT_00413024);
  if (param_3 == 0) {
    DAT_00417468 = 1;
                    // WARNING: Subroutine does not return
    ExitProcess(param_1);
  }
  return;
}



void __cdecl FUN_0040ccb0(undefined **param_1,undefined **param_2)

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



uint __cdecl FUN_0040ccd0(uint param_1)

{
  uint uVar1;
  uint uVar2;
  LPCWSTR pWVar3;
  int iVar4;
  uint local_8 [2];
  
  uVar1 = param_1;
  if (DAT_004176c0 == 0) {
    if ((0x60 < (int)param_1) && ((int)param_1 < 0x7b)) {
      return param_1 - 0x20;
    }
  }
  else {
    if ((int)param_1 < 0x100) {
      if (DAT_0041379c < 2) {
        uVar2 = (byte)PTR_DAT_00413590[param_1 * 2] & 2;
      }
      else {
        uVar2 = FUN_0040bb70(param_1,2);
      }
      if (uVar2 == 0) {
        return uVar1;
      }
    }
    uVar2 = param_1;
    if ((PTR_DAT_00413590[((int)uVar1 >> 8 & 0xffU) * 2 + 1] & 0x80) == 0) {
      param_1._0_2_ = (ushort)(byte)uVar1;
      pWVar3 = (LPCWSTR)0x1;
    }
    else {
      param_1._0_2_ = CONCAT11((byte)uVar1,(char)(uVar1 >> 8));
      param_1._0_3_ = (uint3)(ushort)param_1;
      pWVar3 = (LPCWSTR)0x2;
    }
    iVar4 = FUN_0040f340(DAT_004176c0,0x200,(char *)&param_1,pWVar3,(LPWSTR)local_8,3,0);
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



uint __cdecl FUN_0040cdd0(uint param_1,char **param_2)

{
  char *pcVar1;
  char *pcVar2;
  char **ppcVar3;
  byte bVar4;
  undefined3 extraout_var;
  undefined *puVar5;
  uint uVar6;
  uint uVar7;
  
  ppcVar3 = param_2;
  pcVar1 = param_2[3];
  pcVar2 = param_2[4];
  if ((((uint)pcVar1 & 0x82) == 0) || (((uint)pcVar1 & 0x40) != 0)) {
LAB_0040cef0:
    param_2[3] = (char *)((uint)pcVar1 | 0x20);
    return 0xffffffff;
  }
  uVar6 = 0;
  if (((uint)pcVar1 & 1) != 0) {
    param_2[1] = (char *)0x0;
    if (((uint)pcVar1 & 0x10) == 0) goto LAB_0040cef0;
    *param_2 = param_2[2];
    param_2[3] = (char *)((uint)pcVar1 & 0xfffffffe);
  }
  pcVar1 = param_2[3];
  param_2[1] = (char *)0x0;
  param_2[3] = (char *)((uint)pcVar1 & 0xffffffef | 2);
  if (((uint)pcVar1 & 0x10c) == 0) {
    if ((param_2 == (char **)&DAT_00415a60) || (param_2 == (char **)&DAT_00415a80)) {
      bVar4 = FUN_0040f8d0((uint)pcVar2);
      if (CONCAT31(extraout_var,bVar4) != 0) goto LAB_0040ce43;
    }
    FUN_0040f870((int *)ppcVar3);
  }
LAB_0040ce43:
  if (((uint)ppcVar3[3] & 0x108) == 0) {
    uVar7 = 1;
    uVar6 = FUN_0040f650((uint)pcVar2,(char *)&param_1,1);
  }
  else {
    pcVar1 = ppcVar3[2];
    uVar7 = (int)*ppcVar3 - (int)pcVar1;
    *ppcVar3 = pcVar1 + 1;
    ppcVar3[1] = ppcVar3[6] + -1;
    if ((int)uVar7 < 1) {
      if (pcVar2 == (char *)0xffffffff) {
        puVar5 = &DAT_00415998;
      }
      else {
        puVar5 = (undefined *)((&DAT_00419c20)[(int)pcVar2 >> 5] + ((uint)pcVar2 & 0x1f) * 8);
      }
      if ((puVar5[4] & 0x20) != 0) {
        FUN_0040f590((uint)pcVar2,0,2);
      }
      *ppcVar3[2] = (char)param_1;
    }
    else {
      uVar6 = FUN_0040f650((uint)pcVar2,pcVar1,uVar7);
      *ppcVar3[2] = (char)param_1;
    }
  }
  if (uVar6 != uVar7) {
    ppcVar3[3] = (char *)((uint)ppcVar3[3] | 0x20);
    return 0xffffffff;
  }
  return param_1 & 0xff;
}



int __cdecl FUN_0040cf00(char **param_1,char *param_2,undefined4 *param_3)

{
  uint uVar1;
  short *psVar2;
  int *piVar3;
  undefined4 uVar4;
  WCHAR *pWVar5;
  LPSTR pCVar6;
  char cVar7;
  LPSTR pCVar8;
  LPSTR pCVar9;
  char *pcVar10;
  int iVar11;
  ulonglong uVar12;
  undefined8 uVar13;
  longlong lVar14;
  uint uVar15;
  uint local_24c;
  WCHAR *local_248;
  int local_244;
  int local_240;
  char local_23a;
  char local_239;
  int local_238;
  int local_234;
  int local_230;
  uint local_22c;
  int local_228;
  int local_224;
  int local_220;
  undefined4 local_21c;
  undefined4 local_218;
  CHAR local_214 [4];
  undefined4 local_210;
  undefined4 local_20c;
  uint local_204;
  undefined local_200 [511];
  CHAR local_1;
  
  local_220 = 0;
  pCVar9 = (LPSTR)0x0;
  local_240 = 0;
  cVar7 = *param_2;
  param_2 = param_2 + 1;
  local_21c = CONCAT31(local_21c._1_3_,cVar7);
  do {
    if ((cVar7 == '\0') || (local_240 < 0)) {
      return local_240;
    }
    if ((cVar7 < ' ') || ('x' < cVar7)) {
      uVar1 = 0;
    }
    else {
      uVar1 = (byte)(&DAT_00412138)[cVar7] & 0xf;
    }
    local_220 = (int)(char)(&DAT_00412158)[uVar1 * 8 + local_220] >> 4;
    switch(local_220) {
    case 0:
switchD_0040cf7d_caseD_0:
      local_230 = 0;
      if ((PTR_DAT_00413590[(local_21c & 0xff) * 2 + 1] & 0x80) != 0) {
        FUN_0040d890((int)cVar7,param_1,&local_240);
        cVar7 = *param_2;
        param_2 = param_2 + 1;
      }
      FUN_0040d890((int)cVar7,param_1,&local_240);
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
        local_234 = FUN_0040d960((int *)&param_3);
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
        local_244 = FUN_0040d960((int *)&param_3);
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
          goto switchD_0040cf7d_caseD_0;
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
          uVar4 = FUN_0040d960((int *)&param_3);
          local_200[0] = (char)uVar4;
          pCVar9 = (LPSTR)0x1;
        }
        else {
          uVar4 = FUN_0040d9a0(&param_3);
          pCVar9 = FUN_0040f9e0(local_200,(WCHAR)uVar4);
          if ((int)pCVar9 < 0) {
            local_248 = (WCHAR *)local_200;
            local_228 = 1;
            break;
          }
        }
        local_248 = (WCHAR *)local_200;
        break;
      case 'E':
      case 'G':
        local_218 = 1;
        cVar7 = cVar7 + ' ';
      case 'e':
      case 'f':
      case 'g':
        local_248 = (WCHAR *)local_200;
        if (local_244 < 0) {
          local_244 = 6;
        }
        else if ((local_244 == 0) && (cVar7 == 'g')) {
          local_244 = 1;
        }
        local_210 = *param_3;
        local_20c = param_3[1];
        param_3 = param_3 + 2;
        (*(code *)PTR_FUN_00415800)(&local_210,local_200,(int)cVar7,local_244,local_218);
        if (((local_24c & 0x80) != 0) && (local_244 == 0)) {
          (*(code *)PTR_FUN_0041580c)(local_200);
        }
        if ((cVar7 == 'g') && ((local_24c & 0x80) == 0)) {
          (*(code *)PTR_FUN_00415804)(local_200);
        }
        uVar1 = local_24c | 0x40;
        if (local_200[0] == '-') {
          local_248 = (WCHAR *)(local_200 + 1);
          uVar1 = local_24c | 0x140;
        }
        local_24c = uVar1;
        uVar1 = 0xffffffff;
        pWVar5 = local_248;
        do {
          if (uVar1 == 0) break;
          uVar1 = uVar1 - 1;
          cVar7 = *(char *)pWVar5;
          pWVar5 = (WCHAR *)((int)pWVar5 + 1);
        } while (cVar7 != '\0');
        pCVar9 = (LPSTR)(~uVar1 - 1);
        break;
      case 'S':
        if ((local_24c & 0x830) == 0) {
          local_24c = local_24c | 0x800;
        }
      case 's':
        iVar11 = 0x7fffffff;
        if (local_244 != -1) {
          iVar11 = local_244;
        }
        local_248 = (WCHAR *)FUN_0040d960((int *)&param_3);
        if ((local_24c & 0x810) == 0) {
          pWVar5 = local_248;
          if (local_248 == (WCHAR *)0x0) {
            pWVar5 = (WCHAR *)PTR_DAT_004157f8;
            local_248 = (WCHAR *)PTR_DAT_004157f8;
          }
          for (; (iVar11 != 0 && (iVar11 = iVar11 + -1, *(char *)pWVar5 != '\0'));
              pWVar5 = (WCHAR *)((int)pWVar5 + 1)) {
          }
          pCVar9 = (LPSTR)((int)pWVar5 - (int)local_248);
        }
        else {
          if (local_248 == (WCHAR *)0x0) {
            local_248 = (WCHAR *)PTR_DAT_004157fc;
          }
          local_230 = 1;
          for (pWVar5 = local_248; (iVar11 != 0 && (iVar11 = iVar11 + -1, *pWVar5 != L'\0'));
              pWVar5 = pWVar5 + 1) {
          }
          pCVar9 = (LPSTR)((int)pWVar5 - (int)local_248 >> 1);
        }
        break;
      case 'X':
        goto switchD_0040d191_caseD_58;
      case 'Z':
        psVar2 = (short *)FUN_0040d960((int *)&param_3);
        if ((psVar2 == (short *)0x0) ||
           (local_248 = *(WCHAR **)(psVar2 + 2), local_248 == (WCHAR *)0x0)) {
          uVar1 = 0xffffffff;
          local_248 = (WCHAR *)PTR_DAT_004157f8;
          pcVar10 = PTR_DAT_004157f8;
          do {
            if (uVar1 == 0) break;
            uVar1 = uVar1 - 1;
            cVar7 = *pcVar10;
            pcVar10 = pcVar10 + 1;
          } while (cVar7 != '\0');
          pCVar9 = (LPSTR)(~uVar1 - 1);
        }
        else if ((local_24c & 0x800) == 0) {
          pCVar9 = (LPSTR)(int)*psVar2;
          local_230 = 0;
        }
        else {
          local_230 = 1;
          pCVar9 = (LPSTR)((uint)(int)*psVar2 >> 1);
        }
        break;
      case 'd':
      case 'i':
        local_22c = 10;
        local_24c = local_24c | 0x40;
        goto LAB_0040d4c7;
      case 'n':
        piVar3 = (int *)FUN_0040d960((int *)&param_3);
        if ((local_24c & 0x20) == 0) {
          local_228 = 1;
          *piVar3 = local_240;
        }
        else {
          local_228 = 1;
          *(undefined2 *)piVar3 = (undefined2)local_240;
        }
        break;
      case 'o':
        local_22c = 8;
        if ((local_24c & 0x80) != 0) {
          local_24c = local_24c | 0x200;
        }
        goto LAB_0040d4c7;
      case 'p':
        local_244 = 8;
switchD_0040d191_caseD_58:
        local_224 = 7;
LAB_0040d482:
        local_22c = 0x10;
        if ((local_24c & 0x80) != 0) {
          local_23a = '0';
          local_239 = (char)local_224 + 'Q';
          local_238 = 2;
        }
        goto LAB_0040d4c7;
      case 'u':
        local_22c = 10;
LAB_0040d4c7:
        if ((local_24c & 0x8000) == 0) {
          if ((local_24c & 0x20) == 0) {
            if ((local_24c & 0x40) == 0) {
              uVar1 = FUN_0040d960((int *)&param_3);
              uVar12 = (ulonglong)uVar1;
            }
            else {
              iVar11 = FUN_0040d960((int *)&param_3);
              uVar12 = (ulonglong)iVar11;
            }
          }
          else if ((local_24c & 0x40) == 0) {
            uVar1 = FUN_0040d960((int *)&param_3);
            uVar12 = (ulonglong)uVar1 & 0xffffffff0000ffff;
          }
          else {
            uVar4 = FUN_0040d960((int *)&param_3);
            uVar12 = (ulonglong)(int)(short)uVar4;
          }
        }
        else {
          uVar12 = FUN_0040d980((int *)&param_3);
        }
        iVar11 = (int)(uVar12 >> 0x20);
        if ((((local_24c & 0x40) != 0) && (iVar11 == 0 || (longlong)uVar12 < 0)) &&
           ((longlong)uVar12 < 0)) {
          local_24c = local_24c | 0x100;
          uVar12 = CONCAT44(-(iVar11 + (uint)((int)uVar12 != 0)),-(int)uVar12);
        }
        uVar1 = (uint)(uVar12 >> 0x20);
        if ((local_24c & 0x8000) == 0) {
          uVar1 = 0;
        }
        lVar14 = CONCAT44(uVar1,(uint)uVar12);
        if (local_244 < 0) {
          local_244 = 1;
        }
        else {
          local_24c = local_24c & 0xfffffff7;
        }
        if (((uint)uVar12 | uVar1) == 0) {
          local_238 = 0;
        }
        pWVar5 = (WCHAR *)&local_1;
        iVar11 = local_244;
        while ((uVar1 = local_22c, local_244 = iVar11 + -1, 0 < iVar11 || (lVar14 != 0))) {
          local_204 = (int)local_22c >> 0x1f;
          uVar15 = (uint)((ulonglong)lVar14 >> 0x20);
          uVar13 = __aullrem((uint)lVar14,uVar15,local_22c,local_204);
          iVar11 = (int)uVar13 + 0x30;
          lVar14 = __aulldiv((uint)lVar14,uVar15,uVar1,local_204);
          if (0x39 < iVar11) {
            iVar11 = iVar11 + local_224;
          }
          *(char *)pWVar5 = (char)iVar11;
          pWVar5 = (WCHAR *)((int)pWVar5 + -1);
          iVar11 = local_244;
        }
        pCVar9 = &local_1 + -(int)pWVar5;
        local_248 = (WCHAR *)((int)pWVar5 + 1);
        if (((local_24c & 0x200) != 0) && ((*(char *)local_248 != '0' || (pCVar9 == (LPSTR)0x0)))) {
          pCVar9 = &stack0x00000000 + -(int)pWVar5;
          *(undefined *)pWVar5 = 0x30;
          local_248 = pWVar5;
        }
        break;
      case 'x':
        local_224 = 0x27;
        goto LAB_0040d482;
      }
      if (local_228 == 0) {
        if ((local_24c & 0x40) != 0) {
          if ((local_24c & 0x100) == 0) {
            if ((local_24c & 1) == 0) {
              if ((local_24c & 2) == 0) goto LAB_0040d65f;
              local_23a = ' ';
            }
            else {
              local_23a = '+';
            }
          }
          else {
            local_23a = '-';
          }
          local_238 = 1;
        }
LAB_0040d65f:
        iVar11 = (local_234 - local_238) - (int)pCVar9;
        if ((local_24c & 0xc) == 0) {
          FUN_0040d8e0(0x20,iVar11,param_1,&local_240);
        }
        FUN_0040d920(&local_23a,local_238,param_1,&local_240);
        if (((local_24c & 8) != 0) && ((local_24c & 4) == 0)) {
          FUN_0040d8e0(0x30,iVar11,param_1,&local_240);
        }
        if ((local_230 == 0) || (pWVar5 = local_248, pCVar8 = pCVar9, (int)pCVar9 < 1)) {
          FUN_0040d920((char *)local_248,(int)pCVar9,param_1,&local_240);
        }
        else {
          do {
            pCVar8 = pCVar8 + -1;
            pCVar6 = FUN_0040f9e0(local_214,*pWVar5);
            if ((int)pCVar6 < 1) break;
            FUN_0040d920(local_214,(int)pCVar6,param_1,&local_240);
            pWVar5 = pWVar5 + 1;
          } while (pCVar8 != (LPSTR)0x0);
        }
        if ((local_24c & 4) != 0) {
          FUN_0040d8e0(0x20,iVar11,param_1,&local_240);
        }
      }
    }
    cVar7 = *param_2;
    param_2 = param_2 + 1;
    local_21c = CONCAT31(local_21c._1_3_,cVar7);
  } while( true );
}



void __cdecl FUN_0040d890(uint param_1,char **param_2,int *param_3)

{
  char *pcVar1;
  uint uVar2;
  
  pcVar1 = param_2[1];
  param_2[1] = pcVar1 + -1;
  if ((int)(pcVar1 + -1) < 0) {
    uVar2 = FUN_0040cdd0(param_1,param_2);
  }
  else {
    **param_2 = (char)param_1;
    uVar2 = param_1 & 0xff;
    *param_2 = *param_2 + 1;
  }
  if (uVar2 == 0xffffffff) {
    *param_3 = -1;
    return;
  }
  *param_3 = *param_3 + 1;
  return;
}



void __cdecl FUN_0040d8e0(uint param_1,int param_2,char **param_3,int *param_4)

{
  if (0 < param_2) {
    do {
      param_2 = param_2 + -1;
      FUN_0040d890(param_1,param_3,param_4);
      if (*param_4 == -1) {
        return;
      }
    } while (0 < param_2);
  }
  return;
}



void __cdecl FUN_0040d920(char *param_1,int param_2,char **param_3,int *param_4)

{
  char cVar1;
  
  if (0 < param_2) {
    do {
      param_2 = param_2 + -1;
      cVar1 = *param_1;
      param_1 = param_1 + 1;
      FUN_0040d890((int)cVar1,param_3,param_4);
      if (*param_4 == -1) {
        return;
      }
    } while (0 < param_2);
  }
  return;
}



undefined4 __cdecl FUN_0040d960(int *param_1)

{
  undefined4 *puVar1;
  
  puVar1 = (undefined4 *)*param_1;
  *param_1 = (int)(puVar1 + 1);
  return *puVar1;
}



undefined8 __cdecl FUN_0040d980(int *param_1)

{
  undefined8 *puVar1;
  
  puVar1 = (undefined8 *)*param_1;
  *param_1 = (int)(puVar1 + 1);
  return *puVar1;
}



undefined4 __cdecl FUN_0040d9a0(undefined4 *param_1)

{
  undefined2 *puVar1;
  undefined2 *puVar2;
  
  puVar1 = (undefined2 *)*param_1;
  puVar2 = puVar1 + 2;
  *param_1 = puVar2;
  return CONCAT22((short)((uint)puVar2 >> 0x10),*puVar1);
}



// Library Function - Single Match
//  __setdefaultprecision
// 
// Library: Visual Studio 1998 Release

void __setdefaultprecision(void)

{
  FUN_0040fb90((void *)0x10000,0x30000);
  return;
}



// WARNING: Removing unreachable block (ram,0x0040da21)

undefined4 FUN_0040d9e0(void)

{
  return 0;
}



void FUN_0040da30(void)

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
  FUN_0040d9e0();
  return;
}



void __cdecl FUN_0040da60(char *param_1)

{
  char cVar1;
  char cVar2;
  uint uVar3;
  
  uVar3 = FUN_0040fce0((int)*param_1);
  if (uVar3 != 0x65) {
    do {
      param_1 = param_1 + 1;
      if (DAT_0041379c < 2) {
        uVar3 = (byte)PTR_DAT_00413590[*param_1 * 2] & 4;
      }
      else {
        uVar3 = FUN_0040bb70((int)*param_1,4);
      }
    } while (uVar3 != 0);
  }
  cVar2 = *param_1;
  *param_1 = DAT_004137a0;
  do {
    param_1 = param_1 + 1;
    cVar1 = *param_1;
    *param_1 = cVar2;
    cVar2 = cVar1;
  } while (*param_1 != '\0');
  return;
}



undefined * __cdecl FUN_0040dbb0(undefined4 *param_1,undefined *param_2,int param_3,int param_4)

{
  int *piVar1;
  undefined *puVar2;
  int iVar3;
  undefined4 *puVar4;
  
  piVar1 = DAT_0041746c;
  if (DAT_00417470 == '\0') {
    piVar1 = (int *)FUN_004103a0((char)*param_1);
    FUN_00410300((undefined4 *)(param_2 + (uint)(*piVar1 == 0x2d) + (uint)(0 < param_3)),param_3 + 1
                 ,(int)piVar1);
  }
  else {
    FUN_0040df70((undefined4 *)(param_2 + (*DAT_0041746c == 0x2d)),(uint)(0 < param_3));
  }
  puVar2 = param_2;
  if (*piVar1 == 0x2d) {
    *param_2 = 0x2d;
    puVar2 = param_2 + 1;
  }
  if (0 < param_3) {
    *puVar2 = puVar2[1];
    puVar2 = puVar2 + 1;
    *puVar2 = DAT_004137a0;
  }
  puVar4 = (undefined4 *)(puVar2 + param_3 + (uint)(DAT_00417470 == '\0'));
  *puVar4 = 0x30302b65;
  *(undefined2 *)(puVar4 + 1) = 0x30;
  if (param_4 != 0) {
    *(undefined *)puVar4 = 0x45;
  }
  if (*(char *)piVar1[3] != '0') {
    iVar3 = piVar1[1] + -1;
    if (iVar3 < 0) {
      iVar3 = -iVar3;
      *(undefined *)((int)puVar4 + 1) = 0x2d;
    }
    if (99 < iVar3) {
      *(char *)((int)puVar4 + 2) = *(char *)((int)puVar4 + 2) + (char)(iVar3 / 100);
      iVar3 = iVar3 % 100;
    }
    if (9 < iVar3) {
      *(char *)((int)puVar4 + 3) = *(char *)((int)puVar4 + 3) + (char)(iVar3 / 10);
      iVar3 = iVar3 % 10;
    }
    *(char *)(puVar4 + 1) = *(char *)(puVar4 + 1) + (char)iVar3;
  }
  return param_2;
}



undefined4 * __cdecl FUN_0040dcf0(undefined4 *param_1,undefined4 *param_2,uint param_3)

{
  int iVar1;
  undefined *puVar2;
  int *piVar3;
  uint uVar4;
  undefined4 *puVar5;
  
  piVar3 = DAT_0041746c;
  if (DAT_00417470 == '\0') {
    piVar3 = (int *)FUN_004103a0((char)*param_1);
    FUN_00410300((undefined4 *)((uint)(*piVar3 == 0x2d) + (int)param_2),piVar3[1] + param_3,
                 (int)piVar3);
  }
  else if (DAT_00417474 == param_3) {
    puVar2 = (undefined *)((int)param_2 + DAT_00417474 + (*DAT_0041746c == 0x2d));
    *puVar2 = 0x30;
    puVar2[1] = 0;
  }
  puVar5 = param_2;
  if (*piVar3 == 0x2d) {
    *(undefined *)param_2 = 0x2d;
    puVar5 = (undefined4 *)((int)param_2 + 1);
  }
  if (piVar3[1] < 1) {
    FUN_0040df70(puVar5,1);
    *(undefined *)puVar5 = 0x30;
    puVar5 = (undefined4 *)((int)puVar5 + 1);
  }
  else {
    puVar5 = (undefined4 *)((int)puVar5 + piVar3[1]);
  }
  if (0 < (int)param_3) {
    FUN_0040df70(puVar5,1);
    *(undefined *)puVar5 = DAT_004137a0;
    iVar1 = piVar3[1];
    if (iVar1 < 0) {
      if ((DAT_00417470 != '\0') || (SBORROW4(param_3,-iVar1) == (int)(param_3 + iVar1) < 0)) {
        param_3 = -iVar1;
      }
      FUN_0040df70((undefined4 *)((int)puVar5 + 1),param_3);
      puVar5 = (undefined4 *)((int)puVar5 + 1);
      for (uVar4 = param_3 >> 2; uVar4 != 0; uVar4 = uVar4 - 1) {
        *puVar5 = 0x30303030;
        puVar5 = puVar5 + 1;
      }
      for (uVar4 = param_3 & 3; uVar4 != 0; uVar4 = uVar4 - 1) {
        *(undefined *)puVar5 = 0x30;
        puVar5 = (undefined4 *)((int)puVar5 + 1);
      }
    }
  }
  return param_2;
}



void __cdecl FUN_0040ddf0(undefined4 *param_1,undefined4 *param_2,uint param_3,int param_4)

{
  char cVar1;
  undefined4 *puVar2;
  
  DAT_0041746c = (int *)FUN_004103a0((char)*param_1);
  DAT_00417474 = DAT_0041746c[1] + -1;
  puVar2 = (undefined4 *)((uint)(*DAT_0041746c == 0x2d) + (int)param_2);
  FUN_00410300(puVar2,param_3,(int)DAT_0041746c);
  DAT_00417478 = DAT_00417474 < DAT_0041746c[1] + -1;
  DAT_00417474 = DAT_0041746c[1] + -1;
  if ((-5 < DAT_00417474) && (DAT_00417474 < (int)param_3)) {
    if ((bool)DAT_00417478) {
      cVar1 = *(char *)puVar2;
      while (cVar1 != '\0') {
        cVar1 = *(char *)(undefined4 *)((int)puVar2 + 1);
        puVar2 = (undefined4 *)((int)puVar2 + 1);
      }
      *(char *)((int)puVar2 + -1) = '\0';
    }
    FUN_0040ded0(param_1,param_2,param_3);
    return;
  }
  FUN_0040dea0(param_1,(undefined *)param_2,param_3,param_4);
  return;
}



void __cdecl FUN_0040dea0(undefined4 param_1,undefined *param_2,int param_3,int param_4)

{
  DAT_00417470 = 1;
  FUN_0040dbb0(param_1,param_2,param_3,param_4);
  DAT_00417470 = 0;
  return;
}



void __cdecl FUN_0040ded0(undefined4 param_1,undefined4 *param_2,uint param_3)

{
  DAT_00417470 = 1;
  FUN_0040dcf0(param_1,param_2,param_3);
  DAT_00417470 = 0;
  return;
}



void __cdecl FUN_0040df70(undefined4 *param_1,int param_2)

{
  char cVar1;
  uint uVar2;
  undefined4 *puVar3;
  
  if (param_2 != 0) {
    uVar2 = 0xffffffff;
    puVar3 = param_1;
    do {
      if (uVar2 == 0) break;
      uVar2 = uVar2 - 1;
      cVar1 = *(char *)puVar3;
      puVar3 = (undefined4 *)((int)puVar3 + 1);
    } while (cVar1 != '\0');
    FUN_0040ef60((undefined4 *)(param_2 + (int)param_1),param_1,~uVar2);
  }
  return;
}



LONG __cdecl FUN_0040dfa0(int param_1,_EXCEPTION_POINTERS *param_2)

{
  code *pcVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  int *piVar4;
  LONG LVar5;
  undefined4 *puVar6;
  int iVar7;
  
  piVar4 = FUN_0040e0e0(param_1);
  uVar3 = DAT_0041747c;
  if ((piVar4 == (int *)0x0) || (pcVar1 = (code *)piVar4[2], pcVar1 == (code *)0x0)) {
    LVar5 = UnhandledExceptionFilter(param_2);
    return LVar5;
  }
  if (pcVar1 == (code *)0x5) {
    piVar4[2] = 0;
    return 1;
  }
  if (pcVar1 != (code *)0x1) {
    DAT_0041747c = param_2;
    if (piVar4[1] == 8) {
      if (DAT_00415890 < DAT_00415894 + DAT_00415890) {
        iVar7 = (DAT_00415894 + DAT_00415890) - DAT_00415890;
        puVar6 = (undefined4 *)(DAT_00415890 * 0xc + 0x415820);
        do {
          *puVar6 = 0;
          puVar6 = puVar6 + 3;
          iVar7 = iVar7 + -1;
        } while (iVar7 != 0);
      }
      uVar2 = DAT_0041589c;
      iVar7 = *piVar4;
      if (iVar7 == -0x3fffff72) {
        DAT_0041589c = 0x83;
      }
      else if (iVar7 == -0x3fffff70) {
        DAT_0041589c = 0x81;
      }
      else if (iVar7 == -0x3fffff6f) {
        DAT_0041589c = 0x84;
      }
      else if (iVar7 == -0x3fffff6d) {
        DAT_0041589c = 0x85;
      }
      else if (iVar7 == -0x3fffff73) {
        DAT_0041589c = 0x82;
      }
      else if (iVar7 == -0x3fffff71) {
        DAT_0041589c = 0x86;
      }
      else if (iVar7 == -0x3fffff6e) {
        DAT_0041589c = 0x8a;
      }
      (*pcVar1)(8,DAT_0041589c);
      DAT_0041589c = uVar2;
      DAT_0041747c = (_EXCEPTION_POINTERS *)uVar3;
      return -1;
    }
    piVar4[2] = 0;
    (*pcVar1)(piVar4[1]);
    DAT_0041747c = (_EXCEPTION_POINTERS *)uVar3;
    return -1;
  }
  return -1;
}



int * __cdecl FUN_0040e0e0(int param_1)

{
  int *piVar1;
  
  piVar1 = &DAT_00415818;
  if (DAT_00415818 != param_1) {
    do {
      piVar1 = piVar1 + 3;
      if (&DAT_00415818 + DAT_00415898 * 3 <= piVar1) break;
    } while (*piVar1 != param_1);
  }
  if ((&DAT_00415818 + DAT_00415898 * 3 <= piVar1) || (*piVar1 != param_1)) {
    piVar1 = (int *)0x0;
  }
  return piVar1;
}



void __cdecl FUN_0040e130(uint param_1)

{
  FUN_0040e150(param_1,0,4);
  return;
}



undefined4 __cdecl FUN_0040e150(uint param_1,uint param_2,byte param_3)

{
  uint uVar1;
  
  if (((&DAT_00417591)[param_1 & 0xff] & param_3) == 0) {
    if (param_2 == 0) {
      uVar1 = 0;
    }
    else {
      uVar1 = *(ushort *)(&DAT_0041359a + (param_1 & 0xff) * 2) & param_2;
    }
    if (uVar1 == 0) {
      return 0;
    }
  }
  return 1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0040e190(void)

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
  cVar2 = *DAT_00417400;
  pcVar7 = DAT_00417400;
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
  piVar3 = (int *)FUN_0040ba70(iVar8 * 4 + 4);
  _DAT_00417448 = piVar3;
  if (piVar3 == (int *)0x0) {
    __amsg_exit(9);
  }
  cVar2 = *DAT_00417400;
  local_4 = piVar3;
  pcVar7 = DAT_00417400;
  do {
    if (cVar2 == '\0') {
      FUN_0040bb20(DAT_00417400);
      DAT_00417400 = (char *)0x0;
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
      iVar8 = FUN_0040ba70(uVar4);
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

void FUN_0040e280(void)

{
  byte **ppbVar1;
  byte *pbVar2;
  int iStack_8;
  int iStack_4;
  
  GetModuleFileNameA((HMODULE)0x0,&DAT_00417480,0x104);
  _DAT_00417458 = &DAT_00417480;
  pbVar2 = DAT_00419d30;
  if (*DAT_00419d30 == 0) {
    pbVar2 = &DAT_00417480;
  }
  FUN_0040e320(pbVar2,(byte **)0x0,(byte *)0x0,&iStack_8,&iStack_4);
  ppbVar1 = (byte **)FUN_0040ba70(iStack_4 + iStack_8 * 4);
  if (ppbVar1 == (byte **)0x0) {
    __amsg_exit(8);
  }
  FUN_0040e320(pbVar2,ppbVar1,(byte *)(ppbVar1 + iStack_8),&iStack_8,&iStack_4);
  _DAT_00417440 = ppbVar1;
  _DAT_0041743c = iStack_8 + -1;
  return;
}



void __cdecl FUN_0040e320(byte *param_1,byte **param_2,byte *param_3,int *param_4,int *param_5)

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
      if ((((&DAT_00417591)[bVar2] & 4) != 0) && (*param_5 = *param_5 + 1, param_3 != (byte *)0x0))
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
      if ((*(byte *)((int)param_5 + 0x417591) & 4) != 0) {
        *piVar6 = *piVar6 + 1;
        if (param_3 != (byte *)0x0) {
          *param_3 = *pbVar7;
          param_3 = param_3 + 1;
        }
        pbVar7 = param_1 + 2;
      }
      if (bVar2 == 0x20) break;
      if (bVar2 == 0) goto LAB_0040e3f9;
      param_1 = pbVar7;
    } while (bVar2 != 9);
    if (bVar2 == 0) {
LAB_0040e3f9:
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
          if (((&DAT_00417591)[bVar2] & 4) != 0) {
            pbVar7 = pbVar7 + 1;
            *piVar6 = *piVar6 + 1;
          }
          *piVar6 = *piVar6 + 1;
          goto LAB_0040e4f5;
        }
        if (((&DAT_00417591)[bVar2] & 4) != 0) {
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
LAB_0040e4f5:
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



undefined4 * FUN_0040e530(void)

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
  if (DAT_00417588 == 0) {
    lpWideCharStr = GetEnvironmentStringsW();
    if (lpWideCharStr == (LPWCH)0x0) {
      puVar9 = (undefined4 *)GetEnvironmentStrings();
      if (puVar9 == (undefined4 *)0x0) {
        return (undefined4 *)0x0;
      }
      DAT_00417588 = 2;
    }
    else {
      DAT_00417588 = 1;
    }
  }
  if (DAT_00417588 == 1) {
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
      if ((uVar6 != 0) && (puVar9 = (undefined4 *)FUN_0040ba70(uVar6), puVar9 != (undefined4 *)0x0))
      {
        iVar5 = WideCharToMultiByte(0,0,lpWideCharStr,iVar5,(LPSTR)puVar9,uVar6,(LPCSTR)0x0,
                                    (LPBOOL)0x0);
        if (iVar5 == 0) {
          FUN_0040bb20((undefined *)puVar9);
          puVar9 = (undefined4 *)0x0;
        }
        FreeEnvironmentStringsW(lpWideCharStr);
        return puVar9;
      }
      FreeEnvironmentStringsW(lpWideCharStr);
      return (undefined4 *)0x0;
    }
  }
  else if ((DAT_00417588 == 2) &&
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
    puVar7 = (undefined4 *)FUN_0040ba70(uVar6);
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



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 __cdecl FUN_0040e690(int param_1)

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
  
  CodePage = FUN_0040e880(param_1);
  if (CodePage == DAT_00417694) {
    return 0;
  }
  if (CodePage == 0) {
    FUN_0040e930();
    return 0;
  }
  iVar9 = 0;
  pUVar4 = &DAT_004158a8;
  do {
    if (*pUVar4 == CodePage) {
      puVar13 = (undefined4 *)&DAT_00417590;
      for (iVar8 = 0x40; iVar8 != 0; iVar8 = iVar8 + -1) {
        *puVar13 = 0;
        puVar13 = puVar13 + 1;
      }
      *(undefined *)puVar13 = 0;
      uVar6 = 0;
      pbVar11 = &DAT_004158b8 + iVar9 * 0x30;
      do {
        bVar2 = *pbVar11;
        for (pbVar12 = pbVar11; (bVar2 != 0 && (bVar2 = pbVar12[1], bVar2 != 0));
            pbVar12 = pbVar12 + 2) {
          uVar7 = (uint)*pbVar12;
          if (uVar7 <= bVar2) {
            bVar3 = (&DAT_004158a0)[uVar6];
            do {
              (&DAT_00417591)[uVar7] = (&DAT_00417591)[uVar7] | bVar3;
              uVar7 = uVar7 + 1;
            } while (uVar7 <= bVar2);
          }
          bVar2 = pbVar12[2];
        }
        uVar6 = uVar6 + 1;
        pbVar11 = pbVar11 + 8;
      } while (uVar6 < 4);
      DAT_00417694 = CodePage;
      _DAT_00417698 = FUN_0040e8d0(CodePage);
      _DAT_004176a0 = (&DAT_004158ac)[iVar9 * 0xc];
      _DAT_004176a4 = (&DAT_004158b0)[iVar9 * 0xc];
      _DAT_004176a8 = (&DAT_004158b4)[iVar9 * 0xc];
      return 0;
    }
    pUVar4 = pUVar4 + 0xc;
    iVar9 = iVar9 + 1;
  } while (pUVar4 < &DAT_00415998);
  BVar5 = GetCPInfo(CodePage,&local_14);
  if (BVar5 != 1) {
    if (_DAT_004176ac == 0) {
      return 0xffffffff;
    }
    FUN_0040e930();
    return 0;
  }
  puVar13 = (undefined4 *)&DAT_00417590;
  for (iVar9 = 0x40; iVar9 != 0; iVar9 = iVar9 + -1) {
    *puVar13 = 0;
    puVar13 = puVar13 + 1;
  }
  *(undefined *)puVar13 = 0;
  if (local_14.MaxCharSize < 2) {
    DAT_00417694 = 0;
    _DAT_00417698 = 0;
  }
  else {
    if (local_14.LeadByte[0] != '\0') {
      pBVar10 = local_14.LeadByte + 1;
      do {
        bVar2 = *pBVar10;
        if (bVar2 == 0) break;
        for (uVar6 = (uint)pBVar10[-1]; uVar6 <= bVar2; uVar6 = uVar6 + 1) {
          (&DAT_00417591)[uVar6] = (&DAT_00417591)[uVar6] | 4;
        }
        pBVar1 = pBVar10 + 1;
        pBVar10 = pBVar10 + 2;
      } while (*pBVar1 != 0);
    }
    uVar6 = 1;
    do {
      (&DAT_00417591)[uVar6] = (&DAT_00417591)[uVar6] | 8;
      uVar6 = uVar6 + 1;
    } while (uVar6 < 0xff);
    DAT_00417694 = CodePage;
    _DAT_00417698 = FUN_0040e8d0(CodePage);
  }
  _DAT_004176a0 = 0;
  _DAT_004176a4 = 0;
  _DAT_004176a8 = 0;
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int __cdecl FUN_0040e880(int param_1)

{
  int iVar1;
  bool bVar2;
  
  if (param_1 == -2) {
    _DAT_004176ac = 1;
                    // WARNING: Could not recover jumptable at 0x0040e89d. Too many branches
                    // WARNING: Treating indirect jump as call
    iVar1 = GetOEMCP();
    return iVar1;
  }
  if (param_1 == -3) {
    _DAT_004176ac = 1;
                    // WARNING: Could not recover jumptable at 0x0040e8b2. Too many branches
                    // WARNING: Treating indirect jump as call
    iVar1 = GetACP();
    return iVar1;
  }
  bVar2 = param_1 == -4;
  if (bVar2) {
    param_1 = DAT_004176d0;
  }
  _DAT_004176ac = (uint)bVar2;
  return param_1;
}



undefined4 __cdecl FUN_0040e8d0(undefined4 param_1)

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

void FUN_0040e930(void)

{
  int iVar1;
  undefined4 *puVar2;
  
  puVar2 = (undefined4 *)&DAT_00417590;
  for (iVar1 = 0x40; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  *(undefined *)puVar2 = 0;
  DAT_00417694 = 0;
  _DAT_00417698 = 0;
  _DAT_004176a0 = 0;
  _DAT_004176a4 = 0;
  _DAT_004176a8 = 0;
  return;
}



void FUN_0040e960(void)

{
  FUN_0040e690(-3);
  return;
}



void FUN_0040e970(void)

{
  byte bVar1;
  undefined4 *puVar2;
  DWORD DVar3;
  HANDLE hFile;
  int iVar4;
  HANDLE *ppvVar5;
  int *piVar6;
  uint uVar7;
  UINT UStack_48;
  _STARTUPINFOA local_44;
  
  puVar2 = (undefined4 *)FUN_0040ba70(0x100);
  if (puVar2 == (undefined4 *)0x0) {
    __amsg_exit(0x1b);
  }
  DAT_00419d20 = 0x20;
  DAT_00419c20 = puVar2;
  if (puVar2 < puVar2 + 0x40) {
    do {
      *(undefined *)(puVar2 + 1) = 0;
      *puVar2 = 0xffffffff;
      *(undefined *)((int)puVar2 + 5) = 10;
      puVar2 = puVar2 + 2;
    } while (puVar2 < DAT_00419c20 + 0x40);
  }
  GetStartupInfoA(&local_44);
  if ((local_44.cbReserved2 != 0) && ((UINT *)local_44.lpReserved2 != (UINT *)0x0)) {
    UStack_48 = *(UINT *)local_44.lpReserved2;
    local_44.lpReserved2 = (LPBYTE)((int)local_44.lpReserved2 + 4);
    ppvVar5 = (HANDLE *)((int)local_44.lpReserved2 + UStack_48);
    if (0x7ff < (int)UStack_48) {
      UStack_48 = 0x800;
    }
    if ((int)DAT_00419d20 < (int)UStack_48) {
      piVar6 = &DAT_00419c24;
      do {
        puVar2 = (undefined4 *)FUN_0040ba70(0x100);
        if (puVar2 == (undefined4 *)0x0) {
          UStack_48 = DAT_00419d20;
          break;
        }
        *piVar6 = (int)puVar2;
        DAT_00419d20 = DAT_00419d20 + 0x20;
        if (puVar2 < puVar2 + 0x40) {
          do {
            *(undefined *)(puVar2 + 1) = 0;
            *puVar2 = 0xffffffff;
            *(undefined *)((int)puVar2 + 5) = 10;
            puVar2 = puVar2 + 2;
          } while (puVar2 < (undefined4 *)(*piVar6 + 0x100));
        }
        piVar6 = piVar6 + 1;
      } while ((int)DAT_00419d20 < (int)UStack_48);
    }
    uVar7 = 0;
    if (0 < (int)UStack_48) {
      do {
        if (((*ppvVar5 != (HANDLE)0xffffffff) && ((*local_44.lpReserved2 & 1) != 0)) &&
           (((*local_44.lpReserved2 & 8) != 0 || (DVar3 = GetFileType(*ppvVar5), DVar3 != 0)))) {
          iVar4 = (int)(&DAT_00419c20)[(int)uVar7 >> 5];
          *(HANDLE *)(iVar4 + (uVar7 & 0x1f) * 8) = *ppvVar5;
          *(BYTE *)(iVar4 + (uVar7 & 0x1f) * 8 + 4) = *local_44.lpReserved2;
        }
        uVar7 = uVar7 + 1;
        local_44.lpReserved2 = (LPBYTE)((int)local_44.lpReserved2 + 1);
        ppvVar5 = ppvVar5 + 1;
      } while ((int)uVar7 < (int)UStack_48);
    }
  }
  iVar4 = 0;
  do {
    ppvVar5 = (HANDLE *)(DAT_00419c20 + iVar4 * 2);
    if (DAT_00419c20[iVar4 * 2] == -1) {
      *(undefined *)(ppvVar5 + 1) = 0x81;
      if (iVar4 == 0) {
        DVar3 = 0xfffffff6;
      }
      else {
        DVar3 = 0xfffffff5 - (iVar4 != 1);
      }
      hFile = GetStdHandle(DVar3);
      if ((hFile == (HANDLE)0xffffffff) || (DVar3 = GetFileType(hFile), DVar3 == 0)) {
        bVar1 = *(byte *)(ppvVar5 + 1) | 0x40;
        goto LAB_0040eb4b;
      }
      *ppvVar5 = hFile;
      if ((DVar3 & 0xff) == 2) {
        bVar1 = *(byte *)(ppvVar5 + 1) | 0x40;
        goto LAB_0040eb4b;
      }
      if ((DVar3 & 0xff) == 3) {
        bVar1 = *(byte *)(ppvVar5 + 1) | 8;
        goto LAB_0040eb4b;
      }
    }
    else {
      bVar1 = *(byte *)(ppvVar5 + 1) | 0x80;
LAB_0040eb4b:
      *(byte *)(ppvVar5 + 1) = bVar1;
    }
    iVar4 = iVar4 + 1;
    if (2 < iVar4) {
      SetHandleCount(DAT_00419d20);
      return;
    }
  } while( true );
}



// Library Function - Single Match
//  __global_unwind2
// 
// Library: Visual Studio

void __cdecl __global_unwind2(PVOID param_1)

{
  RtlUnwind(param_1,(PVOID)0x40eb88,(PEXCEPTION_RECORD)0x0,(PVOID)0x0);
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
  undefined4 *unaff_FS_OFFSET;
  undefined4 uStack_1c;
  undefined *puStack_18;
  undefined4 local_14;
  int iStack_10;
  
  iStack_10 = param_1;
  puStack_18 = &LAB_0040eb90;
  uStack_1c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &uStack_1c;
  while( true ) {
    iVar1 = *(int *)(param_1 + 8);
    iVar2 = *(int *)(param_1 + 0xc);
    if ((iVar2 == -1) || (iVar2 == param_2)) break;
    local_14 = *(undefined4 *)(iVar1 + iVar2 * 0xc);
    *(undefined4 *)(param_1 + 0xc) = local_14;
    if (*(int *)(iVar1 + 4 + iVar2 * 0xc) == 0) {
      FUN_0040ec46();
      (**(code **)(iVar1 + 8 + iVar2 * 0xc))();
    }
  }
  *unaff_FS_OFFSET = uStack_1c;
  return;
}



void FUN_0040ec46(void)

{
  undefined4 in_EAX;
  int unaff_EBP;
  
  DAT_004159a8 = *(undefined4 *)(unaff_EBP + 8);
  DAT_004159a4 = in_EAX;
  DAT_004159ac = unaff_EBP;
  return;
}



void FUN_0040ed25(int param_1)

{
  __local_unwind2(*(int *)(param_1 + 0x18),*(int *)(param_1 + 0x1c));
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0040ed40(void)

{
  if ((DAT_00417408 == 1) || ((DAT_00417408 == 0 && (_DAT_004137c8 == 1)))) {
    FUN_0040ed80((undefined *)0xfc);
    if (DAT_004176b0 != (code *)0x0) {
      (*DAT_004176b0)();
    }
    FUN_0040ed80((undefined *)0xff);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_0040ed80(undefined *param_1)

{
  char cVar1;
  undefined **ppuVar2;
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
  
  ppuVar2 = (undefined **)&DAT_004159b0;
  iVar8 = 0;
  do {
    if (param_1 == *ppuVar2) break;
    ppuVar2 = ppuVar2 + 2;
    iVar8 = iVar8 + 1;
  } while (ppuVar2 < &PTR_DAT_00415a40);
  if (param_1 == (undefined *)(&DAT_004159b0)[iVar8 * 2]) {
    if ((DAT_00417408 == 1) || ((DAT_00417408 == 0 && (_DAT_004137c8 == 1)))) {
      if ((DAT_00419c20 == 0) ||
         (hFile = *(HANDLE *)(DAT_00419c20 + 0x10), hFile == (HANDLE)0xffffffff)) {
        hFile = GetStdHandle(0xfffffff4);
      }
      pcVar11 = *(char **)(iVar8 * 8 + 0x4159b4);
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
    else if (param_1 != (undefined *)0xfc) {
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
      pcVar11 = *(char **)(iVar8 * 8 + 0x4159b4);
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
      FUN_004104f0(auStack_1a4,"Microsoft Visual C++ Runtime Library",0x12010);
      return;
    }
  }
  return;
}



undefined4 * __cdecl FUN_0040ef60(undefined4 *param_1,undefined4 *param_2,uint param_3)

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
          goto switchD_0040f117_caseD_2;
        case 3:
          goto switchD_0040f117_caseD_3;
        }
        goto switchD_0040f117_caseD_1;
      }
    }
    else {
      switch(param_3) {
      case 0:
        goto switchD_0040f117_caseD_0;
      case 1:
        goto switchD_0040f117_caseD_1;
      case 2:
        goto switchD_0040f117_caseD_2;
      case 3:
        goto switchD_0040f117_caseD_3;
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
              goto switchD_0040f117_caseD_2;
            case 3:
              goto switchD_0040f117_caseD_3;
            }
            goto switchD_0040f117_caseD_1;
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
              goto switchD_0040f117_caseD_2;
            case 3:
              goto switchD_0040f117_caseD_3;
            }
            goto switchD_0040f117_caseD_1;
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
              goto switchD_0040f117_caseD_2;
            case 3:
              goto switchD_0040f117_caseD_3;
            }
            goto switchD_0040f117_caseD_1;
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
switchD_0040f117_caseD_1:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar3 + 3);
      return param_1;
    case 2:
switchD_0040f117_caseD_2:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar3 + 3);
      *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar3 + 2);
      return param_1;
    case 3:
switchD_0040f117_caseD_3:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar3 + 3);
      *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar3 + 2);
      *(undefined *)((int)puVar4 + 1) = *(undefined *)((int)puVar3 + 1);
      return param_1;
    }
switchD_0040f117_caseD_0:
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
        goto switchD_0040ef95_caseD_2;
      case 3:
        goto switchD_0040ef95_caseD_3;
      }
      goto switchD_0040ef95_caseD_1;
    }
  }
  else {
    switch(param_3) {
    case 0:
      goto switchD_0040ef95_caseD_0;
    case 1:
      goto switchD_0040ef95_caseD_1;
    case 2:
      goto switchD_0040ef95_caseD_2;
    case 3:
      goto switchD_0040ef95_caseD_3;
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
            goto switchD_0040ef95_caseD_2;
          case 3:
            goto switchD_0040ef95_caseD_3;
          }
          goto switchD_0040ef95_caseD_1;
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
            goto switchD_0040ef95_caseD_2;
          case 3:
            goto switchD_0040ef95_caseD_3;
          }
          goto switchD_0040ef95_caseD_1;
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
            goto switchD_0040ef95_caseD_2;
          case 3:
            goto switchD_0040ef95_caseD_3;
          }
          goto switchD_0040ef95_caseD_1;
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
switchD_0040ef95_caseD_1:
    *(undefined *)puVar3 = *(undefined *)param_2;
    return param_1;
  case 2:
switchD_0040ef95_caseD_2:
    *(undefined *)puVar3 = *(undefined *)param_2;
    *(undefined *)((int)puVar3 + 1) = *(undefined *)((int)param_2 + 1);
    return param_1;
  case 3:
switchD_0040ef95_caseD_3:
    *(undefined *)puVar3 = *(undefined *)param_2;
    *(undefined *)((int)puVar3 + 1) = *(undefined *)((int)param_2 + 1);
    *(undefined *)((int)puVar3 + 2) = *(undefined *)((int)param_2 + 2);
    return param_1;
  }
switchD_0040ef95_caseD_0:
  return param_1;
}



int * __cdecl FUN_0040f2a0(int param_1,int param_2)

{
  int iVar1;
  uint uVar2;
  int *piVar3;
  uint dwBytes;
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
      if (DAT_004157f4 < dwBytes) {
LAB_0040f300:
        if (piVar3 != (int *)0x0) {
          return piVar3;
        }
      }
      else {
        piVar3 = FUN_0040c6a0((int *)(dwBytes >> 4));
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
          goto LAB_0040f300;
        }
      }
      piVar3 = (int *)HeapAlloc(DAT_00419d2c,8,dwBytes);
    }
    if ((piVar3 != (int *)0x0) || (DAT_0041740c == 0)) {
      return piVar3;
    }
    iVar1 = FUN_0040c2e0(dwBytes);
    if (iVar1 == 0) {
      return (int *)0x0;
    }
  } while( true );
}



int __cdecl
FUN_0040f340(LCID param_1,uint param_2,char *param_3,LPCWSTR param_4,LPWSTR param_5,int param_6,
            UINT param_7)

{
  int iVar1;
  LPCWSTR cbMultiByte;
  LPCWSTR lpWideCharStr;
  int iVar2;
  
  if (DAT_004176d8 == 0) {
    iVar1 = LCMapStringA(0,0x100,"",1,(LPSTR)0x0,0);
    if (iVar1 == 0) {
      iVar1 = LCMapStringW(0,0x100,L"",1,(LPWSTR)0x0,0);
      if (iVar1 == 0) {
        return 0;
      }
      DAT_004176d8 = 1;
    }
    else {
      DAT_004176d8 = 2;
    }
  }
  cbMultiByte = param_4;
  if (0 < (int)param_4) {
    cbMultiByte = (LPCWSTR)FUN_0040f560(param_3,(int)param_4);
  }
  if (DAT_004176d8 == 2) {
    iVar1 = LCMapStringA(param_1,param_2,param_3,(int)cbMultiByte,(LPSTR)param_5,param_6);
    return iVar1;
  }
  if (DAT_004176d8 != 1) {
    return DAT_004176d8;
  }
  param_4 = (LPCWSTR)0x0;
  if (param_7 == 0) {
    param_7 = DAT_004176d0;
  }
  iVar1 = MultiByteToWideChar(param_7,9,param_3,(int)cbMultiByte,(LPWSTR)0x0,0);
  if (iVar1 == 0) {
    return 0;
  }
  lpWideCharStr = (LPCWSTR)FUN_0040ba70(iVar1 * 2);
  if (lpWideCharStr == (LPCWSTR)0x0) {
    return 0;
  }
  iVar2 = MultiByteToWideChar(param_7,1,param_3,(int)cbMultiByte,lpWideCharStr,iVar1);
  if ((iVar2 != 0) &&
     (iVar2 = LCMapStringW(param_1,param_2,lpWideCharStr,iVar1,(LPWSTR)0x0,0), iVar2 != 0)) {
    if ((param_2 & 0x400) == 0) {
      param_4 = (LPCWSTR)FUN_0040ba70(iVar2 * 2);
      if ((param_4 == (LPCWSTR)0x0) ||
         (iVar1 = LCMapStringW(param_1,param_2,lpWideCharStr,iVar1,param_4,iVar2), iVar1 == 0))
      goto LAB_0040f53f;
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
      if (param_6 == 0) goto LAB_0040f4a4;
      if (param_6 < iVar2) goto LAB_0040f53f;
      iVar1 = LCMapStringW(param_1,param_2,lpWideCharStr,iVar1,param_5,param_6);
    }
    if (iVar1 != 0) {
LAB_0040f4a4:
      FUN_0040bb20((undefined *)lpWideCharStr);
      FUN_0040bb20((undefined *)param_4);
      return iVar2;
    }
  }
LAB_0040f53f:
  FUN_0040bb20((undefined *)lpWideCharStr);
  FUN_0040bb20((undefined *)param_4);
  return 0;
}



int __cdecl FUN_0040f560(char *param_1,int param_2)

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



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

DWORD __cdecl FUN_0040f590(uint param_1,LONG param_2,DWORD param_3)

{
  HANDLE hFile;
  DWORD DVar1;
  uint uVar2;
  int iVar3;
  
  if (param_1 < DAT_00419d20) {
    iVar3 = (param_1 & 0x1f) * 8;
    if ((*(byte *)((&DAT_00419c20)[(int)param_1 >> 5] + 4 + iVar3) & 1) != 0) {
      hFile = (HANDLE)FUN_00410790(param_1);
      if (hFile == (HANDLE)0xffffffff) {
        _DAT_00417420 = 9;
        return 0xffffffff;
      }
      DVar1 = SetFilePointer(hFile,param_2,(PLONG)0x0,param_3);
      if (DVar1 == 0xffffffff) {
        uVar2 = GetLastError();
      }
      else {
        uVar2 = 0;
      }
      if (uVar2 != 0) {
        FUN_00410680(uVar2);
        return 0xffffffff;
      }
      *(byte *)((&DAT_00419c20)[(int)param_1 >> 5] + 4 + iVar3) =
           *(byte *)((&DAT_00419c20)[(int)param_1 >> 5] + 4 + iVar3) & 0xfd;
      return DVar1;
    }
  }
  _DAT_00417420 = 9;
  _DAT_00417424 = 0;
  return 0xffffffff;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int __cdecl FUN_0040f650(uint param_1,char *param_2,uint param_3)

{
  int *piVar1;
  byte bVar2;
  char cVar3;
  char *pcVar4;
  BOOL BVar5;
  int iVar6;
  char *pcVar7;
  DWORD local_41c;
  DWORD local_414;
  DWORD local_410;
  int local_40c;
  int *local_408;
  char local_404 [1028];
  
  if (param_1 < DAT_00419d20) {
    piVar1 = &DAT_00419c20 + ((int)param_1 >> 5);
    iVar6 = (param_1 & 0x1f) * 8;
    bVar2 = *(byte *)(iVar6 + 4 + (&DAT_00419c20)[(int)param_1 >> 5]);
    if ((bVar2 & 1) != 0) {
      local_41c = 0;
      local_40c = 0;
      if (param_3 == 0) {
        return 0;
      }
      local_408 = piVar1;
      if ((bVar2 & 0x20) != 0) {
        FUN_0040f590(param_1,0,2);
      }
      if ((*(byte *)((HANDLE *)(*piVar1 + iVar6) + 1) & 0x80) == 0) {
        BVar5 = WriteFile(*(HANDLE *)(*piVar1 + iVar6),param_2,param_3,&local_410,(LPOVERLAPPED)0x0)
        ;
        if (BVar5 == 0) {
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
            pcVar4 = local_404;
            do {
              if (param_3 <= (uint)((int)pcVar7 - (int)param_2)) break;
              cVar3 = *pcVar7;
              pcVar7 = pcVar7 + 1;
              if (cVar3 == '\n') {
                *pcVar4 = '\r';
                local_40c = local_40c + 1;
                pcVar4 = pcVar4 + 1;
              }
              *pcVar4 = cVar3;
              pcVar4 = pcVar4 + 1;
            } while ((int)pcVar4 - (int)local_404 < 0x400);
            BVar5 = WriteFile(*(HANDLE *)(iVar6 + *local_408),local_404,(int)pcVar4 - (int)local_404
                              ,&local_410,(LPOVERLAPPED)0x0);
            if (BVar5 == 0) {
              local_414 = GetLastError();
              break;
            }
            local_41c = local_41c + local_410;
            if (((int)local_410 < (int)pcVar4 - (int)local_404) ||
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
        _DAT_00417420 = 0x1c;
        _DAT_00417424 = 0;
        return -1;
      }
      if (local_414 == 5) {
        _DAT_00417424 = local_414;
        _DAT_00417420 = 9;
        return -1;
      }
      FUN_00410680(local_414);
      return -1;
    }
  }
  _DAT_00417420 = 9;
  _DAT_00417424 = 0;
  return -1;
}



void __cdecl FUN_0040f870(int *param_1)

{
  int iVar1;
  
  DAT_004176dc = DAT_004176dc + 1;
  iVar1 = FUN_0040ba70(0x1000);
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



byte __cdecl FUN_0040f8d0(uint param_1)

{
  if (DAT_00419d20 <= param_1) {
    return 0;
  }
  return *(byte *)((&DAT_00419c20)[(int)param_1 >> 5] + 4 + (param_1 & 0x1f) * 8) & 0x40;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

LPSTR __cdecl FUN_0040f9e0(LPSTR param_1,WCHAR param_2)

{
  LPSTR pCVar1;
  
  pCVar1 = param_1;
  if (param_1 == (LPSTR)0x0) {
    return param_1;
  }
  if (DAT_004176c0 == 0) {
    if ((ushort)param_2 < 0x100) {
      *param_1 = (CHAR)param_2;
      return (LPSTR)0x1;
    }
  }
  else {
    param_1 = (LPSTR)0x0;
    pCVar1 = (LPSTR)WideCharToMultiByte(DAT_004176d0,0x220,&param_2,1,pCVar1,DAT_0041379c,
                                        (LPCSTR)0x0,(LPBOOL)&param_1);
    if ((pCVar1 != (LPSTR)0x0) && (param_1 == (LPSTR)0x0)) {
      return pCVar1;
    }
  }
  _DAT_00417420 = 0x2a;
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



uint __thiscall FUN_0040fb50(void *this,uint param_1,uint param_2)

{
  uint uVar1;
  undefined2 in_FPUControlWord;
  undefined4 local_8;
  
  local_8 = CONCAT22((short)((uint)this >> 0x10),in_FPUControlWord);
  uVar1 = FUN_0040fbb0(local_8);
  uVar1 = param_2 & param_1 | ~param_2 & uVar1;
  FUN_0040fc50(uVar1);
  return uVar1;
}



void __cdecl FUN_0040fb90(void *param_1,uint param_2)

{
  FUN_0040fb50(param_1,(uint)param_1,param_2 & 0xfff7ffff);
  return;
}



uint __cdecl FUN_0040fbb0(uint param_1)

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
  if (uVar2 < 0x401) {
    if (uVar2 == 0x400) {
      uVar1 = uVar1 | 0x100;
    }
  }
  else if (uVar2 == 0x800) {
    uVar1 = uVar1 | 0x200;
  }
  else if (uVar2 == 0xc00) {
    uVar1 = uVar1 | 0x300;
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



void FUN_0040fc50(uint param_1)

{
  return;
}



uint __cdecl FUN_0040fce0(uint param_1)

{
  uint uVar1;
  uint uVar2;
  LPCWSTR pWVar3;
  int iVar4;
  uint local_8 [2];
  
  uVar1 = param_1;
  if (DAT_004176c0 == 0) {
    if ((0x40 < (int)param_1) && ((int)param_1 < 0x5b)) {
      return param_1 + 0x20;
    }
  }
  else {
    if ((int)param_1 < 0x100) {
      if (DAT_0041379c < 2) {
        uVar2 = (byte)PTR_DAT_00413590[param_1 * 2] & 1;
      }
      else {
        uVar2 = FUN_0040bb70(param_1,1);
      }
      if (uVar2 == 0) {
        return uVar1;
      }
    }
    uVar2 = param_1;
    if ((PTR_DAT_00413590[((int)uVar1 >> 8 & 0xffU) * 2 + 1] & 0x80) == 0) {
      param_1._0_2_ = (ushort)(byte)uVar1;
      pWVar3 = (LPCWSTR)0x1;
    }
    else {
      param_1._0_2_ = CONCAT11((byte)uVar1,(char)(uVar1 >> 8));
      param_1._0_3_ = (uint3)(ushort)param_1;
      pWVar3 = (LPCWSTR)0x2;
    }
    iVar4 = FUN_0040f340(DAT_004176c0,0x100,(char *)&param_1,pWVar3,(LPWSTR)local_8,3,0);
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



undefined4 __cdecl FUN_0040fde0(int param_1,int param_2)

{
  byte bVar1;
  int *piVar2;
  int iVar3;
  
  bVar1 = (byte)(param_2 >> 0x1f);
  iVar3 = (int)(param_2 + (param_2 >> 0x1f & 0x1fU)) >> 5;
  if ((*(uint *)(param_1 + iVar3 * 4) &
      ~(-1 << (0x1f - ((((byte)param_2 ^ bVar1) - bVar1 & 0x1f ^ bVar1) - bVar1) & 0x1f))) != 0) {
    return 0;
  }
  iVar3 = iVar3 + 1;
  if (iVar3 < 3) {
    piVar2 = (int *)(param_1 + iVar3 * 4);
    do {
      if (*piVar2 != 0) {
        return 0;
      }
      iVar3 = iVar3 + 1;
      piVar2 = piVar2 + 1;
    } while (iVar3 < 3);
    return 1;
  }
  return 1;
}



void __cdecl FUN_0040fe50(int param_1,int param_2)

{
  byte bVar1;
  int iVar2;
  int iVar3;
  uint *puVar4;
  
  bVar1 = (byte)(param_2 >> 0x1f);
  iVar3 = (int)(param_2 + (param_2 >> 0x1f & 0x1fU)) >> 5;
  iVar2 = FUN_004109a0(*(uint *)(param_1 + iVar3 * 4),
                       1 << (0x1f - ((((byte)param_2 ^ bVar1) - bVar1 & 0x1f ^ bVar1) - bVar1) &
                            0x1f),(uint *)(param_1 + iVar3 * 4));
  iVar3 = iVar3 + -1;
  if (-1 < iVar3) {
    puVar4 = (uint *)(param_1 + iVar3 * 4);
    do {
      if (iVar2 == 0) {
        return;
      }
      iVar2 = FUN_004109a0(*puVar4,1,puVar4);
      iVar3 = iVar3 + -1;
      puVar4 = puVar4 + -1;
    } while (-1 < iVar3);
  }
  return;
}



undefined4 __cdecl FUN_0040fec0(int param_1,int param_2)

{
  int iVar1;
  byte bVar2;
  int iVar3;
  undefined4 *puVar4;
  undefined4 local_4;
  
  local_4 = 0;
  bVar2 = (byte)(param_2 >> 0x1f);
  bVar2 = 0x1f - ((((byte)param_2 ^ bVar2) - bVar2 & 0x1f ^ bVar2) - bVar2);
  iVar3 = (int)(param_2 + (param_2 >> 0x1f & 0x1fU)) >> 5;
  if (((*(uint *)(param_1 + iVar3 * 4) & 1 << (bVar2 & 0x1f)) != 0) &&
     (iVar1 = FUN_0040fde0(param_1,param_2 + 1), iVar1 == 0)) {
    local_4 = FUN_0040fe50(param_1,param_2 + -1);
  }
  *(uint *)(param_1 + iVar3 * 4) = *(uint *)(param_1 + iVar3 * 4) & -1 << (bVar2 & 0x1f);
  iVar3 = iVar3 + 1;
  if (iVar3 < 3) {
    puVar4 = (undefined4 *)(param_1 + iVar3 * 4);
    for (iVar1 = 3 - iVar3; iVar1 != 0; iVar1 = iVar1 + -1) {
      *puVar4 = 0;
      puVar4 = puVar4 + 1;
    }
  }
  return local_4;
}



void __cdecl FUN_0040ff60(int param_1,undefined4 *param_2)

{
  int iVar1;
  int iVar2;
  
  iVar1 = param_1 - (int)param_2;
  iVar2 = 3;
  do {
    *(undefined4 *)((int)param_2 + iVar1) = *param_2;
    param_2 = param_2 + 1;
    iVar2 = iVar2 + -1;
  } while (iVar2 != 0);
  return;
}



void __cdecl FUN_0040ff80(undefined4 *param_1)

{
  *param_1 = 0;
  param_1[1] = 0;
  param_1[2] = 0;
  return;
}



undefined4 __cdecl FUN_0040ff90(int *param_1)

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



void __cdecl FUN_0040ffb0(uint *param_1,int param_2)

{
  int iVar1;
  byte bVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  uint *puVar6;
  int iVar7;
  
  iVar1 = (int)(param_2 + (param_2 >> 0x1f & 0x1fU)) >> 5;
  bVar2 = (byte)(param_2 >> 0x1f);
  uVar5 = 0;
  bVar2 = (((byte)param_2 ^ bVar2) - bVar2 & 0x1f ^ bVar2) - bVar2;
  param_2 = 3;
  puVar6 = param_1;
  do {
    uVar4 = *puVar6 >> (bVar2 & 0x1f) | uVar5;
    uVar5 = (~(-1 << (bVar2 & 0x1f)) & *puVar6) << (0x20 - bVar2 & 0x1f);
    *puVar6 = uVar4;
    param_2 = param_2 + -1;
    puVar6 = puVar6 + 1;
  } while (param_2 != 0);
  iVar7 = 2;
  iVar3 = 8;
  do {
    if (iVar7 < iVar1) {
      *(undefined4 *)((int)param_1 + iVar3) = 0;
    }
    else {
      *(undefined4 *)((int)param_1 + iVar3) = *(undefined4 *)((int)param_1 + iVar3 + iVar1 * -4);
    }
    iVar7 = iVar7 + -1;
    iVar3 = iVar3 + -4;
  } while (-1 < iVar3);
  return;
}



undefined4 __cdecl FUN_00410070(ushort *param_1,uint *param_2,int *param_3)

{
  ushort uVar1;
  int iVar2;
  undefined4 uVar3;
  uint uVar4;
  int iVar5;
  uint local_18;
  uint local_14;
  int local_10;
  undefined4 local_c [3];
  
  uVar1 = param_1[5];
  local_14 = *(uint *)(param_1 + 1);
  local_18 = *(uint *)(param_1 + 3);
  uVar4 = uVar1 & 0x7fff;
  iVar5 = uVar4 - 0x3fff;
  local_10 = (uint)*param_1 << 0x10;
  if (iVar5 == -0x3fff) {
    iVar5 = 0;
    iVar2 = FUN_0040ff90((int *)&local_18);
    if (iVar2 == 0) {
      FUN_0040ff80(&local_18);
      uVar3 = 2;
      goto LAB_004101f1;
    }
  }
  else {
    FUN_0040ff60((int)local_c,&local_18);
    iVar2 = FUN_0040fec0((int)&local_18,param_3[2]);
    if (iVar2 != 0) {
      iVar5 = uVar4 - 0x3ffe;
    }
    iVar2 = param_3[1];
    if (iVar5 < iVar2 - param_3[2]) {
      FUN_0040ff80(&local_18);
      iVar5 = 0;
      uVar3 = 2;
      goto LAB_004101f1;
    }
    if (iVar5 <= iVar2) {
      FUN_0040ff60((int)&local_18,local_c);
      FUN_0040ffb0(&local_18,iVar2 - iVar5);
      FUN_0040fec0((int)&local_18,param_3[2]);
      FUN_0040ffb0(&local_18,param_3[3] + 1);
      iVar5 = 0;
      uVar3 = 2;
      goto LAB_004101f1;
    }
    if (*param_3 <= iVar5) {
      FUN_0040ff80(&local_18);
      local_18 = local_18 | 0x80000000;
      FUN_0040ffb0(&local_18,param_3[3]);
      iVar5 = param_3[5] + *param_3;
      uVar3 = 1;
      goto LAB_004101f1;
    }
    iVar5 = param_3[5] + iVar5;
    local_18 = local_18 & 0x7fffffff;
    FUN_0040ffb0(&local_18,param_3[3]);
  }
  uVar3 = 0;
LAB_004101f1:
  local_18 = iVar5 << (0x1fU - (char)param_3[3] & 0x1f) |
             -(uint)((uVar1 & 0x8000) != 0) & 0x80000000 | local_18;
  if (param_3[4] == 0x40) {
    param_2[1] = local_18;
    *param_2 = local_14;
    return uVar3;
  }
  if (param_3[4] == 0x20) {
    *param_2 = local_18;
  }
  return uVar3;
}



void __cdecl FUN_00410240(ushort *param_1,uint *param_2)

{
  FUN_00410070(param_1,param_2,(int *)&DAT_00415cc0);
  return;
}



void __cdecl FUN_00410260(ushort *param_1,uint *param_2)

{
  FUN_00410070(param_1,param_2,(int *)&DAT_00415cd8);
  return;
}



void __cdecl FUN_00410280(uint *param_1,byte *param_2)

{
  ushort local_c [6];
  
  FUN_00410ba0(local_c,&param_2,param_2,0,0,0,0);
  FUN_00410240(local_c,param_1);
  return;
}



void __cdecl FUN_004102c0(uint *param_1,byte *param_2)

{
  ushort local_c [6];
  
  FUN_00410ba0(local_c,&param_2,param_2,0,0,0,0);
  FUN_00410260(local_c,param_1);
  return;
}



void __cdecl FUN_00410300(undefined4 *param_1,int param_2,int param_3)

{
  char *pcVar1;
  char cVar2;
  uint uVar3;
  uint uVar4;
  char *pcVar5;
  int iVar6;
  undefined4 *puVar7;
  char *pcVar8;
  
  pcVar5 = *(char **)(param_3 + 0xc);
  pcVar8 = (char *)((int)param_1 + 1);
  *(undefined *)param_1 = 0x30;
  pcVar1 = pcVar8;
  iVar6 = param_2;
  if (0 < param_2) {
    do {
      cVar2 = *pcVar5;
      if (cVar2 == '\0') {
        cVar2 = '0';
      }
      else {
        pcVar5 = pcVar5 + 1;
      }
      *pcVar1 = cVar2;
      pcVar1 = pcVar1 + 1;
      iVar6 = iVar6 + -1;
      param_2 = param_2 + -1;
    } while (param_2 != 0);
  }
  *pcVar1 = '\0';
  if ((-1 < iVar6) && ('4' < *pcVar5)) {
    cVar2 = pcVar1[-1];
    while (pcVar5 = pcVar1 + -1, cVar2 == '9') {
      *pcVar5 = '0';
      cVar2 = pcVar1[-2];
      pcVar1 = pcVar5;
    }
    *pcVar5 = *pcVar5 + '\x01';
  }
  if (*(char *)param_1 == '1') {
    *(int *)(param_3 + 4) = *(int *)(param_3 + 4) + 1;
    return;
  }
  uVar3 = 0xffffffff;
  do {
    pcVar5 = pcVar8;
    if (uVar3 == 0) break;
    uVar3 = uVar3 - 1;
    pcVar5 = pcVar8 + 1;
    cVar2 = *pcVar8;
    pcVar8 = pcVar5;
  } while (cVar2 != '\0');
  uVar3 = ~uVar3;
  puVar7 = (undefined4 *)(pcVar5 + -uVar3);
  for (uVar4 = uVar3 >> 2; uVar4 != 0; uVar4 = uVar4 - 1) {
    *param_1 = *puVar7;
    puVar7 = puVar7 + 1;
    param_1 = param_1 + 1;
  }
  for (uVar3 = uVar3 & 3; uVar3 != 0; uVar3 = uVar3 - 1) {
    *(char *)param_1 = *(char *)puVar7;
    puVar7 = (undefined4 *)((int)puVar7 + 1);
    param_1 = (undefined4 *)((int)param_1 + 1);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined * FUN_004103a0(undefined param_1)

{
  undefined4 in_stack_ffffffe4;
  undefined2 uVar1;
  uint local_c;
  uint local_8;
  undefined2 local_4;
  
  uVar1 = (undefined2)((uint)in_stack_ffffffe4 >> 0x10);
  FUN_00410420(&local_c,(uint *)&param_1);
  _DAT_00417708 = FUN_00411330(local_c,local_8,CONCAT22(uVar1,local_4),0x11,0,&DAT_004176e0);
  _DAT_00417700 = (int)DAT_004176e2;
  _DAT_00417704 = (int)DAT_004176e0;
  _DAT_0041770c = &DAT_004176e4;
  return &DAT_00417700;
}



void __cdecl FUN_00410420(uint *param_1,uint *param_2)

{
  ushort uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  ushort uVar5;
  int iVar6;
  
  uVar4 = 0x80000000;
  uVar1 = *(ushort *)((int)param_2 + 6);
  uVar2 = *param_2;
  uVar3 = (uVar1 & 0x7ff0) >> 4;
  if (uVar3 == 0) {
    uVar4 = 0;
    if (((param_2[1] & 0xfffff) == 0) && (uVar2 == 0)) {
      param_1[1] = 0;
      *param_1 = 0;
      *(undefined2 *)(param_1 + 2) = 0;
      return;
    }
    iVar6 = 0x3c01;
  }
  else if (uVar3 == 0x7ff) {
    iVar6 = 0x7fff;
  }
  else {
    iVar6 = uVar3 + 0x3c00;
  }
  uVar5 = (ushort)iVar6;
  uVar3 = uVar2 >> 0x15 | (param_2[1] & 0xfffff) << 0xb | uVar4;
  param_1[1] = uVar3;
  *param_1 = uVar2 << 0xb;
  for (; uVar4 == 0; uVar4 = uVar4 & 0x80000000) {
    uVar4 = uVar3 * 2;
    uVar3 = *param_1 >> 0x1f | uVar4;
    iVar6 = iVar6 + 0xffff;
    uVar5 = (ushort)iVar6;
    param_1[1] = uVar3;
    *param_1 = *param_1 * 2;
  }
  *(ushort *)(param_1 + 2) = uVar5 | uVar1 & 0x8000;
  return;
}



void FUN_004104e0(void)

{
  __amsg_exit(2);
  return;
}



int __cdecl FUN_004104f0(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  HMODULE hModule;
  int iVar1;
  
  iVar1 = 0;
  if (DAT_00417710 != (FARPROC)0x0) {
LAB_00410540:
    if (DAT_00417714 != (FARPROC)0x0) {
      iVar1 = (*DAT_00417714)();
    }
    if ((iVar1 != 0) && (DAT_00417718 != (FARPROC)0x0)) {
      iVar1 = (*DAT_00417718)(iVar1);
    }
    iVar1 = (*DAT_00417710)(iVar1,param_1,param_2,param_3);
    return iVar1;
  }
  hModule = LoadLibraryA("user32.dll");
  if (hModule != (HMODULE)0x0) {
    DAT_00417710 = GetProcAddress(hModule,"MessageBoxA");
    if (DAT_00417710 != (FARPROC)0x0) {
      DAT_00417714 = GetProcAddress(hModule,"GetActiveWindow");
      DAT_00417718 = GetProcAddress(hModule,"GetLastActivePopup");
      goto LAB_00410540;
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
        goto joined_r0x004105be;
      }
    }
    do {
      if (((uint)puVar5 & 3) == 0) {
        uVar4 = _Count >> 2;
        cVar3 = '\0';
        if (uVar4 == 0) goto LAB_004105fb;
        goto LAB_00410669;
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
joined_r0x00410665:
          while( true ) {
            uVar4 = uVar4 - 1;
            puVar5 = puVar5 + 1;
            if (uVar4 == 0) break;
LAB_00410669:
            *puVar5 = 0;
          }
          cVar3 = '\0';
          _Count = _Count & 3;
          if (_Count != 0) goto LAB_004105fb;
          return _Dest;
        }
        if ((char)(uVar2 >> 8) == '\0') {
          *puVar5 = uVar2 & 0xff;
          goto joined_r0x00410665;
        }
        if ((uVar2 & 0xff0000) == 0) {
          *puVar5 = uVar2 & 0xffff;
          goto joined_r0x00410665;
        }
        if ((uVar2 & 0xff000000) == 0) {
          *puVar5 = uVar2;
          goto joined_r0x00410665;
        }
      }
      *puVar5 = uVar2;
      puVar5 = puVar5 + 1;
      uVar4 = uVar4 - 1;
joined_r0x004105be:
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
LAB_004105fb:
        *(char *)puVar5 = cVar3;
        puVar5 = (uint *)((int)puVar5 + 1);
      }
      return _Dest;
    }
    _Count = _Count - 1;
  } while (_Count != 0);
  return _Dest;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_00410680(uint param_1)

{
  uint *puVar1;
  int iVar2;
  
  _DAT_00417424 = param_1;
  iVar2 = 0;
  puVar1 = &DAT_00415cf0;
  do {
    if (param_1 == *puVar1) {
      _DAT_00417420 = (&DAT_00415cf4)[iVar2 * 2];
      return;
    }
    puVar1 = puVar1 + 2;
    iVar2 = iVar2 + 1;
  } while (puVar1 < &DAT_00415e58);
  if ((0x12 < param_1) && (param_1 < 0x25)) {
    _DAT_00417420 = 0xd;
    return;
  }
  if ((param_1 < 0xbc) || (_DAT_00417420 = 8, 0xca < param_1)) {
    _DAT_00417420 = 0x16;
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 __cdecl FUN_00410790(uint param_1)

{
  if ((param_1 < DAT_00419d20) &&
     ((*(byte *)((&DAT_00419c20)[(int)param_1 >> 5] + 4 + (param_1 & 0x1f) * 8) & 1) != 0)) {
    return *(undefined4 *)((&DAT_00419c20)[(int)param_1 >> 5] + (param_1 & 0x1f) * 8);
  }
  _DAT_00417420 = 9;
  _DAT_00417424 = 0;
  return 0xffffffff;
}



undefined4 __cdecl FUN_004109a0(uint param_1,uint param_2,uint *param_3)

{
  uint uVar1;
  undefined4 uVar2;
  
  uVar2 = 0;
  uVar1 = param_2 + param_1;
  if ((uVar1 < param_1) || (uVar1 < param_2)) {
    uVar2 = 1;
  }
  *param_3 = uVar1;
  return uVar2;
}



void __cdecl FUN_004109d0(uint *param_1,uint *param_2)

{
  int iVar1;
  
  iVar1 = FUN_004109a0(*param_1,*param_2,param_1);
  if (iVar1 != 0) {
    iVar1 = FUN_004109a0(param_1[1],1,param_1 + 1);
    if (iVar1 != 0) {
      param_1[2] = param_1[2] + 1;
    }
  }
  iVar1 = FUN_004109a0(param_1[1],param_2[1],param_1 + 1);
  if (iVar1 != 0) {
    param_1[2] = param_1[2] + 1;
  }
  FUN_004109a0(param_1[2],param_2[2],param_1 + 2);
  return;
}



void __cdecl FUN_00410a40(uint *param_1)

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



void __cdecl FUN_00410a70(uint *param_1)

{
  uint uVar1;
  
  uVar1 = param_1[1];
  param_1[1] = uVar1 >> 1 | param_1[2] << 0x1f;
  param_1[2] = param_1[2] >> 1;
  *param_1 = *param_1 >> 1 | uVar1 << 0x1f;
  return;
}



void __cdecl FUN_00410aa0(char *param_1,int param_2,uint *param_3)

{
  uint uVar1;
  uint *puVar2;
  short sVar3;
  uint local_c;
  uint local_8;
  uint local_4;
  
  puVar2 = param_3;
  sVar3 = 0x404e;
  *param_3 = 0;
  param_3[1] = 0;
  param_3[2] = 0;
  if (param_2 != 0) {
    param_3 = (uint *)param_2;
    do {
      local_c = *puVar2;
      local_8 = puVar2[1];
      local_4 = puVar2[2];
      FUN_00410a40(puVar2);
      FUN_00410a40(puVar2);
      FUN_004109d0(puVar2,&local_c);
      FUN_00410a40(puVar2);
      local_c = (uint)*param_1;
      local_8 = 0;
      local_4 = 0;
      FUN_004109d0(puVar2,&local_c);
      param_1 = param_1 + 1;
      param_3 = (uint *)((int)param_3 + -1);
    } while (param_3 != (uint *)0x0);
  }
  uVar1 = puVar2[2];
  while (uVar1 == 0) {
    sVar3 = sVar3 + -0x10;
    puVar2[2] = puVar2[1] >> 0x10;
    uVar1 = puVar2[2];
    puVar2[1] = *puVar2 >> 0x10 | puVar2[1] << 0x10;
    *puVar2 = *puVar2 << 0x10;
  }
  uVar1 = puVar2[2];
  while ((uVar1 & 0x8000) == 0) {
    FUN_00410a40(puVar2);
    sVar3 = sVar3 + -1;
    uVar1 = puVar2[2];
  }
  *(short *)((int)puVar2 + 10) = sVar3;
  return;
}



undefined4 __cdecl
FUN_00410ba0(ushort *param_1,byte **param_2,byte *param_3,int param_4,int param_5,int param_6,
            int param_7)

{
  char cVar1;
  bool bVar2;
  bool bVar3;
  bool bVar4;
  bool bVar5;
  bool bVar6;
  ushort uVar7;
  int iVar8;
  uint uVar9;
  byte bVar10;
  byte *pbVar11;
  byte *pbVar12;
  uint uVar13;
  byte *pbVar14;
  int local_60;
  char *local_5c;
  uint local_54;
  byte *local_50;
  int local_4c;
  int local_48;
  undefined4 local_30;
  ushort local_2c;
  undefined2 uStack_2a;
  undefined2 uStack_28;
  byte *local_26;
  undefined4 local_22;
  char local_1c [23];
  char local_5;
  
  local_5c = local_1c;
  iVar8 = 0;
  uVar13 = 0;
  uVar7 = 0;
  local_4c = 1;
  local_54 = 0;
  bVar2 = false;
  bVar4 = false;
  bVar3 = false;
  bVar5 = false;
  bVar6 = false;
  local_48 = 0;
  local_60 = 0;
  local_30 = 0;
  local_50 = param_3;
  for (pbVar11 = param_3;
      (((bVar10 = *pbVar11, bVar10 == 0x20 || (bVar10 == 9)) || (bVar10 == 10)) ||
      (pbVar14 = param_3, bVar10 == 0xd)); pbVar11 = pbVar11 + 1) {
  }
  do {
    bVar10 = *pbVar11;
    pbVar12 = pbVar11 + 1;
    param_3 = (byte *)CONCAT31(param_3._1_3_,bVar10);
    switch(iVar8) {
    case 0:
      if (('0' < (char)bVar10) && ((char)bVar10 < ':')) {
        iVar8 = 3;
        goto LAB_00411072;
      }
      if (bVar10 == DAT_004137a0) {
        iVar8 = 5;
      }
      else if (bVar10 == 0x2b) {
        iVar8 = 2;
        uVar7 = 0;
      }
      else if (bVar10 == 0x2d) {
        iVar8 = 2;
        uVar7 = 0x8000;
      }
      else {
        if (bVar10 != 0x30) goto switchD_00410e62_caseD_2c;
        iVar8 = 1;
      }
      break;
    case 1:
      bVar2 = true;
      if (('0' < (char)bVar10) && ((char)bVar10 < ':')) {
        iVar8 = 3;
        goto LAB_00411072;
      }
      if (bVar10 == DAT_004137a0) {
        iVar8 = 4;
      }
      else {
        switch(bVar10) {
        case 0x2b:
        case 0x2d:
          goto switchD_00410e62_caseD_2b;
        default:
          goto switchD_00410e62_caseD_2c;
        case 0x30:
switchD_00410cd6_caseD_30:
          iVar8 = 1;
          break;
        case 0x44:
        case 0x45:
        case 100:
        case 0x65:
          goto switchD_00410e62_caseD_44;
        }
      }
      break;
    case 2:
      if (('0' < (char)bVar10) && ((char)bVar10 < ':')) {
        iVar8 = 3;
        goto LAB_00411072;
      }
      if (bVar10 == DAT_004137a0) {
        iVar8 = 5;
      }
      else {
        if (bVar10 == 0x30) goto switchD_00410cd6_caseD_30;
        iVar8 = 10;
        pbVar12 = pbVar14;
      }
      break;
    case 3:
      while( true ) {
        bVar2 = true;
        if (DAT_0041379c < 2) {
          uVar9 = (byte)PTR_DAT_00413590[((uint)param_3 & 0xff) * 2] & 4;
        }
        else {
          uVar9 = FUN_0040bb70((uint)param_3 & 0xff,4);
        }
        if (uVar9 == 0) break;
        if (uVar13 < 0x19) {
          uVar13 = uVar13 + 1;
          *local_5c = bVar10 - 0x30;
          bVar10 = *pbVar12;
          local_5c = local_5c + 1;
          param_3 = (byte *)CONCAT31(param_3._1_3_,bVar10);
          pbVar12 = pbVar12 + 1;
        }
        else {
          bVar10 = *pbVar12;
          local_60 = local_60 + 1;
          param_3 = (byte *)CONCAT31(param_3._1_3_,bVar10);
          pbVar12 = pbVar12 + 1;
        }
      }
      local_54 = uVar13;
      if (bVar10 != DAT_004137a0) {
        switch(bVar10) {
        case 0x2b:
        case 0x2d:
          goto switchD_00410e62_caseD_2b;
        case 0x44:
        case 0x45:
        case 100:
        case 0x65:
          goto switchD_00410e62_caseD_44;
        }
switchD_00410e62_caseD_2c:
        iVar8 = 10;
        goto LAB_00411072;
      }
      iVar8 = 4;
      break;
    case 4:
      bVar4 = true;
      if (uVar13 == 0) {
        while (bVar10 == 0x30) {
          bVar10 = *pbVar12;
          local_60 = local_60 + -1;
          pbVar12 = pbVar12 + 1;
          param_3._1_3_ = (undefined3)((uint)param_3 >> 8);
          param_3 = (byte *)CONCAT31(param_3._1_3_,bVar10);
        }
      }
      while( true ) {
        bVar2 = true;
        if (DAT_0041379c < 2) {
          uVar9 = (byte)PTR_DAT_00413590[((uint)param_3 & 0xff) * 2] & 4;
        }
        else {
          uVar9 = FUN_0040bb70((uint)param_3 & 0xff,4);
        }
        if (uVar9 == 0) break;
        if (uVar13 < 0x19) {
          uVar13 = uVar13 + 1;
          *local_5c = bVar10 - 0x30;
          local_5c = local_5c + 1;
          local_60 = local_60 + -1;
        }
        bVar10 = *pbVar12;
        pbVar12 = pbVar12 + 1;
        param_3 = (byte *)CONCAT31(param_3._1_3_,bVar10);
      }
      local_54 = uVar13;
      switch(bVar10) {
      case 0x2b:
      case 0x2d:
switchD_00410e62_caseD_2b:
        bVar2 = true;
        pbVar12 = pbVar12 + -1;
        iVar8 = 0xb;
        break;
      default:
        goto switchD_00410e62_caseD_2c;
      case 0x44:
      case 0x45:
      case 100:
      case 0x65:
switchD_00410e62_caseD_44:
        bVar2 = true;
        iVar8 = 6;
      }
      break;
    case 5:
      bVar4 = true;
      if (DAT_0041379c < 2) {
        uVar9 = (byte)PTR_DAT_00413590[(uint)bVar10 * 2] & 4;
      }
      else {
        uVar9 = FUN_0040bb70((uint)bVar10,4);
      }
      if (uVar9 == 0) {
        iVar8 = 10;
        pbVar12 = pbVar14;
      }
      else {
        iVar8 = 4;
        pbVar12 = pbVar11;
      }
      break;
    case 6:
      pbVar11 = pbVar11 + -1;
      pbVar14 = pbVar11;
      local_50 = pbVar11;
      if (('0' < (char)bVar10) && ((char)bVar10 < ':')) {
        iVar8 = 9;
        goto LAB_00411072;
      }
      if (bVar10 == 0x2b) {
LAB_00411066:
        iVar8 = 7;
        pbVar14 = pbVar11;
        local_50 = pbVar11;
      }
      else {
        if (bVar10 != 0x2d) goto LAB_00410f56;
LAB_00411057:
        iVar8 = 7;
        local_4c = -1;
        pbVar14 = pbVar11;
        local_50 = pbVar11;
      }
      break;
    case 7:
      if (('0' < (char)bVar10) && ((char)bVar10 < ':')) {
        iVar8 = 9;
        goto LAB_00411072;
      }
LAB_00410f56:
      if (bVar10 == 0x30) {
        iVar8 = 8;
      }
      else {
        iVar8 = 10;
        pbVar12 = pbVar14;
      }
      break;
    case 8:
      bVar3 = true;
      while (bVar10 == 0x30) {
        bVar10 = *pbVar12;
        pbVar12 = pbVar12 + 1;
      }
      if (((char)bVar10 < '1') || ('9' < (char)bVar10)) goto switchD_00410e62_caseD_2c;
      iVar8 = 9;
LAB_00411072:
      pbVar12 = pbVar12 + -1;
      break;
    case 9:
      bVar3 = true;
      local_48 = 0;
      while( true ) {
        if (DAT_0041379c < 2) {
          uVar13 = (byte)PTR_DAT_00413590[((uint)param_3 & 0xff) * 2] & 4;
        }
        else {
          uVar13 = FUN_0040bb70((uint)param_3 & 0xff,4);
        }
        if (uVar13 == 0) goto LAB_00410fda;
        local_48 = (char)bVar10 + -0x30 + local_48 * 10;
        if (0x1450 < local_48) break;
        bVar10 = *pbVar12;
        pbVar12 = pbVar12 + 1;
        param_3 = (byte *)CONCAT31(param_3._1_3_,bVar10);
      }
      local_48 = 0x1451;
LAB_00410fda:
      while( true ) {
        if (DAT_0041379c < 2) {
          uVar13 = (byte)PTR_DAT_00413590[((uint)param_3 & 0xff) * 2] & 4;
        }
        else {
          uVar13 = FUN_0040bb70((uint)param_3 & 0xff,4);
        }
        if (uVar13 == 0) break;
        bVar10 = *pbVar12;
        pbVar12 = pbVar12 + 1;
        param_3 = (byte *)CONCAT31(param_3._1_3_,bVar10);
      }
      iVar8 = 10;
      pbVar12 = pbVar12 + -1;
      uVar13 = local_54;
      pbVar14 = local_50;
      break;
    case 0xb:
      if (param_7 == 0) goto switchD_00410e62_caseD_2c;
      if (bVar10 == 0x2b) goto LAB_00411066;
      if (bVar10 == 0x2d) goto LAB_00411057;
      iVar8 = 10;
      pbVar12 = pbVar11;
      pbVar14 = pbVar11;
      local_50 = pbVar11;
    }
    pbVar11 = pbVar12;
  } while (iVar8 != 10);
  *param_2 = pbVar12;
  if (bVar2) {
    if (0x18 < uVar13) {
      if ('\x04' < local_5) {
        local_5 = local_5 + '\x01';
      }
      local_5c = local_5c + -1;
      local_60 = local_60 + 1;
      uVar13 = 0x18;
    }
    if (uVar13 == 0) {
      local_2c = 0;
      local_22._0_2_ = 0;
      param_3 = (byte *)0x0;
      pbVar11 = (byte *)0x0;
      goto LAB_00411144;
    }
    cVar1 = local_5c[-1];
    while (cVar1 == '\0') {
      uVar13 = uVar13 - 1;
      local_60 = local_60 + 1;
      cVar1 = local_5c[-2];
      local_5c = local_5c + -1;
    }
    FUN_00410aa0(local_1c,uVar13,(uint *)&local_2c);
    if (local_4c < 0) {
      local_48 = -local_48;
    }
    uVar13 = local_48 + local_60;
    if (!bVar3) {
      uVar13 = uVar13 + param_5;
    }
    if (!bVar4) {
      uVar13 = uVar13 - param_6;
    }
    if ((int)uVar13 < 0x1451) {
      if (-0x1451 < (int)uVar13) {
        FUN_00411a60((int *)&local_2c,uVar13,param_4);
        pbVar11 = (byte *)CONCAT22(uStack_28,uStack_2a);
        param_3 = local_26;
        goto LAB_00411144;
      }
      bVar6 = true;
    }
    else {
      bVar5 = true;
    }
  }
  local_2c = (ushort)param_3;
  pbVar11 = param_3;
  local_22._0_2_ = local_2c;
LAB_00411144:
  if (bVar2) {
    if (bVar5) {
      pbVar11 = (byte *)0x0;
      local_22._0_2_ = 0x7fff;
      param_3 = (byte *)0x80000000;
      local_2c = 0;
      local_30 = 2;
    }
    else if (bVar6) {
      local_2c = 0;
      local_22._0_2_ = 0;
      param_3 = (byte *)0x0;
      pbVar11 = (byte *)0x0;
      local_30 = 1;
    }
  }
  else {
    local_2c = 0;
    local_22._0_2_ = 0;
    param_3 = (byte *)0x0;
    pbVar11 = (byte *)0x0;
    local_30 = 4;
  }
  *param_1 = local_2c;
  *(byte **)(param_1 + 1) = pbVar11;
  *(byte **)(param_1 + 3) = param_3;
  param_1[5] = (ushort)local_22 | uVar7;
  return local_30;
}



undefined4 __cdecl
FUN_00411330(uint param_1,uint param_2,uint param_3,int param_4,byte param_5,short *param_6)

{
  short *psVar1;
  ushort uVar2;
  uint uVar3;
  char cVar4;
  uint uVar5;
  int iVar6;
  short *psVar7;
  short *psVar8;
  int iVar9;
  short sVar10;
  int iVar11;
  undefined local_1c;
  undefined local_1b;
  undefined local_1a;
  undefined local_19;
  undefined local_18;
  undefined local_17;
  undefined local_16;
  undefined local_15;
  undefined local_14;
  undefined local_13;
  undefined local_12;
  undefined local_11;
  undefined2 local_10;
  undefined4 uStack_e;
  undefined4 uStack_a;
  undefined local_6;
  char cStack_5;
  
  psVar1 = param_6;
  local_1c = 0xcc;
  local_1b = 0xcc;
  local_1a = 0xcc;
  local_19 = 0xcc;
  local_18 = 0xcc;
  local_17 = 0xcc;
  local_16 = 0xcc;
  local_15 = 0xcc;
  local_14 = 0xcc;
  local_13 = 0xcc;
  uVar5 = param_3 & 0x7fff;
  local_12 = 0xfb;
  local_11 = 0x3f;
  if ((param_3 & 0x8000) == 0) {
    *(undefined *)(param_6 + 1) = 0x20;
  }
  else {
    *(undefined *)(param_6 + 1) = 0x2d;
  }
  if ((((short)uVar5 == 0) && (param_2 == 0)) && (param_1 == 0)) {
    *param_6 = 0;
LAB_0041153f:
    *(undefined *)(psVar1 + 1) = 0x20;
    *(undefined *)((int)psVar1 + 3) = 1;
    *(undefined *)(psVar1 + 2) = 0x30;
    *(undefined *)((int)psVar1 + 5) = 0;
    return 1;
  }
  if ((short)uVar5 == 0x7fff) {
    *param_6 = 1;
    if (((param_2 != 0x80000000) || (param_1 != 0)) && ((param_2 & 0x40000000) == 0)) {
      *(undefined4 *)(param_6 + 2) = 0x4e532331;
      param_6[4] = 0x4e41;
      *(undefined *)((int)param_6 + 3) = 6;
      *(undefined *)(param_6 + 5) = 0;
      return 0;
    }
    if ((((param_3 & 0x8000) != 0) && (param_2 == 0xc0000000)) && (param_1 == 0)) {
      *(undefined4 *)(param_6 + 2) = 0x4e492331;
      *(undefined *)((int)param_6 + 3) = 5;
      param_6[4] = 0x44;
      return 0;
    }
    if ((param_2 == 0x80000000) && (param_1 == 0)) {
      *(undefined4 *)(param_6 + 2) = 0x4e492331;
      *(undefined *)((int)param_6 + 3) = 5;
      param_6[4] = 0x46;
      return 0;
    }
    *(undefined4 *)(param_6 + 2) = 0x4e512331;
    param_6[4] = 0x4e41;
    *(undefined *)((int)param_6 + 3) = 6;
    *(undefined *)(param_6 + 5) = 0;
    return 0;
  }
  local_6 = (undefined)uVar5;
  cStack_5 = (char)(uVar5 >> 8);
  local_10 = 0;
  sVar10 = (short)(((uVar5 >> 8) + (param_2 >> 0x18) * 2) * 0x4d + -0x134312f4 + uVar5 * 0x4d10 >>
                  0x10);
  uStack_a = param_2;
  uStack_e = param_1;
  FUN_00411a60((int *)&local_10,-(int)sVar10,1);
  if (0x3ffe < CONCAT11(cStack_5,local_6)) {
    sVar10 = sVar10 + 1;
    FUN_004117a0((int *)&local_10,(int *)&local_1c);
  }
  *psVar1 = sVar10;
  iVar9 = param_4;
  if (((param_5 & 1) != 0) && (iVar9 = param_4 + sVar10, param_4 + sVar10 < 1)) {
    *psVar1 = 0;
    goto LAB_0041153f;
  }
  if (0x15 < iVar9) {
    iVar9 = 0x15;
  }
  uVar2 = CONCAT11(cStack_5,local_6);
  local_6 = 0;
  cStack_5 = '\0';
  iVar6 = 8;
  iVar11 = uVar2 - 0x3ffe;
  do {
    FUN_00410a40((uint *)&local_10);
    iVar6 = iVar6 + -1;
  } while (iVar6 != 0);
  if (iVar11 < 0) {
    for (uVar5 = -iVar11 & 0xff; uVar5 != 0; uVar5 = uVar5 - 1) {
      FUN_00410a70((uint *)&local_10);
    }
  }
  psVar1 = psVar1 + 2;
  iVar9 = iVar9 + 1;
  psVar7 = psVar1;
  uVar5 = uStack_e;
  uVar3 = uStack_a;
  if (0 < iVar9) {
    do {
      uStack_a._2_2_ = (undefined2)(uVar3 >> 0x10);
      uStack_a._0_2_ = (undefined2)uVar3;
      uStack_e._2_2_ = (undefined2)(uVar5 >> 0x10);
      uStack_e._0_2_ = (undefined2)uVar5;
      param_1 = CONCAT22((undefined2)uStack_e,local_10);
      param_2 = CONCAT22((undefined2)uStack_a,uStack_e._2_2_);
      param_3 = CONCAT13(cStack_5,CONCAT12(local_6,uStack_a._2_2_));
      uStack_e = uVar5;
      uStack_a = uVar3;
      FUN_00410a40((uint *)&local_10);
      FUN_00410a40((uint *)&local_10);
      FUN_004109d0((uint *)&local_10,&param_1);
      FUN_00410a40((uint *)&local_10);
      cVar4 = cStack_5 + '0';
      cStack_5 = '\0';
      *(char *)psVar7 = cVar4;
      psVar7 = (short *)((int)psVar7 + 1);
      iVar9 = iVar9 + -1;
      uVar5 = uStack_e;
      uVar3 = uStack_a;
    } while (iVar9 != 0);
  }
  psVar8 = psVar7 + -1;
  if (*(char *)((int)psVar7 + -1) < '5') {
    if (psVar1 <= psVar8) {
      do {
        if (*(char *)psVar8 != '0') break;
        psVar8 = (short *)((int)psVar8 + -1);
      } while (psVar1 <= psVar8);
      if (psVar1 <= psVar8) goto LAB_00411696;
    }
    *(char *)psVar1 = '0';
    *param_6 = 0;
    *(undefined *)(param_6 + 1) = 0x20;
    *(undefined *)((int)param_6 + 3) = 1;
    *(undefined *)((int)param_6 + 5) = 0;
    return 1;
  }
  if (psVar1 <= psVar8) {
    do {
      if (*(char *)psVar8 != '9') break;
      *(char *)psVar8 = '0';
      psVar8 = (short *)((int)psVar8 + -1);
    } while (psVar1 <= psVar8);
    if (psVar1 <= psVar8) {
      *(char *)psVar8 = *(char *)psVar8 + '\x01';
      goto LAB_00411696;
    }
  }
  psVar8 = (short *)((int)psVar8 + 1);
  *param_6 = *param_6 + 1;
  *(char *)psVar8 = *(char *)psVar8 + '\x01';
LAB_00411696:
  cVar4 = ((char)psVar8 - (char)param_6) + -3;
  *(char *)((int)param_6 + 3) = cVar4;
  *(undefined *)((int)param_6 + cVar4 + 4) = 0;
  return 1;
}



void __cdecl FUN_004117a0(int *param_1,int *param_2)

{
  ushort uVar1;
  int iVar2;
  ushort uVar3;
  ushort uVar4;
  int iVar5;
  ushort uVar6;
  ushort *puVar7;
  int *piVar8;
  short *local_20;
  int local_18;
  int local_14;
  int local_10;
  byte local_c;
  undefined uStack_b;
  undefined2 uStack_a;
  short local_8;
  undefined2 uStack_6;
  undefined2 local_4;
  ushort uStack_2;
  
  local_14 = 0;
  local_c = 0;
  uStack_b = 0;
  uStack_a = 0;
  local_8 = 0;
  uStack_6 = 0;
  uVar3 = *(ushort *)((int)param_2 + 10) & 0x7fff;
  uVar1 = *(ushort *)((int)param_1 + 10) & 0x7fff;
  uVar6 = (*(ushort *)((int)param_2 + 10) ^ *(ushort *)((int)param_1 + 10)) & 0x8000;
  uVar4 = uVar3 + uVar1;
  local_4 = 0;
  uStack_2 = 0;
  if (((0x7ffe < uVar1) || (0x7ffe < uVar3)) || (0xbffd < uVar4)) {
    param_1[1] = 0;
    *param_1 = 0;
    param_1[2] = (-(uint)(uVar6 != 0) & 0x80000000) + 0x7fff8000;
    return;
  }
  if (uVar4 < 0x3fc0) {
    param_1[2] = 0;
    param_1[1] = 0;
    *param_1 = 0;
    return;
  }
  if (((uVar1 == 0) && (uVar4 = uVar4 + 1, (param_1[2] & 0x7fffffffU) == 0)) &&
     ((param_1[1] == 0 && (*param_1 == 0)))) {
    *(undefined2 *)((int)param_1 + 10) = 0;
    return;
  }
  if (((uVar3 == 0) && (uVar4 = uVar4 + 1, (param_2[2] & 0x7fffffffU) == 0)) &&
     ((param_2[1] == 0 && (*param_2 == 0)))) {
    param_1[2] = 0;
    param_1[1] = 0;
    *param_1 = 0;
    return;
  }
  local_20 = &local_8;
  local_18 = 0;
  iVar5 = 5;
  do {
    if (0 < iVar5) {
      piVar8 = param_2 + 2;
      puVar7 = (ushort *)(local_18 * 2 + (int)param_1);
      local_10 = iVar5;
      do {
        iVar2 = FUN_004109a0(*(uint *)(local_20 + -2),(uint)*(ushort *)piVar8 * (uint)*puVar7,
                             (uint *)(local_20 + -2));
        if (iVar2 != 0) {
          *local_20 = *local_20 + 1;
        }
        puVar7 = puVar7 + 1;
        piVar8 = (int *)((int)piVar8 + -2);
        local_10 = local_10 + -1;
      } while (local_10 != 0);
    }
    local_20 = local_20 + 1;
    local_18 = local_18 + 1;
    iVar5 = iVar5 + -1;
  } while (0 < iVar5);
  uVar4 = uVar4 + 0xc002;
  while ((0 < (short)uVar4 && ((uStack_2 & 0x8000) == 0))) {
    FUN_00410a40((uint *)&local_c);
    uVar4 = uVar4 - 1;
  }
  if ((short)uVar4 < 1) {
    uVar4 = uVar4 - 1;
    if ((short)uVar4 < 0) {
      iVar5 = -(int)(short)uVar4;
      uVar4 = uVar4 + (short)iVar5;
      do {
        if ((local_c & 1) != 0) {
          local_14 = local_14 + 1;
        }
        FUN_00410a70((uint *)&local_c);
        iVar5 = iVar5 + -1;
      } while (iVar5 != 0);
    }
    if (local_14 != 0) {
      local_c = local_c | 1;
    }
  }
  if ((0x8000 < CONCAT11(uStack_b,local_c)) ||
     (iVar2 = CONCAT22(local_4,uStack_6), iVar5 = CONCAT22(local_8,uStack_a),
     (CONCAT22(uStack_a,CONCAT11(uStack_b,local_c)) & 0x1ffff) == 0x18000)) {
    if (CONCAT22(local_8,uStack_a) == -1) {
      iVar5 = 0;
      if (CONCAT22(local_4,uStack_6) == -1) {
        if (uStack_2 == 0xffff) {
          uStack_2 = 0x8000;
          uVar4 = uVar4 + 1;
          iVar2 = 0;
          iVar5 = 0;
        }
        else {
          uStack_2 = uStack_2 + 1;
          iVar2 = 0;
          iVar5 = 0;
        }
      }
      else {
        iVar2 = CONCAT22(local_4,uStack_6) + 1;
      }
    }
    else {
      iVar5 = CONCAT22(local_8,uStack_a) + 1;
      iVar2 = CONCAT22(local_4,uStack_6);
    }
  }
  local_8 = (short)((uint)iVar5 >> 0x10);
  uStack_a = (undefined2)iVar5;
  local_4 = (undefined2)((uint)iVar2 >> 0x10);
  uStack_6 = (undefined2)iVar2;
  if (0x7ffe < uVar4) {
    param_1[1] = 0;
    *param_1 = 0;
    param_1[2] = (-(uint)(uVar6 != 0) & 0x80000000) + 0x7fff8000;
    return;
  }
  *(undefined2 *)param_1 = uStack_a;
  *(uint *)((int)param_1 + 2) = CONCAT22(uStack_6,local_8);
  *(uint *)((int)param_1 + 6) = CONCAT22(uStack_2,local_4);
  *(ushort *)((int)param_1 + 10) = uVar4 | uVar6;
  return;
}



void __cdecl FUN_00411a60(int *param_1,uint param_2,int param_3)

{
  uint uVar1;
  int *piVar2;
  int iVar3;
  undefined2 local_c;
  undefined4 uStack_a;
  undefined2 uStack_6;
  int local_4;
  
  iVar3 = 0x415df8;
  if (param_2 != 0) {
    if ((int)param_2 < 0) {
      param_2 = -param_2;
      iVar3 = 0x415f58;
    }
    if (param_3 == 0) {
      *(undefined2 *)param_1 = 0;
    }
    while (param_2 != 0) {
      iVar3 = iVar3 + 0x54;
      uVar1 = param_2 & 7;
      param_2 = (int)param_2 >> 3;
      if (uVar1 != 0) {
        piVar2 = (int *)(iVar3 + uVar1 * 0xc);
        if (0x7fff < *(ushort *)(iVar3 + uVar1 * 0xc)) {
          local_c = (undefined2)*piVar2;
          uStack_a._0_2_ = (undefined2)((uint)*piVar2 >> 0x10);
          uStack_a._2_2_ = (undefined2)piVar2[1];
          uStack_6 = (undefined2)((uint)piVar2[1] >> 0x10);
          local_4 = piVar2[2];
          uStack_a = CONCAT22(uStack_a._2_2_,(undefined2)uStack_a) + -1;
          piVar2 = (int *)&local_c;
        }
        FUN_004117a0(param_1,piVar2);
      }
    }
  }
  return;
}



void RtlUnwind(PVOID TargetFrame,PVOID TargetIp,PEXCEPTION_RECORD ExceptionRecord,PVOID ReturnValue)

{
                    // WARNING: Could not recover jumptable at 0x00411c10. Too many branches
                    // WARNING: Treating indirect jump as call
  RtlUnwind(TargetFrame,TargetIp,ExceptionRecord,ReturnValue);
  return;
}


