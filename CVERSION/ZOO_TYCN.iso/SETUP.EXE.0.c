typedef unsigned char   undefined;

typedef unsigned long long    GUID;
typedef pointer32 ImageBaseOffset32;

typedef unsigned char    byte;
typedef unsigned int    dword;
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned short    ushort;
typedef unsigned short    wchar16;
typedef unsigned short    word;
typedef struct _s_HandlerType _s_HandlerType, *P_s_HandlerType;

typedef struct _s_HandlerType HandlerType;

typedef struct TypeDescriptor TypeDescriptor, *PTypeDescriptor;

typedef int ptrdiff_t;

struct TypeDescriptor {
    void * pVFTable;
    void * spare;
    char name[0];
};

struct _s_HandlerType {
    uint adjectives;
    struct TypeDescriptor * pType;
    ptrdiff_t dispCatchObj;
    void * addressOfHandler;
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

typedef struct _s_TryBlockMapEntry _s_TryBlockMapEntry, *P_s_TryBlockMapEntry;

typedef int __ehstate_t;

struct _s_TryBlockMapEntry {
    __ehstate_t tryLow;
    __ehstate_t tryHigh;
    __ehstate_t catchHigh;
    int nCatches;
    HandlerType * pHandlerArray;
};

typedef struct _s_TryBlockMapEntry TryBlockMapEntry;

typedef struct _s_UnwindMapEntry _s_UnwindMapEntry, *P_s_UnwindMapEntry;

struct _s_UnwindMapEntry {
    __ehstate_t toState;
    void (* action)(void);
};

typedef struct _s_UnwindMapEntry UnwindMapEntry;

typedef struct CLIENT_ID CLIENT_ID, *PCLIENT_ID;

struct CLIENT_ID {
    void * UniqueProcess;
    void * UniqueThread;
};

typedef struct _s_FuncInfo _s_FuncInfo, *P_s_FuncInfo;

typedef struct _s_FuncInfo FuncInfo;

struct _s_FuncInfo {
    uint magicNumber_and_bbtFlags;
    __ehstate_t maxState;
    UnwindMapEntry * pUnwindMap;
    uint nTryBlocks;
    TryBlockMapEntry * pTryBlockMap;
    uint nIPMapEntries;
    void * pIPToStateMap;
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

typedef struct StringInfo StringInfo, *PStringInfo;

struct StringInfo {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct IMAGE_RESOURCE_DIR_STRING_U_22 IMAGE_RESOURCE_DIR_STRING_U_22, *PIMAGE_RESOURCE_DIR_STRING_U_22;

struct IMAGE_RESOURCE_DIR_STRING_U_22 {
    word Length;
    wchar16 NameString[11];
};

typedef struct IMAGE_RESOURCE_DIR_STRING_U_24 IMAGE_RESOURCE_DIR_STRING_U_24, *PIMAGE_RESOURCE_DIR_STRING_U_24;

struct IMAGE_RESOURCE_DIR_STRING_U_24 {
    word Length;
    wchar16 NameString[12];
};

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




// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __fastcall FUN_00401d70(undefined4 *param_1)

{
  *param_1 = &UNK_0045d578;
  _DAT_0046e440 = 0;
  FUN_00433fa0();
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_00403da0(int param_1)

{
  uint uVar1;
  int iVar2;
  
  if ((*(int *)(param_1 + 8) < 2) || (3 < *(int *)(param_1 + 8))) {
    if (_DAT_0046e9c8 == 1) {
      FUN_0043bec0(0x500,0);
      return 10000;
    }
    if (_DAT_0046e9c8 != 2) {
      _DAT_0046e8fc = 1;
      if ((_DAT_004721a8 == 0) && (_DAT_004734d0 == 0)) {
        FUN_00406de0(5,param_1);
        WaitForSingleObject(_DAT_00475ba0,0xffffffff);
      }
      ResetEvent(_DAT_00475ba0);
      iVar2 = 10000;
      if (_DAT_004721a8 == 0) {
        iVar2 = _DAT_00469eb8;
      }
      uVar1 = FUN_0040d140();
      if ((uVar1 & 4) != 0) {
        _DAT_00471fcc = (uint)(iVar2 != 10000);
      }
      return iVar2;
    }
  }
  return 0x2714;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_00403e50(int param_1)

{
  int iVar1;
  
  if (((*(int *)(param_1 + 8) != 2) && (*(int *)(param_1 + 8) != 3)) && (_DAT_0046e9c8 != 1)) {
    _DAT_0046e8fc = 0;
    if ((_DAT_004721a8 == 0) && (_DAT_004734d0 == 0)) {
      FUN_00406de0(5,param_1);
      WaitForSingleObject(_DAT_00475ba0,0xffffffff);
    }
    ResetEvent(_DAT_00475ba0);
    iVar1 = 10000;
    if (_DAT_004721a8 == 0) {
      iVar1 = _DAT_00469eb8;
    }
    _DAT_0046e9c8 = (iVar1 != 10000) + 1;
    _DAT_00471fcc = (uint)(iVar1 != 10000);
    return iVar1;
  }
  _DAT_00471fcc = 0;
  return 0x2714;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_004048c0(int param_1)

{
  bool bVar1;
  char cVar2;
  int iVar3;
  char *pcVar4;
  char cVar5;
  undefined4 *puVar6;
  undefined8 uVar7;
  undefined4 uStack_110;
  undefined4 uStack_108;
  char acStack_104 [260];
  
  bVar1 = false;
  _DAT_0046ea9c = param_1;
  uStack_110._1_3_ = (undefined3)((uint)_DAT_00463268 >> 8);
  uStack_110 = CONCAT31(uStack_110._1_3_,DAT_004721e8);
  uVar7 = 0;
  puVar6 = (undefined4 *)0x46321c;
  do {
    uStack_108 = (undefined4)((ulonglong)uVar7 >> 0x20);
    if (0x463228 < (int)puVar6) break;
    FUN_0040e750(_DAT_004721c0,*puVar6,acStack_104,0x104);
    iVar3 = FUN_0044bf1a((int)acStack_104[0]);
    if (iVar3 == 0x44) {
      bVar1 = true;
      pcVar4 = (char *)CharNextA(acStack_104);
    }
    else {
      pcVar4 = acStack_104;
    }
    uVar7 = FUN_0044bac4(pcVar4);
    puVar6 = puVar6 + 1;
  } while (!bVar1);
  uStack_108 = (undefined4)((ulonglong)uVar7 >> 0x20);
  _DAT_0046eaa0 = FUN_00404c10();
  *(undefined4 *)(param_1 + 0xc) = _DAT_0046eaa0;
  FUN_00415b70((int)uVar7,uStack_108,0,param_1);
  cVar2 = (char)uStack_110;
  if ((_DAT_00473afc <= _DAT_00473af4) &&
     ((_DAT_00473afc < _DAT_00473af4 || (_DAT_00473af8 < _DAT_00473af0)))) {
    bVar1 = false;
    cVar5 = (char)uStack_110;
    if (_DAT_004734c4 != 0) goto LAB_00404a4d;
    while (!bVar1) {
      if (cVar5 == 'Z') {
        cVar5 = 'A';
      }
      else if (cVar5 == 'z') {
        cVar5 = 'a';
      }
      else {
        cVar5 = cVar5 + '\x01';
      }
      if (cVar2 == cVar5) goto LAB_00404a4d;
      uStack_110 = CONCAT31(uStack_110._1_3_,cVar5);
      iVar3 = FUN_0041bca0(&uStack_110);
      if (iVar3 == 3) {
        DAT_004721e8 = cVar5;
        FUN_00415b70((int)uVar7,uStack_108,0,param_1);
        if ((_DAT_00473afc < _DAT_00473af4) ||
           ((_DAT_00473afc <= _DAT_00473af4 && (_DAT_00473af8 < _DAT_00473af0)))) {
          bVar1 = false;
        }
        else {
          bVar1 = true;
        }
      }
    }
  }
  FUN_00406de0(2,0);
  WaitForSingleObject(_DAT_00475ba0,0xffffffff);
LAB_00404a4d:
  ResetEvent(_DAT_00475ba0);
  return _DAT_00469eb8;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_00404c10(void)

{
  uint uVar1;
  int iVar2;
  undefined auStack_208 [260];
  undefined auStack_104 [260];
  
  uVar1 = FUN_0040d140();
  if (((uVar1 & 4) != 0) || (_DAT_004721e0 != 0)) {
    return 0;
  }
  if (_DAT_004721d8 == 0) {
    FUN_0040e750(_DAT_004721c0,0x7d9,auStack_104,0x104);
    FUN_0040e750(_DAT_004721c0,0x7e5,auStack_208,0x104);
    iVar2 = FUN_0041c750(auStack_104,auStack_208);
    if (iVar2 == 2) {
      return 0;
    }
    if (iVar2 == 3) {
      return 0;
    }
  }
  return 1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __fastcall FUN_00404d20(undefined4 *param_1)

{
  *param_1 = &UNK_0045d68c;
  if (_DAT_0046eaa4 != 0) {
    KillTimer(_DAT_004721c8,_DAT_0046eaa4);
  }
  FUN_00433fa0();
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_00405750(int param_1)

{
  short sVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  
  if (_DAT_004737a8 != 7) {
    if ((_DAT_004706d8 == 0) && (*(int *)(param_1 + 0x220) == 0)) {
      _DAT_0046f9f0 = 0;
      _DAT_0046f9e8 = 0;
      _DAT_0046eebc = 0;
      _DAT_0046eeb4 = 0;
      _DAT_0046eec8 = 0;
      FUN_00406de0(7,0);
      WaitForSingleObject(_DAT_00475ba0,0xffffffff);
      ResetEvent(_DAT_00475ba0);
      _DAT_0046eec0 = 0;
      if (_DAT_0046efdc != (int *)0x0) {
        _DAT_0046eaa4 = SetTimer(_DAT_004721c8,1,3000,0);
      }
      iVar4 = 0;
      do {
        iVar3 = *(int *)(iVar4 * 4 + 0x46e498);
        if (iVar3 != 0) {
          KillTimer(_DAT_004721c8,iVar3);
          *(undefined4 *)(iVar4 * 4 + 0x46e498) = 0;
        }
        if (*(int *)(iVar4 * 4 + 0x46e4d8) != 0) {
          uVar2 = SetTimer(_DAT_004721c8,iVar4 + 2,*(undefined4 *)(iVar4 * 4 + 0x46e458),
                           &UNK_00401d10);
          *(undefined4 *)(iVar4 * 4 + 0x46e498) = uVar2;
        }
        iVar4 = iVar4 + 1;
      } while (iVar4 < 0x10);
      _DAT_004706d8 = 1;
      _DAT_0046eec4 = 0;
      FUN_0043b030(0x46f9f4,1,1);
    }
    WaitForSingleObject(_DAT_00475bdc,0xffffffff);
    if ((_DAT_00475ba8 == 0) && (*(int *)(param_1 + 0x224) == 0)) {
      iVar4 = param_1 + 0x11c;
      iVar3 = FUN_0040d4c0(iVar4);
      if (iVar3 != 0) {
        iVar4 = CharNextA(iVar3);
      }
      lstrcpyA(0x46f3e0,iVar4);
      sVar1 = FUN_0044c058();
      _DAT_0046eebc = (int)sVar1;
      if (99 < sVar1) {
        _DAT_0046eebc = 100;
      }
      if (_DAT_0046f9e8 < _DAT_0046eebc) {
        WaitForSingleObject(_DAT_00475bdc,0xffffffff);
        if (_DAT_0046efd8 != (int *)0x0) {
          (**(code **)(*_DAT_0046efd8 + 0x20))(_DAT_0046eebc);
        }
        _DAT_0046f9e8 = _DAT_0046eebc;
      }
      if (((_DAT_0046efdc != (int *)0x0) &&
          (iVar4 = (**(code **)(_DAT_0046efdc[0x29c] + 4))(),
          (int)(100 / (longlong)iVar4) + _DAT_0046f9f0 <= _DAT_0046eebc)) &&
         (iVar4 = (**(code **)(_DAT_0046efdc[0x29c] + 4))(), _DAT_0046eeb4 < iVar4 + -1)) {
        while (_DAT_0046eec0 == 0) {
          Sleep(0);
          FUN_0040d420();
        }
        WaitForSingleObject(_DAT_00475bdc,0xffffffff);
        FUN_0043b030(_DAT_0046eeb4 * 100 + 0x46fa58,1,0);
        (**(code **)(*_DAT_0046efdc + 0x24))();
        _DAT_0046eeb4 = _DAT_0046eeb4 + 1;
        _DAT_0046eec0 = 0;
        _DAT_0046eaa4 = SetTimer(_DAT_004721c8,1,3000,0);
        _DAT_0046f9f0 = _DAT_0046eebc;
      }
      WaitForSingleObject(_DAT_00475bdc,0xffffffff);
      _DAT_0046eec4 = 1;
    }
    _DAT_00469eb8 = (_DAT_00475ba8 != 0) + 10000;
  }
  if ((*(int *)(param_1 + 0x220) != 0) && (_DAT_004706d8 != 0)) {
    if (_DAT_0046efd4 != 0) {
      *(undefined4 *)(_DAT_0046efd4 + 0x2c0) = 0;
    }
    _DAT_004706d8 = 0;
    lstrcpyA(0x46eecc,0x46333c);
    FUN_0040e750(_DAT_004721c0,(-(uint)(*(int *)(param_1 + 0x224) != 0) & 0xffffff9a) + 0x509,
                 0x46f3e0,0x104);
    if ((*(int *)(param_1 + 0x224) == 0) && (_DAT_0046eebc = 100, *(int *)(param_1 + 0x224) == 0)) {
      if (_DAT_0046efdc != (int *)0x0) {
        (**(code **)(_DAT_0046efdc[0x29c] + 0x14))();
      }
      if (_DAT_0046efd8 != (int *)0x0) {
        (**(code **)(*_DAT_0046efd8 + 0x20))(100);
      }
    }
    _DAT_0046eec4 = 1;
    Sleep(0xfa);
    iVar4 = *(int *)(param_1 + 0x224);
    while (((iVar4 == 0 && (_DAT_0046efdc != (int *)0x0)) && (_DAT_0046eec0 == 0))) {
      Sleep(0);
      FUN_0040d420();
      iVar4 = *(int *)(param_1 + 0x224);
    }
    FUN_0043b030(0,0,0);
  }
  return _DAT_00469eb8;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 * __fastcall FUN_00405cb0(undefined4 *param_1)

{
  param_1[5] = 0;
  param_1[6] = 0;
  param_1[7] = 0;
  param_1[8] = 0;
  param_1[9] = 0;
  param_1[10] = 0;
  param_1[0xb] = 0;
  param_1[0xc] = 0;
  param_1[1] = 0;
  _DAT_00469f74 = _DAT_00469f74 + 1;
  param_1[2] = _DAT_00469f74;
  param_1[3] = 0;
  param_1[4] = 0;
  SetRectEmpty(param_1 + 5);
  SetRectEmpty(param_1 + 9);
  param_1[0xd] = 0;
  param_1[0xe] = 0;
  param_1[0xf] = 0;
  param_1[0x10] = 0;
  *param_1 = 0;
  *(undefined *)(param_1 + 0x11) = 0;
  return param_1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_00405d40(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  bool bVar1;
  ushort uVar2;
  ushort uVar3;
  int *piVar4;
  int iVar5;
  int iVar6;
  undefined4 *puVar7;
  undefined4 *puVar8;
  undefined4 auStack_278 [30];
  undefined4 uStack_200;
  undefined *puStack_1fc;
  undefined4 *puStack_1f8;
  uint uStack_1f4;
  undefined *puStack_1f0;
  undefined *puStack_1ec;
  undefined *puStack_1e8;
  undefined4 *puStack_1e4;
  undefined *puStack_1e0;
  undefined *puStack_1dc;
  undefined auStack_1c8 [4];
  undefined auStack_1c4 [16];
  undefined4 auStack_1b4 [4];
  undefined4 uStack_1a4;
  undefined4 uStack_1a0;
  undefined4 uStack_19c;
  undefined4 uStack_198;
  undefined4 uStack_194;
  undefined4 uStack_190;
  undefined4 uStack_18c;
  undefined4 uStack_184;
  undefined4 uStack_178;
  undefined4 uStack_174;
  undefined4 uStack_170;
  undefined4 uStack_16c;
  undefined4 uStack_168;
  undefined4 uStack_164;
  undefined4 uStack_160;
  undefined4 uStack_15c;
  undefined4 uStack_158;
  undefined4 uStack_154;
  undefined4 uStack_150;
  undefined4 uStack_14c;
  code *pcStack_148;
  undefined4 uStack_140;
  undefined4 uStack_13c;
  undefined4 uStack_138;
  undefined2 uStack_11c;
  undefined4 auStack_118 [3];
  undefined auStack_10c [4];
  undefined uStack_108;
  char cStack_107;
  undefined uStack_106;
  undefined uStack_105;
  
  puStack_1dc = (undefined *)0xa8;
  bVar1 = true;
  puStack_1e0 = (undefined *)0x405d59;
  piVar4 = (int *)FUN_0044ba20();
  if (piVar4 == (int *)0x0) {
    piVar4 = (int *)0x0;
  }
  else {
    puStack_1dc = (undefined *)0x405d6b;
    FUN_0043b1e0();
    *piVar4 = (int)&UNK_0045d6ec;
  }
  puVar7 = auStack_1b4;
  for (iVar5 = 0x28; iVar5 != 0; iVar5 = iVar5 + -1) {
    *puVar7 = 0;
    puVar7 = puVar7 + 1;
  }
  uStack_168 = 1;
  uStack_164 = 1;
  auStack_1b4[1] = param_3;
  uStack_19c = 0xffff;
  uStack_184 = 0x800a;
  uStack_154 = 0xff00ff;
  auStack_118[0] = 0;
  uStack_11c = 0xe;
  uStack_140 = 0;
  uStack_13c = 0;
  uStack_16c = 0;
  auStack_1b4[0] = 0x463354;
  auStack_1b4[2] = 0x142;
  auStack_1b4[3] = 8;
  uStack_1a4 = 0;
  uStack_1a0 = 0;
  uStack_194 = 9;
  uStack_198 = 9;
  uStack_190 = 0x48d;
  uStack_18c = 0x48c;
  uStack_138 = 0x19;
  uStack_174 = param_1;
  uStack_160 = 0;
  uStack_15c = 0x131b2c;
  uStack_158 = 0xffffffff;
  uStack_150 = 0x427b;
  uStack_14c = 0x8080ff;
  uStack_170 = 0xf;
  uStack_178 = 0xfe;
  pcStack_148 = _HotsetupCallback__YG_AW4EBURETCODE__PAX_Z;
  _DAT_00470bf4 = piVar4;
  if (piVar4 != (int *)0x0) {
    iVar5 = *piVar4;
    puVar7 = auStack_1b4;
    puVar8 = auStack_278;
    for (iVar6 = 0x28; iVar6 != 0; iVar6 = iVar6 + -1) {
      *puVar8 = *puVar7;
      puVar7 = puVar7 + 1;
      puVar8 = puVar8 + 1;
    }
    iVar5 = (**(code **)(iVar5 + 0x28))();
    if (iVar5 != 0) {
      puStack_1dc = &UNK_004061b0;
      puStack_1e0 = (undefined *)0x405eb4;
      FUN_00442f70();
      puStack_1e0 = &UNK_004060e0;
      puStack_1e4 = (undefined4 *)0x405ebe;
      FUN_00441e40();
      puStack_1e4 = (undefined4 *)&UNK_004063b0;
      puStack_1e8 = (undefined *)0x405ec8;
      FUN_00441110();
      puStack_1ec = auStack_1c4;
      puStack_1e8 = (undefined *)0x10;
      puStack_1f0 = (undefined *)0x7ee;
      uStack_1f4 = _DAT_004721c0;
      puStack_1f8 = (undefined4 *)0x405ee0;
      FUN_0040e750();
      puStack_1fc = auStack_1c4;
      puStack_1f8 = (undefined4 *)0x10;
      uStack_200 = 0x405eec;
      FUN_0040dc60();
      puStack_1dc = auStack_1c4;
      puStack_1e0 = (undefined *)0x405efc;
      iVar5 = lstrlenA();
      if (iVar5 != 0) {
        puStack_1e4 = (undefined4 *)&uStack_108;
        puStack_1e0 = (undefined *)0x463344;
        puStack_1e8 = (undefined *)0x405f17;
        lstrcpyA();
        puStack_1e4 = (undefined4 *)&uStack_108;
        puStack_1e0 = (undefined *)0x104;
        puStack_1e8 = (undefined *)0x405f29;
        FUN_0040dc60();
        puStack_1e0 = &uStack_108;
        puStack_1e4 = (undefined4 *)0x405f36;
        iVar5 = lstrlenA();
        if ((1 < iVar5) && (cStack_107 == ':')) {
          puStack_1e0 = (undefined *)0x0;
          puStack_1e8 = &stack0xfffffe34;
          puStack_1e4 = (undefined4 *)0x0;
          puStack_1ec = &stack0xfffffe34;
          puStack_1f0 = (undefined *)0x0;
          puStack_1f8 = auStack_118;
          uStack_1f4 = 0x10;
          puStack_1fc = &uStack_108;
          uStack_106 = 0x5c;
          uStack_105 = 0;
          uStack_200 = 0x405f81;
          iVar5 = GetVolumeInformationA();
          if (iVar5 != 0) {
            puStack_1e0 = auStack_1c8;
            puStack_1e4 = auStack_118;
            puStack_1e8 = (undefined *)0x405f98;
            iVar5 = lstrcmpiA();
            if (iVar5 != 0) {
              puStack_1e4 = (undefined4 *)&uStack_108;
              puStack_1e0 = (undefined *)0x104;
              puStack_1e8 = (undefined *)0x7d2;
              puStack_1ec = (undefined *)_DAT_004721c0;
              bVar1 = false;
              puStack_1f0 = (undefined *)0x405fbb;
              FUN_0040e750();
              puStack_1f0 = &uStack_108;
              uStack_1f4 = 0x405fc8;
              iVar5 = FUN_00410890();
              uStack_1f4 = (uint)(iVar5 == 0);
              puStack_1f8 = (undefined4 *)0x405fd3;
              iVar5 = FUN_004135e0();
              if (iVar5 == 0) {
                puStack_1e0 = (undefined *)0x7ef;
                puStack_1e4 = (undefined4 *)0x30;
                puStack_1e8 = (undefined *)_DAT_004721c8;
                _DAT_00472148 = 0;
                puStack_1ec = (undefined *)0x405ff3;
                FUN_0040d270();
              }
              else {
                bVar1 = true;
              }
            }
          }
        }
      }
      puStack_1e4 = (undefined4 *)&uStack_108;
      puStack_1e0 = (undefined *)0x104;
      puStack_1e8 = (undefined *)0x14f;
      puStack_1ec = (undefined *)_DAT_004721c0;
      puStack_1f0 = (undefined *)0x40601b;
      FUN_0040e750();
      puStack_1e0 = &uStack_108;
      uVar2 = 0xff;
      puStack_1e4 = (undefined4 *)0x40602d;
      iVar5 = lstrlenA();
      if (iVar5 != 0) {
        puStack_1e4 = (undefined4 *)auStack_10c;
        puStack_1e8 = (undefined *)0x40603e;
        uVar2 = FUN_0044bab9();
      }
      puStack_1e4 = (undefined4 *)0x406048;
      uVar3 = FUN_0040d140();
      if ((uVar3 & uVar2) == 0) {
        puStack_1dc = (undefined *)0x4b4;
        puStack_1e0 = (undefined *)0x30;
        puStack_1e4 = (undefined4 *)_DAT_004721c8;
        _DAT_00472148 = 0;
        puStack_1e8 = (undefined *)0x406068;
        FUN_0040d270();
      }
      else if (bVar1) {
        puStack_1dc = (undefined *)0x40607c;
        FUN_0043b880();
      }
    }
    if (_DAT_00470bf4 != (int *)0x0) {
      puStack_1dc = (undefined *)0x1;
      puStack_1e0 = (undefined *)0x40608d;
      (**(code **)(*_DAT_00470bf4 + 0x24))();
    }
  }
  puStack_1dc = (undefined *)_DAT_00475bac;
  puStack_1e0 = (undefined *)0x406098;
  FUN_0041d290();
  if (_DAT_004721b4 != 0) {
    return 0xbc3;
  }
  if (_DAT_00475bac == 1) {
    puStack_1e0 = (undefined *)0x4060c0;
    FUN_00414760();
  }
  return 1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int _HotsetupCallback__YG_AW4EBURETCODE__PAX_Z(undefined4 *param_1)

{
  int iVar1;
  
                    // 0x6790  4  ?HotsetupCallback@@YG?AW4EBURETCODE@@PAX@Z
  switch(*param_1) {
  case 1:
    FUN_0043bec0(0x485,0);
    return 10000;
  case 2:
  case 0xb:
    if (*(char *)(param_1 + 1) != '\0') {
      FUN_0043bec0(0x4a2,0);
      return 10000;
    }
    iVar1 = FUN_00405750(param_1);
    return iVar1;
  case 3:
    FUN_0043bec0((-(uint)(*(char *)(param_1 + 1) != '\0') & 2) + 0x481,0);
    return 10000;
  case 4:
    return (-(uint)(_DAT_004721cc != 0x2712) & 2) + 0x2712;
  case 5:
    iVar1 = FUN_00407680(param_1);
    return iVar1;
  case 6:
    iVar1 = FUN_0040b650(param_1);
    return iVar1;
  case 7:
    iVar1 = param_1[3];
    if (iVar1 == 1) {
      iVar1 = FUN_00403e50(param_1);
      return iVar1;
    }
    if (iVar1 == 2) {
      FUN_0043bec0(0x4f1,0);
      return 10000;
    }
    if (iVar1 == 3) {
      FUN_0043bec0(0x501,0);
      return 10000;
    }
  case 0x1b:
    (**(code **)(*_DAT_00475bbc + 0x58))(param_1 + 2,0);
    return 10000;
  case 8:
    iVar1 = FUN_00406bc0(param_1);
    return iVar1;
  case 0xc:
    if ((*(char *)(param_1 + 1) != '\0') && (param_1[3] != 0)) {
      return (-(uint)(_DAT_0046e440 != 0) & 0xfffffffc) + 0x2714;
    }
    break;
  case 0xd:
    iVar1 = FUN_0040a030(param_1);
    return iVar1;
  case 0xe:
    return 0x2714;
  case 0xf:
    iVar1 = param_1[7];
    if ((iVar1 == 0x18a92) || (iVar1 == 0x9a2112)) {
      iVar1 = param_1[9];
      if ((0 < iVar1) && ((iVar1 < 3 && (param_1[5] != 0)))) {
        ShowWindow(_DAT_004721c8,(-(iVar1 != 1) & 3U) + 6);
      }
    }
    else if (((iVar1 == 0x1627f43) && (param_1[8] != 0)) && (param_1[9] == 2)) {
      FUN_004146b0();
      return 10000;
    }
    break;
  case 0x10:
    iVar1 = FUN_00403da0(param_1);
    return iVar1;
  case 0x11:
    iVar1 = FUN_004048c0(param_1);
    return iVar1;
  case 0x15:
    FUN_004100e0(0);
    return 10000;
  case 0x16:
  case 0x17:
    _DAT_00470ae0 = 1;
    _DAT_00470ae4 = 1;
    return 10000;
  case 0x18:
    _DAT_0046e440 = 0;
    return 10000;
  case 0x19:
    if (_DAT_004721cc == 10000) {
      FUN_004100e0(1);
      return 10000;
    }
  }
  return 10000;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_00406bc0(int param_1)

{
  uint uVar1;
  
  if (*(char *)(param_1 + 4) == '\x01') {
    FUN_0043bec0(0x484,0);
  }
  else {
    FUN_0043bec0(0x480,0);
    uVar1 = *(uint *)(param_1 + 8);
    if ((uVar1 & 2) != 0) {
      if ((uVar1 & 1) == 0) {
        return (-(uint)(_DAT_00463340 != 0) & 0xfffffffc) + 0x2714;
      }
      if (_DAT_00463340 == 0) {
        *(uint *)(param_1 + 8) = uVar1 & 0xfffffffd;
        return 10000;
      }
    }
  }
  return 10000;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00406c30(void)

{
  undefined auStack_208 [260];
  undefined auStack_104 [260];
  
  lstrcpyA(&DAT_004706e0,0x472b94);
  FUN_0040f8a0(&DAT_004706e0);
  FUN_0040e750(_DAT_004721c0,0x24,auStack_208,0x104);
  lstrcatA(&DAT_004706e0,auStack_208);
  FUN_0040d100(auStack_104,0x104);
  FUN_0041de30(0x80000002,&DAT_004706e0,auStack_104,1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void LaunchGame(undefined4 param_1)

{
  int iVar1;
  
                    // 0x6cb0  5  LaunchGame
  iVar1 = FUN_004146e0();
  if (iVar1 != 0) {
    iVar1 = FUN_0040d270(_DAT_004721c8,0x44,0x48d);
    if (iVar1 != 6) {
      return;
    }
    FUN_0043bec0(0x49f,0);
    _DAT_00475bac = 1;
    PostMessageA(_DAT_004721c8,0x800b,0,0);
    return;
  }
  iVar1 = FUN_0040ebe0();
  if ((iVar1 != 0) && (iVar1 = FUN_0040c550(), iVar1 == 0)) {
    iVar1 = FUN_00410810();
    if ((iVar1 != 0) || (iVar1 = FUN_00410440(0x62,0), iVar1 != 0)) {
      iVar1 = FUN_00410c50();
      if (iVar1 != 0) {
        return;
      }
      FUN_00406de0(10,param_1);
      FUN_00410ca0();
      return;
    }
    iVar1 = FUN_0040c5e0();
    if (iVar1 == 0) goto LAB_00406dd1;
  }
  iVar1 = FUN_00410440(0x7de,1);
  if ((iVar1 == 0) || (iVar1 = FUN_00410640(), iVar1 != 0)) {
    FUN_0043bec0(0x49b,0);
    iVar1 = FUN_00413d00(0x7e7,0x7d3);
    if (iVar1 == 0) {
      FUN_0043bff0();
      return;
    }
    FUN_00406c30();
    PostMessageA(_DAT_004721c8,0x800b,0,0);
    return;
  }
LAB_00406dd1:
  FUN_0043bff0();
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00406de0(undefined4 param_1,undefined4 param_2)

{
  undefined4 *puVar1;
  int iVar2;
  undefined4 *puVar3;
  
  puVar1 = (undefined4 *)FUN_0044ba20(0x1c);
  if (puVar1 == (undefined4 *)0x0) {
    puVar1 = (undefined4 *)0x0;
  }
  else {
    puVar3 = puVar1;
    for (iVar2 = 7; iVar2 != 0; iVar2 = iVar2 + -1) {
      *puVar3 = 0;
      puVar3 = puVar3 + 1;
    }
  }
  *puVar1 = 0;
  puVar1[2] = param_1;
  puVar1[6] = param_2;
  PostMessageA(_DAT_004721c8,0x806c,0,puVar1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00406e30(ushort param_1)

{
  int iVar1;
  int iVar2;
  
  if (param_1 == 0x812e) {
    ShowWindow(_DAT_004721c8,6);
  }
  else if ((0x812e < param_1) && (param_1 < 0x8132)) {
    if (param_1 != 0x8131) {
      SendMessageA(_DAT_004721c8,0x806a,0,0);
    }
    iVar1 = FUN_0043c120();
    if (iVar1 == 0) {
      iVar1 = _DAT_00470ae8[0x22];
      iVar2 = GetFocus();
      (**(code **)(*_DAT_00470ae8 + 0x20))();
      (**(code **)(*_DAT_004706dc + 0x1c))(1);
      if (iVar1 == iVar2) {
        SetFocus(_DAT_004706dc[0x22]);
        return;
      }
    }
    else {
      iVar1 = _DAT_004706dc[0x22];
      iVar2 = GetFocus();
      (**(code **)(*_DAT_00470ae8 + 0x1c))(1);
      (**(code **)(*_DAT_004706dc + 0x20))();
      if (iVar1 == iVar2) {
        SetFocus(_DAT_00470ae8[0x22]);
        return;
      }
    }
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_00407680(int param_1)

{
  FUN_00406de0(3,*(undefined4 *)(param_1 + 8));
  WaitForSingleObject(_DAT_00475ba0,0xffffffff);
  ResetEvent(_DAT_00475ba0);
  return _DAT_00469eb8;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0040a030(int param_1)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  undefined *puVar4;
  undefined8 uVar5;
  
  iVar2 = 0;
  _DAT_00471088 = param_1;
  if ((_DAT_00463464 != 0) || (_DAT_004721a8 != 0)) {
    _DAT_00463464 = 0;
    *(undefined4 *)(param_1 + 8) = 0;
    *(undefined4 *)(param_1 + 0xc) = 0;
    piVar3 = (int *)0x4633f4;
    do {
      puVar4 = &DAT_004706e0;
      FUN_0040e750(_DAT_004721c0,piVar3[1],&DAT_004706e0,0x400);
      if ((DAT_004706e0 == 'D') || (DAT_004706e0 == 'd')) {
        *piVar3 = 1;
        puVar4 = (undefined *)CharNextA(&DAT_004706e0);
      }
      uVar5 = FUN_0044bac4(puVar4);
      *(undefined8 *)(piVar3 + -9) = uVar5;
      if ((piVar3[-9] == 0) && ((int)((ulonglong)uVar5 >> 0x20) == 0)) {
        iVar1 = 0;
      }
      else {
        iVar1 = 1;
      }
      piVar3[-1] = iVar1;
      if (*piVar3 != 0) {
        *(int *)(_DAT_00471088 + 8) = piVar3[-9];
        *(int *)(_DAT_00471088 + 0xc) = piVar3[-8];
      }
      iVar1 = FUN_0044ba2e(&DAT_004706e0);
      if (iVar1 == -1) {
        *(undefined2 *)(piVar3 + -7) = 0x80cb;
        _DAT_00471e14 = 1;
        _DAT_004633c8 = iVar2;
      }
      piVar3 = piVar3 + 0xc;
      iVar2 = iVar2 + 1;
    } while ((int)piVar3 < 0x463455);
  }
  **(undefined4 **)(param_1 + 0x14) = &UNK_0040a5e0;
  if (_DAT_004721a8 == 0) {
    FUN_00406de0(4,param_1);
    if (_DAT_004721cc != 0x2713) {
      FUN_0040a180();
    }
    WaitForSingleObject(_DAT_00475ba0,0xffffffff);
  }
  ResetEvent(_DAT_00475ba0);
  return _DAT_00469eb8;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0040a180(void)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  undefined8 *puVar6;
  undefined8 uVar7;
  undefined auStack_8 [4];
  undefined4 uStack_4;
  
  uStack_4 = _DAT_00463268;
  if (_DAT_00471e20 != 0) {
    do {
      Sleep(0xfa);
    } while (_DAT_00471e20 != 0);
  }
  _DAT_00471e20 = 1;
  uStack_4 = CONCAT31(uStack_4._1_3_,DAT_004721e8);
  uVar3 = FUN_0041be50();
  if ((1 << ((char)uStack_4 + 0x9fU & 0x1f) & uVar3) != 0) {
    iVar4 = FUN_0041bdc0(&uStack_4,auStack_8,auStack_8,auStack_8,auStack_8);
    if (iVar4 != 0) {
      iVar4 = 0;
      puVar6 = (undefined8 *)0x4633d0;
      do {
        if (*(int *)(puVar6 + 4) != 0) {
          if ((_DAT_004633c8 == iVar4) && (_DAT_00471e14 != 0)) {
            uVar7 = FUN_0040ade0();
            *puVar6 = uVar7;
          }
          FUN_00415b70(*(undefined4 *)puVar6,*(undefined4 *)((int)puVar6 + 4),0,0);
          iVar1 = *(int *)(_DAT_00471088 + 0x10);
          if (*(char *)(iVar1 + 0x28) == '\0') {
            uVar3 = 0;
            iVar5 = 0;
          }
          else {
            uVar3 = *(uint *)(iVar1 + 0x30);
            iVar5 = *(int *)(iVar1 + 0x34);
          }
          uVar2 = *(uint *)(iVar1 + 8);
          iVar1 = *(int *)(iVar1 + 0xc);
          *(uint *)(puVar6 + 3) = uVar2 + uVar3;
          *(uint *)((int)puVar6 + 0x1c) = iVar1 + iVar5 + (uint)CARRY4(uVar2,uVar3);
        }
        puVar6 = puVar6 + 6;
        iVar4 = iVar4 + 1;
      } while ((int)puVar6 < 0x463431);
      _DAT_00471b6c = 1;
      _DAT_00463460 = 1;
    }
    FUN_0043bff0();
  }
  _DAT_00471e20 = 0;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined8 FUN_0040ade0(void)

{
  uint uVar1;
  int iVar2;
  uint *puVar3;
  int iVar4;
  int *piVar5;
  int iStack_14;
  uint *puStack_10;
  int *piStack_c;
  uint uStack_4;
  
  uVar1 = 0;
  iVar4 = 0;
  uStack_4 = 0;
  if (_DAT_00471e24 < 1) {
    return 0;
  }
  iStack_14 = 0;
  piStack_c = (int *)0x470cc8;
  puStack_10 = (uint *)0x470e08;
  do {
    iVar2 = *(int *)(iVar4 * 4 + 0x471afc);
    if (iVar2 == 1) {
      iVar2 = *(int *)(iVar4 * 4 + 0x471b10) + iStack_14;
      uVar1 = uVar1 | *(uint *)(iVar2 * 8 + 0x470e08);
      uStack_4 = uStack_4 | *(uint *)(iVar2 * 8 + 0x470e0c);
    }
    else if ((iVar2 == 2) &&
            (iVar2 = *(int *)(iVar4 * 4 + 0x471d08), puVar3 = puStack_10, piVar5 = piStack_c,
            0 < iVar2)) {
      do {
        if (*piVar5 != 0) {
          uVar1 = uVar1 | *puVar3;
          uStack_4 = uStack_4 | puVar3[1];
        }
        iVar2 = iVar2 + -1;
        puVar3 = puVar3 + 2;
        piVar5 = piVar5 + 1;
      } while (iVar2 != 0);
    }
    puStack_10 = puStack_10 + 0x20;
    iVar4 = iVar4 + 1;
    iStack_14 = iStack_14 + 0x10;
    piStack_c = piStack_c + 0x10;
  } while (iVar4 < _DAT_00471e24);
  return CONCAT44(uStack_4,uVar1);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0040b650(int param_1)

{
  if (*(int *)(param_1 + 0x1c) == 0) {
    return 10000;
  }
  FUN_00406de0(1,*(int *)(param_1 + 0x1c));
  WaitForSingleObject(_DAT_00475ba0,0xffffffff);
  ResetEvent(_DAT_00475ba0);
  return _DAT_00469eb8;
}



undefined4 FUN_0040c550(void)

{
  int iVar1;
  undefined auStack_104 [260];
  
  FUN_0040ebf0(0);
  iVar1 = FUN_00410740();
  if (iVar1 != 0) {
    return 1;
  }
  iVar1 = FUN_00410810();
  if (iVar1 == 0) {
    iVar1 = FUN_00410440(0x62,0);
    if (iVar1 == 0) {
      GetSystemDirectoryA(auStack_104,0x104);
      FUN_0040f8a0(auStack_104);
      lstrcatA(auStack_104,0x4637a4);
      iVar1 = FUN_0040e500(auStack_104,0x463798);
      FUN_0040ebf0(iVar1 == 0);
    }
  }
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

bool FUN_0040c5e0(void)

{
  undefined4 uVar1;
  int iVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  bool bVar5;
  undefined4 uStack_2b4;
  undefined uStack_2b0;
  undefined4 auStack_2ac [7];
  char acStack_290 [8];
  undefined auStack_288 [120];
  undefined auStack_210 [8];
  undefined auStack_208 [252];
  undefined auStack_10c [8];
  undefined auStack_104 [260];
  
  puVar3 = (undefined4 *)0x4637c0;
  puVar4 = auStack_2ac;
  for (iVar2 = 8; iVar2 != 0; iVar2 = iVar2 + -1) {
    *puVar4 = *puVar3;
    puVar3 = puVar3 + 1;
    puVar4 = puVar4 + 1;
  }
  *(undefined2 *)puVar4 = *(undefined2 *)puVar3;
  uStack_2b4 = _DAT_004637b8;
  uStack_2b0 = DAT_004637bc;
  bVar5 = true;
  iVar2 = FUN_00410c50();
  if (iVar2 == 0) {
    FUN_0040e750(_DAT_004721c0,0x7e2,auStack_104,0x104);
    FUN_0040e750(_DAT_004721c0,0x7e3,auStack_288,0x80);
    FUN_0040e750(_DAT_004721c0,0x7fe,auStack_208,0x104);
    FUN_0040dc60(auStack_208,0x104);
    FUN_0043bec0(0x517,0);
    uVar1 = _DAT_004721c8;
    iVar2 = FUN_00410c20(auStack_210,0x516,1,0,1,0,0,0,1,&uStack_2b4,&stack0xfffffd40);
    iVar2 = FUN_0040eef0(uVar1,auStack_10c,-(uint)(acStack_290[0] != '\0') & (uint)acStack_290,0,1,
                         0x9a2112,~-(uint)(iVar2 != 0) & (uint)auStack_210);
    bVar5 = iVar2 == 10000;
    if (iVar2 == 0x2711) {
      FUN_00410ca0();
    }
  }
  return bVar5;
}



bool FUN_0040d0e0(undefined4 param_1)

{
  int iVar1;
  
  iVar1 = FUN_0041bc20(param_1);
  return iVar1 != -1;
}



void FUN_0040d100(undefined4 param_1)

{
  int iVar1;
  char *pcVar2;
  
  lstrcpyA(param_1,&DAT_0047267c);
  iVar1 = FUN_0040d4c0(param_1);
  if ((iVar1 != 0) && (pcVar2 = (char *)CharNextA(iVar1), *pcVar2 == '\0')) {
    return;
  }
  lstrcatA(param_1,0x463be4);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

short FUN_0040d140(void)

{
  byte bVar1;
  uint uStack_94;
  uint uStack_90;
  uint uStack_8c;
  int iStack_88;
  
  if (_DAT_00473518 != 0) {
    return _DAT_00473516;
  }
  uStack_94 = 0x94;
  GetVersionExA(&uStack_94);
  if (iStack_88 != 1) {
    if (iStack_88 == 2) {
      if (uStack_94 == 4) {
        if (0x565 < uStack_8c) {
          _DAT_00473518 = 1;
          _DAT_00473516 = 4;
          return 4;
        }
        if (uStack_8c == 0x565) {
          bVar1 = FUN_0040e3e0();
          if (2 < bVar1) {
            _DAT_00473518 = 1;
            _DAT_00473516 = 4;
            return 4;
          }
        }
      }
      else if (4 < uStack_94) {
        _DAT_00473518 = 1;
        _DAT_00473516 = (-(ushort)(uStack_90 != 0) & 0x18) + 8;
        return _DAT_00473516;
      }
    }
    _DAT_00473518 = 1;
    return _DAT_00473516;
  }
  if (uStack_90 < 10) {
    _DAT_00473518 = 1;
    _DAT_00473516 = 1;
    return 1;
  }
  _DAT_00473518 = 1;
  _DAT_00473516 = (-(ushort)((ushort)uStack_8c < 3000) & 0xfff2) + 0x10;
  return _DAT_00473516;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0040d270(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  int iVar1;
  undefined4 *puVar2;
  undefined uStack_800;
  undefined4 uStack_7ff;
  
  uStack_800 = DAT_0046e83c;
  puVar2 = &uStack_7ff;
  for (iVar1 = 0x1ff; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  *(undefined2 *)puVar2 = 0;
  *(undefined *)((int)puVar2 + 2) = 0;
  FUN_0040e750(_DAT_004721c0,param_3,&uStack_800,0x800);
  FUN_0040d300(param_1,param_2,&uStack_800,&stack0x00000010);
  return;
}



void FUN_0040d2e0(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  FUN_0040d300(param_1,param_2,param_3,&stack0x00000010);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0040d300(int param_1,uint param_2,undefined4 param_3,undefined4 param_4)

{
  int iVar1;
  undefined4 uVar2;
  uint uVar3;
  undefined auStack_800 [2048];
  
  if (param_1 != 0) {
    SetWindowPos(param_1,0xfffffffe,0,0,0,0,0x13);
  }
  wvsprintfA(auStack_800,param_3,param_4);
  FUN_0040dc60(auStack_800,0x800);
  uVar3 = param_2 | (-(uint)(param_1 != 0) & 0xffffe000) + 0x2000;
  iVar1 = lstrlenA(auStack_800);
  if (iVar1 == 0) {
    switch(param_2 & 0xf) {
    case 0:
    case 1:
      return 1;
    case 2:
      return 3;
    case 3:
    case 4:
      return 6;
    case 5:
      return 4;
    default:
      return 0;
    }
  }
  if (_DAT_00472148 != (code *)0x0) {
    uVar2 = (*_DAT_00472148)(param_1,&stack0xfffff7fc,0x472fa4,uVar3);
    return uVar2;
  }
  uVar2 = MessageBoxA(param_1,&stack0xfffff7fc,0x472fa4,uVar3);
  return uVar2;
}



undefined4 FUN_0040d420(void)

{
  int iVar1;
  undefined4 uStack_1c;
  int iStack_18;
  undefined4 uStack_14;
  undefined4 uStack_10;
  
  iVar1 = PeekMessageA(&uStack_1c,0,0,0,1);
  while( true ) {
    if (iVar1 == 0) {
      Sleep(0);
      return 1;
    }
    if (((iStack_18 == 0x12) || (iStack_18 == 0x10)) || (iStack_18 == 2)) break;
    TranslateMessage(&uStack_1c);
    DispatchMessageA(&uStack_1c);
    iVar1 = PeekMessageA(&uStack_1c,0,0,0,1);
  }
  PostMessageA(uStack_1c,iStack_18,uStack_14,uStack_10);
  return 0;
}



char * FUN_0040d4c0(char *param_1)

{
  char cVar1;
  char *pcVar2;
  
  pcVar2 = (char *)0x0;
  cVar1 = *param_1;
  if (cVar1 == '\0') {
    return (char *)0x0;
  }
  do {
    if (cVar1 == '\\') {
      pcVar2 = param_1;
    }
    param_1 = (char *)CharNextA(param_1);
    cVar1 = *param_1;
  } while (cVar1 != '\0');
  return pcVar2;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0040d530(uint param_1,undefined4 param_2)

{
  int iVar1;
  undefined4 *puVar2;
  char *pcStack_118;
  undefined auStack_108 [4];
  char acStack_104 [4];
  char cStack_100;
  undefined4 uStack_ff;
  
  _DAT_00472148 = param_2;
  cStack_100 = DAT_0046e83c;
  puVar2 = &uStack_ff;
  for (iVar1 = 0x3f; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  *(undefined2 *)puVar2 = 0;
  pcStack_118 = (char *)0x472470;
  *(undefined *)((int)puVar2 + 2) = 0;
  lstrcpyA(&cStack_100);
  if (cStack_100 == '\0') {
    pcStack_118 = (char *)0x100;
    iVar1 = FUN_0040e750(_DAT_004721bc,0x182,&cStack_100);
    if (iVar1 == 0) {
      if (param_1 == 0x400) {
        pcStack_118 = (char *)0x40d5b9;
        param_1 = GetUserDefaultLCID();
      }
      pcStack_118 = (char *)0x4;
      GetLocaleInfoA(param_1,3,acStack_104);
      pcStack_118 = acStack_104;
      wsprintfA(&cStack_100,0x463c9c,0x463ca4);
    }
  }
  pcStack_118 = &cStack_100;
  iVar1 = FUN_0040d740();
  if (iVar1 == 0) {
    pcStack_118 = (char *)0x4;
    GetLocaleInfoA(param_1 & 0x3ff | 0x400,3,auStack_108);
    wsprintfA(&stack0xfffffef0,0x463c9c,0x463ca4,&pcStack_118);
    iVar1 = FUN_0040d740(&stack0xfffffef0);
    if (iVar1 == 0) {
      pcStack_118 = (char *)0x100;
      FUN_0040e750(_DAT_004721bc,0x182,&cStack_100);
      if (cStack_100 != '\0') {
        pcStack_118 = &cStack_100;
        iVar1 = FUN_0040d740();
        if (iVar1 != 0) goto LAB_0040d6bc;
      }
      pcStack_118 = (char *)0x463c8c;
      iVar1 = FUN_0040d740();
      if (iVar1 == 0) {
        if (_DAT_00463910 == 0) {
          return 0;
        }
        pcStack_118 = (char *)0x0;
        MessageBoxA(0,0x463c00,0x463ca4);
        _DAT_00463910 = 0;
        return 0;
      }
    }
  }
LAB_0040d6bc:
  pcStack_118 = (char *)0x463bf4;
  iVar1 = FindResourceA(_DAT_004721c0,0x463be8);
  if (iVar1 != 0) {
    _DAT_004721c4 = _DAT_004721c0;
    return 1;
  }
  pcStack_118 = (char *)0x463bf4;
  iVar1 = FindResourceA(_DAT_004721bc,0x463be8);
  if (iVar1 == 0) {
    pcStack_118 = (char *)0x6c;
    FUN_004109b0();
    return 0;
  }
  _DAT_004721c4 = _DAT_004721bc;
  return 1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

bool FUN_0040d740(int param_1)

{
  int iVar1;
  int iVar2;
  undefined *puVar3;
  undefined auStack_30c [244];
  undefined auStack_218 [8];
  undefined auStack_210 [252];
  undefined auStack_114 [4];
  undefined auStack_110 [272];
  
  if (param_1 != 0) {
    iVar1 = lstrlenA(param_1);
    if (0 < iVar1) {
      lstrcpyA(auStack_30c,0x463cb4);
      FUN_0040dc60(auStack_30c,0x104);
      FUN_0040f8a0(auStack_30c);
      lstrcatA(auStack_30c,param_1);
      iVar1 = FUN_0041aa10(auStack_30c);
      if (iVar1 == 0) {
        lstrcatA(auStack_30c,0x463cac);
      }
      FUN_0041bf00(auStack_30c,0x80);
      FUN_0041bce0(auStack_30c);
    }
  }
  iVar1 = lstrlenA(0x472470);
  if (iVar1 == 0) {
    lstrcpyA(&stack0xfffffcf0,0x463344);
    FUN_0040dc60(&stack0xfffffcf0,0x104);
    FUN_0040f8a0(&stack0xfffffcf0);
    lstrcatA(&stack0xfffffcf0,param_1);
  }
  else {
    lstrcpyA(&stack0xfffffcf0,param_1);
  }
  iVar1 = LoadLibraryA(param_1);
  if (iVar1 < 0x20) {
    return false;
  }
  _DAT_004721c0 = iVar1;
  FUN_0041bd80(iVar1,auStack_210,0x104);
  if (&stack0x00000000 != (undefined *)0x210) {
    iVar2 = lstrlenA(auStack_210);
    if (iVar2 != 0) {
      puVar3 = auStack_210;
      goto LAB_0040d87d;
    }
  }
  puVar3 = (undefined *)0x47351c;
LAB_0040d87d:
  lstrcpyA(&DAT_00472574,puVar3);
  FUN_0040dc60(&DAT_00472574,0x104);
  _DAT_00472678 = 1;
  lstrlenA(0x47351c);
  lstrcpyA(0x47351c,&DAT_00472574);
  iVar2 = FUN_00410440(0x7de,1);
  if (((iVar2 == 0) && (_DAT_004721a0 == 0)) && (_DAT_0047219c == 0)) {
    FUN_0040e750(iVar1,0x16f,auStack_110,0x104);
    iVar2 = lstrcmpiA(0x472784,auStack_110);
    if (iVar2 == 0) {
      iVar2 = FUN_00410440(0x7d7,1);
      _DAT_00472198 = (uint)(iVar2 == 0);
      _DAT_004721a0 = (uint)(iVar2 != 0);
      _DAT_0047219c = _DAT_00472198;
    }
  }
  if (_DAT_00472190 == 0) {
    return true;
  }
  FreeLibrary(iVar1);
  _DAT_004721c0 = 0;
  iVar1 = FUN_00410910(auStack_218,auStack_114,0x104);
  if (iVar1 == 0) {
    lstrcpyA(auStack_114,auStack_218);
  }
  auStack_218[0] = 0;
  FUN_004140f0(auStack_114,auStack_218,0);
  iVar1 = FUN_0041feb0(auStack_114,auStack_218,0);
  if (iVar1 != 0) {
    return false;
  }
  FUN_0041bf00(auStack_218,0x80);
  _DAT_004721c0 = LoadLibraryA(auStack_218);
  return 0x1f < _DAT_004721c0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0040da20(code *param_1)

{
  int iVar1;
  char *pcVar2;
  char **ppcVar3;
  char *pcStack_18;
  undefined4 uStack_14;
  undefined4 uStack_10;
  undefined4 uStack_c;
  undefined4 uStack_8;
  undefined *puStack_4;
  
  pcStack_18 = &DAT_0046e83c;
  uStack_14 = 0x463cfc;
  uStack_10 = 0x463ce8;
  uStack_c = 0x463cd4;
  uStack_8 = 0x463cc0;
  puStack_4 = &DAT_0046e83c;
  iVar1 = OleInitialize();
  if (iVar1 < 0) {
    FUN_0040d270(_DAT_004721c8,0x30);
    return;
  }
  iVar1 = LoadLibraryA(param_1);
  if (iVar1 == 0) goto LAB_0040dafd;
  ppcVar3 = (char **)&stack0xffffffd4;
  if ((char)param_1 != '\0') {
    ppcVar3 = &pcStack_18;
  }
  pcVar2 = *ppcVar3;
  if (*pcVar2 == '\0') {
    if (param_1 != (code *)0x0) goto LAB_0040daf2;
  }
  else {
    while (param_1 = (code *)GetProcAddress(iVar1,pcVar2), param_1 == (code *)0x0) {
      pcVar2 = ppcVar3[1];
      ppcVar3 = ppcVar3 + 1;
      if (*pcVar2 == '\0') {
        FreeLibrary(iVar1);
        OleUninitialize();
        return;
      }
    }
LAB_0040daf2:
    (*param_1)();
  }
  FreeLibrary(iVar1);
LAB_0040dafd:
  OleUninitialize();
  return;
}



void FUN_0040db10(int *param_1,undefined4 param_2)

{
  int iVar1;
  
  lstrcpyA(*param_1,param_2);
  iVar1 = lstrlenA(param_2);
  *param_1 = *param_1 + iVar1;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0040db40(undefined4 param_1,undefined4 param_2)

{
  int iVar1;
  undefined4 *puVar2;
  undefined uStack_1c;
  undefined4 auStack_1b [6];
  
  uStack_1c = DAT_0046e83c;
  puVar2 = auStack_1b;
  for (iVar1 = 6; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  FUN_0040e750(_DAT_004721c0,0x10,&uStack_1c,0x19);
  FUN_0041dcd0(0x80000002,0x463d60,&uStack_1c,&DAT_0046e83c,param_1,param_2);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0040dba0(undefined4 param_1,undefined4 param_2)

{
  int iVar1;
  undefined4 *puVar2;
  undefined uStack_1c;
  undefined4 auStack_1b [6];
  
  uStack_1c = DAT_0046e83c;
  puVar2 = auStack_1b;
  for (iVar1 = 6; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  FUN_0040e750(_DAT_004721c0,0xf,&uStack_1c,0x19);
  FUN_0041dcd0(0x80000002,0x463d60,&uStack_1c,&DAT_0046e83c,param_1,param_2);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0040dc60(void)

{
  char cVar1;
  char *pcVar2;
  char *pcVar3;
  char *pcVar4;
  undefined *puVar5;
  int iVar6;
  uint *puVar7;
  undefined4 *puVar8;
  char *pcVar9;
  uint uStack00000008;
  char *in_stack_00001018;
  
  FUN_0044c080();
  pcVar9 = &stack0x00000814;
  if ((DAT_00473514 & 1) == 0) {
    DAT_00473514 = DAT_00473514 | 1;
    _DAT_00463928 = 9;
    _DAT_00463934 = 9;
    _DAT_00463940 = 9;
    _DAT_0046394c = 9;
    _DAT_00463958 = 9;
    _DAT_004639b8 = 9;
    _DAT_00463920 = 0x47298c;
    _DAT_00463924 = 0x463f60;
    _DAT_0046392c = &DAT_004721e8;
    _DAT_00463930 = 0x463f54;
    _DAT_00463938 = 0x4722ec;
    _DAT_0046393c = 0x463f48;
    _DAT_00463944 = 0x472fa4;
    _DAT_00463948 = 0x463f40;
    _DAT_00463950 = 0x472b94;
    _DAT_00463954 = 0x46370c;
    _DAT_0046395c = 0x472888;
    _DAT_00463960 = 0x463f34;
    _DAT_00463964 = 0;
    _DAT_00463968 = 0;
    _DAT_0046396c = 0x463f24;
    _DAT_00463970 = 1;
    _DAT_00463974 = 0;
    _DAT_00463978 = 0x463f18;
    _DAT_0046397c = 2;
    _DAT_00463980 = 0;
    _DAT_00463984 = 0x463f0c;
    _DAT_00463988 = 3;
    _DAT_0046398c = 0;
    _DAT_00463990 = 0x463f04;
    _DAT_00463994 = 5;
    _DAT_00463998 = 0;
    _DAT_0046399c = 0x463ef8;
    _DAT_004639a0 = 6;
    _DAT_004639a4 = 0;
    _DAT_004639a8 = 0x463ef0;
    _DAT_004639ac = 4;
    _DAT_004639b0 = 0;
    _DAT_004639b4 = 0x463ee4;
    _DAT_004639bc = 0x4730a4;
    _DAT_004639c0 = 0x463ed8;
    _DAT_004639c4 = 7;
    _DAT_004639c8 = 0x170;
    _DAT_004639cc = 0x463ec8;
    _DAT_004639d0 = 7;
    _DAT_004639d4 = 0x172;
    _DAT_004639d8 = 0x463ebc;
    _DAT_004639dc = 7;
    _DAT_004639e0 = 0x171;
    _DAT_004639e4 = 0x463eb4;
    _DAT_004639e8 = 7;
    _DAT_004639ec = 0x7d2;
    _DAT_004639f0 = 0x463eac;
    _DAT_004639f4 = 7;
    _DAT_004639f8 = 0x7d4;
    _DAT_004639fc = 0x463ea0;
    _DAT_00463a00 = 7;
    _DAT_00463a04 = 0x16e;
    _DAT_00463a08 = 0x463e94;
    _DAT_00463a0c = 7;
    _DAT_00463a10 = 0x182;
    _DAT_00463a14 = 0x463e84;
    _DAT_00463a18 = 7;
    _DAT_00463a1c = 0x16f;
    _DAT_00463a20 = 0x463e7c;
    _DAT_00463a24 = 7;
    _DAT_00463a28 = 0x173;
    _DAT_00463a2c = 0x463e74;
    _DAT_00463a30 = 7;
    _DAT_00463a34 = 0x174;
    _DAT_00463a38 = 0x463e6c;
    _DAT_00463a3c = 7;
    _DAT_00463a40 = 0x175;
    _DAT_00463a44 = 0x463e64;
    _DAT_00463a48 = 7;
    _DAT_00463a4c = 0x7d3;
    _DAT_00463a50 = 0x463e54;
    _DAT_00463a54 = 7;
    _DAT_00463a58 = 0x7d6;
    _DAT_00463a5c = 0x463e48;
    _DAT_00463a60 = 7;
    _DAT_00463a64 = 0x7d5;
    _DAT_00463a68 = 0x463e3c;
    _DAT_00463a6c = 7;
    _DAT_00463a70 = 0x7d9;
    _DAT_00463a74 = 0x463e30;
    _DAT_00463a78 = 7;
    _DAT_00463a7c = 0x7e5;
    _DAT_00463a80 = 0x463e20;
    _DAT_00463a84 = 7;
    _DAT_00463a88 = 0x7da;
    _DAT_00463a8c = 0x463e10;
    _DAT_00463a90 = 7;
    _DAT_00463a94 = 0x7df;
    _DAT_00463a98 = 0x463e04;
    _DAT_00463a9c = 7;
    _DAT_00463aa0 = 0x137;
    _DAT_00463aa4 = 0x463df4;
    _DAT_00463aa8 = 7;
    _DAT_00463aac = 0x138;
    _DAT_00463ab0 = 0x463de0;
    _DAT_00463ab4 = 7;
    _DAT_00463ab8 = 0x135;
    _DAT_00463abc = 0x463dd8;
    _DAT_00463ac0 = 8;
    _DAT_00463ac4 = 0;
    _DAT_00463ac8 = 0;
    _DAT_00463acc = 0xc;
    _DAT_00463ad0 = 0;
  }
  puVar8 = (undefined4 *)&stack0x00000814;
  for (iVar6 = 0x200; iVar6 != 0; iVar6 = iVar6 + -1) {
    *puVar8 = 0;
    puVar8 = puVar8 + 1;
  }
  cVar1 = *in_stack_00001018;
  do {
    if (cVar1 == '\0') {
      lstrcpynA();
      return;
    }
    pcVar3 = (char *)0x0;
    *pcVar9 = *in_stack_00001018;
    if (*in_stack_00001018 != '%') {
      iVar6 = IsDBCSLeadByte();
      if (iVar6 != 0) {
        pcVar9[1] = in_stack_00001018[1];
      }
      goto LAB_0040e323;
    }
    uStack00000008 = 10;
    pcVar2 = (char *)CharNextA();
    pcVar3 = pcVar2;
    if (pcVar2 == (char *)0x0) goto LAB_0040e323;
    iVar6 = FUN_0044c373();
    if (iVar6 == 0) {
      puVar7 = (uint *)0x46391c;
      do {
        pcVar4 = (char *)puVar7[-1];
        if (pcVar4 == (char *)0x0) break;
        cVar1 = *pcVar3;
        while (((cVar1 != '\0' && (*pcVar4 != '\0')) && (cVar1 == *pcVar4))) {
          pcVar3 = (char *)CharNextA();
          pcVar4 = (char *)CharNextA();
          cVar1 = *pcVar3;
        }
        if (*pcVar4 == '\0') {
          uStack00000008 = *puVar7;
          in_stack_00001018 = pcVar3;
        }
        else {
          puVar7 = puVar7 + 3;
          pcVar3 = pcVar2;
        }
      } while (uStack00000008 == 10);
      if (0xb < uStack00000008) goto LAB_0040e323;
    }
    else {
      uStack00000008 = 0xb;
      in_stack_00001018 = pcVar2;
    }
    switch(uStack00000008) {
    case 0:
      FUN_0040d100();
      puVar5 = (undefined *)FUN_0040d4c0();
      *puVar5 = 0;
      FUN_0040db10();
      break;
    case 1:
      FUN_0044c3c3();
      goto LAB_0040e1f3;
    case 2:
      FUN_0040db40();
      goto LAB_0040e26a;
    case 3:
      FUN_0040dba0();
LAB_0040e26a:
      FUN_0040db10();
      break;
    case 4:
      GetTempPathA();
      puVar5 = (undefined *)FUN_0040d4c0();
      if ((puVar5 != (undefined *)0x0) && (pcVar2 = (char *)CharNextA(), *pcVar2 == '\0')) {
        *puVar5 = 0;
      }
      FUN_0040db10();
      break;
    case 5:
      GetWindowsDirectoryA();
      goto LAB_0040e123;
    case 6:
      GetSystemDirectoryA();
      goto LAB_0040e123;
    case 8:
      FUN_0044ba2e();
      while ((pcVar3 = in_stack_00001018, in_stack_00001018 != (char *)0x0 &&
             (iVar6 = FUN_0044c373(), iVar6 != 0))) {
        in_stack_00001018 = (char *)CharNextA();
      }
    case 7:
      FUN_0040e750();
LAB_0040e1f3:
      FUN_0040db10();
      break;
    case 9:
LAB_0040e123:
      FUN_0040db10();
      break;
    case 10:
      pcVar3 = (char *)0x0;
      break;
    default:
      FUN_0044bab9();
      wsprintfA();
      FUN_0040db10();
      while ((in_stack_00001018 != (char *)0x0 && (iVar6 = FUN_0044c373(), iVar6 != 0))) {
        in_stack_00001018 = (char *)CharNextA();
      }
      goto LAB_0040e33d;
    }
LAB_0040e323:
    if (pcVar3 != in_stack_00001018) {
      CharNextA();
      in_stack_00001018 = (char *)CharNextA();
    }
LAB_0040e33d:
    cVar1 = *in_stack_00001018;
  } while( true );
}



uint FUN_0040e3e0(void)

{
  int iVar1;
  undefined4 uVar2;
  uint uStack_1c;
  undefined4 uStack_18;
  undefined4 uStack_14;
  undefined *puStack_10;
  undefined auStack_c [4];
  undefined4 uStack_8;
  undefined4 uStack_4;
  
  puStack_10 = auStack_c;
  uStack_8 = 0;
  uStack_14 = 1;
  uStack_18 = 0;
  uStack_1c = 0x463f74;
  uVar2 = 0x80000002;
  uStack_4 = 4;
  iVar1 = RegOpenKeyExA(0x80000002);
  if (iVar1 == 0) {
    RegQueryValueExA(uVar2,0x463f68,0,0,&uStack_1c,&uStack_18);
    RegCloseKey(uVar2);
  }
  return uStack_1c >> 8;
}



undefined4
FUN_0040e450(undefined4 param_1,ushort param_2,undefined2 param_3,undefined2 param_4,
            undefined2 param_5)

{
  int iVar1;
  ushort auStack_28 [4];
  ushort auStack_20 [4];
  undefined4 uStack_18;
  undefined4 uStack_14;
  
  iVar1 = FUN_0041e8f0(param_1,&uStack_18);
  if (iVar1 != 0) {
    return 0;
  }
  auStack_20[1] = (short)uStack_18;
  auStack_20[0] = (ushort)((uint)uStack_18 >> 0x10);
  auStack_20[3] = (short)uStack_14;
  auStack_28[0] = param_2;
  auStack_28[1] = param_3;
  auStack_20[2] = (short)((uint)uStack_14 >> 0x10);
  auStack_28[2] = param_4;
  auStack_28[3] = param_5;
  iVar1 = 0;
  do {
    if (auStack_28[iVar1] != auStack_20[iVar1]) {
      if (auStack_28[iVar1] < auStack_20[iVar1] || auStack_28[iVar1] == auStack_20[iVar1]) {
        return 1;
      }
      return 0;
    }
    iVar1 = iVar1 + 1;
  } while (iVar1 < 4);
  return 1;
}



void FUN_0040e500(undefined4 param_1,undefined4 param_2)

{
  undefined2 uVar1;
  undefined2 uVar2;
  undefined2 uVar3;
  undefined2 uVar4;
  undefined4 uVar5;
  undefined2 uStack_68;
  undefined auStack_64 [100];
  
  lstrcpyA(auStack_64,param_2);
  uVar5 = FUN_0044c415(auStack_64,0x463fa0);
  uVar1 = FUN_0044bab9(uVar5);
  uVar5 = FUN_0044c415(0,0x463fa0);
  uVar2 = FUN_0044bab9(uVar5);
  uVar5 = FUN_0044c415(0,0x463fa0);
  uVar3 = FUN_0044bab9(uVar5);
  uVar5 = FUN_0044c415(0,0x463fa0);
  uVar4 = FUN_0044bab9(uVar5);
  FUN_0040e450(param_1,CONCAT22(uVar2,uVar1),CONCAT22(uVar3,uVar2),CONCAT22(uVar4,uVar3),
               CONCAT22(uStack_68,uVar4));
  return;
}



undefined4 FUN_0040e5a0(undefined4 param_1,int *param_2,undefined4 *param_3)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  int iStack_54;
  undefined auStack_50 [4];
  undefined auStack_4c [4];
  undefined auStack_48 [4];
  undefined4 uStack_44;
  undefined4 uStack_40;
  undefined4 uStack_3c;
  undefined *puStack_38;
  uint uStack_30;
  undefined auStack_2c [2];
  undefined2 uStack_2a;
  int iStack_28;
  int iStack_24;
  undefined4 uStack_20;
  
  iVar1 = FUN_0041b870(0x463fa4,0,0,0,3,0x4000000,0);
  if (iVar1 != -1) {
    puStack_38 = auStack_2c;
    uStack_40 = 0x2c;
    uStack_44 = param_1;
    uStack_3c = 0x7303;
    uStack_30 = 1;
    uStack_2a = 0;
    iVar2 = FUN_0041b8d0(iVar1,6,auStack_48,0x1c,auStack_48,0x1c,auStack_50,0);
    CloseHandle(iVar1);
    if ((iVar2 != 0) && ((uStack_30 & 1) == 0)) {
      *param_2 = iStack_24 * iStack_28;
      *param_3 = uStack_20;
      return 1;
    }
  }
  uVar3 = FUN_0041bdc0(param_1,param_2,&iStack_54,param_3,auStack_4c);
  *param_2 = *param_2 * iStack_54;
  return uVar3;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0040e690(void)

{
  undefined *puVar1;
  int iVar2;
  
  if ((_DAT_00472198 == 0) && (_DAT_004721c0 != 0)) {
    if ((DAT_00463ad4 == '?') && (DAT_00463ad4 = DAT_00472574, DAT_00472574 == '\\')) {
      lstrcpyA(&DAT_00463ad4,&DAT_00472574);
      puVar1 = (undefined *)FUN_0040d4c0(&DAT_00463ad4);
      *puVar1 = 0;
    }
    iVar2 = FUN_0040d0e0(&DAT_00472574);
    while (iVar2 == 0) {
      _DAT_004734d4 = 1;
      iVar2 = FUN_0040d270(_DAT_004721c8,0x31,0x94,_DAT_00472678,&DAT_00463ad4);
      _DAT_004734d4 = 0;
      if (iVar2 == 2) {
        return 0;
      }
      iVar2 = FUN_0040d0e0(&DAT_00472574);
    }
  }
  return 1;
}



undefined4 FUN_0040e750(undefined4 param_1,undefined4 param_2,undefined4 *param_3,uint param_4)

{
  char cVar1;
  undefined4 *puVar2;
  int iVar3;
  undefined4 uVar4;
  uint uVar5;
  undefined4 *puVar6;
  
  *(undefined *)param_3 = 0;
  puVar2 = (undefined4 *)FUN_0044c5a2(param_4 * 2);
  if (puVar2 == (undefined4 *)0x0) {
    SetLastError(8);
    return 0;
  }
  iVar3 = LoadStringA(param_1,param_2,puVar2,param_4);
  if (iVar3 == 0) {
    uVar4 = GetLastError();
    SetLastError(uVar4);
    FUN_0044c4b9(puVar2);
    return 0;
  }
  puVar6 = param_3;
  for (uVar5 = param_4 >> 2; uVar5 != 0; uVar5 = uVar5 - 1) {
    *puVar6 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar6 = puVar6 + 1;
  }
  for (uVar5 = param_4 & 3; uVar5 != 0; uVar5 = uVar5 - 1) {
    *(undefined *)puVar6 = *(undefined *)puVar2;
    puVar2 = (undefined4 *)((int)puVar2 + 1);
    puVar6 = (undefined4 *)((int)puVar6 + 1);
  }
  *(undefined *)((int)param_3 + (param_4 - 1)) = 0;
  cVar1 = *(char *)param_3;
  puVar2 = param_3;
  do {
    if (cVar1 == '\0') {
LAB_0040e7e0:
      FUN_0040dc60(param_3,param_4);
      uVar4 = lstrlenA(param_3);
      SetLastError(0);
      FUN_0044c4b9(param_1);
      return uVar4;
    }
    iVar3 = IsDBCSLeadByte(*(undefined *)puVar2);
    if (iVar3 != 0) {
      if (*(char *)((int)puVar2 + 1) == '\0') {
        *(undefined *)puVar2 = 0;
        goto LAB_0040e7e0;
      }
      puVar2 = (undefined4 *)((int)puVar2 + 1);
    }
    cVar1 = *(char *)((int)puVar2 + 1);
    puVar2 = (undefined4 *)((int)puVar2 + 1);
  } while( true );
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0040e830(undefined *param_1,undefined4 param_2,uint param_3)

{
  undefined4 uVar1;
  int iVar2;
  undefined auStack_108 [264];
  
  uVar1 = 1;
  if (_DAT_004734bc == 0) {
    if ((param_3 & 0x60004) != 0) {
      if ((param_3 & 0x20000) != 0) {
        lstrcpyA(auStack_108,param_1);
        FUN_0040dc60(auStack_108,0x105);
      }
      if ((param_3 & 0x40004) != 0) {
        if ((param_3 & 4) == 0) {
          wsprintfA(auStack_108,0x463fb0,param_1);
        }
        else {
          iVar2 = FindResourceA(_DAT_004721c0,param_1,0x463fb4);
          if (iVar2 == 0) {
            FUN_00410aa0(0x9a,param_1);
            return 0;
          }
          iVar2 = LoadResource(_DAT_004721c0,iVar2);
          if (iVar2 == 0) {
            return 0;
          }
          param_1 = (undefined *)LockResource(iVar2);
          param_3 = param_3 & 0xfffbffff;
        }
      }
    }
    if ((param_3 & 0x20000) != 0) {
      param_1 = auStack_108;
    }
    uVar1 = PlaySoundA(param_1,param_2,param_3);
  }
  return uVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined8 FUN_0040e930(void)

{
  uint *puVar1;
  uint *puVar2;
  char cVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  undefined *puVar7;
  undefined4 *puVar8;
  uint uVar9;
  undefined8 uVar10;
  char cStack_20;
  undefined4 uStack_1f;
  
  uVar6 = _DAT_00472164;
  uVar9 = _DAT_00472160;
  cStack_20 = DAT_0046e83c;
  puVar8 = &uStack_1f;
  for (iVar4 = 7; iVar4 != 0; iVar4 = iVar4 + -1) {
    *puVar8 = 0;
    puVar8 = puVar8 + 1;
  }
  *(undefined2 *)puVar8 = 0;
  *(undefined *)((int)puVar8 + 2) = 0;
  iVar4 = FUN_0040eca0();
  iVar5 = 0;
  if (iVar4 == 0) {
    iVar4 = FUN_0040ec60();
    if (iVar4 == 0) {
      FUN_0040e750(_DAT_004721c0,0x13b,&cStack_20,0x20);
      cVar3 = cStack_20;
      cStack_20 = '\0';
      uVar9 = uVar9 | (-(uint)(cVar3 != '1') & 0x1000) + 0x1000;
    }
  }
  iVar4 = FUN_0040ece0();
  if (iVar4 == 0) {
    iVar4 = FUN_0040ec40();
    if (iVar4 == 0) {
      FUN_0040e750(_DAT_004721c0,0x13d,&cStack_20,0x20);
      cVar3 = cStack_20;
      cStack_20 = '\0';
      uVar9 = uVar9 | (-(uint)(cVar3 != '1') & 0x4000) + 0x4000;
    }
  }
  lstrcpyA(&cStack_20,0x473024);
  if (cStack_20 == '\0') {
    FUN_0040e750(_DAT_004721c0,0x13e,&cStack_20,0x20);
  }
  if ((_DAT_00463828 | _DAT_0046382c) != 0) {
    puVar7 = &DAT_00463828;
    while( true ) {
      iVar4 = lstrcmpiA(&cStack_20,puVar7 + -8);
      if (iVar4 == 0) break;
      puVar1 = (uint *)(puVar7 + 0x18);
      puVar2 = (uint *)(puVar7 + 0x1c);
      puVar7 = puVar7 + 0x18;
      iVar5 = iVar5 + 1;
      if ((*puVar1 | *puVar2) == 0) {
        uVar10 = FUN_0040ee80();
        return CONCAT44((uint)((ulonglong)uVar10 >> 0x20) | uVar6,(uint)uVar10 | uVar9);
      }
    }
    uVar9 = uVar9 | *(uint *)(&DAT_00463828 + iVar5 * 0x18);
    uVar6 = uVar6 | *(uint *)(&DAT_0046382c + iVar5 * 0x18);
  }
  uVar10 = FUN_0040ee80();
  return CONCAT44((uint)((ulonglong)uVar10 >> 0x20) | uVar6,(uint)uVar10 | uVar9);
}



void FUN_0040ebe0(void)

{
  FUN_00410440(0x7e0,1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

bool FUN_0040ebf0(int param_1)

{
  uint uVar1;
  
  uVar1 = _DAT_00472160 & 0x40000;
  _DAT_00472160 = -(uint)(param_1 != 0) & 0x40000 | _DAT_00472160 & 0xfffbffff;
  return uVar1 != 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0040ec40(void)

{
  if ((_DAT_00472160 & 0x8000) != 0) {
    return 1;
  }
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0040ec60(void)

{
  if ((_DAT_00472160 & 0x2000) != 0) {
    return 1;
  }
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0040eca0(void)

{
  if ((_DAT_00472160 & 0x1000) != 0) {
    return 1;
  }
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0040ecc0(void)

{
  if ((_DAT_00472164 & 1) != 0) {
    return 1;
  }
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0040ece0(void)

{
  if ((_DAT_00472160 & 0x4000) != 0) {
    return 1;
  }
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0040ed00(void)

{
  if ((_DAT_00472168 & 0x200) != 0) {
    return 1;
  }
  return 0;
}



// WARNING: Removing unreachable block (ram,0x0040ed8f)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0040ed20(int param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  
  iVar1 = param_1;
  uVar7 = 0;
  uVar6 = 0x400;
  iVar5 = param_1;
  FormatMessageA(0x1100,0,param_1,0x400,&param_1,0);
  iVar2 = lstrlenA(uVar7);
  iVar3 = lstrlenA(0);
  iVar4 = lstrlenA(0x463fc8);
  iVar3 = FUN_0044ba20(iVar4 + 9 + iVar2 + iVar3);
  iVar2 = iVar5;
  if (iVar3 != 0) {
    wsprintfA(iVar3,0x463fbc,iVar5,iVar1);
    iVar5 = iVar3;
  }
  FUN_0040d2e0(_DAT_004721c8,uVar6,iVar5);
  if (iVar3 != 0) {
    FUN_0044bb7e(iVar3);
  }
  LocalFree(iVar2);
  return;
}



void FUN_0040ede0(undefined4 param_1)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  undefined4 uVar5;
  int iVar6;
  
  uVar1 = param_1;
  iVar6 = 0;
  uVar5 = param_1;
  FormatMessageA(0x1100,0,param_1,0x400,&param_1,0,0);
  iVar2 = lstrlenA(iVar6);
  iVar3 = lstrlenA(iVar6);
  iVar4 = lstrlenA(0x463fc8);
  iVar2 = FUN_0044ba20(iVar4 + 9 + iVar2 + iVar3);
  if (iVar2 != 0) {
    wsprintfA(iVar2,0x463fbc,uVar5,uVar1);
  }
  if (iVar6 != 0) {
    lstrcatA(iVar2,iVar6);
  }
  if (iVar2 != 0) {
    FUN_0044bb7e(iVar2);
  }
  LocalFree(uVar5);
  return;
}



longlong FUN_0040ee80(void)

{
  char cVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  
  uVar4 = 0x1000000;
  iVar2 = GetKeyboardType(0);
  if (iVar2 == 7) {
    iVar2 = GetKeyboardType(1);
    uVar3 = iVar2 >> 8 & 0xff;
    if (uVar3 == 0) {
      cVar1 = GetKeyboardType(1);
      if (cVar1 == '\0') {
        return 0x100000000000000;
      }
    }
    else {
      if (uVar3 != 0xd) goto LAB_0040eede;
      cVar1 = GetKeyboardType(1);
      if (cVar1 != '\x05') {
        return 0x400000000000000;
      }
    }
    uVar4 = 0x2000000;
  }
LAB_0040eede:
  return (ulonglong)uVar4 << 0x20;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_0040eef0(undefined4 param_1,undefined *param_2,undefined *param_3,undefined4 param_4,
                undefined4 param_5,undefined4 param_6,int param_7,int param_8,int param_9,
                int param_10,int param_11,int param_12,undefined4 *param_13,int param_14,
                int param_15,int param_16)

{
  char cVar1;
  char *pcVar2;
  int iVar3;
  char *pcVar4;
  int iVar5;
  undefined4 uVar6;
  int unaff_EBX;
  undefined4 *puVar7;
  int *piVar8;
  bool bVar9;
  int unaff_retaddr;
  undefined4 auStack_99c [2];
  undefined4 uStack_994;
  undefined4 uStack_990;
  undefined3 uStack_98f;
  undefined *puStack_98c;
  int iStack_988;
  undefined4 uStack_984;
  undefined4 uStack_980;
  int iStack_97c;
  undefined4 uStack_978;
  int iStack_974;
  undefined4 uStack_970;
  uint uStack_96c;
  int iStack_968;
  int aiStack_964 [4];
  undefined *puStack_954;
  undefined *puStack_950;
  undefined *puStack_94c;
  undefined4 uStack_948;
  undefined4 uStack_944;
  undefined4 uStack_930;
  undefined4 uStack_92c;
  undefined auStack_928 [252];
  undefined auStack_82c [8];
  undefined auStack_824 [252];
  undefined auStack_728 [4];
  undefined auStack_724 [4];
  undefined auStack_720 [252];
  undefined auStack_624 [8];
  undefined auStack_61c [260];
  undefined auStack_518 [260];
  undefined auStack_414 [260];
  undefined auStack_310 [260];
  char acStack_20c [524];
  
  auStack_99c[0] = 10000;
  puStack_98c = (undefined *)((uint)puStack_98c & 0xffffff00);
  uStack_990 = 0xf;
  iStack_988 = 0;
  uStack_984 = 0;
  uStack_980 = 0;
  iStack_97c = 0;
  uStack_978 = 0x103;
  iStack_974 = 0;
  uStack_970 = 1;
  if (param_2 == (undefined *)0x0) {
    return 10000;
  }
  iVar3 = lstrlenA(param_2);
  if (iVar3 < 1) {
    return 10000;
  }
  iVar3 = FUN_00410c20(param_6);
  if (iVar3 == 0) {
    lstrcpyA(acStack_20c,param_6);
    FUN_0040dc60(acStack_20c,0x208);
    pcVar4 = (char *)0x0;
    pcVar2 = acStack_20c;
    cVar1 = acStack_20c[0];
    while (cVar1 != '\0') {
      if (cVar1 == '|') {
        pcVar4 = (char *)CharNextA(pcVar2);
        *pcVar2 = '\0';
        break;
      }
      pcVar4 = (char *)CharNextA(pcVar2);
      pcVar2 = pcVar4;
      cVar1 = *pcVar4;
    }
    if ((((param_9 != 0) || (_DAT_004721a8 == 0)) && (*pcVar4 != '\0')) &&
       (iVar3 = FUN_0040d2e0(_DAT_004721c8,0x24,pcVar4), iVar3 != 6)) {
      return (param_10 != 0) + 10000;
    }
    if (acStack_20c[0] != '\0') {
      FUN_004143b0(acStack_20c);
    }
  }
  bVar9 = _DAT_004721e4 != (code *)0x0;
  uStack_96c = (uint)bVar9;
  lstrcpyA(auStack_928,param_1);
  FUN_0040dc60(auStack_928,0x104);
  iStack_968 = FUN_00410890(auStack_928);
  if ((iStack_968 == 0) && (iVar3 = FUN_00410910(auStack_928,auStack_518,0x104), iVar3 != 0)) {
    lstrcpyA(auStack_928,auStack_518);
  }
  if (param_2 != (undefined *)0x0) {
    lstrcpyA(auStack_310,param_2);
    FUN_0040dc60(auStack_310,0x104);
    iVar3 = FUN_00410910(auStack_310,auStack_518,0x104);
    if (iVar3 != 0) {
      lstrcpyA(auStack_310,auStack_518);
    }
    param_2 = auStack_310;
  }
  if (param_3 != (undefined *)0x0) {
    lstrcpyA(auStack_414,param_3);
    FUN_0040dc60(auStack_414,0x104);
    iVar3 = FUN_00410910(auStack_414,auStack_518,0x104);
    if (iVar3 != 0) {
      lstrcpyA(auStack_414,auStack_518);
    }
    param_3 = auStack_414;
  }
  if (param_12 != 0) {
    lstrcpyA(auStack_720,auStack_414);
    iVar3 = lstrlenA(auStack_720);
    if (iVar3 != 0) {
      FUN_0040f8a0(auStack_724);
    }
    lstrcatA(auStack_724,&uStack_92c);
    iVar3 = lstrlenA(param_2);
    if (iVar3 != 0) {
      lstrcatA(auStack_728,&DAT_00463750);
      lstrcatA(auStack_728,param_2);
    }
    auStack_624[0] = 0;
    iVar3 = 0;
    do {
      lstrcpyA(auStack_82c,0x464058);
      wsprintfA(&stack0xfffff65c,0x464054,iVar3);
      lstrcatA(auStack_82c,&stack0xfffff65c);
      FUN_0041dcd0(0x80000002,0x464020,auStack_82c,&DAT_0046e83c,auStack_624,0x104);
      iVar5 = lstrlenA(auStack_624);
      iVar3 = iVar3 + 1;
    } while (iVar5 != 0);
    lstrcpyA(auStack_624,auStack_82c);
    lstrcpyA(auStack_82c,0x463fec);
    lstrcatA(auStack_82c,auStack_624);
    iVar3 = FUN_0041de30(0x80000002,auStack_82c,auStack_728,1);
    unaff_EBX = (-(uint)(iVar3 != 0) & 0xfffffffa) + 0x2716;
    FUN_004146b0();
    goto LAB_0040f5a9;
  }
  uStack_990 = CONCAT31(uStack_98f,DAT_00472198);
  puStack_98c = auStack_928;
  iStack_988 = param_8;
  uStack_978 = param_5;
  uStack_970 = 0;
  if ((bVar9 == 1) && (unaff_EBX = (*_DAT_004721e4)(&uStack_994), unaff_EBX != 10000))
  goto LAB_0040f5a9;
  if ((param_14 != 0) && (iVar3 = FUN_0040e690(), iVar3 == 0)) {
    unaff_EBX = 0x2711;
    goto LAB_0040f5a9;
  }
  piVar8 = aiStack_964;
  for (iVar3 = 0xf; iVar3 != 0; iVar3 = iVar3 + -1) {
    *piVar8 = 0;
    piVar8 = piVar8 + 1;
  }
  aiStack_964[2] = unaff_retaddr;
  if (unaff_retaddr == 0) {
    aiStack_964[2] = GetDesktopWindow();
  }
  puStack_954 = auStack_928;
  puStack_950 = param_2;
  aiStack_964[0] = 0x3c;
  aiStack_964[1] = 0x440;
  puStack_94c = param_3;
  uStack_948 = param_4;
  if (param_11 != 0) {
    _DAT_004734f0 = 1;
  }
  iStack_974 = FUN_0041bf40(aiStack_964);
  if ((iStack_974 == 0) && (param_7 != 0)) {
    uVar6 = GetLastError(0);
    FUN_0040ede0(uVar6);
    if (iStack_968 == 0) {
      FUN_0040d270(unaff_retaddr,0x10,param_7);
    }
    else {
      FUN_0040d270(unaff_retaddr,0x30,param_7,auStack_928);
    }
  }
  uStack_980 = uStack_92c;
  uStack_984 = uStack_944;
  uStack_970 = 1;
  if (uStack_96c == 1) {
    (*_DAT_004721e4)(&uStack_994);
  }
  if (iStack_974 == 1) {
    Sleep(0);
    WaitForInputIdle(uStack_930,10000);
    Sleep(0);
  }
  if (param_8 != 1) goto LAB_0040f539;
  if (iStack_974 == 1) {
    if ((param_15 == 0) && (param_16 == 0)) {
      if (iStack_97c == 0x103) {
        do {
          iVar3 = GetExitCodeProcess(uStack_92c,&iStack_97c);
          if (iVar3 == 0) break;
          FUN_0040d420();
          Sleep(0);
        } while (iStack_97c == 0x103);
        goto LAB_0040f539;
      }
    }
    else {
      iVar3 = FindWindowA(param_16,param_15);
      while (iVar3 != 0) {
        FUN_0040d420();
        Sleep(0);
        iVar3 = FindWindowA(param_16,param_15);
      }
      iStack_97c = 0;
LAB_0040f539:
      if (iStack_974 != 1) goto LAB_0040f565;
    }
    if ((iStack_97c == 0xbc2) || (iStack_97c == 0xbc3)) {
      FUN_004146b0();
    }
    CloseHandle(uStack_92c);
  }
LAB_0040f565:
  uStack_970 = 2;
  if (param_13 != (undefined4 *)0x0) {
    puVar7 = &uStack_994;
    for (iVar3 = 10; iVar3 != 0; iVar3 = iVar3 + -1) {
      *param_13 = *puVar7;
      puVar7 = puVar7 + 1;
      param_13 = param_13 + 1;
    }
  }
  if (uStack_96c == 1) {
    (*_DAT_004721e4)(&uStack_994);
  }
  if (iStack_974 == 0) {
    unaff_EBX = 0x2716;
  }
LAB_0040f5a9:
  if (param_11 != 0) {
    FUN_004146b0();
    lstrcpyA(auStack_928,0x463344);
    FUN_0040f8a0(auStack_928);
    lstrcatA(auStack_928,0x463fe0);
    FUN_0040dc60(auStack_928,0x104);
    FUN_00410910(auStack_928,auStack_720,0x104);
    lstrcatA(auStack_720,0x463fd4);
    wsprintfA(auStack_99c,0x464054,_DAT_004734dc + 1);
    lstrcatA(auStack_720,auStack_99c);
    if (_DAT_004734e0 != 0) {
      lstrcatA(auStack_720,0x463fd0);
    }
    auStack_61c[0] = 0;
    iVar3 = 0;
    do {
      lstrcpyA(auStack_824,0x464058);
      wsprintfA(auStack_99c,0x464054,iVar3);
      lstrcatA(auStack_824,auStack_99c);
      FUN_0041dcd0(0x80000002,0x464020,auStack_824,&DAT_0046e83c,auStack_61c,0x104);
      iVar5 = lstrlenA(auStack_61c);
      iVar3 = iVar3 + 1;
    } while (iVar5 != 0);
    lstrcpyA(auStack_61c,auStack_824);
    lstrcpyA(auStack_824,0x463fec);
    lstrcatA(auStack_824,auStack_61c);
    FUN_0041de30(0x80000002,auStack_824,auStack_720,1);
    unaff_EBX = 0x2715;
  }
  return unaff_EBX;
}



char * FUN_0040f760(char *param_1,char *param_2,int param_3)

{
  char *pcVar1;
  
  if (0 < param_3) {
    param_3 = param_3 + -1;
    pcVar1 = param_1;
    while ((param_3 != 0 && (*param_2 != '\0'))) {
      *pcVar1 = *param_2;
      pcVar1 = (char *)CharNextA(pcVar1);
      param_2 = (char *)CharNextA(param_2);
      param_3 = param_3 + -1;
    }
    *pcVar1 = '\0';
    return param_1;
  }
  return (char *)0x0;
}



// WARNING: Restarted to delay deadcode elimination for space: stack

undefined4 FUN_0040f810(void)

{
  int iVar1;
  int iStack_18;
  undefined *puStack_14;
  undefined *puStack_10;
  undefined auStack_8 [8];
  
  puStack_10 = (undefined *)0x0;
  puStack_14 = (undefined *)0x40f821;
  CoInitialize();
  puStack_10 = auStack_8;
  puStack_14 = &UNK_00460128;
  iStack_18 = 1;
  iVar1 = CoCreateInstance(&UNK_00460118);
  if (iVar1 < 0) {
    CoUninitialize();
    return 0;
  }
  iVar1 = (**ppcRam00000000)();
  if (iVar1 < 0) {
    (*pcRam000214f6)(&UNK_00460108);
    CoUninitialize();
    return 0;
  }
  (**(code **)(iStack_18 + 8))(&iStack_18);
  (*ppcRam00000000[2])(0);
  CoUninitialize();
  return 1;
}



void FUN_0040f8a0(int param_1)

{
  int iVar1;
  char *pcVar2;
  
  iVar1 = lstrlenA(param_1);
  pcVar2 = (char *)CharPrevA(param_1,iVar1 + param_1);
  if (*pcVar2 != '\\') {
    lstrcatA(param_1,0x463be4);
  }
  return;
}



int FUN_0040faf0(char *param_1)

{
  int iVar1;
  
  iVar1 = 0;
  if (*param_1 == '\0') {
    return 0;
  }
  do {
    param_1 = (char *)CharNextA(param_1);
    iVar1 = iVar1 + 1;
  } while (*param_1 != '\0');
  return iVar1;
}



char * FUN_0040fe90(char *param_1,char *param_2)

{
  char cVar1;
  char cVar2;
  int iVar3;
  char *pcVar4;
  char *pcVar5;
  
  if (*param_2 == '\0') {
    return param_1;
  }
  cVar1 = *param_1;
  do {
    pcVar4 = param_1;
    pcVar5 = param_2;
    if (cVar1 == '\0') {
      return (char *)0x0;
    }
    while (cVar1 != '\0') {
      if (*pcVar5 == '\0') {
        return param_1;
      }
      iVar3 = IsDBCSLeadByte(*pcVar4);
      if ((iVar3 == 0) && (iVar3 = FUN_0044c34b((int)*pcVar4), iVar3 != 0)) {
        cVar1 = FUN_0044bf1a((int)*pcVar4);
      }
      else {
        cVar1 = *pcVar4;
      }
      iVar3 = IsDBCSLeadByte(*pcVar5);
      if ((iVar3 == 0) && (iVar3 = FUN_0044c34b((int)*pcVar5), iVar3 != 0)) {
        cVar2 = FUN_0044bf1a((int)*pcVar5);
      }
      else {
        cVar2 = *pcVar5;
      }
      if ((cVar1 != cVar2) ||
         ((iVar3 = IsDBCSLeadByte(*pcVar4), iVar3 != 0 && (pcVar4[1] != pcVar5[1])))) break;
      pcVar4 = (char *)CharNextA(pcVar4);
      pcVar5 = (char *)CharNextA(pcVar5);
      cVar1 = *pcVar4;
    }
    if (*pcVar5 == '\0') {
      return param_1;
    }
    param_1 = (char *)CharNextA(param_1);
    cVar1 = *param_1;
  } while( true );
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0040ff80(undefined4 *param_1,int param_2)

{
  undefined4 *puVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  undefined4 *puVar5;
  undefined4 *puVar6;
  undefined4 uStack_20c;
  undefined uStack_208;
  undefined4 uStack_207;
  undefined4 auStack_104 [65];
  
  uStack_208 = DAT_0046e83c;
  puVar5 = &uStack_207;
  for (iVar3 = 0x40; iVar3 != 0; iVar3 = iVar3 + -1) {
    *puVar5 = 0;
    puVar5 = puVar5 + 1;
  }
  *(undefined2 *)puVar5 = 0;
  *(undefined *)((int)puVar5 + 2) = 0;
  uStack_20c = 0;
  if ((param_2 != 0) && (_DAT_0047217c != 0)) {
    iVar3 = lstrcmpiA(0x4731a8,param_1);
    if (iVar3 != 0) {
      lstrcpyA(&uStack_208,param_1);
      lstrcpyA(&DAT_004721e8,0x4731a8);
      FUN_00417600(0);
      lstrcpyA(&DAT_004721e8,&uStack_208);
    }
  }
  lstrcpyA(0x4731a8,param_1);
  puVar5 = auStack_104;
  if (*(char *)param_1 != '\0') {
    do {
      puVar1 = (undefined4 *)CharNextA(param_1);
      puVar6 = puVar5;
      if (param_1 < puVar1) {
        uVar2 = (int)puVar1 - (int)param_1;
        puVar6 = (undefined4 *)((int)puVar5 + uVar2);
        puVar1 = param_1;
        for (uVar4 = uVar2 >> 2; uVar4 != 0; uVar4 = uVar4 - 1) {
          *puVar5 = *puVar1;
          puVar1 = puVar1 + 1;
          puVar5 = puVar5 + 1;
        }
        param_1 = (undefined4 *)((int)param_1 + uVar2);
        for (uVar2 = uVar2 & 3; uVar2 != 0; uVar2 = uVar2 - 1) {
          *(undefined *)puVar5 = *(undefined *)puVar1;
          puVar1 = (undefined4 *)((int)puVar1 + 1);
          puVar5 = (undefined4 *)((int)puVar5 + 1);
        }
      }
      if ((*(char *)param_1 == '\\') || (*(char *)param_1 == '\0')) {
        *(undefined *)puVar6 = 0;
        iVar3 = FUN_0041b970(auStack_104,0);
        if ((iVar3 != 0) && (uStack_20c = 1, param_2 != 0)) {
          _DAT_0047217c = 1;
        }
      }
      puVar5 = puVar6;
    } while (*(char *)param_1 != '\0');
    return uStack_20c;
  }
  return 0;
}



void FUN_004100a0(char *param_1)

{
  char cVar1;
  int iVar2;
  
  cVar1 = *param_1;
  while (cVar1 != '\0') {
    iVar2 = FUN_0044c323((int)*param_1);
    if (iVar2 != 0) {
      cVar1 = FUN_0044c6dc((int)*param_1);
      *param_1 = cVar1;
    }
    param_1 = (char *)CharNextA(param_1);
    cVar1 = *param_1;
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_004100e0(int param_1)

{
  char *pcVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  code *pcVar5;
  undefined4 unaff_EBX;
  char *pcVar6;
  undefined4 uVar7;
  undefined4 uStack_310;
  undefined auStack_30c [256];
  char acStack_20c [260];
  undefined auStack_108 [264];
  
  uStack_310 = 0x68;
  uVar2 = FUN_0040d140();
  if ((uVar2 & 0x2c) == 0) {
    return 100;
  }
  if (_DAT_00472194 == 0) {
    uVar7 = 0x463344;
    if (param_1 == 0) {
      uVar7 = 0x46378c;
    }
  }
  else {
    uVar7 = 0x4730a4;
  }
  lstrcpyA(auStack_30c,uVar7);
  FUN_0040f8a0(auStack_30c);
  lstrcatA(auStack_30c,0x464080);
  FUN_0040dc60(auStack_30c,0x104);
  iVar3 = LoadLibraryA(auStack_30c);
  if (iVar3 != 0) {
    pcVar6 = acStack_20c;
    FUN_0040e750(_DAT_004721c0,0x7d2,acStack_20c,0x104);
    while (acStack_20c[0] != '\0') {
      if (acStack_20c[0] == '.') {
        *pcVar6 = '\0';
        break;
      }
      pcVar1 = pcVar6 + 1;
      pcVar6 = pcVar6 + 1;
      acStack_20c[0] = *pcVar1;
    }
    if (param_1 == 0) {
      pcVar5 = (code *)GetProcAddress(iVar3,0x464068);
      if (pcVar5 != (code *)0x0) {
        unaff_EBX = (*pcVar5)(acStack_20c);
      }
    }
    else {
      uVar7 = 0x4730a4;
      if (_DAT_00472194 == 0) {
        uVar7 = 0x464070;
      }
      lstrcpyA(&uStack_310,uVar7);
      FUN_0040f8a0(&uStack_310);
      FUN_0040dc60(&uStack_310,0x104);
      iVar4 = FUN_00410910(&uStack_310,auStack_108,0x104);
      if (iVar4 == 0) {
        lstrcpyA(auStack_108,&uStack_310);
      }
      pcVar5 = (code *)GetProcAddress(iVar3,0x463ca4);
      if (pcVar5 != (code *)0x0) {
        unaff_EBX = (*pcVar5)(acStack_20c,auStack_108);
      }
    }
    FreeLibrary(iVar3);
  }
  return unaff_EBX;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_00410290(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                undefined4 param_5,uint param_6)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  undefined4 uVar4;
  undefined auStack_104 [260];
  
  FUN_004200f0();
  lstrcpyA(auStack_104,0x463344);
  FUN_0040f8a0(auStack_104);
  lstrcatA(auStack_104,0x464098);
  FUN_0040f8a0(auStack_104);
  lstrcatA(auStack_104,param_2);
  FUN_0040dc60(auStack_104,0x104);
  iVar1 = FUN_0040d0e0(auStack_104);
  if (iVar1 != 0) {
    uVar4 = 0x464094;
    uVar2 = FUN_0041aa10(param_2,0x464094);
    iVar1 = lstrcmpiA(uVar2,uVar4);
    if (iVar1 == 0) {
      iVar1 = LoadImageA(param_1,auStack_104,param_3,param_4,param_5,param_6 & 0xffff7fff | 0x10);
    }
    else {
      uVar4 = 0x464090;
      uVar2 = FUN_0041aa10(param_2,0x464090);
      iVar1 = lstrcmpiA(uVar2,uVar4);
      if (iVar1 != 0) goto LAB_004103a4;
      FUN_00420640(auStack_104,1,1);
      iVar1 = FUN_004201a0();
    }
    if (iVar1 != 0) goto LAB_00410427;
  }
LAB_004103a4:
  iVar1 = LoadImageA(param_1,param_2,param_3,param_4,param_5,param_6);
  if (iVar1 == 0) {
    iVar3 = FindResourceA(_DAT_004721c0,param_2,0x46408c);
    if (iVar3 == 0) {
      FUN_00410aa0(0x99,param_2);
    }
    else {
      iVar3 = LoadResource(_DAT_004721c0,iVar3);
      if (iVar3 != 0) {
        iVar3 = LockResource(iVar3);
        if (iVar3 != 0) {
          FUN_00420640(iVar3,2,1);
          iVar1 = FUN_004201a0();
        }
      }
    }
  }
LAB_00410427:
  FUN_00420120();
  return iVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

bool __thiscall FUN_00410440(undefined2 param_1,undefined4 param_2,int param_3)

{
  undefined4 uVar1;
  undefined4 uStack_4;
  
  uStack_4 = CONCAT22(_DAT_0046409c,param_1);
  uVar1 = _DAT_004721c0;
  if (param_3 == 0) {
    uVar1 = _DAT_004721bc;
  }
  FUN_0040e750(uVar1,param_2,(int)&uStack_4 + 2,2);
  return uStack_4._2_1_ == '1';
}



undefined4 FUN_004105e0(undefined4 param_1,int param_2)

{
  int iVar1;
  int iVar2;
  int iVar3;
  
  iVar1 = param_2;
  iVar3 = param_2 + 1;
  iVar2 = FUN_0044c5a2(iVar3);
  if (iVar2 != 0) {
    iVar3 = GetFullPathNameA(param_1,iVar3,iVar2,&param_2);
    if ((iVar3 != 0) && (iVar3 < iVar1)) {
      lstrcpyA(param_1,iVar2);
    }
    FUN_0044c4b9(iVar2);
    return param_1;
  }
  return param_1;
}



undefined4 FUN_00410640(void)

{
  int iVar1;
  code *pcVar2;
  uint uVar3;
  undefined4 uVar4;
  undefined auStack_208 [252];
  undefined auStack_10c [4];
  undefined auStack_108 [264];
  
  lstrcpyA(auStack_208,0x4640e4);
  FUN_0040dc60(auStack_208,0x104);
  iVar1 = LoadLibraryA(auStack_208);
  if (iVar1 == 0) {
    return 0;
  }
  pcVar2 = (code *)GetProcAddress(iVar1,0x4640dc);
  if (pcVar2 == (code *)0x0) {
    FreeLibrary(iVar1);
    return 0;
  }
  lstrcpyA(auStack_108,0x4640c8);
  FUN_0040dc60(auStack_108,0x104);
  lstrcpyA(&stack0xfffffcf0,0x4640b0);
  FUN_0040dc60(&stack0xfffffcf0,0x104);
  uVar3 = GetFileAttributesA(&stack0xfffffcf0);
  uVar4 = (*pcVar2)(0x472b94,auStack_10c,~-(uint)((uVar3 & 0x10) != 0) & (uint)&stack0xfffffcec,1);
  FreeLibrary(iVar1);
  return uVar4;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_00410740(void)

{
  undefined4 uVar1;
  char acStack_228 [32];
  char acStack_208 [260];
  undefined auStack_104 [260];
  
  FUN_0040e750(_DAT_004721c0,0x21,auStack_104,0x104);
  FUN_0041dcd0(0x80000002,auStack_104,0x464110,&DAT_0046e83c,acStack_208,0x104);
  if (acStack_208[0] != '\0') {
    FUN_0040f8a0(acStack_208);
    lstrcatA(acStack_208,0x464104);
    FUN_0040e750(_DAT_004721c0,0x7e1,acStack_228,0x20);
    if (acStack_228[0] == '\0') {
      lstrcpyA(acStack_228,0x4640fc);
    }
    uVar1 = FUN_0040e500(acStack_208,acStack_228);
    return uVar1;
  }
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

bool __fastcall FUN_00410810(undefined2 param_1)

{
  undefined4 uStack_4;
  
  uStack_4 = CONCAT22(_DAT_0046409c,param_1);
  FUN_0040e750(_DAT_004721bc,0x62,(int)&uStack_4 + 2,2);
  return DAT_00464118 == uStack_4._2_1_;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_00410890(char *param_1)

{
  int iVar1;
  int iVar2;
  char *pcVar3;
  
  if (*param_1 != '\0') {
    iVar1 = lstrlenA(&DAT_00464120);
    iVar2 = lstrlenA(param_1);
    pcVar3 = param_1;
    if (iVar1 < iVar2) {
      pcVar3 = &DAT_00464120;
    }
    iVar1 = lstrlenA(pcVar3);
    lstrcpynA(&stack0xffffffec,param_1,iVar1 + 1);
  }
  if ((*param_1 != '\0') && (iVar1 = lstrcmpiA(), iVar1 == 0)) {
    return 1;
  }
  return 0;
}



void FUN_00410910(char *param_1,undefined4 param_2,undefined4 param_3)

{
  bool bVar1;
  short sVar2;
  char *pcVar3;
  char *pcVar4;
  char acStack_104 [260];
  
  sVar2 = FUN_0040d140();
  if (sVar2 == 1) {
    bVar1 = false;
    lstrcpyA(acStack_104,param_1);
    pcVar4 = acStack_104;
    pcVar3 = acStack_104;
    while (acStack_104[0] != '\0') {
      if (*pcVar4 == '\\') {
        if (!bVar1) {
          bVar1 = true;
          *pcVar3 = '\\';
          goto LAB_00410968;
        }
      }
      else {
        bVar1 = false;
        *pcVar3 = *pcVar4;
LAB_00410968:
        pcVar3 = (char *)CharNextA(pcVar3);
      }
      pcVar4 = (char *)CharNextA(pcVar4);
      acStack_104[0] = *pcVar4;
    }
    *pcVar3 = '\0';
    param_1 = acStack_104;
  }
  GetShortPathNameA(param_1,param_2,param_3);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_004109b0(undefined4 param_1)

{
  undefined auStack_64 [100];
  
  if (_DAT_004721c0 != 0) {
    FUN_0040e750(_DAT_004721c0,param_1,auStack_64,100);
    MessageBoxA(_DAT_004721c8,auStack_64,0x464164,0);
    return;
  }
  MessageBoxA(_DAT_004721c8,0x464128,0x464164,0);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00410a10(undefined4 param_1,undefined4 param_2)

{
  undefined auStack_c8 [100];
  undefined auStack_64 [100];
  
  if (_DAT_004721c0 != 0) {
    FUN_0040e750(_DAT_004721c0,param_1,auStack_c8,100);
    wsprintfA(auStack_64,auStack_c8,param_2);
    MessageBoxA(_DAT_004721c8,auStack_64,0x464164,0);
    return;
  }
  MessageBoxA(_DAT_004721c8,0x464128,0x464164,0);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00410aa0(undefined4 param_1,undefined4 param_2)

{
  undefined auStack_168 [100];
  undefined auStack_104 [260];
  
  if (_DAT_004721c0 != 0) {
    FUN_0040e750(_DAT_004721c0,param_1,auStack_168,100);
    wsprintfA(auStack_104,auStack_168,param_2);
    MessageBoxA(_DAT_004721c8,auStack_104,0x464164,0);
    return;
  }
  MessageBoxA(_DAT_004721c8,0x464128,0x464164,0);
  return;
}



bool FUN_00410c20(int param_1)

{
  int iVar1;
  
  if (param_1 != 0) {
    iVar1 = lstrlenA(param_1);
    if (iVar1 != 0) {
      iVar1 = lstrcmpiA(param_1,0x464170);
      return iVar1 == 0;
    }
  }
  return true;
}



undefined4 FUN_00410c50(void)

{
  int iVar1;
  undefined4 uVar2;
  int iStack_8;
  undefined4 uStack_4;
  
  iStack_8 = 0;
  uStack_4 = 4;
  iVar1 = FUN_0041dd60(0x80000001,0x472b94,0x464178,&iStack_8,&uStack_4);
  if ((iVar1 != 0) || (uVar2 = 1, iStack_8 != 1)) {
    uVar2 = 0;
  }
  return uVar2;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00410ca0(void)

{
  undefined2 uStack_106;
  undefined auStack_104 [260];
  
  uStack_106 = _DAT_0046411c;
  lstrcpyA(auStack_104,0x472b94);
  FUN_0040f8a0(auStack_104);
  lstrcatA(auStack_104,0x464178);
  FUN_0041de30(0x80000001,auStack_104,&uStack_106,4);
  return;
}



void __fastcall FUN_00410d50(undefined *param_1)

{
  *param_1 = 0;
  param_1[0x80] = 0;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00411650(void)

{
  char cVar1;
  bool bVar2;
  int iVar3;
  char *pcVar4;
  undefined *puVar5;
  char *pcVar6;
  int iVar7;
  uint uVar8;
  char *pcStack00000008;
  int iStack0000000c;
  undefined4 in_stack_00000014;
  undefined4 in_stack_00000018;
  undefined *in_stack_0000001c;
  undefined4 in_stack_00000020;
  undefined *in_stack_00000024;
  undefined4 in_stack_00000028;
  undefined4 in_stack_0000002c;
  undefined *in_stack_00000030;
  undefined4 in_stack_00000034;
  undefined *in_stack_00000038;
  undefined4 in_stack_0000003c;
  undefined4 in_stack_00000040;
  undefined4 in_stack_00000044;
  undefined4 in_stack_00000048;
  undefined4 in_stack_0000004c;
  undefined4 in_stack_00000050;
  undefined4 in_stack_00000054;
  undefined4 in_stack_00000058;
  undefined4 in_stack_0000005c;
  undefined4 in_stack_00000060;
  undefined4 in_stack_00000064;
  undefined4 in_stack_00000068;
  undefined4 in_stack_0000006c;
  undefined4 in_stack_00000070;
  undefined *in_stack_00000074;
  undefined4 in_stack_00000078;
  undefined4 in_stack_0000007c;
  undefined4 in_stack_00000080;
  undefined4 in_stack_00000084;
  undefined4 in_stack_00000088;
  undefined4 in_stack_0000008c;
  undefined4 in_stack_00000090;
  undefined *in_stack_00000094;
  undefined4 in_stack_00000098;
  undefined *in_stack_0000009c;
  undefined4 in_stack_000000a0;
  undefined4 in_stack_000000a4;
  undefined *in_stack_000000a8;
  undefined4 in_stack_000000ac;
  undefined *in_stack_000000b0;
  undefined4 in_stack_000000b4;
  undefined4 in_stack_000000b8;
  undefined *in_stack_000000bc;
  undefined4 in_stack_000000c0;
  undefined *in_stack_000000c4;
  undefined4 in_stack_000000c8;
  undefined4 in_stack_000000cc;
  undefined *in_stack_000000d0;
  undefined4 in_stack_000000d4;
  undefined *in_stack_000000d8;
  undefined4 in_stack_000000dc;
  undefined4 in_stack_000000e0;
  undefined *in_stack_000000e4;
  undefined4 in_stack_000000e8;
  undefined *in_stack_000000ec;
  undefined4 in_stack_000000f0;
  undefined4 in_stack_000000f4;
  undefined *in_stack_000000f8;
  undefined4 in_stack_000000fc;
  undefined *in_stack_00000100;
  undefined4 in_stack_00000104;
  undefined4 in_stack_00000108;
  undefined4 in_stack_0000010c;
  undefined4 in_stack_00000110;
  undefined *in_stack_00000114;
  undefined4 in_stack_00000118;
  undefined4 in_stack_0000011c;
  undefined4 in_stack_00000120;
  undefined4 in_stack_00000124;
  undefined4 in_stack_00000128;
  undefined4 in_stack_0000012c;
  undefined4 in_stack_00000130;
  undefined *in_stack_00000134;
  undefined4 in_stack_00000138;
  undefined *in_stack_0000013c;
  undefined4 in_stack_00000140;
  undefined4 in_stack_00000144;
  undefined *in_stack_00000148;
  undefined4 in_stack_0000014c;
  undefined *in_stack_00000150;
  undefined4 in_stack_00000154;
  undefined4 in_stack_00000158;
  undefined *in_stack_0000015c;
  undefined4 in_stack_00000160;
  undefined *in_stack_00000164;
  undefined4 in_stack_00000168;
  undefined4 in_stack_0000016c;
  undefined *in_stack_00000170;
  undefined4 in_stack_00000174;
  undefined *in_stack_00000178;
  undefined4 in_stack_0000017c;
  undefined4 in_stack_00000180;
  undefined *in_stack_00000184;
  undefined4 in_stack_00000188;
  undefined *in_stack_0000018c;
  undefined4 in_stack_00000190;
  undefined4 in_stack_00000194;
  undefined *in_stack_00000198;
  undefined4 in_stack_0000019c;
  undefined *in_stack_000001a0;
  undefined4 in_stack_000001a4;
  undefined4 in_stack_000001a8;
  undefined *in_stack_000001ac;
  undefined4 in_stack_000001b0;
  undefined *in_stack_000001b4;
  undefined4 in_stack_000001b8;
  undefined4 in_stack_000001bc;
  undefined *in_stack_000001c0;
  undefined4 in_stack_000001c4;
  undefined *in_stack_000001c8;
  undefined4 in_stack_000001cc;
  undefined4 in_stack_000001d0;
  undefined *in_stack_000001d4;
  undefined4 in_stack_000001d8;
  undefined *in_stack_000001dc;
  undefined4 in_stack_000001e0;
  undefined4 in_stack_000001e4;
  undefined4 in_stack_000001e8;
  undefined4 in_stack_000001ec;
  undefined *in_stack_000001f0;
  undefined4 in_stack_000001f4;
  char *in_stack_00004258;
  int *in_stack_0000425c;
  
  FUN_0044c080();
  iStack0000000c = 0;
  bVar2 = false;
  uVar8 = 0;
  iVar7 = 0x2a;
  do {
    FUN_00410d50();
    iVar7 = iVar7 + -1;
  } while (iVar7 != 0);
  in_stack_00000014 = 0;
  in_stack_00000018 = 0x464698;
  in_stack_0000001c = &DAT_0046e83c;
  in_stack_00000020 = 0x46467c;
  in_stack_00000024 = &DAT_0046e83c;
  in_stack_00000028 = 1;
  in_stack_0000002c = 0x464674;
  in_stack_00000030 = &DAT_0046e83c;
  in_stack_00000034 = 0x464654;
  in_stack_00000038 = &DAT_0046e83c;
  in_stack_0000003c = 2;
  in_stack_00000040 = 0x46464c;
  in_stack_00000044 = 0x4646b8;
  in_stack_00000048 = 0x464624;
  in_stack_0000004c = 0x4646a0;
  in_stack_00000050 = 0x11;
  in_stack_00000054 = 0x464618;
  in_stack_00000058 = 0x4646b8;
  in_stack_0000005c = 0x4645f8;
  in_stack_00000060 = 0x4646a0;
  in_stack_00000064 = 0x10;
  in_stack_00000068 = 0x4645ec;
  in_stack_0000006c = 0x4645e0;
  in_stack_00000070 = 0x4645c4;
  in_stack_00000074 = &DAT_0046e83c;
  in_stack_00000078 = 3;
  in_stack_0000007c = 0x4645bc;
  in_stack_00000080 = 0x4645ac;
  in_stack_00000084 = 0x46456c;
  in_stack_00000088 = 0x464564;
  in_stack_0000008c = 4;
  in_stack_00000090 = 0x464558;
  in_stack_00000094 = &DAT_0046e83c;
  in_stack_00000098 = 0x46453c;
  in_stack_0000009c = &DAT_0046e83c;
  in_stack_000000a0 = 5;
  in_stack_000000a4 = 0x464530;
  in_stack_000000a8 = &DAT_0046e83c;
  in_stack_000000ac = 0x464510;
  in_stack_000000b0 = &DAT_0046e83c;
  in_stack_000000b4 = 6;
  in_stack_000000b8 = 0x464508;
  in_stack_000000bc = &DAT_0046e83c;
  in_stack_000000c0 = 0x4644f4;
  in_stack_000000c4 = &DAT_0046e83c;
  in_stack_000000c8 = 7;
  in_stack_000000cc = 0x4644ec;
  in_stack_000000d0 = &DAT_0046e83c;
  in_stack_000000d4 = 0x4644d8;
  in_stack_000000d8 = &DAT_0046e83c;
  in_stack_000000dc = 8;
  in_stack_000000e0 = 0x4644d4;
  in_stack_000000e4 = &DAT_0046e83c;
  in_stack_000000e8 = 0x4644c4;
  in_stack_000000ec = &DAT_0046e83c;
  in_stack_000000f0 = 9;
  in_stack_000000f4 = 0x4644c0;
  in_stack_000000f8 = &DAT_0046e83c;
  in_stack_000000fc = 0x4644ac;
  in_stack_00000100 = &DAT_0046e83c;
  in_stack_00000104 = 10;
  in_stack_00000108 = 0x4644a4;
  in_stack_0000010c = 0x46449c;
  in_stack_00000110 = 0x464480;
  in_stack_00000114 = &DAT_0046e83c;
  in_stack_00000118 = 0xb;
  in_stack_0000011c = 0x464478;
  in_stack_00000120 = 0x46446c;
  in_stack_00000124 = 0x464454;
  in_stack_00000128 = 0x46443c;
  in_stack_0000012c = 0xd;
  in_stack_00000130 = 0x464434;
  in_stack_00000134 = &DAT_0046e83c;
  in_stack_00000138 = 0x46440c;
  in_stack_0000013c = &DAT_0046e83c;
  in_stack_00000140 = 0xe;
  in_stack_00000144 = 0x464400;
  in_stack_00000148 = &DAT_0046e83c;
  in_stack_00000150 = &DAT_0046e83c;
  in_stack_0000015c = &DAT_0046e83c;
  in_stack_00000164 = &DAT_0046e83c;
  in_stack_00000170 = &DAT_0046e83c;
  in_stack_00000178 = &DAT_0046e83c;
  in_stack_00000184 = &DAT_0046e83c;
  in_stack_0000018c = &DAT_0046e83c;
  in_stack_00000198 = &DAT_0046e83c;
  in_stack_000001a0 = &DAT_0046e83c;
  in_stack_000001ac = &DAT_0046e83c;
  in_stack_000001b4 = &DAT_0046e83c;
  in_stack_000001c0 = &DAT_0046e83c;
  in_stack_000001c8 = &DAT_0046e83c;
  in_stack_000001d4 = &DAT_0046e83c;
  in_stack_000001dc = &DAT_0046e83c;
  in_stack_000001f0 = &DAT_0046e83c;
  in_stack_0000014c = 0x4643b4;
  in_stack_00000154 = 0xf;
  in_stack_00000158 = 0x4643ac;
  in_stack_00000160 = 0x46438c;
  in_stack_00000168 = 0x16;
  in_stack_0000016c = 0x464384;
  in_stack_00000174 = 0x464360;
  in_stack_0000017c = 0x1b;
  in_stack_00000180 = 0x464354;
  in_stack_00000188 = 0x46432c;
  in_stack_00000190 = 0x17;
  in_stack_00000194 = 0x464320;
  in_stack_0000019c = 0x464314;
  in_stack_000001a4 = 0x18;
  in_stack_000001a8 = 0x46430c;
  in_stack_000001b0 = 0x4642e8;
  in_stack_000001b8 = 0x19;
  in_stack_000001bc = 0x4642dc;
  in_stack_000001c4 = 0x4642b4;
  in_stack_000001cc = 0x1a;
  in_stack_000001d0 = 0x4642b0;
  in_stack_000001d8 = 0x4642a0;
  in_stack_000001e0 = 0x12;
  in_stack_000001e4 = 0x464294;
  in_stack_000001e8 = 0x46428c;
  in_stack_000001ec = 0x464280;
  in_stack_000001f4 = 0x13;
  _DAT_00472158 = 0;
  _DAT_0047219c = 0;
  _DAT_004721a0 = 0;
  _DAT_00473648 = 0;
  _DAT_0047364c = 0;
  iVar7 = 0;
  pcVar4 = &stack0x000002ac;
  if (*in_stack_00004258 != '\0') {
    pcStack00000008 = &stack0x000002ac;
    do {
      if (iVar7 == 0) {
        if ((*in_stack_00004258 == ' ') || (*in_stack_00004258 == '\t')) goto LAB_00411cf0;
        iVar7 = 1;
LAB_00411ca4:
        switch(*in_stack_00004258) {
        case '\t':
        case ' ':
switchD_00411cb9_caseD_9:
          *pcVar4 = '\0';
          iVar7 = 0;
          break;
        default:
          *pcVar4 = *in_stack_00004258;
          break;
        case '/':
          iStack0000000c = iStack0000000c + 1;
          pcVar4 = pcStack00000008;
          pcStack00000008 = pcStack00000008 + 0x184;
          break;
        case ':':
          *pcVar4 = '\0';
          iVar7 = 2;
          pcVar4 = pcStack00000008 + -0x104;
        }
      }
      else {
        if (iVar7 == 1) goto LAB_00411ca4;
        if (iVar7 == 2) {
          cVar1 = *in_stack_00004258;
          if ((cVar1 != '\t') && (cVar1 != ' ')) {
            if (cVar1 == '\"') {
              bVar2 = !bVar2;
            }
            else {
              *pcVar4 = cVar1;
              iVar3 = IsDBCSLeadByte();
              if (iVar3 != 0) {
                pcVar4[1] = in_stack_00004258[1];
              }
            }
            goto LAB_00411cf0;
          }
          if (bVar2) {
            *pcVar4 = cVar1;
            goto LAB_00411cf0;
          }
          goto switchD_00411cb9_caseD_9;
        }
      }
LAB_00411cf0:
      if (*pcVar4 != '\0') {
        pcVar4 = (char *)CharNextA();
      }
      in_stack_00004258 = (char *)CharNextA();
    } while (*in_stack_00004258 != '\0');
  }
  if (pcVar4 != (char *)0x0) {
    *pcVar4 = '\0';
  }
  if (0 < iStack0000000c) {
    pcStack00000008 = (char *)iStack0000000c;
    pcVar4 = &stack0x0000032c + (iStack0000000c + -1) * 0x184;
    do {
      iVar7 = 0;
      do {
        iVar3 = lstrcmpiA();
        if (iVar3 == 0) {
          if (iVar7 < 0x1e) {
            switch((&stack0x00000014)[iVar7 * 5]) {
            case 0:
              _DAT_00472158 = 1;
              break;
            case 1:
              _DAT_00472150 = 1;
              break;
            case 2:
              lstrcpyA();
              break;
            case 3:
              if ((*pcVar4 == '\0') || (*in_stack_0000425c != 0)) {
                *in_stack_0000425c = 1;
              }
              else if ((pcVar4 == (char *)0x0) || (iVar7 = lstrlenA(), iVar7 == 0)) {
                iVar7 = lstrlenA();
                if (iVar7 == 0) {
                  lstrcpyA();
                }
                else {
                  lstrcpyA();
                }
              }
              else {
                lstrcpyA();
                puVar5 = (undefined *)FUN_0040d4c0();
                if (((puVar5 != (undefined *)0x0) && (pcVar6 = (char *)CharNextA(), *pcVar6 == '\0')
                    ) && (pcVar6 = (char *)CharPrevA(), *pcVar6 != ':')) {
                  *puVar5 = 0;
                }
              }
              break;
            case 4:
              _DAT_00472198 = 1;
              _DAT_0047219c = 1;
              *in_stack_0000425c = 1;
              break;
            case 5:
              _DAT_004721a0 = 1;
              *in_stack_0000425c = 1;
              break;
            case 6:
              uVar8 = uVar8 | 0x1000;
              break;
            case 7:
              uVar8 = uVar8 | 0x2000;
              break;
            case 8:
              uVar8 = uVar8 | 0x4000;
              break;
            case 9:
              uVar8 = uVar8 | 0x8000;
              break;
            case 10:
              lstrcpyA();
              break;
            case 0xb:
              lstrcpyA();
              break;
            case 0xd:
              _DAT_004721d8 = 1;
              break;
            case 0xe:
              _DAT_004721dc = 1;
              break;
            case 0xf:
              _DAT_004721e0 = 1;
              break;
            case 0x15:
              _DAT_004734d0 = 1;
              break;
            case 0x16:
              if (_DAT_004721b0 == 0) {
                _DAT_004721ac = 1;
              }
              else {
                _DAT_004721b4 = 1;
              }
              break;
            case 0x17:
              lstrcpyA();
              break;
            case 0x18:
              _DAT_004734bc = 1;
              break;
            case 0x1b:
              _DAT_00473648 = 1;
              break;
            case 0x1c:
              FUN_0040e750();
              _DAT_0047364c = OpenEventA();
              SetEvent();
              break;
            case 0x1d:
              lstrcpyA();
              iVar7 = lstrlenA();
              if ((&stack0x00000267)[iVar7] == 'C') {
                iVar7 = lstrlenA();
                (&stack0x00000267)[iVar7] = 0;
                _DAT_004734e0 = 1;
              }
              _DAT_004734dc = FUN_0044bab9();
            }
          }
          break;
        }
        iVar7 = iVar7 + 1;
      } while (iVar7 < 0x1e);
      pcVar4 = pcVar4 + -0x184;
      pcStack00000008 = (char *)((int)pcStack00000008 + -1);
    } while (pcStack00000008 != (char *)0x0);
  }
  _DAT_00472160 = uVar8;
  _DAT_00472164 = 0;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_004128f0(int param_1)

{
  ushort uVar1;
  int iVar2;
  int iVar3;
  short *psVar4;
  undefined4 *puVar5;
  int iStack_114;
  undefined auStack_108 [4];
  undefined4 uStack_104;
  undefined4 auStack_100 [64];
  
  psVar4 = _DAT_00473c2c;
  uStack_104 = _DAT_004646e4;
  puVar5 = auStack_100;
  for (iVar3 = 0x40; iVar3 != 0; iVar3 = iVar3 + -1) {
    *puVar5 = 0;
    puVar5 = puVar5 + 1;
  }
  if ((param_1 == 0) && (iVar3 = lstrcmpiA(&DAT_004721e8,0x473c34), iVar3 == 0)) {
    return;
  }
  lstrcpyA(0x473c34,&DAT_004721e8);
  FUN_00414650(1,0);
  iVar3 = FUN_0040d0e0(&DAT_004721e8);
  DAT_00473ae9 = DAT_004721e8;
  CharUpperA(&DAT_00473ae9);
  if (psVar4 != (short *)0x0) {
    do {
      FUN_0040d420();
      if ((*psVar4 == 10) && (uVar1 = psVar4[8], (uVar1 & 1) != 0)) {
        if ((iVar3 != 0) || ((uVar1 & 0x10) == 0)) {
          if ((uVar1 & 0x20) == 0) {
            FUN_0041a7e0(psVar4 + 0x24,auStack_108,0x104);
            FUN_0041c010(auStack_108,psVar4 + 0x16,0);
            goto LAB_00412a2c;
          }
          iVar2 = FUN_00412fe0(psVar4 + 0x24,&stack0xfffffee0);
          psVar4[8] = (ushort)(iVar2 == 0) << 2 | psVar4[8] & 0xfffbU;
          if ((iVar2 == 0) || (iStack_114 == 0)) {
            iVar2 = 0;
          }
          else {
            iVar2 = 1;
          }
          psVar4[9] = (ushort)(iVar2 << 2) | psVar4[9] & 0xfffbU;
        }
        *(undefined4 *)(psVar4 + 0x16) = 0;
      }
LAB_00412a2c:
      psVar4 = *(short **)(psVar4 + 0x1c);
    } while (psVar4 != (short *)0x0);
  }
  FUN_00414650(0,0);
  return;
}



undefined4 FUN_00412fa0(char *param_1)

{
  int iVar1;
  
  if ((param_1 != (char *)0x0) && (iVar1 = lstrlenA(param_1), 0 < iVar1)) {
    for (; *param_1 != '\0'; param_1 = (char *)CharNextA(param_1)) {
      if (*param_1 == '|') {
        return 1;
      }
    }
  }
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

bool FUN_00412fe0(uint *param_1,int param_2)

{
  char cVar1;
  bool bVar2;
  int iVar3;
  char *pcVar4;
  char *pcVar5;
  uint uVar6;
  float10 fVar7;
  float10 fVar8;
  char acStack_288 [64];
  char acStack_248 [64];
  undefined auStack_208 [260];
  undefined auStack_104 [260];
  
  bVar2 = false;
  FUN_0041a870((int)param_1 + 0x1e,auStack_104,0x104);
  FUN_0041a7e0(param_1,auStack_208,0x104);
  if ((*(byte *)(param_1 + 6) & 0x20) != 0) {
    FUN_0041c010(auStack_208,param_2 + 0xc,0);
    iVar3 = FUN_0041f430(auStack_104,acStack_288,0);
    if (iVar3 == 0) {
      FUN_0044c3c3(acStack_288,0x464718,(double)(ulonglong)*param_1 * 0.0001);
      fVar7 = (float10)FUN_0044d0f6(acStack_288);
      if (fVar7 == (float10)0.0) {
        return false;
      }
    }
    iVar3 = FUN_0041f430(auStack_208,acStack_248,0);
    if (iVar3 != 0) {
      pcVar4 = acStack_288;
      pcVar5 = acStack_248;
      while( true ) {
        cVar1 = *pcVar4;
        while ((cVar1 != '\0' && (iVar3 = FUN_0044c373(), iVar3 == 0))) {
          pcVar4 = (char *)CharNextA();
          cVar1 = *pcVar4;
        }
        cVar1 = *pcVar5;
        while ((cVar1 != '\0' && (iVar3 = FUN_0044c373(), iVar3 == 0))) {
          pcVar5 = (char *)CharNextA();
          cVar1 = *pcVar5;
        }
        fVar7 = (float10)FUN_0044d0f6();
        fVar8 = (float10)FUN_0044d0f6(pcVar5);
        if (fVar8 < (float10)(double)fVar7) break;
        iVar3 = FUN_00412fa0();
        if (iVar3 != 0) {
          cVar1 = *pcVar4;
          while (cVar1 != '|') {
            pcVar4 = (char *)CharNextA();
            cVar1 = *pcVar4;
          }
        }
        iVar3 = FUN_00412fa0();
        if (iVar3 != 0) {
          cVar1 = *pcVar5;
          while (cVar1 != '|') {
            pcVar5 = (char *)CharNextA();
            cVar1 = *pcVar5;
          }
        }
        iVar3 = FUN_00412fa0();
        if (iVar3 == 0) {
          return false;
        }
      }
    }
    return true;
  }
  uVar6 = FUN_0041ea10(auStack_104,param_1,auStack_208,param_2,1);
  if ((uVar6 & 7) != 0) {
    if ((uVar6 & 1) == 0) {
      bVar2 = false;
    }
    else {
      *(undefined4 *)(param_2 + 0xc) = 0;
      bVar2 = true;
    }
  }
  if ((uVar6 & 7) == 0) {
    if ((uVar6 & 0x40) == 0) {
      if ((uVar6 & 0x20) != 0) {
        return true;
      }
      if (((uVar6 & 0x10) != 0) && ((uVar6 & 0x400) != 0)) {
        return true;
      }
      if ((uVar6 & 0x100) == 0) {
        if ((uVar6 & 0x400) != 0) {
          return true;
        }
        if (((_DAT_00473504 != 0) && ((uVar6 & 0x200) != 0)) &&
           (((uVar6 & 8) != 0 || ((uVar6 & 0x10) != 0)))) {
          return true;
        }
      }
      else if (param_1[2] != 0) {
        iVar3 = FUN_004132c0(*(undefined4 *)(param_2 + 8),param_1[2]);
        return iVar3 == 6;
      }
    }
    bVar2 = false;
  }
  return bVar2;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_004132c0(uint param_1)

{
  uint *puVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  undefined4 *puVar5;
  undefined4 uStack_118;
  uint uStack_114;
  undefined *puStack_110;
  undefined4 uStack_10c;
  undefined auStack_98 [24];
  undefined auStack_80 [124];
  uint uStack_4;
  
  iVar2 = _DAT_00473c28;
  if (_DAT_00473c28 == 0) {
    if (_DAT_00473d3c == 0) {
      _DAT_00473d3c = 1;
      puVar5 = (undefined4 *)0x473760;
      for (iVar2 = 10; iVar2 != 0; iVar2 = iVar2 + -1) {
        *puVar5 = 0;
        puVar5 = puVar5 + 1;
      }
    }
    iVar2 = 0;
    puVar1 = (uint *)0x473760;
    do {
      if (*puVar1 == 0) break;
      if (*puVar1 == param_1) {
        return *(int *)(iVar2 * 4 + 0x473620);
      }
      puVar1 = puVar1 + 1;
      iVar2 = iVar2 + 1;
    } while ((int)puVar1 < 0x473788);
    puStack_110 = auStack_80;
    uStack_10c = 0x80;
    uStack_114 = param_1 & 0xffff;
    uStack_118 = 0x413338;
    VerLanguageNameA();
    uStack_118 = 0x80;
    VerLanguageNameA(uStack_4 & 0xffff,&uStack_10c);
    iVar2 = FUN_0040d270(_DAT_004721c8,0x34,0xfa,auStack_98,&uStack_118);
    iVar4 = 0;
    piVar3 = (int *)0x473760;
    while (*piVar3 != 0) {
      piVar3 = piVar3 + 1;
      iVar4 = iVar4 + 1;
      if (0x473787 < (int)piVar3) {
        return iVar2;
      }
    }
    if (iVar4 < 10) {
      *(uint *)(iVar4 * 4 + 0x473760) = param_1;
      *(int *)(iVar4 * 4 + 0x473620) = iVar2;
    }
  }
  return iVar2;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_004133d0(undefined *param_1)

{
  undefined4 uVar1;
  int iVar2;
  undefined4 uStack_518;
  undefined auStack_514 [260];
  undefined auStack_410 [260];
  undefined auStack_30c [260];
  undefined auStack_208 [260];
  undefined auStack_104 [260];
  
  *param_1 = 0;
  uStack_518 = 0x104;
  FUN_0040e750(_DAT_004721c0,0x7e9,auStack_514,0x104);
  FUN_0040dc60(auStack_514,0x104);
  FUN_00414f60(auStack_514,auStack_208,0x5c);
  FUN_00415030(auStack_514,auStack_30c,0x5c);
  FUN_004150c0(auStack_514,auStack_104,0x5c);
  uVar1 = FUN_00414e30(auStack_208);
  iVar2 = FUN_0041dd60(uVar1,auStack_104,auStack_30c,auStack_410,&uStack_518);
  if (iVar2 == 0) {
    FUN_004105e0(auStack_410,0x104);
    lstrcpyA(param_1,auStack_410);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_004134c0(void)

{
  int iVar1;
  undefined auStack_208 [252];
  undefined auStack_10c [4];
  undefined auStack_108 [260];
  int iStack_4;
  
  FUN_004133d0(auStack_208);
  iVar1 = lstrlenA(auStack_208);
  if (iVar1 != 0) {
    FUN_0040f8a0(&stack0xfffffdf4);
    FUN_0040e750(_DAT_004721c0,0x7ea,auStack_108,0x104);
    lstrcatA(&stack0xfffffdf4,auStack_108);
    iVar1 = FUN_0040d0e0(&stack0xfffffdf4);
    if (iVar1 != 0) {
      FUN_0040e750(_DAT_004721c0,0x7f0,auStack_108,0x104);
      iVar1 = lstrlenA(auStack_108);
      if (iVar1 == 0) {
        iVar1 = FUN_0041bc20(&stack0xfffffdf0);
        if ((iVar1 != -1) && (iStack_4 != 0)) {
          return 1;
        }
        return 0;
      }
      iVar1 = FUN_0040e500(&stack0xfffffdf0,auStack_10c);
      if (iVar1 != 0) {
        return 1;
      }
    }
  }
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

uint FUN_004135e0(int param_1)

{
  uint uVar1;
  int iVar2;
  undefined auStack_300 [256];
  char acStack_200 [256];
  undefined auStack_100 [256];
  
  FUN_0040e750(_DAT_004721c0,0x11,auStack_300,0x100);
  FUN_0041dc40(auStack_300,&DAT_0046409c,acStack_200,0x100);
  if (acStack_200[0] != '1') {
    return 0;
  }
  if (param_1 != 0) {
    FUN_0040e750(_DAT_004721c0,0x7d1,auStack_300,0x100);
    FUN_0041dc40(auStack_300,&DAT_0046e83c,auStack_100,0x100);
    FUN_0040e750(_DAT_004721c0,0x7d2,auStack_300,0x100);
    wsprintfA(acStack_200,0x464720,auStack_100,auStack_300);
    if (_DAT_004734c4 != 0) {
      uVar1 = FUN_004134c0(acStack_200[0] == '1');
      return uVar1;
    }
    iVar2 = FUN_0041bc20(acStack_200);
    return (uint)(iVar2 != -1);
  }
  return 1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_004139c0(undefined4 param_1,int param_2)

{
  uint *puVar1;
  int iVar2;
  uint uVar3;
  uint *puVar4;
  uint *puVar5;
  undefined4 unaff_EDI;
  int iVar6;
  uint *puStack_158;
  uint *puStack_154;
  uint *puStack_150;
  uint *puStack_14c;
  undefined4 *puStack_148;
  int iStack_144;
  undefined4 uStack_140;
  undefined4 uStack_13c;
  uint *puStack_138;
  undefined uStack_134;
  undefined uStack_133;
  undefined uStack_132;
  undefined uStack_131;
  undefined uStack_130;
  undefined uStack_12f;
  undefined uStack_12e;
  undefined uStack_12d;
  uint uStack_120;
  uint uStack_11c;
  int iStack_118;
  undefined4 uStack_114;
  undefined4 auStack_108 [57];
  int iStack_24;
  undefined4 uStack_14;
  uint *puStack_10;
  
  uStack_11c = _DAT_00472184 << 2;
  uStack_130 = (undefined)unaff_EDI;
  uStack_12f = (undefined)((uint)unaff_EDI >> 8);
  uStack_12e = (undefined)((uint)unaff_EDI >> 0x10);
  uStack_12d = (undefined)((uint)unaff_EDI >> 0x18);
  puVar5 = (uint *)0x0;
  uStack_134 = (undefined)uStack_11c;
  uStack_133 = (undefined)(uStack_11c >> 8);
  uStack_132 = (undefined)(uStack_11c >> 0x10);
  uStack_131 = (undefined)(uStack_11c >> 0x18);
  auStack_108[0] = 0;
  iStack_118 = 0;
  uStack_114 = 0;
  puStack_138 = (uint *)0x4139ea;
  puVar1 = (uint *)FUN_0044c5a2();
  puVar4 = puVar1;
  for (uVar3 = uStack_11c >> 2; uVar3 != 0; uVar3 = uVar3 - 1) {
    *puVar4 = 0;
    puVar4 = puVar4 + 1;
  }
  for (uVar3 = uStack_11c & 3; uVar3 != 0; uVar3 = uVar3 - 1) {
    *(undefined *)puVar4 = 0;
    puVar4 = (uint *)((int)puVar4 + 1);
  }
  uStack_134 = (undefined)param_1;
  uStack_133 = (undefined)((uint)param_1 >> 8);
  uStack_132 = (undefined)((uint)param_1 >> 0x10);
  uStack_131 = (undefined)((uint)param_1 >> 0x18);
  puStack_138 = (uint *)0x413a15;
  puStack_138 = (uint *)lstrlenA();
  uStack_13c = param_1;
  uStack_140 = 0;
  iStack_144 = 0x413a1d;
  uVar3 = FUN_00420b50();
  puStack_148 = auStack_108;
  iStack_144 = 0x104;
  puStack_14c = (uint *)0x25;
  puStack_150 = _DAT_004721c0;
  puStack_154 = (uint *)0x413a37;
  FUN_0040e750();
  puStack_154 = &uStack_120;
  puStack_158 = puVar1;
  iVar2 = FUN_0041dd60(0x80000002,0x472b94,auStack_108);
  puVar4 = puVar1;
  if (iVar2 == 0) {
    uStack_11c = uStack_120;
    for (; uStack_120 != 0; uStack_120 = uStack_120 - 4) {
      if (*puVar4 == uVar3) {
        iStack_118 = 1;
        break;
      }
      if (*puVar4 == 0) {
        puVar5 = puVar4;
      }
      puVar4 = puVar4 + 1;
    }
  }
  if ((param_2 != 0) && (iStack_118 != 0)) {
    uStack_13c = 0x413a9f;
    puStack_138 = puVar1;
    FUN_0044c4b9();
    return 0;
  }
  if ((puVar5 == (uint *)0x0) && (puVar5 = puVar4, param_2 != 0)) {
    uStack_11c = uStack_11c + 4;
  }
  puStack_138 = (uint *)&stack0xfffffedc;
  uStack_13c = 0x2001f;
  uStack_140 = 0;
  iStack_144 = 0x472d9c;
  puStack_148 = (undefined4 *)0x80000002;
  *puVar5 = -(uint)(param_2 != 0) & uVar3;
  puStack_14c = (uint *)0x413ae3;
  iVar2 = RegOpenKeyExA();
  if (iVar2 != 0) {
    puStack_150 = (uint *)0x413aed;
    puStack_14c = puVar1;
    FUN_0044c4b9();
    return 0;
  }
  if (puStack_10 == (uint *)0x0) {
    puStack_10 = &uStack_120;
  }
  puStack_14c = (uint *)&stack0xfffffed8;
  puStack_150 = &uStack_11c;
  puStack_154 = (uint *)&stack0xfffffedc;
  puStack_158 = (uint *)0x0;
  iVar2 = RegQueryValueExA(puStack_138,uStack_14);
  if (iVar2 == 0) {
    switch(uStack_13c) {
    case 1:
      uVar3 = FUN_0044bab9(&uStack_134);
      *puStack_10 = uVar3;
      break;
    default:
      *puStack_10 = 0;
      break;
    case 3:
      *puStack_10 = (((CONCAT12(uStack_12f,CONCAT11(uStack_130,uStack_131)) & 0xff) * 0x100 +
                     (CONCAT12(uStack_130,CONCAT11(uStack_131,uStack_132)) & 0xff)) * 0x100 +
                    (CONCAT12(uStack_131,CONCAT11(uStack_132,uStack_133)) & 0xff)) * 0x100 +
                    (CONCAT12(uStack_132,CONCAT11(uStack_133,uStack_134)) & 0xff);
      break;
    case 4:
      *puStack_10 = CONCAT13(uStack_131,CONCAT12(uStack_132,CONCAT11(uStack_133,uStack_134)));
      break;
    case 5:
      *puStack_10 = (((CONCAT12(uStack_132,CONCAT11(uStack_133,uStack_134)) & 0xff) * 0x100 +
                     (CONCAT12(uStack_131,CONCAT11(uStack_132,uStack_133)) & 0xff)) * 0x100 +
                    (CONCAT12(uStack_130,CONCAT11(uStack_131,uStack_132)) & 0xff)) * 0x100 +
                    (CONCAT12(uStack_12f,CONCAT11(uStack_130,uStack_131)) & 0xff);
    }
  }
  if (iStack_24 == 0) {
    if (iStack_144 == 0) {
      FUN_0044c4b9(puVar1);
      RegCloseKey(puStack_150);
      return 0;
    }
  }
  else if (iStack_24 == 1) {
    iVar2 = 1;
    goto LAB_00413c2b;
  }
  iVar2 = -(uint)(*puStack_10 != 0);
LAB_00413c2b:
  iVar6 = 4;
  *puStack_10 = *puStack_10 + iVar2;
  puVar5 = puStack_10;
  RegSetValueExA(puStack_150,uStack_14,0,4,puStack_10,4);
  if (*puStack_10 == 0) {
    RegDeleteValueA(puVar5,uStack_14);
  }
  RegCloseKey(puVar5);
  lstrcpyA(&puStack_150,0x472b94);
  lstrcatA(&puStack_150,0x463be4);
  puVar5 = _DAT_004721c0;
  iVar2 = lstrlenA(&puStack_150);
  iVar2 = lstrlenA(&puStack_154,0x104 - iVar2);
  FUN_0040e750(puVar5,0x25,(int)&puStack_158 + iVar2);
  FUN_0041de30(0x80000002,&puStack_158,puVar1,-iVar6);
  FUN_0044c4b9(puVar1);
  return 1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_00413d00(undefined4 param_1,undefined4 param_2)

{
  int iVar1;
  int iVar2;
  undefined4 *puVar3;
  char acStack_30c [260];
  char cStack_208;
  undefined4 uStack_207;
  undefined auStack_104 [260];
  
  cStack_208 = DAT_0046e83c;
  puVar3 = &uStack_207;
  for (iVar1 = 0x40; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar3 = 0;
    puVar3 = puVar3 + 1;
  }
  *(undefined2 *)puVar3 = 0;
  *(undefined *)((int)puVar3 + 2) = 0;
  iVar1 = FUN_004146e0();
  if (iVar1 == 0) {
    FUN_0040e750(_DAT_004721c0,param_1,acStack_30c,0x104);
    FUN_0040dc60(acStack_30c,0x104);
    iVar1 = FUN_00410890(acStack_30c);
    lstrcpyA(auStack_104,acStack_30c);
    if (iVar1 == 0) {
      FUN_0040e750(_DAT_004721c0,0x7d1,acStack_30c,0x104);
      FUN_0041dc40(acStack_30c,&DAT_0046e83c,&cStack_208,0x104);
      lstrcpyA(acStack_30c,auStack_104);
      wsprintfA(auStack_104,0x464720,&cStack_208,acStack_30c);
      iVar2 = 0x8c;
      iVar1 = FUN_0041bc20(auStack_104);
      if (iVar1 == -1) {
        return 0;
      }
    }
    else {
      iVar1 = FUN_0040f810();
      iVar2 = (iVar1 != 0) + 0xfc;
    }
    FUN_0040e750(_DAT_004721c0,param_2,acStack_30c,0x104);
    iVar1 = FUN_0040eef0(_DAT_004721c8,auStack_104,
                         -(uint)(acStack_30c[0] != '\0') & (uint)acStack_30c,
                         -(uint)(cStack_208 != '\0') & (uint)&cStack_208,1,0xfafbfcfd,0,iVar2,0,0,0,
                         0,0,0,0,0,0);
    if (iVar1 != 0x2716) {
      return 1;
    }
  }
  else {
    FUN_0040d270(_DAT_004721c8,0x10,0x136);
  }
  return 0;
}



undefined4 FUN_00413f80(undefined4 param_1)

{
  int iVar1;
  undefined4 unaff_ESI;
  undefined4 *puVar2;
  undefined4 uVar3;
  undefined *puStack_368;
  undefined4 auStack_358 [7];
  undefined auStack_33c [48];
  undefined auStack_30c [252];
  undefined auStack_210 [8];
  undefined auStack_208 [252];
  undefined auStack_10c [8];
  undefined auStack_104 [260];
  
  puStack_368 = auStack_30c;
  FUN_0041bd80(0);
  iVar1 = FUN_00410910(auStack_30c,auStack_208,0x104);
  if (iVar1 == 0) {
    puStack_368 = auStack_208;
    lstrcpyA();
  }
  puStack_368 = auStack_30c;
  auStack_30c[0] = 0;
  FUN_004140f0(auStack_208);
  iVar1 = FUN_0041feb0(auStack_208,auStack_30c,0);
  if (iVar1 != 0) {
    return 0;
  }
  puStack_368 = (undefined *)0x80;
  FUN_0041bf00(auStack_30c);
  puStack_368 = auStack_208;
  wsprintfA(auStack_104,0x464764,auStack_30c,param_1);
  puStack_368 = (undefined *)0x104;
  GetWindowsDirectoryA(auStack_208);
  FUN_0041be10(auStack_210);
  puVar2 = auStack_358;
  for (iVar1 = 0x11; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  uVar3 = 0;
  auStack_358[0] = 0x44;
  iVar1 = CreateProcessA(0,auStack_10c,0,0,0,0x4000208,0,auStack_210,auStack_358,&puStack_368);
  if (iVar1 == 0) {
    FUN_0041bce0(auStack_33c);
    return 0;
  }
  CloseHandle(uVar3);
  CloseHandle(unaff_ESI);
  return 1;
}



// WARNING: Removing unreachable block (ram,0x00414268)
// WARNING: Removing unreachable block (ram,0x0041426e)
// WARNING: Removing unreachable block (ram,0x00414272)
// WARNING: Removing unreachable block (ram,0x0041430b)
// WARNING: Removing unreachable block (ram,0x0041431a)
// WARNING: Removing unreachable block (ram,0x00414320)
// WARNING: Removing unreachable block (ram,0x00414328)
// WARNING: Removing unreachable block (ram,0x00414339)
// WARNING: Removing unreachable block (ram,0x00414344)
// WARNING: Removing unreachable block (ram,0x00414350)
// WARNING: Removing unreachable block (ram,0x0041435e)
// WARNING: Removing unreachable block (ram,0x00414366)
// WARNING: Removing unreachable block (ram,0x0041436b)
// WARNING: Removing unreachable block (ram,0x00414373)
// WARNING: Removing unreachable block (ram,0x00414375)
// WARNING: Removing unreachable block (ram,0x00414381)
// WARNING: Removing unreachable block (ram,0x00414377)

int FUN_004140f0(char *param_1,char *param_2,int param_3)

{
  int iVar1;
  undefined4 uVar2;
  char *pcVar3;
  char *pcVar4;
  char cVar5;
  int unaff_EBP;
  bool bVar6;
  int iStack_228;
  int iStack_220;
  uint uStack_21c;
  int aiStack_218 [2];
  undefined auStack_210 [4];
  undefined auStack_20c [4];
  undefined auStack_208 [252];
  undefined auStack_10c [8];
  undefined auStack_104 [260];
  
  iStack_220 = 1;
  uStack_21c = (uint)(*param_2 == '\0');
  if ((param_3 == 0) && (iVar1 = FUN_0041c010(param_1,auStack_20c,0), iVar1 == 0)) {
    uVar2 = GetLastError(0x10,0);
    FUN_0040ed20(uVar2);
    return 0;
  }
  FUN_0041bc60(0x104,auStack_104);
  iVar1 = FUN_0040d4c0(param_2);
  pcVar3 = param_2;
  if (iVar1 != 0) {
    pcVar3 = (char *)CharNextA(iVar1);
  }
  iVar1 = FUN_0040d4c0(param_1);
  pcVar4 = param_1;
  if (iVar1 != 0) {
    pcVar4 = (char *)CharNextA(iVar1);
  }
  if (*param_2 != '\0') {
    pcVar4 = pcVar3;
  }
  lstrcpyA(auStack_208,pcVar4);
  GetTempPathA(0x104,param_2);
  FUN_0040f8a0(param_2);
  FUN_0040f760(&stack0xfffffdd0,param_2,4);
  uStack_21c = 0;
  do {
    if (unaff_EBP != 0) break;
    bVar6 = uStack_21c != 0;
    cVar5 = 'A';
    do {
      iVar1 = FUN_0041bca0(&stack0xfffffdd0);
      if (3 - (uint)bVar6 == iVar1) {
        pcVar3 = param_2;
        if (iStack_228 == 0) {
          pcVar3 = &stack0xfffffdd0;
        }
        FUN_0041be10(pcVar3);
        aiStack_218[0] = 0;
        iStack_220 = 0;
        FUN_0040e5a0(&stack0xfffffdd0,&iStack_220,aiStack_218);
        if (param_1 <= (char *)(aiStack_218[0] * iStack_220)) {
          iVar1 = GetTempPathA(0x104,param_2);
          FUN_0040f8a0(param_2);
          if ((iVar1 != 0) && (lstrcatA(param_2,auStack_210), iVar1 != 0)) {
            SetFileAttributesA(param_2,0x80);
            FUN_0041bce0(param_2);
            unaff_EBP = 1;
            break;
          }
        }
      }
      cVar5 = cVar5 + '\x01';
      iStack_228 = 0;
    } while (cVar5 < '[');
    uStack_21c = uStack_21c + 1;
  } while ((int)uStack_21c < 2);
  FUN_0041be10(auStack_10c);
  return unaff_EBP;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_004143b0(undefined4 param_1)

{
  undefined4 uStack_408;
  undefined uStack_404;
  undefined auStack_400 [1024];
  
  uStack_404 = 0;
  auStack_400[0] = 0;
  uStack_408 = 0x1b;
  lstrcpyA(auStack_400,param_1);
  (*_DAT_004721e4)(&uStack_408);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_004143f0(undefined4 param_1)

{
  undefined auStack_400 [1024];
  
  auStack_400[0] = 0;
  FUN_0040e750(_DAT_004721c0,param_1,auStack_400,0x400,0x1b,0);
  FUN_004143b0(auStack_400);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00414650(int param_1,int param_2)

{
  if (_DAT_00473d40 == 0) {
    _DAT_00473d40 = CreateMutexA(0,0,0x464798);
  }
  if (param_1 == 0) {
    ReleaseMutex(_DAT_00473d40);
  }
  else {
    MsgWaitForMultipleObjects(1,&DAT_00473d40,0,0xffffffff,0xff);
    if (param_2 != 0) {
      CloseHandle(_DAT_00473d40);
      _DAT_00473d40 = 0;
      return;
    }
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_004146b0(void)

{
  if (_DAT_004721b0 == 0) {
    _DAT_004721ac = 1;
  }
  else {
    _DAT_004721b4 = 1;
  }
  FUN_00414890();
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_004146e0(void)

{
  return _DAT_004721ac;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_00414760(void)

{
  int iVar1;
  undefined4 uVar2;
  undefined *puVar3;
  undefined auStack_14 [4];
  undefined4 uStack_10;
  
  iVar1 = IsWindow(_DAT_004721c8);
  if (iVar1 != 0) {
    ShowWindow(_DAT_004721c8,0);
  }
  puVar3 = auStack_14;
  uVar2 = GetCurrentProcess(0x28,puVar3);
  iVar1 = OpenProcessToken(uVar2);
  if (iVar1 != 0) {
    LookupPrivilegeValueA(0,0x4647c0,&stack0xffffffe8);
    uStack_10 = 2;
    AdjustTokenPrivileges(puVar3,0,&stack0xffffffe4,0,0,0);
    GetLastError();
  }
  iVar1 = ExitWindowsEx(2,0);
  if (iVar1 == 0) {
    uVar2 = GetLastError(0);
    FUN_0041b3e0(uVar2);
    _DAT_00472148 = 0;
    iVar1 = IsWindow(_DAT_004721c8);
    FUN_0040d2e0(-(uint)(iVar1 != 0) & _DAT_004721c8,0x10,0x4732ac);
  }
  return 1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00414890(void)

{
  undefined4 uVar1;
  int iVar2;
  undefined auStack_208 [252];
  undefined auStack_10c [268];
  
  lstrcpyA(auStack_208,&DAT_004721e8);
  FUN_0040f8a0(auStack_208);
  uVar1 = _DAT_004721c0;
  iVar2 = lstrlenA(auStack_208);
  iVar2 = lstrlenA(&stack0xfffffdf4,0x104 - iVar2);
  FUN_0040e750(uVar1,0x16f,auStack_208 + iVar2 + -8);
  iVar2 = FUN_00410910(&stack0xfffffdf0,auStack_10c,0x104);
  if (iVar2 == 0) {
    lstrcpyA(&stack0xfffffdf0,0x463344);
    FUN_0040f8a0(&stack0xfffffdf0);
    lstrcatA(&stack0xfffffdf0,0x463fe0);
    FUN_0040dc60(&stack0xfffffdf0,0x104);
    iVar2 = FUN_00410910(&stack0xfffffdf0,auStack_10c,0x104);
    if (iVar2 == 0) {
      return;
    }
  }
  lstrcatA(auStack_10c,0x464810);
  FUN_0041de30(0x80000002,0x4647d4,auStack_10c,1);
  return;
}



undefined4 FUN_00414de0(int param_1,uint param_2,uint param_3,uint param_4,uint param_5)

{
  if (param_1 == 0) {
    param_2 = param_2 & param_4;
    param_3 = param_3 & param_5;
  }
  else if ((param_2 & param_4 | param_3 & param_5) == 0) {
    param_2 = 1;
    param_3 = 0;
  }
  else {
    param_2 = 0;
    param_3 = 0;
  }
  if ((param_2 | param_3) != 0) {
    return 1;
  }
  return 0;
}



undefined4 FUN_00414e30(undefined4 param_1)

{
  int iVar1;
  
  iVar1 = lstrcmpiA(param_1,0x4648dc);
  if (iVar1 == 0) {
    return 0x80000002;
  }
  iVar1 = lstrcmpiA(param_1,0x4648d4);
  if (iVar1 == 0) {
    return 0x80000002;
  }
  iVar1 = lstrcmpiA(param_1,0x4648c0);
  if (iVar1 == 0) {
    return 0x80000002;
  }
  iVar1 = lstrcmpiA(param_1,0x4648b8);
  if (iVar1 == 0) {
    return 0x80000001;
  }
  iVar1 = lstrcmpiA(param_1,0x4648a4);
  if (iVar1 == 0) {
    return 0x80000001;
  }
  iVar1 = lstrcmpiA(param_1,0x46489c);
  if (iVar1 == 0) {
    return 0x80000000;
  }
  iVar1 = lstrcmpiA(param_1,0x464888);
  if (iVar1 == 0) {
    return 0x80000000;
  }
  iVar1 = lstrcmpiA(param_1,0x464884);
  if (iVar1 != 0) {
    iVar1 = lstrcmpiA(param_1,0x464878);
    if (iVar1 == 0) {
      return 0x80000003;
    }
    iVar1 = lstrcmpiA(param_1,0x464870);
    if (iVar1 == 0) {
      return 0x80000005;
    }
    iVar1 = lstrcmpiA(param_1,0x46485c);
    if (iVar1 == 0) {
      return 0x80000005;
    }
    iVar1 = lstrcmpiA(param_1,0x464854);
    if ((iVar1 != 0) && (iVar1 = lstrcmpiA(param_1,0x464844), iVar1 != 0)) {
      return 0;
    }
    return 0x80000006;
  }
  return 0x80000003;
}



int FUN_00414f60(char *param_1,char *param_2,char param_3)

{
  char cVar1;
  int iVar2;
  
  iVar2 = 0;
  cVar1 = *param_1;
  if (param_3 == cVar1) {
    *param_2 = '\0';
    return 0;
  }
  do {
    if (cVar1 == '\0') break;
    *param_2 = cVar1;
    param_1 = (char *)CharNextA(param_1);
    param_2 = (char *)CharNextA(param_2);
    cVar1 = *param_1;
    iVar2 = iVar2 + 1;
  } while (param_3 != cVar1);
  *param_2 = '\0';
  return iVar2;
}



int FUN_00415030(char *param_1,char *param_2,char param_3)

{
  char cVar1;
  char *pcVar2;
  char *pcVar3;
  int iStack_4;
  
  pcVar3 = (char *)0x0;
  cVar1 = *param_1;
  iStack_4 = 0;
  while (pcVar2 = param_1, cVar1 != '\0') {
    while ((param_3 != cVar1 && (cVar1 != '\0'))) {
      pcVar2 = (char *)CharNextA(pcVar2);
      cVar1 = *pcVar2;
    }
    param_1 = pcVar2;
    if (param_3 == *pcVar2) {
      param_1 = (char *)CharNextA(pcVar2);
      pcVar3 = pcVar2;
    }
    cVar1 = *param_1;
  }
  if (param_3 == *pcVar3) {
    param_1 = (char *)CharNextA(pcVar3);
  }
  cVar1 = *param_1;
  if (cVar1 != '\0') {
    do {
      *param_2 = cVar1;
      param_1 = (char *)CharNextA(param_1);
      param_2 = (char *)CharNextA(param_2);
      cVar1 = *param_1;
      iStack_4 = iStack_4 + 1;
    } while (cVar1 != '\0');
    *param_2 = '\0';
    return iStack_4;
  }
  *param_2 = '\0';
  return 0;
}



undefined4 FUN_004150c0(char *param_1,char *param_2,char param_3)

{
  char cVar1;
  char *pcVar2;
  
  cVar1 = *param_1;
  pcVar2 = param_1;
  while ((param_3 != cVar1 && (cVar1 != '\0'))) {
    pcVar2 = (char *)CharNextA(pcVar2);
    cVar1 = *pcVar2;
  }
  if (param_3 == *pcVar2) {
    pcVar2 = (char *)CharNextA(pcVar2);
    cVar1 = *pcVar2;
    if (cVar1 == '\0') {
      *param_1 = '\0';
      return 0;
    }
    do {
      *param_2 = cVar1;
      if (param_3 == *pcVar2) {
        param_1 = param_2;
      }
      pcVar2 = (char *)CharNextA(pcVar2);
      param_2 = (char *)CharNextA(param_2);
      cVar1 = *pcVar2;
    } while (cVar1 != '\0');
    *param_1 = '\0';
    return 0;
  }
  *param_2 = '\0';
  return 0;
}



int FUN_00415b50(int param_1,int param_2)

{
  int iVar1;
  
  iVar1 = param_1 / param_2;
  if (param_1 % param_2 != 0) {
    iVar1 = iVar1 + 1;
  }
  return iVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00415b70(uint param_1,undefined4 param_2,int param_3,int param_4)

{
  char cVar1;
  short *psVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  char *pcVar6;
  int *piVar7;
  bool bVar8;
  undefined4 uStack_2c;
  undefined4 uStack_28;
  undefined4 uStack_24;
  undefined auStack_20 [32];
  
  uStack_2c = _DAT_004646e4;
  FUN_004143f0((param_3 != 0) + 0xde);
  if ((param_1 & 1) == 0) {
    param_1 = param_1 | 1;
  }
  FUN_00414650(1,0);
  uStack_24 = FUN_0044c5a2(0);
  pcVar6 = &DAT_00473ae9;
  do {
    psVar2 = _DAT_00473c2c;
    if (*pcVar6 == '\0') break;
    uStack_2c = CONCAT31(uStack_2c._1_3_,*pcVar6);
    iVar3 = FUN_0040e5a0(&uStack_2c,&param_3,&uStack_28);
    if (iVar3 == 1) {
      *(undefined4 *)(pcVar6 + 7) = 0;
      *(undefined4 *)(pcVar6 + 0xf) = 0;
      *(int *)(pcVar6 + 0x1f) = param_3;
      *(undefined4 *)(pcVar6 + 0x1b) = uStack_28;
      *(undefined4 *)(pcVar6 + 0x17) = 0;
      *(undefined4 *)(pcVar6 + 0xb) = 0;
      *(undefined4 *)(pcVar6 + 0x13) = 0;
      pcVar6[-1] = '\x01';
    }
    else {
      pcVar6[-1] = '\0';
    }
    pcVar6 = pcVar6 + 0x28;
    psVar2 = _DAT_00473c2c;
  } while ((int)pcVar6 < 0x473c29);
  for (; psVar2 != (short *)0x0; psVar2 = *(short **)(psVar2 + 0x1c)) {
    FUN_0040d420();
    if ((((*psVar2 == 10) && ((psVar2[8] & 1U) != 0)) && ((psVar2[8] & 4U) == 0)) &&
       (iVar3 = (uint)*(byte *)(psVar2 + 0x12) * 0x28,
       *(char *)((uint)*(byte *)(psVar2 + 0x12) * 0x28 + 0x473ae8) != '\0')) {
      iVar5 = 0;
      iVar4 = FUN_00414de0(*(byte *)(psVar2 + 9) >> 1 & 1,*(undefined4 *)(psVar2 + 0xc),
                           *(undefined4 *)(psVar2 + 0xe),param_1,param_2);
      if (iVar4 == 0) {
        if (_DAT_00473504 != 0) {
          iVar4 = FUN_00415b50(*(undefined4 *)(psVar2 + 0x16),*(undefined4 *)(&DAT_00473b08 + iVar3)
                              );
          *(int *)(&DAT_00473b00 + iVar3) = *(int *)(&DAT_00473b00 + iVar3) - iVar4;
        }
      }
      else {
        iVar4 = FUN_00415b50(*(undefined4 *)(psVar2 + 0x14),*(undefined4 *)(&DAT_00473b08 + iVar3));
        if (_DAT_00472194 == 0) {
          iVar5 = FUN_00415b50(*(undefined4 *)(psVar2 + 0x16),*(undefined4 *)(&DAT_00473b08 + iVar3)
                              );
        }
        *(int *)(&DAT_00473b00 + iVar3) = *(int *)(&DAT_00473b00 + iVar3) + (iVar4 - iVar5);
      }
    }
  }
  FUN_0040e750(_DAT_004721c0,0x16c,auStack_20,0x20);
  iVar3 = FUN_0044ba2e(auStack_20);
  if (iVar3 != 0) {
    iVar3 = FUN_00415b50(iVar3,_DAT_00473b30);
    _DAT_00473b28 = _DAT_00473b28 + iVar3;
  }
  FUN_0040e750(_DAT_004721c0,0x16d,auStack_20,0x20);
  iVar3 = FUN_0044ba2e(auStack_20);
  if (iVar3 != 0) {
    iVar3 = FUN_00415b50(iVar3,_DAT_00473b08);
    _DAT_00473b00 = _DAT_00473b00 + iVar3;
  }
  if ((param_4 != 0) && (*(int *)(param_4 + 0xc) != 0)) {
    FUN_0040e750(_DAT_004721c0,0x7e6,auStack_20,0x20);
    iVar3 = FUN_0044ba2e(auStack_20);
    _DAT_00473b28 = _DAT_00473b28 + 1 + iVar3 / _DAT_00473b30;
  }
  piVar7 = (int *)&DAT_00473b08;
  do {
    FUN_0040d420();
    cVar1 = *(char *)((int)piVar7 + -0x1f);
    if (cVar1 == '\0') break;
    iVar3 = FUN_0044c058();
    piVar7[-2] = iVar3;
    iVar4 = *piVar7 * iVar3;
    iVar5 = iVar4 >> 0x1f;
    piVar7[-6] = iVar4;
    piVar7[-5] = iVar5;
    if ((-1 < iVar4 || iVar5 < 0) && (iVar5 < 0)) {
      piVar7[-6] = 0;
      piVar7[-5] = 0;
    }
    *(longlong *)(piVar7 + -4) = (longlong)piVar7[-1] * (longlong)*piVar7;
    if ((piVar7 != (int *)&DAT_00473b08) && (DAT_00473ae9 == cVar1)) {
      _DAT_00473b00 = _DAT_00473b00 + iVar3;
      bVar8 = CARRY4(_DAT_00473af0,piVar7[-6]);
      _DAT_00473af0 = _DAT_00473af0 + piVar7[-6];
      _DAT_00473af4 = _DAT_00473af4 + piVar7[-5] + (uint)bVar8;
      piVar7[-6] = 0;
      piVar7[-5] = 0;
      *(undefined *)(piVar7 + -8) = 0;
    }
    piVar7 = piVar7 + 10;
  } while ((int)piVar7 < 0x473c48);
  FUN_0044c4b9(uStack_24);
  FUN_00414650(0,0);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00416020(int param_1)

{
  int *piVar1;
  uint uVar2;
  int iVar3;
  bool bVar4;
  
  if (_DAT_004739d8 != param_1) {
    _DAT_004739d8 = param_1;
    DAT_004737c8 = 0;
    DAT_004738cc = 0;
    _DAT_004737b8 = 0;
    _DAT_004737bc = 0;
    _DAT_004737c0 = 0;
    _DAT_004737c4 = 0;
    _DAT_004739d0 = 0;
    _DAT_004739d4 = 0;
    iVar3 = _DAT_00473c2c;
    if (_DAT_00473c2c != 0) {
      do {
        if ((*(byte *)(iVar3 + 0x10) & 8) != 0) {
          uVar2 = *(uint *)(iVar3 + 0x28);
          bVar4 = CARRY4(_DAT_004737b8,uVar2);
          _DAT_004737b8 = _DAT_004737b8 + uVar2;
          _DAT_004737bc = _DAT_004737bc + ((int)uVar2 >> 0x1f) + (uint)bVar4;
        }
        piVar1 = (int *)(iVar3 + 0x38);
        iVar3 = *piVar1;
      } while (*piVar1 != 0);
    }
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_00416b60(void)

{
  undefined4 uVar1;
  int iVar2;
  undefined4 uVar3;
  short *psVar4;
  undefined4 *puVar5;
  undefined4 uStack_2fb;
  undefined auStack_20c [4];
  undefined auStack_208 [256];
  undefined auStack_108 [4];
  undefined auStack_104 [260];
  
  psVar4 = _DAT_00473c2c;
  FUN_004143f0(0xdc);
  if (psVar4 == (short *)0x0) {
    return 10000;
  }
  do {
    if ((*psVar4 == 10) && ((*(byte *)(psVar4 + 8) & 1) != 0)) {
      FUN_0041a7e0(psVar4 + 0x24,auStack_208,0x104);
      uVar3 = *(undefined4 *)(psVar4 + 0xc);
      uVar1 = *(undefined4 *)(psVar4 + 0xe);
      if (((*(byte *)((int)psVar4 + 0x11) & 2) != 0) &&
         (iVar2 = FUN_00414de0(*(byte *)(psVar4 + 9) >> 1 & 1,uVar3,uVar1,_DAT_00473508,
                               _DAT_0047350c), iVar2 != 0)) {
        FUN_004139c0(auStack_208,0,1);
      }
      if ((((psVar4[8] & 0x400U) != 0) && ((psVar4[8] & 0x800U) == 0)) &&
         (iVar2 = FUN_00414de0(*(byte *)(psVar4 + 9) >> 1 & 1,uVar3,uVar1,_DAT_00473508,
                               _DAT_0047350c), iVar2 != 0)) {
        if (*(int *)(psVar4 + 0x1a) == 0) {
          FUN_0040da20(auStack_208,0);
        }
        else {
          puVar5 = &uStack_2fb;
          for (iVar2 = 0x3c; iVar2 != 0; iVar2 = iVar2 + -1) {
            *puVar5 = 0;
            puVar5 = puVar5 + 1;
          }
          *(undefined2 *)puVar5 = 0;
          *(undefined *)((int)puVar5 + 2) = 0;
          lstrcpyA(auStack_104,0x463fec);
          uVar3 = FUN_0040d4c0(auStack_208);
          uVar3 = CharNextA(uVar3);
          lstrcatA(auStack_108,uVar3);
          lstrcatA(&stack0xfffffcf0,auStack_20c);
          FUN_0041de30(0x80000002,auStack_108,&stack0xfffffcf0,1);
        }
        *(byte *)((int)psVar4 + 0x11) = *(byte *)((int)psVar4 + 0x11) | 8;
      }
    }
    psVar4 = *(short **)(psVar4 + 0x1c);
  } while (psVar4 != (short *)0x0);
  return 10000;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_00417600(void)

{
  int iVar1;
  char *pcVar2;
  undefined auStack_104 [260];
  
  iVar1 = FUN_00410910(&DAT_004721e8,auStack_104);
  if (iVar1 == 0) {
    lstrcpyA(auStack_104);
  }
  iVar1 = lstrlenA(auStack_104);
  pcVar2 = auStack_104 + iVar1 + -4;
  if (&stack0xfffffef8 < pcVar2) {
    do {
      FUN_0041b930(&stack0xfffffef8);
      while (pcVar2 = (char *)CharPrevA(&stack0xfffffef8,pcVar2), *pcVar2 != '\\') {
        if (pcVar2 <= &stack0xfffffef8) {
          _DAT_0047217c = 0;
          return 10000;
        }
      }
      *pcVar2 = '\0';
    } while (&stack0xfffffef8 < pcVar2);
  }
  _DAT_0047217c = 0;
  return 10000;
}



undefined4 FUN_004176a0(undefined4 param_1)

{
  int iVar1;
  
  iVar1 = lstrcmpiA(param_1,0x464988);
  if ((((iVar1 != 0) && (iVar1 = lstrcmpiA(param_1,0x464984), iVar1 != 0)) &&
      (iVar1 = lstrcmpiA(param_1,0x46497c), iVar1 != 0)) &&
     (((iVar1 = lstrcmpiA(param_1,0x464978), iVar1 != 0 &&
       (iVar1 = lstrcmpiA(param_1,0x464974), iVar1 != 0)) &&
      ((iVar1 = lstrcmpiA(param_1,0x46496c), iVar1 < 0 ||
       (iVar1 = lstrcmpiA(param_1,0x464964), 0 < iVar1)))))) {
    iVar1 = lstrcmpiA(param_1,0x46495c);
    if (iVar1 < 0) {
      return 0;
    }
    iVar1 = lstrcmpiA(param_1,0x464954);
    if (0 < iVar1) {
      return 0;
    }
  }
  return 1;
}



undefined ** FUN_00417730(undefined4 param_1,undefined4 param_2)

{
  int iVar1;
  int iVar2;
  undefined ***pppuStack_398;
  undefined ***pppuStack_394;
  undefined **ppuStack_390;
  undefined4 uStack_38c;
  undefined4 uStack_388;
  undefined4 *puStack_384;
  undefined4 **ppuStack_380;
  undefined ***pppuStack_37c;
  undefined **ppuStack_378;
  undefined4 uStack_374;
  undefined4 uStack_370;
  undefined4 *puStack_36c;
  undefined4 **ppuStack_368;
  undefined **ppuStack_364;
  undefined4 uStack_35c;
  undefined4 uStack_358;
  undefined *puStack_354;
  undefined *puStack_350;
  undefined **ppuStack_34c;
  undefined4 uStack_348;
  undefined4 uStack_344;
  undefined4 uStack_340;
  undefined4 uStack_33c;
  undefined *puStack_338;
  undefined auStack_320 [4];
  undefined4 uStack_31c;
  undefined auStack_27c [260];
  undefined auStack_178 [268];
  undefined4 uStack_6c;
  undefined4 **ppuStack_28;
  
  puStack_338 = auStack_320;
  uStack_33c = 0x20019;
  uStack_340 = 0;
  uStack_344 = param_2;
  uStack_348 = 0x80000002;
  uStack_31c = 0;
  ppuStack_34c = (undefined **)0x41775e;
  iVar1 = RegOpenKeyExA();
  if (iVar1 != 0) {
    return (undefined **)0x0;
  }
  ppuStack_34c = &puStack_338;
  puStack_350 = auStack_320;
  puStack_354 = &stack0xfffffcd4;
  uStack_358 = 0;
  uStack_35c = 0x4649b8;
  puStack_338 = (undefined *)0x104;
  ppuStack_364 = (undefined **)0x417791;
  iVar1 = RegQueryValueExA();
  if (iVar1 == 0) {
    ppuStack_364 = &puStack_338;
    ppuStack_368 = ppuStack_28;
    puStack_36c = (undefined4 *)0x4177aa;
    iVar1 = lstrcmpiA();
    if (iVar1 == 0) {
      return (undefined **)0x1;
    }
  }
  ppuStack_364 = &puStack_350;
  ppuStack_368 = (undefined4 **)&puStack_338;
  puStack_36c = &uStack_344;
  uStack_370 = 0;
  uStack_374 = 0x4649ac;
  ppuStack_378 = ppuStack_34c;
  puStack_350 = (undefined *)0x104;
  pppuStack_37c = (undefined ***)0x4177df;
  iVar1 = RegQueryValueExA();
  if (iVar1 == 0) {
    pppuStack_37c = (undefined ***)&puStack_350;
    ppuStack_380 = ppuStack_28;
    puStack_384 = (undefined4 *)0x4177eb;
    iVar1 = lstrcmpiA();
    if (iVar1 == 0) {
      return (undefined **)0x1;
    }
  }
  pppuStack_37c = (undefined ***)&ppuStack_368;
  ppuStack_380 = (undefined4 **)&puStack_350;
  puStack_384 = &uStack_35c;
  uStack_388 = 0;
  uStack_38c = 0x464994;
  ppuStack_390 = ppuStack_364;
  ppuStack_368 = (undefined4 **)0x104;
  pppuStack_394 = (undefined ***)0x417820;
  iVar1 = RegQueryValueExA();
  if (iVar1 == 0) {
    pppuStack_394 = (undefined ***)&ppuStack_368;
    pppuStack_398 = (undefined ***)ppuStack_28;
    iVar1 = lstrcmpiA();
    if (iVar1 == 0) {
      return (undefined **)0x1;
    }
  }
  pppuStack_394 = (undefined ***)&ppuStack_380;
  pppuStack_398 = (undefined ***)&ppuStack_368;
  ppuStack_380 = (undefined4 **)0x104;
  iVar1 = RegQueryValueExA(pppuStack_37c,0x46498c,0,&uStack_374);
  if (iVar1 == 0) {
    iVar1 = lstrcmpiA(ppuStack_28,&ppuStack_380);
    if (iVar1 == 0) {
      return (undefined **)0x1;
    }
  }
  iVar1 = 0;
  do {
    pppuStack_398 = (undefined ***)0x104;
    iVar2 = RegEnumKeyExA(pppuStack_394,iVar1,auStack_178,&pppuStack_398,0,0,0,&uStack_388);
    if (iVar2 == 0) {
      lstrcpyA(auStack_27c,uStack_6c);
      FUN_0040f8a0(auStack_27c);
      lstrcatA(auStack_27c,auStack_178);
      ppuStack_390 = (undefined **)FUN_00417730(ppuStack_28,auStack_27c);
    }
    iVar1 = iVar1 + 1;
  } while ((iVar2 != 0x103) && (ppuStack_390 == (undefined **)0x0));
  return ppuStack_390;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_00417940(undefined4 param_1,int param_2)

{
  char cVar1;
  char cVar2;
  bool bVar3;
  char *pcVar4;
  int iVar5;
  char *pcVar6;
  char *pcVar7;
  char *pcVar8;
  uint uVar9;
  int iVar10;
  code *pcVar11;
  code *pcVar12;
  bool bVar13;
  char cStack_331;
  char *pcStack_32c;
  int iStack_328;
  int iStack_324;
  int iStack_31c;
  int iStack_318;
  int iStack_314;
  undefined auStack_310 [4];
  char acStack_30c [260];
  char acStack_208 [260];
  char acStack_104 [260];
  
  bVar3 = false;
  iStack_328 = 0;
  iStack_324 = 3;
  lstrcpyA(acStack_104,param_1);
  for (pcVar4 = acStack_104; ((cVar1 = *pcVar4, cVar1 == ' ' || (cVar1 == '\t')) || (cVar1 == '\"'))
      ; pcVar4 = (char *)CharNextA(pcVar4)) {
  }
  FUN_00418010(pcVar4);
  if (*pcVar4 != '\0') {
    iVar5 = lstrlenA(pcVar4);
    pcVar6 = pcVar4 + iVar5;
    cVar1 = pcVar4[iVar5];
    while (cVar1 != '\0') {
      pcVar6 = (char *)CharPrevA(pcVar4,pcVar6);
      cVar1 = *pcVar6;
      if (((cVar1 == ' ') || (cVar1 == '\t')) || (cVar1 == '\"')) {
        *pcVar6 = '\0';
      }
      cVar1 = *pcVar6;
    }
    iVar5 = FUN_0040fe90(pcVar4,0x4649f0);
    if (iVar5 == 0) {
      iVar5 = FUN_00417730(pcVar4,0x4649cc);
      if (iVar5 == 0) {
        pcVar7 = (char *)CharNextA(pcVar4);
        pcVar6 = (char *)CharNextA(pcVar7);
        pcVar8 = (char *)CharNextA(pcVar6);
        iVar5 = FUN_0044c2f5((int)*pcVar4);
        if (((0 < iVar5) && (*pcVar7 == ':')) &&
           ((*pcVar6 == '\\' && (cVar1 = *pcVar8, cVar1 != '\0')))) {
          *pcVar8 = '\0';
          iVar5 = FUN_0041bca0(pcVar4);
          if ((((iVar5 == 0) || (iVar5 == 1)) || (iVar5 == 5)) || ((iVar5 == 4 || (iVar5 == 6)))) {
            *pcVar8 = cVar1;
            iStack_324 = iVar5;
          }
          else {
            iVar5 = FUN_0041bdc0(pcVar4,&iStack_31c,&iStack_318,auStack_310,&iStack_314);
            *pcVar8 = cVar1;
            if ((iVar5 != 0) && (5999999 < (uint)(iStack_31c * iStack_318 * iStack_314))) {
              cVar2 = *pcVar6;
              pcVar11 = CharNextA_exref;
              while (cVar2 != '\0') {
                pcVar7 = (char *)(*pcVar11)(pcVar6);
                cVar2 = *pcVar7;
                switch(*pcVar6) {
                case '\t':
                case ' ':
joined_r0x00417b31:
                  if (cVar2 == '\\') goto switchD_00417b02_caseD_22;
                  break;
                case '\"':
                case '*':
                case '/':
                case ':':
                case '<':
                case '>':
                case '?':
                case '|':
                  goto switchD_00417b02_caseD_22;
                case '.':
                  if (cVar1 == '\\') {
                    if ((cVar2 != '\0') && (cVar2 != '.')) goto joined_r0x00417b31;
                    goto switchD_00417b02_caseD_22;
                  }
                  if ((cVar1 == '.') && (cVar2 == '\0')) goto switchD_00417b02_caseD_22;
                  break;
                case '\\':
                  if (cVar1 == '\\') goto switchD_00417b02_caseD_22;
                  if (cVar2 == '\0') {
                    *pcVar6 = '\0';
                  }
                }
                pcVar11 = CharNextA_exref;
                cVar1 = *pcVar6;
                pcVar6 = (char *)CharNextA(pcVar6);
                cVar2 = *pcVar6;
              }
              cVar1 = *pcVar8;
              while (pcVar6 = pcVar8, cVar1 != '\0') {
                while ((cVar1 != '\0' && (cVar1 != '\\'))) {
                  pcVar6 = (char *)(*pcVar11)(pcVar6);
                  cVar1 = *pcVar6;
                }
                if (*pcVar6 == '\\') {
                  *pcVar6 = '\0';
                  iVar5 = FUN_004176a0(pcVar8);
                  if (iVar5 != 0) {
                    *pcVar6 = '\\';
                    goto switchD_00417b02_caseD_22;
                  }
                  *pcVar6 = '\\';
                }
                cVar1 = *pcVar8;
                while ((cVar1 != '\0' && (cVar1 != '\\'))) {
                  pcVar8 = (char *)(*pcVar11)(pcVar8);
                  cVar1 = *pcVar8;
                }
                if (*pcVar8 == '\\') {
                  *pcVar8 = '\0';
                  uVar9 = FUN_0041bc20(pcVar4);
                  *pcVar8 = '\\';
                  if (uVar9 == 0xffffffff) {
                    GetLastError();
                  }
                  if ((((uVar9 & 0x10) == 0) && (pcVar11 = CharNextA_exref, uVar9 != 0xffffffff)) ||
                     (((uVar9 & 4) != 0 && (pcVar11 = CharNextA_exref, uVar9 != 0xffffffff))))
                  goto switchD_00417b02_caseD_22;
                }
                pcVar8 = (char *)(*pcVar11)(pcVar8);
                cVar1 = *pcVar8;
              }
              lstrcpyA(acStack_208,pcVar4);
              FUN_004100a0(acStack_208);
              iVar5 = 0;
              cStack_331 = 'C';
LAB_00417c39:
              pcVar6 = pcVar4;
              pcStack_32c = pcVar4;
              switch(iVar5) {
              case 0:
                GetWindowsDirectoryA(acStack_30c,0x104);
                break;
              case 1:
                GetSystemDirectoryA(acStack_30c,0x104);
                break;
              case 2:
                FUN_0040db40(acStack_30c,0x104);
                break;
              case 3:
                lstrcpyA(acStack_30c,&DAT_00463268);
                acStack_30c[0] = cStack_331;
                iVar10 = GetDriveTypeA(acStack_30c);
                if (iVar10 == 3) {
                  lstrcpyA(acStack_30c,0x4649c0);
                  acStack_30c[0] = cStack_331;
                }
                else {
                  acStack_30c[0] = '\0';
                }
                break;
              default:
                goto switchD_00417c4b_caseD_5;
              case -0x452e541f:
                break;
              }
              iVar10 = lstrlenA(acStack_30c);
              if (iVar10 == 0) {
LAB_00417d3c:
                pcVar12 = pcVar11;
                if (iVar5 != 3) goto LAB_00417d36;
                if (cStack_331 == 'Z') {
                  iVar5 = 4;
                }
                else {
                  cStack_331 = cStack_331 + '\x01';
                }
              }
              else {
                FUN_004100a0(acStack_30c);
                pcVar6 = acStack_30c;
                pcVar8 = acStack_208;
                pcVar12 = CharNextA_exref;
                cVar1 = acStack_30c[0];
                while ((CharNextA_exref = pcVar12, cVar1 != '\0' && (cVar1 == *pcVar8))) {
                  pcVar6 = (char *)(*pcVar11)(pcVar6);
                  pcVar8 = (char *)(*pcVar11)(pcVar8);
                  pcVar12 = CharNextA_exref;
                  cVar1 = *pcVar6;
                }
                if (*pcVar6 != '\0') goto LAB_00417d3c;
                if ((iVar5 != 2) || (*pcVar8 == '\0')) goto switchD_00417b02_caseD_22;
LAB_00417d36:
                iVar5 = iVar5 + 1;
                pcVar11 = pcVar12;
              }
              goto LAB_00417c39;
            }
          }
        }
      }
      else {
        bVar3 = true;
      }
    }
  }
switchD_00417b02_caseD_22:
  if (param_2 != 0) {
    if (iStack_328 == 0x70) {
      FUN_0040d270(_DAT_004721c8,0x30,0x8a);
      return 0x2714;
    }
    if (iStack_324 == 4) {
      FUN_0040d270(_DAT_004721c8,0x30,0x98);
      return 0x2714;
    }
    if (bVar3) {
      FUN_0040d270(_DAT_004721c8,0x30,0x9e);
      return 0x2714;
    }
    FUN_0040d270(_DAT_004721c8,0x30,0x66,&DAT_004721e8);
  }
  return 0x2714;
switchD_00417c4b_caseD_5:
  cVar1 = *pcVar6;
  if ((cVar1 == '\\') || (cVar1 == '\0')) {
    bVar13 = cVar1 == '\0';
    *pcVar6 = '\0';
    iVar5 = FUN_0040faf0(pcVar4);
    if ((0x104 < (uint)(_DAT_004734f4 + iVar5)) || (iVar10 = FUN_0041b970(pcVar4,0), iVar10 == 0)) {
      iStack_328 = GetLastError();
      iVar10 = FUN_0041bc20(pcVar4);
      if ((((iVar10 == -1) || (iStack_328 == 0x10b)) || (iStack_328 == 0x70)) ||
         (0x104 < (uint)(_DAT_004734f4 + iVar5))) {
        if (!bVar13) {
          *pcVar6 = '\\';
        }
        bVar13 = false;
LAB_00417e17:
        if (pcStack_32c != (char *)0x0) {
          iVar5 = lstrlenA(pcVar4);
          pcVar6 = pcVar4 + iVar5;
          while (pcStack_32c < pcVar6) {
            cVar1 = *pcVar6;
            *pcVar6 = '\0';
            FUN_0041b930(pcVar4);
            *pcVar6 = cVar1;
            do {
              pcVar6 = (char *)CharPrevA(pcVar4,pcVar6);
            } while (*pcVar6 != '\\');
          }
        }
        if (bVar13) {
          if ((_DAT_0047214c == (code *)0x0) ||
             (iVar5 = (*_DAT_0047214c)(pcVar4,&param_2), iVar5 != 0x2714)) {
            lstrcpyA(param_1,pcVar4);
            return 10000;
          }
          iStack_328 = 0xa1;
        }
        goto switchD_00417b02_caseD_22;
      }
      pcStack_32c = (char *)0x0;
    }
    if (bVar13) goto LAB_00417e17;
    *pcVar6 = '\\';
    if (pcStack_32c == (char *)0x0) {
      pcStack_32c = pcVar6;
    }
  }
  pcVar6 = (char *)CharNextA(pcVar6);
  goto switchD_00417c4b_caseD_5;
}



void FUN_00418010(char *param_1)

{
  char *pcVar1;
  int iVar2;
  char *pcVar3;
  char *pcVar4;
  bool bVar5;
  
  bVar5 = false;
  pcVar3 = (char *)0x0;
  pcVar4 = param_1;
  if (*param_1 != '\0') {
    do {
      iVar2 = FUN_0044c39b((int)*param_1);
      if (iVar2 == 0) {
        if (pcVar3 != (char *)0x0) {
          if ((bVar5) || (*param_1 == '\\')) {
            pcVar4 = pcVar3;
          }
          pcVar3 = (char *)0x0;
        }
        bVar5 = *param_1 == '\\';
      }
      else if (pcVar3 == (char *)0x0) {
        pcVar3 = pcVar4;
      }
      iVar2 = IsDBCSLeadByte(*param_1);
      if (iVar2 != 0) {
        *pcVar4 = *param_1;
        pcVar4 = pcVar4 + 1;
        param_1 = param_1 + 1;
      }
      *pcVar4 = *param_1;
      pcVar1 = param_1 + 1;
      pcVar4 = pcVar4 + 1;
      param_1 = param_1 + 1;
    } while (*pcVar1 != '\0');
    if (pcVar4 != param_1) {
      *pcVar4 = '\0';
    }
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// WARNING: Restarted to delay deadcode elimination for space: stack

void FUN_0041a230(void)

{
  int iVar1;
  int iVar2;
  undefined4 unaff_retaddr;
  int *piVar3;
  undefined4 uVar4;
  int iStack_8;
  undefined4 uStack_4;
  
  iVar1 = SHGetMalloc(&uStack_4);
  if (-1 < iVar1) {
    uVar4 = 0x14;
    piVar3 = _DAT_004721c8;
    iVar2 = SHGetSpecialFolderLocation(_DAT_004721c8,0x14);
    iVar1 = iStack_8;
    if (-1 < iVar2) {
      iVar2 = SHGetPathFromIDListA(uVar4,iStack_8);
      if (iVar2 != 0) {
        iVar2 = FUN_0040d4c0(unaff_retaddr);
        if (iVar2 != 0) {
          unaff_retaddr = CharNextA(iVar2);
        }
        FUN_0040f8a0(iVar1);
        lstrcatA(iVar1,unaff_retaddr);
        FUN_0040dc60(iVar1,uStack_4);
      }
    }
    (**(code **)(iStack_8 + 0x14))(&iStack_8,uVar4);
    (**(code **)(*piVar3 + 8))(piVar3);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0041a2d0(void)

{
  char cVar1;
  char cVar2;
  int iVar3;
  char *pcVar4;
  char *pcVar5;
  undefined4 uVar6;
  undefined *puVar7;
  undefined4 uVar8;
  int iVar9;
  int unaff_ESI;
  undefined4 uVar10;
  char acStack_410 [240];
  undefined auStack_320 [4];
  undefined auStack_31c [4];
  undefined auStack_318 [252];
  undefined auStack_21c [8];
  char acStack_214 [252];
  undefined auStack_118 [280];
  
  if (_DAT_00473f98 != 0) {
    return 1;
  }
  iVar3 = FUN_0040e750(_DAT_004721bc,9000,acStack_410,0x104);
  cVar1 = acStack_410[0];
  do {
    if (iVar3 == 0) {
      _DAT_00473f98 = 1;
      return 1;
    }
    pcVar4 = acStack_410;
    acStack_410[0] = cVar1;
    while ((cVar1 != '\0' && (DAT_00464a48 != cVar1))) {
      pcVar4 = (char *)CharNextA(pcVar4);
      cVar1 = *pcVar4;
    }
    pcVar5 = (char *)CharNextA(pcVar4);
    *pcVar4 = '\0';
    cVar1 = *pcVar5;
    uVar6 = CharNextA(pcVar5);
    pcVar4 = (char *)CharNextA(uVar6);
    iVar3 = FUN_00410440(0x62,0);
    if (((DAT_0046411c != *pcVar4) || (iVar3 == 0)) && ((DAT_00464118 != *pcVar4 || (iVar3 != 0))))
    {
      uVar6 = CharNextA(pcVar4);
      pcVar4 = (char *)CharNextA(uVar6);
      uVar6 = FUN_0044ba2e(pcVar4);
      cVar2 = *pcVar4;
      while ((cVar2 != '\0' && (DAT_00464a48 != cVar2))) {
        pcVar4 = (char *)CharNextA(pcVar4);
        cVar2 = *pcVar4;
      }
      if (*pcVar4 == '\0') {
        puVar7 = &DAT_0046e83c;
      }
      else {
        puVar7 = (undefined *)CharNextA(pcVar4);
      }
      lstrcpyA(auStack_21c,puVar7);
      FUN_0040dc60(&stack0xfffffbdc,0x104);
      uVar10 = 0x464a44;
      uVar8 = FUN_0041aa10(&stack0xfffffbdc,0x464a44);
      iVar3 = lstrcmpiA(uVar8,uVar10);
      if (iVar3 != 0) {
        uVar10 = 0x464a40;
        uVar8 = FUN_0041aa10(&stack0xfffffbdc,0x464a40);
        iVar3 = lstrcmpiA(uVar8,uVar10);
        if (iVar3 != 0) {
          iVar3 = FUN_0040d4c0(&stack0xfffffbdc);
          if (iVar3 == 0) {
            puVar7 = &stack0xfffffbdc;
          }
          else {
            puVar7 = (undefined *)CharNextA(iVar3);
          }
          lstrcpyA(auStack_320,puVar7);
          FUN_0040e750(_DAT_004721bc,0x182,auStack_118,0x104);
          iVar3 = FUN_0040d4c0(auStack_118);
          if (iVar3 == 0) {
            puVar7 = auStack_118;
          }
          else {
            puVar7 = (undefined *)CharNextA(iVar3);
          }
          iVar3 = lstrcmpiA(puVar7,auStack_320);
          if (cVar1 != '1') {
            auStack_320[0] = 0;
          }
          iVar9 = FUN_004140f0(&stack0xfffffbdc,auStack_320,uVar6);
          if (iVar9 != 0) {
            if (acStack_214[0] == '\0') {
              iVar9 = FUN_0041feb0(&stack0xfffffbe4,auStack_318,0);
              if (iVar9 != 0) {
                return 0;
              }
            }
            else {
              iVar9 = FUN_00421bb0(acStack_214);
              if (iVar9 != 10000) {
                return 0;
              }
            }
            uVar6 = lstrlenA(auStack_318);
            FUN_0041a5c0(auStack_31c,uVar6);
            if (iVar3 == 0) {
              lstrcpyA(0x472470,auStack_318);
            }
          }
          goto LAB_0041a56d;
        }
      }
      iVar3 = FUN_0041a640(&stack0xfffffbdc,auStack_21c);
      if (iVar3 != 10000) {
        return 0;
      }
    }
LAB_0041a56d:
    iVar3 = FUN_0040e750(_DAT_004721bc,unaff_ESI,&stack0xfffffbe4,0x104);
    unaff_ESI = unaff_ESI + 1;
    cVar1 = acStack_410[0];
  } while( true );
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0041a5c0(int param_1,int param_2)

{
  undefined4 *puVar1;
  int *piVar2;
  int iVar3;
  undefined4 *puVar4;
  
  if (param_1 == 0) {
    puVar4 = _DAT_00473f9c;
    if (_DAT_00473f9c != (undefined4 *)0x0) {
      do {
        puVar1 = (undefined4 *)puVar4[1];
        FUN_0041bce0(*puVar4);
        FUN_0044c4b9(*puVar4);
        FUN_0044c4b9(puVar4);
        puVar4 = puVar1;
      } while (puVar1 != (undefined4 *)0x0);
    }
  }
  else {
    piVar2 = (int *)FUN_0044c5a2(8);
    if (piVar2 != (int *)0x0) {
      iVar3 = FUN_0044c5a2(param_2 + 1);
      *piVar2 = iVar3;
      if (iVar3 != 0) {
        lstrcpyA(iVar3,param_1);
      }
      piVar2[1] = (int)_DAT_00473f9c;
      _DAT_00473f9c = piVar2;
      return;
    }
  }
  return;
}



undefined4 FUN_0041a640(undefined4 param_1,char *param_2)

{
  int iVar1;
  undefined auStack_a40 [12];
  int iStack_a34;
  undefined auStack_a28 [260];
  undefined auStack_924 [260];
  undefined auStack_820 [24];
  undefined4 uStack_808;
  undefined2 uStack_804;
  undefined auStack_802 [2050];
  
  lstrcpyA(auStack_802,param_1);
  uStack_808 = 0x20;
  uStack_804 = 0;
  FUN_00412fe0(auStack_820,auStack_a40);
  if (iStack_a34 == 0) {
    if (*param_2 == '\0') {
      FUN_0041a870(param_1,auStack_a28,0x104);
    }
    else {
      lstrcpyA(auStack_a28,param_1);
    }
    FUN_0041a230(auStack_924,0x104,auStack_a28);
    RemoveFontResourceA(auStack_924);
    if (*param_2 == '\0') {
      iVar1 = FUN_0041feb0(auStack_a28,auStack_924,0);
      if (iVar1 != 0) {
        return 0x2716;
      }
    }
    else {
      iVar1 = FUN_00421bb0(param_2,auStack_a28,auStack_924);
      if (iVar1 != 10000) {
        return 0x2716;
      }
    }
    FUN_0041fd50(auStack_924,0);
  }
  return 10000;
}



void FUN_0041a7e0(int param_1,undefined *param_2,undefined4 param_3)

{
  int iVar1;
  uint uVar2;
  
  iVar1 = *(ushort *)(param_1 + 0x1c) + 0x1e + param_1;
  *param_2 = 0;
  uVar2 = *(uint *)(param_1 + 0x18);
  if ((uVar2 & 0x40) == 0) {
    if ((uVar2 & 2) == 0) {
      if ((uVar2 & 1) == 0) {
        if ((uVar2 & 0x20) != 0) {
          FUN_0041a230(param_2,param_3,iVar1);
          return;
        }
        goto LAB_0041a818;
      }
      GetWindowsDirectoryA(param_2,param_3);
    }
    else {
      GetSystemDirectoryA(param_2,param_3);
    }
  }
  else {
    lstrcpyA(param_2,&DAT_004721e8);
  }
  FUN_0040f8a0(param_2);
LAB_0041a818:
  lstrcatA(param_2,iVar1);
  FUN_0040dc60(param_2,param_3);
  return;
}



void FUN_0041a870(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  char *pcVar1;
  
  lstrcpyA(param_2,param_1);
  FUN_0040dc60(param_2,param_3);
  pcVar1 = (char *)CharNextA(param_2);
  if (*pcVar1 != '\\') {
    pcVar1 = (char *)CharNextA(param_2);
    if (*pcVar1 != ':') {
      FUN_0040d100(param_2,param_3);
      lstrcatA(param_2,param_1);
      FUN_0040dc60(param_2,param_3);
    }
  }
  return;
}



undefined4 FUN_0041aa10(char *param_1)

{
  char cVar1;
  char *pcVar2;
  undefined4 uVar3;
  
  cVar1 = *param_1;
  pcVar2 = param_1;
  while (cVar1 != '\0') {
    pcVar2 = (char *)CharNextA(pcVar2);
    cVar1 = *pcVar2;
  }
  pcVar2 = (char *)CharPrevA(param_1,pcVar2);
  cVar1 = *pcVar2;
  while ((cVar1 != '.' && (pcVar2 != param_1))) {
    pcVar2 = (char *)CharPrevA(param_1,pcVar2);
    cVar1 = *pcVar2;
  }
  if (*pcVar2 != '.') {
    return 0;
  }
  uVar3 = CharNextA(pcVar2);
  return uVar3;
}



void FUN_0041b3e0(undefined4 param_1)

{
  undefined4 uVar1;
  
  uVar1 = 0;
  FormatMessageA(0x1100,0,param_1,0x400,&param_1,0,0);
  LocalFree(uVar1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0041b410(void)

{
  if (_DAT_00473fd0 == 0) {
    _DAT_00473fd0 = 1;
    _DAT_00473fcc = LoadLibraryA(0x466b44);
    if (_DAT_00473fcc == 0) {
      _DAT_00473fc8 = _DAT_00473fcc;
      return;
    }
    _DAT_00473fa8 = GetProcAddress(_DAT_00473fcc,0x466b30);
    _DAT_00473fb4 = GetProcAddress(_DAT_00473fcc,0x466b1c);
    _DAT_00473fbc = GetProcAddress(_DAT_00473fcc,0x466b08);
    _DAT_00473fb0 = GetProcAddress(_DAT_00473fcc,0x466af8);
    _DAT_00473fac = GetProcAddress(_DAT_00473fcc,0x466ae4);
    _DAT_00473fc0 = GetProcAddress(_DAT_00473fcc,0x466ad0);
    _DAT_00473fb8 = GetProcAddress(_DAT_00473fcc,0x466ac0);
    _DAT_00473fc4 = GetProcAddress(_DAT_00473fcc,0x466aac);
    if (((((_DAT_00473fa8 == 0) || (_DAT_00473fb4 == 0)) || (_DAT_00473fbc == 0)) ||
        ((_DAT_00473fb0 == 0 || (_DAT_00473fac == 0)))) ||
       ((_DAT_00473fc0 == 0 || ((_DAT_00473fb8 == 0 || (_DAT_00473fc4 == 0)))))) {
      FUN_0041b540();
    }
    _DAT_00473fc8 = 1;
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0041b540(void)

{
  if (_DAT_00473fcc != 0) {
    FreeLibrary(_DAT_00473fcc);
    _DAT_00473fcc = 0;
  }
  _DAT_00473fc8 = 0;
  _DAT_00473fd0 = 0;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0041b570(undefined4 param_1,undefined4 param_2)

{
  int iStack_4;
  
  iStack_4 = 0;
  FUN_0041b620(param_1,&iStack_4,param_2);
  if (iStack_4 != 0) {
    (*_DAT_00473fbc)(iStack_4);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0041b620(int param_1,int *param_2,uint param_3)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 *unaff_retaddr;
  
  if (_DAT_00473fd0 == 0) {
    FUN_0041b410();
  }
  if ((param_1 != 0) && (_DAT_00473fc8 != 0)) {
    iVar1 = FUN_0040eca0();
    if (iVar1 == 0) {
      param_3 = 0;
    }
    if ((param_3 & 0x200) != 0) {
      if (*param_2 == 0) {
        uVar2 = (*_DAT_00473fa8)();
        iVar1 = (*_DAT_00473fb4)(param_1,uVar2);
        if (iVar1 != 0) {
          (*_DAT_00473fbc)(iVar1);
        }
      }
      else {
        (*_DAT_00473fb4)(param_1,*param_2);
        *param_2 = 0;
      }
      iVar1 = (*_DAT_00473fb0)(param_1);
      if (iVar1 == 0) {
        uVar2 = (*_DAT_00473fa8)();
        (*_DAT_00473fb4)(param_1,uVar2);
        iVar1 = (*_DAT_00473fb0)(param_1);
        if (iVar1 == 0) {
          return;
        }
      }
      (*_DAT_00473fac)(iVar1,param_3 >> 10 & 1);
      (*_DAT_00473fc0)(param_1,iVar1);
      return;
    }
    uVar2 = (*_DAT_00473fb4)(param_1,0);
    *unaff_retaddr = uVar2;
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4
FUN_0041b870(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6)

{
  undefined4 unaff_retaddr;
  
  _DAT_00473fe4 = SetErrorMode(0x8001);
  _DAT_00473fd8 = CreateFileA(unaff_retaddr,param_1,param_2,param_3,param_4,param_5,param_6);
  SetErrorMode(_DAT_00473fe4);
  return _DAT_00473fd8;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4
FUN_0041b8d0(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,undefined4 param_7)

{
  undefined4 unaff_retaddr;
  
  _DAT_00473fe4 = SetErrorMode(0x8001);
  _DAT_00473fd4 =
       DeviceIoControl(unaff_retaddr,param_1,param_2,param_3,param_4,param_5,param_6,param_7);
  SetErrorMode(_DAT_00473fe4);
  return _DAT_00473fd4;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0041b930(void)

{
  undefined4 unaff_retaddr;
  
  _DAT_00473fe4 = SetErrorMode(0x8001);
  _DAT_00473fd4 = RemoveDirectoryA(unaff_retaddr);
  SetErrorMode(_DAT_00473fe4);
  return _DAT_00473fd4;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0041b970(undefined4 param_1)

{
  undefined4 unaff_retaddr;
  
  _DAT_00473fe4 = SetErrorMode(0x8001);
  _DAT_00473fd4 = CreateDirectoryA(unaff_retaddr,param_1);
  SetErrorMode(_DAT_00473fe4);
  return _DAT_00473fd4;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0041b9b0(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 unaff_retaddr;
  
  _DAT_00473fe4 = SetErrorMode(0x8001);
  _DAT_00473fd4 = WriteFile(unaff_retaddr,param_1,param_2,param_3,param_4);
  SetErrorMode(_DAT_00473fe4);
  return _DAT_00473fd4;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0041ba00(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 unaff_retaddr;
  
  _DAT_00473fe4 = SetErrorMode(0x8001);
  _DAT_00473fd4 = ReadFile(unaff_retaddr,param_1,param_2,param_3,param_4);
  SetErrorMode(_DAT_00473fe4);
  return _DAT_00473fd4;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0041ba50(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  undefined4 unaff_retaddr;
  
  _DAT_00473fe4 = SetErrorMode(0x8001);
  _DAT_00473fd4 = SetFileTime(unaff_retaddr,param_1,param_2,param_3);
  SetErrorMode(_DAT_00473fe4);
  return _DAT_00473fd4;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0041baa0(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  undefined4 unaff_retaddr;
  
  _DAT_00473fe4 = SetErrorMode(0x8001);
  _DAT_00473fd4 = GetFileTime(unaff_retaddr,param_1,param_2,param_3);
  SetErrorMode(_DAT_00473fe4);
  return _DAT_00473fd4;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0041baf0(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  undefined4 unaff_retaddr;
  
  _DAT_00473fe4 = SetErrorMode(0x8001);
  _DAT_00473fe8 = SetFilePointer(unaff_retaddr,param_1,param_2,param_3);
  SetErrorMode(_DAT_00473fe4);
  return _DAT_00473fe8;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4
FUN_0041bb80(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,undefined4 param_7)

{
  undefined4 unaff_retaddr;
  
  _DAT_00473fe4 = SetErrorMode(0x8001);
  _DAT_00473fd4 =
       GetVolumeInformationA(unaff_retaddr,param_1,param_2,param_3,param_4,param_5,param_6,param_7);
  SetErrorMode(_DAT_00473fe4);
  return _DAT_00473fd4;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0041bc20(void)

{
  undefined4 unaff_retaddr;
  
  _DAT_00473fe4 = SetErrorMode(0x8001);
  _DAT_00473fe8 = GetFileAttributesA(unaff_retaddr);
  SetErrorMode(_DAT_00473fe4);
  return _DAT_00473fe8;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0041bc60(undefined4 param_1)

{
  undefined4 unaff_retaddr;
  
  _DAT_00473fe4 = SetErrorMode(0x8001);
  _DAT_00473fe8 = GetCurrentDirectoryA(unaff_retaddr,param_1);
  SetErrorMode(_DAT_00473fe4);
  return _DAT_00473fe8;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0041bca0(void)

{
  undefined4 unaff_retaddr;
  
  _DAT_00473fe4 = SetErrorMode(0x8001);
  _DAT_00473fe0 = GetDriveTypeA(unaff_retaddr);
  SetErrorMode(_DAT_00473fe4);
  return _DAT_00473fe0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_0041bce0(void)

{
  undefined4 unaff_retaddr;
  
  _DAT_00473fe4 = SetErrorMode(0x8001);
  _DAT_00473fd4 = DeleteFileA(unaff_retaddr);
  if (_DAT_00473fd4 == 0) {
    _DAT_00473fec = GetLastError();
    if (((_DAT_00473fec == 2) || (_DAT_00473fec == 5)) || (_DAT_00473fec == 3)) {
      _DAT_00473fd4 = 1;
    }
  }
  SetErrorMode(_DAT_00473fe4);
  return _DAT_00473fd4;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0041bd40(void)

{
  undefined4 unaff_retaddr;
  
  _DAT_00473fe4 = SetErrorMode(0x8001);
  _DAT_00473fd4 = CloseHandle(unaff_retaddr);
  SetErrorMode(_DAT_00473fe4);
  return _DAT_00473fd4;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0041bd80(undefined4 param_1,undefined4 param_2)

{
  undefined4 unaff_retaddr;
  
  _DAT_00473fe4 = SetErrorMode(0x8001);
  _DAT_00473fe8 = GetModuleFileNameA(unaff_retaddr,param_1,param_2);
  SetErrorMode(_DAT_00473fe4);
  return _DAT_00473fe8;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0041bdc0(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 unaff_retaddr;
  
  _DAT_00473fe4 = SetErrorMode(0x8001);
  _DAT_00473fd4 = GetDiskFreeSpaceA(unaff_retaddr,param_1,param_2,param_3,param_4);
  SetErrorMode(_DAT_00473fe4);
  return _DAT_00473fd4;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0041be10(void)

{
  undefined4 unaff_retaddr;
  
  _DAT_00473fe4 = SetErrorMode(0x8001);
  _DAT_00473fd4 = SetCurrentDirectoryA(unaff_retaddr);
  SetErrorMode(_DAT_00473fe4);
  return _DAT_00473fd4;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0041be50(void)

{
  _DAT_00473fe4 = SetErrorMode(0x8001);
  _DAT_00473fe8 = GetLogicalDrives();
  SetErrorMode(_DAT_00473fe4);
  return _DAT_00473fe8;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0041be80(undefined4 param_1)

{
  undefined4 unaff_retaddr;
  
  _DAT_00473fe4 = SetErrorMode(0x8001);
  _DAT_00473fd8 = FindFirstFileA(unaff_retaddr,param_1);
  SetErrorMode(_DAT_00473fe4);
  return _DAT_00473fd8;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0041bec0(undefined4 param_1)

{
  undefined4 unaff_retaddr;
  
  _DAT_00473fe4 = SetErrorMode(0x8001);
  _DAT_00473fd4 = FindNextFileA(unaff_retaddr,param_1);
  SetErrorMode(_DAT_00473fe4);
  return _DAT_00473fd4;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0041bf00(undefined4 param_1)

{
  undefined4 unaff_retaddr;
  
  _DAT_00473fe4 = SetErrorMode(0x8001);
  _DAT_00473fd4 = SetFileAttributesA(unaff_retaddr,param_1);
  SetErrorMode(_DAT_00473fe4);
  return _DAT_00473fd4;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0041bf40(void)

{
  undefined4 unaff_retaddr;
  
  _DAT_00473fe4 = SetErrorMode(0x8001);
  _DAT_00473fd4 = ShellExecuteExA(unaff_retaddr);
  SetErrorMode(_DAT_00473fe4);
  return _DAT_00473fd4;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0041bf80(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  undefined4 unaff_retaddr;
  
  _DAT_00473fe4 = SetErrorMode(0x8001);
  _DAT_00473fd4 = GetFileVersionInfoA(unaff_retaddr,param_1,param_2,param_3);
  SetErrorMode(_DAT_00473fe4);
  return _DAT_00473fd4;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0041bfd0(undefined4 param_1)

{
  undefined4 unaff_retaddr;
  
  _DAT_00473fe4 = SetErrorMode(0x8001);
  _DAT_00473fe8 = GetFileVersionInfoSizeA(unaff_retaddr,param_1);
  SetErrorMode(_DAT_00473fe4);
  return _DAT_00473fe8;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0041c010(int param_1,int *param_2,undefined4 *param_3)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  undefined4 uStack_28;
  undefined4 uStack_24;
  undefined4 uStack_20;
  undefined4 uStack_1c;
  undefined4 uStack_18;
  
  uVar3 = (uint)(param_3 == (undefined4 *)0x0);
  if (param_2 != (int *)0x0) {
    *param_2 = 0;
  }
  if (param_3 != (undefined4 *)0x0) {
    *param_3 = 0;
    param_3[1] = 0;
  }
  if (param_1 == 0) goto LAB_0041c0ef;
  uStack_18 = 0x8001;
  uStack_1c = 0x41c05d;
  _DAT_00473fe4 = SetErrorMode();
  uStack_1c = 0;
  uStack_20 = 0x80;
  uStack_24 = 3;
  uStack_28 = 0;
  iVar1 = CreateFileA(param_1,0x80000000,1);
  if (iVar1 == -1) {
LAB_0041c0dc:
    GetLastError();
  }
  else {
    iVar2 = GetFileType(iVar1);
    if (iVar2 == 1) {
      if (param_2 != (int *)0x0) {
        iVar2 = GetFileSize(iVar1,&uStack_28);
        if (iVar2 == -1) {
          GetLastError();
        }
        else {
          uStack_1c = 1;
          *param_2 = iVar2;
        }
      }
      if (param_3 != (undefined4 *)0x0) {
        uVar3 = GetFileTime(iVar1,0,0,param_3);
        if (uVar3 != 0) {
          GetLastError();
        }
      }
    }
    iVar1 = CloseHandle(iVar1);
    if (iVar1 == 0) goto LAB_0041c0dc;
  }
  SetErrorMode(_DAT_00473fe4);
LAB_0041c0ef:
  if ((param_2 == (int *)0x0) && (uVar3 != 0)) {
    return 1;
  }
  return 0;
}



int FUN_0041c750(undefined4 param_1,undefined4 param_2)

{
  char cVar1;
  undefined2 uVar2;
  int iVar3;
  code *pcVar4;
  int iVar5;
  char *pcVar6;
  undefined4 uVar7;
  undefined2 *puVar8;
  char acStack_214 [4];
  undefined4 uStack_210;
  uint uStack_20c;
  undefined auStack_208 [248];
  undefined auStack_110 [264];
  undefined4 uStack_8;
  
  uStack_20c = 0;
  uStack_210 = 0;
  lstrcpyA(auStack_208,param_2);
  FUN_0040dc60(auStack_208,0x104);
  iVar3 = LoadLibraryA(auStack_208);
  if (iVar3 == 0) {
    FUN_0041dcd0(0x80000002,0x466bc0,0x466bdc,&DAT_0046e83c,&uStack_20c,0x104);
    iVar3 = lstrlenA(&uStack_20c);
    if (iVar3 == 0) {
      return 0;
    }
  }
  else {
    uStack_20c = uStack_20c & 0xffffff00;
    pcVar4 = (code *)GetProcAddress(iVar3,0x466ba8);
    if (pcVar4 == (code *)0x0) {
      FreeLibrary(iVar3);
      return 0;
    }
    iVar5 = (*pcVar4)(&uStack_210,acStack_214);
    if (iVar5 == 0) {
      FreeLibrary(iVar3);
      return 1;
    }
    FreeLibrary(iVar3);
  }
  iVar3 = lstrlenA(&uStack_210);
  if (iVar3 != 0) {
    pcVar6 = acStack_214;
    iVar3 = 0;
    if (acStack_214[0] != '\0') {
      puVar8 = (undefined2 *)&stack0xfffffdd4;
      do {
        if (3 < iVar3) break;
        uVar2 = FUN_0044bab9(pcVar6);
        *puVar8 = uVar2;
        cVar1 = *pcVar6;
        while ((cVar1 != '\0' && (cVar1 != '.'))) {
          pcVar6 = (char *)CharNextA(pcVar6);
          cVar1 = *pcVar6;
        }
        if (*pcVar6 != '\0') {
          pcVar6 = (char *)CharNextA(pcVar6);
        }
        iVar3 = iVar3 + 1;
        puVar8 = puVar8 + 1;
      } while (*pcVar6 != '\0');
    }
  }
  lstrcpyA(auStack_110,uStack_8);
  uVar7 = FUN_0044c415(auStack_110,0x463fa0);
  FUN_0044bab9(uVar7);
  uVar7 = FUN_0044c415(0,0x463fa0);
  FUN_0044bab9(uVar7);
  uVar7 = FUN_0044c415(0,0x463fa0);
  FUN_0044bab9(uVar7);
  uVar7 = FUN_0044c415(0,0x463fa0);
  FUN_0044bab9(uVar7);
  iVar3 = 0;
  do {
    if (*(short *)(auStack_208 + iVar3 * 2 + -0x1c) != *(short *)(&stack0xfffffdd4 + iVar3 * 2)) {
      return 4 - (uint)(*(ushort *)(auStack_208 + iVar3 * 2 + -0x1c) <
                       *(ushort *)(&stack0xfffffdd4 + iVar3 * 2));
    }
    iVar3 = iVar3 + 1;
  } while (iVar3 < 4);
  return 2;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0041d290(void)

{
  bool bVar1;
  int iVar2;
  char *pcVar3;
  undefined *puVar4;
  uint uVar5;
  undefined **ppuVar6;
  char in_stack_00000250;
  int in_stack_00001d4c;
  undefined *apuStack_18 [2];
  
  FUN_0044c080();
  bVar1 = false;
  if ((_DAT_00472190 == 0) && (_DAT_00472178 == 0)) {
    if (_DAT_004721c0 != 0) {
      FreeLibrary();
    }
    bVar1 = true;
  }
  FUN_0041a5c0();
  if (bVar1) {
    return;
  }
  apuStack_18[1] = &stack0x00000260;
  apuStack_18[0] = (undefined *)0x208;
  GetTempPathA();
  lstrcatA();
  iVar2 = FUN_0041b870();
  if (iVar2 == -1) {
    GetWindowsDirectoryA();
    while (in_stack_00000250 != '\0') {
      pcVar3 = (char *)CharNextA();
      in_stack_00000250 = *pcVar3;
    }
    pcVar3 = (char *)CharPrevA();
    if (*pcVar3 != '\\') {
      lstrcatA();
    }
    lstrcatA();
    iVar2 = FUN_0041b870();
    if (iVar2 == -1) goto LAB_0041d7c2;
  }
  FUN_0041bd80();
  FUN_0040e750();
  if (_DAT_00472190 == 0) {
    FUN_0040d4c0();
    CharNextA();
    iVar2 = lstrcmpiA();
    if (iVar2 == 0) goto LAB_0041d423;
    bVar1 = false;
  }
  else {
LAB_0041d423:
    bVar1 = true;
  }
  FUN_00410910();
  wsprintfA();
  if (bVar1) {
    lstrlenA();
    wsprintfA();
    if (_DAT_004721c0 != 0) {
      FUN_0041bd80();
      FreeLibrary();
      _DAT_004721c0 = 0;
      FUN_00410910();
      lstrlenA();
      wsprintfA();
    }
    if (_DAT_00472178 != 0) {
      FUN_0041bd80();
      puVar4 = (undefined *)FUN_0040d4c0();
      *puVar4 = 0;
      iVar2 = FUN_0040d4c0();
      while (iVar2 != 0) {
        FUN_00410910();
        lstrlenA();
        wsprintfA();
        puVar4 = (undefined *)FUN_0040d4c0();
        if (puVar4 == (undefined *)0x0) break;
        *puVar4 = 0;
        iVar2 = FUN_0040d4c0();
      }
    }
  }
  FUN_00410910();
  lstrlenA();
  wsprintfA();
  CharToOemA();
  lstrlenA();
  FUN_0041b9b0();
  FlushFileBuffers();
  CloseHandle();
  iVar2 = GetEnvironmentVariableA();
  if (iVar2 != 0) {
    uVar5 = FUN_0040d140();
    if (((uVar5 & 0x13) != 0) && (puVar4 = (undefined *)FUN_0040d4c0(), puVar4 != (undefined *)0x0))
    {
      *puVar4 = 0;
      lstrcpyA();
      *puVar4 = 0x5c;
      lstrcatA();
      lstrcatA();
      lstrcatA();
    }
    lstrcatA();
    lstrcatA();
    lstrcpyA();
  }
  if (in_stack_00001d4c == 0) {
    GetWindowsDirectoryA();
    ppuVar6 = apuStack_18;
    for (iVar2 = 0x11; iVar2 != 0; iVar2 = iVar2 + -1) {
      *ppuVar6 = (undefined *)0x0;
      ppuVar6 = ppuVar6 + 1;
    }
    apuStack_18[0] = (undefined *)0x44;
    iVar2 = CreateProcessA();
    if (iVar2 != 0) {
      SetThreadPriority();
      GetCurrentThread();
      SetThreadPriority();
      GetCurrentProcess();
      SetPriorityClass();
      CloseHandle();
      ResumeThread();
      CloseHandle();
    }
  }
  else {
    FUN_0041de30();
  }
LAB_0041d7c2:
  FUN_0041be10();
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0041d7e0(int param_1)

{
  int iVar1;
  undefined4 *puVar2;
  undefined auStack_738 [2];
  undefined uStack_736;
  undefined uStack_735;
  char cStack_734;
  undefined4 auStack_733 [11];
  undefined auStack_704 [4];
  char cStack_700;
  undefined4 auStack_6ff [11];
  undefined auStack_6d0 [4];
  char cStack_6cc;
  undefined4 uStack_6cb;
  undefined auStack_690 [4];
  char cStack_68c;
  undefined4 uStack_68b;
  undefined auStack_58c [52];
  undefined auStack_558 [64];
  undefined auStack_518 [4];
  char cStack_514;
  undefined4 uStack_513;
  undefined auStack_414 [4];
  char cStack_410;
  undefined4 uStack_40f;
  char cStack_30c;
  undefined4 uStack_30b;
  char cStack_208;
  undefined4 uStack_207;
  undefined auStack_108 [264];
  
  cStack_734 = DAT_0046e83c;
  cStack_700 = DAT_0046e83c;
  puVar2 = auStack_733;
  for (iVar1 = 0xc; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  *(undefined *)puVar2 = 0;
  cStack_208 = DAT_0046e83c;
  puVar2 = auStack_6ff;
  for (iVar1 = 0xc; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  *(undefined *)puVar2 = 0;
  cStack_514 = DAT_0046e83c;
  puVar2 = &uStack_207;
  for (iVar1 = 0x40; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  *(undefined2 *)puVar2 = 0;
  *(undefined *)((int)puVar2 + 2) = 0;
  cStack_410 = DAT_0046e83c;
  puVar2 = &uStack_513;
  for (iVar1 = 0x40; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  *(undefined2 *)puVar2 = 0;
  *(undefined *)((int)puVar2 + 2) = 0;
  cStack_68c = DAT_0046e83c;
  puVar2 = &uStack_40f;
  for (iVar1 = 0x40; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  *(undefined2 *)puVar2 = 0;
  *(undefined *)((int)puVar2 + 2) = 0;
  cStack_30c = DAT_0046e83c;
  puVar2 = &uStack_68b;
  for (iVar1 = 0x40; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  *(undefined2 *)puVar2 = 0;
  *(undefined *)((int)puVar2 + 2) = 0;
  cStack_6cc = DAT_0046e83c;
  puVar2 = &uStack_30b;
  for (iVar1 = 0x40; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  *(undefined2 *)puVar2 = 0;
  *(undefined *)((int)puVar2 + 2) = 0;
  puVar2 = &uStack_6cb;
  for (iVar1 = 0xf; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  *(undefined2 *)puVar2 = 0;
  *(undefined *)((int)puVar2 + 2) = 0;
  uStack_736 = 0x31;
  uStack_735 = 0;
  FUN_0040e750(_DAT_004721c0,(-(param_1 != 0) & 0x14U) + 10,0x472c98,0x104);
  iVar1 = FUN_0040e750(_DAT_004721c0,0x7ff,&cStack_734,0x32);
  _DAT_004734b8 = 1;
  if ((iVar1 != 0) && (cStack_734 == '1')) {
    _DAT_004734b8 = 0;
  }
  FUN_0040e750(_DAT_004721c0,0xb,0x472ea0,0x104);
  FUN_0040e750(_DAT_004721c0,0xc,0x472d9c,0x104);
  FUN_0040e750(_DAT_004721c0,2000,&cStack_30c,0x104);
  wsprintfA(0x472b94,0x464720,0x472c98,&cStack_30c);
  FUN_0040db40(&cStack_208,0x104);
  FUN_0040e750(_DAT_004721c0,(-(param_1 != 0) & 7U) + 0x18,&cStack_514,0x104);
  FUN_0040e750(_DAT_004721c0,0x134,&cStack_410,0x104);
  lstrcpyA(&cStack_68c,&cStack_208);
  iVar1 = lstrlenA(&cStack_514);
  if (iVar1 != 0) {
    FUN_0040f8a0(auStack_690);
    lstrcatA(auStack_690,auStack_518);
  }
  FUN_0040f8a0(auStack_690);
  lstrcatA(auStack_690,auStack_414);
  FUN_0040e750(_DAT_004721c0,0x7d1,auStack_704,0x32);
  FUN_0041dc40(auStack_704,auStack_690,&DAT_004721e8,0x104);
  FUN_004105e0(&DAT_004721e8,0x104);
  if (param_1 != 0) {
    iVar1 = lstrcmpiA(auStack_690,&DAT_004721e8);
    if (iVar1 == 0) {
      FUN_0040e750(_DAT_004721c0,0x21,auStack_108,0x104);
      FUN_0040e750(_DAT_004721c0,0x26,auStack_58c,0x32);
      FUN_0041dcd0(0x80000002,auStack_108,auStack_58c,auStack_690,&DAT_004721e8,0x104);
      iVar1 = lstrcmpiA(auStack_690,&DAT_004721e8);
      if (iVar1 != 0) {
        wsprintfA(auStack_690,0x464720,&DAT_004721e8,auStack_414);
        lstrcpyA(&DAT_004721e8,auStack_690);
      }
    }
  }
  FUN_0040e750(_DAT_004721c0,0x16,auStack_6d0,0x40);
  iVar1 = FUN_0041dc40(auStack_6d0,&stack0xfffff8c6,auStack_558,0x40);
  if (iVar1 == 0) {
    _DAT_004734f8 = 0;
  }
  else {
    _DAT_004734f8 = FUN_0044bac4(auStack_558);
  }
  FUN_0040e750(_DAT_004721c0,0x12,auStack_738,0x32);
  FUN_0041dc40(auStack_738,&DAT_0046e83c,0x472888,0x104);
  FUN_0040e750(_DAT_004721c0,0x23,auStack_738,0x32);
  FUN_0041dc40(auStack_738,&DAT_0046e83c,0x47298c,0x104);
  return 1;
}



undefined4 FUN_0041dc40(void)

{
  int iVar1;
  int iVar2;
  undefined4 unaff_ESI;
  undefined4 unaff_EDI;
  undefined4 in_stack_00000010;
  undefined *puVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  undefined auStack_4 [4];
  
  puVar3 = auStack_4;
  uVar5 = 1;
  uVar4 = 0x472b94;
  iVar1 = RegOpenKeyExA(0x80000002,0x472b94,0,1,auStack_4);
  if (iVar1 == 0) {
    puVar3 = auStack_4;
    iVar2 = RegQueryValueExA(uVar4,uVar5,0,0,unaff_ESI,puVar3);
    if (iVar2 != 0) {
      lstrcpynA(unaff_ESI,puVar3,in_stack_00000010);
      lstrlenA(puVar3);
    }
    RegCloseKey(iVar1);
    return unaff_EDI;
  }
  lstrcpynA(unaff_ESI,puVar3,in_stack_00000010);
  uVar4 = lstrlenA(puVar3);
  return uVar4;
}



undefined4 FUN_0041dcd0(undefined4 param_1,undefined4 param_2)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  undefined4 unaff_EBX;
  undefined4 unaff_retaddr;
  int in_stack_00000018;
  undefined4 uStack_18;
  undefined4 *puStack_14;
  
  iVar1 = in_stack_00000018;
  puStack_14 = &stack0x00000018;
  uStack_18 = 1;
  iVar2 = RegOpenKeyExA(param_1,param_2,0);
  if (iVar2 == 0) {
    iVar2 = RegQueryValueExA(param_1,unaff_EBX,0,&stack0xfffffff4,unaff_retaddr,&uStack_18);
    RegCloseKey(puStack_14);
    if (iVar2 == 0) {
      return uStack_18;
    }
  }
  if (iVar1 != 0) {
    lstrcpynA(unaff_retaddr,iVar1,iVar1);
    uVar3 = lstrlenA(iVar1);
    return uVar3;
  }
  return 0;
}



int FUN_0041dd60(undefined4 param_1,undefined4 param_2)

{
  int iVar1;
  undefined4 unaff_retaddr;
  undefined4 *puVar2;
  undefined4 uStack_10;
  undefined4 uStack_c;
  undefined4 uStack_8;
  undefined4 *puStack_4;
  
  puStack_4 = &param_2;
  uStack_8 = 1;
  uStack_c = 0;
  uStack_10 = param_2;
  iVar1 = RegOpenKeyExA(param_1);
  if (iVar1 == 0) {
    puVar2 = &uStack_10;
    iVar1 = RegQueryValueExA(uStack_c,uStack_8,0,puVar2,puStack_4,unaff_retaddr);
    RegCloseKey(puVar2);
  }
  return iVar1;
}



bool FUN_0041de30(undefined4 param_1,undefined4 *param_2,uint param_3)

{
  char cVar1;
  undefined4 *puVar2;
  int iVar3;
  int iVar4;
  undefined4 unaff_retaddr;
  int iVar5;
  undefined4 uVar6;
  undefined4 uStack_138;
  undefined4 *puStack_134;
  undefined4 *puStack_130;
  undefined4 *puStack_12c;
  undefined4 uStack_118;
  undefined4 uStack_114;
  char *pcStack_110;
  undefined auStack_10c [4];
  char acStack_108 [4];
  undefined auStack_104 [260];
  
  puStack_130 = (undefined4 *)auStack_104;
  puStack_12c = param_2;
  uStack_118 = 0;
  puStack_134 = (undefined4 *)0x41de55;
  lstrcpyA();
  puStack_12c = (undefined4 *)auStack_104;
  puStack_130 = (undefined4 *)0x41de62;
  iVar3 = lstrlenA();
  puStack_130 = (undefined4 *)(acStack_108 + iVar3);
  cVar1 = acStack_108[iVar3];
  while (cVar1 != '\\') {
    if (puStack_130 == (undefined4 *)acStack_108) goto LAB_0041de94;
    puStack_134 = (undefined4 *)acStack_108;
    uStack_138 = 0x41de85;
    puStack_130 = (undefined4 *)CharPrevA();
    cVar1 = *(char *)puStack_130;
  }
  pcStack_110 = (char *)((int)puStack_130 + 1);
  *(char *)puStack_130 = '\0';
LAB_0041de94:
  puStack_130 = param_2;
  puStack_134 = (undefined4 *)0x41dea1;
  iVar3 = FUN_00410c20();
  if ((iVar3 != 0) && (param_2 != (undefined4 *)0x0)) {
    *(char *)param_2 = '\0';
  }
  if (param_3 != 0) {
    if (param_3 < 3) {
      puStack_130 = param_2;
      puStack_134 = (undefined4 *)0x41dee0;
      iVar3 = lstrlenA();
      iVar3 = iVar3 + 1;
      goto LAB_0041df0a;
    }
    if (param_3 == 4) {
      puStack_130 = param_2;
      puStack_134 = (undefined4 *)0x41ded2;
      uStack_114 = FUN_0044ba2e();
      iVar3 = 4;
      goto LAB_0041df0a;
    }
  }
  iVar3 = -param_3;
  param_3 = 3;
  if (*(char *)param_2 == '#') {
    param_2 = (undefined4 *)((int)param_2 + 1);
    puStack_134 = (undefined4 *)0x41defb;
    puStack_130 = param_2;
    uStack_114 = FUN_0044ba2e();
  }
LAB_0041df0a:
  puStack_130 = (undefined4 *)auStack_10c;
  puStack_134 = &uStack_118;
  uStack_138 = 0;
  uVar6 = 0xf003f;
  iVar5 = 0;
  iVar4 = RegCreateKeyExA(unaff_retaddr,acStack_108,0,0,0,0xf003f);
  puVar2 = puStack_134;
  if (iVar4 == 0) {
    if (iVar5 != 0) {
      param_2 = &uStack_138;
    }
    iVar4 = FUN_00410c20(puStack_134,0,param_3,param_2,iVar3);
    iVar4 = RegSetValueExA(uVar6,~-(uint)(iVar4 != 0) & (uint)puVar2);
    RegCloseKey(iVar3);
  }
  return iVar4 == 0;
}



// WARNING: Removing unreachable block (ram,0x0041e34b)

float10 FUN_0041e0e0(void)

{
  double dVar1;
  double dVar2;
  uint uVar3;
  undefined4 uVar4;
  int iVar5;
  double *pdVar6;
  int iVar7;
  double *pdVar8;
  uint unaff_EBX;
  int iVar9;
  int iVar10;
  int aiStack_f0 [2];
  undefined8 uStack_e8;
  undefined4 uStack_d0;
  undefined4 uStack_cc;
  undefined4 uStack_c8;
  undefined4 uStack_c4;
  undefined4 uStack_c0;
  undefined4 uStack_bc;
  undefined4 uStack_b8;
  undefined4 uStack_b4;
  undefined4 uStack_b0;
  undefined4 uStack_ac;
  undefined4 uStack_a8;
  undefined4 uStack_a4;
  undefined4 uStack_a0;
  undefined4 uStack_9c;
  undefined4 uStack_98;
  undefined4 uStack_94;
  undefined4 uStack_90;
  undefined4 uStack_8c;
  undefined4 uStack_88;
  undefined4 uStack_84;
  undefined4 uStack_80;
  undefined4 uStack_7c;
  undefined4 uStack_78;
  undefined4 uStack_74;
  undefined4 uStack_70;
  undefined4 uStack_6c;
  undefined4 uStack_68;
  undefined4 uStack_64;
  undefined4 uStack_60;
  undefined4 uStack_5c;
  undefined4 uStack_58;
  undefined4 uStack_54;
  undefined4 uStack_50;
  undefined4 uStack_4c;
  undefined4 uStack_48;
  undefined4 uStack_44;
  undefined4 uStack_40;
  undefined4 uStack_3c;
  undefined4 uStack_38;
  undefined4 uStack_34;
  undefined auStack_30 [44];
  
  uStack_d0 = 0x60000000;
  uStack_cc = 0x40091eb8;
  uStack_c8 = 0xe0000000;
  uStack_c4 = 0x400170a3;
  uStack_c0 = 0x60000000;
  uStack_bc = 0x402a428f;
  uStack_b8 = 0;
  uStack_b4 = 0;
  uStack_b0 = 0xa0000000;
  uStack_ac = 0x3ff19999;
  uStack_a8 = 0xc0000000;
  uStack_a4 = 0x4000cccc;
  uStack_a0 = 0xc0000000;
  uStack_9c = 0x4008cccc;
  uStack_98 = 0x60000000;
  uStack_94 = 0x40106666;
  uStack_90 = 0x40000000;
  uStack_8c = 0x3ff33333;
  uStack_88 = 0xa0000000;
  uStack_84 = 0x40019999;
  uStack_80 = 0xa0000000;
  uStack_7c = 0x40099999;
  uStack_78 = 0xc0000000;
  uStack_74 = 0x4010cccc;
  uStack_70 = 0xc0000000;
  uStack_6c = 0x3ff4cccc;
  uStack_68 = 0x60000000;
  uStack_64 = 0x40026666;
  uStack_60 = 0x60000000;
  uStack_5c = 0x400a6666;
  uStack_58 = 0x40000000;
  uStack_54 = 0x40113333;
  uStack_50 = 0x60000000;
  uStack_4c = 0x3ff66666;
  uStack_48 = 0x40000000;
  uStack_44 = 0x40033333;
  uStack_40 = 0x40000000;
  uStack_3c = 0x400b3333;
  uStack_38 = 0xa0000000;
  uStack_34 = 0x40119999;
  QueryPerformanceFrequency();
  uVar3 = GetCurrentProcess();
  uStack_e8._4_4_ = GetPriorityClass();
  uVar4 = GetCurrentProcess(0x100);
  aiStack_f0[0] = SetPriorityClass(uVar4);
  uVar4 = GetCurrentThread();
  iVar5 = GetThreadPriority(uVar4);
  if (iVar5 != 0x7fffffff) {
    uVar4 = GetCurrentThread(0xf);
    SetThreadPriority(uVar4);
  }
  QueryPerformanceCounter(&stack0xffffff00);
  iVar10 = 1000000;
  do {
    pdVar8 = (double *)&uStack_c0;
    iVar7 = 0;
    do {
      iVar9 = 3;
      *(double *)((int)&uStack_40 + iVar7) = pdVar8[-1] * *(double *)((int)&uStack_e8 + iVar7);
      dVar1 = *(double *)((int)&uStack_40 + iVar7);
      pdVar6 = pdVar8;
      do {
        dVar2 = *pdVar6;
        pdVar6 = pdVar6 + 1;
        iVar9 = iVar9 + -1;
        dVar1 = dVar2 * *(double *)((int)&uStack_e8 + iVar7) + dVar1;
      } while (iVar9 != 0);
      *(double *)((int)&uStack_40 + iVar7) = dVar1;
      iVar7 = iVar7 + 8;
      pdVar8 = pdVar8 + 4;
    } while (iVar7 < 0x20);
    iVar10 = iVar10 + -1;
  } while (iVar10 != 0);
  QueryPerformanceCounter(aiStack_f0);
  if (iVar5 != 0x7fffffff) {
    uVar4 = GetCurrentThread(iVar5);
    SetThreadPriority(uVar4);
  }
  return (float10)CONCAT44((aiStack_f0[0] - (int)auStack_30) - (uint)(unaff_EBX < uVar3),
                           unaff_EBX - uVar3) / (float10)CONCAT44(uStack_48,uStack_4c);
}



void FUN_0041e390(undefined4 *param_1,int param_2)

{
  undefined4 *puVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  
  if (param_2 == 0) {
    puVar1 = (undefined4 *)cpuid_basic_info(0);
  }
  else if (param_2 == 1) {
    puVar1 = (undefined4 *)cpuid_Version_info(1);
  }
  else if (param_2 == 2) {
    puVar1 = (undefined4 *)cpuid_cache_tlb_info(2);
  }
  else if (param_2 == 3) {
    puVar1 = (undefined4 *)cpuid_serial_info(3);
  }
  else if (param_2 == 4) {
    puVar1 = (undefined4 *)cpuid_Deterministic_Cache_Parameters_info(4);
  }
  else if (param_2 == 5) {
    puVar1 = (undefined4 *)cpuid_MONITOR_MWAIT_Features_info(5);
  }
  else if (param_2 == 6) {
    puVar1 = (undefined4 *)cpuid_Thermal_Power_Management_info(6);
  }
  else if (param_2 == 7) {
    puVar1 = (undefined4 *)cpuid_Extended_Feature_Enumeration_info(7);
  }
  else if (param_2 == 9) {
    puVar1 = (undefined4 *)cpuid_Direct_Cache_Access_info(9);
  }
  else if (param_2 == 10) {
    puVar1 = (undefined4 *)cpuid_Architectural_Performance_Monitoring_info(10);
  }
  else if (param_2 == 0xb) {
    puVar1 = (undefined4 *)cpuid_Extended_Topology_info(0xb);
  }
  else if (param_2 == 0xd) {
    puVar1 = (undefined4 *)cpuid_Processor_Extended_States_info(0xd);
  }
  else if (param_2 == 0xf) {
    puVar1 = (undefined4 *)cpuid_Quality_of_Service_info(0xf);
  }
  else if (param_2 == -0x7ffffffe) {
    puVar1 = (undefined4 *)cpuid_brand_part1_info(0x80000002);
  }
  else if (param_2 == -0x7ffffffd) {
    puVar1 = (undefined4 *)cpuid_brand_part2_info(0x80000003);
  }
  else if (param_2 == -0x7ffffffc) {
    puVar1 = (undefined4 *)cpuid_brand_part3_info(0x80000004);
  }
  else {
    puVar1 = (undefined4 *)cpuid(param_2);
  }
  uVar4 = puVar1[1];
  uVar3 = puVar1[2];
  uVar2 = puVar1[3];
  *param_1 = *puVar1;
  param_1[1] = uVar4;
  param_1[2] = uVar2;
  param_1[3] = uVar3;
  return;
}



void __fastcall FUN_0041e3e0(undefined4 *param_1)

{
  param_1[0x28] = 0;
  param_1[1] = 0;
  param_1[2] = 0;
  param_1[3] = 0;
  param_1[4] = 0;
  param_1[5] = 0;
  param_1[6] = 0;
  param_1[0xd] = 4;
  *(undefined2 *)(param_1 + 0xf) = 0;
  *param_1 = 0;
  *(undefined *)(param_1 + 0x12) = 0;
  param_1[7] = 0;
  param_1[8] = 0;
  *(undefined *)(param_1 + 9) = 0;
  *(undefined2 *)(param_1 + 0x26) = 0;
  param_1[0x29] = 0;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 __fastcall FUN_0041e440(uint *param_1)

{
  uint uVar1;
  uint uVar2;
  undefined2 uVar3;
  int iVar4;
  uint uVar5;
  uint *puVar6;
  uint *puVar7;
  undefined4 unaff_ESI;
  float10 extraout_ST0;
  undefined4 uVar8;
  undefined auStack_134 [8];
  undefined auStack_12c [92];
  undefined auStack_d0 [16];
  short sStack_c0;
  undefined auStack_bc [40];
  undefined4 auStack_94 [2];
  int iStack_8c;
  
  FUN_0040e750(_DAT_004721c0,0x144,auStack_12c,100);
  FUN_0044bab9(auStack_12c);
  FUN_0040e750(_DAT_004721c0,0x13f,auStack_12c,100);
  iVar4 = FUN_0044bab9(auStack_12c);
  FUN_0040e750(_DAT_004721c0,0x140,auStack_12c,100);
  FUN_0044bab9(auStack_12c);
  auStack_94[0] = 0x94;
  GetVersionExA(auStack_94);
  GetSystemInfo(auStack_bc);
  if (sStack_c0 != 0) {
    return 0;
  }
  if (0 < iVar4) {
    param_1[6] = (uint)(iStack_8c == 2);
    uVar5 = FUN_00422e10();
    *(ushort *)(param_1 + 0xf) = (ushort)uVar5 & 0x7fff;
    param_1[0xd] = uVar5 >> 0xd & 4;
    uVar5 = FUN_00422de0();
    *param_1 = uVar5 & 0xffff;
    if ((uVar5 & 0xffff) != 0) {
      puVar6 = (uint *)FUN_0041e390(&stack0xfffffebc,0);
      uVar5 = puVar6[1];
      uVar1 = puVar6[2];
      uVar2 = puVar6[3];
      puVar7 = param_1 + 9;
      param_1[7] = *puVar6;
      *puVar7 = uVar5;
      param_1[10] = uVar2;
      param_1[0xb] = uVar1;
      *(undefined *)(param_1 + 0xc) = 0;
      FUN_0040e750(_DAT_004721c0,0x32,auStack_134,100);
      iVar4 = lstrcmpA(puVar7,auStack_134);
      if (iVar4 == 0) {
        param_1[0xd] = 0;
      }
      else {
        FUN_0040e750(_DAT_004721c0,0x33,auStack_134,100);
        iVar4 = lstrcmpA(puVar7,auStack_134);
        if (iVar4 == 0) {
          param_1[0xd] = 1;
        }
        else {
          FUN_0040e750(_DAT_004721c0,0x34,auStack_134,100);
          iVar4 = lstrcmpA(puVar7,auStack_134);
          if (iVar4 == 0) {
            param_1[0xd] = 2;
          }
          else {
            FUN_0040e750(_DAT_004721c0,0x35,auStack_134,100);
            iVar4 = lstrcmpA(puVar7,auStack_134);
            param_1[0xd] = (iVar4 != 0) + 3;
          }
        }
      }
      if (param_1[7] != 0) {
        uVar5 = FUN_00422ef0();
        *(ushort *)(param_1 + 0xe) = (ushort)uVar5 & 0xf;
        *(ushort *)((int)param_1 + 0x3a) = (ushort)(byte)((byte)uVar5 >> 4);
        *(ushort *)(param_1 + 0xf) = (byte)(uVar5 >> 8) & 0xf;
        *(ushort *)((int)param_1 + 0x3e) = (ushort)(uVar5 >> 0xc) & 3;
        uVar5 = FUN_00422f40();
        param_1[0x11] = uVar5;
        param_1[1] = (uint)(((byte)uVar5 & 1) == 1);
        param_1[2] = (uint)((uVar5 & 0x800000) == 0x800000);
        param_1[4] = (uint)(((byte)uVar5 & 0x10) == 0x10);
        param_1[5] = (uint)((uVar5 & 0x100) == 0x100);
        if (1 < param_1[7]) {
          puVar7 = (uint *)FUN_0041e390(auStack_d0,2);
          if (((char)*puVar7 == '\x01') && ((*puVar7 & 0x80000000) == 0)) {
            switch(puVar7[3] & 0xff) {
            case 0x40:
              *(undefined2 *)(param_1 + 0x10) = 0;
              break;
            case 0x41:
              *(undefined2 *)(param_1 + 0x10) = 0x80;
              break;
            case 0x42:
              *(undefined2 *)(param_1 + 0x10) = 0x100;
              break;
            case 0x43:
              *(undefined2 *)(param_1 + 0x10) = 0x200;
              break;
            case 0x44:
              *(undefined2 *)(param_1 + 0x10) = 0x400;
              break;
            case 0x45:
              *(undefined2 *)(param_1 + 0x10) = 0x800;
            }
          }
        }
      }
      puVar7 = (uint *)FUN_0041e390(auStack_d0,0x80000000);
      param_1[8] = *puVar7;
    }
    if (*param_1 != 0) {
      uVar5 = param_1[0xd];
      if (uVar5 == 2) {
        uVar8 = 0x80000001;
      }
      else {
        if ((uVar5 != 1) && (uVar5 != 3)) goto LAB_0041e787;
        uVar8 = 0x80000002;
      }
      FUN_0041e800(uVar8);
    }
  }
LAB_0041e787:
  if ((char)((uint)unaff_ESI >> 0x18) == '\0') {
    uVar3 = 0;
  }
  else {
    uVar3 = FUN_00422db0();
  }
  *(undefined2 *)(param_1 + 0x26) = uVar3;
  if ((char)((uint)unaff_ESI >> 0x10) == '\0') {
    *(undefined8 *)(param_1 + 0x28) = 0;
    return 1;
  }
  FUN_0041e0e0();
  *(double *)(param_1 + 0x28) = (double)extraout_ST0;
  return 1;
}



void __thiscall FUN_0041e800(int param_1,int param_2)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  int iVar4;
  undefined4 *puVar5;
  undefined auStack_10 [16];
  
  if (0x80000000 < *(uint *)(param_1 + 0x20)) {
    if ((*(int *)(param_1 + 0x34) == 1) || (*(int *)(param_1 + 0x34) == 3)) {
      iVar4 = FUN_0041e390(auStack_10,0x80000001);
      *(uint *)(param_1 + 0xc) = (uint)((*(uint *)(iVar4 + 0xc) & 0x80000000) == 0x80000000);
    }
    if (param_2 + 1U < *(uint *)(param_1 + 0x20)) {
      puVar5 = (undefined4 *)FUN_0041e390(auStack_10,param_2);
      uVar1 = *puVar5;
      uVar2 = puVar5[2];
      uVar3 = puVar5[3];
      *(undefined4 *)(param_1 + 0x4c) = puVar5[1];
      *(undefined4 *)(param_1 + 0x48) = uVar1;
      *(undefined4 *)(param_1 + 0x50) = uVar2;
      *(undefined4 *)(param_1 + 0x54) = uVar3;
      puVar5 = (undefined4 *)FUN_0041e390(auStack_10,param_2 + 1U);
      uVar1 = *puVar5;
      uVar2 = puVar5[1];
      uVar3 = puVar5[3];
      *(undefined4 *)(param_1 + 0x60) = puVar5[2];
      *(undefined4 *)(param_1 + 0x58) = uVar1;
      *(undefined4 *)(param_1 + 0x5c) = uVar2;
      *(undefined4 *)(param_1 + 100) = uVar3;
      puVar5 = (undefined4 *)FUN_0041e390(auStack_10,param_2 + 2);
      uVar1 = puVar5[1];
      uVar2 = puVar5[2];
      uVar3 = puVar5[3];
      *(undefined4 *)(param_1 + 0x68) = *puVar5;
      *(undefined4 *)(param_1 + 0x6c) = uVar1;
      *(undefined4 *)(param_1 + 0x70) = uVar2;
      *(undefined4 *)(param_1 + 0x74) = uVar3;
      *(undefined *)(param_1 + 0x78) = 0;
    }
  }
  return;
}



undefined4 FUN_0041e8f0(undefined4 param_1,undefined4 *param_2)

{
  undefined4 *puVar1;
  int iVar2;
  int iVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  undefined4 uStack_8;
  undefined auStack_4 [4];
  
  puVar1 = param_2;
  uVar5 = 0;
  *param_2 = 0;
  param_2[1] = 0;
  param_2[2] = 0;
  iVar2 = FUN_0041bfd0(param_1,&uStack_8);
  if (iVar2 == 0) {
    iVar2 = FUN_0040d0e0(param_1);
    if (iVar2 == 0) {
      return 1;
    }
    uVar5 = 0x30;
  }
  else {
    iVar3 = FUN_0044c5a2(iVar2);
    if (iVar3 == 0) {
      return 4;
    }
    iVar2 = FUN_0041bf80(param_1,uStack_8,iVar2,iVar3);
    if (iVar2 == 0) {
      uVar5 = 0x30;
    }
    else {
      iVar2 = VerQueryValueA(iVar3,0x463be4,&param_2,auStack_4);
      if (iVar2 == 0) {
        uVar5 = 0x30;
      }
      else {
        *puVar1 = param_2[2];
        puVar1[1] = param_2[3];
        iVar2 = VerQueryValueA(iVar3,0x466d68,&param_2,auStack_4);
        if (iVar2 == 0) {
          uVar5 = 0x20;
        }
        else {
          puVar1[2] = *param_2;
        }
      }
    }
    FUN_0044c4b9(iVar3);
  }
  iVar2 = FUN_0041c010(param_1,puVar1 + 3,puVar1 + 4);
  uVar4 = 2;
  if (iVar2 != 0) {
    uVar4 = uVar5;
  }
  return uVar4;
}



ushort FUN_0041ea10(undefined4 param_1,uint *param_2,undefined4 param_3,uint *param_4,int param_5)

{
  uint uVar1;
  int iVar2;
  ushort uVar3;
  uint *puVar4;
  uint *puVar5;
  uint auStack_18 [6];
  
  if (param_5 == 0) {
    uVar1 = FUN_0041e8f0(param_1,auStack_18);
    if ((uVar1 & 7) != 0) goto LAB_0041ea5c;
    puVar4 = auStack_18;
    puVar5 = param_2;
    for (iVar2 = 6; iVar2 != 0; iVar2 = iVar2 + -1) {
      *puVar5 = *puVar4;
      puVar4 = puVar4 + 1;
      puVar5 = puVar5 + 1;
    }
  }
  uVar1 = FUN_0041e8f0(param_3,param_4);
  if ((uVar1 & 7) == 0) {
    uVar1 = *param_4;
    if ((((uVar1 == 0) && (param_4[1] == 0)) && (*param_2 == 0)) && (param_2[1] == 0)) {
      uVar3 = 0x10;
    }
    else if (uVar1 < *param_2) {
      uVar3 = 0x20;
    }
    else if (*param_2 < uVar1) {
      uVar3 = 0x40;
    }
    else if (param_4[1] < param_2[1]) {
      uVar3 = 0x20;
    }
    else {
      uVar3 = (-(ushort)(param_2[1] < param_4[1]) & 0x38) + 8;
    }
    if (((uVar3 & 0x90) == 0) && (param_4[2] != param_2[2])) {
      uVar3 = CONCAT11(1,(char)uVar3);
    }
    else {
      uVar3 = uVar3 | 0x80;
    }
    iVar2 = CompareFileTime(param_4 + 4,param_2 + 4);
    if (iVar2 != 0) {
      if (-1 < iVar2) {
        return uVar3 | 0x800;
      }
      return uVar3 | 0x400;
    }
    return uVar3 | 0x200;
  }
LAB_0041ea5c:
  if (uVar1 != 1) {
    return (-(ushort)(uVar1 != 2) & 2) + 2;
  }
  return 1;
}



undefined4 FUN_0041f430(undefined4 param_1,undefined *param_2,int param_3)

{
  uint3 uVar1;
  bool bVar2;
  byte bVar3;
  undefined4 uVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  int iVar11;
  uint uVar12;
  undefined8 uVar13;
  undefined4 uVar14;
  int iStack_49c;
  undefined uStack_498;
  undefined uStack_497;
  byte bStack_494;
  undefined4 uStack_493;
  undefined uStack_48f;
  byte bStack_48e;
  ushort uStack_48d;
  uint uStack_488;
  int aiStack_484 [2];
  undefined uStack_47c;
  undefined uStack_47b;
  undefined uStack_47a;
  byte bStack_479;
  undefined auStack_474 [2];
  ushort uStack_472;
  byte bStack_470;
  uint uStack_46f;
  uint uStack_468;
  int iStack_464;
  undefined4 uStack_460;
  byte bStack_45c;
  undefined uStack_45b;
  undefined uStack_45a;
  byte bStack_459;
  int iStack_454;
  uint uStack_450;
  uint uStack_44c;
  int iStack_448;
  uint uStack_444;
  uint uStack_440;
  int aiStack_43c [2];
  undefined uStack_434;
  undefined uStack_433;
  undefined uStack_432;
  byte bStack_431;
  undefined auStack_42c [4];
  byte bStack_428;
  uint uStack_427;
  undefined2 uStack_410;
  undefined2 uStack_30c;
  undefined auStack_208 [260];
  undefined auStack_104 [260];
  
  uVar14 = 0x466de0;
  uStack_450 = 0;
  uStack_468 = 0;
  *param_2 = 0;
  iStack_464 = 0;
  uStack_460 = 0;
  uVar4 = FUN_0041aa10(param_1,0x466de0);
  iVar5 = lstrcmpiA(uVar4,uVar14);
  if (iVar5 == 0) {
    uStack_468 = 1;
  }
  else {
    uVar14 = 0x466ddc;
    uVar4 = FUN_0041aa10(param_1,0x466ddc);
    iVar5 = lstrcmpiA(uVar4,uVar14);
    if (iVar5 != 0) goto LAB_0041f4a5;
    iStack_464 = 1;
  }
  uStack_460 = 1;
LAB_0041f4a5:
  uStack_444 = GetSystemDefaultLangID();
  iVar5 = FUN_0041b870(param_1,0x80000000,1,0,3,1,0);
  if (iVar5 == -1) {
    return 0;
  }
  iStack_448 = iVar5;
  if (iStack_464 != 0) {
    FUN_0041ba00(iVar5,aiStack_43c,0x10,&iStack_49c,0);
    if (aiStack_43c[0] != 0x66637474) {
      return 0;
    }
    uStack_468 = (((CONCAT12(uStack_432,CONCAT11(uStack_433,uStack_434)) & 0xff) << 8 |
                  CONCAT12(bStack_431,CONCAT11(uStack_432,uStack_433)) & 0xff) << 8 |
                 CONCAT11(bStack_431,uStack_432) & 0xff) << 8 | (uint)bStack_431;
  }
  if (uStack_468 != 0) {
    uStack_488 = 0xc;
    do {
      if (iStack_464 != 0) {
        iVar6 = FUN_0041baf0(iVar5,uStack_488,0,0);
        if (iVar6 == -1) {
          return 0;
        }
        FUN_0041ba00(iVar5,&bStack_45c,4,&iStack_49c,0);
        bVar3 = bStack_45c;
        uVar8 = CONCAT12(bStack_459,CONCAT11(uStack_45a,uStack_45b)) & 0xff;
        uVar9 = (uint)bStack_45c;
        uVar10 = CONCAT11(bStack_459,uStack_45a) & 0xff;
        uVar12 = (uint)bStack_459;
        bStack_45c = bStack_459;
        uStack_45b = (undefined)uVar10;
        uStack_45a = (undefined)uVar8;
        bStack_459 = bVar3;
        iVar6 = FUN_0041baf0(iVar5,((uVar9 << 8 | uVar8) << 8 | uVar10) << 8 | uVar12,0,0);
        if (iVar6 == -1) {
          return 0;
        }
      }
      FUN_0041ba00(iVar5,auStack_42c,0xc,&iStack_49c,0);
      uStack_440 = (int)(short)((ushort)bStack_428 << 8) | uStack_427 & 0xff;
      uStack_44c = 0;
      if (uStack_440 != 0) {
        do {
          if (0x27 < uStack_44c) break;
          iVar6 = FUN_0041ba00(iVar5,aiStack_484,0x10,&iStack_49c,0);
          if (iVar6 == 0) {
            return 0;
          }
          if (iStack_49c != 0x10) {
            return 0;
          }
          if (aiStack_484[0] == 0x656d616e) {
            iVar6 = FUN_0041baf0(iVar5,(((CONCAT12(uStack_47a,CONCAT11(uStack_47b,uStack_47c)) &
                                         0xff) << 8 |
                                        CONCAT12(bStack_479,CONCAT11(uStack_47a,uStack_47b)) & 0xff)
                                        << 8 | CONCAT11(bStack_479,uStack_47a) & 0xff) << 8 |
                                       (uint)bStack_479,0,0);
            if (iVar6 == -1) {
              return 0;
            }
            iVar6 = FUN_0041ba00(iVar5,auStack_474,6,&iStack_49c,0);
            if (iVar6 == 0) {
              return 0;
            }
            if (iStack_49c == 0) {
              return 0;
            }
            uVar9 = (CONCAT12(bStack_470,uStack_472) & 0xff) << 8 | (uint)(byte)(uStack_472 >> 8);
            if ((short)uVar9 != 0) {
LAB_0041f700:
              uVar9 = uVar9 + 0xffff;
              iVar6 = FUN_0041ba00(iVar5,&uStack_498,0xc,&iStack_49c,0);
              if (iVar6 == 0) {
                return 0;
              }
              if (iStack_49c == 0) {
                return 0;
              }
              if ((CONCAT11(uStack_493._1_1_,uStack_493._2_1_) != 5) ||
                 (CONCAT11(uStack_498,uStack_497) == 0)) goto LAB_0041f752;
              iVar6 = FUN_0041baf0(iVar5,((((CONCAT12(uStack_47a,CONCAT11(uStack_47b,uStack_47c)) &
                                            0xff) << 8 |
                                           CONCAT12(bStack_479,CONCAT11(uStack_47a,uStack_47b)) &
                                           0xff) << 8 | CONCAT11(bStack_479,uStack_47a) & 0xff) << 8
                                         | (uint)bStack_479) +
                                         ((int)(short)((ushort)bStack_470 << 8) | uStack_46f & 0xff)
                                         + ((int)(short)((ushort)bStack_48e << 8) |
                                           uStack_48d & 0xff),0,0);
              if (iVar6 == -1) {
                return 0;
              }
              iVar6 = FUN_0041ba00(iVar5,&uStack_410,
                                   (int)(short)((ushort)uStack_493._3_1_ << 8) |
                                   CONCAT11(bStack_48e,uStack_48f) & 0xff,&iStack_49c,0);
              if (iVar6 == 0) {
                return 0;
              }
              if (iStack_49c == 0) {
                return 0;
              }
              if (CONCAT11(uStack_498,uStack_497) == 3) {
                iVar6 = 0;
                uVar9 = (int)(short)((ushort)uStack_493._3_1_ << 8) |
                        CONCAT11(bStack_48e,uStack_48f) & 0xff;
                if (0 < (int)uVar9) {
                  do {
                    *(ushort *)((int)&uStack_410 + iVar6) =
                         CONCAT11(*(undefined *)((int)&uStack_410 + iVar6),
                                  *(undefined *)((int)&uStack_410 + iVar6 + 1));
                    iVar6 = iVar6 + 2;
                  } while (iVar6 < (int)uVar9);
                }
                *(undefined2 *)((int)&uStack_410 + uVar9) = 0;
                WideCharToMultiByte(0,0,&uStack_410,0xffffffff,auStack_208,0x104,0,0);
                lstrcpyA(&uStack_410,auStack_208);
              }
              else {
                *(undefined *)
                 ((int)&uStack_410 +
                 ((int)(short)((ushort)uStack_493._3_1_ << 8) |
                 CONCAT11(bStack_48e,uStack_48f) & 0xff)) = 0;
              }
              if (uStack_488 < 0x10) {
                lstrcpyA(param_2,&uStack_410);
              }
              else {
                lstrcatA(param_2,0x466dd8);
                lstrcatA(param_2,&uStack_410);
              }
            }
LAB_0041f90b:
            if (param_3 != 0) {
              iVar6 = FUN_0041baf0(iVar5,(((CONCAT12(uStack_47a,CONCAT11(uStack_47b,uStack_47c)) &
                                           0xff) << 8 |
                                          CONCAT12(bStack_479,CONCAT11(uStack_47a,uStack_47b)) &
                                          0xff) << 8 | CONCAT11(bStack_479,uStack_47a) & 0xff) << 8
                                         | (uint)bStack_479,0,0);
              if (iVar6 == -1) {
                return 0;
              }
              uVar13 = FUN_0041ba00(iVar5,auStack_474,6,&iStack_49c,0);
              if ((int)uVar13 == 0) {
                return 0;
              }
              if (iStack_49c == 0) {
                return 0;
              }
              iVar6 = 0;
              uVar9 = (uint)(uStack_472 & 0xff) << 8 |
                      CONCAT31((int3)((ulonglong)uVar13 >> 0x28),(char)(uStack_472 >> 8)) &
                      0xffff00ff;
              uVar12 = 0;
              bVar2 = false;
              iVar11 = uVar9 + 0xffff;
              iStack_454 = iVar11;
              if ((short)uVar9 != 0) {
                do {
                  iStack_454 = iVar11;
                  iVar7 = FUN_0041ba00(iVar5,&uStack_498,0xc,&iStack_49c,0);
                  if (iVar7 == 0) {
                    return 0;
                  }
                  if (iStack_49c == 0) {
                    return 0;
                  }
                  iVar7 = iVar11;
                  if (CONCAT11(uStack_493._1_1_,uStack_493._2_1_) == 4) {
                    if (CONCAT11(uStack_498,uStack_497) == 3) {
                      uVar1 = CONCAT12(uStack_47a,CONCAT11(uStack_47b,uStack_47c));
                      if ((iVar6 == 0) || (CONCAT11(bStack_494,(undefined)uStack_493) == 0x409)) {
                        bVar2 = true;
                        iVar6 = ((((uVar1 & 0xff) << 8 |
                                  CONCAT12(bStack_479,CONCAT11(uStack_47a,uStack_47b)) & 0xff) << 8
                                 | CONCAT11(bStack_479,uStack_47a) & 0xff) << 8 | (uint)bStack_479)
                                + ((int)(short)((ushort)bStack_470 << 8) | uStack_46f & 0xff) +
                                ((int)(short)((ushort)bStack_48e << 8) | uStack_48d & 0xff);
                        uVar12 = (int)(short)((ushort)uStack_493._3_1_ << 8) |
                                 CONCAT11(bStack_48e,uStack_48f) & 0xff;
                      }
                      iVar5 = iStack_448;
                      iVar7 = iStack_454;
                      if ((uStack_444 & 0xffff) ==
                          ((int)(short)((ushort)bStack_494 << 8) | uStack_493 & 0xff)) {
                        bVar2 = true;
                        iVar6 = ((((uVar1 & 0xff) << 8 |
                                  CONCAT12(bStack_479,CONCAT11(uStack_47a,uStack_47b)) & 0xff) << 8
                                 | CONCAT11(bStack_479,uStack_47a) & 0xff) << 8 | (uint)bStack_479)
                                + ((int)(short)((ushort)bStack_470 << 8) | uStack_46f & 0xff) +
                                ((int)(short)((ushort)bStack_48e << 8) | uStack_48d & 0xff);
                        uVar12 = (int)(short)((ushort)uStack_493._3_1_ << 8) |
                                 CONCAT11(bStack_48e,uStack_48f) & 0xff;
                        break;
                      }
                    }
                    else {
                      bVar2 = false;
                      iVar6 = ((((CONCAT12(uStack_47a,CONCAT11(uStack_47b,uStack_47c)) & 0xff) << 8
                                | CONCAT12(bStack_479,CONCAT11(uStack_47a,uStack_47b)) & 0xff) << 8
                               | CONCAT11(bStack_479,uStack_47a) & 0xff) << 8 | (uint)bStack_479) +
                              ((int)(short)((ushort)bStack_470 << 8) | uStack_46f & 0xff) +
                              ((int)(short)((ushort)bStack_48e << 8) | uStack_48d & 0xff);
                      uVar12 = (int)(short)((ushort)uStack_493._3_1_ << 8) |
                               CONCAT11(bStack_48e,uStack_48f) & 0xff;
                    }
                  }
                  iVar11 = iVar7 + 0xffff;
                  iStack_454 = iVar11;
                } while ((short)iVar7 != 0);
                if (iVar6 != 0) {
                  iVar6 = FUN_0041baf0(iVar5,iVar6,0,0);
                  if (iVar6 == -1) {
                    return 0;
                  }
                  iVar6 = FUN_0041ba00(iVar5,&uStack_30c,uVar12,&iStack_49c,0);
                  if (iVar6 == 0) {
                    return 0;
                  }
                  if (iStack_49c == 0) {
                    return 0;
                  }
                  if (bVar2) {
                    iVar6 = 0;
                    if (0 < (int)uVar12) {
                      do {
                        *(ushort *)((int)&uStack_30c + iVar6) =
                             CONCAT11(*(undefined *)((int)&uStack_30c + iVar6),
                                      *(undefined *)((int)&uStack_30c + iVar6 + 1));
                        iVar6 = iVar6 + 2;
                      } while (iVar6 < (int)uVar12);
                    }
                    *(undefined2 *)((int)&uStack_30c + uVar12) = 0;
                    WideCharToMultiByte(0,0,&uStack_30c,0xffffffff,auStack_104,0x104,0,0);
                    lstrcpyA(&uStack_30c,auStack_104);
                  }
                  else {
                    *(undefined *)((int)&uStack_30c + uVar12) = 0;
                  }
                  if (uStack_488 < 0x10) {
                    lstrcpyA(param_3,&uStack_30c);
                  }
                  else {
                    lstrcatA(param_3,0x466dd4);
                    lstrcatA(param_3,&uStack_30c);
                  }
                }
              }
            }
          }
          uStack_44c = uStack_44c + 1;
        } while (uStack_44c < uStack_440);
      }
      uStack_450 = uStack_450 + 1;
      uStack_488 = uStack_488 + 4;
    } while (uStack_450 < uStack_468);
  }
  FUN_0041bd40(iVar5);
  return uStack_460;
LAB_0041f752:
  if ((short)uVar9 == 0) goto LAB_0041f90b;
  goto LAB_0041f700;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0041fd50(char *param_1,int param_2)

{
  undefined *puVar1;
  uint uVar2;
  int iVar3;
  undefined4 *puVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  char *pcStack_220;
  undefined *puStack_21c;
  undefined2 *puStack_218;
  char acStack_208 [4];
  undefined2 uStack_204;
  undefined4 auStack_202 [62];
  char acStack_108 [4];
  undefined auStack_104 [260];
  
  uStack_204 = _DAT_00463750;
  puVar4 = auStack_202;
  for (iVar3 = 0x3f; iVar3 != 0; iVar3 = iVar3 + -1) {
    *puVar4 = 0;
    puVar4 = puVar4 + 1;
  }
  *(undefined2 *)puVar4 = 0;
  puStack_218 = &uStack_204;
  puStack_21c = auStack_104;
  _DAT_004734b4 = _DAT_004734b4 | param_2 != 0;
  pcStack_220 = param_1;
  iVar3 = FUN_0041f430();
  if (iVar3 == 0) {
    return 0x2716;
  }
  puStack_218 = (undefined2 *)&DAT_004739e0;
  if (DAT_004739e0 == '\0') {
    puStack_218 = (undefined2 *)param_1;
  }
  puStack_21c = (undefined *)0x41fdce;
  puStack_218 = (undefined2 *)FUN_0040d4c0();
  puStack_21c = (undefined *)0x41fdd8;
  puVar1 = (undefined *)CharNextA();
  DAT_004739e0 = 0;
  if (acStack_208[0] == ' ') {
    pcStack_220 = acStack_208;
    puStack_21c = puVar1;
    lstrcpyA();
  }
  puStack_21c = (undefined *)0x41fdfc;
  uVar2 = FUN_0040d140();
  if ((uVar2 & 0x2c) == 0) {
    puStack_21c = (undefined *)0x466df0;
  }
  else {
    puStack_21c = (undefined *)0x466e20;
  }
  pcStack_220 = acStack_108;
  lstrcpyA();
  puStack_21c = &stack0xfffffdf4;
  pcStack_220 = (char *)0x2;
  uVar6 = 0;
  iVar3 = RegOpenKeyExA(0x80000002,acStack_108,0);
  if (iVar3 != 0) {
    return 0x2716;
  }
  AddFontResourceA(param_1);
  lstrcatA(&puStack_21c,0x466de4);
  iVar3 = lstrlenA(puVar1);
  uVar5 = 1;
  RegSetValueExA(uVar6,&pcStack_220,0,1,puVar1,iVar3 + 1);
  RegCloseKey(uVar5);
  PostMessageA(0xffff,0x1d,0,0);
  return 10000;
}



int FUN_0041feb0(undefined4 param_1,int param_2,int param_3)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iStack_8;
  undefined auStack_4 [4];
  
  iStack_8 = 0;
  if ((param_3 != 0) && (iVar1 = FUN_0040d0e0(param_2), iVar1 != 0)) {
    return 0x20;
  }
  iVar1 = FUN_0044c5a2(0x10000);
  if (iVar1 == 0) {
    return 0xd;
  }
  iVar2 = FUN_0041b870(param_1,0x80000000,1,0,3,0x80,0);
  if (iVar2 == -1) {
    iStack_8 = 2;
    iVar3 = param_2;
  }
  else {
    iVar3 = FUN_0041b870(param_2,0x40000000,1,0,2,0x80,0);
    if (iVar3 == -1) {
LAB_0041ffb0:
      iStack_8 = GetLastError();
    }
    else {
      param_3 = 1;
      do {
        iVar4 = FUN_0041ba00(iVar2,iVar1,0x10000,&param_3,0);
        if (iVar4 == 0) {
          iStack_8 = 0x1f;
          break;
        }
        if (param_3 == 0) break;
        iVar4 = FUN_0041b9b0(iVar3,iVar1,param_3,auStack_4,0);
        if (iVar4 == 0) goto LAB_0041ffb0;
      } while (param_3 != 0);
    }
  }
  FUN_0044c4b9(iVar1);
  if (iStack_8 == 0) {
    FUN_00420020(param_1,iVar3);
  }
  if (iVar3 != -1) {
    FlushFileBuffers(iVar3);
    CloseHandle(iVar3);
  }
  if (iStack_8 != 0) {
    FUN_0041bce0(param_2);
  }
  if (iVar2 != -1) {
    CloseHandle(iVar2);
  }
  return iStack_8;
}



undefined4 FUN_00420020(undefined4 param_1)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  undefined auStack_8 [8];
  
  iVar1 = FUN_0041b870(param_1,0x80000000,1,0,3,0x80,0);
  if (iVar1 != -1) {
    iVar2 = FUN_0041baa0(iVar1,0,0,auStack_8);
    CloseHandle(iVar1);
    if (iVar2 != 0) {
      uVar3 = FUN_0041ba50(param_1,&stack0xfffffff4,0,&stack0xfffffff4);
      return uVar3;
    }
  }
  return 0;
}



void __fastcall FUN_004200f0(undefined4 *param_1)

{
  *param_1 = &UNK_0045db50;
  param_1[6] = 0;
  param_1[7] = 0;
  param_1[0xb] = 0;
  param_1[3] = 0;
  *(undefined *)(param_1 + 4) = 1;
  param_1[1] = 0;
  param_1[5] = 0;
  return;
}



void __fastcall FUN_00420120(undefined4 *param_1)

{
  *param_1 = &UNK_0045db50;
  if (param_1[6] != 0) {
    FUN_00423b70(param_1 + 6,param_1 + 7,0);
    param_1[7] = 0;
    param_1[6] = 0;
  }
  if (param_1[0xb] != 0) {
    DeleteObject(param_1[0xb]);
    param_1[0xb] = 0;
  }
  if (*(char *)(param_1 + 4) != '\0') {
    FUN_0044bb7e(param_1[3]);
    param_1[3] = 0;
  }
  FUN_0044bb7e(param_1[1]);
  param_1[1] = 0;
  return;
}



undefined4 __fastcall FUN_004201a0(int param_1)

{
  undefined4 uVar1;
  
  uVar1 = *(undefined4 *)(param_1 + 0x2c);
  *(undefined4 *)(param_1 + 0x2c) = 0;
  FUN_0044bb7e(*(undefined4 *)(param_1 + 4));
  *(undefined4 *)(param_1 + 4) = 0;
  return uVar1;
}



undefined __thiscall
FUN_00420640(int *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  undefined uVar1;
  char cVar2;
  int iVar3;
  
  uVar1 = 0;
  cVar2 = (**(code **)*param_1)();
  if (cVar2 != '\0') {
    iVar3 = FUN_0044d908(param_1[6],0);
    if (iVar3 == 0) {
      cVar2 = (**(code **)(*param_1 + 4))(param_2,param_3);
      if (cVar2 != '\0') {
        cVar2 = (**(code **)(*param_1 + 8))();
        if (cVar2 != '\0') {
          cVar2 = (**(code **)(*param_1 + 0xc))(param_4);
          if (cVar2 != '\0') {
            uVar1 = 1;
          }
        }
      }
    }
  }
  (**(code **)(*param_1 + 0x10))(uVar1);
  (**(code **)(*param_1 + 0x14))(uVar1);
  (**(code **)(*param_1 + 0x18))(uVar1);
  (**(code **)(*param_1 + 0x1c))(uVar1);
  return uVar1;
}



uint FUN_00420b50(uint param_1,byte *param_2,uint param_3)

{
  uint uVar1;
  uint uVar2;
  
  if (param_2 == (byte *)0x0) {
    return 0;
  }
  param_1 = ~param_1;
  if (7 < param_3) {
    uVar2 = param_3 >> 3;
    do {
      param_3 = param_3 - 8;
      uVar1 = *(uint *)(&UNK_0045db74 + (param_1 & 0xff ^ (uint)*param_2) * 4) ^ param_1 >> 8;
      uVar1 = *(uint *)(&UNK_0045db74 + (uVar1 & 0xff ^ (uint)param_2[1]) * 4) ^ uVar1 >> 8;
      uVar1 = *(uint *)(&UNK_0045db74 + (uVar1 & 0xff ^ (uint)param_2[2]) * 4) ^ uVar1 >> 8;
      uVar1 = *(uint *)(&UNK_0045db74 + (uVar1 & 0xff ^ (uint)param_2[3]) * 4) ^ uVar1 >> 8;
      uVar1 = *(uint *)(&UNK_0045db74 + (uVar1 & 0xff ^ (uint)param_2[4]) * 4) ^ uVar1 >> 8;
      uVar1 = *(uint *)(&UNK_0045db74 + (uVar1 & 0xff ^ (uint)param_2[5]) * 4) ^ uVar1 >> 8;
      uVar1 = *(uint *)(&UNK_0045db74 + (uVar1 & 0xff ^ (uint)param_2[6]) * 4) ^ uVar1 >> 8;
      param_1 = uVar1 >> 8 ^ *(uint *)(&UNK_0045db74 + (uVar1 & 0xff ^ (uint)param_2[7]) * 4);
      param_2 = param_2 + 8;
      uVar2 = uVar2 - 1;
    } while (uVar2 != 0);
  }
  for (; param_3 != 0; param_3 = param_3 - 1) {
    param_1 = param_1 >> 8 ^ *(uint *)(&UNK_0045db74 + (param_1 & 0xff ^ (uint)*param_2) * 4);
    param_2 = param_2 + 1;
  }
  return ~param_1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_00421550(undefined4 param_1,uint param_2)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  uint *puVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  uint uStack_4;
  
  if (_DAT_004737a0 != 0) {
    return -1;
  }
  iVar1 = _DAT_004721bc;
  if (_DAT_004721bc == 0) {
    iVar1 = GetModuleHandleA(0);
  }
  iVar2 = FindResourceA(iVar1,0x4746cc,0x466f10);
  if (iVar2 == 0) {
    uVar8 = 0;
    uVar7 = 0;
    uStack_4 = 0;
    if (_DAT_00466e60 != 0xffffffff) {
      puVar4 = (uint *)0x466e68;
      uVar6 = _DAT_00466e60;
      do {
        if ((param_2 & uVar6) != 0) {
          uVar8 = uVar8 | puVar4[-1];
          uVar7 = uVar7 | *puVar4;
          uStack_4 = uStack_4 | puVar4[1];
        }
        uVar6 = puVar4[2];
        puVar4 = puVar4 + 4;
      } while (uVar6 != 0xffffffff);
    }
    while( true ) {
      uVar6 = uVar8;
      if (uVar8 == 0) {
        uVar6 = 3;
      }
      uVar5 = uStack_4;
      if (uStack_4 == 0) {
        uVar5 = 0x80000000;
      }
      iVar1 = FUN_0041b870(param_1,uVar5,1,0,uVar6,uVar7 | 0x80000080,0);
      if (iVar1 != -1) break;
      if ((_DAT_004747d0 == 0) ||
         (iVar1 = FUN_0040d270(_DAT_004721c8,0x35,0x88,param_1), iVar1 == 2)) {
        _DAT_004737a0 = 1;
        return -1;
      }
      if (iVar1 != 4) {
        return -1;
      }
    }
    return iVar1;
  }
  uVar7 = (uint)(_DAT_004745a8 != 0);
  if (*(int *)(&DAT_004745a8 + uVar7 * 4) != 0) {
    return -1;
  }
  uVar3 = LoadResource(iVar1,iVar2);
  iVar1 = LockResource(uVar3);
  *(int *)(uVar7 * 4 + 0x4745b8) = iVar1;
  if (iVar1 == 0) {
    return -1;
  }
  *(int *)(uVar7 * 4 + 0x4745c0) = iVar1;
  *(undefined4 *)(uVar7 * 4 + 0x4745b0) = *(undefined4 *)(*(int *)(uVar7 * 4 + 0x4745b8) + 8);
  *(undefined4 *)(&DAT_004745a8 + uVar7 * 4) = 1;
  return (-(uint)(uVar7 != 0) & 2) + 0xffffff0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_00421800(int param_1)

{
  int iVar1;
  
  if (param_1 == 0xffffff0) {
    iVar1 = 0;
  }
  else {
    iVar1 = (-(uint)(param_1 != 0xffffff2) & 0xfffffffe) + 1;
    if (iVar1 == -1) {
      CloseHandle(param_1);
      if (_DAT_00473790 == param_1) {
        FUN_0041bce0(&DAT_004738cc);
      }
      return 0;
    }
  }
  *(undefined4 *)(iVar1 * 4 + 0x4745c0) = 0;
  *(undefined4 *)(iVar1 * 4 + 0x4745b8) = 0;
  *(undefined4 *)(&DAT_004745a8 + iVar1 * 4) = 0;
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_00421bb0(undefined4 param_1,int param_2,undefined4 param_3,undefined4 param_4)

{
  int iVar1;
  undefined *puVar2;
  int iVar3;
  int iVar4;
  undefined4 unaff_EDI;
  int unaff_retaddr;
  int iStack_12c;
  undefined auStack_128 [20];
  undefined auStack_114 [12];
  undefined auStack_108 [4];
  undefined auStack_104 [252];
  undefined4 uStack_8;
  undefined4 uStack_4;
  
  iVar4 = 10000;
  _DAT_004747d0 = param_4;
  iStack_12c = FUN_00424600(&UNK_00421530,&UNK_00421540,FUN_00421550,&UNK_004216e0,&UNK_00421780,
                            FUN_00421800,&UNK_00421860,1,auStack_128);
  if (iStack_12c == 0) {
    return 0x2716;
  }
  _DAT_004745a0 = (uint)(param_2 != 0);
  _DAT_004745a4 = 0;
  lstrcpyA(auStack_104,param_1);
  FUN_0040dc60(auStack_104,0x104);
  iVar1 = FUN_0040d4c0(auStack_104);
  if (iVar1 == 0) {
    puVar2 = auStack_104;
  }
  else {
    puVar2 = (undefined *)CharNextA(iVar1);
  }
  lstrcpyA(0x4746cc,puVar2);
  if (iVar1 == 0) {
    FUN_0041bd80(0,0x4745c8,0x104);
    iVar1 = FUN_0040d4c0(0x4745c8);
    if (iVar1 != 0) {
      puVar2 = (undefined *)CharNextA(iVar1);
      *puVar2 = 0;
    }
  }
  else {
    iVar1 = CharNextA(iVar1);
    lstrcpynA(0x4745c8,auStack_108,iVar1 + (1 - (int)auStack_108));
  }
  if (_DAT_004745a0 == 0) {
    lstrcpyA(&DAT_004737c8,0x4745c8);
    lstrcatA(&DAT_004737c8,0x4746cc);
    uStack_4 = 0x463fa0;
  }
  else {
    lstrcpyA(&DAT_004737c8,uStack_8);
  }
  lstrcpyA(&DAT_004738cc,uStack_4);
  _DAT_004737a4 = 0;
  _DAT_004737a0 = 0;
  iVar1 = FUN_00421550(auStack_114,0x8020,0);
  if (iVar1 == -1) {
    iVar4 = 0x2711;
  }
  else {
    iVar3 = FUN_00424710(unaff_EDI,iVar1,&iStack_12c);
    if (iVar3 == 0) {
      FUN_00421800(iVar1);
      iVar4 = 0x2716;
    }
    else {
      FUN_00421800(iVar1);
      iVar1 = FUN_004247e0(unaff_EDI,0x4746cc,0x4745c8,0,&UNK_00421990,0,0);
      if ((iVar1 == 1) ||
         (iVar4 = (-(uint)(_DAT_004737a0 != 0) & 0xfffffffb) + 0x2716, iVar4 != 0x2716))
      goto LAB_00421dcc;
    }
    if (unaff_retaddr != 0) {
      FUN_0040d270(_DAT_004721c8,0x10,0x97,auStack_114);
      iVar4 = 0x2711;
    }
  }
LAB_00421dcc:
  FUN_004246a0(unaff_EDI);
  iVar1 = 10000;
  if (_DAT_004745a4 == 0) {
    iVar1 = iVar4;
  }
  return iVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_00422c40(void)

{
  undefined8 uVar1;
  uint uVar2;
  undefined4 uVar3;
  byte in_CF;
  byte in_PF;
  byte in_AF;
  byte in_ZF;
  byte in_SF;
  byte in_TF;
  byte in_IF;
  byte in_OF;
  byte in_NT;
  byte in_AC;
  byte in_VIF;
  byte in_VIP;
  byte in_ID;
  uint uVar4;
  
  uVar4 = (uint)(in_NT & 1) * 0x4000 | (uint)(in_OF & 1) * 0x800 | (uint)(in_IF & 1) * 0x200 |
          (uint)(in_TF & 1) * 0x100 | (uint)(in_SF & 1) * 0x80 | (uint)(in_ZF & 1) * 0x40 |
          (uint)(in_AF & 1) * 0x10 | (uint)(in_PF & 1) * 4 | (uint)(in_CF & 1) |
          (uint)(in_ID & 1) * 0x200000 | (uint)(in_VIP & 1) * 0x100000 |
          (uint)(in_VIF & 1) * 0x80000 | (uint)(in_AC & 1) * 0x40000;
  uVar2 = uVar4 ^ 0x200000;
  if (((uint)((uVar2 & 0x4000) != 0) * 0x4000 | (uint)((uVar2 & 0x800) != 0) * 0x800 |
       (uint)((uVar2 & 0x400) != 0) * 0x400 | (uint)((uVar2 & 0x200) != 0) * 0x200 |
       (uint)((uVar2 & 0x100) != 0) * 0x100 | (uint)((uVar2 & 0x80) != 0) * 0x80 |
       (uint)((uVar2 & 0x40) != 0) * 0x40 | (uint)((uVar2 & 0x10) != 0) * 0x10 |
       (uint)((uVar2 & 4) != 0) * 4 | (uint)((uVar2 & 1) != 0) |
       (uint)((uVar2 & 0x200000) != 0) * 0x200000 | (uint)((uVar2 & 0x40000) != 0) * 0x40000) ==
      uVar4) {
    uVar3 = 0xffffffff;
  }
  else {
    _DAT_00474808 = timeGetTime();
    _DAT_00474808 = -_DAT_00474808;
    uVar1 = rdtsc();
    _DAT_00474800 = -(int)uVar1;
    iRam00474804 = -(uint)((int)uVar1 != 0) - (int)((ulonglong)uVar1 >> 0x20);
    uVar3 = 0;
  }
  return uVar3;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00422c90(void)

{
  undefined8 uVar1;
  int iVar2;
  bool bVar3;
  
  iVar2 = timeGetTime();
  _DAT_00474808 = _DAT_00474808 + iVar2;
  uVar1 = rdtsc();
  bVar3 = CARRY4(_DAT_00474800,(uint)uVar1);
  _DAT_00474800 = _DAT_00474800 + (uint)uVar1;
  iRam00474804 = iRam00474804 + (int)((ulonglong)uVar1 >> 0x20) + (uint)bVar3;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_00422cb0(void)

{
  float fVar1;
  float fVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  float10 extraout_ST0;
  float fStack_20;
  int aiStack_1c [4];
  undefined4 uStack_c;
  undefined4 uStack_8;
  undefined4 uStack_4;
  
  iVar5 = 0x3c;
  aiStack_1c[0] = 0x4b;
  fVar1 = (float)_DAT_00474800 / ((float)_DAT_00474808 * 1000.0);
  aiStack_1c[1] = 0x42b40000;
  aiStack_1c[2] = 0x5a;
  aiStack_1c[3] = 0x42f00000;
  uStack_c = 0x78;
  uStack_8 = 0x43340000;
  uStack_4 = 0xb4;
  piVar3 = aiStack_1c;
  iVar4 = 4;
  fVar2 = ABS(fVar1 - 60.0);
  do {
    if (ABS(fVar1 - (float)piVar3[-1]) < fVar2) {
      iVar5 = *piVar3;
      fVar2 = ABS(fVar1 - (float)piVar3[-1]);
    }
    piVar3 = piVar3 + 2;
    iVar4 = iVar4 + -1;
  } while (iVar4 != 0);
  iVar4 = FUN_0044c058();
  if (ABS((float10)iVar4 * (float10)16.66667 - (float10)fVar1) < extraout_ST0) {
    return iVar4 * 0x10ab >> 8;
  }
  return iVar5;
}



undefined4 FUN_00422db0(void)

{
  int iVar1;
  undefined4 uVar2;
  
  iVar1 = FUN_00422c40();
  if (iVar1 != 0) {
    return 0;
  }
  Sleep(500);
  FUN_00422c90();
  uVar2 = FUN_00422cb0();
  return uVar2;
}



undefined4 FUN_00422de0(void)

{
  uint uVar1;
  byte in_CF;
  byte in_PF;
  byte in_AF;
  byte in_ZF;
  byte in_SF;
  byte in_TF;
  byte in_IF;
  byte in_OF;
  byte in_NT;
  byte in_AC;
  byte in_VIF;
  byte in_VIP;
  byte in_ID;
  uint uVar2;
  ushort uStack_8;
  
  uVar2 = (uint)(in_NT & 1) * 0x4000 | (uint)(in_OF & 1) * 0x800 | (uint)(in_IF & 1) * 0x200 |
          (uint)(in_TF & 1) * 0x100 | (uint)(in_SF & 1) * 0x80 | (uint)(in_ZF & 1) * 0x40 |
          (uint)(in_AF & 1) * 0x10 | (uint)(in_PF & 1) * 4 | (uint)(in_CF & 1) |
          (uint)(in_ID & 1) * 0x200000 | (uint)(in_VIP & 1) * 0x100000 |
          (uint)(in_VIF & 1) * 0x80000 | (uint)(in_AC & 1) * 0x40000;
  uVar1 = uVar2 ^ 0x200000;
  uVar2 = ((uint)((uVar1 & 0x4000) != 0) * 0x4000 | (uint)((uVar1 & 0x800) != 0) * 0x800 |
           (uint)((uVar1 & 0x400) != 0) * 0x400 | (uint)((uVar1 & 0x200) != 0) * 0x200 |
           (uint)((uVar1 & 0x100) != 0) * 0x100 | (uint)((uVar1 & 0x80) != 0) * 0x80 |
           (uint)((uVar1 & 0x40) != 0) * 0x40 | (uint)((uVar1 & 0x10) != 0) * 0x10 |
           (uint)((uVar1 & 4) != 0) * 4 | (uint)((uVar1 & 1) != 0) |
           (uint)((uVar1 & 0x200000) != 0) * 0x200000 | (uint)((uVar1 & 0x40000) != 0) * 0x40000) ^
          uVar2;
  uStack_8 = (ushort)(uVar2 != 0);
  return CONCAT22((short)(uVar2 >> 0x10),uStack_8);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

uint FUN_00422e10(void)

{
  short sVar1;
  uint uVar2;
  
  sVar1 = FUN_00422de0();
  if (sVar1 == 0) {
    _DAT_0047480c = FUN_00422f80();
    _DAT_0047480c = _DAT_0047480c & 0xffff;
    uVar2 = FUN_00422fc0();
    if ((short)uVar2 != 0) {
      uVar2 = FUN_00423010();
      if ((short)uVar2 != 2) {
        uVar2 = FUN_00423060();
        if ((short)uVar2 != 3) {
          uVar2 = 4;
        }
      }
    }
  }
  else {
    uVar2 = FUN_004230b0();
  }
  if (_DAT_0047480c != 0) {
    uVar2 = uVar2 | 0x8000;
  }
  return uVar2;
}



// WARNING: Removing unreachable block (ram,0x00422ebe)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00422e70(void)

{
  int iVar1;
  undefined4 uStack_24;
  undefined4 uStack_20;
  undefined4 uStack_1c;
  undefined4 uStack_14;
  undefined4 uStack_10;
  undefined4 uStack_c;
  
  uStack_24 = _DAT_00466f78;
  uStack_20 = _DAT_00466f7c;
  uStack_1c = _DAT_00466f80;
  iVar1 = cpuid_basic_info(0);
  uStack_14 = *(undefined4 *)(iVar1 + 4);
  uStack_10 = *(undefined4 *)(iVar1 + 8);
  uStack_c = *(undefined4 *)(iVar1 + 0xc);
  iVar1 = 0;
  do {
    if (*(char *)((int)&uStack_14 + iVar1) != *(char *)((int)&uStack_24 + iVar1)) {
      _DAT_0047480c = 1;
    }
    iVar1 = iVar1 + 1;
  } while (iVar1 < 0xc);
  return;
}



// WARNING: Removing unreachable block (ram,0x00422f12)

uint FUN_00422ef0(void)

{
  undefined4 *puVar1;
  byte bVar2;
  short sVar3;
  int iVar4;
  ushort uStack_8;
  
  uStack_8 = 0;
  sVar3 = FUN_00422de0();
  if (sVar3 != 0) {
    iVar4 = FUN_00422e70();
    if (0 < iVar4) {
      puVar1 = (undefined4 *)cpuid_Version_info(1);
      uStack_8 = (ushort)*puVar1;
    }
    return (uint)uStack_8;
  }
  bVar2 = FUN_00422e10();
  return (uint)bVar2 << 8;
}



// WARNING: Removing unreachable block (ram,0x00422f61)

undefined4 FUN_00422f40(void)

{
  short sVar1;
  int iVar2;
  undefined4 uStack_8;
  
  uStack_8 = 0;
  sVar1 = FUN_00422de0();
  if (sVar1 != 0) {
    iVar2 = FUN_00422e70();
    if (0 < iVar2) {
      iVar2 = cpuid_Version_info(1);
      uStack_8 = *(undefined4 *)(iVar2 + 8);
    }
    return uStack_8;
  }
  return 0;
}



// WARNING: Removing unreachable block (ram,0x00422f9e)

undefined FUN_00422f80(void)

{
  return 1;
}



undefined2 FUN_00422fc0(void)

{
  byte in_OF;
  undefined2 uStack_8;
  
  uStack_8 = 0;
  if (((((in_OF & 1) * '\b' & 8) != 0) * '\b' & 0xf0U) != 0xf0) {
    uStack_8 = 0xffff;
  }
  return uStack_8;
}



undefined2 FUN_00423010(void)

{
  byte in_OF;
  undefined2 uStack_8;
  
  uStack_8 = 2;
  if (((((in_OF & 1) * '\b' & 8) != 0) * '\b' & 0xf0U | 0x40) != 0) {
    uStack_8 = 0xffff;
  }
  return uStack_8;
}



undefined2 FUN_00423060(void)

{
  undefined2 uVar1;
  uint uVar2;
  byte in_AF;
  byte in_TF;
  byte in_IF;
  byte in_NT;
  byte in_AC;
  byte in_VIF;
  byte in_VIP;
  byte in_ID;
  uint uVar3;
  
  uVar3 = (uint)(in_NT & 1) * 0x4000 | (uint)(in_IF & 1) * 0x200 | (uint)(in_TF & 1) * 0x100 |
          (uint)((short)(ushort)&stack0xfffffff4 < 0) * 0x80 |
          (uint)(((uint)&stack0xfffffff4 & 0xfffc) == 0) * 0x40 | (uint)(in_AF & 1) * 0x10 |
          (uint)((POPCOUNT((ushort)&stack0xfffffff4 & 0xfc) & 1U) == 0) * 4 |
          (uint)(in_ID & 1) * 0x200000 | (uint)(in_VIP & 1) * 0x100000 |
          (uint)(in_VIF & 1) * 0x80000 | (uint)(in_AC & 1) * 0x40000;
  uVar2 = uVar3 ^ 0x40000;
  uVar1 = 3;
  if (((uint)((uVar2 & 0x4000) != 0) * 0x4000 | (uint)((uVar2 & 0x400) != 0) * 0x400 |
       (uint)((uVar2 & 0x200) != 0) * 0x200 | (uint)((uVar2 & 0x100) != 0) * 0x100 |
       (uint)((uVar2 & 0x80) != 0) * 0x80 | (uint)((uVar2 & 0x40) != 0) * 0x40 |
       (uint)((uVar2 & 0x10) != 0) * 0x10 | (uint)((uVar2 & 4) != 0) * 4 |
       (uint)((uVar2 & 0x200000) != 0) * 0x200000 | (uint)((uVar2 & 0x40000) != 0) * 0x40000) !=
      uVar3) {
    uVar1 = 0xffff;
  }
  return uVar1;
}



// WARNING: Removing unreachable block (ram,0x004230ce)

uint FUN_004230b0(void)

{
  uint *puVar1;
  int iVar2;
  uint uStack_c;
  
  uStack_c = 0xffff;
  iVar2 = FUN_00422e70();
  if (0 < iVar2) {
    puVar1 = (uint *)cpuid_Version_info(1);
    uStack_c = *puVar1 >> 8 & 0xf;
  }
  return uStack_c;
}



void FUN_00423b70(int *param_1,int *param_2,int *param_3)

{
  int iVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = 0;
  iVar2 = 0;
  iVar1 = 0;
  if (param_1 != (int *)0x0) {
    iVar3 = *param_1;
  }
  if (param_2 != (int *)0x0) {
    iVar2 = *param_2;
  }
  if (param_3 != (int *)0x0) {
    iVar1 = *param_3;
  }
  FUN_00423c00(iVar3,iVar2,iVar1);
  if (iVar2 != 0) {
    FUN_00426580(iVar3,*(undefined4 *)(iVar2 + 0x38));
    FUN_00426530(iVar2);
    *param_2 = 0;
  }
  if (iVar1 != 0) {
    FUN_00426580(iVar3,*(undefined4 *)(iVar1 + 0x38));
    FUN_00426530(iVar1);
    *param_3 = 0;
  }
  if (iVar3 != 0) {
    FUN_00426530(iVar3);
    *param_1 = 0;
  }
  return;
}



void FUN_00423c00(undefined4 *param_1,int param_2,int param_3)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  int iVar4;
  undefined4 *puVar5;
  int iVar6;
  undefined4 *puVar7;
  undefined4 auStack_40 [16];
  
  if (param_2 != 0) {
    FUN_00423fc0(param_1,param_2);
  }
  if (param_3 != 0) {
    FUN_00423fc0(param_1,param_3);
  }
  FUN_00426580(param_1,param_1[0x29]);
  FUN_00426580(param_1,param_1[0x39]);
  FUN_00426580(param_1,param_1[0x38]);
  FUN_00426580(param_1,param_1[0x79]);
  FUN_00426580(param_1,param_1[0x7a]);
  FUN_00426580(param_1,param_1[0x57]);
  FUN_00426580(param_1,param_1[0x58]);
  FUN_00426580(param_1,param_1[0x59]);
  if ((param_1[0x19] & 0x1000) != 0) {
    FUN_00423ef0(param_1,param_1[0x43]);
  }
  if ((param_1[0x19] & 0x2000) != 0) {
    FUN_00426580(param_1,param_1[0x60]);
  }
  if ((param_1[0x19] & 0x4000) != 0) {
    FUN_00426580(param_1,param_1[0x7b]);
  }
  if (param_1[0x5a] != 0) {
    iVar4 = 1 << (8U - (char)param_1[0x54] & 0x1f);
    iVar6 = 0;
    if (0 < iVar4) {
      do {
        FUN_00426580(param_1,*(undefined4 *)(param_1[0x5a] + iVar6 * 4));
        iVar6 = iVar6 + 1;
      } while (iVar6 < iVar4);
    }
  }
  FUN_00426580(param_1,param_1[0x5a]);
  if (param_1[0x5b] != 0) {
    iVar4 = 1 << (8U - (char)param_1[0x54] & 0x1f);
    iVar6 = 0;
    if (0 < iVar4) {
      do {
        FUN_00426580(param_1,*(undefined4 *)(param_1[0x5b] + iVar6 * 4));
        iVar6 = iVar6 + 1;
      } while (iVar6 < iVar4);
    }
  }
  FUN_00426580(param_1,param_1[0x5b]);
  if (param_1[0x5c] != 0) {
    iVar4 = 1 << (8U - (char)param_1[0x54] & 0x1f);
    iVar6 = 0;
    if (0 < iVar4) {
      do {
        FUN_00426580(param_1,*(undefined4 *)(param_1[0x5c] + iVar6 * 4));
        iVar6 = iVar6 + 1;
      } while (iVar6 < iVar4);
    }
  }
  FUN_00426580(param_1,param_1[0x5c]);
  FUN_00426580(param_1,param_1[0x82]);
  FUN_00425f30(param_1 + 0x1b);
  FUN_00426580(param_1,param_1[0x6a]);
  uVar1 = param_1[0x10];
  uVar2 = param_1[0x12];
  puVar5 = param_1;
  puVar7 = auStack_40;
  for (iVar4 = 0x10; iVar4 != 0; iVar4 = iVar4 + -1) {
    *puVar7 = *puVar5;
    puVar5 = puVar5 + 1;
    puVar7 = puVar7 + 1;
  }
  uVar3 = param_1[0x11];
  puVar5 = param_1;
  for (iVar4 = 0x83; iVar4 != 0; iVar4 = iVar4 + -1) {
    *puVar5 = 0;
    puVar5 = puVar5 + 1;
  }
  param_1[0x11] = uVar3;
  puVar5 = auStack_40;
  puVar7 = param_1;
  for (iVar4 = 0x10; iVar4 != 0; iVar4 = iVar4 + -1) {
    *puVar7 = *puVar5;
    puVar5 = puVar5 + 1;
    puVar7 = puVar7 + 1;
  }
  param_1[0x12] = uVar2;
  param_1[0x10] = uVar1;
  return;
}



void FUN_00423ef0(undefined4 param_1,undefined4 param_2)

{
  FUN_00426580(param_1,param_2);
  return;
}



void FUN_00423f30(int param_1,undefined4 param_2,undefined4 param_3)

{
  undefined4 uVar1;
  
  if ((*(byte *)(param_1 + 0x114) & 0x20) == 0) {
    if ((*(uint *)(param_1 + 100) & 0x800) != 0) {
      return;
    }
  }
  else if ((*(uint *)(param_1 + 100) & 0x300) == 0x300) {
    return;
  }
  uVar1 = FUN_00420b50(*(undefined4 *)(param_1 + 0x108),param_2,param_3);
  *(undefined4 *)(param_1 + 0x108) = uVar1;
  return;
}



void FUN_00423fb0(undefined4 *param_1)

{
  int iVar1;
  
  for (iVar1 = 0x2e; iVar1 != 0; iVar1 = iVar1 + -1) {
    *param_1 = 0;
    param_1 = param_1 + 1;
  }
  return;
}



void FUN_00423fc0(undefined4 param_1,int param_2)

{
  int iVar1;
  int iVar2;
  
  if (*(int *)(param_2 + 0x38) != 0) {
    iVar2 = 0;
    if (0 < *(int *)(param_2 + 0x30)) {
      iVar1 = 0;
      do {
        FUN_00426580(param_1,*(undefined4 *)(iVar1 + 4 + *(int *)(param_2 + 0x38)));
        iVar2 = iVar2 + 1;
        iVar1 = iVar1 + 0x10;
      } while (iVar2 < *(int *)(param_2 + 0x30));
    }
    FUN_00426580(param_1,*(undefined4 *)(param_2 + 0x38));
  }
  FUN_00426580(param_1,*(undefined4 *)(param_2 + 0xa0));
  FUN_00426580(param_1,*(undefined4 *)(param_2 + 0xac));
  if (*(int *)(param_2 + 0xb0) != 0) {
    iVar2 = 0;
    if (*(char *)(param_2 + 0xb5) != '\0') {
      do {
        FUN_00426580(param_1,*(undefined4 *)(*(int *)(param_2 + 0xb0) + iVar2 * 4));
        iVar2 = iVar2 + 1;
      } while (iVar2 < (int)(uint)*(byte *)(param_2 + 0xb5));
    }
    FUN_00426580(param_1,*(undefined4 *)(param_2 + 0xb0));
  }
  FUN_00423fb0(param_2);
  return;
}



void FUN_00424080(int param_1,undefined4 param_2,undefined4 param_3)

{
  if (*(code **)(param_1 + 0x50) != (code *)0x0) {
    (**(code **)(param_1 + 0x50))(param_1,param_2,param_3);
    return;
  }
  FUN_00426610(param_1,0x467248);
  return;
}



void FUN_004240b0(int param_1,undefined4 param_2,int param_3)

{
  *(undefined4 *)(param_1 + 0x5c) = param_2;
  if (param_3 == 0) {
    *(undefined **)(param_1 + 0x50) = &UNK_00424110;
  }
  else {
    *(int *)(param_1 + 0x50) = param_3;
  }
  if (*(int *)(param_1 + 0x4c) != 0) {
    *(undefined4 *)(param_1 + 0x4c) = 0;
    FUN_00426640(param_1,0x467298);
    FUN_00426640(param_1,0x467264);
  }
  *(undefined4 *)(param_1 + 0x144) = 0;
  return;
}



undefined4 *
FUN_00424600(code *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,undefined4 param_7,undefined4 param_8,
            undefined4 param_9)

{
  undefined4 *puVar1;
  
  puVar1 = (undefined4 *)(*param_1)(0x804);
  if (puVar1 == (undefined4 *)0x0) {
    FUN_0042cd70(param_9,5,0);
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



undefined4 FUN_004246a0(int param_1)

{
  FUN_00425870(0xf,param_1);
  if (*(int *)(param_1 + 0x4c) != 0) {
    (**(code **)(param_1 + 4))(*(int *)(param_1 + 0x4c));
  }
  if (*(int *)(param_1 + 0x44) != 0) {
    (**(code **)(param_1 + 4))(*(int *)(param_1 + 0x44));
  }
  if (*(int *)(param_1 + 0x48) != 0) {
    (**(code **)(param_1 + 4))(*(int *)(param_1 + 0x48));
  }
  if (*(int *)(param_1 + 0x88) != -1) {
    (**(code **)(param_1 + 0x18))(*(int *)(param_1 + 0x88));
  }
  if (*(int *)(param_1 + 0x84) != -1) {
    (**(code **)(param_1 + 0x18))(*(int *)(param_1 + 0x84));
  }
  (**(code **)(param_1 + 4))(param_1);
  return 1;
}



undefined4 FUN_00424710(undefined4 *param_1,undefined4 param_2,undefined4 *param_3)

{
  int iVar1;
  int aiStack_24 [2];
  undefined4 uStack_1c;
  undefined4 uStack_c;
  undefined2 uStack_8;
  ushort uStack_6;
  undefined2 uStack_4;
  undefined2 uStack_2;
  
  iVar1 = (*(code *)param_1[4])(param_2,aiStack_24,0x24);
  if (iVar1 != 0x24) {
    return 0;
  }
  if (aiStack_24[0] != 0x4643534d) {
    return 0;
  }
  if ((short)uStack_c != 0x103) {
    FUN_0042cd70(*param_1,3,uStack_c & 0xffff);
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



undefined4
FUN_004247e0(undefined4 *param_1,undefined4 param_2,char *param_3,undefined4 param_4,code *param_5,
            undefined4 param_6,undefined4 param_7)

{
  undefined4 *puVar1;
  char cVar2;
  short sVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  undefined4 *puVar7;
  char *pcVar8;
  char *pcVar9;
  undefined4 *puVar10;
  undefined4 uStack_4;
  
  uStack_4 = 0;
  puVar1 = param_1 + 0x1ef;
  param_1[0xe] = param_7;
  param_1[9] = param_5;
  uVar5 = 0xffffffff;
  param_1[10] = param_6;
  *(undefined2 *)((int)param_1 + 0xae) = 0;
  pcVar9 = param_3;
  do {
    pcVar8 = pcVar9;
    if (uVar5 == 0) break;
    uVar5 = uVar5 - 1;
    pcVar8 = pcVar9 + 1;
    cVar2 = *pcVar9;
    pcVar9 = pcVar8;
  } while (cVar2 != '\0');
  uVar5 = ~uVar5;
  puVar7 = (undefined4 *)(pcVar8 + -uVar5);
  puVar10 = (undefined4 *)((int)param_1 + 0x5b9);
  for (uVar6 = uVar5 >> 2; uVar6 != 0; uVar6 = uVar6 - 1) {
    *puVar10 = *puVar7;
    puVar7 = puVar7 + 1;
    puVar10 = puVar10 + 1;
  }
  for (uVar5 = uVar5 & 3; uVar5 != 0; uVar5 = uVar5 - 1) {
    *(undefined *)puVar10 = *(undefined *)puVar7;
    puVar7 = (undefined4 *)((int)puVar7 + 1);
    puVar10 = (undefined4 *)((int)puVar10 + 1);
  }
  iVar4 = FUN_00424a90(param_1,param_2,0,0xffff);
  if (iVar4 != 0) {
    uVar5 = 0xffffffff;
    param_1[0x27] = 0;
    param_1[0x24] = 0xffff;
    do {
      pcVar9 = param_3;
      if (uVar5 == 0) break;
      uVar5 = uVar5 - 1;
      pcVar9 = param_3 + 1;
      cVar2 = *param_3;
      param_3 = pcVar9;
    } while (cVar2 != '\0');
    uVar5 = ~uVar5;
    puVar7 = (undefined4 *)(pcVar9 + -uVar5);
    puVar10 = (undefined4 *)((int)param_1 + 0x5b9);
    for (uVar6 = uVar5 >> 2; uVar6 != 0; uVar6 = uVar6 - 1) {
      *puVar10 = *puVar7;
      puVar7 = puVar7 + 1;
      puVar10 = puVar10 + 1;
    }
    for (uVar5 = uVar5 & 3; uVar5 != 0; uVar5 = uVar5 - 1) {
      *(undefined *)puVar10 = *(undefined *)puVar7;
      puVar7 = (undefined4 *)((int)puVar7 + 1);
      puVar10 = (undefined4 *)((int)puVar10 + 1);
    }
    iVar4 = FUN_004257a0(param_1);
    while (iVar4 != 0) {
      do {
        sVar3 = *(short *)(param_1 + 0x2b);
        *(short *)(param_1 + 0x2b) = sVar3 + -1;
        if (sVar3 == 0) {
          uStack_4 = 1;
          goto LAB_00424a3e;
        }
        iVar4 = FUN_00425520(param_1);
        if (iVar4 == 0) goto LAB_00424a3e;
        param_1[0x1f0] = param_1 + 0x2d;
        *puVar1 = param_1[0x1d];
        param_1[0x1f1] = (int)param_1 + 0x1b5;
        param_1[0x1f2] = (int)param_1 + 0x2b6;
        *(undefined2 *)(param_1 + 0x1f5) = *(undefined2 *)((int)param_1 + 0x7e);
        *(undefined2 *)((int)param_1 + 0x7d6) = *(undefined2 *)(param_1 + 0x20);
        *(undefined2 *)(param_1 + 0x1f6) = *(undefined2 *)((int)param_1 + 0x82);
        param_1[499] = param_1[0xe];
        *(undefined2 *)((int)param_1 + 0x7de) = *(undefined2 *)(param_1 + 0x1f);
        if ((*(ushort *)(param_1 + 0x1f) & 0xfffd) == 0xfffd) {
          if (param_1[0x27] == 0) {
            iVar4 = (*param_5)(1,puVar1);
            if (iVar4 == -1) {
              FUN_0042cd70(*param_1,0xb,0);
              goto LAB_00424a3e;
            }
          }
          else {
            iVar4 = (*param_5)(2);
            param_1[0x23] = iVar4;
            if (iVar4 == -1) {
              FUN_0042cd70(*param_1,0xb,0);
              goto LAB_00424a3e;
            }
            if (iVar4 == 0) {
              if ((*(ushort *)(param_1 + 0x1f) & 0xfffe) == 0xfffe) {
                *(short *)((int)param_1 + 0xae) = *(short *)((int)param_1 + 0xae) + 1;
              }
            }
            else {
              iVar4 = FUN_00424ed0(param_1);
joined_r0x004249cf:
              if (iVar4 == 0) goto LAB_00424a3e;
            }
          }
        }
        else if (param_1[0x27] == 0) {
          iVar4 = (*param_5)(2,puVar1);
          param_1[0x23] = iVar4;
          if (iVar4 == -1) {
            FUN_0042cd70(*param_1,0xb,0);
            goto LAB_00424a3e;
          }
          if (iVar4 != 0) {
            iVar4 = FUN_00424ed0(param_1);
            goto joined_r0x004249cf;
          }
          if ((*(ushort *)(param_1 + 0x1f) & 0xfffe) == 0xfffe) {
            *(short *)((int)param_1 + 0xae) = *(short *)((int)param_1 + 0xae) + 1;
          }
        }
        else {
          *(undefined2 *)(param_1 + 0x2b) = 0;
        }
      } while (*(short *)(param_1 + 0x2b) != 0);
      iVar4 = FUN_004257a0(param_1);
    }
  }
LAB_00424a3e:
  if (param_1[0x22] != -1) {
    (*(code *)param_1[6])(param_1[0x22]);
  }
  if (param_1[0x21] != -1) {
    (*(code *)param_1[6])(param_1[0x21]);
  }
  param_1[0x22] = 0xffffffff;
  param_1[0x21] = 0xffffffff;
  return uStack_4;
}



bool FUN_00424a90(undefined4 *param_1,char *param_2,short param_3,short param_4)

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
        FUN_0042cd70(*param_1,2,0);
        return false;
      }
      if (aiStack_24[0] != 0x4643534d) {
        FUN_0042cd70(*param_1,2,0);
        return false;
      }
      if ((short)uStack_c != 0x103) {
        FUN_0042cd70(*param_1,3,uStack_c & 0xffff);
        return false;
      }
      if ((param_4 != -1) && ((sStack_4 != param_3 || (sStack_2 != param_4)))) {
        FUN_0042cd70(*param_1,10,0);
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
          FUN_0042cd70(*param_1,2,0);
          return false;
        }
        if (param_1[0x28] == 0xffff) {
          uVar4 = uStack_28 & 0xffff;
          param_1[0x28] = uVar4;
          if (uVar4 != 0) {
            iVar6 = (*(code *)param_1[2])(uVar4);
            param_1[0x13] = iVar6;
            if (iVar6 == 0) {
              FUN_0042cd70(*param_1,5,0);
              return false;
            }
          }
        }
        iVar6 = param_1[0x28];
        if ((iVar6 != 0) &&
           (iVar3 = (*(code *)param_1[4])(param_1[0x22],param_1[0x13],iVar6), iVar3 != iVar6)) {
          FUN_0042cd70(*param_1,2,0);
          return false;
        }
      }
      iVar6 = (uStack_28 >> 0x10 & 0xff) + 8;
      if (param_1[0x11] == 0) {
        param_1[0x29] = iVar6;
        iVar6 = (*(code *)param_1[2])(iVar6);
        param_1[0x11] = iVar6;
        if (iVar6 == 0) {
          FUN_0042cd70(*param_1,5,0);
          return false;
        }
      }
      else if (param_1[0x29] != iVar6) {
        FUN_0042cd70(*param_1,9,0);
        return false;
      }
      iVar6 = (uStack_28 >> 0x18) + 8;
      if (param_1[0x12] == 0) {
        param_1[0x2a] = iVar6;
        iVar6 = (*(code *)param_1[2])(iVar6);
        param_1[0x12] = iVar6;
        if (iVar6 == 0) {
          FUN_0042cd70(*param_1,5,0);
          return false;
        }
      }
      else if (param_1[0x2a] != iVar6) {
        FUN_0042cd70(*param_1,9,0);
        return false;
      }
      if ((*(byte *)((int)param_1 + 0x6e) & 1) == 0) {
        *(undefined *)((int)param_1 + 0x1b5) = 0;
        *(undefined *)((int)param_1 + 0x2b6) = 0;
      }
      else {
        iVar6 = FUN_004256e0((int)param_1 + 0x1b5,0x100,param_1);
        if (iVar6 == 0) {
          return false;
        }
        iVar6 = FUN_004256e0((int)param_1 + 0x2b6,0x100,param_1);
        if (iVar6 == 0) {
          return false;
        }
      }
      if ((*(byte *)((int)param_1 + 0x6e) & 2) == 0) {
        *(undefined *)((int)param_1 + 0x3b7) = 0;
        *(undefined *)(param_1 + 0x12e) = 0;
      }
      else {
        iVar6 = FUN_004256e0((int)param_1 + 0x3b7,0x100,param_1);
        if ((iVar6 == 0) || (iVar6 = FUN_004256e0(param_1 + 0x12e,0x100,param_1), iVar6 == 0)) {
          return false;
        }
      }
      iVar6 = (*(code *)param_1[7])(param_1[0x22],0,1);
      param_1[0xb] = iVar6;
      if (iVar6 == -1) {
        FUN_0042cd70(*param_1,4);
        return false;
      }
      iVar6 = (*(code *)param_1[7])(param_1[0x22],param_1[0x18],0);
      if (iVar6 != -1) {
        *(undefined2 *)(param_1 + 0x2b) = *(undefined2 *)(param_1 + 0x1b);
        iVar6 = FUN_004252c0(param_1);
        return iVar6 != 0;
      }
      FUN_0042cd70(*param_1,4,0);
      return false;
    }
  }
  FUN_0042cd70(*param_1,1,0);
  return false;
}



undefined4 FUN_00424ed0(undefined4 *param_1)

{
  undefined4 *puVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  undefined4 uVar7;
  
  uVar4 = param_1[0x1d];
  if (uVar4 == 0) {
LAB_00424f7c:
    puVar1 = param_1 + 0x1ef;
    param_1[0x1f0] = param_1 + 0x2d;
    param_1[500] = param_1[0x23];
    *(undefined2 *)(param_1 + 0x1f5) = *(undefined2 *)((int)param_1 + 0x7e);
    *(undefined2 *)((int)param_1 + 0x7d6) = *(undefined2 *)(param_1 + 0x20);
    *(undefined2 *)(param_1 + 0x1f6) = *(undefined2 *)((int)param_1 + 0x82);
    param_1[499] = param_1[0xe];
    *(undefined2 *)((int)param_1 + 0x7de) = *(undefined2 *)(param_1 + 0x1f);
    *puVar1 = 0;
    if ((*(byte *)(param_1 + 0x1f6) & 0x40) != 0) {
      *puVar1 = 1;
      *(ushort *)(param_1 + 0x1f6) = *(ushort *)(param_1 + 0x1f6) & 0xffbf;
    }
    iVar2 = (*(code *)param_1[9])(3,puVar1);
    if (iVar2 != -1) {
      param_1[0x23] = 0xffffffff;
      if (iVar2 == 0) {
        FUN_0042cd70(*param_1,8,0);
        return 0;
      }
      return 1;
    }
    uVar7 = 0xb;
LAB_00424fea:
    FUN_0042cd70(*param_1,uVar7,0);
  }
  else {
    uVar6 = param_1[0x1e];
    if (uVar6 <= (uint)param_1[0xc] && param_1[0xc] != uVar6) {
      param_1[0x24] = 0xffff;
    }
    iVar2 = FUN_00425380(param_1,*(undefined2 *)(param_1 + 0x1f));
    while (iVar2 != 0) {
      if (uVar6 < (uint)*(ushort *)(param_1[0x12] + 6) + param_1[0xc]) goto LAB_00424f2f;
      iVar2 = FUN_00425050(param_1);
    }
  }
  goto LAB_00424ff5;
  while( true ) {
    uVar5 = (uint)*(ushort *)(param_1[0x12] + 6) - (uVar6 - param_1[0xc]);
    if (uVar4 < uVar5) {
      uVar5 = uVar4;
    }
    uVar3 = (*(code *)param_1[5])(param_1[0x23],param_1[0x10] + (uVar6 - param_1[0xc]),uVar5);
    if (uVar3 != uVar5) {
      uVar7 = 8;
      goto LAB_00424fea;
    }
    uVar6 = uVar6 + uVar5;
    uVar4 = uVar4 - uVar5;
    if ((uVar4 != 0) && (iVar2 = FUN_00425050(param_1), iVar2 == 0)) break;
LAB_00424f2f:
    if (uVar4 == 0) goto LAB_00424f7c;
  }
LAB_00424ff5:
  if (param_1[0x23] != -1) {
    (*(code *)param_1[6])(param_1[0x23]);
    param_1[0x23] = 0xffffffff;
  }
  return 0;
}



undefined4 FUN_00425050(undefined4 *param_1)

{
  int iVar1;
  short sStack_2;
  
  param_1[0xc] = param_1[0xc] + (uint)*(ushort *)(param_1[0x12] + 6);
  if (*(short *)(param_1 + 0x2c) == 0) {
    iVar1 = FUN_00425130(param_1);
    if (iVar1 == 0) {
      return 0;
    }
  }
  *(short *)(param_1 + 0x2c) = *(short *)(param_1 + 0x2c) + -1;
  iVar1 = FUN_00425570(param_1,0);
  if (iVar1 == 0) {
    return 0;
  }
  if (*(short *)(param_1[0x12] + 6) == 0) {
    iVar1 = FUN_00425130(param_1);
    if (iVar1 != 0) {
      iVar1 = FUN_00425570(param_1,*(undefined2 *)(param_1[0x12] + 4));
      if (iVar1 != 0) {
        *(short *)(param_1 + 0x2c) = *(short *)(param_1 + 0x2c) + -1;
        goto LAB_004250d4;
      }
    }
    return 0;
  }
LAB_004250d4:
  sStack_2 = *(short *)(param_1[0x12] + 6);
  iVar1 = FUN_00425d50(param_1,&sStack_2);
  if (iVar1 == 0) {
    return 0;
  }
  if (*(short *)(param_1[0x12] + 6) != sStack_2) {
    FUN_0042cd70(*param_1,7,0);
    return 0;
  }
  return 1;
}



undefined4 FUN_00425130(int **param_1)

{
  undefined2 uVar1;
  bool bVar2;
  int iVar3;
  short sVar4;
  
  uVar1 = *(undefined2 *)(param_1 + 0x1c);
  sVar4 = *(short *)((int)param_1 + 0x72) + 1;
  param_1[0x1f0] = (int *)((int)param_1 + 0x3b7);
  param_1[0x1f1] = (int *)(param_1 + 0x12e);
  param_1[0x1f2] = (int *)((int)param_1 + 0x5b9);
  param_1[499] = param_1[0xe];
  *(undefined2 *)((int)param_1 + 0x7da) = uVar1;
  *(short *)(param_1 + 0x1f7) = sVar4;
  param_1[0x1f8] = (int *)0x0;
  do {
    bVar2 = false;
    if (param_1[0x21] != (int *)0xffffffff) {
      iVar3 = (*(code *)param_1[6])(param_1[0x21]);
      if (iVar3 != 0) goto LAB_00425263;
    }
    if (param_1[0x22] != (int *)0xffffffff) {
      iVar3 = (*(code *)param_1[6])(param_1[0x22]);
      if (iVar3 != 0) {
LAB_00425263:
        FUN_0042cd70(*param_1,4,0);
        return 0;
      }
    }
    param_1[0x22] = (int *)0xffffffff;
    param_1[0x21] = (int *)0xffffffff;
    iVar3 = (*(code *)param_1[9])(4,param_1 + 0x1ef);
    if (iVar3 == -1) {
      FUN_0042cd70(*param_1,0xb,0);
      return 0;
    }
    iVar3 = FUN_00424a90(param_1,(int)param_1 + 0x3b7,uVar1,sVar4);
    if (iVar3 == 0) {
LAB_0042520a:
      if (**param_1 == 0xb) {
        return 0;
      }
      bVar2 = true;
    }
    else {
      iVar3 = FUN_00425400(param_1,0);
      if (iVar3 == 0) goto LAB_0042520a;
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
        iVar3 = FUN_00425520(param_1);
      } while (iVar3 != 0);
      return 0;
    }
  } while( true );
}



undefined4 FUN_004252c0(undefined4 *param_1)

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
    FUN_0042cd70(*param_1,0xb,0);
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
      FUN_0042cd70(*param_1,0xb,0);
      return 0;
    }
  }
  return 1;
}



undefined4 FUN_00425380(int param_1,uint param_2)

{
  int iVar1;
  
  if (*(int *)(param_1 + 0x9c) != 0) {
    return 1;
  }
  if ((param_2 & 0xfffe) == 0xfffe) {
    param_2 = *(ushort *)(param_1 + 0x6a) - 1;
  }
  if (*(uint *)(param_1 + 0x90) == param_2) {
    return 1;
  }
  iVar1 = FUN_00425c80(param_1);
  if ((iVar1 != 0) && (iVar1 = FUN_00425400(param_1,param_2), iVar1 != 0)) {
    iVar1 = FUN_00425050(param_1);
    if (iVar1 != 0) {
      *(undefined4 *)(param_1 + 0x30) = 0;
      return 1;
    }
    return 0;
  }
  return 0;
}



undefined4 FUN_00425400(undefined4 *param_1,int param_2)

{
  short sVar1;
  int iVar2;
  int iVar3;
  
  param_1[0x24] = param_2;
  iVar2 = (*(code *)param_1[7])(param_1[0x21],param_1[0x29] * param_2 + param_1[0xb],0);
  if (iVar2 != -1) {
    iVar2 = param_1[0x29];
    iVar3 = (*(code *)param_1[4])(param_1[0x21],param_1[0x11],iVar2);
    if (iVar3 == iVar2) {
      iVar2 = (*(code *)param_1[7])(param_1[0x21],*(undefined4 *)param_1[0x11],0);
      if (iVar2 != -1) {
        iVar2 = param_1[0x11];
        *(undefined2 *)(param_1 + 0x2c) = *(undefined2 *)(iVar2 + 4);
        iVar2 = FUN_00425870(CONCAT22((short)((uint)iVar2 >> 0x10),*(undefined2 *)(iVar2 + 6)),
                             param_1);
        if (iVar2 == 0) {
          return 0;
        }
        if (param_1[10] != 0) {
          param_1[0x1f9] = 1;
          param_1[0x1fa] = param_1[0xe];
          sVar1 = (short)param_1[0x29] + -8;
          *(short *)(param_1 + 0x1fc) = sVar1;
          if (sVar1 == 0) {
            param_1[0x1fb] = 0;
          }
          else {
            param_1[0x1fb] = param_1[0x11] + 8;
          }
          *(short *)((int)param_1 + 0x7f2) = (short)param_2;
          iVar2 = (*(code *)param_1[10])(param_1 + 0x1f9);
          if (iVar2 == -1) {
            FUN_0042cd70(*param_1,0xb,0);
            return 0;
          }
        }
        return 1;
      }
    }
  }
  FUN_0042cd70(*param_1,4,0);
  return 0;
}



undefined4 FUN_00425520(undefined4 *param_1)

{
  int iVar1;
  
  iVar1 = (*(code *)param_1[4])(param_1[0x22],param_1 + 0x1d,0x10);
  if (iVar1 == 0x10) {
    iVar1 = FUN_004256e0(param_1 + 0x2d,0x100,param_1);
    if (iVar1 != 0) {
      return 1;
    }
  }
  FUN_0042cd70(*param_1,4,0);
  return 0;
}



undefined4 FUN_00425570(undefined4 *param_1,int param_2)

{
  short sVar1;
  int iVar2;
  uint uVar3;
  undefined4 uVar4;
  int iVar5;
  uint uVar6;
  int *piVar7;
  
  iVar5 = param_1[0x2a];
  iVar2 = (*(code *)param_1[4])(param_1[0x21],param_1[0x12],iVar5);
  if (iVar2 == iVar5) {
    uVar6 = (uint)*(ushort *)(param_1[0x12] + 4);
    if (uVar6 + param_2 < (uint)param_1[0x26] || uVar6 + param_2 == param_1[0x26]) {
      uVar3 = (*(code *)param_1[4])(param_1[0x21],param_1[0xf] + param_2,uVar6);
      if (uVar3 == uVar6) {
        if (*(int *)param_1[0x12] != 0) {
          piVar7 = (int *)param_1[0x12] + 1;
          uVar4 = FUN_0042cd8c(param_1[0xf] + param_2,*(undefined2 *)piVar7,0);
          iVar5 = FUN_0042cd8c(piVar7,param_1[0x2a] + -4,uVar4);
          if (*(int *)param_1[0x12] != iVar5) {
            FUN_0042cd70(*param_1,4,0);
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
          iVar5 = (*(code *)param_1[10])(param_1 + 0x1f9);
          if (iVar5 == -1) {
            FUN_0042cd70(*param_1,0xb,0);
            return 0;
          }
        }
        return 1;
      }
    }
  }
  FUN_0042cd70(*param_1,4,0);
  return 0;
}



undefined4 FUN_004256e0(char *param_1,int param_2,undefined4 *param_3)

{
  char cVar1;
  char cVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  
  iVar3 = (*(code *)param_3[7])(param_3[0x22],0,1);
  iVar4 = (*(code *)param_3[4])(param_3[0x22],param_1,param_2);
  if (iVar4 < 1) {
    FUN_0042cd70(*param_3,4,0);
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
    FUN_0042cd70(*param_3,4,0);
    return 0;
  }
  iVar3 = (*(code *)param_3[7])(param_3[0x22],~uVar5 + iVar3,0);
  if (iVar3 == -1) {
    FUN_0042cd70(*param_3,4,0);
    return 0;
  }
  return 1;
}



undefined4 FUN_004257a0(undefined4 *param_1)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  
  iVar2 = (*(code *)param_1[7])(param_1[0x22],0,1);
  if (iVar2 == -1) {
    FUN_0042cd70(*param_1,4,0);
    return 0;
  }
  piVar1 = param_1 + 0x1ef;
  *(undefined2 *)((int)param_1 + 0x7de) = *(undefined2 *)(param_1 + 0x2b);
  *(undefined2 *)((int)param_1 + 0x7da) = *(undefined2 *)(param_1 + 0x1c);
  *piVar1 = iVar2;
  param_1[499] = param_1[0xe];
  iVar3 = (*(code *)param_1[9])(5,piVar1);
  if (iVar3 == -1) {
    FUN_0042cd70(*param_1,0xb,0);
    return 0;
  }
  *(short *)(param_1 + 0x2b) = *(short *)((int)param_1 + 0x7de);
  if ((*(short *)((int)param_1 + 0x7de) != 0) && (*piVar1 != iVar2)) {
    iVar2 = (*(code *)param_1[7])(param_1[0x22],*piVar1,0);
    if (iVar2 == -1) {
      FUN_0042cd70(*param_1,0xb,0);
      return 0;
    }
  }
  return 1;
}



bool FUN_00425870(short param_1,undefined4 *param_2)

{
  int iVar1;
  
  if (*(short *)((int)param_2 + 0xb2) == param_1) {
    return true;
  }
  iVar1 = FUN_004258d0(param_2);
  if (iVar1 == 0) {
    FUN_0042cd70(*param_2,7,0);
    return false;
  }
  *(short *)((int)param_2 + 0xb2) = param_1;
  iVar1 = FUN_004259c0(param_2);
  return iVar1 != 0;
}



undefined4 FUN_004258d0(undefined4 *param_1)

{
  int iVar1;
  
  switch(*(ushort *)((int)param_1 + 0xb2) & 0xf) {
  case 0:
    break;
  case 1:
    iVar1 = func_0x0042d2f0(param_1[0xd]);
    if (iVar1 != 0) {
      FUN_0042cd70(*param_1,7,0);
      return 0;
    }
    break;
  case 2:
    iVar1 = func_0x0042d150(param_1[0xd]);
    if (iVar1 != 0) {
      FUN_0042cd70(*param_1,7,0);
      return 0;
    }
    break;
  case 3:
    iVar1 = func_0x0042cfc0(param_1[0xd]);
    if (iVar1 != 0) {
      FUN_0042cd70(*param_1,7,0);
      return 0;
    }
    break;
  default:
    FUN_0042cd70(*param_1,6,0);
    return 0;
  case 0xf:
    return 1;
  }
  (*(code *)param_1[1])(param_1[0xf]);
  (*(code *)param_1[1])(param_1[0x10]);
  return 1;
}



undefined4 FUN_004259c0(undefined4 *param_1)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  ushort uVar3;
  int iVar4;
  int iVar5;
  uint uStack_10;
  undefined4 uStack_c;
  int aiStack_8 [2];
  
  uVar3 = *(ushort *)((int)param_1 + 0xb2);
  iVar5 = 0;
  puVar1 = param_1 + 0x25;
  *puVar1 = 0x8000;
  switch(uVar3 & 0xf) {
  case 0:
    param_1[0x26] = 0x8000;
    break;
  case 1:
    iVar4 = FUN_0042d1c0(puVar1,0,0,param_1 + 0x26,0);
    if (iVar4 == 0) break;
    goto LAB_00425ab2;
  case 2:
    uStack_c = param_1[8];
    uStack_10 = (uint)((uVar3 & 0x1f00) >> 8);
    iVar4 = FUN_0042d000(puVar1,&uStack_10,0,0,param_1 + 0x26,0,0,0,0,0,0);
    goto joined_r0x00425ab0;
  case 3:
    aiStack_8[0] = 1 << ((byte)(uVar3 >> 8) & 0x1f);
    iVar4 = FUN_0042ce10(puVar1,aiStack_8,0,0,param_1 + 0x26,0,0,0,0,0,0);
joined_r0x00425ab0:
    if (iVar4 != 0) {
LAB_00425ab2:
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
    FUN_0042cd70(*param_1,iVar5,0);
    *(undefined2 *)((int)param_1 + 0xb2) = 0xf;
    return 0;
  }
  puVar2 = param_1 + 0x26;
  iVar5 = (*(code *)param_1[2])(*puVar2);
  param_1[0xf] = iVar5;
  if (iVar5 == 0) {
    FUN_0042cd70(*param_1,5,0);
    *(undefined2 *)((int)param_1 + 0xb2) = 0xf;
    return 0;
  }
  iVar5 = (*(code *)param_1[2])(*puVar1);
  param_1[0x10] = iVar5;
  if (iVar5 == 0) {
    (*(code *)param_1[1])(param_1[0xf]);
    FUN_0042cd70(*param_1,5,0);
    *(undefined2 *)((int)param_1 + 0xb2) = 0xf;
    return 0;
  }
  uVar3 = *(ushort *)((int)param_1 + 0xb2) & 0xf;
  iVar5 = 0;
  if (uVar3 == 1) {
    iVar4 = FUN_0042d1c0(puVar1,param_1[2],param_1[1],puVar2,param_1 + 0xd);
  }
  else if (uVar3 == 2) {
    iVar4 = FUN_0042d000(puVar1,&uStack_10,param_1[2],param_1[1],puVar2,param_1 + 0xd,param_1[3],
                         param_1[4],param_1[5],param_1[6],param_1[7]);
  }
  else {
    if (uVar3 != 3) goto LAB_00425c01;
    iVar4 = FUN_0042ce10(puVar1,aiStack_8,param_1[2],param_1[1],puVar2,param_1 + 0xd,param_1[3],
                         param_1[4],param_1[5],param_1[6],param_1[7]);
  }
  if (iVar4 != 0) {
    iVar5 = (-(uint)(iVar4 == 1) & 0xfffffffe) + 7;
  }
LAB_00425c01:
  if (iVar5 != 0) {
    (*(code *)param_1[1])(param_1[0xf]);
    (*(code *)param_1[1])(param_1[0x10]);
    FUN_0042cd70(*param_1,iVar5,0);
    *(undefined2 *)((int)param_1 + 0xb2) = 0xf;
    return 0;
  }
  return 1;
}



undefined4 FUN_00425c80(undefined4 *param_1)

{
  int iVar1;
  
  switch(*(ushort *)((int)param_1 + 0xb2) & 0xf) {
  case 0:
  case 0xf:
    break;
  case 1:
    iVar1 = func_0x0042d2d0(param_1[0xd]);
    if (iVar1 != 0) {
      FUN_0042cd70(*param_1,7,0);
      return 0;
    }
    break;
  case 2:
    iVar1 = func_0x0042d130(param_1[0xd]);
    if (iVar1 != 0) {
      FUN_0042cd70(*param_1,7,0);
      return 0;
    }
    break;
  case 3:
    iVar1 = func_0x0042cf90(param_1[0xd]);
    if (iVar1 != 0) {
      FUN_0042cd70(*param_1,7,0);
      return 0;
    }
    break;
  default:
    FUN_0042cd70(*param_1,6,0);
    return 0;
  }
  return 1;
}



undefined4 FUN_00425d50(undefined4 *param_1,ushort *param_2)

{
  ushort uVar1;
  int iVar2;
  uint uVar3;
  undefined *puVar4;
  undefined *puVar5;
  uint uStack_4;
  
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
    uStack_4 = (uint)*param_2;
    iVar2 = func_0x0042d0d0(param_1[0xd],param_1[0xf],*(undefined2 *)(param_1[0x12] + 4),
                            param_1[0x10],&uStack_4);
    if (iVar2 == 0) {
      *param_2 = (ushort)uStack_4;
      return 1;
    }
    FUN_0042cd70(*param_1,7,0);
    return 0;
  case 3:
    uStack_4 = (uint)*param_2;
    iVar2 = func_0x0042cf10(param_1[0xd],param_1[0xf],*(undefined2 *)(param_1[0x12] + 4),
                            param_1[0x10],&uStack_4);
    if (iVar2 == 0) {
      *param_2 = (ushort)uStack_4;
      return 1;
    }
    FUN_0042cd70(*param_1,7,0);
    return 0;
  default:
    FUN_0042cd70(*param_1,6,0);
    return 0;
  }
  uStack_4 = param_1[0x25];
  iVar2 = func_0x0042d260(param_1[0xd],param_1[0xf],*(undefined2 *)(param_1[0x12] + 4),param_1[0x10]
                          ,&uStack_4);
  if (iVar2 == 0) {
    *param_2 = (ushort)uStack_4;
    return 1;
  }
  FUN_0042cd70(*param_1,7,0);
  return 0;
}



undefined4 FUN_00425ee0(int param_1)

{
  uint *puVar1;
  
  if ((param_1 != 0) && (puVar1 = *(uint **)(param_1 + 0x1c), puVar1 != (uint *)0x0)) {
    *(undefined4 *)(param_1 + 0x14) = 0;
    *(undefined4 *)(param_1 + 8) = 0;
    *(undefined4 *)(param_1 + 0x18) = 0;
    *puVar1 = -(uint)(puVar1[3] != 0) & 7;
    FUN_0042d330(*(undefined4 *)(*(int *)(param_1 + 0x1c) + 0x14),param_1,0);
    return 0;
  }
  return 0xfffffffe;
}



undefined4 FUN_00425f30(int param_1)

{
  int iVar1;
  
  if (((param_1 != 0) && (*(int *)(param_1 + 0x1c) != 0)) && (*(int *)(param_1 + 0x24) != 0)) {
    iVar1 = *(int *)(*(int *)(param_1 + 0x1c) + 0x14);
    if (iVar1 != 0) {
      FUN_0042e150(iVar1,param_1);
    }
    (**(code **)(param_1 + 0x24))(*(undefined4 *)(param_1 + 0x28),*(undefined4 *)(param_1 + 0x1c));
    *(undefined4 *)(param_1 + 0x1c) = 0;
    return 0;
  }
  return 0xfffffffe;
}



undefined4 FUN_00425f80(int param_1,int param_2,char *param_3,int param_4)

{
  int iVar1;
  undefined4 uVar2;
  
  if (((param_3 == (char *)0x0) || (*param_3 != DAT_00466fd4)) || (param_4 != 0x38)) {
    return 0xfffffffa;
  }
  if (param_1 == 0) {
    return 0xfffffffe;
  }
  *(undefined4 *)(param_1 + 0x18) = 0;
  if (*(int *)(param_1 + 0x20) == 0) {
    *(undefined **)(param_1 + 0x20) = &UNK_0042e2c0;
    *(undefined4 *)(param_1 + 0x28) = 0;
  }
  if (*(int *)(param_1 + 0x24) == 0) {
    *(undefined **)(param_1 + 0x24) = &UNK_0042e2e0;
  }
  iVar1 = (**(code **)(param_1 + 0x20))(*(undefined4 *)(param_1 + 0x28),1,0x18);
  *(int *)(param_1 + 0x1c) = iVar1;
  if (iVar1 == 0) {
    return 0xfffffffc;
  }
  *(undefined4 *)(iVar1 + 0x14) = 0;
  *(undefined4 *)(*(int *)(param_1 + 0x1c) + 0xc) = 0;
  if (param_2 < 0) {
    param_2 = -param_2;
    *(undefined4 *)(*(int *)(param_1 + 0x1c) + 0xc) = 1;
  }
  if ((7 < param_2) && (param_2 < 0x10)) {
    *(int *)(*(int *)(param_1 + 0x1c) + 0x10) = param_2;
    uVar2 = FUN_0042d3b0(param_1,~-(uint)(*(int *)(*(int *)(param_1 + 0x1c) + 0xc) != 0) & 0x42e190,
                         1 << ((byte)param_2 & 0x1f));
    *(undefined4 *)(*(int *)(param_1 + 0x1c) + 0x14) = uVar2;
    if (*(int *)(*(int *)(param_1 + 0x1c) + 0x14) == 0) {
      FUN_00425f30();
      return 0xfffffffc;
    }
    FUN_00425ee0(param_1);
    return 0;
  }
  FUN_00425f30(param_1);
  return 0xfffffffe;
}



void FUN_00426090(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  FUN_00425f80(param_1,0xf,param_2,param_3);
  return;
}



undefined4 * FUN_004264e0(int param_1)

{
  undefined4 *puVar1;
  int iVar2;
  uint uVar3;
  undefined4 *puVar4;
  
  if (param_1 == 2) {
    uVar3 = 0xb8;
  }
  else {
    if (param_1 != 1) {
      return (undefined4 *)0x0;
    }
    uVar3 = 0x20c;
  }
  puVar1 = (undefined4 *)FUN_0044c5a2(uVar3);
  if (puVar1 != (undefined4 *)0x0) {
    puVar4 = puVar1;
    for (uVar3 = uVar3 >> 2; uVar3 != 0; uVar3 = uVar3 - 1) {
      *puVar4 = 0;
      puVar4 = puVar4 + 1;
    }
    for (iVar2 = 0; iVar2 != 0; iVar2 = iVar2 + -1) {
      *(undefined *)puVar4 = 0;
      puVar4 = (undefined4 *)((int)puVar4 + 1);
    }
  }
  return puVar1;
}



void FUN_00426530(int param_1)

{
  if (param_1 != 0) {
    FUN_0044c4b9(param_1);
  }
  return;
}



int FUN_00426540(int param_1,int param_2)

{
  int iVar1;
  
  if ((param_1 != 0) && (param_2 != 0)) {
    iVar1 = FUN_0044c5a2(param_2);
    if (iVar1 == 0) {
      FUN_00426610(param_1,0x46768c);
    }
    return iVar1;
  }
  return 0;
}



void FUN_00426580(int param_1,int param_2)

{
  if ((param_1 != 0) && (param_2 != 0)) {
    FUN_0044c4b9(param_2);
  }
  return;
}



void FUN_00426610(int param_1,undefined4 param_2)

{
  if (*(code **)(param_1 + 0x40) != (code *)0x0) {
    (**(code **)(param_1 + 0x40))(param_1,param_2);
  }
  FUN_00426760(param_1,param_2);
  return;
}



void FUN_00426640(int param_1,undefined4 param_2)

{
  if (*(code **)(param_1 + 0x44) != (code *)0x0) {
    (**(code **)(param_1 + 0x44))(param_1,param_2);
    return;
  }
  FUN_00426790(param_1,param_2);
  return;
}



void FUN_00426670(undefined4 param_1,undefined4 param_2)

{
  undefined auStack_50 [80];
  
  FUN_004266a0(param_1,auStack_50,param_2);
  FUN_00426610(param_1,auStack_50);
  return;
}



void FUN_004266a0(int param_1,int param_2,undefined4 *param_3)

{
  undefined4 *puVar1;
  byte bVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined4 *puVar6;
  
  iVar3 = 0;
  iVar5 = 0;
  do {
    bVar2 = *(byte *)(iVar5 + 0x114 + param_1);
    iVar5 = iVar5 + 1;
    if (((bVar2 < 0x29) || (bVar2 != 0x7a && 0x79 < bVar2)) || ((0x5a < bVar2 && (bVar2 < 0x61)))) {
      *(undefined *)(iVar3 + param_2) = 0x5b;
      *(undefined *)(iVar3 + 1 + param_2) = (&UNK_0045e29c)[(int)(uint)bVar2 >> 4];
      *(undefined *)(iVar3 + 2 + param_2) = (&UNK_0045e29c)[bVar2 & 0xf];
      iVar4 = iVar3 + 3;
      *(undefined *)(iVar4 + param_2) = 0x5d;
    }
    else {
      *(byte *)(iVar3 + param_2) = bVar2;
      iVar4 = iVar3;
    }
    iVar3 = iVar4 + 1;
  } while (iVar5 < 4);
  if (param_3 == (undefined4 *)0x0) {
    *(undefined *)(iVar3 + param_2) = 0;
    return;
  }
  *(undefined *)(iVar3 + param_2) = 0x3a;
  *(undefined *)(iVar4 + 2 + param_2) = 0x20;
  puVar1 = (undefined4 *)(iVar4 + 3 + param_2);
  puVar6 = puVar1;
  for (iVar3 = 0x10; iVar3 != 0; iVar3 = iVar3 + -1) {
    *puVar6 = *param_3;
    param_3 = param_3 + 1;
    puVar6 = puVar6 + 1;
  }
  *(undefined *)((int)puVar1 + 0x3f) = 0;
  return;
}



void FUN_00426730(undefined4 param_1,undefined4 param_2)

{
  undefined auStack_50 [80];
  
  FUN_004266a0(param_1,auStack_50,param_2);
  FUN_00426640(param_1,auStack_50);
  return;
}



void FUN_00426760(undefined4 param_1,undefined4 param_2)

{
  undefined4 unaff_retaddr;
  int iVar1;
  
  FUN_0044d9fd(0x46a9d0,0x46769c,param_2);
  iVar1 = 1;
  FUN_0044d984(param_1);
  if (iVar1 != 0) {
    FUN_0044d9fd(0x46a9d0,0x4676b0,unaff_retaddr);
  }
  return;
}



void FUN_00426790(int param_1,undefined4 param_2)

{
  if (param_1 != 0) {
    FUN_0044d9fd(0x46a9d0,0x4676b0,param_2);
  }
  return;
}



void FUN_004267b0(int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  *(undefined4 *)(param_1 + 0x48) = param_2;
  *(undefined4 *)(param_1 + 0x40) = param_3;
  *(undefined4 *)(param_1 + 0x44) = param_4;
  return;
}



int FUN_004267d0(byte *param_1)

{
  return (((uint)*param_1 * 0x100 + (uint)param_1[1]) * 0x100 + (uint)param_1[2]) * 0x100 +
         (uint)param_1[3];
}



void FUN_00426820(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  FUN_00424080(param_1,param_2,param_3);
  FUN_00423f30(param_1,param_2,param_3);
  return;
}



undefined4 FUN_00426850(int param_1,uint param_2)

{
  uint uVar1;
  byte bVar2;
  int iVar3;
  
  uVar1 = *(uint *)(param_1 + 0xa8);
  if (uVar1 < param_2) {
    do {
      FUN_00426820(param_1,*(undefined4 *)(param_1 + 0xa4),*(undefined4 *)(param_1 + 0xa8));
      param_2 = param_2 - uVar1;
    } while (uVar1 < param_2);
  }
  if (param_2 != 0) {
    FUN_00426820(param_1,*(undefined4 *)(param_1 + 0xa4),param_2);
  }
  iVar3 = FUN_00426900(param_1);
  if (iVar3 != 0) {
    bVar2 = *(byte *)(param_1 + 0x114) & 0x20;
    if (((bVar2 == 0) || ((*(uint *)(param_1 + 100) & 0x200) != 0)) &&
       ((bVar2 != 0 || ((*(uint *)(param_1 + 100) & 0x400) == 0)))) {
      FUN_00426670(param_1,0x4676e0);
      return 1;
    }
    FUN_00426730(param_1,0x4676e0);
    return 1;
  }
  return 0;
}



bool FUN_00426900(int param_1)

{
  bool bVar1;
  int iVar2;
  int iVar3;
  
  iVar2 = param_1;
  bVar1 = true;
  if ((*(byte *)(param_1 + 0x114) & 0x20) == 0) {
    if ((*(uint *)(param_1 + 100) & 0x800) == 0) goto LAB_0042692c;
  }
  else if ((*(uint *)(param_1 + 100) & 0x300) != 0x300) goto LAB_0042692c;
  bVar1 = false;
LAB_0042692c:
  FUN_00424080(param_1,&param_1,4);
  if (!bVar1) {
    return false;
  }
  iVar3 = FUN_004267d0(&param_1);
  return iVar3 != *(int *)(iVar2 + 0x108);
}



void FUN_0042cd70(undefined4 *param_1,undefined4 param_2,undefined4 param_3)

{
  *param_1 = param_2;
  param_1[2] = 1;
  param_1[1] = param_3;
  return;
}



undefined8 __fastcall
FUN_0042cd8c(undefined4 param_1,undefined4 param_2,uint *param_3,uint param_4,uint param_5)

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
  param_4 = param_4 & 3;
  if (param_4 == 3) {
    bVar4 = *(byte *)param_3;
    param_3 = (uint *)((int)param_3 + 1);
    param_5 = param_5 ^ (uint)bVar4 << 0x10;
LAB_0042cdec:
    bVar4 = *(byte *)param_3;
    param_3 = (uint *)((int)param_3 + 1);
    param_5 = param_5 ^ (uint)bVar4 << 8;
  }
  else {
    if (param_4 == 2) goto LAB_0042cdec;
    if (param_4 != 1) goto LAB_0042ce03;
  }
  param_5 = param_5 ^ *(byte *)param_3;
LAB_0042ce03:
  return CONCAT44(param_2,param_5);
}



undefined4
FUN_0042ce10(int *param_1,undefined4 *param_2,code *param_3,code *param_4,int *param_5,
            undefined4 *param_6,undefined4 param_7,undefined4 param_8,undefined4 param_9,
            undefined4 param_10,undefined4 param_11)

{
  undefined4 *puVar1;
  int iVar2;
  
  *param_5 = *param_1 + 0x1800;
  if (param_6 == (undefined4 *)0x0) {
    return 0;
  }
  *param_6 = 0;
  puVar1 = (undefined4 *)(*param_3)(0x2c);
  if (puVar1 == (undefined4 *)0x0) {
    return 1;
  }
  iVar2 = (*param_3)(0x2efc);
  puVar1[10] = iVar2;
  if (iVar2 == 0) {
    (*param_4)(puVar1);
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
  iVar2 = FUN_0042e930(puVar1[10],*param_2,param_3,param_4,param_7,param_8,param_9,param_10,param_11
                      );
  if (iVar2 == 0) {
    (*param_4)(puVar1);
    return 1;
  }
  *param_6 = puVar1;
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4
FUN_0042d000(uint *param_1,int *param_2,code *param_3,code *param_4,int *param_5,undefined4 *param_6
            )

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
  puVar1 = (undefined4 *)(*param_3)(0x14);
  if (puVar1 == (undefined4 *)0x0) {
    return 1;
  }
  puVar1[1] = param_3;
  puVar1[2] = param_4;
  puVar1[3] = *param_1;
  puVar1[4] = param_2[1];
  *puVar1 = 0x43494451;
  _DAT_00477574 = puVar1;
  iVar2 = FUN_0042ea70(*param_2);
  if (iVar2 != 0) {
    (*param_4)(puVar1);
    return 1;
  }
  *param_6 = puVar1;
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0042d180(undefined4 param_1)

{
  (**(code **)(_DAT_00477574 + 4))(param_1);
  return;
}



undefined4 FUN_0042d1c0(uint *param_1,code *param_2,code *param_3,int *param_4,undefined4 *param_5)

{
  undefined4 *puVar1;
  int iVar2;
  
  if ((*param_1 == 0) || (0x8000 < *param_1)) {
    *param_1 = 0x8000;
  }
  *param_4 = *param_1 + 0xc;
  if (param_5 == (undefined4 *)0x0) {
    return 0;
  }
  *param_5 = 0;
  puVar1 = (undefined4 *)(*param_2)(0x10);
  if (puVar1 == (undefined4 *)0x0) {
    return 1;
  }
  iVar2 = FUN_00430130(param_2);
  puVar1[3] = iVar2;
  if (iVar2 == 0) {
    (*param_3)(puVar1);
    return 1;
  }
  puVar1[1] = param_3;
  puVar1[2] = *param_1;
  *puVar1 = 0x4349444d;
  *param_5 = puVar1;
  return 0;
}



void FUN_0042d330(int *param_1,int param_2,int *param_3)

{
  int iVar1;
  
  if (param_3 != (int *)0x0) {
    *param_3 = param_1[0xf];
  }
  if ((*param_1 == 4) || (*param_1 == 5)) {
    (**(code **)(param_2 + 0x24))(*(undefined4 *)(param_2 + 0x28),param_1[3]);
  }
  if (*param_1 == 6) {
    FUN_00430aa0(param_1[1],param_2);
  }
  *param_1 = 0;
  param_1[0xd] = param_1[10];
  param_1[0xc] = param_1[10];
  param_1[7] = 0;
  param_1[8] = 0;
  if ((code *)param_1[0xe] != (code *)0x0) {
    iVar1 = (*(code *)param_1[0xe])(0,0,0);
    param_1[0xf] = iVar1;
    *(int *)(param_2 + 0x30) = iVar1;
  }
  return;
}



undefined4 * FUN_0042d3b0(int param_1,undefined4 param_2,int param_3)

{
  undefined4 *puVar1;
  int iVar2;
  
  puVar1 = (undefined4 *)(**(code **)(param_1 + 0x20))(*(undefined4 *)(param_1 + 0x28),1,0x40);
  if (puVar1 == (undefined4 *)0x0) {
    return (undefined4 *)0x0;
  }
  iVar2 = (**(code **)(param_1 + 0x20))(*(undefined4 *)(param_1 + 0x28),8,0x5a0);
  puVar1[9] = iVar2;
  if (iVar2 == 0) {
    (**(code **)(param_1 + 0x24))(*(undefined4 *)(param_1 + 0x28),puVar1);
    return (undefined4 *)0x0;
  }
  iVar2 = (**(code **)(param_1 + 0x20))(*(undefined4 *)(param_1 + 0x28),1,param_3);
  puVar1[10] = iVar2;
  if (iVar2 == 0) {
    (**(code **)(param_1 + 0x24))(*(undefined4 *)(param_1 + 0x28),puVar1[9]);
    (**(code **)(param_1 + 0x24))(*(undefined4 *)(param_1 + 0x28),puVar1);
    return (undefined4 *)0x0;
  }
  puVar1[0xb] = iVar2 + param_3;
  puVar1[0xe] = param_2;
  *puVar1 = 0;
  FUN_0042d330(puVar1,param_1,0);
  return puVar1;
}



undefined4 FUN_0042e150(int param_1,int param_2)

{
  FUN_0042d330(param_1,param_2,0);
  (**(code **)(param_2 + 0x24))(*(undefined4 *)(param_2 + 0x28),*(undefined4 *)(param_1 + 0x28));
  (**(code **)(param_2 + 0x24))(*(undefined4 *)(param_2 + 0x28),*(undefined4 *)(param_1 + 0x24));
  (**(code **)(param_2 + 0x24))(*(undefined4 *)(param_2 + 0x28),param_1);
  return 0;
}



void FUN_0042e330(int param_1,int param_2,double param_3,double param_4,double param_5,
                 double param_6,double param_7,double param_8,double param_9,double param_10)

{
  if ((param_1 != 0) && (param_2 != 0)) {
    *(float *)(param_2 + 0x80) = (float)param_3;
    *(float *)(param_2 + 0x84) = (float)param_4;
    *(uint *)(param_2 + 8) = *(uint *)(param_2 + 8) | 4;
    *(float *)(param_2 + 0x88) = (float)param_5;
    *(float *)(param_2 + 0x8c) = (float)param_6;
    *(float *)(param_2 + 0x90) = (float)param_7;
    *(float *)(param_2 + 0x94) = (float)param_8;
    *(float *)(param_2 + 0x98) = (float)param_9;
    *(float *)(param_2 + 0x9c) = (float)param_10;
  }
  return;
}



void FUN_0042e780(int param_1,int param_2,int param_3,int param_4)

{
  char cVar1;
  undefined4 *puVar2;
  int iVar3;
  undefined4 *puVar4;
  undefined4 uVar5;
  uint uVar6;
  int iVar7;
  char **ppcVar8;
  undefined4 *puVar9;
  char **ppcVar10;
  char *pcVar11;
  
  if (((param_1 != 0) && (param_2 != 0)) && (param_4 != 0)) {
    iVar7 = *(int *)(param_2 + 0x34);
    iVar3 = *(int *)(param_2 + 0x30) + param_4;
    if (iVar7 < iVar3) {
      puVar2 = *(undefined4 **)(param_2 + 0x38);
      if (puVar2 == (undefined4 *)0x0) {
        *(undefined4 *)(param_2 + 0x30) = 0;
        *(int *)(param_2 + 0x34) = param_4 + 8;
        uVar5 = FUN_00426540(param_1,(param_4 + 8) * 0x10);
        *(undefined4 *)(param_2 + 0x38) = uVar5;
      }
      else {
        iVar3 = iVar3 + 8;
        *(int *)(param_2 + 0x34) = iVar3;
        puVar4 = (undefined4 *)FUN_00426540(param_1,iVar3 * 0x10);
        *(undefined4 **)(param_2 + 0x38) = puVar4;
        puVar9 = puVar2;
        for (uVar6 = (uint)(iVar7 << 4) >> 2; uVar6 != 0; uVar6 = uVar6 - 1) {
          *puVar4 = *puVar9;
          puVar9 = puVar9 + 1;
          puVar4 = puVar4 + 1;
        }
        for (iVar7 = 0; iVar7 != 0; iVar7 = iVar7 + -1) {
          *(undefined *)puVar4 = *(undefined *)puVar9;
          puVar9 = (undefined4 *)((int)puVar9 + 1);
          puVar4 = (undefined4 *)((int)puVar4 + 1);
        }
        FUN_00426580(param_1,puVar2);
      }
    }
    if (0 < param_4) {
      ppcVar10 = (char **)(param_3 + 8);
      do {
        ppcVar8 = (char **)(*(int *)(param_2 + 0x30) * 0x10 + *(int *)(param_2 + 0x38));
        if (*ppcVar10 == (char *)0x0) {
          *ppcVar10 = &DAT_0046e83c;
        }
        if (**ppcVar10 == '\0') {
          ppcVar8[3] = (char *)0x0;
          *ppcVar8 = (char *)0xffffffff;
        }
        else {
          uVar6 = 0xffffffff;
          pcVar11 = *ppcVar10;
          do {
            if (uVar6 == 0) break;
            uVar6 = uVar6 - 1;
            cVar1 = *pcVar11;
            pcVar11 = pcVar11 + 1;
          } while (cVar1 != '\0');
          ppcVar8[3] = (char *)(~uVar6 - 1);
          *ppcVar8 = ppcVar10[-2];
        }
        ppcVar8[2] = *ppcVar10;
        ppcVar8[1] = ppcVar10[-1];
        param_4 = param_4 + -1;
        *(int *)(param_2 + 0x30) = *(int *)(param_2 + 0x30) + 1;
        ppcVar10 = ppcVar10 + 4;
      } while (param_4 != 0);
    }
  }
  return;
}



undefined4
FUN_0042e930(int param_1,uint param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5,
            undefined4 param_6,undefined4 param_7,undefined4 param_8,undefined4 param_9)

{
  int iVar1;
  
  *(undefined4 *)(param_1 + 12000) = param_3;
  *(undefined4 *)(param_1 + 0x2ee4) = param_4;
  *(undefined4 *)(param_1 + 0x2ee8) = param_5;
  *(undefined4 *)(param_1 + 0x2eec) = param_6;
  *(undefined4 *)(param_1 + 0x2ef0) = param_7;
  *(undefined4 *)(param_1 + 0x2ef4) = param_8;
  *(undefined4 *)(param_1 + 0x2ef8) = param_9;
  *(uint *)(param_1 + 4) = param_2;
  *(uint *)(param_1 + 8) = param_2 - 1;
  if ((param_2 & param_2 - 1) != 0) {
    return 0;
  }
  iVar1 = FUN_00431340(param_1);
  if (iVar1 == 0) {
    return 0;
  }
  FUN_0042e9d0(param_1);
  return 1;
}



void FUN_0042e9d0(int param_1)

{
  FUN_004313c0(param_1);
  FUN_00431420(param_1);
  FUN_00431470(param_1);
  *(undefined4 *)(param_1 + 0x2ecc) = 0;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0042ea70(byte param_1)

{
  _DAT_0047754c = 0;
  _DAT_00477568 = 0;
  DAT_00477564 = param_1;
  _DAT_00477554 = 1 << (param_1 & 0x1f);
  _DAT_00477550 = _DAT_00477554 + -1;
  _DAT_00477540 = FUN_0042d180(_DAT_00477554);
  if (_DAT_00477540 != 0) {
    _DAT_00477538 = &UNK_0042eb00;
    _DAT_00477570 = &UNK_0042ebc0;
    _DAT_00477544 = _DAT_00477554 + _DAT_00477540;
    _DAT_00477548 = _DAT_00477540;
    FUN_004318e0(param_1);
    return 0;
  }
  return 1;
}



undefined4
FUN_0042fcd0(int *param_1,uint param_2,uint param_3,int param_4,int param_5,int param_6,uint param_7
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
  uint uStack_584;
  char cStack_57c;
  int iStack_578;
  undefined4 uStack_574;
  undefined4 uStack_570;
  uint uStack_568;
  uint *puStack_564;
  int iStack_560;
  uint uStack_55c;
  int iStack_558;
  uint uStack_554;
  uint auStack_548 [34];
  int aiStack_4c0 [15];
  uint auStack_484 [289];
  
  uStack_554 = 0;
  puVar3 = auStack_548;
  for (iVar5 = 0x11; uVar2 = param_2, piVar6 = param_1, iVar5 != 0; iVar5 = iVar5 + -1) {
    *puVar3 = 0;
    puVar3 = puVar3 + 1;
  }
  do {
    auStack_548[*piVar6] = auStack_548[*piVar6] + 1;
    uVar2 = uVar2 - 1;
    piVar6 = piVar6 + 1;
  } while (uVar2 != 0);
  if (auStack_548[0] == param_2) {
    *param_8 = 0;
    return 0;
  }
  uVar2 = 1;
  puVar3 = auStack_548 + 1;
  do {
    if (*puVar3 != 0) break;
    puVar3 = puVar3 + 1;
    uVar2 = uVar2 + 1;
  } while (puVar3 <= auStack_548 + 0x10);
  uVar9 = *param_8;
  if (*param_8 < uVar2) {
    uVar9 = uVar2;
  }
  uVar11 = 0x10;
  puVar3 = auStack_548 + 0x10;
  do {
    if (*puVar3 != 0) break;
    puVar3 = puVar3 + -1;
    uVar11 = uVar11 - 1;
  } while (puVar3 != auStack_548);
  if (uVar11 < uVar9) {
    uVar9 = uVar11;
  }
  *param_8 = uVar9;
  iStack_578 = 1 << ((byte)uVar2 & 0x1f);
  if (uVar2 < uVar11) {
    puVar3 = auStack_548 + uVar2;
    uVar7 = uVar2;
    do {
      uVar4 = *puVar3;
      if ((int)(iStack_578 - uVar4) < 0) {
        return 2;
      }
      puVar3 = puVar3 + 1;
      uVar7 = uVar7 + 1;
      iStack_578 = (iStack_578 - uVar4) * 2;
    } while (uVar7 < uVar11);
  }
  uVar7 = auStack_548[uVar11];
  iStack_578 = iStack_578 - uVar7;
  if (iStack_578 < 0) {
    return 2;
  }
  puVar3 = auStack_548 + 0x13;
  auStack_548[uVar11] = uVar7 + iStack_578;
  uVar7 = 0;
  puVar1 = auStack_548;
  auStack_548[18] = 0;
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
      uVar4 = auStack_548[iVar5 + 0x11] + 1;
      auStack_548[iVar5 + 0x11] = uVar4;
      auStack_484[uVar4] = uVar7;
    }
    uVar7 = uVar7 + 1;
  } while (uVar7 < param_2);
  puStack_564 = auStack_484 + 1;
  uStack_584 = 0;
  auStack_548[17] = 0;
  aiStack_4c0[0] = 0;
  iStack_560 = 0;
  iVar5 = -uVar9;
  uStack_55c = 0;
  iStack_558 = -1;
  do {
    if ((int)uVar11 < (int)uVar2) {
      if ((iStack_578 != 0) && (uVar11 != 1)) {
        return 1;
      }
      return 0;
    }
    uStack_568 = auStack_548[uVar2];
    while( true ) {
      uVar7 = uStack_568 - 1;
      if (uStack_568 == 0) break;
      if ((int)(uVar9 + iVar5) < (int)uVar2) {
        iVar15 = iStack_558 << 2;
        do {
          iVar5 = iVar5 + uVar9;
          iStack_558 = iStack_558 + 1;
          uVar4 = (uVar11 & 0xffff) - iVar5;
          if (uVar9 < uVar4) {
            uVar4 = uVar9 & 0xffff;
          }
          uVar8 = uVar2 - iVar5;
          uVar12 = 1 << ((byte)uVar8 & 0x1f);
          if (uStack_568 < uVar12) {
            iVar13 = uVar12 - uStack_568;
            puVar3 = auStack_548 + uVar2;
            while (uVar8 = uVar8 + 1, uVar8 < uVar4) {
              uVar12 = iVar13 * 2;
              puVar3 = puVar3 + 1;
              if (uVar12 < *puVar3 || uVar12 == *puVar3) break;
              iVar13 = uVar12 - *puVar3;
            }
          }
          uStack_55c = 1 << ((byte)uVar8 & 0x1f);
          iStack_560 = param_6 + uStack_554 * 8;
          uStack_554 = uStack_554 + uStack_55c;
          if (param_7 < uStack_554) {
            return 3;
          }
          *(int *)((int)aiStack_4c0 + iVar15 + 4) = iStack_560;
          if (iVar15 + 4 != 0) {
            *(uint *)((int)auStack_548 + iVar15 + 0x48) = uStack_584;
            uStack_574 = CONCAT31(CONCAT21(uStack_574._2_2_,(char)uVar9),(byte)uVar8 + 0x10);
            puVar14 = (undefined4 *)
                      ((uStack_584 >> ((char)iVar5 - (char)uVar9 & 0x1fU)) * 8 +
                      *(int *)((int)aiStack_4c0 + iVar15));
            *puVar14 = uStack_574;
            puVar14[1] = iStack_560;
            uStack_570 = iStack_560;
          }
          iVar15 = iVar15 + 4;
        } while ((int)(uVar9 + iVar5) < (int)uVar2);
      }
      cStack_57c = (char)uVar2;
      bVar10 = (byte)iVar5;
      if (puStack_564 < auStack_484 + param_2 + 1) {
        uVar4 = *puStack_564;
        if (uVar4 < param_3) {
          uStack_574._0_1_ = (uVar4 < 0x100) + '\x0f';
        }
        else {
          iVar15 = (uVar4 - param_3) * 2;
          uStack_574._0_1_ = *(char *)(iVar15 + param_5);
          uVar4 = (uint)*(ushort *)(param_4 + iVar15);
        }
        puStack_564 = puStack_564 + 1;
        uStack_570 = CONCAT22(uStack_570._2_2_,(short)uVar4);
      }
      else {
        uStack_574._0_1_ = 'c';
      }
      uStack_574 = CONCAT31(CONCAT21(uStack_574._2_2_,cStack_57c - bVar10),(char)uStack_574);
      iVar15 = 1 << (cStack_57c - bVar10 & 0x1f);
      uVar4 = uStack_584 >> (bVar10 & 0x1f);
      if (uVar4 < uStack_55c) {
        puVar14 = (undefined4 *)(iStack_560 + uVar4 * 8);
        do {
          uVar4 = uVar4 + iVar15;
          *puVar14 = uStack_574;
          puVar14[1] = uStack_570;
          puVar14 = puVar14 + iVar15 * 2;
        } while (uVar4 < uStack_55c);
      }
      uVar8 = 1 << (cStack_57c - 1U & 0x1f);
      uVar4 = uStack_584 & uVar8;
      while (uVar4 != 0) {
        uStack_584 = uStack_584 ^ uVar8;
        uVar8 = uVar8 >> 1;
        uVar4 = uStack_584 & uVar8;
      }
      uStack_584 = uStack_584 ^ uVar8;
      puVar3 = auStack_548 + iStack_558 + 0x11;
      uStack_568 = uVar7;
      if (((1 << (bVar10 & 0x1f)) - 1U & uStack_584) != *puVar3) {
        do {
          puVar3 = puVar3 + -1;
          iVar5 = iVar5 - uVar9;
          iStack_558 = iStack_558 + -1;
        } while (((1 << ((byte)iVar5 & 0x1f)) - 1U & uStack_584) != *puVar3);
      }
    }
    uVar2 = uVar2 + 1;
  } while( true );
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 * FUN_00430130(code *param_1)

{
  undefined4 *puVar1;
  int iVar2;
  undefined4 *puVar3;
  
  puVar1 = (undefined4 *)(*param_1)(0x1e04);
  if (puVar1 != (undefined4 *)0x0) {
    puVar3 = puVar1;
    for (iVar2 = 0x781; iVar2 != 0; iVar2 = iVar2 + -1) {
      *puVar3 = 0;
      puVar3 = puVar3 + 1;
    }
    if (_DAT_004683a4 == 0) {
      FUN_00430170();
      _DAT_004683a4 = 1;
    }
  }
  return puVar1;
}



int FUN_00430170(void)

{
  int iVar1;
  int iStack_484;
  undefined4 auStack_480 [280];
  undefined4 auStack_20 [8];
  
  iStack_484 = 0;
  do {
    iVar1 = iStack_484 + 1;
    auStack_480[iStack_484] = 8;
    iStack_484 = iVar1;
  } while (iVar1 < 0x90);
  for (; iVar1 < 0x100; iVar1 = iVar1 + 1) {
    auStack_480[iVar1] = 9;
  }
  for (; iVar1 < 0x118; iVar1 = iVar1 + 1) {
    auStack_480[iVar1] = 7;
  }
  for (; iVar1 < 0x120; iVar1 = iVar1 + 1) {
    auStack_480[iVar1] = 8;
  }
  iStack_484 = 9;
  iVar1 = FUN_0042fcd0(auStack_480,0x120,0x101,0x468280,0x4682c0,0x474910,0x208,&iStack_484);
  if (iVar1 == 0) {
    iStack_484 = 0;
    do {
      iVar1 = iStack_484 + 1;
      auStack_480[iStack_484] = 5;
      iStack_484 = iVar1;
    } while (iVar1 < 0x1e);
    iStack_484 = 5;
    iVar1 = FUN_0042fcd0(auStack_480,0x1e,0,0x468300,0x468340,0x474810,0x20,&iStack_484);
    if (iVar1 < 2) {
      iVar1 = 0;
    }
  }
  return iVar1;
}



void FUN_00430aa0(undefined4 param_1,int param_2)

{
  (**(code **)(param_2 + 0x24))(*(undefined4 *)(param_2 + 0x28),param_1);
  return;
}



bool FUN_00431340(int *param_1)

{
  byte bVar1;
  int iVar2;
  uint uVar3;
  
  uVar3 = 4;
  *(undefined *)((int)param_1 + 0x2eb5) = 4;
  do {
    bVar1 = *(byte *)((int)param_1 + 0x2eb5);
    *(byte *)((int)param_1 + 0x2eb5) = bVar1 + 1;
    uVar3 = uVar3 + (1 << ((&UNK_0045e380)[bVar1] & 0x1f));
  } while (uVar3 < (uint)param_1[1]);
  iVar2 = (*(code *)param_1[3000])(param_1[1] + 0x105);
  *param_1 = iVar2;
  return iVar2 != 0;
}



void FUN_004313c0(int param_1)

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



void FUN_00431420(int param_1)

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



void FUN_00431470(int param_1)

{
  *(undefined4 *)(param_1 + 0x2ec8) = 0;
  return;
}



void FUN_00431480(int param_1,undefined4 param_2,undefined4 param_3)

{
  undefined4 uVar1;
  
  uVar1 = FUN_00432820(*(undefined4 *)(param_1 + 0x2ec8),*(undefined4 *)(param_1 + 0x2ec4),param_2,
                       param_3);
  *(undefined4 *)(param_1 + 0x2ec8) = uVar1;
  return;
}



undefined4 FUN_00431710(undefined4 param_1,int param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 uVar1;
  
  if (param_2 == 2) {
    uVar1 = FUN_00433440(param_1,param_3,param_4);
    return uVar1;
  }
  if (param_2 == 1) {
    uVar1 = FUN_00432dd0(param_1,param_3,param_4);
    return uVar1;
  }
  if (param_2 == 3) {
    uVar1 = FUN_00432ce0(param_1,param_3,param_4);
    return uVar1;
  }
  return 0xffffffff;
}



void FUN_00431780(int param_1)

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



void FUN_004317e0(int param_1,byte param_2)

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



uint FUN_004318b0(int param_1,undefined4 param_2)

{
  uint uVar1;
  
  uVar1 = *(uint *)(param_1 + 0x2eb0);
  FUN_004317e0(param_1,param_2);
  return uVar1 >> (0x20U - (char)param_2 & 0x1f);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_004318e0(byte param_1)

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
    *(int *)(iVar4 + 0x476180) = iVar5;
    if (0 < 1 << (*(byte *)(iVar4 + 0x469620) & 0x1f)) {
      iVar5 = iVar5 + (1 << (*(byte *)(iVar4 + 0x469620) & 0x1f));
    }
    iVar4 = iVar4 + 4;
  } while (iVar4 < 0x6c);
  iVar4 = 0;
  iVar6 = 0;
  iVar5 = 0;
  do {
    if (iVar5 < 1 << (param_1 & 0x1f)) {
      _DAT_00476f00 = iVar6 + 1;
      if (iVar5 < 0x1000) {
        _DAT_00477110 = _DAT_00476f00;
      }
      if (iVar5 < 0x40000) {
        _DAT_00477320 = _DAT_00476f00;
      }
    }
    pbVar1 = (byte *)(iVar4 + 0x469690);
    *(int *)(iVar4 + 0x4761ec) = iVar5;
    iVar4 = iVar4 + 4;
    iVar5 = iVar5 + (1 << (*pbVar1 & 0x1f));
    iVar6 = iVar6 + 1;
  } while (iVar4 < 0xa8);
  iVar4 = 0;
  _DAT_004762a0 = 7;
  _DAT_004762a4 = 4;
  piVar2 = (int *)&DAT_004762a8;
  do {
    piVar3 = piVar2 + 2;
    *piVar2 = 7 - iVar4;
    piVar2[1] = iVar4;
    iVar4 = iVar4 + 1;
    piVar2 = piVar3;
  } while (piVar3 < (int *)0x4762e1);
  _DAT_00476ae0 = 0x40;
  _DAT_004768d0 = 0x40;
  _DAT_004766c0 = 0x40;
  _DAT_004764b0 = 0x40;
  iVar4 = 0;
  _DAT_00476ae4 = 4;
  _DAT_004768d4 = 4;
  _DAT_004766c4 = 4;
  _DAT_004764b4 = 4;
  piVar2 = (int *)0x4764b8;
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
  } while (piVar3 < (int *)0x4766b9);
  iVar4 = 0;
  _DAT_00476cf0 = 0x1b;
  _DAT_00476cf4 = 4;
  piVar2 = (int *)0x476cf8;
  do {
    piVar3 = piVar2 + 2;
    *piVar2 = 0x1b - iVar4;
    piVar2[1] = iVar4;
    iVar4 = iVar4 + 1;
    piVar2 = piVar3;
  } while (piVar3 < (int *)0x476dd1);
  iVar4 = 0;
  _DAT_00476f04 = 4;
  _DAT_00477114 = 4;
  _DAT_00477324 = 4;
  piVar2 = (int *)0x476f08;
  do {
    piVar3 = piVar2 + 2;
    *piVar2 = _DAT_00476f00 - iVar4;
    piVar2[0x84] = _DAT_00477110 - iVar4;
    piVar2[0x108] = _DAT_00477320 - iVar4;
    piVar2[1] = iVar4;
    piVar2[0x85] = iVar4;
    piVar2[0x109] = iVar4;
    iVar4 = iVar4 + 1;
    piVar2 = piVar3;
  } while (piVar3 < (int *)0x477059);
  return;
}



void FUN_00431ab0(int *param_1)

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



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int __fastcall FUN_00432300(uint param_1)

{
  return (int)(short)(((((uint)_DAT_00476174 - (uint)_DAT_00476170) + 1) * (param_1 & 0xffff) - 1) /
                     (((uint)_DAT_00476172 - (uint)_DAT_00476170) + 1));
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00432340(uint param_1,uint param_2)

{
  char cVar1;
  uint uVar2;
  int iVar3;
  
  iVar3 = ((uint)_DAT_00476172 - (uint)_DAT_00476170) + 1;
  _DAT_00476172 = (_DAT_00476170 + (short)(((param_1 >> 0x10) * iVar3) / (param_2 & 0xffff))) - 1;
  _DAT_00476170 = _DAT_00476170 + (short)(((param_1 & 0xffff) * iVar3) / (param_2 & 0xffff));
  do {
    if (((_DAT_00476172 ^ _DAT_00476170) & 0x8000) != 0) {
      if (((_DAT_00476170 & 0x4000) == 0) || ((_DAT_00476172 & 0x4000) != 0)) {
        return;
      }
      _DAT_00476174 = _DAT_00476174 ^ 0x4000;
      _DAT_00476170 = _DAT_00476170 & 0x3fff;
      _DAT_00476172 = _DAT_00476172 | 0x4000;
    }
    _DAT_00476170 = _DAT_00476170 << 1;
    _DAT_00476172 = _DAT_00476172 << 1;
    _DAT_00476174 = _DAT_00476174 << 1;
    _DAT_00476172 = _DAT_00476172 | 1;
    if (_DAT_00475954 == 0) {
      if (_DAT_0047756c == 0) {
        uVar2 = 0;
        _DAT_00477534 = 1;
      }
      else {
        _DAT_00475954 = 7;
        _DAT_0047756c = _DAT_0047756c + -1;
        cVar1 = *_DAT_00477530;
        _DAT_00477530 = _DAT_00477530 + 1;
        _DAT_00475950 = (int)cVar1 << 1;
        uVar2 = _DAT_00475950 & 0x100;
      }
    }
    else {
      _DAT_00475950 = _DAT_00475950 << 1;
      _DAT_00475954 = _DAT_00475954 + -1;
      uVar2 = _DAT_00475950 & 0x100;
    }
    if (uVar2 != 0) {
      _DAT_00476174 = _DAT_00476174 | 1;
    }
  } while( true );
}



undefined8 __fastcall
FUN_00432820(undefined4 param_1,undefined4 param_2,char *param_3,uint param_4,char *param_5,
            int param_6)

{
  undefined2 uVar1;
  undefined4 uVar2;
  uint uVar3;
  undefined4 *puVar4;
  char *pcVar5;
  char *pcVar6;
  char *pcVar7;
  
  if (param_6 < 6) {
    return CONCAT44(param_2,param_3 + param_6);
  }
  pcVar7 = param_3 + param_6;
  puVar4 = (undefined4 *)(param_5 + param_6 + -6);
  uVar2 = *puVar4;
  uVar1 = *(undefined2 *)(param_5 + param_6 + -2);
  *puVar4 = 0xe8e8e8e8;
  *(undefined2 *)(param_5 + param_6 + -2) = 0xe8e8;
  pcVar6 = param_5;
  pcVar5 = param_5;
  do {
    while (*pcVar5 == -0x18) {
LAB_0043289f:
      param_3 = pcVar5 + ((int)param_3 - (int)pcVar6);
      if ((int)(pcVar7 + -6) <= (int)param_3) {
        *puVar4 = uVar2;
        *(undefined2 *)(param_5 + param_6 + -2) = uVar1;
        return CONCAT44(param_2,pcVar7);
      }
      uVar3 = *(uint *)(pcVar5 + 1);
      pcVar6 = pcVar5 + 5;
      if (uVar3 < param_4) {
        *(int *)(pcVar5 + 1) = *(int *)(pcVar5 + 1) - (int)param_3;
        param_3 = param_3 + 5;
        pcVar5 = pcVar6;
      }
      else {
        if ((char *)-uVar3 < param_3 || -(int)param_3 == uVar3) {
          *(uint *)(pcVar5 + 1) = *(int *)(pcVar5 + 1) + param_4;
        }
        param_3 = param_3 + 5;
        pcVar5 = pcVar6;
      }
    }
    if (pcVar5[1] == -0x18) {
      pcVar5 = pcVar5 + 1;
      goto LAB_0043289f;
    }
    if (pcVar5[2] == -0x18) {
      pcVar5 = pcVar5 + 2;
      goto LAB_0043289f;
    }
    if (pcVar5[3] == -0x18) {
      pcVar5 = pcVar5 + 3;
      goto LAB_0043289f;
    }
    pcVar5 = pcVar5 + 4;
  } while( true );
}



void FUN_004328f0(int param_1,uint param_2,undefined4 *param_3)

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
    FUN_00431480(param_1,*(undefined4 *)(param_1 + 0x2b0c),param_2);
  }
  return;
}



bool FUN_00432940(int param_1)

{
  int iVar1;
  
  iVar1 = FUN_00432a20(param_1,0x100,param_1 + 0x2b14,param_1 + 0xa18);
  if (iVar1 == 0) {
    return false;
  }
  iVar1 = FUN_00432a20(param_1,(uint)*(byte *)(param_1 + 0x2eb5) << 3,param_1 + 0x2c14,
                       param_1 + 0xb18);
  if (iVar1 == 0) {
    return false;
  }
  iVar1 = FUN_004337fc(param_1,(uint)*(byte *)(param_1 + 0x2eb5) * 8 + 0x100,param_1 + 0xa18,10,
                       param_1 + 0x18,param_1 + 0xe3c);
  if (iVar1 == 0) {
    return false;
  }
  iVar1 = FUN_00432a20(param_1,0xf9,param_1 + 0x2db4,param_1 + 0xcb8);
  if (iVar1 == 0) {
    return false;
  }
  iVar1 = FUN_004337fc(param_1,0xf9,param_1 + 0xcb8,8,param_1 + 0x818,param_1 + 0x233c);
  return iVar1 != 0;
}



bool FUN_00432a20(int param_1,int param_2,int param_3,int param_4)

{
  undefined uVar1;
  byte bVar2;
  uint uVar3;
  short sVar4;
  int iVar5;
  int iVar6;
  undefined auStack_2d4 [24];
  short asStack_2bc [94];
  short asStack_200 [256];
  
  iVar6 = 0;
  do {
    iVar5 = iVar6 + 1;
    uVar1 = FUN_004318b0(param_1,4);
    auStack_2d4[iVar6] = uVar1;
    iVar6 = iVar5;
  } while (iVar5 < 0x14);
  if (*(int *)(param_1 + 0x2ebc) != 0) {
    return false;
  }
  iVar6 = 0;
  FUN_004337fc(param_1,0x14,auStack_2d4,8,asStack_200,asStack_2bc);
  if (0 < param_2) {
    do {
      sVar4 = *(short *)((int)asStack_200 + ((*(uint *)(param_1 + 0x2eb0) & 0xff7fffff) >> 0x17));
      if (sVar4 < 0) {
        uVar3 = 0x800000;
        do {
          if ((uVar3 & *(uint *)(param_1 + 0x2eb0)) == 0) {
            sVar4 = asStack_2bc[-sVar4 * 2];
          }
          else {
            sVar4 = asStack_2bc[-sVar4 * 2 + 1];
          }
          uVar3 = uVar3 >> 1;
        } while (sVar4 < 0);
      }
      FUN_004317e0(param_1,auStack_2d4[sVar4]);
      if (*(int *)(param_1 + 0x2ebc) != 0) {
        return false;
      }
      if (sVar4 == 0x11) {
        bVar2 = FUN_004318b0(param_1,4);
        iVar5 = bVar2 + 4;
        if (param_2 <= (int)(iVar6 + 4 + (uint)bVar2)) {
          iVar5 = param_2 - iVar6;
        }
        for (; 0 < iVar5; iVar5 = iVar5 + -1) {
          *(undefined *)(iVar6 + param_4) = 0;
          iVar6 = iVar6 + 1;
        }
        iVar6 = iVar6 + -1;
      }
      else if (sVar4 == 0x12) {
        bVar2 = FUN_004318b0(param_1,5);
        iVar5 = bVar2 + 0x14;
        if (param_2 <= (int)(iVar6 + 0x14 + (uint)bVar2)) {
          iVar5 = param_2 - iVar6;
        }
        for (; 0 < iVar5; iVar5 = iVar5 + -1) {
          *(undefined *)(iVar6 + param_4) = 0;
          iVar6 = iVar6 + 1;
        }
        iVar6 = iVar6 + -1;
      }
      else if (sVar4 == 0x13) {
        bVar2 = FUN_004318b0(param_1,1);
        iVar5 = bVar2 + 4;
        if (param_2 <= (int)(iVar6 + 4 + (uint)bVar2)) {
          iVar5 = param_2 - iVar6;
        }
        sVar4 = *(short *)((int)asStack_200 + ((*(uint *)(param_1 + 0x2eb0) & 0xff7fffff) >> 0x17));
        if (sVar4 < 0) {
          uVar3 = 0x800000;
          do {
            if ((uVar3 & *(uint *)(param_1 + 0x2eb0)) == 0) {
              sVar4 = asStack_2bc[-sVar4 * 2];
            }
            else {
              sVar4 = asStack_2bc[-sVar4 * 2 + 1];
            }
            uVar3 = uVar3 >> 1;
          } while (sVar4 < 0);
        }
        FUN_004317e0(param_1,auStack_2d4[sVar4]);
        uVar1 = (&UNK_0045e6b1)[(uint)*(byte *)(iVar6 + param_3) - (int)sVar4];
        for (; 0 < iVar5; iVar5 = iVar5 + -1) {
          *(undefined *)(iVar6 + param_4) = uVar1;
          iVar6 = iVar6 + 1;
        }
        iVar6 = iVar6 + -1;
      }
      else {
        *(undefined *)(iVar6 + param_4) =
             (&UNK_0045e6b1)[(uint)*(byte *)(iVar6 + param_3) - (int)sVar4];
      }
      iVar6 = iVar6 + 1;
    } while (iVar6 < param_2);
  }
  return *(int *)(param_1 + 0x2ebc) == 0;
}



bool FUN_00432c90(int param_1)

{
  undefined uVar1;
  int iVar2;
  
  iVar2 = 0;
  do {
    iVar2 = iVar2 + 1;
    uVar1 = FUN_004318b0(param_1,3);
    *(undefined *)(param_1 + 0xe33 + iVar2) = uVar1;
  } while (iVar2 < 8);
  if (*(int *)(param_1 + 0x2ebc) != 0) {
    return false;
  }
  iVar2 = FUN_00433a80(param_1,param_1 + 0xe34,param_1 + 0xdb4);
  return iVar2 != 0;
}



int FUN_00432ce0(int *param_1,uint param_2,int param_3)

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



undefined4 FUN_00432d60(int param_1)

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



int FUN_00432dd0(int param_1,int param_2,int param_3)

{
  int iVar1;
  
  if (param_2 < 0x101) {
    iVar1 = 0x101 - param_2;
    if (param_3 <= 0x101 - param_2) {
      iVar1 = param_3;
    }
    iVar1 = FUN_00432e30(param_1,param_2,iVar1);
    param_3 = (param_3 - iVar1) + param_2;
    *(int *)(param_1 + 0x2ec0) = iVar1;
    param_2 = iVar1;
    if (param_3 < 1) {
      return param_3;
    }
  }
  iVar1 = FUN_00433c13(param_1,param_2,param_3);
  return iVar1;
}



int FUN_00432e30(int *param_1,int param_2,int param_3)

{
  char cVar1;
  short sVar2;
  ushort *puVar3;
  ushort uVar4;
  byte bVar5;
  uint uVar6;
  char cVar7;
  int iVar8;
  ushort *puVar9;
  ushort *puVar10;
  uint uVar11;
  int iVar12;
  char cStack_11;
  uint uStack_10;
  
  cStack_11 = *(char *)(param_1 + 0xbad);
  uStack_10 = param_1[0xbac];
  puVar10 = (ushort *)param_1[0xac1];
  puVar3 = (ushort *)param_1[0xac2];
  param_3 = param_3 + param_2;
  if (param_2 < param_3) {
    do {
      iVar8 = (int)*(short *)(((uStack_10 & 0xffdfffff) >> 0x15) + 0x18 + (int)param_1);
      if (iVar8 < 0) {
        uVar6 = 0x200000;
        do {
          if ((uStack_10 & uVar6) == 0) {
            sVar2 = *(short *)(param_1 + (0x38f - iVar8));
          }
          else {
            sVar2 = *(short *)((int)param_1 + iVar8 * -4 + 0xe3e);
          }
          iVar8 = (int)sVar2;
          uVar6 = uVar6 >> 1;
        } while (iVar8 < 0);
      }
      if (puVar3 <= puVar10) {
        return -1;
      }
      bVar5 = *(byte *)(iVar8 + 0xa18 + (int)param_1);
      uStack_10 = uStack_10 << (bVar5 & 0x1f);
      cStack_11 = cStack_11 - bVar5;
      if (cStack_11 < '\x01') {
        uVar4 = *puVar10;
        puVar10 = puVar10 + 1;
        bVar5 = -cStack_11;
        cStack_11 = cStack_11 + '\x10';
        uStack_10 = uStack_10 | (uint)uVar4 << (bVar5 & 0x1f);
      }
      uVar6 = iVar8 - 0x100;
      if ((int)uVar6 < 0) {
        param_2 = param_2 + 1;
        *(char *)(*param_1 + -1 + param_2) = (char)uVar6;
        *(char *)(param_1[1] + *param_1 + -1 + param_2) = (char)uVar6;
      }
      else {
        uVar11 = uVar6 & 7;
        if (uVar11 == 7) {
          iVar8 = (int)*(short *)(((uStack_10 & 0xff7fffff) >> 0x17) + 0x818 + (int)param_1);
          if (iVar8 < 0) {
            uVar11 = 0x800000;
            do {
              if ((uStack_10 & uVar11) == 0) {
                sVar2 = *(short *)(param_1 + (0x8cf - iVar8));
              }
              else {
                sVar2 = *(short *)((int)param_1 + iVar8 * -4 + 0x233e);
              }
              iVar8 = (int)sVar2;
              uVar11 = uVar11 >> 1;
            } while (iVar8 < 0);
          }
          bVar5 = *(byte *)(iVar8 + 0xcb8 + (int)param_1);
          uStack_10 = uStack_10 << (bVar5 & 0x1f);
          cStack_11 = cStack_11 - bVar5;
          if (cStack_11 < '\x01') {
            uVar4 = *puVar10;
            puVar10 = puVar10 + 1;
            bVar5 = -cStack_11;
            cStack_11 = cStack_11 + '\x10';
            uStack_10 = uStack_10 | (uint)uVar4 << (bVar5 & 0x1f);
          }
          uVar11 = iVar8 + 7;
        }
        cVar7 = (char)((int)uVar6 >> 3);
        if (cVar7 < '\x03') {
          iVar8 = param_1[cVar7 + 3];
          if (cVar7 != '\0') {
            param_1[cVar7 + 3] = param_1[3];
            goto LAB_00433052;
          }
        }
        else {
          if (cVar7 < '\x04') {
            iVar8 = 1;
          }
          else {
            bVar5 = (&UNK_0045e380)[cVar7];
            cVar1 = cStack_11 - bVar5;
            uVar6 = uStack_10 >> (0x20 - bVar5 & 0x1f);
            uStack_10 = uStack_10 << (bVar5 & 0x1f);
            puVar9 = puVar10;
            cStack_11 = cVar1;
            if (cVar1 < '\x01') {
              puVar9 = puVar10 + 1;
              cStack_11 = cVar1 + '\x10';
              uStack_10 = uStack_10 | (uint)*puVar10 << (-cVar1 & 0x1fU);
              if (cStack_11 < '\x01') {
                uVar4 = *puVar9;
                puVar9 = puVar10 + 2;
                bVar5 = -cStack_11;
                cStack_11 = cVar1 + ' ';
                uStack_10 = uStack_10 | (uint)uVar4 << (bVar5 & 0x1f);
              }
            }
            iVar8 = uVar6 + *(int *)(&UNK_0045e3b8 + cVar7 * 4);
            puVar10 = puVar9;
          }
          param_1[5] = param_1[4];
          param_1[4] = param_1[3];
LAB_00433052:
          param_1[3] = iVar8;
        }
        iVar12 = uVar11 + 2;
        do {
          *(undefined *)(*param_1 + param_2) =
               *(undefined *)((param_2 - iVar8 & param_1[2]) + *param_1);
          if (param_2 < 0x101) {
            *(undefined *)(param_1[1] + *param_1 + param_2) = *(undefined *)(*param_1 + param_2);
          }
          param_2 = param_2 + 1;
          iVar12 = iVar12 + -1;
        } while (0 < iVar12);
      }
    } while (param_2 < param_3);
  }
  *(char *)(param_1 + 0xbad) = cStack_11;
  param_1[0xbac] = uStack_10;
  param_1[0xac1] = (int)puVar10;
  return param_2;
}



int FUN_004330c0(int *param_1,uint param_2,int param_3)

{
  short sVar1;
  ushort *puVar2;
  int iVar3;
  ushort uVar4;
  int iVar5;
  byte bVar6;
  uint uVar7;
  char cVar8;
  char cVar9;
  uint uVar10;
  uint uStack_20;
  ushort *puStack_1c;
  int iStack_14;
  uint uStack_10;
  
  cVar8 = *(char *)(param_1 + 0xbad);
  uStack_20 = param_1[0xbac];
  puStack_1c = (ushort *)param_1[0xac1];
  puVar2 = (ushort *)param_1[0xac2];
  iVar3 = *param_1;
  param_3 = param_3 + param_2;
  if ((int)param_2 < param_3) {
    do {
      iVar5 = (int)*(short *)(((uStack_20 & 0xffdfffff) >> 0x15) + 0x18 + (int)param_1);
      if (iVar5 < 0) {
        uVar7 = 0x200000;
        do {
          if ((uStack_20 & uVar7) == 0) {
            sVar1 = *(short *)(param_1 + (0x38f - iVar5));
          }
          else {
            sVar1 = *(short *)((int)param_1 + iVar5 * -4 + 0xe3e);
          }
          iVar5 = (int)sVar1;
          uVar7 = uVar7 >> 1;
        } while (iVar5 < 0);
      }
      if (puVar2 <= puStack_1c) {
        return -1;
      }
      bVar6 = *(byte *)(iVar5 + 0xa18 + (int)param_1);
      uStack_20 = uStack_20 << (bVar6 & 0x1f);
      cVar8 = cVar8 - bVar6;
      if (cVar8 < '\x01') {
        bVar6 = -cVar8;
        cVar8 = cVar8 + '\x10';
        uStack_20 = uStack_20 | (uint)*puStack_1c << (bVar6 & 0x1f);
        puStack_1c = puStack_1c + 1;
      }
      uVar7 = iVar5 - 0x100;
      if ((int)uVar7 < 0) {
        *(char *)(iVar3 + param_2) = (char)uVar7;
        param_2 = param_2 + 1;
      }
      else {
        uVar10 = uVar7 & 7;
        if (uVar10 == 7) {
          iVar5 = (int)*(short *)(((uStack_20 & 0xff7fffff) >> 0x17) + 0x818 + (int)param_1);
          if (iVar5 < 0) {
            uVar10 = 0x800000;
            do {
              if ((uStack_20 & uVar10) == 0) {
                sVar1 = *(short *)(param_1 + (0x8cf - iVar5));
              }
              else {
                sVar1 = *(short *)((int)param_1 + iVar5 * -4 + 0x233e);
              }
              iVar5 = (int)sVar1;
              uVar10 = uVar10 >> 1;
            } while (iVar5 < 0);
          }
          bVar6 = *(byte *)(iVar5 + 0xcb8 + (int)param_1);
          uStack_20 = uStack_20 << (bVar6 & 0x1f);
          cVar8 = cVar8 - bVar6;
          if (cVar8 < '\x01') {
            uVar4 = *puStack_1c;
            bVar6 = -cVar8;
            cVar8 = cVar8 + '\x10';
            puStack_1c = puStack_1c + 1;
            uStack_20 = uStack_20 | (uint)uVar4 << (bVar6 & 0x1f);
          }
          uVar10 = iVar5 + 7;
        }
        cVar9 = (char)((int)uVar7 >> 3);
        if (cVar9 < '\x03') {
          iStack_14 = param_1[cVar9 + 3];
          if (cVar9 != '\0') {
            param_1[cVar9 + 3] = param_1[3];
            param_1[3] = iStack_14;
          }
        }
        else {
          iVar5 = (int)cVar9;
          bVar6 = (&UNK_0045e380)[iVar5];
          if (bVar6 < 3) {
            if (bVar6 == 0) {
              iStack_14 = *(int *)(&UNK_0045e3b8 + iVar5 * 4);
            }
            else {
              cVar8 = cVar8 - bVar6;
              uVar7 = uStack_20 >> (0x20 - bVar6 & 0x1f);
              uStack_20 = uStack_20 << (bVar6 & 0x1f);
              if (cVar8 < '\x01') {
                bVar6 = -cVar8;
                cVar8 = cVar8 + '\x10';
                uStack_20 = uStack_20 | (uint)*puStack_1c << (bVar6 & 0x1f);
                puStack_1c = puStack_1c + 1;
              }
              iStack_14 = uVar7 + *(int *)(&UNK_0045e3b8 + iVar5 * 4);
            }
          }
          else {
            if (bVar6 == 3) {
              uStack_10 = 0;
            }
            else {
              cVar9 = cVar8 - bVar6;
              uStack_10 = uStack_20 >> (0x23 - bVar6 & 0x1f);
              cVar8 = cVar9 + '\x03';
              uStack_20 = uStack_20 << (bVar6 - 3 & 0x1f);
              if (cVar8 < '\x01') {
                bVar6 = -cVar8;
                cVar8 = cVar9 + '\x13';
                uStack_20 = uStack_20 | (uint)*puStack_1c << (bVar6 & 0x1f);
                puStack_1c = puStack_1c + 1;
              }
            }
            iStack_14 = (int)*(char *)((uStack_20 >> 0x19) + 0xdb4 + (int)param_1);
            bVar6 = *(byte *)(iStack_14 + 0xe34 + (int)param_1);
            uStack_20 = uStack_20 << (bVar6 & 0x1f);
            cVar8 = cVar8 - bVar6;
            if (cVar8 < '\x01') {
              bVar6 = -cVar8;
              cVar8 = cVar8 + '\x10';
              uStack_20 = uStack_20 | (uint)*puStack_1c << (bVar6 & 0x1f);
              puStack_1c = puStack_1c + 1;
            }
            iStack_14 = *(int *)(&UNK_0045e3b8 + iVar5 * 4) + uStack_10 * 8 + iStack_14;
          }
          param_1[5] = param_1[4];
          param_1[4] = param_1[3];
          param_1[3] = iStack_14;
        }
        iVar5 = uVar10 + 2;
        uVar7 = param_2 - iStack_14 & param_1[2];
        do {
          uVar7 = uVar7 + 1;
          iVar5 = iVar5 + -1;
          uVar10 = param_2 + 1;
          *(undefined *)(iVar3 + param_2) = *(undefined *)(iVar3 + -1 + uVar7);
          param_2 = uVar10;
        } while (0 < iVar5);
      }
    } while ((int)param_2 < param_3);
  }
  *(char *)(param_1 + 0xbad) = cVar8;
  param_1[0xbac] = uStack_20;
  param_1[0xac1] = (int)puStack_1c;
  param_1[0xbb0] = param_2 & param_1[2];
  return param_2 - param_3;
}



int FUN_00433440(int param_1,int param_2,int param_3)

{
  int iVar1;
  
  if (param_2 < 0x101) {
    iVar1 = 0x101 - param_2;
    if (param_3 <= 0x101 - param_2) {
      iVar1 = param_3;
    }
    iVar1 = FUN_004334a0(param_1,param_2,iVar1);
    param_3 = (param_3 - iVar1) + param_2;
    *(int *)(param_1 + 0x2ec0) = iVar1;
    param_2 = iVar1;
    if (param_3 < 1) {
      return param_3;
    }
  }
  iVar1 = FUN_004330c0(param_1,param_2,param_3);
  return iVar1;
}



int FUN_004334a0(int *param_1,int param_2,int param_3)

{
  undefined uVar1;
  short sVar2;
  ushort *puVar3;
  int iVar4;
  ushort uVar5;
  byte bVar6;
  uint uVar7;
  char cVar8;
  char cVar9;
  int iVar10;
  ushort *puVar11;
  uint uVar12;
  uint uStack_1c;
  uint uStack_18;
  int iStack_14;
  
  cVar9 = *(char *)(param_1 + 0xbad);
  uStack_18 = param_1[0xbac];
  puVar11 = (ushort *)param_1[0xac1];
  puVar3 = (ushort *)param_1[0xac2];
  iVar4 = *param_1;
  param_3 = param_3 + param_2;
  if (param_2 < param_3) {
    do {
      iVar10 = (int)*(short *)(((uStack_18 & 0xffdfffff) >> 0x15) + 0x18 + (int)param_1);
      if (iVar10 < 0) {
        uVar7 = 0x200000;
        do {
          if ((uStack_18 & uVar7) == 0) {
            sVar2 = *(short *)(param_1 + (0x38f - iVar10));
          }
          else {
            sVar2 = *(short *)((int)param_1 + iVar10 * -4 + 0xe3e);
          }
          iVar10 = (int)sVar2;
          uVar7 = uVar7 >> 1;
        } while (iVar10 < 0);
      }
      if (puVar3 <= puVar11) {
        return -1;
      }
      bVar6 = *(byte *)(iVar10 + 0xa18 + (int)param_1);
      uStack_18 = uStack_18 << (bVar6 & 0x1f);
      cVar8 = cVar9 - bVar6;
      cVar9 = cVar8;
      if (cVar8 < '\x01') {
        uVar5 = *puVar11;
        puVar11 = puVar11 + 1;
        cVar9 = cVar8 + '\x10';
        uStack_18 = uStack_18 | (uint)uVar5 << (-cVar8 & 0x1fU);
      }
      uVar7 = iVar10 - 0x100;
      if ((int)uVar7 < 0) {
        *(char *)(iVar4 + param_2) = (char)uVar7;
        iVar10 = param_1[1] + param_2;
        param_2 = param_2 + 1;
        *(char *)(iVar10 + iVar4) = (char)uVar7;
      }
      else {
        uVar12 = uVar7 & 7;
        if (uVar12 == 7) {
          iVar10 = (int)*(short *)(((uStack_18 & 0xff7fffff) >> 0x17) + 0x818 + (int)param_1);
          if (iVar10 < 0) {
            uVar12 = 0x800000;
            do {
              if ((uStack_18 & uVar12) == 0) {
                sVar2 = *(short *)(param_1 + (0x8cf - iVar10));
              }
              else {
                sVar2 = *(short *)((int)param_1 + iVar10 * -4 + 0x233e);
              }
              iVar10 = (int)sVar2;
              uVar12 = uVar12 >> 1;
            } while (iVar10 < 0);
          }
          bVar6 = *(byte *)(iVar10 + 0xcb8 + (int)param_1);
          uStack_18 = uStack_18 << (bVar6 & 0x1f);
          cVar8 = cVar9 - bVar6;
          cVar9 = cVar8;
          if (cVar8 < '\x01') {
            uVar5 = *puVar11;
            puVar11 = puVar11 + 1;
            cVar9 = cVar8 + '\x10';
            uStack_18 = uStack_18 | (uint)uVar5 << (-cVar8 & 0x1fU);
          }
          uVar12 = iVar10 + 7;
        }
        cVar8 = (char)((int)uVar7 >> 3);
        iVar10 = (int)cVar8;
        if (cVar8 < '\x03') {
          iStack_14 = param_1[iVar10 + 3];
          if (cVar8 != '\0') {
            param_1[iVar10 + 3] = param_1[3];
            param_1[3] = iStack_14;
          }
        }
        else {
          bVar6 = (&UNK_0045e380)[iVar10];
          if (bVar6 < 3) {
            if (bVar6 == 0) {
              iStack_14 = 1;
            }
            else {
              cVar9 = cVar9 - bVar6;
              uVar7 = uStack_18 >> (0x20 - bVar6 & 0x1f);
              uStack_18 = uStack_18 << (bVar6 & 0x1f);
              if (cVar9 < '\x01') {
                uVar5 = *puVar11;
                puVar11 = puVar11 + 1;
                bVar6 = -cVar9;
                cVar9 = cVar9 + '\x10';
                uStack_18 = uStack_18 | (uint)uVar5 << (bVar6 & 0x1f);
              }
              iStack_14 = uVar7 + *(int *)(&UNK_0045e3b8 + iVar10 * 4);
            }
          }
          else {
            if (bVar6 == 3) {
              uStack_1c = 0;
            }
            else {
              cVar8 = cVar9 - bVar6;
              uStack_1c = uStack_18 >> (0x23 - bVar6 & 0x1f);
              cVar9 = cVar8 + '\x03';
              uStack_18 = uStack_18 << (bVar6 - 3 & 0x1f);
              if (cVar9 < '\x01') {
                uVar5 = *puVar11;
                puVar11 = puVar11 + 1;
                bVar6 = -cVar9;
                cVar9 = cVar8 + '\x13';
                uStack_18 = uStack_18 | (uint)uVar5 << (bVar6 & 0x1f);
              }
            }
            iStack_14 = (int)*(char *)((uStack_18 >> 0x19) + 0xdb4 + (int)param_1);
            bVar6 = *(byte *)(iStack_14 + 0xe34 + (int)param_1);
            uStack_18 = uStack_18 << (bVar6 & 0x1f);
            cVar9 = cVar9 - bVar6;
            if (cVar9 < '\x01') {
              uVar5 = *puVar11;
              puVar11 = puVar11 + 1;
              bVar6 = -cVar9;
              cVar9 = cVar9 + '\x10';
              uStack_18 = uStack_18 | (uint)uVar5 << (bVar6 & 0x1f);
            }
            iStack_14 = *(int *)(&UNK_0045e3b8 + iVar10 * 4) + uStack_1c * 8 + iStack_14;
          }
          param_1[5] = param_1[4];
          param_1[4] = param_1[3];
          param_1[3] = iStack_14;
        }
        iVar10 = uVar12 + 2;
        do {
          uVar1 = *(undefined *)((param_2 - iStack_14 & param_1[2]) + iVar4);
          *(undefined *)(iVar4 + param_2) = uVar1;
          if (param_2 < 0x101) {
            *(undefined *)(param_1[1] + iVar4 + param_2) = uVar1;
          }
          param_2 = param_2 + 1;
          iVar10 = iVar10 + -1;
        } while (0 < iVar10);
      }
    } while (param_2 < param_3);
  }
  *(char *)(param_1 + 0xbad) = cVar9;
  param_1[0xbac] = uStack_18;
  param_1[0xac1] = (int)puVar11;
  return param_2;
}



undefined8 __fastcall
FUN_004337fc(undefined4 param_1,undefined4 param_2,undefined4 param_3,uint param_4,int param_5,
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
  uint auStack_d4 [19];
  int aiStack_88 [18];
  uint uStack_40;
  int iStack_3c;
  int iStack_34;
  uint uStack_30;
  uint uStack_2c;
  undefined4 *puStack_28;
  uint uStack_24;
  int iStack_20;
  undefined4 uStack_1c;
  undefined4 uStack_c;
  
  uStack_40 = param_4 & 0xffff;
  uStack_1c = param_3;
  iStack_3c = param_5;
  uStack_24 = param_6 & 0xff;
  puStack_28 = param_7;
  iStack_34 = param_8;
  piVar10 = aiStack_88;
  uStack_c = param_2;
  for (iVar4 = 0x10; iVar6 = iStack_3c, piVar10 = piVar10 + 1, uVar5 = uStack_40, iVar4 != 0;
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
    uVar8 = uStack_24;
    bVar12 = 0 < iVar4;
    iVar4 = iVar4 + -1;
  } while (bVar12);
  if (auStack_d4[0] == 0x10000) {
    iVar4 = 1;
    uVar5 = 1 << ((byte)(uStack_24 - 1) & 0x1f);
    iVar6 = CONCAT31((int3)(uStack_24 - 1 >> 8),0x10) - uStack_24;
    iStack_20 = iVar6;
    do {
      auStack_118[iVar4] = auStack_118[iVar4] >> ((byte)iVar6 & 0x1f);
      auStack_d4[iVar4 + 1] = uVar5;
      uVar5 = uVar5 >> 1;
      iVar4 = iVar4 + 1;
    } while (iVar4 <= (int)uVar8);
    cVar1 = (char)iVar4;
    while (cVar1 < '\x11') {
      cVar1 = (char)iVar4;
      iVar4 = iVar4 + 1;
      auStack_d4[iVar4] = 1 << (0x10U - cVar1 & 0x1f);
      cVar1 = (char)iVar4;
    }
    uVar5 = auStack_118[uStack_24 + 1] >> ((byte)iStack_20 & 0x1f);
    if (uVar5 != 0x10000) {
      puVar11 = (undefined2 *)((int)puStack_28 + uVar5 * 2);
      for (iVar4 = (1 << ((byte)uStack_24 & 0x1f)) - uVar5; iVar4 != 0; iVar4 = iVar4 + -1) {
        *puVar11 = 0;
        puVar11 = puVar11 + 1;
      }
    }
    iVar4 = 0;
    uStack_30 = uStack_40;
LAB_00433967:
    do {
      uVar5 = (uint)*(byte *)(iVar4 + iStack_3c);
      if (uVar5 != 0) {
        uStack_2c = auStack_118[uVar5];
        uVar8 = uStack_2c + auStack_d4[uVar5 + 1];
        if ((int)uVar5 <= (int)uStack_24) {
          if (1 << ((byte)uStack_24 & 0x1f) < (int)uVar8) {
            uVar3 = 0;
            goto LAB_00433a41;
          }
          iVar6 = uVar8 - uStack_2c;
          psVar2 = (short *)(uStack_2c * 2 + (int)puStack_28);
          auStack_118[uVar5] = uVar8;
          do {
            *psVar2 = (short)iVar4;
            psVar2 = psVar2 + 1;
            iVar6 = iVar6 + -1;
          } while (iVar6 != 0);
          iVar4 = iVar4 + 1;
          if ((int)uStack_40 <= iVar4) {
            uVar3 = 1;
            goto LAB_00433a41;
          }
          goto LAB_00433967;
        }
        iVar6 = uVar5 - uStack_24;
        uVar7 = uStack_2c << ((byte)uStack_24 + 0x10 & 0x1f);
        auStack_118[uVar5] = uVar8;
        psVar2 = (short *)((int)puStack_28 + (uStack_2c >> ((byte)iStack_20 & 0x1f)) * 2);
        do {
          if (*psVar2 == 0) {
            *psVar2 = (short)uStack_30;
            *(undefined4 *)(iStack_34 + uStack_30 * 4) = 0;
            uStack_30 = uStack_30 + 1;
            *psVar2 = -*psVar2;
          }
          psVar2 = (short *)(iStack_34 + *psVar2 * -4);
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
    } while (iVar4 < (int)uStack_40);
    uVar3 = 1;
  }
  else if (auStack_d4[0] == 0) {
    for (iVar4 = 1 << ((char)uStack_24 - 1U & 0x1f); iVar4 != 0; iVar4 = iVar4 + -1) {
      *puStack_28 = 0;
      puStack_28 = puStack_28 + 1;
    }
    uVar3 = 1;
  }
  else {
    uVar3 = 0;
  }
LAB_00433a41:
  return CONCAT44(uStack_c,uVar3);
}



undefined4 FUN_00433a80(undefined4 param_1,int param_2,undefined4 *param_3)

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
  short sStack_26;
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
  if (sStack_26 != 0) {
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
FUN_00433c13(undefined4 param_1,undefined4 param_2,int *param_3,uint param_4,int param_5)

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
  uint uStack_38;
  int aiStack_28 [4];
  undefined4 uStack_4;
  
  puVar15 = (ushort *)param_3[0xac1];
  uVar4 = param_5 + param_4;
  iVar1 = *param_3;
  uStack_38 = param_3[0xbac];
  aiStack_28[0] = param_3[3];
  aiStack_28[1] = param_3[4];
  aiStack_28[2] = param_3[5];
  aiStack_28[3] = (int)*(byte *)(param_3 + 0xbad);
  uStack_4 = param_2;
  do {
    iVar2 = aiStack_28[1];
    puVar14 = (ushort *)param_3[0xac2];
    uVar16 = param_4;
    while( true ) {
      iVar11 = (int)*(short *)((int)param_3 + (uStack_38 >> 0x16) * 2 + 0x18);
      if (iVar11 < 0) {
        uVar12 = uStack_38 << 10;
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
      uStack_38 = uStack_38 << (bVar10 & 0x1f);
      bVar7 = (char)aiStack_28[3] - bVar10;
      if (bVar7 == 0 || (char)aiStack_28[3] < (char)bVar10) {
        uVar3 = *puVar15;
        puVar15 = puVar15 + 1;
        uStack_38 = (uint)uVar3 << ((bVar7 ^ 0xff) + 1 & 0x1f) | uStack_38;
        bVar7 = bVar7 + 0x10;
      }
      aiStack_28[3] = (int)bVar7;
      uVar12 = iVar11 - 0x100;
      if (-1 < (int)uVar12) break;
      param_4 = uVar16 + 1;
      *(char *)(uVar16 + iVar1) = (char)uVar12;
      puVar14 = (ushort *)param_3[0xac2];
      uVar16 = param_4;
      if (uVar4 <= param_4) goto LAB_00433e54;
    }
    uVar13 = uVar12 >> 3;
    uVar12 = uVar12 & 7;
    if (uVar12 == 7) {
      iVar11 = (int)*(short *)((int)param_3 + (uStack_38 >> 0x18) * 2 + 0x818);
      if (iVar11 < 0) {
        uVar12 = uStack_38 << 8;
        do {
          bVar17 = CARRY4(uVar12,uVar12);
          uVar12 = uVar12 * 2;
          iVar11 = (int)*(short *)((int)param_3 + (iVar11 * -2 + (uint)bVar17) * 2 + 0x233c);
        } while (iVar11 < 0);
      }
      bVar10 = *(byte *)(iVar11 + 0xcb8 + (int)param_3);
      uVar12 = iVar11 + 7;
      uStack_38 = uStack_38 << (bVar10 & 0x1f);
      bVar8 = bVar7 - bVar10;
      aiStack_28[3] = (int)bVar8;
      if (bVar8 == 0 || (char)bVar7 < (char)bVar10) {
        uStack_38 = (uint)*puVar15 << ((bVar8 ^ 0xff) + 1 & 0x1f) | uStack_38;
        aiStack_28[3] = (int)(byte)(bVar8 + 0x10);
        puVar15 = puVar15 + 1;
      }
    }
    uVar5 = uVar13 & 0xff;
    puVar14 = puVar15;
    if ((char)uVar13 < '\x04') {
      if (uVar13 != 0) {
        if ((char)uVar13 == '\x03') {
          iVar11 = 1;
          goto LAB_00433e13;
        }
        iVar2 = aiStack_28[uVar13];
        aiStack_28[uVar13] = aiStack_28[0];
        aiStack_28[0] = iVar2;
      }
    }
    else {
      iVar11 = (uStack_38 >> ((&UNK_00433be0)[uVar5] & 0x1f)) + *(int *)(&UNK_0045e3b8 + uVar5 * 4);
      bVar10 = (&UNK_0045e380)[uVar5];
      uStack_38 = uStack_38 << (bVar10 & 0x1f);
      cVar9 = (char)aiStack_28[3];
      bVar7 = cVar9 - bVar10;
      aiStack_28[3] = (int)bVar7;
      if (bVar7 == 0 || cVar9 < (char)bVar10) {
        uStack_38 = (uint)*puVar15 << ((bVar7 ^ 0xff) + 1 & 0x1f) | uStack_38;
        bVar10 = bVar7 + 0x10;
        aiStack_28[3] = (int)bVar10;
        puVar14 = puVar15 + 1;
        if (bVar10 == 0 || SCARRY1(bVar7,'\x10') != (char)bVar10 < '\0') {
          uStack_38 = (uint)puVar15[1] << ((bVar10 ^ 0xff) + 1 & 0x1f) | uStack_38;
          aiStack_28[3] = (int)(byte)(bVar7 + 0x20);
          puVar14 = puVar15 + 2;
        }
      }
LAB_00433e13:
      aiStack_28[1] = aiStack_28[0];
      aiStack_28[2] = iVar2;
      puVar15 = puVar14;
      aiStack_28[0] = iVar11;
    }
    bVar7 = (byte)aiStack_28[3];
    uVar13 = uVar16 - aiStack_28[0] & param_3[2];
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
LAB_00433e54:
      uVar6 = 0;
      if (param_4 != uVar4) {
        uVar6 = 0xffffffff;
      }
      *(byte *)(param_3 + 0xbad) = bVar7;
      param_3[0xbb0] = param_4 & param_3[2];
      param_3[0xac1] = (int)puVar15;
      param_3[3] = aiStack_28[0];
      param_3[4] = aiStack_28[1];
      param_3[5] = aiStack_28[2];
      param_3[0xbac] = uStack_38;
      return CONCAT44(uStack_4,uVar6);
    }
  } while( true );
}



undefined4 * __thiscall FUN_00433eb0(undefined4 *param_1,undefined4 param_2,int param_3)

{
  undefined4 uVar1;
  int iVar2;
  
  InitializeCriticalSection(param_1 + 5);
  InitializeCriticalSection(param_1 + 0xb);
  FUN_0043c210();
  *param_1 = &UNK_0045e6c4;
  FUN_0043c320();
  param_1[0x1e] = param_2;
  param_1[0x14] = 0;
  param_1[0x15] = 0;
  param_1[0x11] = 0;
  param_1[0x16] = 0;
  param_1[0x20] = 0;
  param_1[0x21] = 0;
  param_1[0x23] = 0;
  param_1[0x25] = 0;
  param_1[0x24] = 0;
  param_1[0x12] = 0;
  if (param_3 == 0) {
    uVar1 = 0;
  }
  else {
    uVar1 = *(undefined4 *)(param_3 + 0x18);
  }
  param_1[0x26] = uVar1;
  param_1[0x35] = 0;
  param_1[2] = 0;
  param_1[1] = 0;
  param_1[4] = 0;
  param_1[3] = 0;
  param_1[0x22] = 0;
  param_1[0x13] = 0;
  param_1[0x19] = 0;
  iVar2 = FUN_0043c120();
  param_1[0x27] = 0;
  param_1[0x1a] = 0;
  param_1[0x17] = (uint)(iVar2 == 0);
  param_1[0x1b] = 0;
  param_1[0x1c] = 0;
  param_1[0x2d] = 0;
  param_1[0x2e] = 0;
  param_1[0x2f] = 0;
  param_1[0x28] = 0;
  param_1[0x29] = 0;
  param_1[0x32] = 0;
  param_1[0x18] = 0;
  param_1[0x2c] = 0xffffffff;
  return param_1;
}



void __fastcall FUN_00433fa0(undefined4 *param_1)

{
  int iVar1;
  int iVar2;
  
  *param_1 = &UNK_0045e6c4;
  FUN_00435ca0();
  FUN_00435aa0();
  iVar1 = param_1[0x21];
  param_1[0x24] = 0;
  param_1[0x23] = 0;
  param_1[0x25] = 0;
  param_1[0x15] = 0;
  param_1[0x14] = 0;
  if (iVar1 != 0) {
    FUN_00443b30();
    FUN_0044bb7e(iVar1);
    param_1[0x21] = 0;
  }
  iVar1 = param_1[0x35];
  if (iVar1 != 0) {
    EnterCriticalSection(iVar1);
    iVar2 = *(int *)(iVar1 + 0x18);
    *(undefined4 *)(iVar1 + 0x1c) = 0;
    while (iVar2 != 0) {
      *(undefined4 *)(iVar1 + 0x18) = *(undefined4 *)(iVar2 + 4);
      if (*(int *)(iVar2 + 8) != 0) {
        *(undefined4 *)(*(int *)(iVar2 + 8) + 100) = 0;
        FUN_0043f350(*(undefined4 *)(iVar2 + 8));
      }
      FUN_0044bb7e(iVar2);
      iVar2 = *(int *)(iVar1 + 0x18);
    }
    *(undefined4 *)(iVar1 + 0x18) = 0;
    LeaveCriticalSection(iVar1);
    iVar1 = param_1[0x35];
    if (iVar1 != 0) {
      FUN_00436700();
      DeleteCriticalSection(iVar1);
      FUN_0044bb7e(iVar1);
    }
    param_1[0x35] = 0;
  }
  iVar1 = param_1[0x22];
  if (iVar1 != 0) {
    FUN_00443b30();
    FUN_0044bb7e(iVar1);
    param_1[0x22] = 0;
  }
  if (param_1[0x1d] != 0) {
    RemovePropA(param_1[0x1d],0x469738);
    DestroyWindow(param_1[0x1d]);
    param_1[0x1d] = 0;
  }
  if (param_1[0x27] != 0) {
    FUN_0044bb7e(param_1[0x27]);
    param_1[0x27] = 0;
  }
  if (param_1[0x32] != 0) {
    FUN_0044bb7e(param_1[0x32]);
    param_1[0x32] = 0;
  }
  FUN_0043c3b0();
  DeleteCriticalSection(param_1 + 0xb);
  DeleteCriticalSection(param_1 + 5);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int __fastcall FUN_00434100(int *param_1)

{
  int iVar1;
  
  iVar1 = FUN_0044ba20(0x20);
  if (iVar1 == 0) {
    iVar1 = 0;
  }
  else {
    InitializeCriticalSection(iVar1);
    *(undefined4 *)(iVar1 + 0x1c) = 0;
    *(undefined4 *)(iVar1 + 0x18) = 0;
  }
  param_1[0x35] = iVar1;
  (**(code **)*param_1)();
  if (*(int *)(param_1[0x1f] + -8) == 0) {
    FUN_0043c590(0x469744);
  }
  SetWindowTextA(param_1[0x1d],param_1[0x1f]);
  FUN_0041b570(param_1[0x1d],0x100);
  param_1[0x14] = 1;
  if (param_1[0x20] != 0) {
    iVar1 = (**(code **)(*param_1 + 0x18))(param_1[0x20]);
    param_1[0x14] = iVar1;
  }
  if ((_DAT_00475be2 != 0) && (param_1[0x13] == 0)) {
    param_1[0x11] = 1;
  }
  return param_1[0x14];
}



void __thiscall FUN_00434450(int param_1,undefined4 param_2)

{
  *(undefined4 *)(param_1 + 0x90) = param_2;
  *(undefined4 *)(param_1 + 0x8c) = param_2;
  return;
}



void __thiscall FUN_00434480(int param_1,undefined4 param_2)

{
  *(undefined4 *)(param_1 + 0x94) = param_2;
  return;
}



void __thiscall FUN_00434490(int param_1,undefined4 param_2)

{
  int iVar1;
  int unaff_ESI;
  undefined4 unaff_retaddr;
  int iStack_10;
  int iStack_c;
  int iStack_8;
  undefined4 uStack_4;
  
  FUN_004449c0();
  iStack_10 = 0;
  iStack_c = 0;
  iStack_8 = 0;
  uStack_4 = 0;
  if (*(int **)(param_1 + 0x84) != (int *)0x0) {
    (**(code **)(**(int **)(param_1 + 0x84) + 8))(&iStack_10);
    iVar1 = IsRectEmpty(unaff_retaddr);
    if (iVar1 == 0) {
      IntersectRect(&stack0xffffffec,unaff_retaddr,&stack0xffffffec);
    }
    (**(code **)(**(int **)(param_1 + 0x84) + 0xc))
              (param_2,unaff_ESI,iStack_10,iStack_c - unaff_ESI,iStack_8 - iStack_10,unaff_ESI,
               iStack_10,0,0,0);
  }
  FUN_00435cf0(&iStack_10);
  return;
}



bool __fastcall FUN_00434b60(int param_1)

{
  int iVar1;
  int iVar2;
  
  if ((*(int *)(param_1 + 0xd0) != 1) && (*(int *)(param_1 + 0xd0) != 2)) {
    return false;
  }
  iVar1 = *(int *)(param_1 + 0xa0);
  if (iVar1 == 0) {
    return *(int *)(**(int **)(param_1 + 200) + 0xa48) == 0;
  }
  if (*(int *)(iVar1 + 0xa48) == 0) {
    iVar2 = 5;
    if (*(int *)(param_1 + 0xd0) != 1) {
      iVar2 = -5;
    }
    *(float *)(iVar1 + 0xa24) = (float)iVar2;
    *(undefined4 *)(iVar1 + 0xa28) = 0;
    return true;
  }
  return false;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __fastcall FUN_00434e80(int param_1)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xd4);
  EnterCriticalSection(iVar2);
  for (iVar1 = *(int *)(iVar2 + 0x18); iVar1 != 0; iVar1 = *(int *)(iVar1 + 4)) {
    if ((*(int **)(iVar1 + 8))[0x1b] == 0) {
      (**(code **)(**(int **)(iVar1 + 8) + 0x20))();
    }
  }
  LeaveCriticalSection(iVar2);
  *(undefined4 *)(param_1 + 100) = 0;
  if (((_DAT_00475bd8 != 0) && (iVar2 = IsWindowVisible(_DAT_00475bd8), iVar2 != 0)) &&
     (iVar2 = FUN_00443260(), iVar2 == param_1)) {
    ShowWindow(_DAT_00475bd8,0);
  }
  ShowWindow(*(undefined4 *)(param_1 + 0x74),0);
  *(undefined4 *)(param_1 + 0x54) = 0;
  return;
}



void __thiscall FUN_00435220(int param_1,undefined4 param_2,undefined4 param_3)

{
  int iVar1;
  int iVar2;
  
  FUN_004449c0();
  if (*(int *)(param_1 + 0x54) != 0) {
    FUN_00434490(param_2,param_3);
    iVar1 = *(int *)(param_1 + 0xd4);
    FUN_004449c0();
    EnterCriticalSection(iVar1);
    for (iVar2 = *(int *)(iVar1 + 0x18); iVar2 != 0; iVar2 = *(int *)(iVar2 + 4)) {
      (**(code **)(**(int **)(iVar2 + 8) + 0x18))(param_2,param_3);
    }
    LeaveCriticalSection(iVar1);
  }
  return;
}



void __thiscall FUN_00435280(undefined4 param_1,int param_2)

{
  if (*(int *)(param_2 + 0x10) == 0) {
    *(undefined4 *)(param_2 + 0x10) = param_1;
  }
  if (*(int *)(param_2 + 0xc) == 0) {
    *(undefined4 *)(param_2 + 0xc) = param_1;
  }
  return;
}



int * FUN_004352a0(undefined4 param_1)

{
  int iVar1;
  int *piVar2;
  
  FUN_00435280(param_1);
  iVar1 = FUN_0044ba20(0x3a8);
  if (iVar1 == 0) {
    piVar2 = (int *)0x0;
  }
  else {
    piVar2 = (int *)FUN_0043d220(param_1);
  }
  (**(code **)(*piVar2 + 4))();
  FUN_00435750(piVar2);
  return piVar2;
}



int * FUN_004352f0(undefined4 param_1)

{
  int iVar1;
  int *piVar2;
  
  FUN_00435280(param_1);
  iVar1 = FUN_0044ba20(0x3b0);
  if (iVar1 == 0) {
    piVar2 = (int *)0x0;
  }
  else {
    piVar2 = (int *)FUN_0043f1b0(param_1);
  }
  (**(code **)(*piVar2 + 4))();
  FUN_00435750(piVar2);
  return piVar2;
}



int * FUN_00435340(undefined4 param_1)

{
  int iVar1;
  int *piVar2;
  
  FUN_00435280(param_1);
  iVar1 = FUN_0044ba20(0x3b0);
  if (iVar1 == 0) {
    piVar2 = (int *)0x0;
  }
  else {
    piVar2 = (int *)FUN_0043e590(param_1);
  }
  (**(code **)(*piVar2 + 4))();
  FUN_00435750(piVar2);
  return piVar2;
}



int * FUN_00435390(undefined4 param_1)

{
  int iVar1;
  int *piVar2;
  
  FUN_00435280(param_1);
  iVar1 = FUN_0044ba20(0x414);
  if (iVar1 == 0) {
    piVar2 = (int *)0x0;
  }
  else {
    piVar2 = (int *)FUN_00444a60(param_1);
  }
  (**(code **)(*piVar2 + 4))();
  FUN_00435750(piVar2);
  return piVar2;
}



int FUN_004353e0(undefined4 param_1)

{
  int iVar1;
  
  FUN_00435280(param_1);
  iVar1 = FUN_0044ba20(0xa70);
  if (iVar1 == 0) {
    iVar1 = 0;
  }
  else {
    iVar1 = FUN_004462f0(param_1);
  }
  (**(code **)(*(int *)(iVar1 + 0x9a8) + 4))();
  FUN_00435750(-(uint)(iVar1 != 0) & iVar1 + 0x9a8U);
  return iVar1;
}



int FUN_00435440(undefined4 param_1)

{
  int iVar1;
  
  FUN_00435280(param_1);
  iVar1 = FUN_0044ba20(0xa80);
  if (iVar1 == 0) {
    iVar1 = 0;
  }
  else {
    iVar1 = FUN_004467a0(param_1);
  }
  (**(code **)(*(int *)(iVar1 + 0x9a8) + 4))();
  FUN_00435750(-(uint)(iVar1 != 0) & iVar1 + 0x9a8U);
  return iVar1;
}



int FUN_004354a0(undefined4 param_1)

{
  int iVar1;
  
  FUN_00435280(param_1);
  iVar1 = FUN_0044ba20(0xa98);
  if (iVar1 == 0) {
    iVar1 = 0;
  }
  else {
    iVar1 = FUN_00446b20(param_1);
  }
  (**(code **)(*(int *)(iVar1 + 0x9a8) + 4))();
  FUN_00435750(-(uint)(iVar1 != 0) & iVar1 + 0x9a8U);
  return iVar1;
}



int * FUN_00435500(undefined4 param_1)

{
  int iVar1;
  int *piVar2;
  
  FUN_00435280(param_1);
  iVar1 = FUN_0044ba20(0x3bc);
  if (iVar1 == 0) {
    piVar2 = (int *)0x0;
  }
  else {
    piVar2 = (int *)FUN_004474e0(param_1);
  }
  (**(code **)(*piVar2 + 4))();
  FUN_00435750(piVar2);
  return piVar2;
}



int * FUN_00435550(undefined4 param_1)

{
  int iVar1;
  int *piVar2;
  
  FUN_00435280(param_1);
  iVar1 = FUN_0044ba20(0xfc);
  if (iVar1 == 0) {
    piVar2 = (int *)0x0;
  }
  else {
    piVar2 = (int *)FUN_0043f690(param_1);
  }
  (**(code **)(*piVar2 + 4))();
  FUN_00435750(piVar2);
  return piVar2;
}



int * FUN_004355a0(undefined4 param_1)

{
  int iVar1;
  int *piVar2;
  
  FUN_00435280(param_1);
  iVar1 = FUN_0044ba20(0x90);
  if (iVar1 == 0) {
    piVar2 = (int *)0x0;
  }
  else {
    piVar2 = (int *)FUN_00448110(param_1);
  }
  (**(code **)(*piVar2 + 4))();
  FUN_00435750(piVar2);
  return piVar2;
}



int * FUN_004355f0(undefined4 param_1)

{
  int iVar1;
  int *piVar2;
  
  FUN_00435280(param_1);
  iVar1 = FUN_0044ba20(0xa0);
  if (iVar1 == 0) {
    piVar2 = (int *)0x0;
  }
  else {
    piVar2 = (int *)FUN_004486b0(param_1);
  }
  (**(code **)(*piVar2 + 4))();
  FUN_00435750(piVar2);
  return piVar2;
}



int __thiscall FUN_00435750(int param_1,int *param_2)

{
  int iVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  int **ppiVar5;
  
  iVar1 = *(int *)(param_1 + 0xd4);
  EnterCriticalSection(iVar1);
  piVar2 = (int *)FUN_0044ba20(0xc);
  if (piVar2 == (int *)0x0) {
    piVar2 = (int *)0x0;
  }
  else {
    piVar2[1] = 0;
    *piVar2 = 0;
    piVar2[2] = 0;
  }
  ppiVar5 = *(int ***)(iVar1 + 0x18);
  if (piVar2 == (int *)0x0) {
    LeaveCriticalSection(iVar1);
    return 0;
  }
  piVar2[2] = (int)param_2;
  param_2[0x19] = (int)piVar2;
  if (*(int *)(iVar1 + 0x18) == 0) {
    piVar2[1] = 0;
    *piVar2 = 0;
    if (*(int ***)(iVar1 + 0x18) != (int **)0x0) {
      **(int ***)(iVar1 + 0x18) = piVar2;
    }
    *(int **)(iVar1 + 0x18) = piVar2;
    *(int **)(iVar1 + 0x1c) = piVar2;
    iVar3 = piVar2[2];
    LeaveCriticalSection(iVar1);
    return iVar3;
  }
  if (ppiVar5 != (int **)0x0) {
    do {
      iVar3 = (**(code **)(*ppiVar5[2] + 0x34))();
      iVar4 = (**(code **)(*param_2 + 0x34))();
      if (iVar4 <= iVar3) break;
      ppiVar5 = (int **)ppiVar5[1];
    } while (ppiVar5 != (int **)0x0);
    if (ppiVar5 != (int **)0x0) {
      if (*ppiVar5 != (int *)0x0) {
        *piVar2 = (int)*ppiVar5;
        piVar2[1] = (int)ppiVar5;
        (*ppiVar5)[1] = (int)piVar2;
        *ppiVar5 = piVar2;
        iVar3 = piVar2[2];
        LeaveCriticalSection(iVar1);
        return iVar3;
      }
      iVar3 = *(int *)(iVar1 + 0x18);
      *piVar2 = 0;
      piVar2[1] = iVar3;
      if (*(int ***)(iVar1 + 0x18) != (int **)0x0) {
        **(int ***)(iVar1 + 0x18) = piVar2;
      }
      *(int **)(iVar1 + 0x18) = piVar2;
      iVar3 = piVar2[2];
      LeaveCriticalSection(iVar1);
      return iVar3;
    }
  }
  iVar3 = *(int *)(iVar1 + 0x1c);
  piVar2[1] = 0;
  *piVar2 = iVar3;
  if (*(int *)(iVar1 + 0x1c) != 0) {
    *(int **)(*(int *)(iVar1 + 0x1c) + 4) = piVar2;
  }
  *(int **)(iVar1 + 0x1c) = piVar2;
  iVar3 = piVar2[2];
  LeaveCriticalSection(iVar1);
  return iVar3;
}



void FUN_00435a80(void)

{
  FUN_00435c30();
  FUN_00435e00();
  return;
}



void __fastcall FUN_00435aa0(int param_1)

{
  int iVar1;
  
  EnterCriticalSection(param_1 + 0x2c);
  iVar1 = *(int *)(param_1 + 0xc);
  *(undefined4 *)(param_1 + 0x58) = 1;
  while (iVar1 != 0) {
    *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(iVar1 + 4);
    FUN_0044bb7e(iVar1);
    iVar1 = *(int *)(param_1 + 0xc);
  }
  *(undefined4 *)(param_1 + 0xc) = 0;
  *(undefined4 *)(param_1 + 0x10) = 0;
  *(undefined4 *)(param_1 + 0x58) = 0;
  LeaveCriticalSection(param_1 + 0x2c);
  return;
}



void FUN_00435b00(undefined4 param_1)

{
  FUN_00435b10(param_1);
  return;
}



void __thiscall FUN_00435b10(int param_1,undefined4 param_2)

{
  int iVar1;
  int iVar2;
  undefined4 uStack_20;
  undefined4 uStack_1c;
  undefined4 uStack_18;
  undefined4 uStack_14;
  undefined4 uStack_10;
  undefined4 uStack_c;
  undefined4 uStack_8;
  undefined4 uStack_4;
  
  iVar1 = *(int *)(param_1 + 0x88);
  uStack_20 = 0;
  uStack_1c = 0;
  uStack_18 = 0;
  uStack_14 = 0;
  if (iVar1 != 0) {
    uStack_4 = *(undefined4 *)(iVar1 + 0x2c);
    uStack_8 = *(undefined4 *)(iVar1 + 0x28);
    uStack_10 = 0;
    uStack_c = 0;
    iVar1 = IntersectRect(&uStack_20,param_2,&uStack_10);
    if (iVar1 != 0) {
      iVar1 = param_1 + 0x2c;
      EnterCriticalSection(iVar1);
      if (*(int *)(param_1 + 0xc) != 0) {
        uStack_10 = 0;
        uStack_c = 0;
        uStack_8 = 0;
        uStack_4 = 0;
        iVar2 = IntersectRect(&uStack_10,*(int *)(param_1 + 0xc) + 8,&uStack_20);
        if (iVar2 != 0) {
          iVar2 = *(int *)(param_1 + 0xc) + 8;
          UnionRect(iVar2,iVar2,&uStack_20);
          LeaveCriticalSection(iVar1);
          return;
        }
      }
      iVar2 = FUN_0044ba20(0x18);
      if (*(int *)(param_1 + 0xc) == 0) {
        *(int *)(param_1 + 0xc) = iVar2;
        *(undefined4 *)(iVar2 + 4) = 0;
      }
      else {
        *(int *)(iVar2 + 4) = *(int *)(param_1 + 0xc);
        **(int **)(param_1 + 0xc) = iVar2;
        *(int *)(param_1 + 0xc) = iVar2;
      }
      *(undefined4 *)(*(int *)(param_1 + 0xc) + 0xc) = uStack_1c;
      *(undefined4 *)(*(int *)(param_1 + 0xc) + 0x14) = uStack_14;
      *(undefined4 *)(*(int *)(param_1 + 0xc) + 8) = uStack_20;
      *(undefined4 *)(*(int *)(param_1 + 0xc) + 0x10) = uStack_18;
      **(undefined4 **)(param_1 + 0xc) = 0;
      LeaveCriticalSection(iVar1);
    }
  }
  return;
}



void __fastcall FUN_00435c30(int param_1)

{
  int iVar1;
  int iVar2;
  bool bVar3;
  
  bVar3 = true;
  EnterCriticalSection(param_1 + 0x2c);
  iVar1 = *(int *)(param_1 + 0xc);
  *(undefined4 *)(param_1 + 0xc) = 0;
  LeaveCriticalSection(param_1 + 0x2c);
  while (iVar1 != 0) {
    if (*(int *)(param_1 + 0x58) == 0) {
      if (bVar3) {
        FUN_00435220(iVar1 + 8,*(undefined4 *)(param_1 + 0x88));
      }
    }
    else {
      bVar3 = false;
    }
    iVar2 = *(int *)(iVar1 + 4);
    FUN_0044bb7e(iVar1);
    iVar1 = iVar2;
  }
  return;
}



void __fastcall FUN_00435ca0(int param_1)

{
  int iVar1;
  
  EnterCriticalSection(param_1 + 0x14);
  iVar1 = *(int *)(param_1 + 4);
  while (iVar1 != 0) {
    *(undefined4 *)(param_1 + 4) = *(undefined4 *)(iVar1 + 4);
    FUN_0044bb7e(iVar1);
    iVar1 = *(int *)(param_1 + 4);
  }
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  LeaveCriticalSection(param_1 + 0x14);
  return;
}



void FUN_00435cf0(undefined4 param_1)

{
  FUN_00435d00(param_1);
  return;
}



void __thiscall FUN_00435d00(int param_1,undefined4 param_2)

{
  int iVar1;
  int iVar2;
  undefined4 uStack_20;
  undefined4 uStack_1c;
  undefined4 uStack_18;
  undefined4 uStack_14;
  undefined4 uStack_10;
  undefined4 uStack_c;
  undefined4 uStack_8;
  undefined4 uStack_4;
  
  iVar1 = param_1 + 0x14;
  EnterCriticalSection(iVar1);
  iVar2 = *(int *)(param_1 + 0x88);
  if (iVar2 != 0) {
    uStack_14 = *(undefined4 *)(iVar2 + 0x2c);
    uStack_18 = *(undefined4 *)(iVar2 + 0x28);
    uStack_20 = 0;
    uStack_1c = 0;
    IntersectRect(&uStack_20,&uStack_20,param_2);
    if (*(int *)(param_1 + 4) != 0) {
      uStack_10 = 0;
      uStack_c = 0;
      uStack_8 = 0;
      uStack_4 = 0;
      iVar2 = IntersectRect(&uStack_10,*(int *)(param_1 + 4) + 8,&uStack_20);
      if (iVar2 != 0) {
        iVar2 = *(int *)(param_1 + 4) + 8;
        UnionRect(iVar2,iVar2,&uStack_20);
        LeaveCriticalSection(iVar1);
        return;
      }
    }
    iVar2 = FUN_0044ba20(0x18);
    if (*(int *)(param_1 + 4) == 0) {
      *(int *)(param_1 + 4) = iVar2;
      *(undefined4 *)(iVar2 + 4) = 0;
    }
    else {
      *(int *)(iVar2 + 4) = *(int *)(param_1 + 4);
      **(int **)(param_1 + 4) = iVar2;
      *(int *)(param_1 + 4) = iVar2;
    }
    iVar2 = *(int *)(param_1 + 4);
    *(undefined4 *)(iVar2 + 8) = uStack_20;
    *(undefined4 *)(iVar2 + 0xc) = uStack_1c;
    *(undefined4 *)(iVar2 + 0x10) = uStack_18;
    *(undefined4 *)(iVar2 + 0x14) = uStack_14;
    **(undefined4 **)(param_1 + 4) = 0;
  }
  LeaveCriticalSection(iVar1);
  return;
}



void __fastcall FUN_00435e00(int param_1)

{
  int iVar1;
  int iVar2;
  undefined4 uStack_10;
  undefined4 uStack_c;
  undefined4 uStack_8;
  undefined4 uStack_4;
  
  FUN_004449c0();
  EnterCriticalSection(param_1 + 0x14);
  iVar1 = *(int *)(param_1 + 4);
  *(undefined4 *)(param_1 + 4) = 0;
  LeaveCriticalSection(param_1 + 0x14);
  uStack_10 = 0;
  uStack_c = 0;
  uStack_8 = 0;
  uStack_4 = 0;
  while (iVar1 != 0) {
    CopyRect(&uStack_10,iVar1 + 8);
    if (*(int *)(param_1 + 0x44) != 0) {
      FUN_00444630(&uStack_10);
    }
    FUN_00435ed0(&uStack_10);
    iVar2 = *(int *)(iVar1 + 4);
    FUN_0044bb7e(iVar1);
    iVar1 = iVar2;
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __thiscall FUN_00435ed0(int param_1,undefined4 *param_2)

{
  int iVar1;
  undefined4 uVar2;
  
  FUN_004449c0();
  if (*(int *)(param_1 + 0x74) != 0) {
    iVar1 = IsWindow(*(int *)(param_1 + 0x74));
    if (iVar1 != 0) {
      uVar2 = GetDC(*(undefined4 *)(param_1 + 0x74));
      if (param_2 == (undefined4 *)0x0) {
        (**(code **)(**(int **)(param_1 + 0x88) + 4))(uVar2,0,0);
        ReleaseDC(*(undefined4 *)(param_1 + 0x74),uVar2);
        return;
      }
      _DAT_00475958 = param_1;
      (**(code **)**(undefined4 **)(param_1 + 0x88))
                (uVar2,*param_2,param_2[1],*param_2,param_2[1],param_2[2],param_2[3]);
      _DAT_00475958 = 0;
      ReleaseDC(*(undefined4 *)(param_1 + 0x74),uVar2);
    }
  }
  return;
}



void __fastcall FUN_00436700(int param_1)

{
  int iVar1;
  
  EnterCriticalSection(param_1);
  iVar1 = *(int *)(param_1 + 0x18);
  *(undefined4 *)(param_1 + 0x1c) = 0;
  while (iVar1 != 0) {
    *(undefined4 *)(param_1 + 0x18) = *(undefined4 *)(iVar1 + 4);
    if (*(int *)(iVar1 + 8) != 0) {
      *(undefined4 *)(*(int *)(iVar1 + 8) + 100) = 0;
      FUN_0043f350(*(undefined4 *)(iVar1 + 8));
    }
    FUN_0044bb7e(iVar1);
    iVar1 = *(int *)(param_1 + 0x18);
  }
  *(undefined4 *)(param_1 + 0x18) = 0;
  LeaveCriticalSection(param_1);
  return;
}



void __thiscall FUN_00436760(int param_1,undefined4 *param_2)

{
  param_2[1] = *(undefined4 *)(param_1 + 0x18);
  *param_2 = 0;
  if (*(undefined4 **)(param_1 + 0x18) != (undefined4 *)0x0) {
    **(undefined4 **)(param_1 + 0x18) = param_2;
  }
  *(undefined4 **)(param_1 + 0x18) = param_2;
  return;
}



void __thiscall FUN_00436780(int param_1,undefined4 *param_2)

{
  *param_2 = *(undefined4 *)(param_1 + 0x1c);
  param_2[1] = 0;
  if (*(int *)(param_1 + 0x1c) != 0) {
    *(undefined4 **)(*(int *)(param_1 + 0x1c) + 4) = param_2;
  }
  *(undefined4 **)(param_1 + 0x1c) = param_2;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_00436830(undefined4 param_1)

{
  int *piVar1;
  int iVar2;
  undefined *puVar3;
  int iVar4;
  
  iVar4 = 0;
  if (_DAT_004697a8 != 6) {
    puVar3 = &DAT_004697a8;
    do {
      iVar2 = lstrcmpA(puVar3 + -0x28,param_1);
      if (iVar2 == 0) break;
      piVar1 = (int *)(puVar3 + 0x2c);
      puVar3 = puVar3 + 0x2c;
      iVar4 = iVar4 + 1;
    } while (*piVar1 != 6);
  }
  return *(undefined4 *)(&DAT_004697a8 + iVar4 * 0x2c);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_00436880(undefined4 param_1)

{
  int *piVar1;
  int iVar2;
  undefined *puVar3;
  int iVar4;
  
  iVar4 = 0;
  if (_DAT_004698e0 != -1) {
    puVar3 = &DAT_004698e0;
    do {
      iVar2 = lstrcmpA(puVar3 + -0x28,param_1);
      if (iVar2 == 0) break;
      piVar1 = (int *)(puVar3 + 0x2c);
      puVar3 = puVar3 + 0x2c;
      iVar4 = iVar4 + 1;
    } while (*piVar1 != -1);
  }
  return *(undefined4 *)(&DAT_004698e0 + iVar4 * 0x2c);
}



int FUN_004368d0(int *param_1,int param_2,undefined4 param_3)

{
  int iVar1;
  int iVar2;
  
  iVar2 = 0;
  iVar1 = *param_1;
  for (; (iVar1 != 0 &&
         ((iVar1 = lstrcmpiA(param_3,param_1[1]), iVar1 != 0 || (param_2 != *param_1))));
      param_1 = param_1 + 10) {
    iVar1 = param_1[10];
    iVar2 = iVar2 + 1;
  }
  if ((param_2 == *param_1) && (iVar1 = lstrcmpiA(param_3,param_1[1]), iVar1 == 0)) {
    return iVar2;
  }
  return -1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00436d40(void)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  
  puVar2 = _DAT_00475bf0;
  if (_DAT_00475bf0 == (undefined4 *)0x0) {
    _DAT_00475bf0 = (undefined4 *)0x0;
    return;
  }
  do {
    puVar1 = (undefined4 *)puVar2[2];
    FUN_0044c4b9(*puVar2);
    FUN_0044c4b9(puVar2);
    puVar2 = puVar1;
  } while (puVar1 != (undefined4 *)0x0);
  _DAT_00475bf0 = puVar1;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00436d80(undefined4 param_1)

{
  int iVar1;
  undefined4 *puVar2;
  int iVar3;
  undefined4 uVar4;
  int iVar5;
  
  puVar2 = (undefined4 *)FUN_0044c5a2(0xc);
  iVar3 = lstrlenA(param_1);
  uVar4 = FUN_0044c5a2(iVar3 + 1);
  *puVar2 = uVar4;
  lstrcpyA(uVar4,param_1);
  puVar2[2] = 0;
  if (_DAT_00475bf0 == (undefined4 *)0x0) {
    _DAT_00475bf0 = puVar2;
    puVar2[1] = 0x7fffffff;
    return;
  }
  iVar5 = 1;
  iVar3 = (int)_DAT_00475bf0;
  do {
    iVar1 = *(int *)(iVar3 + 8);
    if (iVar1 == 0) break;
    iVar5 = iVar5 + 1;
    iVar3 = iVar1;
  } while (iVar5 != 0);
  *(undefined4 **)(iVar3 + 8) = puVar2;
  puVar2[1] = iVar5 + 0x7fffffff;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_00436df0(int param_1)

{
  int *piVar1;
  undefined4 *puVar2;
  
  puVar2 = _DAT_00475bf0;
  if (_DAT_00475bf0 != (undefined4 *)0x0) {
    do {
      if (puVar2[1] == param_1) {
        return *puVar2;
      }
      piVar1 = puVar2 + 2;
      puVar2 = (undefined4 *)*piVar1;
    } while ((undefined4 *)*piVar1 != (undefined4 *)0x0);
  }
  return 0;
}


/*
Unable to decompile 'FUN_00436e10'
Cause: Exception while decompiling 00436e10: process: timeout

*/


void __fastcall FUN_0043b020(undefined4 *param_1)

{
  *param_1 = 0;
  param_1[1] = 0;
  param_1[2] = 0;
  param_1[3] = 0;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

bool FUN_0043b030(int param_1,char param_2)

{
  undefined *puVar1;
  byte bVar2;
  int iVar3;
  undefined4 unaff_EBX;
  undefined2 uVar4;
  uint uVar5;
  int iVar6;
  
  uVar4 = (undefined2)((uint)unaff_EBX >> 0x10);
  bVar2 = 0;
  iVar6 = 0;
  if (param_1 == 0) {
    if (_DAT_004734c0 == 0) {
      iVar6 = FUN_0040e830(0,_DAT_004721c0,0x40);
    }
  }
  else {
    iVar3 = lstrlenA(param_1);
    if (iVar3 != 0) {
      puVar1 = (undefined *)(iVar3 + -2 + param_1);
      if (*(char *)(iVar3 + -2 + param_1) == ',') {
        *puVar1 = 0;
        uVar4 = (undefined2)(CONCAT13(1,(int3)unaff_EBX) >> 0x10);
        iVar6 = FUN_0044bf1a((int)*(char *)(iVar3 + -1 + param_1));
        if (iVar6 == 0x43) {
          uVar4 = 0x101;
        }
        else if ((iVar6 == 0x4c) && ((char)param_1 != '\0')) {
          bVar2 = 1;
        }
      }
      if ((_DAT_004734c0 == 0) && (param_2 != '\0')) {
        uVar5 = 0;
      }
      else {
        uVar5 = 0x10;
      }
      iVar6 = FUN_0040e830(param_1,_DAT_004721c0,
                           -(uint)bVar2 & 8 | (uint)((char)param_1 != '\0') | uVar5 | 0x40006);
      if ((_DAT_004734c0 != 0) && (iVar6 != 0)) {
        _DAT_004734c0 = 0;
      }
      if (((char)uVar4 != '\0') && (iVar6 != 0)) {
        _DAT_004734c0 = 1;
      }
      if ((char)((ushort)uVar4 >> 8) != '\0') {
        *puVar1 = 0x2c;
        return iVar6 == 1;
      }
    }
  }
  return iVar6 == 1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

bool FUN_0043b160(undefined4 param_1,uint param_2)

{
  int iVar1;
  
  if (_DAT_004734c0 == 0) {
    iVar1 = FUN_0040e830(param_1,_DAT_004721c0,param_2);
  }
  else {
    iVar1 = FUN_0040e830(param_1,_DAT_004721c0,param_2 | 0x10);
    if (iVar1 != 0) {
      _DAT_004734c0 = 1;
      return iVar1 == 1;
    }
  }
  return iVar1 == 1;
}



void FUN_0043b1c0(undefined2 param_1,undefined4 param_2)

{
  FUN_0043b160(param_1,param_2);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 * __fastcall FUN_0043b1e0(undefined4 *param_1)

{
  int iVar1;
  undefined4 *puVar2;
  
  param_1[0x28] = 0;
  param_1[0x29] = 0;
  *param_1 = &UNK_0045e720;
  puVar2 = param_1;
  for (iVar1 = 0x2a; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  _DAT_00475bd0 = GetCurrentThreadId();
  _DAT_00475bc0 = 0;
  _DAT_00469eb4 = 0x32;
  param_1[0xd] = 0xffff;
  param_1[0xe] = 0xffff;
  param_1[0xf] = 0xffff;
  param_1[0x10] = 0xffff;
  param_1[0x16] = 0x800a;
  param_1[0x22] = 0xffffff;
  param_1[0x23] = 0xffffffff;
  param_1[0x24] = 0xff00ff;
  param_1[0x25] = 0xffff;
  param_1[0x26] = 0;
  _DAT_00475bbc = param_1;
  _DAT_00475be8 = 0;
  return param_1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __fastcall FUN_0043b2a0(undefined4 *param_1)

{
  int iVar1;
  
  *param_1 = &UNK_0045e720;
  if (param_1[0x19] != 0) {
    DestroyCursor(param_1[0x19]);
    param_1[0x19] = 0;
  }
  if (param_1[0x1a] != 0) {
    DestroyCursor(param_1[0x1a]);
    param_1[0x1a] = 0;
  }
  if (param_1[0x1b] != 0) {
    DestroyCursor(param_1[0x1b]);
    param_1[0x1b] = 0;
  }
  if (_DAT_00475b98 != 0) {
    DeleteObject(_DAT_00475b98);
    _DAT_00475b98 = 0;
  }
  if (_DAT_00475c40 != (int *)0x0) {
    (**(code **)(*_DAT_00475c40 + 0x10))(1);
    _DAT_00475c40 = (int *)0x0;
  }
  iVar1 = param_1[0x21];
  if (iVar1 != 0) {
    FUN_00449a70();
    FUN_0044bb7e(iVar1);
    param_1[0x21] = 0;
  }
  iVar1 = param_1[0xb];
  if (iVar1 != 0) {
    FUN_00443050();
    FUN_0044bb7e(iVar1);
    param_1[0xb] = 0;
  }
  iVar1 = param_1[0xc];
  if (iVar1 != 0) {
    FUN_004491b0();
    FUN_0044bb7e(iVar1);
    param_1[0xc] = 0;
  }
  FUN_00436d40();
  _DAT_00475bbc = 0;
  _DAT_00475bd8 = 0;
  if (_DAT_00475bdc != 0) {
    CloseHandle(_DAT_00475bdc);
  }
  FUN_0043b780();
  FUN_0041b540();
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0043b780(void)

{
  if (_DAT_00475be8 != 0) {
    FreeLibrary(_DAT_00475be8);
  }
  return;
}



void __fastcall FUN_0043b7d0(int param_1)

{
  FUN_00444bd0();
  FUN_0043e890();
  FUN_0043e890();
  FUN_00444bd0();
  if (*(int *)(param_1 + 0x10) != 0) {
    FUN_00449aa0();
    return;
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0043b800(void)

{
  return _DAT_00475b98;
}



// WARNING: Removing unreachable block (ram,0x0043b9e6)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 __fastcall FUN_0043b880(int *param_1)

{
  undefined4 *puVar1;
  undefined4 uVar2;
  int iVar3;
  undefined4 *puVar4;
  undefined auStack_1c [8];
  undefined4 uStack_14;
  
  (**(code **)(*param_1 + 0x18))();
  (**(code **)(*param_1 + 0x14))();
  puVar1 = (undefined4 *)FUN_0044ba20(0x1c);
  if (puVar1 == (undefined4 *)0x0) {
    puVar1 = (undefined4 *)0x0;
  }
  else {
    puVar4 = puVar1;
    for (iVar3 = 7; iVar3 != 0; iVar3 = iVar3 + -1) {
      *puVar4 = 0;
      puVar4 = puVar4 + 1;
    }
  }
  *puVar1 = 0;
  if (_DAT_00472158 == 0) {
    if (_DAT_004721a0 == 0) {
      if (_DAT_0047219c == 0) {
        uVar2 = (**(code **)(*param_1 + 0x44))();
      }
      else {
        iVar3 = (**(code **)(*param_1 + 0x3c))();
        if (iVar3 == 0xffff) {
          PostMessageA(_DAT_00475bd8,0x8002,0,0);
          goto LAB_0043b932;
        }
        uVar2 = (**(code **)(*param_1 + 0x3c))();
      }
    }
    else {
      iVar3 = (**(code **)(*param_1 + 0x40))();
      if (iVar3 == 0xffff) {
        uVar2 = (**(code **)(*param_1 + 0x38))();
      }
      else {
        uVar2 = (**(code **)(*param_1 + 0x40))();
      }
    }
  }
  else {
    uVar2 = (**(code **)(*param_1 + 0x38))();
  }
  puVar1[2] = uVar2;
LAB_0043b932:
  PostMessageA(_DAT_00475bd8,0x806c,0,puVar1);
  FUN_0043baf0();
  iVar3 = GetMessageA(auStack_1c,0,0,0);
  do {
    if (iVar3 == 0) {
      if (_DAT_00475bc4 == 0) {
        iVar3 = param_1[0xb];
        if (iVar3 != 0) {
          FUN_00443050();
          FUN_0044bb7e(iVar3);
        }
        iVar3 = param_1[0xc];
        param_1[0xb] = 0;
        if (iVar3 != 0) {
          FUN_004491b0();
          FUN_0044bb7e(iVar3);
        }
        param_1[0xc] = 0;
        _DAT_00475bd8 = 0;
        iVar3 = param_1[0x21];
        if (iVar3 != 0) {
          FUN_00449a70();
          FUN_0044bb7e(iVar3);
        }
        param_1[0x21] = 0;
        FUN_0043b7d0();
        return uStack_14;
      }
      do {
        Sleep(100);
        GetExitCodeThread(_DAT_00475bc4,&stack0xffffffdc);
      } while( true );
    }
    if ((_DAT_00475c70 == 0) || (iVar3 = FUN_00443260(), iVar3 == 0)) {
LAB_0043b98d:
      TranslateMessage(auStack_1c);
      DispatchMessageA(auStack_1c);
    }
    else {
      iVar3 = FUN_00443260();
      iVar3 = IsDialogMessageA(*(undefined4 *)(iVar3 + 0x74),auStack_1c);
      if (iVar3 == 0) goto LAB_0043b98d;
    }
    iVar3 = GetMessageA(auStack_1c,0,0,0);
  } while( true );
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0043baf0(void)

{
  _DAT_00475bc0 = CreateEventA(0,1,0,0);
  _DAT_00475bc4 = FUN_0044d14d(0,0,&UNK_0043c0a0,0,0,0x475bd4);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0043bc50(ushort param_1)

{
  _DAT_00475be2 = _DAT_00475be2 | param_1;
  if (_DAT_00475be2 != 0) {
    Sleep(0);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0043bc70(ushort param_1)

{
  if ((_DAT_00475be2 != 0) && (_DAT_00475be2 = _DAT_00475be2 & ~param_1, _DAT_00475be2 == 0)) {
    Sleep(0);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __thiscall FUN_0043bec0(int *param_1,undefined4 param_2,undefined4 param_3)

{
  int iVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  undefined4 auStack_800 [8];
  undefined4 auStack_7de [503];
  
  puVar2 = (undefined4 *)0x469ebc;
  puVar3 = auStack_800;
  for (iVar1 = 8; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  *(undefined2 *)puVar3 = *(undefined2 *)puVar2;
  puVar2 = auStack_7de;
  for (iVar1 = 0x1f7; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  *(undefined2 *)puVar2 = 0;
  FUN_0040e750(_DAT_004721c0,param_2,auStack_800,0x800);
  (**(code **)(*param_1 + 0x58))(auStack_800,param_3);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __fastcall FUN_0043bf80(int param_1)

{
  int iVar1;
  undefined4 uVar2;
  
  if ((DAT_00475be0 & 1) != 0) {
    FUN_0043bc50(1);
  }
  iVar1 = FUN_0043bfe0();
  if (iVar1 == 0) {
    DAT_00475be4 = DAT_00475be4 | 1;
    uVar2 = LoadCursorA(0,0x7f02);
    uVar2 = SetCursor(uVar2);
    *(undefined4 *)(param_1 + 0x60) = uVar2;
    return;
  }
  if (_DAT_00475c40 != (int *)0x0) {
    (**(code **)(*_DAT_00475c40 + 0x28))();
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

bool FUN_0043bfe0(void)

{
  return _DAT_00475be4 != 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __fastcall FUN_0043bff0(int param_1)

{
  int iVar1;
  
  iVar1 = FUN_0043bfe0();
  if (iVar1 != 0) {
    FUN_0043bc70(1);
    if (_DAT_00475c40 != (int *)0x0) {
      (**(code **)(*_DAT_00475c40 + 0x28))();
    }
    SetCursor(*(undefined4 *)(param_1 + 0x60));
    *(undefined4 *)(param_1 + 0x60) = 0;
    _DAT_00475be4 = _DAT_00475be4 & 0xfffe;
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0043c120(void)

{
  return **(undefined4 **)(_DAT_00475bbc + 0x84);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0043c130(int param_1,int param_2)

{
  int iVar1;
  undefined4 uVar2;
  
  if (param_2 == 0) {
    iVar1 = FUN_0043bfe0();
    if (iVar1 == 0) {
      iVar1 = *(int *)(_DAT_00475bbc + 100);
      goto joined_r0x0043c18f;
    }
    if (param_1 == 0) {
      iVar1 = *(int *)(_DAT_00475bbc + 0x68);
      if (iVar1 != 0) goto LAB_0043c19e;
      uVar2 = 0x7f02;
    }
    else {
      iVar1 = *(int *)(_DAT_00475bbc + 0x6c);
      if (iVar1 != 0) goto LAB_0043c19e;
      uVar2 = 0x7f8a;
    }
  }
  else {
    iVar1 = *(int *)(_DAT_00475bbc + 100);
joined_r0x0043c18f:
    if (iVar1 != 0) goto LAB_0043c19e;
    uVar2 = 0x7f00;
  }
  iVar1 = LoadCursorA(0,uVar2);
LAB_0043c19e:
  SetCursor(iVar1);
  return 1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0043c1b0(void)

{
  if (_DAT_00475bbc != 0) {
    return *(undefined4 *)(_DAT_00475bbc + 100);
  }
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0043c1c0(undefined4 param_1,undefined4 param_2)

{
  if (_DAT_00475bbc != (int *)0x0) {
    (**(code **)(*_DAT_00475bbc + 0x20))(param_1,param_2);
  }
  return;
}



undefined4 FUN_0043c200(void)

{
  return 0x469ef4;
}



undefined4 * __fastcall FUN_0043c210(undefined4 *param_1)

{
  undefined4 *puVar1;
  
  puVar1 = (undefined4 *)FUN_0043c200();
  *param_1 = *puVar1;
  return param_1;
}



int * __thiscall FUN_0043c220(int *param_1,int *param_2)

{
  int iVar1;
  int *piVar2;
  
  iVar1 = *param_2;
  if (-1 < *(int *)(iVar1 + -0xc)) {
    *param_1 = iVar1;
    InterlockedIncrement(iVar1 + -0xc);
    return param_1;
  }
  piVar2 = (int *)FUN_0043c200();
  *param_1 = *piVar2;
  FUN_0043c590(*param_2);
  return param_1;
}



void __thiscall FUN_0043c260(undefined4 *param_1,int param_2)

{
  undefined4 *puVar1;
  
  if (param_2 == 0) {
    puVar1 = (undefined4 *)FUN_0043c200();
    *param_1 = *puVar1;
    return;
  }
  puVar1 = (undefined4 *)FUN_0044ba20(param_2 + 0xd);
  *puVar1 = 1;
  *(undefined *)((int)puVar1 + param_2 + 0xc) = 0;
  puVar1[1] = param_2;
  puVar1[2] = param_2;
  *param_1 = puVar1 + 3;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __fastcall FUN_0043c2b0(int *param_1)

{
  int iVar1;
  int *piVar2;
  
  if (*param_1 + -0xc != _DAT_00469ef0) {
    iVar1 = InterlockedDecrement(*param_1 + -0xc);
    if (iVar1 < 1) {
      FUN_0044bb7e(*param_1 + -0xc);
    }
    piVar2 = (int *)FUN_0043c200();
    *param_1 = *piVar2;
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0043c2f0(int param_1)

{
  int iVar1;
  
  if (param_1 != _DAT_00469ef0) {
    iVar1 = InterlockedDecrement(param_1);
    if (iVar1 < 1) {
      FUN_0044bb7e(param_1);
    }
  }
  return;
}



void __fastcall FUN_0043c320(int *param_1)

{
  if (*(int *)(*param_1 + -8) != 0) {
    if (-1 < *(int *)(*param_1 + -0xc)) {
      FUN_0043c2b0();
      return;
    }
    FUN_0043c590(0x475bf4);
  }
  return;
}



void __fastcall FUN_0043c340(undefined4 *param_1)

{
  int iVar1;
  uint uVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  
  puVar3 = (undefined4 *)*param_1;
  if (1 < (int)puVar3[-3]) {
    FUN_0043c2b0();
    FUN_0043c260(puVar3[-2]);
    iVar1 = puVar3[-2];
    puVar4 = (undefined4 *)*param_1;
    for (uVar2 = iVar1 + 1U >> 2; uVar2 != 0; uVar2 = uVar2 - 1) {
      *puVar4 = *puVar3;
      puVar3 = puVar3 + 1;
      puVar4 = puVar4 + 1;
    }
    for (uVar2 = iVar1 + 1U & 3; uVar2 != 0; uVar2 = uVar2 - 1) {
      *(undefined *)puVar4 = *(undefined *)puVar3;
      puVar3 = (undefined4 *)((int)puVar3 + 1);
      puVar4 = (undefined4 *)((int)puVar4 + 1);
    }
  }
  return;
}



void __thiscall FUN_0043c380(int *param_1,int param_2)

{
  if ((1 < *(int *)(*param_1 + -0xc)) || (*(int *)(*param_1 + -4) < param_2)) {
    FUN_0043c2b0();
    FUN_0043c260(param_2);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __fastcall FUN_0043c3b0(int *param_1)

{
  int iVar1;
  
  if (*param_1 + -0xc != _DAT_00469ef0) {
    iVar1 = InterlockedDecrement(*param_1 + -0xc);
    if (iVar1 < 1) {
      FUN_0044bb7e(*param_1 + -0xc);
    }
  }
  return;
}



void __thiscall
FUN_0043c3e0(int *param_1,undefined4 *param_2,uint param_3,undefined4 param_4,int param_5)

{
  undefined4 *puVar1;
  uint uVar2;
  undefined4 *puVar3;
  
  if (param_5 + param_3 == 0) {
    puVar1 = (undefined4 *)FUN_0043c200();
    *param_2 = *puVar1;
    return;
  }
  FUN_0043c260(param_5 + param_3);
  puVar1 = (undefined4 *)(*param_1 + param_3);
  puVar3 = (undefined4 *)*param_2;
  for (uVar2 = param_3 >> 2; uVar2 != 0; uVar2 = uVar2 - 1) {
    *puVar3 = *puVar1;
    puVar1 = puVar1 + 1;
    puVar3 = puVar3 + 1;
  }
  for (param_3 = param_3 & 3; param_3 != 0; param_3 = param_3 - 1) {
    *(undefined *)puVar3 = *(undefined *)puVar1;
    puVar1 = (undefined4 *)((int)puVar1 + 1);
    puVar3 = (undefined4 *)((int)puVar3 + 1);
  }
  return;
}



undefined4 * __thiscall FUN_0043c440(undefined4 *param_1,undefined4 *param_2)

{
  undefined4 *puVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  
  puVar1 = (undefined4 *)FUN_0043c200();
  *param_1 = *puVar1;
  if (param_2 != (undefined4 *)0x0) {
    if ((uint)param_2 >> 0x10 == 0) {
      iVar2 = FUN_0043ceb0((uint)param_2 & 0xffff);
      if (iVar2 == 0) {
        FUN_0045b01d(0x469ef8,(uint)param_2 & 0xffff,0x469f18);
        FUN_0045ae4e();
        FUN_0045b01d();
        FUN_0045adb0(10,&UNK_0043cfa0);
        FUN_0043cf80();
        return param_1;
      }
    }
    else {
      uVar3 = lstrlenA(param_2);
      if (uVar3 != 0) {
        FUN_0043c260(uVar3);
        puVar1 = (undefined4 *)*param_1;
        for (uVar4 = uVar3 >> 2; uVar4 != 0; uVar4 = uVar4 - 1) {
          *puVar1 = *param_2;
          param_2 = param_2 + 1;
          puVar1 = puVar1 + 1;
        }
        for (uVar3 = uVar3 & 3; uVar3 != 0; uVar3 = uVar3 - 1) {
          *(undefined *)puVar1 = *(undefined *)param_2;
          param_2 = (undefined4 *)((int)param_2 + 1);
          puVar1 = (undefined4 *)((int)puVar1 + 1);
        }
      }
    }
  }
  return param_1;
}



void __thiscall FUN_0043c4f0(int *param_1,undefined4 *param_2)

{
  uint uVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  
  FUN_0043c380(param_2);
  puVar2 = param_2;
  puVar3 = (undefined4 *)*param_1;
  for (uVar1 = (uint)param_2 >> 2; uVar1 != 0; uVar1 = uVar1 - 1) {
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  for (uVar1 = (uint)param_2 & 3; uVar1 != 0; uVar1 = uVar1 - 1) {
    *(undefined *)puVar3 = *(undefined *)puVar2;
    puVar2 = (undefined4 *)((int)puVar2 + 1);
    puVar3 = (undefined4 *)((int)puVar3 + 1);
  }
  *(undefined4 **)(*param_1 + -8) = param_2;
  *(undefined *)(*param_1 + (int)param_2) = 0;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int * __thiscall FUN_0043c530(int *param_1,int *param_2)

{
  int iVar1;
  int iVar2;
  
  iVar1 = *param_1;
  iVar2 = *param_2;
  if (iVar1 != iVar2) {
    if (((*(int *)(iVar1 + -0xc) < 0) && (iVar1 + -0xc != _DAT_00469ef0)) ||
       (*(int *)(iVar2 + -0xc) < 0)) {
      FUN_0043c4f0(*(undefined4 *)(iVar2 + -8),iVar2);
      return param_1;
    }
    FUN_0043c2b0();
    iVar1 = *param_2;
    *param_1 = iVar1;
    InterlockedIncrement(iVar1 + -0xc);
  }
  return param_1;
}



undefined4 __thiscall FUN_0043c590(undefined4 param_1,int param_2)

{
  undefined4 uVar1;
  
  if (param_2 == 0) {
    FUN_0043c4f0(0,0);
    return param_1;
  }
  uVar1 = lstrlenA(param_2);
  FUN_0043c4f0(uVar1,param_2);
  return param_1;
}



void __thiscall FUN_0043c5d0(int *param_1,undefined4 *param_2,uint param_3,undefined4 *param_4)

{
  uint uVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  
  if ((undefined *)((int)param_4 + (int)param_2) != (undefined *)0x0) {
    FUN_0043c260((undefined *)((int)param_4 + (int)param_2));
    puVar2 = param_2;
    puVar3 = (undefined4 *)*param_1;
    for (uVar1 = (uint)param_2 >> 2; uVar1 != 0; uVar1 = uVar1 - 1) {
      *puVar3 = *puVar2;
      puVar2 = puVar2 + 1;
      puVar3 = puVar3 + 1;
    }
    for (uVar1 = (uint)param_2 & 3; uVar1 != 0; uVar1 = uVar1 - 1) {
      *(undefined *)puVar3 = *(undefined *)puVar2;
      puVar2 = (undefined4 *)((int)puVar2 + 1);
      puVar3 = (undefined4 *)((int)puVar3 + 1);
    }
    puVar2 = (undefined4 *)(*param_1 + (int)param_2);
    for (uVar1 = param_3 >> 2; uVar1 != 0; uVar1 = uVar1 - 1) {
      *puVar2 = *param_4;
      param_4 = param_4 + 1;
      puVar2 = puVar2 + 1;
    }
    for (param_3 = param_3 & 3; param_3 != 0; param_3 = param_3 - 1) {
      *(undefined *)puVar2 = *(undefined *)param_4;
      param_4 = (undefined4 *)((int)param_4 + 1);
      puVar2 = (undefined4 *)((int)puVar2 + 1);
    }
  }
  return;
}



void __thiscall FUN_0043c630(int *param_1,uint param_2,undefined4 *param_3)

{
  int iVar1;
  uint uVar2;
  undefined4 *puVar3;
  
  if (param_2 != 0) {
    iVar1 = *param_1;
    if (*(int *)(iVar1 + -0xc) < 2) {
      if ((int)(*(int *)(iVar1 + -8) + param_2) <= *(int *)(iVar1 + -4)) {
        puVar3 = (undefined4 *)(*(int *)(iVar1 + -8) + iVar1);
        for (uVar2 = param_2 >> 2; uVar2 != 0; uVar2 = uVar2 - 1) {
          *puVar3 = *param_3;
          param_3 = param_3 + 1;
          puVar3 = puVar3 + 1;
        }
        for (uVar2 = param_2 & 3; uVar2 != 0; uVar2 = uVar2 - 1) {
          *(undefined *)puVar3 = *(undefined *)param_3;
          param_3 = (undefined4 *)((int)param_3 + 1);
          puVar3 = (undefined4 *)((int)puVar3 + 1);
        }
        *(uint *)(*param_1 + -8) = *(int *)(*param_1 + -8) + param_2;
        *(undefined *)(*(int *)(*param_1 + -8) + *param_1) = 0;
        return;
      }
    }
    FUN_0043c5d0(*(undefined4 *)(iVar1 + -8),iVar1,param_2,param_3);
    FUN_0043c2f0(iVar1 + -0xc);
  }
  return;
}



undefined4 __thiscall FUN_0043c6b0(undefined4 param_1,int param_2)

{
  undefined4 uVar1;
  
  if (param_2 == 0) {
    FUN_0043c630(0,0);
    return param_1;
  }
  uVar1 = lstrlenA(param_2);
  FUN_0043c630(uVar1,param_2);
  return param_1;
}



undefined4 __fastcall FUN_0043c6f0(undefined4 param_1)

{
  FUN_0043c630(1,&stack0x00000004);
  return param_1;
}



undefined4 __thiscall FUN_0043c710(undefined4 param_1,int *param_2)

{
  FUN_0043c630(*(undefined4 *)(*param_2 + -8),*param_2);
  return param_1;
}



int __thiscall FUN_0043c730(int *param_1,int param_2)

{
  int iVar1;
  uint uVar2;
  undefined4 unaff_EBX;
  undefined4 *puVar3;
  undefined4 *puVar4;
  
  puVar3 = (undefined4 *)*param_1;
  if (((int)puVar3[-3] < 2) && (param_2 <= (int)puVar3[-1])) {
    return *param_1;
  }
  iVar1 = puVar3[-2];
  if (param_2 < iVar1) {
    param_2 = iVar1;
  }
  FUN_0043c260(param_2);
  puVar4 = (undefined4 *)*param_1;
  for (uVar2 = iVar1 + 1U >> 2; uVar2 != 0; uVar2 = uVar2 - 1) {
    *puVar4 = *puVar3;
    puVar4 = puVar4 + 1;
    puVar3 = puVar3 + 1;
  }
  for (uVar2 = iVar1 + 1U & 3; uVar2 != 0; uVar2 = uVar2 - 1) {
    *(undefined *)puVar4 = *(undefined *)puVar3;
    puVar3 = (undefined4 *)((int)puVar3 + 1);
    puVar4 = (undefined4 *)((int)puVar4 + 1);
  }
  *(int *)(*param_1 + -8) = iVar1;
  FUN_0043c2f0(unaff_EBX);
  return *param_1;
}



void __thiscall FUN_0043c7a0(int *param_1,int param_2)

{
  FUN_0043c340();
  if (param_2 == -1) {
    param_2 = lstrlenA(*param_1);
  }
  *(int *)(*param_1 + -8) = param_2;
  *(undefined *)(*param_1 + param_2) = 0;
  return;
}



int __thiscall FUN_0043c7d0(int *param_1,undefined param_2)

{
  int iVar1;
  
  iVar1 = FUN_0044df4b(*param_1,param_2);
  if (iVar1 == 0) {
    return -1;
  }
  return iVar1 - *param_1;
}



void __fastcall FUN_0043c800(char **param_1)

{
  char cVar1;
  int iVar2;
  char *pcVar3;
  
  FUN_0043c340();
  iVar2 = FUN_0040ecc0();
  if (iVar2 == 0) {
    CharUpperA(*param_1);
  }
  else {
    pcVar3 = *param_1;
    cVar1 = *pcVar3;
    if (cVar1 != '\0') {
      do {
        iVar2 = FUN_0044c34b((int)cVar1);
        if (iVar2 != 0) {
          cVar1 = FUN_0044bf1a((int)*pcVar3);
          *pcVar3 = cVar1;
        }
        pcVar3 = (char *)CharNextA(pcVar3);
        cVar1 = *pcVar3;
      } while (cVar1 != '\0');
      return;
    }
  }
  return;
}



void __thiscall FUN_0043c860(int *param_1,int param_2,undefined param_3)

{
  FUN_0043c340();
  *(undefined *)(*param_1 + param_2) = param_3;
  return;
}



int * __thiscall FUN_0043c880(int *param_1,undefined4 param_2,int param_3)

{
  int *piVar1;
  int iVar2;
  undefined unaff_retaddr;
  
  piVar1 = (int *)FUN_0043c200();
  *param_1 = *piVar1;
  if (0 < param_3) {
    FUN_0043c260(param_3);
    iVar2 = 0;
    if (0 < param_3) {
      do {
        iVar2 = iVar2 + 1;
        *(undefined *)(*param_1 + -1 + iVar2) = unaff_retaddr;
      } while (iVar2 < param_3);
    }
  }
  return param_1;
}



undefined4 __thiscall FUN_0043c8c0(int *param_1,undefined4 param_2,int param_3)

{
  FUN_0043c8e0(param_2,param_3,*(int *)(*param_1 + -8) - param_3);
  return param_2;
}



undefined4 __thiscall FUN_0043c8e0(int *param_1,undefined4 param_2,int param_3,int param_4)

{
  int iVar1;
  int iVar2;
  undefined4 unaff_EDI;
  int iVar3;
  
  iVar3 = param_3;
  if (param_3 < 0) {
    iVar3 = 0;
  }
  iVar2 = param_4;
  if (param_4 < 0) {
    iVar2 = 0;
  }
  iVar1 = *(int *)(*param_1 + -8);
  if (iVar1 < iVar3 + iVar2) {
    iVar2 = iVar1 - iVar3;
  }
  if (iVar1 < iVar3) {
    iVar2 = 0;
  }
  FUN_0043c210();
  FUN_0043c3e0(&param_3,iVar2,iVar3,0);
  FUN_0043c220(&stack0xfffffff8);
  FUN_0043c3b0();
  return unaff_EDI;
}



undefined4 __thiscall FUN_0043c950(int *param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  
  if (param_3 < 0) {
    iVar1 = 0;
  }
  else {
    iVar1 = param_3;
    if (*(int *)(*param_1 + -8) < param_3) {
      iVar1 = *(int *)(*param_1 + -8);
    }
  }
  FUN_0043c210();
  FUN_0043c3e0(&param_3,iVar1,*(int *)(*param_1 + -8) - iVar1);
  FUN_0043c220(&stack0xfffffff8);
  FUN_0043c3b0();
  return 0;
}



undefined4 __thiscall FUN_0043c9b0(int *param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  
  if (param_3 < 0) {
    iVar1 = 0;
  }
  else {
    iVar1 = param_3;
    if (*(int *)(*param_1 + -8) < param_3) {
      iVar1 = *(int *)(*param_1 + -8);
    }
  }
  FUN_0043c210();
  FUN_0043c3e0(&param_3,iVar1,0);
  FUN_0043c220(&stack0xfffffff8);
  FUN_0043c3b0();
  return 0;
}



int __thiscall FUN_0043ca10(int *param_1,undefined param_2)

{
  int iVar1;
  
  iVar1 = FUN_0044e077(*param_1,param_2);
  if (iVar1 == 0) {
    return -1;
  }
  return iVar1 - *param_1;
}



void __thiscall FUN_0043ca40(undefined4 *param_1,char *param_2,int *param_3)

{
  char cVar1;
  int iVar2;
  uint uVar3;
  int *piVar4;
  int *piVar5;
  int iVar6;
  bool bVar7;
  undefined4 unaff_retaddr;
  int iStack_10;
  int iStack_c;
  
  iStack_c = 0;
  cVar1 = *param_2;
  piVar5 = param_3;
  do {
    if (cVar1 == '\0') {
      FUN_0043c730(iStack_c);
      FUN_0044e0e9(*param_1,unaff_retaddr,param_1);
      FUN_0043c7a0(0xffffffff);
      return;
    }
    if (*param_2 == '%') {
      param_2 = (char *)FUN_0044e1df(param_2);
      cVar1 = *param_2;
      if (cVar1 == '%') goto LAB_0043cd04;
      iVar6 = 0;
      param_3 = (int *)0x0;
      if (cVar1 == '\0') {
LAB_0043cad7:
        param_3 = (int *)FUN_0044bab9(param_2);
        cVar1 = *param_2;
        while ((piVar4 = piVar5, cVar1 != '\0' && (iVar2 = FUN_0044e150((int)cVar1), iVar2 != 0))) {
          param_2 = (char *)FUN_0044e1df(param_2);
          cVar1 = *param_2;
        }
      }
      else {
        do {
          if (cVar1 == '#') {
            iStack_c = iStack_c + 2;
          }
          else if (cVar1 == '*') {
            param_3 = (int *)*piVar5;
            piVar5 = piVar5 + 1;
          }
          else if ((((cVar1 != '-') && (cVar1 != '+')) && (cVar1 != '0')) && (cVar1 != ' ')) break;
          param_2 = (char *)FUN_0044e1df(param_2);
          cVar1 = *param_2;
        } while (cVar1 != '\0');
        piVar4 = piVar5;
        if (param_3 == (int *)0x0) goto LAB_0043cad7;
      }
      iStack_10 = 0;
      if (*param_2 == '.') {
        param_2 = (char *)FUN_0044e1df(param_2);
        if (*param_2 == '*') {
          iStack_10 = *piVar4;
          piVar4 = piVar4 + 1;
          param_2 = (char *)FUN_0044e1df(param_2);
        }
        else {
          iStack_10 = FUN_0044bab9(param_2);
          cVar1 = *param_2;
          while ((cVar1 != '\0' && (iVar2 = FUN_0044e150((int)cVar1), iVar2 != 0))) {
            param_2 = (char *)FUN_0044e1df(param_2);
            cVar1 = *param_2;
          }
        }
      }
      uVar3 = 0;
      switch(*param_2) {
      case 'F':
      case 'L':
      case 'N':
        break;
      default:
        goto switchD_0043cb89_caseD_47;
      case 'h':
        uVar3 = 0x10000;
        break;
      case 'l':
        uVar3 = 0x20000;
      }
      param_2 = (char *)FUN_0044e1df(param_2);
switchD_0043cb89_caseD_47:
      uVar3 = (int)*param_2 | uVar3;
      piVar5 = piVar4;
      if ((int)uVar3 < 0x10064) {
        if (uVar3 != 0x10063) {
          if ((int)uVar3 < 0x74) {
            if (uVar3 == 0x73) {
              iVar6 = lstrlenA(*piVar4);
              goto LAB_0043cc80;
            }
            if (uVar3 != 0x43) {
              if (uVar3 != 0x53) {
                bVar7 = uVar3 == 99;
                goto LAB_0043cbd9;
              }
              goto LAB_0043cc71;
            }
          }
          else if (uVar3 != 0x10043) {
            if (uVar3 == 0x10053) goto LAB_0043cc52;
            goto LAB_0043cbdf;
          }
        }
LAB_0043cc8e:
        iVar6 = 2;
LAB_0043cca0:
        piVar5 = piVar4 + 1;
        if (iVar6 <= (int)param_3) {
          iVar6 = (int)param_3;
        }
        if ((iStack_10 != 0) && (iStack_10 <= iVar6)) {
          iVar6 = iStack_10;
        }
      }
      else {
        if ((int)uVar3 < 0x20054) {
          if (uVar3 != 0x20053) {
            if (uVar3 == 0x10073) {
LAB_0043cc52:
              iVar6 = lstrlenA(*piVar4);
              goto LAB_0043cc80;
            }
            bVar7 = uVar3 == 0x20043;
LAB_0043cbd9:
            if (!bVar7) goto LAB_0043cbdf;
            goto LAB_0043cc8e;
          }
LAB_0043cc71:
          iVar6 = FUN_0044df2e(*piVar4);
LAB_0043cc80:
          if (iVar6 < 1) {
            iVar6 = 1;
          }
          else {
            piVar5 = piVar4 + 1;
            if (iVar6 == 0) goto LAB_0043cbdf;
          }
          goto LAB_0043cca0;
        }
        if (uVar3 == 0x20063) goto LAB_0043cc8e;
        if (uVar3 == 0x20073) goto LAB_0043cc71;
LAB_0043cbdf:
        switch(*param_2) {
        case 'G':
        case 'e':
        case 'f':
        case 'g':
          piVar5 = piVar5 + 2;
          iVar6 = 0x80;
          if (0x7f < iStack_10 + (int)param_3) {
            iVar6 = iStack_10 + (int)param_3;
          }
          break;
        case 'X':
        case 'd':
        case 'i':
        case 'o':
        case 'u':
        case 'x':
          piVar5 = piVar5 + 1;
          iVar6 = 0x20;
          if (0x1f < iStack_10 + (int)param_3) {
            iVar6 = iStack_10 + (int)param_3;
          }
          break;
        case 'n':
          piVar5 = piVar5 + 1;
          break;
        case 'p':
          piVar5 = piVar5 + 1;
          iVar6 = 0x20;
          if (0x1f < (int)param_3 + iStack_10) {
            iVar6 = (int)param_3 + iStack_10;
          }
        }
      }
      iStack_c = iStack_c + iVar6;
    }
    else {
LAB_0043cd04:
      iVar6 = FUN_0044e13a(param_2);
      iStack_c = iStack_c + iVar6;
    }
    param_2 = (char *)FUN_0044e1df(param_2);
    cVar1 = *param_2;
  } while( true );
}



void FUN_0043cde0(undefined4 param_1,undefined4 param_2)

{
  FUN_0043ca40(param_2,&stack0x0000000c);
  return;
}



bool FUN_0043ceb0(undefined4 param_1)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  undefined auStack_100 [256];
  
  iVar1 = FUN_0043cf50(param_1,auStack_100,0x100);
  if (2 < 0x100U - iVar1) {
    FUN_0043c590(auStack_100);
    return 0 < iVar1;
  }
  iVar1 = 0x100;
  do {
    iVar4 = iVar1 + 0x100;
    uVar2 = FUN_0043c730(iVar1 + 0xff,iVar4);
    iVar3 = FUN_0043cf50(param_1,uVar2);
    iVar1 = iVar4;
  } while (iVar4 - iVar3 < 3);
  FUN_0043c7a0(0xffffffff);
  return 0 < iVar3;
}



void FUN_0043cf50(undefined4 param_1,undefined *param_2,undefined4 param_3)

{
  undefined4 uVar1;
  int iVar2;
  undefined4 uVar3;
  undefined *puVar4;
  
  uVar3 = 0;
  puVar4 = param_2;
  uVar1 = GetModuleHandleA(0,param_1,param_2,param_3);
  iVar2 = LoadStringA(uVar1,uVar3,param_1,puVar4);
  if (iVar2 == 0) {
    *param_2 = 0;
  }
  return;
}



undefined4 __thiscall FUN_0043cf80(undefined4 param_1,code *param_2)

{
  (*param_2)(param_1);
  return param_1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 * __fastcall FUN_0043cfb0(undefined4 *param_1)

{
  undefined4 uVar1;
  int iVar2;
  
  param_1[5] = 0;
  param_1[6] = 0;
  param_1[7] = 0;
  param_1[8] = 0;
  param_1[9] = 0;
  param_1[10] = 0;
  param_1[0xb] = 0;
  param_1[0xc] = 0;
  param_1[1] = 0;
  _DAT_00469f74 = _DAT_00469f74 + 1;
  param_1[2] = _DAT_00469f74;
  param_1[3] = 0;
  param_1[4] = 0;
  SetRectEmpty(param_1 + 5);
  SetRectEmpty(param_1 + 9);
  param_1[0xd] = 0;
  param_1[0xe] = 0;
  param_1[0xf] = 0;
  param_1[0x10] = 0;
  *param_1 = 0;
  *(undefined *)(param_1 + 0x11) = 0;
  param_1[0x26] = 0;
  param_1[0x27] = 0;
  param_1[0x28] = 0;
  param_1[0x29] = 0;
  FUN_0043b020();
  param_1[0x22] = 0;
  _DAT_00469f74 = _DAT_00469f74 + 1;
  param_1[0x23] = _DAT_00469f74;
  param_1[0x24] = 0;
  param_1[0x25] = 0;
  SetRectEmpty(param_1 + 0x26);
  SetRectEmpty(param_1 + 0x2a);
  param_1[0x2e] = 0;
  param_1[0x2f] = 0;
  param_1[0x30] = 0;
  param_1[0x31] = 0;
  param_1[0x21] = 0;
  *(undefined *)(param_1 + 0x32) = 0;
  param_1[0x38] = *(undefined4 *)(_DAT_00475bbc + 0x88);
  param_1[0x39] = *(undefined4 *)(_DAT_00475bbc + 0x8c);
  uVar1 = *(undefined4 *)(_DAT_00475bbc + 0x90);
  param_1[0x33] = 0;
  param_1[0x3a] = uVar1;
  param_1[0x34] = 0;
  param_1[0x35] = 0;
  param_1[0x36] = 0;
  param_1[0x37] = 0;
  param_1[0x46] = 0;
  param_1[0x47] = 0;
  param_1[0x3b] = 0;
  param_1[0x3c] = 0;
  param_1[0x3d] = 0;
  param_1[0x3e] = 0;
  param_1[0x3f] = 1;
  param_1[0x42] = 0;
  param_1[0x40] = 0;
  param_1[0x41] = 0;
  param_1[0x45] = *(undefined4 *)(_DAT_00475bbc + 0x9c);
  iVar2 = _DAT_00475bbc;
  param_1[0x46] = *(undefined4 *)(_DAT_00475bbc + 0xa0);
  param_1[0x47] = *(undefined4 *)(iVar2 + 0xa4);
  param_1[0x43] = *(undefined4 *)(_DAT_00475bbc + 0x94);
  uVar1 = *(undefined4 *)(_DAT_00475bbc + 0x98);
  param_1[0x21] = 1;
  param_1[0x44] = uVar1;
  param_1[0xd] = 1;
  param_1[0x1e] = 1;
  param_1[1] = 400;
  param_1[0x12] = 0;
  param_1[0x13] = 0;
  param_1[0x14] = 0;
  param_1[0x15] = 0;
  param_1[0x16] = 0;
  *(undefined2 *)(param_1 + 0x19) = 0;
  param_1[0x1a] = 0;
  param_1[0x1b] = 0xffffffff;
  param_1[0x1c] = 0;
  param_1[0x1d] = 0;
  param_1[0x48] = 0;
  param_1[0x49] = 0;
  param_1[0x4a] = 0;
  param_1[0x4b] = 0;
  param_1[0x4c] = 0;
  param_1[0x17] = 0;
  param_1[0x18] = 0;
  param_1[0x1f] = 0;
  param_1[0x20] = 0;
  param_1[0x42] = 0x25;
  *param_1 = 8;
  return param_1;
}



void __fastcall FUN_0043d1e0(int param_1)

{
  if (*(int *)(param_1 + 0x54) != 0) {
    FUN_0044c4b9(*(int *)(param_1 + 0x54));
    *(undefined4 *)(param_1 + 0x54) = 0;
  }
  if (*(int *)(param_1 + 0x58) != 0) {
    FUN_0044c4b9(*(int *)(param_1 + 0x58));
    *(undefined4 *)(param_1 + 0x58) = 0;
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 * __thiscall FUN_0043d220(undefined4 *param_1,int param_2)

{
  undefined4 uVar1;
  undefined4 uVar2;
  int iVar3;
  undefined4 *puVar4;
  undefined4 *puVar5;
  
  FUN_0043f3a0(param_2);
  puVar4 = (undefined4 *)(param_2 + 0x84);
  puVar5 = param_1 + 0xb3;
  for (iVar3 = 0x27; iVar3 != 0; iVar3 = iVar3 + -1) {
    *puVar5 = *puVar4;
    puVar4 = puVar4 + 1;
    puVar5 = puVar5 + 1;
  }
  *param_1 = &UNK_0045e77c;
  param_1[0x20] = 0;
  param_1[0x1d] = 0;
  *(undefined2 *)(param_1 + 0xb1) = 0;
  param_1[0xda] = 0;
  param_1[0xdb] = 0;
  param_1[0xae] = 0;
  param_1[0xaf] = 0;
  param_1[0xdc] = 0;
  param_1[0xdd] = 0;
  param_1[0xe0] = 1;
  param_1[0x23] = 0;
  param_1[0x22] = 0;
  param_1[0xb0] = 0;
  param_1[0xe1] = 6;
  *(undefined *)(param_1 + 0x2a) = 0;
  *(undefined *)(param_1 + 0x6b) = 0;
  if (*(int *)(param_2 + 0x104) != 0) {
    *(undefined4 *)(param_2 + 0x104) = 0;
  }
  param_1[0x15] = *(undefined4 *)(param_2 + 0x10);
  param_1[0xb2] = *(undefined4 *)(param_2 + 0x50);
  *(undefined2 *)(param_1 + 0xb1) = *(undefined2 *)(param_2 + 100);
  param_1[0xdc] = *(undefined4 *)(param_2 + 0x124);
  param_1[0xdd] = *(undefined4 *)(param_2 + 0x128);
  uVar1 = *(undefined4 *)(param_2 + 0x4c);
  uVar2 = *(undefined4 *)(param_2 + 0x48);
  param_1[0xd] = uVar2;
  param_1[0xe] = uVar1;
  param_1[0xf] = uVar2;
  param_1[0x10] = uVar1;
  param_1[0xb0] = *(undefined4 *)(param_2 + 0x7c);
  iVar3 = *(int *)(param_2 + 0x68);
  param_1[0x24] = iVar3;
  param_1[0x21] = *(undefined4 *)(param_2 + 0x80);
  if (iVar3 == 0) {
    param_1[0x24] = _DAT_00475bd8;
  }
  if (param_1[0xdd] != 0) {
    FUN_0043f4e0();
  }
  iVar3 = *(int *)(param_2 + 0x120);
  param_1[0xdb] = iVar3;
  if (iVar3 != 0) {
    FUN_0043f4e0();
  }
  iVar3 = *(int *)(param_2 + 300);
  param_1[0xde] = iVar3;
  if (iVar3 != 0) {
    FUN_0043f4e0();
  }
  param_1[0xdf] = *(undefined4 *)(param_2 + 0x130);
  param_1[0x1f] = *(undefined4 *)(param_2 + 0x70);
  param_1[0x29] = *(undefined4 *)(param_2 + 0x6c);
  param_1[0x1e] = *(undefined4 *)(param_2 + 0x78);
  param_1[0xd1] = *(undefined4 *)(param_2 + 0x78);
  lstrcpyA(param_1 + 0xe2,0x469f24);
  if (*(int *)(param_2 + 0x54) != 0) {
    iVar3 = lstrlenA(*(int *)(param_2 + 0x54));
    if (iVar3 != 0) {
      lstrcpyA(param_1 + 0x2a,*(undefined4 *)(param_2 + 0x54));
    }
  }
  if (*(int *)(param_2 + 0x58) != 0) {
    iVar3 = lstrlenA(*(int *)(param_2 + 0x58));
    if (iVar3 != 0) {
      lstrcpyA(param_1 + 0x6b,*(undefined4 *)(param_2 + 0x58));
    }
  }
  param_1[0xac] = *(undefined4 *)(param_2 + 0x5c);
  uVar1 = *(undefined4 *)(param_2 + 0x60);
  param_1[0x1f] = param_1[0x1f] | 0x4001000b;
  param_1[0xad] = uVar1;
  return param_1;
}



void __fastcall FUN_0043d450(undefined4 *param_1)

{
  int iVar1;
  
  iVar1 = param_1[0x20];
  *param_1 = &UNK_0045e77c;
  if (iVar1 != 0) {
    FUN_00443b30();
    FUN_0044bb7e(iVar1);
    param_1[0x20] = 0;
  }
  if ((param_1[0x15] != 0) && (*(undefined4 **)(param_1[0x15] + 0x90) == param_1)) {
    FUN_00434450(0);
  }
  param_1[0x15] = 0;
  if (param_1[0xdd] != 0) {
    FUN_0043f350(param_1[0xdd]);
  }
  if (param_1[0xdb] != 0) {
    FUN_0043f350(param_1[0xdb]);
  }
  if (param_1[0xde] != 0) {
    FUN_0043f350(param_1[0xde] + 0x9a8);
  }
  param_1[0xda] = 0;
  if (param_1[0x22] != 0) {
    RemovePropA(param_1[0x22],0x469f38);
    DestroyWindow(param_1[0x22]);
    param_1[0x22] = 0;
  }
  FUN_0043f460();
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int __fastcall FUN_0043d510(int *param_1)

{
  int iVar1;
  uint uVar2;
  undefined4 uVar3;
  int iVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  
  iVar1 = FUN_0044ba20(0x9a8);
  if (iVar1 == 0) {
    iVar1 = 0;
  }
  else {
    iVar1 = FUN_00443a90();
  }
  param_1[0x20] = iVar1;
  if (iVar1 == 0) {
    return 0;
  }
  iVar1 = FUN_00443b70(param_1[0xb2]);
  if (iVar1 != 0) {
    FUN_00444720(param_1[0x29]);
    iVar4 = *(int *)(param_1[0x20] + 0x28);
    param_1[0x27] = iVar4;
    uVar2 = *(uint *)(param_1[0x20] + 0x2c) / (uint)param_1[0xe1];
    param_1[0x28] = uVar2;
    FUN_0044ad40(0,0,iVar4,uVar2);
    uVar6 = 0;
    iVar4 = param_1[9];
    uVar5 = _DAT_004721bc;
    uVar3 = FUN_0043f660(iVar4,_DAT_004721bc,0);
    iVar4 = CreateWindowExA(0x20,param_1 + 0xe2,0,param_1[0x1f],param_1[0xd],param_1[0xe],
                            param_1[0x27],param_1[0x28],uVar3,iVar4,uVar5,uVar6);
    param_1[0x22] = iVar4;
    if (iVar4 == 0) {
      uVar5 = GetLastError(1);
      FUN_0041b3e0(uVar5);
      return 0;
    }
    iVar4 = SetPropA(iVar4,0x469f38,param_1);
    if (iVar4 != 0) {
      FUN_0041b570(param_1[0x22],0x100);
      param_1[0x1c] = 0;
      (**(code **)(*param_1 + 0x94))();
      if ((int *)param_1[0xda] == (int *)0x0) {
        if ((int *)param_1[0xdb] == (int *)0x0) {
          iVar4 = param_1[0x22];
          uVar5 = 0x469f40;
        }
        else {
          (**(code **)(*(int *)param_1[0xdb] + 0xa0))(0);
          uVar5 = (**(code **)(*(int *)param_1[0xdb] + 0x90))();
          iVar4 = param_1[0x22];
        }
      }
      else {
        (**(code **)(*(int *)param_1[0xda] + 0xa0))(0);
        uVar5 = (**(code **)(*(int *)param_1[0xda] + 0x90))();
        iVar4 = param_1[0x22];
      }
      SetWindowTextA(iVar4,uVar5);
      if (param_1[0x1e] != 0) {
        (**(code **)(*param_1 + 0x7c))();
        param_1[10] = 1;
        return iVar1;
      }
      (**(code **)(*param_1 + 0x80))();
      param_1[10] = 1;
    }
  }
  return iVar1;
}



void __fastcall FUN_0043dd90(int param_1)

{
  undefined4 uVar1;
  
  uVar1 = SetFocus(*(undefined4 *)(param_1 + 0x88));
  *(undefined4 *)(param_1 + 0x8c) = uVar1;
  return;
}



undefined4 * __thiscall FUN_0043e590(undefined4 *param_1,int param_2)

{
  int iVar1;
  
  FUN_0043d220(param_2);
  *param_1 = &UNK_0045e814;
  param_1[0xea] = 0;
  if (*(int *)(param_2 + 0x74) == 0) {
    *(undefined4 *)(param_2 + 0x74) = *(undefined4 *)(param_2 + 0x50);
  }
  param_1[0xe1] = 10;
  param_1[0x15] = *(undefined4 *)(param_2 + 0x10);
  param_1[0xb2] = *(undefined4 *)(param_2 + 0x50);
  *(undefined2 *)(param_1 + 0xb1) = *(undefined2 *)(param_2 + 100);
  param_1[0xdc] = *(undefined4 *)(param_2 + 0x124);
  param_1[0xdd] = *(undefined4 *)(param_2 + 0x128);
  if (*(int *)(param_2 + 0x54) != 0) {
    iVar1 = lstrlenA(*(int *)(param_2 + 0x54));
    if (iVar1 != 0) {
      lstrcpyA(param_1 + 0x2a,*(undefined4 *)(param_2 + 0x54));
    }
  }
  if (*(int *)(param_2 + 0x58) != 0) {
    iVar1 = lstrlenA(*(int *)(param_2 + 0x58));
    if (iVar1 != 0) {
      lstrcpyA(param_1 + 0x6b,*(undefined4 *)(param_2 + 0x58));
    }
  }
  param_1[0xac] = *(undefined4 *)(param_2 + 0x5c);
  param_1[0xad] = *(undefined4 *)(param_2 + 0x60);
  param_1[0xeb] = *(undefined4 *)(param_2 + 0x134);
  lstrcpyA(param_1 + 0xe2,0x469f60);
  return param_1;
}



void __fastcall FUN_0043e690(undefined4 *param_1)

{
  *param_1 = &UNK_0045e814;
  if (*(undefined4 **)(param_1[0x15] + 0x90) == param_1) {
    FUN_00434450(0);
  }
  param_1[0x15] = 0;
  param_1[0xdb] = 0;
  if (param_1[0x22] != 0) {
    RemovePropA(param_1[0x22],0x469f38);
    DestroyWindow(param_1[0x22]);
    param_1[0x22] = 0;
  }
  FUN_0043d450();
  return;
}



undefined4 __fastcall FUN_0043e700(int *param_1)

{
  FUN_0043d510();
  param_1[0x1c] = 2;
  if (param_1[0xeb] != 0) {
    (**(code **)(*param_1 + 0x98))(1);
  }
  return 1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0043e890(void)

{
  UnregisterClassA(0x469f60,_DAT_004721bc);
  return;
}



undefined4 * __thiscall FUN_0043f1b0(undefined4 *param_1,undefined4 param_2)

{
  uint uVar1;
  
  FUN_0043e590(param_2);
  uVar1 = param_1[0x1f];
  *param_1 = &UNK_0045e8b0;
  if ((uVar1 & 0x20000) != 0) {
    param_1[0x1f] = uVar1 | 0x10000;
    return param_1;
  }
  param_1[0x1f] = uVar1 & 0xfffeffff;
  return param_1;
}



void __fastcall FUN_0043f210(undefined4 *param_1)

{
  *param_1 = &UNK_0045e8b0;
  FUN_0043e690();
  return;
}



int FUN_0043f350(undefined4 *param_1)

{
  undefined4 *puVar1;
  int iVar2;
  
  if (param_1 == (undefined4 *)0x0) {
    return 0;
  }
  puVar1 = param_1 + 1;
  EnterCriticalSection(puVar1);
  iVar2 = param_1[7] + -1;
  param_1[7] = iVar2;
  if (iVar2 == 0) {
    LeaveCriticalSection(puVar1);
    (**(code **)*param_1)(1);
    return 0;
  }
  LeaveCriticalSection(puVar1);
  return iVar2;
}



undefined4 * __thiscall FUN_0043f3a0(undefined4 *param_1,undefined4 *param_2)

{
  InitializeCriticalSection(param_1 + 1);
  param_1[0xd] = 0;
  param_1[0xe] = 0;
  param_1[0xf] = 0;
  param_1[0x10] = 0;
  param_1[0x11] = 0;
  param_1[0x12] = 0;
  param_1[0x13] = 0;
  param_1[0x14] = 0;
  param_1[0x16] = 0;
  param_1[10] = 0;
  param_1[0xb] = 0;
  param_1[0x15] = 0;
  param_1[7] = 0;
  param_1[0x19] = 0;
  *param_1 = &UNK_0045e94c;
  param_1[9] = param_2[2];
  param_1[8] = param_2[1];
  param_1[0x15] = param_2[4];
  param_1[0x16] = param_2[3];
  param_1[0xd] = param_2[5];
  param_1[0xe] = param_2[6];
  param_1[0xf] = param_2[7];
  param_1[0x10] = param_2[8];
  param_1[0xc] = param_2[0xd];
  param_1[0x1a] = param_2[0xe];
  param_1[0x1b] = param_2[0xf];
  param_1[0x11] = param_2[9];
  param_1[0x12] = param_2[10];
  param_1[0x13] = param_2[0xb];
  param_1[0x14] = param_2[0xc];
  param_1[0x18] = *param_2;
  *(undefined *)(param_1 + 0x17) = *(undefined *)(param_2 + 0x11);
  FUN_0043f4e0();
  return param_1;
}



void __fastcall FUN_0043f460(undefined4 *param_1)

{
  *param_1 = &UNK_0045e94c;
  param_1[10] = 0;
  DeleteCriticalSection(param_1 + 1);
  return;
}



void __fastcall FUN_0043f480(int param_1)

{
  *(undefined4 *)(param_1 + 0x28) = 1;
  return;
}



int __fastcall FUN_0043f4e0(int param_1)

{
  int iVar1;
  
  EnterCriticalSection(param_1 + 4);
  iVar1 = *(int *)(param_1 + 0x1c) + 1;
  *(int *)(param_1 + 0x1c) = iVar1;
  LeaveCriticalSection(param_1 + 4);
  return iVar1;
}



undefined4 __fastcall FUN_0043f660(int param_1)

{
  if (*(int *)(param_1 + 0x54) != 0) {
    return *(undefined4 *)(*(int *)(param_1 + 0x54) + 0x74);
  }
  return 0;
}



void __thiscall FUN_0043f670(int *param_1,int param_2)

{
  param_1[0xb] = 1;
  if (param_2 != 0) {
    (**(code **)(*param_1 + 0x68))();
  }
  return;
}



undefined4 * __thiscall FUN_0043f690(undefined4 *param_1,int param_2)

{
  FUN_0044afc0(param_2);
  FUN_0043c210();
  param_1[0x35] = 0;
  param_1[0x36] = 0;
  param_1[0x37] = 0;
  param_1[0x38] = 0;
  param_1[0x39] = 0;
  param_1[0x3a] = 0;
  param_1[0x3b] = 0;
  param_1[0x3c] = 0;
  param_1[0x3d] = 0;
  param_1[0x3e] = 0;
  *param_1 = &UNK_0045e9b8;
  param_1[8] = 800;
  FUN_0043c590(&DAT_0046e83c);
  param_1[0x15] = 0;
  param_1[0x21] = 0;
  param_1[0x31] = 0;
  param_1[0x32] = 0;
  param_1[0x2d] = 0;
  param_1[0x2b] = *(undefined4 *)(param_2 + 0x7c);
  param_1[0x33] = *(undefined4 *)(param_2 + 0x6c);
  param_1[0x3d] = 0;
  param_1[0x3e] = 0;
  param_1[0x15] = *(undefined4 *)(param_2 + 0x10);
  if (*(int *)(param_2 + 0x70) != 0) {
    FUN_0043c590(*(int *)(param_2 + 0x70));
  }
  param_1[0xd] = *(undefined4 *)(param_2 + 0x14);
  param_1[0xe] = *(undefined4 *)(param_2 + 0x18);
  param_1[0xf] = *(undefined4 *)(param_2 + 0x1c);
  param_1[0x10] = *(undefined4 *)(param_2 + 0x20);
  param_1[0x15] = *(undefined4 *)(param_2 + 0x10);
  param_1[0x2a] = *(undefined4 *)(param_2 + 0x78);
  param_1[0x21] = *(undefined4 *)(param_2 + 0x68);
  param_1[0x2e] = *(uint *)(param_2 + 0x84) | 0x10;
  param_1[0x25] = *(undefined4 *)(param_2 + 0x5c);
  param_1[0x26] = *(undefined4 *)(param_2 + 0x60);
  param_1[0x27] = *(undefined4 *)(param_2 + 100);
  param_1[0x2f] = *(undefined4 *)(param_2 + 0x88);
  param_1[0x29] = *(undefined4 *)(param_2 + 0x74);
  param_1[0x3d] = *(undefined4 *)(param_2 + 0x94);
  param_1[0x3e] = *(undefined4 *)(param_2 + 0x98);
  param_1[0x30] = *(undefined4 *)(param_2 + 0x8c);
  param_1[0x34] = *(undefined4 *)(param_2 + 0x90);
  param_1[0x2c] = *(undefined4 *)(param_2 + 0x80);
  return param_1;
}



void __fastcall FUN_0043f830(undefined4 *param_1)

{
  *param_1 = &UNK_0045e9b8;
  param_1[10] = 0;
  FUN_0043c3b0();
  FUN_0044b080();
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __fastcall FUN_0043f860(int *param_1)

{
  int iVar1;
  int iVar2;
  undefined4 *puVar3;
  undefined4 uStack_800;
  undefined4 uStack_7fc;
  undefined4 uStack_7f8;
  undefined4 uStack_7f4;
  undefined4 auStack_7f0 [508];
  
  iVar1 = param_1[0x29];
  if (iVar1 != 0) {
    uStack_800 = _DAT_00469f78;
    uStack_7fc = _DAT_00469f7c;
    uStack_7f8 = _DAT_00469f80;
    uStack_7f4 = _DAT_00469f84;
    puVar3 = auStack_7f0;
    for (iVar2 = 0x1fc; iVar2 != 0; iVar2 = iVar2 + -1) {
      *puVar3 = 0;
      puVar3 = puVar3 + 1;
    }
    FUN_0040e750(_DAT_004721c0,iVar1,&uStack_800,0x800);
    FUN_0043c590(&uStack_800);
  }
  (**(code **)(*param_1 + 0xa0))(0);
  if (param_1[0x2c] != 0) {
    FUN_0043c530(param_1 + 0x28);
    (**(code **)(*param_1 + 0x6c))();
  }
  (**(code **)(*param_1 + 0x48))(param_1[0xd],param_1[0xe]);
  param_1[10] = 1;
  return;
}



undefined4 __thiscall FUN_0043f960(int *param_1,undefined4 param_2)

{
  int iVar1;
  
  iVar1 = lstrcmpA(param_1[0x28],param_2);
  if (iVar1 != 0) {
    FUN_0043c590(param_2);
    (**(code **)(*param_1 + 0xa0))(1);
    if (param_1[0xb] != 0) {
      FUN_00435b00(param_1 + 0xd);
    }
    param_1[0x2d] = 0;
    return 1;
  }
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

bool __thiscall FUN_0043f9d0(int *param_1,int param_2)

{
  int iVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  undefined4 uStack_800;
  undefined4 auStack_7d9 [502];
  
  iVar1 = 0;
  if (param_1[0x2d] != param_2) {
    puVar2 = (undefined4 *)0x469f88;
    puVar3 = &uStack_800;
    for (iVar1 = 9; iVar1 != 0; iVar1 = iVar1 + -1) {
      *puVar3 = *puVar2;
      puVar2 = puVar2 + 1;
      puVar3 = puVar3 + 1;
    }
    *(undefined2 *)puVar3 = *(undefined2 *)puVar2;
    *(undefined *)((int)puVar3 + 2) = *(undefined *)((int)puVar2 + 2);
    puVar2 = auStack_7d9;
    for (iVar1 = 0x1f6; iVar1 != 0; iVar1 = iVar1 + -1) {
      *puVar2 = 0;
      puVar2 = puVar2 + 1;
    }
    *(undefined *)puVar2 = 0;
    iVar1 = FUN_0040e750(_DAT_004721c0,param_2,&uStack_800,0x800);
    FUN_0043c590(&uStack_800);
    (**(code **)(*param_1 + 0xa0))(1);
    if (param_1[0xb] != 0) {
      FUN_00435b00(param_1 + 0xd);
    }
    param_1[0x2d] = param_2;
  }
  return 0 < iVar1;
}



void __thiscall FUN_00440180(int *param_1,int param_2,int param_3)

{
  int *piVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  
  iVar3 = param_1[0xb];
  if (iVar3 != 0) {
    (**(code **)(*param_1 + 0x20))();
  }
  iVar4 = param_1[0xd];
  iVar5 = param_1[0xe];
  piVar1 = param_1 + 0xd;
  *piVar1 = param_2;
  param_1[0xe] = param_3;
  param_1[0x10] = param_3 + (param_1[0x10] - iVar5);
  param_1[0xf] = param_2 + (param_1[0xf] - iVar4);
  param_1[0x35] = *piVar1;
  param_1[0x36] = param_1[0xe];
  param_1[0x37] = param_1[0xf];
  param_1[0x38] = param_1[0x10];
  iVar4 = param_1[0x34];
  param_1[0x38] = param_1[0x38] - iVar4;
  piVar2 = param_1 + 0x39;
  param_1[0x37] = param_1[0x37] - iVar4;
  *piVar2 = *piVar1;
  param_1[0x3a] = param_1[0xe];
  param_1[0x3b] = param_1[0xf];
  param_1[0x3c] = param_1[0x10];
  param_1[0x3a] = param_1[0x3a] + iVar4;
  *piVar2 = *piVar2 + iVar4;
  if (iVar3 != 0) {
    (**(code **)(*param_1 + 0x1c))(1);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 * __thiscall FUN_004405d0(undefined4 *param_1,undefined4 param_2,undefined4 param_3)

{
  FUN_00433eb0(param_2,param_3);
  *param_1 = &UNK_0045ea64;
  param_1[0x13] = 1;
  param_1[0x17] = 0;
  _DAT_00475c28 = param_1;
  param_1[0x18] = 1;
  param_1[0x39] = 0;
  param_1[0x38] = 0;
  param_1[0x36] = 0;
  param_1[0x37] = 0;
  param_1[0x3a] = 0;
  param_1[0x3b] = 0;
  *(undefined *)(param_1 + 0x3e) = 0;
  param_1[0x3f] = 0;
  param_1[0x40] = 0;
  param_1[0x41] = 0;
  param_1[0x42] = 0;
  FUN_0043c590(0x469e88);
  return param_1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __fastcall FUN_00440680(undefined4 *param_1)

{
  *param_1 = &UNK_0045ea64;
  if (param_1[0x41] != 0) {
    SetEvent(param_1[0x42]);
    param_1[0x41] = 0;
  }
  if (param_1[0x1d] != 0) {
    FUN_00441860();
    DestroyWindow(param_1[0x1d]);
    param_1[0x1d] = 0;
  }
  _DAT_00475c28 = 0;
  FUN_00433fa0();
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4
_DialogProc_CDirBrowser__SGHPAUHWND____IIJ_Z
          (undefined4 param_1,uint param_2,uint param_3,undefined4 *param_4)

{
  int iVar1;
  uint uVar2;
  int *piVar3;
  uint uVar4;
  int iVar5;
  undefined4 extraout_ECX;
  int unaff_ESI;
  undefined4 *puVar6;
  undefined4 *puVar7;
  undefined4 uVar8;
  undefined auStack_160 [4];
  int iStack_15c;
  int iStack_158;
  int iStack_154;
  int iStack_150;
  byte abStack_14c [8];
  undefined4 auStack_144 [12];
  undefined auStack_114 [4];
  undefined auStack_110 [8];
  undefined auStack_108 [260];
  undefined4 uStack_4;
  
                    // 0x40770  3  ?DialogProc@CDirBrowser@@SGHPAUHWND__@@IIJ@Z
  if (0x112 < param_2) {
    if (param_2 < 0x8072) {
      if (param_2 == 0x8071) {
        FUN_004411e0(1);
        FUN_004413e0();
        (**(code **)(*_DAT_00475c34 + 0x20))();
        SetFocus(*(undefined4 *)(_DAT_00475c34[0x3c] + 0x70));
        return 0;
      }
      if ((param_2 != 0x133) && (param_2 != 0x138)) {
        if (param_2 != 0x201) {
          return 0;
        }
        iVar1 = GetUpdateRect(param_1,&iStack_154,0);
        if (iVar1 != 0) {
          RedrawWindow(param_1,&iStack_154,0,0x1a2);
        }
        PostMessageA(param_1,0xa1,2,param_4);
        return 0;
      }
      piVar3 = (int *)GetWindowLongA(param_4,0xffffffeb);
      if (piVar3 == (int *)0x0) {
        return 0;
      }
      uVar8 = (**(code **)(*piVar3 + 0x78))(param_1,param_2,param_3,param_4);
      return uVar8;
    }
    if (param_2 != 0x8191) {
      if (param_2 != 0x8192) {
        return 0;
      }
      uVar8 = 2;
LAB_00440f26:
      EndDialog(param_1,uVar8);
      return 0;
    }
    uVar8 = (**(code **)(**(int **)(_DAT_00475c28 + 0xf0) + 0x90))();
    iVar1 = lstrlenA(uVar8);
    if (iVar1 == 0) {
      uVar8 = FUN_0043c730(0);
      FUN_00447840(uVar8);
    }
    uVar8 = (**(code **)(*(int *)_DAT_00475c34[0x3c] + 0x90))();
    lstrcpyA(auStack_108,uVar8);
    iVar1 = FUN_00417940(auStack_108,1);
    if (iVar1 == 10000) {
      uVar2 = *(uint *)(_DAT_00475c34[0x3c] + 0xfc);
      uVar4 = lstrlenA(auStack_110);
      if (uVar4 <= uVar2) {
        iVar1 = FUN_0041bc20(auStack_114);
        if (iVar1 == -1) {
          if (_DAT_00475c28 == 0) {
            uVar8 = 0;
          }
          else {
            uVar8 = *(undefined4 *)(_DAT_00475c28 + 0x74);
          }
          iVar1 = FUN_0040d270(uVar8,0x24,0xfb,auStack_110);
          if (iVar1 != 6) goto LAB_00440ec1;
        }
        lstrcpyA(&DAT_004721e8,auStack_110);
        FUN_0040ff80(auStack_110,1);
        _DAT_00469eb8 = 10000;
        FUN_0043c590(auStack_110);
        uVar8 = 1;
        goto LAB_00440f26;
      }
      if (_DAT_00475c28 == 0) {
        uVar8 = 0;
      }
      else {
        uVar8 = *(undefined4 *)(_DAT_00475c28 + 0x74);
      }
      FUN_0040d270(uVar8,0x30,0x199,*(undefined4 *)(_DAT_00475c34[0x3c] + 0xfc));
    }
LAB_00440ec1:
    SetFocus(*(undefined4 *)(_DAT_00475c34[0x3c] + 0x70));
    FUN_0043bff0();
    return 0;
  }
  if (param_2 != 0x112) {
    if (0x20 < param_2) {
      if (param_2 == 0x4e) {
        uVar2 = param_4[2];
        if (uVar2 < 0xfffffe6f) {
          if (uVar2 == 0xfffffe6e) {
            if (_DAT_00475c34[0x3f] == 0) {
              FUN_0043c210();
              FUN_00441aa0(auStack_160,*param_4,param_4[0xf]);
              if (3 < *(int *)(unaff_ESI + -8)) {
                FUN_0043c860(*(int *)(unaff_ESI + -8) + -1,0);
              }
              uVar8 = FUN_0043c730(0);
              FUN_00447840(uVar8);
              FUN_0043c3b0();
              return 0;
            }
          }
          else if (uVar2 == 0xfffffe6a) {
            iVar1 = param_4[3];
            puVar6 = param_4 + 0xe;
            puVar7 = auStack_144;
            for (iVar5 = 10; iVar5 != 0; iVar5 = iVar5 + -1) {
              *puVar7 = *puVar6;
              puVar6 = puVar6 + 1;
              puVar7 = puVar7 + 1;
            }
            if (iVar1 == 1) {
              (**(code **)(*(int *)_DAT_00475c34[0x3b] + 0x78))(auStack_144[1],0x8001);
              return 0;
            }
          }
          else if (uVar2 == 0xfffffe6b) {
            iVar1 = param_4[3];
            puVar6 = param_4 + 0xe;
            puVar7 = auStack_144;
            for (iVar5 = 10; iVar5 != 0; iVar5 = iVar5 + -1) {
              *puVar7 = *puVar6;
              puVar6 = puVar6 + 1;
              puVar7 = puVar7 + 1;
            }
            if (iVar1 == 2) {
              FUN_0043c210();
              FUN_00441aa0(auStack_160,*param_4,auStack_144[1]);
              (**(code **)(*(int *)_DAT_00475c34[0x3b] + 0x70))(1);
              FUN_0043c220(&stack0xfffffe90,extraout_ECX,auStack_144[1]);
              FUN_00441870();
              (**(code **)(*(int *)_DAT_00475c34[0x3b] + 0x70))(0);
              FUN_0043c3b0();
              return 0;
            }
          }
        }
        else if ((0xfffffffc < uVar2) && (uVar2 != 0xffffffff)) {
          uVar8 = GetMessagePos();
          iStack_15c = (int)(short)uVar8;
          iStack_158 = (int)(short)((uint)uVar8 >> 0x10);
          MapWindowPoints(0,*param_4,&iStack_15c,1);
          iStack_154 = iStack_15c;
          iStack_150 = iStack_158;
          iVar1 = SendMessageA(*param_4,0x1111,0,&iStack_154);
          if ((iVar1 != 0) && ((abStack_14c[0] & 0x46) != 0)) {
            FUN_0043c210();
            FUN_00441aa0(auStack_160,*param_4,iVar1);
            if (3 < *(int *)(unaff_ESI + -8)) {
              FUN_0043c860(*(int *)(unaff_ESI + -8) + -1,0);
            }
            uVar8 = FUN_0043c730(0);
            FUN_00447840(uVar8);
            FUN_0043c3b0();
            return 0;
          }
        }
      }
      else {
        if (param_2 == 0x110) {
          uVar8 = FUN_00441010(param_1);
          return uVar8;
        }
        if (param_2 == 0x111) {
          uVar2 = param_3 >> 0x10;
          if (uVar2 != 0) {
            if (uVar2 == 1) {
              FUN_004413e0();
              return 0;
            }
            if (uVar2 == 3) {
              FUN_004411e0(0);
              return 0;
            }
            return 1;
          }
          if ((param_3 & 0xffff) == 1) {
            if (_DAT_00475c34[0x23] != 0) {
              SendMessageA(*(undefined4 *)(_DAT_00475c34[0x23] + 0x88),0x111,0,0);
              return 0;
            }
          }
          else if ((param_3 & 0xffff) == 2) {
            if (_DAT_00475c34[0x37] != 0) {
              SendMessageA(*(undefined4 *)(_DAT_00475c34[0x37] + 0x88),0x111,0,0);
              return 0;
            }
          }
          else if (param_4 != (undefined4 *)0x0) {
            SendMessageA(param_4,0x111,param_3,param_4);
            return 0;
          }
        }
      }
      return 0;
    }
    if (param_2 == 0x20) {
      uVar8 = FUN_0043c130(0,0);
      return uVar8;
    }
    if (param_2 == 0xf) {
      iVar1 = BeginPaint(param_1,auStack_144);
      if (iVar1 != 0) {
        if ((undefined4 *)_DAT_00475c34[0x22] != (undefined4 *)0x0) {
          (***(code ***)(undefined4 *)_DAT_00475c34[0x22])
                    (iVar1,auStack_144[0],auStack_144[1],auStack_144[0],auStack_144[1],
                     auStack_144[2],auStack_144[3]);
        }
        EndPaint(uStack_4,abStack_14c);
      }
      return 1;
    }
    if (param_2 != 0x11) {
      if (param_2 != 0x14) {
        return 0;
      }
      return 1;
    }
    uVar8 = 0x11;
    goto LAB_00440c43;
  }
  uVar2 = param_3 & 0xfff0;
  if (uVar2 == 0xf060) {
    iVar1 = IsWindowVisible(param_1);
    if (iVar1 != 0) {
      MessageBeep(0x30);
      return 0;
    }
LAB_00440c8b:
    if (_DAT_00475bb4 != 0) {
      return 1;
    }
  }
  else if ((uVar2 == 0xf140) || (uVar2 == 0xf170)) goto LAB_00440c8b;
  uVar8 = 0x112;
LAB_00440c43:
  PostMessageA(_DAT_00475bd8,uVar8,param_3,param_4);
  return 1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_00441010(undefined4 param_1)

{
  int iVar1;
  undefined4 uVar2;
  
  _DAT_00475c24 = param_1;
  iVar1 = FUN_0044ba20(0x10c);
  if (iVar1 == 0) {
    _DAT_00475c28 = (int *)0x0;
  }
  else {
    _DAT_00475c28 = (int *)FUN_004405d0(param_1,0);
  }
  (**(code **)(*_DAT_00475c28 + 0x14))();
  _DAT_00475c34 = _DAT_00475c28;
  SetWindowTextA(param_1,0x472fa4);
  FUN_0041b570(param_1,0x100);
  uVar2 = FUN_0043c730(0);
  FUN_00447840(uVar2);
  if ((DAT_00475be0 & 4) != 0) {
    FUN_0043bc50(4);
  }
  (**(code **)(*_DAT_00475c28 + 0x24))();
  (**(code **)(*_DAT_00475c34 + 0x58))();
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00441110(undefined4 param_1)

{
  _DAT_00475c1c = param_1;
  _DAT_00475c2c = 1;
  return;
}



undefined4 __thiscall FUN_00441130(int param_1,int *param_2)

{
  *(int **)(param_1 + 0xd8) = param_2;
  (**(code **)(*param_2 + 0x2c))(1);
  return *(undefined4 *)(param_1 + 0xd8);
}



undefined4 __thiscall FUN_00441150(int param_1,int *param_2)

{
  *(int **)(param_1 + 0xdc) = param_2;
  (**(code **)(*param_2 + 0x2c))(1);
  return *(undefined4 *)(param_1 + 0xdc);
}



void __thiscall FUN_00441170(int param_1,undefined4 param_2)

{
  *(undefined4 *)(param_1 + 0xe4) = param_2;
  return;
}



undefined4 __thiscall FUN_00441180(int param_1,int *param_2)

{
  *(int **)(param_1 + 0xe8) = param_2;
  (**(code **)(*param_2 + 0x2c))(1);
  return *(undefined4 *)(param_1 + 0xe8);
}



undefined4 __thiscall FUN_004411a0(int param_1,int *param_2)

{
  *(int **)(param_1 + 0xec) = param_2;
  (**(code **)(*param_2 + 0x2c))(1);
  return *(undefined4 *)(param_1 + 0xec);
}



undefined4 __thiscall FUN_004411c0(int param_1,int *param_2)

{
  *(int **)(param_1 + 0xf0) = param_2;
  (**(code **)(*param_2 + 0x2c))(1);
  return *(undefined4 *)(param_1 + 0xf0);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __thiscall FUN_004411e0(int param_1,char param_2)

{
  int iVar1;
  undefined4 uVar2;
  char *unaff_EBX;
  int iVar3;
  undefined4 *puStack_68;
  undefined *puStack_64;
  undefined *puStack_60;
  undefined4 uStack_5c;
  undefined4 uStack_58;
  undefined4 uStack_54;
  undefined4 uStack_40;
  undefined auStack_3c [16];
  undefined auStack_2c [36];
  char cStack_8;
  char cStack_4;
  
  if (*(int *)(param_1 + 0x100) == 0) {
    if (param_2 == '\0') {
      *(undefined4 *)(param_1 + 0x100) = 1;
    }
    uStack_40 = _DAT_00469fd4;
    uStack_54 = 0x44121d;
    FUN_0043bf80();
    uStack_54 = 1;
    uStack_58 = 0x44122d;
    (**(code **)(**(int **)(param_1 + 0xe8) + 0x80))();
    uStack_58 = 0x441238;
    (**(code **)(**(int **)(param_1 + 0xe8) + 0x7c))();
    uStack_58 = 0x475c18;
    uStack_5c = 0x441246;
    FUN_0043c220();
    uStack_5c = 0x44124f;
    FUN_0043c800();
    iVar3 = 0;
    if (cStack_4 != '\0') {
      iVar3 = *unaff_EBX + -0x41;
    }
    uStack_5c = 0x8001;
    puStack_60 = (undefined *)0x441270;
    SetErrorMode();
    for (; iVar3 < 0x1a; iVar3 = iVar3 + 1) {
      puStack_60 = &stack0xffffffb4;
      puStack_64 = (undefined *)0x441292;
      iVar1 = FUN_0041bca0();
      if ((iVar1 == 3) || (iVar1 == 2)) {
        puStack_60 = (undefined *)0x0;
        puStack_68 = &uStack_40;
        puStack_64 = (undefined *)0x0;
        iVar1 = FUN_0041bb80(&stack0xffffffb4,auStack_3c,0x10,0,&uStack_40);
        if (iVar1 == 0) {
          puStack_60 = &stack0xffffffb4;
          puStack_64 = auStack_2c;
          puStack_68 = (undefined4 *)0x4412f2;
          lstrcpyA();
        }
        else {
          puStack_60 = auStack_3c;
          puStack_64 = &stack0xffffffb4;
          puStack_68 = (undefined4 *)0x469fcc;
          wsprintfA(auStack_2c);
        }
        puStack_60 = auStack_2c;
        puStack_64 = (undefined *)0x441302;
        FUN_00448810();
      }
      if (cStack_8 != '\0') break;
    }
    puStack_60 = (undefined *)0x0;
    puStack_64 = (undefined *)0x441318;
    SetErrorMode();
    puStack_64 = (undefined *)0x475c18;
    puStack_68 = (undefined4 *)0x441326;
    FUN_0043c220();
    FUN_0043c9b0(&puStack_68,3);
    uVar2 = FUN_00448870();
    FUN_004488a0(uVar2);
    (**(code **)(**(int **)(param_1 + 0xe8) + 0x80))(0);
    FUN_0043bff0();
    FUN_0043c3b0();
    FUN_0043c3b0();
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_00441390(uint *param_1)

{
  int iVar1;
  
  if (((*param_1 & 4) == 0) && (((*param_1 & 2) == 0 || (_DAT_00469fc8 == 0)))) {
    iVar1 = lstrcmpA(0x463fa0,param_1 + 0xb);
    if (iVar1 != 0) {
      iVar1 = lstrcmpA(0x464060,param_1 + 0xb);
      if (iVar1 != 0) {
        return 1;
      }
    }
  }
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __fastcall FUN_004413e0(int param_1)

{
  byte bVar1;
  int iVar2;
  undefined4 uVar3;
  byte *pbVar4;
  int iVar5;
  undefined4 extraout_ECX;
  undefined4 extraout_ECX_00;
  undefined4 extraout_ECX_01;
  undefined4 unaff_EBX;
  undefined4 uVar6;
  byte *pbVar7;
  bool bVar8;
  undefined uVar9;
  byte ***pppbVar10;
  int iStack_26c;
  byte **ppbStack_268;
  byte *apbStack_254 [69];
  undefined auStack_140 [320];
  
  ppbStack_268 = (byte **)0x4413f5;
  FUN_0043c210();
  ppbStack_268 = (byte **)0x441400;
  iVar2 = FUN_004488c0();
  ppbStack_268 = apbStack_254;
  if ((iVar2 != -1) && (iStack_26c = iVar2, FUN_00448830(), 2 < *(int *)(apbStack_254[0] + -8))) {
    ppbStack_268 = (byte **)0x0;
    iStack_26c = 2;
    FUN_0043c860();
    uVar3 = FUN_0043c730(0);
    lstrcpyA(&stack0xfffffda8,uVar3);
    lstrcatA(&stack0xfffffda8,0x463be4);
    SetErrorMode(0x8001);
    iVar2 = FUN_0041bdc0(&stack0xfffffda4,&stack0xfffffda0,&stack0xfffffda0,&stack0xfffffda0,
                         &stack0xfffffda0);
    while (iVar2 == 0) {
      (**(code **)(*_DAT_00475c28 + 0x28))();
      if (_DAT_00475c28 == (int *)0x0) {
        iVar2 = 0;
      }
      else {
        iVar2 = _DAT_00475c28[0x1d];
      }
      uVar3 = FUN_0043c730(0);
      iVar2 = FUN_0040d270(iVar2,0x15,0x197,uVar3);
      (**(code **)(*_DAT_00475c28 + 0x1c))();
      FUN_00435a80();
      if (iVar2 == 2) {
        FUN_0043c590(param_1 + 0xf8);
        FUN_0043c220(&iStack_26c,extraout_ECX);
        uVar3 = FUN_00448870();
        FUN_004488a0(uVar3);
        break;
      }
      iVar2 = FUN_0041bdc0(&stack0xfffffda0,&stack0xfffffd9c,&stack0xfffffd9c,&stack0xfffffd9c,
                           &stack0xfffffd9c);
    }
    SetErrorMode(0);
    pbVar4 = apbStack_254[0];
    pbVar7 = (byte *)(param_1 + 0xf8);
    do {
      bVar1 = *pbVar4;
      bVar8 = bVar1 < *pbVar7;
      if (bVar1 != *pbVar7) {
LAB_00441579:
        iVar2 = (1 - (uint)bVar8) - (uint)(bVar8 != 0);
        goto LAB_0044157e;
      }
      if (bVar1 == 0) break;
      bVar1 = pbVar4[1];
      bVar8 = bVar1 < pbVar7[1];
      if (bVar1 != pbVar7[1]) goto LAB_00441579;
      pbVar4 = pbVar4 + 2;
      pbVar7 = pbVar7 + 2;
    } while (bVar1 != 0);
    iVar2 = 0;
LAB_0044157e:
    if (iVar2 != 0) {
      ppbStack_268 = (byte **)0x441591;
      FUN_0043bf80();
      ppbStack_268 = (byte **)0x1;
      iStack_26c = 0x44159e;
      (**(code **)(**(int **)(param_1 + 0xec) + 0x70))();
      iStack_26c = 0;
      *(undefined4 *)(param_1 + 0xfc) = 1;
      uVar3 = FUN_0043c730();
      lstrcpyA((byte *)(param_1 + 0xf8),uVar3);
      (**(code **)(**(int **)(param_1 + 0xec) + 0x7c))(0);
      FUN_0040d420();
      uVar6 = 0;
      FUN_0043c210();
      uVar3 = FUN_0043c730(0);
      FUN_0043cde0(&stack0xfffffda8,0x469fd8,uVar3);
      iVar2 = FUN_0041be80(unaff_EBX,apbStack_254);
      if (iVar2 != -1) {
        do {
          if ((((uint)apbStack_254[0] & 0x10) != 0) &&
             (iVar5 = FUN_00441390(apbStack_254), iVar5 != 0)) {
            uVar6 = 1;
            break;
          }
          iVar5 = FUN_0041bec0(iVar2,apbStack_254);
        } while (iVar5 != 0);
      }
      FindClose(iVar2);
      pppbVar10 = &ppbStack_268;
      FUN_0043c220(pppbVar10,extraout_ECX_00,0xffff0000,uVar6);
      uVar9 = SUB41(pppbVar10,0);
      uVar3 = FUN_00448330();
      (**(code **)(**(int **)(param_1 + 0xec) + 0x74))(uVar3);
      FUN_0043c220(0x475c18,extraout_ECX_01,0x5c,0);
      FUN_00448500();
      *(undefined4 *)(param_1 + 0xfc) = 0;
      FUN_00441710();
      (**(code **)(**(int **)(param_1 + 0xec) + 0x70))(0);
      FUN_0043bff0();
      if (*(int *)(param_1 + 0x100) != 0) {
        auStack_140[0] = uVar9;
        lstrcpyA(auStack_140,&DAT_004721e8);
        FUN_00447840(auStack_140);
      }
      FUN_0043c3b0();
    }
  }
  ppbStack_268 = (byte **)0x4416ff;
  FUN_0043c3b0();
  return;
}



void __fastcall FUN_00441710(int param_1)

{
  undefined4 uVar1;
  undefined4 uStack_4;
  
  uStack_4 = 0;
  if (*(int *)(param_1 + 0x108) == 0) {
    uVar1 = CreateEventA(0,1,0,0x469fe0);
    *(undefined4 *)(param_1 + 0x108) = uVar1;
  }
  if (*(int *)(param_1 + 0x104) != 0) {
    SetEvent(*(undefined4 *)(param_1 + 0x108));
    *(undefined4 *)(param_1 + 0x104) = 0;
  }
  uVar1 = FUN_0044d14d(0,0,&UNK_00441790,0,0,&uStack_4);
  *(undefined4 *)(param_1 + 0x104) = uVar1;
  return;
}



void FUN_00441860(void)

{
  FUN_00434e80();
  FUN_0043bc70(4);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00441870(void)

{
  byte bVar1;
  int iVar2;
  code *pcVar3;
  byte **ppbVar4;
  byte *pbVar5;
  int iVar6;
  undefined4 uVar7;
  undefined4 extraout_ECX;
  byte *pbVar8;
  undefined4 uVar9;
  undefined4 unaff_EDI;
  bool bVar10;
  byte *pbStack_2a8;
  byte abStack_294 [12];
  int iStack_288;
  uint uStack_284;
  undefined auStack_26c [4];
  undefined auStack_268 [276];
  byte abStack_154 [324];
  undefined4 uStack_10;
  undefined4 uStack_c;
  
  pbStack_2a8 = (byte *)0x441883;
  FUN_0040d420();
  pbStack_2a8 = (byte *)0x46a010;
  uStack_284 = uStack_284 | 8;
  iVar2 = LoadLibraryA();
  if (iVar2 != 0) {
    pcVar3 = (code *)GetProcAddress(iVar2,0x46a000);
    if (pcVar3 != (code *)0x0) {
      (*pcVar3)(&iStack_288,0x20);
    }
    FreeLibrary(iVar2);
  }
  _DAT_00469fc8 = (iStack_288 << 0x1c) >> 0x1f;
  FUN_0043c210();
  FUN_0043c880(0x5c,1);
  ppbVar4 = (byte **)FUN_0043c950(&stack0xfffffd68,1);
  pbVar8 = *ppbVar4;
  pbVar5 = pbStack_2a8;
  do {
    bVar1 = *pbVar5;
    bVar10 = bVar1 < *pbVar8;
    if (bVar1 != *pbVar8) {
LAB_00441926:
      iVar2 = (1 - (uint)bVar10) - (uint)(bVar10 != 0);
      goto LAB_0044192b;
    }
    if (bVar1 == 0) break;
    bVar1 = pbVar5[1];
    bVar10 = bVar1 < pbVar8[1];
    if (bVar1 != pbVar8[1]) goto LAB_00441926;
    pbVar5 = pbVar5 + 2;
    pbVar8 = pbVar8 + 2;
  } while (bVar1 != 0);
  iVar2 = 0;
LAB_0044192b:
  FUN_0043c3b0();
  FUN_0043c3b0();
  if (iVar2 != 0) {
    FUN_0043c6f0(0x5c);
  }
  FUN_0043cde0(&stack0xfffffd5c,0x469ffc,uStack_10);
  iVar2 = FUN_0041be80(unaff_EDI,abStack_294);
  if (iVar2 != -1) {
    do {
      if (((abStack_294[0] & 0x10) != 0) && (iVar6 = FUN_00441390(abStack_294), iVar6 != 0)) {
        FUN_0043c210();
        FUN_0043cde0(&pbStack_2a8,0x469ff4,uStack_10,auStack_268);
        uVar9 = 0;
        uVar7 = FUN_0041be80(pbStack_2a8,abStack_154);
        do {
          if (((abStack_154[0] & 0x10) != 0) && (iVar6 = FUN_00441390(abStack_154), iVar6 != 0)) {
            uVar9 = 1;
            break;
          }
          iVar6 = FUN_0041bec0(uVar7,abStack_154);
        } while (iVar6 != 0);
        FindClose(uVar7);
        FUN_0043c440(auStack_26c,extraout_ECX,uStack_c,uVar9);
        FUN_00448330();
        FUN_0043c3b0();
      }
      iVar6 = FUN_0041bec0(iVar2,abStack_294);
    } while (iVar6 != 0);
    FindClose(iVar2);
  }
  FUN_0043c3b0();
  FUN_0043c3b0();
  return;
}



void FUN_00441aa0(undefined4 param_1,undefined4 param_2,int param_3)

{
  undefined auStack_8 [8];
  
  FUN_0043c210();
  if (param_3 != 0) {
    do {
      FUN_00448400(param_3,auStack_8);
      FUN_0043c6b0(0x463be4);
      FUN_0043c710(param_1);
      FUN_0043c530(&stack0xffffffe8);
      param_3 = SendMessageA(param_2,0x110a,3,param_3);
    } while (param_3 != 0);
  }
  FUN_0043c3b0();
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 * __thiscall FUN_00441b30(undefined4 *param_1,undefined4 param_2,undefined4 param_3)

{
  FUN_00433eb0(param_2,param_3);
  *param_1 = &UNK_0045eac0;
  param_1[0x13] = 1;
  param_1[0x17] = 0;
  param_1[0x18] = 1;
  _DAT_00475c40 = param_1;
  param_1[0x15] = 0;
  param_1[0x3b] = 0;
  param_1[0x3a] = 0;
  param_1[0x37] = 0;
  param_1[0x36] = 0;
  param_1[0x38] = 2000;
  *(undefined *)(param_1 + 0x39) = 0;
  _DAT_00475c44 = CreateEventA(0,1,1,0);
  FUN_0043c590(0x469e4c);
  return param_1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __fastcall FUN_00441bd0(undefined4 *param_1)

{
  int iVar1;
  
  *param_1 = &UNK_0045eac0;
  CloseHandle(_DAT_00475c44);
  _DAT_00475c44 = 0;
  iVar1 = param_1[0x36];
  while (iVar1 != 0) {
    param_1[0x36] = *(undefined4 *)(iVar1 + 8);
    if (iVar1 != 0) {
      FUN_0043c3b0();
      FUN_0044bb7e(iVar1);
    }
    iVar1 = param_1[0x36];
  }
  if (param_1[0x1d] != 0) {
    FUN_00434e80();
    RemovePropA(param_1[0x1d],0x46a01c);
    DestroyWindow(param_1[0x1d]);
    param_1[0x1d] = 0;
  }
  _DAT_00475c40 = 0;
  FUN_00433fa0();
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 __fastcall FUN_00441d30(int param_1)

{
  byte bVar1;
  byte *pbVar2;
  int iVar3;
  byte *unaff_EBX;
  byte *pbVar4;
  bool bVar5;
  
  FUN_00441e20(0x472fa4);
  *(undefined *)(param_1 + 0xe4) = 0;
  ResetEvent(_DAT_00475c44);
  if (*(byte ***)(param_1 + 0xdc) == (byte **)0x0) {
    iVar3 = FUN_0044ba20(0xc);
    if (iVar3 == 0) {
      iVar3 = 0;
    }
    else {
      FUN_0043c210();
      *(undefined4 *)(iVar3 + 4) = 0;
      *(undefined4 *)(iVar3 + 8) = 0;
    }
    FUN_0043c590(unaff_EBX);
    *(int *)(param_1 + 0xdc) = iVar3;
    *(int *)(param_1 + 0xd8) = iVar3;
  }
  else {
    pbVar2 = **(byte ***)(param_1 + 0xdc);
    pbVar4 = unaff_EBX;
    do {
      bVar1 = *pbVar2;
      bVar5 = bVar1 < *pbVar4;
      if (bVar1 != *pbVar4) {
LAB_00441d8a:
        iVar3 = (1 - (uint)bVar5) - (uint)(bVar5 != 0);
        goto LAB_00441d8f;
      }
      if (bVar1 == 0) break;
      bVar1 = pbVar2[1];
      bVar5 = bVar1 < pbVar4[1];
      if (bVar1 != pbVar4[1]) goto LAB_00441d8a;
      pbVar2 = pbVar2 + 2;
      pbVar4 = pbVar4 + 2;
    } while (bVar1 != 0);
    iVar3 = 0;
LAB_00441d8f:
    if (iVar3 != 0) {
      iVar3 = FUN_0044ba20(0xc);
      if (iVar3 == 0) {
        iVar3 = 0;
      }
      else {
        FUN_0043c210();
        *(undefined4 *)(iVar3 + 4) = 0;
        *(undefined4 *)(iVar3 + 8) = 0;
      }
      FUN_0043c590(unaff_EBX);
      *(int *)(*(int *)(param_1 + 0xdc) + 8) = iVar3;
      *(int *)(param_1 + 0xdc) = iVar3;
      return 1;
    }
  }
  return 1;
}



undefined4 __thiscall FUN_00441e20(int param_1,undefined4 param_2)

{
  undefined4 uVar1;
  
  if (*(int *)(param_1 + 0xec) != 0) {
    uVar1 = FUN_0043f960(param_2);
    return uVar1;
  }
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00441e40(undefined4 param_1)

{
  int iVar1;
  
  _DAT_00475c38 = param_1;
  iVar1 = FUN_0044ba20(0xf0);
  if (iVar1 == 0) {
    _DAT_00475c40 = (int *)0x0;
  }
  else {
    _DAT_00475c40 = (int *)FUN_00441b30(_DAT_00475bd8,0);
    if (_DAT_00475c40 != (int *)0x0) {
      _DAT_00475c3c = (**(code **)(*_DAT_00475c40 + 0x14))();
      return;
    }
  }
  _DAT_00475c3c = 0;
  return;
}



void __thiscall FUN_00441ea0(int param_1,undefined4 param_2)

{
  *(undefined4 *)(param_1 + 0xec) = param_2;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4
_DialogProc_CAppMessage__SGHPAUHWND____IIJ_Z
          (undefined4 param_1,uint param_2,uint param_3,undefined4 param_4)

{
  int iVar1;
  int iVar2;
  undefined auStack_50 [8];
  undefined auStack_48 [8];
  undefined4 uStack_40;
  undefined4 uStack_3c;
  undefined4 uStack_38;
  undefined4 uStack_34;
  undefined4 uStack_4;
  
                    // 0x42010  2  ?DialogProc@CAppMessage@@SGHPAUHWND__@@IIJ@Z
  iVar1 = GetPropA(param_1,0x46a01c);
  if (param_2 < 0x111) {
    if (param_2 == 0x110) {
      FUN_0041b570(param_1,0x100);
      SetWindowTextA(param_1,0x472fa4);
      return 0;
    }
    if (param_2 == 0xf) {
      iVar2 = BeginPaint(param_1,&uStack_40);
      if (iVar2 != 0) {
        if ((iVar1 != 0) && (*(undefined4 **)(iVar1 + 0x88) != (undefined4 *)0x0)) {
          (**(code **)**(undefined4 **)(iVar1 + 0x88))
                    (iVar2,uStack_40,uStack_3c,uStack_40,uStack_3c,uStack_38,uStack_34);
          param_1 = uStack_4;
        }
        EndPaint(param_1,auStack_48);
        return 1;
      }
    }
    else if (param_2 != 0x14) {
      if (param_2 != 0x21) {
        return 0;
      }
      if ((_DAT_00475c5c != 0) && (*(int *)(_DAT_00475c5c + 0x74) != 0)) {
        SetActiveWindow(*(int *)(_DAT_00475c5c + 0x74));
        return 4;
      }
    }
  }
  else {
    if (param_2 != 0x112) {
      if (param_2 == 0x201) {
        iVar1 = GetUpdateRect(param_1,auStack_50,0);
        if (iVar1 != 0) {
          RedrawWindow(param_1,auStack_50,0,0x1a2);
        }
        PostMessageA(param_1,0xa1,2,param_4);
      }
      return 0;
    }
    if ((((param_3 & 0xfff0) != 0xf140) && ((param_3 & 0xfff0) != 0xf170)) || (_DAT_00475bb4 == 0))
    {
      PostMessageA(_DAT_00475bd8,0x112,param_3,param_4);
    }
  }
  return 1;
}



void __thiscall FUN_004421b0(int param_1,undefined4 param_2)

{
  *(undefined4 *)(param_1 + 0xe0) = param_2;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 * __thiscall FUN_004421c0(undefined4 *param_1,undefined4 param_2,undefined4 param_3)

{
  FUN_00433eb0(param_2,param_3);
  *param_1 = &UNK_0045eb1c;
  param_1[0x13] = 1;
  param_1[0x17] = 0;
  param_1[0x18] = 1;
  _DAT_00475c5c = param_1;
  param_1[0x3f] = 0;
  param_1[0x3e] = 0;
  param_1[0x3b] = 0;
  param_1[0x3c] = 0;
  param_1[0x3d] = 0;
  param_1[0x3a] = 0;
  param_1[0x36] = 0;
  param_1[0x37] = 0;
  param_1[0x38] = 0;
  param_1[0x39] = 0;
  FUN_0043c590(0x469e7c);
  return param_1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __fastcall FUN_00442260(undefined4 *param_1)

{
  *param_1 = &UNK_0045eb1c;
  if (param_1[0x1d] != 0) {
    FUN_004423b0();
    DestroyWindow(param_1[0x1d]);
    param_1[0x1d] = 0;
  }
  _DAT_00475c5c = 0;
  FUN_00433fa0();
  return;
}



undefined4 __fastcall FUN_00442300(int param_1)

{
  undefined4 uVar1;
  
  FUN_00442340(0x472fa4);
  if (*(int *)(param_1 + 0xf8) != 0) {
    uVar1 = FUN_0043c730(0);
    FUN_0043f960(uVar1);
    return 1;
  }
  return 0;
}



undefined4 __thiscall FUN_00442340(int param_1,undefined4 param_2)

{
  if (*(int *)(param_1 + 0xfc) != 0) {
    FUN_0043f960(param_2);
    return 1;
  }
  return 0;
}



undefined4 __fastcall FUN_00442370(int param_1)

{
  undefined4 uVar1;
  
  FUN_00442340(0x472fa4);
  if (*(int *)(param_1 + 0xfc) != 0) {
    uVar1 = FUN_0043c730(0);
    FUN_0043f960(uVar1);
    return 1;
  }
  return 0;
}



void FUN_004423b0(void)

{
  FUN_00434e80();
  FUN_0043bc70(2);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4
_DialogProc_CAppAlert__SGHPAUHWND____IIJ_Z(undefined4 param_1,uint param_2,uint param_3,int param_4)

{
  int iVar1;
  undefined4 uVar2;
  uint uVar3;
  undefined4 unaff_retaddr;
  undefined auStack_50 [8];
  undefined auStack_48 [8];
  undefined4 uStack_40;
  undefined4 uStack_3c;
  undefined4 uStack_38;
  undefined4 uStack_34;
  undefined4 uStack_4;
  
                    // 0x42450  1  ?DialogProc@CAppAlert@@SGHPAUHWND__@@IIJ@Z
  if (0x112 < param_2) {
    if (param_2 < 0x8192) {
      if (param_2 == 0x8191) {
        switch(_DAT_00475c68) {
        case 0:
          _DAT_00475c64 = 0;
          EndDialog(param_1,0);
          return 0;
        case 1:
          _DAT_00475c64 = 1;
          EndDialog(param_1,1);
          return 0;
        case 2:
          _DAT_00475c64 = 3;
          EndDialog(param_1,3);
          return 0;
        case 3:
        case 4:
          _DAT_00475c64 = 6;
          EndDialog(param_1,6);
          return 0;
        case 5:
          _DAT_00475c64 = 4;
        }
        EndDialog(param_1,_DAT_00475c64);
        return 0;
      }
      if (param_2 == 0x201) {
        iVar1 = GetUpdateRect(param_1,auStack_50,0);
        if (iVar1 != 0) {
          RedrawWindow(param_1,auStack_50,0,0x1a2);
        }
        PostMessageA(param_1,0x111,0,param_4);
        return 0;
      }
      if ((((param_2 == 0x219) && (_DAT_004734d4 != 0)) && (param_3 == 0x8000)) &&
         ((*(int *)(param_4 + 4) == 2 && ((*(byte *)(param_4 + 0x10) & 1) != 0)))) {
        Sleep(2000);
        PostMessageA(unaff_retaddr,0x8191,0,0);
        return 0;
      }
    }
    else if (param_2 == 0x8192) {
      switch(_DAT_00475c68) {
      case 0:
        _DAT_00475c64 = 0;
        break;
      case 1:
      case 3:
      case 5:
        _DAT_00475c64 = 2;
        break;
      case 2:
        _DAT_00475c64 = 5;
        break;
      case 4:
        _DAT_00475c64 = 7;
      }
      EndDialog(param_1,_DAT_00475c64);
    }
    else if (param_2 == 0x8193) {
      if (_DAT_00475c68 == 0) {
        _DAT_00475c64 = 1;
      }
      else {
        if (_DAT_00475c68 == 2) {
          _DAT_00475c64 = 4;
          EndDialog(param_1,4);
          return 0;
        }
        if (_DAT_00475c68 == 3) {
          _DAT_00475c64 = 7;
          EndDialog(param_1,7);
          return 0;
        }
      }
      EndDialog(param_1,_DAT_00475c64);
      return 0;
    }
    return 0;
  }
  if (param_2 != 0x112) {
    if (0x20 < param_2) {
      if (param_2 == 0x110) {
        uVar2 = FUN_00442b20(param_1);
        return uVar2;
      }
      if (param_2 != 0x111) {
        return 0;
      }
      if (param_3 >> 0x10 != 0) {
        return 1;
      }
      if ((param_3 & 0xffff) == 1) {
        if (*(int *)(_DAT_00475c5c + 0x8c) != 0) {
          SendMessageA(*(undefined4 *)(*(int *)(_DAT_00475c5c + 0x8c) + 0x88),0x111,0,0);
          return 0;
        }
        return 0;
      }
      if ((param_3 & 0xffff) == 2) {
        if (*(int *)(_DAT_00475c5c + 0x94) != 0) {
          SendMessageA(*(undefined4 *)(*(int *)(_DAT_00475c5c + 0x94) + 0x88),0x111,0,0);
          return 0;
        }
        return 0;
      }
      if (param_4 != 0) {
        SendMessageA(param_4,0x111,param_3,param_4);
        return 0;
      }
      return 0;
    }
    if (param_2 == 0x20) {
      uVar2 = FUN_0043c130(1,1);
      return uVar2;
    }
    if (param_2 == 0xf) {
      iVar1 = BeginPaint(param_1,&uStack_40);
      if (iVar1 != 0) {
        _DAT_00475958 = _DAT_00475c5c;
        if (*(undefined4 **)(_DAT_00475c5c + 0x88) != (undefined4 *)0x0) {
          (**(code **)**(undefined4 **)(_DAT_00475c5c + 0x88))
                    (iVar1,uStack_40,uStack_3c,uStack_40,uStack_3c,uStack_38,uStack_34);
        }
        EndPaint(uStack_4,auStack_48);
        _DAT_00475958 = 0;
      }
      return 1;
    }
    if (param_2 == 0x11) {
      PostMessageA(_DAT_00475bd8,0x11,param_3,param_4);
      return 1;
    }
    if (param_2 == 0x14) {
      return 1;
    }
    return 0;
  }
  uVar3 = param_3 & 0xfff0;
  if (uVar3 == 0xf060) {
    iVar1 = IsWindowVisible(param_1);
    if (iVar1 != 0) {
      MessageBeep(0x30);
      return 0;
    }
  }
  else if ((uVar3 != 0xf140) && (uVar3 != 0xf170)) goto LAB_00442654;
  if (_DAT_00475bb4 != 0) {
    return 1;
  }
LAB_00442654:
  PostMessageA(_DAT_00475bd8,0x112,param_3,param_4);
  return 1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_00442b20(undefined4 param_1)

{
  int iVar1;
  uint uVar2;
  undefined4 uVar3;
  
  _DAT_00475c58 = param_1;
  iVar1 = FUN_0044ba20(0x104);
  if (iVar1 == 0) {
    _DAT_00475c5c = (int *)0x0;
  }
  else {
    _DAT_00475c5c = (int *)FUN_004421c0(param_1,0);
  }
  (**(code **)(*_DAT_00475c5c + 0x14))();
  FUN_00442300(0x475c48);
  FUN_00442370(0x475c4c);
  _DAT_00475c5c[0x36] = 0;
  _DAT_00475c5c[0x37] = 0;
  _DAT_00475c5c[0x38] = 0;
  *(undefined4 *)(_DAT_00475c5c[0x3a] + 0xa10) = 1;
  _DAT_00475c68 = _DAT_00475c6c & 0xf;
  switch(_DAT_00475c68) {
  case 0:
    (**(code **)(*(int *)_DAT_00475c5c[0x3c] + 0x6c))(400);
    _DAT_00475c5c[0x37] = 1;
    goto switchD_00442bc8_caseD_6;
  case 1:
    uVar3 = 400;
    iVar1 = *(int *)_DAT_00475c5c[0x3b];
    goto LAB_00442cfa;
  case 2:
    (**(code **)(*(int *)_DAT_00475c5c[0x3b] + 0x6c))(0x194);
    _DAT_00475c5c[0x36] = 1;
    (**(code **)(*(int *)_DAT_00475c5c[0x3c] + 0x6c))(0x195);
    uVar3 = 0x196;
    _DAT_00475c5c[0x37] = 1;
    iVar1 = *(int *)_DAT_00475c5c[0x3d];
    break;
  case 3:
    (**(code **)(*(int *)_DAT_00475c5c[0x3b] + 0x6c))(0x192);
    _DAT_00475c5c[0x36] = 1;
    (**(code **)(*(int *)_DAT_00475c5c[0x3c] + 0x6c))(0x193);
    _DAT_00475c5c[0x37] = 1;
    goto LAB_00442d09;
  case 4:
    (**(code **)(*(int *)_DAT_00475c5c[0x3b] + 0x6c))(0x192);
    uVar3 = 0x193;
    _DAT_00475c5c[0x36] = 1;
    iVar1 = *(int *)_DAT_00475c5c[0x3d];
    break;
  case 5:
    uVar3 = 0x195;
    iVar1 = *(int *)_DAT_00475c5c[0x3b];
LAB_00442cfa:
    (**(code **)(iVar1 + 0x6c))(uVar3);
    _DAT_00475c5c[0x36] = 1;
LAB_00442d09:
    uVar3 = 0x191;
    iVar1 = *(int *)_DAT_00475c5c[0x3d];
    break;
  default:
    goto switchD_00442bc8_caseD_6;
  }
  (**(code **)(iVar1 + 0x6c))(uVar3);
  _DAT_00475c5c[0x38] = 1;
switchD_00442bc8_caseD_6:
  uVar2 = _DAT_00475c6c & 0xf00;
  if (uVar2 == 0) {
    if (_DAT_00475c5c[0x36] == 0) {
      iVar1 = _DAT_00475c5c[0x3c];
    }
    else {
      iVar1 = _DAT_00475c5c[0x3b];
    }
LAB_00442d88:
    FUN_00434450(iVar1);
  }
  else {
    if (uVar2 == 0x100) {
      if (_DAT_00475c5c[0x37] == 0) goto LAB_00442d4b;
      iVar1 = _DAT_00475c5c[0x3c];
      goto LAB_00442d88;
    }
    if (uVar2 == 0x200) {
LAB_00442d4b:
      iVar1 = _DAT_00475c5c[0x3d];
      goto LAB_00442d88;
    }
  }
  uVar2 = _DAT_00475c6c & 0xf0;
  _DAT_00475c5c[0x39] = 1;
  switch(uVar2) {
  case 0:
    _DAT_00475c5c[0x39] = 0;
    goto switchD_00442db6_caseD_50;
  case 0x10:
    uVar3 = 0;
    iVar1 = *(int *)(_DAT_00475c5c[0x3a] + 0xa70);
    break;
  case 0x20:
    uVar3 = 1;
    iVar1 = *(int *)(_DAT_00475c5c[0x3a] + 0xa70);
    break;
  case 0x30:
    uVar3 = 2;
    iVar1 = *(int *)(_DAT_00475c5c[0x3a] + 0xa70);
    break;
  case 0x40:
    uVar3 = 3;
    iVar1 = *(int *)(_DAT_00475c5c[0x3a] + 0xa70);
    break;
  default:
    goto switchD_00442db6_caseD_50;
  case 0x80:
    uVar3 = 4;
    iVar1 = *(int *)(_DAT_00475c5c[0x3a] + 0xa70);
  }
  (**(code **)(iVar1 + 0xc))(uVar3);
switchD_00442db6_caseD_50:
  SetWindowTextA(param_1,0x472fa4);
  FUN_0041b570(param_1,0x100);
  (**(code **)(*_DAT_00475c5c + 0x5c))(1);
  (**(code **)(*_DAT_00475c5c + 0x58))();
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00442f70(undefined4 param_1)

{
  _DAT_00475c54 = param_1;
  _DAT_00475c60 = 1;
  return;
}



undefined4 __thiscall FUN_00442f90(int param_1,int param_2)

{
  *(int *)(param_1 + 0xec) = param_2;
  *(undefined4 *)(param_2 + 0x2c0) = 1;
  return *(undefined4 *)(param_1 + 0xec);
}



undefined4 __thiscall FUN_00442fb0(int param_1,int param_2)

{
  *(int *)(param_1 + 0xf0) = param_2;
  *(undefined4 *)(param_2 + 0x2c0) = 1;
  return *(undefined4 *)(param_1 + 0xf0);
}



undefined4 __thiscall FUN_00442fd0(int param_1,int param_2)

{
  *(int *)(param_1 + 0xf4) = param_2;
  *(undefined4 *)(param_2 + 0x2c0) = 1;
  return *(undefined4 *)(param_1 + 0xf4);
}



void __thiscall FUN_00442ff0(int param_1,undefined4 param_2)

{
  *(undefined4 *)(param_1 + 0xfc) = param_2;
  return;
}



void __thiscall FUN_00443000(int param_1,undefined4 param_2)

{
  *(undefined4 *)(param_1 + 0xf8) = param_2;
  return;
}



void __thiscall FUN_00443010(int param_1,undefined4 param_2)

{
  *(undefined4 *)(param_1 + 0xe8) = param_2;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00443050(void)

{
  FUN_004430b0();
  _DAT_00475c70 = 0;
  return;
}



void __fastcall FUN_004430b0(int *param_1)

{
  if ((int *)param_1[2] != (int *)0x0) {
    (**(code **)(*(int *)param_1[2] + 0x10))(1);
    param_1[2] = 0;
  }
  if ((int *)param_1[3] != (int *)0x0) {
    (**(code **)(*(int *)param_1[3] + 0x10))(1);
  }
  if (*param_1 != 0) {
    FUN_0044bb7e(*param_1);
  }
  param_1[1] = 0;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 __thiscall FUN_004431c0(int *param_1,int param_2,int param_3)

{
  int **ppiVar1;
  
  ppiVar1 = (int **)(param_1 + 3);
  param_1[8] = param_3;
  param_1[7] = param_2;
  if (*ppiVar1 != (int *)0x0) {
    param_1[9] = 0;
    (**(code **)(**ppiVar1 + 0x10))(1);
    *ppiVar1 = (int *)0x0;
  }
  (**(code **)(*param_1 + param_1[7] * 4))(ppiVar1,_DAT_00475bd8,param_1[8]);
  (**(code **)(**ppiVar1 + 0x14))();
  param_1[9] = 1;
  return 1;
}



void __thiscall FUN_00443220(int *param_1,int param_2,undefined4 param_3)

{
  *(undefined4 *)(*param_1 + param_2 * 4) = param_3;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_00443260(void)

{
  if (_DAT_00475c70 == 0) {
    return 0;
  }
  return *(undefined4 *)(_DAT_00475c70 + 8);
}



undefined4 FUN_004433c0(int param_1,int param_2)

{
  int *piVar1;
  int **ppiVar2;
  int **ppiVar3;
  int *piVar4;
  int iVar5;
  int iVar6;
  bool bVar7;
  int *piStack_4;
  
  if ((param_1 == 0) || (param_2 == 0)) {
    return 1;
  }
  piVar4 = *(int **)(*(int *)(*(int *)(param_1 + 0xd4) + 0x18) + 8);
joined_r0x004433eb:
  do {
    do {
      while( true ) {
        if (piVar4 == (int *)0x0) {
          return 1;
        }
        if (*(char *)(piVar4 + 0x17) != '\0') break;
        if (piVar4[0x19] == 0) {
          return 1;
        }
        iVar5 = *(int *)(piVar4[0x19] + 4);
        if (iVar5 == 0) {
          return 1;
        }
        piVar4 = *(int **)(iVar5 + 8);
      }
      ppiVar2 = (int **)(piVar4 + 0x19);
      if ((piVar4[0x19] == 0) || (iVar5 = *(int *)(piVar4[0x19] + 4), iVar5 == 0)) {
        piStack_4 = (int *)0x0;
      }
      else {
        piStack_4 = *(int **)(iVar5 + 8);
      }
      iVar5 = *(int *)(param_1 + 0xd4);
      if ((piVar4 != (int *)0x0) && (piVar1 = *ppiVar2, piVar1 != (int *)0x0)) {
        if (*piVar1 == 0) {
          *(int *)(iVar5 + 0x18) = piVar1[1];
        }
        else {
          *(int *)(*piVar1 + 4) = piVar1[1];
        }
        if ((int *)piVar1[1] == (int *)0x0) {
          *(int *)(iVar5 + 0x1c) = *piVar1;
        }
        else {
          *(int *)piVar1[1] = *piVar1;
        }
        *piVar1 = 0;
        piVar1[1] = 0;
      }
      (**(code **)(*piVar4 + 0x10))(param_2);
      piVar4[0x16] = param_2;
      bVar7 = piVar4 == (int *)0x0;
      piVar4 = piStack_4;
    } while ((bVar7) || (ppiVar2 = (int **)*ppiVar2, ppiVar2 == (int **)0x0));
    ppiVar3 = *(int ***)(*(int *)(param_2 + 0xd4) + 0x18);
    iVar5 = (**(code **)(*ppiVar2[2] + 0x34))();
    for (; ppiVar3 != (int **)0x0; ppiVar3 = (int **)ppiVar3[1]) {
      iVar6 = (**(code **)(*ppiVar3[2] + 0x34))();
      if (iVar5 < iVar6) {
        if (ppiVar2 != (int **)0x0) {
          if (ppiVar3 == (int **)0x0) {
            FUN_00436780(ppiVar2);
            break;
          }
          if (*ppiVar3 == (int *)0x0) {
            FUN_00436760(ppiVar2);
          }
          else {
            *ppiVar2 = *ppiVar3;
            ppiVar2[1] = (int *)ppiVar3;
            (*ppiVar3)[1] = (int)ppiVar2;
            *ppiVar3 = (int *)ppiVar2;
          }
        }
        if (ppiVar3 != (int **)0x0) goto joined_r0x004433eb;
        break;
      }
    }
    FUN_00436780(ppiVar2);
  } while( true );
}



undefined4 * __fastcall FUN_00443a90(undefined4 *param_1)

{
  int iVar1;
  undefined4 *puVar2;
  
  param_1[0x266] = 0;
  param_1[0x267] = 0;
  param_1[0x268] = 0;
  param_1[0x269] = 0;
  *param_1 = &UNK_0045eb7c;
  param_1[1] = 0xffffffff;
  param_1[2] = 0;
  param_1[0x18] = 0;
  param_1[0x19] = 0;
  param_1[0x11c] = 0xfeffffff;
  param_1[0x21e] = 0;
  param_1[0x21f] = 0;
  param_1[0x220] = 0;
  puVar2 = param_1 + 0x1b;
  for (iVar1 = 0x100; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  param_1[0x264] = 0;
  param_1[0x261] = 0;
  param_1[0x262] = 0;
  param_1[0x263] = 0;
  puVar2 = param_1 + 0x221;
  for (iVar1 = 0x40; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = 0x1010101;
    puVar2 = puVar2 + 1;
  }
  param_1[0x11b] = 0;
  param_1[0x265] = 0;
  return param_1;
}



void __fastcall FUN_00443b30(undefined4 *param_1)

{
  *param_1 = &UNK_0045eb7c;
  if (param_1[0x19] != 0) {
    SelectObject(param_1[0x19],param_1[0x1a]);
    DeleteDC(param_1[0x19]);
    param_1[0x19] = 0;
  }
  if (param_1[0x18] != 0) {
    DeleteObject(param_1[0x18]);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

bool __thiscall FUN_00443b70(int param_1,uint param_2)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  bool bVar4;
  
  if (*(uint *)(param_1 + 4) == param_2) {
    return true;
  }
  *(uint *)(param_1 + 4) = param_2;
  if (*(int *)(param_1 + 100) != 0) {
    SelectObject(*(int *)(param_1 + 100),*(undefined4 *)(param_1 + 0x68));
    DeleteDC(*(undefined4 *)(param_1 + 100));
    *(undefined4 *)(param_1 + 100) = 0;
  }
  if (*(int *)(param_1 + 0x60) != 0) {
    DeleteObject(*(int *)(param_1 + 0x60));
  }
  if (param_2 < 0x7fffffff) {
    param_2 = param_2 & 0xffff;
  }
  else {
    param_2 = FUN_00436df0(param_2);
  }
  iVar1 = FUN_00410290(_DAT_004721c0,param_2,0,0,0,0xa000);
  bVar4 = iVar1 != 0;
  *(int *)(param_1 + 0x60) = iVar1;
  if (bVar4) {
    iVar1 = GetObjectA(iVar1,0x54,param_1 + 0xc);
    bVar4 = iVar1 != 0;
    if (iVar1 != 0) {
      if (*(int *)(param_1 + 0x2c) < 0) {
        *(undefined4 *)(param_1 + 0x984) = 1;
        *(int *)(param_1 + 0x2c) = -*(int *)(param_1 + 0x2c);
      }
      iVar1 = GetDC(0);
      bVar4 = iVar1 != 0;
      if (bVar4) {
        iVar2 = CreateCompatibleDC(iVar1);
        *(int *)(param_1 + 100) = iVar2;
        if (iVar2 != 0) {
          iVar2 = SelectObject(iVar2,*(undefined4 *)(param_1 + 0x60));
          *(int *)(param_1 + 0x68) = iVar2;
          if ((iVar2 == 0) || (iVar2 == -1)) {
            bVar4 = false;
          }
          else {
            bVar4 = true;
          }
          ReleaseDC(0,iVar1);
          if (!bVar4) {
            return false;
          }
          iVar1 = GetDIBColorTable(*(undefined4 *)(param_1 + 100),0,*(undefined4 *)(param_1 + 0x44),
                                   param_1 + 0x6c);
          if (iVar1 != 0) {
            *(undefined4 *)(param_1 + 8) = 1;
            uVar3 = FUN_00444910(param_1 + 0x470,param_1);
            *(undefined4 *)(param_1 + 0x474) = uVar3;
          }
          return iVar1 != 0;
        }
        bVar4 = false;
      }
      ReleaseDC(0,iVar1);
      return bVar4;
    }
  }
  return bVar4;
}



int __thiscall FUN_00443f80(int param_1,int param_2,int param_3)

{
  if (param_2 < *(int *)(param_1 + 0x28)) {
    if (param_3 < *(int *)(param_1 + 0x2c)) {
      return ((*(int *)(param_1 + 0x2c) - param_3) + -1) *
             (*(int *)(param_1 + 0x28) + 3U & 0xfffffffc) + *(int *)(param_1 + 0x20) + param_2;
    }
  }
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 __fastcall FUN_004444f0(int param_1)

{
  uint uVar1;
  undefined4 uVar2;
  int iVar3;
  undefined4 uVar4;
  
  if (*(uint *)(param_1 + 0x98c) < 0x7fffffff) {
    uVar1 = (uint)*(ushort *)(param_1 + 0x98c);
  }
  else {
    uVar1 = FUN_00436df0(*(uint *)(param_1 + 0x98c));
  }
  uVar4 = _DAT_004721c0;
  uVar2 = FindResourceA(_DAT_004721c0,uVar1,0x46a028);
  iVar3 = LoadResource(uVar4,uVar2);
  if (iVar3 != 0) {
    iVar3 = LockResource(iVar3);
    *(int *)(param_1 + 0x988) = iVar3;
    if (iVar3 == 0) {
      return 0;
    }
    return 1;
  }
  uVar4 = GetLastError();
  FUN_00410aa0(0x9b,uVar1);
  FUN_0041b3e0(uVar4,0);
  return 0;
}



void __thiscall FUN_00444630(int param_1,uint *param_2)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  bool bVar7;
  
  iVar4 = FUN_00443f80(*param_2,param_2[1]);
  iVar1 = *(int *)(param_1 + 0x28);
  uVar2 = param_2[2];
  uVar3 = *param_2;
  uVar5 = param_2[1];
  if ((int)uVar5 < (int)param_2[3]) {
    do {
      uVar6 = uVar5 & 0x80000001;
      bVar7 = uVar6 == 0;
      if ((int)uVar6 < 0) {
        bVar7 = (uVar6 - 1 | 0xfffffffe) == 0xffffffff;
      }
      if (bVar7) {
        uVar6 = *param_2 & 0x80000001;
        if ((int)uVar6 < 0) {
          uVar6 = (uVar6 - 1 | 0xfffffffe) + 1;
        }
        uVar6 = 1 - uVar6;
      }
      else {
        uVar6 = *param_2 & 0x80000001;
        if ((int)uVar6 < 0) {
          uVar6 = (uVar6 - 1 | 0xfffffffe) + 1;
        }
      }
      for (; (int)uVar6 < (int)(uVar2 - uVar3); uVar6 = uVar6 + 2) {
        *(undefined *)(uVar6 + iVar4) = 0;
      }
      iVar4 = iVar4 - (iVar1 + 3U & 0xfffffffc);
      uVar5 = uVar5 + 1;
    } while ((int)uVar5 < (int)param_2[3]);
  }
  return;
}



void __thiscall FUN_00444720(int param_1,undefined4 param_2)

{
  undefined4 uVar1;
  
  *(undefined4 *)(param_1 + 0x470) = param_2;
  uVar1 = FUN_00444910((undefined4 *)(param_1 + 0x470),param_1);
  *(undefined4 *)(param_1 + 0x474) = uVar1;
  return;
}



undefined4 FUN_00444780(void)

{
  return 0;
}



uint FUN_00444910(int *param_1)

{
  int *piVar1;
  byte *pbVar2;
  undefined4 uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  undefined4 uVar7;
  int iVar8;
  undefined4 *puVar9;
  
  piVar1 = param_1;
  uVar5 = 0xffffffff;
  iVar8 = *param_1;
  if (iVar8 == -0x1000001) {
    return 0xffffffff;
  }
  if (iVar8 == -1) {
    pbVar2 = (byte *)FUN_00443f80(0,0);
    return (uint)*pbVar2;
  }
  uVar3 = FUN_0043b800(iVar8);
  uVar4 = GetNearestPaletteIndex(uVar3,iVar8);
  if (uVar4 != 0xffffffff) {
    puVar9 = &param_1;
    uVar7 = 1;
    uVar6 = uVar4;
    uVar3 = FUN_0043b800(uVar4,1,puVar9);
    GetPaletteEntries(uVar3,uVar6,uVar7,puVar9);
    if ((((char)param_1 == *(char *)piVar1) && (param_1._2_1_ == (char)((uint)*piVar1 >> 0x10))) &&
       ((char)((uint)param_1 >> 8) == *(char *)((int)piVar1 + 1))) {
      uVar5 = uVar4;
    }
  }
  return uVar5;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

bool FUN_004449c0(void)

{
  int iVar1;
  
  iVar1 = GetCurrentThreadId();
  return iVar1 == _DAT_00475bd0;
}



undefined4 * __thiscall FUN_00444a60(undefined4 *param_1,int param_2)

{
  undefined4 uVar1;
  
  FUN_0043d220(param_2);
  param_1[0xf5] = 0;
  param_1[0xf6] = 0;
  param_1[0x101] = 0;
  param_1[0x102] = 0;
  param_1[0x103] = 0;
  param_1[0x104] = 0;
  *param_1 = &UNK_0045eb94;
  param_1[0xf8] = 0;
  param_1[0xf7] = 0;
  param_1[0xff] = 0;
  param_1[0x100] = 0;
  param_1[0xf7] = *(undefined4 *)(param_2 + 0x138);
  param_1[0xf9] = *(undefined4 *)(param_2 + 0x13c);
  param_1[0xec] = *(undefined4 *)(param_2 + 0x140);
  param_1[0xed] = *(undefined4 *)(param_2 + 0x144);
  param_1[0xee] = *(undefined4 *)(param_2 + 0x148);
  uVar1 = *(undefined4 *)(param_2 + 0x134);
  param_1[0xfc] = 0;
  param_1[0xfd] = 0;
  param_1[0xfe] = 0;
  param_1[0xf5] = 0;
  param_1[0xf4] = 0;
  param_1[0xfa] = 0;
  param_1[0xea] = 0;
  param_1[0xef] = 0;
  param_1[0xf0] = 0;
  param_1[0xf1] = 0;
  param_1[0xf2] = 0;
  param_1[0xeb] = uVar1;
  param_1[0xf6] = 0;
  param_1[0xe1] = 2;
  lstrcpyA(param_1 + 0xe2,0x46a03c);
  FUN_00445c60(0xbf800000);
  return param_1;
}



void __fastcall FUN_00444ba0(undefined4 *param_1)

{
  *param_1 = &UNK_0045eb94;
  FUN_0043d450();
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00444bd0(void)

{
  UnregisterClassA(0x469f24,_DAT_004721bc);
  return;
}



bool __thiscall FUN_004459f0(int param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  undefined4 uStack_8;
  int iStack_4;
  
  if (*(int *)(param_1 + 0x2c) == 0) {
    return false;
  }
  iVar2 = (**(code **)(*(int *)(*(int *)(param_1 + 0x3f0) + 0x9a8) + 0x3c))();
  if (param_3 < iVar2) {
    iVar2 = (**(code **)(*(int *)(*(int *)(param_1 + 0x3f0) + 0x9a8) + 8))(&param_2);
    return iVar2 != 0;
  }
  iVar2 = (**(code **)(*(int *)(*(int *)(param_1 + 0x3f0) + 0x9a8) + 0x3c))();
  if (*(int *)(param_1 + 0xa0) - iVar2 < param_3) {
    piVar3 = (int *)(**(code **)(*(int *)(*(int *)(param_1 + 0x3f4) + 0x9a8) + 0x54))();
    iStack_4 = (*(int *)(param_1 + 0x38) + param_3) - *piVar3;
    uStack_8 = param_2;
    iVar2 = (**(code **)(*(int *)(*(int *)(param_1 + 0x3f4) + 0x9a8) + 8))(&uStack_8);
    return (bool)(-(iVar2 != 0) & 2);
  }
  piVar3 = (int *)(**(code **)(*(int *)(*(int *)(param_1 + 0x3f8) + 0x9a8) + 0x54))();
  if (param_3 < *piVar3 - *(int *)(param_1 + 0x38)) {
    return (bool)4;
  }
  iVar2 = *(int *)(param_1 + 0x3f8);
  iVar4 = (**(code **)(*(int *)(*(int *)(param_1 + 0x3f0) + 0x9a8) + 0x3c))();
  iVar1 = *(int *)(param_1 + 0x38);
  piVar3 = (int *)(**(code **)(*(int *)(iVar2 + 0x9a8) + 0x54))();
  if (param_3 < (iVar4 - iVar1) + *piVar3) {
    piVar3 = (int *)(**(code **)(*(int *)(*(int *)(param_1 + 0x3f8) + 0x9a8) + 0x54))();
    iStack_4 = (param_3 - *piVar3) + *(int *)(param_1 + 0x38);
    uStack_8 = param_2;
    iVar2 = (**(code **)(*(int *)(*(int *)(param_1 + 0x3f8) + 0x9a8) + 8))(&uStack_8);
    return (bool)((-(iVar2 != 0) & 2U) + 3);
  }
  return (bool)6;
}



void __thiscall FUN_00445ba0(int param_1,undefined4 param_2)

{
  undefined4 uVar1;
  
  uVar1 = 0;
  switch(param_2) {
  case 1:
    uVar1 = 0;
    break;
  case 2:
    uVar1 = 1;
    break;
  case 3:
    goto switchD_00445bb3_caseD_3;
  case 4:
    uVar1 = 2;
    *(undefined4 *)(param_1 + 0x3bc) = 1;
    break;
  case 5:
    FUN_00446080(*(undefined4 *)(param_1 + 0x3dc));
    break;
  case 6:
    uVar1 = 3;
    *(undefined4 *)(param_1 + 0x3c4) = 1;
  }
  SendMessageA(*(undefined4 *)(*(int *)(param_1 + 0x3ac) + 0x70),0x115,uVar1,0);
  uVar1 = SendMessageA(*(undefined4 *)(*(int *)(param_1 + 0x3ac) + 0x70),0xce,0,0);
  FUN_00446110(uVar1);
  FUN_00445f20(param_2);
switchD_00445bb3_caseD_3:
  return;
}



void __thiscall FUN_00445c60(int param_1,undefined4 param_2)

{
  *(undefined4 *)(param_1 + 0x3cc) = param_2;
  return;
}



int __fastcall FUN_00445e00(int param_1)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x408);
  (**(code **)(*(int *)(*(int *)(param_1 + 0x3f8) + 0x9a8) + 0x3c))();
  iVar1 = FUN_0044c058();
  iVar2 = iVar2 + iVar1;
  iVar1 = (**(code **)(*(int *)(*(int *)(param_1 + 0x3f8) + 0x9a8) + 0x3c))();
  if (*(int *)(param_1 + 0x410) - iVar1 < iVar2) {
    iVar2 = (**(code **)(*(int *)(*(int *)(param_1 + 0x3f8) + 0x9a8) + 0x3c))();
    return *(int *)(param_1 + 0x410) - iVar2;
  }
  return iVar2;
}



void __fastcall FUN_00445eb0(int param_1)

{
  (**(code **)(*(int *)(*(int *)(param_1 + 0x3f8) + 0x9a8) + 0x3c))();
  FUN_0044c058();
  return;
}



void __thiscall FUN_00445f20(int param_1,undefined4 param_2)

{
  switch(param_2) {
  case 1:
    (**(code **)(*(int *)(*(int *)(param_1 + 0x3f0) + 0xa70) + 0xc))(1);
    return;
  case 2:
    (**(code **)(*(int *)(*(int *)(param_1 + 0x3f4) + 0xa70) + 0xc))(1);
    return;
  case 4:
    if (*(int *)(param_1 + 0x3fc) == 0) {
      *(undefined4 *)(param_1 + 0x3fc) = 1;
      FUN_00435b00(param_1 + 0x404);
      return;
    }
    break;
  case 6:
    if (*(int *)(param_1 + 0x400) == 0) {
      *(undefined4 *)(param_1 + 0x400) = 1;
      FUN_00435b00(param_1 + 0x404);
    }
  }
  return;
}



void __thiscall FUN_00445fd0(int param_1,undefined4 param_2)

{
  switch(param_2) {
  case 1:
    (**(code **)(*(int *)(*(int *)(param_1 + 0x3f0) + 0xa70) + 0xc))(0);
    return;
  case 2:
    (**(code **)(*(int *)(*(int *)(param_1 + 0x3f4) + 0xa70) + 0xc))(0);
    return;
  case 4:
    if (*(int *)(param_1 + 0x3fc) != 0) {
      *(undefined4 *)(param_1 + 0x3fc) = 0;
      FUN_00435b00(param_1 + 0x404);
      return;
    }
    break;
  case 6:
    if (*(int *)(param_1 + 0x400) != 0) {
      *(undefined4 *)(param_1 + 0x400) = 0;
      FUN_00435b00(param_1 + 0x404);
    }
  }
  return;
}



void __thiscall FUN_00446080(int *param_1,int param_2)

{
  int iVar1;
  int *piVar2;
  undefined4 *puVar3;
  
  if (param_1[0xf7] != param_2) {
    if (param_2 < 0) {
      param_2 = 0;
    }
    if (param_1[0xf9] < param_2) {
      param_2 = param_1[0xf9];
    }
    param_1[0xf7] = param_2;
    iVar1 = FUN_00445e00(param_2);
    piVar2 = (int *)(**(code **)(*(int *)(param_1[0xfe] + 0x9a8) + 0x54))();
    if (iVar1 != *piVar2) {
      puVar3 = (undefined4 *)(**(code **)(*(int *)(param_1[0xfe] + 0x9a8) + 0x50))();
      (**(code **)(*(int *)(param_1[0xfe] + 0x9a8) + 0x48))(*puVar3,iVar1);
      (**(code **)(*param_1 + 100))(param_1 + 0x101);
    }
  }
  return;
}



void __thiscall FUN_00446110(int *param_1,int param_2)

{
  int iVar1;
  int *piVar2;
  undefined4 *puVar3;
  
  if (param_1[0xf3] != -0x40800000) {
    param_2 = FUN_0044c058();
  }
  if (param_1[0xf7] != param_2) {
    if (param_2 < 0) {
      param_2 = 0;
    }
    if (param_1[0xf9] < param_2) {
      param_2 = param_1[0xf9];
    }
    param_1[0xf7] = param_2;
    iVar1 = FUN_00445e00(param_2);
    piVar2 = (int *)(**(code **)(*(int *)(param_1[0xfe] + 0x9a8) + 0x54))();
    if (iVar1 != *piVar2) {
      puVar3 = (undefined4 *)(**(code **)(*(int *)(param_1[0xfe] + 0x9a8) + 0x50))();
      (**(code **)(*(int *)(param_1[0xfe] + 0x9a8) + 0x48))(*puVar3,iVar1);
      (**(code **)(*param_1 + 100))(param_1 + 0x101);
    }
  }
  return;
}



undefined4 * __thiscall FUN_004462f0(undefined4 *param_1,int param_2)

{
  undefined4 uVar1;
  undefined4 uVar2;
  
  FUN_00443a90();
  FUN_0044b3b0(param_2);
  *param_1 = &UNK_0045eca4;
  param_1[0x26a] = &UNK_0045ec2c;
  param_1[0x280] = *(undefined4 *)(param_2 + 0xc);
  param_1[0x29b] = *(undefined4 *)(param_2 + 0x78);
  param_1[0x265] = *(undefined4 *)(param_2 + 0x98);
  param_1[0x266] = *(undefined4 *)(param_2 + 0x9c);
  param_1[0x267] = *(undefined4 *)(param_2 + 0xa0);
  param_1[0x268] = *(undefined4 *)(param_2 + 0xa4);
  param_1[0x269] = *(undefined4 *)(param_2 + 0xa8);
  param_1[0x11c] = *(undefined4 *)(param_2 + 0x7c);
  param_1[0x264] = *(undefined4 *)(param_2 + 0x88);
  param_1[0x263] = *(undefined4 *)(param_2 + 0x90);
  param_1[0x262] = 0;
  param_1[0x261] = *(undefined4 *)(param_2 + 0x94);
  uVar1 = *(undefined4 *)(param_2 + 0x80);
  uVar2 = *(undefined4 *)(param_2 + 0x84);
  param_1[0x277] = uVar1;
  param_1[0x29a] = 0;
  param_1[0x278] = uVar2;
  param_1[0x279] = uVar1;
  param_1[0x27a] = uVar2;
  return param_1;
}



void __fastcall FUN_004463f0(undefined4 *param_1)

{
  param_1[-0x26a] = &UNK_0045eca4;
  *param_1 = &UNK_0045ec2c;
  FUN_0043f460();
  FUN_00443b30();
  return;
}



undefined4 * __thiscall FUN_004467a0(undefined4 *param_1,int param_2)

{
  FUN_004462f0(param_2);
  *param_1 = &UNK_0045ed3c;
  param_1[0x26a] = &UNK_0045ecc4;
  param_1[0x29d] = *(undefined4 *)(param_2 + 0xac);
  param_1[0x29e] = *(undefined4 *)(param_2 + 0xb0);
  param_1[0x29f] = *(undefined4 *)(param_2 + 0xb4);
  param_1[0x29c] = 0;
  return param_1;
}



void __fastcall FUN_00446830(undefined4 *param_1)

{
  param_1[-0x26a] = &UNK_0045ed3c;
  *param_1 = &UNK_0045ecc4;
  FUN_004463f0();
  return;
}



undefined4 * __thiscall FUN_00446b20(undefined4 *param_1,int param_2)

{
  FUN_004462f0(param_2);
  if (param_2 == 0) {
    param_2 = 0;
  }
  else {
    param_2 = param_2 + 0xac;
  }
  FUN_004471e0(param_2);
  param_1[0x29c] = &UNK_0045ee08;
  *param_1 = &UNK_0045ede0;
  param_1[0x26a] = &UNK_0045ed68;
  return param_1;
}



void __fastcall FUN_00446ba0(undefined4 *param_1)

{
  param_1[-0x26a] = &UNK_0045ede0;
  *param_1 = &UNK_0045ed68;
  param_1[0x32] = &UNK_0045ee08;
  FUN_004463f0();
  return;
}



undefined4 * __thiscall FUN_004471e0(undefined4 *param_1,undefined4 *param_2)

{
  int iVar1;
  undefined4 *puVar2;
  
  *param_1 = &UNK_0045ee44;
  puVar2 = param_1;
  for (iVar1 = 10; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  param_1[1] = param_2[5];
  param_1[2] = param_2[6];
  param_1[5] = param_2[1];
  param_1[4] = *param_2;
  param_1[9] = param_2[3];
  param_1[7] = param_2[4];
  param_1[3] = 0;
  if (param_1[2] == 1) {
    param_1[3] = param_1[4] + -1;
  }
  if (param_1[4] == 1) {
    param_1[2] = 2;
  }
  return param_1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 * __fastcall FUN_00447370(undefined4 *param_1)

{
  undefined4 uVar1;
  int iVar2;
  
  FUN_00405cb0();
  param_1[0x17] = *(undefined4 *)(_DAT_00475bbc + 0x88);
  param_1[0x18] = *(undefined4 *)(_DAT_00475bbc + 0x8c);
  uVar1 = *(undefined4 *)(_DAT_00475bbc + 0x90);
  param_1[0x12] = 0;
  param_1[0x19] = uVar1;
  param_1[0x13] = 0;
  param_1[0x14] = 0;
  param_1[0x15] = 0;
  param_1[0x16] = 0;
  param_1[0x25] = 0;
  param_1[0x26] = 0;
  param_1[0x1a] = 0;
  param_1[0x1b] = 0;
  param_1[0x1c] = 0;
  param_1[0x1d] = 0;
  param_1[0x1e] = 1;
  param_1[0x21] = 0;
  param_1[0x1f] = 0;
  param_1[0x20] = 0;
  param_1[0x24] = *(undefined4 *)(_DAT_00475bbc + 0x9c);
  iVar2 = _DAT_00475bbc;
  param_1[0x25] = *(undefined4 *)(_DAT_00475bbc + 0xa0);
  param_1[0x26] = *(undefined4 *)(iVar2 + 0xa4);
  param_1[0x22] = *(undefined4 *)(_DAT_00475bbc + 0x94);
  param_1[0x23] = *(undefined4 *)(_DAT_00475bbc + 0x98);
  *param_1 = 1;
  FUN_0043cfb0();
  param_1[0x76] = 0;
  param_1[0x77] = 0;
  param_1[0x78] = 0;
  param_1[0x79] = 0;
  param_1[0x7a] = 0;
  param_1[0x7b] = 0;
  param_1[0x29] = 0x2000;
  FUN_0043cfb0();
  param_1[0xc9] = 0;
  param_1[0xca] = 0;
  param_1[0xcb] = 0;
  param_1[0xcc] = 0;
  param_1[0xcd] = 0;
  param_1[0xce] = 0;
  param_1[0x7c] = 0x2000;
  param_1[0x28] = 0;
  *param_1 = 0x10000;
  param_1[0xd] = 1;
  param_1[0x27] = 0xffffffff;
  param_1[0x47] = 1;
  param_1[0x9a] = 1;
  return param_1;
}



undefined4 * __thiscall FUN_004474e0(undefined4 *param_1,undefined4 param_2)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  undefined4 *puVar4;
  undefined4 *puVar5;
  int unaff_retaddr;
  
  FUN_0043f690(param_2);
  FUN_0043cfb0();
  param_1[0x95] = 0;
  param_1[0x96] = 0;
  param_1[0x97] = 0;
  param_1[0x98] = 0;
  param_1[0x99] = 0;
  param_1[0x9a] = 0;
  param_1[0x48] = 0x2000;
  FUN_0043cfb0();
  param_1[0xe8] = 0;
  param_1[0xe9] = 0;
  param_1[0xea] = 0;
  param_1[0xeb] = 0;
  param_1[0xec] = 0;
  param_1[0xed] = 0;
  param_1[0x9b] = 0x2000;
  *param_1 = &UNK_0045ee80;
  param_1[0x40] = 0;
  param_1[0x3f] = *(undefined4 *)(unaff_retaddr + 0x9c);
  param_1[0xee] = *(undefined4 *)(unaff_retaddr + 0xa0);
  uVar1 = *(uint *)(unaff_retaddr + 0x48);
  uVar2 = uVar1 | 0x40010000;
  param_1[0x1f] = uVar2;
  if (((uVar1 & 0x800) != 0) || (param_1[0xee] != 0)) {
    param_1[0xee] = 1;
    param_1[0x1f] = uVar2 & 0xfffeffff | 0x8000800;
  }
  puVar4 = (undefined4 *)(unaff_retaddr + 0xa4);
  puVar5 = param_1 + 0x48;
  for (iVar3 = 0x53; iVar3 != 0; iVar3 = iVar3 + -1) {
    *puVar5 = *puVar4;
    puVar4 = puVar4 + 1;
    puVar5 = puVar5 + 1;
  }
  puVar4 = (undefined4 *)(unaff_retaddr + 0x1f0);
  puVar5 = param_1 + 0x9b;
  for (iVar3 = 0x53; iVar3 != 0; iVar3 = iVar3 + -1) {
    *puVar5 = *puVar4;
    puVar4 = puVar4 + 1;
    puVar5 = puVar5 + 1;
  }
  param_1[0x47] = 0;
  param_1[0x46] = 0;
  param_1[0x42] = 0;
  param_1[0x43] = 0;
  param_1[0x44] = 0;
  param_1[0x45] = 0;
  return param_1;
}



void __fastcall FUN_00447630(undefined4 *param_1)

{
  *param_1 = &UNK_0045ee80;
  FUN_0043d1e0();
  FUN_0043d1e0();
  FUN_0043f830();
  return;
}



undefined4 __thiscall FUN_00447840(int *param_1,undefined4 param_2)

{
  SendMessageA(param_1[0x1c],0xc,0,param_2);
  FUN_0043f960(param_2);
  (**(code **)(*param_1 + 0xac))();
  return 1;
}



undefined4 * __thiscall FUN_00448110(undefined4 *param_1,int param_2)

{
  int iVar1;
  undefined4 uVar2;
  
  FUN_0043f3a0(param_2);
  *param_1 = &UNK_0045ef38;
  param_1[0x1d] = 0;
  param_1[0x1e] = 0;
  param_1[0x1f] = *(undefined4 *)(param_2 + 0x48);
  param_1[0x1c] = (uint)*(byte *)(param_2 + 0x4c);
  param_1[0x21] = *(undefined4 *)(param_2 + 0x50);
  iVar1 = *(int *)(param_2 + 0x54);
  param_1[0x22] = iVar1;
  if ((iVar1 == -1) || (iVar1 == 0xff00ff)) {
    param_1[0x22] = 0;
  }
  uVar2 = *(undefined4 *)(param_2 + 0x58);
  param_1[0x20] = 0;
  param_1[0x23] = uVar2;
  return param_1;
}



void __fastcall FUN_004481a0(undefined4 *param_1)

{
  *param_1 = &UNK_0045ef38;
  param_1[0x20] = 0;
  if (param_1[0x1d] != 0) {
    DestroyWindow(param_1[0x1d]);
    param_1[0x1d] = 0;
  }
  if (param_1[0x1e] != 0) {
    ImageList_Destroy(param_1[0x1e]);
    param_1[0x1e] = 0;
  }
  FUN_0043f460();
  return;
}



undefined4 __thiscall FUN_00448330(int param_1,undefined4 param_2)

{
  undefined4 uVar1;
  int iVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  undefined4 auStack_60 [5];
  undefined4 uStack_4c;
  undefined4 uStack_48;
  undefined4 uStack_44;
  undefined4 auStack_3c [15];
  
  FUN_0043c220(&param_2);
  puVar3 = auStack_60;
  for (iVar2 = 10; iVar2 != 0; iVar2 = iVar2 + -1) {
    *puVar3 = 0;
    puVar3 = puVar3 + 1;
  }
  auStack_60[0] = 99;
  auStack_60[3] = FUN_0043c730(0);
  uStack_44 = param_2;
  puVar3 = auStack_3c;
  for (iVar2 = 0xd; iVar2 != 0; iVar2 = iVar2 + -1) {
    *puVar3 = 0;
    puVar3 = puVar3 + 1;
  }
  uStack_4c = 0;
  uStack_48 = 1;
  puVar3 = (undefined4 *)&stack0xffffff9c;
  puVar4 = auStack_3c + 2;
  for (iVar2 = 10; iVar2 != 0; iVar2 = iVar2 + -1) {
    *puVar4 = *puVar3;
    puVar3 = puVar3 + 1;
    puVar4 = puVar4 + 1;
  }
  auStack_3c[1] = 0xffff0003;
  uVar1 = SendMessageA(*(undefined4 *)(param_1 + 0x74),0x1100,0,auStack_3c);
  if (*(int *)(param_1 + 0x80) == 0) {
    *(undefined4 *)(param_1 + 0x80) = uVar1;
  }
  FUN_0043c3b0();
  FUN_0043c3b0();
  return uVar1;
}



void __fastcall FUN_00448400(int param_1)

{
  FUN_0043c730(0x104);
  SendMessageA(*(undefined4 *)(param_1 + 0x74),0x110c,0,&stack0xffffffd4);
  FUN_0043c7a0(0xffffffff);
  return;
}



undefined4 __thiscall FUN_00448500(int *param_1,undefined4 param_2)

{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined4 uVar4;
  int iStack_34;
  undefined4 uStack_30;
  int iStack_2c;
  undefined *puStack_28;
  undefined auStack_8 [4];
  undefined4 uStack_4;
  
  iVar1 = FUN_0043c7d0();
  FUN_0043c210();
  FUN_0043c210();
  if (iVar1 == -1) {
    puStack_28 = (undefined *)0x44853e;
    FUN_0043c530();
  }
  else {
    puStack_28 = auStack_8;
    iStack_2c = 0x44854f;
    iStack_2c = FUN_0043c9b0();
    uStack_30 = 0x448559;
    FUN_0043c530();
    uStack_30 = 0x448562;
    FUN_0043c3b0();
  }
  iStack_34 = param_1[0x1d];
  puStack_28 = (undefined *)param_2;
  iStack_2c = 4;
  uStack_30 = 0x110a;
  iVar2 = SendMessageA();
  while( true ) {
    if (iVar2 == 0) {
      puStack_28 = (undefined *)0x4485c0;
      FUN_0043c3b0();
      puStack_28 = (undefined *)0x4485c9;
      FUN_0043c3b0();
      puStack_28 = (undefined *)0x4485d2;
      FUN_0043c3b0();
      return param_2;
    }
    puStack_28 = &stack0xfffffff0;
    uStack_30 = 0x44858d;
    iStack_2c = iVar2;
    FUN_00448400();
    iVar3 = FUN_0044e610();
    puStack_28 = (undefined *)iVar2;
    if (iVar3 == 0) break;
    iStack_34 = param_1[0x1d];
    iStack_2c = 1;
    uStack_30 = 0x110a;
    iVar2 = SendMessageA();
  }
  iStack_2c = 0x4485e8;
  (**(code **)(*param_1 + 0x74))();
  uStack_30 = 9;
  iStack_34 = 0x110b;
  iStack_2c = iVar2;
  SendMessageA(param_1[0x1d]);
  uStack_30 = uStack_4;
  iStack_2c = iVar2;
  FUN_0043c8c0(&iStack_34,iVar1 + 1);
  uVar4 = FUN_00448500();
  FUN_0043c3b0();
  FUN_0043c3b0();
  FUN_0043c3b0();
  return uVar4;
}



undefined4 * __thiscall FUN_004486b0(undefined4 *param_1,int param_2)

{
  int iVar1;
  
  FUN_0044afc0(param_2);
  *param_1 = &UNK_0045efb8;
  param_1[0x25] = *(undefined4 *)(param_2 + 0x5c);
  iVar1 = *(int *)(param_2 + 100);
  param_1[0x27] = iVar1;
  if ((iVar1 == -1) || (iVar1 == 0xff00ff)) {
    param_1[0x27] = 0;
  }
  return param_1;
}



void __fastcall FUN_00448720(undefined4 *param_1)

{
  *param_1 = &UNK_0045efb8;
  FUN_0044b080();
  return;
}



void __thiscall FUN_00448810(int param_1,undefined4 param_2)

{
  SendMessageA(*(undefined4 *)(param_1 + 0x70),0x143,0,param_2);
  return;
}



void __fastcall FUN_00448830(int param_1)

{
  undefined4 uVar1;
  undefined4 unaff_retaddr;
  
  uVar1 = FUN_0043c730(0x80);
  SendMessageA(*(undefined4 *)(param_1 + 0x70),0x148,unaff_retaddr,uVar1);
  FUN_0043c7a0(0xffffffff);
  return;
}



undefined4 __thiscall FUN_00448870(int param_1,undefined4 param_2)

{
  undefined4 uVar1;
  
  uVar1 = SendMessageA(*(undefined4 *)(param_1 + 0x70),0x14c,0xffffffff,param_2);
  FUN_0043c3b0();
  return uVar1;
}



void __thiscall FUN_004488a0(int param_1,undefined4 param_2)

{
  SendMessageA(*(undefined4 *)(param_1 + 0x70),0x14e,param_2,0);
  return;
}



void __fastcall FUN_004488c0(int param_1)

{
  SendMessageA(*(undefined4 *)(param_1 + 0x70),0x147,0,0);
  return;
}



undefined4 FUN_004489c0(char param_1)

{
  if (((param_1 < '\t') || ('\r' < param_1)) && (param_1 != ' ')) {
    return 0;
  }
  return 1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

char * FUN_004489e0(char *param_1,char *param_2)

{
  char cVar1;
  bool bVar2;
  int iVar3;
  int iVar4;
  
  bVar2 = false;
  iVar4 = 0x104;
  *param_2 = '\0';
  if (param_1 != (char *)0x0) {
    if (_DAT_0046a0b8 != 0) {
      _DAT_0046a0b8 = 0;
      _DAT_00475cb0 = 1;
    }
    cVar1 = *param_1;
    for (; (cVar1 != '\0' &&
           (((iVar3 = FUN_004489c0(cVar1), iVar3 != 0 || (bVar2)) ||
            ((_DAT_00475cb0 != 0 && (*param_1 == ';')))))); param_1 = param_1 + 1) {
      if ((_DAT_00475cb0 == 0) || (*param_1 != ';')) {
        if (bVar2) goto LAB_00448a56;
        if (*param_1 == '\n') goto LAB_00448a6d;
      }
      else {
        bVar2 = true;
        _DAT_00475cb0 = 0;
LAB_00448a56:
        if (*param_1 == '\n') {
          bVar2 = false;
LAB_00448a6d:
          _DAT_00475cb0 = 1;
        }
        else if (*param_1 == '\0') {
          bVar2 = false;
        }
        if (*param_1 == '\n') {
          _DAT_00475cac = _DAT_00475cac + 1;
        }
      }
      cVar1 = param_1[1];
    }
    _DAT_00475cb0 = 0;
    cVar1 = *param_1;
    while ((cVar1 != '\0' && (iVar3 = FUN_004489c0(cVar1), iVar3 == 0))) {
      if (1 < iVar4) {
        *param_2 = *param_1;
        param_2 = param_2 + 1;
      }
      if (*param_1 == '\n') {
        _DAT_00475cac = _DAT_00475cac + 1;
      }
      cVar1 = param_1[1];
      param_1 = param_1 + 1;
      iVar4 = iVar4 + -1;
    }
    *param_2 = '\0';
  }
  return param_1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00448ae0(char *param_1,char *param_2,char param_3)

{
  char *pcVar1;
  char cVar2;
  int iVar3;
  
  iVar3 = 0x104;
  *param_2 = '\0';
  if (param_1 != (char *)0x0) {
    cVar2 = *param_1;
    while ((cVar2 != '\0' && (param_3 != cVar2))) {
      if (1 < iVar3) {
        *param_2 = cVar2;
        param_2 = param_2 + 1;
      }
      if (*param_1 == '\n') {
        _DAT_00475cac = _DAT_00475cac + 1;
      }
      pcVar1 = param_1 + 1;
      param_1 = param_1 + 1;
      iVar3 = iVar3 + -1;
      cVar2 = *pcVar1;
    }
    *param_2 = '\0';
  }
  return;
}



char * FUN_00448b30(char *param_1,undefined4 param_2,undefined4 param_3)

{
  char cVar1;
  int iVar2;
  
  if (param_1 != (char *)0x0) {
    param_1 = (char *)FUN_004489e0(param_1,param_2);
    cVar1 = *param_1;
    while ((cVar1 != '\0' && (iVar2 = lstrcmpiA(param_2,param_3), iVar2 != 0))) {
      param_1 = (char *)FUN_004489e0(param_1,param_2);
      cVar1 = *param_1;
    }
  }
  return param_1;
}



undefined4 FUN_00448b80(undefined4 param_1,undefined *param_2,undefined4 param_3)

{
  bool bVar1;
  undefined4 uVar2;
  int iVar3;
  
  bVar1 = false;
  uVar2 = FUN_00448b30(param_1,param_2,0x46a6f0);
  while( true ) {
    if (bVar1) {
      return uVar2;
    }
    iVar3 = lstrcmpiA(param_2,0x46a6f0);
    if (iVar3 != 0) break;
    uVar2 = FUN_004489e0(uVar2,param_2);
    iVar3 = lstrcmpiA(param_2,param_3);
    if (iVar3 == 0) {
      bVar1 = true;
    }
    else {
      uVar2 = FUN_00448b30(uVar2,param_2,0x46a6f0);
    }
  }
  *param_2 = 0;
  return uVar2;
}



void FUN_00448c00(undefined4 *param_1,char *param_2)

{
  char cVar1;
  int iVar2;
  undefined4 *puVar3;
  char acStack_28 [20];
  undefined4 auStack_14 [4];
  undefined4 uStack_4;
  
  cVar1 = *param_2;
  for (iVar2 = 0; ((cVar1 != '\0' && (cVar1 != ',')) && (iVar2 < 0x14)); iVar2 = iVar2 + 1) {
    acStack_28[iVar2] = cVar1;
    cVar1 = param_2[1];
    param_2 = param_2 + 1;
  }
  acStack_28[iVar2] = '\0';
  auStack_14[1] = FUN_0044bab9(acStack_28);
  param_2 = param_2 + 1;
  cVar1 = *param_2;
  for (iVar2 = 0; ((cVar1 != '\0' && (cVar1 != ',')) && (iVar2 < 0x14)); iVar2 = iVar2 + 1) {
    acStack_28[iVar2] = cVar1;
    cVar1 = param_2[1];
    param_2 = param_2 + 1;
  }
  acStack_28[iVar2] = '\0';
  auStack_14[2] = FUN_0044bab9(acStack_28);
  param_2 = param_2 + 1;
  cVar1 = *param_2;
  for (iVar2 = 0; ((cVar1 != '\0' && (cVar1 != ',')) && (iVar2 < 0x14)); iVar2 = iVar2 + 1) {
    acStack_28[iVar2] = cVar1;
    cVar1 = param_2[1];
    param_2 = param_2 + 1;
  }
  acStack_28[iVar2] = '\0';
  auStack_14[3] = FUN_0044bab9(acStack_28);
  param_2 = param_2 + 1;
  cVar1 = *param_2;
  for (iVar2 = 0; ((cVar1 != '\0' && (cVar1 != ',')) && (iVar2 < 0x14)); iVar2 = iVar2 + 1) {
    acStack_28[iVar2] = cVar1;
    cVar1 = param_2[1];
    param_2 = param_2 + 1;
  }
  acStack_28[iVar2] = '\0';
  uStack_4 = FUN_0044bab9(acStack_28);
  if (*param_2 == ',') {
    cVar1 = param_2[1];
    for (iVar2 = 0; (cVar1 != '\0' && (iVar2 < 0x14)); iVar2 = iVar2 + 1) {
      acStack_28[iVar2] = cVar1;
      cVar1 = param_2[2];
      param_2 = param_2 + 1;
    }
    acStack_28[iVar2] = '\0';
    auStack_14[0] = FUN_0044bab9(acStack_28);
  }
  else {
    auStack_14[0] = 0xffffffff;
  }
  puVar3 = auStack_14;
  for (iVar2 = 5; iVar2 != 0; iVar2 = iVar2 + -1) {
    *param_1 = *puVar3;
    puVar3 = puVar3 + 1;
    param_1 = param_1 + 1;
  }
  return;
}



undefined8 FUN_00448d40(char *param_1)

{
  char cVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  int iVar4;
  char acStack_14 [20];
  
  cVar1 = *param_1;
  for (iVar4 = 0; ((cVar1 != '\0' && (cVar1 != ',')) && (iVar4 < 0x14)); iVar4 = iVar4 + 1) {
    acStack_14[iVar4] = cVar1;
    cVar1 = param_1[1];
    param_1 = param_1 + 1;
  }
  acStack_14[iVar4] = '\0';
  uVar2 = FUN_0044bab9(acStack_14);
  param_1 = param_1 + 1;
  cVar1 = *param_1;
  for (iVar4 = 0; ((cVar1 != '\0' && (cVar1 != ',')) && (iVar4 < 0x14)); iVar4 = iVar4 + 1) {
    acStack_14[iVar4] = cVar1;
    cVar1 = param_1[1];
    param_1 = param_1 + 1;
  }
  acStack_14[iVar4] = '\0';
  uVar3 = FUN_0044bab9(acStack_14);
  return CONCAT44(uVar3,uVar2);
}



void FUN_00448dc0(undefined4 *param_1,char *param_2)

{
  char cVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  int iVar5;
  char acStack_14 [20];
  
  cVar1 = *param_2;
  for (iVar5 = 0; ((cVar1 != '\0' && (cVar1 != ',')) && (iVar5 < 0x14)); iVar5 = iVar5 + 1) {
    acStack_14[iVar5] = cVar1;
    cVar1 = param_2[1];
    param_2 = param_2 + 1;
  }
  acStack_14[iVar5] = '\0';
  uVar2 = FUN_0044bab9(acStack_14);
  param_2 = param_2 + 1;
  cVar1 = *param_2;
  for (iVar5 = 0; ((cVar1 != '\0' && (cVar1 != ',')) && (iVar5 < 0x14)); iVar5 = iVar5 + 1) {
    acStack_14[iVar5] = cVar1;
    cVar1 = param_2[1];
    param_2 = param_2 + 1;
  }
  acStack_14[iVar5] = '\0';
  uVar3 = FUN_0044bab9(acStack_14);
  if (*param_2 == ',') {
    cVar1 = param_2[1];
    for (iVar5 = 0; (cVar1 != '\0' && (iVar5 < 0x14)); iVar5 = iVar5 + 1) {
      acStack_14[iVar5] = cVar1;
      cVar1 = param_2[2];
      param_2 = param_2 + 1;
    }
    acStack_14[iVar5] = '\0';
    uVar4 = FUN_0044bab9(acStack_14);
  }
  else {
    uVar4 = 0xffffffff;
  }
  *param_1 = uVar4;
  param_1[1] = uVar2;
  param_1[2] = uVar3;
  return;
}



int FUN_00448e80(char *param_1)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  undefined auStack_104 [260];
  
  iVar2 = 0;
  if (*param_1 == '\0') {
    return 0;
  }
  do {
    param_1 = (char *)FUN_00448ae0(param_1,auStack_104,0x7c);
    iVar1 = lstrlenA(auStack_104);
    if (0 < iVar1) {
      uVar4 = 0;
      uVar3 = 0x46a0c0;
      do {
        iVar1 = lstrcmpA(auStack_104,uVar3);
        if (iVar1 == 0) {
          if (uVar4 < 0x24) {
            iVar2 = iVar2 + *(int *)(uVar4 * 0x2c + 0x46a0e8);
          }
          break;
        }
        uVar3 = uVar3 + 0x2c;
        uVar4 = uVar4 + 1;
      } while (uVar3 < 0x46a6f0);
    }
    if (*param_1 == '|') {
      param_1 = param_1 + 1;
    }
    if (*param_1 == '\0') {
      return iVar2;
    }
  } while( true );
}



uint FUN_00448f20(char *param_1)

{
  char cVar1;
  undefined uVar2;
  undefined uVar3;
  undefined uVar4;
  int iVar5;
  int iVar6;
  char acStack_14 [20];
  
  iVar6 = 0;
  iVar5 = lstrcmpiA(param_1,0x46a704);
  if (iVar5 == 0) {
    return 0xffffffff;
  }
  iVar5 = lstrcmpiA(param_1,0x46a6f8);
  if (iVar5 != 0) {
    cVar1 = *param_1;
    for (; ((cVar1 != '\0' && (cVar1 != ',')) && (iVar6 < 0x14)); iVar6 = iVar6 + 1) {
      acStack_14[iVar6] = cVar1;
      cVar1 = param_1[1];
      param_1 = param_1 + 1;
    }
    acStack_14[iVar6] = '\0';
    uVar2 = FUN_0044bab9(acStack_14);
    param_1 = param_1 + 1;
    cVar1 = *param_1;
    for (iVar6 = 0; ((cVar1 != '\0' && (cVar1 != ',')) && (iVar6 < 0x14)); iVar6 = iVar6 + 1) {
      acStack_14[iVar6] = cVar1;
      cVar1 = param_1[1];
      param_1 = param_1 + 1;
    }
    acStack_14[iVar6] = '\0';
    uVar3 = FUN_0044bab9(acStack_14);
    param_1 = param_1 + 1;
    cVar1 = *param_1;
    for (iVar6 = 0; ((cVar1 != '\0' && (cVar1 != ',')) && (iVar6 < 0x14)); iVar6 = iVar6 + 1) {
      acStack_14[iVar6] = cVar1;
      cVar1 = param_1[1];
      param_1 = param_1 + 1;
    }
    acStack_14[iVar6] = '\0';
    uVar4 = FUN_0044bab9(acStack_14);
    return (uint)CONCAT21(CONCAT11(uVar4,uVar3),uVar2);
  }
  return 0xfeffffff;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00449020(undefined2 param_1)

{
  _DAT_00475cb4 = ImageList_LoadImageA(_DAT_004721c0,param_1,0,4,0xff00ff,0,0);
  return;
}



undefined4 * __thiscall FUN_00449050(undefined4 *param_1,undefined4 param_2)

{
  FUN_0043c210();
  FUN_0043c210();
  param_1[6] = 0;
  param_1[3] = 0;
  FUN_0043c530(param_2);
  *param_1 = 0;
  param_1[4] = 0;
  param_1[5] = 0;
  return param_1;
}



undefined4 __fastcall FUN_00449090(undefined4 *param_1)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uStack_24;
  undefined4 uStack_20;
  undefined4 uStack_1c;
  undefined4 *puStack_18;
  
  puStack_18 = param_1 + 1;
  uStack_1c = 0x4490a6;
  FUN_0043c530();
  uStack_1c = 0;
  uStack_20 = 0x2c;
  uStack_24 = 0x4490b1;
  uStack_24 = FUN_0043c7d0();
  FUN_0043c860();
  iVar1 = FUN_0043c7d0(0x2c);
  FUN_0043c8c0(&uStack_1c,iVar1 + 1);
  uVar2 = FUN_0044bab9(uStack_24);
  param_1[4] = uVar2;
  uVar3 = 0x2c;
  iVar1 = FUN_0043ca10(0x2c);
  uVar2 = FUN_0043c8c0(&uStack_24,iVar1 + 1);
  FUN_0043c530(uVar2);
  FUN_0043c3b0();
  uVar2 = FUN_0044bab9(uVar3);
  param_1[5] = uVar2;
  uVar2 = CreateFontA(param_1[4],0,0,0,uVar2,0,0,0,1,0,0,0,0,param_1[2]);
  *param_1 = uVar2;
  FUN_0043c3b0();
  return uVar2;
}



void __fastcall FUN_00449160(int *param_1)

{
  if (*param_1 != 0) {
    DeleteObject(*param_1);
  }
  FUN_0043c3b0();
  FUN_0043c3b0();
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __fastcall FUN_004491b0(int *param_1)

{
  int iVar1;
  
  _DAT_00475cb8 = 0;
  iVar1 = *param_1;
  while (iVar1 != 0) {
    *param_1 = *(int *)(iVar1 + 0x20);
    if (iVar1 != 0) {
      FUN_00449160();
      FUN_0044bb7e(iVar1);
    }
    iVar1 = *param_1;
  }
  return;
}



undefined4 __thiscall FUN_004491f0(undefined4 *param_1,undefined4 *param_2)

{
  int iVar1;
  undefined4 *puVar2;
  undefined4 uVar3;
  
  iVar1 = FUN_0044e610(*param_2,0x46a74c);
  if ((iVar1 == 0) || (iVar1 = FUN_0044e610(*param_2,0x46a744), iVar1 == 0)) {
    return *(undefined4 *)param_1[2];
  }
  iVar1 = FUN_0044e610(*param_2,0x46a740);
  if ((iVar1 == 0) || (iVar1 = FUN_0044e610(*param_2,0x46a738), iVar1 == 0)) {
    return *(undefined4 *)param_1[3];
  }
  iVar1 = FUN_0044e610(*param_2,0x46a734);
  if ((iVar1 == 0) || (iVar1 = FUN_0044e610(*param_2,0x463234), iVar1 == 0)) {
    return *(undefined4 *)param_1[4];
  }
  iVar1 = FUN_0044e610(*param_2,0x46a730);
  if ((iVar1 == 0) || (iVar1 = FUN_0044e610(*param_2,0x46a728), iVar1 == 0)) {
    return *(undefined4 *)param_1[5];
  }
  iVar1 = FUN_0044e610(*param_2,0x46a724);
  if ((iVar1 == 0) || (iVar1 = FUN_0044e610(*param_2,0x46a71c), iVar1 == 0)) {
    return *(undefined4 *)param_1[6];
  }
  iVar1 = FUN_0044e610(*param_2,0x46a718);
  if ((iVar1 == 0) || (iVar1 = FUN_0044e610(*param_2,0x46a710), iVar1 == 0)) {
    uVar3 = GetStockObject(0x11);
    return uVar3;
  }
  param_1 = (undefined4 *)*param_1;
  do {
    if (param_1 == (undefined4 *)0x0) {
LAB_00449331:
      puVar2 = (undefined4 *)FUN_00449550(param_2);
      if (puVar2 == (undefined4 *)0x0) {
        return 0;
      }
      return *puVar2;
    }
    iVar1 = FUN_0044e610(*param_2,param_1[1]);
    if (iVar1 == 0) {
      if (param_1 != (undefined4 *)0x0) {
        param_1[3] = param_1[3] + 1;
        return *param_1;
      }
      goto LAB_00449331;
    }
    param_1 = (undefined4 *)param_1[8];
  } while( true );
}



int __thiscall FUN_00449550(int *param_1,undefined4 param_2)

{
  int iVar1;
  int iVar2;
  
  iVar1 = FUN_0044ba20(0x24);
  if (iVar1 == 0) {
    iVar1 = 0;
  }
  else {
    FUN_00449050(param_2);
    *(undefined4 *)(iVar1 + 0x20) = 0;
    *(undefined4 *)(iVar1 + 0x1c) = 0;
  }
  iVar2 = FUN_00449090();
  if (iVar2 != 0) {
    *(int *)(iVar1 + 0x20) = *param_1;
    if (*param_1 != 0) {
      *(int *)(*param_1 + 0x1c) = iVar1;
    }
    *param_1 = iVar1;
  }
  return *param_1;
}



undefined4 __thiscall FUN_004495b0(int param_1,char **param_2)

{
  int iVar1;
  undefined4 uVar2;
  int iStack_18;
  undefined4 uStack_14;
  
  uStack_14 = 0x5d;
  iStack_18 = 0x4495c3;
  iVar1 = FUN_0043c7d0();
  if (((*(int *)(*param_2 + -8) != 0) && (**param_2 == '[')) && (0 < iVar1)) {
    iStack_18 = iVar1 + -1;
    FUN_0043c8e0(&stack0x00000000,1);
    uVar2 = FUN_0043c8c0(&uStack_14,iVar1 + 1);
    FUN_0043c530(uVar2);
    FUN_0043c3b0();
    uVar2 = FUN_004491f0(&iStack_18);
    FUN_0043c3b0();
    return uVar2;
  }
  return **(undefined4 **)(param_1 + 0x10);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_00449640(void)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 unaff_retaddr;
  
  FUN_0043c210();
  uVar2 = _DAT_004721c0;
  uVar1 = FUN_0043c730(0x104,0x104);
  FUN_0040e750(uVar2,unaff_retaddr,uVar1);
  FUN_0043c7a0(0xffffffff);
  uVar2 = FUN_004495b0(&stack0xfffffff4);
  FUN_0043c3b0();
  return uVar2;
}



void __fastcall FUN_00449a70(int param_1)

{
  if (*(int *)(param_1 + 0x14) != 0) {
    DestroyWindow(*(int *)(param_1 + 0x14));
    *(undefined4 *)(param_1 + 0x14) = 0;
  }
  if (*(int *)(param_1 + 0x1c) != 0) {
    DeleteObject(*(int *)(param_1 + 0x1c));
  }
  *(undefined4 *)(param_1 + 0x1c) = 0;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00449aa0(void)

{
  UnregisterClassA(0x4641b0,_DAT_004721bc);
  return;
}



void __thiscall FUN_0044ad40(int *param_1,int param_2,int param_3,int param_4,int param_5)

{
  *param_1 = *param_1 - param_2;
  param_1[1] = param_1[1] - param_3;
  param_1[2] = param_1[2] + param_4;
  param_1[3] = param_1[3] + param_5;
  return;
}



int __thiscall FUN_0044af70(undefined4 *param_1,undefined4 param_2)

{
  int iVar1;
  
  param_1 = (undefined4 *)*param_1;
  do {
    if (param_1 == (undefined4 *)0x0) {
LAB_0044af92:
      FUN_0043c3b0();
      return 0;
    }
    iVar1 = FUN_0044e610(param_2,*param_1);
    if (iVar1 == 0) {
      if (param_1 != (undefined4 *)0x0) {
        iVar1 = param_1[2];
        param_1[2] = iVar1 + -1;
        FUN_0043c3b0();
        return iVar1 + -1;
      }
      goto LAB_0044af92;
    }
    param_1 = (undefined4 *)param_1[3];
  } while( true );
}



undefined4 * __thiscall FUN_0044afc0(undefined4 *param_1,int param_2)

{
  undefined4 uVar1;
  
  FUN_0043f3a0(param_2);
  FUN_0043c210();
  FUN_0043c210();
  *param_1 = &UNK_0045f03c;
  param_1[0x1c] = 0;
  FUN_0043c590(&DAT_0046e83c);
  FUN_0043c590(&DAT_0046e83c);
  param_1[0x21] = *(undefined4 *)(param_2 + 0x54);
  param_1[0x1f] = *(undefined4 *)(param_2 + 0x48);
  param_1[0x20] = *(undefined4 *)(param_2 + 0x4c);
  param_1[0x22] = *(undefined4 *)(param_2 + 0x50);
  param_1[0x24] = 0;
  if (*(int *)(param_2 + 0x58) != 0) {
    uVar1 = FUN_00449640(*(int *)(param_2 + 0x58));
    param_1[0x21] = uVar1;
  }
  return param_1;
}



void __fastcall FUN_0044b080(undefined4 *param_1)

{
  *param_1 = &UNK_0045f03c;
  param_1[0x23] = 0;
  FUN_0043c220(param_1 + 0x1d,param_1);
  FUN_0044af70();
  FUN_0044b1e0();
  if (param_1[0x24] != 0) {
    DeleteObject(param_1[0x24]);
  }
  FUN_0043c3b0();
  FUN_0043c3b0();
  FUN_0043f460();
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int __fastcall FUN_0044b0e0(int *param_1)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 uStack_c;
  int iStack_8;
  
  (**(code **)(*param_1 + 0x74))();
  _DAT_00475cec = param_1;
  iVar1 = CreateWindowExA(0,param_1[0x1d],param_1[0x1e],param_1[0x1f],param_1[0xd],param_1[0xe],
                          param_1[0xf] - param_1[0xd],param_1[0x10] - param_1[0xe],
                          *(undefined4 *)(param_1[0x15] + 0x74),param_1[9],_DAT_004721bc,0);
  param_1[0x1c] = iVar1;
  if (iVar1 == 0) {
    uVar2 = GetLastError(1);
    FUN_0041b3e0(uVar2);
  }
  else {
    SetWindowLongA(iVar1,0xffffffeb,param_1);
    if (param_1[0x21] != 0) {
      SendMessageA(param_1[0x1c],0x30,param_1[0x21],1);
    }
    iVar1 = FUN_0040ed00();
    if ((iVar1 != 0) || (uVar2 = 0x100, param_1[0x22] != 0)) {
      uVar2 = 0x200;
    }
    FUN_0041b570(param_1[0x1c],uVar2);
  }
  iStack_8 = param_1[0x27];
  if ((iStack_8 != -1) && (iStack_8 != 0xff00ff)) {
    uStack_c = 0;
    iVar1 = CreateBrushIndirect(&uStack_c);
    param_1[0x24] = iVar1;
  }
  _DAT_00475cec = (int *)0x0;
  return param_1[0x1c];
}



undefined4 __fastcall FUN_0044b1e0(int param_1)

{
  if (*(int *)(param_1 + 0x70) != 0) {
    DestroyWindow(*(int *)(param_1 + 0x70));
    *(undefined4 *)(param_1 + 0x70) = 0;
  }
  return 1;
}



void __fastcall FUN_0044b2e0(int param_1)

{
  *(undefined4 *)(param_1 + 0x2c) = 0;
  if (*(int *)(param_1 + 0x70) != 0) {
    ShowWindow(*(int *)(param_1 + 0x70),0);
  }
  return;
}



undefined4 * __thiscall FUN_0044b3b0(undefined4 *param_1,int param_2)

{
  int iVar1;
  
  FUN_0043f3a0(param_2);
  param_1[0x1d] = 0;
  param_1[0x1f] = 0;
  param_1[0x21] = 0xbf800000;
  param_1[0x22] = 0xbf800000;
  param_1[0x2a] = 0;
  param_1[0x2b] = 0;
  param_1[0x2c] = 0;
  param_1[0x2d] = 0;
  param_1[0x2e] = 0;
  param_1[0x2f] = 0;
  *param_1 = &UNK_0045f0b8;
  param_1[0x25] = 0;
  param_1[0x26] = 0;
  param_1[0x27] = 0;
  param_1[0x28] = 0;
  param_1[0x29] = *(undefined4 *)(param_2 + 0x48);
  param_1[0x2a] = *(undefined4 *)(param_2 + 0x4c);
  param_1[0x2b] = *(undefined4 *)(param_2 + 0x50);
  param_1[0x2c] = *(undefined4 *)(param_2 + 0x54);
  param_1[0x2d] = *(undefined4 *)(param_2 + 0x58);
  param_1[0x2e] = *(undefined4 *)(param_2 + 0x6c);
  param_1[0x2f] = *(undefined4 *)(param_2 + 0x70);
  param_1[0x1d] = (float)*(int *)(param_2 + 0x5c);
  param_1[0x1e] = (float)*(int *)(param_2 + 0x60);
  param_1[0x1c] = *(undefined4 *)(param_2 + 0x74);
  param_1[0x1f] = (float)*(int *)(param_2 + 100);
  iVar1 = *(int *)(param_2 + 0x68);
  param_1[0x23] = 0;
  param_1[0x24] = 0;
  param_1[0x20] = (float)iVar1;
  return param_1;
}



void __fastcall FUN_0044b4b0(int param_1)

{
  float fVar1;
  
  if ((*(int *)(param_1 + 0xa4) == 1) && (*(uint *)(param_1 + 0x70) != 0)) {
    fVar1 = (float)(ulonglong)*(uint *)(param_1 + 0x70);
    *(float *)(param_1 + 0x74) =
         (float)(*(int *)(param_1 + 0xb8) - *(int *)(param_1 + 0x34)) / fVar1;
    *(float *)(param_1 + 0x78) =
         (float)(*(int *)(param_1 + 0xbc) - *(int *)(param_1 + 0x40)) / fVar1;
  }
  *(float *)(param_1 + 0x8c) = (float)*(int *)(param_1 + 0x34);
  *(float *)(param_1 + 0x90) = (float)*(int *)(param_1 + 0x38);
  FUN_0043f480();
  return;
}



void FUN_0044ba20(undefined4 param_1)

{
  FUN_0044c5b4(param_1,1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_0044ba2e(byte *param_1)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  byte *pbVar5;
  
  while( true ) {
    if (_DAT_0046ae4c < 2) {
      uVar1 = *(byte *)(_DAT_0046ac40 + (uint)*param_1 * 2) & 8;
    }
    else {
      uVar1 = FUN_0044e6e0(*param_1,8);
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
    if (_DAT_0046ae4c < 2) {
      uVar2 = *(byte *)(_DAT_0046ac40 + uVar4 * 2) & 4;
    }
    else {
      uVar2 = FUN_0044e6e0(uVar4,4);
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



void FUN_0044bab9(undefined4 param_1)

{
  FUN_0044ba2e(param_1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

longlong FUN_0044bac4(byte *param_1)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  byte *pbVar4;
  longlong lVar5;
  
  while( true ) {
    if (_DAT_0046ae4c < 2) {
      uVar1 = *(byte *)(_DAT_0046ac40 + (uint)*param_1 * 2) & 8;
    }
    else {
      uVar1 = FUN_0044e6e0(*param_1,8);
    }
    if (uVar1 == 0) break;
    param_1 = param_1 + 1;
  }
  uVar1 = (uint)*param_1;
  pbVar4 = param_1 + 1;
  if ((uVar1 == 0x2d) || (uVar3 = uVar1, uVar1 == 0x2b)) {
    uVar3 = (uint)*pbVar4;
    pbVar4 = param_1 + 2;
  }
  lVar5 = 0;
  while( true ) {
    if (_DAT_0046ae4c < 2) {
      uVar2 = *(byte *)(_DAT_0046ac40 + uVar3 * 2) & 4;
    }
    else {
      uVar2 = FUN_0044e6e0(uVar3,4);
    }
    if (uVar2 == 0) break;
    lVar5 = FUN_0044c170(lVar5,10,0);
    lVar5 = lVar5 + (int)(uVar3 - 0x30);
    uVar3 = (uint)*pbVar4;
    pbVar4 = pbVar4 + 1;
  }
  if (uVar1 == 0x2d) {
    lVar5 = CONCAT44(-((int)((ulonglong)lVar5 >> 0x20) + (uint)((int)lVar5 != 0)),-(int)lVar5);
  }
  return lVar5;
}



void FUN_0044bb7e(undefined4 param_1)

{
  FUN_0044c4b9(param_1);
  return;
}



uint * FUN_0044bba0(uint *param_1,char param_2)

{
  uint uVar1;
  char cVar2;
  uint uVar3;
  uint uVar4;
  uint *puVar5;
  
  uVar1 = (uint)param_1 & 3;
  while (uVar1 != 0) {
    if (*(char *)param_1 == param_2) {
      return param_1;
    }
    if (*(char *)param_1 == '\0') {
      return (uint *)0x0;
    }
    uVar1 = (uint)(uint *)((int)param_1 + 1) & 3;
    param_1 = (uint *)((int)param_1 + 1);
  }
  while( true ) {
    while( true ) {
      uVar1 = *param_1;
      uVar4 = uVar1 ^ CONCAT22(CONCAT11(param_2,param_2),CONCAT11(param_2,param_2));
      uVar3 = uVar1 ^ 0xffffffff ^ uVar1 + 0x7efefeff;
      puVar5 = param_1 + 1;
      if (((uVar4 ^ 0xffffffff ^ uVar4 + 0x7efefeff) & 0x81010100) != 0) break;
      param_1 = puVar5;
      if ((uVar3 & 0x81010100) != 0) {
        if ((uVar3 & 0x1010100) != 0) {
          return (uint *)0x0;
        }
        if ((uVar1 + 0x7efefeff & 0x80000000) == 0) {
          return (uint *)0x0;
        }
      }
    }
    uVar1 = *param_1;
    if ((char)uVar1 == param_2) {
      return param_1;
    }
    if ((char)uVar1 == '\0') {
      return (uint *)0x0;
    }
    cVar2 = (char)(uVar1 >> 8);
    if (cVar2 == param_2) {
      return (uint *)((int)param_1 + 1);
    }
    if (cVar2 == '\0') break;
    cVar2 = (char)(uVar1 >> 0x10);
    if (cVar2 == param_2) {
      return (uint *)((int)param_1 + 2);
    }
    if (cVar2 == '\0') {
      return (uint *)0x0;
    }
    cVar2 = (char)(uVar1 >> 0x18);
    if (cVar2 == param_2) {
      return (uint *)((int)param_1 + 3);
    }
    param_1 = puVar5;
    if (cVar2 == '\0') {
      return (uint *)0x0;
    }
  }
  return (uint *)0x0;
}



uint * FUN_0044bd70(uint *param_1,uint *param_2,uint param_3)

{
  uint uVar1;
  uint uVar2;
  char cVar3;
  uint uVar4;
  uint *puVar5;
  
  if (param_3 == 0) {
    return param_1;
  }
  puVar5 = param_1;
  if (((uint)param_2 & 3) != 0) {
    while( true ) {
      cVar3 = *(char *)param_2;
      param_2 = (uint *)((int)param_2 + 1);
      *(char *)puVar5 = cVar3;
      puVar5 = (uint *)((int)puVar5 + 1);
      param_3 = param_3 - 1;
      if (param_3 == 0) {
        return param_1;
      }
      if (cVar3 == '\0') break;
      if (((uint)param_2 & 3) == 0) {
        uVar4 = param_3 >> 2;
        goto joined_r0x0044bdae;
      }
    }
    do {
      if (((uint)puVar5 & 3) == 0) {
        uVar4 = param_3 >> 2;
        cVar3 = '\0';
        if (uVar4 == 0) goto LAB_0044bdeb;
        goto LAB_0044be59;
      }
      *(undefined *)puVar5 = 0;
      puVar5 = (uint *)((int)puVar5 + 1);
      param_3 = param_3 - 1;
    } while (param_3 != 0);
    return param_1;
  }
  uVar4 = param_3 >> 2;
  if (uVar4 != 0) {
    do {
      uVar1 = *param_2;
      uVar2 = *param_2;
      param_2 = param_2 + 1;
      if (((uVar1 ^ 0xffffffff ^ uVar1 + 0x7efefeff) & 0x81010100) != 0) {
        if ((char)uVar2 == '\0') {
          *puVar5 = 0;
joined_r0x0044be55:
          while( true ) {
            uVar4 = uVar4 - 1;
            puVar5 = puVar5 + 1;
            if (uVar4 == 0) break;
LAB_0044be59:
            *puVar5 = 0;
          }
          cVar3 = '\0';
          param_3 = param_3 & 3;
          if (param_3 != 0) goto LAB_0044bdeb;
          return param_1;
        }
        if ((char)(uVar2 >> 8) == '\0') {
          *puVar5 = uVar2 & 0xff;
          goto joined_r0x0044be55;
        }
        if ((uVar2 & 0xff0000) == 0) {
          *puVar5 = uVar2 & 0xffff;
          goto joined_r0x0044be55;
        }
        if ((uVar2 & 0xff000000) == 0) {
          *puVar5 = uVar2;
          goto joined_r0x0044be55;
        }
      }
      *puVar5 = uVar2;
      puVar5 = puVar5 + 1;
      uVar4 = uVar4 - 1;
joined_r0x0044bdae:
    } while (uVar4 != 0);
    param_3 = param_3 & 3;
    if (param_3 == 0) {
      return param_1;
    }
  }
  do {
    cVar3 = *(char *)param_2;
    param_2 = (uint *)((int)param_2 + 1);
    *(char *)puVar5 = cVar3;
    puVar5 = (uint *)((int)puVar5 + 1);
    if (cVar3 == '\0') {
      while (param_3 = param_3 - 1, param_3 != 0) {
LAB_0044bdeb:
        *(char *)puVar5 = cVar3;
        puVar5 = (uint *)((int)puVar5 + 1);
      }
      return param_1;
    }
    param_3 = param_3 - 1;
  } while (param_3 != 0);
  return param_1;
}



undefined8 FUN_0044be70(uint param_1,uint param_2,uint param_3,uint param_4)

{
  ulonglong uVar1;
  longlong lVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  bool bVar10;
  char cVar11;
  uint uVar9;
  
  cVar11 = (int)param_2 < 0;
  if ((bool)cVar11) {
    bVar10 = param_1 != 0;
    param_1 = -param_1;
    param_2 = -(uint)bVar10 - param_2;
  }
  if ((int)param_4 < 0) {
    cVar11 = cVar11 + '\x01';
    bVar10 = param_3 != 0;
    param_3 = -param_3;
    param_4 = -(uint)bVar10 - param_4;
  }
  uVar3 = param_1;
  uVar5 = param_3;
  uVar6 = param_2;
  uVar9 = param_4;
  if (param_4 == 0) {
    uVar3 = param_2 / param_3;
    iVar4 = (int)(((ulonglong)param_2 % (ulonglong)param_3 << 0x20 | (ulonglong)param_1) /
                 (ulonglong)param_3);
  }
  else {
    do {
      uVar8 = uVar9 >> 1;
      uVar5 = uVar5 >> 1 | (uint)((uVar9 & 1) != 0) << 0x1f;
      uVar7 = uVar6 >> 1;
      uVar3 = uVar3 >> 1 | (uint)((uVar6 & 1) != 0) << 0x1f;
      uVar6 = uVar7;
      uVar9 = uVar8;
    } while (uVar8 != 0);
    uVar1 = CONCAT44(uVar7,uVar3) / (ulonglong)uVar5;
    iVar4 = (int)uVar1;
    lVar2 = (ulonglong)param_3 * (uVar1 & 0xffffffff);
    uVar3 = (uint)((ulonglong)lVar2 >> 0x20);
    uVar5 = uVar3 + iVar4 * param_4;
    if (((CARRY4(uVar3,iVar4 * param_4)) || (param_2 < uVar5)) ||
       ((param_2 <= uVar5 && (param_1 < (uint)lVar2)))) {
      iVar4 = iVar4 + -1;
    }
    uVar3 = 0;
  }
  if (cVar11 == '\x01') {
    bVar10 = iVar4 != 0;
    iVar4 = -iVar4;
    uVar3 = -(uint)bVar10 - uVar3;
  }
  return CONCAT44(uVar3,iVar4);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_0044bf1a(int param_1)

{
  bool bVar1;
  
  if (_DAT_00475dc0 == 0) {
    if ((0x60 < param_1) && (param_1 < 0x7b)) {
      return param_1 + -0x20;
    }
  }
  else {
    InterlockedIncrement(&DAT_00478908);
    bVar1 = _DAT_00478904 != 0;
    if (bVar1) {
      InterlockedDecrement(&DAT_00478908);
      FUN_0044f15a(0x13);
    }
    param_1 = FUN_0044bf89(param_1);
    if (bVar1) {
      FUN_0044f1bb(0x13);
    }
    else {
      InterlockedDecrement(&DAT_00478908);
    }
  }
  return param_1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

uint FUN_0044bf89(uint param_1)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  undefined4 uVar4;
  uint uStack_8;
  
  uVar1 = param_1;
  if (_DAT_00475dc0 == 0) {
    if ((0x60 < (int)param_1) && ((int)param_1 < 0x7b)) {
      uVar1 = param_1 - 0x20;
    }
  }
  else {
    if ((int)param_1 < 0x100) {
      if (_DAT_0046ae4c < 2) {
        uVar2 = *(byte *)(_DAT_0046ac40 + param_1 * 2) & 2;
      }
      else {
        uVar2 = FUN_0044e6e0(param_1,2);
      }
      if (uVar2 == 0) {
        return uVar1;
      }
    }
    if ((*(byte *)(_DAT_0046ac40 + 1 + ((int)uVar1 >> 8 & 0xffU) * 2) & 0x80) == 0) {
      param_1 = CONCAT31((int3)(param_1 >> 8),(char)uVar1) & 0xffff00ff;
      uVar4 = 1;
    }
    else {
      uVar2 = param_1 >> 0x10;
      param_1._0_2_ = CONCAT11((char)uVar1,(char)(uVar1 >> 8));
      param_1 = CONCAT22((short)uVar2,(undefined2)param_1) & 0xff00ffff;
      uVar4 = 2;
    }
    iVar3 = FUN_0044f1d0(_DAT_00475dc0,0x200,&param_1,uVar4,&uStack_8,3,0,1);
    if (iVar3 != 0) {
      if (iVar3 == 1) {
        uVar1 = uStack_8 & 0xff;
      }
      else {
        uVar1 = uStack_8 & 0xffff;
      }
    }
  }
  return uVar1;
}



longlong FUN_0044c058(void)

{
  float10 in_ST0;
  
  return (longlong)ROUND(in_ST0);
}



// WARNING: Unable to track spacebase fully for stack

void FUN_0044c080(void)

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



undefined8 FUN_0044c0b0(uint param_1,uint param_2,uint param_3,uint param_4)

{
  ulonglong uVar1;
  longlong lVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  uint uVar11;
  bool bVar12;
  bool bVar13;
  
  bVar13 = (int)param_2 < 0;
  if (bVar13) {
    bVar12 = param_1 != 0;
    param_1 = -param_1;
    param_2 = -(uint)bVar12 - param_2;
  }
  uVar11 = (uint)bVar13;
  if ((int)param_4 < 0) {
    bVar13 = param_3 != 0;
    param_3 = -param_3;
    param_4 = -(uint)bVar13 - param_4;
  }
  uVar3 = param_1;
  uVar4 = param_3;
  uVar8 = param_2;
  uVar9 = param_4;
  if (param_4 == 0) {
    iVar5 = (int)(((ulonglong)param_2 % (ulonglong)param_3 << 0x20 | (ulonglong)param_1) %
                 (ulonglong)param_3);
    iVar6 = 0;
    if ((int)(uVar11 - 1) < 0) goto LAB_0044c15d;
  }
  else {
    do {
      uVar10 = uVar9 >> 1;
      uVar4 = uVar4 >> 1 | (uint)((uVar9 & 1) != 0) << 0x1f;
      uVar7 = uVar8 >> 1;
      uVar3 = uVar3 >> 1 | (uint)((uVar8 & 1) != 0) << 0x1f;
      uVar8 = uVar7;
      uVar9 = uVar10;
    } while (uVar10 != 0);
    uVar1 = CONCAT44(uVar7,uVar3) / (ulonglong)uVar4;
    uVar3 = (int)uVar1 * param_4;
    lVar2 = (uVar1 & 0xffffffff) * (ulonglong)param_3;
    uVar8 = (uint)((ulonglong)lVar2 >> 0x20);
    uVar4 = (uint)lVar2;
    uVar9 = uVar8 + uVar3;
    if (((CARRY4(uVar8,uVar3)) || (param_2 < uVar9)) || ((param_2 <= uVar9 && (param_1 < uVar4)))) {
      bVar13 = uVar4 < param_3;
      uVar4 = uVar4 - param_3;
      uVar9 = (uVar9 - param_4) - (uint)bVar13;
    }
    iVar5 = uVar4 - param_1;
    iVar6 = (uVar9 - param_2) - (uint)(uVar4 < param_1);
    if (-1 < (int)(uVar11 - 1)) goto LAB_0044c15d;
  }
  bVar13 = iVar5 != 0;
  iVar5 = -iVar5;
  iVar6 = -(uint)bVar13 - iVar6;
LAB_0044c15d:
  return CONCAT44(iVar6,iVar5);
}



longlong FUN_0044c170(uint param_1,uint param_2,uint param_3,uint param_4)

{
  if ((param_4 | param_2) == 0) {
    return (ulonglong)param_1 * (ulonglong)param_3;
  }
  return CONCAT44((int)((ulonglong)param_1 * (ulonglong)param_3 >> 0x20) +
                  param_2 * param_3 + param_1 * param_4,
                  (int)((ulonglong)param_1 * (ulonglong)param_3));
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void entry(void)

{
  int iVar1;
  undefined4 uVar2;
  undefined auStack_60 [44];
  uint uStack_34;
  undefined2 uStack_30;
  undefined *puStack_1c;
  undefined4 *puStack_18;
  void *pvStack_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 uStack_8;
  
  uStack_8 = 0xffffffff;
  puStack_c = &UNK_0045f138;
  puStack_10 = &UNK_0045001c;
  pvStack_14 = ExceptionList;
  puStack_1c = &stack0xffffff88;
  ExceptionList = &pvStack_14;
  _DAT_00475d18 = GetVersion();
  _DAT_00475d24 = _DAT_00475d18 >> 8 & 0xff;
  _DAT_00475d20 = _DAT_00475d18 & 0xff;
  _DAT_00475d1c = _DAT_00475d20 * 0x100 + _DAT_00475d24;
  _DAT_00475d18 = _DAT_00475d18 >> 0x10;
  iVar1 = FUN_0044fec6(1);
  if (iVar1 == 0) {
    FUN_0044c2d1(0x1c);
  }
  iVar1 = FUN_0044fbe3();
  if (iVar1 == 0) {
    FUN_0044c2d1(0x10);
  }
  uStack_8 = 0;
  FUN_0044fa27();
  _DAT_0047890c = GetCommandLineA();
  _DAT_00475cf8 = FUN_0044f8f5();
  FUN_0044f6a8();
  FUN_0044f5ef();
  FUN_0044ebf4();
  uStack_34 = 0;
  GetStartupInfoA(auStack_60);
  uVar2 = FUN_0044f597();
  if ((uStack_34 & 1) == 0) {
    uStack_30 = 10;
  }
  uVar2 = GetModuleHandleA(0,0,uVar2,uStack_30);
  uVar2 = FUN_00405d40(uVar2);
  FUN_0044ec21(uVar2);
  FUN_0044f41f(*(undefined4 *)*puStack_18,puStack_18);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0044c2ac(undefined4 param_1)

{
  if (_DAT_00475d00 == 1) {
    FUN_004500f4();
  }
  FUN_0045012d(param_1);
  (*_DAT_0046a830)(0xff);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0044c2d1(undefined4 param_1)

{
  if (_DAT_00475d00 == 1) {
    FUN_004500f4();
  }
  FUN_0045012d(param_1);
                    // WARNING: Subroutine does not return
  ExitProcess(0xff);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

uint FUN_0044c2f5(int param_1)

{
  uint uVar1;
  
  if (1 < _DAT_0046ae4c) {
    uVar1 = FUN_0044e6e0(param_1,0x103);
    return uVar1;
  }
  return *(ushort *)(_DAT_0046ac40 + param_1 * 2) & 0x103;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

uint FUN_0044c323(int param_1)

{
  uint uVar1;
  
  if (1 < _DAT_0046ae4c) {
    uVar1 = FUN_0044e6e0(param_1,1);
    return uVar1;
  }
  return *(byte *)(_DAT_0046ac40 + param_1 * 2) & 1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

uint FUN_0044c34b(int param_1)

{
  uint uVar1;
  
  if (1 < _DAT_0046ae4c) {
    uVar1 = FUN_0044e6e0(param_1,2);
    return uVar1;
  }
  return *(byte *)(_DAT_0046ac40 + param_1 * 2) & 2;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

uint FUN_0044c373(int param_1)

{
  uint uVar1;
  
  if (1 < _DAT_0046ae4c) {
    uVar1 = FUN_0044e6e0(param_1,4);
    return uVar1;
  }
  return *(byte *)(_DAT_0046ac40 + param_1 * 2) & 4;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

uint FUN_0044c39b(int param_1)

{
  uint uVar1;
  
  if (1 < _DAT_0046ae4c) {
    uVar1 = FUN_0044e6e0(param_1,8);
    return uVar1;
  }
  return *(byte *)(_DAT_0046ac40 + param_1 * 2) & 8;
}



undefined4 FUN_0044c3c3(undefined *param_1,undefined4 param_2)

{
  undefined4 uVar1;
  undefined *puStack_24;
  int iStack_20;
  undefined *puStack_1c;
  undefined4 uStack_18;
  
  puStack_1c = param_1;
  puStack_24 = param_1;
  uStack_18 = 0x42;
  iStack_20 = 0x7fffffff;
  uVar1 = FUN_00450398(&puStack_24,param_2,&stack0x0000000c);
  iStack_20 = iStack_20 + -1;
  if (iStack_20 < 0) {
    FUN_00450280(0,&puStack_24);
  }
  else {
    *puStack_24 = 0;
  }
  return uVar1;
}



uint FUN_0044c415(byte *param_1,byte *param_2)

{
  byte bVar1;
  int iVar2;
  int iVar3;
  byte *pbVar4;
  undefined4 *puVar5;
  undefined4 auStack_24 [8];
  
  iVar2 = FUN_0044fc4a();
  puVar5 = auStack_24;
  for (iVar3 = 8; iVar3 != 0; iVar3 = iVar3 + -1) {
    *puVar5 = 0;
    puVar5 = puVar5 + 1;
  }
  do {
    bVar1 = *param_2;
    pbVar4 = (byte *)((int)auStack_24 + (uint)(bVar1 >> 3));
    *pbVar4 = *pbVar4 | '\x01' << (bVar1 & 7);
    param_2 = param_2 + 1;
  } while (bVar1 != 0);
  if (param_1 == (byte *)0x0) {
    param_1 = *(byte **)(iVar2 + 0x18);
  }
  for (; (bVar1 = *param_1, pbVar4 = param_1,
         (*(byte *)((int)auStack_24 + (uint)(bVar1 >> 3)) & (byte)(1 << (bVar1 & 7))) != 0 &&
         (bVar1 != 0)); param_1 = param_1 + 1) {
  }
  do {
    bVar1 = *pbVar4;
    if (bVar1 == 0) {
LAB_0044c4a4:
      *(byte **)(iVar2 + 0x18) = pbVar4;
      return -(uint)(param_1 != pbVar4) & (uint)param_1;
    }
    if ((*(byte *)((int)auStack_24 + (uint)(bVar1 >> 3)) & (byte)(1 << (bVar1 & 7))) != 0) {
      *pbVar4 = 0;
      pbVar4 = pbVar4 + 1;
      goto LAB_0044c4a4;
    }
    pbVar4 = pbVar4 + 1;
  } while( true );
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0044c4b9(int param_1)

{
  int iVar1;
  undefined4 uStack_2c;
  int iStack_28;
  undefined4 uStack_24;
  int iStack_20;
  void *pvStack_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 uStack_8;
  
  uStack_8 = 0xffffffff;
  puStack_c = &UNK_0045f148;
  puStack_10 = &UNK_0045001c;
  pvStack_14 = ExceptionList;
  if (param_1 == 0) {
    return;
  }
  if (_DAT_004777c8 == 3) {
    ExceptionList = &pvStack_14;
    FUN_0044f15a(9);
    uStack_8 = 0;
    iStack_20 = FUN_00450bea(param_1);
    if (iStack_20 != 0) {
      FUN_00450c15(iStack_20,param_1);
    }
    uStack_8 = 0xffffffff;
    FUN_0044c523();
    iVar1 = iStack_20;
  }
  else {
    ExceptionList = &pvStack_14;
    if (_DAT_004777c8 != 2) goto LAB_0044c585;
    ExceptionList = &pvStack_14;
    FUN_0044f15a(9);
    uStack_8 = 1;
    iStack_28 = FUN_00451945(param_1,&uStack_2c,&uStack_24);
    if (iStack_28 != 0) {
      FUN_0045199c(uStack_2c,uStack_24,iStack_28);
    }
    uStack_8 = 0xffffffff;
    FUN_0044c57b();
    iVar1 = iStack_28;
  }
  if (iVar1 != 0) {
    ExceptionList = pvStack_14;
    return;
  }
LAB_0044c585:
  HeapFree(_DAT_004777c4,0,param_1);
  ExceptionList = pvStack_14;
  return;
}



void FUN_0044c523(void)

{
  FUN_0044f1bb(9);
  return;
}



void FUN_0044c57b(void)

{
  FUN_0044f1bb(9);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0044c5a2(undefined4 param_1)

{
  FUN_0044c5b4(param_1,_DAT_00475eec);
  return;
}



int FUN_0044c5b4(uint param_1,int param_2)

{
  int iVar1;
  
  if (param_1 < 0xffffffe1) {
    do {
      iVar1 = FUN_0044c5e0(param_1);
      if (iVar1 != 0) {
        return iVar1;
      }
      if (param_2 == 0) {
        return 0;
      }
      iVar1 = FUN_00451db6(param_1);
    } while (iVar1 != 0);
  }
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0044c5e0(uint param_1)

{
  int iVar1;
  uint uVar2;
  void *pvStack_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 uStack_8;
  
  uStack_8 = 0xffffffff;
  puStack_c = &UNK_0045f160;
  puStack_10 = &UNK_0045001c;
  pvStack_14 = ExceptionList;
  if (_DAT_004777c8 == 3) {
    ExceptionList = &pvStack_14;
    if (param_1 <= _DAT_004777c0) {
      ExceptionList = &pvStack_14;
      FUN_0044f15a(9);
      uStack_8 = 0;
      iVar1 = FUN_00450f3e(param_1);
      uStack_8 = 0xffffffff;
      FUN_0044c647();
      if (iVar1 != 0) {
        ExceptionList = pvStack_14;
        return;
      }
    }
  }
  else {
    ExceptionList = &pvStack_14;
    if (_DAT_004777c8 == 2) {
      if (param_1 == 0) {
        uVar2 = 0x10;
      }
      else {
        uVar2 = param_1 + 0xf & 0xfffffff0;
      }
      ExceptionList = &pvStack_14;
      if (uVar2 <= _DAT_0046d0b4) {
        ExceptionList = &pvStack_14;
        FUN_0044f15a(9);
        uStack_8 = 1;
        iVar1 = FUN_004519e1(uVar2 >> 4);
        uStack_8 = 0xffffffff;
        FUN_0044c6a6();
        if (iVar1 != 0) {
          ExceptionList = pvStack_14;
          return;
        }
      }
      goto LAB_0044c6bf;
    }
  }
  if (param_1 == 0) {
    param_1 = 1;
  }
  uVar2 = param_1 + 0xf & 0xfffffff0;
LAB_0044c6bf:
  HeapAlloc(_DAT_004777c4,0,uVar2);
  ExceptionList = pvStack_14;
  return;
}



void FUN_0044c647(void)

{
  FUN_0044f1bb(9);
  return;
}



void FUN_0044c6a6(void)

{
  FUN_0044f1bb(9);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_0044c6dc(int param_1)

{
  bool bVar1;
  
  if (_DAT_00475dc0 == 0) {
    if ((0x40 < param_1) && (param_1 < 0x5b)) {
      return param_1 + 0x20;
    }
  }
  else {
    InterlockedIncrement(&DAT_00478908);
    bVar1 = _DAT_00478904 != 0;
    if (bVar1) {
      InterlockedDecrement(&DAT_00478908);
      FUN_0044f15a(0x13);
    }
    param_1 = FUN_0044c74b(param_1);
    if (bVar1) {
      FUN_0044f1bb(0x13);
    }
    else {
      InterlockedDecrement(&DAT_00478908);
    }
  }
  return param_1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

uint FUN_0044c74b(uint param_1)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  undefined4 uVar4;
  uint uStack_8;
  
  uVar1 = param_1;
  if (_DAT_00475dc0 == 0) {
    if ((0x40 < (int)param_1) && ((int)param_1 < 0x5b)) {
      uVar1 = param_1 + 0x20;
    }
  }
  else {
    uVar4 = 1;
    if ((int)param_1 < 0x100) {
      if (_DAT_0046ae4c < 2) {
        uVar2 = *(byte *)(_DAT_0046ac40 + param_1 * 2) & 1;
      }
      else {
        uVar2 = FUN_0044e6e0(param_1,1);
      }
      if (uVar2 == 0) {
        return uVar1;
      }
    }
    if ((*(byte *)(_DAT_0046ac40 + 1 + ((int)uVar1 >> 8 & 0xffU) * 2) & 0x80) == 0) {
      param_1 = CONCAT31((int3)(param_1 >> 8),(char)uVar1) & 0xffff00ff;
    }
    else {
      uVar2 = param_1 >> 0x10;
      param_1._0_2_ = CONCAT11((char)uVar1,(char)(uVar1 >> 8));
      param_1 = CONCAT22((short)uVar2,(undefined2)param_1) & 0xff00ffff;
      uVar4 = 2;
    }
    iVar3 = FUN_0044f1d0(_DAT_00475dc0,0x100,&param_1,uVar4,&uStack_8,3,0,1);
    if (iVar3 != 0) {
      if (iVar3 == 1) {
        uVar1 = uStack_8 & 0xff;
      }
      else {
        uVar1 = uStack_8 & 0xffff;
      }
    }
  }
  return uVar1;
}



void FUN_0044c816(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  FUN_0044c82d(param_1,param_2,param_3,0);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

uint FUN_0044c82d(byte *param_1,byte **param_2,uint param_3,uint param_4)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  undefined4 *puVar4;
  byte bVar5;
  uint uVar6;
  uint uStack_c;
  byte *pbStack_8;
  
  uStack_c = 0;
  bVar5 = *param_1;
  pbStack_8 = param_1 + 1;
  while( true ) {
    if (_DAT_0046ae4c < 2) {
      uVar1 = *(byte *)(_DAT_0046ac40 + (uint)bVar5 * 2) & 8;
    }
    else {
      uVar1 = FUN_0044e6e0(bVar5,8);
    }
    if (uVar1 == 0) break;
    bVar5 = *pbStack_8;
    pbStack_8 = pbStack_8 + 1;
  }
  if (bVar5 == 0x2d) {
    param_4 = param_4 | 2;
LAB_0044c888:
    bVar5 = *pbStack_8;
    pbStack_8 = pbStack_8 + 1;
  }
  else if (bVar5 == 0x2b) goto LAB_0044c888;
  if ((((int)param_3 < 0) || (param_3 == 1)) || (0x24 < (int)param_3)) {
    if (param_2 != (byte **)0x0) {
      *param_2 = param_1;
    }
    return 0;
  }
  if (param_3 == 0) {
    if (bVar5 != 0x30) {
      param_3 = 10;
      goto LAB_0044c8f2;
    }
    if ((*pbStack_8 != 0x78) && (*pbStack_8 != 0x58)) {
      param_3 = 8;
      goto LAB_0044c8f2;
    }
    param_3 = 0x10;
  }
  if (((param_3 == 0x10) && (bVar5 == 0x30)) && ((*pbStack_8 == 0x78 || (*pbStack_8 == 0x58)))) {
    bVar5 = pbStack_8[1];
    pbStack_8 = pbStack_8 + 2;
  }
LAB_0044c8f2:
  uVar1 = (uint)(0xffffffff / (ulonglong)param_3);
  do {
    uVar6 = (uint)bVar5;
    if (_DAT_0046ae4c < 2) {
      uVar2 = *(byte *)(_DAT_0046ac40 + uVar6 * 2) & 4;
    }
    else {
      uVar2 = FUN_0044e6e0(uVar6,4);
    }
    if (uVar2 == 0) {
      if (_DAT_0046ae4c < 2) {
        uVar6 = *(ushort *)(_DAT_0046ac40 + uVar6 * 2) & 0x103;
      }
      else {
        uVar6 = FUN_0044e6e0(uVar6,0x103);
      }
      if (uVar6 == 0) {
LAB_0044c99e:
        pbStack_8 = pbStack_8 + -1;
        if ((param_4 & 8) == 0) {
          if (param_2 != (byte **)0x0) {
            pbStack_8 = param_1;
          }
          uStack_c = 0;
        }
        else if (((param_4 & 4) != 0) ||
                (((param_4 & 1) == 0 &&
                 ((((param_4 & 2) != 0 && (0x80000000 < uStack_c)) ||
                  (((param_4 & 2) == 0 && (0x7fffffff < uStack_c)))))))) {
          puVar4 = (undefined4 *)FUN_00451e44();
          *puVar4 = 0x22;
          if ((param_4 & 1) == 0) {
            uStack_c = ((param_4 & 2) != 0) + 0x7fffffff;
          }
          else {
            uStack_c = 0xffffffff;
          }
        }
        if (param_2 != (byte **)0x0) {
          *param_2 = pbStack_8;
        }
        if ((param_4 & 2) == 0) {
          return uStack_c;
        }
        return -uStack_c;
      }
      iVar3 = FUN_0044bf1a((int)(char)bVar5);
      uVar6 = iVar3 - 0x37;
    }
    else {
      uVar6 = (int)(char)bVar5 - 0x30;
    }
    if (param_3 <= uVar6) goto LAB_0044c99e;
    if ((uStack_c < uVar1) ||
       ((uStack_c == uVar1 && (uVar6 <= (uint)(0xffffffff % (ulonglong)param_3))))) {
      uStack_c = uStack_c * param_3 + uVar6;
      param_4 = param_4 | 8;
    }
    else {
      param_4 = param_4 | 0xc;
    }
    bVar5 = *pbStack_8;
    pbStack_8 = pbStack_8 + 1;
  } while( true );
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_0044ca49(int param_1,char *param_2)

{
  int iVar1;
  char *pcVar2;
  int iVar3;
  undefined4 *puVar4;
  char *pcVar5;
  undefined auStack_8c [132];
  int iStack_8;
  
  iVar3 = 0;
  if ((param_1 < 0) || (5 < param_1)) {
    return 0;
  }
  FUN_0044f15a(0x13);
  _DAT_00478904 = _DAT_00478904 + 1;
  while (_DAT_00478908 != 0) {
    Sleep(1);
  }
  if (param_1 == 0) {
    iStack_8 = 1;
    param_1 = 0;
    if (param_2 == (char *)0x0) {
LAB_0044cc6f:
      iVar1 = FUN_0044cdaa();
    }
    else {
      if (((*param_2 == 'L') && (param_2[1] == 'C')) && (param_2[2] == '_')) {
        pcVar2 = (char *)FUN_00452bb0(param_2,&UNK_0045f1bc);
        pcVar5 = param_2;
        while (((pcVar2 != (char *)0x0 && (iStack_8 = (int)pcVar2 - (int)pcVar5, iStack_8 != 0)) &&
               (*pcVar2 != ';'))) {
          param_2 = (char *)0x1;
          puVar4 = (undefined4 *)&DAT_0046a954;
          do {
            iVar3 = FUN_0044d290(*puVar4,pcVar5,iStack_8);
            if ((iVar3 == 0) && (iVar3 = FUN_00452b30(*puVar4), iStack_8 == iVar3)) break;
            param_2 = (char *)((int)param_2 + 1);
            puVar4 = puVar4 + 3;
          } while ((int)puVar4 < 0x46a985);
          pcVar2 = pcVar2 + 1;
          iVar3 = FUN_00452af0(pcVar2,&UNK_0045f1b8);
          if ((iVar3 == 0) && (*pcVar2 != ';')) break;
          if ((int)param_2 < 6) {
            FUN_0044bd70(auStack_8c,pcVar2,iVar3);
            auStack_8c[iVar3] = 0;
            iVar1 = FUN_0044cc8f(param_2,auStack_8c);
            if (iVar1 != 0) {
              param_1 = param_1 + 1;
            }
          }
          if ((pcVar2[iVar3] == '\0') || (pcVar5 = pcVar2 + iVar3 + 1, *pcVar5 == '\0'))
          goto LAB_0044cbd9;
          pcVar2 = (char *)FUN_00452bb0(pcVar5,&UNK_0045f1bc);
        }
        FUN_0044f1bb(0x13);
        iVar1 = 0;
        goto LAB_0044cc7e;
      }
      iVar1 = FUN_0044ce63(param_2,auStack_8c,0,0,0);
      if (iVar1 != 0) {
        puVar4 = (undefined4 *)&DAT_0046a94c;
        do {
          if (puVar4 != (undefined4 *)&DAT_0046a94c) {
            iVar1 = FUN_00452a60(auStack_8c,*puVar4);
            if ((iVar1 == 0) || (iVar1 = FUN_0044cc8f(iVar3,auStack_8c), iVar1 != 0)) {
              param_1 = param_1 + 1;
            }
            else {
              iStack_8 = 0;
            }
          }
          puVar4 = puVar4 + 3;
          iVar3 = iVar3 + 1;
        } while ((int)puVar4 < 0x46a989);
        if (iStack_8 == 0) {
LAB_0044cbd9:
          if (param_1 != 0) goto LAB_0044cc6f;
          iVar1 = 0;
        }
        else {
          iVar1 = FUN_0044cdaa();
          FUN_0044c4b9(_DAT_0046a94c);
          _DAT_0046a94c = 0;
        }
      }
    }
  }
  else if (param_2 == (char *)0x0) {
    iVar1 = *(int *)(&DAT_0046a94c + param_1 * 0xc);
  }
  else {
    iVar1 = FUN_0044cc8f(param_1,param_2);
  }
  FUN_0044f1bb(0x13);
LAB_0044cc7e:
  _DAT_00478904 = _DAT_00478904 + -1;
  return iVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0044cc8f(int param_1,undefined4 param_2)

{
  uint *puVar1;
  int iVar2;
  int iVar3;
  undefined4 uVar4;
  int iVar5;
  int iVar6;
  undefined auStack_a8 [132];
  undefined auStack_24 [8];
  undefined4 uStack_1c;
  uint uStack_18;
  ushort auStack_14 [4];
  int iStack_c;
  undefined4 uStack_8;
  
  iVar3 = FUN_0044ce63(param_2,auStack_a8,auStack_14,&uStack_1c,param_1);
  if (iVar3 != 0) {
    iVar3 = FUN_00452b30(auStack_a8);
    iVar3 = FUN_0044c5a2(iVar3 + 1);
    if (iVar3 != 0) {
      puVar1 = (uint *)(param_1 * 4 + 0x475db8);
      iVar6 = param_1 * 0xc;
      iVar2 = *(int *)(&DAT_0046a94c + iVar6);
      uStack_18 = *puVar1;
      iStack_c = param_1 * 6 + 0x475f10;
      FUN_00452ce0(auStack_24,iStack_c,6);
      uStack_8 = _DAT_00475dd0;
      uVar4 = FUN_00452bf0(iVar3,auStack_a8);
      *(undefined4 *)(&DAT_0046a94c + iVar6) = uVar4;
      *puVar1 = (uint)auStack_14[0];
      FUN_00452ce0(iStack_c,auStack_14,6);
      if (param_1 == 2) {
        _DAT_00475dd0 = uStack_1c;
      }
      if (param_1 == 1) {
        _DAT_00475dd4 = uStack_1c;
      }
      iVar5 = (**(code **)(iVar6 + 0x46a950))();
      if (iVar5 == 0) {
        if (iVar2 != 0x46a838) {
          FUN_0044c4b9(iVar2);
        }
        return *(undefined4 *)(&DAT_0046a94c + iVar6);
      }
      *(int *)(&DAT_0046a94c + iVar6) = iVar2;
      FUN_0044c4b9(iVar3);
      *puVar1 = uStack_18;
      _DAT_00475dd0 = uStack_8;
    }
  }
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined * FUN_0044cdaa(void)

{
  bool bVar1;
  int iVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  
  bVar1 = true;
  if (_DAT_0046a94c == (undefined *)0x0) {
    _DAT_0046a94c = (undefined *)FUN_0044c5a2(0x351);
  }
  *_DAT_0046a94c = 0;
  FUN_0044cf7e(_DAT_0046a94c,3,_DAT_0046a954,&UNK_0045f1c0,_DAT_0046a958);
  puVar3 = (undefined4 *)&DAT_0046a958;
  do {
    FUN_00452c00(_DAT_0046a94c,&UNK_0045f1b8);
    puVar4 = puVar3 + 3;
    iVar2 = FUN_00452a60(*puVar3,puVar3[3]);
    if (iVar2 != 0) {
      bVar1 = false;
    }
    FUN_0044cf7e(_DAT_0046a94c,3,puVar3[2],&UNK_0045f1c0,*puVar4);
    puVar3 = puVar4;
  } while ((int)puVar4 < 0x46a988);
  if (!bVar1) {
    return _DAT_0046a94c;
  }
  FUN_0044c4b9(_DAT_0046a94c);
  _DAT_0046a94c = (undefined *)0x0;
  return _DAT_0046a964;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined * FUN_0044ce63(char *param_1,undefined *param_2,undefined2 *param_3,undefined4 *param_4)

{
  int iVar1;
  undefined *puVar2;
  undefined auStack_8c [136];
  
  if (param_1 == (char *)0x0) {
LAB_0044cf09:
    puVar2 = (undefined *)0x0;
  }
  else {
    if ((*param_1 == 'C') && (param_1[1] == '\0')) {
      param_2[1] = 0;
      *param_2 = 0x43;
      if (param_3 != (undefined2 *)0x0) {
        *param_3 = 0;
        param_3[1] = 0;
        param_3[2] = 0;
      }
      if (param_4 == (undefined4 *)0x0) {
        return param_2;
      }
      *param_4 = 0;
      return param_2;
    }
    iVar1 = FUN_00452a60(0x46a8c0,param_1);
    if ((iVar1 != 0) && (iVar1 = FUN_00452a60(0x46a83c,param_1), iVar1 != 0)) {
      iVar1 = FUN_0044cfa3(auStack_8c,param_1);
      if ((iVar1 != 0) || (iVar1 = FUN_00453015(auStack_8c,0x475d04,auStack_8c), iVar1 == 0))
      goto LAB_0044cf09;
      _DAT_00475d0c = (uint)_DAT_00475d08;
      FUN_0044d06f(0x46a8c0,auStack_8c);
      if (*param_1 == '\0') {
        param_1 = (char *)0x46a8c0;
      }
      FUN_00452bf0(0x46a83c,param_1);
    }
    if (param_3 != (undefined2 *)0x0) {
      FUN_00452ce0(param_3,0x475d04,6);
    }
    if (param_4 != (undefined4 *)0x0) {
      FUN_00452ce0(param_4,&DAT_00475d0c,4);
    }
    FUN_00452bf0(param_2,0x46a8c0);
    puVar2 = (undefined *)0x46a8c0;
  }
  return puVar2;
}



undefined4 FUN_0044cf7b(void)

{
  return 0;
}



void FUN_0044cf7e(undefined4 param_1,int param_2)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  int iVar3;
  
  if (0 < param_2) {
    puVar2 = &param_2;
    iVar3 = param_2;
    do {
      puVar1 = puVar2 + 1;
      puVar2 = puVar2 + 1;
      FUN_00452c00(param_1,*puVar1);
      iVar3 = iVar3 + -1;
    } while (iVar3 != 0);
  }
  return;
}



undefined4 FUN_0044cfa3(int param_1,char *param_2)

{
  char cVar1;
  int iVar2;
  char *pcVar3;
  int iVar4;
  
  pcVar3 = param_2;
  FUN_004538c0(param_1,0,0x88);
  if (*param_2 != '\0') {
    if ((*param_2 != '.') || (param_2[1] == '\0')) {
      param_2 = (char *)0x0;
      while( true ) {
        iVar2 = FUN_00452af0(pcVar3,&UNK_0045f1c4);
        if (iVar2 == 0) {
          return 0xffffffff;
        }
        cVar1 = pcVar3[iVar2];
        if (param_2 == (char *)0x0) {
          if (0x3f < iVar2) {
            return 0xffffffff;
          }
          iVar4 = param_1;
          if (cVar1 == '.') {
            return 0xffffffff;
          }
        }
        else if (param_2 == (char *)0x1) {
          if (0x3f < iVar2) {
            return 0xffffffff;
          }
          if (cVar1 == '_') {
            return 0xffffffff;
          }
          iVar4 = param_1 + 0x40;
        }
        else {
          if (param_2 != (char *)0x2) {
            return 0xffffffff;
          }
          if ((cVar1 != '\0') && (cVar1 != ',')) {
            return 0xffffffff;
          }
          iVar4 = param_1 + 0x80;
        }
        FUN_0044bd70(iVar4,pcVar3,iVar2);
        if (cVar1 == ',') {
          return 0;
        }
        if (cVar1 == '\0') break;
        param_2 = (char *)((int)param_2 + 1);
        pcVar3 = pcVar3 + iVar2 + 1;
      }
      return 0;
    }
    FUN_00452bf0(param_1 + 0x80,param_2 + 1);
  }
  return 0;
}



void FUN_0044d06f(undefined4 param_1,int param_2)

{
  FUN_00452bf0(param_1,param_2);
  if (*(char *)(param_2 + 0x40) != '\0') {
    FUN_0044cf7e(param_1,2,&UNK_0045f1c8,param_2 + 0x40);
  }
  if (*(char *)(param_2 + 0x80) != '\0') {
    FUN_0044cf7e(param_1,2,0x463fa0,param_2 + 0x80);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

float10 FUN_0044d0f6(byte *param_1)

{
  uint uVar1;
  undefined4 uVar2;
  int iVar3;
  undefined auStack_1c [24];
  
  while( true ) {
    if (_DAT_0046ae4c < 2) {
      uVar1 = *(byte *)(_DAT_0046ac40 + (uint)*param_1 * 2) & 8;
    }
    else {
      uVar1 = FUN_0044e6e0(*param_1,8);
    }
    if (uVar1 == 0) break;
    param_1 = param_1 + 1;
  }
  uVar2 = FUN_00452b30(param_1,0,0);
  iVar3 = FUN_004543c9(auStack_1c,param_1,uVar2);
  return (float10)*(double *)(iVar3 + 0x10);
}



int FUN_0044d14d(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                undefined4 param_5,undefined4 param_6)

{
  int iVar1;
  int iVar2;
  
  iVar2 = 0;
  iVar1 = FUN_0044ddbd(1,0x74);
  if (iVar1 != 0) {
    FUN_0044fc37(iVar1);
    *(undefined4 *)(iVar1 + 4) = 0xffffffff;
    *(undefined4 *)(iVar1 + 0x48) = param_3;
    *(undefined4 *)(iVar1 + 0x4c) = param_4;
    iVar2 = CreateThread(param_1,param_2,0x44d1b8,iVar1,param_5,param_6);
    if (iVar2 != 0) {
      return iVar2;
    }
    iVar2 = GetLastError();
  }
  FUN_0044c4b9(iVar1);
  if (iVar2 != 0) {
    FUN_00451dd1(iVar2);
  }
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0044d254(undefined4 param_1)

{
  int iVar1;
  
  if (_DAT_0046a820 != (code *)0x0) {
    (*_DAT_0046a820)();
  }
  iVar1 = FUN_0044fc4a();
  if (iVar1 == 0) {
    FUN_0044c2ac(0x10);
  }
  FUN_0044fcb1(iVar1);
                    // WARNING: Subroutine does not return
  ExitThread(param_1);
}



uint FUN_0044d290(char *param_1,char *param_2,uint param_3)

{
  char cVar1;
  char cVar2;
  byte bVar3;
  uint uVar4;
  int iVar5;
  char *pcVar6;
  char *pcVar7;
  bool bVar8;
  
  uVar4 = param_3;
  pcVar6 = param_1;
  if (param_3 != 0) {
    do {
      if (uVar4 == 0) break;
      uVar4 = uVar4 - 1;
      cVar1 = *pcVar6;
      pcVar6 = pcVar6 + 1;
    } while (cVar1 != '\0');
    iVar5 = param_3 - uVar4;
    do {
      pcVar6 = param_2;
      pcVar7 = param_1;
      if (iVar5 == 0) break;
      iVar5 = iVar5 + -1;
      pcVar7 = param_1 + 1;
      pcVar6 = param_2 + 1;
      cVar1 = *param_2;
      cVar2 = *param_1;
      param_2 = pcVar6;
      param_1 = pcVar7;
    } while (cVar1 == cVar2);
    bVar3 = pcVar6[-1];
    param_3 = 0;
    bVar8 = bVar3 == pcVar7[-1];
    if (bVar3 < (byte)pcVar7[-1] || bVar8) {
      if (bVar8) {
        return 0;
      }
      param_3 = 0xfffffffe;
    }
    param_3 = ~param_3;
  }
  return param_3;
}



uint FUN_0044d3f9(undefined *param_1,uint param_2,uint param_3,int *param_4)

{
  int *piVar1;
  uint uVar2;
  int iVar3;
  undefined *puVar4;
  uint uVar5;
  uint uVar6;
  
  piVar1 = param_4;
  uVar5 = param_2 * param_3;
  if (uVar5 == 0) {
    param_3 = 0;
  }
  else {
    puVar4 = param_1;
    param_1 = (undefined *)uVar5;
    if ((*(ushort *)(param_4 + 3) & 0x10c) == 0) {
      param_4 = (int *)0x1000;
    }
    else {
      param_4 = (int *)param_4[6];
    }
    do {
      if (((*(ushort *)(piVar1 + 3) & 0x10c) == 0) || (uVar2 = piVar1[1], uVar2 == 0)) {
        if (param_1 < param_4) {
          iVar3 = FUN_004546b9(piVar1);
          if (iVar3 == -1) goto LAB_0044d4d5;
          *puVar4 = (char)iVar3;
          param_4 = (int *)piVar1[6];
          puVar4 = puVar4 + 1;
          param_1 = (undefined *)((int)param_1 - 1);
        }
        else {
          uVar2 = (uint)param_1;
          if (param_4 != (int *)0x0) {
            uVar2 = (int)param_1 - (uint)param_1 % (uint)param_4;
          }
          iVar3 = FUN_00454795(piVar1[4],puVar4,uVar2);
          if (iVar3 == 0) {
            piVar1[3] = piVar1[3] | 0x10;
LAB_0044d4d5:
            return (uVar5 - (int)param_1) / param_2;
          }
          if (iVar3 == -1) {
            piVar1[3] = piVar1[3] | 0x20;
            goto LAB_0044d4d5;
          }
          param_1 = (undefined *)((int)param_1 - iVar3);
          puVar4 = puVar4 + iVar3;
        }
      }
      else {
        uVar6 = (uint)param_1;
        if (uVar2 <= param_1) {
          uVar6 = uVar2;
        }
        FUN_00452ce0(puVar4,*piVar1,uVar6);
        param_1 = (undefined *)((int)param_1 - uVar6);
        piVar1[1] = piVar1[1] - uVar6;
        *piVar1 = *piVar1 + uVar6;
        puVar4 = puVar4 + uVar6;
      }
    } while (param_1 != (undefined *)0x0);
  }
  return param_3;
}



uint FUN_0044d4e1(byte param_1,char *param_2)

{
  char cVar1;
  int iVar2;
  int iVar3;
  char *pcVar4;
  uint uVar5;
  
  pcVar4 = param_2;
  if (param_2[1] == ':') {
    pcVar4 = param_2 + 2;
  }
  cVar1 = *pcVar4;
  if ((((cVar1 == '\\') || (cVar1 == '/')) && (pcVar4[1] == '\0')) ||
     (((param_1 & 0x10) != 0 || (uVar5 = 0x8000, cVar1 == '\0')))) {
    uVar5 = 0x4040;
  }
  uVar5 = uVar5 | (uint)(~param_1 & 1 | 2) << 7;
  iVar2 = FUN_0044e077(param_2,0x2e);
  if (iVar2 != 0) {
    iVar3 = FUN_004549d3(iVar2,&UNK_0045f1f4);
    if (iVar3 != 0) {
      iVar3 = FUN_004549d3(iVar2,&UNK_0045f1ec);
      if (iVar3 != 0) {
        iVar3 = FUN_004549d3(iVar2,&UNK_0045f1e4);
        if (iVar3 != 0) {
          iVar2 = FUN_004549d3(iVar2,&UNK_0045f1dc);
          if (iVar2 != 0) goto LAB_0044d582;
        }
      }
    }
    uVar5 = uVar5 | 0x40;
  }
LAB_0044d582:
  return (uVar5 & 0x1c0) >> 6 | uVar5 | uVar5 >> 3 & 0x38;
}



undefined4 FUN_0044d854(char *param_1)

{
  char *pcVar1;
  uint uVar2;
  char *pcVar3;
  char cVar4;
  
  uVar2 = FUN_00452b30(param_1);
  if (((4 < uVar2) && ((*param_1 == '\\' || (*param_1 == '/')))) &&
     ((param_1[1] == '\\' || (param_1[1] == '/')))) {
    pcVar3 = param_1 + 3;
    cVar4 = param_1[3];
    while (((cVar4 != '\0' && (cVar4 != '\\')) && (cVar4 != '/'))) {
      pcVar1 = pcVar3 + 1;
      pcVar3 = pcVar3 + 1;
      cVar4 = *pcVar1;
    }
    if ((*pcVar3 != '\0') && (pcVar3 = pcVar3 + 1, *pcVar3 != '\0')) {
      for (; (cVar4 = *pcVar3, cVar4 != '\0' && ((cVar4 != '\\' && (cVar4 != '/'))));
          pcVar3 = pcVar3 + 1) {
      }
      if ((*pcVar3 == '\0') || (pcVar3[1] == '\0')) {
        return 1;
      }
    }
  }
  return 0;
}



undefined4 FUN_0044d908(undefined4 *param_1,int param_2,void *param_3,undefined4 param_4)

{
  void *pvVar1;
  uint uVar2;
  undefined4 unaff_EBX;
  undefined4 unaff_EBP;
  undefined4 unaff_ESI;
  undefined4 *puVar3;
  undefined4 unaff_EDI;
  undefined4 *puVar4;
  undefined4 unaff_retaddr;
  
  *param_1 = unaff_EBP;
  param_1[1] = unaff_EBX;
  param_1[2] = unaff_EDI;
  param_1[3] = unaff_ESI;
  param_1[4] = register0x00000010;
  param_1[5] = unaff_retaddr;
  param_1[8] = 0x56433230;
  param_1[9] = 0;
  pvVar1 = ExceptionList;
  param_1[6] = ExceptionList;
  if (pvVar1 == (void *)0xffffffff) {
    param_1[7] = 0xffffffff;
  }
  else if ((param_2 == 0) || (param_1[9] = param_3, pvVar1 = param_3, param_2 == 1)) {
    param_1[7] = *(undefined4 *)((int)pvVar1 + 0xc);
  }
  else {
    param_1[7] = param_4;
    uVar2 = param_2 - 2;
    if (uVar2 != 0) {
      puVar3 = (undefined4 *)&stack0x00000014;
      puVar4 = param_1 + 10;
      if (6 < uVar2) {
        uVar2 = 6;
      }
      for (; uVar2 != 0; uVar2 = uVar2 - 1) {
        *puVar4 = *puVar3;
        puVar3 = puVar3 + 1;
        puVar4 = puVar4 + 1;
      }
    }
  }
  return 0;
}



// WARNING: Unable to track spacebase fully for stack

void FUN_0044d984(int param_1)

{
  void *pvVar1;
  int iVar2;
  
  pvVar1 = *(void **)(param_1 + 0x18);
  if (pvVar1 != ExceptionList) {
    FUN_0044ff24(pvVar1);
  }
  if (pvVar1 != (void *)0x0) {
    iVar2 = FUN_00454fc5(param_1 + 0x20);
    if ((iVar2 == 0) || (*(int *)(param_1 + 0x20) != 0x56433230)) {
      FUN_0044ff66(pvVar1,*(undefined4 *)(param_1 + 0x1c));
    }
    else if (*(code **)(param_1 + 0x24) != (code *)0x0) {
      (**(code **)(param_1 + 0x24))(param_1);
    }
  }
  FUN_0044fffa(0);
                    // WARNING: Could not recover jumptable at 0x0044d9f9. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(param_1 + 0x14))();
  return;
}



undefined4 FUN_0044d9fd(undefined4 param_1,undefined4 param_2)

{
  undefined4 uVar1;
  undefined4 uVar2;
  
  FUN_0044daf5(param_1);
  uVar1 = FUN_0045502a(param_1);
  uVar2 = FUN_00450398(param_1,param_2,&stack0x0000000c);
  FUN_004550b7(uVar1,param_1);
  FUN_0044db47(param_1);
  return uVar2;
}



void FUN_0044daf5(uint param_1)

{
  if ((0x46a98f < param_1) && (param_1 < 0x46abf1)) {
    FUN_0044f15a(((int)(param_1 - 0x46a990) >> 5) + 0x1c);
    return;
  }
  EnterCriticalSection(param_1 + 0x20);
  return;
}



void FUN_0044db24(int param_1,int param_2)

{
  if (param_1 < 0x14) {
    FUN_0044f15a(param_1 + 0x1c);
    return;
  }
  EnterCriticalSection(param_2 + 0x20);
  return;
}



void FUN_0044db47(uint param_1)

{
  if ((0x46a98f < param_1) && (param_1 < 0x46abf1)) {
    FUN_0044f1bb(((int)(param_1 - 0x46a990) >> 5) + 0x1c);
    return;
  }
  LeaveCriticalSection(param_1 + 0x20);
  return;
}



void FUN_0044db76(int param_1,int param_2)

{
  if (param_1 < 0x14) {
    FUN_0044f1bb(param_1 + 0x1c);
    return;
  }
  LeaveCriticalSection(param_2 + 0x20);
  return;
}



void FUN_0044dba0(void)

{
  float10 in_ST0;
  float10 in_ST1;
  
  FUN_0044dbc2((double)in_ST1,(double)in_ST0);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0044dbc2(uint param_1,uint param_2,uint param_3,uint param_4)

{
  uint in_EAX;
  uint uVar1;
  undefined4 uVar2;
  byte extraout_CL;
  char extraout_CL_00;
  uint extraout_ECX;
  int extraout_ECX_00;
  int iVar3;
  int extraout_ECX_01;
  bool bVar4;
  short in_FPUControlWord;
  float10 extraout_ST0;
  float10 fVar5;
  float10 extraout_ST1;
  float10 extraout_ST1_00;
  float10 extraout_ST1_01;
  float10 fVar6;
  unkbyte10 in_ST7;
  undefined auStack_78 [106];
  unkbyte10 Stack_e;
  undefined4 uStack_4;
  
  uStack_4 = CONCAT22((short)(in_EAX >> 0x10),in_FPUControlWord);
  uVar1 = in_EAX;
  if (in_FPUControlWord != 0x27f) {
    Stack_e = CONCAT46(0x44dbd6,(undefined6)Stack_e);
    in_EAX = FUN_004555c5();
    uVar1 = extraout_ECX;
  }
  bVar4 = (uVar1 & 0x7ff00000) == 0x7ff00000;
  if (bVar4) {
    if ((in_EAX & 0xfffff | param_3) == 0) {
      Stack_e = CONCAT46(0x44dc9f,(undefined6)Stack_e);
      fVar5 = (float10)FUN_004555f5();
      iVar3 = extraout_ECX_01;
      fVar6 = extraout_ST1_01;
      goto LAB_0044dc9f;
    }
    Stack_e = CONCAT46(0x44dc62,(undefined6)Stack_e);
    fVar5 = (float10)FUN_004555f5();
    if ((param_4 & 0x80000) == 0) {
      iVar3 = extraout_ECX_00 + 1;
      fVar6 = extraout_ST1_00;
      goto LAB_0044dc9f;
    }
LAB_0044dc6c:
    uVar2 = 1;
  }
  else {
    Stack_e = CONCAT46(0x44dbf1,(undefined6)Stack_e);
    uVar1 = FUN_004555f5();
    if (!bVar4) {
      if (((uVar1 & 0x7ff00000) != 0) || ((param_2 & 0xfffff | param_1) != 0)) {
        if ((param_2 & 0x80000000) != 0) {
          Stack_e = CONCAT46(0x44dd77,(undefined6)Stack_e);
          FUN_0044dd95();
          if (extraout_CL_00 == '\0') {
            uVar2 = 1;
            goto LAB_0044dc3a;
          }
        }
        Stack_e = CONCAT46(0x44dc16,(undefined6)Stack_e);
        uVar2 = FUN_004555b0();
        if (_DAT_00475cf0 != 0) {
          return uVar2;
        }
        uVar2 = FUN_00455699();
        return uVar2;
      }
      if ((param_4 & 0x7ff00000) == 0) {
        if ((param_4 & 0xfffff | param_3) != 0) {
          uVar2 = FUN_0045564e();
          return uVar2;
        }
        uVar2 = FUN_0045564e();
        return uVar2;
      }
      Stack_e = CONCAT46(0x44dd1d,(undefined6)Stack_e);
      uVar2 = FUN_0044dd95();
      if ((param_4 & 0x80000000) == 0) {
        if ((param_2._3_1_ >> 7 & extraout_CL) == 0) {
          return uVar2;
        }
        uVar2 = FUN_0045564e();
        return uVar2;
      }
      uVar2 = 2;
      goto LAB_0044dc3a;
    }
    iVar3 = 0;
    fVar5 = extraout_ST0;
    fVar6 = extraout_ST1;
LAB_0044dc9f:
    if (((param_2 & 0x7ff00000) == 0x7ff00000) && ((param_2 & 0xfffff | param_1) != 0)) {
      if ((param_2 & 0x80000) != 0) goto LAB_0044dc6c;
    }
    else if (iVar3 == 0) {
      Stack_e = in_ST7;
      iVar3 = FUN_0045573c((double)fVar5,(double)fVar6,auStack_78);
      if (iVar3 == 0) {
        return 0;
      }
      uVar2 = 1;
      goto LAB_0044dc3a;
    }
    uVar2 = 7;
  }
LAB_0044dc3a:
  if (_DAT_00475cf0 != 0) {
    return uVar2;
  }
  Stack_e = CONCAT46(0x44dc57,(undefined6)Stack_e);
  uVar2 = FUN_00455550();
  return uVar2;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0044dd95(void)

{
  float10 in_ST0;
  
  if (ROUND(in_ST0) == in_ST0) {
    return;
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_0044ddbd(int param_1,int param_2)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  int iStack_24;
  void *pvStack_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 uStack_8;
  
  uStack_8 = 0xffffffff;
  puStack_c = &UNK_0045f208;
  puStack_10 = &UNK_0045001c;
  pvStack_14 = ExceptionList;
  uVar2 = param_1 * param_2;
  uVar3 = uVar2;
  ExceptionList = &pvStack_14;
  if (uVar2 < 0xffffffe1) {
    if (uVar2 == 0) {
      uVar3 = 1;
    }
    uVar3 = uVar3 + 0xf & 0xfffffff0;
    ExceptionList = &pvStack_14;
  }
  do {
    iStack_24 = 0;
    if (uVar3 < 0xffffffe1) {
      if (_DAT_004777c8 == 3) {
        if (uVar2 <= _DAT_004777c0) {
          FUN_0044f15a(9);
          uStack_8 = 0;
          iStack_24 = FUN_00450f3e(uVar2);
          uStack_8 = 0xffffffff;
          FUN_0044de56();
          uVar4 = uVar2;
          if (iStack_24 == 0) goto LAB_0044deaa;
LAB_0044de99:
          FUN_004538c0(iStack_24,0,uVar4);
        }
LAB_0044dea5:
        if (iStack_24 != 0) {
          ExceptionList = pvStack_14;
          return iStack_24;
        }
      }
      else {
        if ((_DAT_004777c8 != 2) || (_DAT_0046d0b4 < uVar3)) goto LAB_0044dea5;
        FUN_0044f15a(9);
        uStack_8 = 1;
        iStack_24 = FUN_004519e1(uVar3 >> 4);
        uStack_8 = 0xffffffff;
        FUN_0044dedf();
        uVar4 = uVar3;
        if (iStack_24 != 0) goto LAB_0044de99;
      }
LAB_0044deaa:
      iStack_24 = HeapAlloc(_DAT_004777c4,8,uVar3);
    }
    if (iStack_24 != 0) {
      ExceptionList = pvStack_14;
      return iStack_24;
    }
    if (_DAT_00475eec == 0) {
      ExceptionList = pvStack_14;
      return 0;
    }
    iVar1 = FUN_00451db6(uVar3);
    if (iVar1 == 0) {
      ExceptionList = pvStack_14;
      return 0;
    }
  } while( true );
}



void FUN_0044de56(void)

{
  FUN_0044f1bb(9);
  return;
}



void FUN_0044dedf(void)

{
  FUN_0044f1bb(9);
  return;
}



undefined4 FUN_0044defa(int param_1)

{
  int iVar1;
  undefined4 uVar2;
  
  if (param_1 != 0) {
    iVar1 = FUN_00452b30(param_1);
    iVar1 = FUN_0044c5a2(iVar1 + 1);
    if (iVar1 != 0) {
      uVar2 = FUN_00452bf0(iVar1,param_1);
      return uVar2;
    }
  }
  return 0;
}



int FUN_0044df2e(short *param_1)

{
  short sVar1;
  short *psVar2;
  
  sVar1 = *param_1;
  psVar2 = param_1 + 1;
  while (sVar1 != 0) {
    sVar1 = *psVar2;
    psVar2 = psVar2 + 1;
  }
  return ((int)psVar2 - (int)param_1 >> 1) + -1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

byte * FUN_0044df4b(byte *param_1,uint param_2)

{
  byte bVar1;
  uint uVar2;
  byte *pbVar3;
  
  if (_DAT_0047758c == 0) {
    param_1 = (byte *)FUN_0044bba0(param_1,param_2);
  }
  else {
    FUN_0044f15a(0x19);
    while( true ) {
      bVar1 = *param_1;
      uVar2 = (uint)bVar1;
      if (bVar1 == 0) break;
      if ((*(byte *)(uVar2 + 0x4776a1) & 4) == 0) {
        pbVar3 = param_1;
        if (param_2 == uVar2) break;
      }
      else {
        pbVar3 = param_1 + 1;
        if (param_1[1] == 0) {
          FUN_0044f1bb(0x19);
          return (byte *)0x0;
        }
        if (param_2 == CONCAT11(bVar1,param_1[1])) {
          FUN_0044f1bb(0x19);
          return param_1;
        }
      }
      param_1 = pbVar3 + 1;
    }
    FUN_0044f1bb(0x19);
    param_1 = (byte *)(~-(uint)(param_2 != uVar2) & (uint)param_1);
  }
  return param_1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

uint FUN_0044dfe2(byte *param_1,byte *param_2)

{
  byte bVar1;
  uint uVar2;
  byte *pbVar3;
  byte *pbVar4;
  
  if (_DAT_0047758c == 0) {
    uVar2 = FUN_00452bb0(param_1,param_2);
    return uVar2;
  }
  FUN_0044f15a(0x19);
  bVar1 = *param_1;
  while (bVar1 != 0) {
    bVar1 = *param_2;
    pbVar3 = param_2;
    while (bVar1 != 0) {
      bVar1 = *pbVar3;
      if ((*(byte *)(bVar1 + 0x4776a1) & 4) == 0) {
        pbVar4 = pbVar3;
        if (bVar1 == *param_1) break;
      }
      else if (((bVar1 == *param_1) && (pbVar3[1] == param_1[1])) ||
              (pbVar4 = pbVar3 + 1, pbVar3[1] == 0)) break;
      pbVar3 = pbVar4 + 1;
      bVar1 = *pbVar3;
    }
    if ((*pbVar3 != 0) ||
       (((*(byte *)(*param_1 + 0x4776a1) & 4) != 0 && (param_1 = param_1 + 1, *param_1 == 0))))
    break;
    param_1 = param_1 + 1;
    bVar1 = *param_1;
  }
  FUN_0044f1bb(0x19);
  return -(uint)(*param_1 != 0) & (uint)param_1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

byte * FUN_0044e077(byte *param_1,uint param_2)

{
  byte bVar1;
  ushort uVar2;
  byte *pbVar3;
  byte bVar4;
  byte *pbVar5;
  bool bVar6;
  
  pbVar5 = (byte *)0x0;
  if (_DAT_0047758c == 0) {
    pbVar5 = (byte *)FUN_00455d40(param_1,param_2);
  }
  else {
    FUN_0044f15a(0x19);
    do {
      bVar4 = *param_1;
      if ((*(byte *)(bVar4 + 0x4776a1) & 4) == 0) {
        bVar6 = param_2 == bVar4;
LAB_0044e0d2:
        pbVar3 = param_1;
        if (bVar6) {
          pbVar5 = param_1;
        }
      }
      else {
        bVar1 = param_1[1];
        pbVar3 = param_1 + 1;
        if (bVar1 == 0) {
          bVar6 = pbVar5 == (byte *)0x0;
          param_1 = pbVar3;
          bVar4 = bVar1;
          goto LAB_0044e0d2;
        }
        uVar2 = CONCAT11(bVar4,bVar1);
        bVar4 = bVar1;
        if (param_2 == uVar2) {
          pbVar5 = param_1;
        }
      }
      param_1 = pbVar3 + 1;
    } while (bVar4 != 0);
    FUN_0044f1bb(0x19);
  }
  return pbVar5;
}



undefined4 FUN_0044e0e9(undefined *param_1,undefined4 param_2,undefined4 param_3)

{
  undefined4 uVar1;
  undefined *puStack_24;
  int iStack_20;
  undefined *puStack_1c;
  undefined4 uStack_18;
  
  puStack_1c = param_1;
  puStack_24 = param_1;
  uStack_18 = 0x42;
  iStack_20 = 0x7fffffff;
  uVar1 = FUN_00450398(&puStack_24,param_2,param_3);
  iStack_20 = iStack_20 + -1;
  if (iStack_20 < 0) {
    FUN_00450280(0,&puStack_24);
  }
  else {
    *puStack_24 = 0;
  }
  return uVar1;
}



char FUN_0044e13a(byte *param_1)

{
  return ((*(byte *)(*param_1 + 0x4776a1) & 4) != 0) + '\x01';
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

uint FUN_0044e150(uint param_1)

{
  int iVar1;
  uint uVar2;
  undefined uVar3;
  undefined4 uStack_8;
  
  if (param_1 < 0x100) {
    if (1 < _DAT_0046ae4c) {
      uVar2 = FUN_0044e6e0(param_1,4);
      return uVar2;
    }
    return *(byte *)(_DAT_0046ac40 + param_1 * 2) & 4;
  }
  uStack_8 = 0;
  uVar3 = (undefined)param_1;
  uVar2 = param_1 >> 8;
  param_1 = CONCAT13(uVar3,CONCAT12((char)uVar2,(undefined2)param_1));
  if (_DAT_0047758c != 0) {
    iVar1 = FUN_00455df0(1,(int)&param_1 + 2,2,&uStack_8,_DAT_00477578,_DAT_004777a4,1);
    if (((iVar1 != 0) && (uStack_8._2_2_ == 0)) && ((uStack_8 & 4) != 0)) {
      return 1;
    }
  }
  return 0;
}



byte * FUN_0044e1df(byte *param_1)

{
  byte *pbVar1;
  
  pbVar1 = param_1 + 1;
  if ((*(byte *)(*param_1 + 0x4776a1) & 4) != 0) {
    pbVar1 = param_1 + 2;
  }
  return pbVar1;
}



void __fastcall FUN_0044e1f6(undefined4 *param_1)

{
  *param_1 = &UNK_0045f224;
  FUN_0044f15a(0x1b);
  if (param_1[1] != 0) {
    FUN_0044c4b9(param_1[1]);
  }
  FUN_0044f1bb(0x1b);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

uint FUN_0044e23b(uint param_1)

{
  int iVar1;
  uint uVar2;
  undefined uVar3;
  undefined4 uStack_8;
  
  if (param_1 < 0x100) {
    if (1 < _DAT_0046ae4c) {
      uVar2 = FUN_0044e6e0(param_1,8);
      return uVar2;
    }
    return *(byte *)(_DAT_0046ac40 + param_1 * 2) & 8;
  }
  uStack_8 = 0;
  uVar3 = (undefined)param_1;
  uVar2 = param_1 >> 8;
  param_1 = CONCAT13(uVar3,CONCAT12((char)uVar2,(undefined2)param_1));
  if (_DAT_0047758c != 0) {
    iVar1 = FUN_00455df0(1,(int)&param_1 + 2,2,&uStack_8,_DAT_00477578,_DAT_004777a4,1);
    if (((iVar1 != 0) && (uStack_8._2_2_ == 0)) && ((uStack_8 & 8) != 0)) {
      return 1;
    }
  }
  return 0;
}



undefined4 * FUN_0044e2d0(undefined4 *param_1,undefined4 *param_2,uint param_3)

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
          goto switchD_0044e487_caseD_2;
        case 3:
          goto switchD_0044e487_caseD_3;
        }
        goto switchD_0044e487_caseD_1;
      }
    }
    else {
      switch(param_3) {
      case 0:
        goto switchD_0044e487_caseD_0;
      case 1:
        goto switchD_0044e487_caseD_1;
      case 2:
        goto switchD_0044e487_caseD_2;
      case 3:
        goto switchD_0044e487_caseD_3;
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
              goto switchD_0044e487_caseD_2;
            case 3:
              goto switchD_0044e487_caseD_3;
            }
            goto switchD_0044e487_caseD_1;
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
              goto switchD_0044e487_caseD_2;
            case 3:
              goto switchD_0044e487_caseD_3;
            }
            goto switchD_0044e487_caseD_1;
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
              goto switchD_0044e487_caseD_2;
            case 3:
              goto switchD_0044e487_caseD_3;
            }
            goto switchD_0044e487_caseD_1;
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
switchD_0044e487_caseD_1:
      *(undefined *)((int)puVar2 + 3) = *(undefined *)((int)param_2 + 3);
      return param_1;
    case 2:
switchD_0044e487_caseD_2:
      *(undefined *)((int)puVar2 + 3) = *(undefined *)((int)param_2 + 3);
      *(undefined *)((int)puVar2 + 2) = *(undefined *)((int)param_2 + 2);
      return param_1;
    case 3:
switchD_0044e487_caseD_3:
      *(undefined *)((int)puVar2 + 3) = *(undefined *)((int)param_2 + 3);
      *(undefined *)((int)puVar2 + 2) = *(undefined *)((int)param_2 + 2);
      *(undefined *)((int)puVar2 + 1) = *(undefined *)((int)param_2 + 1);
      return param_1;
    }
switchD_0044e487_caseD_0:
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
        goto switchD_0044e305_caseD_2;
      case 3:
        goto switchD_0044e305_caseD_3;
      }
      goto switchD_0044e305_caseD_1;
    }
  }
  else {
    switch(param_3) {
    case 0:
      goto switchD_0044e305_caseD_0;
    case 1:
      goto switchD_0044e305_caseD_1;
    case 2:
      goto switchD_0044e305_caseD_2;
    case 3:
      goto switchD_0044e305_caseD_3;
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
            goto switchD_0044e305_caseD_2;
          case 3:
            goto switchD_0044e305_caseD_3;
          }
          goto switchD_0044e305_caseD_1;
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
            goto switchD_0044e305_caseD_2;
          case 3:
            goto switchD_0044e305_caseD_3;
          }
          goto switchD_0044e305_caseD_1;
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
            goto switchD_0044e305_caseD_2;
          case 3:
            goto switchD_0044e305_caseD_3;
          }
          goto switchD_0044e305_caseD_1;
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
switchD_0044e305_caseD_1:
    *(undefined *)puVar2 = *(undefined *)param_2;
    return param_1;
  case 2:
switchD_0044e305_caseD_2:
    *(undefined *)puVar2 = *(undefined *)param_2;
    *(undefined *)((int)puVar2 + 1) = *(undefined *)((int)param_2 + 1);
    return param_1;
  case 3:
switchD_0044e305_caseD_3:
    *(undefined *)puVar2 = *(undefined *)param_2;
    *(undefined *)((int)puVar2 + 1) = *(undefined *)((int)param_2 + 1);
    *(undefined *)((int)puVar2 + 2) = *(undefined *)((int)param_2 + 2);
    return param_1;
  }
switchD_0044e305_caseD_0:
  return param_1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

byte FUN_0044e610(byte *param_1,byte *param_2)

{
  bool bVar1;
  int iVar2;
  byte bVar3;
  byte bVar4;
  byte bVar5;
  uint uVar6;
  
  iVar2 = _DAT_00478908;
  if (_DAT_00475dc0 == 0) {
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
    _DAT_00478908 = _DAT_00478908 + 1;
    UNLOCK();
    bVar1 = 0 < _DAT_00478904;
    if (bVar1) {
      LOCK();
      UNLOCK();
      _DAT_00478908 = iVar2;
      FUN_0044f15a(0x13);
    }
    uVar6 = (uint)bVar1;
    bVar5 = 0xff;
    do {
      do {
        if (bVar5 == 0) goto LAB_0044e6bf;
        bVar5 = *param_2;
        param_2 = param_2 + 1;
        bVar4 = *param_1;
        param_1 = param_1 + 1;
      } while (bVar5 == bVar4);
      bVar4 = FUN_0044c74b(bVar4,bVar5);
      bVar5 = FUN_0044c74b();
    } while (bVar4 == bVar5);
    bVar5 = (bVar4 < bVar5) * -2 + 1;
LAB_0044e6bf:
    if (uVar6 == 0) {
      LOCK();
      _DAT_00478908 = _DAT_00478908 + -1;
      UNLOCK();
    }
    else {
      FUN_0044f1bb(0x13);
    }
  }
  return bVar5;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

uint __thiscall FUN_0044e6e0(undefined4 param_1,int param_2,uint param_3)

{
  int iVar1;
  undefined4 uVar2;
  uint uStack_8;
  
  if (param_2 + 1U < 0x101) {
    param_2._2_2_ = *(ushort *)(_DAT_0046ac40 + param_2 * 2);
  }
  else {
    if ((*(byte *)(_DAT_0046ac40 + 1 + (param_2 >> 8 & 0xffU) * 2) & 0x80) == 0) {
      uStack_8 = CONCAT31((int3)((uint)param_1 >> 8),(char)param_2) & 0xffff00ff;
      uVar2 = 1;
    }
    else {
      uStack_8._0_2_ = CONCAT11((char)param_2,(char)((uint)param_2 >> 8));
      uStack_8 = CONCAT22((short)((uint)param_1 >> 0x10),(undefined2)uStack_8) & 0xff00ffff;
      uVar2 = 2;
    }
    iVar1 = FUN_00455df0(1,&uStack_8,uVar2,(int)&param_2 + 2,0,0,1);
    if (iVar1 == 0) {
      return 0;
    }
  }
  return param_2._2_2_ & param_3;
}



int FUN_0044e8cc(undefined8 *param_1,int param_2,int param_3,undefined4 param_4)

{
  undefined auStack_2c [24];
  int aiStack_14 [4];
  
  FUN_00456566(*param_1,aiStack_14,auStack_2c);
  FUN_004564ef((uint)(0 < param_3) + param_2 + (uint)(aiStack_14[0] == 0x2d),param_3 + 1,aiStack_14)
  ;
  FUN_0044e92d(param_2,param_3,param_4,aiStack_14,0);
  return param_2;
}



undefined * FUN_0044e92d(undefined *param_1,int param_2,int param_3,int *param_4,char param_5)

{
  undefined *puVar1;
  undefined *puVar2;
  int iVar3;
  
  if (param_5 != '\0') {
    FUN_0044ebcf(param_1 + (*param_4 == 0x2d),0 < param_2);
  }
  puVar2 = param_1;
  if (*param_4 == 0x2d) {
    *param_1 = 0x2d;
    puVar2 = param_1 + 1;
  }
  puVar1 = puVar2;
  if (0 < param_2) {
    puVar1 = puVar2 + 1;
    *puVar2 = puVar2[1];
    *puVar1 = DAT_0046ae50;
  }
  puVar2 = (undefined *)FUN_00452bf0(puVar1 + param_2 + (uint)(param_5 == '\0'),&UNK_0045f280);
  if (param_3 != 0) {
    *puVar2 = 0x45;
  }
  if (*(char *)param_4[3] != '0') {
    iVar3 = param_4[1] + -1;
    if (iVar3 < 0) {
      iVar3 = -iVar3;
      puVar2[1] = 0x2d;
    }
    if (99 < iVar3) {
      puVar2[2] = puVar2[2] + (char)(iVar3 / 100);
      iVar3 = iVar3 % 100;
    }
    if (9 < iVar3) {
      puVar2[3] = puVar2[3] + (char)(iVar3 / 10);
      iVar3 = iVar3 % 10;
    }
    puVar2[4] = puVar2[4] + (char)iVar3;
  }
  return param_1;
}



int FUN_0044e9ef(undefined8 *param_1,int param_2,int param_3)

{
  undefined auStack_2c [24];
  int iStack_14;
  int iStack_10;
  
  FUN_00456566(*param_1,&iStack_14,auStack_2c);
  FUN_004564ef((uint)(iStack_14 == 0x2d) + param_2,iStack_10 + param_3,&iStack_14);
  FUN_0044ea44(param_2,param_3,&iStack_14,0);
  return param_2;
}



undefined * FUN_0044ea44(undefined *param_1,int param_2,int *param_3,char param_4)

{
  int iVar1;
  int iVar2;
  undefined *puVar3;
  
  iVar1 = param_3[1];
  if ((param_4 != '\0') && (iVar1 + -1 == param_2)) {
    iVar2 = *param_3;
    param_1[(uint)(iVar2 == 0x2d) + iVar1 + -1] = 0x30;
    (param_1 + (uint)(iVar2 == 0x2d) + iVar1 + -1)[1] = 0;
  }
  puVar3 = param_1;
  if (*param_3 == 0x2d) {
    *param_1 = 0x2d;
    puVar3 = param_1 + 1;
  }
  if (param_3[1] < 1) {
    FUN_0044ebcf(puVar3,1);
    *puVar3 = 0x30;
    puVar3 = puVar3 + 1;
  }
  else {
    puVar3 = puVar3 + param_3[1];
  }
  if (0 < param_2) {
    FUN_0044ebcf(puVar3,1);
    *puVar3 = DAT_0046ae50;
    iVar1 = param_3[1];
    if (iVar1 < 0) {
      if ((param_4 != '\0') || (SBORROW4(param_2,-iVar1) == param_2 + iVar1 < 0)) {
        param_2 = -iVar1;
      }
      FUN_0044ebcf(puVar3 + 1,param_2);
      FUN_004538c0(puVar3 + 1,0x30,param_2);
    }
  }
  return param_1;
}



void FUN_0044eaeb(undefined8 *param_1,int param_2,int param_3,undefined4 param_4)

{
  int iVar1;
  char *pcVar2;
  char *pcVar3;
  undefined auStack_2c [24];
  int iStack_14;
  int iStack_10;
  
  FUN_00456566(*param_1,&iStack_14,auStack_2c);
  iVar1 = iStack_10 + -1;
  pcVar2 = (char *)((uint)(iStack_14 == 0x2d) + param_2);
  FUN_004564ef(pcVar2,param_3,&iStack_14);
  iStack_10 = iStack_10 + -1;
  if ((iStack_10 < -4) || (param_3 <= iStack_10)) {
    FUN_0044e92d(param_2,param_3,param_4,&iStack_14,1);
  }
  else {
    if (iVar1 < iStack_10) {
      do {
        pcVar3 = pcVar2;
        pcVar2 = pcVar3 + 1;
      } while (*pcVar3 != '\0');
      pcVar3[-1] = '\0';
    }
    FUN_0044ea44(param_2,param_3,&iStack_14,1);
  }
  return;
}



void FUN_0044ebcf(int param_1,int param_2)

{
  int iVar1;
  
  if (param_2 != 0) {
    iVar1 = FUN_00452b30(param_1);
    FUN_0044e2d0(param_1 + param_2,param_1,iVar1 + 1);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0044ebf4(void)

{
  if (_DAT_0046a818 != (code *)0x0) {
    (*_DAT_0046a818)();
  }
  FUN_0044ecfa(0x463038,0x46304c);
  FUN_0044ecfa(&DAT_00463000,0x463034);
  return;
}



void FUN_0044ec21(undefined4 param_1)

{
  FUN_0044ec43(param_1,0,0);
  return;
}



void FUN_0044ec32(undefined4 param_1)

{
  FUN_0044ec43(param_1,1,0);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0044ec43(undefined4 param_1,int param_2,int param_3)

{
  undefined4 uVar1;
  code **ppcVar2;
  
  FUN_0044ece8();
  if (_DAT_00475d54 == 1) {
    uVar1 = GetCurrentProcess(param_1);
    TerminateProcess(uVar1);
  }
  _DAT_00475d50 = 1;
  DAT_00475d4c = (undefined)param_3;
  if (param_2 == 0) {
    if ((_DAT_004778f0 != (code **)0x0) &&
       (ppcVar2 = (code **)(_DAT_004778ec - 4), _DAT_004778f0 <= ppcVar2)) {
      do {
        if (*ppcVar2 != (code *)0x0) {
          (**ppcVar2)();
        }
        ppcVar2 = ppcVar2 + -1;
      } while (_DAT_004778f0 <= ppcVar2);
    }
    FUN_0044ecfa(0x463050,0x463058);
  }
  FUN_0044ecfa(0x46305c,0x463064);
  if (param_3 == 0) {
    _DAT_00475d54 = 1;
                    // WARNING: Subroutine does not return
    ExitProcess(param_1);
  }
  FUN_0044ecf1();
  return;
}



void FUN_0044ece8(void)

{
  FUN_0044f15a(0xd);
  return;
}



void FUN_0044ecf1(void)

{
  FUN_0044f1bb(0xd);
  return;
}



void FUN_0044ecfa(code **param_1,code **param_2)

{
  for (; param_1 < param_2; param_1 = param_1 + 1) {
    if (*param_1 != (code *)0x0) {
      (**param_1)();
    }
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

byte * FUN_0044ed14(byte *param_1,uint param_2)

{
  int iVar1;
  uint uVar2;
  byte *pbVar3;
  undefined4 uStack_3c;
  uint uStack_38;
  byte *pbStack_34;
  undefined4 uStack_30;
  int iStack_2c;
  byte *pbStack_28;
  uint uStack_24;
  void *pvStack_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 uStack_8;
  
  uStack_8 = 0xffffffff;
  puStack_c = &UNK_0045f288;
  puStack_10 = &UNK_0045001c;
  pvStack_14 = ExceptionList;
  pbVar3 = (byte *)0x0;
  if (param_1 == (byte *)0x0) {
    ExceptionList = &pvStack_14;
    pbVar3 = (byte *)FUN_0044c5a2(param_2);
  }
  else {
    if (param_2 == 0) {
      ExceptionList = &pvStack_14;
      FUN_0044c4b9(param_1);
    }
    else {
      ExceptionList = &pvStack_14;
      if (_DAT_004777c8 == 3) {
        do {
          pbStack_28 = (byte *)0x0;
          if (param_2 < 0xffffffe1) {
            FUN_0044f15a(9);
            uStack_8 = 0;
            iStack_2c = FUN_00450bea(param_1);
            if (iStack_2c != 0) {
              if (param_2 <= _DAT_004777c0) {
                iVar1 = FUN_004513f3(iStack_2c,param_1,param_2);
                if (iVar1 == 0) {
                  pbStack_28 = (byte *)FUN_00450f3e(param_2);
                  if (pbStack_28 != (byte *)0x0) {
                    uStack_24 = *(int *)(param_1 + -4) - 1;
                    uVar2 = uStack_24;
                    if (param_2 <= uStack_24) {
                      uVar2 = param_2;
                    }
                    FUN_00452ce0(pbStack_28,param_1,uVar2);
                    iStack_2c = FUN_00450bea(param_1);
                    FUN_00450c15(iStack_2c,param_1);
                  }
                }
                else {
                  pbStack_28 = param_1;
                }
              }
              if (pbStack_28 == (byte *)0x0) {
                if (param_2 == 0) {
                  param_2 = 1;
                }
                param_2 = param_2 + 0xf & 0xfffffff0;
                pbStack_28 = (byte *)HeapAlloc(_DAT_004777c4,0,param_2);
                if (pbStack_28 != (byte *)0x0) {
                  uStack_24 = *(int *)(param_1 + -4) - 1;
                  uVar2 = uStack_24;
                  if (param_2 <= uStack_24) {
                    uVar2 = param_2;
                  }
                  FUN_00452ce0(pbStack_28,param_1,uVar2);
                  FUN_00450c15(iStack_2c,param_1);
                }
              }
            }
            uStack_8 = 0xffffffff;
            FUN_0044ee9f();
            if (iStack_2c == 0) {
              if (param_2 == 0) {
                param_2 = 1;
              }
              param_2 = param_2 + 0xf & 0xfffffff0;
              pbStack_28 = (byte *)HeapReAlloc(_DAT_004777c4,0,param_1,param_2);
            }
          }
          if (pbStack_28 != (byte *)0x0) {
            ExceptionList = pvStack_14;
            return pbStack_28;
          }
          if (_DAT_00475eec == (byte *)0x0) {
            ExceptionList = pvStack_14;
            return (byte *)0x0;
          }
          iVar1 = FUN_00451db6(param_2);
        } while (iVar1 != 0);
      }
      else {
        ExceptionList = &pvStack_14;
        if (_DAT_004777c8 == 2) {
          ExceptionList = &pvStack_14;
          if (param_2 < 0xffffffe1) {
            if (param_2 == 0) {
              param_2 = 0x10;
              ExceptionList = &pvStack_14;
            }
            else {
              param_2 = param_2 + 0xf & 0xfffffff0;
              ExceptionList = &pvStack_14;
            }
          }
          do {
            pbStack_28 = pbVar3;
            if (param_2 < 0xffffffe1) {
              FUN_0044f15a(9);
              uStack_8 = 1;
              pbVar3 = (byte *)FUN_00451945(param_1,&uStack_3c,&uStack_30);
              pbStack_34 = pbVar3;
              if (pbVar3 == (byte *)0x0) {
                pbStack_28 = (byte *)HeapReAlloc(_DAT_004777c4,0,param_1,param_2);
              }
              else {
                if (param_2 < _DAT_0046d0b4) {
                  iVar1 = FUN_00451d0d(uStack_3c,uStack_30,pbVar3,param_2 >> 4);
                  if (iVar1 == 0) {
                    pbStack_28 = (byte *)FUN_004519e1(param_2 >> 4);
                    if (pbStack_28 != (byte *)0x0) {
                      uStack_38 = (uint)*pbVar3 << 4;
                      uVar2 = uStack_38;
                      if (param_2 <= uStack_38) {
                        uVar2 = param_2;
                      }
                      FUN_00452ce0(pbStack_28,param_1,uVar2);
                      FUN_0045199c(uStack_3c,uStack_30,pbVar3);
                    }
                  }
                  else {
                    pbStack_28 = param_1;
                  }
                }
                if ((pbStack_28 == (byte *)0x0) &&
                   (pbStack_28 = (byte *)HeapAlloc(_DAT_004777c4,0,param_2),
                   pbStack_28 != (byte *)0x0)) {
                  uStack_38 = (uint)*pbVar3 << 4;
                  uVar2 = uStack_38;
                  if (param_2 <= uStack_38) {
                    uVar2 = param_2;
                  }
                  FUN_00452ce0(pbStack_28,param_1,uVar2);
                  FUN_0045199c(uStack_3c,uStack_30,pbVar3);
                }
              }
              uStack_8 = 0xffffffff;
              FUN_0044efed();
            }
            if (pbStack_28 != pbVar3) {
              ExceptionList = pvStack_14;
              return pbStack_28;
            }
            if (_DAT_00475eec == pbVar3) {
              ExceptionList = pvStack_14;
              return pbStack_28;
            }
            iVar1 = FUN_00451db6(param_2);
          } while (iVar1 != 0);
        }
        else {
          do {
            pbVar3 = (byte *)0x0;
            if (param_2 < 0xffffffe1) {
              if (param_2 == 0) {
                param_2 = 1;
              }
              param_2 = param_2 + 0xf & 0xfffffff0;
              pbVar3 = (byte *)HeapReAlloc(_DAT_004777c4,0,param_1,param_2);
            }
            if (pbVar3 != (byte *)0x0) {
              ExceptionList = pvStack_14;
              return pbVar3;
            }
            if (_DAT_00475eec == (byte *)0x0) {
              ExceptionList = pvStack_14;
              return (byte *)0x0;
            }
            iVar1 = FUN_00451db6(param_2);
          } while (iVar1 != 0);
        }
      }
    }
    pbVar3 = (byte *)0x0;
  }
  ExceptionList = pvStack_14;
  return pbVar3;
}



void FUN_0044ee9f(void)

{
  FUN_0044f1bb(9);
  return;
}



void FUN_0044efed(void)

{
  FUN_0044f1bb(9);
  return;
}



void FUN_0044f0ad(void)

{
  FUN_0044f1bb(9);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0044f0ff(void)

{
  int unaff_EBP;
  undefined4 unaff_ESI;
  bool in_ZF;
  
  if (in_ZF) {
    unaff_ESI = HeapSize(_DAT_004777c4,0,*(undefined4 *)(unaff_EBP + 8));
  }
  ExceptionList = *(void **)(unaff_EBP + -0x10);
  return unaff_ESI;
}



void FUN_0044f128(void)

{
  FUN_0044f1bb(9);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0044f131(void)

{
  InitializeCriticalSection(_DAT_0046aeb4);
  InitializeCriticalSection(_DAT_0046aea4);
  InitializeCriticalSection(_DAT_0046ae94);
  InitializeCriticalSection(_DAT_0046ae74);
  return;
}



void FUN_0044f15a(int param_1)

{
  int *piVar1;
  int iVar2;
  
  piVar1 = (int *)(param_1 * 4 + 0x46ae70);
  if (*(int *)(param_1 * 4 + 0x46ae70) == 0) {
    iVar2 = FUN_0044c5a2(0x18);
    if (iVar2 == 0) {
      FUN_0044c2ac(0x11);
    }
    FUN_0044f15a(0x11);
    if (*piVar1 == 0) {
      InitializeCriticalSection(iVar2);
      *piVar1 = iVar2;
    }
    else {
      FUN_0044c4b9(iVar2);
    }
    FUN_0044f1bb(0x11);
  }
  EnterCriticalSection(*piVar1);
  return;
}



void FUN_0044f1bb(int param_1)

{
  LeaveCriticalSection(*(undefined4 *)(param_1 * 4 + 0x46ae70));
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_0044f1d0(int param_1,uint param_2,undefined4 param_3,int param_4,undefined4 param_5,
                int param_6,int param_7,int param_8)

{
  int iVar1;
  int iVar2;
  int iStack_84;
  uint uStack_80;
  int *piStack_7c;
  int iStack_78;
  undefined4 uStack_74;
  undefined4 uStack_70;
  int iStack_6c;
  undefined4 uStack_68;
  undefined4 uStack_64;
  int iStack_60;
  int *piStack_5c;
  int iStack_58;
  int iStack_54;
  uint uStack_50;
  undefined *puStack_4c;
  int iStack_48;
  undefined4 uStack_44;
  int iStack_40;
  void *pvStack_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 uStack_8;
  
  uStack_8 = 0xffffffff;
  puStack_c = &UNK_0045f2c0;
  puStack_10 = &UNK_0045001c;
  pvStack_14 = ExceptionList;
  ExceptionList = &pvStack_14;
  if (_DAT_00475dd8 == 0) {
    iStack_40 = 0;
    uStack_44 = 0;
    iStack_48 = 1;
    puStack_4c = &UNK_0045f2b8;
    uStack_50 = 0x100;
    iStack_54 = 0;
    iStack_58 = 0x44f218;
    ExceptionList = &pvStack_14;
    iVar1 = LCMapStringW();
    if (iVar1 == 0) {
      iStack_40 = 0;
      uStack_44 = 0;
      iStack_48 = 1;
      puStack_4c = (undefined *)0x4747d4;
      uStack_50 = 0x100;
      iStack_54 = 0;
      iStack_58 = 0x44f234;
      iVar1 = LCMapStringA();
      if (iVar1 == 0) {
        ExceptionList = pvStack_14;
        return 0;
      }
      _DAT_00475dd8 = 2;
    }
    else {
      _DAT_00475dd8 = 1;
    }
  }
  if (0 < param_4) {
    iStack_40 = param_4;
    uStack_44 = param_3;
    iStack_48 = 0x44f256;
    param_4 = FUN_0044f3f4();
  }
  if (_DAT_00475dd8 == 2) {
    iStack_40 = param_6;
    uStack_44 = param_5;
    iStack_48 = param_4;
    puStack_4c = (undefined *)param_3;
    uStack_50 = param_2;
    iStack_54 = param_1;
    iStack_58 = 0x44f27d;
    iVar1 = LCMapStringA();
    ExceptionList = pvStack_14;
    return iVar1;
  }
  if (_DAT_00475dd8 == 1) {
    if (param_7 == 0) {
      param_7 = _DAT_00475dd0;
    }
    iStack_40 = 0;
    uStack_44 = 0;
    iStack_48 = param_4;
    puStack_4c = (undefined *)param_3;
    uStack_50 = (-(uint)(param_8 != 0) & 8) + 1;
    iStack_54 = param_7;
    iStack_58 = 0x44f2b5;
    iVar1 = MultiByteToWideChar();
    if (iVar1 != 0) {
      uStack_8 = 0;
      iStack_58 = 0x44f2d2;
      piStack_5c = &iStack_54;
      piStack_7c = &iStack_54;
      FUN_0044c080();
      uStack_8 = 0xffffffff;
      if (&stack0x00000000 != (undefined *)0x54) {
        iStack_60 = param_4;
        uStack_64 = param_3;
        uStack_68 = 1;
        iStack_6c = param_7;
        uStack_70 = 0x44f30d;
        iStack_58 = iVar1;
        iVar2 = MultiByteToWideChar();
        if (iVar2 != 0) {
          uStack_70 = 0;
          uStack_74 = 0;
          uStack_80 = param_2;
          iStack_84 = param_1;
          iStack_78 = iVar1;
          iVar2 = LCMapStringW();
          if (iVar2 != 0) {
            if ((param_2 & 0x400) == 0) {
              uStack_8 = 1;
              FUN_0044c080();
              uStack_8 = 0xffffffff;
              if (&stack0x00000000 == (undefined *)0x84) {
                ExceptionList = pvStack_14;
                return 0;
              }
              iVar1 = LCMapStringW(param_1,param_2,&iStack_54,iVar1,&iStack_84,iVar2);
              if (iVar1 == 0) {
                ExceptionList = pvStack_14;
                return 0;
              }
              if (param_6 == 0) {
                param_6 = 0;
                param_5 = 0;
              }
              iVar2 = WideCharToMultiByte(param_7,0x220,&iStack_84,iVar2,param_5,param_6,0,0);
              iVar1 = iVar2;
            }
            else {
              if (param_6 == 0) {
                ExceptionList = pvStack_14;
                return iVar2;
              }
              if (param_6 < iVar2) {
                ExceptionList = pvStack_14;
                return 0;
              }
              iVar1 = LCMapStringW(param_1,param_2,&iStack_54,iVar1,param_5,param_6);
            }
            if (iVar1 != 0) {
              ExceptionList = pvStack_14;
              return iVar2;
            }
          }
        }
      }
    }
  }
  ExceptionList = pvStack_14;
  return 0;
}



int FUN_0044f3f4(char *param_1,int param_2)

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

undefined4 FUN_0044f41f(undefined4 param_1,undefined4 param_2)

{
  code *pcVar1;
  undefined4 uVar2;
  int iVar3;
  int *piVar4;
  undefined4 uVar5;
  int iVar6;
  int iVar7;
  
  iVar3 = FUN_0044fc4a();
  piVar4 = (int *)FUN_0044f55d(param_1,*(undefined4 *)(iVar3 + 0x50));
  if ((piVar4 == (int *)0x0) || (pcVar1 = (code *)piVar4[2], pcVar1 == (code *)0x0)) {
    uVar5 = UnhandledExceptionFilter(param_2);
  }
  else if (pcVar1 == (code *)0x5) {
    piVar4[2] = 0;
    uVar5 = 1;
  }
  else {
    if (pcVar1 != (code *)0x1) {
      uVar5 = *(undefined4 *)(iVar3 + 0x54);
      *(undefined4 *)(iVar3 + 0x54) = param_2;
      if (piVar4[1] == 8) {
        if (_DAT_0046afa8 < _DAT_0046afac + _DAT_0046afa8) {
          iVar6 = _DAT_0046afa8 * 0xc;
          iVar7 = _DAT_0046afa8;
          do {
            *(undefined4 *)(iVar6 + 8 + *(int *)(iVar3 + 0x50)) = 0;
            iVar7 = iVar7 + 1;
            iVar6 = iVar6 + 0xc;
          } while (iVar7 < _DAT_0046afac + _DAT_0046afa8);
        }
        iVar6 = *piVar4;
        uVar2 = *(undefined4 *)(iVar3 + 0x58);
        if (iVar6 == -0x3fffff72) {
          *(undefined4 *)(iVar3 + 0x58) = 0x83;
        }
        else if (iVar6 == -0x3fffff70) {
          *(undefined4 *)(iVar3 + 0x58) = 0x81;
        }
        else if (iVar6 == -0x3fffff6f) {
          *(undefined4 *)(iVar3 + 0x58) = 0x84;
        }
        else if (iVar6 == -0x3fffff6d) {
          *(undefined4 *)(iVar3 + 0x58) = 0x85;
        }
        else if (iVar6 == -0x3fffff73) {
          *(undefined4 *)(iVar3 + 0x58) = 0x82;
        }
        else if (iVar6 == -0x3fffff71) {
          *(undefined4 *)(iVar3 + 0x58) = 0x86;
        }
        else if (iVar6 == -0x3fffff6e) {
          *(undefined4 *)(iVar3 + 0x58) = 0x8a;
        }
        (*pcVar1)(8,*(undefined4 *)(iVar3 + 0x58));
        *(undefined4 *)(iVar3 + 0x58) = uVar2;
      }
      else {
        piVar4[2] = 0;
        (*pcVar1)(piVar4[1]);
      }
      *(undefined4 *)(iVar3 + 0x54) = uVar5;
    }
    uVar5 = 0xffffffff;
  }
  return uVar5;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int * FUN_0044f55d(int param_1,int *param_2)

{
  int *piVar1;
  
  piVar1 = param_2;
  if (*param_2 != param_1) {
    do {
      piVar1 = piVar1 + 3;
      if (param_2 + _DAT_0046afb4 * 3 <= piVar1) break;
    } while (*piVar1 != param_1);
  }
  if ((param_2 + _DAT_0046afb4 * 3 <= piVar1) || (*piVar1 != param_1)) {
    piVar1 = (int *)0x0;
  }
  return piVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

byte * FUN_0044f597(void)

{
  byte bVar1;
  int iVar2;
  byte *pbVar3;
  byte *pbVar4;
  
  if (_DAT_004778e8 == 0) {
    FUN_00455ca9();
  }
  bVar1 = *_DAT_0047890c;
  pbVar4 = _DAT_0047890c;
  if (bVar1 == 0x22) {
    while( true ) {
      pbVar3 = pbVar4;
      bVar1 = pbVar3[1];
      pbVar4 = pbVar3 + 1;
      if ((bVar1 == 0x22) || (bVar1 == 0)) break;
      iVar2 = FUN_00456681(bVar1);
      if (iVar2 != 0) {
        pbVar4 = pbVar3 + 2;
      }
    }
    if (*pbVar4 == 0x22) goto LAB_0044f5d4;
  }
  else {
    while (0x20 < bVar1) {
      bVar1 = pbVar4[1];
      pbVar4 = pbVar4 + 1;
    }
  }
  for (; (*pbVar4 != 0 && (*pbVar4 < 0x21)); pbVar4 = pbVar4 + 1) {
LAB_0044f5d4:
  }
  return pbVar4;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0044f5ef(void)

{
  char cVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  char *pcVar5;
  
  if (_DAT_004778e8 == 0) {
    FUN_00455ca9();
  }
  iVar4 = 0;
  for (pcVar5 = _DAT_00475cf8; *pcVar5 != '\0'; pcVar5 = pcVar5 + iVar2 + 1) {
    if (*pcVar5 != '=') {
      iVar4 = iVar4 + 1;
    }
    iVar2 = FUN_00452b30(pcVar5);
  }
  piVar3 = (int *)FUN_0044c5a2(iVar4 * 4 + 4);
  _DAT_00475d34 = piVar3;
  if (piVar3 == (int *)0x0) {
    FUN_0044c2ac(9);
  }
  cVar1 = *_DAT_00475cf8;
  pcVar5 = _DAT_00475cf8;
  while (cVar1 != '\0') {
    iVar4 = FUN_00452b30(pcVar5);
    if (*pcVar5 != '=') {
      iVar2 = FUN_0044c5a2(iVar4 + 1);
      *piVar3 = iVar2;
      if (iVar2 == 0) {
        FUN_0044c2ac(9);
      }
      FUN_00452bf0(*piVar3,pcVar5);
      piVar3 = piVar3 + 1;
    }
    pcVar5 = pcVar5 + iVar4 + 1;
    cVar1 = *pcVar5;
  }
  FUN_0044c4b9(_DAT_00475cf8);
  _DAT_00475cf8 = (char *)0x0;
  *piVar3 = 0;
  _DAT_004778e4 = 1;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0044f6a8(void)

{
  int iVar1;
  char *pcVar2;
  int iStack_c;
  int iStack_8;
  
  if (_DAT_004778e8 == 0) {
    FUN_00455ca9();
  }
  GetModuleFileNameA(0,0x475ddc,0x104);
  _DAT_00475d44 = 0x475ddc;
  pcVar2 = (char *)0x475ddc;
  if (*_DAT_0047890c != '\0') {
    pcVar2 = _DAT_0047890c;
  }
  FUN_0044f741(pcVar2,0,0,&iStack_8,&iStack_c);
  iVar1 = FUN_0044c5a2(iStack_c + iStack_8 * 4);
  if (iVar1 == 0) {
    FUN_0044c2ac(8);
  }
  FUN_0044f741(pcVar2,iVar1,iVar1 + iStack_8 * 4,&iStack_8,&iStack_c);
  _DAT_00475d2c = iVar1;
  _DAT_00475d28 = iStack_8 + -1;
  return;
}



void FUN_0044f741(byte *param_1,byte **param_2,byte *param_3,int *param_4,int *param_5)

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
      if (((*(byte *)(bVar1 + 0x4776a1) & 4) != 0) &&
         (*param_5 = *param_5 + 1, param_3 != (byte *)0x0)) {
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
      if ((*(byte *)(bVar1 + 0x4776a1) & 4) != 0) {
        *param_5 = *param_5 + 1;
        if (param_3 != (byte *)0x0) {
          *param_3 = *pbVar4;
          param_3 = param_3 + 1;
        }
        pbVar4 = param_1 + 2;
      }
      if (bVar1 == 0x20) break;
      if (bVar1 == 0) goto LAB_0044f7ec;
      param_1 = pbVar4;
    } while (bVar1 != 9);
    if (bVar1 == 0) {
LAB_0044f7ec:
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
          if ((*(byte *)(bVar1 + 0x4776a1) & 4) != 0) {
            pbVar4 = pbVar4 + 1;
            *param_5 = *param_5 + 1;
          }
        }
        else {
          if ((*(byte *)(bVar1 + 0x4776a1) & 4) != 0) {
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



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_0044f8f5(void)

{
  char cVar1;
  short sVar2;
  short *psVar3;
  short *psVar4;
  int iVar5;
  int iVar6;
  char *pcVar7;
  int iVar9;
  short *psVar10;
  char *pcVar11;
  undefined4 uVar12;
  char *pcVar8;
  
  iVar9 = 0;
  psVar10 = (short *)0x0;
  pcVar11 = (char *)0x0;
  if (_DAT_00475ee0 == 0) {
    psVar10 = (short *)GetEnvironmentStringsW();
    if (psVar10 != (short *)0x0) {
      _DAT_00475ee0 = 1;
LAB_0044f94c:
      if ((psVar10 == (short *)0x0) &&
         (psVar10 = (short *)GetEnvironmentStringsW(), psVar10 == (short *)0x0)) {
        return 0;
      }
      sVar2 = *psVar10;
      psVar4 = psVar10;
      while (sVar2 != 0) {
        do {
          psVar3 = psVar4;
          psVar4 = psVar3 + 1;
        } while (*psVar4 != 0);
        psVar4 = psVar3 + 2;
        sVar2 = *psVar4;
      }
      uVar12 = 0;
      iVar5 = WideCharToMultiByte(0,0,psVar10,((int)psVar4 - (int)psVar10 >> 1) + 1,0,0,0,0);
      if (((iVar5 != 0) && (iVar6 = FUN_0044c5a2(iVar5), iVar6 != 0)) &&
         (iVar9 = iVar6, iVar5 = WideCharToMultiByte(0,0,psVar10,uVar12,iVar6,iVar5,0,0), iVar5 == 0
         )) {
        FUN_0044c4b9(iVar9);
        iVar9 = 0;
      }
      FreeEnvironmentStringsW(psVar10);
      return iVar9;
    }
    pcVar11 = (char *)GetEnvironmentStrings();
    if (pcVar11 == (char *)0x0) {
      return 0;
    }
    _DAT_00475ee0 = 2;
  }
  else {
    if (_DAT_00475ee0 == 1) goto LAB_0044f94c;
    if (_DAT_00475ee0 != 2) {
      return 0;
    }
  }
  if ((pcVar11 == (char *)0x0) &&
     (pcVar11 = (char *)GetEnvironmentStrings(), pcVar11 == (char *)0x0)) {
    return 0;
  }
  cVar1 = *pcVar11;
  pcVar7 = pcVar11;
  while (cVar1 != '\0') {
    do {
      pcVar8 = pcVar7;
      pcVar7 = pcVar8 + 1;
    } while (*pcVar7 != '\0');
    pcVar7 = pcVar8 + 2;
    cVar1 = *pcVar7;
  }
  iVar9 = FUN_0044c5a2(pcVar7 + (1 - (int)pcVar11));
  if (iVar9 == 0) {
    iVar9 = 0;
  }
  else {
    FUN_00452ce0(iVar9,pcVar11,pcVar7 + (1 - (int)pcVar11));
  }
  FreeEnvironmentStringsA(pcVar11);
  return iVar9;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0044fa27(void)

{
  int *piVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  int iVar5;
  uint uVar6;
  int iVar7;
  undefined auStack_4c [50];
  short sStack_1a;
  int *piStack_18;
  int *piStack_8;
  
  puVar3 = (undefined4 *)FUN_0044c5a2(0x480);
  if (puVar3 == (undefined4 *)0x0) {
    FUN_0044c2ac(0x1b);
  }
  _DAT_004778e0 = 0x20;
  _DAT_004777e0 = puVar3;
  for (; puVar3 < _DAT_004777e0 + 0x120; puVar3 = puVar3 + 9) {
    *(undefined *)(puVar3 + 1) = 0;
    *puVar3 = 0xffffffff;
    puVar3[2] = 0;
    *(undefined *)((int)puVar3 + 5) = 10;
  }
  GetStartupInfoA(auStack_4c);
  if ((sStack_1a != 0) && (piStack_18 != (int *)0x0)) {
    iVar7 = *piStack_18;
    piStack_18 = piStack_18 + 1;
    piStack_8 = (int *)((int)piStack_18 + iVar7);
    if (0x7ff < iVar7) {
      iVar7 = 0x800;
    }
    iVar5 = iVar7;
    if (_DAT_004778e0 < iVar7) {
      puVar3 = (undefined4 *)0x4777e4;
      do {
        puVar4 = (undefined4 *)FUN_0044c5a2(0x480);
        iVar5 = _DAT_004778e0;
        if (puVar4 == (undefined4 *)0x0) break;
        _DAT_004778e0 = _DAT_004778e0 + 0x20;
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
        iVar5 = iVar7;
      } while (_DAT_004778e0 < iVar7);
    }
    uVar6 = 0;
    if (0 < iVar5) {
      do {
        if (((*piStack_8 != -1) && ((*(byte *)piStack_18 & 1) != 0)) &&
           (((*(byte *)piStack_18 & 8) != 0 || (iVar7 = GetFileType(*piStack_8), iVar7 != 0)))) {
          piVar1 = (int *)(*(int *)(&DAT_004777e0 + ((int)uVar6 >> 5) * 4) + (uVar6 & 0x1f) * 0x24);
          *piVar1 = *piStack_8;
          *(byte *)(piVar1 + 1) = *(byte *)piStack_18;
        }
        piStack_8 = piStack_8 + 1;
        uVar6 = uVar6 + 1;
        piStack_18 = (int *)((int)piStack_18 + 1);
      } while ((int)uVar6 < iVar5);
    }
  }
  iVar7 = 0;
  do {
    piVar1 = _DAT_004777e0 + iVar7 * 9;
    if (_DAT_004777e0[iVar7 * 9] == -1) {
      *(undefined *)(piVar1 + 1) = 0x81;
      if (iVar7 == 0) {
        iVar5 = -10;
      }
      else {
        iVar5 = -0xb - (uint)(iVar7 != 1);
      }
      iVar5 = GetStdHandle(iVar5);
      if ((iVar5 != -1) && (uVar6 = GetFileType(iVar5), uVar6 != 0)) {
        *piVar1 = iVar5;
        if ((uVar6 & 0xff) != 2) {
          if ((uVar6 & 0xff) == 3) {
            *(byte *)(piVar1 + 1) = *(byte *)(piVar1 + 1) | 8;
          }
          goto LAB_0044fbcc;
        }
      }
      *(byte *)(piVar1 + 1) = *(byte *)(piVar1 + 1) | 0x40;
    }
    else {
      *(byte *)(piVar1 + 1) = *(byte *)(piVar1 + 1) | 0x80;
    }
LAB_0044fbcc:
    iVar7 = iVar7 + 1;
    if (2 < iVar7) {
      SetHandleCount(_DAT_004778e0);
      return;
    }
  } while( true );
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0044fbe3(void)

{
  undefined4 *puVar1;
  int iVar2;
  undefined4 uVar3;
  
  FUN_0044f131();
  _DAT_0046afdc = TlsAlloc();
  if (_DAT_0046afdc != -1) {
    puVar1 = (undefined4 *)FUN_0044ddbd(1,0x74);
    if (puVar1 != (undefined4 *)0x0) {
      iVar2 = TlsSetValue(_DAT_0046afdc,puVar1);
      if (iVar2 != 0) {
        FUN_0044fc37(puVar1);
        uVar3 = GetCurrentThreadId();
        puVar1[1] = 0xffffffff;
        *puVar1 = uVar3;
        return 1;
      }
    }
  }
  return 0;
}



void FUN_0044fc37(int param_1)

{
  *(undefined4 *)(param_1 + 0x50) = 0x46af30;
  *(undefined4 *)(param_1 + 0x14) = 1;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 * FUN_0044fc4a(void)

{
  undefined4 uVar1;
  undefined4 *puVar2;
  int iVar3;
  undefined4 uVar4;
  
  uVar1 = GetLastError();
  puVar2 = (undefined4 *)TlsGetValue(_DAT_0046afdc);
  if (puVar2 == (undefined4 *)0x0) {
    puVar2 = (undefined4 *)FUN_0044ddbd(1,0x74);
    if (puVar2 != (undefined4 *)0x0) {
      iVar3 = TlsSetValue(_DAT_0046afdc,puVar2);
      if (iVar3 != 0) {
        FUN_0044fc37(puVar2);
        uVar4 = GetCurrentThreadId();
        puVar2[1] = 0xffffffff;
        *puVar2 = uVar4;
        goto LAB_0044fca5;
      }
    }
    FUN_0044c2ac(0x10);
  }
LAB_0044fca5:
  SetLastError(uVar1);
  return puVar2;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0044fcb1(int param_1)

{
  if (_DAT_0046afdc != -1) {
    if ((param_1 != 0) || (param_1 = TlsGetValue(_DAT_0046afdc), param_1 != 0)) {
      if (*(int *)(param_1 + 0x24) != 0) {
        FUN_0044c4b9(*(int *)(param_1 + 0x24));
      }
      if (*(int *)(param_1 + 0x28) != 0) {
        FUN_0044c4b9(*(int *)(param_1 + 0x28));
      }
      if (*(int *)(param_1 + 0x30) != 0) {
        FUN_0044c4b9(*(int *)(param_1 + 0x30));
      }
      if (*(int *)(param_1 + 0x38) != 0) {
        FUN_0044c4b9(*(int *)(param_1 + 0x38));
      }
      if (*(int *)(param_1 + 0x40) != 0) {
        FUN_0044c4b9(*(int *)(param_1 + 0x40));
      }
      if (*(int *)(param_1 + 0x44) != 0) {
        FUN_0044c4b9(*(int *)(param_1 + 0x44));
      }
      if (*(int *)(param_1 + 0x50) != 0x46af30) {
        FUN_0044c4b9(*(int *)(param_1 + 0x50));
      }
      FUN_0044c4b9(param_1);
    }
    TlsSetValue(_DAT_0046afdc,0);
    return;
  }
  return;
}



void FUN_0044fd51(undefined4 *param_1)

{
  int iVar1;
  short *psVar2;
  
  *param_1 = 0;
  psVar2 = (short *)GetModuleHandleA(0);
  if ((*psVar2 == 0x5a4d) && (iVar1 = *(int *)(psVar2 + 0x1e), iVar1 != 0)) {
    *(undefined *)param_1 = *(undefined *)((int)psVar2 + iVar1 + 0x1a);
    *(undefined *)((int)param_1 + 1) = *(undefined *)((int)psVar2 + iVar1 + 0x1b);
  }
  return;
}



int FUN_0044fd7e(void)

{
  char cVar1;
  int iVar2;
  char *pcVar3;
  undefined4 unaff_EBX;
  char acStack_1230 [4240];
  char acStack_1a0 [260];
  undefined4 uStack_9c;
  uint uStack_98;
  int iStack_8c;
  undefined4 uStack_30;
  char *pcStack_2c;
  char *pcStack_28;
  char *pcStack_24;
  char *pcStack_20;
  undefined *puStack_1c;
  undefined *puStack_18;
  char *pcStack_14;
  undefined4 uStack_10;
  undefined4 *puStack_c;
  byte bVar4;
  
  FUN_0044c080();
  puStack_c = &uStack_9c;
  uStack_9c = 0x94;
  uStack_10 = 0x44fda3;
  iVar2 = GetVersionExA();
  if (((iVar2 == 0) || (iStack_8c != 2)) || (uStack_98 < 5)) {
    pcStack_14 = acStack_1230;
    uStack_10 = 0x1090;
    puStack_18 = &UNK_0045f2f0;
    puStack_1c = (undefined *)0x44fdd8;
    iVar2 = GetEnvironmentVariableA();
    bVar4 = (byte)unaff_EBX;
    if (iVar2 != 0) {
      pcVar3 = acStack_1230;
      while (acStack_1230[0] != '\0') {
        cVar1 = *pcVar3;
        if (('`' < cVar1) && (cVar1 < '{')) {
          *pcVar3 = cVar1 + -0x20;
        }
        pcVar3 = pcVar3 + 1;
        acStack_1230[0] = *pcVar3;
      }
      pcStack_20 = acStack_1230;
      puStack_1c = (undefined *)0x16;
      pcStack_24 = "__GLOBAL_HEAP_SELECTED";
      pcStack_28 = (char *)0x44fe16;
      iVar2 = FUN_0044d290();
      bVar4 = (byte)unaff_EBX;
      if (iVar2 == 0) {
        pcStack_20 = acStack_1230;
      }
      else {
        pcStack_20 = acStack_1a0;
        puStack_1c = (undefined *)0x104;
        pcStack_24 = (char *)0x0;
        pcStack_28 = (char *)0x44fe38;
        GetModuleFileNameA();
        bVar4 = (byte)unaff_EBX;
        pcVar3 = acStack_1a0;
        while (acStack_1a0[0] != '\0') {
          cVar1 = *pcVar3;
          if (('`' < cVar1) && (cVar1 < '{')) {
            *pcVar3 = cVar1 + -0x20;
          }
          bVar4 = (byte)unaff_EBX;
          pcVar3 = pcVar3 + 1;
          acStack_1a0[0] = *pcVar3;
        }
        pcStack_28 = acStack_1a0;
        pcStack_2c = acStack_1230;
        uStack_30 = 0x44fe6c;
        pcStack_20 = (char *)FUN_00455d70();
      }
      if (pcStack_20 != (char *)0x0) {
        puStack_1c = (undefined *)0x2c;
        pcStack_24 = (char *)0x44fe7a;
        iVar2 = FUN_0044bba0();
        if (iVar2 != 0) {
          pcStack_24 = (char *)(iVar2 + 1);
          cVar1 = *pcStack_24;
          pcVar3 = pcStack_24;
          while (cVar1 != '\0') {
            if (*pcVar3 == ';') {
              *pcVar3 = '\0';
            }
            else {
              pcVar3 = pcVar3 + 1;
            }
            cVar1 = *pcVar3;
          }
          puStack_1c = (undefined *)0xa;
          pcStack_20 = (char *)0x0;
          pcStack_28 = (char *)0x44fe9e;
          iVar2 = FUN_0044c816();
          if (iVar2 == 2) {
            return 2;
          }
          if (iVar2 == 3) {
            return 3;
          }
          if (iVar2 == 1) {
            return 1;
          }
        }
      }
    }
    puStack_1c = &stack0xfffffff8;
    pcStack_20 = (char *)0x44feb9;
    FUN_0044fd51();
    iVar2 = 3 - (uint)(bVar4 < 6);
  }
  else {
    iVar2 = 1;
  }
  return iVar2;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0044fec6(int param_1)

{
  int iVar1;
  
  _DAT_004777c4 = HeapCreate(param_1 == 0,0x1000,0);
  if (_DAT_004777c4 != 0) {
    _DAT_004777c8 = FUN_0044fd7e();
    if (_DAT_004777c8 == 3) {
      iVar1 = FUN_00450ba2(0x3f8);
    }
    else {
      if (_DAT_004777c8 != 2) {
        return 1;
      }
      iVar1 = FUN_004516e9();
    }
    if (iVar1 != 0) {
      return 1;
    }
    HeapDestroy(_DAT_004777c4);
  }
  return 0;
}



void FUN_0044ff24(undefined4 param_1)

{
  RtlUnwind(param_1,0x44ff3c,0,0,&stack0xfffffffc);
  return;
}



void FUN_0044ff66(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  void *pvStack_1c;
  undefined *puStack_18;
  undefined4 uStack_14;
  int iStack_10;
  
  iStack_10 = param_1;
  puStack_18 = &UNK_0044ff44;
  pvStack_1c = ExceptionList;
  ExceptionList = &pvStack_1c;
  while( true ) {
    iVar1 = *(int *)(param_1 + 8);
    iVar2 = *(int *)(param_1 + 0xc);
    if ((iVar2 == -1) || (iVar2 == param_2)) break;
    uStack_14 = *(undefined4 *)(iVar1 + iVar2 * 0xc);
    *(undefined4 *)(param_1 + 0xc) = uStack_14;
    if (*(int *)(iVar1 + 4 + iVar2 * 0xc) == 0) {
      FUN_0044fffa(0x101);
      (**(code **)(iVar1 + 8 + iVar2 * 0xc))();
    }
  }
  ExceptionList = pvStack_1c;
  return;
}



undefined4 FUN_0044ffce(void)

{
  undefined4 uVar1;
  
  uVar1 = 0;
  if (*(undefined **)((int)ExceptionList + 4) == &UNK_0044ff44) {
    if (*(int *)((int)ExceptionList + 8) == *(int *)(*(int *)((int)ExceptionList + 0xc) + 0xc)) {
      uVar1 = 1;
    }
  }
  return uVar1;
}



void __fastcall FUN_0044fff1(undefined4 param_1)

{
  undefined4 in_EAX;
  undefined4 unaff_EBP;
  
  uRam0046afec = param_1;
  uRam0046afe8 = in_EAX;
  uRam0046aff0 = unaff_EBP;
  return;
}



void FUN_0044fffa(void)

{
  undefined4 in_EAX;
  int unaff_EBP;
  
  uRam0046afec = *(undefined4 *)(unaff_EBP + 8);
  uRam0046afe8 = in_EAX;
  iRam0046aff0 = unaff_EBP;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_004500f4(void)

{
  if ((_DAT_00475d00 == 1) || ((_DAT_00475d00 == 0 && (_DAT_0046a834 == 1)))) {
    FUN_0045012d(0xfc);
    if (_DAT_00475ee4 != (code *)0x0) {
      (*_DAT_00475ee4)();
    }
    FUN_0045012d(0xff);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0045012d(int param_1)

{
  int *piVar1;
  int iVar2;
  undefined auStack_a4 [160];
  
  iVar2 = 0;
  piVar1 = (int *)0x46aff8;
  do {
    if (param_1 == *piVar1) break;
    piVar1 = piVar1 + 2;
    iVar2 = iVar2 + 1;
  } while (piVar1 < &DAT_0046b088);
  if (param_1 == *(int *)(iVar2 * 8 + 0x46aff8)) {
    if ((_DAT_00475d00 == 1) || ((_DAT_00475d00 == 0 && (_DAT_0046a834 == 1)))) {
      FUN_00452b30();
      GetStdHandle();
      WriteFile();
    }
    else if (param_1 != 0xfc) {
      iVar2 = GetModuleFileNameA();
      if (iVar2 == 0) {
        FUN_00452bf0();
      }
      iVar2 = FUN_00452b30();
      if (0x3c < iVar2 + 1U) {
        FUN_00452b30();
        FUN_0044bd70();
      }
      FUN_00452bf0();
      FUN_00452c00();
      FUN_00452c00();
      FUN_00452c00();
      FUN_004566c3(auStack_a4,&UNK_0045f594);
    }
  }
  return;
}



uint FUN_00450280(uint param_1,int *param_2)

{
  uint uVar1;
  uint uVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  
  piVar3 = param_2;
  uVar1 = param_2[3];
  uVar2 = param_2[4];
  if (((uVar1 & 0x82) == 0) || ((uVar1 & 0x40) != 0)) {
LAB_0045038c:
    param_2[3] = uVar1 | 0x20;
  }
  else {
    if ((uVar1 & 1) != 0) {
      param_2[1] = 0;
      if ((uVar1 & 0x10) == 0) goto LAB_0045038c;
      *param_2 = param_2[2];
      param_2[3] = uVar1 & 0xfffffffe;
    }
    uVar1 = param_2[3];
    param_2[1] = 0;
    param_2 = (int *)0x0;
    piVar3[3] = uVar1 & 0xffffffef | 2;
    if (((uVar1 & 0x10c) == 0) &&
       (((piVar3 != (int *)0x46a9b0 && (piVar3 != (int *)0x46a9d0)) ||
        (iVar4 = FUN_00456a58(uVar2), iVar4 == 0)))) {
      FUN_00456a14(piVar3);
    }
    if ((*(ushort *)(piVar3 + 3) & 0x108) == 0) {
      iVar4 = 1;
      param_2 = (int *)FUN_00456824(uVar2,&param_1,1);
    }
    else {
      iVar5 = piVar3[2];
      iVar4 = *piVar3 - iVar5;
      *piVar3 = iVar5 + 1;
      piVar3[1] = piVar3[6] + -1;
      if (iVar4 < 1) {
        if (uVar2 == 0xffffffff) {
          iVar5 = 0x46afb8;
        }
        else {
          iVar5 = *(int *)(&DAT_004777e0 + ((int)uVar2 >> 5) * 4) + (uVar2 & 0x1f) * 0x24;
        }
        if ((*(byte *)(iVar5 + 4) & 0x20) != 0) {
          FUN_0045674c(uVar2,0,2);
        }
      }
      else {
        param_2 = (int *)FUN_00456824(uVar2,iVar5,iVar4);
      }
      *(undefined *)piVar3[2] = (undefined)param_1;
    }
    if (param_2 == (int *)iVar4) {
      return param_1 & 0xff;
    }
    piVar3[3] = piVar3[3] | 0x20;
  }
  return 0xffffffff;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_00450398(undefined4 param_1,byte *param_2,undefined4 *param_3)

{
  short sVar1;
  uint uVar2;
  short *psVar3;
  short *psVar4;
  undefined4 uVar5;
  int *piVar6;
  int iVar7;
  byte bVar8;
  int iVar9;
  undefined *puVar10;
  ulonglong uVar11;
  longlong lVar12;
  undefined auStack_24c [511];
  undefined uStack_4d;
  undefined4 uStack_4c;
  undefined4 uStack_48;
  int iStack_44;
  int iStack_40;
  undefined auStack_3c [4];
  undefined4 uStack_38;
  int iStack_34;
  int iStack_30;
  int iStack_2c;
  int iStack_28;
  int iStack_24;
  int iStack_20;
  undefined uStack_1a;
  char cStack_19;
  int iStack_18;
  int iStack_14;
  undefined *puStack_10;
  short *psStack_c;
  uint uStack_8;
  
  iStack_34 = 0;
  bVar8 = *param_2;
  param_2 = param_2 + 1;
  puStack_10 = (undefined *)0x0;
  iStack_18 = 0;
  do {
    if ((bVar8 == 0) || (iStack_18 < 0)) {
      return iStack_18;
    }
    if (((char)bVar8 < ' ') || ('x' < (char)bVar8)) {
      uVar2 = 0;
    }
    else {
      uVar2 = (byte)(&UNK_0045f5d4)[(char)bVar8] & 0xf;
    }
    iStack_34 = (int)(char)(&UNK_0045f5f4)[uVar2 * 8 + iStack_34] >> 4;
    switch(iStack_34) {
    case 0:
switchD_00450406_caseD_0:
      iStack_28 = 0;
      if ((*(byte *)(_DAT_0046ac40 + 1 + (uint)bVar8 * 2) & 0x80) != 0) {
        FUN_00450ad9((int)(char)bVar8,param_1,&iStack_18);
        bVar8 = *param_2;
        param_2 = param_2 + 1;
      }
      FUN_00450ad9((int)(char)bVar8,param_1,&iStack_18);
      break;
    case 1:
      iStack_14 = -1;
      uStack_38 = 0;
      iStack_2c = 0;
      iStack_24 = 0;
      iStack_20 = 0;
      uStack_8 = 0;
      iStack_28 = 0;
      break;
    case 2:
      if (bVar8 == 0x20) {
        uStack_8 = uStack_8 | 2;
      }
      else if (bVar8 == 0x23) {
        uStack_8 = uStack_8 | 0x80;
      }
      else if (bVar8 == 0x2b) {
        uStack_8 = uStack_8 | 1;
      }
      else if (bVar8 == 0x2d) {
        uStack_8 = uStack_8 | 4;
      }
      else if (bVar8 == 0x30) {
        uStack_8 = uStack_8 | 8;
      }
      break;
    case 3:
      if (bVar8 == 0x2a) {
        iStack_24 = FUN_00450b77(&param_3);
        if (iStack_24 < 0) {
          uStack_8 = uStack_8 | 4;
          iStack_24 = -iStack_24;
        }
      }
      else {
        iStack_24 = (char)bVar8 + -0x30 + iStack_24 * 10;
      }
      break;
    case 4:
      iStack_14 = 0;
      break;
    case 5:
      if (bVar8 == 0x2a) {
        iStack_14 = FUN_00450b77(&param_3);
        if (iStack_14 < 0) {
          iStack_14 = -1;
        }
      }
      else {
        iStack_14 = (char)bVar8 + -0x30 + iStack_14 * 10;
      }
      break;
    case 6:
      if (bVar8 == 0x49) {
        if ((*param_2 != 0x36) || (param_2[1] != 0x34)) {
          iStack_34 = 0;
          goto switchD_00450406_caseD_0;
        }
        param_2 = param_2 + 2;
        uStack_8 = uStack_8 | 0x8000;
      }
      else if (bVar8 == 0x68) {
        uStack_8 = uStack_8 | 0x20;
      }
      else if (bVar8 == 0x6c) {
        uStack_8 = uStack_8 | 0x10;
      }
      else if (bVar8 == 0x77) {
        uStack_8 = uStack_8 | 0x800;
      }
      break;
    case 7:
      psVar4 = psStack_c;
      if ((char)bVar8 < 'h') {
        if ((char)bVar8 < 'e') {
          if ((char)bVar8 < 'Y') {
            if (bVar8 == 0x58) {
LAB_00450817:
              iStack_30 = 7;
LAB_0045081e:
              puStack_10 = (undefined *)0x10;
              if ((uStack_8 & 0x80) != 0) {
                uStack_1a = 0x30;
                cStack_19 = (char)iStack_30 + 'Q';
                iStack_20 = 2;
              }
              goto LAB_00450888;
            }
            if (bVar8 != 0x43) {
              if ((bVar8 != 0x45) && (bVar8 != 0x47)) {
                if (bVar8 == 0x53) {
                  if ((uStack_8 & 0x830) == 0) {
                    uStack_8 = uStack_8 | 0x800;
                  }
                  goto LAB_004505c5;
                }
                goto LAB_004509a2;
              }
              uStack_38 = 1;
              bVar8 = bVar8 + 0x20;
              goto LAB_00450626;
            }
            if ((uStack_8 & 0x830) == 0) {
              uStack_8 = uStack_8 | 0x800;
            }
LAB_00450653:
            if ((uStack_8 & 0x810) == 0) {
              auStack_24c[0] = FUN_00450b77(&param_3);
              puStack_10 = (undefined *)0x1;
            }
            else {
              uVar5 = FUN_00450b94();
              puStack_10 = (undefined *)FUN_00456a81(auStack_24c,uVar5);
              if ((int)puStack_10 < 0) {
                iStack_2c = 1;
              }
            }
            psVar4 = (short *)auStack_24c;
          }
          else if (bVar8 == 0x5a) {
            psVar3 = (short *)FUN_00450b77(&param_3);
            if ((psVar3 == (short *)0x0) ||
               (psVar4 = *(short **)(psVar3 + 2), psVar4 == (short *)0x0)) {
              psStack_c = _DAT_0046b088;
              psVar4 = _DAT_0046b088;
              goto LAB_00450798;
            }
            if ((uStack_8 & 0x800) == 0) {
              iStack_28 = 0;
              puStack_10 = (undefined *)(int)*psVar3;
            }
            else {
              puStack_10 = (undefined *)((uint)(int)*psVar3 >> 1);
              iStack_28 = 1;
            }
          }
          else {
            if (bVar8 == 99) goto LAB_00450653;
            if (bVar8 == 100) goto LAB_0045087d;
          }
        }
        else {
LAB_00450626:
          uStack_8 = uStack_8 | 0x40;
          psVar4 = (short *)auStack_24c;
          if (iStack_14 < 0) {
            iStack_14 = 6;
          }
          else if ((iStack_14 == 0) && (bVar8 == 0x67)) {
            iStack_14 = 1;
          }
          uStack_4c = *param_3;
          uStack_48 = param_3[1];
          param_3 = param_3 + 2;
          psStack_c = psVar4;
          (*_DAT_0046ae58)(&uStack_4c,auStack_24c,(int)(char)bVar8,iStack_14,uStack_38);
          uVar2 = uStack_8 & 0x80;
          if ((uVar2 != 0) && (iStack_14 == 0)) {
            (*_DAT_0046ae64)(auStack_24c);
          }
          if ((bVar8 == 0x67) && (uVar2 == 0)) {
            (*_DAT_0046ae5c)(auStack_24c);
          }
          if (auStack_24c[0] == '-') {
            uStack_8 = uStack_8 | 0x100;
            psVar4 = (short *)(auStack_24c + 1);
            psStack_c = psVar4;
          }
LAB_00450798:
          puStack_10 = (undefined *)FUN_00452b30(psVar4);
          psVar4 = psStack_c;
        }
      }
      else {
        if (bVar8 == 0x69) {
LAB_0045087d:
          uStack_8 = uStack_8 | 0x40;
        }
        else {
          if (bVar8 == 0x6e) {
            piVar6 = (int *)FUN_00450b77(&param_3);
            if ((uStack_8 & 0x20) == 0) {
              *piVar6 = iStack_18;
            }
            else {
              *(undefined2 *)piVar6 = (undefined2)iStack_18;
            }
            iStack_2c = 1;
            break;
          }
          if (bVar8 == 0x6f) {
            puStack_10 = (undefined *)0x8;
            if ((uStack_8 & 0x80) != 0) {
              uStack_8 = uStack_8 | 0x200;
            }
            goto LAB_00450888;
          }
          if (bVar8 == 0x70) {
            iStack_14 = 8;
            goto LAB_00450817;
          }
          if (bVar8 == 0x73) {
LAB_004505c5:
            iVar9 = iStack_14;
            if (iStack_14 == -1) {
              iVar9 = 0x7fffffff;
            }
            psVar3 = (short *)FUN_00450b77(&param_3);
            if ((uStack_8 & 0x810) == 0) {
              psVar4 = psVar3;
              if (psVar3 == (short *)0x0) {
                psVar3 = _DAT_0046b088;
                psVar4 = _DAT_0046b088;
              }
              for (; (iVar9 != 0 && (*(char *)psVar3 != '\0')); psVar3 = (short *)((int)psVar3 + 1))
              {
                iVar9 = iVar9 + -1;
              }
              puStack_10 = (undefined *)((int)psVar3 - (int)psVar4);
            }
            else {
              if (psVar3 == (short *)0x0) {
                psVar3 = _DAT_0046b08c;
              }
              iStack_28 = 1;
              for (psVar4 = psVar3; (iVar9 != 0 && (*psVar4 != 0)); psVar4 = psVar4 + 1) {
                iVar9 = iVar9 + -1;
              }
              puStack_10 = (undefined *)((int)psVar4 - (int)psVar3 >> 1);
              psVar4 = psVar3;
            }
            goto LAB_004509a2;
          }
          if (bVar8 != 0x75) {
            if (bVar8 != 0x78) goto LAB_004509a2;
            iStack_30 = 0x27;
            goto LAB_0045081e;
          }
        }
        puStack_10 = (undefined *)0xa;
LAB_00450888:
        if ((uStack_8 & 0x8000) == 0) {
          if ((uStack_8 & 0x20) == 0) {
            if ((uStack_8 & 0x40) == 0) {
              uVar2 = FUN_00450b77(&param_3);
              uVar11 = (ulonglong)uVar2;
              goto LAB_004508db;
            }
            uVar2 = FUN_00450b77(&param_3);
          }
          else if ((uStack_8 & 0x40) == 0) {
            uVar2 = FUN_00450b77(&param_3);
            uVar2 = uVar2 & 0xffff;
          }
          else {
            sVar1 = FUN_00450b77(&param_3);
            uVar2 = (uint)sVar1;
          }
          uVar11 = (ulonglong)(int)uVar2;
        }
        else {
          uVar11 = FUN_00450b84(&param_3);
        }
LAB_004508db:
        if ((((uStack_8 & 0x40) != 0) && ((longlong)uVar11 < 0x100000000)) && ((longlong)uVar11 < 0)
           ) {
          uVar11 = CONCAT44(-((int)(uVar11 >> 0x20) + (uint)((int)uVar11 != 0)),-(int)uVar11);
          uStack_8 = uStack_8 | 0x100;
        }
        uVar2 = (uint)(uVar11 >> 0x20);
        if ((uStack_8 & 0x8000) == 0) {
          uVar2 = 0;
        }
        lVar12 = CONCAT44(uVar2,(uint)uVar11);
        if (iStack_14 < 0) {
          iStack_14 = 1;
        }
        else {
          uStack_8 = uStack_8 & 0xfffffff7;
        }
        if (((uint)uVar11 | uVar2) == 0) {
          iStack_20 = 0;
        }
        psStack_c = (short *)&uStack_4d;
        while ((iVar9 = iStack_14 + -1, 0 < iStack_14 || (lVar12 != 0))) {
          iStack_40 = (int)puStack_10 >> 0x1f;
          iStack_44 = (int)puStack_10;
          iStack_14 = iVar9;
          iVar9 = FUN_00456bc0(lVar12,puStack_10,iStack_40);
          iVar9 = iVar9 + 0x30;
          lVar12 = FUN_00456b50(lVar12,iStack_44,iStack_40);
          if (0x39 < iVar9) {
            iVar9 = iVar9 + iStack_30;
          }
          psVar4 = (short *)((int)psStack_c + -1);
          *(char *)psStack_c = (char)iVar9;
          psStack_c = psVar4;
        }
        puStack_10 = &uStack_4d + -(int)psStack_c;
        psVar4 = (short *)((int)psStack_c + 1);
        iStack_14 = iVar9;
        if (((uStack_8 & 0x200) != 0) &&
           ((*(char *)psVar4 != '0' || (puStack_10 == (undefined *)0x0)))) {
          puStack_10 = (undefined *)((int)&uStack_4c + -(int)psStack_c);
          *(char *)psStack_c = '0';
          psVar4 = psStack_c;
        }
      }
LAB_004509a2:
      psStack_c = psVar4;
      uVar2 = uStack_8;
      if (iStack_2c == 0) {
        if ((uStack_8 & 0x40) != 0) {
          if ((uStack_8 & 0x100) == 0) {
            if ((uStack_8 & 1) == 0) {
              if ((uStack_8 & 2) == 0) goto LAB_004509da;
              uStack_1a = 0x20;
            }
            else {
              uStack_1a = 0x2b;
            }
          }
          else {
            uStack_1a = 0x2d;
          }
          iStack_20 = 1;
        }
LAB_004509da:
        iVar9 = (iStack_24 - iStack_20) - (int)puStack_10;
        if ((uStack_8 & 0xc) == 0) {
          FUN_00450b0e(0x20,iVar9,param_1,&iStack_18);
        }
        FUN_00450b3f(&uStack_1a,iStack_20,param_1,&iStack_18);
        if (((uVar2 & 8) != 0) && ((uVar2 & 4) == 0)) {
          FUN_00450b0e(0x30,iVar9,param_1,&iStack_18);
        }
        if ((iStack_28 == 0) || (puVar10 = puStack_10, psVar4 = psStack_c, (int)puStack_10 < 1)) {
          FUN_00450b3f(psStack_c,puStack_10,param_1,&iStack_18);
        }
        else {
          do {
            puVar10 = puVar10 + -1;
            iVar7 = FUN_00456a81(auStack_3c,*psVar4);
            if (iVar7 < 1) break;
            FUN_00450b3f(auStack_3c,iVar7,param_1,&iStack_18);
            psVar4 = psVar4 + 1;
          } while (puVar10 != (undefined *)0x0);
        }
        if ((uStack_8 & 4) != 0) {
          FUN_00450b0e(0x20,iVar9,param_1,&iStack_18);
        }
      }
    }
    bVar8 = *param_2;
    param_2 = param_2 + 1;
  } while( true );
}



void FUN_00450ad9(uint param_1,int *param_2,int *param_3)

{
  int *piVar1;
  
  piVar1 = param_2 + 1;
  *piVar1 = *piVar1 + -1;
  if (*piVar1 < 0) {
    param_1 = FUN_00450280(param_1,param_2);
  }
  else {
    *(undefined *)*param_2 = (undefined)param_1;
    *param_2 = *param_2 + 1;
    param_1 = param_1 & 0xff;
  }
  if (param_1 == 0xffffffff) {
    *param_3 = -1;
    return;
  }
  *param_3 = *param_3 + 1;
  return;
}



void FUN_00450b0e(undefined4 param_1,int param_2,undefined4 param_3,int *param_4)

{
  if (0 < param_2) {
    do {
      param_2 = param_2 + -1;
      FUN_00450ad9(param_1,param_3,param_4);
      if (*param_4 == -1) {
        return;
      }
    } while (0 < param_2);
  }
  return;
}



void FUN_00450b3f(char *param_1,int param_2,undefined4 param_3,int *param_4)

{
  char cVar1;
  
  if (0 < param_2) {
    do {
      param_2 = param_2 + -1;
      cVar1 = *param_1;
      param_1 = param_1 + 1;
      FUN_00450ad9((int)cVar1,param_3,param_4);
      if (*param_4 == -1) {
        return;
      }
    } while (0 < param_2);
  }
  return;
}



undefined4 FUN_00450b77(int *param_1)

{
  *param_1 = *param_1 + 4;
  return *(undefined4 *)(*param_1 + -4);
}



undefined8 FUN_00450b84(int *param_1)

{
  *param_1 = *param_1 + 8;
  return *(undefined8 *)(*param_1 + -8);
}



undefined4 FUN_00450b94(int *param_1)

{
  *param_1 = *param_1 + 4;
  return CONCAT22((short)((uint)*param_1 >> 0x10),*(undefined2 *)(*param_1 + -4));
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_00450ba2(undefined4 param_1)

{
  _DAT_004777bc = HeapAlloc(_DAT_004777c4,0,0x140);
  if (_DAT_004777bc == 0) {
    return 0;
  }
  _DAT_004777b4 = 0;
  _DAT_004777b8 = 0;
  _DAT_004777b0 = _DAT_004777bc;
  _DAT_004777c0 = param_1;
  _DAT_004777a8 = 0x10;
  return 1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

uint FUN_00450bea(int param_1)

{
  uint uVar1;
  
  uVar1 = _DAT_004777bc;
  while( true ) {
    if (_DAT_004777bc + _DAT_004777b8 * 0x14 <= uVar1) {
      return 0;
    }
    if ((uint)(param_1 - *(int *)(uVar1 + 0xc)) < 0x100000) break;
    uVar1 = uVar1 + 0x14;
  }
  return uVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00450c15(uint *param_1,int param_2)

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
  uint uStack_8;
  
  uVar5 = param_1[4];
  puVar12 = (uint *)(param_2 + -4);
  uVar14 = param_2 - param_1[3] >> 0xf;
  piVar3 = (int *)(uVar14 * 0x204 + 0x144 + uVar5);
  uVar13 = *puVar12;
  uStack_8 = uVar13 - 1;
  if ((uStack_8 & 1) == 0) {
    uVar6 = *(uint *)(uStack_8 + (int)puVar12);
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
      uStack_8 = uStack_8 + uVar6;
      *(undefined4 *)(*(int *)((int)puVar12 + uVar13 + 7) + 4) =
           *(undefined4 *)((int)puVar12 + uVar13 + 3);
      *(undefined4 *)(*(int *)((int)puVar12 + uVar13 + 3) + 8) =
           *(undefined4 *)((int)puVar12 + uVar13 + 7);
    }
    puVar10 = (uint *)(((int)uStack_8 >> 4) + -1);
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
      uStack_8 = uStack_8 + uVar7;
      puVar10 = (uint *)(((int)uStack_8 >> 4) + -1);
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
    *puVar12 = uStack_8;
    *(uint *)((uStack_8 - 4) + (int)puVar12) = uStack_8;
    *piVar3 = *piVar3 + -1;
    if (*piVar3 == 0) {
      if (_DAT_004777b4 != (uint *)0x0) {
        VirtualFree(_DAT_004777ac * 0x8000 + _DAT_004777b4[3],0x8000,0x4000);
        _DAT_004777b4[2] = _DAT_004777b4[2] | 0x80000000U >> ((byte)_DAT_004777ac & 0x1f);
        *(undefined4 *)(_DAT_004777b4[4] + 0xc4 + _DAT_004777ac * 4) = 0;
        *(char *)(_DAT_004777b4[4] + 0x43) = *(char *)(_DAT_004777b4[4] + 0x43) + -1;
        if (*(char *)(_DAT_004777b4[4] + 0x43) == '\0') {
          _DAT_004777b4[1] = _DAT_004777b4[1] & 0xfffffffe;
        }
        if (_DAT_004777b4[2] == 0xffffffff) {
          VirtualFree(_DAT_004777b4[3],0,0x8000);
          HeapFree(_DAT_004777c4,0,_DAT_004777b4[4]);
          FUN_0044e2d0(_DAT_004777b4,_DAT_004777b4 + 5,
                       (_DAT_004777b8 * 0x14 - (int)_DAT_004777b4) + -0x14 + _DAT_004777bc);
          _DAT_004777b8 = _DAT_004777b8 + -1;
          if (_DAT_004777b4 < param_1) {
            param_1 = param_1 + -5;
          }
          _DAT_004777b0 = _DAT_004777bc;
        }
      }
      _DAT_004777b4 = param_1;
      _DAT_004777ac = uVar14;
    }
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int * FUN_00450f3e(uint *param_1)

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
  uint uStack_10;
  uint uStack_c;
  int iStack_8;
  
  puVar9 = _DAT_004777bc + _DAT_004777b8 * 5;
  uVar7 = (int)param_1 + 0x17U & 0xfffffff0;
  iVar8 = ((int)((int)param_1 + 0x17U) >> 4) + -1;
  bVar6 = (byte)iVar8;
  if (iVar8 < 0x20) {
    uStack_10 = 0xffffffff >> (bVar6 & 0x1f);
    uStack_c = 0xffffffff;
  }
  else {
    uStack_c = 0xffffffff >> (bVar6 - 0x20 & 0x1f);
    uStack_10 = 0;
  }
  param_1 = _DAT_004777b0;
  if (_DAT_004777b0 < puVar9) {
    do {
      if ((param_1[1] & uStack_c | *param_1 & uStack_10) != 0) break;
      param_1 = param_1 + 5;
    } while (param_1 < puVar9);
  }
  puVar13 = _DAT_004777bc;
  if (param_1 == puVar9) {
    for (; (puVar13 < _DAT_004777b0 && ((puVar13[1] & uStack_c | *puVar13 & uStack_10) == 0));
        puVar13 = puVar13 + 5) {
    }
    param_1 = puVar13;
    if (puVar13 == _DAT_004777b0) {
      for (; (puVar13 < puVar9 && (puVar13[2] == 0)); puVar13 = puVar13 + 5) {
      }
      puVar14 = _DAT_004777bc;
      param_1 = puVar13;
      if (puVar13 == puVar9) {
        for (; (puVar14 < _DAT_004777b0 && (puVar14[2] == 0)); puVar14 = puVar14 + 5) {
        }
        param_1 = puVar14;
        if ((puVar14 == _DAT_004777b0) && (param_1 = (uint *)FUN_00451247(), param_1 == (uint *)0x0)
           ) {
          return (int *)0x0;
        }
      }
      uVar5 = FUN_004512f8(param_1);
      *(undefined4 *)param_1[4] = uVar5;
      if (*(int *)param_1[4] == -1) {
        return (int *)0x0;
      }
    }
  }
  piVar4 = (int *)param_1[4];
  iStack_8 = *piVar4;
  if ((iStack_8 == -1) ||
     ((piVar4[iStack_8 + 0x31] & uStack_c | piVar4[iStack_8 + 0x11] & uStack_10) == 0)) {
    iStack_8 = 0;
    puVar9 = (uint *)(piVar4 + 0x11);
    uVar11 = piVar4[0x31] & uStack_c | piVar4[0x11] & uStack_10;
    while (uVar11 == 0) {
      puVar13 = puVar9 + 0x21;
      iStack_8 = iStack_8 + 1;
      puVar9 = puVar9 + 1;
      uVar11 = *puVar13 & uStack_c | uStack_10 & *puVar9;
    }
  }
  iVar8 = 0;
  piVar2 = piVar4 + iStack_8 * 0x81 + 0x51;
  uStack_10 = piVar4[iStack_8 + 0x11] & uStack_10;
  if (uStack_10 == 0) {
    uStack_10 = piVar4[iStack_8 + 0x31] & uStack_c;
    iVar8 = 0x20;
  }
  for (; -1 < (int)uStack_10; uStack_10 = uStack_10 << 1) {
    iVar8 = iVar8 + 1;
  }
  piVar12 = (int *)piVar2[iVar8 * 2 + 1];
  iVar10 = *piVar12 - uVar7;
  iVar15 = (iVar10 >> 4) + -1;
  if (0x3f < iVar15) {
    iVar15 = 0x3f;
  }
  _DAT_004777b0 = param_1;
  if (iVar15 != iVar8) {
    if (piVar12[1] == piVar12[2]) {
      if (iVar8 < 0x20) {
        pcVar1 = (char *)((int)piVar4 + iVar8 + 4);
        uVar11 = ~(0x80000000U >> ((byte)iVar8 & 0x1f));
        piVar4[iStack_8 + 0x11] = uVar11 & piVar4[iStack_8 + 0x11];
        *pcVar1 = *pcVar1 + -1;
        if (*pcVar1 == '\0') {
          *param_1 = *param_1 & uVar11;
        }
      }
      else {
        pcVar1 = (char *)((int)piVar4 + iVar8 + 4);
        uVar11 = ~(0x80000000U >> ((byte)iVar8 - 0x20 & 0x1f));
        piVar4[iStack_8 + 0x31] = piVar4[iStack_8 + 0x31] & uVar11;
        *pcVar1 = *pcVar1 + -1;
        if (*pcVar1 == '\0') {
          param_1[1] = param_1[1] & uVar11;
        }
      }
    }
    *(int *)(piVar12[2] + 4) = piVar12[1];
    *(int *)(piVar12[1] + 8) = piVar12[2];
    if (iVar10 == 0) goto LAB_00451204;
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
        piVar4[iStack_8 + 0x11] = piVar4[iStack_8 + 0x11] | 0x80000000U >> (bVar6 & 0x1f);
      }
      else {
        *(char *)(iVar15 + 4 + (int)piVar4) = cVar3 + '\x01';
        if (cVar3 == '\0') {
          param_1[1] = param_1[1] | 0x80000000U >> (bVar6 - 0x20 & 0x1f);
        }
        piVar4[iStack_8 + 0x31] = piVar4[iStack_8 + 0x31] | 0x80000000U >> (bVar6 - 0x20 & 0x1f);
      }
    }
  }
  if (iVar10 != 0) {
    *piVar12 = iVar10;
    *(int *)(iVar10 + -4 + (int)piVar12) = iVar10;
  }
LAB_00451204:
  piVar12 = (int *)((int)piVar12 + iVar10);
  *piVar12 = uVar7 + 1;
  *(uint *)((int)piVar12 + (uVar7 - 4)) = uVar7 + 1;
  iVar8 = *piVar2;
  *piVar2 = iVar8 + 1;
  if (((iVar8 == 0) && (param_1 == _DAT_004777b4)) && (iStack_8 == _DAT_004777ac)) {
    _DAT_004777b4 = (uint *)0x0;
  }
  *piVar4 = iStack_8;
  return piVar12 + 1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 * FUN_00451247(void)

{
  undefined4 *puVar1;
  int iVar2;
  
  if (_DAT_004777b8 == _DAT_004777a8) {
    iVar2 = HeapReAlloc(_DAT_004777c4,0,_DAT_004777bc,(_DAT_004777a8 * 5 + 0x50) * 4);
    if (iVar2 == 0) {
      return (undefined4 *)0x0;
    }
    _DAT_004777a8 = _DAT_004777a8 + 0x10;
    _DAT_004777bc = iVar2;
  }
  puVar1 = (undefined4 *)(_DAT_004777bc + _DAT_004777b8 * 0x14);
  iVar2 = HeapAlloc(_DAT_004777c4,8,0x41c4);
  puVar1[4] = iVar2;
  if (iVar2 != 0) {
    iVar2 = VirtualAlloc(0,0x100000,0x2000,4);
    puVar1[3] = iVar2;
    if (iVar2 != 0) {
      puVar1[2] = 0xffffffff;
      *puVar1 = 0;
      puVar1[1] = 0;
      _DAT_004777b8 = _DAT_004777b8 + 1;
      *(undefined4 *)puVar1[4] = 0xffffffff;
      return puVar1;
    }
    HeapFree(_DAT_004777c4,0,puVar1[4]);
  }
  return (undefined4 *)0x0;
}



int FUN_004512f8(int param_1)

{
  int *piVar1;
  char cVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int *piVar6;
  int iVar7;
  int iVar8;
  int *piVar9;
  
  iVar3 = *(int *)(param_1 + 0x10);
  iVar8 = 0;
  for (iVar4 = *(int *)(param_1 + 8); -1 < iVar4; iVar4 = iVar4 << 1) {
    iVar8 = iVar8 + 1;
  }
  iVar7 = 0x3f;
  iVar4 = iVar8 * 0x204 + 0x144 + iVar3;
  iVar5 = iVar4;
  do {
    *(int *)(iVar5 + 8) = iVar5;
    *(int *)(iVar5 + 4) = iVar5;
    iVar5 = iVar5 + 8;
    iVar7 = iVar7 + -1;
  } while (iVar7 != 0);
  piVar9 = (int *)(iVar8 * 0x8000 + *(int *)(param_1 + 0xc));
  iVar5 = VirtualAlloc(piVar9,0x8000,0x1000,4);
  if (iVar5 == 0) {
    iVar8 = -1;
  }
  else {
    if (piVar9 <= piVar9 + 0x1c00) {
      piVar6 = piVar9 + 4;
      do {
        piVar6[-2] = -1;
        piVar6[0x3fb] = -1;
        piVar6[-1] = 0xff0;
        *piVar6 = (int)(piVar6 + 0x3ff);
        piVar6[1] = (int)(piVar6 + -0x401);
        piVar6[0x3fa] = 0xff0;
        piVar1 = piVar6 + 0x3fc;
        piVar6 = piVar6 + 0x400;
      } while (piVar1 <= piVar9 + 0x1c00);
    }
    *(int **)(iVar4 + 0x1fc) = piVar9 + 3;
    piVar9[5] = iVar4 + 0x1f8;
    *(int **)(iVar4 + 0x200) = piVar9 + 0x1c03;
    piVar9[0x1c04] = iVar4 + 0x1f8;
    *(undefined4 *)(iVar3 + 0x44 + iVar8 * 4) = 0;
    *(undefined4 *)(iVar3 + 0xc4 + iVar8 * 4) = 1;
    cVar2 = *(char *)(iVar3 + 0x43);
    *(char *)(iVar3 + 0x43) = cVar2 + '\x01';
    if (cVar2 == '\0') {
      *(uint *)(param_1 + 4) = *(uint *)(param_1 + 4) | 1;
    }
    *(uint *)(param_1 + 8) = *(uint *)(param_1 + 8) & ~(0x80000000U >> ((byte)iVar8 & 0x1f));
  }
  return iVar8;
}



undefined4 FUN_004513f3(uint *param_1,int param_2,int param_3)

{
  char *pcVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  char cVar5;
  uint uVar6;
  int iVar7;
  uint *puVar8;
  byte bVar9;
  uint uVar10;
  uint uVar11;
  uint uVar12;
  uint uVar13;
  uint uStack_c;
  
  uVar6 = param_1[4];
  uVar12 = param_3 + 0x17U & 0xfffffff0;
  uVar10 = param_2 - param_1[3] >> 0xf;
  iVar4 = uVar10 * 0x204 + 0x144 + uVar6;
  iVar7 = *(int *)(param_2 + -4);
  param_3 = iVar7 + -1;
  uVar13 = *(uint *)(iVar7 + -5 + param_2);
  iVar7 = iVar7 + -5 + param_2;
  if (param_3 < (int)uVar12) {
    if (((uVar13 & 1) != 0) || ((int)(uVar13 + param_3) < (int)uVar12)) {
      return 0;
    }
    uStack_c = ((int)uVar13 >> 4) - 1;
    if (0x3f < uStack_c) {
      uStack_c = 0x3f;
    }
    if (*(int *)(iVar7 + 4) == *(int *)(iVar7 + 8)) {
      if (uStack_c < 0x20) {
        pcVar1 = (char *)(uStack_c + 4 + uVar6);
        uVar11 = ~(0x80000000U >> ((byte)uStack_c & 0x1f));
        puVar8 = (uint *)(uVar6 + 0x44 + uVar10 * 4);
        *puVar8 = *puVar8 & uVar11;
        *pcVar1 = *pcVar1 + -1;
        if (*pcVar1 == '\0') {
          *param_1 = *param_1 & uVar11;
        }
      }
      else {
        pcVar1 = (char *)(uStack_c + 4 + uVar6);
        uVar11 = ~(0x80000000U >> ((byte)uStack_c - 0x20 & 0x1f));
        puVar8 = (uint *)(uVar6 + 0xc4 + uVar10 * 4);
        *puVar8 = *puVar8 & uVar11;
        *pcVar1 = *pcVar1 + -1;
        if (*pcVar1 == '\0') {
          param_1[1] = param_1[1] & uVar11;
        }
      }
    }
    *(undefined4 *)(*(int *)(iVar7 + 8) + 4) = *(undefined4 *)(iVar7 + 4);
    *(undefined4 *)(*(int *)(iVar7 + 4) + 8) = *(undefined4 *)(iVar7 + 8);
    iVar7 = uVar13 + (param_3 - uVar12);
    if (0 < iVar7) {
      uVar13 = (iVar7 >> 4) - 1;
      iVar2 = param_2 + -4 + uVar12;
      if (0x3f < uVar13) {
        uVar13 = 0x3f;
      }
      iVar4 = iVar4 + uVar13 * 8;
      *(undefined4 *)(iVar2 + 4) = *(undefined4 *)(iVar4 + 4);
      *(int *)(iVar2 + 8) = iVar4;
      *(int *)(iVar4 + 4) = iVar2;
      *(int *)(*(int *)(iVar2 + 4) + 8) = iVar2;
      if (*(int *)(iVar2 + 4) == *(int *)(iVar2 + 8)) {
        cVar5 = *(char *)(uVar13 + 4 + uVar6);
        *(char *)(uVar13 + 4 + uVar6) = cVar5 + '\x01';
        bVar9 = (byte)uVar13;
        if (uVar13 < 0x20) {
          if (cVar5 == '\0') {
            *param_1 = *param_1 | 0x80000000U >> (bVar9 & 0x1f);
          }
          puVar8 = (uint *)(uVar6 + 0x44 + uVar10 * 4);
        }
        else {
          if (cVar5 == '\0') {
            param_1[1] = param_1[1] | 0x80000000U >> (bVar9 - 0x20 & 0x1f);
          }
          puVar8 = (uint *)(uVar6 + 0xc4 + uVar10 * 4);
          bVar9 = bVar9 - 0x20;
        }
        *puVar8 = *puVar8 | 0x80000000U >> (bVar9 & 0x1f);
      }
      piVar3 = (int *)(param_2 + -4 + uVar12);
      *piVar3 = iVar7;
      *(int *)(iVar7 + -4 + (int)piVar3) = iVar7;
    }
    *(uint *)(param_2 + -4) = uVar12 + 1;
    *(uint *)(param_2 + -8 + uVar12) = uVar12 + 1;
  }
  else if ((int)uVar12 < param_3) {
    param_3 = param_3 - uVar12;
    *(uint *)(param_2 + -4) = uVar12 + 1;
    piVar3 = (int *)(param_2 + -4 + uVar12);
    uVar11 = (param_3 >> 4) - 1;
    piVar3[-1] = uVar12 + 1;
    if (0x3f < uVar11) {
      uVar11 = 0x3f;
    }
    if ((uVar13 & 1) == 0) {
      uVar12 = ((int)uVar13 >> 4) - 1;
      if (0x3f < uVar12) {
        uVar12 = 0x3f;
      }
      if (*(int *)(iVar7 + 4) == *(int *)(iVar7 + 8)) {
        if (uVar12 < 0x20) {
          pcVar1 = (char *)(uVar12 + 4 + uVar6);
          uVar12 = ~(0x80000000U >> ((byte)uVar12 & 0x1f));
          puVar8 = (uint *)(uVar6 + 0x44 + uVar10 * 4);
          *puVar8 = *puVar8 & uVar12;
          *pcVar1 = *pcVar1 + -1;
          if (*pcVar1 == '\0') {
            *param_1 = *param_1 & uVar12;
          }
        }
        else {
          pcVar1 = (char *)(uVar12 + 4 + uVar6);
          uVar12 = ~(0x80000000U >> ((byte)uVar12 - 0x20 & 0x1f));
          puVar8 = (uint *)(uVar6 + 0xc4 + uVar10 * 4);
          *puVar8 = *puVar8 & uVar12;
          *pcVar1 = *pcVar1 + -1;
          if (*pcVar1 == '\0') {
            param_1[1] = param_1[1] & uVar12;
          }
        }
      }
      *(undefined4 *)(*(int *)(iVar7 + 8) + 4) = *(undefined4 *)(iVar7 + 4);
      *(undefined4 *)(*(int *)(iVar7 + 4) + 8) = *(undefined4 *)(iVar7 + 8);
      param_3 = param_3 + uVar13;
      uVar11 = (param_3 >> 4) - 1;
      if (0x3f < uVar11) {
        uVar11 = 0x3f;
      }
    }
    iVar7 = iVar4 + uVar11 * 8;
    piVar3[1] = *(int *)(iVar4 + 4 + uVar11 * 8);
    piVar3[2] = iVar7;
    *(int **)(iVar7 + 4) = piVar3;
    *(int **)(piVar3[1] + 8) = piVar3;
    if (piVar3[1] == piVar3[2]) {
      cVar5 = *(char *)(uVar11 + 4 + uVar6);
      *(char *)(uVar11 + 4 + uVar6) = cVar5 + '\x01';
      bVar9 = (byte)uVar11;
      if (uVar11 < 0x20) {
        if (cVar5 == '\0') {
          *param_1 = *param_1 | 0x80000000U >> (bVar9 & 0x1f);
        }
        puVar8 = (uint *)(uVar6 + 0x44 + uVar10 * 4);
      }
      else {
        if (cVar5 == '\0') {
          param_1[1] = param_1[1] | 0x80000000U >> (bVar9 - 0x20 & 0x1f);
        }
        puVar8 = (uint *)(uVar6 + 0xc4 + uVar10 * 4);
        bVar9 = bVar9 - 0x20;
      }
      *puVar8 = *puVar8 | 0x80000000U >> (bVar9 & 0x1f);
    }
    *piVar3 = param_3;
    *(int *)(param_3 + -4 + (int)piVar3) = param_3;
  }
  return 1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 * FUN_004516e9(void)

{
  bool bVar1;
  int *piVar2;
  int iVar3;
  int *piVar4;
  undefined4 *puVar5;
  
  if (_DAT_0046b0a0 == -1) {
    puVar5 = (undefined4 *)&DAT_0046b090;
  }
  else {
    puVar5 = (undefined4 *)HeapAlloc(_DAT_004777c4,0,0x2020);
    if (puVar5 == (undefined4 *)0x0) {
      return (undefined4 *)0x0;
    }
  }
  piVar2 = (int *)VirtualAlloc(0,0x400000,0x2000,4);
  if (piVar2 != (int *)0x0) {
    iVar3 = VirtualAlloc(piVar2,0x10000,0x1000,4);
    if (iVar3 != 0) {
      if (puVar5 == (undefined4 *)&DAT_0046b090) {
        if (_DAT_0046b090 == (undefined *)0x0) {
          _DAT_0046b090 = &DAT_0046b090;
        }
        if (_DAT_0046b094 == (undefined4 *)0x0) {
          _DAT_0046b094 = (undefined4 *)&DAT_0046b090;
        }
      }
      else {
        *puVar5 = &DAT_0046b090;
        puVar5[1] = _DAT_0046b094;
        _DAT_0046b094 = puVar5;
        *(undefined4 **)puVar5[1] = puVar5;
      }
      puVar5[5] = piVar2 + 0x100000;
      piVar4 = puVar5 + 6;
      puVar5[3] = puVar5 + 0x26;
      puVar5[4] = piVar2;
      puVar5[2] = piVar4;
      iVar3 = 0;
      do {
        bVar1 = 0xf < iVar3;
        iVar3 = iVar3 + 1;
        *piVar4 = (bVar1 - 1 & 0xf1) - 1;
        piVar4[1] = 0xf1;
        piVar4 = piVar4 + 2;
      } while (iVar3 < 0x400);
      FUN_004538c0(piVar2,0,0x10000);
      for (; piVar2 < (int *)(puVar5[4] + 0x10000); piVar2 = piVar2 + 0x400) {
        *(undefined *)(piVar2 + 0x3e) = 0xff;
        *piVar2 = (int)(piVar2 + 2);
        piVar2[1] = 0xf0;
      }
      return puVar5;
    }
    VirtualFree(piVar2,0,0x8000);
  }
  if (puVar5 != (undefined4 *)&DAT_0046b090) {
    HeapFree(_DAT_004777c4,0,puVar5);
  }
  return (undefined4 *)0x0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0045182d(int *param_1)

{
  VirtualFree(param_1[4],0,0x8000);
  if (_DAT_0046d0b0 == param_1) {
    _DAT_0046d0b0 = (int *)param_1[1];
  }
  if (param_1 != (int *)&DAT_0046b090) {
    *(int *)param_1[1] = *param_1;
    *(int *)(*param_1 + 4) = param_1[1];
    HeapFree(_DAT_004777c4,0,param_1);
    return;
  }
  _DAT_0046b0a0 = 0xffffffff;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00451883(int param_1)

{
  int iVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  int iStack_8;
  
  iVar4 = _DAT_0046b094;
  do {
    iVar3 = iVar4;
    if (*(int *)(iVar4 + 0x10) != -1) {
      iStack_8 = 0;
      piVar2 = (int *)(iVar4 + 0x2010);
      iVar3 = 0x3ff000;
      do {
        if (*piVar2 == 0xf0) {
          iVar1 = VirtualFree(iVar3 + *(int *)(iVar4 + 0x10),0x1000,0x4000);
          if (iVar1 != 0) {
            *piVar2 = -1;
            _DAT_00475ee8 = _DAT_00475ee8 + -1;
            if ((*(int **)(iVar4 + 0xc) == (int *)0x0) || (piVar2 < *(int **)(iVar4 + 0xc))) {
              *(int **)(iVar4 + 0xc) = piVar2;
            }
            iStack_8 = iStack_8 + 1;
            param_1 = param_1 + -1;
            if (param_1 == 0) break;
          }
        }
        iVar3 = iVar3 + -0x1000;
        piVar2 = piVar2 + -2;
      } while (-1 < iVar3);
      iVar3 = *(int *)(iVar4 + 4);
      if ((iStack_8 != 0) && (*(int *)(iVar4 + 0x18) == -1)) {
        piVar2 = (int *)(iVar4 + 0x20);
        iVar1 = 1;
        do {
          if (*piVar2 != -1) break;
          iVar1 = iVar1 + 1;
          piVar2 = piVar2 + 2;
        } while (iVar1 < 0x400);
        if (iVar1 == 0x400) {
          FUN_0045182d(iVar4);
        }
      }
    }
    if ((iVar3 == _DAT_0046b094) || (iVar4 = iVar3, param_1 < 1)) {
      return;
    }
  } while( true );
}



int FUN_00451945(uint param_1,undefined4 *param_2,uint *param_3)

{
  undefined4 *puVar1;
  uint uVar2;
  
  puVar1 = (undefined4 *)&DAT_0046b090;
  while ((param_1 < (uint)puVar1[4] || param_1 == puVar1[4] || ((uint)puVar1[5] <= param_1))) {
    puVar1 = (undefined4 *)*puVar1;
    if (puVar1 == (undefined4 *)&DAT_0046b090) {
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

void FUN_0045199c(int param_1,int param_2,byte *param_3)

{
  int *piVar1;
  int iVar2;
  
  piVar1 = (int *)(param_1 + 0x18 + (param_2 - *(int *)(param_1 + 0x10) >> 0xc) * 8);
  *piVar1 = *piVar1 + (uint)*param_3;
  *param_3 = 0;
  piVar1[1] = 0xf1;
  iVar2 = _DAT_00475ee8;
  if ((*piVar1 == 0xf0) && (_DAT_00475ee8 = _DAT_00475ee8 + 1, iVar2 == 0x1f)) {
    FUN_00451883(0x10);
  }
  return;
}



// WARNING: Type propagation algorithm not settling
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int * FUN_004519e1(uint param_1)

{
  int *piVar1;
  int *piVar2;
  int *piVar3;
  int iVar4;
  int *piVar5;
  undefined4 *puVar6;
  int iStack_8;
  
  piVar5 = _DAT_0046d0b0;
  do {
    if (piVar5[4] != -1) {
      piVar2 = (int *)piVar5[2];
      iVar4 = piVar5[4] + ((int)piVar2 + (-0x18 - (int)piVar5) >> 3) * 0x1000;
      if (piVar2 < piVar5 + 0x806) {
        do {
          if (((int)param_1 <= *piVar2) && (param_1 <= (uint)piVar2[1] && piVar2[1] != param_1)) {
            piVar1 = (int *)FUN_00451be9(iVar4,*piVar2,param_1);
            if (piVar1 != (int *)0x0) goto LAB_00451aac;
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
          piVar1 = (int *)FUN_00451be9(iVar4,*piVar2,param_1);
          if (piVar1 != (int *)0x0) {
LAB_00451aac:
            _DAT_0046d0b0 = piVar5;
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
    if (piVar5 == _DAT_0046d0b0) {
      puVar6 = (undefined4 *)&DAT_0046b090;
      while ((puVar6[4] == -1 || (puVar6[3] == 0))) {
        puVar6 = (undefined4 *)*puVar6;
        if (puVar6 == (undefined4 *)&DAT_0046b090) {
          iVar4 = FUN_004516e9();
          if (iVar4 == 0) {
            return (int *)0x0;
          }
          piVar5 = *(int **)(iVar4 + 0x10);
          *(char *)(piVar5 + 2) = (char)param_1;
          _DAT_0046d0b0 = (int *)iVar4;
          *piVar5 = (int)(piVar5 + 2) + param_1;
          piVar5[1] = 0xf0 - param_1;
          *(int *)(iVar4 + 0x18) = *(int *)(iVar4 + 0x18) - (param_1 & 0xff);
          return piVar5 + 0x40;
        }
      }
      piVar5 = (int *)puVar6[3];
      iStack_8 = 0;
      piVar1 = (int *)(puVar6[4] + ((int)((int)piVar5 + (-0x18 - (int)puVar6)) >> 3) * 0x1000);
      iVar4 = *piVar5;
      piVar2 = piVar5;
      for (; (iVar4 == -1 && (iStack_8 < 0x10)); iStack_8 = iStack_8 + 1) {
        piVar2 = piVar2 + 2;
        iVar4 = *piVar2;
      }
      piVar2 = (int *)VirtualAlloc(piVar1,iStack_8 << 0xc,0x1000,4);
      if (piVar2 != piVar1) {
        return (int *)0;
      }
      FUN_004538c0(piVar1,iStack_8 << 0xc,0);
      piVar2 = piVar5;
      if (0 < iStack_8) {
        piVar3 = piVar1 + 1;
        do {
          *(undefined *)(piVar3 + 0x3d) = 0xff;
          piVar3[-1] = (int)(piVar3 + 1);
          *piVar3 = 0xf0;
          *piVar2 = 0xf0;
          piVar2[1] = 0xf1;
          piVar3 = piVar3 + 0x400;
          piVar2 = piVar2 + 2;
          iStack_8 = iStack_8 + -1;
        } while (iStack_8 != 0);
      }
      for (; (piVar2 < puVar6 + 0x806 && (*piVar2 != -1)); piVar2 = piVar2 + 2) {
      }
      _DAT_0046d0b0 = puVar6;
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



int FUN_00451be9(int **param_1,int *param_2,int *param_3)

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
          goto LAB_00451cfc;
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
LAB_00451cfc:
  return (int)ppiVar2 * 0x10 + (int)param_1 * -0xf;
}



undefined4 FUN_00451d0d(int param_1,int **param_2,int **param_3,uint param_4)

{
  int **ppiVar1;
  int *piVar2;
  char cVar3;
  int **ppiVar4;
  int *piVar5;
  uint uVar6;
  
  uVar6 = (uint)*(byte *)param_3;
  piVar2 = (int *)(param_1 + 0x18 + ((int)param_2 - *(int *)(param_1 + 0x10) >> 0xc) * 8);
  if (param_4 < uVar6) {
    *(undefined *)param_3 = (undefined)param_4;
    *piVar2 = *piVar2 + (uVar6 - param_4);
    piVar2[1] = 0xf1;
  }
  else {
    if (param_4 <= uVar6) {
      return 0;
    }
    ppiVar1 = (int **)((int)param_3 + param_4);
    if (param_2 + 0x3e < ppiVar1) {
      return 0;
    }
    for (ppiVar4 = (int **)(uVar6 + (int)param_3); (ppiVar4 < ppiVar1 && (*(char *)ppiVar4 == '\0'))
        ; ppiVar4 = (int **)((int)ppiVar4 + 1)) {
    }
    if (ppiVar4 != ppiVar1) {
      return 0;
    }
    *(undefined *)param_3 = (undefined)param_4;
    if ((param_3 <= *param_2) && (*param_2 < ppiVar1)) {
      if (ppiVar1 < param_2 + 0x3e) {
        piVar5 = (int *)0x0;
        *param_2 = (int *)ppiVar1;
        cVar3 = *(char *)ppiVar1;
        while (cVar3 == '\0') {
          piVar5 = (int *)((int)piVar5 + 1);
          cVar3 = *(char *)((int)ppiVar1 + (int)piVar5);
        }
        param_2[1] = piVar5;
      }
      else {
        param_2[1] = (int *)0x0;
        *param_2 = (int *)(param_2 + 2);
      }
    }
    *piVar2 = *piVar2 + (uVar6 - param_4);
  }
  return 1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_00451db6(undefined4 param_1)

{
  int iVar1;
  
  if (_DAT_00475ef0 != (code *)0x0) {
    iVar1 = (*_DAT_00475ef0)(param_1);
    if (iVar1 != 0) {
      return 1;
    }
  }
  return 0;
}



void FUN_00451dd1(uint param_1)

{
  uint *puVar1;
  undefined4 *puVar2;
  int iVar3;
  
  puVar1 = (uint *)FUN_00451e4d();
  iVar3 = 0;
  *puVar1 = param_1;
  puVar1 = (uint *)0x46d0b8;
  do {
    if (param_1 == *puVar1) {
      puVar2 = (undefined4 *)FUN_00451e44();
      *puVar2 = *(undefined4 *)(iVar3 * 8 + 0x46d0bc);
      return;
    }
    puVar1 = puVar1 + 2;
    iVar3 = iVar3 + 1;
  } while (puVar1 < (uint *)0x46d220);
  if ((0x12 < param_1) && (param_1 < 0x25)) {
    puVar2 = (undefined4 *)FUN_00451e44();
    *puVar2 = 0xd;
    return;
  }
  if ((0xbb < param_1) && (param_1 < 0xcb)) {
    puVar2 = (undefined4 *)FUN_00451e44();
    *puVar2 = 8;
    return;
  }
  puVar2 = (undefined4 *)FUN_00451e44();
  *puVar2 = 0x16;
  return;
}



int FUN_00451e44(void)

{
  int iVar1;
  
  iVar1 = FUN_0044fc4a();
  return iVar1 + 8;
}



int FUN_00451e4d(void)

{
  int iVar1;
  
  iVar1 = FUN_0044fc4a();
  return iVar1 + 0xc;
}



int FUN_00452a60(undefined4 *param_1,byte *param_2)

{
  undefined2 uVar1;
  undefined4 uVar2;
  byte bVar3;
  byte bVar4;
  bool bVar5;
  
  if (((uint)param_1 & 3) != 0) {
    if (((uint)param_1 & 1) != 0) {
      bVar4 = *(byte *)param_1;
      param_1 = (undefined4 *)((int)param_1 + 1);
      bVar5 = bVar4 < *param_2;
      if (bVar4 != *param_2) goto LAB_00452aa4;
      param_2 = param_2 + 1;
      if (bVar4 == 0) {
        return 0;
      }
      if (((uint)param_1 & 2) == 0) goto LAB_00452a70;
    }
    uVar1 = *(undefined2 *)param_1;
    param_1 = (undefined4 *)((int)param_1 + 2);
    bVar4 = (byte)uVar1;
    bVar5 = bVar4 < *param_2;
    if (bVar4 != *param_2) goto LAB_00452aa4;
    if (bVar4 == 0) {
      return 0;
    }
    bVar4 = (byte)((ushort)uVar1 >> 8);
    bVar5 = bVar4 < param_2[1];
    if (bVar4 != param_2[1]) goto LAB_00452aa4;
    if (bVar4 == 0) {
      return 0;
    }
    param_2 = param_2 + 2;
  }
LAB_00452a70:
  while( true ) {
    uVar2 = *param_1;
    bVar4 = (byte)uVar2;
    bVar5 = bVar4 < *param_2;
    if (bVar4 != *param_2) break;
    if (bVar4 == 0) {
      return 0;
    }
    bVar4 = (byte)((uint)uVar2 >> 8);
    bVar5 = bVar4 < param_2[1];
    if (bVar4 != param_2[1]) break;
    if (bVar4 == 0) {
      return 0;
    }
    bVar4 = (byte)((uint)uVar2 >> 0x10);
    bVar5 = bVar4 < param_2[2];
    if (bVar4 != param_2[2]) break;
    bVar3 = (byte)((uint)uVar2 >> 0x18);
    if (bVar4 == 0) {
      return 0;
    }
    bVar5 = bVar3 < param_2[3];
    if (bVar3 != param_2[3]) break;
    param_2 = param_2 + 4;
    param_1 = param_1 + 1;
    if (bVar3 == 0) {
      return 0;
    }
  }
LAB_00452aa4:
  return (uint)bVar5 * -2 + 1;
}



int FUN_00452af0(byte *param_1,byte *param_2)

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



char * FUN_00452b30(uint *param_1)

{
  char cVar1;
  uint uVar2;
  uint *puVar3;
  uint *puVar4;
  
  uVar2 = (uint)param_1 & 3;
  puVar3 = param_1;
  while (uVar2 != 0) {
    cVar1 = *(char *)puVar3;
    puVar3 = (uint *)((int)puVar3 + 1);
    if (cVar1 == '\0') goto LAB_00452b83;
    uVar2 = (uint)puVar3 & 3;
  }
  do {
    do {
      puVar4 = puVar3;
      puVar3 = puVar4 + 1;
    } while (((*puVar4 ^ 0xffffffff ^ *puVar4 + 0x7efefeff) & 0x81010100) == 0);
    uVar2 = *puVar4;
    if ((char)uVar2 == '\0') {
      return (char *)((int)puVar4 - (int)param_1);
    }
    if ((char)(uVar2 >> 8) == '\0') {
      return (char *)((int)puVar4 + (1 - (int)param_1));
    }
    if ((uVar2 & 0xff0000) == 0) {
      return (char *)((int)puVar4 + (2 - (int)param_1));
    }
  } while ((uVar2 & 0xff000000) != 0);
LAB_00452b83:
  return (char *)((int)puVar3 + (-1 - (int)param_1));
}



byte * FUN_00452bb0(byte *param_1,byte *param_2)

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



uint * FUN_00452bf0(uint *param_1,uint *param_2)

{
  byte bVar1;
  uint uVar2;
  uint uVar3;
  uint *puVar4;
  
  uVar3 = (uint)param_2 & 3;
  puVar4 = param_1;
  while (uVar3 != 0) {
    bVar1 = *(byte *)param_2;
    uVar3 = (uint)bVar1;
    param_2 = (uint *)((int)param_2 + 1);
    if (bVar1 == 0) goto LAB_00452cd8;
    *(byte *)puVar4 = bVar1;
    puVar4 = (uint *)((int)puVar4 + 1);
    uVar3 = (uint)param_2 & 3;
  }
  do {
    uVar2 = *param_2;
    uVar3 = *param_2;
    param_2 = param_2 + 1;
    if (((uVar2 ^ 0xffffffff ^ uVar2 + 0x7efefeff) & 0x81010100) != 0) {
      if ((char)uVar3 == '\0') {
LAB_00452cd8:
        *(byte *)puVar4 = (byte)uVar3;
        return param_1;
      }
      if ((char)(uVar3 >> 8) == '\0') {
        *(short *)puVar4 = (short)uVar3;
        return param_1;
      }
      if ((uVar3 & 0xff0000) == 0) {
        *(short *)puVar4 = (short)uVar3;
        *(byte *)((int)puVar4 + 2) = 0;
        return param_1;
      }
      if ((uVar3 & 0xff000000) == 0) {
        *puVar4 = uVar3;
        return param_1;
      }
    }
    *puVar4 = uVar3;
    puVar4 = puVar4 + 1;
  } while( true );
}



uint * FUN_00452c00(uint *param_1,uint *param_2)

{
  byte bVar1;
  uint uVar2;
  uint *puVar3;
  uint uVar4;
  uint *puVar5;
  
  uVar4 = (uint)param_1 & 3;
  puVar3 = param_1;
  while (uVar4 != 0) {
    bVar1 = *(byte *)puVar3;
    puVar3 = (uint *)((int)puVar3 + 1);
    if (bVar1 == 0) goto LAB_00452c4f;
    uVar4 = (uint)puVar3 & 3;
  }
  do {
    do {
      puVar5 = puVar3;
      puVar3 = puVar5 + 1;
    } while (((*puVar5 ^ 0xffffffff ^ *puVar5 + 0x7efefeff) & 0x81010100) == 0);
    uVar4 = *puVar5;
    if ((char)uVar4 == '\0') goto LAB_00452c61;
    if ((char)(uVar4 >> 8) == '\0') {
      puVar5 = (uint *)((int)puVar5 + 1);
      goto LAB_00452c61;
    }
    if ((uVar4 & 0xff0000) == 0) {
      puVar5 = (uint *)((int)puVar5 + 2);
      goto LAB_00452c61;
    }
  } while ((uVar4 & 0xff000000) != 0);
LAB_00452c4f:
  puVar5 = (uint *)((int)puVar3 + -1);
LAB_00452c61:
  uVar4 = (uint)param_2 & 3;
  while (uVar4 != 0) {
    bVar1 = *(byte *)param_2;
    uVar4 = (uint)bVar1;
    param_2 = (uint *)((int)param_2 + 1);
    if (bVar1 == 0) goto LAB_00452cd8;
    *(byte *)puVar5 = bVar1;
    puVar5 = (uint *)((int)puVar5 + 1);
    uVar4 = (uint)param_2 & 3;
  }
  do {
    uVar2 = *param_2;
    uVar4 = *param_2;
    param_2 = param_2 + 1;
    if (((uVar2 ^ 0xffffffff ^ uVar2 + 0x7efefeff) & 0x81010100) != 0) {
      if ((char)uVar4 == '\0') {
LAB_00452cd8:
        *(byte *)puVar5 = (byte)uVar4;
        return param_1;
      }
      if ((char)(uVar4 >> 8) == '\0') {
        *(short *)puVar5 = (short)uVar4;
        return param_1;
      }
      if ((uVar4 & 0xff0000) == 0) {
        *(short *)puVar5 = (short)uVar4;
        *(byte *)((int)puVar5 + 2) = 0;
        return param_1;
      }
      if ((uVar4 & 0xff000000) == 0) {
        *puVar5 = uVar4;
        return param_1;
      }
    }
    *puVar5 = uVar4;
    puVar5 = puVar5 + 1;
  } while( true );
}



undefined4 * FUN_00452ce0(undefined4 *param_1,undefined4 *param_2,uint param_3)

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
          goto switchD_00452e97_caseD_2;
        case 3:
          goto switchD_00452e97_caseD_3;
        }
        goto switchD_00452e97_caseD_1;
      }
    }
    else {
      switch(param_3) {
      case 0:
        goto switchD_00452e97_caseD_0;
      case 1:
        goto switchD_00452e97_caseD_1;
      case 2:
        goto switchD_00452e97_caseD_2;
      case 3:
        goto switchD_00452e97_caseD_3;
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
              goto switchD_00452e97_caseD_2;
            case 3:
              goto switchD_00452e97_caseD_3;
            }
            goto switchD_00452e97_caseD_1;
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
              goto switchD_00452e97_caseD_2;
            case 3:
              goto switchD_00452e97_caseD_3;
            }
            goto switchD_00452e97_caseD_1;
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
              goto switchD_00452e97_caseD_2;
            case 3:
              goto switchD_00452e97_caseD_3;
            }
            goto switchD_00452e97_caseD_1;
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
switchD_00452e97_caseD_1:
      *(undefined *)((int)puVar2 + 3) = *(undefined *)((int)param_2 + 3);
      return param_1;
    case 2:
switchD_00452e97_caseD_2:
      *(undefined *)((int)puVar2 + 3) = *(undefined *)((int)param_2 + 3);
      *(undefined *)((int)puVar2 + 2) = *(undefined *)((int)param_2 + 2);
      return param_1;
    case 3:
switchD_00452e97_caseD_3:
      *(undefined *)((int)puVar2 + 3) = *(undefined *)((int)param_2 + 3);
      *(undefined *)((int)puVar2 + 2) = *(undefined *)((int)param_2 + 2);
      *(undefined *)((int)puVar2 + 1) = *(undefined *)((int)param_2 + 1);
      return param_1;
    }
switchD_00452e97_caseD_0:
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
        goto switchD_00452d15_caseD_2;
      case 3:
        goto switchD_00452d15_caseD_3;
      }
      goto switchD_00452d15_caseD_1;
    }
  }
  else {
    switch(param_3) {
    case 0:
      goto switchD_00452d15_caseD_0;
    case 1:
      goto switchD_00452d15_caseD_1;
    case 2:
      goto switchD_00452d15_caseD_2;
    case 3:
      goto switchD_00452d15_caseD_3;
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
            goto switchD_00452d15_caseD_2;
          case 3:
            goto switchD_00452d15_caseD_3;
          }
          goto switchD_00452d15_caseD_1;
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
            goto switchD_00452d15_caseD_2;
          case 3:
            goto switchD_00452d15_caseD_3;
          }
          goto switchD_00452d15_caseD_1;
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
            goto switchD_00452d15_caseD_2;
          case 3:
            goto switchD_00452d15_caseD_3;
          }
          goto switchD_00452d15_caseD_1;
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
switchD_00452d15_caseD_1:
    *(undefined *)puVar2 = *(undefined *)param_2;
    return param_1;
  case 2:
switchD_00452d15_caseD_2:
    *(undefined *)puVar2 = *(undefined *)param_2;
    *(undefined *)((int)puVar2 + 1) = *(undefined *)((int)param_2 + 1);
    return param_1;
  case 3:
switchD_00452d15_caseD_3:
    *(undefined *)puVar2 = *(undefined *)param_2;
    *(undefined *)((int)puVar2 + 1) = *(undefined *)((int)param_2 + 1);
    *(undefined *)((int)puVar2 + 2) = *(undefined *)((int)param_2 + 2);
    return param_1;
  }
switchD_00452d15_caseD_0:
  return param_1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_00453015(char *param_1)

{
  int iVar1;
  uint uVar2;
  undefined2 *unaff_EBX;
  int unaff_retaddr;
  
  if (_DAT_00475f54 == (code *)0x0) {
    iVar1 = FUN_00453746();
    if (iVar1 == 0) {
      _DAT_00475f54 = (code *)0x45377c;
    }
    else {
      _DAT_00475f54 = GetLocaleInfoA_exref;
    }
  }
  if (param_1 != (char *)0x0) {
    _DAT_00475f44 = param_1;
    if (*param_1 != '\0') {
      FUN_00453192(0x46d790,0x40,&DAT_00475f44);
    }
    _DAT_00475f48 = param_1 + 0x40;
    if ((_DAT_00475f48 != (char *)0x0) && (*_DAT_00475f48 != '\0')) {
      FUN_00453192(0x46d6d8,0x16,&DAT_00475f48);
    }
    _DAT_00475f4c = 0;
    if ((_DAT_00475f44 != (char *)0x0) && (*_DAT_00475f44 != '\0')) {
      if ((_DAT_00475f48 == (char *)0x0) || (*_DAT_00475f48 == '\0')) {
        FUN_00453475();
      }
      else {
        FUN_004531ea();
      }
      goto LAB_004530d2;
    }
    if ((_DAT_00475f48 != (char *)0x0) && (*_DAT_00475f48 != '\0')) {
      FUN_00453588();
      goto LAB_004530d2;
    }
  }
  FUN_00453645();
LAB_004530d2:
  if ((((_DAT_00475f4c == 0) || (uVar2 = FUN_0045365f(param_1 + 0x80), uVar2 == 0)) ||
      (iVar1 = IsValidCodePage(uVar2 & 0xffff), iVar1 == 0)) ||
     (iVar1 = IsValidLocale(_DAT_00475f34,1), iVar1 == 0)) {
    return 0;
  }
  if (unaff_EBX != (undefined2 *)0x0) {
    *unaff_EBX = _DAT_00475f34;
    unaff_EBX[1] = _DAT_00475f50;
    unaff_EBX[2] = (short)uVar2;
  }
  if (unaff_retaddr != 0) {
    iVar1 = (*_DAT_00475f54)(_DAT_00475f34,0x1001,unaff_retaddr,0x40);
    if (iVar1 == 0) {
      return 0;
    }
    iVar1 = (*_DAT_00475f54)(_DAT_00475f50,0x1002,unaff_retaddr + 0x40,0x40);
    if (iVar1 == 0) {
      return 0;
    }
    FUN_00456f32(uVar2,unaff_retaddr + 0x80,10);
  }
  return 1;
}



void FUN_00453192(int param_1,int param_2,int *param_3)

{
  int iVar1;
  int iVar2;
  int iVar3;
  
  iVar2 = 0;
  iVar1 = 1;
  if (-1 < param_2) {
    do {
      if (iVar1 == 0) {
        return;
      }
      iVar3 = (param_2 + iVar2) / 2;
      iVar1 = FUN_0044e610(*param_3,*(undefined4 *)(param_1 + iVar3 * 8));
      if (iVar1 == 0) {
        *param_3 = param_1 + iVar3 * 8 + 4;
      }
      else if (iVar1 < 0) {
        param_2 = iVar3 + -1;
      }
      else {
        iVar2 = iVar3 + 1;
      }
    } while (iVar2 <= param_2);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_004531ea(void)

{
  int iVar1;
  
  iVar1 = FUN_00452b30(_DAT_00475f44);
  _DAT_00475f40 = (uint)(iVar1 == 3);
  iVar1 = FUN_00452b30(_DAT_00475f48);
  _DAT_00475f38 = (uint)(iVar1 == 3);
  _DAT_00475f34 = 0;
  if (_DAT_00475f40 == 0) {
    _DAT_00475f3c = FUN_0045389b(_DAT_00475f44);
  }
  else {
    _DAT_00475f3c = 2;
  }
  EnumSystemLocalesA(0x453271,1);
  if ((((_DAT_00475f4c & 0x100) == 0) || ((_DAT_00475f4c & 0x200) == 0)) ||
     ((_DAT_00475f4c & 7) == 0)) {
    _DAT_00475f4c = 0;
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00453475(void)

{
  int iVar1;
  
  iVar1 = FUN_00452b30(_DAT_00475f44);
  _DAT_00475f40 = (uint)(iVar1 == 3);
  if (iVar1 == 3) {
    _DAT_00475f3c = 2;
  }
  else {
    _DAT_00475f3c = FUN_0045389b(_DAT_00475f44);
  }
  EnumSystemLocalesA(0x4534cb,1);
  if ((_DAT_00475f4c & 4) == 0) {
    _DAT_00475f4c = 0;
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00453588(void)

{
  int iVar1;
  
  iVar1 = FUN_00452b30(_DAT_00475f48);
  _DAT_00475f38 = (uint)(iVar1 == 3);
  EnumSystemLocalesA(0x4535bf,1);
  if ((_DAT_00475f4c & 4) == 0) {
    _DAT_00475f4c = 0;
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00453645(void)

{
  _DAT_00475f4c = _DAT_00475f4c | 0x104;
  _DAT_00475f50 = GetUserDefaultLCID();
  _DAT_00475f34 = _DAT_00475f50;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0045365f(char *param_1)

{
  int iVar1;
  undefined4 uVar2;
  char acStack_c [8];
  
  if (((param_1 == (char *)0x0) || (*param_1 == '\0')) ||
     (iVar1 = FUN_00452a60(param_1,&UNK_0045fcec), iVar1 == 0)) {
    uVar2 = 0x1004;
  }
  else {
    iVar1 = FUN_00452a60(param_1,&UNK_0045fce8);
    if (iVar1 != 0) goto LAB_004536bb;
    uVar2 = 0xb;
  }
  iVar1 = (*_DAT_00475f54)(_DAT_00475f50,uVar2,acStack_c,8);
  if (iVar1 == 0) {
    return;
  }
  param_1 = acStack_c;
LAB_004536bb:
  FUN_0044ba2e(param_1);
  return;
}



undefined4 FUN_004536c5(short param_1)

{
  short *psVar1;
  
  psVar1 = (short *)0x46d6c4;
  do {
    if (param_1 == *psVar1) {
      return 0;
    }
    psVar1 = psVar1 + 1;
  } while (psVar1 < (short *)0x46d6d8);
  return 1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_004536e4(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  undefined auStack_7c [120];
  
  iVar1 = (*_DAT_00475f54)((ushort)param_1 & 0x3ff | 0x400,1,auStack_7c,0x78);
  if (iVar1 == 0) {
    return 0;
  }
  iVar1 = FUN_00453862(auStack_7c);
  if ((param_1 != iVar1) && (param_2 != 0)) {
    iVar1 = FUN_0045389b(_DAT_00475f44);
    iVar2 = FUN_00452b30(_DAT_00475f44);
    if (iVar1 == iVar2) {
      return 0;
    }
  }
  return 1;
}



undefined4 FUN_00453746(void)

{
  int iVar1;
  undefined4 auStack_98 [4];
  int iStack_88;
  
  auStack_98[0] = 0x94;
  iVar1 = GetVersionExA(auStack_98);
  if ((iVar1 != 0) && (iStack_88 == 2)) {
    return 1;
  }
  return 0;
}



int FUN_00453862(char *param_1)

{
  int iVar1;
  char cVar2;
  
  iVar1 = 0;
  while( true ) {
    cVar2 = *param_1;
    param_1 = param_1 + 1;
    if (cVar2 == '\0') break;
    if ((cVar2 < 'a') || ('f' < cVar2)) {
      if (('@' < cVar2) && (cVar2 < 'G')) {
        cVar2 = cVar2 + -7;
      }
    }
    else {
      cVar2 = cVar2 + -0x27;
    }
    iVar1 = (iVar1 + 0xffffffd) * 0x10 + (int)cVar2;
  }
  return iVar1;
}



int FUN_0045389b(char *param_1)

{
  char cVar1;
  int iVar2;
  
  iVar2 = 0;
  while( true ) {
    cVar1 = *param_1;
    param_1 = param_1 + 1;
    if (((cVar1 < 'A') || ('Z' < cVar1)) && ((cVar1 < 'a' || ('z' < cVar1)))) break;
    iVar2 = iVar2 + 1;
  }
  return iVar2;
}



uint * FUN_004538c0(uint *param_1,byte param_2,uint param_3)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint *puVar4;
  
  if (param_3 == 0) {
    return param_1;
  }
  uVar1 = (uint)param_2;
  puVar4 = param_1;
  if (3 < param_3) {
    uVar2 = -(int)param_1 & 3;
    uVar3 = param_3;
    if (uVar2 != 0) {
      uVar3 = param_3 - uVar2;
      do {
        *(byte *)puVar4 = param_2;
        puVar4 = (uint *)((int)puVar4 + 1);
        uVar2 = uVar2 - 1;
      } while (uVar2 != 0);
    }
    uVar1 = uVar1 * 0x1010101;
    param_3 = uVar3 & 3;
    uVar3 = uVar3 >> 2;
    if (uVar3 != 0) {
      for (; uVar3 != 0; uVar3 = uVar3 - 1) {
        *puVar4 = uVar1;
        puVar4 = puVar4 + 1;
      }
      if (param_3 == 0) {
        return param_1;
      }
    }
  }
  do {
    *(char *)puVar4 = (char)uVar1;
    puVar4 = (uint *)((int)puVar4 + 1);
    param_3 = param_3 - 1;
  } while (param_3 != 0);
  return param_1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_00453918(undefined4 param_1,byte *param_2,longlong **param_3)

{
  byte bVar1;
  longlong **pplVar2;
  byte bVar3;
  uint uVar4;
  undefined4 uVar5;
  int iVar6;
  uint uVar7;
  uint uVar8;
  byte bVar9;
  byte *pbVar10;
  char *pcVar11;
  char *pcVar12;
  longlong *plVar13;
  byte *pbVar14;
  bool bVar15;
  longlong lVar16;
  char cStack_1c8;
  char acStack_1c7 [351];
  byte abStack_68 [32];
  longlong **pplStack_48;
  undefined2 uStack_42;
  uint uStack_40;
  byte bStack_3c;
  undefined uStack_3b;
  byte bStack_39;
  int iStack_38;
  longlong *plStack_34;
  longlong *plStack_30;
  undefined8 uStack_2c;
  int iStack_24;
  int iStack_20;
  byte bStack_1c;
  char cStack_1b;
  char cStack_1a;
  char cStack_19;
  uint uStack_18;
  char cStack_13;
  char cStack_12;
  char cStack_11;
  int iStack_10;
  char cStack_9;
  int iStack_8;
  
  cStack_19 = '\0';
  bVar1 = *param_2;
  iStack_8 = 0;
  iStack_38 = 0;
  pbVar10 = param_2;
  do {
    if (bVar1 == 0) {
LAB_0045431e:
      if (uStack_18 == 0xffffffff) {
LAB_00454324:
        if ((iStack_38 == 0) && (cStack_19 == '\0')) {
          iStack_38 = -1;
        }
      }
      return iStack_38;
    }
    if (_DAT_0046ae4c < 2) {
      uVar4 = *(byte *)(_DAT_0046ac40 + (uint)bVar1 * 2) & 8;
    }
    else {
      uVar4 = FUN_0044e6e0(bVar1,8);
    }
    if (uVar4 != 0) {
      iStack_8 = iStack_8 + -1;
      uVar5 = FUN_004543a5(&iStack_8,param_1,param_1);
      FUN_0045438e(uVar5);
      iVar6 = FUN_0044c39b(pbVar10[1]);
      pbVar14 = pbVar10;
      while (pbVar10 = pbVar14 + 1, iVar6 != 0) {
        iVar6 = FUN_0044c39b(pbVar14[2]);
        pbVar14 = pbVar10;
      }
    }
    if (*pbVar10 == 0x25) {
      bStack_39 = 0;
      bStack_1c = 0;
      cStack_1b = '\0';
      cStack_12 = '\0';
      cStack_13 = '\0';
      cStack_1a = '\0';
      iVar6 = 0;
      cStack_9 = '\0';
      iStack_20 = 0;
      iStack_24 = 0;
      iStack_10 = 0;
      cStack_11 = '\x01';
      plStack_34 = (longlong *)0x0;
      do {
        uVar4 = (uint)pbVar10[1];
        param_2 = pbVar10 + 1;
        if (_DAT_0046ae4c < 2) {
          uVar7 = *(byte *)(_DAT_0046ac40 + uVar4 * 2) & 4;
        }
        else {
          uVar7 = FUN_0044e6e0(uVar4,4);
        }
        if (uVar7 == 0) {
          if (uVar4 < 0x4f) {
            if (uVar4 != 0x4e) {
              if (uVar4 == 0x2a) {
                cStack_12 = cStack_12 + '\x01';
              }
              else if (uVar4 != 0x46) {
                if (uVar4 == 0x49) {
                  if ((pbVar10[2] != 0x36) || (pbVar10[3] != 0x34)) goto LAB_00453a73;
                  plStack_34 = (longlong *)((int)plStack_34 + 1);
                  uStack_2c = 0;
                  param_2 = pbVar10 + 3;
                }
                else if (uVar4 == 0x4c) {
                  cStack_11 = cStack_11 + '\x01';
                }
                else {
LAB_00453a73:
                  cStack_13 = cStack_13 + '\x01';
                }
              }
            }
          }
          else if (uVar4 == 0x68) {
            cStack_11 = cStack_11 + -1;
            cStack_9 = cStack_9 + -1;
          }
          else {
            if (uVar4 == 0x6c) {
              cStack_11 = cStack_11 + '\x01';
            }
            else if (uVar4 != 0x77) goto LAB_00453a73;
            cStack_9 = cStack_9 + '\x01';
          }
        }
        else {
          iStack_24 = iStack_24 + 1;
          iStack_10 = (uVar4 - 0x30) + iStack_10 * 10;
        }
        pbVar10 = param_2;
      } while (cStack_13 == '\0');
      pplVar2 = param_3;
      if (cStack_12 == '\0') {
        plStack_30 = *param_3;
        pplVar2 = param_3 + 1;
        pplStack_48 = param_3;
      }
      param_3 = pplVar2;
      cStack_13 = '\0';
      if (cStack_9 == '\0') {
        if ((*param_2 == 0x53) || (*param_2 == 0x43)) {
          cStack_9 = '\x01';
        }
        else {
          cStack_9 = -1;
        }
      }
      uVar4 = *param_2 | 0x20;
      uStack_40 = uVar4;
      if (uVar4 != 0x6e) {
        if ((uVar4 == 99) || (uVar4 == 0x7b)) {
          iStack_8 = iStack_8 + 1;
          uStack_18 = FUN_00454374(param_1);
        }
        else {
          uStack_18 = FUN_004543a5(&iStack_8,param_1);
        }
      }
      if ((iStack_24 != 0) && (iStack_10 == 0)) {
LAB_004542fe:
        iStack_8 = iStack_8 + -1;
        FUN_0045438e(uStack_18,param_1);
        goto LAB_0045431e;
      }
      if (uVar4 < 0x70) {
        if (uVar4 == 0x6f) {
LAB_0045402b:
          if (uStack_18 == 0x2d) {
            cStack_1b = '\x01';
          }
          else if (uStack_18 != 0x2b) goto LAB_00454060;
          iStack_10 = iStack_10 + -1;
          if ((iStack_10 == 0) && (iStack_24 != 0)) {
            cStack_13 = '\x01';
          }
          else {
            iStack_8 = iStack_8 + 1;
            uStack_18 = FUN_00454374(param_1);
          }
          goto LAB_00454060;
        }
        if (uVar4 != 99) {
          if (uVar4 == 100) goto LAB_0045402b;
          if (uVar4 < 0x65) {
LAB_00453da3:
            if (*param_2 != uStack_18) goto LAB_004542fe;
            cStack_19 = cStack_19 + -1;
            if (cStack_12 == '\0') {
              param_3 = pplStack_48;
            }
            goto LAB_0045427f;
          }
          if (0x67 < uVar4) {
            if (uVar4 == 0x69) {
              uVar4 = 100;
              goto LAB_00453b61;
            }
            if (uVar4 != 0x6e) goto LAB_00453da3;
            iVar6 = iStack_8;
            lVar16 = uStack_2c;
            if (cStack_12 != '\0') goto LAB_0045427f;
            goto LAB_00454259;
          }
          pcVar11 = &cStack_1c8;
          if (uStack_18 == 0x2d) {
            cStack_1c8 = '-';
            pcVar11 = acStack_1c7;
LAB_00453b97:
            iStack_10 = iStack_10 + -1;
            iStack_8 = iStack_8 + 1;
            uStack_18 = FUN_00454374(param_1);
          }
          else if (uStack_18 == 0x2b) goto LAB_00453b97;
          if ((iStack_24 == 0) || (0x15d < iStack_10)) {
            iStack_10 = 0x15d;
          }
          while( true ) {
            uVar4 = uStack_18;
            if (_DAT_0046ae4c < 2) {
              uVar7 = *(byte *)(_DAT_0046ac40 + uStack_18 * 2) & 4;
            }
            else {
              uVar7 = FUN_0044e6e0(uStack_18,4);
            }
            if ((uVar7 == 0) ||
               (iVar6 = iStack_10 + -1, bVar15 = iStack_10 == 0, iStack_10 = iVar6, bVar15)) break;
            iStack_20 = iStack_20 + 1;
            *pcVar11 = (char)uVar4;
            pcVar11 = pcVar11 + 1;
            iStack_8 = iStack_8 + 1;
            uStack_18 = FUN_00454374(param_1);
          }
          if ((DAT_0046ae50 == (char)uVar4) &&
             (iVar6 = iStack_10 + -1, bVar15 = iStack_10 != 0, iStack_10 = iVar6, bVar15)) {
            iStack_8 = iStack_8 + 1;
            uVar4 = FUN_00454374(param_1);
            *pcVar11 = DAT_0046ae50;
            while( true ) {
              pcVar11 = pcVar11 + 1;
              uStack_18 = uVar4;
              if (_DAT_0046ae4c < 2) {
                uVar7 = *(byte *)(_DAT_0046ac40 + uVar4 * 2) & 4;
              }
              else {
                uVar7 = FUN_0044e6e0(uVar4,4);
              }
              if ((uVar7 == 0) ||
                 (iVar6 = iStack_10 + -1, bVar15 = iStack_10 == 0, iStack_10 = iVar6, bVar15))
              break;
              iStack_20 = iStack_20 + 1;
              *pcVar11 = (char)uVar4;
              iStack_8 = iStack_8 + 1;
              uVar4 = FUN_00454374(param_1);
            }
          }
          pcVar12 = pcVar11;
          if ((iStack_20 != 0) &&
             (((uVar4 == 0x65 || (uVar4 == 0x45)) &&
              (iVar6 = iStack_10 + -1, bVar15 = iStack_10 != 0, iStack_10 = iVar6, bVar15)))) {
            *pcVar11 = 'e';
            pcVar12 = pcVar11 + 1;
            iStack_8 = iStack_8 + 1;
            uVar4 = FUN_00454374(param_1);
            uStack_18 = uVar4;
            if (uVar4 == 0x2d) {
              *pcVar12 = '-';
              pcVar12 = pcVar11 + 2;
LAB_00453cbe:
              bVar15 = iStack_10 != 0;
              iStack_10 = iStack_10 + -1;
              if (bVar15) goto LAB_00453ccd;
              iStack_10 = 0;
            }
            else if (uVar4 == 0x2b) goto LAB_00453cbe;
            while( true ) {
              if (_DAT_0046ae4c < 2) {
                uVar7 = *(byte *)(_DAT_0046ac40 + uVar4 * 2) & 4;
              }
              else {
                uVar7 = FUN_0044e6e0(uVar4,4);
              }
              if ((uVar7 == 0) ||
                 (iVar6 = iStack_10 + -1, bVar15 = iStack_10 == 0, iStack_10 = iVar6, bVar15))
              break;
              iStack_20 = iStack_20 + 1;
              *pcVar12 = (char)uVar4;
              pcVar12 = pcVar12 + 1;
LAB_00453ccd:
              iStack_8 = iStack_8 + 1;
              uVar4 = FUN_00454374(param_1);
              uStack_18 = uVar4;
            }
          }
          iStack_8 = iStack_8 + -1;
          FUN_0045438e(uVar4,param_1);
          if (iStack_20 != 0) {
            if (cStack_12 == '\0') {
              iStack_38 = iStack_38 + 1;
              *pcVar12 = '\0';
              (*_DAT_0046ae60)(cStack_11 + -1,plStack_30,&cStack_1c8);
            }
            goto LAB_0045427f;
          }
          goto LAB_0045431e;
        }
        if (iStack_24 == 0) {
          iStack_10 = iStack_10 + 1;
          iStack_24 = 1;
        }
        if ('\0' < cStack_9) {
          cStack_1a = '\x01';
        }
        pbVar10 = (byte *)0x46d9a8;
LAB_00453e84:
        bStack_1c = 0xff;
        pbVar14 = pbVar10;
        pbVar10 = param_2;
LAB_00453e88:
        param_2 = pbVar10;
        FUN_004538c0(abStack_68,0,0x20);
        if ((uStack_40 == 0x7b) && (*pbVar14 == 0x5d)) {
          uVar4 = 0x5d;
          abStack_68[11] = 0x20;
          pbVar14 = pbVar14 + 1;
        }
        else {
          uVar4 = (uint)bStack_39;
        }
        while (plVar13 = plStack_30, bVar1 = *pbVar14, bVar1 != 0x5d) {
          if (((bVar1 == 0x2d) && (bVar9 = (byte)uVar4, bVar9 != 0)) &&
             (bVar3 = pbVar14[1], bVar3 != 0x5d)) {
            if (bVar3 <= bVar9) {
              uVar4 = (uint)bVar3;
              bVar3 = bVar9;
            }
            if ((byte)uVar4 <= bVar3) {
              iVar6 = (bVar3 - uVar4) + 1;
              do {
                abStack_68[uVar4 >> 3] = abStack_68[uVar4 >> 3] | '\x01' << ((byte)uVar4 & 7);
                uVar4 = uVar4 + 1;
                iVar6 = iVar6 + -1;
              } while (iVar6 != 0);
            }
            uVar4 = 0;
            pbVar14 = pbVar14 + 2;
          }
          else {
            uVar4 = (uint)bVar1;
            abStack_68[bVar1 >> 3] = abStack_68[bVar1 >> 3] | '\x01' << (bVar1 & 7);
            pbVar14 = pbVar14 + 1;
          }
        }
        if (*pbVar14 == 0) goto LAB_0045431e;
        if (uStack_40 == 0x7b) {
          param_2 = pbVar14;
        }
        iStack_8 = iStack_8 + -1;
        plStack_34 = plStack_30;
        FUN_0045438e(uStack_18,param_1);
        while( true ) {
          if ((iStack_24 != 0) &&
             (iVar6 = iStack_10 + -1, bVar15 = iStack_10 == 0, iStack_10 = iVar6, bVar15))
          goto LAB_00453fed;
          iStack_8 = iStack_8 + 1;
          uStack_18 = FUN_00454374(param_1);
          if ((uStack_18 == 0xffffffff) ||
             (bVar1 = (byte)uStack_18,
             ((int)(char)(abStack_68[(int)uStack_18 >> 3] ^ bStack_1c) & 1 << (bVar1 & 7)) == 0))
          break;
          if (cStack_12 == '\0') {
            if (cStack_1a == '\0') {
              *(byte *)plVar13 = bVar1;
              plVar13 = (longlong *)((int)plVar13 + 1);
              plStack_30 = plVar13;
            }
            else {
              bStack_3c = bVar1;
              if ((*(byte *)(_DAT_0046ac40 + 1 + (uStack_18 & 0xff) * 2) & 0x80) != 0) {
                iStack_8 = iStack_8 + 1;
                uStack_3b = FUN_00454374(param_1);
              }
              FUN_004570c1(&uStack_42,&bStack_3c,_DAT_0046ae4c);
              *(undefined2 *)plVar13 = uStack_42;
              plVar13 = (longlong *)((int)plVar13 + 2);
              plStack_30 = plVar13;
            }
          }
          else {
            plStack_34 = (longlong *)((int)plStack_34 + 1);
          }
        }
        iStack_8 = iStack_8 + -1;
        FUN_0045438e(uStack_18,param_1);
LAB_00453fed:
        if (plStack_34 == plVar13) goto LAB_0045431e;
        if ((cStack_12 == '\0') && (iStack_38 = iStack_38 + 1, uStack_40 != 99)) {
          if (cStack_1a == '\0') {
            *(undefined *)plStack_30 = 0;
          }
          else {
            *(undefined2 *)plStack_30 = 0;
          }
        }
      }
      else {
        if (uVar4 == 0x70) {
          cStack_11 = '\x01';
          goto LAB_0045402b;
        }
        if (uVar4 == 0x73) {
          if ('\0' < cStack_9) {
            cStack_1a = '\x01';
          }
          pbVar10 = (byte *)0x46d9a0;
          goto LAB_00453e84;
        }
        if (uVar4 == 0x75) goto LAB_0045402b;
        if (uVar4 != 0x78) {
          if (uVar4 != 0x7b) goto LAB_00453da3;
          if ('\0' < cStack_9) {
            cStack_1a = '\x01';
          }
          pbVar14 = param_2 + 1;
          pbVar10 = pbVar14;
          if (*pbVar14 == 0x5e) {
            pbVar10 = param_2 + 2;
            param_2 = pbVar14;
            goto LAB_00453e84;
          }
          goto LAB_00453e88;
        }
LAB_00453b61:
        if (uStack_18 == 0x2d) {
          cStack_1b = '\x01';
LAB_00453df0:
          iStack_10 = iStack_10 + -1;
          if ((iStack_10 == 0) && (iStack_24 != 0)) {
            cStack_13 = '\x01';
          }
          else {
            iStack_8 = iStack_8 + 1;
            uStack_18 = FUN_00454374(param_1);
          }
        }
        else if (uStack_18 == 0x2b) goto LAB_00453df0;
        if (uStack_18 == 0x30) {
          iStack_8 = iStack_8 + 1;
          uStack_18 = FUN_00454374(param_1);
          if (((char)uStack_18 == 'x') || ((char)uStack_18 == 'X')) {
            iStack_8 = iStack_8 + 1;
            uStack_18 = FUN_00454374(param_1);
            uVar4 = 0x78;
          }
          else {
            iStack_20 = 1;
            if (uVar4 == 0x78) {
              iStack_8 = iStack_8 + -1;
              FUN_0045438e(uStack_18,param_1);
              uStack_18 = 0x30;
            }
            else {
              uVar4 = 0x6f;
            }
          }
        }
LAB_00454060:
        lVar16 = uStack_2c;
        if (plStack_34 == (longlong *)0x0) {
          if (cStack_13 == '\0') {
            while ((uVar7 = uStack_18, uVar4 != 0x78 && (uVar4 != 0x70))) {
              if (_DAT_0046ae4c < 2) {
                uVar8 = *(byte *)(_DAT_0046ac40 + uStack_18 * 2) & 4;
              }
              else {
                uVar8 = FUN_0044e6e0(uStack_18,4);
              }
              if (uVar8 == 0) goto LAB_00454227;
              if (uVar4 == 0x6f) {
                if (0x37 < (int)uVar7) goto LAB_00454227;
                iVar6 = iVar6 << 3;
              }
              else {
                iVar6 = iVar6 * 10;
              }
LAB_004541ff:
              iStack_20 = iStack_20 + 1;
              iVar6 = iVar6 + -0x30 + uVar7;
              if ((iStack_24 != 0) &&
                 (iStack_10 = iStack_10 + -1, lVar16 = uStack_2c, iStack_10 == 0))
              goto LAB_00454235;
              iStack_8 = iStack_8 + 1;
              uStack_18 = FUN_00454374(param_1);
            }
            if (_DAT_0046ae4c < 2) {
              uVar8 = *(byte *)(_DAT_0046ac40 + uStack_18 * 2) & 0x80;
            }
            else {
              uVar8 = FUN_0044e6e0(uStack_18,0x80);
            }
            if (uVar8 != 0) {
              iVar6 = iVar6 << 4;
              uVar7 = FUN_0045433d(uVar7);
              uStack_18 = uVar7;
              goto LAB_004541ff;
            }
LAB_00454227:
            iStack_8 = iStack_8 + -1;
            FUN_0045438e(uVar7,param_1);
            lVar16 = uStack_2c;
          }
LAB_00454235:
          if (cStack_1b != '\0') {
            iVar6 = -iVar6;
          }
        }
        else {
          if (cStack_13 == '\0') {
            while (uVar7 = uStack_18, uVar4 != 0x78) {
              if (_DAT_0046ae4c < 2) {
                uVar8 = *(byte *)(_DAT_0046ac40 + uStack_18 * 2) & 4;
              }
              else {
                uVar8 = FUN_0044e6e0(uStack_18,4);
              }
              if (uVar8 == 0) goto LAB_00454149;
              if (uVar4 == 0x6f) {
                if (0x37 < (int)uVar7) goto LAB_00454149;
                lVar16 = FUN_004571f0();
              }
              else {
                lVar16 = FUN_0044c170(uStack_2c,10,0);
              }
LAB_0045411b:
              iStack_20 = iStack_20 + 1;
              uStack_2c = lVar16 + (int)(uVar7 - 0x30);
              if ((iStack_24 != 0) &&
                 (iStack_10 = iStack_10 + -1, lVar16 = uStack_2c, iStack_10 == 0))
              goto LAB_00454157;
              iStack_8 = iStack_8 + 1;
              uStack_18 = FUN_00454374(param_1);
            }
            if (_DAT_0046ae4c < 2) {
              uVar8 = *(byte *)(_DAT_0046ac40 + uStack_18 * 2) & 0x80;
            }
            else {
              uVar8 = FUN_0044e6e0(uStack_18,0x80);
            }
            if (uVar8 != 0) {
              lVar16 = FUN_004571f0();
              uStack_2c = lVar16;
              uVar7 = FUN_0045433d(uVar7);
              uStack_18 = uVar7;
              lVar16 = uStack_2c;
              goto LAB_0045411b;
            }
LAB_00454149:
            iStack_8 = iStack_8 + -1;
            FUN_0045438e(uVar7,param_1);
            lVar16 = uStack_2c;
          }
LAB_00454157:
          uStack_2c._4_4_ = (int)((ulonglong)lVar16 >> 0x20);
          uStack_2c._0_4_ = (int)lVar16;
          if (cStack_1b != '\0') {
            lVar16 = CONCAT44(-(uStack_2c._4_4_ + (uint)((int)uStack_2c != 0)),-(int)uStack_2c);
          }
        }
        if (uVar4 == 0x46) {
          iStack_20 = 0;
        }
        if (iStack_20 == 0) goto LAB_0045431e;
        uStack_2c = lVar16;
        if (cStack_12 == '\0') {
          iStack_38 = iStack_38 + 1;
LAB_00454259:
          uStack_2c = lVar16;
          if (plStack_34 == (longlong *)0x0) {
            if (cStack_11 == '\0') {
              *(short *)plStack_30 = (short)iVar6;
            }
            else {
              *(int *)plStack_30 = iVar6;
            }
          }
          else {
            *plStack_30 = lVar16;
          }
        }
      }
LAB_0045427f:
      cStack_19 = cStack_19 + '\x01';
      param_2 = param_2 + 1;
    }
    else {
      iStack_8 = iStack_8 + 1;
      uVar4 = FUN_00454374(param_1);
      param_2 = pbVar10 + 1;
      uStack_18 = uVar4;
      if (*pbVar10 != uVar4) goto LAB_004542fe;
      if ((*(byte *)(_DAT_0046ac40 + 1 + (uVar4 & 0xff) * 2) & 0x80) != 0) {
        iStack_8 = iStack_8 + 1;
        uVar7 = FUN_00454374(param_1);
        bVar1 = *param_2;
        param_2 = pbVar10 + 2;
        if (bVar1 != uVar7) {
          iStack_8 = iStack_8 + -1;
          FUN_0045438e(uVar7,param_1);
          iStack_8 = iStack_8 + -1;
          FUN_0045438e(uVar4,param_1);
          goto LAB_0045431e;
        }
        iStack_8 = iStack_8 + -1;
      }
    }
    if ((uStack_18 == 0xffffffff) && ((*param_2 != 0x25 || (param_2[1] != 0x6e))))
    goto LAB_00454324;
    bVar1 = *param_2;
    pbVar10 = param_2;
  } while( true );
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

uint FUN_0045433d(uint param_1)

{
  uint uVar1;
  
  if (_DAT_0046ae4c < 2) {
    uVar1 = *(byte *)(_DAT_0046ac40 + param_1 * 2) & 4;
  }
  else {
    uVar1 = FUN_0044e6e0(param_1,4);
  }
  if (uVar1 == 0) {
    param_1 = (param_1 & 0xffffffdf) - 7;
  }
  return param_1;
}



uint FUN_00454374(byte **param_1)

{
  byte **ppbVar1;
  byte bVar2;
  uint uVar3;
  
  ppbVar1 = param_1 + 1;
  *ppbVar1 = *ppbVar1 + -1;
  if (-1 < (int)*ppbVar1) {
    bVar2 = **param_1;
    *param_1 = *param_1 + 1;
    return (uint)bVar2;
  }
  uVar3 = FUN_004546b9(param_1);
  return uVar3;
}



void FUN_0045438e(int param_1,undefined4 param_2)

{
  if (param_1 != -1) {
    FUN_0045720f(param_1,param_2);
  }
  return;
}



undefined4 FUN_004543a5(int *param_1,undefined4 param_2)

{
  undefined4 uVar1;
  int iVar2;
  
  do {
    *param_1 = *param_1 + 1;
    uVar1 = FUN_00454374(param_2);
    iVar2 = FUN_0044c39b(uVar1);
  } while (iVar2 != 0);
  return uVar1;
}



void FUN_004543c9(uint *param_1,int param_2)

{
  uint uVar1;
  int iVar2;
  uint uVar3;
  undefined auStack_1c [12];
  undefined4 uStack_10;
  undefined4 uStack_c;
  int iStack_8;
  
  uVar3 = 0;
  uVar1 = FUN_0045727d(auStack_1c,&iStack_8,param_2,0,0,0,0);
  if ((uVar1 & 4) == 0) {
    iVar2 = FUN_00456469(auStack_1c,&uStack_10);
    if (((uVar1 & 2) != 0) || (iVar2 == 1)) {
      uVar3 = 0x80;
    }
    if (((uVar1 & 1) != 0) || (iVar2 == 2)) {
      uVar3 = uVar3 | 0x100;
    }
  }
  else {
    uVar3 = 0x200;
    uStack_10 = 0;
    uStack_c = 0;
  }
  *param_1 = uVar3;
  *(ulonglong *)(param_1 + 4) = CONCAT44(uStack_c,uStack_10);
  param_1[1] = iStack_8 - param_2;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_00454448(uint param_1)

{
  undefined4 uVar1;
  undefined4 *puVar2;
  
  if ((param_1 < _DAT_004778e0) &&
     ((*(byte *)(*(int *)(&DAT_004777e0 + ((int)param_1 >> 5) * 4) + 4 + (param_1 & 0x1f) * 0x24) &
      1) != 0)) {
    FUN_004579ae(param_1);
    uVar1 = FUN_004544a5(param_1);
    FUN_00457a0d(param_1);
    return uVar1;
  }
  puVar2 = (undefined4 *)FUN_00451e44();
  *puVar2 = 9;
  puVar2 = (undefined4 *)FUN_00451e4d();
  *puVar2 = 0;
  return 0xffffffff;
}



undefined4 FUN_004544a5(uint param_1)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  
  iVar1 = FUN_0045796c(param_1);
  if (iVar1 != -1) {
    if ((param_1 == 1) || (param_1 == 2)) {
      iVar1 = FUN_0045796c(2);
      iVar2 = FUN_0045796c(1);
      if (iVar2 == iVar1) goto LAB_004544f3;
    }
    uVar3 = FUN_0045796c(param_1);
    iVar1 = CloseHandle(uVar3);
    if (iVar1 == 0) {
      iVar1 = GetLastError();
      goto LAB_004544f5;
    }
  }
LAB_004544f3:
  iVar1 = 0;
LAB_004544f5:
  FUN_004578ed(param_1);
  *(undefined *)(*(int *)(&DAT_004777e0 + ((int)param_1 >> 5) * 4) + 4 + (param_1 & 0x1f) * 0x24) =
       0;
  if (iVar1 == 0) {
    uVar3 = 0;
  }
  else {
    FUN_00451dd1(iVar1);
    uVar3 = 0xffffffff;
  }
  return uVar3;
}



undefined4 FUN_00454553(int param_1)

{
  undefined4 uVar1;
  
  if (param_1 == 0) {
    uVar1 = FUN_00454615(0);
    return uVar1;
  }
  FUN_0044daf5(param_1);
  uVar1 = FUN_00454582(param_1);
  FUN_0044db47(param_1);
  return uVar1;
}



int FUN_00454582(int param_1)

{
  int iVar1;
  
  iVar1 = FUN_004545b0(param_1);
  if (iVar1 != 0) {
    return -1;
  }
  if ((*(byte *)(param_1 + 0xd) & 0x40) != 0) {
    iVar1 = FUN_00457a2f(*(undefined4 *)(param_1 + 0x10));
    return -(uint)(iVar1 != 0);
  }
  return 0;
}



undefined4 FUN_004545b0(int *param_1)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  
  uVar2 = 0;
  if ((((byte)param_1[3] & 3) == 2) && ((param_1[3] & 0x108U) != 0)) {
    iVar3 = *param_1 - param_1[2];
    if (0 < iVar3) {
      iVar1 = FUN_00456824(param_1[4],param_1[2],iVar3);
      if (iVar1 == iVar3) {
        if ((param_1[3] & 0x80U) != 0) {
          param_1[3] = param_1[3] & 0xfffffffd;
        }
      }
      else {
        param_1[3] = param_1[3] | 0x20;
        uVar2 = 0xffffffff;
      }
    }
  }
  param_1[1] = 0;
  *param_1 = param_1[2];
  return uVar2;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_00454615(int param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  
  iVar2 = 0;
  iVar4 = 0;
  FUN_0044f15a(2);
  iVar3 = 0;
  if (0 < _DAT_00478900) {
    do {
      iVar1 = *(int *)(_DAT_004778f4 + iVar3 * 4);
      if ((iVar1 != 0) && ((*(byte *)(iVar1 + 0xc) & 0x83) != 0)) {
        FUN_0044db24(iVar3,iVar1);
        iVar1 = *(int *)(_DAT_004778f4 + iVar3 * 4);
        if ((*(uint *)(iVar1 + 0xc) & 0x83) != 0) {
          if (param_1 == 1) {
            iVar1 = FUN_00454582(iVar1);
            if (iVar1 != -1) {
              iVar2 = iVar2 + 1;
            }
          }
          else if ((param_1 == 0) && ((*(uint *)(iVar1 + 0xc) & 2) != 0)) {
            iVar1 = FUN_00454582(iVar1);
            if (iVar1 == -1) {
              iVar4 = -1;
            }
          }
        }
        FUN_0044db76(iVar3,*(undefined4 *)(_DAT_004778f4 + iVar3 * 4));
      }
      iVar3 = iVar3 + 1;
    } while (iVar3 < _DAT_00478900);
  }
  FUN_0044f1bb(2);
  if (param_1 != 1) {
    iVar2 = iVar4;
  }
  return iVar2;
}



uint FUN_004546b9(byte **param_1)

{
  byte bVar1;
  byte *pbVar2;
  byte *pbVar3;
  int iVar4;
  
  pbVar3 = param_1[3];
  if ((((uint)pbVar3 & 0x83) != 0) && (((uint)pbVar3 & 0x40) == 0)) {
    if (((uint)pbVar3 & 2) == 0) {
      param_1[3] = (byte *)((uint)pbVar3 | 1);
      if (((uint)pbVar3 & 0x10c) == 0) {
        FUN_00456a14(param_1);
      }
      else {
        *param_1 = param_1[2];
      }
      pbVar3 = (byte *)FUN_00454795(param_1[4],param_1[2],param_1[6]);
      param_1[1] = pbVar3;
      if ((pbVar3 != (byte *)0x0) && (pbVar3 != (byte *)0xffffffff)) {
        if (((uint)param_1[3] & 0x82) == 0) {
          pbVar2 = param_1[4];
          if (pbVar2 == (byte *)0xffffffff) {
            iVar4 = 0x46afb8;
          }
          else {
            iVar4 = *(int *)(&DAT_004777e0 + ((int)pbVar2 >> 5) * 4) + ((uint)pbVar2 & 0x1f) * 0x24;
          }
          if ((*(byte *)(iVar4 + 4) & 0x82) == 0x82) {
            param_1[3] = (byte *)((uint)param_1[3] | 0x2000);
          }
        }
        if (((param_1[6] == (byte *)0x200) && (((uint)param_1[3] & 8) != 0)) &&
           (((uint)param_1[3] & 0x400) == 0)) {
          param_1[6] = (byte *)0x1000;
        }
        param_1[1] = pbVar3 + -1;
        bVar1 = **param_1;
        *param_1 = *param_1 + 1;
        return (uint)bVar1;
      }
      param_1[3] = (byte *)((uint)param_1[3] | (-(uint)(pbVar3 != (byte *)0x0) & 0x10) + 0x10);
      param_1[1] = (byte *)0x0;
    }
    else {
      param_1[3] = (byte *)((uint)pbVar3 | 0x20);
    }
  }
  return 0xffffffff;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_00454795(uint param_1,undefined4 param_2,undefined4 param_3)

{
  undefined4 uVar1;
  undefined4 *puVar2;
  
  if ((param_1 < _DAT_004778e0) &&
     ((*(byte *)(*(int *)(&DAT_004777e0 + ((int)param_1 >> 5) * 4) + 4 + (param_1 & 0x1f) * 0x24) &
      1) != 0)) {
    FUN_004579ae(param_1);
    uVar1 = FUN_004547fa(param_1,param_2,param_3);
    FUN_00457a0d(param_1);
    return uVar1;
  }
  puVar2 = (undefined4 *)FUN_00451e44();
  *puVar2 = 9;
  puVar2 = (undefined4 *)FUN_00451e4d();
  *puVar2 = 0;
  return 0xffffffff;
}



int FUN_004547fa(uint param_1,char *param_2,char *param_3)

{
  int *piVar1;
  byte *pbVar2;
  char cVar3;
  byte bVar4;
  int iVar5;
  undefined4 *puVar6;
  char *pcVar7;
  int iVar8;
  int iStack_10;
  char *pcStack_c;
  char cStack_5;
  
  pcStack_c = (char *)0x0;
  if (param_3 != (char *)0x0) {
    piVar1 = (int *)(&DAT_004777e0 + ((int)param_1 >> 5) * 4);
    iVar8 = (param_1 & 0x1f) * 0x24;
    bVar4 = *(byte *)(*(int *)(&DAT_004777e0 + ((int)param_1 >> 5) * 4) + iVar8 + 4);
    if ((bVar4 & 2) == 0) {
      pcVar7 = param_2;
      if (((bVar4 & 0x48) != 0) &&
         (cVar3 = *(char *)(*(int *)(&DAT_004777e0 + ((int)param_1 >> 5) * 4) + iVar8 + 5),
         cVar3 != '\n')) {
        param_3 = (char *)((int)param_3 + -1);
        *param_2 = cVar3;
        pcVar7 = param_2 + 1;
        pcStack_c = (char *)0x1;
        *(undefined *)(*piVar1 + 5 + iVar8) = 10;
      }
      iVar5 = ReadFile(*(undefined4 *)(*piVar1 + iVar8),pcVar7,param_3,&iStack_10,0);
      if (iVar5 == 0) {
        iVar8 = GetLastError();
        if (iVar8 == 5) {
          puVar6 = (undefined4 *)FUN_00451e44();
          *puVar6 = 9;
          puVar6 = (undefined4 *)FUN_00451e4d();
          *puVar6 = 5;
        }
        else {
          if (iVar8 == 0x6d) {
            return 0;
          }
          FUN_00451dd1(iVar8);
        }
        return -1;
      }
      bVar4 = *(byte *)(*piVar1 + 4 + iVar8);
      if ((bVar4 & 0x80) == 0) {
        return (int)pcStack_c + iStack_10;
      }
      if ((iStack_10 == 0) || (*param_2 != '\n')) {
        bVar4 = bVar4 & 0xfb;
      }
      else {
        bVar4 = bVar4 | 4;
      }
      *(byte *)(*piVar1 + 4 + iVar8) = bVar4;
      param_3 = param_2;
      pcStack_c = param_2 + (int)pcStack_c + iStack_10;
      pcVar7 = param_2;
      if (param_2 < pcStack_c) {
        do {
          cVar3 = *param_3;
          if (cVar3 == '\x1a') {
            pbVar2 = (byte *)(*piVar1 + 4 + iVar8);
            bVar4 = *pbVar2;
            if ((bVar4 & 0x40) == 0) {
              *pbVar2 = bVar4 | 2;
            }
            break;
          }
          if (cVar3 == '\r') {
            if (param_3 < pcStack_c + -1) {
              if (param_3[1] == '\n') {
                param_3 = param_3 + 2;
                goto LAB_00454985;
              }
              *pcVar7 = '\r';
              pcVar7 = pcVar7 + 1;
              param_3 = param_3 + 1;
            }
            else {
              param_3 = param_3 + 1;
              iVar5 = ReadFile(*(undefined4 *)(*piVar1 + iVar8),&cStack_5,1,&iStack_10,0);
              if (((iVar5 == 0) && (iVar5 = GetLastError(), iVar5 != 0)) || (iStack_10 == 0)) {
LAB_0045499f:
                *pcVar7 = '\r';
LAB_004549a2:
                pcVar7 = pcVar7 + 1;
              }
              else if ((*(byte *)(*piVar1 + 4 + iVar8) & 0x48) == 0) {
                if ((pcVar7 == param_2) && (cStack_5 == '\n')) {
LAB_00454985:
                  *pcVar7 = '\n';
                  goto LAB_004549a2;
                }
                FUN_004567b1(param_1,0xffffffff,1);
                if (cStack_5 != '\n') goto LAB_0045499f;
              }
              else {
                if (cStack_5 == '\n') goto LAB_00454985;
                *pcVar7 = '\r';
                pcVar7 = pcVar7 + 1;
                *(char *)(*piVar1 + 5 + iVar8) = cStack_5;
              }
            }
          }
          else {
            *pcVar7 = cVar3;
            pcVar7 = pcVar7 + 1;
            param_3 = param_3 + 1;
          }
        } while (param_3 < pcStack_c);
      }
      return (int)pcVar7 - (int)param_2;
    }
  }
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_004549d3(byte *param_1,byte *param_2)

{
  byte *pbVar1;
  int iVar2;
  uint uVar3;
  byte *pbVar4;
  ushort uVar5;
  ushort uVar6;
  uint uVar7;
  byte *pbStack_10;
  byte *pbStack_c;
  byte bStack_8;
  byte bStack_7;
  
  if (_DAT_0047758c == 0) {
    iVar2 = FUN_0044e610(param_1,param_2);
  }
  else {
    FUN_0044f15a(0x19);
    pbStack_10 = param_2 + -1;
    pbStack_c = param_1 + -1;
    do {
      uVar7 = (uint)*param_1;
      pbVar4 = param_1 + 1;
      pbVar1 = pbStack_c + 1;
      if ((*(byte *)(uVar7 + 0x4776a1) & 4) == 0) {
        param_1 = pbVar4;
        pbStack_c = pbVar1;
        if ((*(byte *)(uVar7 + 0x4776a1) & 0x10) == 0x10) {
          uVar7 = (uint)*(byte *)(uVar7 + 0x4775a0);
        }
      }
      else if (*pbVar4 == 0) {
        uVar7 = 0;
        param_1 = pbVar4;
        pbStack_c = pbVar1;
      }
      else {
        iVar2 = FUN_0044f1d0(_DAT_004777a4,0x200,pbVar1,2,&bStack_8,2,_DAT_00477578,1);
        if (iVar2 == 1) {
          uVar7 = (uint)bStack_8;
        }
        else {
          if (iVar2 != 2) goto LAB_00454b37;
          uVar7 = (uint)bStack_8 * 0x100 + (uint)bStack_7;
        }
        param_1 = param_1 + 2;
        pbStack_c = pbStack_c + 2;
      }
      uVar3 = (uint)*param_2;
      uVar5 = (ushort)*param_2;
      pbVar4 = param_2 + 1;
      pbVar1 = pbStack_10 + 1;
      if ((*(byte *)(uVar3 + 0x4776a1) & 4) == 0) {
        param_2 = pbVar4;
        pbStack_10 = pbVar1;
        if ((*(byte *)(uVar3 + 0x4776a1) & 0x10) == 0x10) {
          uVar5 = (ushort)*(byte *)(uVar3 + 0x4775a0);
        }
      }
      else if (*pbVar4 == 0) {
        uVar5 = 0;
        param_2 = pbVar4;
        pbStack_10 = pbVar1;
      }
      else {
        iVar2 = FUN_0044f1d0(_DAT_004777a4,0x200,pbVar1,2,&bStack_8,2,_DAT_00477578,1);
        if (iVar2 == 1) {
          uVar5 = (ushort)bStack_8;
        }
        else {
          if (iVar2 != 2) {
LAB_00454b37:
            FUN_0044f1bb(0x19);
            return 0x7fffffff;
          }
          uVar5 = (ushort)bStack_8 * 0x100 + (ushort)bStack_7;
        }
        param_2 = param_2 + 2;
        pbStack_10 = pbStack_10 + 2;
      }
      uVar6 = (ushort)uVar7;
      if (uVar6 != uVar5) {
        FUN_0044f1bb(0x19);
        return (-(uint)(uVar5 < uVar6) & 2) - 1;
      }
    } while (uVar6 != 0);
    FUN_0044f1bb(0x19);
    iVar2 = 0;
  }
  return iVar2;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_00454b68(int param_1,int param_2,int param_3,int param_4,int param_5,int param_6,int param_7
                )

{
  int iVar1;
  undefined auStack_28 [8];
  int iStack_20;
  int iStack_18;
  uint uStack_14;
  int iStack_c;
  
  uStack_14 = param_1 - 0x76c;
  if (((int)uStack_14 < 0x46) || (0x8a < (int)uStack_14)) {
    param_6 = -1;
  }
  else {
    iStack_c = *(int *)(param_2 * 4 + 0x46dd54) + param_3;
    if (((uStack_14 & 3) == 0) && (2 < param_2)) {
      iStack_c = iStack_c + 1;
    }
    FUN_00457ac2();
    iStack_20 = param_4;
    iStack_18 = param_2 + -1;
    param_6 = ((param_4 + (uStack_14 * 0x16d + iStack_c + (param_1 + -0x76d >> 2)) * 0x18) * 0x3c +
              param_5) * 0x3c + _DAT_0046dc70 + 0x7c558180 + param_6;
    if ((param_7 == 1) ||
       (((param_7 == -1 && (_DAT_0046dc74 != 0)) && (iVar1 = FUN_00457d77(auStack_28), iVar1 != 0)))
       ) {
      param_6 = param_6 + _DAT_0046dc78;
    }
  }
  return param_6;
}



int FUN_00454c2a(int param_1,char *param_2,uint param_3)

{
  char *pcVar1;
  int iVar2;
  undefined4 *puVar3;
  uint uVar4;
  undefined4 uVar5;
  
  pcVar1 = param_2;
  if ((param_2 != (char *)0x0) && (*param_2 != '\0')) {
    iVar2 = param_1;
    if (param_1 == 0) {
      iVar2 = FUN_0044c5a2(0x104);
      if (iVar2 == 0) {
        puVar3 = (undefined4 *)FUN_00451e44();
        *puVar3 = 0xc;
        return 0;
      }
      param_3 = 0x104;
    }
    uVar4 = GetFullPathNameA(pcVar1,param_3,iVar2,&param_2);
    if (uVar4 < param_3) {
      if (uVar4 != 0) {
        return iVar2;
      }
      if (param_1 == 0) {
        FUN_0044c4b9(iVar2);
      }
      uVar5 = GetLastError();
      FUN_00451dd1(uVar5);
    }
    else {
      if (param_1 == 0) {
        FUN_0044c4b9(iVar2);
      }
      puVar3 = (undefined4 *)FUN_00451e44();
      *puVar3 = 0x22;
    }
    return 0;
  }
  iVar2 = FUN_00458084(param_1,param_3);
  return iVar2;
}



int FUN_00454ccf(void)

{
  int iVar1;
  int iVar2;
  undefined uStack_108;
  char cStack_107;
  
  iVar2 = 0;
  iVar1 = GetCurrentDirectoryA(0x104,&uStack_108);
  if ((iVar1 != 0) && (cStack_107 == ':')) {
    iVar2 = FUN_0044bf1a(uStack_108);
    iVar2 = iVar2 + -0x40;
  }
  return iVar2;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

uint FUN_00454d12(uint param_1)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  undefined uVar5;
  undefined2 uStack_8;
  
  uVar4 = param_1;
  if (param_1 < 0x100) {
    if ((*(byte *)(param_1 + 0x4776a1) & 0x10) == 0x10) {
      uVar4 = (uint)*(byte *)(param_1 + 0x4775a0);
    }
  }
  else {
    uVar5 = (undefined)param_1;
    uVar2 = param_1 >> 8;
    uVar1 = param_1 >> 8;
    param_1 = CONCAT13(uVar5,CONCAT12((char)uVar1,(undefined2)param_1));
    if (((*(byte *)((uVar2 & 0xff) + 0x4776a1) & 4) != 0) &&
       (iVar3 = FUN_0044f1d0(_DAT_004777a4,0x100,(int)&param_1 + 2,2,&uStack_8,2,_DAT_00477578,1),
       iVar3 != 0)) {
      uVar4 = (uint)CONCAT11((undefined)uStack_8,uStack_8._1_1_);
    }
  }
  return uVar4;
}



void FUN_00454fc5(void)

{
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0045502a(int *param_1)

{
  int *piVar1;
  int iVar2;
  
  iVar2 = FUN_00456a58(param_1[4]);
  if (iVar2 == 0) {
    return 0;
  }
  if (param_1 == (int *)0x46a9b0) {
    iVar2 = 0;
  }
  else {
    if (param_1 != (int *)0x46a9d0) {
      return 0;
    }
    iVar2 = 1;
  }
  _DAT_00475d10 = _DAT_00475d10 + 1;
  if ((*(ushort *)(param_1 + 3) & 0x10c) != 0) {
    return 0;
  }
  piVar1 = (int *)(iVar2 * 4 + 0x475f58);
  if (*(int *)(iVar2 * 4 + 0x475f58) == 0) {
    iVar2 = FUN_0044c5a2(0x1000);
    *piVar1 = iVar2;
    if (iVar2 == 0) {
      param_1[2] = (int)(param_1 + 5);
      *param_1 = (int)(param_1 + 5);
      param_1[6] = 2;
      param_1[1] = 2;
      goto LAB_004550a6;
    }
  }
  iVar2 = *piVar1;
  param_1[6] = 0x1000;
  param_1[2] = iVar2;
  *param_1 = iVar2;
  param_1[1] = 0x1000;
LAB_004550a6:
  *(ushort *)(param_1 + 3) = *(ushort *)(param_1 + 3) | 0x1102;
  return 1;
}



void FUN_004550b7(int param_1,undefined4 *param_2)

{
  if ((param_1 != 0) && ((*(byte *)((int)param_2 + 0xd) & 0x10) != 0)) {
    FUN_004545b0(param_2);
    *(byte *)((int)param_2 + 0xd) = *(byte *)((int)param_2 + 0xd) & 0xee;
    param_2[6] = 0;
    *param_2 = 0;
    param_2[2] = 0;
  }
  return;
}



float10 __fastcall
FUN_00455550(undefined4 param_1,undefined4 param_2,undefined2 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,undefined4 param_7,undefined4 param_8)

{
  float10 in_ST0;
  undefined auStack_24 [8];
  undefined4 uStack_1c;
  undefined4 uStack_18;
  undefined4 uStack_14;
  undefined4 uStack_10;
  double dStack_c;
  
  uStack_14 = param_7;
  uStack_10 = param_8;
  dStack_c = (double)in_ST0;
  uStack_1c = param_5;
  uStack_18 = param_6;
  FUN_0045921b(param_2,auStack_24,&param_3);
  return (float10)dStack_c;
}



float10 __fastcall
FUN_00455567(undefined4 param_1,undefined4 param_2,undefined2 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6)

{
  float10 in_ST0;
  undefined auStack_24 [8];
  undefined4 uStack_1c;
  undefined4 uStack_18;
  double dStack_c;
  
  dStack_c = (double)in_ST0;
  uStack_1c = param_5;
  uStack_18 = param_6;
  FUN_0045921b(param_2,auStack_24,&param_3);
  return (float10)dStack_c;
}



unkbyte10 FUN_004555b0(void)

{
  float10 in_ST0;
  float10 fVar1;
  unkbyte10 Var2;
  
  fVar1 = (float10)f2xm1(-(ROUND(in_ST0) - in_ST0));
  Var2 = fscale((float10)1 + fVar1,ROUND(in_ST0));
  return Var2;
}



void FUN_004555c5(void)

{
  return;
}



uint __fastcall FUN_004555f5(undefined4 param_1,int param_2)

{
  uint uVar1;
  
  uVar1 = *(uint *)(param_2 + 4) & 0x7ff00000;
  if (uVar1 != 0x7ff00000) {
    return uVar1;
  }
  return *(uint *)(param_2 + 4);
}



void FUN_0045564e(void)

{
  return;
}



void __fastcall FUN_00455699(undefined4 param_1,int param_2)

{
  ushort in_FPUStatusWord;
  float10 in_ST0;
  ushort unaff_retaddr;
  uint uStack_4;
  
  uStack_4 = (uint)((ulonglong)(double)in_ST0 >> 0x20);
  if (((ulonglong)(double)in_ST0 & 0x7ff0000000000000) == 0) {
    fscale(in_ST0,(float10)1536.0);
  }
  else if ((uStack_4 & 0x7ff00000) == 0x7ff00000) {
    fscale(in_ST0,(float10)-1536.0);
  }
  else if (((unaff_retaddr == 0x27f) || ((unaff_retaddr & 0x20) != 0)) ||
          ((in_FPUStatusWord & 0x20) == 0)) {
    return;
  }
  if (param_2 == 0x1d) {
    FUN_00455550();
    return;
  }
  FUN_00455567();
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0045573c(int param_1,int param_2,double param_3,double *param_4)

{
  double dVar1;
  double dVar2;
  int iVar3;
  
  dVar1 = (double)CONCAT44(param_2,param_1);
  if ((double)CONCAT44(param_2,param_1) < 0.0) {
    dVar1 = -dVar1;
  }
  dVar2 = _DAT_0046def0;
  if (param_3._4_4_ == 0x7ff00000) {
    if (param_3._0_4_ != 0) {
LAB_004557c7:
      if (param_2 == 0x7ff00000) {
        if (param_1 != 0) {
          return 0;
        }
        if (0.0 < param_3) goto LAB_00455862;
        if (param_3 < 0.0) goto LAB_004557f9;
      }
      else {
        if (param_2 != -0x100000) {
          return 0;
        }
        if (param_1 != 0) {
          return 0;
        }
        iVar3 = FUN_0045586c(param_3);
        if (0.0 < param_3) {
          dVar2 = _DAT_0046def0;
          if (iVar3 == 1) {
            dVar2 = -_DAT_0046def0;
          }
          goto LAB_00455862;
        }
        if (param_3 < 0.0) {
          dVar2 = _DAT_0046df10;
          if (iVar3 != 1) {
            dVar2 = 0.0;
          }
          goto LAB_00455862;
        }
      }
      dVar2 = 1.0;
      goto LAB_00455862;
    }
    if (1.0 < dVar1) goto LAB_00455862;
    if (1.0 <= dVar1) {
LAB_0045578c:
      *param_4 = _DAT_0046def8;
      return 1;
    }
  }
  else {
    if ((param_3._4_4_ != -0x100000) || (param_3._0_4_ != 0)) goto LAB_004557c7;
    if (dVar1 <= 1.0) {
      if (1.0 <= dVar1) goto LAB_0045578c;
      goto LAB_00455862;
    }
  }
LAB_004557f9:
  dVar2 = 0.0;
LAB_00455862:
  *param_4 = dVar2;
  return 0;
}



undefined4 __thiscall FUN_0045586c(undefined4 param_1,double param_2)

{
  uint uVar1;
  float10 fVar2;
  undefined4 uVar3;
  
  uVar1 = FUN_00459441(param_2,param_1,param_1);
  if ((uVar1 & 0x90) == 0) {
    fVar2 = (float10)FUN_0045942f(param_2);
    if ((double)fVar2 == param_2) {
      fVar2 = (float10)FUN_0045942f();
      if (fVar2 == (float10)(param_2 / 2.0)) {
        uVar3 = 2;
      }
      else {
        uVar3 = 1;
      }
      return uVar3;
    }
  }
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_004558d1(undefined4 param_1)

{
  byte bVar1;
  byte bVar2;
  int iVar3;
  int *piVar4;
  uint uVar5;
  int iVar6;
  byte *pbVar7;
  int iVar8;
  byte *pbVar9;
  undefined4 uVar10;
  uint uVar11;
  undefined4 *puVar12;
  uint uStack_1c;
  byte abStack_16 [14];
  uint uStack_8;
  
  FUN_0044f15a(0x19);
  iVar3 = FUN_00455a7e(param_1);
  if (iVar3 != _DAT_00477578) {
    if (iVar3 != 0) {
      iVar8 = 0;
      piVar4 = (int *)0x46da48;
LAB_0045590e:
      if (*piVar4 != iVar3) goto code_r0x00455912;
      uStack_8 = 0;
      puVar12 = (undefined4 *)0x4776a0;
      for (iVar6 = 0x40; iVar6 != 0; iVar6 = iVar6 + -1) {
        *puVar12 = 0;
        puVar12 = puVar12 + 1;
      }
      iVar8 = iVar8 * 0x30;
      *(undefined *)puVar12 = 0;
      pbVar9 = (byte *)(iVar8 + 0x46da58);
      do {
        bVar1 = *pbVar9;
        pbVar7 = pbVar9;
        while ((bVar1 != 0 && (bVar1 = pbVar7[1], bVar1 != 0))) {
          uVar11 = (uint)*pbVar7;
          if (uVar11 <= bVar1) {
            bVar2 = *(byte *)(uStack_8 + 0x46da40);
            do {
              *(byte *)(uVar11 + 0x4776a1) = *(byte *)(uVar11 + 0x4776a1) | bVar2;
              uVar11 = uVar11 + 1;
            } while (uVar11 <= bVar1);
          }
          pbVar7 = pbVar7 + 2;
          bVar1 = *pbVar7;
        }
        uStack_8 = uStack_8 + 1;
        pbVar9 = pbVar9 + 8;
      } while (uStack_8 < 4);
      _DAT_0047758c = 1;
      _DAT_00477578 = iVar3;
      _DAT_004777a4 = FUN_00455ac8(iVar3);
      uRam00477580 = *(undefined4 *)(iVar8 + 0x46da4c);
      uRam00477584 = *(undefined4 *)(iVar8 + 0x46da50);
      uRam00477588 = *(undefined4 *)(iVar8 + 0x46da54);
      goto LAB_00455a62;
    }
    goto LAB_00455a5d;
  }
  goto LAB_004558f8;
code_r0x00455912:
  piVar4 = piVar4 + 0xc;
  iVar8 = iVar8 + 1;
  if ((int *)0x46db37 < piVar4) goto code_r0x0045591d;
  goto LAB_0045590e;
code_r0x0045591d:
  iVar8 = GetCPInfo(iVar3,&uStack_1c);
  uVar11 = 1;
  if (iVar8 == 1) {
    _DAT_004777a4 = 0;
    puVar12 = (undefined4 *)0x4776a0;
    for (iVar8 = 0x40; iVar8 != 0; iVar8 = iVar8 + -1) {
      *puVar12 = 0;
      puVar12 = puVar12 + 1;
    }
    *(undefined *)puVar12 = 0;
    if (uStack_1c < 2) {
      _DAT_0047758c = 0;
      _DAT_00477578 = iVar3;
    }
    else {
      _DAT_00477578 = iVar3;
      if (abStack_16[0] != 0) {
        pbVar9 = abStack_16 + 1;
        do {
          bVar1 = *pbVar9;
          if (bVar1 == 0) break;
          for (uVar5 = (uint)pbVar9[-1]; uVar5 <= bVar1; uVar5 = uVar5 + 1) {
            *(byte *)(uVar5 + 0x4776a1) = *(byte *)(uVar5 + 0x4776a1) | 4;
          }
          pbVar7 = pbVar9 + 1;
          pbVar9 = pbVar9 + 2;
        } while (*pbVar7 != 0);
      }
      do {
        *(byte *)(uVar11 + 0x4776a1) = *(byte *)(uVar11 + 0x4776a1) | 8;
        uVar11 = uVar11 + 1;
      } while (uVar11 < 0xff);
      _DAT_004777a4 = FUN_00455ac8(iVar3);
      _DAT_0047758c = 1;
    }
    uRam00477580 = 0;
    uRam00477584 = 0;
    uRam00477588 = 0;
  }
  else {
    if (_DAT_00475f60 == 0) {
      uVar10 = 0xffffffff;
      goto LAB_00455a6f;
    }
LAB_00455a5d:
    FUN_00455afb();
  }
LAB_00455a62:
  FUN_00455b24();
LAB_004558f8:
  uVar10 = 0;
LAB_00455a6f:
  FUN_0044f1bb(0x19);
  return uVar10;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_00455a7e(int param_1)

{
  int iVar1;
  bool bVar2;
  
  if (param_1 == -2) {
    _DAT_00475f60 = 1;
                    // WARNING: Could not recover jumptable at 0x00455a98. Too many branches
                    // WARNING: Treating indirect jump as call
    iVar1 = GetOEMCP();
    return iVar1;
  }
  if (param_1 == -3) {
    _DAT_00475f60 = 1;
                    // WARNING: Could not recover jumptable at 0x00455aad. Too many branches
                    // WARNING: Treating indirect jump as call
    iVar1 = GetACP();
    return iVar1;
  }
  bVar2 = param_1 == -4;
  if (bVar2) {
    param_1 = _DAT_00475dd0;
  }
  _DAT_00475f60 = (uint)bVar2;
  return param_1;
}



undefined4 FUN_00455ac8(int param_1)

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

void FUN_00455afb(void)

{
  int iVar1;
  undefined4 *puVar2;
  
  puVar2 = (undefined4 *)0x4776a0;
  for (iVar1 = 0x40; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  *(undefined *)puVar2 = 0;
  _DAT_00477578 = 0;
  _DAT_0047758c = 0;
  _DAT_004777a4 = 0;
  uRam00477580 = 0;
  uRam00477584 = 0;
  uRam00477588 = 0;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00455b24(void)

{
  int iVar1;
  uint uVar2;
  char cVar3;
  uint uVar4;
  uint uVar5;
  ushort *puVar6;
  undefined uVar7;
  byte *pbVar8;
  undefined4 *puVar9;
  ushort auStack_518 [256];
  undefined auStack_318 [256];
  undefined auStack_218 [256];
  undefined4 auStack_118 [64];
  undefined auStack_18 [6];
  byte bStack_12;
  byte abStack_11 [13];
  
  iVar1 = GetCPInfo(_DAT_00477578,auStack_18);
  if (iVar1 == 1) {
    uVar2 = 0;
    do {
      *(char *)((int)auStack_118 + uVar2) = (char)uVar2;
      uVar2 = uVar2 + 1;
    } while (uVar2 < 0x100);
    auStack_118[0]._0_1_ = 0x20;
    if (bStack_12 != 0) {
      pbVar8 = abStack_11;
      do {
        uVar2 = (uint)bStack_12;
        if (uVar2 <= *pbVar8) {
          uVar4 = (*pbVar8 - uVar2) + 1;
          puVar9 = (undefined4 *)((int)auStack_118 + uVar2);
          for (uVar5 = uVar4 >> 2; uVar5 != 0; uVar5 = uVar5 - 1) {
            *puVar9 = 0x20202020;
            puVar9 = puVar9 + 1;
          }
          for (uVar4 = uVar4 & 3; uVar4 != 0; uVar4 = uVar4 - 1) {
            *(undefined *)puVar9 = 0x20;
            puVar9 = (undefined4 *)((int)puVar9 + 1);
          }
        }
        bStack_12 = pbVar8[1];
        pbVar8 = pbVar8 + 2;
      } while (bStack_12 != 0);
    }
    FUN_00455df0(1,auStack_118,0x100,auStack_518,_DAT_00477578,_DAT_004777a4,0);
    FUN_0044f1d0(_DAT_004777a4,0x100,auStack_118,0x100,auStack_218,0x100,_DAT_00477578,0);
    FUN_0044f1d0(_DAT_004777a4,0x200,auStack_118,0x100,auStack_318,0x100,_DAT_00477578,0);
    uVar2 = 0;
    puVar6 = auStack_518;
    do {
      if ((*puVar6 & 1) == 0) {
        if ((*puVar6 & 2) != 0) {
          *(byte *)(uVar2 + 0x4776a1) = *(byte *)(uVar2 + 0x4776a1) | 0x20;
          uVar7 = auStack_318[uVar2];
          goto LAB_00455c30;
        }
        *(undefined *)(uVar2 + 0x4775a0) = 0;
      }
      else {
        *(byte *)(uVar2 + 0x4776a1) = *(byte *)(uVar2 + 0x4776a1) | 0x10;
        uVar7 = auStack_218[uVar2];
LAB_00455c30:
        *(undefined *)(uVar2 + 0x4775a0) = uVar7;
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
          *(byte *)(uVar2 + 0x4776a1) = *(byte *)(uVar2 + 0x4776a1) | 0x20;
          cVar3 = (char)uVar2 + -0x20;
          goto LAB_00455c7a;
        }
        *(undefined *)(uVar2 + 0x4775a0) = 0;
      }
      else {
        *(byte *)(uVar2 + 0x4776a1) = *(byte *)(uVar2 + 0x4776a1) | 0x10;
        cVar3 = (char)uVar2 + ' ';
LAB_00455c7a:
        *(char *)(uVar2 + 0x4775a0) = cVar3;
      }
      uVar2 = uVar2 + 1;
    } while (uVar2 < 0x100);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00455ca9(void)

{
  if (_DAT_004778e8 == 0) {
    FUN_004558d1(0xfffffffd);
    _DAT_004778e8 = 1;
  }
  return;
}



char * FUN_00455d40(char *param_1,char param_2)

{
  char cVar1;
  int iVar2;
  char *pcVar3;
  char *pcVar4;
  
  iVar2 = -1;
  do {
    pcVar4 = param_1;
    if (iVar2 == 0) break;
    iVar2 = iVar2 + -1;
    pcVar4 = param_1 + 1;
    cVar1 = *param_1;
    param_1 = pcVar4;
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
  } while (param_2 != cVar1);
  pcVar3 = pcVar3 + 1;
  if (*pcVar3 != param_2) {
    pcVar3 = (char *)0x0;
  }
  return pcVar3;
}



uint * FUN_00455d70(uint *param_1,char *param_2)

{
  char *pcVar1;
  char *pcVar2;
  char cVar3;
  uint uVar4;
  uint *puVar5;
  char cVar6;
  uint uVar7;
  uint uVar8;
  char *pcVar9;
  uint *puVar10;
  
  cVar3 = *param_2;
  if (cVar3 == '\0') {
    return param_1;
  }
  if (param_2[1] == '\0') {
    uVar4 = (uint)param_1 & 3;
    while (uVar4 != 0) {
      if (*(char *)param_1 == cVar3) {
        return param_1;
      }
      if (*(char *)param_1 == '\0') {
        return (uint *)0x0;
      }
      uVar4 = (uint)(uint *)((int)param_1 + 1) & 3;
      param_1 = (uint *)((int)param_1 + 1);
    }
    while( true ) {
      while( true ) {
        uVar4 = *param_1;
        uVar8 = uVar4 ^ CONCAT22(CONCAT11(cVar3,cVar3),CONCAT11(cVar3,cVar3));
        uVar7 = uVar4 ^ 0xffffffff ^ uVar4 + 0x7efefeff;
        puVar10 = param_1 + 1;
        if (((uVar8 ^ 0xffffffff ^ uVar8 + 0x7efefeff) & 0x81010100) != 0) break;
        param_1 = puVar10;
        if ((uVar7 & 0x81010100) != 0) {
          if ((uVar7 & 0x1010100) != 0) {
            return (uint *)0x0;
          }
          if ((uVar4 + 0x7efefeff & 0x80000000) == 0) {
            return (uint *)0x0;
          }
        }
      }
      uVar4 = *param_1;
      if ((char)uVar4 == cVar3) {
        return param_1;
      }
      if ((char)uVar4 == '\0') {
        return (uint *)0x0;
      }
      cVar6 = (char)(uVar4 >> 8);
      if (cVar6 == cVar3) {
        return (uint *)((int)param_1 + 1);
      }
      if (cVar6 == '\0') break;
      cVar6 = (char)(uVar4 >> 0x10);
      if (cVar6 == cVar3) {
        return (uint *)((int)param_1 + 2);
      }
      if (cVar6 == '\0') {
        return (uint *)0x0;
      }
      cVar6 = (char)(uVar4 >> 0x18);
      if (cVar6 == cVar3) {
        return (uint *)((int)param_1 + 3);
      }
      param_1 = puVar10;
      if (cVar6 == '\0') {
        return (uint *)0x0;
      }
    }
    return (uint *)0x0;
  }
  do {
    cVar6 = *(char *)param_1;
    do {
      while (puVar10 = param_1, param_1 = (uint *)((int)puVar10 + 1), cVar6 != cVar3) {
        if (cVar6 == '\0') {
          return (uint *)0x0;
        }
        cVar6 = *(char *)param_1;
      }
      cVar6 = *(char *)param_1;
      pcVar9 = param_2;
      puVar5 = puVar10;
    } while (cVar6 != param_2[1]);
    do {
      if (pcVar9[2] == '\0') {
        return puVar10;
      }
      if (*(char *)(uint *)((int)puVar5 + 2) != pcVar9[2]) break;
      pcVar1 = pcVar9 + 3;
      if (*pcVar1 == '\0') {
        return puVar10;
      }
      pcVar2 = (char *)((int)puVar5 + 3);
      pcVar9 = pcVar9 + 2;
      puVar5 = (uint *)((int)puVar5 + 2);
    } while (*pcVar1 == *pcVar2);
  } while( true );
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4
FUN_00455df0(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,int param_5
            ,int param_6,int param_7)

{
  undefined *puVar1;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  int iStack_50;
  int iStack_4c;
  undefined4 uStack_48;
  undefined *puStack_44;
  undefined4 uStack_40;
  undefined *puStack_3c;
  undefined auStack_20 [4];
  int *piStack_1c;
  void *pvStack_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 uStack_8;
  
  uStack_8 = 0xffffffff;
  puStack_c = &UNK_0045fd50;
  puStack_10 = &UNK_0045001c;
  pvStack_14 = ExceptionList;
  piStack_1c = (int *)&stack0xffffffc8;
  iVar4 = _DAT_00475f64;
  ExceptionList = &pvStack_14;
  puVar1 = &stack0xffffffc8;
  if (_DAT_00475f64 == 0) {
    puStack_3c = auStack_20;
    uStack_40 = 1;
    puStack_44 = &UNK_0045f2b8;
    uStack_48 = 1;
    iStack_4c = 0x455e35;
    ExceptionList = &pvStack_14;
    iVar2 = GetStringTypeW();
    iVar4 = 1;
    puVar1 = (undefined *)piStack_1c;
    if (iVar2 == 0) {
      puStack_3c = auStack_20;
      uStack_40 = 1;
      puStack_44 = (undefined *)0x4747d4;
      uStack_48 = 1;
      iStack_4c = 0;
      iStack_50 = 0x455e4f;
      iVar4 = GetStringTypeA();
      if (iVar4 == 0) {
        ExceptionList = pvStack_14;
        return 0;
      }
      iVar4 = 2;
      puVar1 = (undefined *)piStack_1c;
    }
  }
  piStack_1c = (int *)puVar1;
  _DAT_00475f64 = iVar4;
  if (_DAT_00475f64 != 2) {
    if (_DAT_00475f64 == 1) {
      if (param_5 == 0) {
        param_5 = _DAT_00475dd0;
      }
      puStack_3c = (undefined *)0x0;
      uStack_40 = 0;
      puStack_44 = (undefined *)param_3;
      uStack_48 = param_2;
      iStack_4c = (-(uint)(param_7 != 0) & 8) + 1;
      iStack_50 = param_5;
      iVar4 = MultiByteToWideChar();
      if (iVar4 != 0) {
        uStack_8 = 0;
        FUN_0044c080();
        piStack_1c = &iStack_50;
        FUN_004538c0(&iStack_50,0,iVar4 * 2);
        uStack_8 = 0xffffffff;
        if ((&stack0x00000000 != (undefined *)0x50) &&
           (iVar4 = MultiByteToWideChar(param_5,1,param_2,param_3,&iStack_50,iVar4), iVar4 != 0)) {
          uVar3 = GetStringTypeW(param_1,&iStack_50,iVar4,param_4);
          ExceptionList = pvStack_14;
          return uVar3;
        }
      }
    }
    ExceptionList = pvStack_14;
    return 0;
  }
  if (param_6 == 0) {
    param_6 = _DAT_00475dc0;
  }
  puStack_3c = (undefined *)param_4;
  uStack_40 = param_3;
  puStack_44 = (undefined *)param_2;
  uStack_48 = param_1;
  iStack_50 = 0x455e83;
  iStack_4c = param_6;
  uVar3 = GetStringTypeA();
  ExceptionList = pvStack_14;
  return uVar3;
}



uint FUN_00455fe8(uint param_1)

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



uint FUN_0045607a(uint param_1)

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



undefined4 FUN_00456103(int param_1,int param_2)

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



void FUN_0045614c(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  undefined4 *puVar3;
  
  puVar3 = (undefined4 *)(param_1 + (param_2 / 0x20) * 4);
  iVar1 = FUN_00459799(*puVar3,1 << (0x1fU - (char)(param_2 % 0x20) & 0x1f),puVar3);
  iVar2 = param_2 / 0x20 + -1;
  if (-1 < iVar2) {
    puVar3 = (undefined4 *)(param_1 + iVar2 * 4);
    do {
      if (iVar1 == 0) {
        return;
      }
      iVar1 = FUN_00459799(*puVar3,1,puVar3);
      iVar2 = iVar2 + -1;
      puVar3 = puVar3 + -1;
    } while (-1 < iVar2);
  }
  return;
}



undefined4 FUN_004561a2(int param_1,int param_2)

{
  uint *puVar1;
  int iVar2;
  byte bVar3;
  int iVar4;
  undefined4 *puVar5;
  undefined4 uStack_8;
  
  uStack_8 = 0;
  puVar1 = (uint *)(param_1 + (param_2 / 0x20) * 4);
  bVar3 = 0x1f - (char)(param_2 % 0x20);
  if (((*puVar1 & 1 << (bVar3 & 0x1f)) != 0) &&
     (iVar2 = FUN_00456103(param_1,param_2 + 1), iVar2 == 0)) {
    uStack_8 = FUN_0045614c(param_1,param_2 + -1);
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
  return uStack_8;
}



void FUN_0045622e(int param_1,undefined4 *param_2)

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



void FUN_00456249(undefined4 *param_1)

{
  *param_1 = 0;
  param_1[1] = 0;
  param_1[2] = 0;
  return;
}



undefined4 FUN_00456255(int *param_1)

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



void FUN_00456270(uint *param_1,uint param_2)

{
  uint uVar1;
  int iVar2;
  byte bVar3;
  int iVar4;
  int iVar5;
  uint *puVar6;
  int iStack_8;
  
  iStack_8 = 3;
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
    iStack_8 = iStack_8 + -1;
  } while (iStack_8 != 0);
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



undefined4 FUN_004562fd(ushort *param_1,uint *param_2,int *param_3)

{
  ushort uVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  undefined4 uVar5;
  undefined auStack_1c [12];
  uint uStack_10;
  uint uStack_c;
  int iStack_8;
  
  uVar1 = param_1[5];
  uStack_10 = *(uint *)(param_1 + 3);
  uStack_c = *(uint *)(param_1 + 1);
  uVar3 = uVar1 & 0x7fff;
  iVar4 = uVar3 - 0x3fff;
  iStack_8 = (uint)*param_1 << 0x10;
  if (iVar4 == -0x3fff) {
    iVar4 = 0;
    iVar2 = FUN_00456255(&uStack_10);
    if (iVar2 != 0) {
LAB_00456429:
      uVar5 = 0;
      goto LAB_0045642b;
    }
    FUN_00456249(&uStack_10);
  }
  else {
    FUN_0045622e(auStack_1c,&uStack_10);
    iVar2 = FUN_004561a2(&uStack_10,param_3[2]);
    if (iVar2 != 0) {
      iVar4 = uVar3 - 0x3ffe;
    }
    iVar2 = param_3[1];
    if (iVar4 < iVar2 - param_3[2]) {
      FUN_00456249(&uStack_10);
    }
    else {
      if (iVar2 < iVar4) {
        if (*param_3 <= iVar4) {
          FUN_00456249(&uStack_10);
          uStack_10 = uStack_10 | 0x80000000;
          FUN_00456270(&uStack_10,param_3[3]);
          iVar4 = param_3[5] + *param_3;
          uVar5 = 1;
          goto LAB_0045642b;
        }
        uStack_10 = uStack_10 & 0x7fffffff;
        iVar4 = param_3[5] + iVar4;
        FUN_00456270(&uStack_10,param_3[3]);
        goto LAB_00456429;
      }
      FUN_0045622e(&uStack_10,auStack_1c);
      FUN_00456270(&uStack_10,iVar2 - iVar4);
      FUN_004561a2(&uStack_10,param_3[2]);
      FUN_00456270(&uStack_10,param_3[3] + 1);
    }
  }
  iVar4 = 0;
  uVar5 = 2;
LAB_0045642b:
  uStack_10 = iVar4 << (0x1fU - (char)param_3[3] & 0x1f) |
              -(uint)((uVar1 & 0x8000) != 0) & 0x80000000 | uStack_10;
  if (param_3[4] == 0x40) {
    param_2[1] = uStack_10;
    *param_2 = uStack_c;
  }
  else if (param_3[4] == 0x20) {
    *param_2 = uStack_10;
  }
  return uVar5;
}



void FUN_00456469(undefined4 param_1,undefined4 param_2)

{
  FUN_004562fd(param_1,param_2,0x46db40);
  return;
}



void FUN_0045647f(undefined4 param_1,undefined4 param_2)

{
  FUN_004562fd(param_1,param_2,0x46db58);
  return;
}



void FUN_00456495(undefined4 param_1,undefined4 param_2)

{
  undefined auStack_10 [12];
  
  FUN_0045727d(auStack_10,&param_2,param_2,0,0,0,0);
  FUN_00456469(auStack_10,param_1);
  return;
}



void FUN_004564c2(undefined4 param_1,undefined4 param_2)

{
  undefined auStack_10 [12];
  
  FUN_0045727d(auStack_10,&param_2,param_2,0,0,0,0);
  FUN_0045647f(auStack_10,param_1);
  return;
}



void FUN_004564ef(char *param_1,int param_2,int param_3)

{
  char *pcVar1;
  char *pcVar2;
  char *pcVar3;
  int iVar4;
  char *pcVar5;
  char cVar6;
  
  pcVar2 = param_1;
  pcVar5 = *(char **)(param_3 + 0xc);
  pcVar1 = param_1 + 1;
  *param_1 = '0';
  pcVar3 = pcVar1;
  if (0 < param_2) {
    param_1 = (char *)param_2;
    param_2 = 0;
    do {
      cVar6 = *pcVar5;
      if (cVar6 == '\0') {
        cVar6 = '0';
      }
      else {
        pcVar5 = pcVar5 + 1;
      }
      *pcVar3 = cVar6;
      pcVar3 = pcVar3 + 1;
      param_1 = (char *)((int)param_1 + -1);
    } while (param_1 != (char *)0x0);
  }
  *pcVar3 = '\0';
  if ((-1 < param_2) && ('4' < *pcVar5)) {
    while (pcVar3 = pcVar3 + -1, *pcVar3 == '9') {
      *pcVar3 = '0';
    }
    *pcVar3 = *pcVar3 + '\x01';
  }
  if (*pcVar2 == '1') {
    *(int *)(param_3 + 4) = *(int *)(param_3 + 4) + 1;
  }
  else {
    iVar4 = FUN_00452b30(pcVar1);
    FUN_0044e2d0(pcVar2,pcVar1,iVar4 + 1);
  }
  return;
}



int * FUN_00456566(undefined4 param_1,undefined4 param_2,int *param_3,int param_4)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  short sStack_2c;
  char cStack_2a;
  undefined auStack_28 [24];
  undefined4 uStack_10;
  undefined4 uStack_c;
  undefined2 uStack_8;
  
  FUN_004565c2(&uStack_10,&param_1);
  iVar3 = FUN_0045993a(uStack_10,uStack_c,uStack_8,0x11,0,&sStack_2c);
  iVar2 = param_4;
  piVar1 = param_3;
  param_3[2] = iVar3;
  *param_3 = (int)cStack_2a;
  param_3[1] = (int)sStack_2c;
  FUN_00452bf0(param_4,auStack_28);
  piVar1[3] = iVar2;
  return piVar1;
}



void FUN_004565c2(uint *param_1,uint *param_2)

{
  ushort uVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  uint uStack_8;
  
  uVar1 = *(ushort *)((int)param_2 + 6);
  uVar3 = (uVar1 & 0x7ff0) >> 4;
  uVar2 = *param_2;
  uStack_8 = 0x80000000;
  if (uVar3 == 0) {
    if (((param_2[1] & 0xfffff) == 0) && (uVar2 == 0)) {
      param_1[1] = 0;
      *param_1 = 0;
      *(undefined2 *)(param_1 + 2) = 0;
      return;
    }
    iVar4 = 0x3c01;
    uStack_8 = 0;
  }
  else if (uVar3 == 0x7ff) {
    iVar4 = 0x7fff;
  }
  else {
    iVar4 = uVar3 + 0x3c00;
  }
  uStack_8 = uVar2 >> 0x15 | (param_2[1] & 0xfffff) << 0xb | uStack_8;
  param_1[1] = uStack_8;
  *param_1 = uVar2 << 0xb;
  while ((uStack_8 & 0x80000000) == 0) {
    uStack_8 = *param_1 >> 0x1f | uStack_8 * 2;
    *param_1 = *param_1 * 2;
    param_1[1] = uStack_8;
    iVar4 = iVar4 + 0xffff;
  }
  *(ushort *)(param_1 + 2) = uVar1 & 0x8000 | (ushort)iVar4;
  return;
}



void FUN_00456681(undefined4 param_1)

{
  FUN_00456692(param_1,0,4);
  return;
}



undefined4 FUN_00456692(byte param_1,uint param_2,byte param_3)

{
  if ((*(byte *)(param_1 + 0x4776a1) & param_3) == 0) {
    if (param_2 == 0) {
      param_2 = 0;
    }
    else {
      param_2 = *(ushort *)((uint)param_1 * 2 + 0x46ac4a) & param_2;
    }
    if (param_2 == 0) {
      return 0;
    }
  }
  return 1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_004566c3(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  
  iVar3 = 0;
  if (_DAT_00475f6c == (code *)0x0) {
    iVar1 = LoadLibraryA(&UNK_0045fd8c);
    if (iVar1 != 0) {
      _DAT_00475f6c = (code *)GetProcAddress(iVar1,&UNK_0045fd80);
      if (_DAT_00475f6c != (code *)0x0) {
        _DAT_00475f70 = (code *)GetProcAddress(iVar1,&UNK_0045fd70);
        _DAT_00475f74 = (code *)GetProcAddress(iVar1,&UNK_0045fd5c);
        goto LAB_00456712;
      }
    }
    uVar2 = 0;
  }
  else {
LAB_00456712:
    if (_DAT_00475f70 != (code *)0x0) {
      iVar3 = (*_DAT_00475f70)();
      if ((iVar3 != 0) && (_DAT_00475f74 != (code *)0x0)) {
        iVar3 = (*_DAT_00475f74)(iVar3);
      }
    }
    uVar2 = (*_DAT_00475f6c)(iVar3,param_1,param_2,param_3);
  }
  return uVar2;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0045674c(uint param_1,undefined4 param_2,undefined4 param_3)

{
  undefined4 uVar1;
  undefined4 *puVar2;
  
  if ((param_1 < _DAT_004778e0) &&
     ((*(byte *)(*(int *)(&DAT_004777e0 + ((int)param_1 >> 5) * 4) + 4 + (param_1 & 0x1f) * 0x24) &
      1) != 0)) {
    FUN_004579ae(param_1);
    uVar1 = FUN_004567b1(param_1,param_2,param_3);
    FUN_00457a0d(param_1);
    return uVar1;
  }
  puVar2 = (undefined4 *)FUN_00451e44();
  *puVar2 = 9;
  puVar2 = (undefined4 *)FUN_00451e4d();
  *puVar2 = 0;
  return 0xffffffff;
}



int FUN_004567b1(uint param_1,undefined4 param_2,undefined4 param_3)

{
  byte *pbVar1;
  int iVar2;
  undefined4 *puVar3;
  int iVar4;
  
  iVar2 = FUN_0045796c(param_1);
  if (iVar2 == -1) {
    puVar3 = (undefined4 *)FUN_00451e44();
    *puVar3 = 9;
  }
  else {
    iVar2 = SetFilePointer(iVar2,param_2,0,param_3);
    if (iVar2 == -1) {
      iVar4 = GetLastError();
    }
    else {
      iVar4 = 0;
    }
    if (iVar4 == 0) {
      pbVar1 = (byte *)(*(int *)(&DAT_004777e0 + ((int)param_1 >> 5) * 4) + 4 +
                       (param_1 & 0x1f) * 0x24);
      *pbVar1 = *pbVar1 & 0xfd;
      return iVar2;
    }
    FUN_00451dd1(iVar4);
  }
  return -1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_00456824(uint param_1,undefined4 param_2,undefined4 param_3)

{
  undefined4 uVar1;
  undefined4 *puVar2;
  
  if ((param_1 < _DAT_004778e0) &&
     ((*(byte *)(*(int *)(&DAT_004777e0 + ((int)param_1 >> 5) * 4) + 4 + (param_1 & 0x1f) * 0x24) &
      1) != 0)) {
    FUN_004579ae(param_1);
    uVar1 = FUN_00456889(param_1,param_2,param_3);
    FUN_00457a0d(param_1);
    return uVar1;
  }
  puVar2 = (undefined4 *)FUN_00451e44();
  *puVar2 = 9;
  puVar2 = (undefined4 *)FUN_00451e4d();
  *puVar2 = 0;
  return 0xffffffff;
}



int FUN_00456889(uint param_1,char *param_2,uint param_3)

{
  int *piVar1;
  char *pcVar2;
  char cVar3;
  int iVar4;
  char *pcVar5;
  int iVar6;
  undefined4 *puVar7;
  char acStack_418 [1028];
  int iStack_14;
  int iStack_10;
  int iStack_c;
  char *pcStack_8;
  
  iStack_c = 0;
  iStack_14 = 0;
  if (param_3 == 0) {
LAB_004568a2:
    iVar4 = 0;
  }
  else {
    piVar1 = (int *)(&DAT_004777e0 + ((int)param_1 >> 5) * 4);
    iVar4 = (param_1 & 0x1f) * 0x24;
    if ((*(byte *)(*piVar1 + 4 + iVar4) & 0x20) != 0) {
      FUN_004567b1(param_1,0,2);
    }
    if ((*(byte *)((undefined4 *)(*piVar1 + iVar4) + 1) & 0x80) == 0) {
      iVar6 = WriteFile(*(undefined4 *)(*piVar1 + iVar4),param_2,param_3,&iStack_10,0);
      if (iVar6 == 0) {
        param_1 = GetLastError();
      }
      else {
        iStack_c = iStack_10;
        param_1 = 0;
      }
LAB_00456971:
      if (iStack_c != 0) {
        return iStack_c - iStack_14;
      }
      if (param_1 == 0) goto LAB_004569e3;
      if (param_1 == 5) {
        puVar7 = (undefined4 *)FUN_00451e44();
        *puVar7 = 9;
        puVar7 = (undefined4 *)FUN_00451e4d();
        *puVar7 = 5;
      }
      else {
        FUN_00451dd1(param_1);
      }
    }
    else {
      pcStack_8 = param_2;
      param_1 = 0;
      if (param_3 != 0) {
        do {
          pcVar5 = acStack_418;
          do {
            if (param_3 <= (uint)((int)pcStack_8 - (int)param_2)) break;
            pcVar2 = pcStack_8 + 1;
            cVar3 = *pcStack_8;
            pcStack_8 = pcVar2;
            if (cVar3 == '\n') {
              iStack_14 = iStack_14 + 1;
              *pcVar5 = '\r';
              pcVar5 = pcVar5 + 1;
            }
            *pcVar5 = cVar3;
            pcVar5 = pcVar5 + 1;
          } while ((int)pcVar5 - (int)acStack_418 < 0x400);
          iVar6 = WriteFile(*(undefined4 *)(*piVar1 + iVar4),acStack_418,
                            (int)pcVar5 - (int)acStack_418,&iStack_10,0);
          if (iVar6 == 0) {
            param_1 = GetLastError();
            goto LAB_00456971;
          }
          iStack_c = iStack_c + iStack_10;
          if ((iStack_10 < (int)pcVar5 - (int)acStack_418) ||
             (param_3 <= (uint)((int)pcStack_8 - (int)param_2))) goto LAB_00456971;
        } while( true );
      }
LAB_004569e3:
      if (((*(byte *)(*piVar1 + 4 + iVar4) & 0x40) != 0) && (*param_2 == '\x1a')) goto LAB_004568a2;
      puVar7 = (undefined4 *)FUN_00451e44();
      *puVar7 = 0x1c;
      puVar7 = (undefined4 *)FUN_00451e4d();
      *puVar7 = 0;
    }
    iVar4 = -1;
  }
  return iVar4;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00456a14(undefined4 *param_1)

{
  int iVar1;
  
  _DAT_00475d10 = _DAT_00475d10 + 1;
  iVar1 = FUN_0044c5a2(0x1000);
  param_1[2] = iVar1;
  if (iVar1 == 0) {
    param_1[3] = param_1[3] | 4;
    param_1[2] = param_1 + 5;
    param_1[6] = 2;
  }
  else {
    param_1[3] = param_1[3] | 8;
    param_1[6] = 0x1000;
  }
  param_1[1] = 0;
  *param_1 = param_1[2];
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

byte FUN_00456a58(uint param_1)

{
  if (_DAT_004778e0 <= param_1) {
    return 0;
  }
  return *(byte *)(*(int *)(&DAT_004777e0 + ((int)param_1 >> 5) * 4) + 4 + (param_1 & 0x1f) * 0x24)
         & 0x40;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_00456a81(undefined4 param_1,undefined4 param_2)

{
  undefined4 uVar1;
  bool bVar2;
  
  InterlockedIncrement(&DAT_00478908);
  bVar2 = _DAT_00478904 != 0;
  if (bVar2) {
    InterlockedDecrement(&DAT_00478908);
    FUN_0044f15a(0x13);
  }
  uVar1 = FUN_00456ada(param_1,param_2);
  if (bVar2) {
    FUN_0044f1bb(0x13);
  }
  else {
    InterlockedDecrement(&DAT_00478908);
  }
  return uVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined * FUN_00456ada(undefined *param_1,ushort param_2)

{
  undefined *puVar1;
  undefined4 *puVar2;
  
  puVar1 = param_1;
  if (param_1 == (undefined *)0x0) {
    return param_1;
  }
  if (_DAT_00475dc0 == 0) {
    if (param_2 < 0x100) {
      *param_1 = (char)param_2;
      return (undefined *)0x1;
    }
  }
  else {
    param_1 = (undefined *)0x0;
    puVar1 = (undefined *)
             WideCharToMultiByte(_DAT_00475dd0,0x220,&param_2,1,puVar1,_DAT_0046ae4c,0,&param_1);
    if ((puVar1 != (undefined *)0x0) && (param_1 == (undefined *)0x0)) {
      return puVar1;
    }
  }
  puVar2 = (undefined4 *)FUN_00451e44();
  *puVar2 = 0x2a;
  return (undefined *)0xffffffff;
}



undefined8 FUN_00456b50(uint param_1,uint param_2,uint param_3,uint param_4)

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



undefined8 FUN_00456bc0(uint param_1,uint param_2,uint param_3,uint param_4)

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



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_00456c35(int param_1,undefined4 param_2,undefined4 param_3,int *param_4)

{
  byte bVar1;
  bool bVar2;
  int iVar3;
  undefined *puVar4;
  int iVar5;
  uint uVar6;
  byte *pbVar7;
  undefined auStack_84 [128];
  
  if (param_1 != 1) {
    if (param_1 != 0) {
      return 0xffffffff;
    }
    pbVar7 = (byte *)0x475f78;
    iVar3 = FUN_00459bcd(param_2,param_3,0x475f78,4,0);
    if (iVar3 != 0) {
      *(char *)param_4 = '\0';
      while( true ) {
        bVar1 = *pbVar7;
        if (_DAT_0046ae4c < 2) {
          uVar6 = *(byte *)(_DAT_0046ac40 + (uint)bVar1 * 2) & 4;
        }
        else {
          uVar6 = FUN_0044e6e0(bVar1,4);
        }
        if (uVar6 == 0) break;
        pbVar7 = pbVar7 + 2;
        *(byte *)param_4 = *(char *)param_4 * '\n' + bVar1 + -0x30;
        if (0x475f7f < (int)pbVar7) {
          return 0;
        }
      }
      return 0;
    }
    return 0xffffffff;
  }
  puVar4 = auStack_84;
  bVar2 = false;
  iVar3 = FUN_00459ce0(param_2,param_3,auStack_84,0x80,0);
  if (iVar3 == 0) {
    iVar3 = GetLastError();
    if (iVar3 != 0x7a) {
      return 0xffffffff;
    }
    iVar3 = FUN_00459ce0(param_2,param_3,0,0,0);
    if (iVar3 == 0) {
      return 0xffffffff;
    }
    puVar4 = (undefined *)FUN_0044c5a2(iVar3);
    if (puVar4 == (undefined *)0x0) {
      return 0xffffffff;
    }
    bVar2 = true;
    iVar3 = FUN_00459ce0(param_2,param_3,puVar4,iVar3,0);
    if (iVar3 == 0) goto LAB_00456cd3;
  }
  iVar5 = FUN_0044c5a2(iVar3);
  *param_4 = iVar5;
  if (iVar5 != 0) {
    FUN_0044bd70(iVar5,puVar4,iVar3);
    if (bVar2) {
      FUN_0044c4b9(puVar4);
    }
    return 0;
  }
  if (!bVar2) {
    return 0xffffffff;
  }
LAB_00456cd3:
  FUN_0044c4b9(puVar4);
  return 0xffffffff;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4
FUN_00456d6d(undefined4 param_1,undefined4 param_2,int param_3,undefined4 param_4,int param_5,
            int param_6)

{
  undefined *puVar1;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  int iStack_7c;
  undefined4 uStack_78;
  undefined4 uStack_74;
  int iStack_70;
  int *piStack_6c;
  int *piStack_68;
  undefined4 uStack_64;
  int iStack_60;
  int iStack_5c;
  undefined4 uStack_58;
  undefined4 uStack_54;
  int iStack_50;
  undefined4 uStack_4c;
  undefined *puStack_48;
  int iStack_44;
  undefined *puStack_40;
  int *piStack_30;
  int iStack_2c;
  undefined auStack_20 [4];
  int *piStack_1c;
  void *pvStack_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 uStack_8;
  
  uStack_8 = 0xffffffff;
  puStack_c = &UNK_0045fec0;
  puStack_10 = &UNK_0045001c;
  pvStack_14 = ExceptionList;
  piStack_1c = (int *)&stack0xffffffc4;
  iVar4 = _DAT_00475f84;
  ExceptionList = &pvStack_14;
  puVar1 = &stack0xffffffc4;
  if (_DAT_00475f84 == 0) {
    puStack_40 = auStack_20;
    iStack_44 = 1;
    puStack_48 = &UNK_0045f2b8;
    uStack_4c = 1;
    iStack_50 = 0x456db2;
    ExceptionList = &pvStack_14;
    iVar2 = GetStringTypeW();
    iVar4 = 1;
    puVar1 = (undefined *)piStack_1c;
    if (iVar2 == 0) {
      puStack_40 = auStack_20;
      iStack_44 = 1;
      puStack_48 = (undefined *)0x4747d4;
      uStack_4c = 1;
      iStack_50 = 0;
      uStack_54 = 0x456dcc;
      iVar4 = GetStringTypeA();
      if (iVar4 == 0) {
        ExceptionList = pvStack_14;
        return 0;
      }
      iVar4 = 2;
      puVar1 = (undefined *)piStack_1c;
    }
  }
  piStack_1c = (int *)puVar1;
  _DAT_00475f84 = iVar4;
  if (_DAT_00475f84 != 1) {
    if (_DAT_00475f84 == 2) {
      if (param_5 == 0) {
        param_5 = _DAT_00475dd0;
      }
      puStack_40 = (undefined *)0x0;
      iStack_44 = 0;
      puStack_48 = (undefined *)0x0;
      uStack_4c = 0;
      iStack_50 = param_3;
      uStack_54 = param_2;
      uStack_58 = 0x220;
      iStack_5c = param_5;
      iStack_60 = 0x456e26;
      iStack_2c = WideCharToMultiByte();
      if (iStack_2c != 0) {
        uStack_8 = 0;
        iStack_60 = 0x456e40;
        piStack_30 = &iStack_5c;
        piStack_68 = &iStack_5c;
        FUN_0044c080();
        uStack_64 = 0;
        piStack_6c = (int *)0x456e50;
        iStack_60 = iStack_2c;
        piStack_1c = &iStack_5c;
        FUN_004538c0();
        uStack_8 = 0xffffffff;
        if (&stack0x00000000 != (undefined *)0x5c) {
          iStack_60 = 0;
          uStack_64 = 0;
          iStack_70 = param_3;
          uStack_74 = param_2;
          uStack_78 = 0x220;
          iStack_7c = param_5;
          piStack_6c = &iStack_5c;
          piStack_68 = (int *)iStack_2c;
          iVar4 = WideCharToMultiByte();
          if (iVar4 != 0) {
            uStack_8 = 1;
            FUN_0044c080();
            uStack_8 = 0xffffffff;
            if (&stack0x00000000 != (undefined *)0x7c) {
              if (param_6 == 0) {
                param_6 = _DAT_00475dc0;
              }
              param_3 = param_3 * 2;
              piStack_1c = &iStack_7c;
              *(short *)((int)&iStack_7c + param_3) = -1;
              *(undefined2 *)(&stack0xffffff82 + param_3) = 0xffff;
              uVar3 = GetStringTypeA(param_6,param_1,piStack_30,iStack_2c,&iStack_7c);
              if ((*(short *)(&stack0xffffff82 + param_3) != -1) &&
                 (*(short *)((int)&iStack_7c + param_3) == -1)) {
                FUN_0044e2d0(param_4,&iStack_7c,param_3);
                ExceptionList = pvStack_14;
                return uVar3;
              }
            }
          }
        }
      }
    }
    ExceptionList = pvStack_14;
    return 0;
  }
  puStack_40 = (undefined *)param_4;
  iStack_44 = param_3;
  puStack_48 = (undefined *)param_2;
  uStack_4c = param_1;
  iStack_50 = 0x456df3;
  uVar3 = GetStringTypeW();
  ExceptionList = pvStack_14;
  return uVar3;
}



undefined4 FUN_00456f32(int param_1,undefined4 param_2,int param_3)

{
  undefined4 uVar1;
  
  if ((param_3 == 10) && (param_1 < 0)) {
    uVar1 = 1;
    param_3 = 10;
  }
  else {
    uVar1 = 0;
  }
  FUN_00456f5f(param_1,param_2,param_3,uVar1);
  return param_2;
}



void FUN_00456f5f(uint param_1,char *param_2,uint param_3,int param_4)

{
  ulonglong uVar1;
  char *pcVar2;
  char *pcVar3;
  char cVar4;
  
  pcVar2 = param_2;
  if (param_4 != 0) {
    *param_2 = '-';
    param_2 = param_2 + 1;
    param_1 = -param_1;
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
    *param_2 = cVar4;
    pcVar3 = pcVar3 + -1;
    param_2 = param_2 + 1;
  } while (param_2 < pcVar3);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_00456fc0(byte *param_1,char *param_2,int param_3)

{
  char cVar1;
  int iVar2;
  byte bVar3;
  ushort uVar4;
  uint uVar5;
  uint uVar6;
  bool bVar7;
  uint uVar8;
  
  iVar2 = _DAT_00478908;
  if (param_3 != 0) {
    if (_DAT_00475dc0 == 0) {
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
        if (bVar3 != (byte)uVar4) goto LAB_0045701f;
        param_3 = param_3 + -1;
      } while (param_3 != 0);
      param_3 = 0;
      bVar3 = (byte)(uVar4 >> 8);
      bVar7 = bVar3 < (byte)uVar4;
      if (bVar3 != (byte)uVar4) {
LAB_0045701f:
        param_3 = -1;
        if (!bVar7) {
          param_3 = 1;
        }
      }
    }
    else {
      LOCK();
      _DAT_00478908 = _DAT_00478908 + 1;
      UNLOCK();
      bVar7 = 0 < _DAT_00478904;
      if (bVar7) {
        LOCK();
        UNLOCK();
        _DAT_00478908 = iVar2;
        FUN_0044f15a(0x13);
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
        uVar6 = FUN_0044c74b(uVar6,uVar5);
        uVar5 = FUN_0044c74b();
        bVar7 = uVar5 < uVar6;
        if (uVar5 != uVar6) goto LAB_00457095;
        param_3 = param_3 + -1;
      } while (param_3 != 0);
      param_3 = 0;
      bVar7 = uVar5 < uVar6;
      if (uVar5 != uVar6) {
LAB_00457095:
        param_3 = -1;
        if (!bVar7) {
          param_3 = 1;
        }
      }
      if (uVar8 == 0) {
        LOCK();
        _DAT_00478908 = _DAT_00478908 + -1;
        UNLOCK();
      }
      else {
        FUN_0044f1bb(0x13);
      }
    }
  }
  return param_3;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_004570c1(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  undefined4 uVar1;
  bool bVar2;
  
  InterlockedIncrement(&DAT_00478908);
  bVar2 = _DAT_00478904 != 0;
  if (bVar2) {
    InterlockedDecrement(&DAT_00478908);
    FUN_0044f15a(0x13);
  }
  uVar1 = FUN_0045711e(param_1,param_2,param_3);
  if (bVar2) {
    FUN_0044f1bb(0x13);
  }
  else {
    InterlockedDecrement(&DAT_00478908);
  }
  return uVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

uint FUN_0045711e(ushort *param_1,byte *param_2,uint param_3)

{
  byte bVar1;
  int iVar2;
  undefined4 *puVar3;
  
  if ((param_2 != (byte *)0x0) && (param_3 != 0)) {
    bVar1 = *param_2;
    if (bVar1 != 0) {
      if (_DAT_00475dc0 == 0) {
        if (param_1 != (ushort *)0x0) {
          *param_1 = (ushort)bVar1;
        }
        return 1;
      }
      if ((*(byte *)(_DAT_0046ac40 + 1 + (uint)bVar1 * 2) & 0x80) == 0) {
        iVar2 = MultiByteToWideChar(_DAT_00475dd0,9,param_2,1,param_1,param_1 != (ushort *)0x0);
        if (iVar2 != 0) {
          return 1;
        }
      }
      else {
        if (1 < (int)_DAT_0046ae4c) {
          if ((int)param_3 < (int)_DAT_0046ae4c) goto LAB_004571b0;
          iVar2 = MultiByteToWideChar(_DAT_00475dd0,9,param_2,_DAT_0046ae4c,param_1,
                                      param_1 != (ushort *)0x0);
          if (iVar2 != 0) {
            return _DAT_0046ae4c;
          }
        }
        if ((_DAT_0046ae4c <= param_3) && (param_2[1] != 0)) {
          return _DAT_0046ae4c;
        }
      }
LAB_004571b0:
      puVar3 = (undefined4 *)FUN_00451e44();
      *puVar3 = 0x2a;
      return 0xffffffff;
    }
    if (param_1 != (ushort *)0x0) {
      *param_1 = 0;
    }
  }
  return 0;
}



longlong __fastcall FUN_004571f0(byte param_1,int param_2)

{
  uint in_EAX;
  
  if (0x3f < param_1) {
    return 0;
  }
  if (param_1 < 0x20) {
    return CONCAT44(param_2 << (param_1 & 0x1f) | in_EAX >> 0x20 - (param_1 & 0x1f),
                    in_EAX << (param_1 & 0x1f));
  }
  return (ulonglong)(in_EAX << (param_1 & 0x1f)) << 0x20;
}



uint FUN_0045720f(uint param_1,char **param_2)

{
  char *pcVar1;
  
  if ((param_1 != 0xffffffff) &&
     ((pcVar1 = param_2[3], ((uint)pcVar1 & 1) != 0 ||
      ((((uint)pcVar1 & 0x80) != 0 && (((uint)pcVar1 & 2) == 0)))))) {
    if (param_2[2] == (char *)0x0) {
      FUN_00456a14(param_2);
    }
    if (*param_2 == param_2[2]) {
      if (param_2[1] != (char *)0x0) {
        return 0xffffffff;
      }
      *param_2 = *param_2 + 1;
    }
    if ((*(byte *)(param_2 + 3) & 0x40) == 0) {
      *param_2 = *param_2 + -1;
      **param_2 = (char)param_1;
    }
    else {
      *param_2 = *param_2 + -1;
      if (**param_2 != (char)param_1) {
        *param_2 = *param_2 + 1;
        return 0xffffffff;
      }
    }
    param_2[1] = param_2[1] + 1;
    param_2[3] = (char *)((uint)param_2[3] & 0xffffffef | 1);
    return param_1 & 0xff;
  }
  return 0xffffffff;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4
FUN_0045727d(ushort *param_1,byte **param_2,byte *param_3,undefined4 param_4,int param_5,int param_6
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
  char acStack_60 [23];
  char cStack_49;
  ushort uStack_44;
  undefined2 uStack_42;
  undefined2 uStack_40;
  byte *pbStack_3e;
  undefined4 uStack_3a;
  int iStack_34;
  int iStack_30;
  undefined4 uStack_2c;
  int iStack_28;
  int iStack_24;
  int iStack_20;
  int iStack_1c;
  undefined4 uStack_18;
  int iStack_14;
  char *pcStack_10;
  int iStack_c;
  uint uStack_8;
  
  pcStack_10 = acStack_60;
  uStack_2c = 0;
  iStack_1c = 1;
  uStack_8 = 0;
  iStack_14 = 0;
  iStack_28 = 0;
  iStack_24 = 0;
  iStack_30 = 0;
  iStack_34 = 0;
  iStack_20 = 0;
  iStack_c = 0;
  uStack_18 = 0;
  for (pbVar8 = param_3;
      (((bVar6 = *pbVar8, bVar6 == 0x20 || (bVar6 == 9)) || (bVar6 == 10)) || (bVar6 == 0xd));
      pbVar8 = pbVar8 + 1) {
  }
  iVar7 = 4;
  iVar4 = 0;
  iVar5 = iStack_14;
LAB_004572d4:
  iStack_14 = iVar5;
  iVar5 = 1;
  bVar6 = *pbVar8;
  pbVar9 = pbVar8 + 1;
  pbVar10 = param_3;
  iVar1 = iStack_14;
  switch(iVar4) {
  case 0:
    if (('0' < (char)bVar6) && ((char)bVar6 < ':')) {
LAB_004572f1:
      iStack_14 = iVar1;
      iVar4 = 3;
      goto LAB_00457516;
    }
    if (bVar6 == DAT_0046ae50) goto LAB_00457300;
    if (bVar6 == 0x2b) {
      uStack_2c = 0;
      iVar4 = 2;
      pbVar8 = pbVar9;
      iVar5 = iStack_14;
    }
    else if (bVar6 == 0x2d) {
      uStack_2c = 0x8000;
      iVar4 = 2;
      pbVar8 = pbVar9;
      iVar5 = iStack_14;
    }
    else {
      iVar4 = iVar5;
      pbVar8 = pbVar9;
      iVar5 = iStack_14;
      if (bVar6 != 0x30) goto LAB_004575f0;
    }
    goto LAB_004572d4;
  case 1:
    iStack_14 = 1;
    if (('0' < (char)bVar6) && (iVar1 = iVar5, (char)bVar6 < ':')) goto LAB_004572f1;
    iVar4 = iVar7;
    pbVar8 = pbVar9;
    if (bVar6 != DAT_0046ae50) {
      iVar4 = iVar5;
      if ((bVar6 == 0x2b) || (iVar4 = iStack_14, bVar6 == 0x2d)) goto LAB_00457385;
      iVar4 = iVar5;
      iStack_14 = iVar5;
      if (bVar6 != 0x30) goto LAB_0045735e;
    }
    goto LAB_004572d4;
  case 2:
    if (('0' < (char)bVar6) && ((char)bVar6 < ':')) goto LAB_004572f1;
    if (bVar6 == DAT_0046ae50) {
LAB_00457300:
      iVar4 = 5;
      pbVar8 = pbVar9;
      iVar5 = iStack_14;
    }
    else {
      iVar4 = iVar5;
      pbVar8 = pbVar9;
      iVar5 = iStack_14;
      if (bVar6 != 0x30) goto LAB_004575f5;
    }
    goto LAB_004572d4;
  case 3:
    iStack_14 = iVar5;
    while( true ) {
      if (_DAT_0046ae4c < 2) {
        uVar2 = *(byte *)(_DAT_0046ac40 + (uint)bVar6 * 2) & 4;
      }
      else {
        uVar2 = FUN_0044e6e0(bVar6,4);
      }
      if (uVar2 == 0) break;
      if (uStack_8 < 0x19) {
        uStack_8 = uStack_8 + 1;
        pcVar3 = pcStack_10 + 1;
        *pcStack_10 = bVar6 - 0x30;
        pcStack_10 = pcVar3;
      }
      else {
        iStack_c = iStack_c + 1;
      }
      bVar6 = *pbVar9;
      pbVar9 = pbVar9 + 1;
    }
    iVar4 = iVar7;
    pbVar8 = pbVar9;
    iVar5 = iStack_14;
    if (bVar6 != DAT_0046ae50) goto LAB_00457472;
    goto LAB_004572d4;
  case 4:
    iStack_14 = 1;
    iStack_28 = 1;
    iVar4 = iVar5;
    if (uStack_8 == 0) {
      while (iVar5 = iStack_28, iVar4 = iStack_14, bVar6 == 0x30) {
        iStack_c = iStack_c + -1;
        bVar6 = *pbVar9;
        pbVar9 = pbVar9 + 1;
      }
    }
    while( true ) {
      iStack_14 = iVar4;
      iStack_28 = iVar5;
      if (_DAT_0046ae4c < 2) {
        uVar2 = *(byte *)(_DAT_0046ac40 + (uint)bVar6 * 2) & 4;
      }
      else {
        uVar2 = FUN_0044e6e0(bVar6,4);
      }
      if (uVar2 == 0) break;
      if (uStack_8 < 0x19) {
        uStack_8 = uStack_8 + 1;
        iStack_c = iStack_c + -1;
        pcVar3 = pcStack_10 + 1;
        *pcStack_10 = bVar6 - 0x30;
        pcStack_10 = pcVar3;
      }
      bVar6 = *pbVar9;
      pbVar9 = pbVar9 + 1;
      iVar5 = iStack_28;
      iVar4 = iStack_14;
    }
LAB_00457472:
    iVar4 = iStack_14;
    if ((bVar6 == 0x2b) || (bVar6 == 0x2d)) {
LAB_00457385:
      iStack_14 = iVar4;
      iVar4 = 0xb;
      pbVar8 = pbVar9 + -1;
      iVar5 = iStack_14;
    }
    else {
LAB_0045735e:
      if (((char)bVar6 < 'D') ||
         (('E' < (char)bVar6 && (((char)bVar6 < 'd' || ('e' < (char)bVar6)))))) goto LAB_004575f0;
      iVar4 = 6;
      pbVar8 = pbVar9;
      iVar5 = iStack_14;
    }
    goto LAB_004572d4;
  case 5:
    iStack_28 = iVar5;
    if (_DAT_0046ae4c < 2) {
      uVar2 = *(byte *)(_DAT_0046ac40 + (uint)bVar6 * 2) & 4;
    }
    else {
      uVar2 = FUN_0044e6e0(bVar6,4);
    }
    iVar4 = iVar7;
    if (uVar2 != 0) goto LAB_00457516;
    goto LAB_004575f5;
  case 6:
    param_3 = pbVar8 + -1;
    if (((char)bVar6 < '1') || ('9' < (char)bVar6)) {
      if (bVar6 == 0x2b) goto LAB_0045754b;
      if (bVar6 == 0x2d) goto LAB_0045753f;
      pbVar10 = param_3;
      if (bVar6 != 0x30) goto LAB_004575f5;
LAB_004574e4:
      iVar4 = 8;
      pbVar8 = pbVar9;
      iVar5 = iStack_14;
      goto LAB_004572d4;
    }
    break;
  case 7:
    if (((char)bVar6 < '1') || ('9' < (char)bVar6)) {
      if (bVar6 == 0x30) goto LAB_004574e4;
      goto LAB_004575f5;
    }
    break;
  case 8:
    iStack_24 = 1;
    while (bVar6 == 0x30) {
      bVar6 = *pbVar9;
      pbVar9 = pbVar9 + 1;
    }
    if (((char)bVar6 < '1') || ('9' < (char)bVar6)) goto LAB_004575f0;
    break;
  case 9:
    iStack_24 = 1;
    iVar4 = 0;
    goto LAB_00457576;
  default:
    goto switchD_004572e0_caseD_a;
  case 0xb:
    if (param_7 != 0) {
      param_3 = pbVar8;
      if (bVar6 == 0x2b) {
LAB_0045754b:
        iVar4 = 7;
        pbVar8 = pbVar9;
        iVar5 = iStack_14;
      }
      else {
        pbVar10 = pbVar8;
        if (bVar6 != 0x2d) goto LAB_004575f5;
LAB_0045753f:
        iStack_1c = -1;
        iVar4 = 7;
        pbVar8 = pbVar9;
        iVar5 = iStack_14;
      }
      goto LAB_004572d4;
    }
    iVar4 = 10;
    pbVar9 = pbVar8;
switchD_004572e0_caseD_a:
    pbVar8 = pbVar9;
    pbVar10 = pbVar9;
    iVar5 = iStack_14;
    if (iVar4 != 10) goto LAB_004572d4;
    goto LAB_004575f5;
  }
  iVar4 = 9;
LAB_00457516:
  pbVar8 = pbVar9 + -1;
  iVar5 = iStack_14;
  goto LAB_004572d4;
LAB_00457576:
  if (_DAT_0046ae4c < 2) {
    uVar2 = *(byte *)(_DAT_0046ac40 + (uint)bVar6 * 2) & 4;
  }
  else {
    uVar2 = FUN_0044e6e0(bVar6,4);
  }
  if (uVar2 == 0) goto LAB_004575c0;
  iVar4 = (char)bVar6 + -0x30 + iVar4 * 10;
  if (0x1450 < iVar4) goto LAB_004575b8;
  bVar6 = *pbVar9;
  pbVar9 = pbVar9 + 1;
  goto LAB_00457576;
LAB_004575b8:
  iVar4 = 0x1451;
LAB_004575c0:
  while( true ) {
    iStack_20 = iVar4;
    if (_DAT_0046ae4c < 2) {
      uVar2 = *(byte *)(_DAT_0046ac40 + (uint)bVar6 * 2) & 4;
    }
    else {
      uVar2 = FUN_0044e6e0(bVar6,4);
    }
    if (uVar2 == 0) break;
    bVar6 = *pbVar9;
    pbVar9 = pbVar9 + 1;
    iVar4 = iStack_20;
  }
LAB_004575f0:
  pbVar10 = pbVar9 + -1;
LAB_004575f5:
  *param_2 = pbVar10;
  if (iStack_14 == 0) {
    uStack_44 = 0;
    uStack_3a._0_2_ = 0;
    pbStack_3e = (byte *)0x0;
    param_3 = (byte *)0x0;
    uStack_18 = 4;
    goto LAB_00457703;
  }
  pcVar3 = pcStack_10;
  if (0x18 < uStack_8) {
    if ('\x04' < cStack_49) {
      cStack_49 = cStack_49 + '\x01';
    }
    uStack_8 = 0x18;
    iStack_c = iStack_c + 1;
    pcVar3 = pcStack_10 + -1;
  }
  if (uStack_8 == 0) {
    uStack_44 = 0;
    uStack_3a._0_2_ = 0;
    pbStack_3e = (byte *)0x0;
    param_3 = (byte *)0x0;
  }
  else {
    while (pcVar3 = pcVar3 + -1, *pcVar3 == '\0') {
      uStack_8 = uStack_8 - 1;
      iStack_c = iStack_c + 1;
    }
    FUN_00459873(acStack_60,uStack_8,&uStack_44);
    iVar4 = iStack_20;
    if (iStack_1c < 0) {
      iVar4 = -iStack_20;
    }
    iVar4 = iVar4 + iStack_c;
    if (iStack_24 == 0) {
      iVar4 = iVar4 + param_5;
    }
    if (iStack_28 == 0) {
      iVar4 = iVar4 - param_6;
    }
    if (iVar4 < 0x1451) {
      if (-0x1451 < iVar4) {
        FUN_0045a01e(&uStack_44,iVar4,param_4);
        param_3 = (byte *)CONCAT22(uStack_40,uStack_42);
        goto LAB_00457688;
      }
      iStack_34 = 1;
    }
    else {
      iStack_30 = 1;
    }
    uStack_3a._0_2_ = (ushort)param_3;
    pbStack_3e = param_3;
    uStack_44 = (ushort)uStack_3a;
  }
LAB_00457688:
  if (iStack_30 == 0) {
    if (iStack_34 != 0) {
      uStack_44 = 0;
      uStack_3a._0_2_ = 0;
      pbStack_3e = (byte *)0x0;
      param_3 = (byte *)0x0;
      uStack_18 = 1;
    }
  }
  else {
    param_3 = (byte *)0x0;
    uStack_3a._0_2_ = 0x7fff;
    pbStack_3e = (byte *)0x80000000;
    uStack_44 = 0;
    uStack_18 = 2;
  }
LAB_00457703:
  *(byte **)(param_1 + 3) = pbStack_3e;
  *(byte **)(param_1 + 1) = param_3;
  param_1[5] = (ushort)uStack_3a | (ushort)uStack_2c;
  *param_1 = uStack_44;
  return uStack_18;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_0045774e(void)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  int *piVar3;
  int iVar4;
  int iStack_8;
  int iStack_4;
  
  iVar4 = -1;
  FUN_0044f15a(0x12);
  iStack_8 = 0;
  iStack_4 = 0;
  piVar3 = (int *)&DAT_004777e0;
  while (puVar2 = (undefined4 *)*piVar3, puVar1 = puVar2, puVar2 != (undefined4 *)0x0) {
    for (; puVar2 < puVar1 + 0x120; puVar2 = puVar2 + 9) {
      if ((*(byte *)(puVar2 + 1) & 1) == 0) {
        if (puVar2[2] == 0) {
          FUN_0044f15a(0x11);
          if (puVar2[2] == 0) {
            InitializeCriticalSection(puVar2 + 3);
            puVar2[2] = puVar2[2] + 1;
          }
          FUN_0044f1bb(0x11);
        }
        EnterCriticalSection(puVar2 + 3);
        if ((*(byte *)(puVar2 + 1) & 1) == 0) {
          *puVar2 = 0xffffffff;
          iVar4 = ((int)puVar2 - *piVar3) / 0x24 + iStack_4;
          if (iVar4 != -1) goto LAB_00457860;
          break;
        }
        LeaveCriticalSection(puVar2 + 3);
      }
      puVar1 = (undefined4 *)*piVar3;
    }
    iStack_4 = iStack_4 + 0x20;
    piVar3 = piVar3 + 1;
    iStack_8 = iStack_8 + 1;
    if (0x4778df < (int)piVar3) goto LAB_00457860;
  }
  puVar2 = (undefined4 *)FUN_0044c5a2(0x480);
  if (puVar2 != (undefined4 *)0x0) {
    _DAT_004778e0 = _DAT_004778e0 + 0x20;
    *(undefined4 **)(&DAT_004777e0 + iStack_8 * 4) = puVar2;
    puVar1 = puVar2;
    for (; puVar2 < puVar1 + 0x120; puVar2 = puVar2 + 9) {
      *(undefined *)(puVar2 + 1) = 0;
      *puVar2 = 0xffffffff;
      puVar2[2] = 0;
      *(undefined *)((int)puVar2 + 5) = 10;
      puVar1 = *(undefined4 **)(&DAT_004777e0 + iStack_8 * 4);
    }
    iVar4 = iStack_8 << 5;
    FUN_004579ae(iVar4);
  }
LAB_00457860:
  FUN_0044f1bb(0x12);
  return iVar4;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_00457871(uint param_1,undefined4 param_2)

{
  undefined4 *puVar1;
  int iVar2;
  undefined4 uVar3;
  
  if (param_1 < _DAT_004778e0) {
    iVar2 = (param_1 & 0x1f) * 0x24;
    if (*(int *)(*(int *)(&DAT_004777e0 + ((int)param_1 >> 5) * 4) + iVar2) == -1) {
      if (_DAT_0046a834 == 1) {
        if (param_1 == 0) {
          uVar3 = 0xfffffff6;
        }
        else if (param_1 == 1) {
          uVar3 = 0xfffffff5;
        }
        else {
          if (param_1 != 2) goto LAB_004578ca;
          uVar3 = 0xfffffff4;
        }
        SetStdHandle(uVar3,param_2);
      }
LAB_004578ca:
      *(undefined4 *)(*(int *)(&DAT_004777e0 + ((int)param_1 >> 5) * 4) + iVar2) = param_2;
      return 0;
    }
  }
  puVar1 = (undefined4 *)FUN_00451e44();
  *puVar1 = 9;
  puVar1 = (undefined4 *)FUN_00451e4d();
  *puVar1 = 0;
  return 0xffffffff;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_004578ed(uint param_1)

{
  int *piVar1;
  undefined4 *puVar2;
  int iVar3;
  undefined4 uVar4;
  
  if (param_1 < _DAT_004778e0) {
    iVar3 = (param_1 & 0x1f) * 0x24;
    piVar1 = (int *)(*(int *)(&DAT_004777e0 + ((int)param_1 >> 5) * 4) + iVar3);
    if (((*(byte *)(piVar1 + 1) & 1) != 0) && (*piVar1 != -1)) {
      if (_DAT_0046a834 == 1) {
        if (param_1 == 0) {
          uVar4 = 0xfffffff6;
        }
        else if (param_1 == 1) {
          uVar4 = 0xfffffff5;
        }
        else {
          if (param_1 != 2) goto LAB_00457949;
          uVar4 = 0xfffffff4;
        }
        SetStdHandle(uVar4,0);
      }
LAB_00457949:
      *(undefined4 *)(*(int *)(&DAT_004777e0 + ((int)param_1 >> 5) * 4) + iVar3) = 0xffffffff;
      return 0;
    }
  }
  puVar2 = (undefined4 *)FUN_00451e44();
  *puVar2 = 9;
  puVar2 = (undefined4 *)FUN_00451e4d();
  *puVar2 = 0;
  return 0xffffffff;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0045796c(uint param_1)

{
  undefined4 *puVar1;
  
  if ((param_1 < _DAT_004778e0) &&
     ((*(byte *)(*(int *)(&DAT_004777e0 + ((int)param_1 >> 5) * 4) + 4 + (param_1 & 0x1f) * 0x24) &
      1) != 0)) {
    return *(undefined4 *)
            (*(int *)(&DAT_004777e0 + ((int)param_1 >> 5) * 4) + (param_1 & 0x1f) * 0x24);
  }
  puVar1 = (undefined4 *)FUN_00451e44();
  *puVar1 = 9;
  puVar1 = (undefined4 *)FUN_00451e4d();
  *puVar1 = 0;
  return 0xffffffff;
}



void FUN_004579ae(uint param_1)

{
  int iVar1;
  int iVar2;
  
  iVar2 = (param_1 & 0x1f) * 0x24;
  iVar1 = *(int *)(&DAT_004777e0 + ((int)param_1 >> 5) * 4) + iVar2;
  if (*(int *)(iVar1 + 8) == 0) {
    FUN_0044f15a(0x11);
    if (*(int *)(iVar1 + 8) == 0) {
      InitializeCriticalSection(iVar1 + 0xc);
      *(int *)(iVar1 + 8) = *(int *)(iVar1 + 8) + 1;
    }
    FUN_0044f1bb(0x11);
  }
  EnterCriticalSection(*(int *)(&DAT_004777e0 + ((int)param_1 >> 5) * 4) + 0xc + iVar2);
  return;
}



void FUN_00457a0d(uint param_1)

{
  LeaveCriticalSection
            (*(int *)(&DAT_004777e0 + ((int)param_1 >> 5) * 4) + 0xc + (param_1 & 0x1f) * 0x24);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_00457a2f(uint param_1)

{
  undefined4 uVar1;
  int *piVar2;
  undefined4 *puVar3;
  int iVar4;
  
  if (_DAT_004778e0 <= param_1) {
LAB_00457ab0:
    puVar3 = (undefined4 *)FUN_00451e44();
    *puVar3 = 9;
    return -1;
  }
  iVar4 = (param_1 & 0x1f) * 0x24;
  if ((*(byte *)(*(int *)(&DAT_004777e0 + ((int)param_1 >> 5) * 4) + 4 + iVar4) & 1) == 0)
  goto LAB_00457ab0;
  FUN_004579ae(param_1);
  if ((*(byte *)(*(int *)(&DAT_004777e0 + ((int)param_1 >> 5) * 4) + 4 + iVar4) & 1) != 0) {
    uVar1 = FUN_0045796c(param_1);
    iVar4 = FlushFileBuffers(uVar1);
    if (iVar4 == 0) {
      iVar4 = GetLastError();
    }
    else {
      iVar4 = 0;
    }
    if (iVar4 == 0) goto LAB_00457aa5;
    piVar2 = (int *)FUN_00451e4d();
    *piVar2 = iVar4;
  }
  puVar3 = (undefined4 *)FUN_00451e44();
  *puVar3 = 9;
  iVar4 = -1;
LAB_00457aa5:
  FUN_00457a0d(param_1);
  return iVar4;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00457ac2(void)

{
  if (_DAT_00476040 == 0) {
    FUN_0044f15a(0xb);
    if (_DAT_00476040 == 0) {
      FUN_00457af0();
      _DAT_00476040 = _DAT_00476040 + 1;
    }
    FUN_0044f1bb(0xb);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00457af0(void)

{
  char cVar1;
  char cVar2;
  char *pcVar3;
  int iVar4;
  char *pcVar5;
  int iStack_8;
  
  FUN_0044f15a(0xc);
  _DAT_0046dd18 = 0xffffffff;
  _DAT_0046dd08 = 0xffffffff;
  _DAT_00475f88 = 0;
  pcVar3 = (char *)FUN_0045a09a(&UNK_0045ff18);
  if (pcVar3 == (char *)0x0) {
    FUN_0044f1bb(0xc);
    iVar4 = GetTimeZoneInformation(&DAT_00475f90);
    if (iVar4 == -1) {
      return;
    }
    _DAT_0046dc70 = _DAT_00475f90 * 0x3c;
    _DAT_00475f88 = 1;
    if (_DAT_00475fd6 != 0) {
      _DAT_0046dc70 = _DAT_0046dc70 + _DAT_00475fe4 * 0x3c;
    }
    if ((_DAT_0047602a == 0) || (_DAT_00476038 == 0)) {
      _DAT_0046dc74 = 0;
      _DAT_0046dc78 = 0;
    }
    else {
      _DAT_0046dc74 = 1;
      _DAT_0046dc78 = (_DAT_00476038 - _DAT_00475fe4) * 0x3c;
    }
    iVar4 = WideCharToMultiByte(_DAT_00475dd0,0x220,0x475f94,0xffffffff,_DAT_0046dcfc,0x3f,0,
                                &iStack_8);
    if ((iVar4 == 0) || (iStack_8 != 0)) {
      *_DAT_0046dcfc = 0;
    }
    else {
      _DAT_0046dcfc[0x3f] = 0;
    }
    iVar4 = WideCharToMultiByte(_DAT_00475dd0,0x220,0x475fe8,0xffffffff,_DAT_0046dd00,0x3f,0,
                                &iStack_8);
    if ((iVar4 != 0) && (iStack_8 == 0)) {
      _DAT_0046dd00[0x3f] = 0;
      return;
    }
LAB_00457d61:
    *_DAT_0046dd00 = 0;
  }
  else {
    if ((*pcVar3 != '\0') &&
       ((_DAT_0047603c == 0 || (iVar4 = FUN_00452a60(pcVar3,_DAT_0047603c), iVar4 != 0)))) {
      FUN_0044c4b9(_DAT_0047603c);
      iVar4 = FUN_00452b30(pcVar3);
      _DAT_0047603c = FUN_0044c5a2(iVar4 + 1);
      if (_DAT_0047603c != 0) {
        FUN_00452bf0(_DAT_0047603c,pcVar3);
        FUN_0044f1bb(0xc);
        FUN_0044bd70(_DAT_0046dcfc,pcVar3,3);
        pcVar5 = pcVar3 + 3;
        _DAT_0046dcfc[3] = 0;
        cVar2 = *pcVar5;
        if (cVar2 == '-') {
          pcVar5 = pcVar3 + 4;
        }
        _DAT_0046dc70 = FUN_0044ba2e(pcVar5);
        _DAT_0046dc70 = _DAT_0046dc70 * 0xe10;
        for (; (cVar1 = *pcVar5, cVar1 == '+' || (('/' < cVar1 && (cVar1 < ':'))));
            pcVar5 = pcVar5 + 1) {
        }
        if (*pcVar5 == ':') {
          pcVar5 = pcVar5 + 1;
          iVar4 = FUN_0044ba2e(pcVar5);
          _DAT_0046dc70 = _DAT_0046dc70 + iVar4 * 0x3c;
          for (; ('/' < *pcVar5 && (*pcVar5 < ':')); pcVar5 = pcVar5 + 1) {
          }
          if (*pcVar5 == ':') {
            pcVar5 = pcVar5 + 1;
            iVar4 = FUN_0044ba2e(pcVar5);
            _DAT_0046dc70 = _DAT_0046dc70 + iVar4;
            for (; ('/' < *pcVar5 && (*pcVar5 < ':')); pcVar5 = pcVar5 + 1) {
            }
          }
        }
        if (cVar2 == '-') {
          _DAT_0046dc70 = -_DAT_0046dc70;
        }
        _DAT_0046dc74 = (int)*pcVar5;
        if (_DAT_0046dc74 != 0) {
          FUN_0044bd70(_DAT_0046dd00,pcVar5,3);
          _DAT_0046dd00[3] = 0;
          return;
        }
        goto LAB_00457d61;
      }
    }
    FUN_0044f1bb(0xc);
  }
  return;
}



undefined4 FUN_00457d77(undefined4 param_1)

{
  undefined4 uVar1;
  
  FUN_0044f15a(0xb);
  uVar1 = FUN_00457d98(param_1);
  FUN_0044f1bb(0xb);
  return uVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

bool FUN_00457d98(int *param_1)

{
  int iVar1;
  int iVar2;
  undefined2 uVar3;
  undefined2 uVar4;
  undefined2 uVar5;
  
  if (_DAT_0046dc74 != 0) {
    iVar2 = param_1[5];
    if ((iVar2 != _DAT_0046dd08) || (iVar2 != _DAT_0046dd18)) {
      if (_DAT_00475f88 == 0) {
        FUN_00457f44(1,1,iVar2,4,1,0,0,2,0,0,0);
        FUN_00457f44(0,1,param_1[5],10,5,0,0,2,0,0,0);
      }
      else {
        if (_DAT_00476028 != 0) {
          uVar4 = 0;
          uVar3 = 0;
          uVar5 = _DAT_0047602e;
        }
        else {
          uVar4 = _DAT_0047602c;
          uVar3 = _DAT_0047602e;
          uVar5 = 0;
        }
        FUN_00457f44(1,_DAT_00476028 == 0,iVar2,_DAT_0047602a,uVar3,uVar4,uVar5,_DAT_00476030,
                     _DAT_00476032,_DAT_00476034,_DAT_00476036);
        if (_DAT_00475fd4 != 0) {
          uVar4 = 0;
          uVar3 = 0;
          iVar2 = param_1[5];
          uVar5 = _DAT_00475fda;
        }
        else {
          iVar2 = param_1[5];
          uVar4 = _DAT_00475fd8;
          uVar3 = _DAT_00475fda;
          uVar5 = 0;
        }
        FUN_00457f44(0,_DAT_00475fd4 == 0,iVar2,_DAT_00475fd6,uVar3,uVar4,uVar5,_DAT_00475fdc,
                     _DAT_00475fde,_DAT_00475fe0,_DAT_00475fe2);
      }
    }
    iVar2 = param_1[7];
    if (_DAT_0046dd0c < _DAT_0046dd1c) {
      if ((_DAT_0046dd0c <= iVar2) && (iVar2 <= _DAT_0046dd1c)) {
        if ((_DAT_0046dd0c < iVar2) && (iVar2 < _DAT_0046dd1c)) {
          return true;
        }
LAB_00457f10:
        iVar1 = ((param_1[2] * 0x3c + param_1[1]) * 0x3c + *param_1) * 1000;
        if (iVar2 == _DAT_0046dd0c) {
          return _DAT_0046dd10 <= iVar1;
        }
        return iVar1 < _DAT_0046dd20;
      }
    }
    else {
      if (iVar2 < _DAT_0046dd1c) {
        return true;
      }
      if (_DAT_0046dd0c < iVar2) {
        return true;
      }
      if ((iVar2 <= _DAT_0046dd1c) || (_DAT_0046dd0c <= iVar2)) goto LAB_00457f10;
    }
  }
  return false;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00457f44(int param_1,int param_2,uint param_3,int param_4,int param_5,int param_6,
                 int param_7,int param_8,int param_9,int param_10,int param_11)

{
  int iVar1;
  int iVar2;
  
  if (param_2 == 1) {
    if ((param_3 & 3) == 0) {
      iVar1 = *(int *)(&DAT_0046dd20 + param_4 * 4);
    }
    else {
      iVar1 = *(int *)(param_4 * 4 + 0x46dd54);
    }
    iVar2 = (int)(param_3 * 0x16d + -0x63db + iVar1 + 1 + ((int)(param_3 - 1) >> 2)) % 7;
    if (param_6 < iVar2) {
      iVar1 = iVar1 + 1 + (param_5 * 7 - iVar2) + param_6;
    }
    else {
      iVar1 = iVar1 + -6 + (param_5 * 7 - iVar2) + param_6;
    }
    if (param_5 == 5) {
      if ((param_3 & 3) == 0) {
        iVar2 = *(int *)(param_4 * 4 + 0x46dd24);
      }
      else {
        iVar2 = *(int *)(param_4 * 4 + 0x46dd58);
      }
      if (iVar2 < iVar1) {
        iVar1 = iVar1 + -7;
      }
    }
  }
  else {
    if ((param_3 & 3) == 0) {
      iVar1 = *(int *)(&DAT_0046dd20 + param_4 * 4);
    }
    else {
      iVar1 = *(int *)(param_4 * 4 + 0x46dd54);
    }
    iVar1 = iVar1 + param_7;
  }
  if (param_1 == 1) {
    _DAT_0046dd08 = param_3;
    _DAT_0046dd10 = ((param_8 * 0x3c + param_9) * 0x3c + param_10) * 1000 + param_11;
    _DAT_0046dd0c = iVar1;
  }
  else {
    _DAT_0046dd20 = ((param_8 * 0x3c + param_9) * 0x3c + _DAT_0046dc78 + param_10) * 1000 + param_11
    ;
    if (_DAT_0046dd20 < 0) {
      _DAT_0046dd20 = _DAT_0046dd20 + 86400000;
      _DAT_0046dd1c = iVar1 + -1;
    }
    else {
      _DAT_0046dd1c = iVar1;
      if (86399999 < _DAT_0046dd20) {
        _DAT_0046dd20 = _DAT_0046dd20 + -86400000;
        _DAT_0046dd1c = iVar1 + 1;
      }
    }
    _DAT_0046dd18 = param_3;
  }
  return;
}



undefined4 FUN_00458084(undefined4 param_1,undefined4 param_2)

{
  undefined4 uVar1;
  
  FUN_0044f15a(0xc);
  uVar1 = FUN_004580ab(0,param_1,param_2);
  FUN_0044f1bb(0xc);
  return uVar1;
}



undefined4 FUN_004580ab(uint param_1,int param_2,uint param_3)

{
  int iVar1;
  undefined4 *puVar2;
  uint uVar3;
  undefined4 uVar4;
  undefined auStack_10c [260];
  undefined auStack_8 [4];
  
  uVar3 = param_1;
  if (param_1 == 0) {
    iVar1 = GetCurrentDirectoryA(0x104,auStack_10c);
  }
  else {
    iVar1 = FUN_00458180(param_1);
    if (iVar1 == 0) {
      puVar2 = (undefined4 *)FUN_00451e4d();
      *puVar2 = 0xf;
      puVar2 = (undefined4 *)FUN_00451e44();
      *puVar2 = 0xd;
      return 0;
    }
    param_1 = (uint)CONCAT12(0x2e,CONCAT11(0x3a,(char)uVar3 + '@'));
    iVar1 = GetFullPathNameA(&param_1,0x104,auStack_10c,auStack_8);
  }
  if ((iVar1 != 0) && (uVar3 = iVar1 + 1, uVar3 < 0x105)) {
    if (param_2 == 0) {
      if ((int)uVar3 <= (int)param_3) {
        uVar3 = param_3;
      }
      iVar1 = FUN_0044c5a2(uVar3);
      if (iVar1 != 0) {
LAB_0045816c:
        uVar4 = FUN_00452bf0(iVar1,auStack_10c);
        return uVar4;
      }
      puVar2 = (undefined4 *)FUN_00451e44();
      *puVar2 = 0xc;
    }
    else {
      iVar1 = param_2;
      if ((int)uVar3 <= (int)param_3) goto LAB_0045816c;
      puVar2 = (undefined4 *)FUN_00451e44();
      *puVar2 = 0x22;
    }
  }
  return 0;
}



undefined4 FUN_00458180(uint param_1)

{
  char cVar1;
  int iVar2;
  
  if (param_1 != 0) {
    cVar1 = (char)param_1;
    param_1 = (uint)CONCAT12(0x5c,CONCAT11(0x3a,cVar1 + '@'));
    iVar2 = GetDriveTypeA(&param_1);
    if ((iVar2 == 0) || (iVar2 == 1)) {
      return 0;
    }
  }
  return 1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

uint FUN_004581b7(undefined4 param_1,uint param_2,uint param_3,uint param_4)

{
  byte *pbVar1;
  uint uVar2;
  uint uVar3;
  undefined4 *puVar4;
  int iVar5;
  undefined4 uVar6;
  int iVar7;
  int *piVar8;
  bool bVar9;
  undefined4 uStack_20;
  undefined4 uStack_1c;
  uint uStack_18;
  int iStack_14;
  undefined4 uStack_10;
  undefined4 uStack_c;
  byte bStack_5;
  
  bVar9 = (param_2 & 0x80) == 0;
  uStack_20 = 0xc;
  uStack_1c = 0;
  if (bVar9) {
    bStack_5 = 0;
  }
  else {
    bStack_5 = 0x10;
  }
  uStack_18 = (uint)bVar9;
  if (((param_2 & 0x8000) == 0) && (((param_2 & 0x4000) != 0 || (_DAT_00476064 != 0x8000)))) {
    bStack_5 = bStack_5 | 0x80;
  }
  uVar2 = param_2 & 3;
  if (uVar2 == 0) {
    uStack_10 = 0x80000000;
  }
  else if (uVar2 == 1) {
    uStack_10 = 0x40000000;
  }
  else {
    if (uVar2 != 2) goto LAB_004582bb;
    uStack_10 = 0xc0000000;
  }
  if (param_3 == 0x10) {
    iStack_14 = 0;
  }
  else if (param_3 == 0x20) {
    iStack_14 = 1;
  }
  else if (param_3 == 0x30) {
    iStack_14 = 2;
  }
  else {
    if (param_3 != 0x40) goto LAB_004582bb;
    iStack_14 = 3;
  }
  uVar2 = param_2 & 0x700;
  if (uVar2 < 0x401) {
    if ((uVar2 == 0x400) || (uVar2 == 0)) {
      uStack_c = 3;
    }
    else if (uVar2 == 0x100) {
      uStack_c = 4;
    }
    else {
      if (uVar2 == 0x200) goto LAB_004582d5;
      if (uVar2 != 0x300) goto LAB_004582bb;
      uStack_c = 2;
    }
  }
  else {
    if (uVar2 != 0x500) {
      if (uVar2 == 0x600) {
LAB_004582d5:
        uStack_c = 5;
        goto LAB_004582e5;
      }
      if (uVar2 != 0x700) {
LAB_004582bb:
        puVar4 = (undefined4 *)FUN_00451e44();
        *puVar4 = 0x16;
        puVar4 = (undefined4 *)FUN_00451e4d();
        *puVar4 = 0;
        return 0xffffffff;
      }
    }
    uStack_c = 1;
  }
LAB_004582e5:
  uVar2 = 0x80;
  if (((param_2 & 0x100) != 0) && ((~_DAT_00475d14 & param_4 & 0x80) == 0)) {
    uVar2 = 1;
  }
  if ((param_2 & 0x40) != 0) {
    uVar2 = uVar2 | 0x4000000;
    uStack_10 = CONCAT13(uStack_10._3_1_,0x10000);
  }
  if ((param_2 & 0x1000) != 0) {
    uVar2 = uVar2 | 0x100;
  }
  if ((param_2 & 0x20) == 0) {
    if ((param_2 & 0x10) != 0) {
      uVar2 = uVar2 | 0x10000000;
    }
  }
  else {
    uVar2 = uVar2 | 0x8000000;
  }
  uVar3 = FUN_0045774e();
  if (uVar3 == 0xffffffff) {
    puVar4 = (undefined4 *)FUN_00451e44();
    *puVar4 = 0x18;
    puVar4 = (undefined4 *)FUN_00451e4d();
    *puVar4 = 0;
    return 0xffffffff;
  }
  iVar5 = CreateFileA(param_1,uStack_10,iStack_14,&uStack_20,uStack_c,uVar2,0);
  if (iVar5 != -1) {
    iVar7 = GetFileType(iVar5);
    if (iVar7 != 0) {
      if (iVar7 == 2) {
        bStack_5 = bStack_5 | 0x40;
      }
      else if (iVar7 == 3) {
        bStack_5 = bStack_5 | 8;
      }
      FUN_00457871(uVar3,iVar5);
      iVar5 = (uVar3 & 0x1f) * 0x24;
      param_1._3_1_ = bStack_5 & 0x48;
      *(byte *)(*(int *)(&DAT_004777e0 + ((int)uVar3 >> 5) * 4) + 4 + iVar5) = bStack_5 | 1;
      if ((((bStack_5 & 0x48) == 0) && ((bStack_5 & 0x80) != 0)) && ((param_2 & 2) != 0)) {
        iStack_14 = FUN_004567b1(uVar3,0xffffffff,2);
        if (iStack_14 == -1) {
          piVar8 = (int *)FUN_00451e4d();
          if (*piVar8 == 0x83) goto LAB_0045845f;
        }
        else {
          param_3 = param_3 & 0xffffff;
          iVar7 = FUN_004547fa(uVar3,(int)&param_3 + 3,1);
          if ((((iVar7 != 0) || (param_3._3_1_ != '\x1a')) ||
              (iVar7 = FUN_0045a117(uVar3,iStack_14), iVar7 != -1)) &&
             (iVar7 = FUN_004567b1(uVar3,0,0), iVar7 != -1)) goto LAB_0045845f;
        }
        FUN_00454448(uVar3);
        uVar2 = 0xffffffff;
      }
      else {
LAB_0045845f:
        uVar2 = uVar3;
        if ((param_1._3_1_ == 0) && ((param_2 & 8) != 0)) {
          pbVar1 = (byte *)(*(int *)(&DAT_004777e0 + ((int)uVar3 >> 5) * 4) + 4 + iVar5);
          *pbVar1 = *pbVar1 | 0x20;
        }
      }
      goto LAB_00458478;
    }
    CloseHandle(iVar5);
  }
  uVar6 = GetLastError();
  FUN_00451dd1(uVar6);
  uVar2 = 0xffffffff;
LAB_00458478:
  FUN_00457a0d(uVar3);
  return uVar2;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0045921b(int param_1,int *param_2,ushort *param_3)

{
  int iVar1;
  undefined4 uVar2;
  undefined auStack_5c [40];
  undefined8 uStack_34;
  uint uStack_24;
  
  param_3 = (ushort *)(uint)*param_3;
  iVar1 = *param_2;
  if (iVar1 == 1) {
LAB_00459260:
    uVar2 = 8;
  }
  else if (iVar1 == 2) {
    uVar2 = 4;
  }
  else if (iVar1 == 3) {
    uVar2 = 0x11;
  }
  else if (iVar1 == 4) {
    uVar2 = 0x12;
  }
  else {
    if (iVar1 == 5) goto LAB_00459260;
    if (iVar1 == 7) {
      *param_2 = 1;
      goto LAB_004592b6;
    }
    if (iVar1 != 8) goto LAB_004592b6;
    uVar2 = 0x10;
  }
  iVar1 = FUN_0045a4ef(uVar2,param_2 + 6,param_3);
  if (iVar1 == 0) {
    if (((param_1 == 0x10) || (param_1 == 0x16)) || (param_1 == 0x1d)) {
      uStack_34 = *(undefined8 *)(param_2 + 4);
      uStack_24 = uStack_24 & 0xffffffe3 | 3;
    }
    else {
      uStack_24 = uStack_24 & 0xfffffffe;
    }
    FUN_0045a23c(auStack_5c,&param_3,uVar2,param_1,param_2 + 2,param_2 + 6);
  }
LAB_004592b6:
  FUN_0045a74b(param_3,0xffff);
  if (((*param_2 != 8) && (_DAT_0046dff8 == 0)) && (iVar1 = FUN_0044cf7b(param_2), iVar1 != 0)) {
    return;
  }
  FUN_0045a706(*param_2);
  return;
}



float10 FUN_004592eb(undefined8 param_1,short param_2)

{
  double dStack_c;
  
  dStack_c = (double)CONCAT26((param_2 + 0x3fe) * 0x10 | param_1._6_2_ & 0x800f,(undefined6)param_1)
  ;
  return (float10)dStack_c;
}



undefined4 FUN_00459314(int param_1,uint param_2)

{
  undefined4 uStack_8;
  
  if (param_2 == 0x7ff00000) {
    if (param_1 == 0) {
      return 1;
    }
  }
  else if ((param_2 == 0xfff00000) && (param_1 == 0)) {
    return 2;
  }
  if ((param_2._2_2_ & 0x7ff8) == 0x7ff8) {
    uStack_8 = 3;
  }
  else {
    if (((param_2._2_2_ & 0x7ff8) != 0x7ff0) || (((param_2 & 0x7ffff) == 0 && (param_1 == 0)))) {
      return 0;
    }
    uStack_8 = 4;
  }
  return uStack_8;
}



float10 FUN_0045936e(uint param_1,uint param_2,int *param_3)

{
  ushort uVar1;
  int iVar2;
  bool bVar3;
  int iVar4;
  float10 fVar5;
  double dStack_c;
  
  if ((double)CONCAT17(param_2._3_1_,CONCAT16(param_2._2_1_,CONCAT24((ushort)param_2,param_1))) ==
      0.0) {
    iVar4 = 0;
    dStack_c = 0.0;
  }
  else if (((param_2 & 0x7ff00000) == 0) && (((param_2 & 0xfffff) != 0 || (param_1 != 0)))) {
    iVar4 = -0x3fd;
    if (0.0 <= (double)CONCAT17(param_2._3_1_,
                                CONCAT16(param_2._2_1_,CONCAT24((ushort)param_2,param_1)))) {
      bVar3 = false;
    }
    else {
      bVar3 = true;
    }
    while ((param_2._2_1_ & 0x10) == 0) {
      iVar2 = CONCAT13(param_2._3_1_,CONCAT12(param_2._2_1_,(ushort)param_2)) << 1;
      param_2._0_2_ = (ushort)iVar2;
      param_2._2_1_ = (byte)((uint)iVar2 >> 0x10);
      param_2._3_1_ = (byte)((uint)iVar2 >> 0x18);
      if ((param_1 & 0x80000000) != 0) {
        param_2._0_2_ = (ushort)param_2 | 1;
      }
      param_1 = param_1 << 1;
      iVar4 = iVar4 + -1;
    }
    uVar1 = CONCAT11(param_2._3_1_,param_2._2_1_) & 0xffef;
    param_2._2_1_ = (byte)uVar1;
    param_2._3_1_ = (byte)(uVar1 >> 8);
    if (bVar3) {
      param_2._3_1_ = param_2._3_1_ | 0x80;
    }
    fVar5 = (float10)FUN_004592eb(CONCAT17(param_2._3_1_,
                                           CONCAT16(param_2._2_1_,CONCAT24((ushort)param_2,param_1))
                                          ),0);
    dStack_c = (double)fVar5;
  }
  else {
    fVar5 = (float10)FUN_004592eb(CONCAT17(param_2._3_1_,
                                           CONCAT16(param_2._2_1_,CONCAT24((ushort)param_2,param_1))
                                          ),0);
    dStack_c = (double)fVar5;
    iVar4 = (short)((ushort)(param_2 >> 0x14) & 0x7ff) + -0x3fe;
  }
  *param_3 = iVar4;
  return (float10)dStack_c;
}



float10 FUN_0045942f(double param_1)

{
  return (float10)ROUND(param_1);
}



int FUN_00459441(int param_1,uint param_2)

{
  int iVar1;
  int iStack_8;
  
  if ((param_2._2_2_ & 0x7ff0) == 0x7ff0) {
    iVar1 = FUN_00459314();
    if (iVar1 != 1) {
      if (iVar1 == 2) {
        iStack_8 = 4;
      }
      else if (iVar1 == 3) {
        iStack_8 = 2;
      }
      else {
        iStack_8 = 1;
      }
      return iStack_8;
    }
    return 0x200;
  }
  if (((param_2 & 0x7ff00000) == 0) && (((param_2 & 0xfffff) != 0 || (param_1 != 0)))) {
    return (-(uint)((param_2 & 0x80000000) != 0) & 0xffffff90) + 0x80;
  }
  if ((double)CONCAT26(param_2._2_2_,CONCAT24((undefined2)param_2,param_1)) == 0.0) {
    return (-(uint)((param_2 & 0x80000000) != 0) & 0xffffffe0) + 0x40;
  }
  return (-(uint)((param_2 & 0x80000000) != 0) & 0xffffff08) + 0x100;
}



bool FUN_004594d3(undefined4 param_1,undefined4 param_2)

{
  int iVar1;
  
  iVar1 = IsBadReadPtr(param_1,param_2);
  return iVar1 == 0;
}



bool FUN_004594ef(undefined4 param_1,undefined4 param_2)

{
  int iVar1;
  
  iVar1 = IsBadWritePtr(param_1,param_2);
  return iVar1 == 0;
}



bool FUN_0045950b(undefined4 param_1)

{
  int iVar1;
  
  iVar1 = IsBadCodePtr(param_1);
  return iVar1 == 0;
}



void FUN_00459523(void)

{
  int iVar1;
  void *pvStack_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 uStack_8;
  
  puStack_c = &UNK_0045ff20;
  puStack_10 = &UNK_0045001c;
  pvStack_14 = ExceptionList;
  uStack_8 = 0;
  ExceptionList = &pvStack_14;
  iVar1 = FUN_0044fc4a();
  if (*(int *)(iVar1 + 0x60) != 0) {
    uStack_8 = 1;
    iVar1 = FUN_0044fc4a();
    (**(code **)(iVar1 + 0x60))();
  }
  uStack_8 = 0xffffffff;
  FUN_0045a7c4();
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00459584(void)

{
  void *pvStack_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 uStack_8;
  
  puStack_c = &UNK_0045ff38;
  puStack_10 = &UNK_0045001c;
  pvStack_14 = ExceptionList;
  ExceptionList = &pvStack_14;
  if (_DAT_0046df18 != (code *)0x0) {
    uStack_8 = 1;
    ExceptionList = &pvStack_14;
    (*_DAT_0046df18)();
  }
  uStack_8 = 0xffffffff;
  FUN_00459523();
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_004595da(int param_1)

{
  bool bVar1;
  int iVar2;
  int iVar3;
  code *pcVar4;
  code *extraout_ECX;
  int iVar5;
  code *pcVar6;
  code **ppcVar7;
  undefined4 uStack_10;
  undefined4 uStack_c;
  
  bVar1 = false;
  if (param_1 == 2) {
    ppcVar7 = (code **)&DAT_00476048;
    pcVar6 = _DAT_00476048;
LAB_00459660:
    bVar1 = true;
    FUN_0044f15a(1);
    iVar2 = param_1;
  }
  else {
    if (((param_1 != 4) && (param_1 != 8)) && (param_1 != 0xb)) {
      if (param_1 == 0xf) {
        ppcVar7 = (code **)&DAT_00476054;
        pcVar6 = _DAT_00476054;
      }
      else if (param_1 == 0x15) {
        ppcVar7 = (code **)&DAT_0047604c;
        pcVar6 = _DAT_0047604c;
      }
      else {
        if (param_1 != 0x16) {
          return 0xffffffff;
        }
        ppcVar7 = (code **)&DAT_00476050;
        pcVar6 = _DAT_00476050;
      }
      goto LAB_00459660;
    }
    iVar2 = FUN_0044fc4a();
    iVar5 = FUN_0045975c(param_1,*(undefined4 *)(iVar2 + 0x50));
    ppcVar7 = (code **)(iVar5 + 8);
    pcVar6 = *ppcVar7;
  }
  if (pcVar6 == (code *)0x1) {
    if (!bVar1) {
      return 0;
    }
    FUN_0044f1bb(1);
    return 0;
  }
  pcVar4 = (code *)0x0;
  if (pcVar6 == (code *)0x0) {
    if (bVar1) {
      FUN_0044f1bb(1);
    }
    FUN_0044ec32(3);
    pcVar4 = extraout_ECX;
  }
  if (((param_1 == 8) || (param_1 == 0xb)) || (param_1 == 4)) {
    uStack_c = *(undefined4 *)(iVar2 + 0x54);
    *(code **)(iVar2 + 0x54) = pcVar4;
    if (param_1 == 8) {
      uStack_10 = *(undefined4 *)(iVar2 + 0x58);
      *(undefined4 *)(iVar2 + 0x58) = 0x8c;
      goto LAB_004596d4;
    }
  }
  else {
LAB_004596d4:
    if (param_1 == 8) {
      if (_DAT_0046afa8 < _DAT_0046afac + _DAT_0046afa8) {
        iVar3 = _DAT_0046afa8 * 0xc;
        iVar5 = _DAT_0046afa8;
        do {
          iVar3 = iVar3 + 0xc;
          *(undefined4 *)(*(int *)(iVar2 + 0x50) + -4 + iVar3) = 0;
          iVar5 = iVar5 + 1;
        } while (iVar5 < _DAT_0046afac + _DAT_0046afa8);
      }
      goto LAB_00459712;
    }
  }
  *ppcVar7 = pcVar4;
LAB_00459712:
  if (bVar1) {
    FUN_0044f1bb(1);
  }
  if (param_1 == 8) {
    (*pcVar6)(8,*(undefined4 *)(iVar2 + 0x58));
  }
  else {
    (*pcVar6)(param_1);
    if ((param_1 != 0xb) && (param_1 != 4)) {
      return 0;
    }
  }
  *(undefined4 *)(iVar2 + 0x54) = uStack_c;
  if (param_1 == 8) {
    *(undefined4 *)(iVar2 + 0x58) = uStack_10;
  }
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

uint FUN_0045975c(int param_1,uint param_2)

{
  int *piVar1;
  uint uVar2;
  uint uVar3;
  
  uVar2 = param_2;
  if (*(int *)(param_2 + 4) != param_1) {
    uVar3 = param_2;
    do {
      uVar2 = uVar3 + 0xc;
      if (param_2 + _DAT_0046afb4 * 0xc <= uVar2) break;
      piVar1 = (int *)(uVar3 + 0x10);
      uVar3 = uVar2;
    } while (*piVar1 != param_1);
  }
  if ((param_2 + _DAT_0046afb4 * 0xc <= uVar2) || (*(int *)(uVar2 + 4) != param_1)) {
    uVar2 = 0;
  }
  return uVar2;
}



undefined4 FUN_00459799(uint param_1,uint param_2,uint *param_3)

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



void FUN_004597ba(undefined4 *param_1,undefined4 *param_2)

{
  int iVar1;
  
  iVar1 = FUN_00459799(*param_1,*param_2,param_1);
  if (iVar1 != 0) {
    iVar1 = FUN_00459799(param_1[1],1,param_1 + 1);
    if (iVar1 != 0) {
      param_1[2] = param_1[2] + 1;
    }
  }
  iVar1 = FUN_00459799(param_1[1],param_2[1],param_1 + 1);
  if (iVar1 != 0) {
    param_1[2] = param_1[2] + 1;
  }
  FUN_00459799(param_1[2],param_2[2],param_1 + 2);
  return;
}



void FUN_00459818(uint *param_1)

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



void FUN_00459846(uint *param_1)

{
  uint uVar1;
  
  uVar1 = param_1[1];
  param_1[1] = uVar1 >> 1 | param_1[2] << 0x1f;
  param_1[2] = param_1[2] >> 1;
  *param_1 = *param_1 >> 1 | uVar1 << 0x1f;
  return;
}



void FUN_00459873(char *param_1,int param_2,uint *param_3)

{
  uint *puVar1;
  uint uStack_14;
  uint uStack_10;
  uint uStack_c;
  int iStack_8;
  
  puVar1 = param_3;
  iStack_8 = 0x404e;
  *param_3 = 0;
  param_3[1] = 0;
  param_3[2] = 0;
  if (param_2 != 0) {
    param_3 = (uint *)param_2;
    do {
      uStack_14 = *puVar1;
      uStack_10 = puVar1[1];
      uStack_c = puVar1[2];
      FUN_00459818(puVar1);
      FUN_00459818(puVar1);
      FUN_004597ba(puVar1,&uStack_14);
      FUN_00459818(puVar1);
      uStack_10 = 0;
      uStack_c = 0;
      uStack_14 = (uint)*param_1;
      FUN_004597ba(puVar1,&uStack_14);
      param_1 = param_1 + 1;
      param_3 = (uint *)((int)param_3 + -1);
    } while (param_3 != (uint *)0x0);
  }
  while (puVar1[2] == 0) {
    puVar1[2] = puVar1[1] >> 0x10;
    iStack_8 = iStack_8 + 0xfff0;
    puVar1[1] = *puVar1 >> 0x10 | puVar1[1] << 0x10;
    *puVar1 = *puVar1 << 0x10;
  }
  while ((puVar1[2] & 0x8000) == 0) {
    FUN_00459818(puVar1);
    iStack_8 = iStack_8 + 0xffff;
  }
  *(undefined2 *)((int)puVar1 + 10) = (undefined2)iStack_8;
  return;
}



undefined4
FUN_0045993a(int param_1,uint param_2,uint param_3,int param_4,byte param_5,short *param_6)

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
  undefined *puVar10;
  undefined uStack_20;
  undefined uStack_1f;
  undefined uStack_1e;
  undefined uStack_1d;
  undefined uStack_1c;
  undefined uStack_1b;
  undefined uStack_1a;
  undefined uStack_19;
  undefined uStack_18;
  undefined uStack_17;
  undefined uStack_16;
  undefined uStack_15;
  undefined2 uStack_14;
  undefined2 uStack_12;
  undefined2 uStack_10;
  undefined2 uStack_e;
  undefined2 uStack_c;
  undefined uStack_a;
  char cStack_9;
  undefined4 uStack_8;
  
  psVar2 = param_6;
  uVar4 = param_3 & 0x7fff;
  uStack_20 = 0xcc;
  uStack_1f = 0xcc;
  uStack_1e = 0xcc;
  uStack_1d = 0xcc;
  uStack_1c = 0xcc;
  uStack_1b = 0xcc;
  uStack_1a = 0xcc;
  uStack_19 = 0xcc;
  uStack_18 = 0xcc;
  uStack_17 = 0xcc;
  uStack_16 = 0xfb;
  uStack_15 = 0x3f;
  uStack_8 = 1;
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
          if ((param_2 != 0x80000000) || (param_1 != 0)) goto LAB_00459a2f;
          puVar10 = &UNK_0045ff58;
        }
        else {
          if (param_1 != 0) {
LAB_00459a2f:
            puVar10 = &UNK_0045ff50;
            goto LAB_00459a34;
          }
          puVar10 = &UNK_0045ff60;
        }
        FUN_00452bf0(param_6 + 2,puVar10);
        *(undefined *)((int)psVar2 + 3) = 5;
      }
      else {
        puVar10 = &UNK_0045ff68;
LAB_00459a34:
        FUN_00452bf0(param_6 + 2,puVar10);
        *(undefined *)((int)psVar2 + 3) = 6;
      }
      return 0;
    }
    uStack_14 = 0;
    uStack_a = (undefined)uVar4;
    cStack_9 = (char)(uVar4 >> 8);
    uStack_e = (undefined2)param_2;
    uStack_c = (undefined2)(param_2 >> 0x10);
    uStack_12 = (undefined2)param_1;
    uStack_10 = (undefined2)((uint)param_1 >> 0x10);
    sVar7 = (short)(((uVar4 >> 8) + (param_2 >> 0x18) * 2) * 0x4d + -0x134312f4 + uVar4 * 0x4d10 >>
                   0x10);
    FUN_0045a01e(&uStack_14,-(int)sVar7,1);
    if (0x3ffe < CONCAT11(cStack_9,uStack_a)) {
      sVar7 = sVar7 + 1;
      FUN_00459dfe(&uStack_14,&uStack_20);
    }
    *psVar2 = sVar7;
    iVar9 = param_4;
    if (((param_5 & 1) == 0) || (iVar9 = param_4 + sVar7, 0 < param_4 + sVar7)) {
      if (0x15 < iVar9) {
        iVar9 = 0x15;
      }
      iVar8 = CONCAT11(cStack_9,uStack_a) - 0x3ffe;
      uStack_a = 0;
      cStack_9 = '\0';
      param_6 = (short *)0x8;
      do {
        FUN_00459818(&uStack_14);
        param_6 = (short *)((int)param_6 + -1);
      } while (param_6 != (short *)0x0);
      if (iVar8 < 0) {
        param_6 = (short *)0x0;
        for (uVar4 = -iVar8 & 0xff; uVar4 != 0; uVar4 = uVar4 - 1) {
          FUN_00459846(&uStack_14);
        }
      }
      param_4 = iVar9 + 1;
      psVar5 = psVar2 + 2;
      param_6 = psVar5;
      if (0 < param_4) {
        do {
          param_1 = CONCAT22(uStack_12,uStack_14);
          param_2 = CONCAT22(uStack_e,uStack_10);
          param_3 = CONCAT13(cStack_9,CONCAT12(uStack_a,uStack_c));
          FUN_00459818(&uStack_14);
          FUN_00459818(&uStack_14);
          FUN_004597ba(&uStack_14,&param_1);
          FUN_00459818(&uStack_14);
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
            if (psVar1 <= psVar6) goto LAB_00459b8c;
            break;
          }
          *(undefined *)psVar6 = 0x30;
        }
        psVar6 = (short *)((int)psVar6 + 1);
        *psVar2 = *psVar2 + 1;
LAB_00459b8c:
        *(char *)psVar6 = *(char *)psVar6 + '\x01';
LAB_00459b8e:
        cVar3 = ((char)psVar6 - (char)psVar2) + -3;
        *(char *)((int)psVar2 + 3) = cVar3;
        *(undefined *)(cVar3 + 4 + (int)psVar2) = 0;
        return uStack_8;
      }
      for (; psVar1 <= psVar6; psVar6 = (short *)((int)psVar6 + -1)) {
        if (*(char *)psVar6 != '0') {
          if (psVar1 <= psVar6) goto LAB_00459b8e;
          break;
        }
      }
      *psVar2 = 0;
      *(undefined *)(psVar2 + 1) = 0x20;
      *(undefined *)((int)psVar2 + 3) = 1;
      *(undefined *)psVar1 = 0x30;
      goto LAB_00459bc4;
    }
  }
  *psVar2 = 0;
  *(undefined *)(psVar2 + 1) = 0x20;
  *(undefined *)((int)psVar2 + 3) = 1;
  *(undefined *)(psVar2 + 2) = 0x30;
LAB_00459bc4:
  *(undefined *)((int)psVar2 + 5) = 0;
  return 1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4
FUN_00459bcd(undefined4 param_1,undefined4 param_2,undefined4 param_3,int param_4,int param_5)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 uStack_44;
  undefined4 uStack_40;
  undefined4 uStack_3c;
  int iStack_38;
  void *pvStack_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 uStack_8;
  
  uStack_8 = 0xffffffff;
  puStack_c = &UNK_0045ff70;
  puStack_10 = &UNK_0045001c;
  pvStack_14 = ExceptionList;
  ExceptionList = &pvStack_14;
  if (_DAT_0047605c == 0) {
    iStack_38 = 0;
    uStack_3c = 0;
    uStack_40 = 1;
    uStack_44 = 0;
    ExceptionList = &pvStack_14;
    iVar1 = GetLocaleInfoW();
    if (iVar1 == 0) {
      iStack_38 = 0;
      uStack_3c = 0;
      uStack_40 = 1;
      uStack_44 = 0;
      iVar1 = GetLocaleInfoA();
      if (iVar1 == 0) {
        ExceptionList = pvStack_14;
        return 0;
      }
      iStack_38 = 2;
    }
    else {
      iStack_38 = 1;
    }
    _DAT_0047605c = iStack_38;
  }
  if (_DAT_0047605c != 1) {
    if (_DAT_0047605c == 2) {
      if (param_5 == 0) {
        param_5 = _DAT_00475dd0;
      }
      iStack_38 = 0;
      uStack_3c = 0;
      uStack_40 = param_2;
      uStack_44 = param_1;
      iVar1 = GetLocaleInfoA();
      if (iVar1 != 0) {
        uStack_8 = 0;
        FUN_0044c080();
        uStack_8 = 0xffffffff;
        if ((&stack0x00000000 != (undefined *)0x44) &&
           (iVar1 = GetLocaleInfoA(param_1,param_2,&uStack_44,iVar1), iVar1 != 0)) {
          if (param_4 == 0) {
            param_4 = 0;
            param_3 = 0;
          }
          uVar2 = MultiByteToWideChar(param_5,1,&uStack_44,0xffffffff,param_3,param_4);
          ExceptionList = pvStack_14;
          return uVar2;
        }
      }
    }
    ExceptionList = pvStack_14;
    return 0;
  }
  iStack_38 = param_4;
  uStack_3c = param_3;
  uStack_40 = param_2;
  uStack_44 = param_1;
  uVar2 = GetLocaleInfoW();
  ExceptionList = pvStack_14;
  return uVar2;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4
FUN_00459ce0(undefined4 param_1,undefined4 param_2,undefined4 param_3,int param_4,int param_5)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 uStack_44;
  undefined4 uStack_40;
  undefined4 uStack_3c;
  int iStack_38;
  void *pvStack_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 uStack_8;
  
  uStack_8 = 0xffffffff;
  puStack_c = &UNK_0045ff80;
  puStack_10 = &UNK_0045001c;
  pvStack_14 = ExceptionList;
  ExceptionList = &pvStack_14;
  if (_DAT_00476060 == 0) {
    iStack_38 = 0;
    uStack_3c = 0;
    uStack_40 = 1;
    uStack_44 = 0;
    ExceptionList = &pvStack_14;
    iVar1 = GetLocaleInfoW();
    if (iVar1 == 0) {
      iStack_38 = 0;
      uStack_3c = 0;
      uStack_40 = 1;
      uStack_44 = 0;
      iVar1 = GetLocaleInfoA();
      if (iVar1 == 0) {
        ExceptionList = pvStack_14;
        return 0;
      }
      iStack_38 = 2;
    }
    else {
      iStack_38 = 1;
    }
    _DAT_00476060 = iStack_38;
  }
  if (_DAT_00476060 != 2) {
    if (_DAT_00476060 == 1) {
      if (param_5 == 0) {
        param_5 = _DAT_00475dd0;
      }
      iStack_38 = 0;
      uStack_3c = 0;
      uStack_40 = param_2;
      uStack_44 = param_1;
      iVar1 = GetLocaleInfoW();
      if (iVar1 != 0) {
        uStack_8 = 0;
        FUN_0044c080();
        uStack_8 = 0xffffffff;
        if ((&stack0x00000000 != (undefined *)0x44) &&
           (iVar1 = GetLocaleInfoW(param_1,param_2,&uStack_44,iVar1), iVar1 != 0)) {
          if (param_4 == 0) {
            param_4 = 0;
            param_3 = 0;
          }
          uVar2 = WideCharToMultiByte(param_5,0x220,&uStack_44,0xffffffff,param_3,param_4,0,0);
          ExceptionList = pvStack_14;
          return uVar2;
        }
      }
    }
    ExceptionList = pvStack_14;
    return 0;
  }
  iStack_38 = param_4;
  uStack_3c = param_3;
  uStack_40 = param_2;
  uStack_44 = param_1;
  uVar2 = GetLocaleInfoA();
  ExceptionList = pvStack_14;
  return uVar2;
}



void FUN_00459dfe(int *param_1,int *param_2)

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
  byte bStack_28;
  undefined uStack_27;
  undefined2 uStack_26;
  short sStack_24;
  undefined2 uStack_22;
  undefined2 uStack_20;
  undefined uStack_1e;
  byte bStack_1d;
  int iStack_1c;
  int iStack_18;
  int iStack_14;
  int *piStack_10;
  ushort *puStack_c;
  short *psStack_8;
  
  piVar5 = param_2;
  piVar4 = param_1;
  iStack_18 = 0;
  bStack_28 = 0;
  uStack_27 = 0;
  uStack_26 = 0;
  sStack_24 = 0;
  uStack_22 = 0;
  uStack_20 = 0;
  uStack_1e = 0;
  bStack_1d = 0;
  uVar6 = *(ushort *)((int)param_1 + 10) & 0x7fff;
  uVar8 = *(ushort *)((int)param_2 + 10) & 0x7fff;
  uVar9 = (*(ushort *)((int)param_2 + 10) ^ *(ushort *)((int)param_1 + 10)) & 0x8000;
  uVar3 = uVar8 + uVar6;
  if (((uVar6 < 0x7fff) && (uVar8 < 0x7fff)) && (uVar3 < 0xbffe)) {
    if (uVar3 < 0x3fc0) {
LAB_00459ea1:
      param_1[2] = 0;
      param_1[1] = 0;
      *param_1 = 0;
      return;
    }
    if (((uVar6 != 0) || (uVar3 = uVar3 + 1, (param_1[2] & 0x7fffffffU) != 0)) ||
       ((uVar6 = 0, param_1[1] != 0 || (*param_1 != 0)))) {
      if (((uVar8 == 0) && (uVar3 = uVar3 + 1, (param_2[2] & 0x7fffffffU) == 0)) &&
         ((param_2[1] == 0 && (*param_2 == 0)))) goto LAB_00459ea1;
      iStack_14 = 0;
      psStack_8 = &sStack_24;
      param_2 = (int *)0x5;
      do {
        if (0 < (int)param_2) {
          puStack_c = (ushort *)(iStack_14 * 2 + (int)param_1);
          piStack_10 = piVar5 + 2;
          iStack_1c = (int)param_2;
          do {
            iVar7 = FUN_00459799(*(undefined4 *)(psStack_8 + -2),
                                 (uint)*puStack_c * (uint)*(ushort *)piStack_10,psStack_8 + -2);
            if (iVar7 != 0) {
              *psStack_8 = *psStack_8 + 1;
            }
            puStack_c = puStack_c + 1;
            piStack_10 = (int *)((int)piStack_10 + -2);
            iStack_1c = iStack_1c + -1;
          } while (iStack_1c != 0);
        }
        psStack_8 = psStack_8 + 1;
        iStack_14 = iStack_14 + 1;
        param_2 = (int *)((int)param_2 + -1);
      } while (0 < (int)param_2);
      param_1._0_2_ = uVar3 + 0xc002;
      if ((short)(ushort)param_1 < 1) {
LAB_00459f55:
        param_1._0_2_ = (ushort)param_1 - 1;
        if ((short)(ushort)param_1 < 0) {
          iVar7 = -(int)(short)(ushort)param_1;
          param_1._0_2_ = (ushort)param_1 + (short)iVar7;
          do {
            if ((bStack_28 & 1) != 0) {
              iStack_18 = iStack_18 + 1;
            }
            FUN_00459846(&bStack_28);
            iVar7 = iVar7 + -1;
          } while (iVar7 != 0);
          if (iStack_18 != 0) {
            bStack_28 = bStack_28 | 1;
          }
        }
      }
      else {
        do {
          if ((bStack_1d & 0x80) != 0) break;
          FUN_00459818(&bStack_28);
          param_1._0_2_ = (ushort)param_1 - 1;
        } while (0 < (short)(ushort)param_1);
        if ((short)(ushort)param_1 < 1) goto LAB_00459f55;
      }
      if ((0x8000 < CONCAT11(uStack_27,bStack_28)) ||
         (sVar1 = CONCAT11(bStack_1d,uStack_1e), iVar2 = CONCAT22(uStack_20,uStack_22),
         iVar7 = CONCAT22(sStack_24,uStack_26),
         (CONCAT22(uStack_26,CONCAT11(uStack_27,bStack_28)) & 0x1ffff) == 0x18000)) {
        if (CONCAT22(sStack_24,uStack_26) == -1) {
          iVar7 = 0;
          if (CONCAT22(uStack_20,uStack_22) == -1) {
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
            iVar2 = CONCAT22(uStack_20,uStack_22) + 1;
          }
        }
        else {
          iVar7 = CONCAT22(sStack_24,uStack_26) + 1;
          sVar1 = CONCAT11(bStack_1d,uStack_1e);
          iVar2 = CONCAT22(uStack_20,uStack_22);
        }
      }
      sStack_24 = (short)((uint)iVar7 >> 0x10);
      uStack_26 = (undefined2)iVar7;
      uStack_20 = (undefined2)((uint)iVar2 >> 0x10);
      uStack_22 = (undefined2)iVar2;
      bStack_1d = (byte)((ushort)sVar1 >> 8);
      uStack_1e = (undefined)sVar1;
      if (0x7ffe < (ushort)param_1) goto LAB_00459ffe;
      uVar6 = (ushort)param_1 | uVar9;
      *(undefined2 *)piVar4 = uStack_26;
      *(uint *)((int)piVar4 + 2) = CONCAT22(uStack_22,sStack_24);
      *(uint *)((int)piVar4 + 6) = CONCAT13(bStack_1d,CONCAT12(uStack_1e,uStack_20));
    }
    *(ushort *)((int)piVar4 + 10) = uVar6;
  }
  else {
LAB_00459ffe:
    piVar4[1] = 0;
    *piVar4 = 0;
    piVar4[2] = (-(uint)(uVar9 != 0) & 0x80000000) + 0x7fff8000;
  }
  return;
}



void FUN_0045a01e(undefined2 *param_1,uint param_2,int param_3)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  undefined4 *puVar4;
  undefined2 uStack_10;
  undefined4 uStack_e;
  undefined2 uStack_a;
  undefined4 uStack_8;
  
  iVar3 = 0x46dfb8;
  if (param_2 != 0) {
    if ((int)param_2 < 0) {
      param_2 = -param_2;
      iVar3 = 0x46e118;
    }
    if (param_3 == 0) {
      *param_1 = 0;
    }
    while (param_2 != 0) {
      iVar3 = iVar3 + 0x54;
      uVar1 = (int)param_2 >> 3;
      uVar2 = param_2 & 7;
      param_2 = uVar1;
      if (uVar2 != 0) {
        puVar4 = (undefined4 *)(iVar3 + uVar2 * 0xc);
        if (0x7fff < *(ushort *)(iVar3 + uVar2 * 0xc)) {
          uStack_10 = (undefined2)*puVar4;
          uStack_e._0_2_ = (undefined2)((uint)*puVar4 >> 0x10);
          uStack_e._2_2_ = (undefined2)puVar4[1];
          uStack_a = (undefined2)((uint)puVar4[1] >> 0x10);
          uStack_8 = puVar4[2];
          uStack_e = CONCAT22(uStack_e._2_2_,(undefined2)uStack_e) + -1;
          puVar4 = (undefined4 *)&uStack_10;
        }
        FUN_00459dfe(param_1,puVar4);
      }
    }
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_0045a09a(int param_1)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  int *piVar4;
  
  if (((_DAT_004778e4 != 0) &&
      ((_DAT_00475d34 != (int *)0x0 ||
       (((_DAT_00475d3c != 0 && (iVar1 = FUN_0045a81a(), iVar1 == 0)) &&
        (_DAT_00475d34 != (int *)0x0)))))) && (piVar4 = _DAT_00475d34, param_1 != 0)) {
    uVar2 = FUN_00452b30(param_1);
    for (; *piVar4 != 0; piVar4 = piVar4 + 1) {
      uVar3 = FUN_00452b30(*piVar4);
      if (((uVar2 < uVar3) && (*(char *)(*piVar4 + uVar2) == '=')) &&
         (iVar1 = FUN_0045a7db(*piVar4,param_1,uVar2), iVar1 == 0)) {
        return *piVar4 + 1 + uVar2;
      }
    }
  }
  return 0;
}



int FUN_0045a117(undefined4 param_1,int param_2)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  int *piVar5;
  undefined4 *puVar6;
  int iVar7;
  undefined auStack_1008 [4064];
  undefined4 uStack_28;
  undefined4 uStack_24;
  undefined4 uStack_20;
  undefined *puStack_1c;
  undefined *puStack_18;
  int iStack_14;
  
  FUN_0044c080();
  iVar7 = 0;
  iStack_14 = 0;
  puStack_18 = (undefined *)param_1;
  puStack_1c = (undefined *)0x45a133;
  iVar1 = FUN_004567b1();
  if (iVar1 != -1) {
    iStack_14 = 0;
    puStack_18 = (undefined *)param_1;
    puStack_1c = (undefined *)0x45a14f;
    iVar2 = FUN_004567b1();
    if (iVar2 != -1) {
      iVar2 = param_2 - iVar2;
      if (iVar2 < 1) {
        if (iVar2 < 0) {
          iStack_14 = 0;
          puStack_18 = (undefined *)param_2;
          puStack_1c = (undefined *)param_1;
          uStack_20 = 0x45a1e8;
          FUN_004567b1();
          uStack_20 = param_1;
          uStack_24 = 0x45a1f0;
          iStack_14 = FUN_0045796c();
          puStack_18 = (undefined *)0x45a1fa;
          iVar7 = SetEndOfFile();
          iVar7 = (iVar7 != 0) - 1;
          if (iVar7 == -1) {
            iStack_14 = 0x45a20c;
            puVar6 = (undefined4 *)FUN_00451e44();
            *puVar6 = 0xd;
            iStack_14 = 0x45a218;
            uVar3 = GetLastError();
            iStack_14 = 0x45a21f;
            puVar6 = (undefined4 *)FUN_00451e4d();
            *puVar6 = uVar3;
          }
        }
      }
      else {
        puStack_1c = auStack_1008;
        iStack_14 = 0x1000;
        puStack_18 = (undefined *)0x0;
        uStack_20 = 0x45a177;
        FUN_004538c0();
        uStack_20 = 0x8000;
        uStack_24 = param_1;
        uStack_28 = 0x45a184;
        uVar3 = FUN_0045a888();
        do {
          iStack_14 = 0x1000;
          if (iVar2 < 0x1000) {
            iStack_14 = iVar2;
          }
          puStack_18 = auStack_1008;
          puStack_1c = (undefined *)param_1;
          uStack_20 = 0x45a1a2;
          iVar4 = FUN_00456889();
          if (iVar4 == -1) {
            iStack_14 = 0x45a1b7;
            piVar5 = (int *)FUN_00451e4d();
            if (*piVar5 == 5) {
              iStack_14 = 0x45a1c1;
              puVar6 = (undefined4 *)FUN_00451e44();
              *puVar6 = 0xd;
            }
            iVar7 = -1;
            break;
          }
          iVar2 = iVar2 - iVar4;
        } while (0 < iVar2);
        puStack_18 = (undefined *)param_1;
        puStack_1c = (undefined *)0x45a1d5;
        iStack_14 = uVar3;
        FUN_0045a888();
      }
      puStack_18 = (undefined *)iVar1;
      iStack_14 = 0;
      puStack_1c = (undefined *)param_1;
      uStack_20 = 0x45a22e;
      FUN_004567b1();
      return iVar7;
    }
  }
  return -1;
}



void FUN_0045a23c(uint *param_1,uint *param_2,uint param_3,uint param_4,undefined8 *param_5,
                 undefined8 *param_6)

{
  uint *puVar1;
  undefined8 *puVar2;
  byte bVar3;
  uint uVar4;
  
  uVar4 = param_3;
  puVar1 = param_2;
  param_1[1] = 0;
  param_1[2] = 0;
  param_1[3] = 0;
  if ((param_3 & 0x10) != 0) {
    param_3 = 0xc000008f;
    param_1[1] = param_1[1] | 1;
  }
  if ((uVar4 & 2) != 0) {
    param_3 = 0xc0000093;
    param_1[1] = param_1[1] | 2;
  }
  if ((uVar4 & 1) != 0) {
    param_3 = 0xc0000091;
    param_1[1] = param_1[1] | 4;
  }
  if ((uVar4 & 4) != 0) {
    param_3 = 0xc000008e;
    param_1[1] = param_1[1] | 8;
  }
  if ((uVar4 & 8) != 0) {
    param_3 = 0xc0000090;
    param_1[1] = param_1[1] | 0x10;
  }
  param_1[2] = (~*param_2 & 1) << 4 | param_1[2] & 0xffffffef;
  param_1[2] = (~*param_2 & 4) << 1 | param_1[2] & 0xfffffff7;
  param_1[2] = ~*param_2 >> 1 & 4 | param_1[2] & 0xfffffffb;
  param_1[2] = ~*param_2 >> 3 & 2 | param_1[2] & 0xfffffffd;
  param_1[2] = ~*param_2 >> 5 & 1 | param_1[2] & 0xfffffffe;
  bVar3 = FUN_0045a72e();
  puVar2 = param_6;
  if ((bVar3 & 1) != 0) {
    param_1[3] = param_1[3] | 0x10;
  }
  if ((bVar3 & 4) != 0) {
    param_1[3] = param_1[3] | 8;
  }
  if ((bVar3 & 8) != 0) {
    param_1[3] = param_1[3] | 4;
  }
  if ((bVar3 & 0x10) != 0) {
    param_1[3] = param_1[3] | 2;
  }
  if ((bVar3 & 0x20) != 0) {
    param_1[3] = param_1[3] | 1;
  }
  uVar4 = *puVar1 & 0xc00;
  if (uVar4 == 0) {
    *param_1 = *param_1 & 0xfffffffc;
  }
  else {
    if (uVar4 == 0x400) {
      uVar4 = *param_1 & 0xfffffffd | 1;
    }
    else {
      if (uVar4 != 0x800) {
        if (uVar4 == 0xc00) {
          *param_1 = *param_1 | 3;
        }
        goto LAB_0045a3b1;
      }
      uVar4 = *param_1 & 0xfffffffe | 2;
    }
    *param_1 = uVar4;
  }
LAB_0045a3b1:
  uVar4 = *puVar1 & 0x300;
  if (uVar4 == 0) {
    uVar4 = *param_1 & 0xffffffeb | 8;
LAB_0045a3e7:
    *param_1 = uVar4;
  }
  else {
    if (uVar4 == 0x200) {
      uVar4 = *param_1 & 0xffffffe7 | 4;
      goto LAB_0045a3e7;
    }
    if (uVar4 == 0x300) {
      *param_1 = *param_1 & 0xffffffe3;
    }
  }
  *param_1 = (param_4 & 0xfff) << 5 | *param_1 & 0xfffe001f;
  param_1[8] = param_1[8] | 1;
  param_1[8] = param_1[8] & 0xffffffe3 | 2;
  *(undefined8 *)(param_1 + 4) = *param_5;
  param_1[0x14] = param_1[0x14] | 1;
  param_1[0x14] = param_1[0x14] & 0xffffffe3 | 2;
  *(undefined8 *)(param_1 + 0x10) = *param_6;
  FUN_0045a73c();
  RaiseException(param_3,0,1,&param_1);
  if ((*(byte *)(param_1 + 2) & 0x10) != 0) {
    *puVar1 = *puVar1 & 0xfffffffe;
  }
  if ((*(byte *)(param_1 + 2) & 8) != 0) {
    *puVar1 = *puVar1 & 0xfffffffb;
  }
  if ((*(byte *)(param_1 + 2) & 4) != 0) {
    *puVar1 = *puVar1 & 0xfffffff7;
  }
  if ((*(byte *)(param_1 + 2) & 2) != 0) {
    *puVar1 = *puVar1 & 0xffffffef;
  }
  if ((*(byte *)(param_1 + 2) & 1) != 0) {
    *puVar1 = *puVar1 & 0xffffffdf;
  }
  uVar4 = *param_1 & 3;
  if (uVar4 == 0) {
    *puVar1 = *puVar1 & 0xfffff3ff;
  }
  else {
    if (uVar4 == 1) {
      uVar4 = *puVar1 & 0xfffff7ff | 0x400;
    }
    else {
      if (uVar4 != 2) {
        if (uVar4 == 3) {
          *(byte *)((int)puVar1 + 1) = *(byte *)((int)puVar1 + 1) | 0xc;
        }
        goto LAB_0045a4bc;
      }
      uVar4 = *puVar1 & 0xfffffbff | 0x800;
    }
    *puVar1 = uVar4;
  }
LAB_0045a4bc:
  uVar4 = *param_1 >> 2 & 7;
  if (uVar4 == 0) {
    uVar4 = *puVar1 & 0xfffff3ff | 0x300;
  }
  else {
    if (uVar4 != 1) {
      if (uVar4 == 2) {
        *puVar1 = *puVar1 & 0xfffff3ff;
      }
      goto LAB_0045a4e5;
    }
    uVar4 = *puVar1 & 0xfffff3ff | 0x200;
  }
  *puVar1 = uVar4;
LAB_0045a4e5:
  *puVar2 = *(undefined8 *)(param_1 + 0x10);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

bool FUN_0045a4ef(uint param_1,double *param_2,uint param_3)

{
  double dVar1;
  bool bVar2;
  uint uVar3;
  bool bVar4;
  float10 fVar5;
  undefined8 uStack_10;
  int iStack_8;
  
  uVar3 = param_1 & 0x1f;
  bVar2 = true;
  if (((param_1 & 8) != 0) && ((param_3 & 1) != 0)) {
    FUN_0045a76e(1);
    uVar3 = param_1 & 0x17;
    goto LAB_0045a6e4;
  }
  if (((param_1 & 4) != 0) && ((param_3 & 4) != 0)) {
    FUN_0045a76e(4);
    uVar3 = param_1 & 0x1b;
    goto LAB_0045a6e4;
  }
  if (((param_1 & 1) == 0) || ((param_3 & 8) == 0)) {
    if (((param_1 & 2) != 0) && ((param_3 & 0x10) != 0)) {
      bVar4 = (param_1 & 0x10) != 0;
      if (*param_2 != 0.0) {
        fVar5 = (float10)FUN_0045936e(*param_2,&iStack_8);
        iStack_8 = iStack_8 + -0x600;
        if (iStack_8 < -0x432) {
          uStack_10 = 0.0;
          bVar4 = bVar2;
        }
        else {
          uStack_10 = (double)(ulonglong)
                              (SUB87((double)fVar5,0) & 0xfffffffffffff | 0x10000000000000);
          if (iStack_8 < -0x3fd) {
            iStack_8 = -0x3fd - iStack_8;
            do {
              if ((((ulonglong)uStack_10 & 1) != 0) && (!bVar4)) {
                bVar4 = bVar2;
              }
              uVar3 = (uint)uStack_10 >> 1;
              if (((ulonglong)uStack_10 & 0x100000000) != 0) {
                uStack_10._3_1_ = (byte)((ulonglong)uStack_10 >> 0x18) >> 1;
                uStack_10._0_3_ = (undefined3)uVar3;
                uStack_10._0_4_ = CONCAT13(uStack_10._3_1_,(undefined3)uStack_10) | 0x80000000;
                uVar3 = (uint)uStack_10;
              }
              uStack_10._0_4_ = uVar3;
              uStack_10 = (double)CONCAT44(uStack_10._4_4_ >> 1,(uint)uStack_10);
              iStack_8 = iStack_8 + -1;
            } while (iStack_8 != 0);
          }
          if ((double)fVar5 < 0.0) {
            uStack_10 = -uStack_10;
          }
        }
        *param_2 = uStack_10;
        bVar2 = bVar4;
      }
      if (bVar2) {
        FUN_0045a76e(0x10);
      }
      uVar3 = param_1 & 0x1d;
    }
    goto LAB_0045a6e4;
  }
  FUN_0045a76e(8);
  uVar3 = param_3 & 0xc00;
  dVar1 = _DAT_0046def0;
  if (uVar3 == 0) {
    if (*param_2 <= 0.0) {
      dVar1 = -_DAT_0046def0;
    }
LAB_0045a604:
    *param_2 = dVar1;
  }
  else {
    if (uVar3 == 0x400) {
      dVar1 = _DAT_0046df00;
      if (*param_2 <= 0.0) {
        dVar1 = -_DAT_0046def0;
      }
      goto LAB_0045a604;
    }
    if (uVar3 == 0x800) {
      if (*param_2 <= 0.0) {
        dVar1 = -_DAT_0046df00;
      }
      goto LAB_0045a604;
    }
    if (uVar3 == 0xc00) {
      dVar1 = _DAT_0046df00;
      if (*param_2 <= 0.0) {
        dVar1 = -_DAT_0046df00;
      }
      goto LAB_0045a604;
    }
  }
  uVar3 = param_1 & 0x1e;
LAB_0045a6e4:
  if (((param_1 & 0x10) != 0) && ((param_3 & 0x20) != 0)) {
    FUN_0045a76e(0x20);
    uVar3 = uVar3 & 0xffffffef;
  }
  return uVar3 == 0;
}



void FUN_0045a706(int param_1)

{
  undefined4 *puVar1;
  
  if (param_1 == 1) {
    puVar1 = (undefined4 *)FUN_00451e44();
    *puVar1 = 0x21;
  }
  else if ((1 < param_1) && (param_1 < 4)) {
    puVar1 = (undefined4 *)FUN_00451e44();
    *puVar1 = 0x22;
    return;
  }
  return;
}



int FUN_0045a72e(void)

{
  short in_FPUStatusWord;
  
  return (int)in_FPUStatusWord;
}



int FUN_0045a73c(void)

{
  short in_FPUStatusWord;
  
  return (int)in_FPUStatusWord;
}



int FUN_0045a74b(void)

{
  short in_FPUControlWord;
  
  return (int)in_FPUControlWord;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0045a76e(void)

{
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_0045a7c4(undefined4 param_1,int param_2)

{
  int iVar1;
  undefined4 unaff_retaddr;
  
  FUN_0045012d(10);
  FUN_004595da(0x16);
  FUN_0044ec32(3);
  if (param_2 == 0) {
    return 0;
  }
  iVar1 = FUN_0045a8e9(_DAT_004777a4,1,unaff_retaddr,param_2,param_1,param_2,_DAT_00477578);
  if (iVar1 == 0) {
    return 0x7fffffff;
  }
  return iVar1 + -2;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_0045a7db(undefined4 param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  
  if (param_3 == 0) {
    return 0;
  }
  iVar1 = FUN_0045a8e9(_DAT_004777a4,1,param_1,param_3,param_2,param_3,_DAT_00477578);
  if (iVar1 == 0) {
    return 0x7fffffff;
  }
  return iVar1 + -2;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0045a81a(void)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  
  iVar1 = *_DAT_00475d3c;
  piVar3 = _DAT_00475d3c;
  while( true ) {
    if (iVar1 == 0) {
      return 0;
    }
    iVar1 = WideCharToMultiByte(1,0,iVar1,0xffffffff,0,0,0,0);
    if (((iVar1 == 0) || (iVar2 = FUN_0044c5a2(iVar1), iVar2 == 0)) ||
       (iVar1 = WideCharToMultiByte(1,0,*piVar3,0xffffffff,iVar2,iVar1,0,0), iVar1 == 0)) break;
    FUN_0045ab66(iVar2,0);
    iVar1 = piVar3[1];
    piVar3 = piVar3 + 1;
  }
  return 0xffffffff;
}



int FUN_0045a888(uint param_1,int param_2)

{
  byte bVar1;
  undefined4 *puVar2;
  byte bVar3;
  
  bVar1 = *(byte *)(*(int *)(&DAT_004777e0 + ((int)param_1 >> 5) * 4) + 4 + (param_1 & 0x1f) * 0x24)
  ;
  if (param_2 == 0x8000) {
    bVar3 = bVar1 & 0x7f;
  }
  else {
    if (param_2 != 0x4000) {
      puVar2 = (undefined4 *)FUN_00451e44();
      *puVar2 = 0x16;
      return -1;
    }
    bVar3 = bVar1 | 0x80;
  }
  *(byte *)(*(int *)(&DAT_004777e0 + ((int)param_1 >> 5) * 4) + 4 + (param_1 & 0x1f) * 0x24) = bVar3
  ;
  return (-(uint)((bVar1 & 0x80) != 0) & 0xffffc000) + 0x8000;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4
FUN_0045a8e9(int param_1,undefined4 param_2,byte *param_3,int param_4,byte *param_5,int param_6,
            int param_7)

{
  undefined *puVar1;
  int iVar2;
  undefined4 uVar3;
  byte *pbVar4;
  int iVar5;
  int iStack_98;
  undefined4 uStack_94;
  byte *pbStack_90;
  int iStack_8c;
  undefined4 uStack_88;
  undefined4 uStack_84;
  int iStack_80;
  undefined4 uStack_7c;
  byte *pbStack_78;
  int iStack_74;
  int *piStack_70;
  int iStack_6c;
  int iStack_68;
  undefined4 uStack_64;
  byte *pbStack_60;
  int iStack_5c;
  byte *pbStack_58;
  uint *puStack_54;
  uint uStack_40;
  byte abStack_3a [14];
  int *piStack_2c;
  int *piStack_28;
  int iStack_24;
  int iStack_20;
  int *piStack_1c;
  void *pvStack_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 uStack_8;
  
  uStack_8 = 0xffffffff;
  puStack_c = &UNK_00460040;
  puStack_10 = &UNK_0045001c;
  pvStack_14 = ExceptionList;
  piStack_1c = (int *)&stack0xffffffb0;
  ExceptionList = &pvStack_14;
  puVar1 = &stack0xffffffb0;
  if (_DAT_00476068 == 0) {
    puStack_54 = (uint *)0x1;
    pbStack_58 = &UNK_0045f2b8;
    iStack_5c = 1;
    pbStack_60 = &UNK_0045f2b8;
    uStack_64 = 0;
    iStack_68 = 0;
    iStack_6c = 0x45a92d;
    ExceptionList = &pvStack_14;
    iVar2 = CompareStringW();
    if (iVar2 == 0) {
      puStack_54 = (uint *)0x1;
      pbStack_58 = (byte *)0x4747d4;
      iStack_5c = 1;
      pbStack_60 = (undefined *)0x4747d4;
      uStack_64 = 0;
      iStack_68 = 0;
      iStack_6c = 0x45a94a;
      iVar2 = CompareStringA();
      if (iVar2 == 0) {
        ExceptionList = pvStack_14;
        return 0;
      }
      _DAT_00476068 = 2;
      puVar1 = (undefined *)piStack_1c;
    }
    else {
      _DAT_00476068 = 1;
      puVar1 = (undefined *)piStack_1c;
    }
  }
  piStack_1c = (int *)puVar1;
  if (0 < param_4) {
    puStack_54 = (uint *)param_4;
    pbStack_58 = param_3;
    iStack_5c = 0x45a96c;
    param_4 = FUN_0044f3f4();
  }
  if (0 < param_6) {
    puStack_54 = (uint *)param_6;
    pbStack_58 = param_5;
    iStack_5c = 0x45a983;
    param_6 = FUN_0044f3f4();
  }
  if (_DAT_00476068 == 2) {
    puStack_54 = (uint *)param_6;
    pbStack_58 = param_5;
    pbStack_60 = param_3;
    uStack_64 = param_2;
    iStack_68 = param_1;
    iStack_6c = 0x45a9a8;
    iStack_5c = param_4;
    uVar3 = CompareStringA();
    ExceptionList = pvStack_14;
    return uVar3;
  }
  if (_DAT_00476068 == 1) {
    if (param_7 == 0) {
      param_7 = _DAT_00475dd0;
    }
    if ((param_4 == 0) || (param_6 == 0)) {
      if (param_4 == param_6) {
        ExceptionList = pvStack_14;
        return 2;
      }
      if (1 < param_6) {
        ExceptionList = pvStack_14;
        return 1;
      }
      if (1 < param_4) {
        ExceptionList = pvStack_14;
        return 3;
      }
      puStack_54 = &uStack_40;
      pbStack_58 = (byte *)param_7;
      iStack_5c = 0x45a9f9;
      iVar2 = GetCPInfo();
      if (iVar2 == 0) {
        ExceptionList = pvStack_14;
        return 0;
      }
      if (0 < param_4) {
        if (uStack_40 < 2) {
          ExceptionList = pvStack_14;
          return 3;
        }
        pbVar4 = abStack_3a;
        while( true ) {
          if (abStack_3a[0] == 0) {
            ExceptionList = pvStack_14;
            return 3;
          }
          if (pbVar4[1] == 0) break;
          if ((*pbVar4 <= *param_3) && (*param_3 <= pbVar4[1])) {
            ExceptionList = pvStack_14;
            return 2;
          }
          pbVar4 = pbVar4 + 2;
          abStack_3a[0] = *pbVar4;
        }
        ExceptionList = pvStack_14;
        return 3;
      }
      if (0 < param_6) {
        if (uStack_40 < 2) {
          ExceptionList = pvStack_14;
          return 1;
        }
        pbVar4 = abStack_3a;
        while( true ) {
          if (abStack_3a[0] == 0) {
            ExceptionList = pvStack_14;
            return 1;
          }
          if (pbVar4[1] == 0) break;
          if ((*pbVar4 <= *param_5) && (*param_5 <= pbVar4[1])) {
            ExceptionList = pvStack_14;
            return 2;
          }
          pbVar4 = pbVar4 + 2;
          abStack_3a[0] = *pbVar4;
        }
        ExceptionList = pvStack_14;
        return 1;
      }
    }
    puStack_54 = (uint *)0x0;
    pbStack_58 = (byte *)0x0;
    pbStack_60 = param_3;
    uStack_64 = 9;
    iStack_68 = param_7;
    iStack_6c = 0x45aa78;
    iStack_5c = param_4;
    iStack_20 = MultiByteToWideChar();
    if (iStack_20 != 0) {
      uStack_8 = 0;
      iStack_6c = 0x45aa92;
      piStack_70 = &iStack_68;
      piStack_28 = &iStack_68;
      FUN_0044c080();
      uStack_8 = 0xffffffff;
      if (&stack0x00000000 != (undefined *)0x68) {
        iStack_6c = iStack_20;
        pbStack_78 = param_3;
        uStack_7c = 1;
        iStack_80 = param_7;
        uStack_84 = 0x45aad5;
        iStack_74 = param_4;
        piStack_1c = &iStack_68;
        iVar2 = MultiByteToWideChar();
        if (iVar2 != 0) {
          uStack_84 = 0;
          uStack_88 = 0;
          iStack_8c = param_6;
          pbStack_90 = param_5;
          uStack_94 = 9;
          iStack_98 = param_7;
          iVar2 = MultiByteToWideChar();
          if (iVar2 != 0) {
            uStack_8 = 1;
            piStack_2c = &iStack_98;
            iStack_24 = iVar2;
            FUN_0044c080();
            uStack_8 = 0xffffffff;
            if ((&stack0x00000000 != (undefined *)0x98) &&
               (piStack_1c = &iStack_98,
               iVar5 = MultiByteToWideChar(param_7,1,param_5,param_6,&iStack_98,iVar2), iVar5 != 0))
            {
              uVar3 = CompareStringW(param_1,param_2,piStack_28,iStack_20,&iStack_98,iVar2);
              ExceptionList = pvStack_14;
              return uVar3;
            }
          }
        }
      }
    }
  }
  ExceptionList = pvStack_14;
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0045ab66(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  undefined *puVar4;
  int *piVar5;
  bool bVar6;
  
  if (param_1 == 0) {
    return 0xffffffff;
  }
  iVar1 = FUN_0044df4b(param_1,0x3d);
  if (iVar1 == 0) {
    return 0xffffffff;
  }
  if (param_1 == iVar1) {
    return 0xffffffff;
  }
  bVar6 = *(char *)(iVar1 + 1) == '\0';
  if (_DAT_00475d34 == _DAT_00475d38) {
    _DAT_00475d34 = (int *)FUN_0045ad45(_DAT_00475d34);
  }
  if (_DAT_00475d34 == (int *)0x0) {
    if ((param_2 == 0) || (_DAT_00475d3c == (undefined4 *)0x0)) {
      if (bVar6) {
        return 0;
      }
      _DAT_00475d34 = (int *)FUN_0044c5a2(4);
      if (_DAT_00475d34 == (int *)0x0) {
        return 0xffffffff;
      }
      *_DAT_00475d34 = 0;
      if (_DAT_00475d3c == (undefined4 *)0x0) {
        _DAT_00475d3c = (undefined4 *)FUN_0044c5a2(4);
        if (_DAT_00475d3c == (undefined4 *)0x0) {
          return 0xffffffff;
        }
        *_DAT_00475d3c = 0;
      }
    }
    else {
      iVar2 = FUN_0045a81a();
      if (iVar2 != 0) {
        return 0xffffffff;
      }
    }
  }
  piVar3 = _DAT_00475d34;
  iVar2 = FUN_0045aced(param_1,iVar1 - param_1);
  if ((iVar2 < 0) || (*piVar3 == 0)) {
    if (bVar6) {
      return 0;
    }
    if (iVar2 < 0) {
      iVar2 = -iVar2;
    }
    piVar3 = (int *)FUN_0044ed14(piVar3,iVar2 * 4 + 8);
    if (piVar3 == (int *)0x0) {
      return 0xffffffff;
    }
    piVar3[iVar2] = param_1;
    piVar3[iVar2 + 1] = 0;
  }
  else {
    if (!bVar6) {
      piVar3[iVar2] = param_1;
      goto LAB_0045ac9a;
    }
    piVar5 = piVar3 + iVar2;
    FUN_0044c4b9(piVar3[iVar2]);
    for (; *piVar5 != 0; piVar5 = piVar5 + 1) {
      iVar2 = iVar2 + 1;
      *piVar5 = piVar5[1];
    }
    piVar3 = (int *)FUN_0044ed14(piVar3,iVar2 << 2);
    if (piVar3 == (int *)0x0) goto LAB_0045ac9a;
  }
  _DAT_00475d34 = piVar3;
LAB_0045ac9a:
  if (param_2 != 0) {
    iVar2 = FUN_00452b30(param_1);
    iVar2 = FUN_0044c5a2(iVar2 + 2);
    if (iVar2 != 0) {
      FUN_00452bf0(iVar2,param_1);
      puVar4 = (undefined *)((iVar2 - param_1) + iVar1);
      *puVar4 = 0;
      SetEnvironmentVariableA(iVar2,~-(uint)bVar6 & (uint)(puVar4 + 1));
      FUN_0044c4b9(iVar2);
    }
  }
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_0045aced(undefined4 param_1,int param_2)

{
  int iVar1;
  int *piVar2;
  
  iVar1 = *_DAT_00475d34;
  piVar2 = _DAT_00475d34;
  while( true ) {
    if (iVar1 == 0) {
      return -((int)piVar2 - (int)_DAT_00475d34 >> 2);
    }
    iVar1 = FUN_0045a7db(param_1,iVar1,param_2);
    if ((iVar1 == 0) &&
       ((*(char *)(*piVar2 + param_2) == '=' || (*(char *)(*piVar2 + param_2) == '\0')))) break;
    iVar1 = piVar2[1];
    piVar2 = piVar2 + 1;
  }
  return (int)piVar2 - (int)_DAT_00475d34 >> 2;
}



undefined4 * FUN_0045ad45(int *param_1)

{
  int iVar1;
  int *piVar2;
  undefined4 *puVar3;
  undefined4 uVar4;
  int iVar5;
  undefined4 *puVar6;
  
  iVar5 = 0;
  if (param_1 != (int *)0x0) {
    iVar1 = *param_1;
    piVar2 = param_1;
    while (iVar1 != 0) {
      piVar2 = piVar2 + 1;
      iVar5 = iVar5 + 1;
      iVar1 = *piVar2;
    }
    puVar3 = (undefined4 *)FUN_0044c5a2(iVar5 * 4 + 4);
    if (puVar3 == (undefined4 *)0x0) {
      FUN_0044c2ac(9);
    }
    iVar5 = *param_1;
    puVar6 = puVar3;
    while (iVar5 != 0) {
      param_1 = param_1 + 1;
      uVar4 = FUN_0044defa(iVar5);
      *puVar6 = uVar4;
      puVar6 = puVar6 + 1;
      iVar5 = *param_1;
    }
    *puVar6 = 0;
    return puVar3;
  }
  return (undefined4 *)0x0;
}



int * __thiscall FUN_0045adb0(int *param_1,undefined4 param_2)

{
  uint *puVar1;
  int iVar2;
  
  iVar2 = FUN_0045aef9();
  if (iVar2 != 0) {
    if (*(int *)((int)param_1 + *(int *)(*param_1 + 4) + 0x30) == 0) {
      iVar2 = FUN_0045ae2c((undefined)param_2);
      if (iVar2 == -1) {
        iVar2 = (**(code **)(**(int **)(*(int *)(*param_1 + 4) + 4 + (int)param_1) + 0x1c))
                          ((undefined)param_2);
        if (iVar2 == -1) {
          puVar1 = (uint *)(*(int *)(*param_1 + 4) + 8 + (int)param_1);
          *puVar1 = *puVar1 | 6;
        }
      }
    }
    else {
      param_2._3_1_ = 0;
      param_2._2_1_ = (undefined)param_2;
      FUN_0045b209(&DAT_0046e83c,(int)&param_2 + 2);
    }
    FUN_0045af6d();
  }
  return param_1;
}



uint __thiscall FUN_0045ae2c(int *param_1,uint param_2)

{
  if ((undefined *)param_1[7] < (undefined *)param_1[8]) {
    *(undefined *)param_1[7] = (undefined)param_2;
    param_1[7] = param_1[7] + 1;
    param_2 = param_2 & 0xff;
  }
  else {
    param_2 = (**(code **)(*param_1 + 0x1c))(param_2);
  }
  return param_2;
}



int * __thiscall FUN_0045ae4e(int *param_1,int param_2)

{
  uint uVar1;
  byte bVar2;
  int iVar3;
  undefined auStack_18 [12];
  ushort uStack_c;
  undefined uStack_a;
  undefined uStack_9;
  undefined2 uStack_8;
  undefined uStack_6;
  undefined uStack_5;
  
  uStack_c = uRam00464054;
  uStack_a = uRam00464056;
  uStack_9 = 0;
  uStack_8 = 0;
  uStack_6 = 0;
  uStack_5 = 0;
  iVar3 = FUN_0045aef9();
  if (iVar3 != 0) {
    if (param_2 != 0) {
      uVar1 = *(uint *)((int)param_1 + *(int *)(*param_1 + 4) + 0x24);
      if ((uVar1 & 0x60) == 0) {
        if ((uVar1 & 0x400) != 0) {
          uStack_8 = CONCAT11(uStack_8._1_1_,0x2b);
        }
      }
      else {
        if ((uVar1 & 0x40) == 0) {
          uStack_c = CONCAT11(0x6f,(undefined)uStack_c);
        }
        else {
          bVar2 = ~(byte)(uVar1 >> 4);
          uStack_c = CONCAT11(bVar2,(undefined)uStack_c) & 0x20ff | 0x5800;
          uStack_8 = CONCAT11(bVar2,(undefined)uStack_8) & 0x20ff | 0x5800;
        }
        if ((*(byte *)((int)param_1 + *(int *)(*param_1 + 4) + 0x24) & 0x80) != 0) {
          uStack_8 = CONCAT11(uStack_8._1_1_,0x30);
        }
      }
    }
    FUN_0044c3c3(auStack_18,&uStack_c,param_2);
    FUN_0045b209(&uStack_8,auStack_18);
    FUN_0045af6d();
  }
  return param_1;
}



undefined4 __fastcall FUN_0045aef9(int *param_1)

{
  int iVar1;
  uint uVar2;
  
  if (*(int *)((int)param_1 + *(int *)(*param_1 + 4) + 0x34) < 0) {
    FUN_0045b43f((int)param_1 + *(int *)(*param_1 + 4) + 0x38);
  }
  iVar1 = *(int *)(*param_1 + 4);
  uVar2 = *(uint *)(iVar1 + 8 + (int)param_1);
  if (uVar2 != 0) {
    *(uint *)((int)param_1 + iVar1 + 8) = uVar2 | 2;
    if (*(int *)((int)param_1 + *(int *)(*param_1 + 4) + 0x34) < 0) {
      FUN_0045b44a((int)param_1 + *(int *)(*param_1 + 4) + 0x38);
    }
    return 0;
  }
  if (*(int *)((int)param_1 + iVar1 + 0x20) != 0) {
    FUN_0045b046();
  }
  iVar1 = *(int *)(*(int *)(*param_1 + 4) + 4 + (int)param_1);
  if (*(int *)(iVar1 + 0x30) < 0) {
    FUN_0045b43f(iVar1 + 0x34);
  }
  return 1;
}



void __fastcall FUN_0045af6d(int *param_1)

{
  uint *puVar1;
  int iVar2;
  
  *(undefined4 *)(*(int *)(*param_1 + 4) + 0x30 + (int)param_1) = 0;
  if ((*(byte *)((int)param_1 + *(int *)(*param_1 + 4) + 0x25) & 0x20) != 0) {
    iVar2 = (**(code **)(**(int **)((int)param_1 + *(int *)(*param_1 + 4) + 4) + 4))();
    if (iVar2 == -1) {
      *(undefined4 *)(*(int *)(*param_1 + 4) + 8 + (int)param_1) = 6;
    }
  }
  if ((*(byte *)(*(int *)(*param_1 + 4) + 0x25 + (int)param_1) & 0x40) != 0) {
    iVar2 = FUN_00454553(0x46a9b0);
    if (iVar2 == -1) {
      puVar1 = (uint *)(*(int *)(*param_1 + 4) + 8 + (int)param_1);
      *puVar1 = *puVar1 | 2;
    }
    iVar2 = FUN_00454553(0x46a9d0);
    if (iVar2 == -1) {
      puVar1 = (uint *)(*(int *)(*param_1 + 4) + 8 + (int)param_1);
      *puVar1 = *puVar1 | 2;
    }
  }
  iVar2 = *(int *)(*(int *)(*param_1 + 4) + 4 + (int)param_1);
  if (*(int *)(iVar2 + 0x30) < 0) {
    FUN_0045b44a(iVar2 + 0x34);
  }
  if (*(int *)((int)param_1 + *(int *)(*param_1 + 4) + 0x34) < 0) {
    FUN_0045b44a((int)param_1 + *(int *)(*param_1 + 4) + 0x38);
  }
  return;
}



undefined4 __thiscall FUN_0045b01d(undefined4 param_1,undefined4 param_2)

{
  int iVar1;
  
  iVar1 = FUN_0045aef9();
  if (iVar1 != 0) {
    FUN_0045b209(&DAT_0046e83c,param_2);
    FUN_0045af6d();
  }
  return param_1;
}



int * __fastcall FUN_0045b046(int *param_1)

{
  uint *puVar1;
  int iVar2;
  
  if (*(int *)((int)param_1 + *(int *)(*param_1 + 4) + 0x34) < 0) {
    FUN_0045b43f((int)param_1 + *(int *)(*param_1 + 4) + 0x38);
  }
  iVar2 = *(int *)(*(int *)(*param_1 + 4) + 4 + (int)param_1);
  if (*(int *)(iVar2 + 0x30) < 0) {
    FUN_0045b43f(iVar2 + 0x34);
  }
  iVar2 = (**(code **)(**(int **)(*(int *)(*param_1 + 4) + 4 + (int)param_1) + 4))();
  if (iVar2 == -1) {
    puVar1 = (uint *)(*(int *)(*param_1 + 4) + 8 + (int)param_1);
    *puVar1 = *puVar1 | 2;
  }
  iVar2 = *(int *)(*(int *)(*param_1 + 4) + 4 + (int)param_1);
  if (*(int *)(iVar2 + 0x30) < 0) {
    FUN_0045b44a(iVar2 + 0x34);
  }
  if (*(int *)((int)param_1 + *(int *)(*param_1 + 4) + 0x34) < 0) {
    FUN_0045b44a((int)param_1 + *(int *)(*param_1 + 4) + 0x38);
  }
  return param_1;
}



int * FUN_0045b0f9(void)

{
  undefined4 uVar1;
  int *extraout_ECX;
  int unaff_EBP;
  
  FUN_0045bfcc();
  *(undefined4 *)(unaff_EBP + -0x10) = 0;
  *(int **)(unaff_EBP + -0x14) = extraout_ECX;
  if (*(int *)(unaff_EBP + 0xc) != 0) {
    *extraout_ECX = (int)&UNK_00460064;
    FUN_0045b455();
    *(undefined4 *)(unaff_EBP + -0x10) = 1;
    *(undefined4 *)(unaff_EBP + -4) = 0;
  }
  uVar1 = *(undefined4 *)(unaff_EBP + 8);
  *(undefined **)(*(int *)(*extraout_ECX + 4) + (int)extraout_ECX) = &UNK_00460060;
  FUN_0045b519(uVar1);
  ExceptionList = *(void **)(unaff_EBP + -0xc);
  extraout_ECX[1] = 0;
  return extraout_ECX;
}



int * __thiscall FUN_0045b209(int *param_1,undefined4 param_2,undefined4 param_3)

{
  uint *puVar1;
  uint uVar2;
  bool bVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iStack_8;
  
  iVar4 = FUN_00452b30(param_2);
  iVar5 = FUN_00452b30(param_3);
  uVar2 = *(uint *)(*(int *)(*param_1 + 4) + 0x30 + (int)param_1);
  if ((uint)(iVar5 + iVar4) < uVar2) {
    iStack_8 = (uVar2 - iVar5) - iVar4;
  }
  else {
    iStack_8 = 0;
  }
  if (((*(byte *)((int)param_1 + *(int *)(*param_1 + 4) + 0x24) & 10) == 0) &&
     (iVar6 = iStack_8 + -1, bVar3 = 0 < iStack_8, iVar7 = iStack_8, iStack_8 = iVar6, bVar3)) {
    do {
      iVar6 = FUN_0045ae2c(*(undefined *)((int)param_1 + *(int *)(*param_1 + 4) + 0x2c));
      if (iVar6 == -1) {
        puVar1 = (uint *)(*(int *)(*param_1 + 4) + 8 + (int)param_1);
        *puVar1 = *puVar1 | 6;
      }
      iVar7 = iVar7 + -1;
      iStack_8 = iStack_8 + -1;
    } while (iVar7 != 0);
  }
  if ((iVar4 != 0) &&
     (iVar6 = (**(code **)(**(int **)(*(int *)(*param_1 + 4) + 4 + (int)param_1) + 0x14))
                        (param_2,iVar4), iVar6 != iVar4)) {
    puVar1 = (uint *)(*(int *)(*param_1 + 4) + 8 + (int)param_1);
    *puVar1 = *puVar1 | 6;
  }
  if (((*(byte *)(*(int *)(*param_1 + 4) + 0x24 + (int)param_1) & 8) != 0) &&
     (iVar6 = iStack_8 + -1, bVar3 = 0 < iStack_8, iVar4 = iStack_8, iStack_8 = iVar6, bVar3)) {
    do {
      iVar6 = FUN_0045ae2c(*(undefined *)((int)param_1 + *(int *)(*param_1 + 4) + 0x2c));
      if (iVar6 == -1) {
        puVar1 = (uint *)(*(int *)(*param_1 + 4) + 8 + (int)param_1);
        *puVar1 = *puVar1 | 6;
      }
      iVar4 = iVar4 + -1;
      iStack_8 = iStack_8 + -1;
    } while (iVar4 != 0);
  }
  iVar4 = (**(code **)(**(int **)(*(int *)(*param_1 + 4) + 4 + (int)param_1) + 0x14))(param_3,iVar5)
  ;
  if (iVar4 != iVar5) {
    puVar1 = (uint *)(*(int *)(*param_1 + 4) + 8 + (int)param_1);
    *puVar1 = *puVar1 | 6;
  }
  if (((*(byte *)(*(int *)(*param_1 + 4) + 0x24 + (int)param_1) & 2) != 0) && (0 < iStack_8)) {
    do {
      iVar4 = FUN_0045ae2c(*(undefined *)((int)param_1 + *(int *)(*param_1 + 4) + 0x2c));
      if (iVar4 == -1) {
        puVar1 = (uint *)(*(int *)(*param_1 + 4) + 8 + (int)param_1);
        *puVar1 = *puVar1 | 6;
      }
      iStack_8 = iStack_8 + -1;
    } while (iStack_8 != 0);
  }
  return param_1;
}



void FUN_0045b429(undefined4 param_1)

{
  InitializeCriticalSection(param_1);
  return;
}



void FUN_0045b434(undefined4 param_1)

{
  DeleteCriticalSection(param_1);
  return;
}



void FUN_0045b43f(undefined4 param_1)

{
  EnterCriticalSection(param_1);
  return;
}



void FUN_0045b44a(undefined4 param_1)

{
  LeaveCriticalSection(param_1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 * __fastcall FUN_0045b455(undefined4 *param_1)

{
  int iVar1;
  
  param_1[0xd] = 0xffffffff;
  param_1[1] = 0;
  param_1[3] = 0;
  param_1[4] = 0;
  param_1[8] = 0;
  param_1[9] = 0;
  param_1[0xc] = 0;
  param_1[7] = 0;
  *param_1 = &UNK_0046008c;
  param_1[2] = 4;
  param_1[10] = 6;
  *(undefined *)(param_1 + 0xb) = 0x20;
  FUN_0045b429(param_1 + 0xe);
  iVar1 = _DAT_00476108;
  _DAT_00476108 = _DAT_00476108 + 1;
  if (iVar1 == 0) {
    FUN_0045b429(0x4760d0);
  }
  return param_1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __fastcall FUN_0045b4cf(undefined4 *param_1)

{
  param_1[0xd] = 0xffffffff;
  *param_1 = &UNK_0046008c;
  _DAT_00476108 = _DAT_00476108 + -1;
  if (_DAT_00476108 == 0) {
    FUN_0045b434(0x4760d0);
  }
  FUN_0045b434(param_1 + 0xe);
  if ((param_1[7] != 0) && ((undefined4 *)param_1[1] != (undefined4 *)0x0)) {
    (***(code ***)(undefined4 *)param_1[1])(1);
  }
  param_1[1] = 0;
  param_1[2] = 4;
  return;
}



void __thiscall FUN_0045b519(int param_1,int param_2)

{
  if ((*(int *)(param_1 + 0x1c) != 0) && (*(undefined4 **)(param_1 + 4) != (undefined4 *)0x0)) {
    (**(code **)**(undefined4 **)(param_1 + 4))(1);
  }
  *(int *)(param_1 + 4) = param_2;
  if (param_2 == 0) {
    *(uint *)(param_1 + 8) = *(uint *)(param_1 + 8) | 4;
  }
  else {
    *(uint *)(param_1 + 8) = *(uint *)(param_1 + 8) & 0xfffffffb;
  }
  return;
}



void FUN_0045b583(void)

{
  undefined4 *extraout_ECX;
  int unaff_EBP;
  
  FUN_0045bfcc();
  *(undefined4 **)(unaff_EBP + -0x10) = extraout_ECX;
  *extraout_ECX = &UNK_004600ac;
  *(undefined4 *)(unaff_EBP + -4) = 0;
  if ((int)extraout_ECX[0xc] < 0) {
    FUN_0045b43f(extraout_ECX + 0xd);
  }
  if (extraout_ECX[0x14] == 0) {
    FUN_0045b792();
  }
  else {
    FUN_0045b5da();
  }
  *(undefined4 *)(unaff_EBP + -4) = 0xffffffff;
  FUN_0045ba45();
  ExceptionList = *(void **)(unaff_EBP + -0xc);
  return;
}



int * __fastcall FUN_0045b5da(int *param_1)

{
  int iVar1;
  int iVar2;
  
  if (param_1[0x13] != -1) {
    if (param_1[0xc] < 0) {
      FUN_0045b43f(param_1 + 0xd);
    }
    iVar1 = (**(code **)(*param_1 + 4))();
    iVar2 = FUN_00454448(param_1[0x13]);
    if ((iVar2 != -1) && (iVar1 != -1)) {
      param_1[0x13] = -1;
      if (-1 < param_1[0xc]) {
        return param_1;
      }
      FUN_0045b44a(param_1 + 0xd);
      return param_1;
    }
    if (param_1[0xc] < 0) {
      FUN_0045b44a(param_1 + 0xd);
    }
  }
  return (int *)0x0;
}



int __fastcall FUN_0045b73e(int param_1)

{
  if (*(uint *)(param_1 + 0x28) < *(uint *)(param_1 + 0x2c)) {
    return *(uint *)(param_1 + 0x2c) - *(uint *)(param_1 + 0x28);
  }
  return 0;
}



undefined4 __fastcall FUN_0045b792(int param_1)

{
  byte bVar1;
  uint uVar2;
  int iVar3;
  char *pcVar4;
  int iVar5;
  
  if (*(int *)(param_1 + 0x4c) == -1) {
    return 0xffffffff;
  }
  if (*(int *)(param_1 + 8) == 0) {
    uVar2 = *(uint *)(param_1 + 0x18);
    if (*(uint *)(param_1 + 0x1c) < uVar2) {
      iVar5 = 0;
    }
    else {
      iVar5 = *(uint *)(param_1 + 0x1c) - uVar2;
    }
    if ((iVar5 != 0) && (iVar3 = FUN_00456824(*(int *)(param_1 + 0x4c),uVar2,iVar5), iVar3 != iVar5)
       ) {
      if (0 < iVar3) {
        if (*(int *)(param_1 + 0x20) != 0) {
          *(int *)(param_1 + 0x1c) = *(int *)(param_1 + 0x1c) - iVar3;
        }
        FUN_0044e2d0(*(int *)(param_1 + 0x18),iVar3 + *(int *)(param_1 + 0x18),iVar5 - iVar3);
      }
      return 0xffffffff;
    }
    *(undefined4 *)(param_1 + 0x18) = 0;
    *(undefined4 *)(param_1 + 0x1c) = 0;
    *(undefined4 *)(param_1 + 0x20) = 0;
    iVar5 = FUN_0045b73e();
    if (0 < iVar5) {
      uVar2 = *(uint *)(param_1 + 0x4c);
      bVar1 = *(byte *)(*(int *)(&DAT_004777e0 + ((int)uVar2 >> 5) * 4) + 4 + (uVar2 & 0x1f) * 0x24)
      ;
      if ((bVar1 & 0x80) != 0) {
        for (pcVar4 = *(char **)(param_1 + 0x28); pcVar4 < *(char **)(param_1 + 0x2c);
            pcVar4 = pcVar4 + 1) {
          if (*pcVar4 == '\n') {
            iVar5 = iVar5 + 1;
          }
        }
        if ((bVar1 & 2) != 0) {
          iVar5 = iVar5 + 1;
        }
      }
      iVar5 = FUN_0045674c(uVar2,-iVar5,1);
      if (iVar5 == -1) {
        return 0xffffffff;
      }
    }
    *(undefined4 *)(param_1 + 0xc) = 0xffffffff;
    *(undefined4 *)(param_1 + 0x24) = 0;
    *(undefined4 *)(param_1 + 0x28) = 0;
    *(undefined4 *)(param_1 + 0x2c) = 0;
  }
  return 0;
}



undefined4 * __fastcall FUN_0045b9ea(undefined4 *param_1)

{
  param_1[3] = 0xffffffff;
  param_1[0xc] = 0xffffffff;
  param_1[1] = 0;
  param_1[2] = 0;
  param_1[4] = 0;
  param_1[5] = 0;
  param_1[6] = 0;
  param_1[7] = 0;
  param_1[8] = 0;
  param_1[9] = 0;
  param_1[10] = 0;
  param_1[0xb] = 0;
  *param_1 = &UNK_004600dc;
  FUN_0045b429(param_1 + 0xd);
  return param_1;
}



void __fastcall FUN_0045ba45(undefined4 *param_1)

{
  *param_1 = &UNK_004600dc;
  FUN_0045b434(param_1 + 0xd);
  FUN_0045bb96();
  if ((param_1[1] != 0) && (param_1[4] != 0)) {
    FUN_0044bb7e(param_1[4]);
  }
  return;
}



undefined4 __fastcall FUN_0045bb96(int param_1)

{
  if ((*(uint *)(param_1 + 0x2c) <= *(uint *)(param_1 + 0x28)) &&
     (*(uint *)(param_1 + 0x1c) < *(uint *)(param_1 + 0x18) ||
      *(uint *)(param_1 + 0x1c) == *(uint *)(param_1 + 0x18))) {
    return 0;
  }
  return 0xffffffff;
}



int __fastcall FUN_0045bbad(int *param_1)

{
  int iVar1;
  
  if ((param_1[2] == 0) && (param_1[4] == 0)) {
    iVar1 = (**(code **)(*param_1 + 0x28))();
    return (-(uint)(iVar1 != -1) & 2) - 1;
  }
  return 0;
}



void __thiscall FUN_0045bbf8(int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  if ((*(int *)(param_1 + 4) != 0) && (*(int *)(param_1 + 0x10) != 0)) {
    FUN_0044bb7e(*(int *)(param_1 + 0x10));
  }
  *(undefined4 *)(param_1 + 0x10) = param_2;
  *(undefined4 *)(param_1 + 4) = param_4;
  *(undefined4 *)(param_1 + 0x14) = param_3;
  return;
}



int __thiscall FUN_0045bc9c(int *param_1,char param_2)

{
  char *pcVar1;
  int iVar2;
  
  if ((uint)param_1[9] < (uint)param_1[10]) {
    pcVar1 = (char *)(param_1[10] - 1);
    param_1[10] = (int)pcVar1;
    *pcVar1 = param_2;
    iVar2 = (int)param_2;
  }
  else {
    iVar2 = (**(code **)(*param_1 + 0x24))((int)param_2);
  }
  return iVar2;
}



void VerLanguageNameA(void)

{
                    // WARNING: Could not recover jumptable at 0x0045bcc2. Too many branches
                    // WARNING: Treating indirect jump as call
  VerLanguageNameA();
  return;
}



void RtlUnwind(void)

{
                    // WARNING: Could not recover jumptable at 0x0045bcc8. Too many branches
                    // WARNING: Treating indirect jump as call
  RtlUnwind();
  return;
}



void GetFileVersionInfoA(void)

{
                    // WARNING: Could not recover jumptable at 0x0045bcce. Too many branches
                    // WARNING: Treating indirect jump as call
  GetFileVersionInfoA();
  return;
}



void GetFileVersionInfoSizeA(void)

{
                    // WARNING: Could not recover jumptable at 0x0045bcd4. Too many branches
                    // WARNING: Treating indirect jump as call
  GetFileVersionInfoSizeA();
  return;
}



void VerQueryValueA(void)

{
                    // WARNING: Could not recover jumptable at 0x0045bcda. Too many branches
                    // WARNING: Treating indirect jump as call
  VerQueryValueA();
  return;
}



void FUN_0045bce6(code *UNRECOVERED_JUMPTABLE)

{
                    // WARNING: Load size is inaccurate
  ExceptionList = *ExceptionList;
                    // WARNING: Could not recover jumptable at 0x0045bd11. Too many branches
                    // WARNING: Treating indirect jump as call
  (*UNRECOVERED_JUMPTABLE)();
  return;
}



void FUN_0045bd1a(undefined4 param_1,code *UNRECOVERED_JUMPTABLE)

{
  LOCK();
  UNLOCK();
                    // WARNING: Could not recover jumptable at 0x0045bd1f. Too many branches
                    // WARNING: Treating indirect jump as call
  (*UNRECOVERED_JUMPTABLE)();
  return;
}



void FUN_0045bd21(undefined4 param_1,code *UNRECOVERED_JUMPTABLE)

{
  LOCK();
  UNLOCK();
                    // WARNING: Could not recover jumptable at 0x0045bd26. Too many branches
                    // WARNING: Treating indirect jump as call
  (*UNRECOVERED_JUMPTABLE)();
  return;
}



void FUN_0045bd28(undefined4 param_1,int param_2)

{
  void *pvVar1;
  
  pvVar1 = ExceptionList;
  RtlUnwind(param_1,0x45bd50,param_2,0);
  *(uint *)(param_2 + 4) = *(uint *)(param_2 + 4) & 0xfffffffd;
  *(void **)pvVar1 = ExceptionList;
  ExceptionList = pvVar1;
  return;
}



undefined4
FUN_0045bdad(undefined4 param_1,undefined4 param_2,undefined4 param_3,int param_4,undefined4 param_5
            )

{
  undefined4 uVar1;
  void *pvStack_18;
  undefined4 uStack_14;
  undefined4 uStack_10;
  undefined4 uStack_c;
  int iStack_8;
  
  uStack_10 = param_2;
  uStack_14 = 0x45be01;
  iStack_8 = param_4 + 1;
  uStack_c = param_1;
  pvStack_18 = ExceptionList;
  ExceptionList = &pvStack_18;
  uVar1 = FUN_0045c810(param_3,param_1,param_5);
  ExceptionList = pvStack_18;
  return uVar1;
}



undefined4
FUN_0045be26(undefined4 *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,undefined4 param_7)

{
  int iVar1;
  undefined4 *puStack_34;
  undefined4 uStack_30;
  undefined4 *puStack_2c;
  undefined4 uStack_28;
  undefined4 uStack_24;
  undefined4 uStack_20;
  undefined4 uStack_1c;
  undefined4 uStack_18;
  undefined4 uStack_14;
  undefined *puStack_10;
  undefined *puStack_c;
  int iStack_8;
  
  puStack_c = &stack0xfffffffc;
  puStack_10 = &stack0xffffffbc;
  uStack_28 = 0x45bedc;
  uStack_24 = param_5;
  uStack_20 = param_2;
  uStack_1c = param_6;
  uStack_18 = param_7;
  iStack_8 = 0;
  uStack_14 = 0x45beae;
  puStack_2c = (undefined4 *)ExceptionList;
  ExceptionList = &puStack_2c;
  puStack_34 = param_1;
  uStack_30 = param_3;
  iVar1 = FUN_0044fc4a(*param_1,&puStack_34);
  (**(code **)(iVar1 + 0x68))();
  if (iStack_8 != 0) {
                    // WARNING: Load size is inaccurate
    *puStack_2c = *ExceptionList;
  }
  ExceptionList = puStack_2c;
  return 0;
}



int FUN_0045bf51(uint param_1,int param_2,int param_3,uint *param_4,uint *param_5)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  uint uStack_8;
  
  iVar2 = param_1;
  uStack_8 = *(uint *)(param_1 + 0xc);
  iVar1 = *(int *)(param_1 + 0x10);
  uVar3 = uStack_8;
  param_1 = uStack_8;
  if (-1 < param_2) {
    do {
      if (uVar3 == 0xffffffff) {
        FUN_00459584();
      }
      uVar3 = uVar3 - 1;
      if (((*(int *)(iVar1 + 4 + uVar3 * 0x14) < param_3) &&
          (param_3 <= *(int *)(iVar1 + uVar3 * 0x14 + 8))) || (uVar3 == 0xffffffff)) {
        param_2 = param_2 + -1;
        uStack_8 = param_1;
        param_1 = uVar3;
      }
    } while (-1 < param_2);
  }
  uVar3 = uVar3 + 1;
  *param_4 = uVar3;
  *param_5 = uStack_8;
  if ((*(uint *)(iVar2 + 0xc) <= uStack_8 && uStack_8 != *(uint *)(iVar2 + 0xc)) ||
     (uStack_8 < uVar3)) {
    FUN_00459584();
  }
  return iVar1 + uVar3 * 0x14;
}



void FUN_0045bfcc(void)

{
  undefined auStack_c [12];
  
  ExceptionList = auStack_c;
  return;
}



undefined4
FUN_0045bfeb(int *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,int *param_5,
            int param_6,undefined4 param_7,uint param_8)

{
  undefined4 uVar1;
  
  if (*param_5 != 0x19930520) {
    FUN_00459584();
  }
  if ((*(byte *)(param_1 + 1) & 0x66) == 0) {
    if (param_5[3] != 0) {
      if (((*param_1 == -0x1f928c9d) && (0x19930520 < (uint)param_1[5])) &&
         (*(code **)(param_1[7] + 8) != (code *)0x0)) {
        uVar1 = (**(code **)(param_1[7] + 8))
                          (param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8 & 0xff);
        return uVar1;
      }
      FUN_0045c086(param_1,param_2,param_3,param_4,param_5,param_8,param_6,param_7);
    }
  }
  else if ((param_5[1] != 0) && (param_6 == 0)) {
    FUN_0045c340(param_2,param_4,param_5,0xffffffff);
  }
  return 1;
}



void FUN_0045c086(int *param_1,int param_2,undefined4 param_3,undefined4 param_4,int param_5,
                 char param_6,undefined4 param_7,undefined4 param_8)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  int *piVar4;
  uint uStack_1c;
  undefined4 uStack_18;
  int iStack_14;
  int iStack_10;
  int iStack_c;
  uint uStack_8;
  
  uStack_18 = uStack_18 & 0xffffff00;
  iStack_14 = *(int *)(param_2 + 8);
  if ((iStack_14 < -1) || (*(int *)(param_5 + 4) <= iStack_14)) {
    FUN_00459584();
  }
  if (*param_1 == -0x1f928c9d) {
    if (((param_1[4] == 3) && (param_1[5] == 0x19930520)) && (param_1[7] == 0)) {
      iVar2 = FUN_0044fc4a();
      if (*(int *)(iVar2 + 0x6c) == 0) {
        return;
      }
      iVar2 = FUN_0044fc4a();
      param_1 = *(int **)(iVar2 + 0x6c);
      iVar2 = FUN_0044fc4a();
      param_3 = *(undefined4 *)(iVar2 + 0x70);
      uStack_18 = CONCAT31(uStack_18._1_3_,1);
      iVar2 = FUN_004594d3(param_1,1);
      if (iVar2 == 0) {
        FUN_00459584();
      }
      if (*param_1 != -0x1f928c9d) goto LAB_0045c20e;
      if (((param_1[4] == 3) && (param_1[5] == 0x19930520)) && (param_1[7] == 0)) {
        FUN_00459584();
      }
    }
    iVar2 = iStack_14;
    if (((*param_1 == -0x1f928c9d) && (param_1[4] == 3)) && (param_1[5] == 0x19930520)) {
      piVar3 = (int *)FUN_0045bf51(param_5,param_7,iStack_14,&uStack_8,&uStack_1c);
      do {
        if (uStack_1c <= uStack_8) {
          if (param_6 == '\0') {
            return;
          }
          FUN_0045c778(param_1,1);
          return;
        }
        if ((*piVar3 == iVar2 || *piVar3 < iVar2) && (iVar2 <= piVar3[1])) {
          iVar1 = piVar3[4];
          for (iStack_10 = piVar3[3]; iVar2 = iStack_14, 0 < iStack_10; iStack_10 = iStack_10 + -1)
          {
            piVar4 = *(int **)(param_1[7] + 0xc);
            for (iStack_c = *piVar4; 0 < iStack_c; iStack_c = iStack_c + -1) {
              piVar4 = piVar4 + 1;
              iVar2 = FUN_0045c2e3(iVar1,*piVar4,param_1[7]);
              if (iVar2 != 0) {
                FUN_0045c3f4(param_1,param_2,param_3,param_4,param_5,iVar1,*piVar4,piVar3,param_7,
                             param_8,uStack_18);
                iVar2 = iStack_14;
                goto LAB_0045c1ee;
              }
            }
            iVar1 = iVar1 + 0x10;
          }
        }
LAB_0045c1ee:
        uStack_8 = uStack_8 + 1;
        piVar3 = piVar3 + 5;
      } while( true );
    }
  }
LAB_0045c20e:
  if (param_6 == '\0') {
    FUN_0045c239(param_1,param_2,param_3,param_4,param_5,iStack_14,param_7,param_8);
    return;
  }
  FUN_00459523();
  return;
}



void FUN_0045c239(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,int param_6,undefined4 param_7,undefined4 param_8)

{
  int iVar1;
  int *piVar2;
  int iVar3;
  uint uStack_c;
  uint uStack_8;
  
  iVar1 = FUN_0044fc4a();
  if ((*(int *)(iVar1 + 0x68) != 0) &&
     (iVar1 = FUN_0045be26(param_1,param_2,param_3,param_4,param_5,param_7,param_8), iVar1 != 0)) {
    return;
  }
  piVar2 = (int *)FUN_0045bf51(param_5,param_7,param_6,&uStack_8,&uStack_c);
  for (; uStack_8 < uStack_c; uStack_8 = uStack_8 + 1) {
    if ((*piVar2 <= param_6) && (param_6 <= piVar2[1])) {
      iVar3 = piVar2[3] * 0x10 + piVar2[4];
      iVar1 = *(int *)(iVar3 + -0xc);
      if ((iVar1 == 0) || (*(char *)(iVar1 + 8) == '\0')) {
        FUN_0045c3f4(param_1,param_2,param_3,param_4,param_5,iVar3 + -0x10,0,piVar2,param_7,param_8,
                     1);
      }
    }
    piVar2 = piVar2 + 5;
  }
  return;
}



undefined4 FUN_0045c2e3(byte *param_1,byte *param_2,uint *param_3)

{
  int iVar1;
  undefined4 uVar2;
  
  iVar1 = *(int *)(param_1 + 4);
  if ((iVar1 == 0) || (*(char *)(iVar1 + 8) == '\0')) {
LAB_0045c33a:
    uVar2 = 1;
  }
  else {
    if (iVar1 == *(int *)(param_2 + 4)) {
LAB_0045c314:
      if (((((*param_2 & 2) == 0) || ((*param_1 & 8) != 0)) &&
          (((*param_3 & 1) == 0 || ((*param_1 & 1) != 0)))) &&
         (((*param_3 & 2) == 0 || ((*param_1 & 2) != 0)))) goto LAB_0045c33a;
    }
    else {
      iVar1 = FUN_00452a60(iVar1 + 8,*(int *)(param_2 + 4) + 8);
      if (iVar1 == 0) goto LAB_0045c314;
    }
    uVar2 = 0;
  }
  return uVar2;
}



void FUN_0045c340(int param_1,undefined4 param_2,int param_3,int param_4)

{
  int iVar1;
  int iVar2;
  void *pvStack_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 uStack_8;
  
  puStack_c = &UNK_00460158;
  puStack_10 = &UNK_0045001c;
  pvStack_14 = ExceptionList;
  ExceptionList = &pvStack_14;
  for (iVar2 = *(int *)(param_1 + 8); uStack_8 = 0xffffffff, iVar2 != param_4;
      iVar2 = *(int *)(*(int *)(param_3 + 8) + iVar2 * 8)) {
    if ((iVar2 < 0) || (*(int *)(param_3 + 4) <= iVar2)) {
      FUN_00459584();
    }
    uStack_8 = 0;
    iVar1 = *(int *)(*(int *)(param_3 + 8) + 4 + iVar2 * 8);
    if (iVar1 != 0) {
      FUN_0045c810(iVar1,param_1,0x103);
    }
  }
  *(int *)(param_1 + 8) = iVar2;
  ExceptionList = pvStack_14;
  return;
}



void FUN_0045c3f4(undefined4 param_1,int param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,int param_6,int param_7,undefined4 *param_8,undefined4 param_9,
                 int param_10)

{
  int iVar1;
  
  if (param_7 != 0) {
    FUN_0045c5b4(param_1,param_2,param_6,param_7);
  }
  if (param_10 == 0) {
    param_10 = param_2;
  }
  FUN_0045bd28(param_10,param_1);
  FUN_0045c340(param_2,param_4,param_5,*param_8);
  *(int *)(param_2 + 8) = param_8[1] + 1;
  iVar1 = FUN_0045c46f(param_1,param_2,param_3,param_5,*(undefined4 *)(param_6 + 0xc),param_9,0x100)
  ;
  if (iVar1 != 0) {
    FUN_0045bce6(iVar1,param_2);
  }
  return;
}



undefined4
FUN_0045c46f(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,undefined4 param_7)

{
  int iVar1;
  undefined4 uVar2;
  void *pvStack_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 uStack_8;
  
  uStack_8 = 0xffffffff;
  puStack_c = &UNK_00460168;
  puStack_10 = &UNK_0045001c;
  pvStack_14 = ExceptionList;
  ExceptionList = &pvStack_14;
  FUN_0044fc4a();
  FUN_0044fc4a();
  iVar1 = FUN_0044fc4a();
  *(undefined4 *)(iVar1 + 0x6c) = param_1;
  iVar1 = FUN_0044fc4a();
  *(undefined4 *)(iVar1 + 0x70) = param_3;
  uStack_8 = 1;
  uVar2 = FUN_0045bdad(param_2,param_4,param_5,param_6,param_7);
  uStack_8 = 0xffffffff;
  FUN_0045c53c();
  ExceptionList = pvStack_14;
  return uVar2;
}



void FUN_0045c53c(void)

{
  int iVar1;
  int unaff_EBP;
  int unaff_ESI;
  int *unaff_EDI;
  
  *(undefined4 *)(unaff_ESI + -4) = *(undefined4 *)(unaff_EBP + -0x28);
  iVar1 = FUN_0044fc4a();
  *(undefined4 *)(iVar1 + 0x6c) = *(undefined4 *)(unaff_EBP + -0x1c);
  iVar1 = FUN_0044fc4a();
  *(undefined4 *)(iVar1 + 0x70) = *(undefined4 *)(unaff_EBP + -0x20);
  if ((((*unaff_EDI == -0x1f928c9d) && (unaff_EDI[4] == 3)) && (unaff_EDI[5] == 0x19930520)) &&
     ((*(int *)(unaff_EBP + -0x24) == 0 && (*(int *)(unaff_EBP + -0x2c) != 0)))) {
    FUN_0044ffce();
    FUN_0045c778();
  }
  return;
}



void FUN_0045c5b4(int param_1,int param_2,byte *param_3,byte *param_4)

{
  int *piVar1;
  int iVar2;
  undefined4 uVar3;
  void *pvStack_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 uStack_8;
  
  puStack_c = &UNK_00460180;
  puStack_10 = &UNK_0045001c;
  pvStack_14 = ExceptionList;
  if (*(int *)(param_3 + 4) == 0) {
    return;
  }
  if (*(char *)(*(int *)(param_3 + 4) + 8) == '\0') {
    return;
  }
  if (*(int *)(param_3 + 8) == 0) {
    return;
  }
  piVar1 = (int *)(*(int *)(param_3 + 8) + 0xc + param_2);
  uStack_8 = 0;
  if ((*param_3 & 8) == 0) {
    if ((*param_4 & 1) == 0) {
      if (*(int *)(param_4 + 0x18) == 0) {
        ExceptionList = &pvStack_14;
        iVar2 = FUN_004594d3(*(undefined4 *)(param_1 + 0x18),1);
        if ((iVar2 != 0) && (iVar2 = FUN_004594ef(piVar1,1), iVar2 != 0)) {
          uVar3 = FUN_0045c7df(*(undefined4 *)(param_1 + 0x18),param_4 + 8,
                               *(undefined4 *)(param_4 + 0x14));
          FUN_0044e2d0(piVar1,uVar3);
          ExceptionList = pvStack_14;
          return;
        }
      }
      else {
        ExceptionList = &pvStack_14;
        iVar2 = FUN_004594d3(*(undefined4 *)(param_1 + 0x18),1);
        if (((iVar2 != 0) && (iVar2 = FUN_004594ef(piVar1,1), iVar2 != 0)) &&
           (iVar2 = FUN_0045950b(*(undefined4 *)(param_4 + 0x18)), iVar2 != 0)) {
          if ((*param_4 & 4) != 0) {
            uVar3 = FUN_0045c7df(*(undefined4 *)(param_1 + 0x18),param_4 + 8,1);
            FUN_0045bd21(piVar1,*(undefined4 *)(param_4 + 0x18),uVar3);
            ExceptionList = pvStack_14;
            return;
          }
          uVar3 = FUN_0045c7df(*(undefined4 *)(param_1 + 0x18),param_4 + 8);
          FUN_0045bd1a(piVar1,*(undefined4 *)(param_4 + 0x18),uVar3);
          ExceptionList = pvStack_14;
          return;
        }
      }
    }
    else {
      ExceptionList = &pvStack_14;
      iVar2 = FUN_004594d3(*(undefined4 *)(param_1 + 0x18),1);
      if ((iVar2 != 0) && (iVar2 = FUN_004594ef(piVar1,1), iVar2 != 0)) {
        FUN_0044e2d0(piVar1,*(undefined4 *)(param_1 + 0x18),*(undefined4 *)(param_4 + 0x14));
        if (*(int *)(param_4 + 0x14) != 4) {
          ExceptionList = pvStack_14;
          return;
        }
        iVar2 = *piVar1;
        if (iVar2 == 0) {
          ExceptionList = pvStack_14;
          return;
        }
        goto LAB_0045c642;
      }
    }
  }
  else {
    ExceptionList = &pvStack_14;
    iVar2 = FUN_004594d3(*(undefined4 *)(param_1 + 0x18),1);
    if ((iVar2 != 0) && (iVar2 = FUN_004594ef(piVar1,1), iVar2 != 0)) {
      iVar2 = *(int *)(param_1 + 0x18);
      *piVar1 = iVar2;
LAB_0045c642:
      iVar2 = FUN_0045c7df(iVar2,param_4 + 8);
      *piVar1 = iVar2;
      ExceptionList = pvStack_14;
      return;
    }
  }
  FUN_00459584();
  ExceptionList = pvStack_14;
  return;
}



void FUN_0045c778(int param_1)

{
  int iVar1;
  void *pvStack_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 uStack_8;
  
  puStack_c = &UNK_00460190;
  puStack_10 = &UNK_0045001c;
  pvStack_14 = ExceptionList;
  if ((param_1 != 0) && (iVar1 = *(int *)(*(int *)(param_1 + 0x1c) + 4), iVar1 != 0)) {
    uStack_8 = 0;
    ExceptionList = &pvStack_14;
    FUN_0045bd1a(*(undefined4 *)(param_1 + 0x18),iVar1);
  }
  ExceptionList = pvStack_14;
  return;
}



int FUN_0045c7df(int param_1,int *param_2)

{
  int iVar1;
  int iVar2;
  
  iVar1 = param_2[1];
  iVar2 = *param_2 + param_1;
  if (-1 < iVar1) {
    iVar2 = iVar2 + *(int *)(*(int *)(iVar1 + param_1) + param_2[2]) + iVar1;
  }
  return iVar2;
}



void __thiscall FUN_0045c810(undefined4 param_1,undefined4 param_2,undefined4 param_3,int param_4)

{
  code *pcVar1;
  int iVar2;
  
  pcVar1 = (code *)FUN_0044fff1(param_4,&stack0xfffffffc,param_1);
  (*pcVar1)();
  iVar2 = *(int *)(param_4 + 0x10);
  if (iVar2 == 0x100) {
    iVar2 = 2;
  }
  FUN_0044fff1(iVar2,param_4);
  return;
}



void Unwind_0045c85c(void)

{
  int unaff_EBP;
  
  if ((*(uint *)(unaff_EBP + -0x10) & 1) != 0) {
    FUN_0045b4cf();
    return;
  }
  return;
}



void Unwind_0045c880(void)

{
  int unaff_EBP;
  
  if ((*(uint *)(unaff_EBP + -0x10) & 1) != 0) {
    FUN_0045b4cf();
    return;
  }
  return;
}



void Unwind_0045c8a4(void)

{
  int unaff_EBP;
  
  FUN_0044bb7e(*(undefined4 *)(unaff_EBP + -0x10));
  return;
}



void Unwind_0045c8b8(void)

{
  FUN_0045ba45();
  return;
}



void Unwind_0045c8cc(void)
{
  int unaff_EBP;
  
  FUN_0044bb7e(*(undefined4 *)(unaff_EBP + -0x10));
  return;
}

