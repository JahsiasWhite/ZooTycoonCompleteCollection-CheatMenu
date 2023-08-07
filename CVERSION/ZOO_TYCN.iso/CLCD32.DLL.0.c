typedef unsigned char   undefined;

typedef unsigned int    word;
typedef struct OLD_IMAGE_DOS_HEADER OLD_IMAGE_DOS_HEADER, *POLD_IMAGE_DOS_HEADER;

struct OLD_IMAGE_DOS_HEADER {
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
};




// WARNING: Instruction at (ram,0x0001021e) overlaps instruction at (ram,0x0001021d)
// 
// WARNING: Control flow encountered bad instruction data
// WARNING: Stack frame is not setup normally: Input value of stackpointer is not used
// WARNING: This function may have set the stack pointer
// WARNING: Removing unreachable block (ram,0x0001009c)
// WARNING: Removing unreachable block (ram,0x000101e1)
// WARNING: Removing unreachable block (ram,0x000101e3)
// WARNING: Removing unreachable block (ram,0x0001016d)
// WARNING: Removing unreachable block (ram,0x00010193)
// WARNING: Removing unreachable block (ram,0x00010196)
// WARNING: Removing unreachable block (ram,0x0001021e)
// WARNING: Removing unreachable block (ram,0x00010248)
// WARNING: Removing unreachable block (ram,0x000101bd)
// WARNING: Removing unreachable block (ram,0x000101f7)
// WARNING: Removing unreachable block (ram,0x0001007a)

void __stdcall16far entry(void)

{
  byte *pbVar1;
  undefined2 *puVar2;
  undefined *puVar3;
  undefined2 uVar4;
  code *pcVar5;
  undefined2 in_CX;
  byte bVar6;
  undefined2 uVar7;
  int in_BX;
  undefined *puVar8;
  int unaff_BP;
  undefined2 *unaff_SI;
  undefined2 *unaff_DI;
  undefined2 unaff_ES;
  undefined4 uVar9;
  
  bVar6 = (byte)((uint)in_CX >> 8);
                    // WARNING: Read-only address (ram,0x000100b6) is written
  uRam000100b6 = 0x1000;
  puVar8 = (undefined *)0xb8;
  pcVar5 = (code *)swi(0x21);
  (*pcVar5)();
  pcVar5 = (code *)swi(0x21);
  uVar9 = (*pcVar5)();
  uVar7 = (undefined2)((ulong)uVar9 >> 0x10);
  *(undefined **)(puVar8 + -2) = puVar8;
  *(undefined2 *)(puVar8 + -4) = 0x7369;
  pbVar1 = (byte *)((int)unaff_SI + in_BX + 0x72);
  *pbVar1 = *pbVar1 & (byte)((ulong)uVar9 >> 0x18);
  out(*unaff_SI,uVar7);
  uVar4 = in(uVar7);
  *unaff_DI = uVar4;
  pbVar1 = (byte *)((int)unaff_DI + unaff_BP + 99);
  *pbVar1 = *pbVar1 & (byte)((ulong)uVar9 >> 8);
  out(*(undefined *)(unaff_SI + 1),uVar7);
  out(*(undefined *)((int)unaff_SI + 3),uVar7);
  out(unaff_SI[2],uVar7);
  if (*pbVar1 != 0) {
    out(*(undefined *)(unaff_SI + 3),uVar7);
    pbVar1 = (byte *)((int)unaff_DI + in_BX + 0x70);
    *pbVar1 = *pbVar1 & bVar6;
    puVar2 = unaff_SI + 0x2b;
    *(byte *)puVar2 = *(byte *)puVar2 & (byte)uVar9;
    *(int *)(puVar8 + -6) = in_BX;
    pbVar1 = (byte *)((int)unaff_DI + 0x71);
    *pbVar1 = *pbVar1 & bVar6;
    puVar3 = (undefined *)((int)unaff_SI + in_BX + 7);
    *puVar3 = *puVar3;
    puVar3 = (undefined *)((int)unaff_SI + in_BX + 7);
    *puVar3 = *puVar3;
    puVar3 = (undefined *)((int)unaff_SI + in_BX + 7);
    *puVar3 = *puVar3;
    return;
  }
  *(undefined2 *)(puVar8 + -6) = 0x53;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}


