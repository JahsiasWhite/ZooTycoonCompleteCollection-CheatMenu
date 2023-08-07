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




// WARNING: Control flow encountered bad instruction data
// WARNING: Instruction at (ram,0x000101b1) overlaps instruction at (ram,0x000101b0)
// 
// WARNING: Stack frame is not setup normally: Input value of stackpointer is not used
// WARNING: This function may have set the stack pointer
// WARNING: Removing unreachable block (ram,0x0001007a)
// WARNING: Removing unreachable block (ram,0x00010094)
// WARNING: Removing unreachable block (ram,0x0001009c)
// WARNING: Removing unreachable block (ram,0x000100da)
// WARNING: Removing unreachable block (ram,0x0001013d)
// WARNING: Removing unreachable block (ram,0x00010165)
// WARNING: Removing unreachable block (ram,0x000101c6)
// WARNING: Removing unreachable block (ram,0x000101b1)
// WARNING: Removing unreachable block (ram,0x00010086)

void __cdecl16far entry(void)

{
  int *piVar1;
  byte *pbVar2;
  undefined *puVar3;
  char *pcVar4;
  undefined2 *puVar5;
  undefined2 uVar6;
  code *pcVar7;
  byte bVar9;
  int iVar8;
  undefined2 in_CX;
  byte bVar10;
  undefined2 uVar11;
  int in_BX;
  undefined *puVar12;
  int unaff_BP;
  undefined2 *unaff_SI;
  undefined2 *puVar13;
  undefined2 *unaff_DI;
  undefined2 unaff_ES;
  undefined4 uVar14;
  
  bVar10 = (byte)((uint)in_CX >> 8);
                    // WARNING: Read-only address (ram,0x000100b6) is written
  uRam000100b6 = 0x1000;
  puVar12 = (undefined *)0xb8;
  pcVar7 = (code *)swi(0x21);
  (*pcVar7)();
  pcVar7 = (code *)swi(0x21);
  uVar14 = (*pcVar7)();
  uVar11 = (undefined2)((ulong)uVar14 >> 0x10);
  iVar8 = (int)uVar14;
  *(undefined **)(puVar12 + -2) = puVar12;
  *(undefined2 *)(puVar12 + -4) = 0x7369;
  pbVar2 = (byte *)((int)unaff_SI + in_BX + 0x72);
  *pbVar2 = *pbVar2 & (byte)((ulong)uVar14 >> 0x18);
  out(*unaff_SI,uVar11);
  uVar6 = in(uVar11);
  *unaff_DI = uVar6;
  pbVar2 = (byte *)((int)unaff_DI + unaff_BP + 99);
  bVar9 = (byte)((ulong)uVar14 >> 8);
  *pbVar2 = *pbVar2 & bVar9;
  out(*(undefined *)(unaff_SI + 1),uVar11);
  out(*(undefined *)((int)unaff_SI + 3),uVar11);
  puVar13 = unaff_SI + 3;
  out(unaff_SI[2],uVar11);
  if (*pbVar2 != 0) {
    puVar5 = puVar13;
    puVar13 = (undefined2 *)((int)unaff_SI + 7);
    out(*(undefined *)puVar5,uVar11);
    pbVar2 = (byte *)((int)unaff_DI + in_BX + 0x70);
    *pbVar2 = *pbVar2 & bVar10;
    puVar5 = unaff_SI + 0x2b;
    *(byte *)puVar5 = *(byte *)puVar5 & (byte)uVar14;
    *(int *)(puVar12 + -6) = in_BX;
    pbVar2 = (byte *)((int)unaff_DI + 0x71);
    *pbVar2 = *pbVar2 & bVar10;
    iVar8 = (uint)(bVar9 | 10) << 8;
    puVar3 = (undefined *)(in_BX + (int)puVar13);
    *puVar3 = *puVar3;
    puVar3 = (undefined *)(in_BX + (int)puVar13);
    *puVar3 = *puVar3;
    puVar3 = (undefined *)(in_BX + (int)puVar13);
    *puVar3 = *puVar3;
    *(int *)(puVar12 + -8) = iVar8;
    unaff_BP = unaff_BP + 1;
  }
  pcVar4 = (char *)(in_BX + (int)puVar13);
  *pcVar4 = *pcVar4 + (char)iVar8;
  piVar1 = (int *)((int)unaff_DI + unaff_BP + 2);
  *piVar1 = *piVar1 + iVar8;
  pcVar4 = (char *)((int)puVar13 + 99);
  *pcVar4 = *pcVar4 + (char)((uint)in_BX >> 8);
  return;
}


