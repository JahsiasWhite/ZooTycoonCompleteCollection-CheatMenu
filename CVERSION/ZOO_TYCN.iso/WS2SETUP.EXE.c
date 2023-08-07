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




// WARNING: Instruction at (ram,0x000100a2) overlaps instruction at (ram,0x000100a1)
// 
// WARNING: Stack frame is not setup normally: Input value of stackpointer is not used
// WARNING: This function may have set the stack pointer
// WARNING: Removing unreachable block (ram,0x0001009c)
// WARNING: Removing unreachable block (ram,0x0001007a)

void entry(void)

{
  byte *pbVar1;
  char *pcVar2;
  int *piVar3;
  uint *puVar4;
  uint uVar5;
  undefined2 *puVar6;
  int *piVar7;
  code *pcVar8;
  byte bVar9;
  char cVar10;
  byte bVar11;
  char cVar12;
  char cVar15;
  undefined2 uVar13;
  undefined2 extraout_var;
  byte *pbVar14;
  int in_CX;
  byte bVar17;
  int iVar16;
  int in_BX;
  int iVar18;
  undefined *puVar20;
  undefined *puVar21;
  int unaff_BP;
  undefined2 *unaff_SI;
  undefined2 *puVar22;
  undefined2 *unaff_DI;
  undefined2 unaff_ES;
  undefined4 uVar23;
  char cVar19;
  
                    // WARNING: Read-only address (ram,0x000100b6) is written
  uRam000100b6 = 0x1000;
  puVar20 = (undefined *)0xb8;
  pcVar8 = (code *)swi(0x21);
  (*pcVar8)();
  pcVar8 = (code *)swi(0x21);
  uVar23 = (*pcVar8)();
  iVar16 = (int)((ulong)uVar23 >> 0x10);
  pbVar14 = (byte *)CONCAT22(extraout_var,(int)uVar23);
  *(undefined **)(puVar20 + -2) = puVar20;
  puVar21 = puVar20 + -4;
  *(undefined2 *)(puVar20 + -4) = 0x7369;
  pbVar1 = (byte *)((int)unaff_SI + in_BX + 0x72);
  bVar17 = (byte)((ulong)uVar23 >> 0x18);
  *pbVar1 = *pbVar1 & bVar17;
  out(*unaff_SI,iVar16);
  cVar12 = (char)((ulong)uVar23 >> 0x10);
  piVar7 = unaff_DI + 1;
  uVar13 = in(iVar16);
  *unaff_DI = uVar13;
  pbVar1 = (byte *)((int)piVar7 + unaff_BP + 0x61);
  *pbVar1 = *pbVar1 & (byte)((ulong)uVar23 >> 8);
  out(*(undefined *)(unaff_SI + 1),iVar16);
  out(*(undefined *)((int)unaff_SI + 3),iVar16);
  puVar22 = unaff_SI + 3;
  out(unaff_SI[2],iVar16);
  if (*pbVar1 != 0) {
    puVar6 = puVar22;
    puVar22 = (undefined2 *)((int)unaff_SI + 7);
    out(*(char *)puVar6,iVar16);
    pbVar1 = (byte *)((int)piVar7 + in_BX + 0x6e);
    bVar9 = (byte)((uint)in_CX >> 8);
    *pbVar1 = *pbVar1 & bVar9;
    puVar6 = unaff_SI + 0x2b;
    *(byte *)puVar6 = *(byte *)puVar6 & (byte)uVar23;
    *(int *)(puVar20 + -6) = in_BX;
    pbVar1 = (byte *)((int)unaff_DI + 0x71);
    *pbVar1 = *pbVar1 & bVar9;
    pbVar14 = (byte *)((ulong)((uint3)(CONCAT22(extraout_var,(int)uVar23) >> 8) | 10) << 8);
    pcVar2 = (char *)(in_BX + (int)puVar22);
    *pcVar2 = *pcVar2;
    pcVar2 = (char *)(in_BX + (int)puVar22);
    *pcVar2 = *pcVar2;
    pcVar2 = (char *)(in_BX + (int)puVar22);
    *pcVar2 = *pcVar2;
    puVar21 = puVar20 + -8;
    *(int *)(puVar20 + -8) = (int)pbVar14;
    unaff_BP = unaff_BP + 1;
  }
  pcVar2 = (char *)(in_BX + (int)puVar22);
  bVar9 = (byte)pbVar14;
  *pcVar2 = *pcVar2 + bVar9;
  piVar3 = piVar7;
  *piVar3 = *piVar3 + (int)pbVar14;
  cVar19 = (char)((uint)in_BX >> 8) + bVar17;
  iVar18 = CONCAT11(cVar19,(char)in_BX);
  piVar3 = (int *)(iVar18 + 0x32);
  *piVar3 = *piVar3 + -1;
  pcVar2 = (char *)(iVar18 + (int)puVar22);
  *pcVar2 = *pcVar2 + bVar9;
  pcVar2 = (char *)(iVar18 + (int)puVar22);
  *pcVar2 = *pcVar2 + bVar9;
  *pbVar14 = *pbVar14 | bVar9;
  cVar15 = (char)((ulong)pbVar14 >> 8);
  cVar10 = bVar9 + cVar15;
  pcVar2 = (char *)(unaff_BP + (int)puVar22);
  *pcVar2 = *pcVar2 + cVar10;
  in_CX = in_CX + *(int *)(unaff_BP + (int)piVar7);
  piVar3 = (int *)(unaff_BP + (int)piVar7);
  *piVar3 = *piVar3 + (int)CONCAT31((int3)((ulong)pbVar14 >> 8),cVar10);
  bVar11 = in(iVar16);
  pcVar2 = (char *)(iVar18 + (int)puVar22);
  *pcVar2 = *pcVar2 + bVar11;
  cVar15 = cVar15 * '\x02';
  pcVar2 = (char *)(iVar18 + (int)puVar22);
  *pcVar2 = *pcVar2 + bVar11;
  pcVar2 = (char *)((int)piVar7 + unaff_BP + 0x5c);
  cVar10 = (char)((uint)in_CX >> 8);
  *pcVar2 = *pcVar2 + cVar10;
  pbVar1 = (byte *)(iVar18 + (int)puVar22);
  bVar17 = *pbVar1;
  *pbVar1 = *pbVar1 + bVar11;
  pcVar2 = (char *)(iVar18 + (int)puVar22);
  *pcVar2 = *pcVar2 + bVar11 + CARRY1(bVar17,bVar11);
  pcVar2 = (char *)(iVar18 + (int)puVar22);
  *pcVar2 = *pcVar2 + bVar11;
  pcVar2 = (char *)(iVar18 + (int)piVar7);
  *pcVar2 = *pcVar2 + bVar11;
  pcVar2 = (char *)(iVar18 + (int)puVar22);
  *pcVar2 = *pcVar2 + bVar11;
  pcVar2 = (char *)(iVar18 + (int)puVar22);
  *pcVar2 = *pcVar2 + bVar11;
  puVar4 = (uint *)(iVar18 + (int)puVar22);
  uVar5 = *puVar4;
  *puVar4 = *puVar4 + CONCAT11(cVar15,bVar11);
  pcVar2 = (char *)(iVar18 + (int)puVar22);
  *pcVar2 = *pcVar2 + bVar11 + CARRY2(uVar5,CONCAT11(cVar15,bVar11));
  pcVar2 = (char *)(iVar18 + (int)puVar22);
  *pcVar2 = *pcVar2 + bVar11;
  bVar11 = bVar11 + *(char *)(iVar18 + (int)puVar22);
  uVar13 = CONCAT11(cVar15,bVar11);
  puVar6 = puVar22;
  *(byte *)puVar6 = *(char *)puVar6 + bVar11;
  pcVar2 = (char *)(iVar18 + (int)puVar22);
  *pcVar2 = *pcVar2 + bVar11;
  puVar6 = puVar22;
  *(byte *)puVar6 = *(char *)puVar6 + bVar11;
  pcVar2 = (char *)(iVar18 + (int)puVar22);
  *pcVar2 = *pcVar2 + bVar11;
  puVar6 = puVar22;
  *(byte *)puVar6 = *(char *)puVar6 + bVar11;
  pcVar2 = (char *)(iVar18 + (int)puVar22);
  *pcVar2 = *pcVar2 + bVar11;
  pcVar2 = (char *)(iVar18 + (int)puVar22);
  *pcVar2 = *pcVar2 + bVar11;
  pcVar2 = (char *)(iVar18 + (int)puVar22);
  *pcVar2 = *pcVar2 + bVar11;
  pbVar1 = (byte *)(iVar18 + (int)puVar22);
  bVar17 = *pbVar1;
  bVar9 = *pbVar1;
  *pbVar1 = *pbVar1 + bVar11;
  if (SCARRY1(bVar9,bVar11)) {
    pcVar2 = (char *)(iVar18 + (int)puVar22);
    *pcVar2 = *pcVar2 + bVar11 + CARRY1(bVar17,bVar11);
    pcVar2 = (char *)(iVar18 + (int)puVar22);
    *pcVar2 = *pcVar2 + cVar12;
    pcVar2 = (char *)(iVar18 + (int)puVar22);
    *pcVar2 = *pcVar2 + bVar11;
    pbVar1 = (byte *)(iVar18 + (int)puVar22);
    bVar17 = *pbVar1;
    *pbVar1 = *pbVar1 + bVar11;
    pcVar2 = (char *)(iVar18 + (int)puVar22);
    *pcVar2 = *pcVar2 + bVar11 + CARRY1(bVar17,bVar11);
    pcVar2 = (char *)(iVar18 + (int)puVar22);
    *pcVar2 = *pcVar2 + cVar12;
    pcVar2 = (char *)(iVar18 + (int)puVar22);
    *pcVar2 = *pcVar2 + bVar11;
    pcVar2 = (char *)(iVar18 + (int)puVar22);
    *pcVar2 = *pcVar2 + bVar11;
    pbVar1 = (byte *)(iVar18 + (int)puVar22);
    bVar17 = *pbVar1;
    *pbVar1 = *pbVar1 + bVar11;
    pcVar2 = (char *)(iVar18 + (int)puVar22);
    *pcVar2 = *pcVar2 + bVar11 + CARRY1(bVar17,bVar11);
    pcVar2 = (char *)(iVar18 + (int)puVar22);
    *pcVar2 = *pcVar2 + bVar11;
    pcVar2 = (char *)(iVar18 + (int)puVar22);
    *pcVar2 = *pcVar2 + bVar11;
    pcVar2 = (char *)(iVar18 + (int)puVar22);
    *pcVar2 = *pcVar2 + bVar11;
    pcVar2 = (char *)(iVar18 + (int)puVar22);
    *pcVar2 = *pcVar2 + bVar11;
    pcVar2 = (char *)(iVar18 + (int)puVar22);
    *pcVar2 = *pcVar2 + bVar11;
    iVar16 = (int)cVar15 >> 7;
    uVar13 = in(iVar16);
    pcVar2 = (char *)(iVar18 + (int)puVar22);
    *pcVar2 = *pcVar2 + (char)uVar13;
  }
  else {
    pcVar2 = (char *)(iVar18 + (int)puVar22);
    *pcVar2 = *pcVar2 + bVar11;
    cRam00000fa6 = cRam00000fa6 + cVar10;
    pcVar2 = (char *)(unaff_BP + (int)puVar22);
    *pcVar2 = *pcVar2 + bVar11;
    pcVar2 = (char *)(iVar18 + (int)puVar22);
    *pcVar2 = *pcVar2 + bVar11;
    pcVar2 = (char *)(iVar18 + (int)puVar22);
    *pcVar2 = *pcVar2 + bVar11;
    pcVar2 = (char *)(iVar18 + (int)puVar22);
    *pcVar2 = *pcVar2 + cVar12;
    pbVar1 = (byte *)(iVar18 + (int)puVar22);
    bVar17 = *pbVar1;
    *pbVar1 = *pbVar1 + bVar11;
    pcVar2 = (char *)(iVar18 + (int)puVar22);
    *pcVar2 = *pcVar2 + bVar11 + CARRY1(bVar17,bVar11);
    pcVar2 = (char *)(iVar18 + (int)puVar22);
    *pcVar2 = *pcVar2 + bVar11;
    pcVar2 = (char *)(iVar18 + (int)puVar22);
    *pcVar2 = *pcVar2 + cVar12;
    pbVar1 = (byte *)(iVar18 + (int)puVar22);
    bVar17 = *pbVar1;
    *pbVar1 = *pbVar1 + bVar11;
    pcVar2 = (char *)(iVar18 + (int)puVar22);
    *pcVar2 = *pcVar2 + bVar11 + CARRY1(bVar17,bVar11);
    pcVar2 = (char *)(iVar18 + (int)puVar22);
    *pcVar2 = *pcVar2 + bVar11;
    pcVar2 = (char *)(iVar18 + (int)puVar22);
    *pcVar2 = *pcVar2 + bVar11;
    pcVar2 = (char *)(iVar18 + (int)puVar22);
    *pcVar2 = *pcVar2 + cVar12;
    pcVar2 = (char *)(iVar18 + (int)puVar22);
    *pcVar2 = *pcVar2 + bVar11;
    pcVar2 = (char *)(iVar18 + (int)puVar22);
    *pcVar2 = *pcVar2 + bVar11;
    pcVar2 = (char *)(iVar18 + (int)puVar22);
    *pcVar2 = *pcVar2 + bVar11;
    pcVar2 = (char *)(iVar18 + (int)puVar22);
    *pcVar2 = *pcVar2 + bVar11;
    pcVar2 = (char *)(iVar18 + (int)puVar22);
    *pcVar2 = *pcVar2 + bVar11;
    pcVar2 = (char *)((int)piVar7 + iVar18 + 0xed);
    *pcVar2 = *pcVar2 + (char)in_BX;
    pcVar2 = (char *)(iVar18 + (int)puVar22);
    *pcVar2 = *pcVar2 + cVar19;
  }
  pcVar2 = (char *)(iVar18 + (int)puVar22);
  cVar12 = (char)uVar13;
  *pcVar2 = *pcVar2 + cVar12;
  pcVar2 = (char *)((int)puVar22 + iVar18 + 1);
  *pcVar2 = *pcVar2 + (char)((uint)uVar13 >> 8);
  pcVar2 = (char *)(iVar18 + (int)puVar22);
  *pcVar2 = *pcVar2 + cVar12;
  pcVar2 = (char *)(iVar18 + (int)puVar22);
  *pcVar2 = *pcVar2 + cVar12;
  pcVar2 = (char *)(iVar18 + (int)puVar22);
  *pcVar2 = *pcVar2 + cVar12;
  pcVar2 = (char *)(iVar18 + (int)puVar22);
  *pcVar2 = *pcVar2 + cVar12;
  *(undefined2 *)(puVar21 + -3) = uVar13;
  *(int *)(puVar21 + -5) = in_CX;
  *(int *)(puVar21 + -7) = iVar16;
  *(int *)(puVar21 + -9) = iVar18;
  *(undefined **)(puVar21 + -0xb) = puVar21 + -1;
  *(int *)(puVar21 + -0xd) = unaff_BP;
  *(undefined2 **)(puVar21 + -0xf) = puVar22;
  *(int **)(puVar21 + -0x11) = piVar7;


//   pcVar8 = (code *)swi(1);
//   (*pcVar8)();
  syscall(1);


  return;
}


