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
// WARNING: Instruction at (ram,0x00010201) overlaps instruction at (ram,0x00010200)
// 
// WARNING: Stack frame is not setup normally: Input value of stackpointer is not used
// WARNING: This function may have set the stack pointer
// WARNING: Removing unreachable block (ram,0x0001009c)
// WARNING: Removing unreachable block (ram,0x0001007a)
// WARNING: Removing unreachable block (ram,0x0001009e)
// WARNING: Removing unreachable block (ram,0x0001018d)
// WARNING: Removing unreachable block (ram,0x000101b5)
// WARNING: Removing unreachable block (ram,0x00010216)
// WARNING: Removing unreachable block (ram,0x00010201)

void entry(void)

{
  byte *pbVar1;
  undefined *puVar2;
  undefined2 *puVar3;
  undefined2 uVar4;
  code *pcVar5;
  undefined uVar6;
  byte bVar7;
  undefined2 in_CX;
  byte bVar8;
  undefined2 uVar9;
  int in_BX;
  undefined *puVar10;
  undefined *puVar11;
  int unaff_BP;
  undefined2 *unaff_SI;
  undefined2 *puVar12;
  undefined2 *unaff_DI;
  undefined2 *puVar13;
  undefined2 unaff_ES;
  undefined4 uVar14;
  
  bVar8 = (byte)((uint)in_CX >> 8);
                    // WARNING: Read-only address (ram,0x000100b6) is written
  uRam000100b6 = 0x1000;
  puVar10 = (undefined *)0xb8;
  pcVar5 = (code *)swi(0x21);
  (*pcVar5)();
  pcVar5 = (code *)swi(0x21);
  uVar14 = (*pcVar5)();
  uVar9 = (undefined2)((ulong)uVar14 >> 0x10);
  bVar7 = (byte)((ulong)uVar14 >> 8);
  *(undefined **)(puVar10 + -2) = puVar10;
  puVar11 = puVar10 + -4;
  *(undefined2 *)(puVar10 + -4) = 0x7369;
  pbVar1 = (byte *)((int)unaff_SI + in_BX + 0x72);
  *pbVar1 = *pbVar1 & (byte)((ulong)uVar14 >> 0x18);
  out(*unaff_SI,uVar9);
  puVar13 = unaff_DI + 1;
  uVar4 = in(uVar9);
  *unaff_DI = uVar4;
  pbVar1 = (byte *)((int)puVar13 + unaff_BP + 0x61);
  *pbVar1 = *pbVar1 & bVar7;
  out(*(undefined *)(unaff_SI + 1),uVar9);
  out(*(undefined *)((int)unaff_SI + 3),uVar9);
  puVar12 = unaff_SI + 3;
  out(unaff_SI[2],uVar9);
  if (*pbVar1 != 0) {
    puVar3 = puVar12;
    puVar12 = (undefined2 *)((int)unaff_SI + 7);
    out(*(undefined *)puVar3,uVar9);
    pbVar1 = (byte *)((int)puVar13 + in_BX + 0x6e);
    *pbVar1 = *pbVar1 & bVar8;
    puVar3 = unaff_SI + 0x2b;
    *(byte *)puVar3 = *(byte *)puVar3 & (byte)uVar14;
    puVar11 = puVar10 + -6;
    *(int *)(puVar10 + -6) = in_BX;
    pbVar1 = (byte *)((int)unaff_DI + 0x71);
    *pbVar1 = *pbVar1 & bVar8;
    bVar7 = bVar7 | 10;
    puVar2 = (undefined *)(in_BX + (int)puVar12);
    *puVar2 = *puVar2;
    puVar2 = (undefined *)(in_BX + (int)puVar12);
    *puVar2 = *puVar2;
    puVar2 = (undefined *)(in_BX + (int)puVar12);
    *puVar2 = *puVar2;
    puVar13 = (undefined2 *)0x46fd;
  }
  *(undefined2 **)(puVar11 + -2) = puVar12;
  in(uVar9);
  *(undefined **)(puVar11 + -4) = (undefined *)((int)puVar12 + 1);
  in(uVar9);
  *(undefined2 **)(puVar11 + -6) = puVar12 + 1;
  in(uVar9);
  *(undefined2 **)(puVar11 + -8) = puVar13;
  uVar6 = in(uVar9);
  LOCK();
  *(undefined2 *)(unaff_BP + 0x56) = CONCAT11(bVar7,uVar6);
  UNLOCK();
  in(uVar9);
  in(uVar9);
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}


