
/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Instruction at (ram,0x0001008b) overlaps instruction at (ram,0x0001008a)
    */
/* WARNING: Stack frame is not setup normally: Input value of stackpointer is not used */
/* WARNING: This function may have set the stack pointer */
/* WARNING: Removing unreachable block (ram,0x0001001f) */
/* WARNING: Removing unreachable block (ram,0x0001004e) */
/* WARNING: Removing unreachable block (ram,0x0001002e) */
/* WARNING: Removing unreachable block (ram,0x00010036) */
/* WARNING: Removing unreachable block (ram,0x0001007a) */
/* WARNING: Removing unreachable block (ram,0x00010064) */
/* WARNING: Removing unreachable block (ram,0x0001007d) */
/* WARNING: Removing unreachable block (ram,0x0001008b) */
/* WARNING: Removing unreachable block (ram,0x0001008a) */
/* WARNING: Removing unreachable block (ram,0x00010091) */

void entry(void)

{
  byte *pbVar1;
  char *pcVar2;
  uint *puVar3;
  int *piVar4;
  byte bVar5;
  undefined2 *puVar6;
  code *pcVar7;
  undefined3 uVar8;
  char cVar9;
  byte bVar10;
  uint uVar11;
  int iVar12;
  char in_CL;
  byte bVar13;
  undefined2 uVar14;
  int iVar15;
  int in_BX;
  int iVar16;
  undefined *puVar17;
  undefined *puVar18;
  int unaff_BP;
  undefined2 *unaff_SI;
  int iVar19;
  int *piVar20;
  undefined2 *unaff_DI;
  char *pcVar21;
  undefined2 unaff_ES;
  bool bVar22;
  byte in_AF;
  undefined in_XMM0 [16];
  undefined4 uVar23;
  
                    /* WARNING: Read-only address (ram,0x000100b6) is written */
  uRam000100b6 = 0x1000;
  puVar17 = (undefined *)0xb8;
  pcVar7 = (code *)swi(0x21);
  (*pcVar7)();
  pcVar7 = (code *)swi(0x21);
  uVar23 = (*pcVar7)();
  iVar15 = (int)((ulong)uVar23 >> 0x10);
  *(undefined **)(puVar17 + -2) = puVar17;
  *(undefined2 *)(puVar17 + -4) = 0x7369;
  pbVar1 = (byte *)((int)unaff_SI + in_BX + 0x72);
  bVar13 = (byte)((ulong)uVar23 >> 0x18);
  *pbVar1 = *pbVar1 & bVar13;
  puVar6 = unaff_SI + 1;
  out(*unaff_SI,iVar15);
  uVar14 = in(iVar15);
  *unaff_DI = uVar14;
  pbVar1 = (byte *)((int)puVar6 + unaff_BP + 0x65);
  *pbVar1 = *pbVar1 & bVar13;
  uRam00004460 = CONCAT12(uRam00004460._2_1_,(uint)uRam00004460 ^ (uint)puVar6);
  *(undefined **)(puVar17 + -5) = puVar17 + -3;
  *(undefined2 **)(puVar17 + -7) = puVar6;
  *(undefined **)(puVar17 + -9) = puVar17 + -7;
  *(int *)(puVar17 + -0xb) = iVar15;
  *(int *)(puVar17 + -0xd) = in_BX + 1;
  uVar11 = ((uint)uVar23 | 0x4553) + *(int *)(in_BX + 1 + (int)unaff_SI + 3) | 0x4547;
  *(undefined **)(puVar17 + -0xd) = puVar17 + -0xb;
  *(int *)(puVar17 + -0xf) = (int)unaff_SI + 3;
  iVar16 = in_BX + 2;
  *(undefined **)(puVar17 + -0x11) = puVar17 + -0xf;
  *(int *)(puVar17 + -0x13) = iVar15;
  *(int *)(puVar17 + -0x15) = iVar16;
  iVar15 = iVar15 + *(int *)(in_BX + 0x47);
  *(uint *)(puVar17 + -0x15) = uVar11;
  iVar12 = uVar11 + 0x900;
  *(int *)(puVar17 + -0x17) = iVar16;
  *(undefined **)(puVar17 + -0x19) = puVar17 + -0x17;
  *(undefined **)(puVar17 + -0x1a) = puVar17 + -0x18;
  pcVar21 = *(char **)(puVar17 + -0x1a);
  *(undefined2 *)(puVar17 + -0x1a) = unaff_ES;
  pcVar2 = pcVar21;
  *pcVar2 = *pcVar2 + in_CL + -4;
  *(undefined **)(puVar17 + -0x1d) = puVar17 + -0x1b;
  *(int *)(puVar17 + -0x1f) = iVar15;
  uVar14 = *(undefined2 *)(puVar17 + -0x1f);
  *(int *)(puVar17 + -0x1f) = iVar12;
  *(undefined **)(puVar17 + -0x21) = puVar17 + -0x1f;
  uVar11 = CONCAT11((char)((uint)iVar12 >> 8),(char)iVar12 + *(char *)((int)unaff_SI + in_BX + 5)) |
           0x53;
  *(undefined **)(puVar17 + -0x23) = puVar17 + -0x21;
  *(int *)(puVar17 + -0x25) = iVar15;
  *(undefined **)(puVar17 + -0x27) = puVar17 + -0x25;
  *(int *)(puVar17 + -0x29) = iVar16;
  cVar9 = (char)uVar14;
  uVar14 = *(undefined2 *)(puVar17 + -0x27);
  pcVar2 = (char *)(iVar16 + *(int *)(puVar17 + -0x29));
  *pcVar2 = *pcVar2 + cVar9 + -3;
  *(undefined **)(puVar17 + -0x27) = puVar17 + -0x25;
  *(undefined **)(puVar17 + -0x28) = puVar17 + -0x26;
  pbVar1 = (byte *)(iVar16 + (int)(unaff_SI + 2));
  *pbVar1 = *pbVar1 | (byte)uVar11;
  *(undefined2 *)(puVar17 + -0x28) = 0x1000;
  *(undefined **)(puVar17 + -0x2a) = puVar17 + -0x28;
  *(uint *)(puVar17 + -0x2c) = uVar11;
  *(undefined2 **)(puVar17 + -0x2e) = unaff_SI + 2;
  *(undefined **)(puVar17 + -0x30) = puVar17 + -0x2e;
  *(int *)(puVar17 + -0x32) = iVar15;
  puVar3 = (uint *)(in_BX + 3 + (int)unaff_SI + 5);
  *puVar3 = *puVar3 | uVar11;
  *(undefined2 *)(puVar17 + -0x32) = 0x1000;
  *(int *)(puVar17 + -0x34) = in_BX + 3;
  *(undefined **)(puVar17 + -0x36) = puVar17 + -0x34;
  *(uint *)(puVar17 + -0x38) = uVar11;
  *(int *)(puVar17 + -0x3a) = (int)unaff_SI + 5;
  *(undefined **)(puVar17 + -0x3c) = puVar17 + -0x3a;
  *(int *)(puVar17 + -0x3e) = iVar15;
  *(undefined2 **)(puVar17 + -0x3e) = unaff_SI + 3;
  *(undefined **)(puVar17 + -0x40) = puVar17 + -0x3e;
  *(int *)(puVar17 + -0x42) = iVar15;
  rcpps(in_XMM0,*(undefined (*) [16])(*(int *)(puVar17 + -0x42) + 0x54));
  *(int *)(puVar17 + -0x42) = (int)unaff_SI + 7;
  *(undefined **)(puVar17 + -0x44) = puVar17 + -0x42;
  *(int *)(puVar17 + -0x46) = iVar15;
  *(undefined **)(puVar17 + -0x46) = puVar17 + -0x44;
  *(int *)(puVar17 + -0x48) = iVar15;
  *(undefined **)(puVar17 + -0x4a) = puVar17 + -0x48;
  *(int *)(puVar17 + -0x4c) = in_BX + 6;
  bVar13 = cVar9 - 0xb;
  iVar16 = *(int *)(puVar17 + -0x46);
  iVar12 = *(int *)(puVar17 + -0x44);
  *(int *)(puVar17 + -0x44) = iVar12;
  *(int *)(puVar17 + -0x46) = iVar15;
  *(undefined **)(puVar17 + -0x48) = puVar17 + -0x46;
  *(int *)(puVar17 + -0x49) = in_BX + 6;
  *(undefined **)(puVar17 + -0x4b) = puVar17 + -0x49;
  *(int *)(puVar17 + -0x4d) = unaff_BP + 9;
  *(undefined2 *)(puVar17 + -0x4f) = 0x1000;
  pbVar1 = (byte *)(unaff_BP + 9 + iVar16 + -1);
  bVar22 = CARRY1(*pbVar1,bVar13);
  *pbVar1 = *pbVar1 + bVar13;
  iVar19 = (int)unaff_SI + 7;
  *(undefined **)(puVar17 + -0x51) = puVar17 + -0x4f;
  *(int *)(puVar17 + -0x53) = iVar19;
  iVar16 = in_BX + 7;
  *(undefined **)(puVar17 + -0x55) = puVar17 + -0x53;
  *(int *)(puVar17 + -0x57) = iVar15 + 1;
  *(int *)(puVar17 + -0x59) = iVar16;
  uRam000092a9 = LocalDescriptorTableRegister();
  *(undefined **)(puVar17 + -0x5b) = puVar17 + -0x59;
  *(int *)(puVar17 + -0x5d) = iVar19;
  pbVar1 = (byte *)(iVar16 + iVar19);
  bVar13 = *pbVar1;
  bVar10 = (byte)iVar12;
  bVar5 = *pbVar1;
  *pbVar1 = bVar5 + bVar10 + bVar22;
  *(undefined2 *)(puVar17 + -0x5f) = 0x1000;
  *(int *)(puVar17 + -0x61) = iVar16;
  *(int *)(puVar17 + -99) = iVar12;
  *(undefined **)(puVar17 + -0x66) = puVar17 + -100;
  piVar4 = (int *)(in_BX + 8 + iVar19);
  *piVar4 = *piVar4 + iVar12 + (uint)(CARRY1(bVar13,bVar10) || CARRY1(bVar5 + bVar10,bVar22));
  iVar12 = *(int *)(puVar17 + -0x66);
  *(undefined **)(puVar17 + -0x66) = puVar17 + -100;
  bVar10 = bVar10 - 1;
  *(int *)(puVar17 + -0x68) = unaff_BP + 0xb;
  *(undefined **)(puVar17 + -0x69) = puVar17 + -0x67;
  uRam00004460 = CONCAT21(uRam00004460._1_2_ ^ (uint)(unaff_SI + 3),(undefined)uRam00004460);
  pcVar2 = (char *)(in_BX + 7 + iVar12);
  *pcVar2 = *pcVar2 + bVar10;
  pbVar1 = (byte *)(in_BX + 7 + (int)(unaff_SI + 3));
  bVar13 = *pbVar1;
  *pbVar1 = *pbVar1 + bVar10;
  *(undefined2 *)(puVar17 + -0x6b) = uVar14;
  in_BX = in_BX + 6;
  *(int *)(puVar17 + -0x6d) = iVar15 + 1;
  iVar15 = unaff_BP + 0xd;
  puVar18 = puVar17 + -0x6e;
  iVar16 = iVar12 * 2 + (uint)CARRY1(bVar13,bVar10);
  in_AF = 9 < (bVar10 & 0xf) | in_AF;
  pcVar2 = (char *)(iVar15 + iVar16);
  *pcVar2 = *pcVar2 + (bVar10 + in_AF * -6 & 0xf);
  pcVar7 = (code *)swi(0x3f);
  uVar11 = (*pcVar7)();
  piVar4 = (int *)((int)unaff_SI + in_BX + 5);
  *piVar4 = *piVar4 + uVar11;
  puVar3 = (uint *)(iVar15 + iVar16);
  *puVar3 = *puVar3 | uVar11;
  pcVar7 = (code *)swi(0x3f);
  (*pcVar7)();
  pcVar7 = (code *)swi(0x3f);
  bVar13 = (*pcVar7)();
  piVar4 = (int *)(unaff_BP + 0x1d);
  *piVar4 = *piVar4 + iVar15;
  in_AF = 9 < (bVar13 & 0xf) | in_AF;
  bVar13 = bVar13 + in_AF * -6 & 0xf;
  piVar4 = (int *)((int)unaff_SI + unaff_BP + 0x12);
  *piVar4 = *piVar4 + in_BX;
  in_AF = 9 < bVar13 | in_AF;
  piVar4 = (int *)((int)unaff_SI + 0xf);
  *piVar4 = *piVar4 + in_BX;
  in_AF = 9 < (bVar13 + in_AF * -6 & 0xf) | in_AF;
  piVar4 = (int *)((int)unaff_SI + 0x30f);
  *piVar4 = *piVar4 + iVar16;
  pcVar7 = (code *)swi(0x3f);
  uVar14 = (*pcVar7)();
  piVar4 = (int *)((int)unaff_SI + 0xf);
  *piVar4 = *piVar4 + iVar16;
  in_AF = 9 < ((byte)uVar14 & 0xf) | in_AF;
  iRam0000476d = iRam0000476d +
                 (CONCAT11((char)((uint)uVar14 >> 8) - in_AF,(byte)uVar14 + in_AF * -6) & 0xff0f);
  pcVar7 = (code *)swi(0x3f);
  (*pcVar7)();
  iRam00004769 = iRam00004769 + iVar15;
  pcVar7 = (code *)swi(0x3f);
  (*pcVar7)();
  piVar20 = (int *)((int)unaff_SI + iVar16 + 5);
  piVar4 = piVar20;
  *piVar4 = *piVar4 + iVar15;
  uVar8 = SegmentLimit(iVar15);
  iVar12 = (int)uVar8;
  piVar4 = piVar20 + 0x185;
  *piVar4 = *piVar4 + in_BX;
  pcVar7 = (code *)swi(0x3f);
  (*pcVar7)();
  piVar4 = (int *)((int)piVar20 + unaff_BP + 0x12);
  *piVar4 = (int)(puVar18 + *piVar4);
  piVar4 = (int *)(unaff_BP + 0x31d);
  *piVar4 = *piVar4 + iVar12 + iVar15;
  pcVar7 = (code *)swi(0x3f);
  (*pcVar7)();
  piVar4 = (int *)(unaff_BP + 0x31d);
  *piVar4 = *piVar4 + iVar15;
  pcVar7 = (code *)swi(0x3f);
  uVar23 = (*pcVar7)();
  bVar13 = (char)uVar23 + (char)((ulong)uVar23 >> 0x10) +
           (char)*(undefined2 *)(in_BX + (int)piVar20) +
           CARRY2((uint)uVar23,(uint)((ulong)uVar23 >> 0x10)) | *(byte *)(iVar15 + iVar16 + 0x4c);
  uRam0000a98e = uRam0000a98e ^ (uint)piVar20;
  if ((int)uRam0000a98e < 0) {
                    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
  }
  pcVar2 = (char *)(in_BX + 1 + (int)piVar20);
  *pcVar2 = *pcVar2 + bVar13;
  pcVar2 = (char *)(in_BX + 1 + (int)piVar20);
  *pcVar2 = *pcVar2 + bVar13;
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}

