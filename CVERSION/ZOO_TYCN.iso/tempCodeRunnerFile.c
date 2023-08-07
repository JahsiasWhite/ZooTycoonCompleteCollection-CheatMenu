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