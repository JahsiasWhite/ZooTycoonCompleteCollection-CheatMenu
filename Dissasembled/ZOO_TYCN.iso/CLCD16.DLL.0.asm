                             //
                             // Code1 
                             // ram:1000:0000-ram:1000:1448
                             //
                             **************************************************************
                             * Title:  CLCD16.exe                                         *
                             * Format: New Executable (NE) Windows                        *
                             * CRC:    00000000                                           *
                             *                                                            *
                             * Program Entry Point (CS:IP):   0001:01fc                   *
                             * Initial Stack Pointer (SS:SP): 0000:0000                   *
                             * Auto Data Segment Index:       0002                        *
                             * Initial Heap Size:             0400                        *
                             * Initial Stack Size:            0000                        *
                             * Minimum Code Swap Size:        0000                        *
                             *                                                            *
                             * Linker Version:  5.60                                      *
                             * Target OS:       Windows                                   *
                             * Windows Version: 4.0                                       *
                             *                                                            *
                             * Program Flags:     01                                      *
                             *         Single Data                                        *
                             * Application Flags: 83                                      *
                             *         Windows P.M. API                                   *
                             *         Library Module                                     *
                             * Other Flags:       08                                      *
                             *                                                            *
                             **************************************************************
             assume DS = 0x1008
             assume DF = 0x0  (Default)
                             Segment:    1
                             Offset:     000002a0
                             Length:     1449
                             Min Alloc:  1449
                             Flags:      1d50
                                 Code
                                 Discardable
                                 Moveable
                                 Preload
                                 Impure (Non-shareable)
       1000:0000 d0              ??         D0h
       1000:0001 13              ??         13h
       1000:0002 00              ??         00h
       1000:0003 10              ??         10h
       1000:0004 8e              ??         8Eh
       1000:0005 10              ??         10h
       1000:0006 00              ??         00h
       1000:0007 10              ??         10h
       1000:0008 6e              ??         6Eh    n
       1000:0009 10              ??         10h
       1000:000a 00              ??         00h
       1000:000b 10              ??         10h
       1000:000c d2              ??         D2h
       1000:000d 0b              ??         0Bh
       1000:000e 00              ??         00h
       1000:000f 10              ??         10h
       1000:0010 bc              ??         BCh
       1000:0011 0a              ??         0Ah
       1000:0012 00              ??         00h
       1000:0013 10              ??         10h
       1000:0014 9c              ??         9Ch
       1000:0015 0a              ??         0Ah
       1000:0016 00              ??         00h
       1000:0017 10              ??         10h
       1000:0018 7c              ??         7Ch    |
       1000:0019 0a              ??         0Ah
       1000:001a 00              ??         00h
       1000:001b 10              ??         10h
       1000:001c 5c              ??         5Ch    \
       1000:001d 0a              ??         0Ah
       1000:001e 00              ??         00h
       1000:001f 10              ??         10h
       1000:0020 ae              ??         AEh
       1000:0021 10              ??         10h
       1000:0022 00              ??         00h
       1000:0023 10              ??         10h
       1000:0024 2c              ??         2Ch    ,
       1000:0025 0f              ??         0Fh
       1000:0026 00              ??         00h
       1000:0027 10              ??         10h
       1000:0028 fe              ??         FEh
       1000:0029 0d              ??         0Dh
       1000:002a 00              ??         00h
       1000:002b 10              ??         10h
       1000:002c 2e              ??         2Eh    .
       1000:002d 09              ??         09h
       1000:002e 00              ??         00h
       1000:002f 10              ??         10h
       1000:0030 06              ??         06h
       1000:0031 0d              ??         0Dh
       1000:0032 00              ??         00h
       1000:0033 10              ??         10h
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined FUN_1000_0034()
                               assume DS = 0x1008
             undefined         AL:1           <RETURN>
                             FUN_1000_0034                                   XREF[1]:     DLLENTRYPOINT:1000:091e(c)  
       1000:0034 58              POP        AX
       1000:0035 5a              POP        DX
       1000:0036 68 08 10        PUSH       0x1008
       1000:0039 68 10 00        PUSH       0x10
       1000:003c 68 00 10        PUSH       0x1000
       1000:003f 68 4a 00        PUSH       0x4a
       1000:0042 0e              PUSH       CS
       1000:0043 52              PUSH       DX
       1000:0044 50              PUSH       AX
       1000:0045 ea 5c 00        JMPF       KERNEL::Ordinal_651                              undefined Ordinal_651()
                 10 10
                             -- Flow Override: CALL_RETURN (CALL_TERMINATOR)
       1000:004a 74 68 6b        ds         "thk_ThunkData32"
                 5f 54 68 
                 75 6e 6b 
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined __stdcall16far WEP(undefined2 param_1)
                               assume DS = 0x1008
             undefined         AL:1           <RETURN>
             undefined2        Stack[0x4]:2   param_1                                 XREF[1]:     1000:0077(*)  
                             Ordinal_5                                       XREF[1]:     Entry Point(*)  
                             WEP
       1000:005a 8c d8           MOV        AX,DS
       1000:005c 90              NOP
       1000:005d 45              INC        BP
       1000:005e 55              PUSH       BP
       1000:005f 8b ec           MOV        BP,SP
       1000:0061 1e              PUSH       DS
       1000:0062 8e d8           MOV        DS,AX
       1000:0064 8c d9           MOV        CX,DS
       1000:0066 0f 02 c1        LAR        AX,CX
       1000:0069 75 1d           JNZ        LAB_1000_0088
       1000:006b 25 00 80        AND        AX,0x8000
       1000:006e 74 18           JZ         LAB_1000_0088
       1000:0070 a0 2e 01        MOV        AL,[DAT_1008_012e]
       1000:0073 0a c0           OR         AL,AL
       1000:0075 74 11           JZ         LAB_1000_0088
       1000:0077 ff 76 06        PUSH       word ptr [BP + param_1]
       1000:007a 9a 96 00        CALLF      FUN_1000_0096                                    undefined FUN_1000_0096()
                 00 10
       1000:007f 50              PUSH       AX
       1000:0080 9a fe 02        CALLF      FUN_1000_02fe                                    undefined FUN_1000_02fe()
                 00 10
       1000:0085 58              POP        AX
       1000:0086 eb 03           JMP        LAB_1000_008b
                             LAB_1000_0088                                   XREF[3]:     1000:0069(j), 1000:006e(j), 
                                                                                          1000:0075(j)  
       1000:0088 b8 01 00        MOV        AX,0x1
                             LAB_1000_008b                                   XREF[1]:     1000:0086(j)  
       1000:008b 83 ed 02        SUB        BP,0x2
       1000:008e 8b e5           MOV        SP,BP
       1000:0090 1f              POP        DS
       1000:0091 5d              POP        BP
       1000:0092 4d              DEC        BP
       1000:0093 ca 02 00        RETF       0x2
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined __stdcall16far FUN_1000_0096()
                               assume DS = 0x1008
             undefined         AL:1           <RETURN>
                             FUN_1000_0096                                   XREF[1]:     WEP:1000:007a(c)  
       1000:0096 8c d8           MOV        AX,DS
       1000:0098 90              NOP
       1000:0099 45              INC        BP
       1000:009a 55              PUSH       BP
       1000:009b 8b ec           MOV        BP,SP
       1000:009d 1e              PUSH       DS
       1000:009e 8e d8           MOV        DS,AX
       1000:00a0 b8 01 00        MOV        AX,0x1
       1000:00a3 83 ed 02        SUB        BP,0x2
       1000:00a6 8b e5           MOV        SP,BP
       1000:00a8 1f              POP        DS
       1000:00a9 5d              POP        BP
       1000:00aa 4d              DEC        BP
       1000:00ab ca 02 00        RETF       0x2
       1000:00ae 00              ??         00h
       1000:00af 00              ??         00h
       1000:00b0 00              ??         00h
       1000:00b1 00              ??         00h
       1000:00b2 00              ??         00h
       1000:00b3 00              ??         00h
       1000:00b4 00              ??         00h
       1000:00b5 00              ??         00h
       1000:00b6 00              ??         00h
       1000:00b7 00              ??         00h
       1000:00b8 00              ??         00h
       1000:00b9 00              ??         00h
       1000:00ba 00              ??         00h
       1000:00bb 00              ??         00h
       1000:00bc 00              ??         00h
       1000:00bd 00              ??         00h
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined __cdecl16far FUN_1000_00be(undefined4 param_1,
                               assume DS = 0x1008
             undefined         AL:1           <RETURN>
             undefined4        Stack[0x4]:4   param_1                                 XREF[2,1]:   1000:00c7(*), 
                                                                                                   1000:00fe(*), 
                                                                                                   1000:0101(*)  
             undefined2        Stack[0x8]:2   param_2                                 XREF[1]:     1000:00dc(*)  
             undefined2        Stack[0xa]:2   param_3                                 XREF[1]:     1000:00c1(*)  
                             FUN_1000_00be                                   XREF[12]:    SETPMVECTOR_IF:1000:0990(c), 
                                                                                          SETPMVECTOR_IF:1000:09cc(c), 
                                                                                          SETRMINTS_IF:1000:0b1f(c), 
                                                                                          SETRMINTS_IF:1000:0b59(c), 
                                                                                          SETVECTORS_IF:1000:0c34(c), 
                                                                                          SETVECTORS_IF:1000:0c67(c), 
                                                                                          GETV86VECTOR_IF:1000:0e60(c), 
                                                                                          GETV86VECTOR_IF:1000:0e9c(c), 
                                                                                          SETV86VECTOR_IF:1000:0f9a(c), 
                                                                                          SETV86VECTOR_IF:1000:0fd6(c), 
                                                                                          INITIV:1000:10eb(c), 
                                                                                          INITIV:1000:1127(c)  
       1000:00be 55              PUSH       BP
       1000:00bf 8b ec           MOV        BP,SP
       1000:00c1 8b 4e 0c        MOV        CX,word ptr [BP + param_3]
       1000:00c4 e3 38           JCXZ       LAB_1000_00fe
       1000:00c6 57              PUSH       DI
       1000:00c7 c4 7e 06        LES        DI,[BP + param_1]
       1000:00ca 8b d7           MOV        DX,DI
       1000:00cc f7 da           NEG        DX
       1000:00ce 74 0c           JZ         LAB_1000_00dc
       1000:00d0 2b d1           SUB        DX,CX
       1000:00d2 1b db           SBB        BX,BX
       1000:00d4 23 d3           AND        DX,BX
       1000:00d6 03 d1           ADD        DX,CX
       1000:00d8 87 d1           XCHG       CX,DX
       1000:00da 2b d1           SUB        DX,CX
                             LAB_1000_00dc                                   XREF[1]:     1000:00ce(j)  
       1000:00dc 8b 46 0a        MOV        AX,word ptr [BP + param_2]
       1000:00df 8a e0           MOV        AH,AL
       1000:00e1 d1 e9           SHR        CX,0x1
       1000:00e3 f3 ab           STOSW.REP  ES:DI
       1000:00e5 13 c9           ADC        CX,CX
       1000:00e7 f3 aa           STOSB.REP  ES:DI
       1000:00e9 87 d1           XCHG       CX,DX
       1000:00eb e3 10           JCXZ       LAB_1000_00fd
       1000:00ed 8c c3           MOV        BX,ES
       1000:00ef 81 c3 34 00     ADD        BX,0x34
       1000:00f3 8e c3           MOV        ES,BX
       1000:00f5 d1 e9           SHR        CX,0x1
       1000:00f7 f3 ab           STOSW.REP  ES:DI
       1000:00f9 13 c9           ADC        CX,CX
       1000:00fb f3 aa           STOSB.REP  ES:DI
                             LAB_1000_00fd                                   XREF[1]:     1000:00eb(j)  
       1000:00fd 5f              POP        DI
                             LAB_1000_00fe                                   XREF[1]:     1000:00c4(j)  
       1000:00fe 8b 46 06        MOV        AX,word ptr [BP + param_1]
       1000:0101 8b 56 08        MOV        DX,word ptr [BP + param_1+0x2]
       1000:0104 5d              POP        BP
       1000:0105 cb              RETF
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined __cdecl16far FUN_1000_0106()
                               assume DS = 0x1008
             undefined         AL:1           <RETURN>
                             FUN_1000_0106                                   XREF[1]:     FUN_1000_12c0:1000:1304(c)  
       1000:0106 32 ed           XOR        CH,CH
       1000:0108 e3 06           JCXZ       LAB_1000_0110
                             LAB_1000_010a                                   XREF[1]:     1000:010e(j)  
       1000:010a d1 ea           SHR        DX,0x1
       1000:010c d1 d8           RCR        AX,0x1
       1000:010e e2 fa           LOOP       LAB_1000_010a
                             LAB_1000_0110                                   XREF[1]:     1000:0108(j)  
       1000:0110 cb              RETF
       1000:0111 00              ??         00h
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined __cdecl16far FUN_1000_0112(undefined4 param_1,
                               assume DS = 0x1008
             undefined         AL:1           <RETURN>
             undefined4        Stack[0x4]:4   param_1                                 XREF[2,1]:   1000:0120(*), 
                                                                                                   1000:0165(*), 
                                                                                                   1000:0168(*)  
             undefined4        Stack[0x8]:4   param_2                                 XREF[1]:     1000:011d(*)  
             undefined2        Stack[0xc]:2   param_3                                 XREF[1]:     1000:0115(*)  
                             FUN_1000_0112                                   XREF[2]:     SETVECTORS_IF:1000:0ce0(c), 
                                                                                          GETPMVECTOR_IF:1000:0dd2(c)  
       1000:0112 55              PUSH       BP
       1000:0113 8b ec           MOV        BP,SP
       1000:0115 8b 4e 0e        MOV        CX,word ptr [BP + param_3]
       1000:0118 1e              PUSH       DS
       1000:0119 57              PUSH       DI
       1000:011a 56              PUSH       SI
       1000:011b e3 48           JCXZ       LAB_1000_0165
       1000:011d c5 76 0a        LDS        SI,[BP + param_2]
       1000:0120 c4 7e 06        LES        DI,[BP + param_1]
                             LAB_1000_0123                                   XREF[2]:     1000:015a(j), 1000:0163(j)  
       1000:0123 8b c1           MOV        AX,CX
       1000:0125 48              DEC        AX
       1000:0126 8b d7           MOV        DX,DI
       1000:0128 f7 d2           NOT        DX
       1000:012a 2b c2           SUB        AX,DX
       1000:012c 1b db           SBB        BX,BX
       1000:012e 23 c3           AND        AX,BX
       1000:0130 03 c2           ADD        AX,DX
       1000:0132 8b d6           MOV        DX,SI
       1000:0134 f7 d2           NOT        DX
       1000:0136 2b c2           SUB        AX,DX
       1000:0138 1b db           SBB        BX,BX
       1000:013a 23 c3           AND        AX,BX
       1000:013c 03 c2           ADD        AX,DX
       1000:013e 40              INC        AX
       1000:013f 91              XCHG       AX,CX
       1000:0140 2b c1           SUB        AX,CX
       1000:0142 d1 e9           SHR        CX,0x1
       1000:0144 f3 a5           MOVSW.REP  ES:DI,SI
       1000:0146 13 c9           ADC        CX,CX
       1000:0148 f3 a4           MOVSB.REP  ES:DI,SI
       1000:014a 91              XCHG       AX,CX
       1000:014b e3 18           JCXZ       LAB_1000_0165
       1000:014d 0b f6           OR         SI,SI
       1000:014f 75 07           JNZ        LAB_1000_0158
       1000:0151 8c d8           MOV        AX,DS
       1000:0153 05 34 00        ADD        AX,0x34
       1000:0156 8e d8           MOV        DS,AX
                             LAB_1000_0158                                   XREF[1]:     1000:014f(j)  
       1000:0158 0b ff           OR         DI,DI
       1000:015a 75 c7           JNZ        LAB_1000_0123
       1000:015c 8c c0           MOV        AX,ES
       1000:015e 05 34 00        ADD        AX,0x34
       1000:0161 8e c0           MOV        ES,AX
       1000:0163 eb be           JMP        LAB_1000_0123
                             LAB_1000_0165                                   XREF[2]:     1000:011b(j), 1000:014b(j)  
       1000:0165 8b 46 06        MOV        AX,word ptr [BP + param_1]
       1000:0168 8b 56 08        MOV        DX,word ptr [BP + param_1+0x2]
       1000:016b 5e              POP        SI
       1000:016c 5f              POP        DI
       1000:016d 1f              POP        DS
       1000:016e 5d              POP        BP
       1000:016f cb              RETF
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined __cdecl16far FUN_1000_0170(undefined4 param_1,
                               assume DS = 0x1008
             undefined         AL:1           <RETURN>
             undefined4        Stack[0x4]:4   param_1                                 XREF[2,1]:   1000:0179(*), 
                                                                                                   1000:01b0(*), 
                                                                                                   1000:01b3(*)  
             undefined2        Stack[0x8]:2   param_2                                 XREF[1]:     1000:018e(*)  
             undefined2        Stack[0xa]:2   param_3                                 XREF[1]:     1000:0173(*)  
                             FUN_1000_0170                                   XREF[1]:     FUN_1000_13ba:1000:13c7(c)  
       1000:0170 55              PUSH       BP
       1000:0171 8b ec           MOV        BP,SP
       1000:0173 8b 4e 0c        MOV        CX,word ptr [BP + param_3]
       1000:0176 e3 38           JCXZ       LAB_1000_01b0
       1000:0178 57              PUSH       DI
       1000:0179 c4 7e 06        LES        DI,[BP + param_1]
       1000:017c 8b d7           MOV        DX,DI
       1000:017e f7 da           NEG        DX
       1000:0180 74 0c           JZ         LAB_1000_018e
       1000:0182 2b d1           SUB        DX,CX
       1000:0184 1b db           SBB        BX,BX
       1000:0186 23 d3           AND        DX,BX
       1000:0188 03 d1           ADD        DX,CX
       1000:018a 87 d1           XCHG       CX,DX
       1000:018c 2b d1           SUB        DX,CX
                             LAB_1000_018e                                   XREF[1]:     1000:0180(j)  
       1000:018e 8b 46 0a        MOV        AX,word ptr [BP + param_2]
       1000:0191 8a e0           MOV        AH,AL
       1000:0193 d1 e9           SHR        CX,0x1
       1000:0195 f3 ab           STOSW.REP  ES:DI
       1000:0197 13 c9           ADC        CX,CX
       1000:0199 f3 aa           STOSB.REP  ES:DI
       1000:019b 87 d1           XCHG       CX,DX
       1000:019d e3 10           JCXZ       LAB_1000_01af
       1000:019f 8c c3           MOV        BX,ES
       1000:01a1 81 c3 34 00     ADD        BX,0x34
       1000:01a5 8e c3           MOV        ES,BX
       1000:01a7 d1 e9           SHR        CX,0x1
       1000:01a9 f3 ab           STOSW.REP  ES:DI
       1000:01ab 13 c9           ADC        CX,CX
       1000:01ad f3 aa           STOSB.REP  ES:DI
                             LAB_1000_01af                                   XREF[1]:     1000:019d(j)  
       1000:01af 5f              POP        DI
                             LAB_1000_01b0                                   XREF[1]:     1000:0176(j)  
       1000:01b0 8b 46 06        MOV        AX,word ptr [BP + param_1]
       1000:01b3 8b 56 08        MOV        DX,word ptr [BP + param_1+0x2]
       1000:01b6 5d              POP        BP
       1000:01b7 cb              RETF
                             DAT_1000_01b8                                   XREF[4]:     entry:1000:0241(R), 
                                                                                          entry:1000:025b(R), 
                                                                                          FUN_1000_0607:1000:0617(R), 
                                                                                          FUN_1000_0756:1000:0762(R)  
       1000:01b8 48 00           undefined2 0048h
       1000:01ba 50              ??         50h    P
       1000:01bb 53              ??         53h    S
       1000:01bc 51              ??         51h    Q
       1000:01bd 52              ??         52h    R
       1000:01be 06              ??         06h
       1000:01bf b8              ??         B8h
       1000:01c0 48              ??         48h    H
       1000:01c1 00              ??         00h
       1000:01c2 0b              ??         0Bh
       1000:01c3 c0              ??         C0h
       1000:01c4 79              ??         79h    y
       1000:01c5 12              ??         12h
       1000:01c6 07              ??         07h
       1000:01c7 5a              ??         5Ah    Z
       1000:01c8 59              ??         59h    Y
       1000:01c9 5b              ??         5Bh    [
       1000:01ca 58              ??         58h    X
       1000:01cb 9a              ??         9Ah
       1000:01cc 27              ??         27h    '
       1000:01cd 00              ??         00h
       1000:01ce 11              ??         11h
       1000:01cf 10              ??         10h
       1000:01d0 eb              ??         EBh
       1000:01d1 04              ??         04h
       1000:01d2 90              ??         90h
       1000:01d3 33              ??         33h    3
       1000:01d4 c0              ??         C0h
       1000:01d5 cb              ??         CBh
       1000:01d6 eb              ??         EBh
       1000:01d7 24              ??         24h    $
       1000:01d8 90              ??         90h
       1000:01d9 90              ??         90h
       1000:01da eb              ??         EBh
       1000:01db 0e              ??         0Eh
       1000:01dc 57              ??         57h    W
       1000:01dd 9a              ??         9Ah
       1000:01de 28              ??         28h    (
       1000:01df 00              ??         00h
       1000:01e0 10              ??         10h
       1000:01e1 10              ??         10h
       1000:01e2 48              ??         48h    H
       1000:01e3 74              ??         74h    t
       1000:01e4 05              ??         05h
       1000:01e5 40              ??         40h    @
       1000:01e6 83              ??         83h
       1000:01e7 c4              ??         C4h
       1000:01e8 0a              ??         0Ah
       1000:01e9 cb              ??         CBh
       1000:01ea 07              ??         07h
       1000:01eb 5a              ??         5Ah    Z
       1000:01ec 59              ??         59h    Y
       1000:01ed 5b              ??         5Bh    [
       1000:01ee 58              ??         58h    X
       1000:01ef eb              ??         EBh
       1000:01f0 0b              ??         0Bh
       1000:01f1 43              ??         43h    C
       1000:01f2 44              ??         44h    D
       1000:01f3 44              ??         44h    D
       1000:01f4 01              ??         01h
       1000:01f5 00              ??         00h
       1000:01f6 16              ??         16h
       1000:01f7 00              ??         00h
       1000:01f8 1e              ??         1Eh
       1000:01f9 00              ??         00h
       1000:01fa 42              ??         42h    B
       1000:01fb 00              ??         00h
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined __cdecl16far entry()
                               assume DS = 0x1008
             undefined         AL:1           <RETURN>
                             entry                                           XREF[1]:     Entry Point(*)  
       1000:01fc 8c d8           MOV        AX,DS
       1000:01fe 90              NOP
       1000:01ff 45              INC        BP
       1000:0200 55              PUSH       BP
       1000:0201 8b ec           MOV        BP,SP
       1000:0203 1e              PUSH       DS
       1000:0204 8e d8           MOV        DS,AX
       1000:0206 57              PUSH       DI
       1000:0207 56              PUSH       SI
       1000:0208 89 3e 24 01     MOV        word ptr [DAT_1008_0124],DI
       1000:020c 8c 1e 26 01     MOV        word ptr [DAT_1008_0126],DS
       1000:0210 89 0e 28 01     MOV        word ptr [DAT_1008_0128],CX
       1000:0214 89 1e 2a 01     MOV        word ptr [DAT_1008_012a],BX
       1000:0218 89 36 2c 01     MOV        word ptr [DAT_1008_012c],SI
       1000:021c e3 0e           JCXZ       LAB_1000_022c
       1000:021e 1e              PUSH       DS
       1000:021f 33 c0           XOR        AX,AX
       1000:0221 50              PUSH       AX
       1000:0222 51              PUSH       CX
       1000:0223 9a 08 00        CALLF      KERNEL::LOCALINIT                                undefined LOCALINIT()
                 10 10
       1000:0228 0b c0           OR         AX,AX
       1000:022a 74 69           JZ         LAB_1000_0295
                             LAB_1000_022c                                   XREF[1]:     1000:021c(j)  
       1000:022c b8 ff ff        MOV        AX,0xffff
       1000:022f 50              PUSH       AX
       1000:0230 9a 24 00        CALLF      KERNEL::LOCKSEGMENT                              undefined LOCKSEGMENT()
                 10 10
       1000:0235 9a 04 00        CALLF      KERNEL::GETVERSION                               undefined GETVERSION()
                 10 10
       1000:023a 86 c4           XCHG       AH,AL
       1000:023c a3 4a 01        MOV        [DAT_1008_014a],AX
       1000:023f b4 30           MOV        AH,0x30
       1000:0241 2e f7 06        TEST       word ptr CS:[DAT_1000_01b8],0x1                  = 0048h
                 b8 01 01 00
       1000:0248 74 07           JZ         LAB_1000_0251
       1000:024a 9a 30 00        CALLF      KERNEL::DOS3CALL                                 undefined DOS3CALL()
                 10 10
       1000:024f eb 02           JMP        LAB_1000_0253
                             LAB_1000_0251                                   XREF[1]:     1000:0248(j)  
       1000:0251 cd 21           INT        0x21
                             LAB_1000_0253                                   XREF[1]:     1000:024f(j)  
       1000:0253 a3 4e 01        MOV        [DAT_1008_014e],AX
       1000:0256 86 c4           XCHG       AH,AL
       1000:0258 a3 4c 01        MOV        [DAT_1008_014c],AX
       1000:025b 2e f7 06        TEST       word ptr CS:[DAT_1000_01b8],0x1                  = 0048h
                 b8 01 01 00
       1000:0262 75 05           JNZ        LAB_1000_0269
       1000:0264 b0 00           MOV        AL,0x0
       1000:0266 a2 51 01        MOV        [DAT_1008_0151],AL                               = 01h
                             LAB_1000_0269                                   XREF[1]:     1000:0262(j)  
       1000:0269 9a b6 02        CALLF      FUN_1000_02b6                                    undefined FUN_1000_02b6()
                 00 10
       1000:026e 9a ea 03        CALLF      FUN_1000_03ea                                    undefined FUN_1000_03ea()
                 00 10
       1000:0273 fe 06 2e 01     INC        byte ptr [DAT_1008_012e]
       1000:0277 ff 36 72 01     PUSH       word ptr [DAT_1008_0172]
       1000:027b ff 36 70 01     PUSH       word ptr [DAT_1008_0170]
       1000:027f ff 36 6e 01     PUSH       word ptr [DAT_1008_016e]
       1000:0283 ff 36 6c 01     PUSH       word ptr [DAT_1008_016c]
       1000:0287 ff 36 6a 01     PUSH       word ptr [DAT_1008_016a]
       1000:028b 9a 9a 03        CALLF      FUN_1000_039a                                    undefined FUN_1000_039a()
                 00 10
       1000:0290 83 c4 0a        ADD        SP,0xa
       1000:0293 5e              POP        SI
       1000:0294 5f              POP        DI
                             LAB_1000_0295                                   XREF[1]:     1000:022a(j)  
       1000:0295 83 ed 02        SUB        BP,0x2
       1000:0298 8b e5           MOV        SP,BP
       1000:029a 1f              POP        DS
       1000:029b 5d              POP        BP
       1000:029c 4d              DEC        BP
       1000:029d cb              RETF
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined __stdcall16far FUN_1000_029e()
                               assume DS = 0x1008
             undefined         AL:1           <RETURN>
                             FUN_1000_029e                                   XREF[1]:     FUN_1000_039a:1000:03b8(c)  
       1000:029e 8c d8           MOV        AX,DS
       1000:02a0 90              NOP
       1000:02a1 45              INC        BP
       1000:02a2 55              PUSH       BP
       1000:02a3 8b ec           MOV        BP,SP
       1000:02a5 1e              PUSH       DS
       1000:02a6 8e d8           MOV        DS,AX
       1000:02a8 b8 01 00        MOV        AX,0x1
       1000:02ab 83 ed 02        SUB        BP,0x2
       1000:02ae 8b e5           MOV        SP,BP
       1000:02b0 1f              POP        DS
       1000:02b1 5d              POP        BP
       1000:02b2 4d              DEC        BP
       1000:02b3 ca 0a 00        RETF       0xa
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined __cdecl16far FUN_1000_02b6()
                               assume DS = 0x1008
             undefined         AL:1           <RETURN>
                             FUN_1000_02b6                                   XREF[1]:     entry:1000:0269(c)  
       1000:02b6 8c d8           MOV        AX,DS
       1000:02b8 90              NOP
       1000:02b9 45              INC        BP
       1000:02ba 55              PUSH       BP
       1000:02bb 8b ec           MOV        BP,SP
       1000:02bd 1e              PUSH       DS
       1000:02be 8e d8           MOV        DS,AX
       1000:02c0 8b 0e 98 01     MOV        CX,word ptr [DAT_1008_0198]
       1000:02c4 e3 14           JCXZ       LAB_1000_02da
       1000:02c6 33 f6           XOR        SI,SI
       1000:02c8 a1 9a 01        MOV        AX,[DAT_1008_019a]
       1000:02cb 8b 16 9c 01     MOV        DX,word ptr [DAT_1008_019c]
       1000:02cf 33 db           XOR        BX,BX
       1000:02d1 ff 1e 96 01     CALLF      [0x196]=>DAT_1008_0198
       1000:02d5 73 03           JNC        LAB_1000_02da
       1000:02d7 e9 a8 01        JMP        FUN_1000_0482                                    undefined FUN_1000_0482()
                             -- Flow Override: CALL_RETURN (CALL_TERMINATOR)
                             LAB_1000_02da                                   XREF[2]:     1000:02c4(j), 1000:02d5(j)  
       1000:02da be a2 01        MOV        SI,0x1a2
       1000:02dd bf a2 01        MOV        DI,0x1a2
       1000:02e0 e8 a3 00        CALL       FUN_1000_0386                                    undefined FUN_1000_0386()
       1000:02e3 be a2 01        MOV        SI,0x1a2
       1000:02e6 bf a2 01        MOV        DI,0x1a2
       1000:02e9 e8 9a 00        CALL       FUN_1000_0386                                    undefined FUN_1000_0386()
       1000:02ec be a2 01        MOV        SI,0x1a2
       1000:02ef bf a2 01        MOV        DI,0x1a2
       1000:02f2 e8 91 00        CALL       FUN_1000_0386                                    undefined FUN_1000_0386()
       1000:02f5 83 ed 02        SUB        BP,0x2
       1000:02f8 8b e5           MOV        SP,BP
       1000:02fa 1f              POP        DS
       1000:02fb 5d              POP        BP
       1000:02fc 4d              DEC        BP
       1000:02fd cb              RETF
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined __cdecl16far FUN_1000_02fe()
                               assume DS = 0x1008
             undefined         AL:1           <RETURN>
                             FUN_1000_02fe                                   XREF[1]:     WEP:1000:0080(c)  
       1000:02fe 8c d8           MOV        AX,DS
       1000:0300 90              NOP
       1000:0301 45              INC        BP
       1000:0302 55              PUSH       BP
       1000:0303 8b ec           MOV        BP,SP
       1000:0305 1e              PUSH       DS
       1000:0306 8e d8           MOV        DS,AX
       1000:0308 56              PUSH       SI
       1000:0309 57              PUSH       DI
       1000:030a b9 00 01        MOV        CX,0x100
       1000:030d eb 0f           JMP        LAB_1000_031e
       1000:030f 8c              ??         8Ch
       1000:0310 d8              ??         D8h
       1000:0311 90              ??         90h
       1000:0312 45              ??         45h    E
       1000:0313 55              ??         55h    U
       1000:0314 8b              ??         8Bh
       1000:0315 ec              ??         ECh
       1000:0316 1e              ??         1Eh
       1000:0317 8e              ??         8Eh
       1000:0318 d8              ??         D8h
       1000:0319 56              ??         56h    V
       1000:031a 57              ??         57h    W
       1000:031b b9              ??         B9h
       1000:031c 01              ??         01h
       1000:031d 01              ??         01h
                             LAB_1000_031e                                   XREF[1]:     1000:030d(j)  
       1000:031e 88 2e 7b 01     MOV        byte ptr [DAT_1008_017b],CH
       1000:0322 51              PUSH       CX
       1000:0323 0a c9           OR         CL,CL
       1000:0325 75 12           JNZ        LAB_1000_0339
       1000:0327 be 82 02        MOV        SI,0x282
       1000:032a bf 82 02        MOV        DI,0x282
       1000:032d e8 56 00        CALL       FUN_1000_0386                                    undefined FUN_1000_0386()
       1000:0330 be a2 01        MOV        SI,0x1a2
       1000:0333 bf a2 01        MOV        DI,0x1a2
       1000:0336 e8 4d 00        CALL       FUN_1000_0386                                    undefined FUN_1000_0386()
                             LAB_1000_0339                                   XREF[1]:     1000:0325(j)  
       1000:0339 be a2 01        MOV        SI,0x1a2
       1000:033c bf a2 01        MOV        DI,0x1a2
       1000:033f e8 44 00        CALL       FUN_1000_0386                                    undefined FUN_1000_0386()
       1000:0342 be a2 01        MOV        SI,0x1a2
       1000:0345 bf a2 01        MOV        DI,0x1a2
       1000:0348 e8 3b 00        CALL       FUN_1000_0386                                    undefined FUN_1000_0386()
       1000:034b e8 8a 04        CALL       FUN_1000_07d8                                    undefined FUN_1000_07d8()
       1000:034e e8 47 01        CALL       FUN_1000_0498                                    undefined FUN_1000_0498()
       1000:0351 58              POP        AX
       1000:0352 5f              POP        DI
       1000:0353 5e              POP        SI
       1000:0354 83 ed 02        SUB        BP,0x2
       1000:0357 8b e5           MOV        SP,BP
       1000:0359 1f              POP        DS
       1000:035a 5d              POP        BP
       1000:035b 4d              DEC        BP
       1000:035c cb              RETF
       1000:035d 8b              ??         8Bh
       1000:035e 0e              ??         0Eh
       1000:035f 98              ??         98h
       1000:0360 01              ??         01h
       1000:0361 e3              ??         E3h
       1000:0362 07              ??         07h
       1000:0363 bb              ??         BBh
       1000:0364 02              ??         02h
       1000:0365 00              ??         00h
       1000:0366 ff              ??         FFh
       1000:0367 1e              ??         1Eh
       1000:0368 96              ??         96h
       1000:0369 01              ??         01h
       1000:036a 1e              ??         1Eh
       1000:036b c5              ??         C5h
       1000:036c 16              ??         16h
       1000:036d 38              ??         38h    8
       1000:036e 01              ??         01h
       1000:036f b8              ??         B8h
       1000:0370 00              ??         00h
       1000:0371 25              ??         25h    %
       1000:0372 2e              ??         2Eh    .
       1000:0373 f7              ??         F7h
       1000:0374 06              ??         06h
       1000:0375 b8              ??         B8h
       1000:0376 01              ??         01h
       1000:0377 01              ??         01h
       1000:0378 00              ??         00h
       1000:0379 74              ??         74h    t
       1000:037a 07              ??         07h
       1000:037b 9a              ??         9Ah
       1000:037c 30              ??         30h    0
       1000:037d 00              ??         00h
       1000:037e 10              ??         10h
       1000:037f 10              ??         10h
       1000:0380 eb              ??         EBh
       1000:0381 02              ??         02h
       1000:0382 cd              ??         CDh
       1000:0383 21              ??         21h    !
       1000:0384 1f              ??         1Fh
       1000:0385 c3              ??         C3h
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined __cdecl16near FUN_1000_0386()
                               assume DS = 0x1008
             undefined         AL:1           <RETURN>
                             FUN_1000_0386                                   XREF[9]:     FUN_1000_02b6:1000:02e0(c), 
                                                                                          FUN_1000_02b6:1000:02e9(c), 
                                                                                          FUN_1000_02b6:1000:02f2(c), 
                                                                                          FUN_1000_02fe:1000:032d(c), 
                                                                                          FUN_1000_02fe:1000:0336(c), 
                                                                                          FUN_1000_02fe:1000:033f(c), 
                                                                                          FUN_1000_02fe:1000:0348(c), 
                                                                                          1000:0392(j), 1000:0396(j)  
       1000:0386 3b f7           CMP        SI,DI
       1000:0388 73 0e           JNC        LAB_1000_0398
       1000:038a 83 ef 04        SUB        DI,0x4
       1000:038d 8b 05           MOV        AX,word ptr [DI]
       1000:038f 0b 45 02        OR         AX,word ptr [DI + 0x2]
       1000:0392 74 f2           JZ         FUN_1000_0386
       1000:0394 ff 1d           CALLF      [DI]
       1000:0396 eb ee           JMP        FUN_1000_0386
                             LAB_1000_0398                                   XREF[1]:     1000:0388(j)  
       1000:0398 c3              RET
       1000:0399 00              ??         00h
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined __cdecl16far FUN_1000_039a()
                               assume DS = 0x1008
             undefined         AL:1           <RETURN>
                             FUN_1000_039a                                   XREF[1]:     entry:1000:028b(c)  
       1000:039a 8c d8           MOV        AX,DS
       1000:039c 90              NOP
       1000:039d 45              INC        BP
       1000:039e 55              PUSH       BP
       1000:039f 8b ec           MOV        BP,SP
       1000:03a1 1e              PUSH       DS
       1000:03a2 8e d8           MOV        DS,AX
       1000:03a4 ff 36 24 01     PUSH       word ptr [DAT_1008_0124]
       1000:03a8 ff 36 26 01     PUSH       word ptr [DAT_1008_0126]
       1000:03ac ff 36 28 01     PUSH       word ptr [DAT_1008_0128]
       1000:03b0 ff 36 2c 01     PUSH       word ptr [DAT_1008_012c]
       1000:03b4 ff 36 2a 01     PUSH       word ptr [DAT_1008_012a]
       1000:03b8 9a 9e 02        CALLF      FUN_1000_029e                                    undefined FUN_1000_029e()
                 00 10
       1000:03bd 83 ed 02        SUB        BP,0x2
       1000:03c0 8b e5           MOV        SP,BP
       1000:03c2 1f              POP        DS
       1000:03c3 5d              POP        BP
       1000:03c4 4d              DEC        BP
       1000:03c5 cb              RETF
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined __cdecl16far FUN_1000_03c6()
                               assume DS = 0x1008
             undefined         AL:1           <RETURN>
                             FUN_1000_03c6                                   XREF[1]:     FUN_1000_04f2:1000:04f5(c)  
       1000:03c6 8c d8           MOV        AX,DS
       1000:03c8 90              NOP
       1000:03c9 45              INC        BP
       1000:03ca 55              PUSH       BP
       1000:03cb 8b ec           MOV        BP,SP
       1000:03cd 1e              PUSH       DS
       1000:03ce 8e d8           MOV        DS,AX
       1000:03d0 b8 fc 00        MOV        AX,0xfc
       1000:03d3 50              PUSH       AX
       1000:03d4 0e              PUSH       CS
       1000:03d5 e8 f9 00        CALL       FUN_1000_04d1                                    undefined FUN_1000_04d1()
       1000:03d8 b8 ff 00        MOV        AX,0xff
       1000:03db 50              PUSH       AX
       1000:03dc 0e              PUSH       CS
       1000:03dd e8 f1 00        CALL       FUN_1000_04d1                                    undefined FUN_1000_04d1()
       1000:03e0 83 ed 02        SUB        BP,0x2
       1000:03e3 8b e5           MOV        SP,BP
       1000:03e5 1f              POP        DS
       1000:03e6 5d              POP        BP
       1000:03e7 4d              DEC        BP
       1000:03e8 cb              RETF
       1000:03e9 00              ??         00h
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined __cdecl16far FUN_1000_03ea()
                               assume DS = 0x1008
             undefined         AL:1           <RETURN>
             undefined2        Stack[-0x6]:2  local_6                                 XREF[2]:     1000:0408(*), 
                                                                                                   1000:0464(*)  
             undefined2        Stack[-0x8]:2  local_8                                 XREF[3]:     1000:0449(*), 
                                                                                                   1000:0459(*), 
                                                                                                   1000:046f(*)  
             undefined2        Stack[-0xa]:2  local_a                                 XREF[1]:     1000:040b(*)  
                             FUN_1000_03ea                                   XREF[1]:     entry:1000:026e(c)  
       1000:03ea 8c d8           MOV        AX,DS
       1000:03ec 90              NOP
       1000:03ed 45              INC        BP
       1000:03ee 55              PUSH       BP
       1000:03ef 8b ec           MOV        BP,SP
       1000:03f1 1e              PUSH       DS
       1000:03f2 8e d8           MOV        DS,AX
       1000:03f4 83 ec 06        SUB        SP,0x6
       1000:03f7 1e              PUSH       DS
       1000:03f8 9a 38 00        CALLF      KERNEL::GETDOSENVIRONMENT                        undefined GETDOSENVIRONMENT()
                 10 10
       1000:03fd 0b c0           OR         AX,AX
       1000:03ff 74 03           JZ         LAB_1000_0404
       1000:0401 ba 00 00        MOV        DX,0x0
                             LAB_1000_0404                                   XREF[1]:     1000:03ff(j)  
       1000:0404 8b da           MOV        BX,DX
       1000:0406 8e c2           MOV        ES,DX
       1000:0408 8c 46 fc        MOV        word ptr [BP + local_6],ES
       1000:040b 8c 5e f8        MOV        word ptr [BP + local_a],DS
       1000:040e 33 c0           XOR        AX,AX
       1000:0410 33 f6           XOR        SI,SI
       1000:0412 33 ff           XOR        DI,DI
       1000:0414 b9 ff ff        MOV        CX,0xffff
       1000:0417 0b db           OR         BX,BX
       1000:0419 74 0e           JZ         LAB_1000_0429
       1000:041b 26 80 3e        CMP        byte ptr ES:[0x0],0x0
                 00 00 00
       1000:0421 74 06           JZ         LAB_1000_0429
                             LAB_1000_0423                                   XREF[1]:     1000:0427(j)  
       1000:0423 f2 ae           SCASB.RE   ES:DI
       1000:0425 46              INC        SI
       1000:0426 ae              SCASB      ES:DI
       1000:0427 75 fa           JNZ        LAB_1000_0423
                             LAB_1000_0429                                   XREF[2]:     1000:0419(j), 1000:0421(j)  
       1000:0429 8b c7           MOV        AX,DI
       1000:042b 40              INC        AX
       1000:042c 24 fe           AND        AL,0xfe
       1000:042e 46              INC        SI
       1000:042f 8b fe           MOV        DI,SI
       1000:0431 d1 e6           SHL        SI,0x1
       1000:0433 d1 e6           SHL        SI,0x1
       1000:0435 b9 09 00        MOV        CX,0x9
       1000:0438 e8 f9 00        CALL       FUN_1000_0534                                    undefined FUN_1000_0534()
       1000:043b 52              PUSH       DX
       1000:043c 50              PUSH       AX
       1000:043d 8b c6           MOV        AX,SI
       1000:043f e8 f2 00        CALL       FUN_1000_0534                                    undefined FUN_1000_0534()
       1000:0442 a3 70 01        MOV        [DAT_1008_0170],AX
       1000:0445 89 16 72 01     MOV        word ptr [DAT_1008_0172],DX
       1000:0449 89 56 fa        MOV        word ptr [BP + local_8],DX
       1000:044c 06              PUSH       ES
       1000:044d 1f              POP        DS
       1000:044e 8b cf           MOV        CX,DI
       1000:0450 8b d8           MOV        BX,AX
       1000:0452 33 f6           XOR        SI,SI
       1000:0454 5f              POP        DI
       1000:0455 07              POP        ES
       1000:0456 49              DEC        CX
       1000:0457 e3 16           JCXZ       LAB_1000_046f
                             LAB_1000_0459                                   XREF[1]:     1000:046d(j)  
       1000:0459 8e 5e fa        MOV        DS,word ptr [BP + local_8]
       1000:045c 89 3f           MOV        word ptr [BX],DI
       1000:045e 8c 47 02        MOV        word ptr [BX + 0x2],ES
       1000:0461 83 c3 04        ADD        BX,0x4
       1000:0464 8e 5e fc        MOV        DS,word ptr [BP + local_6]
                             LAB_1000_0467                                   XREF[1]:     1000:046b(j)  
       1000:0467 ac              LODSB      SI
       1000:0468 aa              STOSB      ES:DI
       1000:0469 0a c0           OR         AL,AL
       1000:046b 75 fa           JNZ        LAB_1000_0467
       1000:046d e2 ea           LOOP       LAB_1000_0459
                             LAB_1000_046f                                   XREF[1]:     1000:0457(j)  
       1000:046f 8e 5e fa        MOV        DS,word ptr [BP + local_8]
       1000:0472 89 0f           MOV        word ptr [BX],CX
       1000:0474 89 4f 02        MOV        word ptr [BX + 0x2],CX
       1000:0477 1f              POP        DS
       1000:0478 83 ed 02        SUB        BP,0x2
       1000:047b 8b e5           MOV        SP,BP
       1000:047d 1f              POP        DS
       1000:047e 5d              POP        BP
       1000:047f 4d              DEC        BP
       1000:0480 cb              RETF
       1000:0481 00              ??         00h
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined FUN_1000_0482()
                               assume DS = 0x1008
             undefined         AL:1           <RETURN>
                             FUN_1000_0482                                   XREF[1]:     FUN_1000_02b6:1000:02d7(c)  
       1000:0482 b8 02 00        MOV        AX,0x2
       1000:0485 e9 6a 00        JMP        FUN_1000_04f2                                    undefined FUN_1000_04f2()
                             -- Flow Override: CALL_RETURN (CALL_TERMINATOR)
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined __cdecl16far FUN_1000_0488()
                               assume DS = 0x1008
             undefined         AL:1           <RETURN>
                             FUN_1000_0488                                   XREF[1]:     FUN_1000_0576:1000:05a2(c)  
       1000:0488 2e 80 3e        CMP        byte ptr CS:[___EXPORTEDSTUB],0xb8
                 62 05 b8
       1000:048e 74 03           JZ         LAB_1000_0493
       1000:0490 8c d0           MOV        AX,SS
       1000:0492 cb              RETF
                             LAB_1000_0493                                   XREF[1]:     1000:048e(j)  
       1000:0493 2e a1 63 05     MOV        AX,CS:[___EXPORTEDSTUB+1]
       1000:0497 cb              RETF
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined __cdecl16near FUN_1000_0498()
                               assume DS = 0x1008
             undefined         AL:1           <RETURN>
                             FUN_1000_0498                                   XREF[1]:     FUN_1000_02fe:1000:034e(c)  
       1000:0498 c3              RET
       1000:0499 00              ??         00h
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined __stdcall16far FUN_1000_049a(undefined2 param_1)
                               assume DS = 0x1008
             undefined         AL:1           <RETURN>
             undefined2        Stack[0x4]:2   param_1                                 XREF[1]:     1000:04a8(*)  
                             FUN_1000_049a                                   XREF[1]:     FUN_1000_04f2:1000:04fd(c)  
       1000:049a 8c d8           MOV        AX,DS
       1000:049c 90              NOP
       1000:049d 45              INC        BP
       1000:049e 55              PUSH       BP
       1000:049f 8b ec           MOV        BP,SP
       1000:04a1 1e              PUSH       DS
       1000:04a2 8e d8           MOV        DS,AX
       1000:04a4 56              PUSH       SI
       1000:04a5 57              PUSH       DI
       1000:04a6 1e              PUSH       DS
       1000:04a7 07              POP        ES
       1000:04a8 8b 56 06        MOV        DX,word ptr [BP + param_1]
       1000:04ab be aa 01        MOV        SI,0x1aa
                             LAB_1000_04ae                                   XREF[1]:     1000:04c1(j)  
       1000:04ae ad              LODSW      SI=>DAT_1008_01aa                                = "6000\r\n- stack overflow\r\n"
       1000:04af 3b c2           CMP        AX,DX
       1000:04b1 74 10           JZ         LAB_1000_04c3
       1000:04b3 40              INC        AX
       1000:04b4 96              XCHG       AX,SI
       1000:04b5 74 0c           JZ         LAB_1000_04c3
       1000:04b7 97              XCHG       AX,DI
       1000:04b8 33 c0           XOR        AX,AX
       1000:04ba b9 ff ff        MOV        CX,0xffff
       1000:04bd f2 ae           SCASB.RE   ES:DI
       1000:04bf 8b f7           MOV        SI,DI
       1000:04c1 eb eb           JMP        LAB_1000_04ae
                             LAB_1000_04c3                                   XREF[2]:     1000:04b1(j), 1000:04b5(j)  
       1000:04c3 96              XCHG       AX,SI
       1000:04c4 5f              POP        DI
       1000:04c5 5e              POP        SI
       1000:04c6 83 ed 02        SUB        BP,0x2
       1000:04c9 8b e5           MOV        SP,BP
       1000:04cb 1f              POP        DS
       1000:04cc 5d              POP        BP
       1000:04cd 4d              DEC        BP
       1000:04ce ca 02 00        RETF       0x2
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined __stdcall16far FUN_1000_04d1()
                               assume DS = 0x1008
             undefined         AL:1           <RETURN>
                             FUN_1000_04d1                                   XREF[3]:     FUN_1000_03c6:1000:03d5(c), 
                                                                                          FUN_1000_03c6:1000:03dd(c), 
                                                                                          FUN_1000_04f2:1000:04f9(c)  
       1000:04d1 8c d8           MOV        AX,DS
       1000:04d3 90              NOP
       1000:04d4 45              INC        BP
       1000:04d5 55              PUSH       BP
       1000:04d6 8b ec           MOV        BP,SP
       1000:04d8 1e              PUSH       DS
       1000:04d9 8e d8           MOV        DS,AX
       1000:04db 57              PUSH       DI
       1000:04dc 5f              POP        DI
       1000:04dd 83 ed 02        SUB        BP,0x2
       1000:04e0 8b e5           MOV        SP,BP
       1000:04e2 1f              POP        DS
       1000:04e3 5d              POP        BP
       1000:04e4 4d              DEC        BP
       1000:04e5 ca 02 00        RETF       0x2
       1000:04e8 9a              ??         9Ah
       1000:04e9 88              ??         88h
       1000:04ea 04              ??         04h
       1000:04eb 00              ??         00h
       1000:04ec 10              ??         10h
       1000:04ed 8e              ??         8Eh
       1000:04ee d8              ??         D8h
       1000:04ef b8              ??         B8h
       1000:04f0 03              ??         03h
       1000:04f1 00              ??         00h
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined FUN_1000_04f2()
                               assume DS = 0x1008
             undefined         AL:1           <RETURN>
                             FUN_1000_04f2                                   XREF[4]:     FUN_1000_0482:1000:0485(c), 
                                                                                          FUN_1000_0534:1000:055a(c), 
                                                                                          FUN_1000_0607:1000:0665(c), 
                                                                                          FUN_1000_0756:1000:07d0(c)  
       1000:04f2 50              PUSH       AX
       1000:04f3 50              PUSH       AX
       1000:04f4 0e              PUSH       CS
       1000:04f5 e8 ce fe        CALL       FUN_1000_03c6                                    undefined FUN_1000_03c6()
       1000:04f8 0e              PUSH       CS
       1000:04f9 e8 d5 ff        CALL       FUN_1000_04d1                                    undefined FUN_1000_04d1()
       1000:04fc 0e              PUSH       CS
       1000:04fd e8 9a ff        CALL       FUN_1000_049a                                    undefined FUN_1000_049a(undefine
       1000:0500 33 db           XOR        BX,BX
       1000:0502 0b c0           OR         AX,AX
       1000:0504 74 1d           JZ         LAB_1000_0523
       1000:0506 8b f8           MOV        DI,AX
       1000:0508 b8 09 00        MOV        AX,0x9
       1000:050b 80 3d 4d        CMP        byte ptr [DI],0x4d
       1000:050e 75 03           JNZ        LAB_1000_0513
       1000:0510 b8 0f 00        MOV        AX,0xf
                             LAB_1000_0513                                   XREF[1]:     1000:050e(j)  
       1000:0513 03 f8           ADD        DI,AX
       1000:0515 57              PUSH       DI
       1000:0516 1e              PUSH       DS
       1000:0517 07              POP        ES
       1000:0518 b0 0d           MOV        AL,0xd
       1000:051a b9 22 00        MOV        CX,0x22
       1000:051d f2 ae           SCASB.RE   ES:DI
       1000:051f 88 5d ff        MOV        byte ptr [DI + -0x1],BL
       1000:0522 58              POP        AX
                             LAB_1000_0523                                   XREF[1]:     1000:0504(j)  
       1000:0523 53              PUSH       BX
       1000:0524 1e              PUSH       DS
       1000:0525 50              PUSH       AX
       1000:0526 9a 3c 00        CALLF      KERNEL::FATALAPPEXIT                             undefined FATALAPPEXIT()
                 10 10
       1000:052b b8 ff 00        MOV        AX,0xff
       1000:052e 50              PUSH       AX
       1000:052f 9a 00 00        CALLF      KERNEL::FATALEXIT                                undefined FATALEXIT()
                 10 10
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined __cdecl16near FUN_1000_0534()
                               assume DS = 0x1008
             undefined         AL:1           <RETURN>
                             FUN_1000_0534                                   XREF[2]:     FUN_1000_03ea:1000:0438(c), 
                                                                                          FUN_1000_03ea:1000:043f(c)  
       1000:0534 55              PUSH       BP
       1000:0535 8b ec           MOV        BP,SP
       1000:0537 53              PUSH       BX
       1000:0538 06              PUSH       ES
       1000:0539 51              PUSH       CX
       1000:053a b9 00 10        MOV        CX,0x1000
       1000:053d 87 0e 80 01     XCHG       word ptr [DAT_1008_0180],CX                      = 1000h
       1000:0541 51              PUSH       CX
       1000:0542 50              PUSH       AX
       1000:0543 9a af 06        CALLF      FUN_1000_06af                                    undefined FUN_1000_06af(undefine
                 00 10
       1000:0548 5b              POP        BX
       1000:0549 8f 06 80 01     POP        word ptr [DAT_1008_0180]                         = 1000h
       1000:054d 59              POP        CX
       1000:054e 8b da           MOV        BX,DX
       1000:0550 0b d8           OR         BX,AX
       1000:0552 74 04           JZ         LAB_1000_0558
       1000:0554 07              POP        ES
       1000:0555 5b              POP        BX
       1000:0556 eb 05           JMP        LAB_1000_055d
                             LAB_1000_0558                                   XREF[1]:     1000:0552(j)  
       1000:0558 8b c1           MOV        AX,CX
       1000:055a e9 95 ff        JMP        FUN_1000_04f2                                    undefined FUN_1000_04f2()
                             -- Flow Override: CALL_RETURN (CALL_TERMINATOR)
                             LAB_1000_055d                                   XREF[1]:     1000:0556(j)  
       1000:055d 8b e5           MOV        SP,BP
       1000:055f 5d              POP        BP
       1000:0560 c3              RET
       1000:0561 00              ??         00h
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined __cdecl16far ___EXPORTEDSTUB()
                               assume DS = 0x1008
             undefined         AL:1           <RETURN>
             undefined         Stack[-0x4]:1  local_4                                 XREF[1]:     1000:056e(*)  
                             ___EXPORTEDSTUB+1                               XREF[2,1]:   Entry Point(*), 
                             Ordinal_14                                                   FUN_1000_0488:1000:0488(R), 
                             ___EXPORTEDSTUB                                              FUN_1000_0488:1000:0493(R)  
       1000:0562 8c d8           MOV        AX,DS
       1000:0564 90              NOP
       1000:0565 45              INC        BP
       1000:0566 55              PUSH       BP
       1000:0567 8b ec           MOV        BP,SP
       1000:0569 1e              PUSH       DS
       1000:056a 8e d8           MOV        DS,AX
       1000:056c 33 c0           XOR        AX,AX
       1000:056e 8d 66 fe        LEA        SP,[BP + local_4]
       1000:0571 1f              POP        DS
       1000:0572 5d              POP        BP
       1000:0573 4d              DEC        BP
       1000:0574 cb              RETF
       1000:0575 90              ??         90h
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined __cdecl16near FUN_1000_0576()
                               assume DS = 0x1008
             undefined         AL:1           <RETURN>
                             FUN_1000_0576                                   XREF[1]:     FUN_1000_06af:1000:06d9(c)  
       1000:0576 51              PUSH       CX
       1000:0577 57              PUSH       DI
       1000:0578 f6 47 02 01     TEST       byte ptr [BX + 0x2],0x1
       1000:057c 74 68           JZ         LAB_1000_05e6
       1000:057e e8 ec 00        CALL       FUN_1000_066d                                    undefined FUN_1000_066d()
       1000:0581 8b fe           MOV        DI,SI
       1000:0583 8b 04           MOV        AX,word ptr [SI]
       1000:0585 a8 01           TEST       AL,0x1
       1000:0587 74 03           JZ         LAB_1000_058c
       1000:0589 2b c8           SUB        CX,AX
       1000:058b 49              DEC        CX
                             LAB_1000_058c                                   XREF[1]:     1000:0587(j)  
       1000:058c 41              INC        CX
       1000:058d 41              INC        CX
       1000:058e 8b 77 04        MOV        SI,word ptr [BX + 0x4]
       1000:0591 0b f6           OR         SI,SI
       1000:0593 74 51           JZ         LAB_1000_05e6
       1000:0595 03 ce           ADD        CX,SI
       1000:0597 73 09           JNC        LAB_1000_05a2
       1000:0599 33 c0           XOR        AX,AX
       1000:059b ba f0 ff        MOV        DX,0xfff0
       1000:059e e3 35           JCXZ       LAB_1000_05d5
       1000:05a0 eb 44           JMP        LAB_1000_05e6
                             LAB_1000_05a2                                   XREF[1]:     1000:0597(j)  
       1000:05a2 9a 88 04        CALLF      FUN_1000_0488                                    undefined FUN_1000_0488()
                 00 10
       1000:05a7 8e c0           MOV        ES,AX
       1000:05a9 26 a1 80 01     MOV        AX,ES:[0x180]
       1000:05ad 3d 00 10        CMP        AX,0x1000
       1000:05b0 74 16           JZ         LAB_1000_05c8
       1000:05b2 ba 00 80        MOV        DX,0x8000
                             LAB_1000_05b5                                   XREF[1]:     1000:05bb(j)  
       1000:05b5 3b d0           CMP        DX,AX
       1000:05b7 72 06           JC         LAB_1000_05bf
       1000:05b9 d1 ea           SHR        DX,0x1
       1000:05bb 75 f8           JNZ        LAB_1000_05b5
       1000:05bd eb 22           JMP        LAB_1000_05e1
                             LAB_1000_05bf                                   XREF[1]:     1000:05b7(j)  
       1000:05bf 83 fa 08        CMP        DX,0x8
       1000:05c2 72 1d           JC         LAB_1000_05e1
       1000:05c4 d1 e2           SHL        DX,0x1
       1000:05c6 8b c2           MOV        AX,DX
                             LAB_1000_05c8                                   XREF[2]:     1000:05b0(j), 1000:05e4(j)  
       1000:05c8 48              DEC        AX
       1000:05c9 8b d0           MOV        DX,AX
       1000:05cb 03 c1           ADD        AX,CX
       1000:05cd 73 02           JNC        LAB_1000_05d1
       1000:05cf 33 c0           XOR        AX,AX
                             LAB_1000_05d1                                   XREF[1]:     1000:05cd(j)  
       1000:05d1 f7 d2           NOT        DX
       1000:05d3 23 c2           AND        AX,DX
                             LAB_1000_05d5                                   XREF[1]:     1000:059e(j)  
       1000:05d5 52              PUSH       DX
       1000:05d6 e8 2e 00        CALL       FUN_1000_0607                                    undefined FUN_1000_0607()
       1000:05d9 5a              POP        DX
       1000:05da 73 0d           JNC        LAB_1000_05e9
       1000:05dc 83 fa f0        CMP        DX,-0x10
       1000:05df 74 05           JZ         LAB_1000_05e6
                             LAB_1000_05e1                                   XREF[2]:     1000:05bd(j), 1000:05c2(j)  
       1000:05e1 b8 10 00        MOV        AX,0x10
       1000:05e4 eb e2           JMP        LAB_1000_05c8
                             LAB_1000_05e6                                   XREF[4]:     1000:057c(j), 1000:0593(j), 
                                                                                          1000:05a0(j), 1000:05df(j)  
       1000:05e6 f9              STC
       1000:05e7 eb 1b           JMP        LAB_1000_0604
                             LAB_1000_05e9                                   XREF[1]:     1000:05da(j)  
       1000:05e9 8b d0           MOV        DX,AX
       1000:05eb 2b 57 04        SUB        DX,word ptr [BX + 0x4]
       1000:05ee 89 47 04        MOV        word ptr [BX + 0x4],AX
       1000:05f1 89 7f 0a        MOV        word ptr [BX + 0xa],DI
       1000:05f4 8b 77 0c        MOV        SI,word ptr [BX + 0xc]
       1000:05f7 4a              DEC        DX
       1000:05f8 89 14           MOV        word ptr [SI],DX
       1000:05fa 42              INC        DX
       1000:05fb 03 f2           ADD        SI,DX
       1000:05fd c7 04 fe ff     MOV        word ptr [SI],0xfffe
       1000:0601 89 77 0c        MOV        word ptr [BX + 0xc],SI
                             LAB_1000_0604                                   XREF[1]:     1000:05e7(j)  
       1000:0604 5f              POP        DI
       1000:0605 59              POP        CX
       1000:0606 c3              RET
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined __cdecl16near FUN_1000_0607()
                               assume DS = 0x1008
             undefined         AL:1           <RETURN>
                             FUN_1000_0607                                   XREF[1]:     FUN_1000_0576:1000:05d6(c)  
       1000:0607 8b d0           MOV        DX,AX
       1000:0609 f6 47 02 04     TEST       byte ptr [BX + 0x2],0x4
       1000:060d 74 02           JZ         LAB_1000_0611
       1000:060f eb 51           JMP        LAB_1000_0662
                             LAB_1000_0611                                   XREF[1]:     1000:060d(j)  
       1000:0611 52              PUSH       DX
       1000:0612 51              PUSH       CX
       1000:0613 53              PUSH       BX
       1000:0614 8b 77 06        MOV        SI,word ptr [BX + 0x6]
       1000:0617 2e 8b 1e        MOV        BX,word ptr CS:[DAT_1000_01b8]                   = 0048h
                 b8 01
       1000:061c 33 c9           XOR        CX,CX
       1000:061e 0b d2           OR         DX,DX
       1000:0620 75 07           JNZ        LAB_1000_0629
       1000:0622 f7 c3 10 00     TEST       BX,0x10
       1000:0626 75 40           JNZ        LAB_1000_0668
       1000:0628 41              INC        CX
                             LAB_1000_0629                                   XREF[1]:     1000:0620(j)  
       1000:0629 b8 02 20        MOV        AX,0x2002
       1000:062c f7 c3 01 00     TEST       BX,0x1
       1000:0630 75 03           JNZ        LAB_1000_0635
       1000:0632 b8 20 20        MOV        AX,0x2020
                             LAB_1000_0635                                   XREF[1]:     1000:0630(j)  
       1000:0635 56              PUSH       SI
       1000:0636 51              PUSH       CX
       1000:0637 52              PUSH       DX
       1000:0638 50              PUSH       AX
       1000:0639 9a 10 00        CALLF      KERNEL::GLOBALREALLOC                            undefined GLOBALREALLOC()
                 10 10
       1000:063e 0b c0           OR         AX,AX
       1000:0640 74 26           JZ         LAB_1000_0668
       1000:0642 3b c6           CMP        AX,SI
       1000:0644 75 1c           JNZ        LAB_1000_0662
       1000:0646 56              PUSH       SI
       1000:0647 9a 20 00        CALLF      KERNEL::GLOBALSIZE                               undefined GLOBALSIZE()
                 10 10
       1000:064c 0b d0           OR         DX,AX
       1000:064e 74 12           JZ         LAB_1000_0662
       1000:0650 5b              POP        BX
       1000:0651 59              POP        CX
       1000:0652 5a              POP        DX
       1000:0653 8b c2           MOV        AX,DX
       1000:0655 f6 47 02 04     TEST       byte ptr [BX + 0x2],0x4
       1000:0659 74 04           JZ         LAB_1000_065f
       1000:065b 4a              DEC        DX
       1000:065c 89 57 fe        MOV        word ptr [BX + -0x2],DX
                             LAB_1000_065f                                   XREF[1]:     1000:0659(j)  
       1000:065f f8              CLC
       1000:0660 eb 0a           JMP        LAB_1000_066c
                             LAB_1000_0662                                   XREF[3]:     1000:060f(j), 1000:0644(j), 
                                                                                          1000:064e(j)  
       1000:0662 b8 12 00        MOV        AX,0x12
       1000:0665 e9 8a fe        JMP        FUN_1000_04f2                                    undefined FUN_1000_04f2()
                             -- Flow Override: CALL_RETURN (CALL_TERMINATOR)
                             LAB_1000_0668                                   XREF[2]:     1000:0626(j), 1000:0640(j)  
       1000:0668 5b              POP        BX
       1000:0669 59              POP        CX
       1000:066a 5a              POP        DX
       1000:066b f9              STC
                             LAB_1000_066c                                   XREF[1]:     1000:0660(j)  
       1000:066c c3              RET
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined __cdecl16near FUN_1000_066d()
                               assume DS = 0x1008
             undefined         AL:1           <RETURN>
                             FUN_1000_066d                                   XREF[1]:     FUN_1000_0576:1000:057e(c)  
       1000:066d 57              PUSH       DI
       1000:066e 8b 77 0a        MOV        SI,word ptr [BX + 0xa]
       1000:0671 3b 77 0c        CMP        SI,word ptr [BX + 0xc]
       1000:0674 75 03           JNZ        LAB_1000_0679
       1000:0676 8b 77 08        MOV        SI,word ptr [BX + 0x8]
                             LAB_1000_0679                                   XREF[2]:     1000:0674(j), 1000:0685(j)  
       1000:0679 ad              LODSW      SI
       1000:067a 83 f8 fe        CMP        AX,-0x2
       1000:067d 74 08           JZ         LAB_1000_0687
       1000:067f 8b fe           MOV        DI,SI
       1000:0681 24 fe           AND        AL,0xfe
       1000:0683 03 f0           ADD        SI,AX
       1000:0685 eb f2           JMP        LAB_1000_0679
                             LAB_1000_0687                                   XREF[1]:     1000:067d(j)  
       1000:0687 4f              DEC        DI
       1000:0688 4f              DEC        DI
       1000:0689 8b f7           MOV        SI,DI
       1000:068b 5f              POP        DI
       1000:068c c3              RET
       1000:068d 00              ??         00h
       1000:068e 8c              ??         8Ch
       1000:068f d8              ??         D8h
       1000:0690 90              ??         90h
       1000:0691 45              ??         45h    E
       1000:0692 55              ??         55h    U
       1000:0693 8b              ??         8Bh
       1000:0694 ec              ??         ECh
       1000:0695 1e              ??         1Eh
       1000:0696 8e              ??         8Eh
       1000:0697 d8              ??         D8h
       1000:0698 56              ??         56h    V
       1000:0699 c4              ??         C4h
       1000:069a 76              ??         76h    v
       1000:069b 06              ??         06h
       1000:069c 8c              ??         8Ch
       1000:069d c1              ??         C1h
       1000:069e e3              ??         E3h
       1000:069f 05              ??         05h
       1000:06a0 26              ??         26h    &
       1000:06a1 80              ??         80h
       1000:06a2 4c              ??         4Ch    L
       1000:06a3 fe              ??         FEh
       1000:06a4 01              ??         01h
       1000:06a5 5e              ??         5Eh    ^
       1000:06a6 83              ??         83h
       1000:06a7 ed              ??         EDh
       1000:06a8 02              ??         02h
       1000:06a9 8b              ??         8Bh
       1000:06aa e5              ??         E5h
       1000:06ab 1f              ??         1Fh
       1000:06ac 5d              ??         5Dh    ]
       1000:06ad 4d              ??         4Dh    M
       1000:06ae cb              ??         CBh
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined __cdecl16far FUN_1000_06af(undefined2 param_1)
                               assume DS = 0x1008
             undefined         AL:1           <RETURN>
             undefined2        Stack[0x4]:2   param_1                                 XREF[2]:     1000:06bb(*), 
                                                                                                   1000:0739(*)  
                             FUN_1000_06af                                   XREF[1]:     FUN_1000_0534:1000:0543(c)  
       1000:06af 8c d8           MOV        AX,DS
       1000:06b1 90              NOP
       1000:06b2 45              INC        BP
       1000:06b3 55              PUSH       BP
       1000:06b4 8b ec           MOV        BP,SP
       1000:06b6 1e              PUSH       DS
       1000:06b7 8e d8           MOV        DS,AX
       1000:06b9 56              PUSH       SI
       1000:06ba 57              PUSH       DI
                             LAB_1000_06bb                                   XREF[1]:     1000:0748(j)  
       1000:06bb 8b 4e 06        MOV        CX,word ptr [BP + param_1]
       1000:06be 83 f9 e6        CMP        CX,-0x1a
       1000:06c1 77 69           JA         LAB_1000_072c
       1000:06c3 1e              PUSH       DS
       1000:06c4 a1 88 01        MOV        AX,[DAT_1008_0188]
       1000:06c7 0b c0           OR         AX,AX
       1000:06c9 74 48           JZ         LAB_1000_0713
       1000:06cb bf e6 07        MOV        DI,0x7e6
                             LAB_1000_06ce                                   XREF[1]:     1000:0708(j)  
       1000:06ce 8b 36 90 01     MOV        SI,word ptr [DAT_1008_0190]
       1000:06d2 c5 1e 8a 01     LDS        BX,[DAT_1008_018a]
                             LAB_1000_06d6                                   XREF[1]:     1000:06fb(j)  
       1000:06d6 1e              PUSH       DS
                             LAB_1000_06d7                                   XREF[1]:     1000:06e6(j)  
       1000:06d7 56              PUSH       SI
       1000:06d8 57              PUSH       DI
       1000:06d9 ff d7           CALL       DI                                               undefined FUN_1000_0576()
                                                                                             undefined FUN_1000_07e6()
       1000:06db 5f              POP        DI
       1000:06dc 5e              POP        SI
       1000:06dd 73 2b           JNC        LAB_1000_070a
       1000:06df 8c da           MOV        DX,DS
       1000:06e1 c5 5f 0e        LDS        BX,[BX + 0xe]
       1000:06e4 3b d6           CMP        DX,SI
       1000:06e6 75 ef           JNZ        LAB_1000_06d7
       1000:06e8 58              POP        AX
       1000:06e9 1f              POP        DS
       1000:06ea 1e              PUSH       DS
       1000:06eb c4 36 8a 01     LES        SI,[0x18a]
       1000:06ef 26 8b 74 14     MOV        SI,word ptr ES:[SI + 0x14]
       1000:06f3 c5 1e 86 01     LDS        BX,[0x186]
       1000:06f7 8c da           MOV        DX,DS
       1000:06f9 3b d0           CMP        DX,AX
       1000:06fb 75 d9           JNZ        LAB_1000_06d6
       1000:06fd 1f              POP        DS
       1000:06fe 1e              PUSH       DS
       1000:06ff 81 ff 76 05     CMP        DI,0x576
       1000:0703 74 0e           JZ         LAB_1000_0713
       1000:0705 bf 76 05        MOV        DI,0x576
       1000:0708 eb c4           JMP        LAB_1000_06ce
                             LAB_1000_070a                                   XREF[1]:     1000:06dd(j)  
       1000:070a 5e              POP        SI
       1000:070b 81 ff e6 07     CMP        DI,0x7e6
       1000:070f 74 0f           JZ         LAB_1000_0720
       1000:0711 eb 0a           JMP        LAB_1000_071d
                             LAB_1000_0713                                   XREF[2]:     1000:06c9(j), 1000:0703(j)  
       1000:0713 07              POP        ES
       1000:0714 06              PUSH       ES
       1000:0715 bf 86 01        MOV        DI,0x186
       1000:0718 e8 3b 00        CALL       FUN_1000_0756                                    undefined FUN_1000_0756()
       1000:071b 72 0e           JC         LAB_1000_072b
                             LAB_1000_071d                                   XREF[1]:     1000:0711(j)  
       1000:071d e8 c6 00        CALL       FUN_1000_07e6                                    undefined FUN_1000_07e6()
                             LAB_1000_0720                                   XREF[1]:     1000:070f(j)  
       1000:0720 1f              POP        DS
       1000:0721 89 16 8c 01     MOV        word ptr [0x18c],DX
       1000:0725 89 1e 8a 01     MOV        word ptr [0x18a],BX
       1000:0729 eb 20           JMP        LAB_1000_074b
                             LAB_1000_072b                                   XREF[1]:     1000:071b(j)  
       1000:072b 1f              POP        DS
                             LAB_1000_072c                                   XREF[1]:     1000:06c1(j)  
       1000:072c 33 c0           XOR        AX,AX
       1000:072e 99              CWD
       1000:072f 8b 0e 84 01     MOV        CX,word ptr [DAT_1008_0184]
       1000:0733 0b 0e 82 01     OR         CX,word ptr [DAT_1008_0182]
       1000:0737 74 12           JZ         LAB_1000_074b
       1000:0739 ff 76 06        PUSH       word ptr [BP + param_1]
       1000:073c ff 1e 82 01     CALLF      [0x182]
       1000:0740 83 c4 02        ADD        SP,0x2
       1000:0743 99              CWD
       1000:0744 0b c0           OR         AX,AX
       1000:0746 74 03           JZ         LAB_1000_074b
       1000:0748 e9 70 ff        JMP        LAB_1000_06bb
                             LAB_1000_074b                                   XREF[3]:     1000:0729(j), 1000:0737(j), 
                                                                                          1000:0746(j)  
       1000:074b 5f              POP        DI
       1000:074c 5e              POP        SI
       1000:074d 83 ed 02        SUB        BP,0x2
       1000:0750 8b e5           MOV        SP,BP
       1000:0752 1f              POP        DS
       1000:0753 5d              POP        BP
       1000:0754 4d              DEC        BP
       1000:0755 cb              RETF
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined __cdecl16near FUN_1000_0756()
                               assume DS = 0x1008
             undefined         AL:1           <RETURN>
                             FUN_1000_0756                                   XREF[1]:     FUN_1000_06af:1000:0718(c)  
       1000:0756 8b d1           MOV        DX,CX
       1000:0758 81 c2 19 10     ADD        DX,0x1019
       1000:075c 81 e2 00 f0     AND        DX,0xf000
       1000:0760 51              PUSH       CX
       1000:0761 06              PUSH       ES
       1000:0762 2e 8b 1e        MOV        BX,word ptr CS:[DAT_1000_01b8]                   = 0048h
                 b8 01
       1000:0767 33 c9           XOR        CX,CX
       1000:0769 0b d2           OR         DX,DX
       1000:076b 75 07           JNZ        LAB_1000_0774
       1000:076d f7 c3 10 00     TEST       BX,0x10
       1000:0771 75 60           JNZ        LAB_1000_07d3
       1000:0773 41              INC        CX
                             LAB_1000_0774                                   XREF[1]:     1000:076b(j)  
       1000:0774 53              PUSH       BX
       1000:0775 b8 02 20        MOV        AX,0x2002
       1000:0778 f7 c3 01 00     TEST       BX,0x1
       1000:077c 75 03           JNZ        LAB_1000_0781
       1000:077e b8 20 20        MOV        AX,0x2020
                             LAB_1000_0781                                   XREF[1]:     1000:077c(j)  
       1000:0781 50              PUSH       AX
       1000:0782 51              PUSH       CX
       1000:0783 52              PUSH       DX
       1000:0784 9a 0c 00        CALLF      KERNEL::GLOBALALLOC                              undefined GLOBALALLOC()
                 10 10
       1000:0789 5b              POP        BX
       1000:078a 0b c0           OR         AX,AX
       1000:078c 74 45           JZ         LAB_1000_07d3
       1000:078e 50              PUSH       AX
       1000:078f f7 c3 01 00     TEST       BX,0x1
       1000:0793 74 10           JZ         LAB_1000_07a5
       1000:0795 50              PUSH       AX
       1000:0796 9a 18 00        CALLF      KERNEL::GLOBALLOCK                               undefined GLOBALLOCK()
                 10 10
       1000:079b 0b c0           OR         AX,AX
       1000:079d 75 2e           JNZ        LAB_1000_07cd
       1000:079f 0b c2           OR         AX,DX
       1000:07a1 74 2a           JZ         LAB_1000_07cd
       1000:07a3 8b c2           MOV        AX,DX
                             LAB_1000_07a5                                   XREF[1]:     1000:0793(j)  
       1000:07a5 8e d8           MOV        DS,AX
       1000:07a7 50              PUSH       AX
       1000:07a8 9a 20 00        CALLF      KERNEL::GLOBALSIZE                               undefined GLOBALSIZE()
                 10 10
       1000:07ad 0b d0           OR         DX,AX
       1000:07af 74 1c           JZ         LAB_1000_07cd
       1000:07b1 8b d0           MOV        DX,AX
       1000:07b3 58              POP        AX
       1000:07b4 07              POP        ES
       1000:07b5 59              POP        CX
       1000:07b6 33 db           XOR        BX,BX
       1000:07b8 89 47 06        MOV        word ptr [BX + 0x6],AX
       1000:07bb 26 8b 45 0c     MOV        AX,word ptr ES:[DI + 0xc]
       1000:07bf 89 47 02        MOV        word ptr [BX + 0x2],AX
       1000:07c2 8b c2           MOV        AX,DX
       1000:07c4 e8 c5 00        CALL       FUN_1000_088c                                    undefined FUN_1000_088c()
       1000:07c7 e8 f6 00        CALL       FUN_1000_08c0                                    undefined FUN_1000_08c0()
       1000:07ca f8              CLC
       1000:07cb eb 09           JMP        LAB_1000_07d6
                             LAB_1000_07cd                                   XREF[3]:     1000:079d(j), 1000:07a1(j), 
                                                                                          1000:07af(j)  
       1000:07cd b8 12 00        MOV        AX,0x12
       1000:07d0 e9 1f fd        JMP        FUN_1000_04f2                                    undefined FUN_1000_04f2()
                             -- Flow Override: CALL_RETURN (CALL_TERMINATOR)
                             LAB_1000_07d3                                   XREF[2]:     1000:0771(j), 1000:078c(j)  
       1000:07d3 07              POP        ES
       1000:07d4 59              POP        CX
       1000:07d5 f9              STC
                             LAB_1000_07d6                                   XREF[1]:     1000:07cb(j)  
       1000:07d6 c3              RET
       1000:07d7 00              ??         00h
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined __cdecl16near FUN_1000_07d8()
                               assume DS = 0x1008
             undefined         AL:1           <RETURN>
                             FUN_1000_07d8                                   XREF[1]:     FUN_1000_02fe:1000:034b(c)  
       1000:07d8 55              PUSH       BP
       1000:07d9 8b ec           MOV        BP,SP
       1000:07db bb 86 01        MOV        BX,0x186
       1000:07de 1e              PUSH       DS
       1000:07df 07              POP        ES
       1000:07e0 e8 7f 00        CALL       FUN_1000_0862                                    undefined FUN_1000_0862()
       1000:07e3 5d              POP        BP
       1000:07e4 c3              RET
       1000:07e5 00              ??         00h
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined __cdecl16near FUN_1000_07e6()
                               assume DS = 0x1008
             undefined         AL:1           <RETURN>
                             FUN_1000_07e6                                   XREF[2]:     FUN_1000_06af:1000:06d9(c), 
                                                                                          FUN_1000_06af:1000:071d(c)  
       1000:07e6 41              INC        CX
       1000:07e7 80 e1 fe        AND        CL,0xfe
       1000:07ea 53              PUSH       BX
       1000:07eb fc              CLD
       1000:07ec 8b 77 0a        MOV        SI,word ptr [BX + 0xa]
       1000:07ef 8b 5f 0c        MOV        BX,word ptr [BX + 0xc]
       1000:07f2 33 ff           XOR        DI,DI
       1000:07f4 eb 23           JMP        LAB_1000_0819
                             LAB_1000_07f6                                   XREF[1]:     1000:0813(j)  
       1000:07f6 8b c3           MOV        AX,BX
       1000:07f8 5b              POP        BX
       1000:07f9 a8 01           TEST       AL,0x1
       1000:07fb 75 42           JNZ        LAB_1000_083f
       1000:07fd 53              PUSH       BX
       1000:07fe 8b 77 08        MOV        SI,word ptr [BX + 0x8]
       1000:0801 8b 5f 0a        MOV        BX,word ptr [BX + 0xa]
       1000:0804 3b de           CMP        BX,SI
       1000:0806 74 36           JZ         LAB_1000_083e
       1000:0808 4b              DEC        BX
       1000:0809 33 ff           XOR        DI,DI
       1000:080b eb 0c           JMP        LAB_1000_0819
       1000:080d 90              ??         90h
                             LAB_1000_080e                                   XREF[2]:     1000:081c(j), 1000:082e(j)  
       1000:080e 8d 54 fe        LEA        DX,[SI + -0x2]
       1000:0811 3b d3           CMP        DX,BX
       1000:0813 73 e1           JNC        LAB_1000_07f6
       1000:0815 03 f0           ADD        SI,AX
       1000:0817 72 23           JC         LAB_1000_083c
                             LAB_1000_0819                                   XREF[2]:     1000:07f4(j), 1000:080b(j)  
       1000:0819 ad              LODSW      SI
       1000:081a a8 01           TEST       AL,0x1
       1000:081c 74 f0           JZ         LAB_1000_080e
       1000:081e 8b fe           MOV        DI,SI
                             LAB_1000_0820                                   XREF[1]:     1000:083a(j)  
       1000:0820 48              DEC        AX
       1000:0821 3b c1           CMP        AX,CX
       1000:0823 73 23           JNC        LAB_1000_0848
       1000:0825 03 f0           ADD        SI,AX
       1000:0827 72 13           JC         LAB_1000_083c
       1000:0829 8b d0           MOV        DX,AX
       1000:082b ad              LODSW      SI
       1000:082c a8 01           TEST       AL,0x1
       1000:082e 74 de           JZ         LAB_1000_080e
       1000:0830 03 c2           ADD        AX,DX
       1000:0832 83 c0 02        ADD        AX,0x2
       1000:0835 8b f7           MOV        SI,DI
       1000:0837 89 44 fe        MOV        word ptr [SI + -0x2],AX
       1000:083a eb e4           JMP        LAB_1000_0820
                             LAB_1000_083c                                   XREF[2]:     1000:0817(j), 1000:0827(j)  
       1000:083c 8b c0           MOV        AX,AX
                             LAB_1000_083e                                   XREF[1]:     1000:0806(j)  
       1000:083e 5b              POP        BX
                             LAB_1000_083f                                   XREF[1]:     1000:07fb(j)  
       1000:083f 8b 47 08        MOV        AX,word ptr [BX + 0x8]
       1000:0842 89 47 0a        MOV        word ptr [BX + 0xa],AX
       1000:0845 f9              STC
       1000:0846 eb 19           JMP        LAB_1000_0861
                             LAB_1000_0848                                   XREF[1]:     1000:0823(j)  
       1000:0848 5b              POP        BX
       1000:0849 89 4c fe        MOV        word ptr [SI + -0x2],CX
       1000:084c 74 09           JZ         LAB_1000_0857
       1000:084e 03 f9           ADD        DI,CX
       1000:0850 2b c1           SUB        AX,CX
       1000:0852 48              DEC        AX
       1000:0853 89 05           MOV        word ptr [DI],AX
       1000:0855 2b f9           SUB        DI,CX
                             LAB_1000_0857                                   XREF[1]:     1000:084c(j)  
       1000:0857 03 f9           ADD        DI,CX
       1000:0859 89 7f 0a        MOV        word ptr [BX + 0xa],DI
       1000:085c 8b c6           MOV        AX,SI
       1000:085e 8c da           MOV        DX,DS
       1000:0860 f8              CLC
                             LAB_1000_0861                                   XREF[1]:     1000:0846(j)  
       1000:0861 c3              RET
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined __cdecl16near FUN_1000_0862()
                               assume DS = 0x1008
             undefined         AL:1           <RETURN>
                             FUN_1000_0862                                   XREF[1]:     FUN_1000_07d8:1000:07e0(c)  
       1000:0862 55              PUSH       BP
       1000:0863 8b ec           MOV        BP,SP
       1000:0865 57              PUSH       DI
       1000:0866 26 c4 1f        LES        BX,ES:[BX]
                             LAB_1000_0869                                   XREF[1]:     1000:0885(j)  
       1000:0869 8c c1           MOV        CX,ES
       1000:086b e3 1a           JCXZ       LAB_1000_0887
       1000:086d 26 8b 47 06     MOV        AX,word ptr ES:[BX + 0x6]
       1000:0871 26 c4 5f 0e     LES        BX,ES:[BX + 0xe]
       1000:0875 53              PUSH       BX
       1000:0876 06              PUSH       ES
       1000:0877 50              PUSH       AX
       1000:0878 50              PUSH       AX
       1000:0879 9a 1c 00        CALLF      KERNEL::GLOBALUNLOCK                             undefined GLOBALUNLOCK()
                 10 10
       1000:087e 9a 14 00        CALLF      KERNEL::GLOBALFREE                               undefined GLOBALFREE()
                 10 10
       1000:0883 07              POP        ES
       1000:0884 5b              POP        BX
       1000:0885 eb e2           JMP        LAB_1000_0869
                             LAB_1000_0887                                   XREF[1]:     1000:086b(j)  
       1000:0887 5f              POP        DI
       1000:0888 8b e5           MOV        SP,BP
       1000:088a 5d              POP        BP
       1000:088b c3              RET
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined __cdecl16near FUN_1000_088c()
                               assume DS = 0x1008
             undefined         AL:1           <RETURN>
                             FUN_1000_088c                                   XREF[1]:     FUN_1000_0756:1000:07c4(c)  
       1000:088c 06              PUSH       ES
       1000:088d 57              PUSH       DI
       1000:088e 8b f8           MOV        DI,AX
       1000:0890 03 fb           ADD        DI,BX
       1000:0892 89 7f 04        MOV        word ptr [BX + 0x4],DI
       1000:0895 4f              DEC        DI
       1000:0896 4f              DEC        DI
       1000:0897 83 e8 18        SUB        AX,0x18
       1000:089a 8d 77 16        LEA        SI,[BX + 0x16]
       1000:089d c7 05 fe ff     MOV        word ptr [DI],0xfffe
       1000:08a1 89 7f 0c        MOV        word ptr [BX + 0xc],DI
       1000:08a4 48              DEC        AX
       1000:08a5 89 04           MOV        word ptr [SI],AX
       1000:08a7 8c 1f           MOV        word ptr [BX],DS
       1000:08a9 8b c6           MOV        AX,SI
       1000:08ab 8c da           MOV        DX,DS
       1000:08ad 8e c2           MOV        ES,DX
       1000:08af 8d 7f 08        LEA        DI,[BX + 0x8]
       1000:08b2 fc              CLD
       1000:08b3 ab              STOSW      ES:DI
       1000:08b4 ab              STOSW      ES:DI
       1000:08b5 47              INC        DI
       1000:08b6 47              INC        DI
       1000:08b7 33 c0           XOR        AX,AX
       1000:08b9 ab              STOSW      ES:DI
       1000:08ba ab              STOSW      ES:DI
       1000:08bb ab              STOSW      ES:DI
       1000:08bc ab              STOSW      ES:DI
       1000:08bd 5f              POP        DI
       1000:08be 07              POP        ES
       1000:08bf c3              RET
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined __cdecl16near FUN_1000_08c0()
                               assume DS = 0x1008
             undefined         AL:1           <RETURN>
                             FUN_1000_08c0                                   XREF[1]:     FUN_1000_0756:1000:07c7(c)  
       1000:08c0 26 8b 45 02     MOV        AX,word ptr ES:[DI + 0x2]
       1000:08c4 0b c0           OR         AX,AX
       1000:08c6 75 09           JNZ        LAB_1000_08d1
       1000:08c8 26 8c 5d 02     MOV        word ptr ES:[DI + 0x2],DS
       1000:08cc 26 89 1d        MOV        word ptr ES:[DI],BX
       1000:08cf eb 14           JMP        LAB_1000_08e5
                             LAB_1000_08d1                                   XREF[1]:     1000:08c6(j)  
       1000:08d1 06              PUSH       ES
       1000:08d2 26 c4 75 08     LES        SI,ES:[DI + 0x8]
       1000:08d6 26 8c 5c 10     MOV        word ptr ES:[SI + 0x10],DS
       1000:08da 26 89 5c 0e     MOV        word ptr ES:[SI + 0xe],BX
       1000:08de 8c 47 14        MOV        word ptr [BX + 0x14],ES
       1000:08e1 89 77 12        MOV        word ptr [BX + 0x12],SI
       1000:08e4 07              POP        ES
                             LAB_1000_08e5                                   XREF[1]:     1000:08cf(j)  
       1000:08e5 26 8c 5d 0a     MOV        word ptr ES:[DI + 0xa],DS
       1000:08e9 26 89 5d 08     MOV        word ptr ES:[DI + 0x8],BX
       1000:08ed 26 8c 5d 06     MOV        word ptr ES:[DI + 0x6],DS
       1000:08f1 26 89 5d 04     MOV        word ptr ES:[DI + 0x4],BX
       1000:08f5 c3              RET
       1000:08f6 00              ??         00h
       1000:08f7 00              ??         00h
       1000:08f8 00              ??         00h
       1000:08f9 00              ??         00h
       1000:08fa 00              ??         00h
       1000:08fb 00              ??         00h
       1000:08fc 00              ??         00h
       1000:08fd 00              ??         00h
       1000:08fe 00              ??         00h
       1000:08ff 00              ??         00h
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined __stdcall16far DLLENTRYPOINT(undefined2 param_
                               assume DS = 0x1008
             undefined         AL:1           <RETURN>
             undefined2        Stack[0xe]:2   param_1                                 XREF[1]:     1000:0915(*)  
             undefined2        Stack[0x10]:2  param_2                                 XREF[1]:     1000:091b(*)  
             undefined2        Stack[0x12]:2  param_3                                 XREF[1]:     1000:0918(*)  
                             Ordinal_2                                       XREF[1]:     Entry Point(*)  
                             DLLENTRYPOINT
       1000:0900 b8 08 10        MOV        AX,0x1008
       1000:0903 55              PUSH       BP
       1000:0904 8b ec           MOV        BP,SP
       1000:0906 1e              PUSH       DS
       1000:0907 8e d8           MOV        DS,AX
       1000:0909 68 00 10        PUSH       0x1000
       1000:090c 68 c4 11        PUSH       0x11c4
       1000:090f 68 00 10        PUSH       0x1000
       1000:0912 68 b8 11        PUSH       0x11b8
       1000:0915 ff 76 10        PUSH       word ptr [BP + param_1]
       1000:0918 ff 76 14        PUSH       word ptr [BP + param_3]
       1000:091b ff 76 12        PUSH       word ptr [BP + param_2]
       1000:091e 9a 34 00        CALLF      FUN_1000_0034                                    undefined FUN_1000_0034()
                 00 10
       1000:0923 3d 01 00        CMP        AX,0x1
       1000:0926 1b c0           SBB        AX,AX
       1000:0928 40              INC        AX
       1000:0929 1f              POP        DS
       1000:092a c9              LEAVE
       1000:092b ca 10 00        RETF       0x10
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined __stdcall16far SETPMVECTOR_IF(undefined4 param
                               assume DS = 0x1008
             undefined         AL:1           <RETURN>
             undefined4        Stack[0x4]:4   param_1                                 XREF[1]:     1000:0a3d(*)  
             undefined4        Stack[0x8]:4   param_2                                 XREF[1]:     1000:0a27(*)  
             undefined1        Stack[0xc]:1   param_3                                 XREF[4]:     1000:0939(*), 
                                                                                                   1000:094e(*), 
                                                                                                   1000:0957(*), 
                                                                                                   1000:09f9(*)  
             undefined2        Stack[-0x4]:2  local_4                                 XREF[2]:     1000:096f(*), 
                                                                                                   1000:0976(*)  
             undefined2        Stack[-0x6]:2  local_6                                 XREF[4]:     1000:096c(*), 
                                                                                                   1000:0981(*), 
                                                                                                   1000:09b2(*), 
                                                                                                   1000:0a43(*)  
             undefined2        Stack[-0x8]:2  local_8                                 XREF[4]:     1000:09c7(*), 
                                                                                                   1000:09d4(*), 
                                                                                                   1000:0a0d(*), 
                                                                                                   1000:0a36(*)  
             undefined2        Stack[-0xc]:2  local_c                                 XREF[2]:     1000:0988(*), 
                                                                                                   1000:0998(*)  
             undefined2        Stack[-0xe]:2  local_e                                 XREF[2]:     1000:09bc(*), 
                                                                                                   1000:0a1c(*)  
             undefined2        Stack[-0x10]:2 local_10                                XREF[2]:     1000:09ab(*), 
                                                                                                   1000:09fd(*)  
             undefined2        Stack[-0x12]:2 local_12                                XREF[2]:     1000:09a8(*), 
                                                                                                   1000:0a4b(*)  
             undefined2        Stack[-0x14]:2 local_14                                XREF[3]:     1000:09f4(*), 
                                                                                                   1000:0a31(*), 
                                                                                                   1000:0a53(*)  
             undefined2        Stack[-0x16]:2 local_16                                XREF[2]:     1000:097e(*), 
                                                                                                   1000:09e3(*)  
             undefined2        Stack[-0x18]:2 local_18                                XREF[2]:     1000:0979(*), 
                                                                                                   1000:09e0(*)  
                             Ordinal_10                                      XREF[1]:     Entry Point(*)  
                             SETPMVECTOR_IF
       1000:092e b8 08 10        MOV        AX,0x1008
       1000:0931 c8 16 00 00     ENTER      0x16,0x0
       1000:0935 56              PUSH       SI
       1000:0936 1e              PUSH       DS
       1000:0937 8e d8           MOV        DS,AX
       1000:0939 8a 5e 0e        MOV        BL,byte ptr [BP + param_3]
       1000:093c 2a ff           SUB        BH,BH
       1000:093e f6 87 21        TEST       byte ptr [BX + 0x21],0x2
                 00 02
       1000:0943 74 09           JZ         LAB_1000_094e
       1000:0945 8a cb           MOV        CL,BL
       1000:0947 2a ed           SUB        CH,CH
       1000:0949 83 e9 20        SUB        CX,0x20
       1000:094c eb 05           JMP        LAB_1000_0953
                             LAB_1000_094e                                   XREF[1]:     1000:0943(j)  
       1000:094e 8a 4e 0e        MOV        CL,byte ptr [BP + param_3]
       1000:0951 2a ed           SUB        CH,CH
                             LAB_1000_0953                                   XREF[1]:     1000:094c(j)  
       1000:0953 8a c1           MOV        AL,CL
       1000:0955 2c 41           SUB        AL,0x41
       1000:0957 88 46 0e        MOV        byte ptr [BP + param_3],AL
       1000:095a 3c 19           CMP        AL,0x19
       1000:095c 76 05           JBE        LAB_1000_0963
                             LAB_1000_095e                                   XREF[2]:     1000:0974(j), 1000:09ba(j)  
       1000:095e 33 c0           XOR        AX,AX
       1000:0960 e9 f3 00        JMP        LAB_1000_0a56
                             LAB_1000_0963                                   XREF[1]:     1000:095c(j)  
       1000:0963 6a 00           PUSH       0x0
       1000:0965 6a 05           PUSH       0x5
       1000:0967 9a 4c 00        CALLF      KERNEL::GLOBALDOSALLOC                           undefined GLOBALDOSALLOC()
                 10 10
       1000:096c 89 46 fc        MOV        word ptr [BP + local_6],AX
       1000:096f 89 56 fe        MOV        word ptr [BP + local_4],DX
       1000:0972 0b d0           OR         DX,AX
       1000:0974 74 e8           JZ         LAB_1000_095e
       1000:0976 8b 46 fe        MOV        AX,word ptr [BP + local_4]
       1000:0979 c7 46 ea        MOV        word ptr [BP + local_18],0x0
                 00 00
       1000:097e 89 46 ec        MOV        word ptr [BP + local_16],AX
       1000:0981 8b 56 fc        MOV        DX,word ptr [BP + local_6]
       1000:0984 2b c9           SUB        CX,CX
       1000:0986 8b f1           MOV        SI,CX
       1000:0988 89 56 f6        MOV        word ptr [BP + local_c],DX
       1000:098b 6a 05           PUSH       0x5
       1000:098d 51              PUSH       CX
       1000:098e 52              PUSH       DX
       1000:098f 51              PUSH       CX
       1000:0990 9a be 00        CALLF      FUN_1000_00be                                    undefined FUN_1000_00be(undefine
                 00 10
       1000:0995 83 c4 08        ADD        SP,0x8
       1000:0998 8e 46 f6        MOV        ES,word ptr [BP + local_c]
       1000:099b 26 c6 04 06     MOV        byte ptr ES:[SI],0x6
       1000:099f 6a 00           PUSH       0x0
       1000:09a1 6a 1c           PUSH       0x1c
       1000:09a3 9a 4c 00        CALLF      KERNEL::GLOBALDOSALLOC                           undefined GLOBALDOSALLOC()
                 10 10
       1000:09a8 89 46 f0        MOV        word ptr [BP + local_12],AX
       1000:09ab 89 56 f2        MOV        word ptr [BP + local_10],DX
       1000:09ae 0b d0           OR         DX,AX
       1000:09b0 75 0a           JNZ        LAB_1000_09bc
       1000:09b2 ff 76 fc        PUSH       word ptr [BP + local_6]
       1000:09b5 9a 50 00        CALLF      KERNEL::GLOBALDOSFREE                            undefined GLOBALDOSFREE()
                 10 10
       1000:09ba eb a2           JMP        LAB_1000_095e
                             LAB_1000_09bc                                   XREF[1]:     1000:09b0(j)  
       1000:09bc 89 76 f4        MOV        word ptr [BP + local_e],SI
       1000:09bf 6a 1c           PUSH       0x1c
       1000:09c1 6a 00           PUSH       0x0
       1000:09c3 2b c9           SUB        CX,CX
       1000:09c5 8b f1           MOV        SI,CX
       1000:09c7 89 46 fa        MOV        word ptr [BP + local_8],AX
       1000:09ca 50              PUSH       AX
       1000:09cb 51              PUSH       CX
       1000:09cc 9a be 00        CALLF      FUN_1000_00be                                    undefined FUN_1000_00be(undefine
                 00 10
       1000:09d1 83 c4 08        ADD        SP,0x8
       1000:09d4 8e 46 fa        MOV        ES,word ptr [BP + local_8]
       1000:09d7 26 c6 04 1c     MOV        byte ptr ES:[SI],0x1c
       1000:09db 26 c6 44        MOV        byte ptr ES:[SI + 0x2],0x3
                 02 03
       1000:09e0 8b 46 ea        MOV        AX,word ptr [BP + local_18]
       1000:09e3 8b 56 ec        MOV        DX,word ptr [BP + local_16]
       1000:09e6 26 89 44 0e     MOV        word ptr ES:[SI + 0xe],AX
       1000:09ea 26 89 54 10     MOV        word ptr ES:[SI + 0x10],DX
       1000:09ee 26 c7 44        MOV        word ptr ES:[SI + 0x12],0x5
                 12 05 00
       1000:09f4 c7 46 ee        MOV        word ptr [BP + local_14],0x0
                 00 00
       1000:09f9 8a 46 0e        MOV        AL,byte ptr [BP + param_3]
       1000:09fc 50              PUSH       AX
       1000:09fd 8b 56 f2        MOV        DX,word ptr [BP + local_10]
       1000:0a00 2b c9           SUB        CX,CX
       1000:0a02 52              PUSH       DX
       1000:0a03 51              PUSH       CX
       1000:0a04 9a 58 12        CALLF      FUN_1000_1258                                    undefined FUN_1000_1258(undefine
                 00 10
       1000:0a09 0b c0           OR         AX,AX
       1000:0a0b 74 36           JZ         LAB_1000_0a43
       1000:0a0d 8e 46 fa        MOV        ES,word ptr [BP + local_8]
       1000:0a10 26 8a 64 04     MOV        AH,byte ptr ES:[SI + 0x4]
       1000:0a14 80 e4 83        AND        AH,0x83
       1000:0a17 80 fc 01        CMP        AH,0x1
       1000:0a1a 75 1a           JNZ        LAB_1000_0a36
       1000:0a1c c4 5e f4        LES        BX,[BP + local_e]
       1000:0a1f 26 8b 47 01     MOV        AX,word ptr ES:[BX + 0x1]
       1000:0a23 26 8b 57 03     MOV        DX,word ptr ES:[BX + 0x3]
       1000:0a27 c4 5e 0a        LES        BX,[BP + param_2]
       1000:0a2a 26 89 07        MOV        word ptr ES:[BX],AX
       1000:0a2d 26 89 57 02     MOV        word ptr ES:[BX + 0x2],DX
       1000:0a31 c7 46 ee        MOV        word ptr [BP + local_14],0x1
                 01 00
                             LAB_1000_0a36                                   XREF[1]:     1000:0a1a(j)  
       1000:0a36 8e 46 fa        MOV        ES,word ptr [BP + local_8]
       1000:0a39 26 8b 44 03     MOV        AX,word ptr ES:[SI + 0x3]
       1000:0a3d c4 5e 06        LES        BX,[BP + param_1]
       1000:0a40 26 89 07        MOV        word ptr ES:[BX],AX
                             LAB_1000_0a43                                   XREF[1]:     1000:0a0b(j)  
       1000:0a43 ff 76 fc        PUSH       word ptr [BP + local_6]
       1000:0a46 9a 50 00        CALLF      KERNEL::GLOBALDOSFREE                            undefined GLOBALDOSFREE()
                 10 10
       1000:0a4b ff 76 f0        PUSH       word ptr [BP + local_12]
       1000:0a4e 9a 50 00        CALLF      KERNEL::GLOBALDOSFREE                            undefined GLOBALDOSFREE()
                 10 10
       1000:0a53 8b 46 ee        MOV        AX,word ptr [BP + local_14]
                             LAB_1000_0a56                                   XREF[1]:     1000:0960(j)  
       1000:0a56 1f              POP        DS
       1000:0a57 5e              POP        SI
       1000:0a58 c9              LEAVE
       1000:0a59 ca 0a 00        RETF       0xa
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined __stdcall16far SETIDT_IF(undefined2 param_1, u
                               assume DS = 0x1008
             undefined         AL:1           <RETURN>
             undefined2        Stack[0x4]:2   param_1                                 XREF[1]:     1000:0a6e(*)  
             undefined2        Stack[0x6]:2   param_2                                 XREF[1]:     1000:0a6b(*)  
             undefined1        Stack[0x8]:1   param_3                                 XREF[1]:     1000:0a65(*)  
                             Ordinal_6                                       XREF[1]:     Entry Point(*)  
                             SETIDT_IF
       1000:0a5c b8 08 10        MOV        AX,0x1008
       1000:0a5f 55              PUSH       BP
       1000:0a60 8b ec           MOV        BP,SP
       1000:0a62 1e              PUSH       DS
       1000:0a63 8e d8           MOV        DS,AX
       1000:0a65 8a 46 0a        MOV        AL,byte ptr [BP + param_3]
       1000:0a68 50              PUSH       AX
       1000:0a69 6a 02           PUSH       0x2
       1000:0a6b ff 76 08        PUSH       word ptr [BP + param_2]
       1000:0a6e ff 76 06        PUSH       word ptr [BP + param_1]
       1000:0a71 9a bc 0a        CALLF      SETRMINTS_IF                                     undefined SETRMINTS_IF(undefined
                 00 10
       1000:0a76 1f              POP        DS
       1000:0a77 c9              LEAVE
       1000:0a78 ca 06 00        RETF       0x6
       1000:0a7b 00              ??         00h
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined __stdcall16far GETIDT_IF(undefined2 param_1, u
                               assume DS = 0x1008
             undefined         AL:1           <RETURN>
             undefined2        Stack[0x4]:2   param_1                                 XREF[1]:     1000:0a8e(*)  
             undefined2        Stack[0x6]:2   param_2                                 XREF[1]:     1000:0a8b(*)  
             undefined1        Stack[0x8]:1   param_3                                 XREF[1]:     1000:0a85(*)  
                             Ordinal_8                                       XREF[1]:     Entry Point(*)  
                             GETIDT_IF
       1000:0a7c b8 08 10        MOV        AX,0x1008
       1000:0a7f 55              PUSH       BP
       1000:0a80 8b ec           MOV        BP,SP
       1000:0a82 1e              PUSH       DS
       1000:0a83 8e d8           MOV        DS,AX
       1000:0a85 8a 46 0a        MOV        AL,byte ptr [BP + param_3]
       1000:0a88 50              PUSH       AX
       1000:0a89 6a 00           PUSH       0x0
       1000:0a8b ff 76 08        PUSH       word ptr [BP + param_2]
       1000:0a8e ff 76 06        PUSH       word ptr [BP + param_1]
       1000:0a91 9a bc 0a        CALLF      SETRMINTS_IF                                     undefined SETRMINTS_IF(undefined
                 00 10
       1000:0a96 1f              POP        DS
       1000:0a97 c9              LEAVE
       1000:0a98 ca 06 00        RETF       0x6
       1000:0a9b 00              ??         00h
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined __stdcall16far GETRMINTS_IF(undefined2 param_1
                               assume DS = 0x1008
             undefined         AL:1           <RETURN>
             undefined2        Stack[0x4]:2   param_1                                 XREF[1]:     1000:0aae(*)  
             undefined2        Stack[0x6]:2   param_2                                 XREF[1]:     1000:0aab(*)  
             undefined1        Stack[0x8]:1   param_3                                 XREF[1]:     1000:0aa5(*)  
                             Ordinal_13                                      XREF[1]:     Entry Point(*)  
                             GETRMINTS_IF
       1000:0a9c b8 08 10        MOV        AX,0x1008
       1000:0a9f 55              PUSH       BP
       1000:0aa0 8b ec           MOV        BP,SP
       1000:0aa2 1e              PUSH       DS
       1000:0aa3 8e d8           MOV        DS,AX
       1000:0aa5 8a 46 0a        MOV        AL,byte ptr [BP + param_3]
       1000:0aa8 50              PUSH       AX
       1000:0aa9 6a 05           PUSH       0x5
       1000:0aab ff 76 08        PUSH       word ptr [BP + param_2]
       1000:0aae ff 76 06        PUSH       word ptr [BP + param_1]
       1000:0ab1 9a bc 0a        CALLF      SETRMINTS_IF                                     undefined SETRMINTS_IF(undefined
                 00 10
       1000:0ab6 1f              POP        DS
       1000:0ab7 c9              LEAVE
       1000:0ab8 ca 06 00        RETF       0x6
       1000:0abb 00              ??         00h
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined __stdcall16far SETRMINTS_IF(undefined4 param_1
                               assume DS = 0x1008
             undefined         AL:1           <RETURN>
             undefined4        Stack[0x4]:4   param_1                                 XREF[1]:     1000:0bb2(*)  
             undefined1        Stack[0x8]:1   param_2                                 XREF[1]:     1000:0b27(*)  
             undefined1        Stack[0xa]:1   param_3                                 XREF[4]:     1000:0ac8(*), 
                                                                                                   1000:0add(*), 
                                                                                                   1000:0ae6(*), 
                                                                                                   1000:0b86(*)  
             undefined2        Stack[-0x4]:2  local_4                                 XREF[2]:     1000:0afe(*), 
                                                                                                   1000:0b05(*)  
             undefined2        Stack[-0x6]:2  local_6                                 XREF[4]:     1000:0afb(*), 
                                                                                                   1000:0b14(*), 
                                                                                                   1000:0b42(*), 
                                                                                                   1000:0bb8(*)  
             undefined2        Stack[-0x8]:2  local_8                                 XREF[3]:     1000:0b54(*), 
                                                                                                   1000:0b61(*), 
                                                                                                   1000:0b9a(*)  
             undefined2        Stack[-0xc]:2  local_c                                 XREF[2]:     1000:0b3b(*), 
                                                                                                   1000:0b8a(*)  
             undefined2        Stack[-0xe]:2  local_e                                 XREF[2]:     1000:0b38(*), 
                                                                                                   1000:0bc0(*)  
             undefined2        Stack[-0x10]:2 local_10                                XREF[3]:     1000:0b81(*), 
                                                                                                   1000:0ba9(*), 
                                                                                                   1000:0bc8(*)  
             undefined2        Stack[-0x12]:2 local_12                                XREF[2]:     1000:0b0d(*), 
                                                                                                   1000:0b70(*)  
             undefined2        Stack[-0x14]:2 local_14                                XREF[2]:     1000:0b08(*), 
                                                                                                   1000:0b6d(*)  
                             Ordinal_7                                       XREF[4]:     Entry Point(*), 
                             SETRMINTS_IF                                                 SETIDT_IF:1000:0a71(c), 
                                                                                          GETIDT_IF:1000:0a91(c), 
                                                                                          GETRMINTS_IF:1000:0ab1(c)  
       1000:0abc b8 08 10        MOV        AX,0x1008
       1000:0abf c8 12 00 00     ENTER      0x12,0x0
       1000:0ac3 57              PUSH       DI
       1000:0ac4 56              PUSH       SI
       1000:0ac5 1e              PUSH       DS
       1000:0ac6 8e d8           MOV        DS,AX
       1000:0ac8 8a 5e 0c        MOV        BL,byte ptr [BP + param_3]
       1000:0acb 2a ff           SUB        BH,BH
       1000:0acd f6 87 21        TEST       byte ptr [BX + 0x21],0x2
                 00 02
       1000:0ad2 74 09           JZ         LAB_1000_0add
       1000:0ad4 8a cb           MOV        CL,BL
       1000:0ad6 2a ed           SUB        CH,CH
       1000:0ad8 83 e9 20        SUB        CX,0x20
       1000:0adb eb 05           JMP        LAB_1000_0ae2
                             LAB_1000_0add                                   XREF[1]:     1000:0ad2(j)  
       1000:0add 8a 4e 0c        MOV        CL,byte ptr [BP + param_3]
       1000:0ae0 2a ed           SUB        CH,CH
                             LAB_1000_0ae2                                   XREF[1]:     1000:0adb(j)  
       1000:0ae2 8a c1           MOV        AL,CL
       1000:0ae4 2c 41           SUB        AL,0x41
       1000:0ae6 88 46 0c        MOV        byte ptr [BP + param_3],AL
       1000:0ae9 3c 19           CMP        AL,0x19
       1000:0aeb 76 05           JBE        LAB_1000_0af2
                             LAB_1000_0aed                                   XREF[2]:     1000:0b03(j), 1000:0b4a(j)  
       1000:0aed 33 c0           XOR        AX,AX
       1000:0aef e9 d9 00        JMP        LAB_1000_0bcb
                             LAB_1000_0af2                                   XREF[1]:     1000:0aeb(j)  
       1000:0af2 6a 00           PUSH       0x0
       1000:0af4 6a 01           PUSH       0x1
       1000:0af6 9a 4c 00        CALLF      KERNEL::GLOBALDOSALLOC                           undefined GLOBALDOSALLOC()
                 10 10
       1000:0afb 89 46 fc        MOV        word ptr [BP + local_6],AX
       1000:0afe 89 56 fe        MOV        word ptr [BP + local_4],DX
       1000:0b01 0b d0           OR         DX,AX
       1000:0b03 74 e8           JZ         LAB_1000_0aed
       1000:0b05 8b 46 fe        MOV        AX,word ptr [BP + local_4]
       1000:0b08 c7 46 ee        MOV        word ptr [BP + local_14],0x0
                 00 00
       1000:0b0d 89 46 f0        MOV        word ptr [BP + local_12],AX
       1000:0b10 6a 01           PUSH       0x1
       1000:0b12 6a 00           PUSH       0x0
       1000:0b14 8b 56 fc        MOV        DX,word ptr [BP + local_6]
       1000:0b17 2b c9           SUB        CX,CX
       1000:0b19 52              PUSH       DX
       1000:0b1a 51              PUSH       CX
       1000:0b1b 8b f1           MOV        SI,CX
       1000:0b1d 8b fa           MOV        DI,DX
       1000:0b1f 9a be 00        CALLF      FUN_1000_00be                                    undefined FUN_1000_00be(undefine
                 00 10
       1000:0b24 83 c4 08        ADD        SP,0x8
       1000:0b27 8a 46 0a        MOV        AL,byte ptr [BP + param_2]
       1000:0b2a 8e c7           MOV        ES,DI
       1000:0b2c 26 88 04        MOV        byte ptr ES:[SI],AL
       1000:0b2f 6a 00           PUSH       0x0
       1000:0b31 6a 1c           PUSH       0x1c
       1000:0b33 9a 4c 00        CALLF      KERNEL::GLOBALDOSALLOC                           undefined GLOBALDOSALLOC()
                 10 10
       1000:0b38 89 46 f4        MOV        word ptr [BP + local_e],AX
       1000:0b3b 89 56 f6        MOV        word ptr [BP + local_c],DX
       1000:0b3e 0b d0           OR         DX,AX
       1000:0b40 75 0a           JNZ        LAB_1000_0b4c
       1000:0b42 ff 76 fc        PUSH       word ptr [BP + local_6]
       1000:0b45 9a 50 00        CALLF      KERNEL::GLOBALDOSFREE                            undefined GLOBALDOSFREE()
                 10 10
       1000:0b4a eb a1           JMP        LAB_1000_0aed
                             LAB_1000_0b4c                                   XREF[1]:     1000:0b40(j)  
       1000:0b4c 6a 1c           PUSH       0x1c
       1000:0b4e 6a 00           PUSH       0x0
       1000:0b50 2b c9           SUB        CX,CX
       1000:0b52 8b f1           MOV        SI,CX
       1000:0b54 89 46 fa        MOV        word ptr [BP + local_8],AX
       1000:0b57 50              PUSH       AX
       1000:0b58 51              PUSH       CX
       1000:0b59 9a be 00        CALLF      FUN_1000_00be                                    undefined FUN_1000_00be(undefine
                 00 10
       1000:0b5e 83 c4 08        ADD        SP,0x8
       1000:0b61 8e 46 fa        MOV        ES,word ptr [BP + local_8]
       1000:0b64 26 c6 04 1c     MOV        byte ptr ES:[SI],0x1c
       1000:0b68 26 c6 44        MOV        byte ptr ES:[SI + 0x2],0xc
                 02 0c
       1000:0b6d 8b 46 ee        MOV        AX,word ptr [BP + local_14]
       1000:0b70 8b 56 f0        MOV        DX,word ptr [BP + local_12]
       1000:0b73 26 89 44 0e     MOV        word ptr ES:[SI + 0xe],AX
       1000:0b77 26 89 54 10     MOV        word ptr ES:[SI + 0x10],DX
       1000:0b7b 26 c7 44        MOV        word ptr ES:[SI + 0x12],0x1
                 12 01 00
       1000:0b81 c7 46 f2        MOV        word ptr [BP + local_10],0x0
                 00 00
       1000:0b86 8a 46 0c        MOV        AL,byte ptr [BP + param_3]
       1000:0b89 50              PUSH       AX
       1000:0b8a 8b 56 f6        MOV        DX,word ptr [BP + local_c]
       1000:0b8d 2b c9           SUB        CX,CX
       1000:0b8f 52              PUSH       DX
       1000:0b90 51              PUSH       CX
       1000:0b91 9a 58 12        CALLF      FUN_1000_1258                                    undefined FUN_1000_1258(undefine
                 00 10
       1000:0b96 0b c0           OR         AX,AX
       1000:0b98 74 1e           JZ         LAB_1000_0bb8
       1000:0b9a 8e 46 fa        MOV        ES,word ptr [BP + local_8]
       1000:0b9d 26 8a 64 04     MOV        AH,byte ptr ES:[SI + 0x4]
       1000:0ba1 80 e4 83        AND        AH,0x83
       1000:0ba4 80 fc 01        CMP        AH,0x1
       1000:0ba7 75 05           JNZ        LAB_1000_0bae
       1000:0ba9 c7 46 f2        MOV        word ptr [BP + local_10],0x1
                 01 00
                             LAB_1000_0bae                                   XREF[1]:     1000:0ba7(j)  
       1000:0bae 26 8b 44 03     MOV        AX,word ptr ES:[SI + 0x3]
       1000:0bb2 c4 5e 06        LES        BX,[BP + param_1]
       1000:0bb5 26 89 07        MOV        word ptr ES:[BX],AX
                             LAB_1000_0bb8                                   XREF[1]:     1000:0b98(j)  
       1000:0bb8 ff 76 fc        PUSH       word ptr [BP + local_6]
       1000:0bbb 9a 50 00        CALLF      KERNEL::GLOBALDOSFREE                            undefined GLOBALDOSFREE()
                 10 10
       1000:0bc0 ff 76 f4        PUSH       word ptr [BP + local_e]
       1000:0bc3 9a 50 00        CALLF      KERNEL::GLOBALDOSFREE                            undefined GLOBALDOSFREE()
                 10 10
       1000:0bc8 8b 46 f2        MOV        AX,word ptr [BP + local_10]
                             LAB_1000_0bcb                                   XREF[1]:     1000:0aef(j)  
       1000:0bcb 1f              POP        DS
       1000:0bcc 5e              POP        SI
       1000:0bcd 5f              POP        DI
       1000:0bce c9              LEAVE
       1000:0bcf ca 08 00        RETF       0x8
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined __stdcall16far SETVECTORS_IF(undefined1 param_
                               assume DS = 0x1008
             undefined         AL:1           <RETURN>
             undefined1        Stack[0x4]:1   param_1                                 XREF[2]:     1000:0c07(*), 
                                                                                                   1000:0ca2(*)  
             undefined2        Stack[0x6]:2   param_2                                 XREF[1]:     1000:0cdd(*)  
             undefined2        Stack[0x8]:2   param_3                                 XREF[1]:     1000:0cda(*)  
             undefined2        Stack[0xa]:2   param_4                                 XREF[1]:     1000:0c94(*)  
             undefined2        Stack[0xc]:2   param_5                                 XREF[1]:     1000:0c97(*)  
             undefined1        Stack[0xe]:1   param_6                                 XREF[4]:     1000:0bdd(*), 
                                                                                                   1000:0bf2(*), 
                                                                                                   1000:0bfb(*), 
                                                                                                   1000:0cae(*)  
             undefined2        Stack[-0x4]:2  local_4                                 XREF[3]:     1000:0c62(*), 
                                                                                                   1000:0c6f(*), 
                                                                                                   1000:0cc2(*)  
             undefined2        Stack[-0x8]:2  local_8                                 XREF[2]:     1000:0c48(*), 
                                                                                                   1000:0cb2(*)  
             undefined2        Stack[-0xa]:2  local_a                                 XREF[2]:     1000:0c45(*), 
                                                                                                   1000:0cf5(*)  
             undefined2        Stack[-0xc]:2  local_c                                 XREF[3]:     1000:0ca9(*), 
                                                                                                   1000:0ce8(*), 
                                                                                                   1000:0cfd(*)  
             undefined2        Stack[-0x10]:2 local_10                                XREF[2]:     1000:0c1d(*), 
                                                                                                   1000:0ced(*)  
             undefined2        Stack[-0x12]:2 local_12                                XREF[2]:     1000:0c57(*), 
                                                                                                   1000:0cd1(*)  
             undefined2        Stack[-0x14]:2 local_14                                XREF[2]:     1000:0c25(*), 
                                                                                                   1000:0c7e(*)  
             undefined2        Stack[-0x16]:2 local_16                                XREF[2]:     1000:0c20(*), 
                                                                                                   1000:0c7b(*)  
             undefined2        Stack[-0x18]:2 local_18                                XREF[2]:     1000:0c2d(*), 
                                                                                                   1000:0cd4(*)  
             undefined2        Stack[-0x1a]:2 local_1a                                XREF[2]:     1000:0c2a(*), 
                                                                                                   1000:0cd7(*)  
                             Ordinal_3                                       XREF[1]:     Entry Point(*)  
                             SETVECTORS_IF
       1000:0bd2 b8 08 10        MOV        AX,0x1008
       1000:0bd5 c8 18 00 00     ENTER      0x18,0x0
       1000:0bd9 56              PUSH       SI
       1000:0bda 1e              PUSH       DS
       1000:0bdb 8e d8           MOV        DS,AX
       1000:0bdd 8a 5e 10        MOV        BL,byte ptr [BP + param_6]
       1000:0be0 2a ff           SUB        BH,BH
       1000:0be2 f6 87 21        TEST       byte ptr [BX + 0x21],0x2
                 00 02
       1000:0be7 74 09           JZ         LAB_1000_0bf2
       1000:0be9 8a cb           MOV        CL,BL
       1000:0beb 2a ed           SUB        CH,CH
       1000:0bed 83 e9 20        SUB        CX,0x20
       1000:0bf0 eb 05           JMP        LAB_1000_0bf7
                             LAB_1000_0bf2                                   XREF[1]:     1000:0be7(j)  
       1000:0bf2 8a 4e 10        MOV        CL,byte ptr [BP + param_6]
       1000:0bf5 2a ed           SUB        CH,CH
                             LAB_1000_0bf7                                   XREF[1]:     1000:0bf0(j)  
       1000:0bf7 8a c1           MOV        AL,CL
       1000:0bf9 2c 41           SUB        AL,0x41
       1000:0bfb 88 46 10        MOV        byte ptr [BP + param_6],AL
       1000:0bfe 3c 19           CMP        AL,0x19
       1000:0c00 76 05           JBE        LAB_1000_0c07
                             LAB_1000_0c02                                   XREF[1]:     1000:0c55(j)  
       1000:0c02 33 c0           XOR        AX,AX
       1000:0c04 e9 f9 00        JMP        LAB_1000_0d00
                             LAB_1000_0c07                                   XREF[1]:     1000:0c00(j)  
       1000:0c07 80 7e 06 01     CMP        byte ptr [BP + param_1],0x1
       1000:0c0b 1b f6           SBB        SI,SI
       1000:0c0d 81 e6 d0 fe     AND        SI,0xfed0
       1000:0c11 81 c6 30 09     ADD        SI,0x930
       1000:0c15 6a 00           PUSH       0x0
       1000:0c17 56              PUSH       SI
       1000:0c18 9a 4c 00        CALLF      KERNEL::GLOBALDOSALLOC                           undefined GLOBALDOSALLOC()
                 10 10
       1000:0c1d 89 46 f2        MOV        word ptr [BP + local_10],AX
       1000:0c20 c7 46 ec        MOV        word ptr [BP + local_16],0x0
                 00 00
       1000:0c25 89 56 ee        MOV        word ptr [BP + local_14],DX
       1000:0c28 2b c9           SUB        CX,CX
       1000:0c2a 89 4e e8        MOV        word ptr [BP + local_1a],CX
       1000:0c2d 89 46 ea        MOV        word ptr [BP + local_18],AX
       1000:0c30 56              PUSH       SI
       1000:0c31 51              PUSH       CX
       1000:0c32 50              PUSH       AX
       1000:0c33 51              PUSH       CX
       1000:0c34 9a be 00        CALLF      FUN_1000_00be                                    undefined FUN_1000_00be(undefine
                 00 10
       1000:0c39 83 c4 08        ADD        SP,0x8
       1000:0c3c 6a 00           PUSH       0x0
       1000:0c3e 6a 1b           PUSH       0x1b
       1000:0c40 9a 4c 00        CALLF      KERNEL::GLOBALDOSALLOC                           undefined GLOBALDOSALLOC()
                 10 10
       1000:0c45 89 46 f8        MOV        word ptr [BP + local_a],AX
       1000:0c48 89 56 fa        MOV        word ptr [BP + local_8],DX
       1000:0c4b 0b d0           OR         DX,AX
       1000:0c4d 75 08           JNZ        LAB_1000_0c57
       1000:0c4f 50              PUSH       AX
       1000:0c50 9a 50 00        CALLF      KERNEL::GLOBALDOSFREE                            undefined GLOBALDOSFREE()
                 10 10
       1000:0c55 eb ab           JMP        LAB_1000_0c02
                             LAB_1000_0c57                                   XREF[1]:     1000:0c4d(j)  
       1000:0c57 89 76 f0        MOV        word ptr [BP + local_12],SI
       1000:0c5a 6a 1b           PUSH       0x1b
       1000:0c5c 6a 00           PUSH       0x0
       1000:0c5e 2b c9           SUB        CX,CX
       1000:0c60 8b f1           MOV        SI,CX
       1000:0c62 89 46 fe        MOV        word ptr [BP + local_4],AX
       1000:0c65 50              PUSH       AX
       1000:0c66 51              PUSH       CX
       1000:0c67 9a be 00        CALLF      FUN_1000_00be                                    undefined FUN_1000_00be(undefine
                 00 10
       1000:0c6c 83 c4 08        ADD        SP,0x8
       1000:0c6f 8e 46 fe        MOV        ES,word ptr [BP + local_4]
       1000:0c72 26 c6 04 1b     MOV        byte ptr ES:[SI],0x1b
       1000:0c76 26 c6 44        MOV        byte ptr ES:[SI + 0x2],0x80
                 02 80
       1000:0c7b 8b 46 ec        MOV        AX,word ptr [BP + local_16]
       1000:0c7e 8b 56 ee        MOV        DX,word ptr [BP + local_14]
       1000:0c81 26 89 44 0e     MOV        word ptr ES:[SI + 0xe],AX
       1000:0c85 26 89 54 10     MOV        word ptr ES:[SI + 0x10],DX
       1000:0c89 26 c6 44        MOV        byte ptr ES:[SI + 0xd],0x0
                 0d 00
       1000:0c8e 26 c7 44        MOV        word ptr ES:[SI + 0x12],0x1
                 12 01 00
       1000:0c94 8b 46 0c        MOV        AX,word ptr [BP + param_4]
       1000:0c97 8b 56 0e        MOV        DX,word ptr [BP + param_5]
       1000:0c9a 26 89 44 14     MOV        word ptr ES:[SI + 0x14],AX
       1000:0c9e 26 89 54 16     MOV        word ptr ES:[SI + 0x16],DX
       1000:0ca2 8a 46 06        MOV        AL,byte ptr [BP + param_1]
       1000:0ca5 26 88 44 18     MOV        byte ptr ES:[SI + 0x18],AL
       1000:0ca9 c7 46 f6        MOV        word ptr [BP + local_c],0x0
                 00 00
       1000:0cae 8a 46 10        MOV        AL,byte ptr [BP + param_6]
       1000:0cb1 50              PUSH       AX
       1000:0cb2 8b 56 fa        MOV        DX,word ptr [BP + local_8]
       1000:0cb5 2b c9           SUB        CX,CX
       1000:0cb7 52              PUSH       DX
       1000:0cb8 51              PUSH       CX
       1000:0cb9 9a 58 12        CALLF      FUN_1000_1258                                    undefined FUN_1000_1258(undefine
                 00 10
       1000:0cbe 0b c0           OR         AX,AX
       1000:0cc0 74 2b           JZ         LAB_1000_0ced
       1000:0cc2 8e 46 fe        MOV        ES,word ptr [BP + local_4]
       1000:0cc5 26 8a 64 04     MOV        AH,byte ptr ES:[SI + 0x4]
       1000:0cc9 80 e4 83        AND        AH,0x83
       1000:0ccc 80 fc 01        CMP        AH,0x1
       1000:0ccf 75 1c           JNZ        LAB_1000_0ced
       1000:0cd1 ff 76 f0        PUSH       word ptr [BP + local_12]
       1000:0cd4 ff 76 ea        PUSH       word ptr [BP + local_18]
       1000:0cd7 ff 76 e8        PUSH       word ptr [BP + local_1a]
       1000:0cda ff 76 0a        PUSH       word ptr [BP + param_3]
       1000:0cdd ff 76 08        PUSH       word ptr [BP + param_2]
       1000:0ce0 9a 12 01        CALLF      FUN_1000_0112                                    undefined FUN_1000_0112(undefine
                 00 10
       1000:0ce5 83 c4 0a        ADD        SP,0xa
       1000:0ce8 c7 46 f6        MOV        word ptr [BP + local_c],0x1
                 01 00
                             LAB_1000_0ced                                   XREF[2]:     1000:0cc0(j), 1000:0ccf(j)  
       1000:0ced ff 76 f2        PUSH       word ptr [BP + local_10]
       1000:0cf0 9a 50 00        CALLF      KERNEL::GLOBALDOSFREE                            undefined GLOBALDOSFREE()
                 10 10
       1000:0cf5 ff 76 f8        PUSH       word ptr [BP + local_a]
       1000:0cf8 9a 50 00        CALLF      KERNEL::GLOBALDOSFREE                            undefined GLOBALDOSFREE()
                 10 10
       1000:0cfd 8b 46 f6        MOV        AX,word ptr [BP + local_c]
                             LAB_1000_0d00                                   XREF[1]:     1000:0c04(j)  
       1000:0d00 1f              POP        DS
       1000:0d01 5e              POP        SI
       1000:0d02 c9              LEAVE
       1000:0d03 ca 0c 00        RETF       0xc
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined __stdcall16far GETPMVECTOR_IF(undefined2 param
                               assume DS = 0x1008
             undefined         AL:1           <RETURN>
             undefined2        Stack[0x4]:2   param_1                                 XREF[2]:     1000:0d3d(*), 
                                                                                                   1000:0dca(*)  
             undefined2        Stack[0x6]:2   param_2                                 XREF[2]:     1000:0d3a(*), 
                                                                                                   1000:0dcd(*)  
             undefined2        Stack[0x8]:2   param_3                                 XREF[2]:     1000:0d42(*), 
                                                                                                   1000:0d87(*)  
             undefined2        Stack[0xa]:2   param_4                                 XREF[1]:     1000:0da5(*)  
             undefined2        Stack[0xc]:2   param_5                                 XREF[1]:     1000:0da8(*)  
             undefined1        Stack[0xe]:1   param_6                                 XREF[4]:     1000:0d12(*), 
                                                                                                   1000:0d27(*), 
                                                                                                   1000:0d30(*), 
                                                                                                   1000:0d9b(*)  
             undefined2        Stack[-0x4]:2  local_4                                 XREF[4]:     1000:0d81(*), 
                                                                                                   1000:0d8f(*), 
                                                                                                   1000:0da2(*), 
                                                                                                   1000:0dde(*)  
             undefined2        Stack[-0x6]:2  local_6                                 XREF[4]:     1000:0d84(*), 
                                                                                                   1000:0d96(*), 
                                                                                                   1000:0d9f(*), 
                                                                                                   1000:0dda(*)  
             undefined2        Stack[-0xa]:2  local_a                                 XREF[2,1]:   1000:0d7e(*), 
                                                                                                   1000:0dc7(*), 
                                                                                                   1000:0de2(*)  
             undefined2        Stack[-0xc]:2  local_c                                 XREF[2]:     1000:0d5c(*), 
                                                                                                   1000:0d66(*)  
             undefined2        Stack[-0xe]:2  local_e                                 XREF[3]:     1000:0d59(*), 
                                                                                                   1000:0d71(*), 
                                                                                                   1000:0de8(*)  
             undefined2        Stack[-0x10]:2 local_10                                XREF[2]:     1000:0d6e(*), 
                                                                                                   1000:0dad(*)  
             undefined2        Stack[-0x12]:2 local_12                                XREF[2]:     1000:0d69(*), 
                                                                                                   1000:0db0(*)  
             undefined2        Stack[-0x14]:2 local_14                                XREF[2]:     1000:0d79(*), 
                                                                                                   1000:0dc1(*)  
             undefined2        Stack[-0x16]:2 local_16                                XREF[2]:     1000:0d74(*), 
                                                                                                   1000:0dc4(*)  
             undefined2        Stack[-0x18]:2 local_18                                XREF[1]:     1000:0d8a(*)  
                             Ordinal_9                                       XREF[1]:     Entry Point(*)  
                             GETPMVECTOR_IF
       1000:0d06 b8 08 10        MOV        AX,0x1008
       1000:0d09 c8 16 00 00     ENTER      0x16,0x0
       1000:0d0d 57              PUSH       DI
       1000:0d0e 56              PUSH       SI
       1000:0d0f 1e              PUSH       DS
       1000:0d10 8e d8           MOV        DS,AX
       1000:0d12 8a 5e 10        MOV        BL,byte ptr [BP + param_6]
       1000:0d15 2a ff           SUB        BH,BH
       1000:0d17 f6 87 21        TEST       byte ptr [BX + 0x21],0x2
                 00 02
       1000:0d1c 74 09           JZ         LAB_1000_0d27
       1000:0d1e 8a cb           MOV        CL,BL
       1000:0d20 2a ed           SUB        CH,CH
       1000:0d22 83 e9 20        SUB        CX,0x20
       1000:0d25 eb 05           JMP        LAB_1000_0d2c
                             LAB_1000_0d27                                   XREF[1]:     1000:0d1c(j)  
       1000:0d27 8a 4e 10        MOV        CL,byte ptr [BP + param_6]
       1000:0d2a 2a ed           SUB        CH,CH
                             LAB_1000_0d2c                                   XREF[1]:     1000:0d25(j)  
       1000:0d2c 8a c1           MOV        AL,CL
       1000:0d2e 2c 41           SUB        AL,0x41
       1000:0d30 88 46 10        MOV        byte ptr [BP + param_6],AL
       1000:0d33 3c 19           CMP        AL,0x19
       1000:0d35 76 03           JBE        LAB_1000_0d3a
       1000:0d37 e9 ba 00        JMP        LAB_1000_0df4
                             LAB_1000_0d3a                                   XREF[1]:     1000:0d35(j)  
       1000:0d3a 8b 46 08        MOV        AX,word ptr [BP + param_2]
       1000:0d3d 0b 46 06        OR         AX,word ptr [BP + param_1]
       1000:0d40 74 21           JZ         LAB_1000_0d63
       1000:0d42 8b 76 0a        MOV        SI,word ptr [BP + param_3]
       1000:0d45 0b f6           OR         SI,SI
       1000:0d47 74 1a           JZ         LAB_1000_0d63
       1000:0d49 81 fe 40 01     CMP        SI,0x140
       1000:0d4d 77 14           JA         LAB_1000_0d63
       1000:0d4f 6a 00           PUSH       0x0
       1000:0d51 68 00 08        PUSH       0x800
       1000:0d54 9a 4c 00        CALLF      KERNEL::GLOBALDOSALLOC                           undefined GLOBALDOSALLOC()
                 10 10
       1000:0d59 89 46 f4        MOV        word ptr [BP + local_e],AX
       1000:0d5c 89 56 f6        MOV        word ptr [BP + local_c],DX
       1000:0d5f 0b d0           OR         DX,AX
       1000:0d61 75 03           JNZ        LAB_1000_0d66
                             LAB_1000_0d63                                   XREF[3]:     1000:0d40(j), 1000:0d47(j), 
                                                                                          1000:0d4d(j)  
       1000:0d63 e9 8e 00        JMP        LAB_1000_0df4
                             LAB_1000_0d66                                   XREF[1]:     1000:0d61(j)  
       1000:0d66 8b 46 f6        MOV        AX,word ptr [BP + local_c]
       1000:0d69 c7 46 f0        MOV        word ptr [BP + local_12],0x0
                 00 00
       1000:0d6e 89 46 f2        MOV        word ptr [BP + local_10],AX
       1000:0d71 8b 46 f4        MOV        AX,word ptr [BP + local_e]
       1000:0d74 c7 46 ec        MOV        word ptr [BP + local_16],0x0
                 00 00
       1000:0d79 89 46 ee        MOV        word ptr [BP + local_14],AX
       1000:0d7c 2b c0           SUB        AX,AX
       1000:0d7e 89 46 f8        MOV        word ptr [BP + local_a],AX
       1000:0d81 89 46 fe        MOV        word ptr [BP + local_4],AX
       1000:0d84 89 46 fc        MOV        word ptr [BP + local_6],AX
       1000:0d87 8b 7e 0a        MOV        DI,word ptr [BP + param_3]
       1000:0d8a 8b 76 ea        MOV        SI,word ptr [BP + local_18]
                             LAB_1000_0d8d                                   XREF[1]:     1000:0de6(j)  
       1000:0d8d 2b c0           SUB        AX,AX
       1000:0d8f 39 46 fe        CMP        word ptr [BP + local_4],AX
       1000:0d92 77 54           JA         LAB_1000_0de8
       1000:0d94 72 05           JC         LAB_1000_0d9b
       1000:0d96 39 7e fc        CMP        word ptr [BP + local_6],DI
       1000:0d99 73 4d           JNC        LAB_1000_0de8
                             LAB_1000_0d9b                                   XREF[1]:     1000:0d94(j)  
       1000:0d9b 8a 46 10        MOV        AL,byte ptr [BP + param_6]
       1000:0d9e 50              PUSH       AX
       1000:0d9f 8b 46 fc        MOV        AX,word ptr [BP + local_6]
       1000:0da2 8b 56 fe        MOV        DX,word ptr [BP + local_4]
       1000:0da5 03 46 0c        ADD        AX,word ptr [BP + param_4]
       1000:0da8 13 56 0e        ADC        DX,word ptr [BP + param_5]
       1000:0dab 52              PUSH       DX
       1000:0dac 50              PUSH       AX
       1000:0dad ff 76 f2        PUSH       word ptr [BP + local_10]
       1000:0db0 ff 76 f0        PUSH       word ptr [BP + local_12]
       1000:0db3 9a d0 11        CALLF      FUN_1000_11d0                                    undefined FUN_1000_11d0(undefine
                 00 10
       1000:0db8 8b f0           MOV        SI,AX
       1000:0dba 0b f0           OR         SI,AX
       1000:0dbc 74 2a           JZ         LAB_1000_0de8
       1000:0dbe 68 00 08        PUSH       0x800
       1000:0dc1 ff 76 ee        PUSH       word ptr [BP + local_14]
       1000:0dc4 ff 76 ec        PUSH       word ptr [BP + local_16]
       1000:0dc7 8b 46 f8        MOV        AX,word ptr [BP + local_a]
       1000:0dca 03 46 06        ADD        AX,word ptr [BP + param_1]
       1000:0dcd 8b 56 08        MOV        DX,word ptr [BP + param_2]
       1000:0dd0 52              PUSH       DX
       1000:0dd1 50              PUSH       AX
       1000:0dd2 9a 12 01        CALLF      FUN_1000_0112                                    undefined FUN_1000_0112(undefine
                 00 10
       1000:0dd7 83 c4 0a        ADD        SP,0xa
       1000:0dda 83 46 fc 01     ADD        word ptr [BP + local_6],0x1
       1000:0dde 83 56 fe 00     ADC        word ptr [BP + local_4],0x0
       1000:0de2 80 46 f9 08     ADD        byte ptr [BP + local_a+0x1],0x8
       1000:0de6 eb a5           JMP        LAB_1000_0d8d
                             LAB_1000_0de8                                   XREF[3]:     1000:0d92(j), 1000:0d99(j), 
                                                                                          1000:0dbc(j)  
       1000:0de8 ff 76 f4        PUSH       word ptr [BP + local_e]
       1000:0deb 9a 50 00        CALLF      KERNEL::GLOBALDOSFREE                            undefined GLOBALDOSFREE()
                 10 10
       1000:0df0 8b c6           MOV        AX,SI
       1000:0df2 eb 02           JMP        LAB_1000_0df6
                             LAB_1000_0df4                                   XREF[2]:     1000:0d37(j), 1000:0d63(j)  
       1000:0df4 33 c0           XOR        AX,AX
                             LAB_1000_0df6                                   XREF[1]:     1000:0df2(j)  
       1000:0df6 1f              POP        DS
       1000:0df7 5e              POP        SI
       1000:0df8 5f              POP        DI
       1000:0df9 c9              LEAVE
       1000:0dfa ca 0c 00        RETF       0xc
       1000:0dfd 00              ??         00h
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined __stdcall16far GETV86VECTOR_IF(undefined4 para
                               assume DS = 0x1008
             undefined         AL:1           <RETURN>
             undefined4        Stack[0x4]:4   param_1                                 XREF[1]:     1000:0f0d(*)  
             undefined4        Stack[0x8]:4   param_2                                 XREF[1]:     1000:0ef7(*)  
             undefined1        Stack[0xc]:1   param_3                                 XREF[4]:     1000:0e09(*), 
                                                                                                   1000:0e1e(*), 
                                                                                                   1000:0e27(*), 
                                                                                                   1000:0ec9(*)  
             undefined2        Stack[-0x4]:2  local_4                                 XREF[2]:     1000:0e3f(*), 
                                                                                                   1000:0e46(*)  
             undefined2        Stack[-0x6]:2  local_6                                 XREF[4]:     1000:0e3c(*), 
                                                                                                   1000:0e51(*), 
                                                                                                   1000:0e82(*), 
                                                                                                   1000:0f13(*)  
             undefined2        Stack[-0x8]:2  local_8                                 XREF[4]:     1000:0e97(*), 
                                                                                                   1000:0ea4(*), 
                                                                                                   1000:0edd(*), 
                                                                                                   1000:0f06(*)  
             undefined2        Stack[-0xc]:2  local_c                                 XREF[2]:     1000:0e58(*), 
                                                                                                   1000:0e68(*)  
             undefined2        Stack[-0xe]:2  local_e                                 XREF[2]:     1000:0e8c(*), 
                                                                                                   1000:0eec(*)  
             undefined2        Stack[-0x10]:2 local_10                                XREF[2]:     1000:0e7b(*), 
                                                                                                   1000:0ecd(*)  
             undefined2        Stack[-0x12]:2 local_12                                XREF[2]:     1000:0e78(*), 
                                                                                                   1000:0f1b(*)  
             undefined2        Stack[-0x14]:2 local_14                                XREF[3]:     1000:0ec4(*), 
                                                                                                   1000:0f01(*), 
                                                                                                   1000:0f23(*)  
             undefined2        Stack[-0x16]:2 local_16                                XREF[2]:     1000:0e4e(*), 
                                                                                                   1000:0eb3(*)  
             undefined2        Stack[-0x18]:2 local_18                                XREF[2]:     1000:0e49(*), 
                                                                                                   1000:0eb0(*)  
                             Ordinal_11                                      XREF[1]:     Entry Point(*)  
                             GETV86VECTOR_IF
       1000:0dfe b8 08 10        MOV        AX,0x1008
       1000:0e01 c8 16 00 00     ENTER      0x16,0x0
       1000:0e05 56              PUSH       SI
       1000:0e06 1e              PUSH       DS
       1000:0e07 8e d8           MOV        DS,AX
       1000:0e09 8a 5e 0e        MOV        BL,byte ptr [BP + param_3]
       1000:0e0c 2a ff           SUB        BH,BH
       1000:0e0e f6 87 21        TEST       byte ptr [BX + 0x21],0x2
                 00 02
       1000:0e13 74 09           JZ         LAB_1000_0e1e
       1000:0e15 8a cb           MOV        CL,BL
       1000:0e17 2a ed           SUB        CH,CH
       1000:0e19 83 e9 20        SUB        CX,0x20
       1000:0e1c eb 05           JMP        LAB_1000_0e23
                             LAB_1000_0e1e                                   XREF[1]:     1000:0e13(j)  
       1000:0e1e 8a 4e 0e        MOV        CL,byte ptr [BP + param_3]
       1000:0e21 2a ed           SUB        CH,CH
                             LAB_1000_0e23                                   XREF[1]:     1000:0e1c(j)  
       1000:0e23 8a c1           MOV        AL,CL
       1000:0e25 2c 41           SUB        AL,0x41
       1000:0e27 88 46 0e        MOV        byte ptr [BP + param_3],AL
       1000:0e2a 3c 19           CMP        AL,0x19
       1000:0e2c 76 05           JBE        LAB_1000_0e33
                             LAB_1000_0e2e                                   XREF[2]:     1000:0e44(j), 1000:0e8a(j)  
       1000:0e2e 33 c0           XOR        AX,AX
       1000:0e30 e9 f3 00        JMP        LAB_1000_0f26
                             LAB_1000_0e33                                   XREF[1]:     1000:0e2c(j)  
       1000:0e33 6a 00           PUSH       0x0
       1000:0e35 6a 05           PUSH       0x5
       1000:0e37 9a 4c 00        CALLF      KERNEL::GLOBALDOSALLOC                           undefined GLOBALDOSALLOC()
                 10 10
       1000:0e3c 89 46 fc        MOV        word ptr [BP + local_6],AX
       1000:0e3f 89 56 fe        MOV        word ptr [BP + local_4],DX
       1000:0e42 0b d0           OR         DX,AX
       1000:0e44 74 e8           JZ         LAB_1000_0e2e
       1000:0e46 8b 46 fe        MOV        AX,word ptr [BP + local_4]
       1000:0e49 c7 46 ea        MOV        word ptr [BP + local_18],0x0
                 00 00
       1000:0e4e 89 46 ec        MOV        word ptr [BP + local_16],AX
       1000:0e51 8b 56 fc        MOV        DX,word ptr [BP + local_6]
       1000:0e54 2b c9           SUB        CX,CX
       1000:0e56 8b f1           MOV        SI,CX
       1000:0e58 89 56 f6        MOV        word ptr [BP + local_c],DX
       1000:0e5b 6a 05           PUSH       0x5
       1000:0e5d 51              PUSH       CX
       1000:0e5e 52              PUSH       DX
       1000:0e5f 51              PUSH       CX
       1000:0e60 9a be 00        CALLF      FUN_1000_00be                                    undefined FUN_1000_00be(undefine
                 00 10
       1000:0e65 83 c4 08        ADD        SP,0x8
       1000:0e68 8e 46 f6        MOV        ES,word ptr [BP + local_c]
       1000:0e6b 26 c6 04 08     MOV        byte ptr ES:[SI],0x8
       1000:0e6f 6a 00           PUSH       0x0
       1000:0e71 6a 1c           PUSH       0x1c
       1000:0e73 9a 4c 00        CALLF      KERNEL::GLOBALDOSALLOC                           undefined GLOBALDOSALLOC()
                 10 10
       1000:0e78 89 46 f0        MOV        word ptr [BP + local_12],AX
       1000:0e7b 89 56 f2        MOV        word ptr [BP + local_10],DX
       1000:0e7e 0b d0           OR         DX,AX
       1000:0e80 75 0a           JNZ        LAB_1000_0e8c
       1000:0e82 ff 76 fc        PUSH       word ptr [BP + local_6]
       1000:0e85 9a 50 00        CALLF      KERNEL::GLOBALDOSFREE                            undefined GLOBALDOSFREE()
                 10 10
       1000:0e8a eb a2           JMP        LAB_1000_0e2e
                             LAB_1000_0e8c                                   XREF[1]:     1000:0e80(j)  
       1000:0e8c 89 76 f4        MOV        word ptr [BP + local_e],SI
       1000:0e8f 6a 1c           PUSH       0x1c
       1000:0e91 6a 00           PUSH       0x0
       1000:0e93 2b c9           SUB        CX,CX
       1000:0e95 8b f1           MOV        SI,CX
       1000:0e97 89 46 fa        MOV        word ptr [BP + local_8],AX
       1000:0e9a 50              PUSH       AX
       1000:0e9b 51              PUSH       CX
       1000:0e9c 9a be 00        CALLF      FUN_1000_00be                                    undefined FUN_1000_00be(undefine
                 00 10
       1000:0ea1 83 c4 08        ADD        SP,0x8
       1000:0ea4 8e 46 fa        MOV        ES,word ptr [BP + local_8]
       1000:0ea7 26 c6 04 1c     MOV        byte ptr ES:[SI],0x1c
       1000:0eab 26 c6 44        MOV        byte ptr ES:[SI + 0x2],0x3
                 02 03
       1000:0eb0 8b 46 ea        MOV        AX,word ptr [BP + local_18]
       1000:0eb3 8b 56 ec        MOV        DX,word ptr [BP + local_16]
       1000:0eb6 26 89 44 0e     MOV        word ptr ES:[SI + 0xe],AX
       1000:0eba 26 89 54 10     MOV        word ptr ES:[SI + 0x10],DX
       1000:0ebe 26 c7 44        MOV        word ptr ES:[SI + 0x12],0x5
                 12 05 00
       1000:0ec4 c7 46 ee        MOV        word ptr [BP + local_14],0x0
                 00 00
       1000:0ec9 8a 46 0e        MOV        AL,byte ptr [BP + param_3]
       1000:0ecc 50              PUSH       AX
       1000:0ecd 8b 56 f2        MOV        DX,word ptr [BP + local_10]
       1000:0ed0 2b c9           SUB        CX,CX
       1000:0ed2 52              PUSH       DX
       1000:0ed3 51              PUSH       CX
       1000:0ed4 9a 58 12        CALLF      FUN_1000_1258                                    undefined FUN_1000_1258(undefine
                 00 10
       1000:0ed9 0b c0           OR         AX,AX
       1000:0edb 74 36           JZ         LAB_1000_0f13
       1000:0edd 8e 46 fa        MOV        ES,word ptr [BP + local_8]
       1000:0ee0 26 8a 64 04     MOV        AH,byte ptr ES:[SI + 0x4]
       1000:0ee4 80 e4 83        AND        AH,0x83
       1000:0ee7 80 fc 01        CMP        AH,0x1
       1000:0eea 75 1a           JNZ        LAB_1000_0f06
       1000:0eec c4 5e f4        LES        BX,[BP + local_e]
       1000:0eef 26 8b 47 01     MOV        AX,word ptr ES:[BX + 0x1]
       1000:0ef3 26 8b 57 03     MOV        DX,word ptr ES:[BX + 0x3]
       1000:0ef7 c4 5e 0a        LES        BX,[BP + param_2]
       1000:0efa 26 89 07        MOV        word ptr ES:[BX],AX
       1000:0efd 26 89 57 02     MOV        word ptr ES:[BX + 0x2],DX
       1000:0f01 c7 46 ee        MOV        word ptr [BP + local_14],0x1
                 01 00
                             LAB_1000_0f06                                   XREF[1]:     1000:0eea(j)  
       1000:0f06 8e 46 fa        MOV        ES,word ptr [BP + local_8]
       1000:0f09 26 8b 44 03     MOV        AX,word ptr ES:[SI + 0x3]
       1000:0f0d c4 5e 06        LES        BX,[BP + param_1]
       1000:0f10 26 89 07        MOV        word ptr ES:[BX],AX
                             LAB_1000_0f13                                   XREF[1]:     1000:0edb(j)  
       1000:0f13 ff 76 fc        PUSH       word ptr [BP + local_6]
       1000:0f16 9a 50 00        CALLF      KERNEL::GLOBALDOSFREE                            undefined GLOBALDOSFREE()
                 10 10
       1000:0f1b ff 76 f0        PUSH       word ptr [BP + local_12]
       1000:0f1e 9a 50 00        CALLF      KERNEL::GLOBALDOSFREE                            undefined GLOBALDOSFREE()
                 10 10
       1000:0f23 8b 46 ee        MOV        AX,word ptr [BP + local_14]
                             LAB_1000_0f26                                   XREF[1]:     1000:0e30(j)  
       1000:0f26 1f              POP        DS
       1000:0f27 5e              POP        SI
       1000:0f28 c9              LEAVE
       1000:0f29 ca 0a 00        RETF       0xa
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined __stdcall16far SETV86VECTOR_IF(undefined4 para
                               assume DS = 0x1008
             undefined         AL:1           <RETURN>
             undefined4        Stack[0x4]:4   param_1                                 XREF[1]:     1000:104f(*)  
             undefined4        Stack[0x8]:4   param_2                                 XREF[2]:     1000:0f37(*), 
                                                                                                   1000:1039(*)  
             undefined1        Stack[0xc]:1   param_3                                 XREF[4]:     1000:0f43(*), 
                                                                                                   1000:0f58(*), 
                                                                                                   1000:0f61(*), 
                                                                                                   1000:1003(*)  
             undefined2        Stack[-0x4]:2  local_4                                 XREF[2]:     1000:0f79(*), 
                                                                                                   1000:0f80(*)  
             undefined2        Stack[-0x6]:2  local_6                                 XREF[4]:     1000:0f76(*), 
                                                                                                   1000:0f8b(*), 
                                                                                                   1000:0fbc(*), 
                                                                                                   1000:1055(*)  
             undefined2        Stack[-0x8]:2  local_8                                 XREF[2]:     1000:0f92(*), 
                                                                                                   1000:0fa2(*)  
             undefined2        Stack[-0xa]:2  local_a                                 XREF[2]:     1000:0fc6(*), 
                                                                                                   1000:1026(*)  
             undefined2        Stack[-0xc]:2  local_c                                 XREF[4]:     1000:0fd1(*), 
                                                                                                   1000:0fde(*), 
                                                                                                   1000:1017(*), 
                                                                                                   1000:1048(*)  
             undefined2        Stack[-0x10]:2 local_10                                XREF[2]:     1000:0fb5(*), 
                                                                                                   1000:1007(*)  
             undefined2        Stack[-0x12]:2 local_12                                XREF[2]:     1000:0fb2(*), 
                                                                                                   1000:105d(*)  
             undefined2        Stack[-0x14]:2 local_14                                XREF[3]:     1000:0ffe(*), 
                                                                                                   1000:1043(*), 
                                                                                                   1000:1065(*)  
             undefined2        Stack[-0x16]:2 local_16                                XREF[2]:     1000:0f88(*), 
                                                                                                   1000:0fed(*)  
             undefined2        Stack[-0x18]:2 local_18                                XREF[2]:     1000:0f83(*), 
                                                                                                   1000:0fea(*)  
                             Ordinal_12                                      XREF[1]:     Entry Point(*)  
                             SETV86VECTOR_IF
       1000:0f2c b8 08 10        MOV        AX,0x1008
       1000:0f2f c8 16 00 00     ENTER      0x16,0x0
       1000:0f33 56              PUSH       SI
       1000:0f34 1e              PUSH       DS
       1000:0f35 8e d8           MOV        DS,AX
       1000:0f37 c4 5e 0a        LES        BX,[BP + param_2]
       1000:0f3a 2b c0           SUB        AX,AX
       1000:0f3c 26 89 47 02     MOV        word ptr ES:[BX + 0x2],AX
       1000:0f40 26 89 07        MOV        word ptr ES:[BX],AX
       1000:0f43 8a 5e 0e        MOV        BL,byte ptr [BP + param_3]
       1000:0f46 2a ff           SUB        BH,BH
       1000:0f48 f6 87 21        TEST       byte ptr [BX + 0x21],0x2
                 00 02
       1000:0f4d 74 09           JZ         LAB_1000_0f58
       1000:0f4f 8a cb           MOV        CL,BL
       1000:0f51 2a ed           SUB        CH,CH
       1000:0f53 83 e9 20        SUB        CX,0x20
       1000:0f56 eb 05           JMP        LAB_1000_0f5d
                             LAB_1000_0f58                                   XREF[1]:     1000:0f4d(j)  
       1000:0f58 8a 4e 0e        MOV        CL,byte ptr [BP + param_3]
       1000:0f5b 2a ed           SUB        CH,CH
                             LAB_1000_0f5d                                   XREF[1]:     1000:0f56(j)  
       1000:0f5d 8a c1           MOV        AL,CL
       1000:0f5f 2c 41           SUB        AL,0x41
       1000:0f61 88 46 0e        MOV        byte ptr [BP + param_3],AL
       1000:0f64 3c 19           CMP        AL,0x19
       1000:0f66 76 05           JBE        LAB_1000_0f6d
                             LAB_1000_0f68                                   XREF[2]:     1000:0f7e(j), 1000:0fc4(j)  
       1000:0f68 33 c0           XOR        AX,AX
       1000:0f6a e9 fb 00        JMP        LAB_1000_1068
                             LAB_1000_0f6d                                   XREF[1]:     1000:0f66(j)  
       1000:0f6d 6a 00           PUSH       0x0
       1000:0f6f 6a 07           PUSH       0x7
       1000:0f71 9a 4c 00        CALLF      KERNEL::GLOBALDOSALLOC                           undefined GLOBALDOSALLOC()
                 10 10
       1000:0f76 89 46 fc        MOV        word ptr [BP + local_6],AX
       1000:0f79 89 56 fe        MOV        word ptr [BP + local_4],DX
       1000:0f7c 0b d0           OR         DX,AX
       1000:0f7e 74 e8           JZ         LAB_1000_0f68
       1000:0f80 8b 46 fe        MOV        AX,word ptr [BP + local_4]
       1000:0f83 c7 46 ea        MOV        word ptr [BP + local_18],0x0
                 00 00
       1000:0f88 89 46 ec        MOV        word ptr [BP + local_16],AX
       1000:0f8b 8b 56 fc        MOV        DX,word ptr [BP + local_6]
       1000:0f8e 2b c9           SUB        CX,CX
       1000:0f90 8b f1           MOV        SI,CX
       1000:0f92 89 56 fa        MOV        word ptr [BP + local_8],DX
       1000:0f95 6a 07           PUSH       0x7
       1000:0f97 51              PUSH       CX
       1000:0f98 52              PUSH       DX
       1000:0f99 51              PUSH       CX
       1000:0f9a 9a be 00        CALLF      FUN_1000_00be                                    undefined FUN_1000_00be(undefine
                 00 10
       1000:0f9f 83 c4 08        ADD        SP,0x8
       1000:0fa2 8e 46 fa        MOV        ES,word ptr [BP + local_8]
       1000:0fa5 26 c6 04 0a     MOV        byte ptr ES:[SI],0xa
       1000:0fa9 6a 00           PUSH       0x0
       1000:0fab 6a 1c           PUSH       0x1c
       1000:0fad 9a 4c 00        CALLF      KERNEL::GLOBALDOSALLOC                           undefined GLOBALDOSALLOC()
                 10 10
       1000:0fb2 89 46 f0        MOV        word ptr [BP + local_12],AX
       1000:0fb5 89 56 f2        MOV        word ptr [BP + local_10],DX
       1000:0fb8 0b d0           OR         DX,AX
       1000:0fba 75 0a           JNZ        LAB_1000_0fc6
       1000:0fbc ff 76 fc        PUSH       word ptr [BP + local_6]
       1000:0fbf 9a 50 00        CALLF      KERNEL::GLOBALDOSFREE                            undefined GLOBALDOSFREE()
                 10 10
       1000:0fc4 eb a2           JMP        LAB_1000_0f68
                             LAB_1000_0fc6                                   XREF[1]:     1000:0fba(j)  
       1000:0fc6 89 76 f8        MOV        word ptr [BP + local_a],SI
       1000:0fc9 6a 1c           PUSH       0x1c
       1000:0fcb 6a 00           PUSH       0x0
       1000:0fcd 2b c9           SUB        CX,CX
       1000:0fcf 8b f1           MOV        SI,CX
       1000:0fd1 89 46 f6        MOV        word ptr [BP + local_c],AX
       1000:0fd4 50              PUSH       AX
       1000:0fd5 51              PUSH       CX
       1000:0fd6 9a be 00        CALLF      FUN_1000_00be                                    undefined FUN_1000_00be(undefine
                 00 10
       1000:0fdb 83 c4 08        ADD        SP,0x8
       1000:0fde 8e 46 f6        MOV        ES,word ptr [BP + local_c]
       1000:0fe1 26 c6 04 1c     MOV        byte ptr ES:[SI],0x1c
       1000:0fe5 26 c6 44        MOV        byte ptr ES:[SI + 0x2],0x3
                 02 03
       1000:0fea 8b 46 ea        MOV        AX,word ptr [BP + local_18]
       1000:0fed 8b 56 ec        MOV        DX,word ptr [BP + local_16]
       1000:0ff0 26 89 44 0e     MOV        word ptr ES:[SI + 0xe],AX
       1000:0ff4 26 89 54 10     MOV        word ptr ES:[SI + 0x10],DX
       1000:0ff8 26 c7 44        MOV        word ptr ES:[SI + 0x12],0x7
                 12 07 00
       1000:0ffe c7 46 ee        MOV        word ptr [BP + local_14],0x0
                 00 00
       1000:1003 8a 46 0e        MOV        AL,byte ptr [BP + param_3]
       1000:1006 50              PUSH       AX
       1000:1007 8b 56 f2        MOV        DX,word ptr [BP + local_10]
       1000:100a 2b c9           SUB        CX,CX
       1000:100c 52              PUSH       DX
       1000:100d 51              PUSH       CX
       1000:100e 9a 58 12        CALLF      FUN_1000_1258                                    undefined FUN_1000_1258(undefine
                 00 10
       1000:1013 0b c0           OR         AX,AX
       1000:1015 74 3e           JZ         LAB_1000_1055
       1000:1017 8e 46 f6        MOV        ES,word ptr [BP + local_c]
       1000:101a 26 8a 64 04     MOV        AH,byte ptr ES:[SI + 0x4]
       1000:101e 80 e4 83        AND        AH,0x83
       1000:1021 80 fc 01        CMP        AH,0x1
       1000:1024 75 22           JNZ        LAB_1000_1048
       1000:1026 c4 5e f8        LES        BX,[BP + local_a]
       1000:1029 2a e4           SUB        AH,AH
       1000:102b 26 8a 47 02     MOV        AL,byte ptr ES:[BX + 0x2]
       1000:102f 26 8a 4f 01     MOV        CL,byte ptr ES:[BX + 0x1]
       1000:1033 2a ed           SUB        CH,CH
       1000:1035 2b c1           SUB        AX,CX
       1000:1037 40              INC        AX
       1000:1038 99              CWD
       1000:1039 c4 5e 0a        LES        BX,[BP + param_2]
       1000:103c 26 89 07        MOV        word ptr ES:[BX],AX
       1000:103f 26 89 57 02     MOV        word ptr ES:[BX + 0x2],DX
       1000:1043 c7 46 ee        MOV        word ptr [BP + local_14],0x1
                 01 00
                             LAB_1000_1048                                   XREF[1]:     1000:1024(j)  
       1000:1048 8e 46 f6        MOV        ES,word ptr [BP + local_c]
       1000:104b 26 8b 44 03     MOV        AX,word ptr ES:[SI + 0x3]
       1000:104f c4 5e 06        LES        BX,[BP + param_1]
       1000:1052 26 89 07        MOV        word ptr ES:[BX],AX
                             LAB_1000_1055                                   XREF[1]:     1000:1015(j)  
       1000:1055 ff 76 fc        PUSH       word ptr [BP + local_6]
       1000:1058 9a 50 00        CALLF      KERNEL::GLOBALDOSFREE                            undefined GLOBALDOSFREE()
                 10 10
       1000:105d ff 76 f0        PUSH       word ptr [BP + local_12]
       1000:1060 9a 50 00        CALLF      KERNEL::GLOBALDOSFREE                            undefined GLOBALDOSFREE()
                 10 10
       1000:1065 8b 46 ee        MOV        AX,word ptr [BP + local_14]
                             LAB_1000_1068                                   XREF[1]:     1000:0f6a(j)  
       1000:1068 1f              POP        DS
       1000:1069 5e              POP        SI
       1000:106a c9              LEAVE
       1000:106b ca 0a 00        RETF       0xa
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined __stdcall16far GETVECTORS_IF(undefined2 param_
                               assume DS = 0x1008
             undefined         AL:1           <RETURN>
             undefined2        Stack[0x4]:2   param_1                                 XREF[1]:     1000:1080(*)  
             undefined2        Stack[0x6]:2   param_2                                 XREF[1]:     1000:107d(*)  
             undefined2        Stack[0x8]:2   param_3                                 XREF[1]:     1000:107a(*)  
             undefined2        Stack[0xa]:2   param_4                                 XREF[1]:     1000:1077(*)  
                             Ordinal_4                                       XREF[1]:     Entry Point(*)  
                             GETVECTORS_IF
       1000:106e b8 08 10        MOV        AX,0x1008
       1000:1071 55              PUSH       BP
       1000:1072 8b ec           MOV        BP,SP
       1000:1074 1e              PUSH       DS
       1000:1075 8e d8           MOV        DS,AX
       1000:1077 ff 76 0c        PUSH       word ptr [BP + param_4]
       1000:107a ff 76 0a        PUSH       word ptr [BP + param_3]
       1000:107d ff 76 08        PUSH       word ptr [BP + param_2]
       1000:1080 ff 76 06        PUSH       word ptr [BP + param_1]
       1000:1083 9a c0 12        CALLF      FUN_1000_12c0                                    undefined FUN_1000_12c0(undefine
                 00 10
       1000:1088 1f              POP        DS
       1000:1089 c9              LEAVE
       1000:108a ca 08 00        RETF       0x8
       1000:108d 00              ??         00h
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined __stdcall16far INITVECTORS(undefined2 param_1,
                               assume DS = 0x1008
             undefined         AL:1           <RETURN>
             undefined2        Stack[0x4]:2   param_1                                 XREF[1]:     1000:10a0(*)  
             undefined2        Stack[0x6]:2   param_2                                 XREF[1]:     1000:109d(*)  
             undefined2        Stack[0x8]:2   param_3                                 XREF[1]:     1000:109a(*)  
             undefined2        Stack[0xa]:2   param_4                                 XREF[1]:     1000:1097(*)  
                             Ordinal_15                                      XREF[1]:     Entry Point(*)  
                             INITVECTORS
       1000:108e b8 08 10        MOV        AX,0x1008
       1000:1091 55              PUSH       BP
       1000:1092 8b ec           MOV        BP,SP
       1000:1094 1e              PUSH       DS
       1000:1095 8e d8           MOV        DS,AX
       1000:1097 ff 76 0c        PUSH       word ptr [BP + param_4]
       1000:109a ff 76 0a        PUSH       word ptr [BP + param_3]
       1000:109d ff 76 08        PUSH       word ptr [BP + param_2]
       1000:10a0 ff 76 06        PUSH       word ptr [BP + param_1]
       1000:10a3 9a 20 13        CALLF      FUN_1000_1320                                    undefined FUN_1000_1320(undefine
                 00 10
       1000:10a8 1f              POP        DS
       1000:10a9 c9              LEAVE
       1000:10aa ca 08 00        RETF       0x8
       1000:10ad 00              ??         00h
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined __stdcall16far INITIV(undefined4 param_1, unde
                               assume DS = 0x1008
             undefined         AL:1           <RETURN>
             undefined4        Stack[0x4]:4   param_1                                 XREF[1]:     1000:1198(*)  
             undefined4        Stack[0x8]:4   param_2                                 XREF[1]:     1000:1182(*)  
             undefined1        Stack[0xc]:1   param_3                                 XREF[1]:     1000:1154(*)  
             undefined2        Stack[-0x4]:2  local_4                                 XREF[2]:     1000:10c5(*), 
                                                                                                   1000:10d1(*)  
             undefined2        Stack[-0x6]:2  local_6                                 XREF[4]:     1000:10c2(*), 
                                                                                                   1000:10dc(*), 
                                                                                                   1000:110d(*), 
                                                                                                   1000:119e(*)  
             undefined2        Stack[-0x8]:2  local_8                                 XREF[4]:     1000:1122(*), 
                                                                                                   1000:112f(*), 
                                                                                                   1000:1168(*), 
                                                                                                   1000:1191(*)  
             undefined2        Stack[-0xc]:2  local_c                                 XREF[2]:     1000:10e3(*), 
                                                                                                   1000:10f3(*)  
             undefined2        Stack[-0xe]:2  local_e                                 XREF[2]:     1000:1117(*), 
                                                                                                   1000:1177(*)  
             undefined2        Stack[-0x10]:2 local_10                                XREF[2]:     1000:1106(*), 
                                                                                                   1000:1158(*)  
             undefined2        Stack[-0x12]:2 local_12                                XREF[2]:     1000:1103(*), 
                                                                                                   1000:11a6(*)  
             undefined2        Stack[-0x14]:2 local_14                                XREF[3]:     1000:114f(*), 
                                                                                                   1000:118c(*), 
                                                                                                   1000:11ae(*)  
             undefined2        Stack[-0x16]:2 local_16                                XREF[2]:     1000:10d9(*), 
                                                                                                   1000:113e(*)  
             undefined2        Stack[-0x18]:2 local_18                                XREF[2]:     1000:10d4(*), 
                                                                                                   1000:113b(*)  
                             Ordinal_16                                      XREF[1]:     Entry Point(*)  
                             INITIV
       1000:10ae b8 08 10        MOV        AX,0x1008
       1000:10b1 c8 16 00 00     ENTER      0x16,0x0
       1000:10b5 56              PUSH       SI
       1000:10b6 1e              PUSH       DS
       1000:10b7 8e d8           MOV        DS,AX
       1000:10b9 6a 00           PUSH       0x0
       1000:10bb 6a 05           PUSH       0x5
       1000:10bd 9a 4c 00        CALLF      KERNEL::GLOBALDOSALLOC                           undefined GLOBALDOSALLOC()
                 10 10
       1000:10c2 89 46 fc        MOV        word ptr [BP + local_6],AX
       1000:10c5 89 56 fe        MOV        word ptr [BP + local_4],DX
       1000:10c8 0b d0           OR         DX,AX
       1000:10ca 75 05           JNZ        LAB_1000_10d1
                             LAB_1000_10cc                                   XREF[1]:     1000:1115(j)  
       1000:10cc 33 c0           XOR        AX,AX
       1000:10ce e9 e0 00        JMP        LAB_1000_11b1
                             LAB_1000_10d1                                   XREF[1]:     1000:10ca(j)  
       1000:10d1 8b 46 fe        MOV        AX,word ptr [BP + local_4]
       1000:10d4 c7 46 ea        MOV        word ptr [BP + local_18],0x0
                 00 00
       1000:10d9 89 46 ec        MOV        word ptr [BP + local_16],AX
       1000:10dc 8b 56 fc        MOV        DX,word ptr [BP + local_6]
       1000:10df 2b c9           SUB        CX,CX
       1000:10e1 8b f1           MOV        SI,CX
       1000:10e3 89 56 f6        MOV        word ptr [BP + local_c],DX
       1000:10e6 6a 05           PUSH       0x5
       1000:10e8 51              PUSH       CX
       1000:10e9 52              PUSH       DX
       1000:10ea 51              PUSH       CX
       1000:10eb 9a be 00        CALLF      FUN_1000_00be                                    undefined FUN_1000_00be(undefine
                 00 10
       1000:10f0 83 c4 08        ADD        SP,0x8
       1000:10f3 8e 46 f6        MOV        ES,word ptr [BP + local_c]
       1000:10f6 26 c6 04 06     MOV        byte ptr ES:[SI],0x6
       1000:10fa 6a 00           PUSH       0x0
       1000:10fc 6a 1c           PUSH       0x1c
       1000:10fe 9a 4c 00        CALLF      KERNEL::GLOBALDOSALLOC                           undefined GLOBALDOSALLOC()
                 10 10
       1000:1103 89 46 f0        MOV        word ptr [BP + local_12],AX
       1000:1106 89 56 f2        MOV        word ptr [BP + local_10],DX
       1000:1109 0b d0           OR         DX,AX
       1000:110b 75 0a           JNZ        LAB_1000_1117
       1000:110d ff 76 fc        PUSH       word ptr [BP + local_6]
       1000:1110 9a 50 00        CALLF      KERNEL::GLOBALDOSFREE                            undefined GLOBALDOSFREE()
                 10 10
       1000:1115 eb b5           JMP        LAB_1000_10cc
                             LAB_1000_1117                                   XREF[1]:     1000:110b(j)  
       1000:1117 89 76 f4        MOV        word ptr [BP + local_e],SI
       1000:111a 6a 1c           PUSH       0x1c
       1000:111c 6a 00           PUSH       0x0
       1000:111e 2b c9           SUB        CX,CX
       1000:1120 8b f1           MOV        SI,CX
       1000:1122 89 46 fa        MOV        word ptr [BP + local_8],AX
       1000:1125 50              PUSH       AX
       1000:1126 51              PUSH       CX
       1000:1127 9a be 00        CALLF      FUN_1000_00be                                    undefined FUN_1000_00be(undefine
                 00 10
       1000:112c 83 c4 08        ADD        SP,0x8
       1000:112f 8e 46 fa        MOV        ES,word ptr [BP + local_8]
       1000:1132 26 c6 04 1c     MOV        byte ptr ES:[SI],0x1c
       1000:1136 26 c6 44        MOV        byte ptr ES:[SI + 0x2],0x3
                 02 03
       1000:113b 8b 46 ea        MOV        AX,word ptr [BP + local_18]
       1000:113e 8b 56 ec        MOV        DX,word ptr [BP + local_16]
       1000:1141 26 89 44 0e     MOV        word ptr ES:[SI + 0xe],AX
       1000:1145 26 89 54 10     MOV        word ptr ES:[SI + 0x10],DX
       1000:1149 26 c7 44        MOV        word ptr ES:[SI + 0x12],0x5
                 12 05 00
       1000:114f c7 46 ee        MOV        word ptr [BP + local_14],0x0
                 00 00
       1000:1154 8a 46 0e        MOV        AL,byte ptr [BP + param_3]
       1000:1157 50              PUSH       AX
       1000:1158 8b 56 f2        MOV        DX,word ptr [BP + local_10]
       1000:115b 2b c9           SUB        CX,CX
       1000:115d 52              PUSH       DX
       1000:115e 51              PUSH       CX
       1000:115f 9a 58 12        CALLF      FUN_1000_1258                                    undefined FUN_1000_1258(undefine
                 00 10
       1000:1164 0b c0           OR         AX,AX
       1000:1166 74 36           JZ         LAB_1000_119e
       1000:1168 8e 46 fa        MOV        ES,word ptr [BP + local_8]
       1000:116b 26 8a 64 04     MOV        AH,byte ptr ES:[SI + 0x4]
       1000:116f 80 e4 83        AND        AH,0x83
       1000:1172 80 fc 01        CMP        AH,0x1
       1000:1175 75 1a           JNZ        LAB_1000_1191
       1000:1177 c4 5e f4        LES        BX,[BP + local_e]
       1000:117a 26 8b 47 01     MOV        AX,word ptr ES:[BX + 0x1]
       1000:117e 26 8b 57 03     MOV        DX,word ptr ES:[BX + 0x3]
       1000:1182 c4 5e 0a        LES        BX,[BP + param_2]
       1000:1185 26 89 07        MOV        word ptr ES:[BX],AX
       1000:1188 26 89 57 02     MOV        word ptr ES:[BX + 0x2],DX
       1000:118c c7 46 ee        MOV        word ptr [BP + local_14],0x1
                 01 00
                             LAB_1000_1191                                   XREF[1]:     1000:1175(j)  
       1000:1191 8e 46 fa        MOV        ES,word ptr [BP + local_8]
       1000:1194 26 8b 44 03     MOV        AX,word ptr ES:[SI + 0x3]
       1000:1198 c4 5e 06        LES        BX,[BP + param_1]
       1000:119b 26 89 07        MOV        word ptr ES:[BX],AX
                             LAB_1000_119e                                   XREF[1]:     1000:1166(j)  
       1000:119e ff 76 fc        PUSH       word ptr [BP + local_6]
       1000:11a1 9a 50 00        CALLF      KERNEL::GLOBALDOSFREE                            undefined GLOBALDOSFREE()
                 10 10
       1000:11a6 ff 76 f0        PUSH       word ptr [BP + local_12]
       1000:11a9 9a 50 00        CALLF      KERNEL::GLOBALDOSFREE                            undefined GLOBALDOSFREE()
                 10 10
       1000:11ae 8b 46 ee        MOV        AX,word ptr [BP + local_14]
                             LAB_1000_11b1                                   XREF[1]:     1000:10ce(j)  
       1000:11b1 1f              POP        DS
       1000:11b2 5e              POP        SI
       1000:11b3 c9              LEAVE
       1000:11b4 ca 0a 00        RETF       0xa
       1000:11b7 00              ??         00h
       1000:11b8 43 4c 43        ds         "CLCD32.DLL"
                 44 33 32 
                 2e 44 4c 
       1000:11c4 43 4c 43        ds         "CLCD16.DLL"
                 44 31 36 
                 2e 44 4c 
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined __stdcall16far FUN_1000_11d0(undefined2 param_
                               assume DS = 0x1008
             undefined         AL:1           <RETURN>
             undefined2        Stack[0x4]:2   param_1                                 XREF[1]:     1000:11d6(*)  
             undefined2        Stack[0x6]:2   param_2                                 XREF[1]:     1000:11ed(*)  
             undefined2        Stack[0x8]:2   param_3                                 XREF[1]:     1000:1225(*)  
             undefined2        Stack[0xa]:2   param_4                                 XREF[1]:     1000:121a(*)  
             undefined1        Stack[0xc]:1   param_5                                 XREF[1]:     1000:1203(*)  
             undefined2        Stack[-0x12]:2 local_12                                XREF[1]:     1000:1200(*)  
             undefined1        Stack[-0x14]:1 local_14                                XREF[1]:     1000:1242(*)  
             undefined2        Stack[-0x16]:2 local_16                                XREF[1]:     1000:11e8(*)  
             undefined2        Stack[-0x18]:2 local_18                                XREF[1]:     1000:11e3(*)  
             undefined2        Stack[-0x1a]:2 local_1a                                XREF[1]:     1000:120b(*)  
             undefined2        Stack[-0x1c]:2 local_1c                                XREF[1]:     1000:1208(*)  
             undefined2        Stack[-0x1e]:2 local_1e                                XREF[1]:     1000:1215(*)  
             undefined2        Stack[-0x20]:2 local_20                                XREF[1]:     1000:1210(*)  
             undefined2        Stack[-0x22]:2 local_22                                XREF[1]:     1000:11f9(*)  
             undefined2        Stack[-0x24]:2 local_24                                XREF[1]:     1000:11f6(*)  
             undefined2        Stack[-0x2e]:2 local_2e                                XREF[1]:     1000:1220(*)  
             undefined2        Stack[-0x30]:2 local_30                                XREF[1]:     1000:121d(*)  
             undefined2        Stack[-0x32]:2 local_32                                XREF[1]:     1000:122b(*)  
             undefined2        Stack[-0x34]:2 local_34                                XREF[3]:     1000:11d9(*), 
                                                                                                   1000:1228(*), 
                                                                                                   1000:1232(*)  
             undefined2        Stack[-0x36]:2 local_36                                XREF[1]:     1000:11f3(*)  
             undefined2        Stack[-0x38]:2 local_38                                XREF[1]:     1000:11f0(*)  
                             FUN_1000_11d0                                   XREF[1]:     GETPMVECTOR_IF:1000:0db3(c)  
       1000:11d0 c8 36 00 00     ENTER      0x36,0x0
       1000:11d4 57              PUSH       DI
       1000:11d5 56              PUSH       SI
       1000:11d6 8b 7e 06        MOV        DI,word ptr [BP + param_1]
       1000:11d9 8d 46 ce        LEA        AX,[BP + local_34]
       1000:11dc 16              PUSH       SS
       1000:11dd 50              PUSH       AX
       1000:11de 9a ba 13        CALLF      FUN_1000_13ba                                    undefined FUN_1000_13ba(undefine
                 00 10
       1000:11e3 c7 46 ea        MOV        word ptr [BP + local_18],0x1508
                 08 15
       1000:11e8 c7 46 ec        MOV        word ptr [BP + local_16],0x0
                 00 00
       1000:11ed 8b 4e 08        MOV        CX,word ptr [BP + param_2]
       1000:11f0 89 7e ca        MOV        word ptr [BP + local_38],DI
       1000:11f3 89 4e cc        MOV        word ptr [BP + local_36],CX
       1000:11f6 89 7e de        MOV        word ptr [BP + local_24],DI
       1000:11f9 c7 46 e0        MOV        word ptr [BP + local_22],0x0
                 00 00
       1000:11fe 8b c1           MOV        AX,CX
       1000:1200 89 4e f0        MOV        word ptr [BP + local_12],CX
       1000:1203 8a 46 0e        MOV        AL,byte ptr [BP + param_5]
       1000:1206 2a e4           SUB        AH,AH
       1000:1208 89 46 e6        MOV        word ptr [BP + local_1c],AX
       1000:120b c7 46 e8        MOV        word ptr [BP + local_1a],0x0
                 00 00
       1000:1210 c7 46 e2        MOV        word ptr [BP + local_20],0x1
                 01 00
       1000:1215 c7 46 e4        MOV        word ptr [BP + local_1e],0x0
                 00 00
       1000:121a 8b 46 0c        MOV        AX,word ptr [BP + param_4]
       1000:121d 89 46 d2        MOV        word ptr [BP + local_30],AX
       1000:1220 c7 46 d4        MOV        word ptr [BP + local_2e],0x0
                 00 00
       1000:1225 8b 46 0a        MOV        AX,word ptr [BP + param_3]
       1000:1228 89 46 ce        MOV        word ptr [BP + local_34],AX
       1000:122b c7 46 d0        MOV        word ptr [BP + local_32],0x0
                 00 00
       1000:1230 6a 2f           PUSH       0x2f
       1000:1232 8d 46 ce        LEA        AX,[BP + local_34]
       1000:1235 16              PUSH       SS
       1000:1236 50              PUSH       AX
       1000:1237 9a 90 13        CALLF      FUN_1000_1390                                    undefined FUN_1000_1390(undefine
                 00 10
       1000:123c 8b f0           MOV        SI,AX
       1000:123e 0b f0           OR         SI,AX
       1000:1240 74 0d           JZ         LAB_1000_124f
       1000:1242 8a 46 ee        MOV        AL,byte ptr [BP + local_14]
       1000:1245 25 01 00        AND        AX,0x1
       1000:1248 3d 01 00        CMP        AX,0x1
       1000:124b 1b f6           SBB        SI,SI
       1000:124d f7 de           NEG        SI
                             LAB_1000_124f                                   XREF[1]:     1000:1240(j)  
       1000:124f 8b c6           MOV        AX,SI
       1000:1251 5e              POP        SI
       1000:1252 5f              POP        DI
       1000:1253 c9              LEAVE
       1000:1254 ca 0a 00        RETF       0xa
       1000:1257 00              ??         00h
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined __stdcall16far FUN_1000_1258(undefined2 param_
                               assume DS = 0x1008
             undefined         AL:1           <RETURN>
             undefined2        Stack[0x4]:2   param_1                                 XREF[1]:     1000:125e(*)  
             undefined2        Stack[0x6]:2   param_2                                 XREF[1]:     1000:1275(*)  
             undefined1        Stack[0x8]:1   param_3                                 XREF[1]:     1000:128b(*)  
             undefined2        Stack[-0x12]:2 local_12                                XREF[1]:     1000:1288(*)  
             undefined1        Stack[-0x14]:1 local_14                                XREF[1]:     1000:12aa(*)  
             undefined2        Stack[-0x16]:2 local_16                                XREF[1]:     1000:1270(*)  
             undefined2        Stack[-0x18]:2 local_18                                XREF[1]:     1000:126b(*)  
             undefined2        Stack[-0x1a]:2 local_1a                                XREF[1]:     1000:1293(*)  
             undefined2        Stack[-0x1c]:2 local_1c                                XREF[1]:     1000:1290(*)  
             undefined2        Stack[-0x22]:2 local_22                                XREF[1]:     1000:1281(*)  
             undefined2        Stack[-0x24]:2 local_24                                XREF[1]:     1000:127e(*)  
             undefined         Stack[-0x34]:1 local_34                                XREF[2]:     1000:1261(*), 
                                                                                                   1000:129a(*)  
             undefined2        Stack[-0x36]:2 local_36                                XREF[1]:     1000:127b(*)  
             undefined2        Stack[-0x38]:2 local_38                                XREF[1]:     1000:1278(*)  
                             FUN_1000_1258                                   XREF[6]:     SETPMVECTOR_IF:1000:0a04(c), 
                                                                                          SETRMINTS_IF:1000:0b91(c), 
                                                                                          SETVECTORS_IF:1000:0cb9(c), 
                                                                                          GETV86VECTOR_IF:1000:0ed4(c), 
                                                                                          SETV86VECTOR_IF:1000:100e(c), 
                                                                                          INITIV:1000:115f(c)  
       1000:1258 c8 36 00 00     ENTER      0x36,0x0
       1000:125c 57              PUSH       DI
       1000:125d 56              PUSH       SI
       1000:125e 8b 7e 06        MOV        DI,word ptr [BP + param_1]
       1000:1261 8d 46 ce        LEA        AX,[BP + local_34]
       1000:1264 16              PUSH       SS
       1000:1265 50              PUSH       AX
       1000:1266 9a ba 13        CALLF      FUN_1000_13ba                                    undefined FUN_1000_13ba(undefine
                 00 10
       1000:126b c7 46 ea        MOV        word ptr [BP + local_18],0x1510
                 10 15
       1000:1270 c7 46 ec        MOV        word ptr [BP + local_16],0x0
                 00 00
       1000:1275 8b 4e 08        MOV        CX,word ptr [BP + param_2]
       1000:1278 89 7e ca        MOV        word ptr [BP + local_38],DI
       1000:127b 89 4e cc        MOV        word ptr [BP + local_36],CX
       1000:127e 89 7e de        MOV        word ptr [BP + local_24],DI
       1000:1281 c7 46 e0        MOV        word ptr [BP + local_22],0x0
                 00 00
       1000:1286 8b c1           MOV        AX,CX
       1000:1288 89 4e f0        MOV        word ptr [BP + local_12],CX
       1000:128b 8a 46 0a        MOV        AL,byte ptr [BP + param_3]
       1000:128e 2a e4           SUB        AH,AH
       1000:1290 89 46 e6        MOV        word ptr [BP + local_1c],AX
       1000:1293 c7 46 e8        MOV        word ptr [BP + local_1a],0x0
                 00 00
       1000:1298 6a 2f           PUSH       0x2f
       1000:129a 8d 46 ce        LEA        AX,[BP + local_34]
       1000:129d 16              PUSH       SS
       1000:129e 50              PUSH       AX
       1000:129f 9a 90 13        CALLF      FUN_1000_1390                                    undefined FUN_1000_1390(undefine
                 00 10
       1000:12a4 8b f0           MOV        SI,AX
       1000:12a6 0b f0           OR         SI,AX
       1000:12a8 74 0d           JZ         LAB_1000_12b7
       1000:12aa 8a 46 ee        MOV        AL,byte ptr [BP + local_14]
       1000:12ad 25 01 00        AND        AX,0x1
       1000:12b0 3d 01 00        CMP        AX,0x1
       1000:12b3 1b f6           SBB        SI,SI
       1000:12b5 f7 de           NEG        SI
                             LAB_1000_12b7                                   XREF[1]:     1000:12a8(j)  
       1000:12b7 8b c6           MOV        AX,SI
       1000:12b9 5e              POP        SI
       1000:12ba 5f              POP        DI
       1000:12bb c9              LEAVE
       1000:12bc ca 06 00        RETF       0x6
       1000:12bf 00              ??         00h
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined __stdcall16far FUN_1000_12c0(undefined4 param_
                               assume DS = 0x1008
             undefined         AL:1           <RETURN>
             undefined4        Stack[0x4]:4   param_1                                 XREF[1]:     1000:1312(*)  
             undefined4        Stack[0x8]:4   param_2                                 XREF[1]:     1000:1309(*)  
             undefined1        Stack[-0x14]:1 local_14                                XREF[1]:     1000:12eb(*)  
             undefined2        Stack[-0x16]:2 local_16                                XREF[1]:     1000:12d4(*)  
             undefined2        Stack[-0x18]:2 local_18                                XREF[1]:     1000:12cf(*)  
             undefined2        Stack[-0x22]:2 local_22                                XREF[1]:     1000:12ff(*)  
             undefined2        Stack[-0x24]:2 local_24                                XREF[2]:     1000:12fc(*), 
                                                                                                   1000:130f(*)  
             undefined         Stack[-0x34]:1 local_34                                XREF[2]:     1000:12c5(*), 
                                                                                                   1000:12db(*)  
                             FUN_1000_12c0                                   XREF[1]:     GETVECTORS_IF:1000:1083(c)  
       1000:12c0 c8 32 00 00     ENTER      0x32,0x0
       1000:12c4 56              PUSH       SI
       1000:12c5 8d 46 ce        LEA        AX,[BP + local_34]
       1000:12c8 16              PUSH       SS
       1000:12c9 50              PUSH       AX
       1000:12ca 9a ba 13        CALLF      FUN_1000_13ba                                    undefined FUN_1000_13ba(undefine
                 00 10
       1000:12cf c7 46 ea        MOV        word ptr [BP + local_18],0x150c
                 0c 15
       1000:12d4 c7 46 ec        MOV        word ptr [BP + local_16],0x0
                 00 00
       1000:12d9 6a 2f           PUSH       0x2f
       1000:12db 8d 46 ce        LEA        AX,[BP + local_34]
       1000:12de 16              PUSH       SS
       1000:12df 50              PUSH       AX
       1000:12e0 9a 90 13        CALLF      FUN_1000_1390                                    undefined FUN_1000_1390(undefine
                 00 10
       1000:12e5 8b f0           MOV        SI,AX
       1000:12e7 0b f0           OR         SI,AX
       1000:12e9 74 2d           JZ         LAB_1000_1318
       1000:12eb 8a 46 ee        MOV        AL,byte ptr [BP + local_14]
       1000:12ee 25 01 00        AND        AX,0x1
       1000:12f1 3d 01 00        CMP        AX,0x1
       1000:12f4 1b f6           SBB        SI,SI
       1000:12f6 f7 de           NEG        SI
       1000:12f8 0b f6           OR         SI,SI
       1000:12fa 74 1c           JZ         LAB_1000_1318
       1000:12fc 8b 46 de        MOV        AX,word ptr [BP + local_24]
       1000:12ff 8b 56 e0        MOV        DX,word ptr [BP + local_22]
       1000:1302 b1 08           MOV        CL,0x8
       1000:1304 9a 06 01        CALLF      FUN_1000_0106                                    undefined FUN_1000_0106()
                 00 10
       1000:1309 c4 5e 0a        LES        BX,[BP + param_2]
       1000:130c 26 88 07        MOV        byte ptr ES:[BX],AL
       1000:130f 8a 46 de        MOV        AL,byte ptr [BP + local_24]
       1000:1312 c4 5e 06        LES        BX,[BP + param_1]
       1000:1315 26 88 07        MOV        byte ptr ES:[BX],AL
                             LAB_1000_1318                                   XREF[2]:     1000:12e9(j), 1000:12fa(j)  
       1000:1318 8b c6           MOV        AX,SI
       1000:131a 5e              POP        SI
       1000:131b c9              LEAVE
       1000:131c ca 08 00        RETF       0x8
       1000:131f 00              ??         00h
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined __stdcall16far FUN_1000_1320(undefined2 param_
                               assume DS = 0x1008
             undefined         AL:1           <RETURN>
             undefined2        Stack[0x4]:2   param_1                                 XREF[1]:     1000:1326(*)  
             undefined2        Stack[0x6]:2   param_2                                 XREF[2]:     1000:1329(*), 
                                                                                                   1000:1380(*)  
             undefined2        Stack[0x8]:2   param_3                                 XREF[1]:     1000:1344(*)  
             undefined2        Stack[0xa]:2   param_4                                 XREF[1]:     1000:1347(*)  
             undefined1        Stack[-0x14]:1 local_14                                XREF[1]:     1000:1362(*)  
             undefined2        Stack[-0x16]:2 local_16                                XREF[1]:     1000:133f(*)  
             undefined2        Stack[-0x18]:2 local_18                                XREF[2]:     1000:133a(*), 
                                                                                                   1000:1373(*)  
             undefined2        Stack[-0x1a]:2 local_1a                                XREF[1]:     1000:134d(*)  
             undefined2        Stack[-0x1c]:2 local_1c                                XREF[1]:     1000:134a(*)  
             undefined2        Stack[-0x24]:2 local_24                                XREF[1]:     1000:1379(*)  
             undefined         Stack[-0x34]:1 local_34                                XREF[2]:     1000:1330(*), 
                                                                                                   1000:1352(*)  
                             FUN_1000_1320                                   XREF[1]:     INITVECTORS:1000:10a3(c)  
       1000:1320 c8 32 00 00     ENTER      0x32,0x0
       1000:1324 57              PUSH       DI
       1000:1325 56              PUSH       SI
       1000:1326 8b 7e 06        MOV        DI,word ptr [BP + param_1]
       1000:1329 8e 46 08        MOV        ES,word ptr [BP + param_2]
       1000:132c 26 c6 05 00     MOV        byte ptr ES:[DI],0x0
       1000:1330 8d 46 ce        LEA        AX,[BP + local_34]
       1000:1333 16              PUSH       SS
       1000:1334 50              PUSH       AX
       1000:1335 9a ba 13        CALLF      FUN_1000_13ba                                    undefined FUN_1000_13ba(undefine
                 00 10
       1000:133a c7 46 ea        MOV        word ptr [BP + local_18],0x150b
                 0b 15
       1000:133f c7 46 ec        MOV        word ptr [BP + local_16],0x0
                 00 00
       1000:1344 8b 46 0a        MOV        AX,word ptr [BP + param_3]
       1000:1347 8b 56 0c        MOV        DX,word ptr [BP + param_4]
       1000:134a 89 46 e6        MOV        word ptr [BP + local_1c],AX
       1000:134d 89 56 e8        MOV        word ptr [BP + local_1a],DX
       1000:1350 6a 2f           PUSH       0x2f
       1000:1352 8d 46 ce        LEA        AX,[BP + local_34]
       1000:1355 16              PUSH       SS
       1000:1356 50              PUSH       AX
       1000:1357 9a 90 13        CALLF      FUN_1000_1390                                    undefined FUN_1000_1390(undefine
                 00 10
       1000:135c 8b f0           MOV        SI,AX
       1000:135e 0b f0           OR         SI,AX
       1000:1360 74 25           JZ         LAB_1000_1387
       1000:1362 8a 46 ee        MOV        AL,byte ptr [BP + local_14]
       1000:1365 25 01 00        AND        AX,0x1
       1000:1368 3d 01 00        CMP        AX,0x1
       1000:136b 1b f6           SBB        SI,SI
       1000:136d f7 de           NEG        SI
       1000:136f 0b f6           OR         SI,SI
       1000:1371 74 14           JZ         LAB_1000_1387
       1000:1373 83 7e ea 00     CMP        word ptr [BP + local_18],0x0
       1000:1377 74 0e           JZ         LAB_1000_1387
       1000:1379 81 7e de        CMP        word ptr [BP + local_24],0xadad
                 ad ad
       1000:137e 75 07           JNZ        LAB_1000_1387
       1000:1380 8e 46 08        MOV        ES,word ptr [BP + param_2]
       1000:1383 26 c6 05 01     MOV        byte ptr ES:[DI],0x1
                             LAB_1000_1387                                   XREF[4]:     1000:1360(j), 1000:1371(j), 
                                                                                          1000:1377(j), 1000:137e(j)  
       1000:1387 8b c6           MOV        AX,SI
       1000:1389 5e              POP        SI
       1000:138a 5f              POP        DI
       1000:138b c9              LEAVE
       1000:138c ca 08 00        RETF       0x8
       1000:138f 00              ??         00h
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined __stdcall16far FUN_1000_1390(undefined4 param_
                               assume DS = 0x1008
             undefined         AL:1           <RETURN>
             undefined4        Stack[0x4]:4   param_1                                 XREF[1]:     1000:13a5(*)  
             undefined1        Stack[0x8]:1   param_2                                 XREF[1]:     1000:139e(*)  
             undefined2        Stack[-0x4]:2  local_4                                 XREF[3]:     1000:1395(*), 
                                                                                                   1000:13ac(*), 
                                                                                                   1000:13b2(*)  
                             FUN_1000_1390                                   XREF[4]:     FUN_1000_11d0:1000:1237(c), 
                                                                                          FUN_1000_1258:1000:129f(c), 
                                                                                          FUN_1000_12c0:1000:12e0(c), 
                                                                                          FUN_1000_1320:1000:1357(c)  
       1000:1390 c8 02 00 00     ENTER      0x2,0x0
       1000:1394 57              PUSH       DI
       1000:1395 c7 46 fe        MOV        word ptr [BP + local_4],0x0
                 00 00
       1000:139a 57              PUSH       DI
       1000:139b b8 00 03        MOV        AX,0x300
       1000:139e 8a 5e 0a        MOV        BL,byte ptr [BP + param_2]
       1000:13a1 b7 01           MOV        BH,0x1
       1000:13a3 33 c9           XOR        CX,CX
       1000:13a5 c4 7e 06        LES        DI,[BP + param_1]
       1000:13a8 cd 31           INT        0x31
       1000:13aa 72 05           JC         LAB_1000_13b1
       1000:13ac c7 46 fe        MOV        word ptr [BP + local_4],0x1
                 01 00
                             LAB_1000_13b1                                   XREF[1]:     1000:13aa(j)  
       1000:13b1 5f              POP        DI
       1000:13b2 8b 46 fe        MOV        AX,word ptr [BP + local_4]
       1000:13b5 5f              POP        DI
       1000:13b6 c9              LEAVE
       1000:13b7 ca 06 00        RETF       0x6
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined __stdcall16far FUN_1000_13ba(undefined2 param_
                               assume DS = 0x1008
             undefined         AL:1           <RETURN>
             undefined2        Stack[0x4]:2   param_1                                 XREF[1]:     1000:13c4(*)  
             undefined2        Stack[0x6]:2   param_2                                 XREF[1]:     1000:13c1(*)  
                             FUN_1000_13ba                                   XREF[4]:     FUN_1000_11d0:1000:11de(c), 
                                                                                          FUN_1000_1258:1000:1266(c), 
                                                                                          FUN_1000_12c0:1000:12ca(c), 
                                                                                          FUN_1000_1320:1000:1335(c)  
       1000:13ba 55              PUSH       BP
       1000:13bb 8b ec           MOV        BP,SP
       1000:13bd 6a 32           PUSH       0x32
       1000:13bf 6a 00           PUSH       0x0
       1000:13c1 ff 76 08        PUSH       word ptr [BP + param_2]
       1000:13c4 ff 76 06        PUSH       word ptr [BP + param_1]
       1000:13c7 9a 70 01        CALLF      FUN_1000_0170                                    undefined FUN_1000_0170(undefine
                 00 10
       1000:13cc c9              LEAVE
       1000:13cd ca 04 00        RETF       0x4
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined __stdcall16far ISLOADCOMPLETE(undefined2 param
                               assume DS = 0x1008
             undefined         AL:1           <RETURN>
             undefined2        Stack[0x4]:2   param_1                                 XREF[1]:     1000:13dc(*)  
             undefined2        Stack[0x6]:2   param_2                                 XREF[2]:     1000:13e4(*), 
                                                                                                   1000:142b(*)  
             undefined2        Stack[-0x4]:2  local_4                                 XREF[4]:     1000:13f1(*), 
                                                                                                   1000:1406(*), 
                                                                                                   1000:1415(*), 
                                                                                                   1000:1437(*)  
             undefined2        Stack[-0xa]:2  local_a                                 XREF[3]:     1000:13df(*), 
                                                                                                   1000:1432(*), 
                                                                                                   1000:143f(*)  
                             Ordinal_17                                      XREF[1]:     Entry Point(*)  
                             ISLOADCOMPLETE
       1000:13d0 b8 08 10        MOV        AX,0x1008
       1000:13d3 c8 08 00 00     ENTER      0x8,0x0
       1000:13d7 57              PUSH       DI
       1000:13d8 56              PUSH       SI
       1000:13d9 1e              PUSH       DS
       1000:13da 8e d8           MOV        DS,AX
       1000:13dc 8b 7e 06        MOV        DI,word ptr [BP + param_1]
       1000:13df c7 46 f8        MOV        word ptr [BP + local_a],0x0
                 00 00
       1000:13e4 8e 46 08        MOV        ES,word ptr [BP + param_2]
       1000:13e7 26 c6 05 00     MOV        byte ptr ES:[DI],0x0
       1000:13eb 16              PUSH       SS
       1000:13ec 9a 40 00        CALLF      KERNEL::ALLOCSELECTOR                            undefined ALLOCSELECTOR()
                 10 10
       1000:13f1 89 46 fe        MOV        word ptr [BP + local_4],AX
       1000:13f4 0b c0           OR         AX,AX
       1000:13f6 74 47           JZ         LAB_1000_143f
       1000:13f8 50              PUSH       AX
       1000:13f9 6a 0f           PUSH       0xf
       1000:13fb 6a f0           PUSH       -0x10
       1000:13fd 9a 54 00        CALLF      KERNEL::SETSELECTORBASE                          undefined SETSELECTORBASE()
                 10 10
       1000:1402 0b c0           OR         AX,AX
       1000:1404 74 31           JZ         LAB_1000_1437
       1000:1406 ff 76 fe        PUSH       word ptr [BP + local_4]
       1000:1409 6a 00           PUSH       0x0
       1000:140b 6a 10           PUSH       0x10
       1000:140d 9a 58 00        CALLF      KERNEL::SETSELECTORLIMIT                         undefined SETSELECTORLIMIT()
                 10 10
       1000:1412 bb 05 00        MOV        BX,0x5
       1000:1415 8b 4e fe        MOV        CX,word ptr [BP + local_4]
       1000:1418 8e c1           MOV        ES,CX
       1000:141a 8b f3           MOV        SI,BX
       1000:141c 26 80 3e        CMP        byte ptr ES:[0x7],0x2f
                 07 00 2f
       1000:1422 74 0e           JZ         LAB_1000_1432
       1000:1424 26 80 7c        CMP        byte ptr ES:[SI + 0x5],0x2f
                 05 2f
       1000:1429 74 07           JZ         LAB_1000_1432
       1000:142b 8e 46 08        MOV        ES,word ptr [BP + param_2]
       1000:142e 26 c6 05 01     MOV        byte ptr ES:[DI],0x1
                             LAB_1000_1432                                   XREF[2]:     1000:1422(j), 1000:1429(j)  
       1000:1432 c7 46 f8        MOV        word ptr [BP + local_a],0x1
                 01 00
                             LAB_1000_1437                                   XREF[1]:     1000:1404(j)  
       1000:1437 ff 76 fe        PUSH       word ptr [BP + local_4]
       1000:143a 9a 44 00        CALLF      KERNEL::FREESELECTOR                             undefined FREESELECTOR()
                 10 10
                             LAB_1000_143f                                   XREF[1]:     1000:13f6(j)  
       1000:143f 8b 46 f8        MOV        AX,word ptr [BP + local_a]
       1000:1442 1f              POP        DS
       1000:1443 5e              POP        SI
       1000:1444 5f              POP        DI
       1000:1445 c9              LEAVE
       1000:1446 ca 04 00        RETF       0x4
                             //
                             // Data2 
                             // ram:1008:0000-ram:1008:0281
                             //
             assume DS = <UNKNOWN>
                             Segment:    2
                             Offset:     000017e0
                             Length:     0282
                             Min Alloc:  0282
                             Flags:      0d71
                                 Data
                                 Moveable
                                 Preload
                                 Pure (Shareable)
       1008:0000 00              ??         00h
       1008:0001 00              ??         00h
       1008:0002 00              ??         00h
       1008:0003 00              ??         00h
       1008:0004 05              ??         05h
       1008:0005 00              ??         00h
       1008:0006 00              ??         00h
       1008:0007 00              ??         00h
       1008:0008 00              ??         00h
       1008:0009 00              ??         00h
       1008:000a 00              ??         00h
       1008:000b 00              ??         00h
       1008:000c 00              ??         00h
       1008:000d 00              ??         00h
       1008:000e 00              ??         00h
       1008:000f 00              ??         00h
                             Ordinal_1                                       XREF[1]:     Entry Point(*)  
                             THK_THUNKDATA16
       1008:0010 4c              ??         4Ch    L
       1008:0011 53              ??         53h    S
       1008:0012 30              ??         30h    0
       1008:0013 31              ??         31h    1
       1008:0014 a5              ??         A5h
       1008:0015 4f              ??         4Fh    O
       1008:0016 01              ??         01h
       1008:0017 00              ??         00h
       1008:0018 00              ??         00h
       1008:0019 00              ??         00h
       1008:001a 00              ??         00h
       1008:001b 10              ??         10h
       1008:001c 00              ??         00h
       1008:001d 00              ??         00h
       1008:001e 00              ??         00h
       1008:001f 00              ??         00h
       1008:0020 00              ??         00h
       1008:0021 20              ??         20h     
       1008:0022 20              ??         20h     
       1008:0023 20              ??         20h     
       1008:0024 20              ??         20h     
       1008:0025 20              ??         20h     
       1008:0026 20              ??         20h     
       1008:0027 20              ??         20h     
       1008:0028 20              ??         20h     
       1008:0029 20              ??         20h     
       1008:002a 28              ??         28h    (
       1008:002b 28              ??         28h    (
       1008:002c 28              ??         28h    (
       1008:002d 28              ??         28h    (
       1008:002e 28              ??         28h    (
       1008:002f 20              ??         20h     
       1008:0030 20              ??         20h     
       1008:0031 20              ??         20h     
       1008:0032 20              ??         20h     
       1008:0033 20              ??         20h     
       1008:0034 20              ??         20h     
       1008:0035 20              ??         20h     
       1008:0036 20              ??         20h     
       1008:0037 20              ??         20h     
       1008:0038 20              ??         20h     
       1008:0039 20              ??         20h     
       1008:003a 20              ??         20h     
       1008:003b 20              ??         20h     
       1008:003c 20              ??         20h     
       1008:003d 20              ??         20h     
       1008:003e 20              ??         20h     
       1008:003f 20              ??         20h     
       1008:0040 20              ??         20h     
       1008:0041 48              ??         48h    H
       1008:0042 10              ??         10h
       1008:0043 10              ??         10h
       1008:0044 10              ??         10h
       1008:0045 10              ??         10h
       1008:0046 10              ??         10h
       1008:0047 10              ??         10h
       1008:0048 10              ??         10h
       1008:0049 10              ??         10h
       1008:004a 10              ??         10h
       1008:004b 10              ??         10h
       1008:004c 10              ??         10h
       1008:004d 10              ??         10h
       1008:004e 10              ??         10h
       1008:004f 10              ??         10h
       1008:0050 10              ??         10h
       1008:0051 84              ??         84h
       1008:0052 84              ??         84h
       1008:0053 84              ??         84h
       1008:0054 84              ??         84h
       1008:0055 84              ??         84h
       1008:0056 84              ??         84h
       1008:0057 84              ??         84h
       1008:0058 84              ??         84h
       1008:0059 84              ??         84h
       1008:005a 84              ??         84h
       1008:005b 10              ??         10h
       1008:005c 10              ??         10h
       1008:005d 10              ??         10h
       1008:005e 10              ??         10h
       1008:005f 10              ??         10h
       1008:0060 10              ??         10h
       1008:0061 10              ??         10h
       1008:0062 81              ??         81h
       1008:0063 81              ??         81h
       1008:0064 81              ??         81h
       1008:0065 81              ??         81h
       1008:0066 81              ??         81h
       1008:0067 81              ??         81h
       1008:0068 01              ??         01h
       1008:0069 01              ??         01h
       1008:006a 01              ??         01h
       1008:006b 01              ??         01h
       1008:006c 01              ??         01h
       1008:006d 01              ??         01h
       1008:006e 01              ??         01h
       1008:006f 01              ??         01h
       1008:0070 01              ??         01h
       1008:0071 01              ??         01h
       1008:0072 01              ??         01h
       1008:0073 01              ??         01h
       1008:0074 01              ??         01h
       1008:0075 01              ??         01h
       1008:0076 01              ??         01h
       1008:0077 01              ??         01h
       1008:0078 01              ??         01h
       1008:0079 01              ??         01h
       1008:007a 01              ??         01h
       1008:007b 01              ??         01h
       1008:007c 10              ??         10h
       1008:007d 10              ??         10h
       1008:007e 10              ??         10h
       1008:007f 10              ??         10h
       1008:0080 10              ??         10h
       1008:0081 10              ??         10h
       1008:0082 82              ??         82h
       1008:0083 82              ??         82h
       1008:0084 82              ??         82h
       1008:0085 82              ??         82h
       1008:0086 82              ??         82h
       1008:0087 82              ??         82h
       1008:0088 02              ??         02h
       1008:0089 02              ??         02h
       1008:008a 02              ??         02h
       1008:008b 02              ??         02h
       1008:008c 02              ??         02h
       1008:008d 02              ??         02h
       1008:008e 02              ??         02h
       1008:008f 02              ??         02h
       1008:0090 02              ??         02h
       1008:0091 02              ??         02h
       1008:0092 02              ??         02h
       1008:0093 02              ??         02h
       1008:0094 02              ??         02h
       1008:0095 02              ??         02h
       1008:0096 02              ??         02h
       1008:0097 02              ??         02h
       1008:0098 02              ??         02h
       1008:0099 02              ??         02h
       1008:009a 02              ??         02h
       1008:009b 02              ??         02h
       1008:009c 10              ??         10h
       1008:009d 10              ??         10h
       1008:009e 10              ??         10h
       1008:009f 10              ??         10h
       1008:00a0 20              ??         20h     
       1008:00a1 00              ??         00h
       1008:00a2 00              ??         00h
       1008:00a3 00              ??         00h
       1008:00a4 00              ??         00h
       1008:00a5 00              ??         00h
       1008:00a6 00              ??         00h
       1008:00a7 00              ??         00h
       1008:00a8 00              ??         00h
       1008:00a9 00              ??         00h
       1008:00aa 00              ??         00h
       1008:00ab 00              ??         00h
       1008:00ac 00              ??         00h
       1008:00ad 00              ??         00h
       1008:00ae 00              ??         00h
       1008:00af 00              ??         00h
       1008:00b0 00              ??         00h
       1008:00b1 00              ??         00h
       1008:00b2 00              ??         00h
       1008:00b3 00              ??         00h
       1008:00b4 00              ??         00h
       1008:00b5 00              ??         00h
       1008:00b6 00              ??         00h
       1008:00b7 00              ??         00h
       1008:00b8 00              ??         00h
       1008:00b9 00              ??         00h
       1008:00ba 00              ??         00h
       1008:00bb 00              ??         00h
       1008:00bc 00              ??         00h
       1008:00bd 00              ??         00h
       1008:00be 00              ??         00h
       1008:00bf 00              ??         00h
       1008:00c0 00              ??         00h
       1008:00c1 00              ??         00h
       1008:00c2 00              ??         00h
       1008:00c3 00              ??         00h
       1008:00c4 00              ??         00h
       1008:00c5 00              ??         00h
       1008:00c6 00              ??         00h
       1008:00c7 00              ??         00h
       1008:00c8 00              ??         00h
       1008:00c9 00              ??         00h
       1008:00ca 00              ??         00h
       1008:00cb 00              ??         00h
       1008:00cc 00              ??         00h
       1008:00cd 00              ??         00h
       1008:00ce 00              ??         00h
       1008:00cf 00              ??         00h
       1008:00d0 00              ??         00h
       1008:00d1 00              ??         00h
       1008:00d2 00              ??         00h
       1008:00d3 00              ??         00h
       1008:00d4 00              ??         00h
       1008:00d5 00              ??         00h
       1008:00d6 00              ??         00h
       1008:00d7 00              ??         00h
       1008:00d8 00              ??         00h
       1008:00d9 00              ??         00h
       1008:00da 00              ??         00h
       1008:00db 00              ??         00h
       1008:00dc 00              ??         00h
       1008:00dd 00              ??         00h
       1008:00de 00              ??         00h
       1008:00df 00              ??         00h
       1008:00e0 00              ??         00h
       1008:00e1 00              ??         00h
       1008:00e2 00              ??         00h
       1008:00e3 00              ??         00h
       1008:00e4 00              ??         00h
       1008:00e5 00              ??         00h
       1008:00e6 00              ??         00h
       1008:00e7 00              ??         00h
       1008:00e8 00              ??         00h
       1008:00e9 00              ??         00h
       1008:00ea 00              ??         00h
       1008:00eb 00              ??         00h
       1008:00ec 00              ??         00h
       1008:00ed 00              ??         00h
       1008:00ee 00              ??         00h
       1008:00ef 00              ??         00h
       1008:00f0 00              ??         00h
       1008:00f1 00              ??         00h
       1008:00f2 00              ??         00h
       1008:00f3 00              ??         00h
       1008:00f4 00              ??         00h
       1008:00f5 00              ??         00h
       1008:00f6 00              ??         00h
       1008:00f7 00              ??         00h
       1008:00f8 00              ??         00h
       1008:00f9 00              ??         00h
       1008:00fa 00              ??         00h
       1008:00fb 00              ??         00h
       1008:00fc 00              ??         00h
       1008:00fd 00              ??         00h
       1008:00fe 00              ??         00h
       1008:00ff 00              ??         00h
       1008:0100 00              ??         00h
       1008:0101 00              ??         00h
       1008:0102 00              ??         00h
       1008:0103 00              ??         00h
       1008:0104 00              ??         00h
       1008:0105 00              ??         00h
       1008:0106 00              ??         00h
       1008:0107 00              ??         00h
       1008:0108 00              ??         00h
       1008:0109 00              ??         00h
       1008:010a 00              ??         00h
       1008:010b 00              ??         00h
       1008:010c 00              ??         00h
       1008:010d 00              ??         00h
       1008:010e 00              ??         00h
       1008:010f 00              ??         00h
       1008:0110 00              ??         00h
       1008:0111 00              ??         00h
       1008:0112 00              ??         00h
       1008:0113 00              ??         00h
       1008:0114 00              ??         00h
       1008:0115 00              ??         00h
       1008:0116 00              ??         00h
       1008:0117 00              ??         00h
       1008:0118 00              ??         00h
       1008:0119 00              ??         00h
       1008:011a 00              ??         00h
       1008:011b 00              ??         00h
       1008:011c 00              ??         00h
       1008:011d 00              ??         00h
       1008:011e 00              ??         00h
       1008:011f 00              ??         00h
       1008:0120 00              ??         00h
       1008:0121 00              ??         00h
       1008:0122 00              ??         00h
       1008:0123 01              ??         01h
                             DAT_1008_0124                                   XREF[2]:     entry:1000:0208(W), 
                                                                                          FUN_1000_039a:1000:03a4(R)  
       1008:0124 00 00           undefined2 0000h
                             DAT_1008_0126                                   XREF[2]:     entry:1000:020c(W), 
                                                                                          FUN_1000_039a:1000:03a8(R)  
       1008:0126 00 00           undefined2 0000h
                             DAT_1008_0128                                   XREF[2]:     entry:1000:0210(W), 
                                                                                          FUN_1000_039a:1000:03ac(R)  
       1008:0128 00 00           undefined2 0000h
                             DAT_1008_012a                                   XREF[2]:     entry:1000:0214(W), 
                                                                                          FUN_1000_039a:1000:03b4(R)  
       1008:012a 00 00           undefined2 0000h
                             DAT_1008_012c                                   XREF[2]:     entry:1000:0218(W), 
                                                                                          FUN_1000_039a:1000:03b0(R)  
       1008:012c 00 00           undefined2 0000h
                             DAT_1008_012e                                   XREF[2]:     WEP:1000:0070(R), 
                                                                                          entry:1000:0273(RW)  
       1008:012e 00              undefined1 00h
       1008:012f 01              ??         01h
       1008:0130 00              ??         00h
       1008:0131 ff              ??         FFh
       1008:0132 ff              ??         FFh
       1008:0133 00              ??         00h
       1008:0134 00              ??         00h
       1008:0135 00              ??         00h
       1008:0136 00              ??         00h
       1008:0137 00              ??         00h
       1008:0138 00              ??         00h
       1008:0139 00              ??         00h
       1008:013a 00              ??         00h
       1008:013b 00              ??         00h
       1008:013c 00              ??         00h
       1008:013d 00              ??         00h
       1008:013e 00              ??         00h
       1008:013f 00              ??         00h
       1008:0140 00              ??         00h
       1008:0141 00              ??         00h
       1008:0142 00              ??         00h
       1008:0143 00              ??         00h
       1008:0144 00              ??         00h
       1008:0145 00              ??         00h
       1008:0146 00              ??         00h
       1008:0147 00              ??         00h
       1008:0148 00              ??         00h
       1008:0149 00              ??         00h
                             DAT_1008_014a                                   XREF[1]:     entry:1000:023c(W)  
       1008:014a 00 00           undefined2 0000h
                             DAT_1008_014c                                   XREF[1]:     entry:1000:0258(W)  
       1008:014c 00 00           undefined2 0000h
                             DAT_1008_014e                                   XREF[1]:     entry:1000:0253(W)  
       1008:014e 00 00           undefined2 0000h
       1008:0150 02              ??         02h
                             DAT_1008_0151                                   XREF[1]:     entry:1000:0266(W)  
       1008:0151 01              undefined1 01h
       1008:0152 00              ??         00h
       1008:0153 00              ??         00h
       1008:0154 14              ??         14h
       1008:0155 00              ??         00h
       1008:0156 00              ??         00h
       1008:0157 00              ??         00h
       1008:0158 00              ??         00h
       1008:0159 00              ??         00h
       1008:015a 00              ??         00h
       1008:015b 00              ??         00h
       1008:015c 00              ??         00h
       1008:015d 00              ??         00h
       1008:015e 00              ??         00h
       1008:015f 00              ??         00h
       1008:0160 00              ??         00h
       1008:0161 00              ??         00h
       1008:0162 00              ??         00h
       1008:0163 00              ??         00h
       1008:0164 00              ??         00h
       1008:0165 00              ??         00h
       1008:0166 00              ??         00h
       1008:0167 00              ??         00h
       1008:0168 00              ??         00h
       1008:0169 00              ??         00h
                             DAT_1008_016a                                   XREF[1]:     entry:1000:0287(R)  
       1008:016a 00 00           undefined2 0000h
                             DAT_1008_016c                                   XREF[1]:     entry:1000:0283(R)  
       1008:016c 00 00           undefined2 0000h
                             DAT_1008_016e                                   XREF[1]:     entry:1000:027f(R)  
       1008:016e 00 00           undefined2 0000h
                             DAT_1008_0170                                   XREF[2]:     entry:1000:027b(R), 
                                                                                          FUN_1000_03ea:1000:0442(W)  
       1008:0170 00 00           undefined2 0000h
                             DAT_1008_0172                                   XREF[2]:     entry:1000:0277(R), 
                                                                                          FUN_1000_03ea:1000:0445(W)  
       1008:0172 00 00           undefined2 0000h
       1008:0174 78              ??         78h    x
       1008:0175 01              ??         01h
       1008:0176 00              ??         00h
       1008:0177 00              ??         00h
       1008:0178 00              ??         00h
       1008:0179 00              ??         00h
       1008:017a 00              ??         00h
                             DAT_1008_017b                                   XREF[1]:     FUN_1000_02fe:1000:031e(W)  
       1008:017b 00              undefined1 00h
       1008:017c 00              ??         00h
       1008:017d 00              ??         00h
       1008:017e 00              ??         00h
       1008:017f 00              ??         00h
                             DAT_1008_0180                                   XREF[2]:     FUN_1000_0534:1000:053d(RW), 
                                                                                          FUN_1000_0534:1000:0549(W)  
       1008:0180 00 10           undefined2 1000h
                             DAT_1008_0182                                   XREF[1]:     FUN_1000_06af:1000:0733(R)  
       1008:0182 00 00           undefined2 0000h
                             DAT_1008_0184                                   XREF[1]:     FUN_1000_06af:1000:072f(R)  
       1008:0184 00 00           undefined2 0000h
       1008:0186 00              ??         00h
       1008:0187 00              ??         00h
                             DAT_1008_0188                                   XREF[1]:     FUN_1000_06af:1000:06c4(R)  
       1008:0188 00 00           undefined2 0000h
                             DAT_1008_018a                                   XREF[1]:     FUN_1000_06af:1000:06d2(R)  
       1008:018a 00 00 00 00     undefined4 00000000h
       1008:018e 00              ??         00h
       1008:018f 00              ??         00h
                             DAT_1008_0190                                   XREF[1]:     FUN_1000_06af:1000:06ce(R)  
       1008:0190 00 00           undefined2 0000h
       1008:0192 03              ??         03h
       1008:0193 00              ??         00h
       1008:0194 00              ??         00h
       1008:0195 00              ??         00h
                             DAT_1008_0196                                   XREF[1]:     FUN_1000_02b6:1000:02d1(R)  
       1008:0196 00 00           undefined2 0000h
                             DAT_1008_0198                                   XREF[2]:     FUN_1000_02b6:1000:02c0(R), 
                                                                                          FUN_1000_02b6:1000:02d1(R)  
       1008:0198 00 00           undefined2 0000h
                             DAT_1008_019a                                   XREF[1]:     FUN_1000_02b6:1000:02c8(R)  
       1008:019a 00 00           undefined2 0000h
                             DAT_1008_019c                                   XREF[1]:     FUN_1000_02b6:1000:02cb(R)  
       1008:019c 00 00           undefined2 0000h
       1008:019e 00              ??         00h
       1008:019f 00              ??         00h
       1008:01a0 00              ??         00h
       1008:01a1 00              ??         00h
       1008:01a2 3c              ??         3Ch    <
       1008:01a3 3c              ??         3Ch    <
       1008:01a4 4e              ??         4Eh    N
       1008:01a5 4d              ??         4Dh    M
       1008:01a6 53              ??         53h    S
       1008:01a7 47              ??         47h    G
       1008:01a8 3e              ??         3Eh    >
       1008:01a9 3e              ??         3Eh    >
                             DAT_1008_01aa                                   XREF[1]:     FUN_1000_049a:1000:04ae(R)  
       1008:01aa 00 00           undefined2 0000h
                             s_6000_-_stack_overflow_1008_01ad               XREF[0,1]:   FUN_1000_049a:1000:04ae(R)  
       1008:01ac 52 36 30        ds         "R6000\r\n- stack overflow\r\n"
                 30 30 0d 
                 0a 2d 20 
       1008:01c6 03              ??         03h
       1008:01c7 00              ??         00h
       1008:01c8 52 36 30        ds         "R6003\r\n- integer divide by 0\r\n"
                 30 33 0d 
                 0a 2d 20 
       1008:01e7 09              ??         09h
       1008:01e8 00              ??         00h
       1008:01e9 52 36 30        ds         "R6009\r\n- not enough space for environment\r
                 30 39 0d 
                 0a 2d 20 
       1008:0215 12              ??         12h
       1008:0216 00              ??         00h
       1008:0217 52 36 30        ds         "R6018\r\n- unexpected heap error\r\n"
                 31 38 0d 
                 0a 2d 20 
       1008:0238 fc              ??         FCh
       1008:0239 00              ??         00h
       1008:023a 0d              ??         0Dh
       1008:023b 0a              ??         0Ah
       1008:023c 00              ??         00h
       1008:023d ff              ??         FFh
       1008:023e 00              ??         00h
       1008:023f 72 75 6e        ds         "run-time error "
                 2d 74 69 
                 6d 65 20 
       1008:024f 02              ??         02h
       1008:0250 00              ??         00h
       1008:0251 52 36 30        ds         "R6002\r\n- floating-point support not loaded\
                 30 32 0d 
                 0a 2d 20 
       1008:027e ff              ??         FFh
       1008:027f ff              ??         FFh
       1008:0280 ff              ??         FFh
       1008:0281 00              ??         00h
                             //
                             // EXTERNAL 
                             // ram:1010:0000-ram:1010:005f
                             //
                             **************************************************************
                             *                       THUNK FUNCTION                       *
                             **************************************************************
                             thunk undefined FATALEXIT()
                               Thunked-Function: KERNEL::FATALEXIT
             undefined         AL:1           <RETURN>
                             KERNEL::FATALEXIT                               XREF[1]:     FUN_1000_04f2:1000:052f(c)  
       1010:0000                 ??         ??
       1010:0001                 ??         ??
       1010:0002                 ??         ??
       1010:0003                 ??         ??
                             **************************************************************
                             *                       THUNK FUNCTION                       *
                             **************************************************************
                             thunk undefined GETVERSION()
                               Thunked-Function: KERNEL::GETVERSION
             undefined         AL:1           <RETURN>
                             KERNEL::GETVERSION                              XREF[1]:     entry:1000:0235(c)  
       1010:0004                 ??         ??
       1010:0005                 ??         ??
       1010:0006                 ??         ??
       1010:0007                 ??         ??
                             **************************************************************
                             *                       THUNK FUNCTION                       *
                             **************************************************************
                             thunk undefined LOCALINIT()
                               Thunked-Function: KERNEL::LOCALINIT
             undefined         AL:1           <RETURN>
                             KERNEL::LOCALINIT                               XREF[1]:     entry:1000:0223(c)  
       1010:0008                 ??         ??
       1010:0009                 ??         ??
       1010:000a                 ??         ??
       1010:000b                 ??         ??
                             **************************************************************
                             *                       THUNK FUNCTION                       *
                             **************************************************************
                             thunk undefined GLOBALALLOC()
                               Thunked-Function: KERNEL::GLOBALALLOC
             undefined         AL:1           <RETURN>
                             KERNEL::GLOBALALLOC                             XREF[1]:     FUN_1000_0756:1000:0784(c)  
       1010:000c                 ??         ??
       1010:000d                 ??         ??
       1010:000e                 ??         ??
       1010:000f                 ??         ??
                             **************************************************************
                             *                       THUNK FUNCTION                       *
                             **************************************************************
                             thunk undefined GLOBALREALLOC()
                               Thunked-Function: KERNEL::GLOBALREALLOC
             undefined         AL:1           <RETURN>
                             KERNEL::GLOBALREALLOC                           XREF[1]:     FUN_1000_0607:1000:0639(c)  
       1010:0010                 ??         ??
       1010:0011                 ??         ??
       1010:0012                 ??         ??
       1010:0013                 ??         ??
                             **************************************************************
                             *                       THUNK FUNCTION                       *
                             **************************************************************
                             thunk undefined GLOBALFREE()
                               Thunked-Function: KERNEL::GLOBALFREE
             undefined         AL:1           <RETURN>
                             KERNEL::GLOBALFREE                              XREF[1]:     FUN_1000_0862:1000:087e(c)  
       1010:0014                 ??         ??
       1010:0015                 ??         ??
       1010:0016                 ??         ??
       1010:0017                 ??         ??
                             **************************************************************
                             *                       THUNK FUNCTION                       *
                             **************************************************************
                             thunk undefined GLOBALLOCK()
                               Thunked-Function: KERNEL::GLOBALLOCK
             undefined         AL:1           <RETURN>
                             KERNEL::GLOBALLOCK                              XREF[1]:     FUN_1000_0756:1000:0796(c)  
       1010:0018                 ??         ??
       1010:0019                 ??         ??
       1010:001a                 ??         ??
       1010:001b                 ??         ??
                             **************************************************************
                             *                       THUNK FUNCTION                       *
                             **************************************************************
                             thunk undefined GLOBALUNLOCK()
                               Thunked-Function: KERNEL::GLOBALUNLOCK
             undefined         AL:1           <RETURN>
                             KERNEL::GLOBALUNLOCK                            XREF[1]:     FUN_1000_0862:1000:0879(c)  
       1010:001c                 ??         ??
       1010:001d                 ??         ??
       1010:001e                 ??         ??
       1010:001f                 ??         ??
                             **************************************************************
                             *                       THUNK FUNCTION                       *
                             **************************************************************
                             thunk undefined GLOBALSIZE()
                               Thunked-Function: KERNEL::GLOBALSIZE
             undefined         AL:1           <RETURN>
                             KERNEL::GLOBALSIZE                              XREF[2]:     FUN_1000_0607:1000:0647(c), 
                                                                                          FUN_1000_0756:1000:07a8(c)  
       1010:0020                 ??         ??
       1010:0021                 ??         ??
       1010:0022                 ??         ??
       1010:0023                 ??         ??
                             **************************************************************
                             *                       THUNK FUNCTION                       *
                             **************************************************************
                             thunk undefined LOCKSEGMENT()
                               Thunked-Function: KERNEL::LOCKSEGMENT
             undefined         AL:1           <RETURN>
                             KERNEL::LOCKSEGMENT                             XREF[1]:     entry:1000:0230(c)  
       1010:0024                 ??         ??
       1010:0025                 ??         ??
       1010:0026                 ??         ??
       1010:0027                 ??         ??
                             **************************************************************
                             *                       THUNK FUNCTION                       *
                             **************************************************************
                             thunk undefined GETMODULEUSAGE()
                               Thunked-Function: KERNEL::GETMODULEUSAGE
             undefined         AL:1           <RETURN>
                             KERNEL::GETMODULEUSAGE
       1010:0028                 ??         ??
       1010:0029                 ??         ??
       1010:002a                 ??         ??
       1010:002b                 ??         ??
                             **************************************************************
                             *                       THUNK FUNCTION                       *
                             **************************************************************
                             thunk undefined INITTASK()
                               Thunked-Function: KERNEL::INITTASK
             undefined         AL:1           <RETURN>
                             KERNEL::INITTASK
       1010:002c                 ??         ??
       1010:002d                 ??         ??
       1010:002e                 ??         ??
       1010:002f                 ??         ??
                             **************************************************************
                             *                       THUNK FUNCTION                       *
                             **************************************************************
                             thunk undefined DOS3CALL()
                               Thunked-Function: KERNEL::DOS3CALL
             undefined         AL:1           <RETURN>
                             KERNEL::DOS3CALL                                XREF[1]:     entry:1000:024a(c)  
       1010:0030                 ??         ??
       1010:0031                 ??         ??
       1010:0032                 ??         ??
       1010:0033                 ??         ??
                             **************************************************************
                             *                       THUNK FUNCTION                       *
                             **************************************************************
                             thunk undefined __AHINCR()
                               Thunked-Function: KERNEL::__AHINCR
             undefined         AL:1           <RETURN>
                             KERNEL::__AHINCR
       1010:0034                 ??         ??
       1010:0035                 ??         ??
       1010:0036                 ??         ??
       1010:0037                 ??         ??
                             **************************************************************
                             *                       THUNK FUNCTION                       *
                             **************************************************************
                             thunk undefined GETDOSENVIRONMENT()
                               Thunked-Function: KERNEL::GETDOSENVIRONME
             undefined         AL:1           <RETURN>
                             KERNEL::GETDOSENVIRONMENT                       XREF[1]:     FUN_1000_03ea:1000:03f8(c)  
       1010:0038                 ??         ??
       1010:0039                 ??         ??
       1010:003a                 ??         ??
       1010:003b                 ??         ??
                             **************************************************************
                             *                       THUNK FUNCTION                       *
                             **************************************************************
                             thunk undefined FATALAPPEXIT()
                               Thunked-Function: KERNEL::FATALAPPEXIT
             undefined         AL:1           <RETURN>
                             KERNEL::FATALAPPEXIT                            XREF[1]:     FUN_1000_04f2:1000:0526(c)  
       1010:003c                 ??         ??
       1010:003d                 ??         ??
       1010:003e                 ??         ??
       1010:003f                 ??         ??
                             **************************************************************
                             *                       THUNK FUNCTION                       *
                             **************************************************************
                             thunk undefined ALLOCSELECTOR()
                               Thunked-Function: KERNEL::ALLOCSELECTOR
             undefined         AL:1           <RETURN>
                             KERNEL::ALLOCSELECTOR                           XREF[1]:     ISLOADCOMPLETE:1000:13ec(c)  
       1010:0040                 ??         ??
       1010:0041                 ??         ??
       1010:0042                 ??         ??
       1010:0043                 ??         ??
                             **************************************************************
                             *                       THUNK FUNCTION                       *
                             **************************************************************
                             thunk undefined FREESELECTOR()
                               Thunked-Function: KERNEL::FREESELECTOR
             undefined         AL:1           <RETURN>
                             KERNEL::FREESELECTOR                            XREF[1]:     ISLOADCOMPLETE:1000:143a(c)  
       1010:0044                 ??         ??
       1010:0045                 ??         ??
       1010:0046                 ??         ??
       1010:0047                 ??         ??
                             **************************************************************
                             *                       THUNK FUNCTION                       *
                             **************************************************************
                             thunk undefined __WINFLAGS()
                               Thunked-Function: KERNEL::__WINFLAGS
             undefined         AL:1           <RETURN>
                             KERNEL::__WINFLAGS
       1010:0048                 ??         ??
       1010:0049                 ??         ??
       1010:004a                 ??         ??
       1010:004b                 ??         ??
                             **************************************************************
                             *                       THUNK FUNCTION                       *
                             **************************************************************
                             thunk undefined GLOBALDOSALLOC()
                               Thunked-Function: KERNEL::GLOBALDOSALLOC
             undefined         AL:1           <RETURN>
                             KERNEL::GLOBALDOSALLOC                          XREF[13]:    SETPMVECTOR_IF:1000:0967(c), 
                                                                                          SETPMVECTOR_IF:1000:09a3(c), 
                                                                                          SETRMINTS_IF:1000:0af6(c), 
                                                                                          SETRMINTS_IF:1000:0b33(c), 
                                                                                          SETVECTORS_IF:1000:0c18(c), 
                                                                                          SETVECTORS_IF:1000:0c40(c), 
                                                                                          GETPMVECTOR_IF:1000:0d54(c), 
                                                                                          GETV86VECTOR_IF:1000:0e37(c), 
                                                                                          GETV86VECTOR_IF:1000:0e73(c), 
                                                                                          SETV86VECTOR_IF:1000:0f71(c), 
                                                                                          SETV86VECTOR_IF:1000:0fad(c), 
                                                                                          INITIV:1000:10bd(c), 
                                                                                          INITIV:1000:10fe(c)  
       1010:004c                 ??         ??
       1010:004d                 ??         ??
       1010:004e                 ??         ??
       1010:004f                 ??         ??
                             **************************************************************
                             *                       THUNK FUNCTION                       *
                             **************************************************************
                             thunk undefined GLOBALDOSFREE()
                               Thunked-Function: KERNEL::GLOBALDOSFREE
             undefined         AL:1           <RETURN>
                             KERNEL::GLOBALDOSFREE                           XREF[19]:    SETPMVECTOR_IF:1000:09b5(c), 
                                                                                          SETPMVECTOR_IF:1000:0a46(c), 
                                                                                          SETPMVECTOR_IF:1000:0a4e(c), 
                                                                                          SETRMINTS_IF:1000:0b45(c), 
                                                                                          SETRMINTS_IF:1000:0bbb(c), 
                                                                                          SETRMINTS_IF:1000:0bc3(c), 
                                                                                          SETVECTORS_IF:1000:0c50(c), 
                                                                                          SETVECTORS_IF:1000:0cf0(c), 
                                                                                          SETVECTORS_IF:1000:0cf8(c), 
                                                                                          GETPMVECTOR_IF:1000:0deb(c), 
                                                                                          GETV86VECTOR_IF:1000:0e85(c), 
                                                                                          GETV86VECTOR_IF:1000:0f16(c), 
                                                                                          GETV86VECTOR_IF:1000:0f1e(c), 
                                                                                          SETV86VECTOR_IF:1000:0fbf(c), 
                                                                                          SETV86VECTOR_IF:1000:1058(c), 
                                                                                          SETV86VECTOR_IF:1000:1060(c), 
                                                                                          INITIV:1000:1110(c), 
                                                                                          INITIV:1000:11a1(c), 
                                                                                          INITIV:1000:11a9(c)  
       1010:0050                 ??         ??
       1010:0051                 ??         ??
       1010:0052                 ??         ??
       1010:0053                 ??         ??
                             **************************************************************
                             *                       THUNK FUNCTION                       *
                             **************************************************************
                             thunk undefined SETSELECTORBASE()
                               Thunked-Function: KERNEL::SETSELECTORBASE
             undefined         AL:1           <RETURN>
                             KERNEL::SETSELECTORBASE                         XREF[1]:     ISLOADCOMPLETE:1000:13fd(c)  
       1010:0054                 ??         ??
       1010:0055                 ??         ??
       1010:0056                 ??         ??
       1010:0057                 ??         ??
                             **************************************************************
                             *                       THUNK FUNCTION                       *
                             **************************************************************
                             thunk undefined SETSELECTORLIMIT()
                               Thunked-Function: KERNEL::SETSELECTORLIMIT
             undefined         AL:1           <RETURN>
                             KERNEL::SETSELECTORLIMIT                        XREF[1]:     ISLOADCOMPLETE:1000:140d(c)  
       1010:0058                 ??         ??
       1010:0059                 ??         ??
       1010:005a                 ??         ??
       1010:005b                 ??         ??
                             **************************************************************
                             *                       THUNK FUNCTION                       *
                             **************************************************************
                             thunk undefined Ordinal_651()
                               Thunked-Function: KERNEL::Ordinal_651
             undefined         AL:1           <RETURN>
                             KERNEL::Ordinal_651                             XREF[1]:     FUN_1000_0034:1000:0045(c)  
       1010:005c                 ??         ??
       1010:005d                 ??         ??
       1010:005e                 ??         ??
       1010:005f                 ??         ??
