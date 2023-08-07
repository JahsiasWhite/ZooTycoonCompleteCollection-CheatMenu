                             //
                             // CODE_0 
                             // ram:1000:0000-ram:1000:0218
                             //
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined entry()
                               assume CS = 0x1000
                               assume SP = 0xb8
                               assume SS = 0x1000
             undefined         AL:1           <RETURN>
                             entry                                           XREF[2]:     Entry Point(*), 1000:0095(RW)  
       1000:0000 0e              PUSH       CS=>LAB_1000_00b6
             assume SS = <UNKNOWN>
             assume SP = <UNKNOWN>
                             LAB_1000_0001                                   XREF[1]:     1000:0193(RW)  
       1000:0001 1f              POP        DS=>LAB_1000_00b6
       1000:0002 ba 0e 00        MOV        DX,0xe
       1000:0005 b4 09           MOV        AH,0x9
       1000:0007 cd 21           INT        0x21
       1000:0009 b8 01 4c        MOV        AX,0x4c01
       1000:000c cd 21           INT        0x21
       1000:000e 54              PUSH       SP
       1000:000f 68 69 73        PUSH       0x7369
       1000:0012 20 70 72        AND        byte ptr [BX + SI + 0x72],DH
       1000:0015 6f              OUTSW      DX,SI
       1000:0016 67 72 61        JC         LAB_1000_007a
       1000:0019 6d              INSW       ES:DI,DX
       1000:001a 20 72 65        AND        byte ptr [BP + SI + 0x65],DH
       1000:001d 71 75           JNO        LAB_1000_0094
       1000:001f 69 72 65        IMUL       SI,word ptr [BP + SI + 0x65],0x2073
                 73 20
       1000:0024 4d              DEC        BP
       1000:0025 69 63 72        IMUL       SP,word ptr [BP + DI + 0x72],0x736f
                 6f 73
       1000:002a 6f              OUTSW      DX,SI
       1000:002b 66 74 20        JZ         LAB_1000_004c+2
       1000:002e 57              PUSH       DI
       1000:002f 69 6e 64        IMUL       BP,word ptr [BP + 0x64],0x776f
                 6f 77
       1000:0034 73 2e           JNC        LAB_1000_0063+1
       1000:0036 0d 0a 24        OR         AX,0x240a
       1000:0039 00 00           ADD        byte ptr [BX + SI],AL
       1000:003b 00 00           ADD        byte ptr [BX + SI],AL
       1000:003d 00 00           ADD        byte ptr [BX + SI],AL
       1000:003f 00 4e 45        ADD        byte ptr [BP + 0x45],CL
       1000:0042 05 3c 62        ADD        AX,0x623c
       1000:0045 01 69 00        ADD        word ptr [BX + DI + 0x0],BP
       1000:0048 00 00           ADD        byte ptr [BX + SI],AL
       1000:004a 00 00           ADD        byte ptr [BX + SI],AL
                             LAB_1000_004c+2                                 XREF[0,1]:   1000:002b(j)  
       1000:004c 01 83 02 00     ADD        word ptr [BP + DI + 0x2],AX
       1000:0050 00 04           ADD        byte ptr [SI],AL
       1000:0052 00 00           ADD        byte ptr [BX + SI],AL
       1000:0054 fc              CLD
       1000:0055 01 01           ADD        word ptr [BX + DI],AX
       1000:0057 00 00           ADD        byte ptr [BX + SI],AL
       1000:0059 00 00           ADD        byte ptr [BX + SI],AL
       1000:005b 00 02           ADD        byte ptr [BP + SI],AL
       1000:005d 00 01           ADD        byte ptr [BX + DI],AL
       1000:005f 00 0e 00 40     ADD        byte ptr [DAT_1000_4000],CL
                             LAB_1000_0063+1                                 XREF[0,1]:   1000:0034(j)  
       1000:0063 00 50 00        ADD        byte ptr [BX + SI + 0x0],DL
       1000:0066 50              PUSH       AX
       1000:0067 00 58 01        ADD        byte ptr [BX + SI + 0x1],BL
       1000:006a 5a              POP        DX
       1000:006b 01 4b 02        ADD        word ptr [BP + DI + 0x2],CX
       1000:006e 00 00           ADD        byte ptr [BX + SI],AL
       1000:0070 11 00           ADC        word ptr [BX + SI],AX
       1000:0072 04 00           ADD        AL,0x0
       1000:0074 00 00           ADD        byte ptr [BX + SI],AL
       1000:0076 02 08           ADD        CL,byte ptr [BX + SI]
       1000:0078 28 00           SUB        byte ptr [BX + SI],AL
                             LAB_1000_007a                                   XREF[1]:     1000:0016(j)  
       1000:007a 80 01 00        ADD        byte ptr [BX + DI],0x0
       1000:007d 00 00           ADD        byte ptr [BX + SI],AL
       1000:007f 04 2a           ADD        AL,0x2a
       1000:0081 00 49 14        ADD        byte ptr [BX + DI + 0x14],CL
       1000:0084 50              PUSH       AX
       1000:0085 1d 49 14        SBB        AX,0x1449
       1000:0088 7e 01           JLE        LAB_1000_008a+1
                             LAB_1000_008a+1                                 XREF[0,1]:   1000:0088(j)  
       1000:008a 82 02 71        ADD        byte ptr [BP + SI],0x71
       1000:008d 0d 82 02        OR         AX,0x282
       1000:0090 06              PUSH       ES
       1000:0091 43              INC        BX
       1000:0092 4c              DEC        SP
       1000:0093 43              INC        BX
                             LAB_1000_0094                                   XREF[1]:     1000:001d(j)  
       1000:0094 44              INC        SP
       1000:0095 31 36 00 00     XOR        word ptr [0x0]=>entry,SI
       1000:0099 0d 53 45        OR         AX,0x4553
       1000:009c 54              PUSH       SP
       1000:009d 56              PUSH       SI
       1000:009e 45              INC        BP
       1000:009f 43              INC        BX
       1000:00a0 54              PUSH       SP
       1000:00a1 4f              DEC        DI
       1000:00a2 52              PUSH       DX
       1000:00a3 53              PUSH       BX
       1000:00a4 5f              POP        DI
       1000:00a5 49              DEC        CX
       1000:00a6 46              INC        SI
       1000:00a7 03 00           ADD        AX,word ptr [BX + SI]
       1000:00a9 0d 47 45        OR         AX,0x4547
       1000:00ac 54              PUSH       SP
       1000:00ad 56              PUSH       SI
       1000:00ae 45              INC        BP
       1000:00af 43              INC        BX
       1000:00b0 54              PUSH       SP
       1000:00b1 4f              DEC        DI
       1000:00b2 52              PUSH       DX
       1000:00b3 53              PUSH       BX
       1000:00b4 5f              POP        DI
       1000:00b5 49              DEC        CX
                             LAB_1000_00b6                                   XREF[2]:     1000:0000(W), 1000:0001(R)  
       1000:00b6 46              INC        SI
       1000:00b7 04 00           ADD        AL,0x0
       1000:00b9 03 57 45        ADD        DX,word ptr [BX + 0x45]
       1000:00bc 50              PUSH       AX
       1000:00bd 05 00 09        ADD        AX,0x900
       1000:00c0 53              PUSH       BX
       1000:00c1 45              INC        BP
       1000:00c2 54              PUSH       SP
       1000:00c3 49              DEC        CX
       1000:00c4 44              INC        SP
       1000:00c5 54              PUSH       SP
       1000:00c6 5f              POP        DI
       1000:00c7 49              DEC        CX
       1000:00c8 46              INC        SI
       1000:00c9 06              PUSH       ES
       1000:00ca 00 0d           ADD        byte ptr [DI],CL
       1000:00cc 44              INC        SP
       1000:00cd 4c              DEC        SP
       1000:00ce 4c              DEC        SP
       1000:00cf 45              INC        BP
       1000:00d0 4e              DEC        SI
       1000:00d1 54              PUSH       SP
       1000:00d2 52              PUSH       DX
       1000:00d3 59              POP        CX
       1000:00d4 50              PUSH       AX
       1000:00d5 4f              DEC        DI
       1000:00d6 49              DEC        CX
       1000:00d7 4e              DEC        SI
       1000:00d8 54              PUSH       SP
       1000:00d9 02 00           ADD        AL,byte ptr [BX + SI]
       1000:00db 0c 53           OR         AL,0x53
       1000:00dd 45              INC        BP
       1000:00de 54              PUSH       SP
       1000:00df 52              PUSH       DX
       1000:00e0 4d              DEC        BP
       1000:00e1 49              DEC        CX
       1000:00e2 4e              DEC        SI
       1000:00e3 54              PUSH       SP
       1000:00e4 53              PUSH       BX
       1000:00e5 5f              POP        DI
       1000:00e6 49              DEC        CX
       1000:00e7 46              INC        SI
       1000:00e8 07              POP        ES
       1000:00e9 00 09           ADD        byte ptr [BX + DI],CL
       1000:00eb 47              INC        DI
       1000:00ec 45              INC        BP
       1000:00ed 54              PUSH       SP
       1000:00ee 49              DEC        CX
       1000:00ef 44              INC        SP
       1000:00f0 54              PUSH       SP
       1000:00f1 5f              POP        DI
       1000:00f2 49              DEC        CX
       1000:00f3 46              INC        SI
       1000:00f4 08 00           OR         byte ptr [BX + SI],AL
       1000:00f6 0e              PUSH       CS
       1000:00f7 47              INC        DI
       1000:00f8 45              INC        BP
       1000:00f9 54              PUSH       SP
       1000:00fa 50              PUSH       AX
       1000:00fb 4d              DEC        BP
       1000:00fc 56              PUSH       SI
       1000:00fd 45              INC        BP
       1000:00fe 43              INC        BX
       1000:00ff 54              PUSH       SP
       1000:0100 4f              DEC        DI
       1000:0101 52              PUSH       DX
       1000:0102 5f              POP        DI
       1000:0103 49              DEC        CX
       1000:0104 46              INC        SI
       1000:0105 09 00           OR         word ptr [BX + SI],AX
       1000:0107 0e              PUSH       CS
       1000:0108 53              PUSH       BX
       1000:0109 45              INC        BP
       1000:010a 54              PUSH       SP
       1000:010b 50              PUSH       AX
       1000:010c 4d              DEC        BP
       1000:010d 56              PUSH       SI
       1000:010e 45              INC        BP
       1000:010f 43              INC        BX
       1000:0110 54              PUSH       SP
       1000:0111 4f              DEC        DI
       1000:0112 52              PUSH       DX
       1000:0113 5f              POP        DI
       1000:0114 49              DEC        CX
       1000:0115 46              INC        SI
       1000:0116 0a 00           OR         AL,byte ptr [BX + SI]
       1000:0118 0f 47 45 54     CMOVA      AX,word ptr [DI + 0x54]
       1000:011c 56              PUSH       SI
       1000:011d 38 36 56 45     CMP        byte ptr [DAT_1000_4556],DH
       1000:0121 43              INC        BX
       1000:0122 54              PUSH       SP
       1000:0123 4f              DEC        DI
       1000:0124 52              PUSH       DX
       1000:0125 5f              POP        DI
       1000:0126 49              DEC        CX
       1000:0127 46              INC        SI
       1000:0128 0b 00           OR         AX,word ptr [BX + SI]
       1000:012a 0f 53 45 54     RCPPS      XMM0,xmmword ptr [DI + 0x54]
       1000:012e 56              PUSH       SI
       1000:012f 38 36 56 45     CMP        byte ptr [DAT_1000_4556],DH
       1000:0133 43              INC        BX
       1000:0134 54              PUSH       SP
       1000:0135 4f              DEC        DI
       1000:0136 52              PUSH       DX
       1000:0137 5f              POP        DI
       1000:0138 49              DEC        CX
       1000:0139 46              INC        SI
       1000:013a 0c 00           OR         AL,0x0
       1000:013c 0c 47           OR         AL,0x47
       1000:013e 45              INC        BP
       1000:013f 54              PUSH       SP
       1000:0140 52              PUSH       DX
       1000:0141 4d              DEC        BP
       1000:0142 49              DEC        CX
       1000:0143 4e              DEC        SI
       1000:0144 54              PUSH       SP
       1000:0145 53              PUSH       BX
       1000:0146 5f              POP        DI
       1000:0147 49              DEC        CX
       1000:0148 46              INC        SI
       1000:0149 0d 00 0f        OR         AX,0xf00
       1000:014c 5f              POP        DI
       1000:014d 5f              POP        DI
       1000:014e 5f              POP        DI
       1000:014f 45              INC        BP
       1000:0150 58              POP        AX
       1000:0151 50              PUSH       AX
       1000:0152 4f              DEC        DI
       1000:0153 52              PUSH       DX
       1000:0154 54              PUSH       SP
       1000:0155 45              INC        BP
       1000:0156 44              INC        SP
       1000:0157 53              PUSH       BX
       1000:0158 54              PUSH       SP
       1000:0159 55              PUSH       BP
       1000:015a 42              INC        DX
       1000:015b 0e              PUSH       CS
       1000:015c 00 0b           ADD        byte ptr [BP + DI],CL
       1000:015e 49              DEC        CX
       1000:015f 4e              DEC        SI
       1000:0160 49              DEC        CX
       1000:0161 54              PUSH       SP
       1000:0162 56              PUSH       SI
       1000:0163 45              INC        BP
       1000:0164 43              INC        BX
       1000:0165 54              PUSH       SP
       1000:0166 4f              DEC        DI
       1000:0167 52              PUSH       DX
       1000:0168 53              PUSH       BX
       1000:0169 0f 00 06        SLDT       word ptr [DAT_1000_4e49]
                 49 4e
       1000:016e 49              DEC        CX
       1000:016f 54              PUSH       SP
       1000:0170 49              DEC        CX
       1000:0171 56              PUSH       SI
       1000:0172 10 00           ADC        byte ptr [BX + SI],AL
       1000:0174 0e              PUSH       CS
       1000:0175 49              DEC        CX
       1000:0176 53              PUSH       BX
       1000:0177 4c              DEC        SP
       1000:0178 4f              DEC        DI
       1000:0179 41              INC        CX
       1000:017a 44              INC        SP
       1000:017b 43              INC        BX
       1000:017c 4f              DEC        DI
       1000:017d 4d              DEC        BP
       1000:017e 50              PUSH       AX
       1000:017f 4c              DEC        SP
       1000:0180 45              INC        BP
       1000:0181 54              PUSH       SP
       1000:0182 45              INC        BP
       1000:0183 11 00           ADC        word ptr [BX + SI],AX
       1000:0185 0f 54 48 4b     ANDPS      XMM1,xmmword ptr [BX + SI + 0x4b]
       1000:0189 5f              POP        DI
       1000:018a 54              PUSH       SP
       1000:018b 48              DEC        AX
       1000:018c 55              PUSH       BP
       1000:018d 4e              DEC        SI
       1000:018e 4b              DEC        BX
       1000:018f 44              INC        SP
       1000:0190 41              INC        CX
       1000:0191 54              PUSH       SP
       1000:0192 41              INC        CX
       1000:0193 31 36 01 00     XOR        word ptr [LAB_1000_0001],SI
       1000:0197 00 01           ADD        byte ptr [BX + DI],AL
       1000:0199 00 00           ADD        byte ptr [BX + SI],AL
       1000:019b 06              PUSH       ES
       1000:019c 4b              DEC        BX
       1000:019d 45              INC        BP
       1000:019e 52              PUSH       DX
       1000:019f 4e              DEC        SI
       1000:01a0 45              INC        BP
       1000:01a1 4c              DEC        SP
       1000:01a2 11 ff           ADC        DI,DI
       1000:01a4 03 cd           ADD        CX,BP
       1000:01a6 3f              AAS
       1000:01a7 02 10           ADD        DL,byte ptr [BX + SI]
       1000:01a9 00 03           ADD        byte ptr [BP + DI],AL
       1000:01ab cd 3f           INT        0x3f
       1000:01ad 01 00           ADD        word ptr [BX + SI],AX
       1000:01af 09 03           OR         word ptr [BP + DI],AX
       1000:01b1 cd 3f           INT        0x3f
       1000:01b3 01 d2           ADD        DX,DX
       1000:01b5 0b 03           OR         AX,word ptr [BP + DI]
       1000:01b7 cd 3f           INT        0x3f
       1000:01b9 01 6e 10        ADD        word ptr [BP + 0x10],BP
       1000:01bc 03 cd           ADD        CX,BP
       1000:01be 3f              AAS
       1000:01bf 01 5a 00        ADD        word ptr [BP + SI + 0x0],BX
       1000:01c2 03 cd           ADD        CX,BP
       1000:01c4 3f              AAS
       1000:01c5 01 5c 0a        ADD        word ptr [SI + 0xa],BX
       1000:01c8 03 cd           ADD        CX,BP
       1000:01ca 3f              AAS
       1000:01cb 01 bc 0a 03     ADD        word ptr [SI + 0x30a],DI
       1000:01cf cd 3f           INT        0x3f
       1000:01d1 01 7c 0a        ADD        word ptr [SI + 0xa],DI
       1000:01d4 03 cd           ADD        CX,BP
       1000:01d6 3f              AAS
       1000:01d7 01 06 0d 03     ADD        word ptr [DAT_1000_030d],AX
       1000:01db cd 3f           INT        0x3f
       1000:01dd 01 2e 09 03     ADD        word ptr [DAT_1000_0309],BP
       1000:01e1 cd 3f           INT        0x3f
       1000:01e3 01 fe           ADD        SI,DI
       1000:01e5 0d 03 cd        OR         AX,0xcd03
       1000:01e8 3f              AAS
       1000:01e9 01 2c           ADD        word ptr [SI],BP
       1000:01eb 0f 03 cd        LSL        CX,BP
       1000:01ee 3f              AAS
       1000:01ef 01 9c 0a 03     ADD        word ptr [SI + 0x30a],BX
       1000:01f3 cd 3f           INT        0x3f
       1000:01f5 01 62 05        ADD        word ptr [BP + SI + 0x5],SP
       1000:01f8 03 cd           ADD        CX,BP
       1000:01fa 3f              AAS
       1000:01fb 01 8e 10 03     ADD        word ptr [BP + 0x310],CX
       1000:01ff cd 3f           INT        0x3f
       1000:0201 01 ae 10 03     ADD        word ptr [BP + 0x310],BP
       1000:0205 cd 3f           INT        0x3f
       1000:0207 01 d0           ADD        AX,DX
       1000:0209 13 00           ADC        AX,word ptr [BX + SI]
       1000:020b 0a 43 4c        OR         AL,byte ptr [BP + DI + 0x4c]
       1000:020e 43              INC        BX
       1000:020f 44              INC        SP
       1000:0210 31 36 2e 65     XOR        word ptr [DAT_1000_652e],SI
       1000:0214 78 65           JS         LAB_1000_027b
       1000:0216 00 00           ADD        byte ptr [BX + SI],AL
       1000:0218 00              ADD        byte ptr [BX + SI],AL
       1000:021a                 ??         ??
       1000:021b                 ??         ??
       1000:021c                 ??         ??
       1000:021d                 ??         ??
       1000:021e                 ??         ??
       1000:021f                 ??         ??
       1000:0220                 ??         ??
       1000:0221                 ??         ??
       1000:0222                 ??         ??
       1000:0223                 ??         ??
       1000:0224                 ??         ??
       1000:0225                 ??         ??
       1000:0226                 ??         ??
       1000:0227                 ??         ??
       1000:0228                 ??         ??
       1000:0229                 ??         ??
       1000:022a                 ??         ??
       1000:022b                 ??         ??
       1000:022c                 ??         ??
       1000:022d                 ??         ??
       1000:022e                 ??         ??
       1000:022f                 ??         ??
       1000:0230                 ??         ??
       1000:0231                 ??         ??
       1000:0232                 ??         ??
       1000:0233                 ??         ??
       1000:0234                 ??         ??
       1000:0235                 ??         ??
       1000:0236                 ??         ??
       1000:0237                 ??         ??
       1000:0238                 ??         ??
       1000:0239                 ??         ??
       1000:023a                 ??         ??
       1000:023b                 ??         ??
       1000:023c                 ??         ??
       1000:023d                 ??         ??
       1000:023e                 ??         ??
       1000:023f                 ??         ??
       1000:0240                 ??         ??
       1000:0241                 ??         ??
       1000:0242                 ??         ??
       1000:0243                 ??         ??
       1000:0244                 ??         ??
       1000:0245                 ??         ??
       1000:0246                 ??         ??
       1000:0247                 ??         ??
       1000:0248                 ??         ??
       1000:0249                 ??         ??
       1000:024a                 ??         ??
       1000:024b                 ??         ??
       1000:024c                 ??         ??
       1000:024d                 ??         ??
       1000:024e                 ??         ??
       1000:024f                 ??         ??
       1000:0250                 ??         ??
       1000:0251                 ??         ??
       1000:0252                 ??         ??
       1000:0253                 ??         ??
       1000:0254                 ??         ??
       1000:0255                 ??         ??
       1000:0256                 ??         ??
       1000:0257                 ??         ??
       1000:0258                 ??         ??
       1000:0259                 ??         ??
       1000:025a                 ??         ??
       1000:025b                 ??         ??
       1000:025c                 ??         ??
       1000:025d                 ??         ??
       1000:025e                 ??         ??
       1000:025f                 ??         ??
       1000:0260                 ??         ??
       1000:0261                 ??         ??
       1000:0262                 ??         ??
       1000:0263                 ??         ??
       1000:0264                 ??         ??
       1000:0265                 ??         ??
       1000:0266                 ??         ??
       1000:0267                 ??         ??
       1000:0268                 ??         ??
       1000:0269                 ??         ??
       1000:026a                 ??         ??
       1000:026b                 ??         ??
       1000:026c                 ??         ??
       1000:026d                 ??         ??
       1000:026e                 ??         ??
       1000:026f                 ??         ??
       1000:0270                 ??         ??
       1000:0271                 ??         ??
       1000:0272                 ??         ??
       1000:0273                 ??         ??
       1000:0274                 ??         ??
       1000:0275                 ??         ??
       1000:0276                 ??         ??
       1000:0277                 ??         ??
       1000:0278                 ??         ??
       1000:0279                 ??         ??
       1000:027a                 ??         ??
                             LAB_1000_027b                                   XREF[1]:     entry:1000:0214(j)  
       1000:027b                 ??         ??
       1000:027c                 ??         ??
       1000:027d                 ??         ??
       1000:027e                 ??         ??
       1000:027f                 ??         ??
       1000:0280                 ??         ??
       1000:0281                 ??         ??
       1000:0282                 ??         ??
       1000:0283                 ??         ??
       1000:0284                 ??         ??
       1000:0285                 ??         ??
       1000:0286                 ??         ??
       1000:0287                 ??         ??
       1000:0288                 ??         ??
       1000:0289                 ??         ??
       1000:028a                 ??         ??
       1000:028b                 ??         ??
       1000:028c                 ??         ??
       1000:028d                 ??         ??
       1000:028e                 ??         ??
       1000:028f                 ??         ??
       1000:0290                 ??         ??
       1000:0291                 ??         ??
       1000:0292                 ??         ??
       1000:0293                 ??         ??
       1000:0294                 ??         ??
       1000:0295                 ??         ??
       1000:0296                 ??         ??
       1000:0297                 ??         ??
       1000:0298                 ??         ??
       1000:0299                 ??         ??
       1000:029a                 ??         ??
       1000:029b                 ??         ??
       1000:029c                 ??         ??
       1000:029d                 ??         ??
       1000:029e                 ??         ??
       1000:029f                 ??         ??
       1000:02a0                 ??         ??
       1000:02a1                 ??         ??
       1000:02a2                 ??         ??
       1000:02a3                 ??         ??
       1000:02a4                 ??         ??
       1000:02a5                 ??         ??
       1000:02a6                 ??         ??
       1000:02a7                 ??         ??
       1000:02a8                 ??         ??
       1000:02a9                 ??         ??
       1000:02aa                 ??         ??
       1000:02ab                 ??         ??
       1000:02ac                 ??         ??
       1000:02ad                 ??         ??
       1000:02ae                 ??         ??
       1000:02af                 ??         ??
       1000:02b0                 ??         ??
       1000:02b1                 ??         ??
       1000:02b2                 ??         ??
       1000:02b3                 ??         ??
       1000:02b4                 ??         ??
       1000:02b5                 ??         ??
       1000:02b6                 ??         ??
       1000:02b7                 ??         ??
       1000:02b8                 ??         ??
                             //
                             // HEADER 
                             // HEADER::00000000-HEADER::0000003f
                             //
             assume CS = <UNKNOWN>
             assume DF = <UNKNOWN>
     R::00000000 4d 5a 59        OLD_IMAG                                                    Magic number
                 00 02 00 
                 00 00 04 
     R::0000001c 00              ??         00h
     R::0000001d 00              ??         00h
     R::0000001e 00              ??         00h
     R::0000001f 00              ??         00h
     R::00000020 00              ??         00h
     R::00000021 00              ??         00h
     R::00000022 00              ??         00h
     R::00000023 00              ??         00h
     R::00000024 00              ??         00h
     R::00000025 00              ??         00h
     R::00000026 00              ??         00h
     R::00000027 00              ??         00h
     R::00000028 00              ??         00h
     R::00000029 00              ??         00h
     R::0000002a 00              ??         00h
     R::0000002b 00              ??         00h
     R::0000002c 00              ??         00h
     R::0000002d 00              ??         00h
     R::0000002e 00              ??         00h
     R::0000002f 00              ??         00h
     R::00000030 00              ??         00h
     R::00000031 00              ??         00h
     R::00000032 00              ??         00h
     R::00000033 00              ??         00h
     R::00000034 00              ??         00h
     R::00000035 00              ??         00h
     R::00000036 00              ??         00h
     R::00000037 00              ??         00h
     R::00000038 00              ??         00h
     R::00000039 00              ??         00h
     R::0000003a 00              ??         00h
     R::0000003b 00              ??         00h
     R::0000003c 80              ??         80h
     R::0000003d 00              ??         00h
     R::0000003e 00              ??         00h
     R::0000003f 00              ??         00h
