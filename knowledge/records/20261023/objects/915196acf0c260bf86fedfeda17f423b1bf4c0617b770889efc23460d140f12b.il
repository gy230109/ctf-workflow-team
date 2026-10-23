===== T1Class.T1.Check1  (rva=0x2050)  =====
  IL_0000: nop 
  IL_0001: ldc.i4.m1 
  IL_0002: stloc.0 
  IL_0003: ldc.i4.0 
  IL_0004: stloc.1 
  IL_0005: br 153
  IL_000A: nop 
  IL_000B: ldarg.0 
  IL_000C: ldc.i4.s 29
  IL_000E: shr.un 
  IL_000F: ldarg.0 
  IL_0010: ldc.i4.s 28
  IL_0012: shr.un 
  IL_0013: xor 
  IL_0014: ldarg.0 
  IL_0015: ldc.i4.s 25
  IL_0017: shr.un 
  IL_0018: xor 
  IL_0019: ldarg.0 
  IL_001A: ldc.i4.s 23
  IL_001C: shr.un 
  IL_001D: xor 
  IL_001E: ldc.i4.1 
  IL_001F: conv.i8 
  IL_0020: and 
  IL_0021: ldarg.0 
  IL_0022: ldc.i4.1 
  IL_0023: shl 
  IL_0024: or 
  IL_0025: starg.s 0
  IL_0027: ldarg.1 
  IL_0028: ldc.i4.s 30
  IL_002A: shr.un 
  IL_002B: ldarg.1 
  IL_002C: ldc.i4.s 27
  IL_002E: shr.un 
  IL_002F: xor 
  IL_0030: ldc.i4.1 
  IL_0031: conv.i8 
  IL_0032: and 
  IL_0033: ldarg.1 
  IL_0034: ldc.i4.1 
  IL_0035: shl 
  IL_0036: or 
  IL_0037: starg.s 1
  IL_0039: ldarg.2 
  IL_003A: ldc.i4.s 31
  IL_003C: shr.un 
  IL_003D: ldarg.2 
  IL_003E: ldc.i4.s 30
  IL_0040: shr.un 
  IL_0041: xor 
  IL_0042: ldarg.2 
  IL_0043: ldc.i4.s 29
  IL_0045: shr.un 
  IL_0046: xor 
  IL_0047: ldarg.2 
  IL_0048: ldc.i4.s 28
  IL_004A: shr.un 
  IL_004B: xor 
  IL_004C: ldarg.2 
  IL_004D: ldc.i4.s 26
  IL_004F: shr.un 
  IL_0050: xor 
  IL_0051: ldarg.2 
  IL_0052: ldc.i4.s 24
  IL_0054: shr.un 
  IL_0055: xor 
  IL_0056: ldc.i4.1 
  IL_0057: conv.i8 
  IL_0058: and 
  IL_0059: ldarg.2 
  IL_005A: ldc.i4.1 
  IL_005B: shl 
  IL_005C: or 
  IL_005D: starg.s 2
  IL_005F: ldloc.1 
  IL_0060: ldc.i4.8 
  IL_0061: rem 
  IL_0062: ldc.i4.0 
  IL_0063: ceq 
  IL_0065: stloc.2 
  IL_0066: ldloc.2 
  IL_0067: brfalse.s 6
  IL_0069: nop 
  IL_006A: ldloc.0 
  IL_006B: ldc.i4.1 
  IL_006C: add 
  IL_006D: stloc.0 
  IL_006E: nop 
  IL_006F: ldarg.3 
  IL_0070: ldloc.0 
  IL_0071: ldarg.3 
  IL_0072: ldloc.0 
  IL_0073: ldelem.u1 
  IL_0074: ldc.i4.1 
  IL_0075: shl 
  IL_0076: conv.i8 
  IL_0077: ldarg.2 
  IL_0078: ldc.i4.s 32
  IL_007A: shr.un 
  IL_007B: ldc.i4.1 
  IL_007C: conv.i8 
  IL_007D: and 
  IL_007E: ldarg.0 
  IL_007F: ldc.i4.s 30
  IL_0081: shr.un 
  IL_0082: ldc.i4.1 
  IL_0083: conv.i8 
  IL_0084: and 
  IL_0085: and 
  IL_0086: ldarg.2 
  IL_0087: ldc.i4.s 32
  IL_0089: shr.un 
  IL_008A: ldc.i4.1 
  IL_008B: conv.i8 
  IL_008C: and 
  IL_008D: ldc.i4.1 
  IL_008E: conv.i8 
  IL_008F: xor 
  IL_0090: ldarg.1 
  IL_0091: ldc.i4.s 31
  IL_0093: shr.un 
  IL_0094: ldc.i4.1 
  IL_0095: conv.i8 
  IL_0096: and 
  IL_0097: and 
  IL_0098: xor 
  IL_0099: conv.u4 
  IL_009A: conv.u8 
  IL_009B: or 
  IL_009C: conv.u1 
  IL_009D: stelem.i1 
  IL_009E: nop 
  IL_009F: ldloc.1 
  IL_00A0: ldc.i4.1 
  IL_00A1: add 
  IL_00A2: stloc.1 
  IL_00A3: ldloc.1 
  IL_00A4: ldc.i4 320
  IL_00A9: clt 
  IL_00AB: stloc.3 
  IL_00AC: ldloc.3 
  IL_00AD: brtrue 4294967128
  IL_00B2: ret 

===== T1Class.T1.ParseKey  (rva=0x2110)  =====
  IL_0000: nop 
  IL_0001: ldc.i4.0 
  IL_0002: stloc.0 
  IL_0003: br.s 49
  IL_0005: nop 
  IL_0006: ldc.i4.0 
  IL_0007: stloc.1 
  IL_0008: br.s 31
  IL_000A: nop 
  IL_000B: ldarg.1 
  IL_000C: ldloc.0 
  IL_000D: ldc.i4.4 
  IL_000E: mul 
  IL_000F: ldloc.1 
  IL_0010: add 
  IL_0011: ldarg.0 
  IL_0012: ldloc.0 
  IL_0013: ldelem.i8 
  IL_0014: ldloc.1 
  IL_0015: ldc.i4.8 
  IL_0016: mul 
  IL_0017: ldc.i4.s 63
  IL_0019: and 
  IL_001A: shr.un 
  IL_001B: ldc.i4 255
  IL_0020: conv.i8 
  IL_0021: and 
  IL_0022: conv.u1 
  IL_0023: stelem.i1 
  IL_0024: nop 
  IL_0025: ldloc.1 
  IL_0026: ldc.i4.1 
  IL_0027: add 
  IL_0028: stloc.1 
  IL_0029: ldloc.1 
  IL_002A: ldc.i4.4 
  IL_002B: clt 
  IL_002D: stloc.2 
  IL_002E: ldloc.2 
  IL_002F: brtrue.s 217
  IL_0031: nop 
  IL_0032: ldloc.0 
  IL_0033: ldc.i4.1 
  IL_0034: add 
  IL_0035: stloc.0 
  IL_0036: ldloc.0 
  IL_0037: ldc.i4.3 
  IL_0038: clt 
  IL_003A: stloc.3 
  IL_003B: ldloc.3 
  IL_003C: brtrue.s 199
  IL_003E: ret 

===== T1Class.T1..ctor  (rva=0x215c)  =====
  IL_0000: ldarg.0 
  IL_0001: call MR:System.Object::.ctor
  IL_0006: nop 
  IL_0007: nop 
  IL_0008: nop 
  IL_0009: ldnull 
  IL_000A: stloc.0 
  IL_000B: ldnull 
  IL_000C: stloc.1 
  IL_000D: ldnull 
  IL_000E: stloc.2 
  IL_000F: ldstr 'AchivePoint1'
  IL_0014: call MR:System.Environment::GetEnvironmentVariable
  IL_0019: stloc.0 
  IL_001A: ldstr 'AchivePoint2'
  IL_001F: call MR:System.Environment::GetEnvironmentVariable
  IL_0024: stloc.1 
  IL_0025: ldstr 'AchivePoint3'
  IL_002A: call MR:System.Environment::GetEnvironmentVariable
  IL_002F: stloc.2 
  IL_0030: ldloc.0 
  IL_0031: brfalse.s 9
  IL_0033: ldloc.1 
  IL_0034: brfalse.s 6
  IL_0036: ldloc.2 
  IL_0037: ldnull 
  IL_0038: ceq 
  IL_003A: br.s 1
  IL_003C: ldc.i4.1 
  IL_003D: stloc.s 12
  IL_003F: ldloc.s 12
  IL_0041: brfalse.s 6
  IL_0043: nop 
  IL_0044: leave 258
  IL_0049: ldloc.0 
  IL_004A: call MR:System.UInt64::Parse
  IL_004F: stloc.3 
  IL_0050: ldloc.1 
  IL_0051: call MR:System.UInt64::Parse
  IL_0056: stloc.s 4
  IL_0058: ldloc.2 
  IL_0059: call MR:System.UInt64::Parse
  IL_005E: stloc.s 5
  IL_0060: ldc.i4.3 
  IL_0061: newarr 16777236
  IL_0066: stloc.s 6
  IL_0068: ldc.i4.s 40
  IL_006A: newarr 16777237
  IL_006F: stloc.s 7
  IL_0071: ldc.i4.s 40
  IL_0073: newarr 16777237
  IL_0078: stloc.s 8
  IL_007A: ldc.i4.s 12
  IL_007C: newarr 16777237
  IL_0081: stloc.s 9
  IL_0083: ldc.i4.s 40
  IL_0085: newarr 16777237
  IL_008A: dup 
  IL_008B: ldtoken tok0x4000002
  IL_0090: call MR:System.Runtime.CompilerServices.RuntimeHelpers::InitializeArray
  IL_0095: stloc.s 10
  IL_0097: ldc.i4.s 19
  IL_0099: newarr 16777237
  IL_009E: dup 
  IL_009F: ldtoken tok0x4000001
  IL_00A4: call MR:System.Runtime.CompilerServices.RuntimeHelpers::InitializeArray
  IL_00A9: stloc.s 11
  IL_00AB: ldloc.s 6
  IL_00AD: ldc.i4.0 
  IL_00AE: ldloc.3 
  IL_00AF: stelem.i8 
  IL_00B0: ldloc.s 6
  IL_00B2: ldc.i4.1 
  IL_00B3: ldloc.s 4
  IL_00B5: stelem.i8 
  IL_00B6: ldloc.s 6
  IL_00B8: ldc.i4.2 
  IL_00B9: ldloc.s 5
  IL_00BB: stelem.i8 
  IL_00BC: ldloc.s 6
  IL_00BE: ldc.i4.0 
  IL_00BF: ldelem.i8 
  IL_00C0: ldloc.s 6
  IL_00C2: ldc.i4.1 
  IL_00C3: ldelem.i8 
  IL_00C4: ldloc.s 6
  IL_00C6: ldc.i4.2 
  IL_00C7: ldelem.i8 
  IL_00C8: ldloc.s 7
  IL_00CA: call MD:T1Class.T1.Check1
  IL_00CF: nop 
  IL_00D0: ldloc.s 10
  IL_00D2: ldloc.s 7
  IL_00D4: call tok0x2b000001
  IL_00D9: stloc.s 13
  IL_00DB: ldloc.s 13
  IL_00DD: brfalse.s 100
  IL_00DF: nop 
  IL_00E0: ldloc.s 6
  IL_00E2: ldloc.s 9
  IL_00E4: call MD:T1Class.T1.ParseKey
  IL_00E9: nop 
  IL_00EA: ldc.i4.0 
  IL_00EB: stloc.s 14
  IL_00ED: br.s 30
  IL_00EF: nop 
  IL_00F0: ldloc.s 11
  IL_00F2: ldloc.s 14
  IL_00F4: ldloc.s 11
  IL_00F6: ldloc.s 14
  IL_00F8: ldelem.u1 
  IL_00F9: ldloc.s 9
  IL_00FB: ldloc.s 14
  IL_00FD: ldloc.s 9
  IL_00FF: ldlen 
  IL_0100: conv.i4 
  IL_0101: rem 
  IL_0102: ldelem.u1 
  IL_0103: xor 
  IL_0104: conv.u1 
  IL_0105: stelem.i1 
  IL_0106: nop 
  IL_0107: ldloc.s 14
  IL_0109: ldc.i4.1 
  IL_010A: add 
  IL_010B: stloc.s 14
  IL_010D: ldloc.s 14
  IL_010F: ldloc.s 11
  IL_0111: ldlen 
  IL_0112: conv.i4 
  IL_0113: clt 
  IL_0115: stloc.s 15
  IL_0117: ldloc.s 15
  IL_0119: brtrue.s 212
  IL_011B: ldstr 'flag{'
  IL_0120: call MR:System.Text.Encoding::get_Default
  IL_0125: ldloc.s 11
  IL_0127: callvirt MR:System.Text.Encoding::GetString
  IL_012C: ldstr '}'
  IL_0131: call MR:System.String::Concat
  IL_0136: ldstr 'Congratulations!'
  IL_013B: ldc.i4.0 
  IL_013C: call MR:System.Windows.Forms.MessageBox::Show
  IL_0141: pop 
  IL_0142: nop 
  IL_0143: nop 
  IL_0144: leave.s 5
  IL_0146: pop 
  IL_0147: nop 
  IL_0148: nop 
  IL_0149: leave.s 0
  IL_014B: ret 

