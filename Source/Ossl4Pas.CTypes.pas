{******************************************************************************}
{                                                                              }
{  Ossl4Pas : OpenSSL 3.x wrappers for Delphi & Free Pascal                    }
{                                                                              }
{  Copyright (c) 2026 [Your Name / Organization]                               }
{                                                                              }
{  Licensed under the Modified BSD License (3-Clause) or the Mozilla Public    }
{  License v1.1 (MPL 1.1). You may obtain a copy of the licenses at:           }
{                                                                              }
{      https://opensource.org/licenses/BSD-3-Clause                            }
{      https://www.mozilla.org/MPL/MPL-1.1.html                                }
{                                                                              }
{  Unless required by applicable law or agreed to in writing, software         }
{  distributed under the License is distributed on an "AS IS" BASIS,           }
{  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.    }
{                                                                              }
{******************************************************************************}

unit Ossl4Pas.CTypes;

{$INCLUDE 'Ossl4Pas_CompilerDefines.inc'}

interface

{$IFDEF FPC}
  uses CTypes;
{$ENDIF}

type
(*============================================================================*)
(*  DELPHI COMPATIBILITY LAYER                                                *)
(*  These definitions are guarded by "if not Declared" so they do not conflict*)
(*  when running on FPC (which includes CTypes) or if defined elsewhere.      *)
(*============================================================================*)
   _dummy_ = System.integer; // to avoid empty "type" section
  // 1. Basic Type Mapping
  {$IF not Declared(qword)}
    {$IF Declared(UInt64)}
      qword = UInt64;
    {$ELSE}
      qword = Int64; // Fallback for legacy Delphi versions
    {$ENDIF}
  {$ENDIF}

  {$IF not Declared(ptruint)}
    {$IF Declared(NativeUInt)}
      ptruint = NativeUInt;
    {$ELSE}
      ptruint = Cardinal;
    {$ENDIF}
  {$ENDIF}

  {$IF not Declared(pptruint)}
    pptruint = ^ptruint;
  {$ENDIF}

  // 2. Fixed Width C Types
  {$IF not Declared(cint8)}   cint8   = ShortInt; pcint8    = ^cint8;   {$ENDIF}
  {$IF not Declared(cuint8)}  cuint8  = Byte;     pcuint8   = ^cuint8;  {$ENDIF}
  {$IF not Declared(cchar)}   cchar   = cint8;    pcchar    = ^cchar;   {$ENDIF}
  {$IF not Declared(cschar)}  cschar  = cint8;    pcschar   = ^cschar;  {$ENDIF}
  {$IF not Declared(cuchar)}  cuchar  = cuint8;   pcuchar   = ^cuchar;  {$ENDIF}

  {$IF not Declared(cint16)}  cint16  = SmallInt; pcint16   = ^cint16;  {$ENDIF}
  {$IF not Declared(cuint16)} cuint16 = Word;     pcuint16  = ^cuint16; {$ENDIF}
  {$IF not Declared(cshort)}  cshort  = cint16;   pcshort   = ^cshort;  {$ENDIF}
  {$IF not Declared(csshort)} csshort = cint16;   pcsshort  = ^csshort; {$ENDIF}
  {$IF not Declared(cushort)} cushort = cuint16;  pcushort  = ^cushort; {$ENDIF}

  {$IF not Declared(cint32)}  cint32   = LongInt;  pcint32   = ^cint32; {$ENDIF}
  {$IF not Declared(cuint32)} cuint32  = LongWord; pcuint32  = ^cuint32;{$ENDIF}

  {$IF not Declared(cint64)}  cint64   = Int64;    pcint64   = ^cint64; {$ENDIF}
  {$IF not Declared(cuint64)} cuint64  = qword;    pcuint64  = ^cuint64;{$ENDIF}

  {$IF not Declared(clonglong)}
    clonglong   = cint64; pclonglong  = ^clonglong;
  {$ENDIF}
  {$IF not Declared(cslonglong)}
    cslonglong  = cint64; pcslonglong = ^cslonglong;
  {$ENDIF}
  {$IF not Declared(culonglong)}
    culonglong  = cuint64; pculonglong = ^culonglong;
  {$ENDIF}

  {$IF not Declared(cbool)}   cbool   = LongBool; pcbool    = ^cbool;   {$ENDIF}

  // 3. Platform Dependent C Types
  // Logic:
  // - Windows (32/64): "long" is always 32-bit.
  // - Unix/Linux (64-bit): "long" is 64-bit (LP64 model).
  // - Unix/Linux (32-bit): "long" is 32-bit.

{$IF Defined(CPU64BITS) and not Defined(MSWINDOWS)}
  // 64-bit Non-Windows (Linux, macOS, Android, iOS)
  {$IF not Declared(cint)}    cint     = cint32;  pcint      = ^cint;   {$ENDIF}
  {$IF not Declared(csint)}   csint    = cint32;  pcsint     = ^csint;  {$ENDIF}
  {$IF not Declared(cuint)}   cuint    = cuint32; pcuint     = ^cuint;  {$ENDIF}

  // 'long' is 64-bit
  {$IF not Declared(clong)}   clong    = Int64;   pclong     = ^clong;  {$ENDIF}
  {$IF not Declared(cslong)}  cslong   = Int64;   pcslong    = ^cslong; {$ENDIF}
  {$IF not Declared(culong)}  culong   = qword;   pculong    = ^culong; {$ENDIF}
{$ELSE}
  // Windows (32/64) or 32-bit Non-Windows
  {$IF not Declared(cint)}    cint     = cint32;  pcint      = ^cint;   {$ENDIF}
  {$IF not Declared(csint)}   csint    = cint32;  pcsint     = ^csint;  {$ENDIF}
  {$IF not Declared(cuint)}   cuint    = cuint32; pcuint     = ^cuint;  {$ENDIF}

  // 'long' is 32-bit
  {$IF not Declared(clong)}   clong    = LongInt; pclong     = ^clong;  {$ENDIF}
  {$IF not Declared(cslong)}  cslong   = LongInt; pcslong    = ^cslong; {$ENDIF}
  {$IF not Declared(culong)}  culong   = Cardinal;pculong    = ^culong; {$ENDIF}
{$ENDIF}

  {$IF not Declared(csigned)}  csigned   = cint;  pcsigned   = ^csigned;  {$ENDIF}
  {$IF not Declared(cunsigned)}cunsigned = cuint; pcunsigned = ^cunsigned;{$ENDIF}

  // 4. size_t (Native Pointer Size)
  {$IF not Declared(csize_t)} csize_t = ptruint; pcsize_t   = pptruint;{$ENDIF}
  {$IF not Declared(size_t)} size_t   = csize_t; psize_t    = ^size_t;{$ENDIF}

implementation

end.
