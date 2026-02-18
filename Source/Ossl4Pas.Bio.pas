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

unit Ossl4Pas.Bio;

{$INCLUDE 'Ossl4Pas_CompilerDefines.inc'}

interface

uses
  Ossl4Pas.CTypes,
  Ossl4Pas.Api.Types,
  Ossl4Pas.Types,
  Ossl4Pas.Api.Bio;

type
{ TODO :
This is preliminary implementtation.
Needs to add more helper functions }

  /// <summary>
  ///   Pascal-friendly extensions for BIO text operations.
  ///   Provides explicit Ansi/Unicode handling and System.Format integration.
  /// </summary>
  TOsslApiBioTextHelper = class helper for TOsslApiBioText
  public
    // -------------------------------------------------------------------------
    // BIO_puts (Write String)
    // -------------------------------------------------------------------------

    /// <summary>Writes a Raw/Ansi string to the BIO.</summary>
    class function BIO_putsA(b: PBIO; const AStr: RawByteString): cint; static;
      {$IFDEF INLINE_ON}inline;{$ENDIF}

    /// <summary>Writes a Unicode string to the BIO (Converts to UTF-8).</summary>
    class function BIO_putsW(b: PBIO; const AStr: UnicodeString): cint; static;
      {$IFDEF INLINE_ON}inline;{$ENDIF}

    /// <summary>Writes a string (Default encoding) to the BIO.</summary>
    class function BIO_puts(b: PBIO; const AStr: string): cint; overload; static;
      {$IFDEF INLINE_ON}inline;{$ENDIF}

    // -------------------------------------------------------------------------
    // BIO_gets (Read String)
    // -------------------------------------------------------------------------

    /// <summary>Reads a line into a RawByteString.</summary>
    class function BIO_getsA(b: PBIO; AMaxLen: cint; out AStr: RawByteString): cint;
      static; {$IFDEF INLINE_ON}inline;{$ENDIF}

    /// <summary>Reads a line into a UnicodeString (Assumes UTF-8 input).</summary>
    class function BIO_getsW(b: PBIO; AMaxLen: cint; out AStr: UnicodeString): cint;
      static; {$IFDEF INLINE_ON}inline;{$ENDIF}

    /// <summary>Reads a line into a string (Default encoding).</summary>
    class function BIO_gets(b: PBIO; AMaxLen: cint; out AStr: string): cint;
      overload; static; {$IFDEF INLINE_ON}inline;{$ENDIF}

    // -------------------------------------------------------------------------
    // BIO_printf (Format & Write)
    // -------------------------------------------------------------------------

    /// <summary>Formats arguments using Ansi strings and writes to BIO.</summary>
    class function BIO_printfA(b: PBIO; const AStr: RawByteString;
      const Args: array of const): cint; static;

    /// <summary>Formats arguments using Unicode strings, converts to UTF-8, and writes to BIO.</summary>
    class function BIO_printfW(b: PBIO; const AStr: UnicodeString;
      const Args: array of const): cint; static;

    /// <summary>Formats arguments and writes to BIO (Default encoding).</summary>
    class function BIO_printf(b: PBIO; const AStr: string;
      const Args: array of const): cint; overload; static;
  end;

implementation

uses
  {$IFDEF DCC}
  System.SysUtils,
  System.AnsiStrings; // For Format
  {$ENDIF}
  {$IFDEF FPC}
  Sysutils;
  {$ENDIF}


{ TOsslApiBioTextHelper }

// =============================================================================
// BIO_puts
// =============================================================================

class function TOsslApiBioTextHelper.BIO_putsA(b: PBIO; const AStr: RawByteString): cint;
begin
  // Direct pass-through to C-API. Safe because RawByteString auto-casts to PAnsiChar.
  // Note: We use the static F_BIO_puts from TOsslApiBioText if accessible,
  // or call the class method.
  if Length(AStr) > 0 then
    Result:=BIO_puts(b, PAnsiChar(AStr))
  else
    Result:=0;
end;

class function TOsslApiBioTextHelper.BIO_putsW(b: PBIO; const AStr: UnicodeString): cint;
var
  lBytes: TBytes;
  lLen: cint;

begin
  if Length(AStr) <= 0 then
    Exit(0);

  // OpenSSL 3.x generally expects UTF-8 for text IO
  lBytes:=TEncoding.UTF8.GetBytes(AStr);
  lLen:=Length(lBytes);
  if lLen > 0 then
    // Use the base Write method for binary safety, or puts if null-term is guaranteed
    Result:=BIO_puts(b, PAnsiChar(@lBytes[0]))
  else
    Result:=0;
end;

class function TOsslApiBioTextHelper.BIO_puts(b: PBIO; const AStr: string): cint;
begin
  {$IFDEF UNICODE_DEFAULT}
  Result:=BIO_putsW(b, AStr);
  {$ELSE}
  Result:=BIO_putsA(b, AStr);
  {$ENDIF}
end;

// =============================================================================
// BIO_gets
// =============================================================================

class function TOsslApiBioTextHelper.BIO_getsA(b: PBIO; AMaxLen: cint;
  out AStr: RawByteString): cint;
begin
  if AMaxLen <= 0 then
    Exit(0);

  SetLength(AStr, AMaxLen);
  // BIO_gets returns total length read
  Result:=TOsslApiBioText.BIO_gets(b, PAnsiChar(AStr), AMaxLen);

  if Result > 0 then
    SetLength(AStr, Result)
  else
    AStr:='';
end;

class function TOsslApiBioTextHelper.BIO_getsW(b: PBIO; AMaxLen: cint;
  out AStr: UnicodeString): cint;
var
  lStr: RawByteString;

begin
  // Read as Ansi/UTF8 first
  Result:=BIO_getsA(b, AMaxLen, lStr);
  // Convert to Unicode (assuming UTF-8 content from OpenSSL)
  AStr:=UnicodeString(UTF8String(lStr));
end;

class function TOsslApiBioTextHelper.BIO_gets(b: PBIO; AMaxLen: cint;
  out AStr: string): cint;
begin
  {$IFDEF UNICODE_DEFAULT}
  Result:=BIO_getsW(b, AMaxLen, AStr);
  {$ELSE}
  Result:=BIO_getsA(b, AMaxLen, RawByteString(AStr));
  {$ENDIF}
end;

// =============================================================================
// BIO_printf
// =============================================================================

class function TOsslApiBioTextHelper.BIO_printfA(b: PBIO; const AStr: RawByteString;
  const Args: array of const): cint;
var
  lStr: RawByteString;

begin
  {$IFDEF DCC}
  lStr:=System.AnsiStrings.Format(AStr, Args);
  {$ENDIF}
  {$IFDEF FPC}
  lStr:=Format(AStr, Args);
  {$ENDIF}
  Result:=BIO_putsA(b, lStr);
end;

class function TOsslApiBioTextHelper.BIO_printfW(b: PBIO; const AStr: UnicodeString;
  const Args: array of const): cint;
var
  lStr: UnicodeString;

begin
  {$IFDEF DCC}
  lStr:=Format(AStr, Args);
  {$ENDIF}
  {$IFDEF FPC}
  lStr:=UnicodeFormat(AStr, Args);
  {$ENDIF}
  Result:=BIO_putsW(b, lStr);
end;

class function TOsslApiBioTextHelper.BIO_printf(b: PBIO; const AStr: string;
  const Args: array of const): cint;
begin
  {$IFDEF UNICODE_DEFAULT}
  Result:=BIO_printfW(b, AStr, Args);
  {$ELSE}
  Result:=BIO_printfA(b, AStr, Args);
  {$ENDIF}
end;

end.
