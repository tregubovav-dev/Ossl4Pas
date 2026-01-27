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

unit Ossl4Pas.Api.Err;

{$INCLUDE 'Ossl4Pas_CompilerDefines.inc'}

interface

uses
  System.SysUtils,
  Ossl4Pas.Api.Types,  // Defines PBIO
  Ossl4Pas.CTypes,
  Ossl4Pas.Types,
  Ossl4Pas.Binding;


const
  { ============================================================================
    ERROR CONSTANTS (openssl/err.h)
    Target: OpenSSL 3.0+
    ============================================================================ }

  // ---------------------------------------------------------------------------
  // ERROR DATA FLAGS
  // Used with ERR_get_error_all, ERR_peek_error_data, etc.
  // ---------------------------------------------------------------------------
  ERR_TXT_MALLOCED  = $01;
  ERR_TXT_STRING    = $02;

  // ---------------------------------------------------------------------------
  // LIBRARY CODES (ERR_LIB_*)
  // Identifies which subsystem generated the error.
  // ---------------------------------------------------------------------------
  ERR_LIB_NONE      = 1;
  ERR_LIB_SYS       = 2;
  ERR_LIB_BN        = 3;
  ERR_LIB_RSA       = 4;
  ERR_LIB_DH        = 5;
  ERR_LIB_EVP       = 6;
  ERR_LIB_BUF       = 7;
  ERR_LIB_OBJ       = 8;
  ERR_LIB_PEM       = 9;
  ERR_LIB_DSA       = 10;
  ERR_LIB_X509      = 11;
  // 12 was ERR_LIB_METH (Removed)
  ERR_LIB_ASN1      = 13;
  ERR_LIB_CONF      = 14;
  ERR_LIB_CRYPTO    = 15;
  ERR_LIB_EC        = 16;
  // 17..19 Gaps
  ERR_LIB_SSL       = 20;
  // 21..31 Gaps (SSL23, Proxy, etc removed)
  ERR_LIB_BIO       = 32;
  ERR_LIB_PKCS7     = 33;
  ERR_LIB_X509V3    = 34;
  ERR_LIB_PKCS12    = 35;
  ERR_LIB_RAND      = 36;
  ERR_LIB_DSO       = 37;
  ERR_LIB_ENGINE    = 38;
  ERR_LIB_OCSP      = 39;
  ERR_LIB_UI        = 40;
  ERR_LIB_COMP      = 41;
  ERR_LIB_ECDSA     = 42;
  ERR_LIB_ECDH      = 43;
  ERR_LIB_OSSL_STORE= 44;
  ERR_LIB_FIPS      = 45;
  ERR_LIB_CMS       = 46;
  ERR_LIB_TS        = 47;
  ERR_LIB_HMAC      = 48;
  // 49 was ERR_LIB_JPAKE (Removed)
  ERR_LIB_CT        = 50;
  ERR_LIB_ASYNC     = 51;
  ERR_LIB_KDF       = 52;
  ERR_LIB_SM2       = 53;
  ERR_LIB_ESS       = 54;
  ERR_LIB_PROP      = 55;
  ERR_LIB_CRMF      = 56;
  ERR_LIB_PROV      = 57;
  ERR_LIB_CMP       = 58;
  ERR_LIB_OSSL_ENCODER = 59;
  ERR_LIB_OSSL_DECODER = 60;
  ERR_LIB_HTTP      = 61;
  ERR_LIB_USER      = 128;

  // ---------------------------------------------------------------------------
  // GLOBAL REASON CODES (ERR_R_*)
  // Generic reasons that apply to multiple libraries.
  // ---------------------------------------------------------------------------

const
  // Macros to help decode recorded system errors
  ERR_SYSTEM_FLAG   = Cardinal($80000000);
  ERR_SYSTEM_MASK   = Cardinal($7FFFFFFF);

  // Macros to help decode recorded OpenSSL errors
  ERR_LIB_OFFSET    = 23;
  ERR_LIB_MASK      = $FF;

  ERR_RFLAGS_OFFSET = 18;
  ERR_RFLAGS_MASK   = $1F;
  ERR_REASON_MASK   = $7FFFFF;

  // Reason flags (pre-shifted)
  ERR_RFLAG_FATAL   = (1 shl ERR_RFLAGS_OFFSET); // $040000
  ERR_RFLAG_COMMON  = (2 shl ERR_RFLAGS_OFFSET); // $080000
  ERR_R_FATAL       = ERR_RFLAG_FATAL or ERR_RFLAG_COMMON;

  ERR_R_MALLOC_FAILURE                    = (1 or ERR_R_FATAL);
  ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED       = (2 or ERR_R_FATAL);
  ERR_R_PASSED_NULL_PARAMETER             = (3 or ERR_R_FATAL);
  ERR_R_INTERNAL_ERROR                    = (4 or ERR_R_FATAL);
  ERR_R_DISABLED                          = (5 or ERR_R_FATAL);
  ERR_R_INIT_FAIL                         = (6 or ERR_R_FATAL);
  ERR_R_PASSED_INVALID_ARGUMENT           = (7);
  ERR_R_OPERATION_FAIL                    = (8 or ERR_R_FATAL);
  ERR_R_INVALID_PROVIDER_FUNCTIONS        = (9 or ERR_R_FATAL);
  ERR_R_INTERRUPTED_OR_CANCELLED          = (10);
  ERR_R_NESTED_ASN1_ERROR                 = (58);
  ERR_R_MISSING_ASN1_EOS                  = (63);
  ERR_R_UNSUPPORTED                       = (64);
  ERR_R_FETCH_FAILED                      = (65);
  ERR_R_INVALID_PROPERTY_DEFINITION       = (66);
  ERR_R_UNABLE_TO_GET_READ_LOCK           = (67);
  ERR_R_UNABLE_TO_GET_WRITE_LOCK          = (68);

  // Max Error Buffer Size
  ERR_MAX_DATA_SIZE = 1024;

type
  // ---------------------------------------------------------------------------
  // GROUP 1: READER (Essential)
  // Used for retrieving and formatting errors.
  // ---------------------------------------------------------------------------
  TOsslApiErrCodes = class sealed
  public type
    TRoutine_ERR_get_error           = function: culong; cdecl;
    TRoutine_ERR_peek_error          = function: culong; cdecl;
    TRoutine_ERR_peek_last_error     = function: culong; cdecl;
    TRoutine_ERR_clear_error         = procedure; cdecl;

  strict private class var
    FIntialized: boolean;

    F_ERR_get_error:           TRoutine_ERR_get_error;
    F_ERR_peek_error:          TRoutine_ERR_peek_error;
    F_ERR_peek_last_error:     TRoutine_ERR_peek_last_error;
    F_ERR_clear_error:         TRoutine_ERR_clear_error;

  strict private const
    cBindings: array[0..3] of TOsslBindEntry = (
      (Name: 'ERR_get_error';             VarPtr: @@TOsslApiErrCodes.F_ERR_get_error;            MinVer: 0),
      (Name: 'ERR_peek_error';            VarPtr: @@TOsslApiErrCodes.F_ERR_peek_error;           MinVer: 0),
      (Name: 'ERR_peek_last_error';       VarPtr: @@TOsslApiErrCodes.F_ERR_peek_last_error;      MinVer: 0),
      (Name: 'ERR_clear_error';           VarPtr: @@TOsslApiErrCodes.F_ERR_clear_error;          MinVer: 0)
    );

  strict private
    class procedure Bind(const ALibHandle: TLibHandle;
      const AVersion: TOsslVersion); static;
    class procedure UnBind; static;

  public
    class constructor Create;

    class function ERR_get_error: culong; static; {$IFDEF INLINE_ON}inline;{$ENDIF}
    class function ERR_peek_error: culong; static; {$IFDEF INLINE_ON}inline;{$ENDIF}
    class function ERR_peek_last_error: culong; static; {$IFDEF INLINE_ON}inline;{$ENDIF}
    class procedure ERR_clear_error; static; {$IFDEF INLINE_ON}inline;{$ENDIF}

    class property Initialized: boolean read FIntialized;
  end;

  // ---------------------------------------------------------------------------
  // GROUP 2: Textual error description
  // Used for retrieving and formatting error strings.
  // ---------------------------------------------------------------------------
  TOsslApiErrStrings = class sealed
  public type
    TRoutine_ERR_error_string        = function(e: culong;
      buf: PAnsiChar): PAnsiChar; cdecl;
    TRoutine_ERR_error_string_n      = procedure(e: culong;
      buf: PAnsiChar; len: size_t); cdecl;

    TRoutine_ERR_lib_error_string    = function(e: culong): PAnsiChar; cdecl;
    TRoutine_ERR_reason_error_string = function(e: culong): PAnsiChar; cdecl;

    TRoutine_ERR_peek_error_func     = function(func: PPAnsiChar): culong; cdecl;
    TRoutine_ERR_peek_last_error_func= function(func: PPAnsiChar): culong; cdecl;

    TRoutine_ERR_peek_error_data     = function(data: PPAnsiChar;
      flags: Pcint): culong; cdecl;
    TRoutine_ERR_peek_last_error_data= function(data: PPAnsiChar;
      flags: Pcint): culong; cdecl;

    TRoutine_ERR_get_error_all       = function(file_: PPAnsiChar; line: Pcint;
      func: PPAnsiChar; data: PPAnsiChar; flags: Pcint): culong; cdecl;
    TRoutine_ERR_peek_error_all      = function(file_: PPAnsiChar; line: Pcint;
      func: PPAnsiChar; data: PPAnsiChar; flags: Pcint): culong; cdecl;
    TRoutine_ERR_peek_last_error_all = function(file_: PPAnsiChar; line: Pcint;
      func: PPAnsiChar; data: PPAnsiChar; flags: Pcint): culong; cdecl;

  strict private class var
    FIntialized: boolean;
    FMsgBindErr: AnsiString;

    F_ERR_error_string:        TRoutine_ERR_error_string;
    F_ERR_error_string_n:      TRoutine_ERR_error_string_n;
    F_ERR_lib_error_string:    TRoutine_ERR_lib_error_string;
    F_ERR_reason_error_string: TRoutine_ERR_reason_error_string;
    F_ERR_peek_error_func:      TRoutine_ERR_peek_error_func;
    F_ERR_peek_last_error_func: TRoutine_ERR_peek_last_error_func;
    F_ERR_peek_error_data:      TRoutine_ERR_peek_error_data;
    F_ERR_peek_last_error_data: TRoutine_ERR_peek_last_error_data;
    F_ERR_get_error_all:        TRoutine_ERR_get_error_all;
    F_ERR_peek_error_all:       TRoutine_ERR_peek_error_all;
    F_ERR_peek_last_error_all:  TRoutine_ERR_peek_last_error_all;

  strict private const
    cBindings: array[0..10] of TOsslBindEntry = (
      (Name: 'ERR_error_string';          VarPtr: @@TOsslApiErrStrings.F_ERR_error_string;         MinVer: 0),
      (Name: 'ERR_error_string_n';        VarPtr: @@TOsslApiErrStrings.F_ERR_error_string_n;       MinVer: 0),
      (Name: 'ERR_lib_error_string';      VarPtr: @@TOsslApiErrStrings.F_ERR_lib_error_string;     MinVer: 0),
      (Name: 'ERR_reason_error_string';   VarPtr: @@TOsslApiErrStrings.F_ERR_reason_error_string;  MinVer: 0),
      (Name: 'ERR_peek_error_func';       VarPtr: @@TOsslApiErrStrings.F_ERR_peek_error_func;      MinVer: 0),
      (Name: 'ERR_peek_last_error_func';  VarPtr: @@TOsslApiErrStrings.F_ERR_peek_last_error_func; MinVer: 0),
      (Name: 'ERR_peek_error_data';       VarPtr: @@TOsslApiErrStrings.F_ERR_peek_error_data;      MinVer: 0),
      (Name: 'ERR_peek_last_error_data';  VarPtr: @@TOsslApiErrStrings.F_ERR_peek_last_error_data; MinVer: 0),
      (Name: 'ERR_get_error_all';         VarPtr: @@TOsslApiErrStrings.F_ERR_get_error_all;        MinVer: 0),
      (Name: 'ERR_peek_error_all';        VarPtr: @@TOsslApiErrStrings.F_ERR_peek_error_all;       MinVer: 0),
      (Name: 'ERR_peek_last_error_all';   VarPtr: @@TOsslApiErrStrings.F_ERR_peek_last_error_all;  MinVer: 0)
    );

  strict private
    class procedure SetMsgBindErr; static; {$IFDEF INLINE_ON}inline;{$ENDIF}
    class function GetMsgBindErrBuf(buf: PAnsiChar; len: size_t): PAnsiChar;
      overload; static;
    class function GetMsgBindErrBuf: PAnsiChar; overload; static;
      {$IFDEF INLINE_ON}inline;{$ENDIF}
    class function GetMsgBindErrBufFlag(data: PPAnsiChar;
      flags: pcint): cint; overload; static;
    class function GetMsgBindErrBufFlagAll(file_, func, data: PPAnsiChar;
      line, flags: pcint): cint; overload; static;
    class procedure Bind(const ALibHandle: TLibHandle;
      const AVersion: TOsslVersion); static;
    class procedure UnBind; static;

  const
    cErrorStringBufSize = 256;

  public
    class constructor Create;

     // ERR_error_string Overloads

    /// <summary>
    ///   Converts error code to string using a user-supplied buffer.
    ///   Buffer must be at least 256 bytes.
    /// </summary>
    class function ERR_error_string(e: culong; buf: PAnsiChar): PAnsiChar; overload;
      static; {$IFDEF INLINE_ON}inline;{$ENDIF}

    // ERR_error_string_n (Thread Safe)
    class procedure ERR_error_string_n(e: culong; buf: PAnsiChar; len: size_t);
      static; {$IFDEF INLINE_ON}inline;{$ENDIF}

    class function ERR_lib_error_string(e: culong): PAnsiChar;
      static; {$IFDEF INLINE_ON}inline;{$ENDIF}

    class function ERR_reason_error_string(e: culong): PAnsiChar;
      static; {$IFDEF INLINE_ON}inline;{$ENDIF}

    class function ERR_peek_error_func(func: PPAnsiChar): culong;
      static; {$IFDEF INLINE_ON}inline;{$ENDIF}
    class function ERR_peek_last_error_func(func: PPAnsiChar): culong;
      static; {$IFDEF INLINE_ON}inline;{$ENDIF}

    class function ERR_peek_error_data(data: PPAnsiChar;
      flags: pcint): culong; static; {$IFDEF INLINE_ON}inline;{$ENDIF}
    class function ERR_peek_last_error_data(data: PPAnsiChar;
      flags: pcint): culong; static; {$IFDEF INLINE_ON}inline;{$ENDIF}

    // OpenSSL 3.0 "All" Routines
    // Returns code, outputs pointers to internal strings (no copy needed)
    class function ERR_get_error_all(file_: PPAnsiChar; line: pcint;
      func: PPAnsiChar; data: PPAnsiChar; flags: pcint): culong;
      overload; static; {$IFDEF INLINE_ON}inline;{$ENDIF}

    class function ERR_peek_error_all(file_: PPAnsiChar; line: pcint;
      func: PPAnsiChar; data: PPAnsiChar; flags: pcint): culong;
      static; {$IFDEF INLINE_ON}inline;{$ENDIF}
    class function ERR_peek_last_error_all(file_: PPAnsiChar; line: pcint;
      func: PPAnsiChar; data: PPAnsiChar; flags: pcint): culong;
      static; {$IFDEF INLINE_ON}inline;{$ENDIF}

    class property Initialized: boolean read FIntialized;
 end;

  TOsslApiErrStringsHelper = class helper for TOsslApiErrStrings
  public
    class function GetLibNameA(e: culong): RawByteString;
      static; {$IFDEF INLINE_ON}inline;{$ENDIF}

    class function GetLibNameW(e: culong): UnicodeString;
      static; {$IFDEF INLINE_ON}inline;{$ENDIF}

    class function GetLibName(e: culong): string;
      static; {$IFDEF INLINE_ON}inline;{$ENDIF}

    class function GetReasonA(e: culong): RawByteString;
      static; {$IFDEF INLINE_ON}inline;{$ENDIF}

    class function GetReasonW(e: culong): UnicodeString;
      static; {$IFDEF INLINE_ON}inline;{$ENDIF}

    class function GetReason(e: culong): string;
      static; {$IFDEF INLINE_ON}inline;{$ENDIF}

    class function GetErrorStringA(e: culong; AMaxlen: size_t): RawByteString;
      static; {$IFDEF INLINE_ON}inline;{$ENDIF}

    class function GetErrorStringW(e: culong; AMaxlen: size_t): UnicodeString;
      static; {$IFDEF INLINE_ON}inline;{$ENDIF}

    class function GetErrorString(e: culong; AMaxlen: size_t): string;
      static; {$IFDEF INLINE_ON}inline;{$ENDIF}

    class function GetErrorStringsA(out AFileName, AFunc, AData: RawByteString;
      var line, flags: cint): culong;
      overload; static; {$IFDEF INLINE_ON}inline;{$ENDIF}

    class function GetErrorStringsW(out AFileName, AFunc, AData: UnicodeString;
      var line, flags: cint): culong;
      overload; static; {$IFDEF INLINE_ON}inline;{$ENDIF}

    class function GetErrorStrings(out AFileName, AFunc, AData: string;
      var line, flags: cint): culong;
      overload; static; {$IFDEF INLINE_ON}inline;{$ENDIF}
  end;

  // ---------------------------------------------------------------------------
  // GROUP 3: SYSTEM & ADVANCED (Stack, Print, Put)
  // Used for advanced error handling, printing to BIO, or custom errors.
  // ---------------------------------------------------------------------------
  TOsslApiErrSystem = class sealed
  public type
    TRoutine_ERR_set_mark       = function: cint; cdecl;
    TRoutine_ERR_pop_to_mark    = function: cint; cdecl;
    TRoutine_ERR_print_errors   = procedure(bp: PBIO); cdecl;
    TRoutine_ERR_put_error      = procedure(lib, func, reason: cint; file_: PAnsiChar; line: cint); cdecl;

  strict private class var
    FIntialized: boolean;

    F_ERR_set_mark:       TRoutine_ERR_set_mark;
    F_ERR_pop_to_mark:    TRoutine_ERR_pop_to_mark;
    F_ERR_print_errors:   TRoutine_ERR_print_errors;
    F_ERR_put_error:      TRoutine_ERR_put_error;

  strict private const
    cBindings: array[0..3] of TOsslBindEntry = (
      (Name: 'ERR_set_mark';       VarPtr: @@TOsslApiErrSystem.F_ERR_set_mark;       MinVer: 0),
      (Name: 'ERR_pop_to_mark';    VarPtr: @@TOsslApiErrSystem.F_ERR_pop_to_mark;    MinVer: 0),
      (Name: 'ERR_print_errors';   VarPtr: @@TOsslApiErrSystem.F_ERR_print_errors;   MinVer: 0),
      (Name: 'ERR_put_error';      VarPtr: @@TOsslApiErrSystem.F_ERR_put_error;      MinVer: 0)
    );

  strict private
    class procedure Bind(const ALibHandle: TLibHandle;
      const AVersion: TOsslVersion); static;
    class procedure UnBind; static;

  public
    class constructor Create;

    class function ERR_set_mark: cint; static; {$IFDEF INLINE_ON}inline;{$ENDIF}
    class function ERR_pop_to_mark: cint; static; {$IFDEF INLINE_ON}inline;{$ENDIF}

    class procedure ERR_print_errors(bp: PBIO); static; {$IFDEF INLINE_ON}inline;{$ENDIF}
    class procedure ERR_put_error(lib, func, reason: cint; file_: PAnsiChar; line: cint); static; {$IFDEF INLINE_ON}inline;{$ENDIF}

    class property Initialized: boolean read FIntialized;
  end;

implementation

uses
  System.AnsiStrings,
  Ossl4Pas.Loader,
  Ossl4Pas.ResStrings;

function GetInitialized(const AEntries: array of TOsslBindEntry): boolean;
var
  i: integer;

begin
  Result:=True;
  for i:=Low(AEntries) to High(AEntries) do
    if not (Assigned(AEntries[i].VarPtr) and Assigned(AEntries[i].VarPtr^)) then
      Exit(False);
end;


{ TOsslApiErrCodes }

class constructor TOsslApiErrCodes.Create;
begin
  TOsslLoader.RegisterBinding(ltCrypto, @Bind, @UnBind);
end;

class procedure TOsslApiErrCodes.Bind(const ALibHandle: TLibHandle;
  const AVersion: TOsslVersion);
begin
  try
    TOsslBinding.Bind(ALibHandle, AVersion, cBindings, False);
  finally
    FIntialized:=GetInitialized(cBindings);
  end;
end;

class procedure TOsslApiErrCodes.UnBind;
begin
  try
    TOsslBinding.Reset(cBindings, False);
  finally
    FIntialized:=GetInitialized(cBindings);
  end;
end;

class function TOsslApiErrCodes.ERR_get_error: culong;
begin
  if Assigned(F_ERR_get_error) then
    Result:=F_ERR_get_error
  else
    Result:=0;
end;

class function TOsslApiErrCodes.ERR_peek_error: culong;
begin
  if Assigned(F_ERR_peek_error) then
    Result:=F_ERR_peek_error()
  else
    Result:=0;
end;

class function TOsslApiErrCodes.ERR_peek_last_error: culong;
begin
  if Assigned(F_ERR_peek_last_error) then
    Result:=F_ERR_peek_last_error()
  else
    Result:=F_ERR_peek_last_error;
end;

class procedure TOsslApiErrCodes.ERR_clear_error;
begin
  if Assigned(F_ERR_clear_error) then
    F_ERR_clear_error();
end;

{ TOsslApiErrStrings }

class constructor TOsslApiErrStrings.Create;
begin
  UnBind;
  TOsslLoader.RegisterBinding(ltCrypto, @Bind, @UnBind);
end;

class procedure TOsslApiErrStrings.SetMsgBindErr;
begin
  FMsgBindErr:=AnsiString(@resErrRoutineNotBound);
end;

class function TOsslApiErrStrings.GetMsgBindErrBuf(buf: PAnsiChar;
  len: size_t): PAnsiChar;
var
  lCopyLen: size_t;

begin
  Result:=PAnsiChar(FMsgBindErr);
  if not Assigned(buf) or (len = 0) then
    Exit;

  lCopyLen:=Length(FMsgBindErr);
  if len-1 < lCopyLen then
    lCopyLen:=len-1;

  if lCopyLen > 0 then
    Move(PAnsiChar(FMsgBindErr)^, buf^, lCopyLen);

  buf[lCopyLen]:=#0;
end;

class function TOsslApiErrStrings.GetMsgBindErrBuf: PAnsiChar;
begin
  Result:=PAnsiChar(FMsgBindErr);
end;

class function TOsslApiErrStrings.GetMsgBindErrBufFlag(data: PPAnsiChar;
  flags: pcint): cint;
begin
  Result:=0;
  if Assigned(data) then
    data^:=GetMsgBindErrBuf;
  if Assigned(flags) then
    flags^:=ERR_TXT_STRING;
end;

class function TOsslApiErrStrings.GetMsgBindErrBufFlagAll(file_, func,
  data: PPAnsiChar; line, flags: pcint): cint;
begin
  Result:=GetMsgBindErrBufFlag(data, flags);
  if Assigned(file_) then
    file_^:=GetMsgBindErrBuf;
  if Assigned(func) then
    func^:=GetMsgBindErrBuf;
  if Assigned(line) then
    line^:=0;
end;

class procedure TOsslApiErrStrings.Bind(const ALibHandle: TLibHandle;
  const AVersion: TOsslVersion);
begin
  try
    TOsslBinding.Bind(ALibHandle, AVersion, cBindings, False);
  finally
    FIntialized:=GetInitialized(cBindings);
  end;
end;

class procedure TOsslApiErrStrings.UnBind;
begin
  try
    TOsslBinding.Reset(cBindings, False);
  finally
    FIntialized:=GetInitialized(cBindings);
  end;
end;

class function TOsslApiErrStrings.ERR_error_string(e: culong;
  buf: PAnsiChar): PAnsiChar;
begin
  if Assigned(F_ERR_error_string) then
    Exit(F_ERR_error_string(e, buf))
  else
    Result:=GetMsgBindErrBuf(buf, cErrorStringBufSize);
end;

class procedure TOsslApiErrStrings.ERR_error_string_n(e: culong;
  buf: PAnsiChar; len: size_t);
begin
  if Assigned(F_ERR_error_string_n) then
    F_ERR_error_string_n(e, buf, len)
  else
    GetMsgBindErrBuf(buf, len);
end;

class function TOsslApiErrStrings.ERR_lib_error_string(e: culong): PAnsiChar;
begin
  if Assigned(F_ERR_lib_error_string) then
    Result:=F_ERR_lib_error_string(e)
  else
    Result:=GetMsgBindErrBuf;
end;

class function TOsslApiErrStrings.ERR_reason_error_string(e: culong): PAnsiChar;
begin
  if Assigned(F_ERR_reason_error_string) then
    Result:=F_ERR_reason_error_string(e)
  else
    Result:=GetMsgBindErrBuf;
end;

class function TOsslApiErrStrings.ERR_peek_error_func(func: PPAnsiChar): culong;
begin
  if Assigned(F_ERR_peek_error_func) then
    Exit(F_ERR_peek_error_func(func));

  Result:=0;
  if Assigned(func) then
    func^:=GetMsgBindErrBuf;
end;

class function TOsslApiErrStrings.ERR_peek_last_error_func(func: PPAnsiChar): culong;
begin
  if Assigned(F_ERR_peek_last_error_func) then
    Exit(F_ERR_peek_last_error_func(func));

  Result:=0;
  if Assigned(func) then
    func^:=GetMsgBindErrBuf;
end;

class function TOsslApiErrStrings.ERR_peek_error_data(data: PPAnsiChar;
  flags: pcint): culong;
begin
  if Assigned(F_ERR_peek_error_data) then
    Result:=F_ERR_peek_error_data(data, flags)
  else
    Result:=GetMsgBindErrBufFlag(data, flags);
end;

class function TOsslApiErrStrings.ERR_peek_last_error_data(data: PPAnsiChar;
  flags: pcint): culong;
begin
  if Assigned(F_ERR_peek_last_error_data) then
    Result:=F_ERR_peek_last_error_data(data, flags)
  else
    Result:=GetMsgBindErrBufFlag(data, flags);
end;

class function TOsslApiErrStrings.ERR_get_error_all(file_: PPAnsiChar;
  line: pcint; func: PPAnsiChar; data: PPAnsiChar; flags: pcint): culong;
begin
  if Assigned(F_ERR_get_error_all) then
    Result:=F_ERR_get_error_all(file_, line, func, data, flags)
  else
    Result:=GetMsgBindErrBufFlagAll(file_, func, data, line, flags);
end;

class function TOsslApiErrStrings.ERR_peek_error_all(file_: PPAnsiChar;
  line: pcint; func: PPAnsiChar; data: PPAnsiChar; flags: pcint): culong;
begin
  if Assigned(F_ERR_peek_error_all) then
    Result:=F_ERR_peek_error_all(file_, line, func, data, flags)
  else
    Result:=GetMsgBindErrBufFlagAll(file_, func, data, line, flags);
end;

class function TOsslApiErrStrings.ERR_peek_last_error_all(file_: PPAnsiChar;
  line: pcint; func: PPAnsiChar; data: PPAnsiChar; flags: pcint): culong;
begin
  Result := F_ERR_peek_last_error_all(file_, line, func, data, flags);
end;

{ TOsslApiErrStringsHelper }

class function TOsslApiErrStringsHelper.GetErrorStringA(e: culong;
  AMaxlen: size_t): RawByteString;
begin
  if AMaxLen = 0 then
    Exit;

  SetLength(Result, AMaxlen);
  ERR_error_string_n(e, @Result[1], AMaxLen);
end;

class function TOsslApiErrStringsHelper.GetErrorStringW(e: culong;
  AMaxlen: size_t): UnicodeString;
begin
  Result:=UnicodeString(GetErrorStringA(e, AMaxLen));
end;

class function TOsslApiErrStringsHelper.GetErrorString(e: culong;
  AMaxlen: size_t): string;
begin
  {$IFDEF UNICODE_DEFAULT}
    Result:=GetErrorStringW(e, AMaxLen);
  {$ELSE}
    Result:=GetErrorStringA(e, AMaxLen);
  {$ENDIF}
end;

class function TOsslApiErrStringsHelper.GetLibNameA(e: culong): RawByteString;
begin
  Result:=RawByteString(ERR_lib_error_string(e));
end;

class function TOsslApiErrStringsHelper.GetLibNameW(e: culong): UnicodeString;
begin
  Result:=UnicodeString(ERR_lib_error_string(e));
end;

class function TOsslApiErrStringsHelper.GetLibName(e: culong): string;
begin
  {$IFDEF UNICODE_DEFAULT}
    Result:=GetLibNameW(e);
  {$ELSE}
    Result:=GetLibNameA(e);
  {$ENDIF}
end;

class function TOsslApiErrStringsHelper.GetReasonA(e: culong): RawByteString;
begin
  Result:=RawByteString(ERR_reason_error_string(e));
end;

class function TOsslApiErrStringsHelper.GetReasonW(e: culong): UnicodeString;
begin
  Result:=UnicodeString(ERR_reason_error_string(e));
end;

class function TOsslApiErrStringsHelper.GetReason(e: culong): string;
begin
  {$IFDEF UNICODE_DEFAULT}
    Result:=GetReasonW(e);
  {$ELSE}
    Result:=GetReasonA(e);
  {$ENDIF}
end;

class function TOsslApiErrStringsHelper.GetErrorStringsA(out AFileName, AFunc,
  AData: RawByteString; var line, flags: cint): culong;
var
  lFileName, lFunc, lData: PAnsiChar;

begin
  Result:=TOsslApiErrStrings.ERR_get_error_all(@lFileName, @line, @lFunc,
    @lData, @flags);
  AFileName:=RawByteString(lFileName);
  AFunc:=RawByteString(lFunc);
  AData:=RawByteString(lData);
end;

class function TOsslApiErrStringsHelper.GetErrorStringsW(out AFileName, AFunc,
  AData: UnicodeString; var line, flags: cint): culong;
var
  lFileName, lFunc, lData: PAnsiChar;

begin
  Result:=TOsslApiErrStrings.ERR_get_error_all(@lFileName, @line, @lFunc,
    @lData, @flags);
  AFileName:=UnicodeString(lFileName);
  AFunc:=UnicodeString(lFunc);
  AData:=UnicodeString(lData);
end;

class function TOsslApiErrStringsHelper.GetErrorStrings(out AFileName, AFunc,
  AData: string; var line, flags: cint): culong;
begin
  {$IFDEF UNICODE_DEFAULT}
    Result:=GetErrorStringsW(AFileName, AFunc, AData, line, flags);
  {$ELSE}
    Result:=GetErrorStringsA(AFileName, AFunc, AData, line, flags);
  {$ENDIF}
end;

{ TOsslApiErrSystem }

class constructor TOsslApiErrSystem.Create;
begin
  UnBind;
  TOsslLoader.RegisterBinding(ltCrypto, @Bind, @UnBind);
end;

class procedure TOsslApiErrSystem.Bind(const ALibHandle: TLibHandle;
  const AVersion: TOsslVersion);
begin
  try
    TOsslBinding.Bind(ALibHandle, AVersion, cBindings);
  finally
    FIntialized:=GetInitialized(cBindings);
  end;
end;

class procedure TOsslApiErrSystem.UnBind;
begin
  try
    TOsslBinding.Reset(cBindings);
  finally
    FIntialized:=GetInitialized(cBindings);
  end;
end;

class function TOsslApiErrSystem.ERR_set_mark: cint;
begin
  if Assigned(F_ERR_set_mark) then
    Result:=F_ERR_set_mark()
  else
    Result:=0;
end;

class function TOsslApiErrSystem.ERR_pop_to_mark: cint;
begin
  if Assigned(F_ERR_pop_to_mark) then
    Result:=F_ERR_pop_to_mark()
  else
    Result:=0;
end;

class procedure TOsslApiErrSystem.ERR_print_errors(bp: PBIO);
begin
  if Assigned(F_ERR_print_errors) then
    F_ERR_print_errors(bp);
end;

class procedure TOsslApiErrSystem.ERR_put_error(lib, func, reason: cint;
  file_: PAnsiChar; line: cint);
begin
  if Assigned(F_ERR_put_error) then
    F_ERR_put_error(lib, func, reason, file_, line);
end;

end.
