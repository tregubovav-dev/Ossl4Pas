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

unit Ossl4Pas.Err;

{$INCLUDE 'Ossl4Pas_CompilerDefines.inc'}

interface

uses
  {$IFDEF DCC}
  System.SysUtils,
  System.SyncObjs,
  System.Generics.Collections,
  {$ENDIF}
  {$IFDEF FPC}
  SysUtils,
  SyncObjs,
  Generics.Collections,
  {$ENDIF}
  {$IFDEF STUB_TSPINWAIT}
  fpc.stub.syncobjs,
  {$ENDIF}
  Ossl4Pas.CTypes,
  Ossl4Pas.Types,
  Ossl4Pas.Api.Err;


type
  { ============================================================================
    ENUMERATIONS
    Mapped directly to the constants defined in Ossl4Pas.Api.Err.
    ============================================================================ }

  /// <summary>Identifies the subsystem that generated the error.</summary>
  TOsslLibCode = (
    olcUnknown      = 0,
    olcNone         = ERR_LIB_NONE,           // 1
    olcSys          = ERR_LIB_SYS,            // 2
    olcBn           = ERR_LIB_BN,             // 3
    olcRsa          = ERR_LIB_RSA,            // 4
    olcDh           = ERR_LIB_DH,             // 5
    olcEvp          = ERR_LIB_EVP,            // 6
    olcBuf          = ERR_LIB_BUF,            // 7
    olcObj          = ERR_LIB_OBJ,            // 8
    olcPem          = ERR_LIB_PEM,            // 9
    olcDsa          = ERR_LIB_DSA,            // 10
    olcX509         = ERR_LIB_X509,           // 11
    // 12 skipped
    olcAsn1         = ERR_LIB_ASN1,           // 13
    olcConf         = ERR_LIB_CONF,           // 14
    olcCrypto       = ERR_LIB_CRYPTO,         // 15
    olcEc           = ERR_LIB_EC,             // 16
    // 17..19 skipped
    olcSsl          = ERR_LIB_SSL,            // 20
    // 21..31 skipped
    olcBio          = ERR_LIB_BIO,            // 32
    olcPkcs7        = ERR_LIB_PKCS7,          // 33
    olcX509V3       = ERR_LIB_X509V3,         // 34
    olcPkcs12       = ERR_LIB_PKCS12,         // 35
    olcRand         = ERR_LIB_RAND,           // 36
    olcDso          = ERR_LIB_DSO,            // 37
    olcEngine       = ERR_LIB_ENGINE,         // 38
    olcOcsp         = ERR_LIB_OCSP,           // 39
    olcUi           = ERR_LIB_UI,             // 40
    olcComp         = ERR_LIB_COMP,           // 41
    olcEcdsa        = ERR_LIB_ECDSA,          // 42
    olcEcdh         = ERR_LIB_ECDH,           // 43
    olcOsslStore    = ERR_LIB_OSSL_STORE,     // 44
    olcFips         = ERR_LIB_FIPS,           // 45
    olcCms          = ERR_LIB_CMS,            // 46
    olcTs           = ERR_LIB_TS,             // 47
    olcHmac         = ERR_LIB_HMAC,           // 48
    // empty        = 49
    olcCt           = ERR_LIB_CT,             // 50
    olcAsync        = ERR_LIB_ASYNC,          // 51
    olcKdf          = ERR_LIB_KDF,            // 52
    olcSm2          = ERR_LIB_SM2,            // 53
    olcEss          = ERR_LIB_ESS,            // 54
    olcProp         = ERR_LIB_PROP,           // 55
    olcCrmf         = ERR_LIB_CRMF,           // 56
    olcProv         = ERR_LIB_PROV,           // 57
    olcCmp          = ERR_LIB_CMP,            // 58
    olcOsslEncoder  = ERR_LIB_OSSL_ENCODER,   // 59
    olcOsslDecoder  = ERR_LIB_OSSL_DECODER,   // 60
    olcHttp         = ERR_LIB_HTTP,           // 61
    // empty        = 62 .. 127
    olcUser         = ERR_LIB_USER            // 128
  );


  /// <summary>Reason Flags extracted from the error code.</summary>
  TOsslReasonFlag = (
    orfFatal,   // Contains ERR_R_FATAL
    orfCommon  // Contains ERR_RFLAG_COMMON
  );

  POsslReasonFlags = ^TOsslReasonFlags;
  TOsslReasonFlags = set of TOsslReasonFlag;


type
  TOsslErrCode = type culong;

  TOsslErrCodeHelper = record helper for TOsslErrCode
  const
    cErrCodeReasonFlagsEnumMask = cardinal((1 shl (Ord(High(TOsslReasonFlag))+1))-1);
    cUnknownLibIDs              = [12, 17..19, 21..31, 49, 129..255];

  private
    function GetLib: TOsslLibCode; {$IFDEF INLINE_ON}inline;{$ENDIF}
    function GetLibRaw: cuint8; {$IFDEF INLINE_ON}inline;{$ENDIF}
    function GetReason: culong; {$IFDEF INLINE_ON}inline;{$ENDIF}
    function GetReasonFlags: TOsslReasonFlags; {$IFDEF INLINE_ON}inline;{$ENDIF}
    function GetFlagsRaw: culong; {$IFDEF INLINE_ON}inline;{$ENDIF}
    function GetIsFatal: boolean; {$IFDEF INLINE_ON}inline;{$ENDIF}
    function GetIsCommon: boolean; {$IFDEF INLINE_ON}inline;{$ENDIF}
    function GetIsSystem: boolean; {$IFDEF INLINE_ON}inline;{$ENDIF}
    function GetIsError: boolean; {$IFDEF INLINE_ON}inline;{$ENDIF}

  public
    property Lib: TOsslLibCode read GetLib;
    property LibRaw: cuint8 read GetLibRaw;
    property Reason: culong read GetReason;
    property ReasonFlags: TOsslReasonFlags read GetReasonFlags;
    property ReasonFlagsRaw: culong read GetFlagsRaw;
    property IsFatal: boolean read GetIsFatal;
    property IsCommon: boolean read GetIsCommon;
    property IsSystem: boolean read GetIsSystem;
    property IsError: boolean read GetIsError;
  end;

type
  // ---------------------------------------------------------------------------
  // EXCEPTION HIERARCHY
  // ---------------------------------------------------------------------------

  /// <summary>
  ///   Base exception class for OpenSSL errors.
  ///   Automatically retrieves the error queue stack upon creation using TOsslAPIErrReader.
  /// </summary>
  EOsslCustomError = class(Exception)
  public type
    TErrorMessageFlag = (emfStack, emfCode, emfLibName, emfFileName,
      emfLine, emfDescript, emfFuncName);
    TErrorMessageFlags = set of TErrorMessageFlag;

  protected type
    TErrorEntry = record
      ErrCode: TOsslErrCode;
      FileName: string;
      FuncName: string;
      Descript: string;
      Line: cint;
    end;

    TErrorStack = TList<TErrorEntry>;

    { TErrorMessageFlagRec }

    TErrorMessageFlagRec = record
    private type
      PErrorMessageFlags = ^TErrorMessageFlags;

    public const
      cMask = cardinal((1 shl (Ord(High(TErrorMessageFlag))+1))-1);

    private
      FStorage: cardinal;

    public
    {$IFDEF DCC}
      ///   Atomically assigns the value of one flags record to another.
      ///   Implements the ":=" operator.
      /// </summary>
      /// <param name="Dest">The destination record to be updated.</param>
      /// <param name="Src">The source record.</param>
      class operator Assign(var Dest: TErrorMessageFlagRec;
        const [ref] Src: TErrorMessageFlagRec); {$IFDEF INLINE_ON}inline;{$ENDIF}
    {$ENDIF}
    {$IFDEF FPC}
      // FPC does not suppor `operator Assign` we have to use `operator Initialize` instead
      class operator Copy(constref Src: TErrorMessageFlagRec;
        var Dest: TErrorMessageFlagRec); {$IFDEF INLINE_ON}inline;{$ENDIF}
    {$ENDIF}

      /// <summary>
      ///   Implicitly converts a standard Pascal Set to the thread-safe record.
      /// </summary>
      class operator Implicit(a: TErrorMessageFlags): TErrorMessageFlagRec;
        {$IFDEF INLINE_ON}inline;{$ENDIF}

      /// <summary>
      ///   Implicitly converts the thread-safe record back to a standard Pascal Set.
      /// </summary>
      class operator Implicit(a: TErrorMessageFlagRec): TErrorMessageFlags;
        {$IFDEF INLINE_ON}inline;{$ENDIF}

      /// <summary>
      ///   Checks if a specific flag is set within the record.
      ///   Implements the standard "in" operator.
      /// </summary>
      class operator In(a: TErrorMessageFlagRec; b: TErrorMessageFlag): boolean;
        {$IFDEF INLINE_ON}inline;{$ENDIF}

      /// <summary>
      ///   Atomically adds a flag to the specified record using a spin-lock strategy.
      /// </summary>
      /// <param name="a">The record to modify.</param>
      /// <param name="b">The flag to include.</param>
      class procedure Include(a: TErrorMessageFlagRec; b: TErrorMessageFlag); overload;
        static; {$IFDEF INLINE_ON}inline;{$ENDIF}

      /// <summary>
      ///   Atomically adds a flag to the current instance.
      /// </summary>
      /// <param name="AFLag">The flag to include.</param>
      procedure Include(AFLag: TErrorMessageFlag); overload;
        {$IFDEF INLINE_ON}inline;{$ENDIF}

      /// <summary>
      ///   Atomically removes a flag from the specified record using a spin-lock strategy.
      /// </summary>
      /// <param name="a">The record to modify.</param>
      /// <param name="b">The flag to exclude.</param>
      class procedure Exclude(a: TErrorMessageFlagRec; b: TErrorMessageFlag); overload;
        static; {$IFDEF INLINE_ON}inline;{$ENDIF}

      /// <summary>
      ///   Atomically removes a flag from the current instance.
      /// </summary>
      /// <param name="AFlag">The flag to exclude.</param>
      procedure Exclude(AFlag: TErrorMessageFlag); overload;
        {$IFDEF INLINE_ON}inline;{$ENDIF}

    end;

  private class var
    FErrorMessageFlags: TErrorMessageFlagRec;

  public class var
    ErrUnknownError: string;
    ErrFmtSpace: string;
    ErrFmtComma: string;
    ErrFmtCode: string;
    ErrFmtLib: string;
    ErrFmtFile: string;
    ErrFmtLine: string;
    ErrFmtFunc: string;
    ErrFmtDescript: string;
    ErrFmtOsslWithMessage: string;
    ErrFmtOsslWithoutMessage: string;
    ErrFmtNestedSectionBegins: string;
    ErrFmtNestedSectionEnds: string;
    ErrFmtNestedLineBegins: string;
    ErrFmtNestedLineEnds: string;
    ErrFmtNestedNewLine: string;

  const
    cErrStackMaxSize = 512;
    cDefaultErrorMessageFlags = [emfCode, emfLibName, emfDescript];

  private
    FErrorStack: TErrorStack;
    procedure FillErrorStack;
    class function GetLibName(e: TOsslErrCode): string; static;
     {$IFDEF INLINE_ON}inline;{$ENDIF}
    function GetLastError: TOsslErrCode; {$IFDEF INLINE_ON}inline;{$ENDIF}
    function GetIsErrorStackEmpty: boolean; {$IFDEF INLINE_ON}inline;{$ENDIF}

  protected
    class function GetOsslErrorExists: boolean; static;

    property ErrorStack: TErrorStack read FErrorStack;
    property IsErrorStackEmpty: boolean read GetIsErrorStackEmpty;

  public
    class constructor Create;
    class procedure LoadStrings;

    constructor Create(const AMsg: string); overload;
    constructor CreateFmt(const AMsg: string; const Args: array of const); overload;
    constructor CreateRes(ResStringRec: PResStringRec); overload;
    constructor CreateResFmt(ResStringRec: PResStringRec;
      const Args: array of const); overload;
    destructor Destroy; override;

    class property OsslErrorExist: boolean read GetOsslErrorExists;

     { TODO : Revew and provide better way to manage flags }
    class property ErrorMessageFlags: TErrorMessageFlagRec read FErrorMessageFlags;

    function ToString: string; overload; override;
    function ToString(AFlags: TErrorMessageFlags): string; reintroduce;
      overload; virtual;
    function ToString(const AErrorEntry: TErrorEntry;
      AFlags: TErrorMessageFlags): string; reintroduce; overload; virtual;

    property LastError: TOsslErrCode read GetLastError;
  end;

implementation

uses
  Ossl4Pas.ResStrings;

{ TOsslErrCodeHelper }

function TOsslErrCodeHelper.GetLib: TOsslLibCode;
var
  lLibRaw: cuint8;

begin
  lLibRaw:=GetLibRaw;
  if lLibRaw in cUnknownLibIDs then
    Result:=olcUnknown
  else
    Result:=TOsslLibCode(lLibRaw);
end;

function TOsslErrCodeHelper.GetLibRaw: cuint8;
begin
  //  static ossl_unused ossl_inline int ERR_GET_LIB(unsigned long errcode)
  //  {
  //    if (ERR_SYSTEM_ERROR(errcode))
  //        return ERR_LIB_SYS;
  //    return (errcode >> ERR_LIB_OFFSET) & ERR_LIB_MASK;
  //  }

  if IsSystem then
    Result:=ERR_LIB_SYS
  else
    Result:=cuint8((Self shr ERR_LIB_OFFSET) and ERR_LIB_MASK);
end;

function TOsslErrCodeHelper.GetReason: culong;
begin
  //  static ossl_unused ossl_inline int ERR_GET_REASON(unsigned long errcode)
  //  {
  //      if (ERR_SYSTEM_ERROR(errcode))
  //          return errcode & ERR_SYSTEM_MASK;
  //      return errcode & ERR_REASON_MASK;
  //  }

  if IsSystem then
    Result:=culong(Self and ERR_SYSTEM_MASK)
  else
    Result:=culong(Self and ERR_REASON_MASK);
end;

function TOsslErrCodeHelper.GetReasonFlags: TOsslReasonFlags;
var
  lFlagsRaw: cuint8;

begin
  lFlagsRaw:=culong((GetFlagsRaw shr ERR_RFLAGS_OFFSET)
    and cErrCodeReasonFlagsEnumMask);
  Result:=POsslReasonFlags(@lFlagsRaw)^;
end;

function TOsslErrCodeHelper.GetFlagsRaw: culong;
begin
  //  static ossl_unused ossl_inline int ERR_GET_RFLAGS(unsigned long errcode)
  //  {
  //      if (ERR_SYSTEM_ERROR(errcode))
  //          return 0;
  //      return errcode & (ERR_RFLAGS_MASK << ERR_RFLAGS_OFFSET);
  //  }

  if IsSystem then
    Result:=0
  else
    Result:=culong((Self and (ERR_RFLAGS_MASK shl ERR_RFLAGS_OFFSET)));
end;

function TOsslErrCodeHelper.GetIsFatal: boolean;
begin
  //  static ossl_unused ossl_inline int ERR_FATAL_ERROR(unsigned long errcode)
  //  {
  //      return (ERR_GET_RFLAGS(errcode) & ERR_RFLAG_FATAL) != 0;
  //  }

  Result:=(GetFlagsRaw and ERR_RFLAG_FATAL) <> 0;
end;

function TOsslErrCodeHelper.GetIsCommon: boolean;
begin
  //  static ossl_unused ossl_inline int ERR_COMMON_ERROR(unsigned long errcode)
  //  {
  //      return (ERR_GET_RFLAGS(errcode) & ERR_RFLAG_COMMON) != 0;
  //  }

  Result:=(GetFlagsRaw and ERR_RFLAG_COMMON) <> 0;
end;

function TOsslErrCodeHelper.GetIsSystem: boolean;
begin
  // #define ERR_SYSTEM_ERROR(errcode) (((errcode) & ERR_SYSTEM_FLAG) != 0)

  Result:=(Self and ERR_SYSTEM_FLAG) <> 0;
end;

function TOsslErrCodeHelper.GetIsError: boolean;
begin
  Result:=Self <> 0;
end;

{ EOsslCustomError.TErrorMessageFlagRec }

{$IFDEF DCC}
class operator EOsslCustomError.TErrorMessageFlagRec.Assign(var Dest: TErrorMessageFlagRec;
  const [ref] Src: TErrorMessageFlagRec);
{$ENDIF}
{$IFDEF FPC}
class operator EOsslCustomError.TErrorMessageFlagRec.Copy(constref Src: TErrorMessageFlagRec;
        var Dest: TErrorMessageFlagRec);
{$ENDIF}
begin
  {$IF Defined(USE_TINTERLOCKED)}
  TInterlocked.Exchange(Dest.FStorage, Src.FStorage);
  {$ELSEIF Defined(USE_ATOMIC_DCC)}
  AtomicExchange(PInteger(@Dest.FStorage)^, PInteger(@Src.FStorage)^);
  {$ELSEIF Defined(USE_ATOMIC_FPC)}
  System.InterlockedExchange(cardinal(Dest.FStorage), cardinal(Src.FStorage))
  {$ENDIF}
end;

class operator EOsslCustomError.TErrorMessageFlagRec.Implicit(
  a: TErrorMessageFlags): TErrorMessageFlagRec;
begin
  // clean possible garbage bits with `and cMask`
  Result.FStorage:=PCardinal(@a)^ and cMask;
end;

class operator EOsslCustomError.TErrorMessageFlagRec.Implicit(
  a: TErrorMessageFlagRec): TErrorMessageFlags;
begin
  // explicitly convert to `TLoaderFlags`
  Result:=PErrorMessageFlags(@a)^;
end;

class operator EOsslCustomError.TErrorMessageFlagRec.in(
  a: TErrorMessageFlagRec; b: TErrorMessageFlag): boolean;
var
  lFlag: cardinal;

begin
  lFlag:=1 shl Ord(b);
  Result:=(a.FStorage and lFlag) = lFlag;
end;

procedure EOsslCustomError.TErrorMessageFlagRec.Include(AFLag: TErrorMessageFlag);
begin
  Include(Self, AFlag); // calls a `class procedure Include`
end;

class procedure EOsslCustomError.TErrorMessageFlagRec.Include(a: TErrorMessageFlagRec;
  b: TErrorMessageFlag);
var
  lOld, lNew, lPrev: cardinal;
  lBits: cardinal;
  lSpin: TSpinWait;

begin
  lSpin.Reset;
  // Note: Assuming intention is (1 shl Ord(b)).
  // If b is passed as the mask directly, this is correct.
  // If b is the Enum, this should be: lBits := 1 shl Ord(b);
  lBits:=cardinal(b);
  lOld:=a.FStorage;

  repeat
    lNew:=lOld or lBits;
    // Optimization: If flag is already set, exit immediately without atomic write
    if lOld = lNew then
      Exit;

    // Try to swap lOld with lNew.
    // If a.FStorage equals lOld, it becomes lNew, and lPrev returns lOld.
    // If they don't match (another thread changed it), lPrev returns the `current` value.
    {$IF Defined(USE_TINTERLOCKED)}
    lPrev:=TInterlocked.CompareExchange(a.FStorage, lNew, lOld);
    {$ELSEIF Defined(USE_ATOMIC_DCC)}
    PCardinal(@lPrev)^:=AtomicCmpExchange(PInteger(@a.FStorage)^,
      PInteger(@lNew)^, PInteger(@lOld)^);
    {$ELSEIF Defined(USE_ATOMIC_FPC)}
    System.InterlockedCompareExchange(cardinal(a.FStorage), cardinal(lNew), cardinal(lNew));
    {$ENDIF}
    if lPrev = lOld then
      Exit;

    // CAS failed: Update our expectation (lOld) to the current value and retry
    lOld:=lPrev;
    lSpin.SpinCycle; // spin cycle(s) and try again
  until False;
end;

procedure EOsslCustomError.TErrorMessageFlagRec.Exclude(AFlag: TErrorMessageFlag);
begin
  Exclude(Self, AFlag); // calls a `class procedure Include`
end;

class procedure EOsslCustomError.TErrorMessageFlagRec.Exclude(a: TErrorMessageFlagRec;
  b: TErrorMessageFlag);
var
  lOld, lNew, lPrev: cardinal;
  lBits: cardinal;
  lSpin: TSpinWait;

begin
  lSpin.Reset;
  lBits:=cardinal(b); // See note in `Include` regarding bit shifting
  lOld:=a.FStorage;

  repeat
    lNew:=lOld and not lBits;
    // Optimization: If flag is already cleared, exit immediately
    if lOld = lNew then
      Exit;

    // see note in `Include` about swapping lOld and lNew
    {$IF Defined(USE_TINTERLOCKED)}
    lPrev:=TInterlocked.CompareExchange(a.FStorage, lNew, lOld);
    {$ELSEIF Defined(USE_ATOMIC_DCC)}
    PCardinal(@lPrev)^:=AtomicCmpExchange(PInteger(@a.FStorage)^,
      PInteger(@lNew)^, PInteger(@lOld)^);
    {$ELSEIF Defined(USE_ATOMIC_FPC)}
    System.InterlockedCompareExchange(cardinal(a.FStorage), cardinal(lNew), cardinal(lNew));
    {$ENDIF}

    if lPrev = lOld then
      Exit;

    lOld:=lPrev;
    lSpin.SpinCycle;
  until False;
end;

{ EOsslCustomError }

class constructor EOsslCustomError.Create;
begin
  LoadStrings;
  FErrorMessageFlags:=cDefaultErrorMessageFlags;
end;

class procedure EOsslCustomError.LoadStrings;
begin
  ErrUnknownError:=LoadResString(@resErrUnknownError);
  ErrFmtSpace:=LoadResString(@resErrFmtSpace);
  ErrFmtComma:=LoadResString(@resErrFmtComma);
  ErrFmtCode:=LoadResString(@resErrFmtCode);
  ErrFmtLib:=LoadResString(@resErrFmtLib);
  ErrFmtFile:=LoadResString(@resErrFmtFile);
  ErrFmtLine:=LoadResString(@resErrFmtLine);
  ErrFmtFunc:=LoadResString(@resErrFmtFunc);
  ErrFmtDescript:=LoadResString(@resErrFmtDescript);
  ErrFmtOsslWithMessage:=LoadResString(@resErrFmtOsslWithMessage);
  ErrFmtOsslWithoutMessage:=LoadResString(@resErrFmtOsslWithoutMessage);
  ErrFmtNestedSectionBegins:=LoadResString(@resErrFmtNestedSectionBegins);
  ErrFmtNestedSectionEnds:=LoadResString(@resErrFmtNestedSectionEnds);
  ErrFmtNestedLineBegins:=LoadResString(@resErrFmtNestedLineBegins);
  ErrFmtNestedLineEnds:=LoadResString(@resErrFmtNestedLineEnds);
  ErrFmtNestedNewLine:=LoadResString(@resErrFmtNestedNewLine);
end;

class function EOsslCustomError.GetOsslErrorExists: boolean;
begin
  Result:=TOsslAPIErrCodes.Initialized and (TOsslAPIErrCodes.ERR_peek_error <> 0);
end;

constructor EOsslCustomError.Create(const AMsg: string);
begin
  inherited;
  FillErrorStack;
  Self.Message:=ToString(TErrorMessageFlags(ErrorMessageFlags)-[emfStack]);
end;

constructor EOsslCustomError.CreateFmt(const AMsg: string;
  const Args: array of const);
begin
  inherited;
  FillErrorStack;
  Self.Message:=ToString(TErrorMessageFlags(ErrorMessageFlags)-[emfStack]);
end;

constructor EOsslCustomError.CreateRes(ResStringRec: PResStringRec);
begin
  inherited;
  FillErrorStack;
  Self.Message:=ToString(TErrorMessageFlags(ErrorMessageFlags)-[emfStack]);
end;

constructor EOsslCustomError.CreateResFmt(ResStringRec: PResStringRec;
  const Args: array of const);
begin
  inherited;
  FillErrorStack;
  Self.Message:=ToString(TErrorMessageFlags(ErrorMessageFlags)-[emfStack]);
end;

destructor EOsslCustomError.Destroy;
begin
  FreeAndNil(FErrorStack);
  inherited;
end;

procedure EOsslCustomError.FillErrorStack;
var
  lEntry: TErrorEntry;
  lFlags: cint;
  lErrCode: TOsslErrCode;
  lCount: integer;

begin
  if not TOsslAPIErrStrings.Initialized then
    Exit;

  if not Assigned(FErrorStack) then
    FErrorStack:=TErrorStack.Create;

  lCount:=0;
  repeat
    lErrCode:=TOsslAPIErrStrings.GetErrorStrings(lEntry.FileName,
      lEntry.FuncName, lEntry.Descript, lEntry.Line, lFlags);

    if not lErrCode.IsError then
      break;

    lEntry.ErrCode:=lErrCode;
    FErrorStack.Add(lEntry);
    Inc(lCount);
  until lCount >= cErrStackMaxSize;
end;

function EOsslCustomError.GetLastError: TOsslErrCode;
begin
  if IsErrorStackEmpty then
    Result:=0
  else
    Result:=FErrorStack[0].ErrCode;
end;

function EOsslCustomError.GetIsErrorStackEmpty: boolean;
begin
  Result:=FErrorStack.Count = 0;
end;

class function EOsslCustomError.GetLibName(e: TOsslErrCode): string;
begin
  if e.IsError and TOsslAPIErrStrings.Initialized then
    Result:=TOsslAPIErrStrings.GetLibName(e);
end;

function EOsslCustomError.ToString: string;
begin
  Result:=ToString(ErrorMessageFlags);
end;

function EOsslCustomError.ToString(AFlags: TErrorMessageFlags): string;
var
  i: integer;
  lLineCount: integer;
  lTempStr: string;


begin
  if GetLastError = 0 then
  begin
    Result:=Self.Message;
    if Result.IsEmpty then
      Result:=resErrUnknownError;
    Exit;
  end;

  lLineCount:=ErrorStack.Count;

  lTempStr:=ToString(ErrorStack[0], AFlags);
  if Self.Message.IsEmpty then
    Result:=Format(ErrFmtOsslWithoutMessage, [lTempStr])
  else
    Result:=Format(ErrFmtOsslWithMessage, [Self.Message, lTempStr]);

  if lLineCount < 1 then
    Exit;

  Result:=Result+ErrFmtNestedSectionBegins;
  for i:=1 to lLineCount-1 do
  begin
    lTempStr:=ToString(ErrorStack[i], AFlags);
    Result:=Result+ErrFmtNestedLineBegins+lTempStr+ErrFmtNestedLineEnds;
    if i < lLineCount-1 then
      Result:=Result+ErrFmtNestedNewLine
  end;
  Result:=Result+ErrFmtNestedSectionEnds;
end;

function EOsslCustomError.ToString(const AErrorEntry: TErrorEntry;
  AFlags: TErrorMessageFlags): string;

  function AddWithSpace(ALeft, ARight: string): string;
  begin
    if ALeft.IsEmpty then
      Result:=''
    else
      Result:=ALeft+' ';
    Result:=Result+ARight;
  end;

begin
  Result:='';
  if not AErrorEntry.ErrCode.IsError then
    Exit;
  if emfCode in AFlags then
    Result:=Format(ErrFmtCode, [AErrorEntry.ErrCode]);
  if emfLibName in AFlags then
    Result:=AddWithSpace(Result, Format(ErrFmtLib,
      [GetLibName(AErrorEntry.ErrCode)]));
  if emfFileName in AFlags then
    Result:=AddWithSpace(Result, Format(ErrFmtFile, [AErrorEntry.FileName]));
 if emfLine in AFlags then
    Result:=AddWithSpace(Result, Format(ErrFmtLine, [AErrorEntry.Line]));
 if emfDescript in AFlags then
    Result:=AddWithSpace(Result, Format(ErrFmtDescript, [AErrorEntry.Descript]));
end;

end.
