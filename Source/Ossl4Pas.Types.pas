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

unit Ossl4Pas.Types;

{$INCLUDE 'Ossl4Pas_CompilerDefines.inc'}

interface

uses
{$IFDEF FPC}
  CTypes,
  SysUtils,
  DynLibs,
  {$IFDEF T_WINDOWS}Windows, {$ENDIF}
  {$IFDEF T_POSIX}dl, {$ENDIF}
  SyncObjs,
{$ENDIF}
{$IFDEF DCC}
  System.SysUtils,
  {$IFDEF T_WINDOWS}Winapi.Windows,{$ENDIF}
  {$IFDEF POSIX}Posix.Dlfcn,{$ENDIF}
{$ENDIF}
  Ossl4Pas.CTypes;

const
  cLib3VersionProc = 'OpenSSL_version_num';
  cLib1VersionProc = 'SSLeay';

type
  ///  <summary>Parent class for `Ossl4Pas` exceptions</summary>
  EOsslCustomError = class(Exception);

  /// <summary>
  ///   Represents an OpenSSL version number parsed from the C unsigned long format.
  /// </summary>
  /// <remarks>
  ///   Encapsulates the OpenSSL versioning scheme (MNN00PP0) and provides
  ///   helpers for comparison and string formatting.
  /// </remarks>
  TOsslVersion = record
  public const
    cEmpty = 0;
  private const
    cMajorShift  = 28;
    cMinorShift  = 20;
    cFixShift    = 12;
    cPatchShift  = 4;

    cByteMask    = $FF;
    cStatusMask  = $0F;

  private
    FVersion: culong;

    function GetMajor: cuint8; {$IFDEF INLINE_ON}inline;{$ENDIF}
    function GetMinor: cuint8; {$IFDEF INLINE_ON}inline;{$ENDIF}
    function GetFix: cuint8; {$IFDEF INLINE_ON}inline;{$ENDIF}
    function GetPatch: cuint8; {$IFDEF INLINE_ON}inline;{$ENDIF}
    function GetStatus: cuint8; {$IFDEF INLINE_ON}inline;{$ENDIF}
    function GetIsRelease: boolean; {$IFDEF INLINE_ON}inline;{$ENDIF}
    function GetAsString: string; {$IFDEF INLINE_ON}inline;{$ENDIF}
    function GetIsEmpty: boolean; {$IFDEF INLINE_ON}inline;{$ENDIF}

  public
    /// <summary>
    ///   Initializes a new instance of the TOsslVersion record from a raw integer.
    /// </summary>
    /// <param name="AVersion">
    ///   The raw version number (e.g., from OpenSSL_version_num).
    /// </param>
    constructor Create(AVersion: culong); overload;

    /// <summary>
    ///   Initializes a new instance of the TOsslVersion record from components.
    /// </summary>
    /// <param name="AMajor">The major version number.</param>
    /// <param name="AMinor">The minor version number.</param>
    /// <param name="AFix">The fix level (usually 0 in OpenSSL 3.x).</param>
    /// <param name="APatch">The patch level.</param>
    /// <param name="AStatus">The status tag (default is $F for Release).</param>
    constructor Create(AMajor, AMinor, AFix: cuint8;
      APatch: cuint8 = 0; AStatus: cuint8 = $F); overload;

    /// <summary>
    ///   Implicitly converts a raw culong to TOsslVersion.
    /// </summary>
    class operator Implicit(a: culong): TOsslVersion;
      {$IFDEF INLINE_ON}inline;{$ENDIF}

    /// <summary>
    ///   Implicitly converts TOsslVersion to a raw culong.
    /// </summary>
    class operator Implicit(a: TOsslVersion): culong; inline;
      {$IFDEF INLINE_ON}inline;{$ENDIF}

    /// <summary>
    ///   Strictly compares two TOsslVersion instances.
    /// </summary>
    class operator Equal(a, b: TOsslVersion): boolean;
      {$IFDEF INLINE_ON}inline;{$ENDIF}

    /// <summary>
    ///   Strictly compares two TOsslVersion instances.
    /// </summary>
    class operator NotEqual(a, b: TOsslVersion): boolean;
      {$IFDEF INLINE_ON}inline;{$ENDIF}

    /// <summary>
    ///   Strictly compares two TOsslVersion instances.
    /// </summary>
    class operator GreaterThan(a, b: TOsslVersion): boolean;
      {$IFDEF INLINE_ON}inline;{$ENDIF}


    /// <summary>
    ///   Strictly compares two TOsslVersion instances.
    /// </summary>
    class operator GreaterThanOrEqual(a, b: TOsslVersion): boolean;
      {$IFDEF INLINE_ON}inline;{$ENDIF}

    /// <summary>
    ///   Strictly compares two TOsslVersion instances.
    /// </summary>
    class operator LessThan(a, b: TOsslVersion): boolean;
      {$IFDEF INLINE_ON}inline;{$ENDIF}


    /// <summary>
    ///   Strictly compares two TOsslVersion instances.
    /// </summary>
    class operator LessThanOrEqual(a, b: TOsslVersion): boolean;
      {$IFDEF INLINE_ON}inline;{$ENDIF}

    /// <summary>
    ///   Checks if the provided version is binary compatible with this version.
    /// </summary>
    /// <param name="AVersion">The version to check against.</param>
    /// <returns>True if Major and Minor versions match.</returns>
    function AreCompatible(AVersion: TOsslVersion): boolean; overload;
      {$IFDEF INLINE_ON}inline;{$ENDIF}

    /// <summary>
    ///   Checks if the provided version is binary compatible with this version.
    /// </summary>
    /// <param name="AVersion">The version to check against.</param>
    /// <returns>True if Major and Minor versions match.</returns>
    function AreCompatible(AVersion: culong): boolean; overload;
      {$IFDEF INLINE_ON}inline;{$ENDIF}

    /// <summary>
    ///   The raw integer representation of the version.
    /// </summary>
    property Version: culong read FVersion;

    /// <summary>The Major version component.</summary>
    property Major:   cuint8 read GetMajor;

    /// <summary>The Minor version component.</summary>
    property Minor:   cuint8 read GetMinor;

    /// <summary>The Fix version component (rarely used in 3.x).</summary>
    property Fix:     cuint8 read GetFix;

    /// <summary>The Patch version component.</summary>
    property Patch:   cuint8 read GetPatch;

    /// <summary>The Status tag (0=Dev, $F=Release).</summary>
    property Status:  cuint8 read GetStatus;

    /// <summary>
    ///   True if this version represents a final release (Status = $F).
    /// </summary>
    property IsRelease: boolean read GetIsRelease;

    /// <summary>
    ///   True if this version represents is not set (all zeros).
    /// </summary>
    property IsEmpty: boolean read GetIsEmpty;

    /// <summary>
    ///   Returns the string representation in format "M.Mi.Fx.Pa.S".
    /// </summary>
    property AsString: string read GetAsString;
  end;

 /// <summary>Identifies the specific OpenSSL library (Crypto or SSL).</summary>
  TLibType    = (ltCrypto, ltSsl);

  /// <summary>Set of library types.</summary>
  TLibTypes  = set of TLibType;

  /// <summary>Platform-independent handle to a loaded dynamic library.</summary>
  TLibHandle    = type HMODULE;

  /// <summary>Helper methods for TLibHandle.</summary>
  TLibHandleHelper = record helper for TLibHandle
  public const
    cNilHandle = TLibHandle(0);

  private
    function DoGetProcAddress(const AProcName: string): pointer;
      {$IFDEF INLINE_ON}inline;{$ENDIF}
    function DoGetFileName: string;

  public
    /// <summary>Creates a new LibHandle.</summary>
    constructor Create(AModuleHandle: HMODULE); overload;

    /// <summary>Loads library and returns the loaded library handle.</summary>
    constructor Create(const ALibName: string); overload;

    /// <summary>True if the handle is 0/Nil.</summary>
    function IsEmpty: boolean; {$IFDEF INLINE_ON}inline;{$ENDIF}

    /// <summary>Retrieves the address of an exported function.</summary>
    property ProcAddress[const AProcName: string]: pointer read DoGetProcAddress;

    /// <summary>Retrieves the file name of the loaded module.</summary>
    property FileName: string read DoGetFileName;
  end;

  TLibHandleList   = array[TLibType] of TLibHandle;
  TLibVersionList  = array[TLibType] of TOsslVersion;

  /// <summary>Callback signature for binding function pointers.</summary>
  TBindProc = procedure(const ALibHandle: TLibHandle;
    const AVersion: TOsslVersion);

  /// <summary>Callback signature for unbinding/cleanup.</summary>
  TUnBindProc = procedure;

  /// <summary>
  ///   Stores registration details for a specific library binding.
  /// </summary>
  TBindParam = record
  private
    FLibType:     TLibType;
    FBinded:      boolean;
    FBindProc:    TBindProc;
    FUnbindProc:  TUnBindProc;
  public
    constructor Create(ALIbType: TLibType; ABindProc: TBindProc;
      AUnbindProc: TUnBindProc);

    /// <summary>Executes the binding callback.</summary>
    procedure DoBind(AHandle: TLibHandle; const AVersion: TOsslVersion);
        {$IFDEF INLINE_ON}inline;{$ENDIF}

    /// <summary>Executes the unbinding callback.</summary>
    procedure DoUnBind;
      {$IFDEF INLINE_ON}inline;{$ENDIF}
    property LibType:     TLibType read FLibType;
    property BindProc:    TBindProc read FBindProc;
    property UnbindProc:  TUnBindProc read FUnbindProc;
    property IsBinded:    boolean read FBinded;
  end;


implementation

uses
  Ossl4Pas.ResStrings;

{ TOsslVersion }

constructor TOsslVersion.Create(AVersion: culong);
begin
  FVersion:=AVersion;
end;

constructor TOsslVersion.Create(AMajor, AMinor, AFix, APatch, AStatus: cuint8);
begin
  FVersion:=(culong(AMajor)   shl cMajorShift) or
              (culong(AMinor)   shl cMinorShift) or
              (culong(AFix)     shl cFixShift)   or
              (culong(APatch)   shl cPatchShift) or
              (culong(AStatus)  and cStatusMask);
end;

function TOsslVersion.GetMajor: cuint8;
begin
  Result:=(FVersion shr cMajorShift) and cByteMask;
end;

function TOsslVersion.GetMinor: cuint8;
begin
  Result:=(FVersion shr cMinorShift) and cByteMask;
end;

function TOsslVersion.GetFix: cuint8;
begin
  Result:=(FVersion shr cFixShift) and cByteMask;
end;

function TOsslVersion.GetPatch: cuint8;
begin
  Result:=(FVersion shr cPatchShift) and cByteMask;
end;

function TOsslVersion.GetStatus: cuint8;
begin
  Result:=FVersion and cStatusMask;
end;

function TOsslVersion.GetIsRelease: boolean;
begin
  Result:=GetStatus = cStatusMask;
end;

function TOsslVersion.GetIsEmpty: boolean;
begin
  Result:=FVersion = cEmpty;
end;

function TOsslVersion.GetAsString: string;
begin
  Result:=Format(resVersionShort,
    [Major, Minor, Fix, Patch, Status]);
end;

class operator TOsslVersion.Implicit(a: culong): TOsslVersion;
begin
  Result.FVersion:=a;
end;

class operator TOsslVersion.Implicit(a: TOsslVersion): culong;
begin
  Result:=a.FVersion;
end;

class operator TOsslVersion.Equal(a, b: TOsslVersion): boolean;
begin
  Result:=a.FVersion = b.FVersion;
end;

class operator TOsslVersion.NotEqual(a, b: TOsslVersion): boolean;
begin
  Result:=a.FVersion <> b.FVersion;
end;

class operator TOsslVersion.GreaterThan(a, b: TOsslVersion): boolean;
begin
  Result:=a.FVersion > b.FVersion;
end;

class operator TOsslVersion.GreaterThanOrEqual(a, b: TOsslVersion): boolean;
begin
  Result:=a.FVersion >= b.FVersion;
end;

class operator TOsslVersion.LessThan(a, b: TOsslVersion): boolean;
begin
  Result:=a.FVersion < b.FVersion;
end;

class operator TOsslVersion.LessThanOrEqual(a, b: TOsslVersion): boolean;
begin
  Result:=a.FVersion <= b.FVersion;
end;

function TOsslVersion.AreCompatible(AVersion: culong): boolean;
begin
  Result:=AreCompatible(TOsslVersion.Create(AVersion));
end;

function TOsslVersion.AreCompatible(AVersion: TOsslVersion): boolean;
begin
  Result:=(Self.Major = AVersion.Major) and (Self.Minor = AVersion.Minor);
end;

{ TLibHandleHelper }

constructor TLibHandleHelper.Create(AModuleHandle: HMODULE);
begin
  Self:=AModuleHandle;
end;

constructor TLibHandleHelper.Create(
  const ALibName: string);

  const
  {$IFDEF T_WINDOWS}
    cErrMode = SEM_FAILCRITICALERRORS;
  {$ELSE}
    cErrMode = 0;
  {$ENDIF}
begin
  {$IFDEF DCC}
  Self:=SafeLoadLibrary(ALibName, cErrMode);
  {$ENDIF}
  {$IFDEF FPC}
  Self:=SafeLoadLibrary(ALibName);
  {$ENDIF}
end;

function TLibHandleHelper.IsEmpty: boolean;
begin
  Result:=Self = cNilHandle;
end;

function TLibHandleHelper.DoGetProcAddress(
  const AProcName: string): pointer;
begin
  Result:=nil;
  if Self = 0 then
    Exit;
  Result:=GetProcAddress(Self, PChar(AProcName));
end;

function TLibHandleHelper.DoGetFileName: string;
{$IFDEF T_WINDOWS}
const
  cStartBufLen = MAX_PATH;

var
  lBufLen: cardinal;
  lLen: cardinal;

begin
  lBufLen:=cStartBufLen;
  repeat
    SetLength(Result, lBufLen);
    lLen:=GetModuleFileName(THandle(Self), PChar(Result), lBufLen);
    if lLen < lBufLen then
    begin
      SetLength(Result, lLen);
      break;
    end;
    lBufLen:=lBufLen*2;
  until lBufLen >= $F777; //32 Kb
end;
{$ELSE}
var
  lInfo: Dl_info;
  lSymAddr: pointer;
  lLibPtr: NativeUInt;
begin
  Result:='';
  if Self = cNilHandle then Exit;

  // Prepare Handle for POSIX API
  // FPC 'dl' unit expects Pointer. Delphi 'Posix.Dlfcn' expects THandle/Pointer.
  lLibPtr:=NativeUInt(Self);

  // 1. Find a known symbol inside the library (OpenSSL 3.x / 1.1)
  lSymAddr:=dlsym(lLibPtr, cLib3VersionProc);

  // Fallback for older/different builds
  if not Assigned(lSymAddr) then
    lSymAddr:=dlsym(lLibPtr, cLib1VersionProc);

  // 2. Use dladdr to find the file containing that symbol
  if Assigned(lSymAddr) and (dladdr(NativeUInt(lSymAddr), lInfo) <> 0) then
  begin
    // dli_fname contains the absolute path
    Result:=string(lInfo.dli_fname);
  end;
end;
{$ENDIF}

{ TBindParam }

constructor TBindParam.Create(ALIbType: TLibType;
  ABindProc: TBindProc; AUnbindProc: TUnBindProc);
begin
  Assert(Assigned(ABindProc), 'At least ABindProc should not be ''nil''.');
  FLibType:=ALIbType;
  FBindProc:=ABindProc;
  FUnbindProc:=AUnbindProc;
end;

procedure TBindParam.DoBind(AHandle: TLibHandle;
  const AVersion: TOsslVersion);
begin
  FBinded:=True;
  FBindProc(AHandle, AVersion);
end;

procedure TBindParam.DoUnBind;
begin
  if IsBinded and Assigned(FUnbindProc) then
  try
    FUnbindProc;
    FBinded:=False;
  except
  // suppress exceptions.
  // we can't do anything at this point to handle it
  // however, we must try to UnBind all remaining bindings.
  end;
end;

{$IFDEF T_LINUX}
// We have to export __dso_handle in Linux if OpenSSL static library
// built without 'no-dso' flag.
procedure  __dso_handle; cdecl;
begin
end;

exports
  __dso_handle;
{$ENDIF}



end.
