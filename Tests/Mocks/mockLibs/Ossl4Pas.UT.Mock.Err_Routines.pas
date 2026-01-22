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

unit Ossl4Pas.UT.Mock.Err_Routines;

interface

uses
  System.AnsiStrings,
  System.SysUtils,
  System.Generics.Collections,
  Ossl4Pas.CTypes,
  Ossl4Pas.UT.Consts;


// -----------------------------------------------------------------------------
// CONTROL FUNCTION (Called by Unit Test Setup)
// -----------------------------------------------------------------------------
procedure Mock_Err_Push(AErrCode: culong; AFileName, AFuncName, AData: PAnsiChar;
  ALine, AFlags: cint); cdecl;
procedure Mock_Err_Clear; cdecl;

// -----------------------------------------------------------------------------
// OPENSSL EXPORTS (Simulations)
// -----------------------------------------------------------------------------

function ERR_get_error: culong; cdecl;
function ERR_peek_error: culong; cdecl;
function ERR_peek_last_error: culong; cdecl;
procedure ERR_clear_error; cdecl;

function ERR_error_string(e: culong; buf: PAnsiChar): PAnsiChar; cdecl;
procedure ERR_error_string_n(e: culong; buf: PAnsiChar; len: size_t); cdecl;

function ERR_lib_error_string(e: culong): PAnsiChar; cdecl;
function ERR_reason_error_string(e: culong): PAnsiChar; cdecl;

function ERR_peek_error_func(func: PPAnsiChar): culong; cdecl;
function ERR_peek_last_error_func(func: PPAnsiChar): culong; cdecl;

function ERR_peek_error_data(data: PPAnsiChar; flags: Pcint): culong; cdecl;
function ERR_peek_last_error_data(data: PPAnsiChar; flags: Pcint): culong; cdecl;

function ERR_get_error_all(file_: PPAnsiChar; line: Pcint; func: PPAnsiChar;
  data: PPAnsiChar; flags: Pcint): culong; cdecl;
function ERR_peek_error_all(file_: PPAnsiChar; line: Pcint; func: PPAnsiChar;
  data: PPAnsiChar; flags: Pcint): culong; cdecl;
function ERR_peek_last_error_all(file_: PPAnsiChar; line: Pcint; func: PPAnsiChar;
  data: PPAnsiChar; flags: Pcint): culong; cdecl;

// -----------------------------------------------------------------------------
// Mock underhood classes (Simulations)
// -----------------------------------------------------------------------------
type
  TOsslErrorStack = class
  public type
    TErrEntry = record
      ErrCode: culong;
      FileName: AnsiString;
      FuncName: AnsiString;
      Data: AnsiString;
      Line: integer;
      Flags: integer;
    end;

    TErrStack = TList<TErrEntry>;

  private
    FStack: TErrStack;
    FHistory: TErrStack;

    function GetCount: cardinal;
    function GetIsEmpty: boolean;

  public
    constructor Create;
    destructor Destroy; override;
    function PushEntry(const AEntry: TErrEntry): boolean;
    function PopEntry(var AEntry: TErrEntry): boolean;
    function PeekEntry(var AEntry: TErrEntry): boolean;
    function PeekLastEntry(var AEntry: TErrEntry): boolean;
    procedure Clear;

    property Count: cardinal read GetCount;
    property IsEmpty: boolean read GetIsEmpty;
  end;

  TOsslSingleErrorStack = class(TOsslErrorStack)
  public const
    cDefaultErrorStackSize = 32;

  private class var
    FInstance: TOsslErrorStack;

    class function GetInstance: TOsslErrorStack; overload; static;
    class function GetInitialized: boolean; static;

  public
    class destructor Destroy;
    class procedure Reset;

    class Property IsInitialized: boolean read GetInitialized;
    class property Instance:TOsslErrorStack read GetInstance;
  end;

implementation

uses
  System.SyncObjs;

procedure Mock_Err_Push(AErrCode: culong; AFileName, AFuncName, AData: PAnsiChar;
  ALine, AFlags: cint); cdecl;
begin
  var lEntry: TOsslErrorStack.TErrEntry;
  with lEntry do
  begin
    ErrCode:=AErrCode;
    FileName:=AnsiString(AFileName);
    FuncName:=AnsiString(AFuncName);
    Data:=AnsiString(AData);
    Line:=ALine;
    Flags:=AFlags;
  end;
  TOsslSingleErrorStack.Instance.PushEntry(lEntry);
end;

procedure Mock_Err_Clear; cdecl;
begin
  TOsslSingleErrorStack.Instance.Clear;
end;


function ERR_get_error: culong; cdecl;
begin
  var lEntry: TOsslErrorStack.TErrEntry;
  if TOsslSingleErrorStack.Instance.PopEntry(lEntry) then
    Result:=lEntry.ErrCode
  else
    Result:=0;
end;

function ERR_peek_error: culong; cdecl;
begin
  var lEntry: TOsslErrorStack.TErrEntry;
  if TOsslSingleErrorStack.Instance.PeekEntry(lEntry) then
    Result:=lEntry.ErrCode
  else
    Result:=0;
end;

function ERR_peek_last_error: culong; cdecl;
begin
  var lEntry: TOsslErrorStack.TErrEntry;
  if TOsslSingleErrorStack.Instance.PeekLastEntry(lEntry) then
    Result:=lEntry.ErrCode
  else
    Result:=0;
end;

procedure ERR_clear_error; cdecl;
begin
  TOsslSingleErrorStack.Instance.Clear;
end;

function ERR_error_string(e: culong; buf: PAnsiChar): PAnsiChar; cdecl;
begin
  if not Assigned(buf) then
    Exit(nil);

  Result:=buf;
  FillChar(buf^, 256, #0);
  var lStr:=System.AnsiStrings.Format('Error: [0x%8x].', [e]);
  Move(PAnsiChar(lStr)^, buf^, Length(lStr));
end;

procedure ERR_error_string_n(e: culong; buf: PAnsiChar; len: size_t); cdecl;
begin
  if not Assigned(buf) then
    Exit;

  var lStr:=System.AnsiStrings.Format('Error: [0x%8x].', [e]);
  var lPStr:=PAnsiChar(lStr);
  if Length(lStr) < (len-1) then
    len:=Length(lStr);
  Move(PAnsiChar(lStr)^, buf^, len-1);
  lPStr[Len]:=#0;
end;

function ERR_lib_error_string(e: culong): PAnsiChar; cdecl;
begin
  var lLibId:=(e shr ERR_LIB_OFFSET) and ERR_LIB_MASK;
  case lLibId of
  ERR_LIB_NONE..ERR_LIB_HTTP:
    Result:=cErrLibNames[lLibId];
  ERR_LIB_USER:
    Result:=cErrLibNameUser;
  else
    Result:='';
  end;
end;

function ERR_reason_error_string(e: culong): PAnsiChar; cdecl;
begin
  Result:=cErrReasonConst;
end;

function ERR_peek_error_func(func: PPAnsiChar): culong; cdecl;
begin
  var lEntry: TOsslErrorStack.TErrEntry;
  if TOsslSingleErrorStack.Instance.PeekEntry(lEntry) then
  begin
    if Assigned(func) then
      func^:=PAnsiChar(lEntry.FuncName);
    Result:=lEntry.ErrCode
  end
  else
  begin
    if Assigned(func) then
      func^:=nil;
    Result:=0;
  end;
end;

function ERR_peek_last_error_func(func: PPAnsiChar): culong; cdecl;
begin
  var lEntry: TOsslErrorStack.TErrEntry;
  if TOsslSingleErrorStack.Instance.PeekLastEntry(lEntry) then
  begin
    if Assigned(func) then
      func^:=PAnsiChar(lEntry.FuncName);
    Result:=lEntry.ErrCode
  end
  else
  begin
    if Assigned(func) then
      func^:=nil;
    Result:=0;
  end;
end;

function ERR_peek_error_data(data: PPAnsiChar; flags: Pcint): culong; cdecl;
begin
  var lEntry: TOsslErrorStack.TErrEntry;
  if TOsslSingleErrorStack.Instance.PeekEntry(lEntry) then
  begin
    if Assigned(data) then
      data^:=PAnsiChar(lEntry.Data);
    if Assigned(flags) then
      flags^:=ERR_TXT_STRING;
    Result:=lEntry.ErrCode
  end
  else
  begin
    if Assigned(data) then
      data^:=nil;
    if Assigned(flags) then
      flags^:=0;
    Result:=0;
  end;
end;

function ERR_peek_last_error_data(data: PPAnsiChar; flags: Pcint): culong; cdecl;
begin
  var lEntry: TOsslErrorStack.TErrEntry;
  if TOsslSingleErrorStack.Instance.PeekLastEntry(lEntry) then
  begin
    if Assigned(data) then
      data^:=PAnsiChar(lEntry.Data);
    if Assigned(flags) then
      flags^:=ERR_TXT_STRING;
    Result:=lEntry.ErrCode
  end
  else
  begin
    if Assigned(data) then
      data^:=nil;
    if Assigned(flags) then
      flags^:=0;
    Result:=0;
  end;
end;

function ERR_get_error_all(file_: PPAnsiChar; line: Pcint; func: PPAnsiChar;
  data: PPAnsiChar; flags: Pcint): culong; cdecl;
begin
  var lEntry: TOsslErrorStack.TErrEntry;
  if TOsslSingleErrorStack.Instance.PopEntry(lEntry) then
  begin
    if Assigned(file_) then
      file_^:=PAnsiChar(lEntry.FileName);
    if Assigned(line) then
      line^:=lEntry.Line;
    if Assigned(func) then
      func^:=PAnsiChar(lEntry.FuncName);
    if Assigned(data) then
      data^:=PAnsiChar(lEntry.Data);
    if Assigned(flags) then
      flags^:=ERR_TXT_STRING;
    Result:=lEntry.ErrCode
  end
  else
  begin
    if Assigned(file_) then
      file_^:=nil;
    if Assigned(line) then
      line^:=0;
    if Assigned(func) then
      func^:=nil;
    if Assigned(data) then
      data^:=nil;
    if Assigned(flags) then
      flags^:=0;
    Result:=0;
  end;
end;

function ERR_peek_error_all(file_: PPAnsiChar; line: Pcint; func: PPAnsiChar;
  data: PPAnsiChar; flags: Pcint): culong; cdecl;
begin
  var lEntry: TOsslErrorStack.TErrEntry;
  if TOsslSingleErrorStack.Instance.PeekEntry(lEntry) then
  begin
    if Assigned(file_) then
      file_^:=PAnsiChar(lEntry.FileName);
    if Assigned(line) then
      line^:=lEntry.Line;
    if Assigned(func) then
      func^:=PAnsiChar(lEntry.FuncName);
    if Assigned(data) then
      data^:=PAnsiChar(lEntry.Data);
    if Assigned(flags) then
      flags^:=ERR_TXT_STRING;
    Result:=lEntry.ErrCode
  end
  else
  begin
    if Assigned(file_) then
      file_^:=nil;
    if Assigned(line) then
      line^:=0;
    if Assigned(func) then
      func^:=nil;
    if Assigned(data) then
      data^:=nil;
    if Assigned(flags) then
      flags^:=0;
    Result:=0;
  end;
end;

function ERR_peek_last_error_all(file_: PPAnsiChar; line: Pcint; func: PPAnsiChar;
  data: PPAnsiChar; flags: Pcint): culong; cdecl;
begin
  var lEntry: TOsslErrorStack.TErrEntry;
  if TOsslSingleErrorStack.Instance.PeekLastEntry(lEntry) then
  begin
    if Assigned(file_) then
      file_^:=PAnsiChar(lEntry.FileName);
    if Assigned(line) then
      line^:=lEntry.Line;
    if Assigned(func) then
      func^:=PAnsiChar(lEntry.FuncName);
    if Assigned(data) then
      data^:=PAnsiChar(lEntry.Data);
    if Assigned(flags) then
      flags^:=ERR_TXT_STRING;
    Result:=lEntry.ErrCode
  end
  else
  begin
    if Assigned(file_) then
      file_^:=nil;
    if Assigned(line) then
      line^:=0;
    if Assigned(func) then
      func^:=nil;
    if Assigned(data) then
      data^:=nil;
    if Assigned(flags) then
      flags^:=0;
    Result:=0;
  end;
end;

{ TOsslErrorStack }

constructor TOsslErrorStack.Create;
begin
  FStack:=TErrStack.Create;
  FHistory:=TErrStack.Create;
end;

destructor TOsslErrorStack.Destroy;
begin
  FreeAndNil(FHistory);
  FreeAndNil(FStack);
end;

function TOsslErrorStack.GetCount: cardinal;
begin
  Result:=FStack.Count;
end;

function TOsslErrorStack.GetIsEmpty: boolean;
begin
  Result:=Count = 0;
end;

function TOsslErrorStack.PushEntry(const AEntry: TErrEntry): boolean;
begin
  FStack.Add(AEntry);
  Result:=True;
end;

function TOsslErrorStack.PopEntry(var AEntry: TErrEntry): boolean;
begin
  Result:=PeekEntry(AEntry);
  if not Result then
    Exit;

  FHistory.Add(AEntry);
  FStack.Delete(0);
end;

function TOsslErrorStack.PeekEntry(var AEntry: TErrEntry): boolean;
begin
  if IsEmpty then
    Exit(False);
  AEntry:=FStack[0];
  Result:=True;
end;

function TOsslErrorStack.PeekLastEntry(var AEntry: TErrEntry): boolean;
begin
  if IsEmpty then
    Exit(False);
  AEntry:=FStack[Count-1];
  Result:=True;
end;

procedure TOsslErrorStack.Clear;
begin
  FHistory.Clear;
  FStack.Clear;
end;

{ TOsslSingleErrorStack }

class destructor TOsslSingleErrorStack.Destroy;
begin
  Reset;
end;

class function TOsslSingleErrorStack.GetInitialized: boolean;
begin
  Result:=Assigned(FInstance);
end;

class function TOsslSingleErrorStack.GetInstance: TOsslErrorStack;
begin
  if not Assigned(FInstance) then
    FInstance:=TOsslErrorStack.Create;
  Result:=FInstance;
end;

class procedure TOsslSingleErrorStack.Reset;
begin
  FreeAndNil(FInstance);
end;

end.
