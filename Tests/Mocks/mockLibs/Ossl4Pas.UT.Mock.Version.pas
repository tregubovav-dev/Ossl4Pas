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

unit Ossl4Pas.UT.Mock.Version;

interface

uses
  System.SysUtils,
  System.Classes,
  System.IOUtils,
  {$IF Defined(MSWINDOWS)}
  Winapi.Windows,
  {$ELSE}
  Posix.Dlfcn,
  {$ENDIF }
  Ossl4pas.Types,
  Ossl4pas.CTypes;


  function OpenSSL_version_num: culong; cdecl;
  function SSLeay: culong; cdecl;
  function DummyStr: PChar; cdecl;
  function DummyAdd(AValue, AAddition: cint): cint; cdecl;
  function IsLibName(var ALibName: PChar): boolean; cdecl;

var
  GLibPath: string = '';

implementation

// Defaults to OpenSSL 3.0.0 Release if no config file found
const
  cDefaultVersion: culong = $3000000F;

{$IF not Defined(VER3600) }
type
  TFIleHelper = record helper for TFile
    class function GetSize(AFileName: string): Int64; static;
  end;

class function TFIleHelper.GetSize(AFileName: string): Int64;
begin
  var lStream: TFileStream:=nil;
  try
    lStream:=TFileStream.Create(AFileName, fmOpenRead);
    Result:=lStream.Size;
  finally
    lStream.Free;
  end;
end;
{$ENDIF}


function LoadVersion: culong;
var
  lPath: string;
  lVerStr: string;
  lVer: Int64;

begin
  Result:=cDefaultVersion;
  if Length(GLibPath) = 0 then
    Exit; // Leave default version

  lPath:=TPath.ChangeExtension(GLibPath, 'ver');
  if TFile.GetSize(lPath) > 64 then // Restrict reading size.
    Exit; //

  lVerStr:=TFile.ReadAllText(lPath).Trim;
  if not Int64.TryParse(lVerStr, lVer) then
    Exit;

  if (lVer >= 0) and (lVer <= $FFFFFFFF) then
    Result:=lVer;
end;

function OpenSSL_version_num: culong; cdecl;
begin
  Result:=LoadVersion;
end;

function SSLeay: culong; cdecl;
begin
  Result:=LoadVersion;
end;

const
  cDummyStr = 'Dummy String';

function DummyStr: PChar; cdecl;
begin
  Result:=PChar(cDummyStr);
end;

function DummyAdd(AValue, AAddition: cint): cint; cdecl;
begin
  Result:=AValue+AAddition;
end;


function IsLibName(var ALibName: PChar): boolean; cdecl;
var
  lDirName, lFileName: string;
  lLibName: string;

begin
  try
    lLibName:=string(ALibName);
    lDirName:=TPath.GetDirectoryName(lLibName);
    lFileName:=TPath.GetFileName(lLibName);
    {$IFDEF MSWINDOWS}
    Result:=SameText(TPath.GetFileName(GLibPath), lFileName);
    if not lDirName.IsEmpty then
      Result:=Result and SameText(TPath.GetDirectoryName(GLibPath), lDirName);
    {$ELSE}
    Result:=SameStr(TPath.GetFileName(GLibPath), lFileName);
    if not lDirName.IsEmpty then
      Result:=Result and SameStr(TPath.GetDirectoryName(GLibPath), lDirName);
    {$ENDIF}
    ALibName:=PChar(GLibPath);

  except
    Result:=False;
    ALibName:=nil;
  end;
end;

procedure CheckLibPath;
var
  lPath: string;

begin
  SetLength(lPath, MAX_PATH);
  SetLength(lPath,
    GetModuleFileName(HInstance, PChar(lPath), MAX_PATH));
  if not lPath.IsEmpty then
    GLibPath:=lPath;
end;

{ TFIleHelper }

initialization
  CheckLibPath;

end.
