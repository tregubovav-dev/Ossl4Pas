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

// This unit is designed to emulate the part of TPath, TDirectory and TFile types
// in Free Pascal version below 3.2.4

unit fpc.stub.ioutils;

{$INCLUDE 'Ossl4Pas_CompilerDefines.inc'}

interface

uses
  Classes,
  SysUtils,
  Types;

type

  { TPath }

  TPath = record
  const
    cUNCPfx     = '\\?\UNC\\';
    cExtenedPfx = '\\?\';
    cDrivePfx   = ':\';

  private class var
    FAltDirectorySeparatorChar: char;
    FDirectorySeparatorChar: char;
    FExtensionSeparatorChar: char;
    FPathSeparator: char;
    FVolumeSeparatorChar: char;

  private
    class function StartWithUNC(const aPath: string): boolean; static;
    class function StartWithExtended(const aPath: string): boolean; static;
    class function StartWithDrive(const aPath: string): boolean; static;
  public
    class constructor Create;

    class function GetFullPath(const aPath: string): string; static;
    class function GetDirectoryName(FileName: string): string; static;
    class function HasValidPathChars(const aPath: string;
      const UseWildcards: Boolean): Boolean; static;
    class function Combine(const Path1, Path2: string;
          const ValidateParams : Boolean = True): string; static;

    class property ExtensionSeparatorChar: char read FExtensionSeparatorChar;
    class property AltDirectorySeparatorChar: char read FAltDirectorySeparatorChar;
    class property DirectorySeparatorChar: char read FDirectorySeparatorChar;
    class property PathSeparator: char read FPathSeparator;
    class property VolumeSeparatorChar: char read FVolumeSeparatorChar;
  end;

  { TDirectory }

  TDirectory = record
    class function GetCurrentDirectory: string; static;
  end;

  { TFile }

  TFile = record
    class function Exists(const aPath: string; FollowLink: boolean = True): boolean; static;
  end;

  EInOutArgumentException = class(Exception);

resourcestring
  resErrInvalidCharsInPath = 'Invalid characters in the path "%s".';
  resErrRootedPath         = 'Unable to combine paths when 2nd path starts '+
                             'with drive or extended prefix: "%s".';

implementation

{ TPath }

class constructor TPath.Create;
var
  lChr: char;
begin
  FAltDirectorySeparatorChar := #0;
  FExtensionSeparatorChar    := System.ExtensionSeparator;
  FDirectorySeparatorChar    := System.DirectorySeparator;
  FPathSeparator             := System.PathSeparator;
  FVolumeSeparatorChar       := System.DriveSeparator;

  for lChr in AllowDirectorySeparators do
    if (lChr <> System.DirectorySeparator) and (FAltDirectorySeparatorChar = #0) then
      FAltDirectorySeparatorChar := lChr;
end;

class function TPath.StartWithUNC(const aPath: string): boolean;
begin
  Result := aPath.StartsWith(cUNCPfx, True);
end;

class function TPath.StartWithExtended(const aPath: string): boolean;
begin
  Result := aPath.StartsWith(cExtenedPfx, True);
end;

class function TPath.StartWithDrive(const aPath: string): boolean;
begin
  Result := aPath.Length >= 3;
  Result := Result and (CharInSet(aPath[1], ['a'..'z', 'A'..'Z']))
                   and (aPath[2] = cDrivePfx[1])
                   and (aPath[3] = cDrivePfx[2]);
end;

class function TPath.GetFullPath(const aPath: string): string;
begin
  Result := ExpandFileName(aPath);
end;

class function TPath.GetDirectoryName(FileName: string): string;
begin
  Result := ExcludeTrailingPathDelimiter(ExtractFileDir(FileName));
end;

class function TPath.HasValidPathChars(const aPath: string;
  const UseWildcards: Boolean): Boolean;
var
  i, lStart, lLen: integer;
begin
  lLen := aPath.Length;
  if lLen = 0 then Exit(True);

  Result := False;

  {$IFDEF T_WINDOWS}
  if StartWithUNC(aPath) then
    lStart := cUNCPfx.Length + 1
  else if StartWithExtended(aPath) then
    lStart := cExtenedPfx.Length + 1
  else
  {$ENDIF}
    lStart := 1;

  for i := lStart to lLen do
  begin
    if (not UseWildcards) and CharInSet(aPath[i], ['?','*']) then
       Exit;

    {$IFDEF T_WINDOWS}
    if CharInSet(aPath[i], [#0..#$20, '"', '<', '>', '|']) then
       Exit;
    {$ELSE}
    if CharInSet(aPath[i], [#0..#$20]) then Exit;
    {$ENDIF}
  end;
  Result := True;
end;

class function TPath.Combine(const Path1, Path2: string;
  const ValidateParams: Boolean): string;
var
  lPath2: string;
begin
  if Path2.IsEmpty then Exit(Path1);
  if Path1.IsEmpty then Exit(Path2);

  if ValidateParams then
  begin
    if not TPath.HasValidPathChars(Path1, False) then
       raise EInOutArgumentException.CreateFmt(resErrInvalidCharsInPath, [Path1]);
    if not TPath.HasValidPathChars(Path2, False) then
       raise EInOutArgumentException.CreateFmt(resErrInvalidCharsInPath, [Path2]);
  end;

  {$IFDEF T_WINDOWS}
  if TPath.StartWithDrive(Path2) or TPath.StartWithExtended(Path2) or
     TPath.StartWithUNC(Path2) then
    raise EInOutArgumentException.CreateFmt(resErrRootedPath, [Path2]);
  {$ENDIF}

  if CharInSet(Path2[1], AllowDirectorySeparators) then
    lPath2 := Copy(Path2, 2)
  else
    lPath2 := Path2;

  if CharInSet(Path1[Path1.Length], AllowDirectorySeparators) then
    Result := Path1
  else
    Result := Path1 + TPath.DirectorySeparatorChar;

  Result := Result + lPath2;
end;

{ TDirectory }

class function TDirectory.GetCurrentDirectory: string;
begin
  Result := GetCurrentDir;
end;

{ TFile }

class function TFile.Exists(const aPath: string; FollowLink: Boolean): Boolean;
begin
  Result := SysUtils.FileExists(aPath, FollowLink);
end;

end.
