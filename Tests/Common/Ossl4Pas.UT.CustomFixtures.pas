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

unit Ossl4Pas.UT.CustomFixtures;

interface

uses
  System.SysUtils,
  System.SyncObjs,
  DUnitX.TestFramework,
  Ossl4Pas.CTypes,
  Ossl4Pas.Types,
  Ossl4Pas.Loader,
  Ossl4Pas.UT.Utils,
  Ossl4Pas.Mock.Loader;

type
  TDelphiPlatform = (dpUnknown, dpWIN32, dpWIN64, dpWINARM64, dpANDROID32,
    dpANDROID64, dpLINUX64, dpOSX64, dpOSXARM64, dpIOS64);
  TDelphiPlatforms = set of TDelphiPlatform;

  TDelphiPlatformHelper = record helper for TDelphiPlatform
  public
    class function RunningPlatform: TDelphiPlatform; static;
  end;

  TDelphiPlatformsHelper = record helper for TDelphiPlatforms
  public const
    cAllPlatforms = [Low(TDelphiPlatform)..High(TDelphiPlatform)];

  public
    function InPlatforms: boolean;
  end;

  TCustomFixture = class
  protected
    procedure LoadStrings; virtual;
  public
    [SetupFixture]
    procedure SetupFixture;
  end;

  TCustomLoaderFixture = class(TCustomFixture)
  protected
    class procedure Reset; virtual;
  public
    [Setup]
    procedure Setup;

    [TearDown]
    procedure TearDown;
  end;

  TBindCountLoaderFixture = class(TCustomLoaderFixture)
  private class var
    FBindCallCount: integer;
  protected
    class procedure Reset; override;
    class procedure ResetCallCount;
  public
    class function AddBindCall: integer; static;
    class function AddUnBindCall: integer; static;
  end;

  TMockLibHandler = class
  private
    FKeepWorkDir: boolean;
    FWorkdirCreated: boolean;
    function GetWorkDir: string;

  public
    procedure CopyFile(ASrc, ADst: string);
    procedure DeleteFile(ASrc: string);
    procedure WriteVersion(ADst: string; const AVersion: TOsslVersion);

    procedure SetupMock(ALibName: string; const AVersion: TOsslVersion); overload;
    procedure SetupMock(ALibType: TLibType;
      const AVersion: TOsslVersion); overload;
    procedure SetupMocks(ALibTypes: TLibTypes;
      const AVersion: TOsslVersion);
    procedure SetupAllMocks(AVersion: TOsslVersion);

    procedure CleanUpMock(ALibName: string); overload;
    procedure CleanUpMock(ALibType: TLibType); overload;
    procedure CleanUpMocks(ALibTypes: TLibTypes);
    procedure CleanUpAllMocks; virtual;

    procedure LoaderUnload(ALibType: TLibType); overload;
    procedure LoaderUnload(ALibTypes: TLibTypes); overload;
    procedure LoaderUnloadAll; overload;

    procedure CheckWorkDir;
    procedure CleanWorkDir;

    function CheckLibTypes(ALibTypes: TLibTypes): TLibTypes;

    property WorkDir: string read GetWorkDir;
    property KeepWorkDir: boolean read FKeepWorkDir write FKeepWorkDir;
  end;

  TCustomMockLoadFixture = class(TBindCountLoaderFixture)
  private
    FMockLibHandler: TMockLibHandler;

  protected
    property MockLibHandler: TMocklibHandler read FMockLibHandler;

  public
    destructor Destroy; override;

    [SetupFixture]
    procedure SetupFixture;
  end;

  TMockLoadSingleTestFixture = class(TCustomMockLoadFixture)
  public
    [Setup]
    procedure Setup;

    [TearDown]
    procedure TearDown;
  end;

implementation

uses
  System.Classes,
  System.IOUtils,
  Ossl4Pas.ResStrings;

{ TCustomFixture }

procedure TCustomFixture.SetupFixture;
var
  lStr: string;

begin
  LoadStrings;
end;

procedure TCustomFixture.LoadStrings;
var
  lStr: string;

begin
  // preloads resourcestrings to avoid
  // false positive memory leaks reports

  // Ossl4Pas.Loader strings
  lStr := resVersionShort;

  // EOsslLoader strings
  lStr := resLoaderNotSet;
  lStr := resLoaderUnsupported;
  lStr := resNoVersionFound;
  lStr := resLoadLibVersionIncompatible;
  lStr := resLoadLibNotFound;
  lStr := resLoadLibVersionsIncompatible;
  lStr := resLoadBindLibNotLoaded;

  // Ossl4Pas.Api.Err strings
  lStr := resErrRoutineNotBound;

  // Ossl4Pas.Err - EOsslCustomError.TErrorEntry strings
  lStr := resErrFmtSpace;
  lStr := resErrFmtComma;
  lStr := resErrFmtCode;
  lStr := resErrFmtLib;
  lStr := resErrFmtFile;
  lStr := resErrFmtLine;
  lStr := resErrFmtFunc;
  lStr := resErrFmtDescript;

  // EOsslCustomError strings
  lStr := resErrUnknownError;
  lStr := resErrFmtOsslWithMessage;
  lStr := resErrFmtOsslWithoutMessage;
  lStr := resErrFmtNestedSectionBegins;
  lStr := resErrFmtNestedSectionEnds;
  lStr := resErrFmtNestedLineBegins;
  lStr := resErrFmtNestedLineEnds;
  lStr := resErrFmtNestedNewLine;

  lStr:='';
end;

{ TCustomLoaderFixture }

class procedure TCustomLoaderFixture.Reset;
begin
  TBaseMockLoader.ResetSingleton;
end;

procedure TCustomLoaderFixture.Setup;
begin
  Reset;
end;

procedure TCustomLoaderFixture.TearDown;
begin
  Reset;
end;

{ TBindCountLoaderFixture }

class function TBindCountLoaderFixture.AddBindCall: integer;
begin
  Result:=TInterlocked.Increment(FBindCallCount);
end;

class function TBindCountLoaderFixture.AddUnBindCall: integer;
begin
  Result:=TInterlocked.Decrement(FBindCallCount);
end;

class procedure TBindCountLoaderFixture.ResetCallCount;
begin
  TInterlocked.Exchange(FBindCallCount, 0);
end;

class procedure TBindCountLoaderFixture.Reset;
begin
  ResetCallCount;
  inherited;
end;

{ TMockLibHandler }

function TMockLibHandler.GetWorkDir: string;
begin
  Result:=TMockLibConfig.MockWorkDir;
end;

procedure TMockLibHandler.CopyFile(ASrc, ADst: string);
begin
  var lSrc: TStream:=nil;
  var lDst: TStream:=nil;
  try
    lSrc:=TFile.OpenRead(ASrc);
    lDst:=TFile.Open(ADst, TFileMode.fmCreate);
    lDst.CopyFrom(lSrc);
  finally
    lDst.Free;
    lSrc.Free;
  end;
end;

procedure TMockLibHandler.DeleteFile(ASrc: string);
begin
  if TFile.Exists(ASrc) then
    TFile.Delete(ASrc);
end;

procedure TMockLibHandler.WriteVersion(ADst: string;
  const AVersion: TOsslVersion);
begin
  TFile.WriteAllText(ADst, '$'+AVersion.Version.ToHexString(8));
end;

procedure TMockLibHandler.SetupMock(ALibName: string;
  const AVersion: TOsslVersion);
begin
  CopyFile(TMockLibConfig.MockLibPath, TMockLibConfig.GetWorkMockLibPath(ALibName));
  WriteVersion(TMockLibConfig.GetMockLibVerFile(ALibName), AVersion);
end;

procedure TMockLibHandler.SetupMock(
  ALibType: TLibType; const AVersion: TOsslVersion);
begin
  SetupMock(TOsslLoader.LibName[ALibType], AVersion);
end;

procedure TMockLibHandler.SetupMocks(
  ALibTypes: TLibTypes; const AVersion: TOsslVersion);
begin
  for var lLib in ALibTypes do
    SetupMock(lLib, AVersion);
end;

procedure TMockLibHandler.SetupAllMocks(
  AVersion: TOsslVersion);
begin
  SetupMocks(TOsslLoader.cLibTypesAll, AVersion);
end;

procedure TMockLibHandler.CleanUpMock(ALibName: string);
begin
  DeleteFile(TMockLibConfig.GetMockLibVerFile(ALibName));
  DeleteFile(TMockLibConfig.GetWorkMockLibPath(ALibName));
end;

procedure TMockLibHandler.CleanUpMock(
  ALibType: TLibType);
begin
  CleanUpMock(TOsslLoader.LibName[ALibType]);
end;

procedure TMockLibHandler.CleanUpMocks(
  ALibTypes: TLibTypes);
begin
  for var lLib in ALibTypes do
    CleanUpMock(lLib);
end;

procedure TMockLibHandler.CleanUpAllMocks;
begin
  CleanUpMocks(TOsslLoader.cLibTypesAll);
end;

procedure TMockLibHandler.LoaderUnload(ALibType: TLibType);
begin
  if TOsslCustomLoader.IsLoaderSet then
    TOsslCustomLoader.Unload([ALibType]);
end;

procedure TMockLibHandler.LoaderUnload(
  ALibTypes: TLibTypes);
begin
  if TOsslCustomLoader.IsLoaderSet then
    TOsslCustomLoader.Unload(ALibTypes);
end;

procedure TMockLibHandler.LoaderUnloadAll;
begin
  if TOsslCustomLoader.IsLoaderSet then
    TOsslCustomLoader.Unload(TOsslCustomLoader.cLibTypesAll);
end;

procedure TMockLibHandler.CheckWorkDir;
begin
  var FWorkDir:=TMockLibConfig.MockWorkDir;
  if string.IsNullOrEmpty(FWorkDir) then
    Exit; // use current Directory
  if not TDirectory.Exists(TMockLibConfig.MockWorkDir) then
  begin
    TDirectory.CreateDirectory(TMockLibConfig.MockWorkDir);
    FWorkDirCreated:=True;
  end;
end;

procedure TMockLibHandler.CleanWorkDir;
begin
  if FWorkdirCreated then
    TDirectory.Delete(TMockLibConfig.MockWorkDir, True);
end;

function TMockLibHandler.CheckLibTypes(
  ALibTypes: TLibTypes): TLibTypes;
const
  cBaseLibType = TOsslLoader.cBaseLibType;

begin
  Result:=ALibTypes;
  if (ALibTypes - [cBaseLibType]) <> [] then
    Include(Result, cBaseLibType);
end;

{ TCustomMockLoadFixture }

destructor TCustomMockLoadFixture.Destroy;
begin
  FreeAndNil(FMockLibHandler);
end;

procedure TCustomMockLoadFixture.SetupFixture;
begin
  FMockLibHandler:=TMockLibHandler.Create;
end;

{ TMockLoadSingleTestFixture }

procedure TMockLoadSingleTestFixture.Setup;
begin
  inherited;
  MockLibHandler.CheckWorkDir;
end;

procedure TMockLoadSingleTestFixture.TearDown;
begin
  try
    MockLibHandler.LoaderUnloadAll;
    MockLibHandler.CleanUpAllMocks;
    MockLibHandler.CleanWorkDir;
  finally
    inherited;
  end;
end;

{ TDelphiPlatformHelper }

class function TDelphiPlatformHelper.RunningPlatform: TDelphiPlatform;
begin
{$IF Defined(Win32)}
  Result:=dpWIN32;
{$ELSEIF Defined(Win64)}
  {$IF Defined(CPUX64)}
  Result:=dpWIN64;
  {$ELSEIF Defined(CPUARM64)}
  Result:=dpWINARM64;
  {$ELSE}
  Result:=dpUnknown;
  {$ENDIF}
{$ELSEIF Defined(ANDROID32)}
  Result:=dpANDROID32;
{$ELSEIF Defined(ANDROID64)}
  Result:=dpANDROID64;
{$ELSEIF Defined(OSX64)}
  Result:=dpOSX64;
{$ELSEIF Defined(OSXARM64)}
  Result:=dpOSXARM64;
{$ELSEIF Defined(IOS64)}
  Result:=dpIOS64;
{$ELSE}
  Result:=dpUnknown;
{$ENDIF}
end;

{ TDelphiPlatformsHelper }

function TDelphiPlatformsHelper.InPlatforms: boolean;
begin
  Result:=TDelphiPlatform.RunningPlatform in Self;
end;

end.
