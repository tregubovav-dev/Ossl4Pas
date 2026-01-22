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

unit Ossl4Pas.UT.Utils;

interface

uses
  System.SysUtils,
  System.Classes;

type
  {$IFDEF MSWINDOWS}
  TFastMMDebugConfig = class
  public const
    cEnvVarNameDll = 'OSSL4PAS_FASTMM_DEBUG_DLL';
    cShortOptNameDll = 'fmd';
    cLongOptNameDll = 'fastmmdebugdll';

    cEnvVarEnable = 'OSSL4PAS_FASTMM_LOG_ENABLEL';
    cShortOptEnable = 'fme';
    cLongOptEnable = 'fastmmlogenable';

    cEnvVarLogName = 'OSSL4PAS_FASTMM_LOG_NAME';
    cShorOptLogName = 'fml';
    cLongOptLogName = 'fastmmlogname';

  private class var
    FDebudDLLName: string;
    FReportFileName: string;
    FActive: boolean;
    FInitialActive: boolean;
  private
    class procedure RegisterOptions; static;
    class function GetActive: boolean; static;
    class procedure SetActive(const Value: boolean); static;
    class function FinalizeFileName(APath, ADefaultFileName: string): string;

  public
    class constructor Create;
    class destructor Destroy;

    class property CmdParamActive: boolean read FActive;
    class property DebugModeActive: boolean read GetActive write SetActive;
  end;
  {$ENDIF}

  TMockLibConfig = class
  public const
    cEnvVarNameMockLib    = 'OSSL4PAS_MOCKLIB';
    cLongOptNameMockLib   = 'mocklib-path';
    cShortOptNameMockLib  = 'mkl';

    cEnvVarNameWorkDir    = 'OSSL4PAS_MOCKLIB_WORKDIR';
    cLongOptNameWorkDir   = 'mock-workdir';
    cShortOptNameWorkDir  = 'mkw';

    cDefaultMockLibName   = 'mocklib';
    {$IF Defined(MSWINDOWS)}
    cLibExt               = 'dll';
    {$ELSEIF Defined(LINUX) or Defined(ANDROID)}
    cLibExt               = 'so';
    {$ELSEIF Defined(OSX)}
    cLibExt               = 'dlyb';
    {$ENDIF}
    cVerExt               = 'ver';

  private class var
    FMockLibPath: string;
    FMockWorkDir: string;
  private
    class procedure RegisterOptions; static;
    class procedure SetMockLibPath(Value: string);
    class procedure SetMockWorkDir(Value: string);
  public
    class constructor Create;

    class function GetWorkMockLibPath(ALibName: string): string;
    class function GetMockLibVerFile(ALibName: string): string;

    class property MockLibPath: string read FMockLibPath;
    class property MockWorkDir: string read FMockWorkDir;
  end;

resourcestring
  rcFastMMDebugEnableHelp = 'Enable or disable detailed memory leak';
  rcFastMMLogHelp         = 'Memory leak report file name.';
{$IFDEF MSWINDOWS}
  {$IFDEF WIN32}
  rcFastMMDllNamelHelp    = 'Full path to FastMM_FullDebugMode.dll';
  {$ENDIF}
  {$IFDEF WIN64}
  rcFastMMDllNamelHelp    = 'Full path to FastMM_FullDebugMode64.dll';
  {$ENDIF}
{$ENDIF}
  rcMockLibPathHelp       = 'Full path to mock library.';
  rcMockLibWorkDirHelp    = 'Full path to mock library working directory.';

implementation

uses
  {$IFDEF MSWINDOWS}
  FastMM5,
  {$ENDIF}
  System.IOUtils,
  DUnitX.CommandLine.Options;

{$IFDEF MSWINDOWS}

{ TFastMMDebugLoader }

class constructor TFastMMDebugConfig.Create;
begin
  FDebudDLLName:=FinalizeFileName(GetEnvironmentVariable(cEnvVarNameDll),
    CFastMM_DefaultDebugSupportLibraryName);
  FReportFileName:=FinalizeFileName(GetEnvironmentVariable(cEnvVarLogName),
    FastMM_GetEventLogFilename);
  FActive:=not GetEnvironmentVariable(cEnvVarEnable).IsEmpty;
  RegisterOptions;
end;

class destructor TFastMMDebugConfig.Destroy;
begin
  if (not FInitialActive) and DebugModeActive then
    DebugModeActive:=False;
end;

class function TFastMMDebugConfig.FinalizeFileName(APath,
  ADefaultFileName: string): string;
begin
  if APath.IsEmpty then
    Exit(ADefaultFileName);
  if TFile.Exists(APath) then
    Exit(APath);
  Result:=TPath.Combine(APath, ADefaultFileName);
end;

class procedure TFastMMDebugConfig.RegisterOptions;
begin
  TOptionsRegistry.RegisterOption<string>(cLongOptNameDll, cShortOptNameDll,
    rcFastMMDllNamelHelp,
    procedure(Value: string)
    begin
      FDebudDLLName:=FinalizeFileName(Value, CFastMM_DefaultDebugSupportLibraryName);
    end
  );
  TOptionsRegistry.RegisterOption<string>(cLongOptLogName, cShorOptLogName,
    rcFastMMLogHelp,
    procedure(Value: string)
    begin
      FReportFileName:=FinalizeFileName(Value, FastMM_GetEventLogFilename);
    end
  );
  TOptionsRegistry.RegisterOption<boolean>(cShortOptEnable, cLongOptEnable,
    rcFastMMDebugEnableHelp,
    procedure(Value: boolean)
    begin
      FActive:=Value;
    end
  );
end;

class procedure TFastMMDebugConfig.SetActive(const Value: boolean);
begin
  if Value <> DebugModeActive then
    if Value then
    begin
      ReportMemoryLeaksOnShutdown:=True;
      FastMM_DebugSupportLibraryName:=PChar(FDebudDLLName);
      FastMM_SetEventLogFilename(PChar(FReportFileName));
      FastMM_EnterDebugMode;

      FastMM_MessageBoxEvents:=[];
      FastMM_OutputDebugStringEvents:=FastMM_OutputDebugStringEvents+
        [mmetUnexpectedMemoryLeakDetail, mmetUnexpectedMemoryLeakSummary];
      FastMM_LogToFileEvents:=FastMM_LogToFileEvents+
        [mmetUnexpectedMemoryLeakDetail, mmetUnexpectedMemoryLeakSummary];
    end
    else
      FastMM_ExitDebugMode;
end;

class function TFastMMDebugConfig.GetActive: boolean;
begin
  Result:=FastMM_DebugModeActive;
end;

{$ENDIF}

{ TMockLibConfig }

class constructor TMockLibConfig.Create;
begin
  SetMockLibPath(GetEnvironmentVariable(cEnvVarNameMockLib));
  SetMockWorkDir(GetEnvironmentVariable(cEnvVarNameWorkDir));
  RegisterOptions;
end;

class procedure TMockLibConfig.RegisterOptions;
begin
  TOptionsRegistry.RegisterOption<string>(cLongOptNameMockLib,
    cShortOptNameMockLib, rcMockLibPathHelp,
    procedure(Value: string)
    begin
      SetMockLibPath(Value);
    end
  );

  TOptionsRegistry.RegisterOption<string>(cLongOptNameWorkDir,
    cShortOptNameWorkDir, rcMockLibWorkDirHelp,
    procedure(Value: string)
    begin
      SetMockWorkDir(Value);
    end
  );
end;

class procedure TMockLibConfig.SetMockLibPath(Value: string);
begin
  if string.IsNullOrWhiteSpace(Value) then
    FMockLibPath:=TPath.Combine(
      TDirectory.GetCurrentDirectory,
      cDefaultMockLibName+TPath.ExtensionSeparatorChar+cLibExt)
  else
    FMockLibPath:=TPath.GetFullPath(Value);
end;

class procedure TMockLibConfig.SetMockWorkDir(Value: string);
begin
  if string.IsNullOrWhiteSpace(Value) then
    FMockWorkDir:=TDirectory.GetCurrentDirectory
  else
    FMockWorkDir:=TPath.GetFullPath(Value);
end;

class function TMockLibConfig.GetMockLibVerFile(ALibName: string): string;
begin
  Result:=TPath.Combine(FMockWorkDir, TPath.ChangeExtension(ALibName, cVerExt));
end;

class function TMockLibConfig.GetWorkMockLibPath(ALibName: string): string;
begin
  Result:=TPath.Combine(FMockWorkDir, TPath.ChangeExtension(ALibName, cLibExt));
end;

end.
