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

unit Ossl4Pas.Api.Crypto;

{$INCLUDE 'Ossl4Pas_CompilerDefines.inc'}

interface

uses
  Ossl4Pas.CTypes,
  Ossl4Pas.Api.Types,
  Ossl4Pas.Types,
  Ossl4Pas.Loader,
  Ossl4Pas.Binding,
  Ossl4Pas.Static;


type
  /// <summary>
  ///   API wrapper for OpenSSL version and build information routines.
  /// </summary>
  TOsslApiCryptoVersion = class sealed
  public type
    TRoutine_Crypto_VersionNum      = function: culong; cdecl;
    TRoutine_Crypto_VersionPart     = function: cuint; cdecl;
    TRoutine_Crypto_VersionCharVal  = function: PAnsiChar; cdecl;
    TRoutine_Crypto_VersionInfo     = function(AType: cint): PAnsiChar; cdecl;

  public const
    /// <summary>
    ///   Constant for <see cref="OpenSSL_version"/>. Returns the full descriptive version text.
    ///   Example: 'OpenSSL 3.0.0 7 Sep 2021'.
    /// </summary>
    OPENSSL_VERSION_ = 0;

    /// <summary>
    ///   Constant for <see cref="OpenSSL_version"/>. Returns the compiler flags set for the compilation process.
    /// </summary>
    OPENSSL_CFLAGS = 1;

    /// <summary>
    ///   Constant for <see cref="OpenSSL_version"/>. Returns the date of the build process.
    /// </summary>
    OPENSSL_BUILT_ON = 2;

    /// <summary>
    ///   Constant for <see cref="OpenSSL_version"/>. Returns the "Configure" target of the library build.
    /// </summary>
    OPENSSL_PLATFORM = 3;

    /// <summary>
    ///   Constant for <see cref="OpenSSL_version"/>. Returns the OPENSSLDIR setting of the library build.
    /// </summary>
    OPENSSL_DIR = 4;

    /// <summary>
    ///   Constant for <see cref="OpenSSL_version"/>. Returns the ENGINESDIR setting. Deprecated in OpenSSL 3.0.
    /// </summary>
    OPENSSL_ENGINES_DIR = 5;

    /// <summary>
    ///   Constant for <see cref="OpenSSL_version"/>. Returns the short version identifier string (e.g., '3.0.0').
    /// </summary>
    OPENSSL_VERSION_STRING = 6;

    /// <summary>
    ///   Constant for <see cref="OpenSSL_version"/>. Returns the longer version identifier string,
    ///   combining version, pre-release, and build metadata.
    /// </summary>
    OPENSSL_FULL_VERSION_STRING = 7;

    /// <summary>
    ///   Constant for <see cref="OpenSSL_version"/>. Returns the MODULESDIR setting of the library build.
    /// </summary>
    OPENSSL_MODULES_DIR = 8;

    /// <summary>
    ///   Constant for <see cref="OpenSSL_version"/>. Returns the current OpenSSL CPU settings capability flags.
    /// </summary>
    OPENSSL_CPU_INFO = 9;

    /// <summary>
    ///   Constant for <see cref="OpenSSL_version"/>. Returns the Windows install context used to compute the registry key name.
    /// </summary>
    OPENSSL_WINCTX = 10;

    /// <summary>
    ///   Constant for <see cref="OPENSSL_info"/>. Returns the configured OPENSSLDIR (default config file location).
    /// </summary>
    OPENSSL_INFO_CONFIG_DIR = 1001;

    /// <summary>
    ///   Constant for <see cref="OPENSSL_info"/>. Returns the configured ENGINESDIR (default engine location).
    /// </summary>
    OPENSSL_INFO_ENGINES_DIR = 1002;

    /// <summary>
    ///   Constant for <see cref="OPENSSL_info"/>. Returns the configured MODULESDIR (default dynamically loadable module location).
    /// </summary>
    OPENSSL_INFO_MODULES_DIR = 1003;

    /// <summary>
    ///   Constant for <see cref="OPENSSL_info"/>. Returns the configured dynamically loadable module extension (e.g., '.so', '.dll').
    /// </summary>
    OPENSSL_INFO_DSO_EXTENSION = 1004;

    /// <summary>
    ///   Constant for <see cref="OPENSSL_info"/>. Returns the separator between a directory specification and a filename.
    /// </summary>
    OPENSSL_INFO_DIR_FILENAME_SEPARATOR = 1005;

    /// <summary>
    ///   Constant for <see cref="OPENSSL_info"/>. Returns the OpenSSL list separator (e.g., ':' on Unix, ';' on Windows).
    /// </summary>
    OPENSSL_INFO_LIST_SEPARATOR = 1006;

    /// <summary>
    ///   Constant for <see cref="OPENSSL_info"/>. Returns the seed source (internal use).
    /// </summary>
    OPENSSL_INFO_SEED_SOURCE = 1007;

    /// <summary>
    ///   Constant for <see cref="OPENSSL_info"/>. Returns the current OpenSSL CPU settings.
    /// </summary>
    OPENSSL_INFO_CPU_SETTINGS = 1008;

    /// <summary>
    ///   Constant for <see cref="OPENSSL_info"/>. Returns the Windows install context.
    /// </summary>
    OPENSSL_INFO_WINDOWS_CONTEXT = 1009;

  {$IFDEF LINK_DYNAMIC}
  private class var
    F_OpenSSL_version_num: TOsslApiCryptoVersion.TRoutine_Crypto_VersionNum;
    F_OPENSSL_version_major: TRoutine_Crypto_VersionPart;
    F_OPENSSL_version_minor: TRoutine_Crypto_VersionPart;
    F_OPENSSL_version_patch: TRoutine_Crypto_VersionPart;
    F_OPENSSL_version_pre_release: TRoutine_Crypto_VersionCharVal;
    F_OPENSSL_version_build_metadata: TRoutine_Crypto_VersionCharVal;
    F_OpenSSL_version: TRoutine_Crypto_VersionInfo;
    F_OPENSSL_info: TRoutine_Crypto_VersionInfo;

  strict private const
    cBindings: array[0..7] of TOsslBindEntry = (
      ( Name: 'OpenSSL_version_num';
        VarPtr: @@TOsslApiCryptoVersion.F_OpenSSL_version_num;
        MinVer: 0; FallbackPtr: nil
      ),
      ( Name: 'OPENSSL_version_major';
        VarPtr: @@TOsslApiCryptoVersion.F_OPENSSL_version_major;
        MinVer: 0; FallbackPtr: nil
      ),
      ( Name: 'OPENSSL_version_minor';
        VarPtr: @@TOsslApiCryptoVersion.F_OPENSSL_version_minor;
        MinVer: 0; FallbackPtr: nil
      ),
      ( Name: 'OPENSSL_version_patch';
        VarPtr: @@TOsslApiCryptoVersion.F_OPENSSL_version_patch;
        MinVer: 0; FallbackPtr: nil
      ),
      ( Name: 'OPENSSL_version_pre_release';
        VarPtr: @@TOsslApiCryptoVersion.F_OPENSSL_version_pre_release;
        MinVer: 0; FallbackPtr: nil
      ),
      ( Name: 'OPENSSL_version_build_metadata';
        VarPtr: @@TOsslApiCryptoVersion.F_OPENSSL_version_build_metadata;
        MinVer: 0; FallbackPtr: nil
      ),
      ( Name: 'OpenSSL_version';
        VarPtr: @@TOsslApiCryptoVersion.F_OpenSSL_version;
        MinVer: 0; FallbackPtr: nil
      ),
      ( Name: 'OPENSSL_info';
        VarPtr: @@TOsslApiCryptoVersion.F_OPENSSL_info;
        MinVer: 0; FallbackPtr: nil
      )
    );

    class procedure Bind(const ALibHandle: TLibHandle; const AVersion: TOsslVersion); static;
    class procedure UnBind; static;
  {$ENDIF}
  public
  {$IFDEF LINK_DYNAMIC}
    class constructor Create;
  {$ENDIF}

    /// <summary>
    ///   Returns the OpenSSL version number as a single integer.
    ///   <para>Format: 0xMNN00PP0L (Major, Minor, Patch).</para>
    /// </summary>
    class function OpenSSL_version_num: culong; static; {$IFDEF INLINE_ON}inline;{$ENDIF}

    /// <summary>
    ///   Returns the Major part of the version identifier.
    /// </summary>
    class function OPENSSL_version_major: cuint; static; {$IFDEF INLINE_ON}inline;{$ENDIF}

    /// <summary>
    ///   Returns the Minor part of the version identifier.
    /// </summary>
    class function OPENSSL_version_minor: cuint; static; {$IFDEF INLINE_ON}inline;{$ENDIF}

    /// <summary>
    ///   Returns the Patch part of the version identifier.
    /// </summary>
    class function OPENSSL_version_patch: cuint; static; {$IFDEF INLINE_ON}inline;{$ENDIF}

    /// <summary>
    ///   Returns text indicating a pre-release version (e.g., "-dev", "-alpha3").
    ///   Returns an empty string if undefined.
    /// </summary>
    class function OPENSSL_version_pre_release: PAnsiChar; static; {$IFDEF INLINE_ON}inline;{$ENDIF}

    /// <summary>
    ///   Returns extra build metadata information (e.g., "+fips").
    ///   Returns an empty string if undefined.
    /// </summary>
    class function OPENSSL_version_build_metadata: PAnsiChar; static; {$IFDEF INLINE_ON}inline;{$ENDIF}

    /// <summary>
    ///   Returns formatted version and build strings based on the provided type constant.
    /// </summary>
    /// <param name="AType">
    ///   The type of information to retrieve. Use <c>OPENSSL_VERSION_</c>,
    ///   <c>OPENSSL_CFLAGS</c>, <c>OPENSSL_BUILT_ON</c>, <c>OPENSSL_PLATFORM</c>,
    ///   <c>OPENSSL_DIR</c>, <c>OPENSSL_ENGINES_DIR</c>, <c>OPENSSL_MODULES_DIR</c>,
    ///   <c>OPENSSL_CPU_INFO</c>, or <c>OPENSSL_WINCTX</c> constants.
    /// </param>
    class function OpenSSL_version(AType: cint): PAnsiChar; static; {$IFDEF INLINE_ON}inline;{$ENDIF}

    /// <summary>
    ///   Returns configuration and system path information based on the provided type constant.
    ///   Returns NULL for unknown types.
    /// </summary>
    /// <param name="AType">
    ///   The type of configuration info to retrieve. Use <c>OPENSSL_INFO_CONFIG_DIR</c>,
    ///   <c>OPENSSL_INFO_ENGINES_DIR</c>, <c>OPENSSL_INFO_MODULES_DIR</c>,
    ///   <c>OPENSSL_INFO_DSO_EXTENSION</c>, <c>OPENSSL_INFO_DIR_FILENAME_SEPARATOR</c>,
    ///   <c>OPENSSL_INFO_LIST_SEPARATOR</c>, <c>OPENSSL_INFO_SEED_SOURCE</c>,
    ///   <c>OPENSSL_INFO_CPU_SETTINGS</c>, or <c>OPENSSL_INFO_WINDOWS_CONTEXT</c> constants.
    /// </param>
    class function OPENSSL_info(AType: cint): PAnsiChar; static; {$IFDEF INLINE_ON}inline;{$ENDIF}  end;

  /// <summary>
  ///   Pascal-friendly helper for OpenSSL version and info retrieval.
  ///   Converts C-string returns into native Pascal strings and types.
  /// </summary>
  TOsslApiCryptoVersionHelper = class helper for TOsslApiCryptoVersion
  private
    class function GetVersion: TOsslVersion; static; {$IFDEF INLINE_ON}inline;{$ENDIF}
    class function GetVersionStr(AType: integer): string; static;
    class function GetInfoStr(AType: integer): string; static;
    class function GetInfoChar(AType: integer): char; static;
    class function GetBuildMetadata: string; static;
    class function GetPreRelease: string; static;
  public
    /// <summary>Returns the parsed version object.</summary>
    class property Version: TOsslVersion read GetVersion;

    /// <summary>Returns pre-release text (e.g., "-dev").</summary>
    class property PreRelease: string read GetPreRelease;

    /// <summary>Returns build metadata (e.g., "+fips").</summary>
    class property BuildMetadata: string read GetBuildMetadata;

    /// <summary>Full descriptive version text.</summary>
    class property VersionText: string index TOsslApiCryptoVersion.OPENSSL_VERSION_ read GetVersionStr;

    /// <summary>Compiler flags used to build the library.</summary>
    class property CFlags: string index TOsslApiCryptoVersion.OPENSSL_CFLAGS read GetVersionStr;

    /// <summary>Date the library was built.</summary>
    class property BuiltOn: string index TOsslApiCryptoVersion.OPENSSL_BUILT_ON read GetVersionStr;

    /// <summary>The "Configure" target platform of the build.</summary>
    class property Platform: string index TOsslApiCryptoVersion.OPENSSL_PLATFORM read GetVersionStr;

    /// <summary>The configured OPENSSLDIR setting.</summary>
    class property DirectoryText: string index TOsslApiCryptoVersion.OPENSSL_DIR read GetVersionStr;

    /// <summary>The configured ENGINESDIR setting (Deprecated in 3.0).</summary>
    class property EnginesDirectoryText: string index TOsslApiCryptoVersion.OPENSSL_ENGINES_DIR read GetVersionStr;

    /// <summary>Short version string (e.g., '3.0.0').</summary>
    class property VersionStr: string index TOsslApiCryptoVersion.OPENSSL_VERSION_STRING read GetVersionStr;

    /// <summary>Full version string including pre-release and metadata.</summary>
    class property FullVersionStr: string index TOsslApiCryptoVersion.OPENSSL_FULL_VERSION_STRING read GetVersionStr;

    /// <summary>The configured MODULESDIR setting.</summary>
    class property ModulesDirectoryText: string index TOsslApiCryptoVersion.OPENSSL_MODULES_DIR read GetVersionStr;

    /// <summary>Current CPU capability flags.</summary>
    class property CPUInfo: string index TOsslApiCryptoVersion.OPENSSL_CPU_INFO read GetVersionStr;

    /// <summary>Windows install context string.</summary>
    class property WindowsCtx: string index TOsslApiCryptoVersion.OPENSSL_WINCTX read GetVersionStr;

    /// <summary>Default location for configuration files.</summary>
    class property ConfigDirectory: string index TOsslApiCryptoVersion.OPENSSL_INFO_CONFIG_DIR read GetInfoStr;

    /// <summary>Default location for engine modules.</summary>
    class property EnginesDirectory: string index TOsslApiCryptoVersion.OPENSSL_INFO_ENGINES_DIR read GetInfoStr;

    /// <summary>Default location for dynamically loadable modules.</summary>
    class property ModulesDirectory: string index TOsslApiCryptoVersion.OPENSSL_INFO_MODULES_DIR read GetInfoStr;

    /// <summary>Dynamically loadable module file extension.</summary>
    class property DSOExtention: string index TOsslApiCryptoVersion.OPENSSL_INFO_DSO_EXTENSION read GetInfoStr;

    /// <summary>OS-specific directory/filename separator.</summary>
    class property DirectorySeparatorChar: char index TOsslApiCryptoVersion.OPENSSL_INFO_DIR_FILENAME_SEPARATOR read GetInfoChar;

    /// <summary>OS-specific list separator (e.g., ':' or ';').</summary>
    class property PathSeparatorChar: char index TOsslApiCryptoVersion.OPENSSL_INFO_LIST_SEPARATOR read GetInfoChar;

    /// <summary>Seed source configuration.</summary>
    class property SeedSource: string index TOsslApiCryptoVersion.OPENSSL_INFO_SEED_SOURCE read GetInfoStr;

    /// <summary>Current CPU capability flags.</summary>
    class property CPUSettings: string index TOsslApiCryptoVersion.OPENSSL_INFO_CPU_SETTINGS read GetInfoStr;

    /// <summary>Windows install context string.</summary>
    class property WindowsContext: string index TOsslApiCryptoVersion.OPENSSL_INFO_WINDOWS_CONTEXT read GetInfoStr;
  end;

implementation

{ TOsslApiCryptoVersion }

{$IFDEF LINK_DYNAMIC}

class constructor TOsslApiCryptoVersion.Create;
begin
  UnBind;
  TOsslLoader.RegisterBinding(ltCrypto, @Bind, @UnBind);
end;

class procedure TOsslApiCryptoVersion.Bind(const ALibHandle: TLibHandle;
  const AVersion: TOsslVersion);
begin
  TOsslBinding.Bind(ALibHandle, AVersion, cBindings);
end;

class procedure TOsslApiCryptoVersion.UnBind;
begin
  TOsslBinding.Reset(cBindings);
end;
{$ENDIF}

{$IFDEF LINK_STATIC}
function F_OPENSSL_version_major: cuint; cdecl; external cLibCryptoLib name 'OPENSSL_version_major';
function F_OPENSSL_version_minor: cuint; cdecl; external cLibCryptoLib name 'OPENSSL_version_minor';
function F_OPENSSL_version_patch: cuint; cdecl; external cLibCryptoLib name 'OPENSSL_version_patch';
function F_OPENSSL_version_pre_release: PAnsiChar; cdecl; external cLibCryptoLib name 'OPENSSL_version_pre_release';
function F_OPENSSL_version_build_metadata: PAnsiChar; cdecl; external cLibCryptoLib name 'OPENSSL_version_build_metadata';
function F_OpenSSL_version_num: culong; cdecl; external cLibCryptoLib name 'OpenSSL_version_num';
function F_OpenSSL_version(AType: cint): PAnsiChar; cdecl; external cLibCryptoLib name 'OpenSSL_version';
function F_OPENSSL_info(AType: cint): PAnsiChar; cdecl; external cLibCryptoLib name 'OPENSSL_info';
{$ENDIF}

class function TOsslApiCryptoVersion.OPENSSL_version_major: cuint;
begin
  Result:=F_OPENSSL_version_major();
end;

class function TOsslApiCryptoVersion.OPENSSL_version_minor: cuint;
begin
  Result:=F_OPENSSL_version_minor();
end;

class function TOsslApiCryptoVersion.OPENSSL_version_patch: cuint;
begin
  Result:=F_OPENSSL_version_patch();
end;

class function TOsslApiCryptoVersion.OPENSSL_version_pre_release: PAnsiChar;
begin
  Result:=F_OPENSSL_version_pre_release();
end;

class function TOsslApiCryptoVersion.OPENSSL_version_build_metadata: PAnsiChar;
begin
  Result:=F_OPENSSL_version_build_metadata();
end;

class function TOsslApiCryptoVersion.OpenSSL_version_num: culong;
begin
  Result:=F_OpenSSL_version_num();
end;

class function TOsslApiCryptoVersion.OPENSSL_info(AType: cint): PAnsiChar;
begin
  Result:=F_OPENSSL_info(AType);
end;

class function TOsslApiCryptoVersion.OpenSSL_version(AType: cint): PAnsiChar;
begin
  Result:=F_OpenSSL_version(AType);
end;


{ TOsslApiCryptoVersionHelper }

// Note on String Conversions:
// OpenSSL version and info routines return static, 7-bit ASCII C-strings.
// Therefore, we rely on the RTL's fast implicit PAnsiChar -> [Unicode]String
// conversion (which also safely handles nil pointers), bypassing the explicit
// UTF8String casting required for most other OpenSSL string APIs.

class function TOsslApiCryptoVersionHelper.GetPreRelease: string;
begin
  Result:=string(OPENSSL_version_pre_release);
end;

class function TOsslApiCryptoVersionHelper.GetBuildMetadata: string;
begin
  Result:=string(OPENSSL_version_build_metadata);
end;

class function TOsslApiCryptoVersionHelper.GetVersionStr(
  AType: integer): string;
begin
  Result:=string(OpenSSL_version(AType));
end;

class function TOsslApiCryptoVersionHelper.GetInfoStr(AType: integer): string;
begin
  Result:=string(OPENSSL_info(AType));
end;

class function TOsslApiCryptoVersionHelper.GetInfoChar(AType: integer): char;
var
  lResult: PAnsiChar;

begin
  lResult:=OPENSSL_info(AType);
  if Assigned(lResult) then
    Result:=Char(lResult^)
  else
    Result:=#0;
end;

class function TOsslApiCryptoVersionHelper.GetVersion: TOsslVersion;
begin
  Result:=TOsslVersion.Create(OpenSSL_version_num);
end;

end.
