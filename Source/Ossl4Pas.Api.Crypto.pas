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
  TOsslApiCryptoVersion = class
  public type
    TRoutine_Crypto_VersionNum      = function: culong; cdecl;
    TRoutine_Crypto_VersionPart     = function: cuint; cdecl;
    TRoutine_Crypto_VersionCharVal  = function: PAnsiChar; cdecl;
    TRoutine_Crypto_VersionInfo     = function(AType: cint): PAnsiChar; cdecl;

  public const
    // these constant operates with the function OpenSSL_version
    OPENSSL_VERSION_ = 0;
    OPENSSL_CFLAGS = 1;
    OPENSSL_BUILT_ON = 2;
    OPENSSL_PLATFORM = 3;
    OPENSSL_DIR = 4;
    OPENSSL_ENGINES_DIR = 5;
    OPENSSL_VERSION_STRING = 6;
    OPENSSL_FULL_VERSION_STRING = 7;
    OPENSSL_MODULES_DIR = 8;
    OPENSSL_CPU_INFO = 9;
    OPENSSL_WINCTX = 10;

    // these constant operates with the function OPENSSL_info
    OPENSSL_INFO_CONFIG_DIR = 1001;
    OPENSSL_INFO_ENGINES_DIR = 1002;
    OPENSSL_INFO_MODULES_DIR = 1003;
    OPENSSL_INFO_DSO_EXTENSION = 1004;
    OPENSSL_INFO_DIR_FILENAME_SEPARATOR = 1005;
    OPENSSL_INFO_LIST_SEPARATOR = 1006;
    OPENSSL_INFO_SEED_SOURCE = 1007;
    OPENSSL_INFO_CPU_SETTINGS = 1008;
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
        VarPtr: @@TOsslApiCryptoVersion.F_OpenSSL_version_num;
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

    class function OpenSSL_version_num: culong; static;
    class function OPENSSL_version_major: cuint; static;
    class function OPENSSL_version_minor: cuint; static;
    class function OPENSSL_version_patch: cuint; static;
    class function OPENSSL_version_pre_release: PAnsiChar; static;
    class function OPENSSL_version_build_metadata: PAnsiChar; static;
    class function OpenSSL_version(AType: cint): PAnsiChar; static;
    class function OPENSSL_info(AType: cint): PAnsiChar; static;
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
  Result:=F_OPENSSL_version_major;
end;

class function TOsslApiCryptoVersion.OPENSSL_version_minor: cuint;
begin
  Result:=F_OPENSSL_version_minor;
end;

class function TOsslApiCryptoVersion.OPENSSL_version_patch: cuint;
begin
  Result:=F_OPENSSL_version_patch;
end;

class function TOsslApiCryptoVersion.OPENSSL_version_pre_release: PAnsiChar;
begin
  Result:=F_OPENSSL_version_pre_release;
end;

class function TOsslApiCryptoVersion.OPENSSL_version_build_metadata: PAnsiChar;
begin
  Result:=F_OPENSSL_version_build_metadata;
end;

class function TOsslApiCryptoVersion.OpenSSL_version_num: culong;
begin
  Result:=F_OpenSSL_version_num;
end;

class function TOsslApiCryptoVersion.OPENSSL_info(AType: cint): PAnsiChar;
begin
  Result:=F_OPENSSL_info(AType);
end;

class function TOsslApiCryptoVersion.OpenSSL_version(AType: cint): PAnsiChar;
begin
  Result:=F_OpenSSL_version(AType);
end;


end.
