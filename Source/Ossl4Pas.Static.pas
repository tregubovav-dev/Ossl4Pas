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

unit Ossl4Pas.Static;

{$I Ossl4Pas_CompilerDefines.inc}

interface

{$IFDEF LINK_STATIC}
	{$IFDEF T_WINDOWS}
const
	cLibCryptoLib = 'libcrypto.lib';
	cLibSslLib    = 'libssl.lib';
	{$ENDIF}
	{$IFDEF T_POSIX}
const
	cLibCryptoLib = 'libcrypto.a';
	cLibSslLib    = 'libssl.a';
	{$ENDIF}
{$ENDIF}

implementation

{$IFDEF T_LINUX}
{$HINTS OFF}
// We have to export __dso_handle in Linux if OpenSSL static library
// built without 'no-dso' flag.
procedure  __dso_handle; cdecl;
begin
end;

exports
	__dso_handle;
{$HINTS ON}
{$ENDIF}

end.
