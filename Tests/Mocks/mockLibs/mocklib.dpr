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

library mocklib;

{ Important note about DLL memory management: ShareMem must be the
  first unit in your library's USES clause AND your project's (select
  Project-View Source) USES clause if your DLL exports any procedures or
  functions that pass strings as parameters or function results. This
  applies to all strings passed to and from your DLL--even those that
  are nested in records and classes. ShareMem is the interface unit to
  the BORLNDMM.DLL shared memory manager, which must be deployed along
  with your DLL. To avoid using BORLNDMM.DLL, pass string information
  using PChar or ShortString parameters.

  Important note about VCL usage: when this DLL will be implicitly
  loaded and this DLL uses TWicImage / TImageCollection created in
  any unit initialization section, then Vcl.WicImageInit must be
  included into your library's USES clause. }

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
  Ossl4pas.CTypes,
  Ossl4Pas.UT.Mock.Version in 'Ossl4Pas.UT.Mock.Version.pas',
  Ossl4Pas.UT.Mock.Err_Routines in 'Ossl4Pas.UT.Mock.Err_Routines.pas',
  Ossl4Pas.UT.Consts in '..\..\Common\Ossl4Pas.UT.Consts.pas';

{$R *.res}

exports
// Version Mocks
  OpenSSL_version_num,
  SSLeay,
  DummyStr,
  DummyAdd,
  IsLibName,

  // Errors Mocks Management
  Mock_Err_Push,
  Mock_Err_Clear,
  // ERR_ API Basic Routines
  ERR_get_error,
  ERR_peek_error,
  ERR_peek_last_error,
  ERR_clear_error,
  // ERR_ API Strings Routines
  ERR_error_string,
  ERR_error_string_n,
  ERR_lib_error_string,
  ERR_reason_error_string,
  ERR_peek_error_func,
  ERR_peek_last_error_func,
  ERR_peek_error_data,
  ERR_peek_last_error_data,
  ERR_get_error_all,
  ERR_peek_error_all,
  ERR_peek_last_error_all;


begin

end.
