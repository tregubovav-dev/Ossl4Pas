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

{$IFDEF LINK_STATIC}
  {$IFDEF T_WINDOWS}
  // There is a Delphi Native linker limitation to use '.lib' files
  // This clause should not be used with Win32/Win64 Platforms
    {$IFDEF DCC}
      {$LINK 'libssl.lib'}
      {$LINK 'libcrypto.lib'}
    {$ENDIF}
    {$IFDEF FPC}
      {$LINKLIB 'libssl.lib'}
      {$LINKLIB 'libcrypto.lib'}
    {$ENDIF}
  {$ENDIF}
  {$IFDEF T_POSIX}
    {$IFDEF DCC}
      {$LINK 'libssl.a'}
      {$LINK 'libcrypto.a'}
    {$ENDIF}
    {$IFDEF FPC}
      {$LINKLIB 'libssl.a'}
      {$LINKLIB 'libcrypto.a'}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}
