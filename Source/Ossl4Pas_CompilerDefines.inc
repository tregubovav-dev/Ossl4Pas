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


// Ossl4Pas_CompilerDefines.inc
{$IF Defined(FPC) and (FPC_FULLVERSION >= 30200)}
  {$DEFINE CONDITIONALEXPRESSIONS}
{$ENDIF}

{$IFDEF CONDITIONALEXPRESSIONS}
  {$IFDEF LINK_STATIC}
    {$UNDEF LINK_DYNAMIC}
  {$ELSE}
    {$DEFINE LINK_DYNAMIC}
  {$ENDIF}

  {$IFDEF LINK_STATIC}
    {$I ossl_version_scope.inc}
  {$ELSE}
    {$I ossl_version_shared.inc}
  {$ENDIF}

  {$IFDEF FPC}
    {$MODE DELPHI}
    {$MODESWITCH ADVANCEDRECORDS}
    {$UNDEF UNICODE_DEFAULT}
    {$DEFINE STUB_TSPINWAIT}
    {$DEFINE STUB_IOUTILS}
  {$ENDIF}

  {$IFDEF DCC}
    {$DEFINE UNICODE_DEFAULT}
  {$ENDIF}

  // Define explicit condifional variables
  {$IFDEF WIN64}
    {$DEFINE T_WIN64}
    {$DEFINE T_WINDOWS}
  {$ENDIF}

  {$IFDEF WIN32}
    {$DEFINE T_WIN32}
    {$DEFINE T_WINDOWS}
  {$ENDIF}

  {$IFDEF LINUX}
    {$DEFINE T_LINUX}
    {$IFNDEF POSIX}
      {$DEFINE T_POSIX}
    {$ENDIF}
  {$ENDIF}

  {$IFDEF ANDROID}
    {$DEFINE T_ANDROID}
    {$IFNDEF POSIX}
      {$DEFINE T_POSIX}
    {$ENDIF}
  {$ENDIF}

  {$IF Defined(DCC) AND Defined(OSX)}
    {$DEFINE T_OSX}
    {$IFNDEF POSIX}
      {$DEFINE T_POSIX}
    {$ENDIF}
  {$IFEND}

  {$IF Defined(DCC) AND Defined(IOS)}
    {$DEFINE T_IOS}
    {$IFNDEF POSIX}
      {$DEFINE T_POSIX}
    {$ENDIF}
  {$IFEND}

  {$IF Defined(FPC) AND
    (Defined(MACOS) AND Defined(DARWIN) AND (NOT Defined(IOS)))}
    {$DEFINE T_OSX}
    {$IFNDEF POSIX}
      {$DEFINE T_POSIX}
    {$ENDIF}
  {$IFEND}

  {$IF Defined(FPC) AND (Defined(DARWIN) AND Defined(IOS))}
    {$DEFINE T_IOS}
    {$IFNDEF POSIX}
      {$DEFINE T_POSIX}
    {$ENDIF}
  {$IFEND}

  // noreturn directive
  {$IFNDEF NORETURN}
    {$IF Defined(DCC) AND (CompilerVersion >= 37.0)}
      {$DEFINE NORETURN}
    {$ELSEIF Defined(FPC) AND (FPC_FULLVERSION >= 30200)}
      {$DEFINE NORETURN}
    {$IFEND}
  {$ENDIF}

  // Define inlining support
  {$IF (NOT Defined(DEBUG)) OR Defined(INLINE_OFF)}
    {$DEFINE INLINE_ON}
  {$IFEND}

  {$IF NOT (Defined(INLINE_ON)) AND Defined(INLINE_FORCE_ON)}
    {$DEFINE INLINE_ON}
  {$IFEND}

  {$IF Defined(DCC) and (CompilerVersion >= 36)}
    {$DEFINE USE_TINTERLOCKED}
  {$ENDIF}

  {$IF Defined(FPC) and (FPC_FULLVERSION >= 30204)}
    {$DEFINE USE_TINTERLOCKED}
  {$ENDIF}


  {$IF (not Defined(USE_TINTERLOCKED)) and
    (Defined(FPC) and (FPC_FULLVERSION < 30204))}
    {$DEFINE USE_ATOMIC_FPC}
  {$ENDIF}

  {$IF (not Defined(USE_TINTERLOCKED)) and Defined(DCC)}
    {$DEFINE USE_ATOMIC_DCC}
  {$ENDIF}

  {$IF not Defined(DCC)}
    {$DEFINE EMULATE_TSPINWAIT}
  {$ENDIF}


  // static linkage
  {$IF Defined(T_IOS)}
    {$DEFINE LINK_STATIC}
  {$IFEND}

{$ELSE}
  {$MESSAGE Warning 'Unsupported compiler version'}
{$ENDIF}

