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

unit Ossl4Pas.Binding;

{$INCLUDE 'Ossl4Pas_CompilerDefines.inc'}

interface

uses
{$IFDEF T_WINDOWS}
  Winapi.Windows,
{$ENDIF}
  Ossl4Pas.CTypes,
  Ossl4Pas.Types;

type
  EOsslBindError = class(EOsslCustomError)
    class procedure RaiseException(const AMessage: string);
    class procedure RaiseExceptionFmt(const AMessage: string;
      Args: array of const);
    class procedure RaiseExceptionRes(ResStringRec: PResStringRec);
    class procedure RaiseExceptionResFmt(ResStringRec: PResStringRec;
      Args: array of const);
  end;

  /// <summary>
  ///   Defines a mapping between an OpenSSL symbol name and a Pascal function variable.
  /// </summary>
  TOsslBindEntry = record
    /// <summary>The case-sensitive name of the exported function (e.g., 'BIO_new').</summary>
    Name: string;
    /// <summary>Address of the function variable to assign.</summary>
    VarPtr: PPointer;
    /// <summary>Minimum OpenSSL version required. 0 = Any.</summary>
    MinVer: culong;
    /// <summary>
    ///   Optional custom address to assign if the symbol is missing or incompatible.
    ///   If nil, the default behavior (Stub or nil) is used.
    /// </summary>
    FallbackPtr: Pointer;
  end;

  /// <summary>
  ///   Helper class to automate symbol resolution and error stubbing.
  /// </summary>
  TOsslBinding = class
  public
    /// <summary>
    ///   Iterates through the table and assigns function pointers.
    ///   If a symbol is missing or version is too low, assigns a safe error stub.
    /// </summary>
    class procedure Bind(const ALibHandle: TLibHandle;
      const ACurrentVer: TOsslVersion; const AEntries:
      array of TOsslBindEntry; ASetStub: boolean = True); static;

    /// <summary>
    ///   Resets all function pointers in the table to the safe Stub.
    ///   Used for initialization and unbinding.
    /// </summary>
    class procedure Reset(const AEntries: array of TOsslBindEntry;
      ASetStub: boolean = True); static;

    /// <summary>
    ///   The universal stub for missing functions. Raises EOsslLoader.
    /// </summary>
    /// <remarks>
    ///   Since OpenSSL uses cdecl, the caller cleans the stack. Raising an exception
    ///   here is safe for any function signature because it never returns to the call site.
    /// </remarks>
    class procedure Stub_FuncNotAvailable; cdecl; static;
  end;

implementation

uses
  System.SysUtils,
  Ossl4Pas.Loader,
  Ossl4Pas.ResStrings;

{ EOsslBindError }

class procedure EOsslBindError.RaiseException(const AMessage: string);
begin
  raise EOsslBindError.Create(AMessage);
end;

class procedure EOsslBindError.RaiseExceptionFmt(const AMessage: string;
  Args: array of const);
begin
  raise EOsslBindError.CreateFmt(AMessage, Args);
end;

class procedure EOsslBindError.RaiseExceptionRes(ResStringRec: PResStringRec);
begin
  raise EOsslBindError.CreateRes(ResStringRec);
end;

class procedure EOsslBindError.RaiseExceptionResFmt(ResStringRec: PResStringRec;
  Args: array of const);
begin
  raise EOsslBindError.CreateResFmt(ResStringRec, Args);
end;

{ TOsslBinding }

class procedure TOsslBinding.Stub_FuncNotAvailable;
begin
  EOsslBindError.RaiseExceptionRes(@resErrRoutineNotBound);
end;

class procedure TOsslBinding.Bind(const ALibHandle: TLibHandle;
  const ACurrentVer: TOsslVersion; const AEntries: array of TOsslBindEntry;
  ASetStub: boolean);
var
  i: Integer;
  lProcAddr: pointer;
  lEntry: TOsslBindEntry;
  lIsCompatible: Boolean;
  lPVar: PPointer;

begin
  for i:=Low(AEntries) to High(AEntries) do
  begin
    lEntry:=AEntries[i];
    lPVar:=lEntry.VarPtr;
    if not Assigned(lPVar) then
      continue; // Skip binding to avoid carch on app/library initialization
    lProcAddr:=nil;

    // 1. Version Check
    lIsCompatible:=True;
    if lEntry.MinVer > 0 then
      lIsCompatible:=ACurrentVer >= lEntry.MinVer; // Uses TOsslVersion operators

    if lIsCompatible then
      // 2. Resolve Symbol
      lProcAddr:=ALibHandle.ProcAddress[lEntry.Name];

    if Assigned(lProcAddr) then
      lPVar^:=lProcAddr
    else
    begin
      // Symbol missing or Version incompatible
      if Assigned(lEntry.FallbackPtr) then
        lPVar^:=lEntry.FallbackPtr  // <--- Use Custom Fallback
      else if ASetStub then
        lPVar^:=@Stub_FuncNotAvailable
      else
        lPVar^:=nil;
    end;
  end;
end;

class procedure TOsslBinding.Reset(const AEntries: array of TOsslBindEntry;
  ASetStub: boolean);
var
  i: Integer;
  lPVar: PPointer;

begin
  for i:=Low(AEntries) to High(AEntries) do
  begin
    lPVar:=AEntries[i].VarPtr;

    if Assigned(lPVar) then
    begin
      // Reset logic: Prefer Fallback if available, otherwise Stub/Nil
      if Assigned(AEntries[i].FallbackPtr) then
        lPVar^:=AEntries[i].FallbackPtr
      else if ASetStub then
        lPVar^:=@Stub_FuncNotAvailable
      else
        lPVar^:=nil;
    end;
  end;
end;

end.
