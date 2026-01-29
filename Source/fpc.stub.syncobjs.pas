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

// This unit is designed to emulate the TSpinWait record in Free Pascal
// until updated syncobjs unit will be released

unit fpc.stub.syncobjs;

{$INCLUDE 'Ossl4Pas_CompilerDefines.inc'}

interface

type

  { TSpinWait }

  TSpinWait = record
  private
    FCount: integer;
    function GetNextSpinCycleWillYield: boolean;
  public
    procedure Reset;
    procedure SpinCycle;
    property NextSpinCycleWillYield: boolean read GetNextSpinCycleWillYield;
  end;

implementation

{ TSpinWait }

procedure TSpinWait.Reset;
begin
  FCount:=0;
end;

function TSpinWait.GetNextSpinCycleWillYield: boolean;
begin
  Result:=(FCount > 16) or (CPUCount =1);
end;

procedure TSpinWait.SpinCycle;
begin
  if GetNextSpinCycleWillYield then
    System.ThreadSwitch
  else
    // Active Spin (Burn CPU cycles efficiently)
    // "PAUSE" instruction hints to CPU that this is a spin-loop
    {$IF defined(CPUI386) or defined(CPUX86_64)}
      asm pause end;
    {$ELSE}
      // On ARM or others, a simple yield is often safer/easier
      // if no specific 'YIELD' asm instruction is available/known.
      System.ThreadSwitch;
    {$IFEND}

  // Increment, but prevent overflow
  if FCount < High(Integer) then
    Inc(FCount);
end;
end.

