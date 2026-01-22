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

unit Ossl4Pas.Mock.Loader;

interface

uses
  SysUtils,
  System.SyncObjs,
  Ossl4Pas.CTypes,
  Ossl4Pas.Types,
  Ossl4Pas.Loader;

type
  /// <summary>
  ///   A concrete implementation of TOsslCustomLoader for Unit Testing.
  ///   It simulates successful loading without accessing the disk.
  /// </summary>
  TBaseMockLoader = class(TOsslCustomLoader)
  public type
(*    TLibTypes = TOsslCustomLoader.TLibTypes; *)

  public const
    cHandleCrypto = 1000+Ord(ltCrypto);
    cHandleSsl    = 1000+Ord(ltSsl);
    cVersion      = $30000F;

  private class var
    FRefCount: integer;

  protected
    procedure InternalLoad(ALibTypes: TLibTypes); override;
    procedure InternalUnload(ALibTypes: TLibTypes); override;
  public
    class procedure ResetSingleton; reintroduce;
    class property RefCount: integer read FRefCount;

    constructor Create; override;
    destructor Destroy; override;

  end;

implementation

constructor TBaseMockLoader.Create;
begin
  inherited;
  TInterlocked.Increment(FRefCount);
end;

destructor TBaseMockLoader.Destroy;
begin
  TInterlocked.Decrement(FRefCount);
  inherited;
end;

{ TMockLoader }

procedure TBaseMockLoader.InternalLoad(ALibTypes: TLibTypes);
var
  lLibType: TLibType;
begin
  // Simulate successful load
  for lLibType in ALibTypes do
  begin
    // Generate a fake non-zero handle (e.g., 1000+EnumValue)
    if not InstIsLibLoaded[lLibType] then
    begin
      InstLibHandle[lLibType]:=TLibHandle(1000+Ord(lLibType));
      // Simulate version 3.0.0
      InstLibVersion[lLibType]:=TOsslVersion.Create(cVersion);
    end;
  end;

  // Simulate the binding process normally handled by InternalLoad
  try
    DoBind(ALibTypes);
  except
    InternalUnload(ALibTypes);
  end;
end;

procedure TBaseMockLoader.InternalUnload(ALibTypes: TLibTypes);
var
  lLibType: TLibType;
begin
  DoUnBind(ALibTypes);
  for lLibType:=Low(TLibType) to High(TLibType) do
  begin
    if (lLibType in ALibTypes) then
      InstLibHandle[lLibType]:=TLibHandle.cNilHandle;
  end;
end;

class procedure TBaseMockLoader.ResetSingleton;
begin
  inherited;
  FRefCount:=0;
end;

end.
