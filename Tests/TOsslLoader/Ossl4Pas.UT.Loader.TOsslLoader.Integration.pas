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

unit Ossl4Pas.UT.Loader.TOsslLoader.Integration;

interface

uses
  System.SysUtils,
  System.Classes,
  DUnitX.TestFramework,
  Ossl4Pas.CTypes,
  Ossl4Pas.Types,
  Ossl4Pas.Loader,
  Ossl4Pas.UT.CustomFixtures;

type
  TBindSelectorClass = class of TBindSelector;
  TBindSelector       = class abstract
    class function GetLibName: string;
    class function GetLibType: TLibType; virtual; abstract;
  end;

  TBindCryptoClass  = class of TBindCrypto;
  TBindCrypto       = class(TBindSelector)
    class function GetLibType: TLibType; override;
  end;

  TBindSslClass = class of TBindSsl;
  TBindSsl      = class(TBindSelector)
    class function GetLibType: TLibType; override;
  end;

  TBinder<T: TBindSelector> = record
  public type
    TDummyStrFunc   = function: PChar; cdecl;
    TDummyAddFunc   = function(AValue, AAddition: cint): cint; cdecl;
    TIsLibNameFunc  = function(var ALibName: PChar): boolean; cdecl;

  private const
    cDummyStrName   = 'DummyStr';
    cDummyAddName   = 'DummyAdd';
    cIsLibName      = 'IsLibName';

  private class var
    FVersion: TOsslVersion;
    FDummyStr: TDummyStrFunc;
    FDummyAdd: TDummyAddFunc;
    FIsLibName: TIsLibNameFunc;

  private
    class procedure Bind(const ALibHandle: TLibHandle;
      const AVersion: TOsslVersion); static;
    class procedure UnBind; static;

  public
    class procedure DoBind; static;
    class function DummyStr: PChar; static; cdecl;
    class function DummyAdd(AValue, AAddition: cint): cint; static; cdecl;
    class function IsLibName(var ALibName: PChar): boolean; static; cdecl;
  end;

  TCryptoBinder = TBinder<TBindCrypto>;
  TSslBinder    = TBinder<TBindSsl>;

  [Category('OsslLoader,OsslLoaderIntegration')]
  TOsslCustomLoaderIntegrationFixture = class(TMockLoadSingleTestFixture)
    procedure LoadAndBindLib<T: TBindSelector>(AVersion: culong);
      overload;

  public
    [AutoNameTestCase('ltCrypto, $3060000F,True')]
    [AutoNameTestCase('ltCrypto, $3000000F,True')]
    [AutoNameTestCase('ltCrypto, $1010100F,False')]
    [AutoNameTestCase('ltSsl, $3060000F,True')]
    [AutoNameTestCase('ltSsl, $3000000F,True')]
    [AutoNameTestCase('ltSsl, $1010100F,False')]
    procedure LoadVersion(ALibType: TLibType; AVersion: culong;
      AExpected: boolean);

    [AutoNameTestCase('$3060000F,$3060000F,True')]
    [AutoNameTestCase('$3060000F,$3060000A,True')]
    [AutoNameTestCase('$3060000F,$3060100F,True')]
    [AutoNameTestCase('$3060000F,$3000000F,False')]
    [AutoNameTestCase('$3000000F,$3060000F,False')]
    procedure LoadVersionDiff(ACryptoVer, ASslVer: culong; AExpected: boolean);

    [AutoNameTestCase('$3060000F')]
    [IgnoreMemoryLeaks]
    // DUnitX report false positive memory leak.
    // The loader binfing registry is updated during this test
    // Unfortunately the binding registry can't be reset after the test
    // without impacting other loader finctionality.
    procedure LoadAndBindLibCrypto(AVersion: culong); overload;

    [AutoNameTestCase('$3060000F')]
    [IgnoreMemoryLeaks]
    // DUnitX report false positive memory leak.
    // The loader binfing registry is updated during this test
    // Unfortunately the binding registry can't be reset after the test
    // without impacting other loader finctionality.
    procedure LoadAndBindLibSsl(AVersion: culong); overload;
  end;

implementation

uses
  System.IOUtils,
  Ossl4Pas.UT.Utils;

{ TBindSelector }

class function TBindSelector.GetLibName: string;
begin
  Result:=TOsslLoader.LibName[GetLibType];
end;

{ TBindCrypto }

class function TBindCrypto.GetLibType: TLibType;
begin
  Result:=ltCrypto;
end;

{ TBindSsl }

class function TBindSsl.GetLibType: TLibType;
begin
  Result:=ltSsl;
end;

{ TBinder<T> }

class procedure TBinder<T>.Bind(const ALibHandle: TLibHandle;
  const AVersion: TOsslVersion);
const
  cFailNotFound = 'Function "%s" not found in library "%s".';

begin
  var lFileName:=ALibHandle.FileName;

  begin
    var lProc:=ALibHandle.ProcAddress[cDummyStrName];
    Assert.IsNotNull(lProc,
      Format(cFailNotFound, [cDummyStrName, lFileName])
    );
    @FDummyStr:=lProc;
  end;

  begin
    var lProc:=ALibHandle.ProcAddress[cDummyAddName];
    Assert.IsNotNull(lProc,
      Format(cFailNotFound, [cDummyAddName, lFileName])
    );
    @FDummyAdd:=lProc;
  end;

  begin
    var lProc:=ALibHandle.ProcAddress[cIsLibName];
    Assert.IsNotNull(lProc,
      Format(cFailNotFound, [cIsLibName, lFileName])
    );
    @FIsLibName:=lProc;
  end;
end;

class procedure TBinder<T>.UnBind;
begin
  @FDummyStr:=nil;
  @FDummyAdd:=nil;
  @FIsLibName:=nil;
end;

class procedure TBinder<T>.DoBind;
begin
  TOsslLoader.RegisterBinding(T.GetLibType, Bind, UnBind);
end;

class function TBinder<T>.DummyStr: PChar;
begin
  Assert.IsNotNull(pointer(@FDummyStr), 'Method DummyStr is not initialized.');
  Result:=FDummyStr();
end;

class function TBinder<T>.DummyAdd(AValue, AAddition: cint): cint;
begin
  Assert.IsNotNull(pointer(@FDummyAdd), 'Method DummyAdd is not initialized.');
  Result:=FDummyAdd(AValue, AAddition);
end;

class function TBinder<T>.IsLibName(var ALibName: PChar): boolean;
begin
  Assert.IsNotNull(pointer(@FIsLibName), 'Method IsLibName is not initialized.');
  Result:=FIsLibName(ALibName);
end;


{ TOsslCustomLoaderIntegrationFixture }

procedure TOsslCustomLoaderIntegrationFixture.LoadVersion(
  ALibType: TLibType; AVersion: culong; AExpected: boolean);
begin
  MockLibHandler.SetupMocks(
    MockLibHandler.CheckLibTypes([ALibType]), TOsslVersion.Create(AVersion));
  if AExpected then
  begin
    Assert.WillNotRaise(
      procedure
      begin
        TOsslLoader.Load([ALibType], MockLibHandler.WorkDir);
      end,
      EOsslLoader
    );
    Assert.IsTrue(TOsslLoader.IsLibLoaded[ALibType],
      'The requested library is not loaded.');
  end
  else
  begin
    Assert.WillRaise(
      procedure
      begin
        TOsslLoader.Load([ALibType], MockLibHandler.WorkDir);
      end,
      EOsslLoader
    );
    Assert.IsTrue(TOsslLoader.LibsLoaded = [], 'No library should remian be loaded.');
  end;

end;


procedure TOsslCustomLoaderIntegrationFixture.LoadVersionDiff(ACryptoVer,
  ASslVer: culong; AExpected: boolean);
begin
  MockLibHandler.SetupMock(ltCrypto, TOsslVersion.Create(ACryptoVer));
  MockLibHandler.SetupMock(ltSsl, TOsslVersion.Create(ASslVer));
  if AExpected then
  begin
    Assert.WillNotRaise(
      procedure
      begin
        TOsslLoader.Load(TOsslCustomLoader.cLibTypesAll, MockLibHandler.WorkDir);
      end,
      EOsslLoader
    );
    Assert.IsTrue(TOsslLoader.LibsLoaded = TOsslCustomLoader.cLibTypesAll,
      'All libraries should be loaded.');
  end
  else
  begin
    Assert.WillRaise(
      procedure
      begin
        TOsslLoader.Load(TOsslCustomLoader.cLibTypesAll, MockLibHandler.WorkDir);
      end,
      EOsslLoader
    );
    Assert.IsTrue(TOsslLoader.LibsLoaded = [ltCrypto],
      'The only LibCrypto should remain be loaded.');
  end;
end;

procedure TOsslCustomLoaderIntegrationFixture.LoadAndBindLib<T>(
  AVersion: culong);
var
  lLibType: TLibType;
  lLibName: string;
  lPLibName: PChar;

begin
  lLibType:=T.GetLibType;

  MockLibHandler.SetupMocks(
    MockLibHandler.CheckLibTypes([lLibType]), TOsslVersion.Create(AVersion));

  TBinder<T>.DoBind;

  Assert.WillNotRaise(
    procedure
    begin
      TOsslLoader.Load([lLibType], MockLibHandler.WorkDir);
    end,
    EOsslLoader
  );
  Assert.IsTrue(TOsslLoader.IsLibLoaded[lLibType],
    'The LibCrypto library is not loaded.');

  Assert.AreEqual(PChar('Dummy String'), TBinder<T>.DummyStr,
    'DummyStr returns wrong value.');
  Assert.AreEqual(cint(18+25), TBinder<T>.DummyAdd(18,25),
    'DummyAdd returns wrong value.');

  lLibName:=TOsslLoader.LibName[lLibType];
  lPLibName:=PChar(lLibName);
  Assert.IsTrue(TBinder<T>.IsLibName(lPLibName), 'IsLibName returned False');
  Assert.AreNotEqual(PChar(lLibName), lPLibName,
    'IsLibName did not return loaded library path.');
{$IFDEF MSWINDOWS}
  Assert.IsTrue(SameText(lLibName, TPath.GetFileName(lPLibName)),
    Format('Unexpected library name "%s".', [TPath.GetFileName(lPLibName)]));
{$ELSE}
  Assert.IsTrue(SameStr(lLibName, TPath.GetFileName(lPLibName)),
    Format('Unexpected library name "%s".', [TPath.GetFileName(lPLibName)]));
{$ENDIF}
end;

procedure TOsslCustomLoaderIntegrationFixture.LoadAndBindLibCrypto(
  AVersion: culong);
begin
  LoadAndBindLib<TBindCrypto>(AVersion);
end;

procedure TOsslCustomLoaderIntegrationFixture.LoadAndBindLibSsl(
  AVersion: culong);
begin
  LoadAndBindLib<TBindSsl>(AVersion);
end;

initialization
  TDUnitX.RegisterTestFixture(TOsslCustomLoaderIntegrationFixture);

end.
