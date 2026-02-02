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

unit Ossl4Pas.UT.Binding.Behavior;

interface

uses
  System.SysUtils,
  System.Classes,
  System.SyncObjs,
  DUnitX.TestFramework,
  Ossl4Pas.CTypes,
  Ossl4Pas.Types,
  Ossl4Pas.Loader,
  Ossl4Pas.Binding,
  Ossl4Pas.Mock.Loader,
  Ossl4Pas.UT.Loader.CustomFixtures;

type
  [Category('OsslLoader,OsslBinderBehavior')]
  TOsslBinderBehaviorFixture = class(TMockLoadSingleTestFixture)
  public type
    TBindKind = (bkNone, bkStub, bkNull, bkFallBack);

  protected
    procedure SetMock(ALibType: TLibType; AVersion: culong);

  public
    [AutoNameTestCase('ltCrypto,$3000000F,bkStub')]
    [AutoNameTestCase('ltCrypto,$3020000F,bkNone')]
    [AutoNameTestCase('ltCrypto,$3060000F,bkNone')]
    procedure BindDummyStr( ALibType: TLibType; AVersion: culong;
      AExpected: TBindKind);

    [AutoNameTestCase('ltCrypto,$3000000F,bkFallBack')]
    [AutoNameTestCase('ltCrypto,$3020000F,bkNone')]
    [AutoNameTestCase('ltCrypto,$3060000F,bkNone')]
    procedure BindDummyAdd(ALibType: TLibType; AVersion: culong;
      AExpected: TBindKind);

    [AutoNameTestCase('ltCrypto,$3000000F,bkStub')]
    [AutoNameTestCase('ltCrypto,$3060000F,bkStub')]
    procedure BindNonExist(ALibType: TLibType; AVersion: culong;
      AExpected: TBindKind);

    [AutoNameTestCase('ltCrypto,$3000000F,bkNull')]
    [AutoNameTestCase('ltCrypto,$3020000F,bkNone')]
    [AutoNameTestCase('ltCrypto,$3060000F,bkNone')]
    procedure BindIsLibName(ALibType: TLibType; AVersion: culong;
      AExpected: TBindKind);

    [AutoNameTestCase('ltCrypto,$3000000F,bkFallBack')]
    [AutoNameTestCase('ltCrypto,$3020000F,bkFallBack')]
    [AutoNameTestCase('ltCrypto,$3060000F,bkFallBack')]
    procedure BindNonExistFB(ALibType: TLibType; AVersion: culong;
      AExpected: TBindKind);
  end;


implementation

type
  ECustomBind = class(Exception);
  ENullBind   = class(ECustomBind);
  EFallBack   = class(ECustomBind);

  TTestApiClass = class
  public type
    TDummyStrFunc   = function: PChar; cdecl;
    TDummyAddFunc   = function(AValue, AAddition: cint): cint; cdecl;
    TIsLibNameFunc  = function(var ALibName: PChar): boolean; cdecl;
    TNonExist       = function: string; cdecl;

  const
    cDummyStrName   = 'DummyStr';
    cDummyAddName   = 'DummyAdd';
    cIsLibName      = 'IsLibName';
    cNonExistName   = 'NonExist';
    cNonExistFBName = 'NonExistFB';

  class var
    FDummyStr:    TDummyStrFunc;
    FDummyAdd:    TDummyAddFunc;
    FIsLibName:   TIsLibNameFunc;
    FNonExist:    TNonExist;
    FNonExistFB:  TNonExist;

  protected
    class procedure RaiseNullBind(AMethodName: string); static;
    class procedure RaiseFallBackBind(AMethodName: string); static;
    class procedure CheckBind(const AProcVar: pointer; AProcName: string); static;

    class function FallBackDummyStr: PChar; static; cdecl;
    class function FallBackDummyAdd(AValue, AAddition: cint): cint; static; cdecl;
    class function FallBackIsLibName(var ALibName: PChar): boolean; static; cdecl;
    class function FallBackNonExist: pointer; static; cdecl;
    class function FallBackNonExistFB: pointer; static; cdecl;

    class procedure BindStub(const ALibHandle: TLibHandle;
      const AVersion: TOsslVersion); static;
    class procedure UnBindStub; static;

    class procedure BindNull(const ALibHandle: TLibHandle;
      const AVersion: TOsslVersion); static;
    class procedure UnBindNull; static;

  public
    class function DummyStr: PChar; static; cdecl;
    class function DummyAdd(AValue, AAddition: cint): cint; static; cdecl;
    class function IsLibName(var ALibName: PChar): boolean; static; cdecl;
    class function NonExists: string; static; cdecl;
    class function NonExistsFB: string; static; cdecl;

  class constructor Create;

  const
    cBindingStub: array[0..2] of TOsslBindEntry = (
      (Name: cDummyStrName; VarPtr: @@TTestApiClass.FDummyStr; MinVer: $30200000),
      (Name: cDummyAddName; VarPtr: @@TTestApiClass.FDummyAdd;
        MinVer: $30200000; FallbackPtr: @TTestApiClass.FallBackDummyAdd),
      (Name: cNonExistName; VarPtr: @@TTestApiClass.FNonExist; MinVer: 0)
    );

    cBindingNull: array[0..1] of TOsslBindEntry = (
      (Name: cIsLibName; VarPtr: @@TTestApiClass.FIsLibName; MinVer: $30200000),
      (Name: cNonExistFBName; VarPtr: @@TTestApiClass.FNonExistFB;
        MinVer: $30200000; FallbackPtr: @TTestApiClass.FallBackNonExist)
    );
  end;

{ TTestApiClass }

class constructor TTestApiClass.Create;
begin
  TOsslCustomLoader.RegisterBinding(ltCrypto, @BindStub, @UnBindStub);
  TOsslCustomLoader.RegisterBinding(ltCrypto, @BindNull, @UnBindNull);

  // Initialize default values.
  UnBindStub;
  UnBindNull;
end;

class procedure TTestApiClass.BindStub(const ALibHandle: TLibHandle;
  const AVersion: TOsslVersion);
begin
  TOsslBinding.Bind(ALibHandle, AVersion, cBindingStub);
end;

class procedure TTestApiClass.UnBindStub;
begin
  TOsslBinding.Reset(cBindingStub);
end;

class procedure TTestApiClass.BindNull(const ALibHandle: TLibHandle;
  const AVersion: TOsslVersion);
begin
  TOsslBinding.Bind(ALibHandle, AVersion, cBindingNull, False);
end;

class procedure TTestApiClass.UnBindNull;
begin
  TOsslBinding.Reset(cBindingNull, False);
end;

class procedure TTestApiClass.RaiseNullBind(AMethodName: string); noreturn;
begin
  raise ENullBind.Create(AMethodName);
end;

class procedure TTestApiClass.RaiseFallBackBind(AMethodName: string); noreturn;
begin
  raise EFallBack.Create(AMethodName);
end;

class function TTestApiClass.FallBackDummyAdd(AValue, AAddition: cint): cint;
begin
  RaiseFallBackBind(cDummyAddName);
  Result:=0;
end;

class function TTestApiClass.FallBackDummyStr: PChar; noreturn;
begin
  RaiseFallBackBind(cDummyStrName);
  Result:=nil;
end;

class function TTestApiClass.FallBackIsLibName(var ALibName: PChar): boolean;
begin
  ALibName:=PChar(nil);
  RaiseFallBackBind(cIsLibName);
end;

class function TTestApiClass.FallBackNonExist: pointer;
begin
  RaiseFallBackBind(cNonExistName);
  Result:=nil;
end;

class function TTestApiClass.FallBackNonExistFB: pointer;
begin
  RaiseFallBackBind(cNonExistFBName);
  Result:=nil;
end;

class procedure TTestApiClass.CheckBind(const AProcVar: pointer;
  AProcName: string);
begin
  if not Assigned(AProcVar) then
    RaiseNullBind(AProcName);
end;

class function TTestApiClass.DummyAdd(AValue, AAddition: cint): cint;
begin
  CheckBind(@FDummyAdd, cDummyAddName);
  Result:=FDummyAdd(AValue, AAddition);
end;

class function TTestApiClass.DummyStr: PChar;
begin
  CheckBind(@FDummyStr, cDummyStrName);
  Result:=FDummyStr();
end;

class function TTestApiClass.IsLibName(var ALibName: PChar): boolean;
begin
  CheckBind(@FIsLibName, cIsLibName);
  Result:=FIsLibName(ALibName);
end;

class function TTestApiClass.NonExists: string;
begin
  CheckBind(@FNonExist, cNonExistName);
  Result:=FNonExist() ;
end;

class function TTestApiClass.NonExistsFB: string;
begin
  CheckBind(@FNonExistFB, cNonExistFBName);
  Result:=FNonExistFB() ;
end;

{ TOsslBinderBehaviorFixture }

procedure TOsslBinderBehaviorFixture.SetMock(ALibType: TLibType;
  AVersion: culong);
begin
  MockLibHandler.SetupMocks(
    MockLibHandler.CheckLibTypes([ALibType]), TOsslVersion.Create(AVersion));

  Assert.WillNotRaise(
    procedure
    begin
      TOsslLoader.Load([ltCrypto], MockLibHandler.WorkDir);
    end,
    EOsslLoader
  );
  Assert.IsTrue(TOsslLoader.IsLibLoaded[ltCrypto],
    'The LibCrypto library is not loaded.');
end;

procedure TOsslBinderBehaviorFixture.BindDummyStr(ALibType: TLibType;
  AVersion: culong; AExpected: TBindKind);
begin
  SetMock(ALibType, AVersion);

  case AExpected of
    bkNone:
      Assert.AreEqual(PChar('Dummy String'), TTestApiClass.DummyStr(),
        'DummyStr returns wrong value.');
    bkStub:
      Assert.WillRaise(
        procedure begin TTestApiClass.DummyStr(); end,
        EOsslBindError
      );
    bkNull:
      Assert.WillRaise(
        procedure begin TTestApiClass.DummyStr(); end,
        ENullBind
      );
    bkFallBack:
      Assert.WillRaise(
        procedure begin TTestApiClass.DummyStr(); end,
        EFallBack
      );
  end;
end;

procedure TOsslBinderBehaviorFixture.BindDummyAdd(ALibType: TLibType;
  AVersion: culong; AExpected: TBindKind);
begin
  SetMock(ALibType, AVersion);

  case AExpected of
    bkNone:
      Assert.AreEqual(cint(18+25), TTestApiClass.DummyAdd(18,25),
        'DummyAdd returns wrong value.');
    bkStub:
      Assert.WillRaise(
        procedure begin TTestApiClass.DummyAdd(18,25); end,
        EOsslBindError
      );
    bkNull:
      Assert.WillRaise(
        procedure begin TTestApiClass.DummyAdd(18,25); end,
        ENullBind
      );
    bkFallBack:
      Assert.WillRaise(
        procedure begin TTestApiClass.DummyAdd(18,25); end,
        EFallBack
      );
  end;
end;

procedure TOsslBinderBehaviorFixture.BindNonExist(ALibType: TLibType;
  AVersion: culong; AExpected: TBindKind);
begin
  SetMock(ALibType, AVersion);

  case AExpected of
    bkNone:
      Assert.AreEqual(TTestApiClass.cNonExistName+'-FallBack', TTestApiClass.NonExists,
        TTestApiClass.cNonExistName+' returns wrong value.');
    bkStub:
      Assert.WillRaise(
        procedure begin TTestApiClass.NonExists; end,
        EOsslBindError
      );
    bkNull:
      Assert.WillRaise(
        procedure begin TTestApiClass.NonExists; end,
        ENullBind
      );
    bkFallBack:
      Assert.WillRaise(
        procedure begin TTestApiClass.NonExists; end,
        EFallBack
      );
  end;
end;

procedure CheckIsLib;
begin
  var lPLibName: PChar:='';
  Assert.IsFalse(TTestApiClass.IsLibName(lPLibName), 'IsLibName should returned False');
end;

procedure TOsslBinderBehaviorFixture.BindIsLibName(ALibType: TLibType;
  AVersion: culong; AExpected: TBindKind);

begin
  SetMock(ALibType, AVersion);

  case AExpected of
    bkNone:
      CheckIsLib;
    bkStub:
      Assert.WillRaise(
        procedure begin CheckIsLib; end,
        EOsslBindError
      );
    bkNull:
      Assert.WillRaise(
        procedure begin CheckIsLib; end,
        ENullBind
      );
    bkFallBack:
      Assert.WillRaise(
        procedure begin CheckIsLib; end,
        EFallBack
      );
  end;
end;

procedure TOsslBinderBehaviorFixture.BindNonExistFB(ALibType: TLibType;
  AVersion: culong; AExpected: TBindKind);
begin
  SetMock(ALibType, AVersion);

  case AExpected of
    bkNone:
      Assert.AreEqual(TTestApiClass.cNonExistFBName+'-FallBack', TTestApiClass.NonExistsFB,
        TTestApiClass.cNonExistName+' returns wrong value.');
    bkStub:
      Assert.WillRaise(
        procedure begin TTestApiClass.NonExistsFB; end,
        EOsslBindError
      );
    bkNull:
      Assert.WillRaise(
        procedure begin TTestApiClass.NonExistsFB; end,
        ENullBind
      );
    bkFallBack:
      Assert.WillRaise(
        procedure begin TTestApiClass.NonExistsFB; end,
        EFallBack
      );
  end;
end;

initialization
  TDUnitX.RegisterTestFixture(TOsslBinderBehaviorFixture);


end.
