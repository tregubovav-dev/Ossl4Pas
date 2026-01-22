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

unit Ossl4Pas.UT.Types.OsslVersion;

interface

uses
  System.SysUtils,
  System.Classes,
  Ossl4Pas.CTypes,
  OSsl4Pas.Types,
  OSsl4Pas.Loader,
  DUnitX.TestFramework;

type
  [TestFixture]
  TOsslVersionFixture = class
  private
    class function GetMajor(AValue: culong): byte; static;
    class function GetMinor(AValue: culong): byte; static;
    class function GetFix(AValue: culong): byte; static;
    class function GetPatch(AValue: culong): byte; static;
    class function GetStatus(AValue: culong): byte; static;

  public
    [AutoNameTestCase('$10912058,1,9,18,5,8')]
    [AutoNameTestCase('$3000000F,3,0,0,0,15')]
    [AutoNameTestCase('$3060000F,3,6,0,0,15')]
    [AutoNameTestCase('$3250F00F,3,37,15,0,15')]
    [AutoNameTestCase('$F0F0F0FF,15,15,15,15,15')]
    procedure CreateFromInt(AValue: culong; AMajor, AMinor, AFix, APatch,
      AStatus: cuint8);

    [AutoNameTestCase('1,9,18,5,8,$10912058')]
    [AutoNameTestCase('3,6,0,0,15,$3060000F')]
    [AutoNameTestCase('3,5,18,0,15,$3051200F')]
    [AutoNameTestCase('15,15,15,15,15,$F0F0F0FF')]
    procedure CreateFromParts(AMajor, AMinor, AFix, APatch, AStatus: cuint8;
      AExpected: culong);

    [AutoNameTestCase('$10912058,False')]
    [AutoNameTestCase('$3000000F,True')]
    [AutoNameTestCase('$F0F0F0FF,True')]
    [AutoNameTestCase('$F0F0F0F8,False')]
    procedure IsRelease(AValue: culong; AExpected: boolean);

    [AutoNameTestCase('$10912058,1.09.18.05.8')]
    [AutoNameTestCase('$3000000F,3.00.00.00.F')]
    [AutoNameTestCase('$F0F0F0CF,15.15.15.12.F')]
    [AutoNameTestCase('$F0F0F0FA,15.15.15.15.A')]
    [AutoNameTestCase('$F0F0F0A0,15.15.15.10.0')]
    procedure AsString(AValue: culong; AExpected: string);

    [AutoNameTestCase('$10912058,$10912058')]
    [AutoNameTestCase('$3000000F,$3000000F')]
    [AutoNameTestCase('$3060000F,$3060000F')]
    [AutoNameTestCase('$3250F00F,$3250F00F')]
    [AutoNameTestCase('$F0F0F0FF,$F0F0F0FF')]
    procedure OpImplicitVerInt(AVer, AInt: culong);

    [AutoNameTestCase('$3000000F,$3000000F,True')]
    [AutoNameTestCase('$F0F0F0FF,$F0F0F0FF,True')]
    [AutoNameTestCase('$00000000,$00000000,True')]
    [AutoNameTestCase('$F0F0F0FF,$E0F0F0FF,False')]
    [AutoNameTestCase('$F0F0F0FF,$F1F0F0FF,False')]
    [AutoNameTestCase('$F0F0F0FF,$F0F0E0FF,False')]
    [AutoNameTestCase('$F0F0F0FF,$F0F0F00F,False')]
    [AutoNameTestCase('$F0F0F0FF,$F0F0F0F0,False')]
    procedure OpEqual(AVer1, AVer2: culong; AExpected: boolean);

    [AutoNameTestCase('$3000000F,$3000000F,False')]
    [AutoNameTestCase('$F0F0F0FF,$F0F0F0FF,False')]
    [AutoNameTestCase('$00000000,$00000000,False')]
    [AutoNameTestCase('$F0F0F0FF,$E0F0F0FF,True')]
    [AutoNameTestCase('$F0F0F0FF,$F1F0F0FF,True')]
    [AutoNameTestCase('$F0F0F0FF,$F0F0E0FF,True')]
    [AutoNameTestCase('$F0F0F0FF,$F0F0F00F,True')]
    [AutoNameTestCase('$F0F0F0FF,$F0F0F0F0,True')]
    procedure OpNotEqual(AVer1, AVer2: culong; AExpected: boolean);

    [AutoNameTestCase('$3000000F,$3000000E,True')]
    [AutoNameTestCase('$3000000F,$3000000F,False')]
    [AutoNameTestCase('$3000000E,$3000000F,False')]
    procedure OpGreaterThan(AVer1, AVer2: culong; AExpected: boolean);

    [AutoNameTestCase('$3000000F,$3000000E,True')]
    [AutoNameTestCase('$3000000F,$3000000F,True')]
    [AutoNameTestCase('$3000000E,$3000000F,False')]
    procedure OpGreaterThanOrEqual(AVer1, AVer2: culong; AExpected: boolean);

    [AutoNameTestCase('$3000000E,$3000000F,True')]
    [AutoNameTestCase('$3000000F,$3000000F,False')]
    [AutoNameTestCase('$3000000F,$3000000E,False')]
    procedure OpLessThan(AVer1, AVer2: culong; AExpected: boolean);

    [AutoNameTestCase('$3000000E,$3000000F,True')]
    [AutoNameTestCase('$3000000F,$3000000F,True')]
    [AutoNameTestCase('$3000000F,$3000000E,False')]
    procedure OpLessThanOrEqual(AVer1, AVer2: culong; AExpected: boolean);

    [AutoNameTestCase('$10912058,$10912058,True')]
    [AutoNameTestCase('$10912058,$1091205F,True')]
    [AutoNameTestCase('$10912058,$1090000F,True')]
    [AutoNameTestCase('$3000000F,$1090000F,False')]
    [AutoNameTestCase('$3060000F,$3050000F,False')]
    [AutoNameTestCase('$3060000F,$3070000F,False')]
    procedure AreCompatibleVer(AVer1, AVer2: culong; AExpected: boolean);

    [AutoNameTestCase('$10912058,$10912058,True')]
    [AutoNameTestCase('$10912058,$1091205F,True')]
    [AutoNameTestCase('$10912058,$1090000F,True')]
    [AutoNameTestCase('$3000000F,$1090000F,False')]
    [AutoNameTestCase('$3060000F,$3050000F,False')]
    [AutoNameTestCase('$3060000F,$3070000F,False')]
    procedure AreCompatibleVerInt(AVer, AInt: culong; AExpected: boolean);
  end;

implementation

uses
  OSsl4Pas.ResStrings;

{ TOsslVersionFixture }

{$REGION 'TOsslVersionFixture support methods'}

class function TOsslVersionFixture.GetMajor(AValue: culong): byte;
begin
  Result:=(AValue and $F0000000) shr 28;
end;

class function TOsslVersionFixture.GetMinor(AValue: culong): byte;
begin
  Result:=(AValue and $0FF00000) shr 20;
end;

class function TOsslVersionFixture.GetFix(AValue: culong): byte;
begin
  Result:=(AValue and $000FF000) shr 12;
end;

class function TOsslVersionFixture.GetPatch(AValue: culong): byte;
begin
  Result:=(AValue and $00000FF0) shr 4;
end;

class function TOsslVersionFixture.GetStatus(AValue: culong): byte;
begin
  Result:=(AValue and $0000000F);
end;

{$ENDREGION 'TOsslVersionFixture support methods'}

procedure TOsslVersionFixture.CreateFromInt(AValue: culong; AMajor, AMinor,
  AFix, APatch, AStatus: cuint8);
begin
  var lVer:=TOsslVersion.Create(AValue);
  Assert.AreEqual(AMajor, lVer.Major, 'Major version mismatch.');
  Assert.AreEqual(AMinor, lVer.Minor, 'Minor version mismatch.');
  Assert.AreEqual(AFix, lVer.Fix, 'Fix version mismatch.');
  Assert.AreEqual(APatch, lVer.Patch, 'Patch version mismatch.');
  Assert.AreEqual(AStatus, lVer.Status, 'Status version mismatch.');
end;

procedure TOsslVersionFixture.CreateFromParts(AMajor, AMinor, AFix, APatch,
  AStatus: cuint8; AExpected: culong);
begin
  var lVer:=TOsslVersion.Create(AMajor, AMinor, AFix, APatch, AStatus);
  Assert.AreEqual<culong>(AExpected, lVer, 'Values mismatch.');
  Assert.AreEqual<culong>(AExpected, lVer.Version, 'Vesrion property mismatch.');
end;

procedure TOsslVersionFixture.IsRelease(AValue: culong; AExpected: boolean);
begin
  var lVer:=TOsslVersion.Create(AValue);
  Assert.AreEqual(AExpected, lVer.IsRelease, 'Release status is not equal to expected.')
end;

procedure TOsslVersionFixture.AsString(AValue: culong; AExpected: string);
begin
  var lVer:=TOsslVersion.Create(AValue);
  Assert.AreEqual(AExpected, lVer.AsString, False, 'Version string mismatch.');
end;

procedure TOsslVersionFixture.OpImplicitVerInt(AVer, AInt: culong);
begin
  begin
    var lVer:=TOsslVersion.Create(AVer);
    var lInt: culong:=lVer;
    Assert.AreEqual<cuint>(AInt, lInt, 'Implicit cast TOsslVersion -> culong failed.');
  end;
  begin
    var lVer: TOsslVersion:=AVer;
    Assert.AreEqual(AInt, lVer.Version, 'Implicit cast culong -> TOsslVersion failed.');
  end;
end;

procedure TOsslVersionFixture.OpEqual(AVer1, AVer2: culong; AExpected: boolean);
begin
  var lVer1:=TOsslVersion.Create(AVer1);
  var lVer2:=TOsslVersion.Create(AVer2);
  Assert.AreEqual(lVer1 = lVer2, AExpected,
    Format('Equality comparision "%s" and "%s" failed.',
    [lVer1.AsString, lVer2.AsString])
  );
end;

procedure TOsslVersionFixture.OpNotEqual(AVer1, AVer2: culong;
  AExpected: boolean);
begin
  var lVer1:=TOsslVersion.Create(AVer1);
  var lVer2:=TOsslVersion.Create(AVer2);
  Assert.AreEqual(lVer1 <> lVer2, AExpected,
    Format('Non-Equality comparision "%s" and "%s" failed.',
    [lVer1.AsString, lVer2.AsString])
  );
end;

procedure TOsslVersionFixture.OpGreaterThan(AVer1, AVer2: culong;
  AExpected: boolean);
begin
  var lVer1:=TOsslVersion.Create(AVer1);
  var lVer2:=TOsslVersion.Create(AVer2);
  Assert.AreEqual(lVer1 > lVer2, AExpected,
    Format('Comparision "%s" > "%s" failed.',
    [lVer1.AsString, lVer2.AsString])
  );
end;

procedure TOsslVersionFixture.OpGreaterThanOrEqual(AVer1, AVer2: culong;
  AExpected: boolean);
begin
  var lVer1:=TOsslVersion.Create(AVer1);
  var lVer2:=TOsslVersion.Create(AVer2);
  Assert.AreEqual(lVer1 >= lVer2, AExpected,
    Format('Comparision "%s" >= "%s" failed.',
    [lVer1.AsString, lVer2.AsString])
  );
end;

procedure TOsslVersionFixture.OpLessThan(AVer1, AVer2: culong;
  AExpected: boolean);
begin
  var lVer1:=TOsslVersion.Create(AVer1);
  var lVer2:=TOsslVersion.Create(AVer2);
  Assert.AreEqual(lVer1 < lVer2, AExpected,
    Format('Comparision "%s" < "%s" failed.',
    [lVer1.AsString, lVer2.AsString])
  );
end;

procedure TOsslVersionFixture.OpLessThanOrEqual(AVer1, AVer2: culong;
  AExpected: boolean);
begin
  var lVer1:=TOsslVersion.Create(AVer1);
  var lVer2:=TOsslVersion.Create(AVer2);
  Assert.AreEqual(lVer1 <= lVer2, AExpected,
    Format('Comparision "%s" <= "%s" failed.',
    [lVer1.AsString, lVer2.AsString])
  );
end;

procedure TOsslVersionFixture.AreCompatibleVer(AVer1, AVer2: culong;
  AExpected: boolean);
begin
  var lVer1:=TOsslVersion.Create(AVer1);
  var lVer2:=TOsslVersion.Create(AVer2);
  Assert.AreEqual(lVer1.AreCompatible(AVer2), AExpected,
    Format('Version compatibility "%s" and "%s" failed.',
    [lVer1.AsString, lVer2.AsString])
  );
end;

procedure TOsslVersionFixture.AreCompatibleVerInt(AVer, AInt: culong;
  AExpected: boolean);
begin
  var lVer:=TOsslVersion.Create(AVer);
  Assert.AreEqual(lVer.AreCompatible(AInt), AExpected,
    Format('Version compatibility "%s" and "%x" failed.',
    [lVer.AsString, AInt])
  );
end;

initialization
  TDUnitX.RegisterTestFixture(TOsslVersionFixture);

end.
