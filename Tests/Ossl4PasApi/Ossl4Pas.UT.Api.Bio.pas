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

unit Ossl4Pas.UT.Api.Bio;

interface

uses
  System.SysUtils,
  System.Classes,
  System.IOUtils,
  System.Rtti,
  DUnitX.TestFramework,
  Ossl4Pas.UT.Utils,
  Ossl4Pas.UT.CustomFixtures,
  Ossl4Pas.Types,
  Ossl4Pas.CTypes,
  Ossl4Pas.Api.Types,
  Ossl4Pas.Api.Bio,
  Ossl4Pas.Loader;

type
  [TestFixture]
  TOsslApiCustomFixture = class(TCustomFixture)
  protected
    procedure LoadOsslLib(APaths, ALibPathSuffix: string); overload;
    procedure LoadOsslLib(ALibPathSuffix: string); overload;
    procedure UnloadOsslLib;
    function GetLibVersion(ALibType: TLibType): TOsslVersion;
  public
    [TearDown]
    procedure TearDown;

    [TearDownFixture]
    procedure TearDownFixture;

    property LibVersion[ALibType: TLibType]: TOsslVersion read GetLibVersion;

  end;

type
  TBIOMethodEnum = (mtsFile, mtsMem, mtsSecMem, mtsSocket, mtsConnect, mtsAccept,
                    mtsFD, mtsLog, mtsBio, mtsNull, mtsCore, mtsDGram,
                    mtsDGramSctp, mtsDGramPair, mtfNull, mtfBuffer, mtfReadBuf,
                    mtbLineBuf, mtfNBioTest, mtfPreffix);

  TBIOMethodEnumHelper = record helper for TBIOMethodEnum
    function MethodName: string;
    function MethodClass: TOsslApiBioMethodClass;
    function MinVersion: TOsslVersion;
  end;

  TOsslMethodRec = record
    Name: string;
    ClassType: TOsslApiBioMethodClass;
    MinVer: culong;
    procedure CheckMethod(AVer: TOsslVersion; ANullExpected: boolean);
  end;

const
  cMethods: array[TBIOMethodEnum] of TOsslMethodRec = (
    (Name: 'BIO_s_file'; ClassType: TOsslApiBioMethodFile; MinVer: 0),
    (Name: 'BIO_s_mem'; ClassType: TOsslApiBioMethodMem; MinVer: 0),
    (Name: 'BIO_s_secmem'; ClassType: TOsslApiBioMethodSecMem; MinVer: 0),
    (Name: 'BIO_s_socket'; ClassType: TOsslApiBioMethodSocket; MinVer: 0),
    (Name: 'BIO_s_connect'; ClassType: TOsslApiBioMethodConnect; MinVer: 0),
    (Name: 'BIO_s_accept'; ClassType: TOsslApiBioMethodAccept; MinVer: 0),
    (Name: 'BIO_s_fd'; ClassType: TOsslApiBioMethodFd; MinVer: 0),
    (Name: 'BIO_s_log'; ClassType: TOsslApiBioMethodLog; MinVer: 0),
    (Name: 'BIO_s_bio'; ClassType: TOsslApiBioMethodBio; MinVer: 0),
    (Name: 'BIO_s_null'; ClassType: TOsslApiBioMethodNull; MinVer: 0),
    (Name: 'BIO_s_core'; ClassType: TOsslApiBioMethodCore; MinVer: 0),
    (Name: 'BIO_s_datagram'; ClassType: TOsslApiBioMethodDatagram; MinVer: 0),
    (Name: 'BIO_s_datagram_sctp'; ClassType: TOsslApiBioMethodDatagramSctp; MinVer: 0),
    (Name: 'BIO_s_dgram_pair'; ClassType: TOsslApiBioMethodDatagramPair; MinVer: $30200000), // OpenSSL 3.2+
    (Name: 'BIO_f_null'; ClassType: TOsslApiBioFilterNull; MinVer: 0),
    (Name: 'BIO_f_buffer'; ClassType: TOsslApiBioFilterBuffer; MinVer: 0),
    (Name: 'BIO_f_readbuffer'; ClassType: TOsslApiBioFilterReadBuffer; MinVer: 0),
    (Name: 'BIO_f_linebuffer'; ClassType: TOsslApiBioFilterLineBuffer; MinVer: 0),
    (Name: 'BIO_f_nbio_test'; ClassType: TOsslApiBioFilterNbioTest; MinVer: 0),
    (Name: 'BIO_f_prefix'; ClassType: TOsslApiBioFilterPrefix; MinVer: 0)
  );

type
  [TestFixture]
  TOsslApiBioMethodFixture = class(TOsslApiCustomFixture)
  public
    [AutoNameTestCase('mtsFile,3.0,False')]
    [AutoNameTestCase('mtsFile,3.6,False')]
    [AutoNameTestCase('mtsMem,3.0,False')]
    [AutoNameTestCase('mtsMem,3.6,False')]
    [AutoNameTestCase('mtsSecMem,3.0,False')]
    [AutoNameTestCase('mtsSecMem,3.6,False')]
    [AutoNameTestCase('mtsSocket,3.0,False')]
    [AutoNameTestCase('mtsSocket,3.6,False')]
    [AutoNameTestCase('mtsConnect,3.0,False')]
    [AutoNameTestCase('mtsConnect,3.6,False')]
    [AutoNameTestCase('mtsAccept,3.0,False')]
    [AutoNameTestCase('mtsAccept,3.6,False')]
    [AutoNameTestCase('mtsFD,3.0,False')]
    [AutoNameTestCase('mtsFD,3.6,False')]
{$IFDEF MSWINDOWS}
    [AutoNameTestCase('mtsLog,3.0,True')]
    [AutoNameTestCase('mtsLog,3.6,True')]
{$ELSE}
    [AutoNameTestCase('mtsLog,3.0,False')]
    [AutoNameTestCase('mtsLog,3.6,False')]
{$ENDIF}
    [AutoNameTestCase('mtsBio,3.0,False')]
    [AutoNameTestCase('mtsBio,3.6,False')]
    [AutoNameTestCase('mtsNull,3.0,False')]
    [AutoNameTestCase('mtsNull,3.6,False')]
    [AutoNameTestCase('mtsCore,3.0,False')]
    [AutoNameTestCase('mtsCore,3.6,False')]
    [AutoNameTestCase('mtsDGram,3.0,False')]
    [AutoNameTestCase('mtsDGram,3.6,False')]
{$IFDEF LINUX}
    // this method is available only in Linux
    [AutoNameTestCase('mtsDGramSctp,3.0,False')]
    [AutoNameTestCase('mtsDGramSctp,3.6,False')]
{$ENDIF}
    [AutoNameTestCase('mtsDGramPair,3.0,True')]
    [AutoNameTestCase('mtsDGramPair,3.2,False')]
    [AutoNameTestCase('mtsDGramPair,3.6,False')]
    [AutoNameTestCase('mtfNull,3.0,False')]
    [AutoNameTestCase('mtfNull,3.6,False')]
    [AutoNameTestCase('mtfBuffer,3.0,False')]
    [AutoNameTestCase('mtfBuffer,3.6,False')]
    [AutoNameTestCase('mtfReadBuf,3.0,False')]
    [AutoNameTestCase('mtfReadBuf,3.6,False')]
    [AutoNameTestCase('mtbLineBuf,3.0,False')]
    [AutoNameTestCase('mtbLineBuf,3.6,False')]
    [AutoNameTestCase('mtfNBioTest,3.0,False')]
    [AutoNameTestCase('mtfNBioTest,3.6,False')]
    [AutoNameTestCase('mtfPreffix,3.0,False')]
    [AutoNameTestCase('mtfPreffix,3.6,False')]
    procedure Method(AMethod: TBIOMethodEnum; ALibPathSuffix: string;
      ANullExpected: boolean = False);
  end;

  [TestFixture]
  TOsslApiBioLifecycleFixture = class(TOsslApiCustomFixture)
  public
    [Test]
    [AutoNameTestCase('mtsMem,3.0')]
    [AutoNameTestCase('mtsNull,3.0')]
    [AutoNameTestCase('mtsSocket,3.0')]
    // Just creation, no connection
    procedure Test_Cycle(AMethod: TBIOMethodEnum; ALibPathSuffix: string);

    [Test]
    [AutoNameTestCase('3.0')]
    [AutoNameTestCase('3.2')]
    [AutoNameTestCase('3.6')]
    // Just creation, no connection
    procedure Test_RefCounting(ALibPathSuffix: string);
  end;

  [TestFixture]
  TOsslApiBioBaseFixture = class(TOsslApiCustomFixture)
  public
  end;

implementation

{ TBIOMethodEnumHelper }

function TBIOMethodEnumHelper.MethodClass: TOsslApiBioMethodClass;
begin
  Result:=cMethods[Self].ClassType;
end;

function TBIOMethodEnumHelper.MethodName: string;
begin
  Result:=cMethods[Self].Name;
end;

function TBIOMethodEnumHelper.MinVersion: TOsslVersion;
begin
  Result:=TOsslVersion.Create(cMethods[Self].MinVer);
end;

{ TOsslApiBioMethodFixture.TOsslMethod }

procedure TOsslMethodRec.CheckMethod(AVer: TOsslVersion;
  ANullExpected: boolean);
begin
  var lErrStr:=Format('OpenSsl routine "%s" (class ''%s'').',
    [Name, ClassType.ClassName]);
  if ANullExpected then
    Assert.IsNull(ClassType.GetMethodHandle, lErrStr)
  else
    Assert.IsNotNull(ClassType.GetMethodHandle, lErrStr);
end;

{ TOsslApiCustomFixture }

function TOsslApiCustomFixture.GetLibVersion(ALibType: TLibType): TOsslVersion;
begin
  Assert.IsTrue(TOsslLoader.IsLibLoaded[ALibType],
    Format('OpenSsl library "%s" is not loaded', [TOsslLoader.LibName[ALibType]]));
  Result:=TOsslLoader.LibVersion[ALibType];
end;

procedure TOsslApiCustomFixture.LoadOsslLib(ALibPathSuffix: string);
begin
  LoadOsslLib(TOsslLibPathConfig.OsslLibPath, ALibPathSuffix);
end;

procedure TOsslApiCustomFixture.TearDown;
begin
  TOsslLoader.Unload([ltCrypto]);
  TOsslLoader.ResetSingleton;
end;

procedure TOsslApiCustomFixture.TearDownFixture;
begin
  TOsslLoader.Unload([ltCrypto]);
  TOsslLoader.ResetSingleton;
end;

procedure TOsslApiCustomFixture.LoadOsslLib(APaths, ALibPathSuffix: string);
begin
  TOsslLoader.Flags:=TOsslLoader.Flags+[lfStrictPath];
  if not APaths.IsEmpty then
  begin
    var lPaths: TStringList:=nil;
    try
      {$IFDEF MSWINDOWS}
      lPaths:=TStringList.Create(dupIgnore, False, False);
      {$ELSE}
      lPaths:=TStringList.Create(dupIgnore, False, True);
      {$ENDIF}
      lPaths.Delimiter:=TPath.PathSeparator;
      lPaths.DelimitedText:=APaths;
      for var i:=0 to lPaths.Count-1 do
        lPaths[i]:=TPath.Combine(lPaths[i], ALibPathSuffix);
      APaths:=lPaths.DelimitedText;
    finally
      lPaths.Free;
    end;
  end;
  TOsslLoader.Load([ltCrypto], APaths);
  Assert.IsTrue(TOsslLoader.IsLibLoaded[ltCrypto], 'LibCrypto fails to load.')
end;

procedure TOsslApiCustomFixture.UnloadOsslLib;
begin
  TOsslLoader.Unload([ltCrypto]);
end;

{ TOsslApiBioMethodFixture }

procedure TOsslApiBioMethodFixture.Method(AMethod: TBIOMethodEnum;
  ALibPathSuffix: string; ANullExpected: boolean);
begin
  LoadOsslLib(ALibPathSuffix);
  cMethods[AMethod].CheckMethod(LibVersion[ltCrypto], ANullExpected);
end;

{ TOsslApiBioLifecycleFixture }

procedure TOsslApiBioLifecycleFixture.Test_Cycle(AMethod: TBIOMethodEnum;
  ALibPathSuffix: string);
begin
  LoadOsslLib(ALibPathSuffix);

  var lMethod:=AMethod.MethodClass.GetMethodHandle;
  Assert.IsNotNull(lMethod, 'BIO Method factory returned nil');

  // 2. Create (BIO_new binding check)
  var lBio:=TOsslApiBioBase.BIO_new(lMethod);
  Assert.IsNotNull(lBio, 'BIO_new returned nil');

  try
    // 3. Basic usage check (optional, proves the object is valid)
    // Writing 0 bytes should generally be safe and return 0 or -1 depending on type
    // This confirms the VMT inside the C structure is valid.
    if AMethod <> mtsNull then
    begin
      // Just a sanity check that we can call a method on the instance
      TOsslApiBioBase.BIO_pending(lBio);
    end;

  finally
    // 4. Free (BIO_free binding check)
    var lRet: cint:=TOsslApiBioBase.BIO_free(lBio);
    // BIO_free returns 1 on success, 0 on failure
    Assert.AreEqual<cint>(1, lRet, 'BIO_free failed');
  end;
end;

procedure TOsslApiBioLifecycleFixture.Test_RefCounting(ALibPathSuffix: string);
begin
  LoadOsslLib(ALibPathSuffix);

  // 1. Get Method (Factory binding check)
  var lMethod:=TOsslApiBioMethodMem.BIO_s_mem;
  var lBio:=TOsslApiBioBase.BIO_new(lMethod);
  Assert.IsNotNull(lBio);

  // Ref Count is 1
  // UpRef -> Ref Count 2
  Assert.AreEqual<cint>(1, TOsslApiBioBase.BIO_up_ref(lBio), 'UpRef should return 1 (True)');

  // Free -> Ref Count 1 (Object still alive)
  Assert.AreEqual<cint>(1, TOsslApiBioBase.BIO_free(lBio), 'First free should succeed');

  // Real Free -> Ref Count 0 (Object destroyed)
  Assert.AreEqual<cint>(1, TOsslApiBioBase.BIO_free(lBio), 'Second free should succeed');
end;

initialization
  TDUnitX.RegisterTestFixture(TOsslApiBioMethodFixture);
  TDUnitX.RegisterTestFixture(TOsslApiBioLifecycleFixture);
  //  TDUnitX.RegisterTestFixture(TOsslApiBioBaseFixture);

end.
