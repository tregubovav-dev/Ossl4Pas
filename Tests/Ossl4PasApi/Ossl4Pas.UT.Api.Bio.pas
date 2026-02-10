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
    function GetLibVersion(ALibType: TLibType): TOsslVersion;
  public
    [SetupFixture]
    procedure SetupFixture;

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
  public const
    cAllPlatforms = TDelphiPlatforms.cAllPlatforms;

  public
    Name: string;
    ClassType: TOsslApiBioMethodClass;
    MinVer: culong;
    Platforms: TDelphiPlatforms;
    procedure CheckMethod(AVer: TOsslVersion; ANullExpected: boolean);
    function IsCheckNeeded: boolean;
  end;

const
  cMethods: array[TBIOMethodEnum] of TOsslMethodRec = (
    (Name: 'BIO_s_file'; ClassType: TOsslApiBioMethodFile;
     MinVer: 0; Platforms: TOsslMethodRec.cAllPlatforms),
    (Name: 'BIO_s_mem'; ClassType: TOsslApiBioMethodMem;
     MinVer: 0; Platforms: TOsslMethodRec.cAllPlatforms),
    (Name: 'BIO_s_secmem'; ClassType: TOsslApiBioMethodSecMem;
     MinVer: 0; Platforms: TOsslMethodRec.cAllPlatforms),
    (Name: 'BIO_s_socket'; ClassType: TOsslApiBioMethodSocket;
     MinVer: 0; Platforms: TOsslMethodRec.cAllPlatforms),
    (Name: 'BIO_s_connect'; ClassType: TOsslApiBioMethodConnect;
     MinVer: 0; Platforms: TOsslMethodRec.cAllPlatforms),
    (Name: 'BIO_s_accept'; ClassType: TOsslApiBioMethodAccept;
     MinVer: 0; Platforms: TOsslMethodRec.cAllPlatforms),
    (Name: 'BIO_s_fd'; ClassType: TOsslApiBioMethodFd;
     MinVer: 0; Platforms: TOsslMethodRec.cAllPlatforms),
    (Name: 'BIO_s_log'; ClassType: TOsslApiBioMethodLog;
     MinVer: 0; Platforms: TOsslMethodRec.cAllPlatforms),
    (Name: 'BIO_s_bio'; ClassType: TOsslApiBioMethodBio;
     MinVer: 0; Platforms: TOsslMethodRec.cAllPlatforms),
    (Name: 'BIO_s_null'; ClassType: TOsslApiBioMethodNull;
     MinVer: 0; Platforms: TOsslMethodRec.cAllPlatforms),
    (Name: 'BIO_s_core'; ClassType: TOsslApiBioMethodCore;
     MinVer: 0; Platforms: TOsslMethodRec.cAllPlatforms),
    (Name: 'BIO_s_datagram'; ClassType: TOsslApiBioMethodDatagram;
     MinVer: 0; Platforms: TOsslMethodRec.cAllPlatforms),
    (Name: 'BIO_s_datagram_sctp'; ClassType: TOsslApiBioMethodDatagramSctp;
     MinVer: 0; Platforms: [dpLINUX64]),
    (Name: 'BIO_s_dgram_pair'; ClassType: TOsslApiBioMethodDatagramPair;
     MinVer: $30200000; Platforms: TOsslMethodRec.cAllPlatforms), // OpenSSL 3.2+
    (Name: 'BIO_f_null'; ClassType: TOsslApiBioFilterNull;
     MinVer: 0; Platforms: TOsslMethodRec.cAllPlatforms),
    (Name: 'BIO_f_buffer'; ClassType: TOsslApiBioFilterBuffer;
     MinVer: 0; Platforms: TOsslMethodRec.cAllPlatforms),
    (Name: 'BIO_f_readbuffer'; ClassType: TOsslApiBioFilterReadBuffer;
     MinVer: 0; Platforms: TOsslMethodRec.cAllPlatforms),
    (Name: 'BIO_f_linebuffer'; ClassType: TOsslApiBioFilterLineBuffer;
     MinVer: 0; Platforms: TOsslMethodRec.cAllPlatforms),
    (Name: 'BIO_f_nbio_test'; ClassType: TOsslApiBioFilterNbioTest;
     MinVer: 0; Platforms: TOsslMethodRec.cAllPlatforms),
    (Name: 'BIO_f_prefix'; ClassType: TOsslApiBioFilterPrefix;
     MinVer: 0; Platforms: TOsslMethodRec.cAllPlatforms)
  );

type
  [TestFixture]
  TOsslApiBioMethodFixture = class(TOsslApiCustomFixture)
  public
    [AutoNameTestCase('mtsFile,False')]
    [AutoNameTestCase('mtsMem,False')]
    [AutoNameTestCase('mtsSecMem,False')]
    [AutoNameTestCase('mtsSocket,False')]
    [AutoNameTestCase('mtsConnect,False')]
    [AutoNameTestCase('mtsAccept,False')]
    [AutoNameTestCase('mtsFD,False')]
{$IFDEF MSWINDOWS}
    [AutoNameTestCase('mtsLog,True')]
{$ELSE}
    [AutoNameTestCase('mtsLog,False')]
{$ENDIF}
    [AutoNameTestCase('mtsBio,False')]
    [AutoNameTestCase('mtsNull,False')]
    [AutoNameTestCase('mtsCore,False')]
    [AutoNameTestCase('mtsDGram,False')]
{$IFDEF LINUX}
    // this method is available only in Linux
    [AutoNameTestCase('mtsDGramSctp,False')]
    [AutoNameTestCase('mtsDGramSctp,False')]
{$ENDIF}
    [AutoNameTestCase('mtsDGramPair,False')]
    [AutoNameTestCase('mtfNull,False')]
    [AutoNameTestCase('mtfBuffer,False')]
    [AutoNameTestCase('mtfReadBuf,False')]
    [AutoNameTestCase('mtbLineBuf,False')]
    [AutoNameTestCase('mtfNBioTest,False')]
    [AutoNameTestCase('mtfPreffix,False')]
    procedure Method(AMethod: TBIOMethodEnum; ANullExpected: boolean = False);
  end;

  [TestFixture]
  TOsslApiBioLifecycleFixture = class(TOsslApiCustomFixture)
  public
    [AutoNameTestCase('mtsMem')]
    [AutoNameTestCase('mtsNull')]
    [AutoNameTestCase('mtsSocket')]
    // Just creation, no connection
    procedure Test_Cycle(AMethod: TBIOMethodEnum);

    [Test]
    // Just creation, no connection
    procedure Test_RefCounting;
  end;

  [TestFixture]
  TOsslApiBioBaseFixture = class(TOsslApiCustomFixture)
  public
  end;

implementation

{$IFDEF MSWINDOWS}
uses
  Winapi.WinSock,
  Winapi.Winsock2;
{$ENDIF}

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
  Assert.IsTrue(Platforms.InPlatforms, 'Method does not supported for this platform.');

  var lErrStr:=Format('OpenSsl routine "%s" (class ''%s'').',
    [Name, ClassType.ClassName]);
  if ANullExpected then
    Assert.IsNull(ClassType.GetMethodHandle, lErrStr)
  else
    Assert.IsNotNull(ClassType.GetMethodHandle, lErrStr);
end;

function TOsslMethodRec.IsCheckNeeded: boolean;
begin
  Result:=Platforms.InPlatforms;
end;

{ TOsslApiCustomFixture }

function TOsslApiCustomFixture.GetLibVersion(ALibType: TLibType): TOsslVersion;
begin
  Assert.IsTrue(TOsslLoader.IsLibLoaded[ALibType],
    Format('OpenSsl library "%s" is not loaded', [TOsslLoader.LibName[ALibType]]));
  Result:=TOsslLoader.LibVersion[ALibType];
end;

procedure TOsslApiCustomFixture.SetupFixture;
begin
  TOsslLoader.Flags:=TOsslLoader.Flags+[lfStrictPath];
  TOsslLoader.Load([ltCrypto], TOsslLibPathConfig.OsslLibPath);
  Assert.IsTrue(TOsslLoader.IsLibLoaded[ltCrypto], 'LibCrypto fails to load.')
end;

procedure TOsslApiCustomFixture.TearDownFixture;
begin
  TOsslLoader.Unload([ltCrypto]);
  TOsslLoader.ResetSingleton;
end;

{ TOsslApiBioMethodFixture }

procedure TOsslApiBioMethodFixture.Method(AMethod: TBIOMethodEnum;
  ANullExpected: boolean);
begin
  if not cMethods[AMethod].IsCheckNeeded then
    Exit;

  var lVer:=GetLibVersion(ltCrypto);
  var lMinVer:=cMethods[AMethod].MinVer;

  if not (lVer.AreCompatible(lMinVer) or (lMinVer > lVer)) then
    cMethods[AMethod].CheckMethod(LibVersion[ltCrypto], ANullExpected);
  // Otherwise the method is not supported by LibCrypto. Test pass.
  // Do not use Assert.Pass as it reports a False Positive Memory Leak
end;

{ TOsslApiBioLifecycleFixture }

procedure TOsslApiBioLifecycleFixture.Test_Cycle(AMethod: TBIOMethodEnum);
begin
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

procedure TOsslApiBioLifecycleFixture.Test_RefCounting;
begin
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
