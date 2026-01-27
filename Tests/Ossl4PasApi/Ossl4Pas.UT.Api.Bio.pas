unit Ossl4Pas.UT.Api.Bio;

interface

uses
  System.SysUtils,
  System.Classes,
  System.IOUtils,
  System.Rtti,
  DUnitX.TestFramework,
  Ossl4Pas.UT.Utils,
  Ossl4Pas.Types,
  Ossl4Pas.CTypes,
  Ossl4Pas.Api.Bio,
  Ossl4Pas.Loader;

type
  [TestFixture]
  TOsslApiCustomFixture = class
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

 TOsslApiBioMethodFixture = class(TOsslApiCustomFixture)
 protected type
  TOsslMethod = record
    Name: string;
    ClassType: TOsslApiBioMethodClass;
    MinVer: culong;
    procedure CheckMethod(AVer: TOsslVersion; ANullExpected: boolean);
  end;

 const
cMethods: array[0..19] of TOsslMethod = (
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

 public
    [AutoNameTestCase('BIO_s_file,3.0,False')]
    [AutoNameTestCase('BIO_s_file,3.6,False')]
    [AutoNameTestCase('BIO_s_mem,3.0,False')]
    [AutoNameTestCase('BIO_s_mem,3.6,False')]
    [AutoNameTestCase('BIO_s_secmem,3.0,False')]
    [AutoNameTestCase('BIO_s_secmem,3.6,False')]
    [AutoNameTestCase('BIO_s_socket,3.0,False')]
    [AutoNameTestCase('BIO_s_socket,3.6,False')]
    [AutoNameTestCase('BIO_s_connect,3.0,False')]
    [AutoNameTestCase('BIO_s_connect,3.6,False')]
    [AutoNameTestCase('BIO_s_accept,3.0,False')]
    [AutoNameTestCase('BIO_s_accept,3.6,False')]
    [AutoNameTestCase('BIO_s_fd,3.0,False')]
    [AutoNameTestCase('BIO_s_fd,3.6,False')]
    [AutoNameTestCase('BIO_s_log,3.0,False')]
{$IFDEF MSWINDOWS}
    [AutoNameTestCase('BIO_s_log,3.6,True')]
{$ENDIF}
{$IFDEF POSIX}
    // This method always return "null" in latest OpenSsl versions
    [AutoNameTestCase('BIO_s_log,3.6,False')]
{$ENDIF}
    [AutoNameTestCase('BIO_s_bio,3.0,False')]
    [AutoNameTestCase('BIO_s_bio,3.6,False')]
    [AutoNameTestCase('BIO_s_null,3.0,False')]
    [AutoNameTestCase('BIO_s_null,3.6,False')]
    [AutoNameTestCase('BIO_s_core,3.0,False')]
    [AutoNameTestCase('BIO_s_core,3.6,False')]
    [AutoNameTestCase('BIO_s_datagram,3.0,False')]
    [AutoNameTestCase('BIO_s_datagram,3.6,False')]
{$IFDEF POSIX}
    // this method is not available for Windows
    [AutoNameTestCase('BIO_s_datagram_sctp,3.0,False')]
    [AutoNameTestCase('BIO_s_datagram_sctp,3.6,False')]
{$ENDIF}
    [AutoNameTestCase('BIO_s_dgram_pair,3.0,True')]
    [AutoNameTestCase('BIO_s_dgram_pair,3.2,False')]
    [AutoNameTestCase('BIO_s_dgram_pair,3.6,False')]
    [AutoNameTestCase('BIO_f_null,3.0,False')]
    [AutoNameTestCase('BIO_f_null,3.6,False')]
    [AutoNameTestCase('BIO_f_buffer,3.0,False')]
    [AutoNameTestCase('BIO_f_buffer,3.6,False')]
    [AutoNameTestCase('BIO_f_readbuffer,3.0,False')]
    [AutoNameTestCase('BIO_f_readbuffer,3.6,False')]
    [AutoNameTestCase('BIO_f_linebuffer,3.0,False')]
    [AutoNameTestCase('BIO_f_linebuffer,3.6,False')]
    [AutoNameTestCase('BIO_f_nbio_test,3.0,False')]
    [AutoNameTestCase('BIO_f_nbio_test,3.6,False')]
    [AutoNameTestCase('BIO_f_prefix,3.0,False')]
    [AutoNameTestCase('BIO_f_prefix,3.6,False')]
    procedure Method(AMethodName, ALibPathSuffix: string;
      ANullExpected: boolean = False);
 end;

 TOsslApiBioBaseFixture = class(TOsslApiCustomFixture)
 public
 end;

implementation

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
    TOsslLoader.Load([ltCrypto], APaths);
    Assert.IsTrue(TOsslLoader.IsLibLoaded[ltCrypto], 'LibCrypto fails to load.')
  end;
end;

procedure TOsslApiCustomFixture.UnloadOsslLib;
begin
  TOsslLoader.Unload([ltCrypto]);
end;

{ TOsslApiBioMethodFixture.TOsslMethod }

procedure TOsslApiBioMethodFixture.TOsslMethod.CheckMethod(AVer: TOsslVersion;
  ANullExpected: boolean);
begin
  var lErrStr:=Format('OpenSsl routine "%s" (class ''%s'').',
    [Name, ClassType.ClassName]);
  if ANullExpected then
    Assert.IsNull(ClassType.GetMethodHandle, lErrStr)
  else
    Assert.IsNotNull(ClassType.GetMethodHandle, lErrStr);
end;

{ TOsslApiBioMethodFixture }

procedure TOsslApiBioMethodFixture.Method(AMethodName, ALibPathSuffix: string;
  ANullExpected: boolean);
begin
  var lMethodIdx: integer := -1;
  LoadOsslLib(ALibPathSuffix);
  for var i := Low(cMethods) to High(cMethods) do
    if SameText(AMethodName, cMethods[i].Name) then
    begin
      lMethodIdx:=i;
      break
    end;
  Assert. AreNotEqual(-1, lMethodIdx,
    Format('Method "%s" not found.', [AMethodName]));
  cMethods[lMethodIdx].CheckMethod(LibVersion[ltCrypto], ANullExpected);
end;

initialization
  TDUnitX.RegisterTestFixture(TOsslApiBioMethodFixture);
//  TDUnitX.RegisterTestFixture(TOsslApiBioBaseFixture);

end.
