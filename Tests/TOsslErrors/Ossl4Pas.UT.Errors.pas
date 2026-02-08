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

unit Ossl4Pas.UT.Errors;

interface

uses
  System.SysUtils,
  Ossl4Pas.CTypes,
  Ossl4Pas.Types,
  Ossl4Pas.Loader,
  Ossl4Pas.Api.Err, // Constants
  Ossl4Pas.Err,     // UUT
  Ossl4Pas.UT.Consts,
  DUnitX.TestFramework,
  Ossl4Pas.UT.CustomFixtures;

type
  [TestFixture]
  TOsslErrCodeFixture = class
  public
    // -------------------------------------------------------------------------
    // 1. Library Extraction Tests
    // -------------------------------------------------------------------------

    // Valid Libraries (OpenSSL 3.0)
    [TestCase('Lib_None',   '1,olcNone')]
    [TestCase('Lib_EVP',    '6,olcEvp')]
    [TestCase('Lib_ASN1',   '13,olcAsn1')] // Corrected from 12
    [TestCase('Lib_SSL',    '20,olcSsl')]
    [TestCase('Lib_BIO',    '32,olcBio')]
    [TestCase('Lib_HTTP',   '61,olcHttp')]
    [TestCase('Lib_USER',   '128,olcUser')]

    // Gaps / Unknowns (Should map to olcUnknown = 0)
    [TestCase('Lib_Zero',   '0,olcUnknown')]
    [TestCase('Lib_Gap12',  '12,olcUnknown')] // Old ERR_LIB_METH
    [TestCase('Lib_Gap18',  '18,olcUnknown')]
    [TestCase('Lib_Gap25',  '25,olcUnknown')]
    [TestCase('Lib_High',   '250,olcUnknown')]
    procedure Test_GetLib(ALibVal: integer; AExpected: TOsslLibCode);

    // -------------------------------------------------------------------------
    // 2. Reason & Flags Tests
    // -------------------------------------------------------------------------

    [Test]
    procedure Test_GetReason_Simple;

    [Test]
    procedure Test_GetReason_WithSystemFlag;

    [Test]
    procedure Test_IsFatal;

    [Test]
    procedure Test_IsSystem;

    [Test]
    procedure Test_ReasonFlags_Extraction;

    [Test]
    procedure Test_ImplicitConversion;
  end;

  [TestFixture]
  TOsslErrFixture = class(TCustomMockLoadFixture)
  const
    cLibVer = $3000000F; // mock lib to reprorts this version

  private type
    // Signatures for Mock Control Functions
    TMock_Err_Push = procedure(AErrCode: culong; AFileName, AFuncName, AData: PAnsiChar;
      ALine, AFlags: cint); cdecl;
    TMock_Err_Clear = procedure; cdecl;

  private class var
    FMockPush: TMock_Err_Push;
    FMockClear: TMock_Err_Clear;

  private
    class procedure DoBind(const ALibHandle: TLibHandle;
      const AVersion: TOsslVersion); static;
    class procedure DoUnbind; static;

  protected
    class procedure Reset; override;
    procedure CheckMockManagement;
    procedure PushMockError(Lib: Integer; Reason: Integer;
      const File_, Func, Data: string; Line: Integer; Flags: Integer);

  public
    destructor Destroy; override;

    [SetupFixture]
    procedure SetupFixture;

    [TearDownFixture]
    procedure TearDownFixture;

    // -------------------------------------------------------------------------
    // API Layer Tests
    // -------------------------------------------------------------------------
    [Test]
    procedure Test_Api_GetError_Simple;

    [Test]
    procedure Test_Api_PeekError;

    [Test]
    procedure Test_Api_ErrorString;

    // -------------------------------------------------------------------------
    // Framework Layer Tests (EOsslCustomError)
    // -------------------------------------------------------------------------
    [Test]
    procedure Test_Exception_EmptyStack;

    [Test]
    procedure Test_Exception_SingleError;

    [Test]
    procedure Test_Exception_MultiStack;

    [Test]
    procedure Test_Exception_Formatting;
  end;

implementation

{ TOsslErrCodeHelperFixture }

procedure TOsslErrCodeFixture.Test_GetLib(ALibVal: integer; AExpected: TOsslLibCode);
var
  lCode: TOsslErrCode;
  lRaw: culong;
begin
  // Construct raw code: (Lib << 23)
  // We assume Reason is 0 for this test.
  lRaw:=(culong(ALibVal) and ERR_LIB_MASK) shl ERR_LIB_OFFSET;

  lCode:=TOsslErrCode(lRaw);

  Assert.AreEqual(ALibVal, integer(lCode.LibRaw), 'Raw Lib ID extraction failed');
  Assert.AreEqual(AExpected, lCode.Lib, 'Enum mapping failed');
end;

procedure TOsslErrCodeFixture.Test_GetReason_Simple;
var
  lCode: TOsslErrCode;
  lRaw: culong;
begin
  // Reason is the lower 23 bits.
  // Test value: 123 (random reason)
  lRaw:=123;

  // Add a Library ID (SSL=20) to ensure masking works
  lRaw:=lRaw or (20 shl ERR_LIB_OFFSET);

  lCode:=TOsslErrCode(lRaw);

  Assert.AreEqual(123, integer(lCode.Reason), 'Reason extraction failed');
end;

procedure TOsslErrCodeFixture.Test_GetReason_WithSystemFlag;
var
  lCode: TOsslErrCode;
begin
  // If ERR_SYSTEM_FLAG (Bit 31) is set, OpenSSL macros say:
  // ERR_GET_REASON(l) = (l & ERR_SYSTEM_MASK)
  // ERR_SYSTEM_MASK is 0x7FFFFFFF (everything except bit 31).

  lCode:=TOsslErrCode(ERR_SYSTEM_FLAG or 500);

  Assert.IsTrue(lCode.IsSystem, 'Should be System error');
  Assert.AreEqual(500, integer(lCode.Reason), 'System error code extraction failed');

  // System errors force Lib to ERR_LIB_SYS (2)
  Assert.AreEqual(TOsslLibCode.olcSys, lCode.Lib, 'System error should map to olcSys');
end;

procedure TOsslErrCodeFixture.Test_IsFatal;
var
  lCode: TOsslErrCode;
begin
  // ERR_R_FATAL is defined as a bitmask in the Reason field.
  lCode:=TOsslErrCode(ERR_R_FATAL);

  Assert.IsTrue(lCode.IsFatal, 'Should detect Fatal flag');
  Assert.IsFalse(lCode.IsSystem, 'IsSystem flag should not True.');
end;

procedure TOsslErrCodeFixture.Test_IsSystem;
var
  lCode: TOsslErrCode;
begin
  lCode:=TOsslErrCode(ERR_SYSTEM_FLAG);

  Assert.IsTrue(lCode.IsSystem, 'Should detect System flag');
  Assert.IsFalse(lCode.IsFatal, 'IsFatal should not be True.');
end;

procedure TOsslErrCodeFixture.Test_ReasonFlags_Extraction;
var
  lCode: TOsslErrCode;
  lFlags: TOsslReasonFlags;
begin
  // Construct a code with both Fatal and Common flags.
  // ERR_R_FATAL usually implies both in 3.0 headers: (ERR_RFLAG_FATAL | ERR_RFLAG_COMMON)
  lCode:=TOsslErrCode(ERR_R_FATAL);

  lFlags:=lCode.ReasonFlags;

  Assert.IsTrue(orfFatal in lFlags, 'orfFatal should be set');
  Assert.IsTrue(orfCommon in lFlags, 'orfCommon should be set (implied by ERR_R_FATAL)');
end;

procedure TOsslErrCodeFixture.Test_ImplicitConversion;
var
  lRaw: culong;
  lCode: TOsslErrCode;

begin
  lRaw:=$12345678;

  // Test culong -> TOsslErrCode
  lCode:=TOsslErrCode(lRaw);
  Assert.AreEqual(lRaw, culong(lCode), 'operator `TOsslErrCode.Implicit` failed.');
end;


type
  TTestOsslLoader = class(TOsslLoader)
  public
    class property LibHandle;
  end;


{ TOsslErrFixture }

procedure TOsslErrFixture.SetupFixture;
begin
  inherited;
  MockLibHandler.CheckWorkDir;
  MockLibHandler.SetupMocks(
    MockLibHandler.CheckLibTypes([ltCrypto]), TOsslVersion.Create(cLibVer));

  TTestOsslLoader.RegisterBinding(ltCrypto, @DoBind, @DoUnbind);
  TTestOsslLoader.Load([ltCrypto], MockLibHandler.WorkDir);
  CheckMockManagement;
end;

procedure TOsslErrFixture.TearDownFixture;
begin
  MockLibHandler.LoaderUnloadAll;
  MockLibHandler.CleanUpAllMocks;
  MockLibHandler.CleanWorkDir;
end;

destructor TOsslErrFixture.Destroy;
begin
  inherited Reset;
  inherited;
end;

class procedure TOsslErrFixture.DoBind(const ALibHandle: TLibHandle;
  const AVersion: TOsslVersion);
begin
  @FMockPush:=ALibHandle.ProcAddress['Mock_Err_Push'];
  @FMockClear:=ALibHandle.ProcAddress['Mock_Err_Clear'];
end;

class procedure TOsslErrFixture.DoUnbind;
begin
  @FMockPush:=nil;
  @FMockClear:=nil;
end;

procedure TOsslErrFixture.CheckMockManagement;
begin
  Assert.IsNotNull(@FMockPush, 'Mock_Err_Push not found in DLL');
  Assert.IsNotNull(@FMockClear, 'Mock_Err_Clear not found in DLL');
end;

procedure TOsslErrFixture.PushMockError(Lib, Reason: Integer;
  const File_, Func, Data: string; Line: Integer; Flags: Integer);
var
  Code: culong;
begin
  // Construct Code: (Lib << 23) | Reason
  Code := (culong(Lib) shl ERR_LIB_OFFSET) or culong(Reason);

  // Note: PAnsiChar casts are valid here because we pass them to the DLL immediately
  // and the DLL copies them into its internal storage.
  FMockPush(Code, PAnsiChar(AnsiString(File_)), PAnsiChar(AnsiString(Func)),
    PAnsiChar(AnsiString(Data)), Line, Flags);
end;

class procedure TOsslErrFixture.Reset;
begin
// do nothing
end;

// -----------------------------------------------------------------------------
// API Tests
// -----------------------------------------------------------------------------

procedure TOsslErrFixture.Test_Api_GetError_Simple;
begin
  // 1. Push Error
  PushMockError(ERR_LIB_SSL, 100, 'test.c', 'TestFunc', '', 10, 0);

  // 2. Get Error via API
  var Code := TOsslAPIErrCodes.ERR_get_error;

  // 3. Verify
  Assert.AreNotEqual<culong>(0, Code,
    '`TOsslAPIErrCodes.ERR_get_error` returns `0`.');
  Assert.AreEqual(ERR_LIB_SSL, Integer(TOsslErrCode(Code).LibRaw),
    '`TOsslAPIErrCodes.ERR_get_error` returns wrong Library code.');

  // 4. Verify Queue Empty
  Assert.AreEqual<culong>(0, TOsslAPIErrCodes.ERR_get_error,
    'Errors queue is not empty, but should be.');
end;

procedure TOsslErrFixture.Test_Api_PeekError;
begin
  PushMockError(ERR_LIB_BIO, 50, '', '', '', 0, 0);

  // Peek should NOT remove
  Assert.AreNotEqual<culong>(0, TOsslAPIErrCodes.ERR_peek_error,
    '`TOsslAPIErrCodes.ERR_peek_error` should not emove error from the queue.');
  Assert.AreNotEqual<culong>(0, TOsslAPIErrCodes.ERR_peek_error,
    '`TOsslAPIErrCodes.ERR_peek_error` should not emove error from the queue.');

  // Get removes
  Assert.AreNotEqual<culong>(0, TOsslAPIErrCodes.ERR_get_error,
    'No error in queue.');
  Assert.AreEqual<culong>(0, TOsslAPIErrCodes.ERR_get_error,
    'Queue is not empty.');
end;

procedure TOsslErrFixture.Test_Api_ErrorString;
var
  lBuf: array[0..255] of AnsiChar;

begin
  // Helper test
  var lMsg: string:=TOsslAPIErrStrings.GetErrorString($12345678, 256);
  Assert.IsTrue(lMsg.Contains('12345678'), 'Error string should contain hex code');
end;

// -----------------------------------------------------------------------------
// Exception Tests
// -----------------------------------------------------------------------------

type
  EOsslTestError = class(EOsslCustomError)
  public
    property IsErrorStackEmpty;
  end;

procedure TOsslErrFixture.Test_Exception_EmptyStack;
begin
  try
    raise EOsslTestError.Create('Base Message');
  except
    on E: EOsslCustomError do
    begin
      Assert.InheritsFrom(E.ClassType, EOsslCustomError,
        'Exception is not inherited form ''EOsslCustomError''.');
      Assert.AreEqual('Base Message', E.Message, 'Incorrect exception message.');
      Assert.IsTrue(EOsslTestError(E).IsErrorStackEmpty,
        'Error(s) repoerted.');
      Assert.AreEqual<culong>(0, E.LastError,
        '`EOsslCustomError.LastError` returns non-Zero value.');
    end;
  end;
end;

procedure TOsslErrFixture.Test_Exception_SingleError;
begin
  PushMockError(ERR_LIB_EVP, 99, 'evp_lib.c', 'EVP_DecryptFinal', 'Bad Padding', 42, ERR_TXT_STRING);

  try
    raise EOsslTestError.Create('Decryption Failed');
  except
    on E: EOsslCustomError do
    begin
      Assert.InheritsFrom(E.ClassType, EOsslCustomError,
        'Exception is not inherited form ''EOsslCustomError''.');
      Assert.IsFalse(EOsslTestError(E).IsErrorStackEmpty,
        'Exception reports no errors.');
      Assert.AreEqual<NativeInt>(1, EOsslTestError(E).ErrorStack.Count,
        Format('%d errors in Error Stack.',[EOsslTestError(E).ErrorStack.Count]));

      var Entry:=EOsslTestError(E).ErrorStack[0];
      Assert.AreEqual(TOsslLibCode.olcEvp, Entry.ErrCode.Lib,
        'Wrong error code reported.');
      Assert.AreEqual('evp_lib.c', Entry.FileName,
        'Wrong file name reported.');
      Assert.AreEqual('EVP_DecryptFinal', Entry.FuncName,
        'Wrong func name reported.');
      Assert.AreEqual('Bad Padding', Entry.Descript,
        'Wrong error description reported.');

      // Verify Message Composition
      Assert.IsTrue(E.Message.Contains('Decryption Failed'),
        'Wrong Exception message.');
      Assert.IsTrue(E.Message.Contains('Bad Padding'),
        'Wrong Exception message.');
    end;
  end;
end;

procedure TOsslErrFixture.Test_Exception_MultiStack;
begin
  // OpenSSL pushes errors: Deepest/First cause -> ... -> Highest level
  // Queue: [Deepest, Middle, Highest]
  // ERR_get_error returns Deepest first (FIFO)

  // 1. Deepest: Malloc fail
  PushMockError(ERR_LIB_SYS, ERR_R_MALLOC_FAILURE, 'mem.c', 'malloc', '', 10, 0);
  // 2. Middle: BIO fail
  PushMockError(ERR_LIB_BIO, 0, 'bio.c', 'BIO_new', '', 20, 0);
  // 3. High: SSL fail
  PushMockError(ERR_LIB_SSL, 0, 'ssl.c', 'SSL_connect', '', 30, 0);

  try
    raise EOsslTestError.Create('Connection Failed');
  except
    on E: EOsslCustomError do
    begin
      Assert.InheritsFrom(E.ClassType, EOsslCustomError,
        'Exception is not inherited form ''EOsslCustomError''.');
      Assert.AreEqual<NativeInt>(3, EOsslTestError(E).ErrorStack.Count,
        'Incorrect number of error in stack reported.');

      // Stack[0] should be the first error popped (Malloc)
      Assert.AreEqual(TOsslLibCode.olcSys,
        EOsslTestError(E).ErrorStack[0].ErrCode.Lib,
        'Wrong error code reported.');

      // Stack[2] should be the last error (SSL)
      Assert.AreEqual(TOsslLibCode.olcSsl,
        EOsslTestError(E).ErrorStack[2].ErrCode.Lib,
        'Wrong error code reported in last error in the stack.');
    end;
  end;
end;

procedure TOsslErrFixture.Test_Exception_Formatting;
begin
  PushMockError(ERR_LIB_BIO, 5, 'file.c', 'func', 'data', 10, ERR_TXT_STRING);

  try
    raise EOsslCustomError.Create('Error');
  except
    on E: EOsslCustomError do
    begin
      // Test custom formatting flags
      var S := E.ToString([emfLibName, emfDescript]);

      Assert.IsTrue(S.Contains('LibBio'), 'Should contain LibName');
      Assert.IsTrue(S.Contains('data'), 'Should contain Description');
      Assert.IsFalse(S.Contains('file.c'), 'Should NOT contain FileName');
    end;
  end;
end;

initialization
  TDUnitX.RegisterTestFixture(TOsslErrCodeFixture);
  TDUnitX.RegisterTestFixture(TOsslErrFixture);

end.
