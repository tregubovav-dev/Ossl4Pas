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

unit Ossl4Pas.UT.Loader.Behavior;

interface

uses
  System.SysUtils,
  System.Classes,
  System.SyncObjs,
  DUnitX.TestFramework,
  Ossl4Pas.CTypes,
  Ossl4Pas.Types,
  Ossl4Pas.Loader,
  Ossl4Pas.Mock.Loader,
  Ossl4Pas.UT.CustomFixtures;

type
  [Category('OsslLoader,OsslLoaderBehavior')]
  TOsslCustomLoaderBehaviorFixture = class(TBindCountLoaderFixture)
  public
    [Test]
    procedure SetLoaderClass;

    [Test]
    procedure SingletonInstance;

    [Test]
    procedure GetLoaderGenericPositive;

    [Test]
    procedure GetLoaderGenericNegative;

    [Test]
    procedure RegisterBindAndLoadCrypto;

    [Test]
    procedure RegisterBindAndLoadSsl;

    [AutoNameTestCase('1')]
    [AutoNameTestCase('8')]
    [AutoNameTestCase('32')]
    [IgnoreMemoryLeaks]
    // DUnitX report false positive memory leak.
    // FastMM5 does not detect any memory leak instead.
    procedure MultiThreadLoading(ACount: integer);
  end;

implementation

type
  TBindSelector = class abstract
    class function GetLibType: TLibType; virtual; abstract;
  end;

  TBindSelectorCrypto = class(TBindSelector)
    class function GetLibType: TLibType; override;
  end;

  TBindSelectorSsl = class(TBindSelector)
    class function GetLibType: TLibType; override;
  end;

  // Provide consumer behavior
  TMockConsumer<T: TBindSelector> = class
  public type
    TBinder = record
    private class var
      FRegistered: boolean;
      FHandle: TLibHandle;
      FVersion: TOsslVersion;

    private
      class procedure DoBind(const ALibHandle: TLibHandle;
        const AVersion: TOsslVersion); static;
      class procedure DoUnBind; static;
    public
      class procedure Reset; static;
      class property Registered: boolean read FRegistered;
      class property Handle: TLibHandle read FHandle;
      class property Version: TOsslVersion read FVersion;
    end;
  private
    FLoaderClass: TOsslCustomLoaderClass;
    class function GetRegistered: boolean; static;
    class function GetHadnle: TLibHandle; static;
    class function GetVersion: TOsslVersion; static;
  public
    constructor Create(ALoaderClass: TOsslCustomLoaderClass);
    procedure RegisterBindings;
    class procedure ResetBinding;

    property LoaderClass: TOsslCustomLoaderClass read FLoaderClass;
    class property Registered: boolean read GetRegistered;
    class property Handle: TLibHandle read GetHadnle;
    class property Version: TOsslVersion read GetVersion;
  end;


  TGlobalLoader = class(TBaseMockLoader);
  TBehaviorLoader  = class(TBaseMockLoader)
    destructor Destroy; override;
  end;

{ TBindSelectorCrypto }

class function TBindSelectorCrypto.GetLibType: TLibType;
begin
  Result:=ltCrypto;
end;

{ TBindSelectorSsl }

class function TBindSelectorSsl.GetLibType: TLibType;
begin
  Result:=ltSsl;
end;

{ TMockConsumer<T>.TBinder }

class procedure TMockConsumer<T>.TBinder.DoBind(const ALibHandle: TLibHandle;
  const AVersion: TOsslVersion);
begin
  FRegistered:=True;
  FHandle:=ALibHandle;
  FVersion:=AVersion;
end;

class procedure TMockConsumer<T>.TBinder.DoUnBind;
begin
  FRegistered:=False;
  FHandle:=TLibHandle.cNilHandle;
  FVersion:=TOsslVersion.cEmpty;
end;

class procedure TMockConsumer<T>.TBinder.Reset;
begin
  DoUnbind;
end;

{ TMockConsumer<T> }

constructor TMockConsumer<T>.Create(ALoaderClass: TOsslCustomLoaderClass);
begin
  Assert.IsNotNull(ALoaderClass, 'ALoaderClass mst not be ''nil''.');
  FLoaderClass:=ALoaderClass;
  Assert.IsTrue(ALoaderClass.SetLoader, 'Unable to set loader class.');
end;

class function TMockConsumer<T>.GetRegistered: boolean;
begin
  Result:=TBinder.Registered;
end;

class function TMockConsumer<T>.GetHadnle: TLibHandle;
begin
  Result:=TBinder.Handle;
end;

class function TMockConsumer<T>.GetVersion: TOsslVersion;
begin
  Result:=TBinder.Version;
end;

procedure TMockConsumer<T>.RegisterBindings;
begin
  LoaderClass.RegisterBinding(T.GetLibType, @TBinder.DoBind, @TBinder.DoUnbind);
end;

class procedure TMockConsumer<T>.ResetBinding;
begin
  TBinder.Reset;
end;

{ TBehaviorLoader }

destructor TBehaviorLoader.Destroy;
begin
  inherited;
end;

{ TOsslCustomLoaderBehaviorFixture }

type
  TSimpleLoaderClass = class of TSimpleLoader;
  TSimpleLoader = class(TBaseMockLoader);

procedure TOsslCustomLoaderBehaviorFixture.SetLoaderClass;
begin
  Assert.IsTrue(TGlobalLoader.SetLoaderClass(TSimpleLoader),
    'Loader Class is not set.');
  Assert.InheritsFrom(TGlobalLoader.LoaderClass, TSimpleLoader,
    'Singleton should be a ''TSimpleLoader'' type.');
end;

procedure TOsslCustomLoaderBehaviorFixture.SingletonInstance;
begin
  Assert.IsTrue(TSimpleLoader.SetLoader,
    'Loader Class is not set.');

  var lLoaderA:=TGlobalLoader.GetLoader;
  var lLoaderB:=TGlobalLoader.GetLoader;
  Assert.AreEqual(1, TGlobalLoader.RefCount,
    'The only single loader instance expected.');

  Assert.IsNotNull(lLoaderA, 'Singleton should return valid instance.');
  Assert.InheritsFrom(lLoaderA.ClassType, TSimpleLoader,
    'Singleton should be a ''TSimpleLoader'' type.');
  Assert.AreEqual(lLoaderA, lLoaderB, 'Single,ton should return the same instance.');
end;

procedure TOsslCustomLoaderBehaviorFixture.GetLoaderGenericPositive;
begin
  var lLoaderA: TSimpleLoader;
  Assert.IsTrue(TGlobalLoader.GetLoader<TSimpleLoader>(lLoaderA),
    'Loader Class is not set.');
  Assert.InheritsFrom(lLoaderA.ClassType, TSimpleLoader,
    'Singleton should be a ''TSimpleLoader'' type.');
end;

procedure TOsslCustomLoaderBehaviorFixture.GetLoaderGenericNegative;
begin
  Assert.IsTrue(TGlobalLoader.SetLoaderClass(TGlobalLoader),
    'Loader Class is not set.');

  var lLoader: TSimpleLoader:=nil;
  Assert.IsFalse(TGlobalLoader.GetLoader<TSimpleLoader>(lLoader),
    '''GetLoader<TSimpleLoader>(lLoader)'' should return false.');

  Assert.IsNull(lLoader,
    '''GetLoader<TSimpleLoader>(lLoader)'' should not return ''lLoader'' value.');
  if Assigned(lLoader) then
    Assert.InheritsFrom(lLoader.ClassType, TGlobalLoader,
      'Singleton should be a ''TGlobalLoader'' type.');
end;

procedure TOsslCustomLoaderBehaviorFixture.RegisterBindAndLoadCrypto;
begin
  var lConsumerCrypto: TMockConsumer<TBindSelectorCrypto>:=nil;
  try
    lConsumerCrypto:=TMockConsumer<TBindSelectorCrypto>.Create(TBehaviorLoader);
    lConsumerCrypto.RegisterBindings;

    TOsslCustomLoader.Load([ltCrypto]);
    Assert.AreEqual<culong>(TGlobalLoader.cVersion,
      TOsslCustomLoader.LibVersion[ltCrypto], 'LibCrypto version mismatch.');

    Assert.IsTrue(TOsslCustomLoader.IsLibLoaded[ltCrypto],
      'TOsslCustomLoader does not report LibCrypto loaded.');
    Assert.IsTrue(lConsumerCrypto.Registered, 'LibCrypto binding failed.');
    Assert.AreEqual<TLibHandle>(TGlobalLoader.cHandleCrypto, lConsumerCrypto.Handle,
      'LibCrypto wrong Handle.');
    Assert.AreEqual<culong>(TGlobalLoader.cVersion, lConsumerCrypto.Version,
      'LibCrypto version mismatch.');
  finally
    lConsumerCrypto.Free;
  end;
end;

procedure TOsslCustomLoaderBehaviorFixture.RegisterBindAndLoadSsl;
begin
  var lConsumerCrypto: TMockConsumer<TBindSelectorCrypto>:=nil;
  var lConsumerSsl: TMockConsumer<TBindSelectorSsl>:=nil;
  try
    lConsumerSsl:=TMockConsumer<TBindSelectorSsl>.Create(TBehaviorLoader);
    lConsumerCrypto:=TMockConsumer<TBindSelectorCrypto>.Create(TBehaviorLoader);

    lConsumerSsl.RegisterBindings;
    lConsumerCrypto.RegisterBindings;

    TOsslCustomLoader.Load([ltSsl]);

    Assert.IsTrue(TOsslCustomLoader.IsLibLoaded[ltSsl],
      'TOsslCustomLoader does not report LibSsl loaded.');
    Assert.AreEqual<culong>(TGlobalLoader.cVersion,
      TOsslCustomLoader.LibVersion[ltSsl], 'LibSsl version mismatch.');

    Assert.IsTrue(lConsumerSsl.Registered, 'LibSsl binding failed.');
    Assert.AreEqual<TLibHandle>(TGlobalLoader.cHandleSsl, lConsumerSsl.Handle,
      'LibSsl wrong Handle.');
    Assert.AreEqual<culong>(TGlobalLoader.cVersion, lConsumerSsl.Version,
      'LibSsl version mismatch.');

  finally
    lConsumerSsl.Free;
    lConsumerCrypto.Free;
  end;
end;

procedure TOsslCustomLoaderBehaviorFixture.MultiThreadLoading(ACount: integer);
begin
  Assert.IsTrue(ACount > 0, '''ACount must be greater than zero.');

  var lStartSignal: TSimpleEvent:=nil;
  var lCompleteSignal: TCountdownEvent:=nil;
  var lThreads: array of TThread;

  try
    lStartSignal:=TSimpleEvent.Create(nil, True, False, '');
    lCompleteSignal:=TCountdownEvent.Create(ACount);
    SetLength(lThreads, ACount);

    for var i:=0 to ACount-1 do
    begin
      var lThread: TThread:=nil;
      try
        lThread:=TThread.CreateAnonymousThread(
          procedure
          begin
            var lTimeout:=Random(ACount-1);
            try
              while not TThread.CheckTerminated do
              begin
                if not (lStartSignal.WaitFor(1000) = wrSignaled) then
                  continue;
                TThread.Sleep(lTimeout);
                TBehaviorLoader.SetLoader;
                break;
              end;
            finally
              lCompleteSignal.Signal;
            end;
          end
        );
        lThread.FreeOnTerminate:=False;
        lThread.Start;
        lThreads[i]:=lThread;
      except
        lThread.Free;
        raise;
      end;
    end;
    lStartSignal.SetEvent;
    Log('Waiting for threads'' execution completion.');

    Assert.IsTrue(lCompleteSignal.WaitFor(5000) = wrSignaled,
      'Threads did not complete in 5sec. Test failed.');
    Assert.AreEqual(1, TGlobalLoader.RefCount,
      'The only single loader instance expected.');
    var lLoader:=TGlobalLoader.GetLoader;
    Assert.InheritsFrom(lLoader.ClassType, TBehaviorLoader,
      'Singleton should be a ''TBehaviorLoader'' type.');

  finally
    if not (lCompleteSignal.WaitFor(1000) = wrSignaled) then
      for var i:=0 to ACount-1 do
        lThreads[i].Terminate;

    for var i:=0 to ACount-1 do
    begin
      lThreads[i].WaitFor;
      lThreads[i].Free;
    end;

    lCompleteSignal.Free;
    lStartSignal.Free;
  end;

end;

initialization
  TDUnitX.RegisterTestFixture(TOsslCustomLoaderBehaviorFixture);

end.
