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

unit Ossl4Pas.Loader;

{$INCLUDE 'Ossl4Pas_CompilerDefines.inc'}

interface

{$IFDEF LINK_DYNAMIC}

uses
{$IF Defined(FPC)}
  CTypes,
  SysUtils,
  Classes,
  Generics.Collections,
  DynLibs,
  {$IFDEF T_WINDOWS}Windows, {$ENDIF}
  {$IFDEF T_POSIX}dl, {$ENDIF}
  SyncObjs,
{$ELSEIF Defined(DCC)}
  System.SysUtils,
  System.Classes,
  System.SyncObjs,
  System.Generics.Collections,
  {$IFDEF T_WINDOWS}Winapi.Windows,{$ENDIF}
  {$IFDEF POSIX}Posix.Dlfcn,{$ENDIF}
{$ELSE}
  {$MESSAGE Warning 'Unknown platfrom. May not be supported'}
{$ENDIF}
  Ossl4Pas.Api.Err,
  Ossl4Pas.CTypes,
  Ossl4Pas.Types;

type

{$REGION 'TOsslLoader declaration'}

  /// <summary>Base exception class for all OpenSSL Loader errors.</summary>
  EOsslLoader = class(Exception);

  /// <summary>Exception raised when an OS-level library loading error occurs.</summary>
  EOsslLib  = class(EOSError)
    /// <summary>
    ///   Raises an EOsslLib exception with the last OS error code.
    /// </summary>
    /// <param name="LastError">The OS error code (optional).</param>
    /// <param name="AdditionalInfo">Extra context for the error message.</param>
    class procedure RaiseLastOSError(LastError: Integer = 0;
      const AdditionalInfo: string = ''); static;
  end;

  TOsslCustomLoaderClass = class of TOsslCustomLoader;

  /// <summary>
  ///   Abstract base class for OpenSSL Library Loaders.
  /// </summary>
  /// <remarks>
  ///   Provides the infrastructure for Singleton management, binding registration,
  ///   and thread-safe state access. Concrete loading logic must be implemented
  ///   by descendants.
  /// </remarks>
  TOsslCustomLoader = class abstract
  public const
    cLibTypesAll: TLibTypes = [ltCrypto..ltSsl];
    cBaseLibType  = Low(TLibType);

  strict private class var
    FLoaderClass: TOsslCustomLoaderClass;
    FLoader:      TOsslCustomLoader;

  strict private
    FBindLock:    TCriticalSection;
    FLibsToLoad:  TLibTypes;
    FLibHandles:  TLibHandleList;
    FLibVersions: TLibVersionList;
  private
    class function GetIsLibLoaded(ALibType: TLibType): boolean; static;
      {$IFDEF INLINE_ON}inline;{$ENDIF}

    class function GetLibsLoaded: TLibTypes; static;
      {$IFDEF INLINE_ON}inline;{$ENDIF}

    class function GetLibVersion(ALibType: TLibType): TOsslVersion; static;
      {$IFDEF INLINE_ON}inline;{$ENDIF}

    class function GetIsLoaderSet: boolean; static;
      {$IFDEF INLINE_ON}inline;{$ENDIF}

    function DoGetIsLibLoaded(ALibType: TLibType): boolean;
      {$IFDEF INLINE_ON}inline;{$ENDIF}

    function DoGetLibsLoaded: TLibTypes;
      {$IFDEF INLINE_ON}inline;{$ENDIF}

    function DoGetLibHandle(ALibType: TLibType): TLibHandle;
      {$IFDEF INLINE_ON}inline;{$ENDIF}

    procedure DoSetLibHandle(ALibType: TLibType; const Value: TLibHandle);
      {$IFDEF INLINE_ON}inline;{$ENDIF}

    function DoGetLibVersion(ALibType: TLibType): TOsslVersion;
      {$IFDEF INLINE_ON}inline;{$ENDIF}

    procedure DoSetLibVersion(ALibType: TLibType; const Value: TOsslVersion);
    class function GetLibsToLoad: TLibTypes; static;
    class function GetLibHandle(ALibType: TLibType): TLibHandle; static;

  protected
    ///  <summary>
    ///    Raises <see cref="EOsslLoader"> exception with a message
    ///  </summary>
    ///  <param name="AMessage">A message string</param>
    class procedure RaiseException(AMessage: string); static;

    ///  <summary>
    ///    Raises <see cref="EOsslLoader"> exception with a formatted message
    ///  </summary>
    ///  <param name="AMessage">
    ///    A message string containing format specifier(s) to be replaced
    ///    with a values from <c>Args</c> parameter.
    ///  </param>
    ///  <param name="Args">
    ///    Args is an array of constants containing values to format
    ///    according to format specifiers in Msg.
    ///  </param>
    class procedure RaiseExceptionFmt(AMessage: string;
      const Args: array of const); static;


    ///  <summary>
    ///    Raises <see cref="EOsslLoader"> exception with a message that is
    ///    loaded from a library resources.
    ///  </summary>
    ///  <param name="ResStringRec">Is a pointer to resource string.</param>
    class procedure RaiseExceptionRes(ResStringRec: PResStringRec); static;

    ///  <summary>
    ///    Raises <see cref="EOsslLoader"> exception with a message that is
    ///    loaded from a library resources.
    ///  </summary>
    ///  <param name="ResStringRec">
    ///    Is a pointer to resource string containing format specifier(s)
    ///    to be replaced with a values from <c>Args</c> parameter.
    ///  </param>
    ///  <param name="Args">
    ///    Args is an array of constants containing values to format
    ///    according to format specifiers in Msg.
    ///  </param>
    class procedure RaiseExceptionResFmt(ResStringRec: PResStringRec;
      const Args: array of const); static;

    /// <summary>
    ///   Atomically registers the class type to be used for the Singleton instance.
    /// </summary>
    class function SetLoaderClass(ALoaderClass: TOsslCustomLoaderClass): boolean;
      {$IFDEF INLINE_ON}inline;{$ENDIF}

    /// <summary>
    ///   Factory method to create a new instance of the loader.
    ///   Can be overridden by concrete descendants.
    /// </summary>
    class function NewLoader: TOsslCustomLoader; virtual;

    /// <summary>
    ///   Retrieves the Singleton instance, creating it if necessary.
    /// </summary>
    class function GetLoader: TOsslCustomLoader; overload;
      {$IFDEF INLINE_ON}inline;{$ENDIF}

    /// <summary>
    ///   Retrieves the Singleton instance cast to a specific type.
    /// </summary>
    class function GetLoader<T: TOsslCustomLoader>(out ALoader: T): boolean;
      overload;{$IFDEF INLINE_ON}inline;{$ENDIF}

    class property LibHandle[ALibType: TLibType]: TLibHandle read GetLibHandle;

    /// <summary>
    ///   Acquires the thread-safe lock used for binding operations.
    /// </summary>
    procedure BindLock; {$IFDEF INLINE_ON}inline;{$ENDIF}

    /// <summary>
    ///   Releases the thread-safe lock used for binding operations.
    /// </summary>
    procedure BindUnlock; {$IFDEF INLINE_ON}inline;{$ENDIF}

    /// <summary>
    ///   Executes the binding callback defined in the parameter.
    /// </summary>
    /// <param name="AParam">The binding parameter record.</param>
    /// <remarks>
    ///   This method checks if the library is loaded before calling the proc.
    ///   It does NOT acquire the lock; the caller must ensure thread safety.
    /// </remarks>
    procedure DoBind(const AParam: TBindParam); overload;
      {$IFDEF INLINE_ON}inline;{$ENDIF}

    /// <summary>
    ///   Executes the binding callback within a thread-safe lock.
    /// </summary>
    /// <param name="AParam">The binding parameter record.</param>
    procedure DoSafeBind(const AParam: TBindParam); overload;
      {$IFDEF INLINE_ON}inline;{$ENDIF}

    /// <summary>
    ///   Iterates through all registered bindings for the specified types
    ///   and executes them.
    /// </summary>
    /// <param name="ALibTypes">The set of libraries to bind.</param>
    procedure DoBind(ALibTypes: TLibTypes); overload;

    /// <summary>
    ///   Executes the unbinding callback defined in the parameter.
    /// </summary>
    procedure DoUnBind(const AParam: TBindParam); overload;
      {$IFDEF INLINE_ON}inline;{$ENDIF}

    /// <summary>
    ///   Iterates through all registered bindings for the specified types
    ///   and executes their unbind procedures.
    /// </summary>
    procedure DoUnBind(ALibTypes: TLibTypes); overload;

    /// <summary>
    ///   Abstract method to implement the actual library loading logic.
    /// </summary>
    procedure InternalLoad(ALibTypes: TLibTypes); overload; virtual; abstract;

    /// <summary>
    ///   Abstract method to implement the actual library unloading logic.
    /// </summary>
    procedure InternalUnload(ALibTypes: TLibTypes); virtual; abstract;

    /// <summary>
    ///   Reports libraries to be loaded based on registered Bindings
    /// </summary>
    class property LibsToLoad: TLibTypes read GetLibsToLoad;

    /// <summary>
    ///   Instance accessor for the IsLibLoaded status.
    /// </summary>
    property InstIsLibLoaded[ALibType: TLibType]: boolean read DoGetIsLibLoaded;

    /// <summary>
    ///   Instance accessor for the set of loaded libraries.
    /// </summary>
    property InstLibsLoaded: TLibTypes read DoGetLibsLoaded;

    /// <summary>
    ///   Instance accessor for the raw library handles.
    /// </summary>
    property InstLibHandle[ALibType: TLibType]: TLibHandle read DoGetLibHandle
      write DoSetLibHandle;

    /// <summary>
    ///   Instance accessor for the loaded library versions.
    /// </summary>
    property InstLibVersion[ALibType: TLibType]: TOsslVersion read DoGetLibVersion
      write DoSetLibVersion;

  public
    class destructor Destroy;

    /// <summary>
    ///   Registers the calling class as the active Loader implementation.
    /// </summary>
    class function SetLoader: boolean;

    /// <summary>
    ///   Registers a binding callback to be executed when the specified library loads.
    /// </summary>
    class procedure RegisterBinding(const ALibType: TLibType;
      ABindProc: TBindProc; AUnBindProc: TUnBindProc);

    /// <summary>
    ///   Triggers the loading of the specified libraries.
    /// </summary>
    class procedure Load(ALibTypes: TLibTypes);
      {$IFDEF INLINE_ON}inline;{$ENDIF}

    /// <summary>
    ///   Triggers the loading of libraries with registered Bindings.
    /// </summary>
    class procedure LoadRegistered;
      {$IFDEF INLINE_ON}inline;{$ENDIF}

    /// <summary>
    ///   Triggers the unloading of the specified libraries.
    /// </summary>
    class procedure Unload(ALibTypes: TLibTypes);
      {$IFDEF INLINE_ON}inline;{$ENDIF}

    {$IFDEF UNITTEST}
    // Backdor for unit tests only. Should never be used in production.
    class procedure ResetSingleton;
    {$ENDIF}

    /// <summary>Checks if a loader instance is initialized.</summary>
    class property IsLoaderSet: boolean read GetIsLoaderSet;
    /// <summary>The class type currently registered as the Loader.</summary>
    class property LoaderClass: TOsslCustomLoaderClass read FLoaderClass;
    /// <summary>Checks if a specific library is currently loaded.</summary>
    class property IsLibLoaded[ALibType: TLibType]: boolean read GetIsLibLoaded;
    /// <summary>Returns the set of currently loaded libraries.</summary>
    class property LibsLoaded: TLibTypes read GetLibsLoaded;
    /// <summary>Returns the version of a loaded library.</summary>
    class property LibVersion[ALibType: TLibType]: TOsslVersion read GetLibVersion;

    constructor Create; virtual;
    destructor Destroy; override;
  end;

  TOsslLoaderClass = class of TOsslLoader;

  /// <summary>
  ///   Standard implementation of the OpenSSL Loader.
  /// </summary>
  /// <remarks>
  ///   Implements library searching, path normalization, system path fallback,
  ///   and strict version/path validation logic.
  /// </remarks>
  TOsslLoader = class(TOsslCustomLoader)
  public type
    TLoaderFlag   = (lfStrictPath, lfPathNormalize);
    TLoaderFlags  = set of TLoaderFlag;


    /// <summary>
    ///   Thread-safe wrapper for TLoaderFlags to allow atomic updates.
    /// </summary>

    { TLoaderFlagsRec }

    /// <summary>
    ///   Thread-safe wrapper for TLoaderFlags to allow atomic updates.
    /// </summary>
    /// <remarks>
    ///   Standard Pascal Sets are not thread-safe. This record encapsulates the
    ///   bitmask storage and provides Interlocked operations for assignment
    ///   and bit manipulation (Include/Exclude).
    /// </remarks>
    TLoaderFlagsRec = record
    private type
      PLoaderFLags = ^TLoaderFlags;
    private const
      cMask = cardinal((1 shl (Ord(High(TLoaderFlag))+1))-1);

    strict private
      FStorage: cardinal;
    public
    {$IFDEF DCC}
      /// <summary>
      ///   Atomically assigns the value of one flags record to another.
      ///   Implements the ":=" operator.
      /// </summary>
      /// <param name="Dest">The destination record to be updated.</param>
      /// <param name="Src">The source record.</param>
      class operator Assign(var Dest: TLoaderFlagsRec;
        const [ref] Src: TLoaderFlagsRec); {$IFDEF INLINE_ON}inline;{$ENDIF}
    {$ENDIF}
    {$IFDEF FPC}
      // FPC does not suppor `operator Assign` we have to use `operator Initialize` instead
      class operator Copy(constref Src: TLoaderFlagsRec;
        var Dest: TLoaderFlagsRec); {$IFDEF INLINE_ON}inline;{$ENDIF}
    {$ENDIF}

      /// <summary>
      ///   Implicitly converts a standard Pascal Set to the thread-safe record.
      /// </summary>
      class operator Implicit(a: TLoaderFlags): TLoaderFlagsRec;
        {$IFDEF INLINE_ON}inline;{$ENDIF}

      /// <summary>
      ///   Implicitly converts the thread-safe record back to a standard Pascal Set.
      /// </summary>
      class operator Implicit(a: TLoaderFlagsRec): TLoaderFlags;
        {$IFDEF INLINE_ON}inline;{$ENDIF}

      /// <summary>
      ///   Checks if a specific flag is set within the record.
      ///   Implements the standard "in" operator.
      /// </summary>
      class operator In(a: TLoaderFlagsRec; b: TLoaderFlag): boolean;
        {$IFDEF INLINE_ON}inline;{$ENDIF}

      /// <summary>
      ///   Atomically adds a flag to the specified record using a spin-lock strategy.
      /// </summary>
      /// <param name="a">The record to modify.</param>
      /// <param name="b">The flag to include.</param>
      class procedure Include(a: TLoaderFlagsRec; b: TLoaderFlag); overload;
        static; {$IFDEF INLINE_ON}inline;{$ENDIF}

      /// <summary>
      ///   Atomically adds a flag to the current instance.
      /// </summary>
      /// <param name="AFLag">The flag to include.</param>
      procedure Include(AFLag: TLoaderFlag); overload;
        {$IFDEF INLINE_ON}inline;{$ENDIF}

      /// <summary>
      ///   Atomically removes a flag from the specified record using a spin-lock strategy.
      /// </summary>
      /// <param name="a">The record to modify.</param>
      /// <param name="b">The flag to exclude.</param>
      class procedure Exclude(a: TLoaderFlagsRec; b: TLoaderFlag); overload;
        static; {$IFDEF INLINE_ON}inline;{$ENDIF}

      /// <summary>
      ///   Atomically removes a flag from the current instance.
      /// </summary>
      /// <param name="AFlag">The flag to exclude.</param>
      procedure Exclude(AFlag: TLoaderFlag); overload;
        {$IFDEF INLINE_ON}inline;{$ENDIF}
    end;

  public const
    cLibTypesAll  = [ltCrypto..ltSsl];
    cBaseLibType  = Low(TLibType);

    cMinVersion = $3000000F;

  protected const
    {$IF Defined(T_WIN32)}
      cLibNames: array[TLibType] of string = ('libcrypto-3.dll', 'libssl-3.dll');
    {$ELSEIF Defined(T_WIN64)}
      cLibNames: array[TLibType] of string = ('libcrypto-3-x64.dll', 'libssl-3-x64.dll');
    {$ELSEIF Defined(T_LINUX)}
      cLibNames: array[TLibType] of string = ('libcrypto.so.3', 'libssl.so.3');
    {$ELSEIF Defined(T_OSX)}
      cLibNames: array[TLibType] of string = ('libcrypto.3.dylib', 'libssl.3.dylib');
    {$ELSEIF Defined(T_ANDROID)}
      cLibNames: array[TLibType] of string = ('libcrypto.so', 'libssl.so');
    {$ENDIF}
  private
    FFlags:       TLoaderFlagsRec;
    FSearchPath: string;
    FLoadedPath:  string;

    class function SysLoadLibrary(const ALibName: string;
      ASuppressException: boolean; out ALibVer: TOsslVersion): TLibHandle;
      overload; static; {$IFDEF INLINE_ON}inline;{$ENDIF}
    class function GetLibName(ALibType: TLibType): string; overload; static;
      {$IFDEF INLINE_ON}inline;{$ENDIF}

    procedure DoSetFlags(const Value: TLoaderFlags);
      {$IFDEF INLINE_ON}inline;{$ENDIF}
    class function GetFlags: TLoaderFlags; static;
      {$IFDEF INLINE_ON}inline;{$ENDIF}
    class function GetLoadedPath: string; static;
      {$IFDEF INLINE_ON}inline;{$ENDIF}
    class function GetSearchPath: string; static;
      {$IFDEF INLINE_ON}inline;{$ENDIF}
    class procedure SetFlags(const Value: TLoaderFlags); static;
      {$IFDEF INLINE_ON}inline;{$ENDIF}
    class procedure SetSearchPaths(const Value: string); static;
      {$IFDEF INLINE_ON}inline;{$ENDIF}

    function DoGetFlags: TLoaderFlags;
      {$IFDEF INLINE_ON}inline;{$ENDIF}
protected

    /// <summary>
    ///   Retrieves the Singleton instance cast to <c>TOsslLoader</c>,
    ///   creating it if necessary.
    /// </summary>
    /// <remarks>
    ///   This method enforces type safety. If the currently registered loader class
    ///   is not compatible with <c>TOsslLoader</c>, an <see cref="EOsslLoader" />
    ///   exception is raised.
    /// </remarks>
    class function GetLoader: TOsslLoader; reintroduce;
      {$IFDEF INLINE_ON}inline;{$ENDIF}

    /// <summary>
    ///   Creates a TStringList configured for parsing delimited path strings.
    /// </summary>
    /// <param name="APaths">The delimited string of paths.</param>
    /// <returns>A TStringList instance (User is responsible for freeing).</returns>
    class function NewPathStringList(APaths: string): TStringList; static;
      {$IFDEF INLINE_ON}inline;{$ENDIF}

    /// <summary>
    ///   Retrieves the OpenSSL version from a loaded library handle.
    /// </summary>
    /// <param name="ALibHandle">The handle to check.</param>
    /// <param name="AVersion">Return The parsed version structure.</param>
    /// <returns>
    ///   Returns <c>True</c> if version is found and parsed,
    ///  otherwise <c>False</c>
    ///  </returns>
    ///  <remark>
    ///   <c>AVersion</c> return value may be undefined if method return <c>False</c>
    ///  </remark>
    class function CheckLibVersion(ALibHandle: TLibHandle;
      out AVersion: TOsslVersion): boolean; overload;
      static;

    /// <summary>
    ///   Orchestrates the loading of specified libraries using default paths.
    /// </summary>
    procedure InternalLoad(ALibTypes: TLibTypes); overload; override;

    /// <summary>
    ///   Orchestrates the loading of specified libraries using a specific search path.
    /// </summary>
    procedure InternalLoad(ALibTypes: TLibTypes; ASearchPath: string);
      overload;

    /// <summary>
    ///   Orchestrates the unloading and cleanup of specified libraries.
    /// </summary>
    procedure InternalUnload(ALibTypes: TLibTypes); override;

    /// <summary>
    ///   Parses and sets the internal search path list from a string.
    /// </summary>
    procedure DoSetSearchPaths(ALibPaths: string); overload;

    /// <summary>
    ///   Performs the low-level search and load operation for a specific library type.
    /// </summary>
    /// <remarks>
    ///   Implements the logic for iterating search paths, checking file existence,
    ///   verifying versions, and ensuring the SSL library loads from the same
    ///   location as the Crypto library.
    /// </remarks>
    function DoLoadLibrary(ALibType: TLibType): TLibHandle; overload; virtual;

    /// <summary>Instance backing property for Flags.</summary>
    property InstanceFlags: TLoaderFlags read DoGetFlags write DoSetFlags;

    /// <summary>Instance backing property for SearchPath.</summary>
    property InstanceSearchPath: string read FSearchPath write DoSetSearchPaths;

    /// <summary>Instance backing property for LoadedPath.</summary>
    property InstanceLoadedPath: string read FLoadedPath;

  public
    /// <summary>
    ///   Loads the specified libraries using a custom search path.
    /// </summary>
    /// <param name="ALibTypes">The set of libraries to load.</param>
    /// <param name="ALibPaths">
    ///   A delimited string of paths to search (Overrides defaults).
    /// </param>
    class procedure Load(ALibTypes: TLibTypes; ALibPaths: string);
       overload; {$IFDEF INLINE_ON}inline;{$ENDIF}

    /// <summary>Returns the platform-specific filename of the library.</summary>
    class property LibName[ALibType: TLibType]: string read GetLibName;

    /// <summary>Configuration flags for the loader (Strict paths, Normalization).</summary>
    class property Flags: TLoaderFlags read GetFlags write SetFlags;

    /// <summary>The currently configured search path(s).</summary>
    class property SearchPath: string read GetSearchPath write SetSearchPaths;

    /// <summary>
    ///   The actual directory path from which the Crypto library was loaded.
    ///   (Used as the Anchor for loading SSL).
    /// </summary>
    class property LoadedPath: string read GetLoadedPath;

  end;
{$ENDREGION 'TOsslLoader declaration'}

{$ENDIF LINK_DYNAMIC}

implementation

{$IFDEF LINK_DYNAMIC}

uses
{$IFDEF DCC}
  System.SysConst,
  System.IOUtils,
{$ENDIF}
{$IFDEF FPC}
  sysconst,
{$ENDIF}
{$IFDEF STUB_TSPINWAIT}
  fpc.stub.syncobjs,
{$ENDIF}
{$IFDEF STUB_IOUTILS}
  fpc.stub.ioutils,
{$ENDIF}
  Ossl4Pas.ResStrings;

{$REGION 'TOsslLoaderRegistry implementation'}
type
  TOsslLoaderRegistry = class
  private type
    TBindParamList  = TThreadList<TBindParam>;
    TBindSnapshot   = TList<TBindParam>;

  strict private class var
    FRegistry: TBindParamList;

  private
    class function GetRegistry: TBindParamList;

  public
    class constructor Create;
    class destructor Destroy;

    class procedure Add(const AParam: TBindParam);

    class function GetSnapshot(ALibTypes: TLibTypes): TBindSnapshot;
  end;

  { TOsslLoaderRegistry }

// Unit initialization and class constructor execution order is non-deterministic.
// We rely on `GetRegistry` for lazy initialization to handle requests made
// before this constructor runs.
// However, this explicit initialization is required for Unit Tests; without it,
// DUnitX/FastMM may report false-positive memory leaks due to lifecycle tracking issues.
class constructor TOsslLoaderRegistry.Create;
begin
  GetRegistry; // instantiate registry explicitly
end;

class destructor TOsslLoaderRegistry.Destroy;
begin
  FreeAndNil(FRegistry);
end;

class procedure TOsslLoaderRegistry.Add(const AParam: TBindParam);
begin
  GetRegistry.Add(AParam);
end;

class function TOsslLoaderRegistry.GetRegistry: TBindParamList;
var
  lRegistry: TBindParamList;

begin
  if Assigned(FRegistry) then
    Exit(FRegistry);

  lRegistry:=TBindParamList.Create;
  {$IF Defined(USE_TINTERLOCKED)}
  if TInterlocked.CompareExchange<TBindParamList>(FRegistry,
    lRegistry, nil) <> nil then
  {$ELSEIF Defined(USE_ATOMIC_DCC)}
  if AtomicCmpExchange(pointer(FRegistry), pointer(lRegistry), nil) <> nil then
  {$ELSEIF Defined(USE_ATOMIC_FPC)}
  if System.InterlockedCompareExchange(pointer(FRegistry), pointer(lRegistry),
     nil) <> nil then
  {$ENDIF}
    lRegistry.Free; // some other thread installed the singleton.
  Result:=FRegistry;
end;

class function TOsslLoaderRegistry.GetSnapshot(ALibTypes: TLibTypes): TBindSnapshot;
var
  lRegistry: TBindParamList;
  lLockList: TBindSnapshot;
  i: NativeInt;

begin
  lRegistry:=GetRegistry;
  Result:=TBindSnapshot.Create;
  try
    try
      lLockList:=lRegistry.LockList;
      for i:=0 to lLockList.Count-1 do
      if lLockList[i].LibType in ALibTypes then
        Result.Add(lLockList[i]);
    finally
      lRegistry.UnlockList;
    end;
  except
    FreeAndNil(Result);
    Raise;
  end;
end;

{$ENDREGION 'TOsslLoaderRegistry implementation'}

{$REGION 'TOsslLoader Support Classes '}

{ ============================================================================
  INTERNAL: Version Function Prototype
  ============================================================================ }
type
  Tfunc_OpenSSL_version_num = function: TOsslVersion; cdecl;

{ TOsslCustomLoader }

class destructor TOsslCustomLoader.Destroy;
begin
  FreeAndNil(FLoader);
end;

class procedure TOsslCustomLoader.RaiseException(AMessage: string);
begin
  raise EOsslLoader.Create(AMessage);
end;

class procedure TOsslCustomLoader.RaiseExceptionFmt(AMessage: string;
  const Args: array of const);
begin
  raise EOsslLoader.CreateFmt(AMessage, Args);
end;

class procedure TOsslCustomLoader.RaiseExceptionRes(ResStringRec: PResStringRec);
begin
  raise EOsslLoader.CreateRes(ResStringRec);
end;

class procedure TOsslCustomLoader.RaiseExceptionResFmt(ResStringRec: PResStringRec;
  const Args: array of const);
begin
  raise EOsslLoader.CreateResFmt(ResStringRec, Args);
end;

class function TOsslCustomLoader.NewLoader: TOsslCustomLoader;
begin
  // by default it creates the instance of a `FLoaderClass` type.
  // However, derived class(es) can overwrite this behavior
  Result:=Self.Create;
end;

class procedure TOsslCustomLoader.RegisterBinding(const ALibType: TLibType;
  ABindProc: TBindProc; AUnBindProc: TUnBindProc);
var
  lBindParam: TBindParam;

begin
  lBindParam.Create(ALibType, ABindProc, AUnBindProc);
  TOsslLoaderRegistry.Add(lBindParam);
  if IsLibLoaded[ALibType] then
    GetLoader.DoSafeBind(lBindParam);
end;

class function TOsslCustomLoader.SetLoader: boolean;
var
  lNewLoader: TOsslCustomLoader;

begin
  if Assigned(FLoader) then
    Exit(True);  // Singleton instantiated already

  if not (Assigned(FLoaderClass) or SetLoaderClass(Self)) then
    Exit(False); // set `FLoaderClass` to `Self` if it not set already

  lNewLoader:=FLoaderClass.NewLoader;

  // try to set singleton instance
  {$IF Defined(USE_TINTERLOCKED)}
  if TInterlocked.CompareExchange<TOsslCustomLoader>(
    FLoader, lNewLoader, nil) <> nil then
  {$ELSEIF Defined(USE_ATOMIC_DCC)}
  if AtomicCmpExchange(pointer(FLoader), pointer(lNewLoader), nil) <> nil then
  {$ELSEIF Defined(USE_ATOMIC_FPC)}
  if System.InterlockedCompareExchange(pointer(FLoader), pointer(lNewLoader),
     nil) <> nil then
  {$ENDIF}
      lNewLoader.Free; // if other thread outpaced, destroy the local instance.
  Result:=Assigned(FLoader);
end;

class function TOsslCustomLoader.SetLoaderClass(
  ALoaderClass: TOsslCustomLoaderClass): boolean;
begin
  if not Assigned(ALoaderClass) then
    Exit(False); // Reset to noll is not allowed

  if IsLoaderSet and (FLoaderClass <> ALoaderClass) then
    Exit(False); // Singleton instantiated and it's a different class.

  // try to replace 'nil' value with a new one atomically

  {$IF Defined(USE_TINTERLOCKED)}
  TInterlocked.CompareExchange(pointer(FLoaderClass), pointer(ALoaderClass), nil);
  {$ELSEIF Defined(USE_ATOMIC_DCC)}
  AtomicCmpExchange(pointer(FLoaderClass), pointer(ALoaderClass), nil);
  {$ELSEIF Defined(USE_ATOMIC_FPC)}
  System.InterlockedCompareExchange(pointer(FLoaderClass), pointer(ALoaderClass),
    nil);
  {$ENDIF}
  Result:=FLoaderClass = ALoaderClass;
end;

class function TOsslCustomLoader.GetIsLoaderSet: boolean;
begin
  Result:=Assigned(FLoader);
end;

class function TOsslCustomLoader.GetLibsToLoad: TLibTypes;
begin
  if IsLoaderSet then
    Result:=GetLoader.FLibsToLoad
  else
    Result:=[];
end;

class function TOsslCustomLoader.GetIsLibLoaded(ALibType: TLibType): boolean;
begin
  if IsLoaderSet then
    Result:=GetLoader.InstIsLibLoaded[ALibType]
  else
    Result:=False;
end;

class function TOsslCustomLoader.GetLibHandle(ALibType: TLibType): TLibHandle;
begin
  if IsLoaderSet then
    Result:=GetLoader.InstLibHandle[ALibType]
  else
    Result:=0;
end;

class function TOsslCustomLoader.GetLibsLoaded: TLibTypes;
begin
  Result:=GetLoader.InstLibsLoaded;
end;

class function TOsslCustomLoader.GetLibVersion(
  ALibType: TLibType): TOsslVersion;
begin
  Result:=GetLoader.InstLibVersion[ALibType];
end;

class function TOsslCustomLoader.GetLoader: TOsslCustomLoader;
begin
  if not SetLoader then
    RaiseExceptionRes(@resLoaderNotSet);
  Result:=FLoader;
end;

class function TOsslCustomLoader.GetLoader<T>(out ALoader: T): boolean;
begin
  Result:=SetLoaderClass(T);
  if Result then
  begin
    ALoader:=T(GetLoader);
    Result:=Assigned(ALoader);
  end;
end;

class procedure TOsslCustomLoader.Load(ALibTypes: TLibTypes);
begin
  SetLoader;
  GetLoader.InternalLoad(ALibTypes);
end;

class procedure TOsslCustomLoader.LoadRegistered;
begin
  Load(LibsToLoad);
end;

class procedure TOsslCustomLoader.Unload(ALibTypes: TLibTypes);
var
  lLoader: TOsslCustomLoader;

begin
  if not IsLoaderSet then
    Exit; // nothing to unload;

  lLoader:=GetLoader;
  if Assigned(lLoader) then
    lLoader.InternalUnLoad(ALibTypes);
end;

{$IFDEF UNITTEST}
// FOR UNIT TEST USAGE ONLY
// This method resets singleton instantly
class procedure TOsslCustomLoader.ResetSingleton;
begin
  FreeAndNil(FLoader);
  FLoaderClass:=nil;
end;

{$ENDIF}

{$ENDREGION 'TOsslCustomLoader class methods'}

{$REGION 'TOsslCustomLoader Instance methods'}

constructor TOsslCustomLoader.Create;
begin
  FBindLock:=TCriticalSection.Create;
//  FBindParams:=TBindParamList.Create;
end;

destructor TOsslCustomLoader.Destroy;
begin
  BindLock;
  try
    InternalUnload(cLibTypesAll);
//    FreeAndNil(FBindParams)
  finally
    BindUnlock;
  end;
  FreeAndNil(FBindLock);
end;

procedure TOsslCustomLoader.BindLock;
begin
  FBindLock.Enter;
end;

procedure TOsslCustomLoader.BindUnlock;
begin
  FBindLock.Leave;
end;

procedure TOsslCustomLoader.DoBind(const AParam: TBindParam);
var
  lLibType: TLibType;

begin
  lLibType:=AParam.LibType;
  Include(FLibsToLoad, lLibType);
  if InstIsLibLoaded[lLibType] then
    AParam.DoBind(InstLibHandle[lLibType], InstLibVersion[lLibType]);
end;

procedure TOsslCustomLoader.DoSafeBind(const AParam: TBindParam);
begin
  BindLock;
  try
    DoBind(AParam);
  finally
    BindUnlock;
  end;
end;

procedure TOsslCustomLoader.DoBind(ALibTypes: TLibTypes);
var
  i, s: NativeInt;
  lSnapshot: TOsslLoaderRegistry.TBindSnapshot;

begin
  if ALibTypes = [] then
    Exit;

  lSnapshot:=nil;
  BindLock;
  try
    // Get a cussrent snapshot of bindings from the registry
    lSnapshot:=TOsslLoaderRegistry.GetSnapshot(ALibTypes);
    s:=-1; // keeps the last index (i) of `FBindParam` passed to `DoBind`
    try
      for i:=0 to lSnapshot.Count-1 do
      begin
        s:=i;
        if lSnapshot[i].LibType in ALibTypes then
        DoBind(lSnapshot[i]);
      end;
    except
      for i:=0 to s-1 do // trying to unbind to safely unload library(ies)
        DoUnbind(lSnapshot[i]);
    end;
  finally
    BindUnlock;
    lSnapshot.Free;
  end;
end;

procedure TOsslCustomLoader.DoUnBind(const AParam: TBindParam);
begin
  if InstIsLibLoaded[AParam.LibType] then
    AParam.DoUnBind;
end;

procedure TOsslCustomLoader.DoUnBind(ALibTypes: TLibTypes);
var
  i: NativeInt;
  lSnapshot: TOsslLoaderRegistry.TBindSnapshot;

begin
  if ALibTypes = [] then
    Exit;

  lSnapshot:=nil;
  BindLock;
  try
    // Get a cussrent snapshot of bindings from the registry
    lSnapshot:=TOsslLoaderRegistry.GetSnapshot(ALibTypes);
    for i:=lSnapshot.Count-1 downto 0 do
      if lSnapshot[i].LibType in ALibTypes then
        DoUnBind(lSnapshot[i]);
  finally
    BindUnlock;
    lSnapshot.Free;
  end;
end;

function TOsslCustomLoader.DoGetIsLibLoaded(ALibType: TLibType): boolean;
begin
  Result:=not FLibHandles[ALibType].IsEmpty;
end;

function TOsslCustomLoader.DoGetLibsLoaded: TLibTypes;
var
  i: TLibType;

begin
  Result:=[];
  for i:=Low(TLibType) to High(TLibType)  do
    if InstIsLibLoaded[i]  then
      Include(Result, i);
end;

function TOsslCustomLoader.DoGetLibHandle(ALibType: TLibType): TLibHandle;
begin
  Result:=FLibHandles[ALibType];
end;

procedure TOsslCustomLoader.DoSetLibHandle(ALibType: TLibType;
  const Value: TLibHandle);
begin
  FLibHandles[ALibType]:=Value;
end;

function TOsslCustomLoader.DoGetLibVersion(ALibType: TLibType): TOsslVersion;
begin
  Result:=FLibVersions[ALibType];
end;

procedure TOsslCustomLoader.DoSetLibVersion(ALibType: TLibType;
  const Value: TOsslVersion);
begin
  FLibVersions[ALibType]:=Value;
end;

{$ENDREGION 'TOsslCustomLoader Instance methods'}


{$ENDREGION 'TOsslCustomLoader implementation'}


{$REGION 'TOsslLoader implementation'}

{ EOsslLib }

class procedure EOsslLib.RaiseLastOSError(LastError: Integer;
  const AdditionalInfo: string);
var
  Error: EOsslLib;

begin
  if LastError <> 0 then
    Error:=EOsslLib.CreateResFmt(@SOSError,
      [LastError, SysErrorMessage(LastError), AdditionalInfo])
  else
    Error:=EOsslLib.CreateRes(@SUnkOSError);
  Error.ErrorCode:=LastError;
  raise Error{$IFDEF DCC} at ReturnAddress;{$ENDIF}
end;

{ TOsslLoader.TLoaderFlagsRec }
{$IFDEF DCC}
class operator TOsslLoader.TLoaderFlagsRec.Assign(var Dest: TLoaderFlagsRec;
  const [ref] Src: TLoaderFlagsRec);
{$ENDIF}
{$IFDEF FPC}
class operator TOsslLoader.TLoaderFlagsRec.Copy(constref Src: TLoaderFlagsRec;
        var Dest: TLoaderFlagsRec);
{$ENDIF}
begin
  {$IF Defined(USE_TINTERLOCKED)}
  TInterlocked.Exchange(Dest.FStorage, Src.FStorage);
  {$ELSEIF Defined(USE_ATOMIC_DCC)}
  AtomicExchange(PInteger(@Dest.FStorage)^, PInteger(@Src.FStorage)^);
  {$ELSEIF Defined(USE_ATOMIC_FPC)}
  System.InterlockedExchange(cardinal(Dest.FStorage), cardinal(Src.FStorage))
  {$ENDIF}
end;

class operator TOsslLoader.TLoaderFlagsRec.Implicit(
  a: TLoaderFlags): TLoaderFlagsRec;
begin
  // clean possible garbage bits with `and cMask`
  Result.FStorage:=PCardinal(@a)^ and cMask;
end;

class operator TOsslLoader.TLoaderFlagsRec.Implicit(
  a: TLoaderFlagsRec): TLoaderFlags;
begin
  // explicitly convert to `TLoaderFlags`
  Result:=PLoaderFlags(@a)^;
end;

class operator TOsslLoader.TLoaderFlagsRec.In(a: TLoaderFlagsRec; b: TLoaderFlag
  ): boolean;
var
  lFlag: cardinal;

begin
  lFlag:=1 shl Ord(b);
  Result:=(a.FStorage and lFlag) = lFlag;
end;

procedure TOsslLoader.TLoaderFlagsRec.Include(AFLag: TLoaderFlag);
begin
  Include(Self, AFlag); // calls a `class procedure Include`
end;

class procedure TOsslLoader.TLoaderFlagsRec.Include(a: TLoaderFlagsRec;
  b: TLoaderFlag);
var
  lOld, lNew, lPrev: cardinal;
  lBits: cardinal;
  lSpin: TSpinWait;

begin
  lSpin.Reset;
  // Note: Assuming intention is (1 shl Ord(b)).
  // If b is passed as the mask directly, this is correct.
  // If b is the Enum, this should be: lBits := 1 shl Ord(b);
  lBits:=cardinal(b);
  lOld:=a.FStorage;

  repeat
    lNew:=lOld or lBits;
    // Optimization: If flag is already set, exit immediately without atomic write
    if lOld = lNew then
      Exit;

    // Try to swap lOld with lNew.
    // If a.FStorage equals lOld, it becomes lNew, and lPrev returns lOld.
    // If they don't match (another thread changed it), lPrev returns the `current` value.
    {$IF Defined(USE_TINTERLOCKED)}
    lPrev:=TInterlocked.CompareExchange(a.FStorage, lNew, lOld);
    {$ELSEIF Defined(USE_ATOMIC_DCC)}
    PInteger(@lPrev)^:=AtomicCmpExchange(PInteger(@a.FStorage)^,
      PInteger(@lNew)^, PInteger(@lOld)^);
    {$ELSEIF Defined(USE_ATOMIC_FPC)}
    lPrev:=System.InterlockedCompareExchange(cardinal(a.FStorage),
      cardinal(lNew), cardinal(lNew));
    {$ENDIF}
    if lPrev = lOld then
      Exit;

    // CAS failed: Update our expectation (lOld) to the current value and retry
    lOld:=lPrev;
    lSpin.SpinCycle; // spin cycle(s) and try again
  until False;
end;

procedure TOsslLoader.TLoaderFlagsRec.Exclude(AFlag: TLoaderFlag);
begin
  Exclude(Self, AFlag); // calls a `class procedure Include`
end;

class procedure TOsslLoader.TLoaderFlagsRec.Exclude(a: TLoaderFlagsRec;
  b: TLoaderFlag);
var
  lOld, lNew, lPrev: cardinal;
  lBits: cardinal;
  lSpin: TSpinWait;

begin
  lSpin.Reset;
  lBits:=cardinal(b); // See note in `Include` regarding bit shifting
  lOld:=a.FStorage;

  repeat
    lNew:=lOld and not lBits;
    // Optimization: If flag is already cleared, exit immediately
    if lOld = lNew then
      Exit;


    // see note in `Include` about swapping lOld and lNew
    {$IF Defined(USE_TINTERLOCKED)}
    lPrev:=TInterlocked.CompareExchange(a.FStorage, lNew, lOld);
    {$ELSEIF Defined(USE_ATOMIC_DCC)}
    PCardinal(@lPrev)^:=AtomicCmpExchange(PInteger(@a.FStorage)^,
      PInteger(@lNew)^, PInteger(@lOld)^);
    {$ELSEIF Defined(USE_ATOMIC_FPC)}
    lPrev:=System.InterlockedCompareExchange(cardinal(a.FStorage),
      cardinal(lNew), cardinal(lNew));
    {$ENDIF}

    if lPrev = lOld then
      Exit;

    lOld:=lPrev;
    lSpin.SpinCycle;
  until False;
end;

{$ENDREGION 'TOsslLoader Support types '}

{ TOsslLoader }

{$REGION 'TOsslLoader Class methods'}

class function TOsslLoader.GetLoader: TOsslLoader;
begin
  // additional parentheses around static generic method call is a
  // workaround for https://gitlab.com/freepascal.org/fpc/source/-/issues/39881
  if not (TOsslCustomLoader.GetLoader<TOsslLoader>(Result)) then
    RaiseExceptionRes(@resLoaderUnsupported);
end;

class function TOsslLoader.NewPathStringList(APaths: string): TStringList;
const
{$IFDEF T_WINDOWS}
  cCaseSensitive = False;
{$ELSE}
  cCaseSensitive = True;
{$ENDIF}

begin
{$IFDEF DCC}
  Result:=TStringList.Create(dupIgnore, False, cCaseSensitive);
{$ENDIF}
{$IFDEF FPC}
  Result:=TStringList.Create;
  Result.Duplicates:=dupIgnore;
  Result.Sorted:=False;
  Result.CaseSensitive:=cCaseSensitive;
{$ENDIF}
  Result.QuoteChar:=#0;
  Result.Delimiter:=TPath.PathSeparator;
  Result.DelimitedText:=APaths;
end;

class function TOsslLoader.SysLoadLibrary(const ALibName: string;
  ASuppressException: boolean; out ALibVer: TOsslVersion): TLibHandle;
const
  {$IFDEF T_WINDOWS}
    cErrMode = SEM_FAILCRITICALERRORS;
  {$ELSE}
    cErrMode = 0;
  {$ENDIF}
begin
  Result:=TLibHandle.Create(ALibName);
  if Result.IsEmpty then
  begin
    if not ASuppressException then
      EOsslLib.RaiseLastOSError;
  end
  else if not CheckLibVersion(Result, ALibVer) then
  begin
    FreeLibrary(Result);

    RaiseExceptionResFmt(@resNoVersionFound, [ALibName]);
  end;
end;

class function TOsslLoader.GetLibName(ALibType: TLibType): string;
begin
  Result:=cLibNames[ALibType];
end;

class function TOsslLoader.GetLoadedPath: string;
begin
  Result:=GetLoader.InstanceLoadedPath;
end;

class function TOsslLoader.GetFlags: TLoaderFlags;
begin
  Result:=GetLoader.InstanceFlags;
end;

class procedure TOsslLoader.SetFlags(const Value: TLoaderFlags);
begin
  GetLoader.InstanceFlags:=Value;
end;

class function TOsslLoader.GetSearchPath: string;
begin
  Result:=GetLoader.InstanceSearchPath;
end;

class procedure TOsslLoader.SetSearchPaths(const Value: string);
begin
  GetLoader.InstanceSearchPath:=Value;
end;

class function TOsslLoader.CheckLibVersion(ALibHandle: TLibHandle;
  out AVersion: TOsslVersion): boolean;
var
  lVerFunc: function: culong; cdecl;
  lVerVal: culong;

begin
  // Open SSL v3.0+ provides a `OpenSSL_version_num` routine that returns the
  // OpenSsl version from both libraries.
  // OpenSsl v1.1.x and below provides `SSLeay` routine for retriving the version.
  Result:=False;
  lVerVal:=0;

  // Try `OpenSSL_version_num` first
  @lVerFunc:=GetProcAddress(ALibHandle, PChar(cLib3VersionProc));

  // Try `SSLeay` if no `OpenSSL_version_num` found
  if not Assigned(@lVerFunc) then
    @lVerFunc:=GetProcAddress(ALibHandle, PChar(cLib1VersionProc));

  // Retrive and return the version
  if Assigned(@lVerFunc) then
  begin
    lVerVal:=lVerFunc();
    Result:=True;
  end;

  AVersion:=TOsslVersion.Create(lVerVal);
end;

class procedure TOsslLoader.Load(ALibTypes: TLibTypes; ALibPaths: string);
begin
  GetLoader.InternalLoad(ALibTypes, ALibPaths);
end;

{$ENDREGION}

{$REGION 'TOsslLoader Instance methods'}

function TOsslLoader.DoGetFlags: TLoaderFlags;
begin
  Result:=FFlags;
end;

procedure TOsslLoader.DoSetFlags(const Value: TLoaderFlags);
begin
  FFlags:=Value;
end;

procedure TOsslLoader.DoSetSearchPaths(ALibPaths: string);
var
  lLibPathStrings: TStringList;
  lPath, lAddPath, lLibPaths: string;
  lPathSeparator: char;

begin
{$IFDEF T_WINDOWS}
  if SameText(InstanceSearchPath, ALibPaths) then
{$ELSE}
  if SameStr(InstanceSearchPath, ALibPaths) then
{$ENDIF}
  Exit;

  lPathSeparator:=TPath.PathSeparator;
  lLibPathStrings:=nil;
  lLibPaths:='';

  if not ALibPaths.IsEmpty then
  try
    lLibPathStrings:=NewPathStringList(ALibPaths);
    for lPath in lLibPathStrings do
    begin
      lAddPath:='';
      if not TPath.HasValidPathChars(lPath, False) then
        // RAISE EXCEPTION
        ;
      if lfPathNormalize in InstanceFlags then
      begin
        lAddPath:=TPath.GetFullPath(lPath);
        if Length(lAddPath) > 0 then
        begin
          if Length(lLibPaths) > 0 then
            lLibPaths:=lLibPaths+lPathSeparator;
          lLibPaths:=lLibPaths+lAddPath;
        end;
      end;
    end;
  finally
    lLibPathStrings.Free;
  end;
  InstanceSearchPath:=lLibPaths;
end;

function TOsslLoader.DoLoadLibrary(ALibType: TLibType): TLibHandle;
var
  lSearchPathStrings: TStringList;
  lPath: string;
  lLibPath: string;
  lLibVer: TOsslVersion;
  lSuppressException: boolean;

begin
  Result:=TLibHandle.cNilHandle;

  if InstIsLibLoaded[ALibType] then
    Exit(InstLibHandle[ALibType]);

  if (ALibType <> cBaseLibType) and (not InstIsLibLoaded[cBaseLibType]) then
    DoLoadLibrary(cBaseLibType);

  Result:=TLibHandle.cNilHandle;
  lLibPath:='';
  lLibVer:=0;
  lSearchPathStrings:=nil;

  try
    if (ALibType = cBaseLibType) then
    try
      // Parse paths string and return paths as String List
      lSearchPathStrings:=NewPathStringList(InstanceSearchPath);

      // Add currend disrectory and empty path to allow search library
      // in the currect directory and in the system `PATH`
      if not (lfStrictPath in InstanceFlags) then
      begin
        { TODO : Add application directory path }

        lSearchPathStrings.Add(TDirectory.GetCurrentDirectory);
        if not IsLibrary then
          lSearchPathStrings.Add(TPath.GetDirectoryName(ParamStr(0)));
        lSearchPathStrings.Add(''); // allow to find lib in system path
      end;

      // loop through the list of paths and try to load `LibCrypto`
      for lPath in lSearchPathStrings do
      begin
        lSuppressException:=lPath.IsEmpty;
        if lSuppressException then
          lLibPath:=LibName[ALibType]
        else
          lLibPath:=TPath.GetFullPath(TPath.Combine(lPath, LibName[ALibType]));

        if lSuppressException or TFile.Exists(lLibPath) then
        begin
          Result:=SysLoadLibrary(lLibPath, lSuppressException, lLibVer);

          if not Result.IsEmpty then
          begin
            if  lLibVer < cMinVersion then
            begin
            // Incompatible OopenSSL library version.
              RaiseExceptionResFmt(@resLoadLibVersionIncompatible,
                [lLibPath, lLibVer.AsString]);
            end;

            lLibPath:=TPath.GetFullPath(TPath.GetDirectoryName(Result.FileName));

            InstLibHandle[cBaseLibType]:=Result;
            InstLibVersion[cBaseLibType]:=lLibVer;
            FLoadedPath:=lLibPath;
            Break;
          end;
        end;
      end;

      if Result.IsEmpty then
        RaiseExceptionResFmt(@resLoadLibNotFound,
          [LibName[ALibType], lSearchPathStrings.DelimitedText]);

    finally
      lSearchPathStrings.Free;
    end
    else
    begin
      lLibPath:=TPath.GetFullPath(TPath.Combine(FLoadedPath, LibName[ALibType]));
      if not TFile.Exists(lLibPath) then
        RaiseExceptionResFmt(@resLoadLibNotFound, [LibName[ALibType], FLoadedPath]);

      Result:=SysLoadLibrary(lLibPath, False, lLibVer);
      if not InstLibVersion[cBaseLibType].AreCompatible(lLibVer) then
        //RAISE EXCEPTION
        RaiseExceptionResFmt(@resLoadLibVersionsIncompatible,
          [LibName[cBaseLibType], LibName[ALibType],
           InstLibVersion[cBaseLibType].AsString, lLibVer.AsString]);

      InstLibHandle[ALibType]:=Result;
      InstLibVersion[ALibType]:=lLibVer;
    end;

  except
    if not Result.IsEmpty then
      FreeLibrary(Result);
    raise
  end;
end;

procedure TOsslLoader.InternalLoad(ALibTypes: TLibTypes; ASearchPath: string);
var
  lLibsLoaded: TLibTypes;

begin
  BindLock;
  try
    lLibsLoaded:=InstLibsLoaded;
    if lLibsLoaded = ALibTypes then
      Exit; // Already loaded

    if lLibsLoaded = [] then
      FSearchPath:=ASearchPath; // LibPaths can be changed only if no Lib is loaded

    InternalLoad(ALibTypes);
  finally
    BindUnlock;
  end;
end;

procedure TOsslLoader.InternalLoad(ALibTypes: TLibTypes);
var
  lLibType: TLibType;
  lLibsLoaded: TLibTypes;

begin
  lLibsLoaded:=[];
  for lLibType in ALibTypes do
  begin
    Include(lLibsLoaded, lLibType);
    DoLoadLibrary(lLibType);
  end;
  try
    DoBind(ALibTypes);
  except
    InternalUnload(lLibsLoaded);
    raise;
  end;
end;

procedure TOsslLoader.InternalUnload(ALibTypes: TLibTypes);
var
  lLibType: TLibType;

begin
  if ALibTypes = [] then
    Exit;

  DoUnBind(ALibTypes);
  for lLibType:=High(TLibType) downto Low(TLibType) do
    if InstIsLibLoaded[lLibType] then
    try
      FreeLibrary(InstLibHandle[lLibType]);
    finally
      InstLibHandle[lLibType]:=TLibHandle.cNilHandle;
    end;
end;

{$ENDREGION 'TOsslLoader Instance methods'}

{$ENDREGION 'TOsslLoader implementation'}

{$ENDIF LINK_DYNAMIC}

end.
