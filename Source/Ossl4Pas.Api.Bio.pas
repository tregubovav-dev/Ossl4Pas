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

unit Ossl4Pas.Api.Bio;

{$INCLUDE 'Ossl4Pas_CompilerDefines.inc'}

interface

uses
  Ossl4Pas.CTypes,
  Ossl4Pas.Api.Types,
  Ossl4Pas.Types,
  Ossl4Pas.Loader,
  Ossl4Pas.Binding;

type
  /// <summary>
  ///   Metaclass type for BIO Methods, used for passing types to factories.
  /// </summary>
  TOsslBioMethodClass = class of TOsslBioCustomMethod;

  /// <summary>
  ///   Abstract base class for OpenSSL BIO Methods (VMTs).
  /// </summary>
  /// <remarks>
  ///   Specific implementations (Memory, File, Socket) inherit from this
  ///   and bind their own factory functions.
  /// </remarks>
  TOsslBioCustomMethod = class abstract
  protected
    /// <summary>
    ///   Returns the raw OpenSSL BIO_METHOD pointer.
    /// </summary>
    class function GetMethodHandle: PBIO_METHOD; virtual; abstract;
  public
    property MethodHandle: PBIO_METHOD read GetMethodHandle;
  end;

  // ---------------------------------------------------------------------------
  // CONCRETE IMPLEMENTATIONS
  // ---------------------------------------------------------------------------

  /// <summary>
  ///   Wrapper for BIO_s_mem().
  ///   A memory BIO is a source/sink that reads/writes to a memory buffer.
  /// </summary>
  TOsslBioMethodMem = class(TOsslBioCustomMethod)
  private type
    TRoutine_BIO_s_mem = function: PBIO_METHOD; cdecl;

  private class var
     FBioSMem: TRoutine_BIO_s_mem;

  const
    cBindings: array[0..0] of TOsslBindEntry = (
      (Name: 'BIO_s_mem';
       VarPtr: @@TOsslBioMethodMem.FBioSMem;
       MinVer: 0)
    );
  private
    class procedure Bind(const ALibHandle: TLibHandle;
      const AVersion: TOsslVersion); static;
    class procedure UnBind; static;
  protected
    class function GetMethodHandle: PBIO_METHOD; override;
  public
    class constructor Create;
  end;

  /// <summary>
  ///   Wrapper for BIO_s_file().
  ///   A file BIO is a source/sink that wraps standard C library file streams.
  /// </summary>
  TOsslBioMethodFile = class(TOsslBioCustomMethod)
  private type
    TRoutine_BIO_s_file = function: PBIO_METHOD; cdecl;

  private class var
    FBioSFile: TRoutine_BIO_s_file;

  const
    cBioFileBindings: array[0..0] of TOsslBindEntry = (
      (Name: 'BIO_s_file';
       VarPtr: @@TOsslBioMethodFile.FBioSFile;
       MinVer: 0)
    );

  private
    class procedure Bind(const ALibHandle: TLibHandle;
      const AVersion: TOsslVersion); static;
    class procedure UnBind; static;
  protected
    class function GetMethodHandle: PBIO_METHOD; override;
  public
    class constructor Create;
  end;

  /// <summary>
  ///   Wrapper for BIO_s_socket().
  ///   A socket BIO is a source/sink that wraps a raw OS network socket.
  /// </summary>
  TOsslBioMethodSocket = class(TOsslBioCustomMethod)
  private type
    TRoutine_BIO_s_socket = function: PBIO_METHOD; cdecl;

  private class var
    FBioSSsocket: TRoutine_BIO_s_socket;

  const
    cBioSocketBindings: array[0..0] of TOsslBindEntry = (
      (Name: 'BIO_s_socket';
       VarPtr: @@TOsslBioMethodSocket.FBioSSsocket;
       MinVer: 0)
    );

  private
    class procedure Bind(const ALibHandle: TLibHandle;
      const AVersion: TOsslVersion); static;
    class procedure UnBind; static;
  protected
    class function GetMethodHandle: PBIO_METHOD; override;
  public
    class constructor Create;
  end;

  /// <summary>
  ///   Wrapper for BIO_s_null().
  ///   A null BIO discards all data written to it and returns EOF on read.
  /// </summary>
  TOsslBioMethodNull = class(TOsslBioCustomMethod)
  private type
    TRoutine_BIO_s_null = function: PBIO_METHOD; cdecl;

  private class var
    FBioSNull: TRoutine_BIO_s_null;

  const
    cBioNullBindings: array[0..0] of TOsslBindEntry = (
      (Name: 'BIO_s_null';
       VarPtr: @@TOsslBioMethodNull.FBioSNull;
       MinVer: 0)
    );

  private
    class procedure Bind(const ALibHandle: TLibHandle;
      const AVersion: TOsslVersion); static;
    class procedure UnBind; static;
  protected
    class function GetMethodHandle: PBIO_METHOD; override;
  public
    class constructor Create;
  end;

type
  TOsslBioBase = class
  protected type
    // OpenSsl warpper procedural types
    TRoutine_BIO_new         = function(AMethod: PBIO_METHOD): PBIO; cdecl;
    TRoutine_BIO_new_mem_buf = function(ABuf: Pointer; len: cint): PBIO; cdecl;
    TRoutine_BIO_free        = function(a: PBIO): cint; cdecl;
    TRoutine_BIO_up_ref      = function(a: PBIO): cint; cdecl;
    TRoutine_BIO_read        = function(b: PBIO; data: Pointer; dlen: cint): cint; cdecl;
    TRoutine_BIO_write       = function(b: PBIO; data: Pointer; dlen: cint): cint; cdecl;
    TRoutine_BIO_ctrl        = function(b: PBIO; cmd: cint; larg: clong; parg: Pointer): clong; cdecl;
    TRoutine_BIO_push        = function(b: PBIO; append: PBIO): PBIO; cdecl;
    TRoutine_BIO_pop         = function(b: PBIO): PBIO; cdecl;
    TRoutine_BIO_next        = function(b: PBIO): PBIO; cdecl;

    /// <summary>
    ///   Encapsulates BIO control operations (Reset, Flush, EOF, Pending).
    /// </summary>
    TOsslBioCtrl = record
    private
      FHandle: PBIO;
      function Op(Cmd: Integer; LArg: clong; PArg: Pointer): clong;
        {$IFDEF INLINE_ON}inline;{$ENDIF}
    public
      /// <summary>Initializes the helper with a raw handle.</summary>
      constructor Create(AHandle: PBIO);

      /// <summary>Resets the BIO to its initial state.</summary>
      function Reset: Boolean;
      /// <summary>Flushes any buffered output.</summary>
      function Flush: Boolean;
      /// <summary>Returns true if the BIO has reached End-Of-File.</summary>
      function EOF: Boolean;
      /// <summary>Returns the number of bytes pending in the read/write buffer.</summary>
      function Pending: Integer;
      /// <summary>Returns the number of bytes pending in the write buffer.</summary>
      function WritePending: Integer;
    end;

    /// <summary>
    ///   Encapsulates BIO Chain management (Push, Pop, Next).
    /// </summary>
    TOsslBioChain = record
    private
      FHandle: PBIO;
    public
      constructor Create(AHandle: PBIO);

      /// <summary>Appends a BIO to this chain.</summary>
      function Push(Append: PBIO): PBIO;
      /// <summary>Removes this BIO from a chain.</summary>
      function Pop: PBIO;
      /// <summary>Returns the next BIO in the chain.</summary>
      function Next: PBIO;
    end;
  strict private class var
    F_Bio_new:          TRoutine_BIO_new;
    F_BIO_new_mem_buf:  TRoutine_BIO_new_mem_buf;
    F_BIO_free:         TRoutine_BIO_free;
    F_BIO_up_ref:       TRoutine_BIO_up_ref;
    F_BIO_read:         TRoutine_BIO_read;
    F_BIO_write:        TRoutine_BIO_write;
    F_BIO_ctrl:         TRoutine_BIO_ctrl;
    F_BIO_push:         TRoutine_BIO_push;
    F_BIO_pop:          TRoutine_BIO_pop;
    F_BIO_next:         TRoutine_BIO_next;
  const
    cBindings: array[0..9] of TOsslBindEntry = (
      (Name: 'BIO_new';         VarPtr: @@TOsslBioBase.F_Bio_new;         MinVer: 0),
      (Name: 'BIO_new_mem_buf'; VarPtr: @@TOsslBioBase.F_BIO_new_mem_buf; MinVer: 0),
      (Name: 'BIO_free';        VarPtr: @@TOsslBioBase.F_BIO_free;        MinVer: 0),
      (Name: 'BIO_up_ref';      VarPtr: @@TOsslBioBase.F_BIO_up_ref;      MinVer: 0),
      (Name: 'BIO_read';        VarPtr: @@TOsslBioBase.F_BIO_read;        MinVer: 0),
      (Name: 'BIO_write';       VarPtr: @@TOsslBioBase.F_BIO_write;       MinVer: 0),
      (Name: 'BIO_ctrl';        VarPtr: @@TOsslBioBase.F_BIO_ctrl;        MinVer: 0),
      (Name: 'BIO_push';        VarPtr: @@TOsslBioBase.F_BIO_push;        MinVer: 0),
      (Name: 'BIO_pop';         VarPtr: @@TOsslBioBase.F_BIO_pop;         MinVer: 0),
      (Name: 'BIO_next';        VarPtr: @@TOsslBioBase.F_BIO_next;        MinVer: 0)
    );
  strict private
    FHandle: PBIO;

    // Binding callbacks
    class procedure Bind(const ALibHandle: TLibHandle;
      const AVersion: TOsslVersion); static;
    class procedure UnBind; static;
  public
    class constructor Create;

    // OpenSSL routine wrappers
    class function BIO_new(AMethod: PBIO_METHOD): PBIO; static; cdecl;
      {$IFDEF INLINE_ON}inline;{$ENDIF}
    class function BIO_new_mem_buf(ABuf: Pointer; len: cint): PBIO; static;
      cdecl; {$IFDEF INLINE_ON}inline;{$ENDIF}
    class function BIO_free(a: PBIO): cint; static; cdecl;
      {$IFDEF INLINE_ON}inline;{$ENDIF}
    class function BIO_up_ref(a: PBIO): cint; static; cdecl;
      {$IFDEF INLINE_ON}inline;{$ENDIF}
    class function BIO_read(b: PBIO; data: Pointer; dlen: cint): cint; static;
      cdecl; {$IFDEF INLINE_ON}inline;{$ENDIF}
    class function BIO_write(b: PBIO; data: Pointer; dlen: cint): cint; static;
      cdecl; {$IFDEF INLINE_ON}inline;{$ENDIF}
    class function BIO_ctrl(bp: PBIO; cmd: cint; larg: clong;
      parg: Pointer): clong; static; cdecl; {$IFDEF INLINE_ON}inline;{$ENDIF}
    class function BIO_push(b: PBIO; append: PBIO): PBIO; static; cdecl;
      {$IFDEF INLINE_ON}inline;{$ENDIF}
    class function BIO_pop(b: PBIO): PBIO; static; cdecl;
      {$IFDEF INLINE_ON}inline;{$ENDIF}
    class function BIO_next(b: PBIO): PBIO; static; cdecl;
      {$IFDEF INLINE_ON}inline;{$ENDIF}

    // instance methods
    constructor Create(AMethod: TOsslBioCustomMethod); overload;
    constructor Create(AData: pointer; ADataLen: cint); overload;
    destructor Destroy; override;

    property Handle: PBIO read FHandle;
  end;


implementation

{ ============================================================================
  TOsslBioMethodMem (Memory)
  ============================================================================ }

class constructor TOsslBioMethodMem.Create;
begin
  UnBind;
  TOsslLoader.RegisterBinding(ltCrypto, @Bind, @UnBind);
end;

class procedure TOsslBioMethodMem.Bind(const ALibHandle: TLibHandle;
  const AVersion: TOsslVersion);
begin
  TOsslBinding.Bind(ALibHandle, AVersion, cBindings);
end;

class procedure TOsslBioMethodMem.UnBind;
begin
  TOsslBinding.Reset(cBindings);
end;

class function TOsslBioMethodMem.GetMethodHandle: PBIO_METHOD;
begin
  Result:=FBioSMem();
end;

{ ============================================================================
  TOsslBioMethodFile (File)
  ============================================================================ }

class constructor TOsslBioMethodFile.Create;
begin
  UnBind;
  TOsslLoader.RegisterBinding(ltCrypto, @Bind, @UnBind);
end;

class procedure TOsslBioMethodFile.Bind(const ALibHandle: TLibHandle;
  const AVersion: TOsslVersion);
begin
  TOsslBinding.Bind(ALibHandle, AVersion, cBioFileBindings);
end;

class procedure TOsslBioMethodFile.UnBind;
begin
  TOsslBinding.Reset(cBioFileBindings);
end;

class function TOsslBioMethodFile.GetMethodHandle: PBIO_METHOD;
begin
  Result:=FBioSFile();
end;

{ ============================================================================
  TOsslBioMethodSocket (Socket)
  ============================================================================ }

class constructor TOsslBioMethodSocket.Create;
begin
  UnBind;
  TOsslLoader.RegisterBinding(ltCrypto, @Bind, @UnBind);
end;

class procedure TOsslBioMethodSocket.Bind(const ALibHandle: TLibHandle;
  const AVersion: TOsslVersion);
begin
  TOsslBinding.Bind(ALibHandle, AVersion, cBioSocketBindings);
end;

class procedure TOsslBioMethodSocket.UnBind;
begin
  TOsslBinding.Reset(cBioSocketBindings);
end;

class function TOsslBioMethodSocket.GetMethodHandle: PBIO_METHOD;
begin
  Result:=FBioSSsocket();
end;

{ ============================================================================
  TOsslBioMethodNull (Null/Sink)
  ============================================================================ }

class constructor TOsslBioMethodNull.Create;
begin
  UnBind;
  TOsslLoader.RegisterBinding(ltCrypto, @Bind, @UnBind);
end;

class procedure TOsslBioMethodNull.Bind(const ALibHandle: TLibHandle;
  const AVersion: TOsslVersion);
begin
  TOsslBinding.Bind(ALibHandle, AVersion, cBioNullBindings);
end;

class procedure TOsslBioMethodNull.UnBind;
begin
  TOsslBinding.Reset(cBioNullBindings);
end;

class function TOsslBioMethodNull.GetMethodHandle: PBIO_METHOD;
begin
  Result:=FBioSNull();
end;

{ TOsslBioBase.TOsslBioCtrl }

constructor TOsslBioBase.TOsslBioCtrl.Create(AHandle: PBIO);
begin

end;

function TOsslBioBase.TOsslBioCtrl.EOF: Boolean;
begin

end;

function TOsslBioBase.TOsslBioCtrl.Flush: Boolean;
begin

end;

function TOsslBioBase.TOsslBioCtrl.Op(Cmd: Integer; LArg: clong;
  PArg: Pointer): clong;
begin

end;

function TOsslBioBase.TOsslBioCtrl.Pending: Integer;
begin

end;

function TOsslBioBase.TOsslBioCtrl.Reset: Boolean;
begin

end;

function TOsslBioBase.TOsslBioCtrl.WritePending: Integer;
begin

end;

{ TOsslBioBase.TOsslBioChain }

constructor TOsslBioBase.TOsslBioChain.Create(AHandle: PBIO);
begin

end;

function TOsslBioBase.TOsslBioChain.Next: PBIO;
begin

end;

function TOsslBioBase.TOsslBioChain.Pop: PBIO;
begin

end;

function TOsslBioBase.TOsslBioChain.Push(Append: PBIO): PBIO;
begin

end;

{ TOsslBioBase }

class constructor TOsslBioBase.Create;
begin
  UnBind;
  TOsslCustomLoader.RegisterBinding(ltCrypto, Bind, UnBind);
end;

class procedure TOsslBioBase.Bind(
  const ALibHandle: TLibHandle; const AVersion: TOsslVersion);
begin
  TOsslBinding.Bind(ALibHandle, AVersion, cBindings)
end;

class procedure TOsslBioBase.UnBind;
begin
  TOsslBinding.Reset(cBindings);
end;

class function TOsslBioBase.BIO_new(AMethod: PBIO_METHOD): PBIO;
begin
  Result:=F_Bio_new(AMethod);
end;

class function TOsslBioBase.BIO_new_mem_buf(ABuf: Pointer; len: cint): PBIO;
begin
  Result:=F_BIO_new_mem_buf(ABuf, len);
end;

class function TOsslBioBase.BIO_free(a: PBIO): cint;
begin
  Result:=F_BIO_free(a);
end;

class function TOsslBioBase.BIO_up_ref(a: PBIO): cint;
begin
  Result:=F_BIO_up_ref(a);
end;

class function TOsslBioBase.BIO_read(b: PBIO; data: Pointer; dlen: cint): cint;
begin
  Result:=F_BIO_read(b, data, dlen);
end;

class function TOsslBioBase.BIO_write(b: PBIO; data: Pointer; dlen: cint): cint;
begin
  Result:=F_BIO_write(b, data, dlen);
end;

class function TOsslBioBase.BIO_ctrl(bp: PBIO; cmd: cint; larg: clong;
  parg: Pointer): clong;
begin
  Result:=F_BIO_ctrl(bp, cmd, larg, parg);
end;

class function TOsslBioBase.BIO_push(b, append: PBIO): PBIO;
begin
  Result:=F_BIO_push(b, append);
end;

class function TOsslBioBase.BIO_pop(b: PBIO): PBIO;
begin
  Result:=F_BIO_pop(b);
end;

class function TOsslBioBase.BIO_next(b: PBIO): PBIO;
begin
  Result:=F_BIO_next(b);
end;

constructor TOsslBioBase.Create(AMethod: TOsslBioCustomMethod);
begin
  FHandle:=BIO_new(AMethod.MethodHandle);
end;

constructor TOsslBioBase.Create(AData: pointer; ADataLen: cint);
begin
  FHandle:=BIO_new_mem_buf(AData, ADataLen);
end;

destructor TOsslBioBase.Destroy;
begin
  BIO_free(FHandle);
  inherited;
end;

end.
