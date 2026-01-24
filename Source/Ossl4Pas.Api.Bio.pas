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

const
  { There are the classes of BIOs }
  BIO_TYPE_DESCRIPTOR     = $0100; // socket, fd, connect or accept
  BIO_TYPE_FILTER         = $0200;
  BIO_TYPE_SOURCE_SINK    = $0400;

  { These are the 'types' of BIOs }
  BIO_TYPE_NONE           = 0;
  BIO_TYPE_MEM            = (1 or BIO_TYPE_SOURCE_SINK);
  BIO_TYPE_FILE           = (2 or BIO_TYPE_SOURCE_SINK);

  BIO_TYPE_FD             = (4 or BIO_TYPE_SOURCE_SINK or BIO_TYPE_DESCRIPTOR);
  BIO_TYPE_SOCKET         = (5 or BIO_TYPE_SOURCE_SINK or BIO_TYPE_DESCRIPTOR);
  BIO_TYPE_NULL           = (6 or BIO_TYPE_SOURCE_SINK);
  BIO_TYPE_SSL            = (7 or BIO_TYPE_FILTER);
  BIO_TYPE_MD             = (8 or BIO_TYPE_FILTER);
  BIO_TYPE_BUFFER         = (9 or BIO_TYPE_FILTER);
  BIO_TYPE_CIPHER         = (10 or BIO_TYPE_FILTER);
  BIO_TYPE_BASE64         = (11 or BIO_TYPE_FILTER);
  BIO_TYPE_CONNECT        = (12 or BIO_TYPE_SOURCE_SINK or BIO_TYPE_DESCRIPTOR);
  BIO_TYPE_ACCEPT         = (13 or BIO_TYPE_SOURCE_SINK or BIO_TYPE_DESCRIPTOR);

  BIO_TYPE_NBIO_TEST      = (16 or BIO_TYPE_FILTER); // server proxy BIO
  BIO_TYPE_NULL_FILTER    = (17 or BIO_TYPE_FILTER);
  BIO_TYPE_BIO            = (19 or BIO_TYPE_SOURCE_SINK); // half a BIO pair
  BIO_TYPE_LINEBUFFER     = (20 or BIO_TYPE_FILTER);
  BIO_TYPE_DGRAM          = (21 or BIO_TYPE_SOURCE_SINK or BIO_TYPE_DESCRIPTOR);
  BIO_TYPE_ASN1           = (22 or BIO_TYPE_FILTER);
  BIO_TYPE_COMP           = (23 or BIO_TYPE_FILTER);

  {$IFNDEF OPENSSL_NO_SCTP}
  BIO_TYPE_DGRAM_SCTP     = (24 or BIO_TYPE_SOURCE_SINK or BIO_TYPE_DESCRIPTOR);
  {$ENDIF}
  BIO_TYPE_CORE_TO_PROV   = (25 or BIO_TYPE_SOURCE_SINK);
  BIO_TYPE_DGRAM_PAIR     = (26 or BIO_TYPE_SOURCE_SINK);
  BIO_TYPE_DGRAM_MEM      = (27 or BIO_TYPE_SOURCE_SINK);

  { Custom type starting index returned by BIO_get_new_index() }
  BIO_TYPE_START          = 128;
  { Custom type maximum index that can be returned by BIO_get_new_index() }
  BIO_TYPE_MASK           = $FF;

const
  {
    BIO_FILENAME_READ|BIO_CLOSE to open or close on free.
    BIO_set_fp(in,stdin,BIO_NOCLOSE);
  }
  BIO_NOCLOSE             = $00;
  BIO_CLOSE               = $01;

const
  { These are used in the following macros and are passed to BIO_ctrl() }
  BIO_CTRL_RESET          = 1;  // opt - rewind/zero etc
  BIO_CTRL_EOF            = 2;  // opt - are we at the eof
  BIO_CTRL_INFO           = 3;  // opt - extra tit-bits
  BIO_CTRL_SET            = 4;  // man - set the 'IO' type
  BIO_CTRL_GET            = 5;  // man - get the 'IO' type
  BIO_CTRL_PUSH           = 6;  // opt - internal, used to signify change
  BIO_CTRL_POP            = 7;  // opt - internal, used to signify change
  BIO_CTRL_GET_CLOSE      = 8;  // man - set the 'close' on free
  BIO_CTRL_SET_CLOSE      = 9;  // man - set the 'close' on free
  BIO_CTRL_PENDING        = 10; // opt - is their more data buffered
  BIO_CTRL_FLUSH          = 11; // opt - 'flush' buffered output
  BIO_CTRL_DUP            = 12; // man - extra stuff for 'duped' BIO
  BIO_CTRL_WPENDING       = 13; // opt - number of bytes still to write
  BIO_CTRL_SET_CALLBACK   = 14; // opt - set callback function
  BIO_CTRL_GET_CALLBACK   = 15; // opt - set callback function

  BIO_CTRL_PEEK           = 29; // BIO_f_buffer special
  BIO_CTRL_SET_FILENAME   = 30; // BIO_s_file special

  { dgram BIO stuff }
  BIO_CTRL_DGRAM_CONNECT            = 31; // BIO dgram special
  BIO_CTRL_DGRAM_SET_CONNECTED      = 32; // allow for an externally connected socket to be passed in
  BIO_CTRL_DGRAM_SET_RECV_TIMEOUT   = 33; // setsockopt, essentially
  BIO_CTRL_DGRAM_GET_RECV_TIMEOUT   = 34; // getsockopt, essentially
  BIO_CTRL_DGRAM_SET_SEND_TIMEOUT   = 35; // setsockopt, essentially
  BIO_CTRL_DGRAM_GET_SEND_TIMEOUT   = 36; // getsockopt, essentially

  BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP = 37; // flag whether the last
  BIO_CTRL_DGRAM_GET_SEND_TIMER_EXP = 38; // I/O operation timed out

  { #ifdef IP_MTU_DISCOVER }
  BIO_CTRL_DGRAM_MTU_DISCOVER       = 39; // set DF bit on egress packets
  { #endif }

  BIO_CTRL_DGRAM_QUERY_MTU          = 40; // as kernel for current MTU
  BIO_CTRL_DGRAM_GET_FALLBACK_MTU   = 47;
  BIO_CTRL_DGRAM_GET_MTU            = 41; // get cached value for MTU
  BIO_CTRL_DGRAM_SET_MTU            = 42; // set cached value for MTU. want to use this if asking the kernel fails

  BIO_CTRL_DGRAM_MTU_EXCEEDED       = 43; // check whether the MTU was exceed in the previous write operation

  BIO_CTRL_DGRAM_GET_PEER           = 46;
  BIO_CTRL_DGRAM_SET_PEER           = 44; // Destination for the data

  BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT   = 45; // Next DTLS handshake timeout to adjust socket timeouts
  BIO_CTRL_DGRAM_SET_DONT_FRAG      = 48;

  BIO_CTRL_DGRAM_GET_MTU_OVERHEAD   = 49;

  { Deliberately outside of OPENSSL_NO_SCTP - used in bss_dgram.c }
  BIO_CTRL_DGRAM_SCTP_SET_IN_HANDSHAKE = 50;

  { SCTP stuff }
  BIO_CTRL_DGRAM_SCTP_ADD_AUTH_KEY  = 51;
  BIO_CTRL_DGRAM_SCTP_NEXT_AUTH_KEY = 52;
  BIO_CTRL_DGRAM_SCTP_AUTH_CCS_RCVD = 53;
  BIO_CTRL_DGRAM_SCTP_GET_SNDINFO   = 60;
  BIO_CTRL_DGRAM_SCTP_SET_SNDINFO   = 61;
  BIO_CTRL_DGRAM_SCTP_GET_RCVINFO   = 62;
  BIO_CTRL_DGRAM_SCTP_SET_RCVINFO   = 63;
  BIO_CTRL_DGRAM_SCTP_GET_PRINFO    = 64;
  BIO_CTRL_DGRAM_SCTP_SET_PRINFO    = 65;
  BIO_CTRL_DGRAM_SCTP_SAVE_SHUTDOWN = 70;

  BIO_CTRL_DGRAM_SET_PEEK_MODE      = 71;

  {
   internal BIO:
   # define BIO_CTRL_SET_KTLS_SEND                 72
   # define BIO_CTRL_SET_KTLS_SEND_CTRL_MSG        74
   # define BIO_CTRL_CLEAR_KTLS_CTRL_MSG           75
  }

  BIO_CTRL_GET_KTLS_SEND            = 73;
  BIO_CTRL_GET_KTLS_RECV            = 76;

  BIO_CTRL_DGRAM_SCTP_WAIT_FOR_DRY  = 77;
  BIO_CTRL_DGRAM_SCTP_MSG_WAITING   = 78;

  { BIO_f_prefix controls }
  BIO_CTRL_SET_PREFIX               = 79;
  BIO_CTRL_SET_INDENT               = 80;
  BIO_CTRL_GET_INDENT               = 81;

  BIO_CTRL_DGRAM_GET_LOCAL_ADDR_CAP    = 82;
  BIO_CTRL_DGRAM_GET_LOCAL_ADDR_ENABLE = 83;
  BIO_CTRL_DGRAM_SET_LOCAL_ADDR_ENABLE = 84;
  BIO_CTRL_DGRAM_GET_EFFECTIVE_CAPS    = 85;
  BIO_CTRL_DGRAM_GET_CAPS              = 86;
  BIO_CTRL_DGRAM_SET_CAPS              = 87;
  BIO_CTRL_DGRAM_GET_NO_TRUNC          = 88;
  BIO_CTRL_DGRAM_SET_NO_TRUNC          = 89;

  {
   internal BIO:
   # define BIO_CTRL_SET_KTLS_TX_ZEROCOPY_SENDFILE 90
  }

  BIO_CTRL_GET_RPOLL_DESCRIPTOR      = 91;
  BIO_CTRL_GET_WPOLL_DESCRIPTOR      = 92;
  BIO_CTRL_DGRAM_DETECT_PEER_ADDR    = 93;
  BIO_CTRL_DGRAM_SET0_LOCAL_ADDR     = 94;

const
  { modifiers }
  BIO_FP_READ             = $02;
  BIO_FP_WRITE            = $04;
  BIO_FP_APPEND           = $08;
  BIO_FP_TEXT             = $10;

  BIO_FLAGS_READ          = $01;
  BIO_FLAGS_WRITE         = $02;
  BIO_FLAGS_IO_SPECIAL    = $04;
  BIO_FLAGS_RWS           = (BIO_FLAGS_READ or BIO_FLAGS_WRITE or BIO_FLAGS_IO_SPECIAL);
  BIO_FLAGS_SHOULD_RETRY  = $08;

  BIO_FLAGS_UPLINK        = 0;

  BIO_FLAGS_BASE64_NO_NL  = $100;

  {
   This is used with memory BIOs:
   BIO_FLAGS_MEM_RDONLY means we shouldn't free up or change the data in any way;
   BIO_FLAGS_NONCLEAR_RST means we shouldn't clear data on reset.
  }
  BIO_FLAGS_MEM_RDONLY    = $200;
  BIO_FLAGS_NONCLEAR_RST  = $400;
  BIO_FLAGS_IN_EOF        = $800;

  { the BIO FLAGS values 0x1000 to 0x8000 are reserved for internal KTLS flags }

const
  {
    The next three are used in conjunction with the BIO_should_io_special()
    condition.  After this returns true, BIO *BIO_get_retry_BIO(BIO *bio, int
    *reason); will walk the BIO stack and return the 'reason' for the special
    and the offending BIO. Given a BIO, BIO_get_retry_reason(bio) will return
    the code.
  }

  { Returned from the SSL bio when the certificate retrieval code had an error }
  BIO_RR_SSL_X509_LOOKUP  = $01;
  { Returned from the connect BIO when a connect would have blocked }
  BIO_RR_CONNECT          = $02;
  { Returned from the accept BIO when an accept would have blocked }
  BIO_RR_ACCEPT           = $03;

  { These are passed by the BIO callback }
  BIO_CB_FREE             = $01;
  BIO_CB_READ             = $02;
  BIO_CB_WRITE            = $03;
  BIO_CB_PUTS             = $04;
  BIO_CB_GETS             = $05;
  BIO_CB_CTRL             = $06;
  BIO_CB_RECVMMSG         = $07;
  BIO_CB_SENDMMSG         = $08;

  {
   The callback is called before and after the underling operation, The
   BIO_CB_RETURN flag indicates if it is after the call
  }
  BIO_CB_RETURN           = $80;

const
  BIO_POLL_DESCRIPTOR_TYPE_NONE    = 0;
  BIO_POLL_DESCRIPTOR_TYPE_SOCK_FD = 1;
  BIO_POLL_DESCRIPTOR_TYPE_SSL     = 2;
  BIO_POLL_DESCRIPTOR_CUSTOM_START = 8192;

const
  BIO_C_SET_CONNECT                 = 100;
  BIO_C_DO_STATE_MACHINE            = 101;
  BIO_C_SET_NBIO                    = 102;
  // # define BIO_C_SET_PROXY_PARAM                   103
  BIO_C_SET_FD                      = 104;
  BIO_C_GET_FD                      = 105;
  BIO_C_SET_FILE_PTR                = 106;
  BIO_C_GET_FILE_PTR                = 107;
  BIO_C_SET_FILENAME                = 108;
  BIO_C_SET_SSL                     = 109;
  BIO_C_GET_SSL                     = 110;
  BIO_C_SET_MD                      = 111;
  BIO_C_GET_MD                      = 112;
  BIO_C_GET_CIPHER_STATUS           = 113;
  BIO_C_SET_BUF_MEM                 = 114;
  BIO_C_GET_BUF_MEM_PTR             = 115;
  BIO_C_GET_BUFF_NUM_LINES          = 116;
  BIO_C_SET_BUFF_SIZE               = 117;
  BIO_C_SET_ACCEPT                  = 118;
  BIO_C_SSL_MODE                    = 119;
  BIO_C_GET_MD_CTX                  = 120;
  // # define BIO_C_GET_PROXY_PARAM                   121
  BIO_C_SET_BUFF_READ_DATA          = 122; // data to read first
  BIO_C_GET_CONNECT                 = 123;
  BIO_C_GET_ACCEPT                  = 124;
  BIO_C_SET_SSL_RENEGOTIATE_BYTES   = 125;
  BIO_C_GET_SSL_NUM_RENEGOTIATES    = 126;
  BIO_C_SET_SSL_RENEGOTIATE_TIMEOUT = 127;
  BIO_C_FILE_SEEK                   = 128;
  BIO_C_GET_CIPHER_CTX              = 129;
  BIO_C_SET_BUF_MEM_EOF_RETURN      = 130; // return end of input value
  BIO_C_SET_BIND_MODE               = 131;
  BIO_C_GET_BIND_MODE               = 132;
  BIO_C_FILE_TELL                   = 133;
  BIO_C_GET_SOCKS                   = 134;
  BIO_C_SET_SOCKS                   = 135;

  BIO_C_SET_WRITE_BUF_SIZE          = 136; // for BIO_s_bio
  BIO_C_GET_WRITE_BUF_SIZE          = 137;
  BIO_C_MAKE_BIO_PAIR               = 138;
  BIO_C_DESTROY_BIO_PAIR            = 139;
  BIO_C_GET_WRITE_GUARANTEE         = 140;
  BIO_C_GET_READ_REQUEST            = 141;
  BIO_C_SHUTDOWN_WR                 = 142;
  BIO_C_NREAD0                      = 143;
  BIO_C_NREAD                       = 144;
  BIO_C_NWRITE0                     = 145;
  BIO_C_NWRITE                      = 146;
  BIO_C_RESET_READ_REQUEST          = 147;
  BIO_C_SET_MD_CTX                  = 148;

  BIO_C_SET_PREFIX                  = 149;
  BIO_C_GET_PREFIX                  = 150;
  BIO_C_SET_SUFFIX                  = 151;
  BIO_C_GET_SUFFIX                  = 152;

  BIO_C_SET_EX_ARG                  = 153;
  BIO_C_GET_EX_ARG                  = 154;

  BIO_C_SET_CONNECT_MODE            = 155;

  BIO_C_SET_TFO                     = 156; // like BIO_C_SET_NBIO

  BIO_C_SET_SOCK_TYPE               = 157;
  BIO_C_GET_SOCK_TYPE               = 158;
  BIO_C_GET_DGRAM_BIO               = 159;

const
  // IP families we support, for BIO_s_connect() and BIO_s_accept()
  // Note: the underlying operating system may not support some of them
  BIO_FAMILY_IPV4                   = 4;
  BIO_FAMILY_IPV6                   = 6;
  BIO_FAMILY_IPANY                  = 256;

const
  BIO_SOCK_REUSEADDR              = $01;
  BIO_SOCK_V6_ONLY                = $02;
  BIO_SOCK_KEEPALIVE              = $04;
  BIO_SOCK_NONBLOCK               = $08;
  BIO_SOCK_NODELAY                = $10;
  BIO_SOCK_TFO                    = $20; // TCP Fast Open

const
  // Aliases kept for backward compatibility
  BIO_BIND_NORMAL                 = 0;
  BIO_BIND_REUSEADDR              = BIO_SOCK_REUSEADDR;
  BIO_BIND_REUSEADDR_IF_UNUSED    = BIO_SOCK_REUSEADDR;

const
  // If set, BIO_lookup_ex() will not resolve the address to a name
  BIO_LOOKUP_FLAG_NO_RES_ADDR     = 1;

type
  BIO_hostserv_priorities = (
    BIO_PARSE_PRIO_HOST,
    BIO_PARSE_PRIO_SERV
  );

  BIO_lookup_type = (
    BIO_LOOKUP_CLIENT,
    BIO_LOOKUP_SERVER
  );

{ ============================================================================ }
{   BIO TYPES & STRUCTS                                                        }
{ ============================================================================ }

  // Opaque types (Forward definitions in C)
  // typedef union bio_addr_st BIO_ADDR;
  TBIO_ADDR_st = record end;
  PBIO_ADDR = ^TBIO_ADDR_st;

  // typedef struct bio_addrinfo_st BIO_ADDRINFO;
  TBIO_ADDRINFO_st = record end;
  PBIO_ADDRINFO = ^TBIO_ADDRINFO_st;

  // typedef struct bio_method_st BIO_METHOD;
  TBIO_METHOD_st = record end;
  PBIO_METHOD = ^TBIO_METHOD_st;

{ ============================================================================ }
{  SCTP PARAMETER STRUCTS                                                      }
{  These are public structures used with BIO_ctrl (DTLS/SCTP).                 }
{ ============================================================================ }

  PBIO_dgram_sctp_sndinfo = ^TBIO_dgram_sctp_sndinfo;
  TBIO_dgram_sctp_sndinfo = record
    snd_sid: cuint16;
    snd_flags: cuint16;
    snd_ppid: cuint32;
    snd_context: cuint32;
  end;

  PBIO_dgram_sctp_rcvinfo = ^TBIO_dgram_sctp_rcvinfo;
  TBIO_dgram_sctp_rcvinfo = record
    rcv_sid: cuint16;
    rcv_ssn: cuint16;
    rcv_flags: cuint16;
    rcv_ppid: cuint32;
    rcv_tsn: cuint32;
    rcv_cumtsn: cuint32;
    rcv_context: cuint32;
  end;

  PBIO_dgram_sctp_prinfo = ^TBIO_dgram_sctp_prinfo;
  TBIO_dgram_sctp_prinfo = record
    pr_policy: cuint16;
    pr_value: cuint32;
  end;

type
{ ============================================================================ }
{  BIO callbacks                                                               }
{ ============================================================================ }

  TBIO_callback_fn_ex = function(b: PBIO; oper: cint; const argp: pointer;
    len: csize_t; argi: cint; argl: clong; ret: cint;
    processed: psize_t): clong; cdecl;

  TBIO_info_cb = function(b: PBIO; state: cint; res: cint): cint; cdecl;

  // Prefix and suffix callback in ASN1 BIO
  Tasn1_ps_func = function(b: PBIO; pbuf: PPointer; plen: pcint;
    parg: pointer): cint; cdecl;

  TBIO_dgram_sctp_notification_handler_fn = procedure(b: PBIO;
    context, buf: pointer); cdecl;

type
  /// <summary>
  ///   Metaclass type for BIO Methods, used for passing types to factories.
  /// </summary>
  TOsslApiBioMethodClass = class of TOsslApiBioCustomMethod;

  /// <summary>
  ///   Abstract base class for OpenSSL BIO Methods (VMTs).
  /// </summary>
  /// <remarks>
  ///   Specific implementations (Memory, File, Socket) inherit from this
  ///   and bind their own factory functions.
  /// </remarks>
  TOsslApiBioCustomMethod = class abstract
  protected type
    TRoutine_METHOD = function: PBIO_METHOD; cdecl;
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

  // ---------------------------------------------------------------------------
  // SOURCE / SINK METHODS (BIO_s_*)
  // ---------------------------------------------------------------------------

  /// <summary>Wrapper for BIO_s_file(). Standard file stream I/O.</summary>
  TOsslApiBioMethodFile = class(TOsslApiBioCustomMethod)
  private class var
    FMethod: TOsslApiBioCustomMethod.TRoutine_METHOD;
  const
    cBindings: array[0..0] of TOsslBindEntry =
      ((Name: 'BIO_s_file'; VarPtr: @@TOsslApiBioMethodFile.FMethod; MinVer: 0));
  private
    class procedure Bind(const ALibHandle: TLibHandle; const AVersion: TOsslVersion); static;
    class procedure UnBind; static;
  protected
    class function GetMethodHandle: PBIO_METHOD; override;
  public
    class constructor Create;
  end;

  /// <summary>Wrapper for BIO_s_mem(). Read/Write to memory buffer.</summary>
  TOsslApiBioMethodMem = class(TOsslApiBioCustomMethod)
  private class var
    FMethod: TOsslApiBioCustomMethod.TRoutine_METHOD;
  const
    cBindings: array[0..0] of TOsslBindEntry =
      ((Name: 'BIO_s_mem'; VarPtr: @@TOsslApiBioMethodMem.FMethod; MinVer: 0));
  private
    class procedure Bind(const ALibHandle: TLibHandle; const AVersion: TOsslVersion); static;
    class procedure UnBind; static;
  protected
    class function GetMethodHandle: PBIO_METHOD; override;
  public
    class constructor Create;
  end;

  /// <summary>Wrapper for BIO_s_secmem(). Like Mem, but uses secure heap.</summary>
  TOsslApiBioMethodSecMem = class(TOsslApiBioCustomMethod)
  private class var
    FMethod: TOsslApiBioCustomMethod.TRoutine_METHOD;
  const
    cBindings: array[0..0] of TOsslBindEntry =
      ((Name: 'BIO_s_secmem'; VarPtr: @@TOsslApiBioMethodSecMem.FMethod; MinVer: 0));
  private
    class procedure Bind(const ALibHandle: TLibHandle; const AVersion: TOsslVersion); static;
    class procedure UnBind; static;
  protected
    class function GetMethodHandle: PBIO_METHOD; override;
  public
    class constructor Create;
  end;

  /// <summary>Wrapper for BIO_s_socket(). Raw OS socket I/O.</summary>
  TOsslApiBioMethodSocket = class(TOsslApiBioCustomMethod)
  private class var
    FMethod: TOsslApiBioCustomMethod.TRoutine_METHOD;
  const cBindings: array[0..0] of TOsslBindEntry =
    ((Name: 'BIO_s_socket'; VarPtr: @@TOsslApiBioMethodSocket.FMethod; MinVer: 0));
  private
    class procedure Bind(const ALibHandle: TLibHandle; const AVersion: TOsslVersion); static;
    class procedure UnBind; static;
  protected
    class function GetMethodHandle: PBIO_METHOD; override;
  public
    class constructor Create;
  end;

  /// <summary>Wrapper for BIO_s_connect(). TCP Client connection.</summary>
  TOsslApiBioMethodConnect = class(TOsslApiBioCustomMethod)
  private class var
    FMethod: TOsslApiBioCustomMethod.TRoutine_METHOD;
  const
    cBindings: array[0..0] of TOsslBindEntry =
      ((Name: 'BIO_s_connect'; VarPtr: @@TOsslApiBioMethodConnect.FMethod; MinVer: 0));
  private
    class procedure Bind(const ALibHandle: TLibHandle; const AVersion: TOsslVersion); static;
    class procedure UnBind; static;
  protected
    class function GetMethodHandle: PBIO_METHOD; override;
  public
    class constructor Create;
  end;

  /// <summary>Wrapper for BIO_s_accept(). TCP Server acceptor.</summary>
  TOsslApiBioMethodAccept = class(TOsslApiBioCustomMethod)
  private class var
    FMethod: TOsslApiBioCustomMethod.TRoutine_METHOD;
  const
    cBindings: array[0..0] of TOsslBindEntry =
      ((Name: 'BIO_s_accept'; VarPtr: @@TOsslApiBioMethodAccept.FMethod; MinVer: 0));
  private
    class procedure Bind(const ALibHandle: TLibHandle; const AVersion: TOsslVersion); static;
    class procedure UnBind; static;
  protected
    class function GetMethodHandle: PBIO_METHOD; override;
  public
    class constructor Create;
  end;

  /// <summary>Wrapper for BIO_s_fd(). Raw File Descriptor I/O.</summary>
  TOsslApiBioMethodFd = class(TOsslApiBioCustomMethod)
  private class var
    FMethod: TOsslApiBioCustomMethod.TRoutine_METHOD;
  const
    cBindings: array[0..0] of TOsslBindEntry =
      ((Name: 'BIO_s_fd'; VarPtr: @@TOsslApiBioMethodFd.FMethod; MinVer: 0));
  private
    class procedure Bind(const ALibHandle: TLibHandle; const AVersion: TOsslVersion); static;
    class procedure UnBind; static;
  protected
    class function GetMethodHandle: PBIO_METHOD; override;
  public
    class constructor Create;
  end;

  /// <summary>Wrapper for BIO_s_log(). System logging (syslog/eventlog).</summary>
  TOsslApiBioMethodLog = class(TOsslApiBioCustomMethod)
  private class var
    FMethod: TOsslApiBioCustomMethod.TRoutine_METHOD;
  const
    cBindings: array[0..0] of TOsslBindEntry =
      ((Name: 'BIO_s_log'; VarPtr: @@TOsslApiBioMethodLog.FMethod; MinVer: 0));
  private
    class procedure Bind(const ALibHandle: TLibHandle; const AVersion: TOsslVersion); static;
    class procedure UnBind; static;
  protected
    class function GetMethodHandle: PBIO_METHOD; override;
  public
    class constructor Create;
  end;

  /// <summary>Wrapper for BIO_s_bio(). Internal BIO pair (pipe).</summary>
  TOsslApiBioMethodBio = class(TOsslApiBioCustomMethod)
  private class var
    FMethod: TOsslApiBioCustomMethod.TRoutine_METHOD;
  const
    cBindings: array[0..0] of TOsslBindEntry =
      ((Name: 'BIO_s_bio'; VarPtr: @@TOsslApiBioMethodBio.FMethod; MinVer: 0));
  private
    class procedure Bind(const ALibHandle: TLibHandle; const AVersion: TOsslVersion); static;
    class procedure UnBind; static;
  protected
    class function GetMethodHandle: PBIO_METHOD; override;
  public
    class constructor Create;
  end;

  /// <summary>Wrapper for BIO_s_null(). Discards data (Sink) / EOF (Source).</summary>
  TOsslApiBioMethodNull = class(TOsslApiBioCustomMethod)
  private class var
    FMethod: TOsslApiBioCustomMethod.TRoutine_METHOD;
  const
    cBindings: array[0..0] of TOsslBindEntry =
      ((Name: 'BIO_s_null'; VarPtr: @@TOsslApiBioMethodNull.FMethod; MinVer: 0));
  private
    class procedure Bind(const ALibHandle: TLibHandle; const AVersion: TOsslVersion); static;
    class procedure UnBind; static;
  protected
    class function GetMethodHandle: PBIO_METHOD; override;
  public
    class constructor Create;
  end;

  /// <summary>Wrapper for BIO_s_core(). OpenSSL 3.0 Core Provider integration.</summary>
  TOsslApiBioMethodCore = class(TOsslApiBioCustomMethod)
  private class var
    FMethod: TOsslApiBioCustomMethod.TRoutine_METHOD;
  const
    cBindings: array[0..0] of TOsslBindEntry =
      ((Name: 'BIO_s_core'; VarPtr: @@TOsslApiBioMethodCore.FMethod; MinVer: 0));
  private
    class procedure Bind(const ALibHandle: TLibHandle; const AVersion: TOsslVersion); static;
    class procedure UnBind; static;
  protected
    class function GetMethodHandle: PBIO_METHOD; override;
  public
    class constructor Create;
  end;

  /// <summary>Wrapper for BIO_s_dgram_pair(). UDP support.</summary>
  TOsslApiBioMethodDatagramPair = class(TOsslApiBioCustomMethod)
  private class var
    FMethod: TOsslApiBioCustomMethod.TRoutine_METHOD;
  const
    cBindings: array[0..0] of TOsslBindEntry =
      ((Name: 'BIO_s_dgram_pair'; VarPtr: @@TOsslApiBioMethodDatagramPair.FMethod; MinVer: $30200000));
  private
    class procedure Bind(const ALibHandle: TLibHandle; const AVersion: TOsslVersion); static;
    class procedure UnBind; static;
  protected
    class function GetMethodHandle: PBIO_METHOD; override;
  public
    class constructor Create;
  end;

  /// <summary>Wrapper for BIO_s_datagram(). UDP support.</summary>
  TOsslApiBioMethodDatagram = class(TOsslApiBioCustomMethod)
  private class var
    FMethod: TOsslApiBioCustomMethod.TRoutine_METHOD;
  const
    cBindings: array[0..0] of TOsslBindEntry =
      ((Name: 'BIO_s_datagram'; VarPtr: @@TOsslApiBioMethodDatagram.FMethod; MinVer: 0));
  private
    class procedure Bind(const ALibHandle: TLibHandle; const AVersion: TOsslVersion); static;
    class procedure UnBind; static;
  protected
    class function GetMethodHandle: PBIO_METHOD; override;
  public
    class constructor Create;
  end;

  /// <summary>Wrapper for BIO_s_datagram_sctp(). SCTP support.</summary>
  TOsslApiBioMethodDatagramSctp = class(TOsslApiBioCustomMethod)
  private class var
    FMethod: TOsslApiBioCustomMethod.TRoutine_METHOD;
  const
    cBindings: array[0..0] of TOsslBindEntry =
      ((Name: 'BIO_s_datagram_sctp'; VarPtr: @@TOsslApiBioMethodDatagramSctp.FMethod; MinVer: 0));
  private
    class procedure Bind(const ALibHandle: TLibHandle; const AVersion: TOsslVersion); static;
    class procedure UnBind; static;
  protected
    class function GetMethodHandle: PBIO_METHOD; override;
  public
    class constructor Create;
  end;

  // ---------------------------------------------------------------------------
  // FILTER METHODS (BIO_f_*)
  // ---------------------------------------------------------------------------

  /// <summary>Wrapper for BIO_f_null(). Transparent filter (does nothing).</summary>
  TOsslApiBioFilterNull = class(TOsslApiBioCustomMethod)
  private class var
    FMethod: TOsslApiBioCustomMethod.TRoutine_METHOD;
  const
    cBindings: array[0..0] of TOsslBindEntry =
      ((Name: 'BIO_f_null'; VarPtr: @@TOsslApiBioFilterNull.FMethod; MinVer: 0));
  private
    class procedure Bind(const ALibHandle: TLibHandle; const AVersion: TOsslVersion); static;
    class procedure UnBind; static;
  protected
    class function GetMethodHandle: PBIO_METHOD; override;
  public
    class constructor Create;
  end;

  /// <summary>Wrapper for BIO_f_buffer(). Buffering filter.</summary>
  TOsslApiBioFilterBuffer = class(TOsslApiBioCustomMethod)
  private class var
    FMethod: TOsslApiBioCustomMethod.TRoutine_METHOD;
  const
    cBindings: array[0..0] of TOsslBindEntry =
      ((Name: 'BIO_f_buffer'; VarPtr: @@TOsslApiBioFilterBuffer.FMethod; MinVer: 0));
  private
    class procedure Bind(const ALibHandle: TLibHandle; const AVersion: TOsslVersion); static;
    class procedure UnBind; static;
  protected
    class function GetMethodHandle: PBIO_METHOD; override;
  public
    class constructor Create;
  end;

  /// <summary>Wrapper for BIO_f_readbuffer(). Read-only buffering filter.</summary>
  TOsslApiBioFilterReadBuffer = class(TOsslApiBioCustomMethod)
  private class var
    FMethod: TOsslApiBioCustomMethod.TRoutine_METHOD;
  const
    cBindings: array[0..0] of TOsslBindEntry =
      ((Name: 'BIO_f_readbuffer'; VarPtr: @@TOsslApiBioFilterReadBuffer.FMethod; MinVer: 0));
  private
    class procedure Bind(const ALibHandle: TLibHandle; const AVersion: TOsslVersion); static;
    class procedure UnBind; static;
  protected
    class function GetMethodHandle: PBIO_METHOD; override;
  public
    class constructor Create;
  end;

  /// <summary>Wrapper for BIO_f_linebuffer(). Line-oriented buffering.</summary>
  TOsslApiBioFilterLineBuffer = class(TOsslApiBioCustomMethod)
  private class var
    FMethod: TOsslApiBioCustomMethod.TRoutine_METHOD;
  const
    cBindings: array[0..0] of TOsslBindEntry =
      ((Name: 'BIO_f_linebuffer'; VarPtr: @@TOsslApiBioFilterLineBuffer.FMethod; MinVer: 0));
  private
    class procedure Bind(const ALibHandle: TLibHandle; const AVersion: TOsslVersion); static;
    class procedure UnBind; static;
  protected
    class function GetMethodHandle: PBIO_METHOD; override;
  public
    class constructor Create;
  end;

  /// <summary>Wrapper for BIO_f_nbio_test(). Non-blocking I/O test filter.</summary>
  TOsslApiBioFilterNbioTest = class(TOsslApiBioCustomMethod)
  private class var
    FMethod: TOsslApiBioCustomMethod.TRoutine_METHOD;
  const
    cBindings: array[0..0] of TOsslBindEntry =
      ((Name: 'BIO_f_nbio_test'; VarPtr: @@TOsslApiBioFilterNbioTest.FMethod; MinVer: 0));
  private
    class procedure Bind(const ALibHandle: TLibHandle; const AVersion: TOsslVersion); static;
    class procedure UnBind; static;
  protected
    class function GetMethodHandle: PBIO_METHOD; override;
  public
    class constructor Create;
  end;

  /// <summary>Wrapper for BIO_f_prefix(). Prefix/Indentation filter.</summary>
  TOsslApiBioFilterPrefix = class(TOsslApiBioCustomMethod)
  private class var
    FMethod: TOsslApiBioCustomMethod.TRoutine_METHOD;
  const
    cBindings: array[0..0] of TOsslBindEntry =
      ((Name: 'BIO_f_prefix'; VarPtr: @@TOsslApiBioFilterPrefix.FMethod; MinVer: 0));
  private
    class procedure Bind(const ALibHandle: TLibHandle; const AVersion: TOsslVersion); static;
    class procedure UnBind; static;
  protected
    class function GetMethodHandle: PBIO_METHOD; override;
  public
    class constructor Create;
  end;

type
  TOsslApiBioBase = class
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
    TOsslApiBioCtrl = record
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
    TOsslApiBioChain = record
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
      (Name: 'BIO_new';         VarPtr: @@TOsslApiBioBase.F_Bio_new;         MinVer: 0),
      (Name: 'BIO_new_mem_buf'; VarPtr: @@TOsslApiBioBase.F_BIO_new_mem_buf; MinVer: 0),
      (Name: 'BIO_free';        VarPtr: @@TOsslApiBioBase.F_BIO_free;        MinVer: 0),
      (Name: 'BIO_up_ref';      VarPtr: @@TOsslApiBioBase.F_BIO_up_ref;      MinVer: 0),
      (Name: 'BIO_read';        VarPtr: @@TOsslApiBioBase.F_BIO_read;        MinVer: 0),
      (Name: 'BIO_write';       VarPtr: @@TOsslApiBioBase.F_BIO_write;       MinVer: 0),
      (Name: 'BIO_ctrl';        VarPtr: @@TOsslApiBioBase.F_BIO_ctrl;        MinVer: 0),
      (Name: 'BIO_push';        VarPtr: @@TOsslApiBioBase.F_BIO_push;        MinVer: 0),
      (Name: 'BIO_pop';         VarPtr: @@TOsslApiBioBase.F_BIO_pop;         MinVer: 0),
      (Name: 'BIO_next';        VarPtr: @@TOsslApiBioBase.F_BIO_next;        MinVer: 0)
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
    constructor Create(AMethod: TOsslApiBioCustomMethod); overload;
    constructor Create(AData: pointer; ADataLen: cint); overload;
    destructor Destroy; override;

    property Handle: PBIO read FHandle;
  end;


implementation

{ ============================================================================
  TOsslApiBioMethodMem (Memory)
  ============================================================================ }

class constructor TOsslApiBioMethodMem.Create;
begin
  UnBind;
  TOsslLoader.RegisterBinding(ltCrypto, @Bind, @UnBind);
end;

class procedure TOsslApiBioMethodMem.Bind(const ALibHandle: TLibHandle;
  const AVersion: TOsslVersion);
begin
  TOsslBinding.Bind(ALibHandle, AVersion, cBindings);
end;

class procedure TOsslApiBioMethodMem.UnBind;
begin
  TOsslBinding.Reset(cBindings);
end;

class function TOsslApiBioMethodMem.GetMethodHandle: PBIO_METHOD;
begin
  Result:=FMethod();
end;

{ ============================================================================
  TOsslApiBioMethodFile (File)
  ============================================================================ }

class constructor TOsslApiBioMethodFile.Create;
begin
  UnBind;
  TOsslLoader.RegisterBinding(ltCrypto, @Bind, @UnBind);
end;

class procedure TOsslApiBioMethodFile.Bind(const ALibHandle: TLibHandle;
  const AVersion: TOsslVersion);
begin
  TOsslBinding.Bind(ALibHandle, AVersion, cBindings);
end;

class procedure TOsslApiBioMethodFile.UnBind;
begin
  TOsslBinding.Reset(cBindings);
end;

class function TOsslApiBioMethodFile.GetMethodHandle: PBIO_METHOD;
begin
  Result:=FMethod();
end;

{ ============================================================================
  TOsslApiBioMethodSocket (Socket)
  ============================================================================ }

class constructor TOsslApiBioMethodSocket.Create;
begin
  UnBind;
  TOsslLoader.RegisterBinding(ltCrypto, @Bind, @UnBind);
end;

class procedure TOsslApiBioMethodSocket.Bind(const ALibHandle: TLibHandle;
  const AVersion: TOsslVersion);
begin
  TOsslBinding.Bind(ALibHandle, AVersion, cBindings);
end;

class procedure TOsslApiBioMethodSocket.UnBind;
begin
  TOsslBinding.Reset(cBindings);
end;

class function TOsslApiBioMethodSocket.GetMethodHandle: PBIO_METHOD;
begin
  Result:=FMethod();
end;

{ ============================================================================
  TOsslApiBioMethodNull (Null/Sink)
  ============================================================================ }

class constructor TOsslApiBioMethodNull.Create;
begin
  UnBind;
  TOsslLoader.RegisterBinding(ltCrypto, @Bind, @UnBind);
end;

class procedure TOsslApiBioMethodNull.Bind(const ALibHandle: TLibHandle;
  const AVersion: TOsslVersion);
begin
  TOsslBinding.Bind(ALibHandle, AVersion, cBindings);
end;

class procedure TOsslApiBioMethodNull.UnBind;
begin
  TOsslBinding.Reset(cBindings);
end;

class function TOsslApiBioMethodNull.GetMethodHandle: PBIO_METHOD;
begin
  Result:=FMethod();
end;

{ TOsslApiBioMethodSecMem }

class constructor TOsslApiBioMethodSecMem.Create;
begin
  UnBind;
  TOsslLoader.RegisterBinding(ltCrypto, @Bind, @UnBind);
end;

class procedure TOsslApiBioMethodSecMem.Bind(const ALibHandle: TLibHandle;
  const AVersion: TOsslVersion);
begin
  TOsslBinding.Bind(ALibHandle, AVersion, cBindings);
end;

class procedure TOsslApiBioMethodSecMem.UnBind;
begin
  TOsslBinding.Reset(cBindings);
end;

class function TOsslApiBioMethodSecMem.GetMethodHandle: PBIO_METHOD;
begin
  Result := FMethod();
end;

{ TOsslApiBioMethodConnect }

class constructor TOsslApiBioMethodConnect.Create;
begin
  UnBind;
  TOsslLoader.RegisterBinding(ltCrypto, @Bind, @UnBind);
end;

class procedure TOsslApiBioMethodConnect.Bind(const ALibHandle: TLibHandle;
  const AVersion: TOsslVersion);
begin
  TOsslBinding.Bind(ALibHandle, AVersion, cBindings);
end;

class procedure TOsslApiBioMethodConnect.UnBind;
begin
  TOsslBinding.Reset(cBindings);
end;

class function TOsslApiBioMethodConnect.GetMethodHandle: PBIO_METHOD;
begin
  Result := FMethod();
end;

{ TOsslApiBioMethodAccept }

class constructor TOsslApiBioMethodAccept.Create;
begin
  UnBind;
  TOsslLoader.RegisterBinding(ltCrypto, @Bind, @UnBind);
end;

class procedure TOsslApiBioMethodAccept.Bind(const ALibHandle: TLibHandle;
  const AVersion: TOsslVersion);
begin
  TOsslBinding.Bind(ALibHandle, AVersion, cBindings);
end;

class procedure TOsslApiBioMethodAccept.UnBind;
begin
  TOsslBinding.Reset(cBindings);
end;

class function TOsslApiBioMethodAccept.GetMethodHandle: PBIO_METHOD;
begin
  Result := FMethod();
end;

{ TOsslApiBioMethodFd }

class constructor TOsslApiBioMethodFd.Create;
begin
  UnBind;
  TOsslLoader.RegisterBinding(ltCrypto, @Bind, @UnBind);
end;

class procedure TOsslApiBioMethodFd.Bind(const ALibHandle: TLibHandle;
  const AVersion: TOsslVersion);
begin
  TOsslBinding.Bind(ALibHandle, AVersion, cBindings);
end;

class procedure TOsslApiBioMethodFd.UnBind;
begin
  TOsslBinding.Reset(cBindings);
end;

class function TOsslApiBioMethodFd.GetMethodHandle: PBIO_METHOD;
begin
  Result := FMethod();
end;


{ TOsslApiBioMethodLog }

class constructor TOsslApiBioMethodLog.Create;
begin
  UnBind;
  TOsslLoader.RegisterBinding(ltCrypto, @Bind, @UnBind);
end;

class procedure TOsslApiBioMethodLog.Bind(const ALibHandle: TLibHandle;
  const AVersion: TOsslVersion);
begin
  TOsslBinding.Bind(ALibHandle, AVersion, cBindings);
end;

class procedure TOsslApiBioMethodLog.UnBind;
begin
  TOsslBinding.Reset(cBindings);
end;

class function TOsslApiBioMethodLog.GetMethodHandle: PBIO_METHOD;
begin
  Result := FMethod();
end;


{ TOsslApiBioMethodBio }

class constructor TOsslApiBioMethodBio.Create;
begin
  UnBind;
  TOsslLoader.RegisterBinding(ltCrypto, @Bind, @UnBind);
end;

class procedure TOsslApiBioMethodBio.Bind(const ALibHandle: TLibHandle;
  const AVersion: TOsslVersion);
begin
  TOsslBinding.Bind(ALibHandle, AVersion, cBindings);
end;

class procedure TOsslApiBioMethodBio.UnBind;
begin
  TOsslBinding.Reset(cBindings);
end;

class function TOsslApiBioMethodBio.GetMethodHandle: PBIO_METHOD;
begin
  Result := FMethod();
end;

{ TOsslApiBioMethodCore }

class constructor TOsslApiBioMethodCore.Create;
begin
  UnBind;
  TOsslLoader.RegisterBinding(ltCrypto, @Bind, @UnBind);
end;

class procedure TOsslApiBioMethodCore.Bind(const ALibHandle: TLibHandle;
  const AVersion: TOsslVersion);
begin
  TOsslBinding.Bind(ALibHandle, AVersion, cBindings);
end;

class procedure TOsslApiBioMethodCore.UnBind;
begin
  TOsslBinding.Reset(cBindings);
end;

class function TOsslApiBioMethodCore.GetMethodHandle: PBIO_METHOD;
begin
  Result := FMethod();
end;

{ TOsslApiBioMethodDatagramPair }

class constructor TOsslApiBioMethodDatagramPair.Create;
begin
  UnBind;
  TOsslLoader.RegisterBinding(ltCrypto, @Bind, @UnBind);
end;

class procedure TOsslApiBioMethodDatagramPair.Bind(const ALibHandle: TLibHandle;
  const AVersion: TOsslVersion);
begin
  TOsslBinding.Bind(ALibHandle, AVersion, cBindings);
end;

class procedure TOsslApiBioMethodDatagramPair.UnBind;
begin
  TOsslBinding.Reset(cBindings);
end;

class function TOsslApiBioMethodDatagramPair.GetMethodHandle: PBIO_METHOD;
begin
  Result := FMethod();
end;

{ TOsslApiBioMethodDatagram }

class constructor TOsslApiBioMethodDatagram.Create;
begin
  UnBind;
  TOsslLoader.RegisterBinding(ltCrypto, @Bind, @UnBind);
end;

class procedure TOsslApiBioMethodDatagram.Bind(const ALibHandle: TLibHandle;
  const AVersion: TOsslVersion);
begin
  TOsslBinding.Bind(ALibHandle, AVersion, cBindings);
end;

class procedure TOsslApiBioMethodDatagram.UnBind;
begin
  TOsslBinding.Reset(cBindings);
end;

class function TOsslApiBioMethodDatagram.GetMethodHandle: PBIO_METHOD;
begin
  Result := FMethod();
end;

{ TOsslApiBioMethodDatagramSctp }

class constructor TOsslApiBioMethodDatagramSctp.Create;
begin
  UnBind;
  TOsslLoader.RegisterBinding(ltCrypto, @Bind, @UnBind);
end;

class procedure TOsslApiBioMethodDatagramSctp.Bind(const ALibHandle: TLibHandle;
  const AVersion: TOsslVersion);
begin
  TOsslBinding.Bind(ALibHandle, AVersion, cBindings);
end;

class procedure TOsslApiBioMethodDatagramSctp.UnBind;
begin
  TOsslBinding.Reset(cBindings);
end;

class function TOsslApiBioMethodDatagramSctp.GetMethodHandle: PBIO_METHOD;
begin
  Result := FMethod();
end;

// -----------------------------------------------------------------------------
// FILTERS
// -----------------------------------------------------------------------------

{ TOsslApiBioFilterNull }

class constructor TOsslApiBioFilterNull.Create;
begin
  UnBind;
  TOsslLoader.RegisterBinding(ltCrypto, @Bind, @UnBind);
end;

class procedure TOsslApiBioFilterNull.Bind(const ALibHandle: TLibHandle;
  const AVersion: TOsslVersion);
begin
  TOsslBinding.Bind(ALibHandle, AVersion, cBindings);
end;

class procedure TOsslApiBioFilterNull.UnBind;
begin
  TOsslBinding.Reset(cBindings);
end;

class function TOsslApiBioFilterNull.GetMethodHandle: PBIO_METHOD;
begin
  Result := FMethod();
end;

{ TOsslApiBioFilterBuffer }

class constructor TOsslApiBioFilterBuffer.Create;
begin
  UnBind;
  TOsslLoader.RegisterBinding(ltCrypto, @Bind, @UnBind);
end;

class procedure TOsslApiBioFilterBuffer.Bind(const ALibHandle: TLibHandle;
  const AVersion: TOsslVersion);
begin
  TOsslBinding.Bind(ALibHandle, AVersion, cBindings);
end;

class procedure TOsslApiBioFilterBuffer.UnBind;
begin
  TOsslBinding.Reset(cBindings);
end;

class function TOsslApiBioFilterBuffer.GetMethodHandle: PBIO_METHOD;
begin
  Result := FMethod();
end;

{ TOsslApiBioFilterReadBuffer }

class constructor TOsslApiBioFilterReadBuffer.Create;
begin
  UnBind;
  TOsslLoader.RegisterBinding(ltCrypto, @Bind, @UnBind);
end;

class procedure TOsslApiBioFilterReadBuffer.Bind(const ALibHandle: TLibHandle;
  const AVersion: TOsslVersion);
begin
  TOsslBinding.Bind(ALibHandle, AVersion, cBindings);
end;

class procedure TOsslApiBioFilterReadBuffer.UnBind;
begin
  TOsslBinding.Reset(cBindings);
end;

class function TOsslApiBioFilterReadBuffer.GetMethodHandle: PBIO_METHOD;
begin
  Result := FMethod();
end;

{ TOsslApiBioFilterLineBuffer }

class constructor TOsslApiBioFilterLineBuffer.Create;
begin
  UnBind;
  TOsslLoader.RegisterBinding(ltCrypto, @Bind, @UnBind);
end;

class procedure TOsslApiBioFilterLineBuffer.Bind(const ALibHandle: TLibHandle;
  const AVersion: TOsslVersion);
begin
  TOsslBinding.Bind(ALibHandle, AVersion, cBindings);
end;

class procedure TOsslApiBioFilterLineBuffer.UnBind;
begin
  TOsslBinding.Reset(cBindings);
end;

class function TOsslApiBioFilterLineBuffer.GetMethodHandle: PBIO_METHOD;
begin
  Result := FMethod();
end;

{ TOsslApiBioFilterNbioTest }

class constructor TOsslApiBioFilterNbioTest.Create;
begin
  UnBind;
  TOsslLoader.RegisterBinding(ltCrypto, @Bind, @UnBind);
end;

class procedure TOsslApiBioFilterNbioTest.Bind(const ALibHandle: TLibHandle;
  const AVersion: TOsslVersion);
begin
  TOsslBinding.Bind(ALibHandle, AVersion, cBindings);
end;

class procedure TOsslApiBioFilterNbioTest.UnBind;
begin
  TOsslBinding.Reset(cBindings);
end;

class function TOsslApiBioFilterNbioTest.GetMethodHandle: PBIO_METHOD;
begin
  Result := FMethod();
end;

{ TOsslApiBioFilterPrefix }

class constructor TOsslApiBioFilterPrefix.Create;
begin
  UnBind;
  TOsslLoader.RegisterBinding(ltCrypto, @Bind, @UnBind);
end;

class procedure TOsslApiBioFilterPrefix.Bind(const ALibHandle: TLibHandle;
  const AVersion: TOsslVersion);
begin
  TOsslBinding.Bind(ALibHandle, AVersion, cBindings);
end;

class procedure TOsslApiBioFilterPrefix.UnBind;
begin
  TOsslBinding.Reset(cBindings);
end;

class function TOsslApiBioFilterPrefix.GetMethodHandle: PBIO_METHOD;
begin
  Result := FMethod();
end;

{ TOsslApiBioBase.TOsslApiBioCtrl }

constructor TOsslApiBioBase.TOsslApiBioCtrl.Create(AHandle: PBIO);
begin

end;

function TOsslApiBioBase.TOsslApiBioCtrl.EOF: Boolean;
begin

end;

function TOsslApiBioBase.TOsslApiBioCtrl.Flush: Boolean;
begin

end;

function TOsslApiBioBase.TOsslApiBioCtrl.Op(Cmd: Integer; LArg: clong;
  PArg: Pointer): clong;
begin

end;

function TOsslApiBioBase.TOsslApiBioCtrl.Pending: Integer;
begin

end;

function TOsslApiBioBase.TOsslApiBioCtrl.Reset: Boolean;
begin

end;

function TOsslApiBioBase.TOsslApiBioCtrl.WritePending: Integer;
begin

end;

{ TOsslApiBioBase.TOsslApiBioChain }

constructor TOsslApiBioBase.TOsslApiBioChain.Create(AHandle: PBIO);
begin

end;

function TOsslApiBioBase.TOsslApiBioChain.Next: PBIO;
begin

end;

function TOsslApiBioBase.TOsslApiBioChain.Pop: PBIO;
begin

end;

function TOsslApiBioBase.TOsslApiBioChain.Push(Append: PBIO): PBIO;
begin

end;

{ TOsslApiBioBase }

class constructor TOsslApiBioBase.Create;
begin
  UnBind;
  TOsslCustomLoader.RegisterBinding(ltCrypto, Bind, UnBind);
end;

class procedure TOsslApiBioBase.Bind(
  const ALibHandle: TLibHandle; const AVersion: TOsslVersion);
begin
  TOsslBinding.Bind(ALibHandle, AVersion, cBindings)
end;

class procedure TOsslApiBioBase.UnBind;
begin
  TOsslBinding.Reset(cBindings);
end;

class function TOsslApiBioBase.BIO_new(AMethod: PBIO_METHOD): PBIO;
begin
  Result:=F_Bio_new(AMethod);
end;

class function TOsslApiBioBase.BIO_new_mem_buf(ABuf: Pointer; len: cint): PBIO;
begin
  Result:=F_BIO_new_mem_buf(ABuf, len);
end;

class function TOsslApiBioBase.BIO_free(a: PBIO): cint;
begin
  Result:=F_BIO_free(a);
end;

class function TOsslApiBioBase.BIO_up_ref(a: PBIO): cint;
begin
  Result:=F_BIO_up_ref(a);
end;

class function TOsslApiBioBase.BIO_read(b: PBIO; data: Pointer; dlen: cint): cint;
begin
  Result:=F_BIO_read(b, data, dlen);
end;

class function TOsslApiBioBase.BIO_write(b: PBIO; data: Pointer; dlen: cint): cint;
begin
  Result:=F_BIO_write(b, data, dlen);
end;

class function TOsslApiBioBase.BIO_ctrl(bp: PBIO; cmd: cint; larg: clong;
  parg: Pointer): clong;
begin
  Result:=F_BIO_ctrl(bp, cmd, larg, parg);
end;

class function TOsslApiBioBase.BIO_push(b, append: PBIO): PBIO;
begin
  Result:=F_BIO_push(b, append);
end;

class function TOsslApiBioBase.BIO_pop(b: PBIO): PBIO;
begin
  Result:=F_BIO_pop(b);
end;

class function TOsslApiBioBase.BIO_next(b: PBIO): PBIO;
begin
  Result:=F_BIO_next(b);
end;

constructor TOsslApiBioBase.Create(AMethod: TOsslApiBioCustomMethod);
begin
  FHandle:=BIO_new(AMethod.MethodHandle);
end;

constructor TOsslApiBioBase.Create(AData: pointer; ADataLen: cint);
begin
  FHandle:=BIO_new_mem_buf(AData, ADataLen);
end;

destructor TOsslApiBioBase.Destroy;
begin
  BIO_free(FHandle);
  inherited;
end;

end.
