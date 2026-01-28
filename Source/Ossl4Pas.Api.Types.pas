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

unit Ossl4Pas.Api.Types;

{$INCLUDE 'Ossl4Pas_CompilerDefines.inc'}

interface

uses
  Ossl4Pas.CTypes;

type
  { ============================================================================
    CORE & LIBRARY CONTEXT
    Declared in: <openssl/crypto.h>, <openssl/core.h>, <openssl/types.h>
    ============================================================================ }

  // The library context (the "global" state replacement in OpenSSL 3.0+)
  POSSL_LIB_CTX = ^TOSSL_LIB_CTX;
  TOSSL_LIB_CTX = record end;

  // Parameter passing structure (used for Providers/EVP)
  // Note: OSSL_PARAM is actually a public struct, but defined as opaque here per your template.
  POSSL_PARAM = ^TOSSL_PARAM;
  TOSSL_PARAM = record end;

  // Asynchronous job contexts
  PASYNC_JOB = ^TASYNC_JOB;
  TASYNC_JOB = record end;

  PASYNC_WAIT_CTX = ^TASYNC_WAIT_CTX;
  TASYNC_WAIT_CTX = record end;

  { ============================================================================
    PROVIDERS, ENCODERS, DECODERS (OpenSSL 3.x Architecture)
    Declared in: <openssl/provider.h>, <openssl/encoder.h>, <openssl/decoder.h>
    ============================================================================ }

  // Provider handle
  POSSL_PROVIDER = ^TOSSL_PROVIDER;
  TOSSL_PROVIDER = record end;

  // Encoders (Key -> Bytes)
  POSSL_ENCODER = ^TOSSL_ENCODER;
  TOSSL_ENCODER = record end;

  POSSL_ENCODER_CTX = ^TOSSL_ENCODER_CTX;
  TOSSL_ENCODER_CTX = record end;

  // Decoders (Bytes -> Key)
  POSSL_DECODER = ^TOSSL_DECODER;
  TOSSL_DECODER = record end;

  POSSL_DECODER_CTX = ^TOSSL_DECODER_CTX;
  TOSSL_DECODER_CTX = record end;

  { ============================================================================
    BIO (Basic Input/Output)
    Declared in: <openssl/bio.h>
    ============================================================================ }

  // The BIO Handle
  PPBIO = ^PBIO;
  PBIO  = ^TBIO;
  TBIO  = record end;

  // The BIO Method Table
  PBIO_METHOD = ^TBIO_METHOD;
  TBIO_METHOD = record end;

  // BIO Address Info (Socket addresses)
  PBIO_ADDR = ^TBIO_ADDR;
  TBIO_ADDR = record end;

  PBIO_ADDRINFO = ^TBIO_ADDRINFO;
  TBIO_ADDRINFO = record end;

  // BIO message prefix/suffix
  PBIO_f_buffer_ctx = ^TBIO_f_buffer_ctx;
  TBIO_f_buffer_ctx = record end;

  { ============================================================================
    EVP (High-Level Cryptography)
    Declared in: <openssl/evp.h>
    ============================================================================ }

  // Public/Private Key Pair
  PEVP_PKEY = ^TEVP_PKEY;
  TEVP_PKEY = record end;

  // Context for Key Operations (Sign/Verify/Encrypt)
  PEVP_PKEY_CTX = ^TEVP_PKEY_CTX;
  TEVP_PKEY_CTX = record end;

  // Key Methods
  PEVP_PKEY_METHOD = ^TEVP_PKEY_METHOD;
  TEVP_PKEY_METHOD = record end;

  PEVP_PKEY_ASN1_METHOD = ^TEVP_PKEY_ASN1_METHOD;
  TEVP_PKEY_ASN1_METHOD = record end;

  // Symmetric Ciphers (AES, ChaCha20, etc.)
  PEVP_CIPHER = ^TEVP_CIPHER;
  TEVP_CIPHER = record end;

  PEVP_CIPHER_CTX = ^TEVP_CIPHER_CTX;
  TEVP_CIPHER_CTX = record end;

  // Message Digests (SHA256, SHA3, etc.)
  PEVP_MD = ^TEVP_MD;
  TEVP_MD = record end;

  PEVP_MD_CTX = ^TEVP_MD_CTX;
  TEVP_MD_CTX = record end;

  // MAC (Message Authentication Codes: HMAC, CMAC, KMAC)
  PEVP_MAC = ^TEVP_MAC;
  TEVP_MAC = record end;

  PEVP_MAC_CTX = ^TEVP_MAC_CTX;
  TEVP_MAC_CTX = record end;

  // KDF (Key Derivation Functions: HKDF, PBKDF2)
  PEVP_KDF = ^TEVP_KDF;
  TEVP_KDF = record end;

  PEVP_KDF_CTX = ^TEVP_KDF_CTX;
  TEVP_KDF_CTX = record end;

  // Random Number Generator Context
  PEVP_RAND = ^TEVP_RAND;
  TEVP_RAND = record end;

  PEVP_RAND_CTX = ^TEVP_RAND_CTX;
  TEVP_RAND_CTX = record end;

  // Signature Algorithms (New in 3.0)
  PEVP_SIGNATURE = ^TEVP_SIGNATURE;
  TEVP_SIGNATURE = record end;

  // Key Exchange Algorithms (New in 3.0)
  PEVP_KEYEXCH = ^TEVP_KEYEXCH;
  TEVP_KEYEXCH = record end;

  // KEM (Key Encapsulation Mechanism) (New in 3.0/3.2)
  PEVP_KEM = ^TEVP_KEM;
  TEVP_KEM = record end;

  { ============================================================================
    BIG NUMBERS
    Declared in: <openssl/bn.h>
    ============================================================================ }

  // The Big Number
  PBIGNUM = ^TBIGNUM;
  TBIGNUM = record end;

  // Context for BN operations (temp variables)
  PBN_CTX = ^TBN_CTX;
  TBN_CTX = record end;

  // Montgomery Context
  PBN_MONT_CTX = ^TBN_MONT_CTX;
  TBN_MONT_CTX = record end;

  // Reciprocal Context
  PBN_RECP_CTX = ^TBN_RECP_CTX;
  TBN_RECP_CTX = record end;

  // Generation Callback
  PBN_GENCB = ^TBN_GENCB;
  TBN_GENCB = record end;

  // Blinding Context
  PBN_BLINDING = ^TBN_BLINDING;
  TBN_BLINDING = record end;

  { ============================================================================
    ASN.1 (Abstract Syntax Notation)
    Declared in: <openssl/asn1.h>
    ============================================================================ }

  // Generic ASN1 Type
  PASN1_TYPE = ^TASN1_TYPE;
  TASN1_TYPE = record end;

  // Generic ASN1 Value (void*)
  PASN1_VALUE = ^TASN1_VALUE;
  TASN1_VALUE = record end;

  // Base String Type
  PASN1_STRING = ^TASN1_STRING;
  TASN1_STRING = record end;

  // Specific ASN1 Primitive Types
  PASN1_INTEGER = ^TASN1_INTEGER;
  TASN1_INTEGER = record end;

  PASN1_ENUMERATED = ^TASN1_ENUMERATED;
  TASN1_ENUMERATED = record end;

  PASN1_BIT_STRING = ^TASN1_BIT_STRING;
  TASN1_BIT_STRING = record end;

  PASN1_OCTET_STRING = ^TASN1_OCTET_STRING;
  TASN1_OCTET_STRING = record end;

  PASN1_PRINTABLESTRING = ^TASN1_PRINTABLESTRING;
  TASN1_PRINTABLESTRING = record end;

  PASN1_T61STRING = ^TASN1_T61STRING;
  TASN1_T61STRING = record end;

  PASN1_IA5STRING = ^TASN1_IA5STRING;
  TASN1_IA5STRING = record end;

  PASN1_GENERALSTRING = ^TASN1_GENERALSTRING;
  TASN1_GENERALSTRING = record end;

  PASN1_BMPSTRING = ^TASN1_BMPSTRING;
  TASN1_BMPSTRING = record end;

  PASN1_UNIVERSALSTRING = ^TASN1_UNIVERSALSTRING;
  TASN1_UNIVERSALSTRING = record end;

  PASN1_UTF8STRING = ^TASN1_UTF8STRING;
  TASN1_UTF8STRING = record end;

  PASN1_VISIBLESTRING = ^TASN1_VISIBLESTRING;
  TASN1_VISIBLESTRING = record end;

  // Time Types
  PASN1_TIME = ^TASN1_TIME;
  TASN1_TIME = record end;

  PASN1_UTCTIME = ^TASN1_UTCTIME;
  TASN1_UTCTIME = record end;

  PASN1_GENERALIZEDTIME = ^TASN1_GENERALIZEDTIME;
  TASN1_GENERALIZEDTIME = record end;

  // Object Identifier (OID)
  PASN1_OBJECT = ^TASN1_OBJECT;
  TASN1_OBJECT = record end;

  PASN1_NULL = ^TASN1_NULL;
  TASN1_NULL = record end;

  // Context for S/MIME
  PASN1_PCTX = ^TASN1_PCTX;
  TASN1_PCTX = record end;

  PASN1_SCTX = ^TASN1_SCTX;
  TASN1_SCTX = record end;

  { ============================================================================
    X.509 CERTIFICATES
    Declared in: <openssl/x509.h>, <openssl/x509v3.h>
    ============================================================================ }

  // The Certificate
  PX509 = ^TX509;
  TX509 = record end;

  // Certificate Request (CSR)
  PX509_REQ = ^TX509_REQ;
  TX509_REQ = record end;

  // Certificate Revocation List (CRL)
  PX509_CRL = ^TX509_CRL;
  TX509_CRL = record end;

  // Revoked Entry in CRL
  PX509_REVOKED = ^TX509_REVOKED;
  TX509_REVOKED = record end;

  // X509 Name (Distinguished Name)
  PX509_NAME = ^TX509_NAME;
  TX509_NAME = record end;

  // X509 Name Entry (Key=Value pair in DN)
  PX509_NAME_ENTRY = ^TX509_NAME_ENTRY;
  TX509_NAME_ENTRY = record end;

  // X509 Extension
  PX509_EXTENSION = ^TX509_EXTENSION;
  TX509_EXTENSION = record end;

  // X509 Public Key Info
  PX509_PUBKEY = ^TX509_PUBKEY;
  TX509_PUBKEY = record end;

  // Algorithm Identifier
  PX509_ALGOR = ^TX509_ALGOR;
  TX509_ALGOR = record end;

  // Signature
  PX509_SIG = ^TX509_SIG;
  TX509_SIG = record end;

  // Generic Attribute
  PX509_ATTRIBUTE = ^TX509_ATTRIBUTE;
  TX509_ATTRIBUTE = record end;

  // Trusted Store
  PX509_STORE = ^TX509_STORE;
  TX509_STORE = record end;

  // Context for Store Verification
  PX509_STORE_CTX = ^TX509_STORE_CTX;
  TX509_STORE_CTX = record end;

  // Verification Parameters
  PX509_VERIFY_PARAM = ^TX509_VERIFY_PARAM;
  TX509_VERIFY_PARAM = record end;

  // Lookup Method (for loading certs from Files/Dirs)
  PX509_LOOKUP = ^TX509_LOOKUP;
  TX509_LOOKUP = record end;

  PX509_LOOKUP_METHOD = ^TX509_LOOKUP_METHOD;
  TX509_LOOKUP_METHOD = record end;

  // Container for different X509 types (Cert, CRL, etc)
  PX509_OBJECT = ^TX509_OBJECT;
  TX509_OBJECT = record end;

  // X509 V3 Context
  PX509V3_CTX = ^TX509V3_CTX;
  TX509V3_CTX = record end;

  { ============================================================================
    X.509 POLICY TREE
    Declared in: <openssl/x509_vfy.h>
    ============================================================================ }

  PX509_POLICY_TREE = ^TX509_POLICY_TREE;
  TX509_POLICY_TREE = record end;

  PX509_POLICY_NODE = ^TX509_POLICY_NODE;
  TX509_POLICY_NODE = record end;

  PX509_POLICY_LEVEL = ^TX509_POLICY_LEVEL;
  TX509_POLICY_LEVEL = record end;

  PX509_POLICY_CACHE = ^TX509_POLICY_CACHE;
  TX509_POLICY_CACHE = record end;

  { ============================================================================
    SSL / TLS
    Declared in: <openssl/ssl.h>
    ============================================================================ }

  // SSL Context (Factory)
  PSSL_CTX = ^TSSL_CTX;
  TSSL_CTX = record end;

  // SSL Connection
  PSSL = ^TSSL;
  TSSL = record end;

  // SSL Session
  PSSL_SESSION = ^TSSL_SESSION;
  TSSL_SESSION = record end;

  // SSL Method (Version/Protocol)
  PSSL_METHOD = ^TSSL_METHOD;
  TSSL_METHOD = record end;

  // SSL Cipher
  PSSL_CIPHER = ^TSSL_CIPHER;
  TSSL_CIPHER = record end;

  // SSL Configuration Context
  PSSL_CONF_CTX = ^TSSL_CONF_CTX;
  TSSL_CONF_CTX = record end;

  // QUIC support types (New in 3.x, heavily expanded in 3.2/3.4)
  PSSL_QUIC_METHOD = ^TSSL_QUIC_METHOD;
  TSSL_QUIC_METHOD = record end;

  { ============================================================================
    OSSL_STORE (URI based loading of objects)
    Declared in: <openssl/store.h>
    ============================================================================ }

  // The Store Context
  POSSL_STORE_CTX = ^TOSSL_STORE_CTX;
  TOSSL_STORE_CTX = record end;

  // Info retrieved from store
  POSSL_STORE_INFO = ^TOSSL_STORE_INFO;
  TOSSL_STORE_INFO = record end;

  // Search criteria
  POSSL_STORE_SEARCH = ^TOSSL_STORE_SEARCH;
  TOSSL_STORE_SEARCH = record end;

  // Store Loader (Backend)
  POSSL_STORE_LOADER = ^TOSSL_STORE_LOADER;
  TOSSL_STORE_LOADER = record end;

  { ============================================================================
    CMS (Cryptographic Message Syntax) & PKCS7
    Declared in: <openssl/cms.h>, <openssl/pkcs7.h>
    ============================================================================ }

  // CMS Types
  PCMS_ContentInfo = ^TCMS_ContentInfo;
  TCMS_ContentInfo = record end;

  PCMS_SignerInfo = ^TCMS_SignerInfo;
  TCMS_SignerInfo = record end;

  PCMS_CertificateChoices = ^TCMS_CertificateChoices;
  TCMS_CertificateChoices = record end;

  PCMS_RevocationInfoChoice = ^TCMS_RevocationInfoChoice;
  TCMS_RevocationInfoChoice = record end;

  PCMS_RecipientInfo = ^TCMS_RecipientInfo;
  TCMS_RecipientInfo = record end;

  PCMS_ReceiptRequest = ^TCMS_ReceiptRequest;
  TCMS_ReceiptRequest = record end;

  // PKCS7 Types (Legacy but widely used)
  PPKCS7 = ^TPKCS7;
  TPKCS7 = record end;

  PPKCS7_SIGNED = ^TPKCS7_SIGNED;
  TPKCS7_SIGNED = record end;

  PPKCS7_ENVELOPE = ^TPKCS7_ENVELOPE;
  TPKCS7_ENVELOPE = record end;

  PPKCS7_SIGNER_INFO = ^TPKCS7_SIGNER_INFO;
  TPKCS7_SIGNER_INFO = record end;

  PPKCS7_RECIP_INFO = ^TPKCS7_RECIP_INFO;
  TPKCS7_RECIP_INFO = record end;

  PPKCS7_ISSUER_AND_SERIAL = ^TPKCS7_ISSUER_AND_SERIAL;
  TPKCS7_ISSUER_AND_SERIAL = record end;

  { ============================================================================
    PKCS12 (PFX / Key Bags)
    Declared in: <openssl/pkcs12.h>
    ============================================================================ }

  PPKCS12 = ^TPKCS12;
  TPKCS12 = record end;

  PPKCS12_SAFEBAG = ^TPKCS12_SAFEBAG;
  TPKCS12_SAFEBAG = record end;

  PPKCS12_BAGS = ^TPKCS12_BAGS;
  TPKCS12_BAGS = record end;

  { ============================================================================
    CONFIGURATION
    Declared in: <openssl/conf.h>
    ============================================================================ }

  PCONF = ^TCONF;
  TCONF = record end;

  PCONF_METHOD = ^TCONF_METHOD;
  TCONF_METHOD = record end;

  PCONF_IMODULE = ^TCONF_IMODULE;
  TCONF_IMODULE = record end;

  PCONF_MODULE = ^TCONF_MODULE;
  TCONF_MODULE = record end;

  { ============================================================================
    UI (User Interface / Password Prompts)
    Declared in: <openssl/ui.h>
    ============================================================================ }

  PUI = ^TUI;
  TUI = record end;

  PUI_METHOD = ^TUI_METHOD;
  TUI_METHOD = record end;

  PUI_STRING = ^TUI_STRING;
  TUI_STRING = record end;

  { ============================================================================
    HTTP CLIENT (New in 3.0)
    Declared in: <openssl/http.h>
    ============================================================================ }

  POSSL_HTTP_REQ_CTX = ^TOSSL_HTTP_REQ_CTX;
  TOSSL_HTTP_REQ_CTX = record end;

  { ============================================================================
    LEGACY CRYPTO STRUCTS (Still present but often wrappers around EVP)
    Declared in: <openssl/rsa.h>, <openssl/dsa.h>, <openssl/dh.h>, <openssl/ec.h>
    ============================================================================ }

  PRSA = ^TRSA;
  TRSA = record end;
  PRSA_METHOD = ^TRSA_METHOD;
  TRSA_METHOD = record end;

  PDSA = ^TDSA;
  TDSA = record end;
  PDSA_METHOD = ^TDSA_METHOD;
  TDSA_METHOD = record end;

  PDH = ^TDH;
  TDH = record end;
  PDH_METHOD = ^TDH_METHOD;
  TDH_METHOD = record end;

  PEC_KEY = ^TEC_KEY;
  TEC_KEY = record end;

  PEC_GROUP = ^TEC_GROUP;
  TEC_GROUP = record end;

  PEC_POINT = ^TEC_POINT;
  TEC_POINT = record end;

  PEC_METHOD = ^TEC_METHOD;
  TEC_METHOD = record end;

implementation

end.
