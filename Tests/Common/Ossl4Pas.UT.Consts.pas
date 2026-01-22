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

unit Ossl4Pas.UT.Consts;

interface

const
  ERR_TXT_MALLOCED  = $01;
  ERR_TXT_STRING    = $02;

  ERR_LIB_NONE      = 1;
  // ... Registered Library names range
  ERR_LIB_HTTP      = 61;
  // ... Unregistered Library names range
  ERR_LIB_USER      = 128;

  ERR_LIB_OFFSET    = 23;
  ERR_LIB_MASK      = $FF;


  cErrLibNames: array[1..61] of PAnsiChar = (
    'LibNone',          // ERR_LIB_NONE      = 1;
    'LibSys',           // ERR_LIB_SYS       = 2;
    'LibBn',            // ERR_LIB_BN        = 3;
    'LibRsa',           // ERR_LIB_RSA       = 4;
    'LibDh',            // ERR_LIB_DH        = 5;
    'LibEvp',           // ERR_LIB_EVP       = 6;
    'LibBuf',           // ERR_LIB_BUF       = 7;
    'LibObj',           // ERR_LIB_OBJ       = 8;
    'LibPem',           // ERR_LIB_PEM       = 9;
    'LibDsa',           // ERR_LIB_DSA       = 10;
    'LibX509',          // ERR_LIB_X509      = 11;
    '',                 // 12 was ERR_LIB_METH (Removed)
    'LibAsn1',          // ERR_LIB_ASN1      = 13;
    'LibConf',          // ERR_LIB_CONF      = 14;
    'LibCrypto',        // ERR_LIB_CRYPTO    = 15;
    'LibEc',            // ERR_LIB_EC        = 16;
    '', '', '',         // 17..19 Gaps
    'LibSsl',           // ERR_LIB_SSL       = 20;
    '', '', '', '', '', '', '', '', '', '', '', // 21..31 Gaps (SSL23, Proxy, etc removed)
    'LibBio',           // ERR_LIB_BIO       = 32;
    'LibPkcs7',         // ERR_LIB_PKCS7     = 33;
    'LibX509V3',        // ERR_LIB_X509V3    = 34;
    'LibPkcs12',        // ERR_LIB_PKCS12    = 35;
    'LibRand',          // ERR_LIB_RAND      = 36;
    'LibDso',           // ERR_LIB_DSO       = 37;
    'LibEngine',        // ERR_LIB_ENGINE    = 38;
    'LibOcsp',          // ERR_LIB_OCSP      = 39;
    'LibUi',            // ERR_LIB_UI        = 40;
    'LibComp',          // ERR_LIB_COMP      = 41;
    'LibEcdsa',         // ERR_LIB_ECDSA     = 42;
    'LibEcdh',          // ERR_LIB_ECDH      = 43;
    'LibOsslStore',     // ERR_LIB_OSSL_STORE= 44;
    'LibFips',          // ERR_LIB_FIPS      = 45;
    'LibCms',           // ERR_LIB_CMS       = 46;
    'LibTs',            // ERR_LIB_TS        = 47;
    'LibHmac',          // ERR_LIB_HMAC      = 48;
    '',                 // 49 was ERR_LIB_JPAKE (Removed)
    'LibCt',            // ERR_LIB_CT        = 50;
    'LibAsync',         // ERR_LIB_ASYNC     = 51;
    'LibKdf',           // ERR_LIB_KDF       = 52;
    'LibSm2',           // ERR_LIB_SM2       = 53;
    'LibEss',           // ERR_LIB_ESS       = 54;
    'LibProp',          // ERR_LIB_PROP      = 55;
    'LibCrmf',          // ERR_LIB_CRMF      = 56;
    'LibProv',          // ERR_LIB_PROV      = 57;
    'LibCmp',           // ERR_LIB_CMP       = 58;
    'LibOsslEncoder',   // ERR_LIB_OSSL_ENCODER = 59;
    'LibOsslDecoder',   // ERR_LIB_OSSL_DECODER = 60;
    'LibHttp'           // ERR_LIB_HTTP      = 61;
  );
  cErrLibNameUser: PAnsiChar = 'User Lib';
  cErrReasonConst: PAnsiChar = 'A mock reason.';

implementation

end.
