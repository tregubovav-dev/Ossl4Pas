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


// Ossl4Pas_Versions.inc
{$IFDEF OSSL_3_7}
  {$DEFINE OSSL_3_6}
{$ENDIF}

{$IFDEF OSSL_3_6}
  {$DEFINE OSSL_3_5}
{$ENDIF}

{$IFDEF OSSL_3_5}
  {$DEFINE OSSL_3_4}
{$ENDIF}

{$IFDEF OSSL_3_4}
  {$DEFINE OSSL_3_3}
{$ENDIF}

{$IFDEF OSSL_3_3}
  {$DEFINE OSSL_3_2}
{$ENDIF}

{$IFDEF OSSL_3_2}
  {$DEFINE OSSL_3_1}
{$ENDIF}

{$IFDEF OSSL_3_1}
  {$DEFINE OSSL_3_0}
{$ENDIF}

// At least 3.0 is defined

{$IFNDEF OSSL_3_0}
  {$DEFINE OSSL_3_0}
{$ENDIF}
