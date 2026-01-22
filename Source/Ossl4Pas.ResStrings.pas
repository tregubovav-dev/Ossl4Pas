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

unit Ossl4Pas.ResStrings;

{$INCLUDE 'Ossl4Pas_CompilerDefines.inc'}

interface

resourcestring
  // Ossl4Pas.Loader strings.
  { TOsslVersion strings }
  resVersionShort         = '%.1d.%.2d.%.2d.%.2d.%.1x';


  { EOsslLoader strings }
  resLoaderNotSet                 = 'OpenSSL loader is not registered.';
  resLoaderUnsupported            = 'Unsupported OpenSSL loader registered.';
  resNoVersionFound               = 'The library %s loading failed. '+
                                    'It does not provide version information.';
  resLoadLibVersionIncompatible   = 'Incompatible OpenSSL library version at: '+
                                    '%s. Expected version 3.0 or higher, but found %s';
  resLoadLibNotFound              = 'Libraries ''%s'' is not found at %s path(s).';
  resLoadLibVersionsIncompatible  = 'Libraries ''%s'' and ''%s'' versions are incompatible. '+
                                    '%0:s version: %2:s, but %1:s version: %3:s';
  resLoadBindLibNotLoaded         = 'Unable to bind routines from ''%s''. '+
                                    'Library  is not loaded yet.';

  // Ossl4Pas.Api.Err strings
  resErrRoutineNotBound           = 'Attempted to call an OpenSSL function '+
                                    'that was not found or is incompatible.';

  // Ossl4Pas.Err
  { EOsslCustomError.TErrorEntry strings }
  resErrFmtSpace                  = ' ';
  resErrFmtComma                  = ', ';
  resErrFmtCode                   = '[0x%8x]';
  resErrFmtLib                    = 'in library "%s"';
  resErrFmtFile                   = 'in the file: "%s"';
  resErrFmtLine                   = 'at line: "%d"';
  resErrFmtFunc                   = 'in function: "%d"';
  resErrFmtDescript               = '"%s"';

  { EOsslCustomError strings }
  resErrUnknownError              = 'Unknown Error.';
  resErrFmtOsslWithMessage        = '%s - ''%s''.';
  resErrFmtOsslWithoutMessage     = '%s.';
  resErrFmtNestedSectionBegins    = sLineBreak+'Nested errors:'+sLineBreak;
  resErrFmtNestedSectionEnds      = '';
  resErrFmtNestedLineBegins       = '  ';
  resErrFmtNestedLineEnds         = '';
  resErrFmtNestedNewLine          = ';'+sLineBreak;


implementation

end.
