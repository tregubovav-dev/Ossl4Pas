\# Ossl4Pas



\*\*Ossl4Pas\*\* is a modern, robust Object Pascal wrapper for the \*\*OpenSSL 3.x\*\* cryptography library.



\## ⚠️ Project Status: Early Access



\*\*This project is currently in an early development stage.\*\*



\*   \*\*Current Focus:\*\* Primary development and testing are currently targeting \*\*Delphi (10.4+)\*\*.

\*   \*\*Roadmap:\*\* Full \*\*Free Pascal (FPC)\*\* support is planned and will be implemented in upcoming phases.



\## Project Philosophy



\*\*Ossl4Pas\*\* is designed to provide a "Native Pascal" experience when working with OpenSSL, avoiding the complexity of raw C-style API calls in consumer code.



\*   \*\*Native Syntax:\*\* Wraps OpenSSL opaque structures in Pascal Objects and Records, exposing functionality via properties and methods rather than flat function calls.

\*   \*\*Modern Pascal:\*\* Heavily leverages modern language features—such as \*\*Managed Records\*\* (where supported), \*\*Class/Type Helpers\*\*, and \*\*Generics\*\*—to simplify memory management and improve code readability.

\*   \*\*Minimal C Interference:\*\* While the raw API is available for advanced users, the framework layer hides pointers and manual reference counting behind safe, idiomatic Pascal abstractions.



> \*\*Note on TaurusTLS:\*\*

> This framework is related to the \*\*TaurusTLS\*\* project but is \*\*not\*\* intended to replace or compete with it. Ossl4Pas is a focused, standalone wrapper for OpenSSL 3.x internals, whereas TaurusTLS is a comprehensive TLS library suite.



\## Planned Distribution Models



To ensure maximum compatibility across desktop and mobile platforms, the framework is designed to support three distinct distribution models:



1\.  \*\*Dynamic Binding (Late Binding):\*\*

&nbsp;   \*   Loads standard `.dll` / `.so` / `.dylib` files at runtime.

&nbsp;   \*   \*\*Target:\*\* Windows, Linux, and macOS (Desktop/Server).



2\.  \*\*Static Linking:\*\*

&nbsp;   \*   Links OpenSSL object code directly into the executable.

&nbsp;   \*   \*\*Target:\*\* iOS (where dynamic loading is restricted) and embedded systems.



3\.  \*\*Dynamic Package with Static Core (.bpl):\*\*

&nbsp;   \*   Encapsulates statically linked OpenSSL code within a Delphi Runtime Package (`.bpl`).

&nbsp;   \*   \*\*Target:\*\* macOS and Android (simplifies deployment by avoiding external `.so` dependency issues while keeping the app modular).



\## Features



\*   \*\*OpenSSL 3.0+ Support:\*\* Built strictly for modern OpenSSL (3.0 through 3.4). No legacy 1.x baggage.

\*   \*\*Robust Loader:\*\* Thread-safe, lazy loading with "Anchor" logic to ensure `libcrypto` and `libssl` load from the same location.

\*   \*\*Error Handling:\*\* Automatic draining of the OpenSSL error queue into structured, informative Pascal Exceptions.



\## Architecture Overview



The library is split into distinct layers:



1\.  \*\*Loader (`Ossl4Pas.Loader`):\*\* Manages the loading strategy (Dynamic vs Static).

2\.  \*\*API (`Ossl4Pas.Api.\*`):\*\* Static classes exposing the raw C-API with strict types.

3\.  \*\*Framework (`Ossl4Pas.\*`):\*\* High-level classes (e.g., `TOsslBio`, `EOsslError`) for easy usage.



\## Usage Example



```pascal

uses

&nbsp; Ossl4Pas.Bio,

&nbsp; Ossl4Pas.Err;



procedure WriteData;

var

&nbsp; Bio: TOsslBio;

begin

&nbsp; try

&nbsp;   // Create a Memory BIO (Uses TOsslBioMethodMem factory internally)

&nbsp;   Bio := TOsslBio.CreateMemory; 

&nbsp;   

&nbsp;   // Write data (Throws EOsslError on failure)

&nbsp;   Bio.Write('Hello OpenSSL', 13);

&nbsp;   

&nbsp;   // Use functional grouping for control operations via helpers

&nbsp;   if Bio.Ctrl.Pending > 0 then

&nbsp;     Writeln('Data successfully buffered');

&nbsp;     

&nbsp; except

&nbsp;   on E: EOsslError do

&nbsp;     Writeln('OpenSSL Error: ' + E.Message); // Contains full OpenSSL error stack

&nbsp; end;

end;

