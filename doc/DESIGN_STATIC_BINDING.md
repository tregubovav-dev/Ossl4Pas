# Design: OpenSSL Static Binding

This document outlines the architecture, directory structure, and build process changes required to support **Static Linking** of OpenSSL libraries (`.lib`/`.a`) into Ossl4Pas-based applications.

## 1. Directory Structure

To support parallel testing of multiple OpenSSL versions and linkage types, we define a strict directory layout for external dependencies. This structure is populated by the **`Scripts/setup_libs.py`** script.

**Root:** `lib/openssl/` (Relative to Repo Root)

**Format:** `lib/openssl/{Version}/{Platform}/{Linkage}/`

**Example Layout:**
```text
lib/openssl/
├── 3.0.19/
│   ├── Win64EC/
│   │   ├── static/    
│   │   │   ├── libcrypto.lib
│   │   │   ├── libssl.lib
│   │   │   └── ossl_version_scope.inc  <-- Auto-generated definitions (e.g. {$DEFINE OSSL_3_0}, {$DEFINE OSSL_STRICT_3_0})
│       ├── lib/static    
│       │       ├── libcrypto.lib
│       │       ├── libssl.lib
│       │       └── ossl_version_scope.inc
│       └── libcrypto.dll    
│       └── libss.dll    
│   └── Linux64/
│       ├── lib/static    
│       │       ├── libcrypto.a
│       │       ├── libssl.a
│       │       └── ossl_version_scope.inc
│       └── libcrypto.so    
│       └── libss.so    
├── 3.3.6/
│   └── ...
```

## 2. Compilation Architecture

### A. Versioning Strategy (Injection + Cascade)
To ensure code compiles correctly against the specific OpenSSL version being linked:

1.  **Injection:** The build script adds the specific `lib/static` folder (e.g., `.../3.3.6/Win64EC/lib/static`) to the Search Path.
2.  **Scope:** The compiler finds `ossl_version_scope.inc` in that folder, which contains a couple defines: `{$DEFINE OSSL_3_3}` and `{$DEFINE OSSL_STRICT_3_3}`
3.  **Cascade:** The unit `Ossl4Pas_Version.inc` (included globally) detects `OSSL_3_3` and automatically defines all lower versions (`OSSL_3_2`, `OSSL_3_1`, `OSSL_3_0`).
4.  **Strict:** The define `{$DEFINE OSSL_STRICT_3_3}` in `ossl_version_scope.inc` declares the distinct OpenSSL library version. 

### B. Unit Adaptation Pattern (`Ossl4Pas.Api.*`)

We use a **"Same Name" Optimization** to keep the high-level class implementation identical for both modes.

*   **Dynamic Mode:** `F_BIO_new` is a **Function Pointer Variable**.
*   **Static Mode:** `F_BIO_new` is an **External Function Declaration**.

**Implementation Pattern:**

```pascal
implementation

{$IFDEF LINK_STATIC}
  // 1. STATIC MODE: External Function Declaration
  // We map the internal name 'F_BIO_new' to the exported symbol 'BIO_new'
  function F_BIO_new(Method: PBIO_METHOD): PBIO; cdecl; external 'libcrypto' name 'BIO_new';
{$ELSE}
  // 2. DYNAMIC MODE: Function Pointer Variable
  // Initialized to Stub by default
  var F_BIO_new: TRoutine_BIO_new = nil; 
{$ENDIF}

// ...

// The Wrapper implementation is identical for both!
class function TOsslApiBio.BIO_new(Method: PBIO_METHOD): PBIO;
begin
  // If Static: Calls the external function directly.
  // If Dynamic: Calls the function pointer variable.
  Result := F_BIO_new(Method);
end;
```

### C. Handling Missing Symbols (Versioning)
In Static mode, referencing a symbol that doesn't exist in the linked `.lib` causes a **Linker Error**. We must guard newer API calls with version defines.

```pascal
{$IFDEF LINK_STATIC}
  {$IFDEF OSSL_3_2}
    // Only declare if we are linking against 3.2 or higher
    function F_BIO_s_dgram_pair(...): ...; external ...;
  {$ENDIF}
{$ELSE}
    var F_BIO_s_dgram_pair: ...;
{$ENDIF}

class function TOsslApiBioDgram.BIO_s_dgram_pair: PBIO_METHOD;
begin
  {$IFDEF LINK_STATIC}
    {$IFDEF OSSL_3_2}
      Result := F_BIO_s_dgram_pair();
    {$ELSE}
      // Graceful degradation for static builds on older versions
      Result := nil; 
    {$ENDIF}
  {$ELSE}
    // Dynamic mode handles missing symbols via Stubs/Nil checks
    Result := F_BIO_s_dgram_pair();
  {$ENDIF}
end;
```

### D. System Dependencies
The research displayed serious incompatibilities between native linkes used for `Win32` and `Win64` targets and `LLVM` based linkers for all other targts.
We made a decision to support only `LLVM` linkers as native linkes do not support linkage with `static` libraries and require to build amalgamated object file and include all external routines into the single unit. Otherwise the `LLVM` linkers allows to declare a single external routine in any unit.
We created the `Ossl4Pas.Static.pas` unit that declares static library file names.

**Required Links (Windows):** (Currently the ARM64EC can support static linking)
*   `ws2_32.lib` (Winsock)
*   `gdi32.lib`
*   `advapi32.lib`
*   `crypt32.lib`
*   `user32.lib`

**Required Exports: (Linux)**
* `__dso_handle` routine must be exported 

## 3. Build Script Updates (`build_dcc.py`)

The python script needs to support an "Inverted Matrix" for static builds:
1.  Loop through defined `openssl_versions`.
2.  For each version:
    *   Clean output directory.
    *   Set `OpenSSL_LibPath` property to `lib/openssl/{Ver}/{Plat}/lib/static`.
    *   Set `DCC_Define` to include `LINK_STATIC`.
    *   **Note:** We do *not* define `OSSL_3_x` manually; the inclusion of `ossl_version_scope.inc` handles it.
    *   Build `Test_Api_Static.dproj`.
    *   Rename output EXE to `Test_Api_Static_{Ver}.exe` to prevent overwriting.
    *   Run Test.

---

## 4. Execution Plan & Checklist

### Phase 1: Infrastructure
- [x] Create `setup_libs.py` to download and organize OpenSSL binaries.
- [x] Implement `ossl_version_scope.inc` generation.
- [x] Run setup script and verify directory structure.

### Phase 2: Base Code Adaptation
- [x] Create `Ossl4Pas.Static.pas`.
- [x] Create `Ossl4Pas_Version.inc` (Cascade logic).
- [x] Modify `Ossl4Pas_CompilerDefines.inc` to include version logic.
- [x] Refactor `Ossl4Pas.Api.Bio` to support `{$IFDEF LINK_STATIC}` using the "Same Name" pattern.
- [ ] Refactor `Ossl4Pas.Api.Err` to support `{$IFDEF LINK_STATIC}`.

### Phase 3: Build System
- [ ] Update `build_config_dcc.json` to define static test projects.
- [ ] Update `build_dcc.py` to handle "Static Matrix" build logic (renaming output EXEs).

### Phase 4: Verification
- [ ] Run `build_dcc.py --tags static` on Windows.
- [ ] Verify `Test_Api_Static_3.0.exe` runs successfully.
- [ ] Verify `Test_Api_Static_3.3.exe` runs successfully.