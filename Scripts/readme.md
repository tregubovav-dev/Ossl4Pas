# Delphi Local Build Script (`build_dcc.py`)

This script is a unified build and test automation tool for Delphi projects. It orchestrates **MSBuild** to compile multiple projects across multiple Delphi versions and platforms, manages dependencies via Environment Variables, and executes Unit Tests automatically (including multi-version matrix testing).

## Key Features
*   **Multi-Compiler Support:** Build against multiple installed Delphi versions (e.g., 10.4, 11, 12) in a single run.
*   **Matrix Testing:** Automatically run integration tests against multiple OpenSSL versions (e.g., 3.0, 3.3, 3.4) sequentially.
*   **Dependency Injection:** Injects paths via Environment Variables to override system libraries (e.g., FastMM5) without modifying `.dproj` files.
*   **Shared Output:** Consolidates DCU, BPL, and EXE files into a unified directory structure to resolve runtime package dependencies automatically.
*   **Flexible Configuration:** Supports variable substitution, path normalization, and CLI overrides.

## Prerequisites

1.  **Python 3.6+** (Uses standard libraries only).
2.  **Delphi (RAD Studio)** installed.
3.  **OpenSSL Binaries** (Required for integration tests).

## Quick Start

Run the script from the directory containing the config file:

```bash
cd Scripts/dcc
python build_dcc.py
```

By default, this will:
1.  Read `build_config_dcc.json`.
2.  Build all active projects for **Win32** and **Win64** using the **Debug** configuration.
3.  Run any projects marked as `type: "test"`.
4.  Output artifacts to `_build_results/`.

---

## Command Line Arguments

You can override configuration settings using CLI switches:

| Argument | Description | Example |
| :--- | :--- | :--- |
| `--config <path>` | Use a specific JSON configuration file. | `python build_dcc.py --config my_ci.json` |
| `--platforms <list>` | Comma-separated list of platforms to build. | `--platforms Win64` |
| `--compilers <list>` | Comma-separated list of Compiler IDs to run. | `--compilers 12.0,11.0` |
| `--openssl-versions <list>`| Override the list of OpenSSL versions for matrix tests. | `--openssl-versions 3.0,3.3` |
| `--build-config <name>` | Build configuration (Debug/Release). | `--build-config Release` |
| `--tags <list>` | Filter projects by tag. | `--tags core,fast` |
| `--clean` | Delete the build output directory after a successful run. | `--clean` |
| `--no-clean` | Force keeping the output directory (Default). | `--no-clean` |

---

## Configuration (`build_config_dcc.json`)

### 1. Global Settings
```json
{
  "root": "Z:\\Projects\\Ossl4Pas",   // Base path for resolving relative paths in this config
  "output_root": "_build_results",    // Directory for compiled artifacts
  "git_path": "git",                  
  "clean_on_success": false,
  "default_config": "Debug",
  "default_compilers": ["12.0"],      // Default compilers to run if CLI arg is missing
  "platforms": ["Win64", "Win32"]
}
```

### 2. Compilers (`dcc`)
Define installed Delphi versions and version-specific variables.

```json
  "dcc": {
    "12.0": { 
      "path": "C:\\Program Files (x86)...\\23.0\\bin\\rsvars.bat", 
      "active": true,
      "variables": { "dcc_suffix": "D12" }
    }
  }
```

### 3. Build Options (Environment & Defines)
Injects Environment Variables and Preprocessor Defines into the MSBuild process.
*   **Env Vars:** Used to resolve paths inside `.dproj` files (e.g., `$(FASTMM5)`). Paths defined here are automatically converted to absolute paths relative to `root`.

```json
  "build_options": {
    "common": {
      "env_vars": {
        "FASTMM5": "Libs\\FastMM5",
        "DUNITX": "Libs\\DUnitX\\Source"
      },
      "defines": ["CI_BUILD", "UNITTEST"]
    },
    "Debug": { "defines": ["FullDebugMode"] }
  }
```

### 4. Dependencies & Matrix
Configures external dependencies for Integration Tests.

*   **`mocklib`**: Path to the compiled mock library (supports `{build_id}`, `{platform}` placeholders).
*   **`openssl_path`**: Template path to OpenSSL binaries. Supports `{platform}` and `{version}` substitution.
*   **`openssl_versions`**: List of versions to iterate through for Matrix tests.

```json
  "dependencies": {
    "mocklib": {
      "path": "{output_dir}\\mocklib.dll"
    },
    "openssl_versions": ["3.0", "3.3"],
    "openssl_path": "C:\\Libs\\OpenSSL\\{platform}\\{version}\\bin"
  }
```

### 5. Common Parameters
Defines default command-line arguments passed to **all** test executables. These can be overridden per project.

```json
  "common_params": {
    "-exit": "Continue",
    "-xml": "{output_dir}\\{project_name}_results.xml"
  }
```

### 6. Projects
List of `.dproj` or `.dpk` files.

*   **`path`**: Supports variable substitution (e.g., `{dcc_suffix}`).
*   **`type`**: `"package"` (Build only) or `"test"` (Build and Run).
*   **`matrix`**: If `true`, this test runs multiple times, once for each version in `openssl_versions`.
*   **`params`**: Project-specific overrides for command line arguments.

```json
  "projects": [
    { 
      "name": "Core_Package", 
      "path": "Packages\\Ossl4Pas_{dcc_suffix}.dproj", 
      "type": "package"
    },
    { 
      "name": "Test_API", 
      "path": "Tests\\Api\\TestApi.dproj", 
      "type": "test",
      "matrix": true,  // Runs against OpenSSL 3.0, then 3.3
      "tags": ["integration"]
    }
  ]
```

---

## Directory Structure

The script generates a unique Build ID for every run to avoid file locking collisions.

**Output Format:**
`[OutputRoot] \ [BuildID] \ DCC \ [Platform] \ [Config] \`

All artifacts for a specific run (EXE, DLL, BPL, DCU) are placed in this folder. This allows Test Executables to automatically find the Runtime Packages (`.bpl`) and Mock Libraries (`.dll`) built in previous steps without PATH manipulation.