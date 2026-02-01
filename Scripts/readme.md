# Delphi Local build script (`build_dcc.py`)

This script is a unified build and test automation tool for Delphi projects. It orchestrates **MSBuild** to compile multiple projects across multiple Delphi versions and platforms, manages dependencies, and executes Unit Tests automatically.

## Key Features
*   **Multi-Compiler Support:** Build against multiple installed Delphi versions (e.g., 10.4, 11, 12) in a single run.
*   **Dependency Management:** Automatically injects source paths (e.g., FastMM5, DUnitX) to override default system libraries.
*   **Shared Output:** Consolidates DCU, BPL, and EXE files into a unified directory structure to resolve runtime package dependencies automatically.
*   **Test Orchestration:** Runs test executables immediately after building and reports results.

## Prerequisites

1.  **Python 3.6+** (Uses standard libraries only).
2.  **Delphi (RAD Studio)** installed.
3.  **OpenSSL Binaries** (for running integration tests).

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
| `--config <path>` | Use a specific JSON configuration file. | `python build_dcc.py --config my_ci_config.json` |
| `--platforms <list>` | Comma-separated list of platforms to build. Overrides config. | `--platforms Win64` or `--platforms Win32,Win64` |
| `--compilers <list>` | Comma-separated list of Compiler IDs to run. | `--compilers 12.0` or `--compilers 11.0,12.0` |
| `--build-config <name>` | Build configuration (Debug/Release). | `--build-config Release` |
| `--tags <list>` | Filter projects by tag. Only projects containing at least one of these tags will run. | `--tags core,fast` |
| `--clean` | Delete the build output directory (`_build_results`) after a successful run. | `--clean` |
| `--no-clean` | Force keeping the output directory (Default behavior). | `--no-clean` |

---

## Configuration (`build_config_dcc.json`)

The behavior is controlled by a JSON file. Below is the schema definition.

### 1. Global Settings
```json
{
  "root": "..\\..",                  // Root of the repo relative to this config file
  "output_root": "_build_results",    // Directory for compiled artifacts
  "git_path": "git",                  // Path to git executable (for build ID generation)
  "clean_on_success": false,          // Delete artifacts if all tests pass?
  "default_config": "Debug",          // Default MSBuild config
  "platforms": ["Win64", "Win32"],    // Platforms to build
  // ...
}
```

### 2. Compilers (`dcc`)
Define installed Delphi versions. The `variables` section allows you to define placeholders (like `{dcc_suffix}`) to handle version-specific project filenames (e.g., `Package_D12.dproj`).

```json
  "dcc": {
    "12.0": { 
      "path": "C:\\Program Files (x86)...\\23.0\\bin\\rsvars.bat", 
      "active": true,
      "variables": { "dcc_suffix": "D12" }
    },
    "11.0": {
      "path": "C:\\Program Files (x86)...\\22.0\\bin\\rsvars.bat", 
      "active": false 
    }
  }
```

### 3. Build Options (Search Paths & Defines)
Injects Search Paths and Preprocessor Defines into MSBuild.
*   **Search Paths:** Added to `DCC_SysLibPath` to ensure your custom sources (e.g., FastMM5) take precedence over pre-compiled DCUs shipped with Delphi.
*   **Env Vars:** Injected into the process environment.

```json
  "build_options": {
    "common": {
      "env_vars": {
        "FASTMM5": "Libs\\FastMM5",
        "DUNITX": "Libs\\DUnitX"
      },
      "search_paths": [
        "$(FASTMM5)", 
        "$(DUNITX)"
      ],
      "defines": ["CI_BUILD", "UNITTEST"]
    },
    "Debug": { "defines": ["FullDebugMode"] },
    "Release": { "defines": [] }
  }
```

### 4. Projects
List of `.dproj` or `.dpk` files to build.

*   **`path`**: Supports variable substitution (e.g., `{dcc_suffix}` comes from the Compiler definition).
*   **`type`**: `"package"` (Build only) or `"test"` (Build and Run).
*   **`tags`**: Used for filtering via CLI.
*   **`params`**: Command line arguments passed to the Test Executable (supports `{build_id}`, `{platform}`, `{config}` placeholders).

```json
  "projects": [
    { 
      "name": "Core_Package", 
      "path": "Packages\\Ossl4Pas_{dcc_suffix}.dproj", 
      "type": "package",
      "tags": ["core"]
    },
    { 
      "name": "Test_Loader", 
      "path": "Tests\\Loader\\TestLoader.dproj", 
      "type": "test",
      "tags": ["tests"],
      "params": {
        "-mkl": "_build_results\\{build_id}\\DCC\\{platform}\\{config}\\MockLib.dll"
      }
    }
  ]
```

---

## Directory Structure

The script generates a unique Build ID for every run to avoid file locking collisions.

**Output Format:**
`[OutputRoot] \ [BuildID] \ DCC \ [Platform] \ [Config] \`

**Example:**
`_build_results \ 20260130_Feature_A1B2 \ DCC \ Win64 \ Debug \`

All artifacts for a specific run (EXE, DLL, BPL, DCU) are placed in this folder. This ensures that Test Executables can automatically find the Runtime Packages (`.bpl`) and Mock Libraries (`.dll`) built in previous steps without needing to modify the system `%PATH%`.