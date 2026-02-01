import os
import sys
import json
import subprocess
import argparse
import datetime
import shutil
import random
import string

# ==============================================================================
# DEFAULTS
# ==============================================================================
DEFAULT_CONFIG_FILE = "build_config_dcc.json"
DEFAULT_BUILD_CONFIG = "Debug"

# ==============================================================================
# UTILITIES
# ==============================================================================
def log(msg, level="INFO"):
    print(f"[{level}] {msg}")

def get_git_branch(git_exe):
    try:
        result = subprocess.run(
            [git_exe, "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True, text=True, check=True
        )
        return result.stdout.strip().replace('/', '_')
    except Exception:
        return "UnknownBranch"

def generate_build_id(git_exe):
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    branch = get_git_branch(git_exe)
    rand_suffix = ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
    return f"{timestamp}_{branch}_{rand_suffix}"

def load_config(args):
    """Merges Defaults < Config File < Env Vars < CLI Args."""
    cfg = {
        "output_root": "_build",
        "git_path": "git",
        "clean_on_success": False,
        "default_config": "Debug",
        "dcc": {},
        "default_compilers": [], # New: List of compiler IDs to run by default
        "platforms": ["Win64"],
        "projects": [],
        "dependencies": {},
        "build_options": {"common": {"search_paths": [], "defines": []}}
    }
    
    # ... (File loading logic remains the same) ...
    # Load File
    file_path = args.config if args.config else DEFAULT_CONFIG_FILE
    if os.path.exists(file_path):
        try:
            with open(file_path, 'r') as f:
                file_cfg = json.load(f)
                cfg.update(file_cfg)
        except Exception as e:
            log(f"Error reading config file: {e}", "ERROR")
            sys.exit(1)

    # CLI Overrides
    if args.platforms:
        cfg["platforms"] = args.platforms.split(',')
    if args.compilers: # New CLI override
        cfg["default_compilers"] = args.compilers.split(',')
    if args.build_config:
        cfg["default_config"] = args.build_config
    if args.clean is not None:
        cfg["clean_on_success"] = args.clean
        
    return cfg

# ==============================================================================
# BUILD ENGINE
# ==============================================================================
def run_msbuild(rsvars, project, platform, config_name, output_dir, log_file, config_data):
    """
    Executes MSBuild with injected Environment Variables and Search Paths.
    """
    os.makedirs(output_dir, exist_ok=True)
    dcu_dir = os.path.join(output_dir, "DCU")
    
    # 1. Resolve Options
    build_opts = config_data.get("build_options", {})
    common_opts = build_opts.get("common", {})
    config_opts = build_opts.get(config_name, {})

    # 2. Prepare Environment Variables
    build_env = os.environ.copy()
    
    def merge_env(source_dict):
        for k, v in source_dict.items():
            val_str = str(v)
            # Resolve relative paths to absolute based on CWD (Repo Root)
            if not os.path.isabs(val_str) and "$(" not in val_str and "%" not in val_str:
                if os.path.exists(val_str):
                    build_env[k] = os.path.abspath(val_str)
                else:
                    build_env[k] = val_str
            else:
                build_env[k] = val_str

    merge_env(common_opts.get("env_vars", {}))
    merge_env(config_opts.get("env_vars", {}))
    merge_env(project.get("env_vars", {}))

    # 3. Resolve Defines
    defines = common_opts.get("defines", []) + config_opts.get("defines", [])
    define_arg = ""
    if defines:
        defines_joined = ";".join(defines)
        define_arg = f'/p:DCC_Define="{defines_joined};$(DCC_Define)"'

    # 4. Resolve Search Paths (Restored Logic)
    search_paths = common_opts.get("search_paths", []) + config_opts.get("search_paths", [])
    search_path_args = []
    
    if search_paths:
        # Convert all to Absolute
        abs_paths = [os.path.abspath(p) for p in search_paths]
        paths_joined = ";".join(abs_paths)
        
        # Override SysLibPath to force precedence over standard libs
        search_path_args.append(f'/p:DCC_SysLibPath="{paths_joined};$(DCC_SysLibPath)"')
        # Override UnitSearchPath for standard visibility
        search_path_args.append(f'/p:DCC_UnitSearchPath="{paths_joined};$(DCC_UnitSearchPath)"')

    # 5. Construct Command
    cmd = [
        f'"{rsvars}"',
        "&&",
        "msbuild",
        f'"{project["path"]}"',
        "/t:Build",
        "/v:minimal",
        "/p:DCC_Hints=false", 
        f"/p:Config={config_name}",
        f"/p:Platform={platform}",
        f'/p:DCC_ExeOutput="{output_dir}"',
        f'/p:DCC_DcuOutput="{dcu_dir}"', 
        f'/p:DCC_BplOutput="{output_dir}"',
        f'/p:DCC_DcpOutput="{output_dir}"',
        define_arg
    ] + search_path_args # Add search paths
        
    full_cmd = " ".join(filter(None, cmd))

    with open(log_file, "a") as lf:
        lf.write(f"\n{'='*80}\nBUILDING: {project['name']} ({platform})\n{'='*80}\n")
        
        # Log relevant vars
        all_custom_keys = set(common_opts.get("env_vars", {}).keys()) | \
                          set(config_opts.get("env_vars", {}).keys()) | \
                          set(project.get("env_vars", {}).keys())
                          
        for k in all_custom_keys:
            if k in build_env:
                lf.write(f"  [ENV] {k}={build_env[k]}\n")

        lf.write(f"\n  [CMD] {full_cmd}\n")
            
        lf.flush()
        
        result = subprocess.run(
            full_cmd, 
            shell=True, 
            stdout=lf, 
            stderr=subprocess.STDOUT,
            env=build_env 
        )
    
    return result.returncode == 0

# ==============================================================================
# TEST ENGINE
# ==============================================================================
def execute_test_process(cmd_args, log_file):
    with open(log_file, "a") as lf:
        cmd_str = " ".join(cmd_args)
        lf.write(f"\n{'='*80}\nCMD: {cmd_str}\n{'='*80}\n")
        lf.flush()
        try:
            result = subprocess.run(cmd_args, stdout=lf, stderr=subprocess.STDOUT)
            return result.returncode == 0
        except Exception as e:
            lf.write(f"EXECUTION ERROR: {e}\n")
            return False

def run_test_project(project, output_dir, common_params, build_id, platform, config_name, log_file):
    exe_name = os.path.splitext(os.path.basename(project["path"]))[0] + ".exe"
    exe_path = os.path.join(output_dir, exe_name)
    
    if not os.path.exists(exe_path):
        log(f"Test executable missing: {exe_path}", "FAIL")
        return False

    log(f"  > Running {project['name']}...")

    # 1. Prepare Variable Context for Substitution
    # These variables can be used inside the JSON params values
    context = {
        "build_id": build_id,
        "platform": platform,
        "config": config_name,
        "compiler": "DCC",
        "output_dir": output_dir,
        "exe_path": exe_path,
        "project_name": project["name"]
    }

    # 2. Merge Parameters
    # Start with common params
    final_params = common_params.copy()
    
    # Override/Add project specific params
    project_params = project.get("params", {})
    final_params.update(project_params)

    # 3. Construct Command Line
    cmd = [exe_path]

    for switch, value in final_params.items():
        if value:
            try:
                # Apply variable substitution to the value (e.g. {build_id})
                formatted_value = value.format(**context)
                # Normalize paths (fix slashes for OS)
                formatted_value = os.path.normpath(formatted_value)
                
                # Construct switch: -key:value
                # We don't manually add quotes here; subprocess.run handles spaces in args automatically.
                cmd.append(f"{switch}:{formatted_value}")
            except KeyError as e:
                log(f"    [WARN] Parameter '{switch}' missing variable {e}. Using raw value.", "WARN")
                cmd.append(f"{switch}:{value}")
        else:
            # Flag only (e.g. "-verbose")
            cmd.append(switch)

    # 4. Execute
    if not execute_test_process(cmd, log_file):
        log(f"    Failed: {project['name']}", "FAIL")
        return False
    else:
        return True


# ==============================================================================
# MAIN
# ==============================================================================
def main():
    parser = argparse.ArgumentParser(description="Ossl4Pas Delphi Build Orchestrator")
    parser.add_argument("--config", help="Path to JSON config file")
    parser.add_argument("--platforms", help="Comma separated list (Win32,Win64)")
    parser.add_argument("--compilers", help="Comma separated list of compiler IDs (e.g. 11.0,12.0)")
    parser.add_argument("--build-config", help="Debug or Release")
    parser.add_argument("--tags", help="Comma separated list of tags to filter projects")
    parser.add_argument("--clean", action="store_true", help="Clean output on success")
    parser.add_argument("--no-clean", action="store_false", dest="clean")
    
    args = parser.parse_args()    

    # 1. Determine Config File Location
    # We need absolute path to resolve the "root" setting correctly later
    config_file_path = args.config if args.config else DEFAULT_CONFIG_FILE
    if not os.path.isabs(config_file_path):
        config_file_path = os.path.abspath(config_file_path)

    # Load Config
    cfg = load_config(args) # Note: ensure load_config uses config_file_path if you modified it

    # 2. Handle Root Directory Switching
    original_cwd = os.getcwd()
    
    # Default to current dir if not set
    relative_root = cfg.get("root", ".") 
    
    # Resolve root relative to the CONFIG FILE, not the current execution dir
    config_dir = os.path.dirname(config_file_path)
    target_root = os.path.abspath(os.path.join(config_dir, relative_root))

    if not os.path.exists(target_root):
        log(f"Configured root directory does not exist: {target_root}", "ERROR")
        sys.exit(1)

    log(f"Switching Working Directory to: {target_root}")
    os.chdir(target_root)

    try:    

        cli_tags = set(args.tags.split(',')) if args.tags else set()
        build_id = generate_build_id(cfg["git_path"])
        root_dir = os.path.abspath(cfg["output_root"])
        build_dir = os.path.join(root_dir, build_id)
        
        log(f"Starting Build Sequence: {build_id}")
        if cli_tags:
            log(f"Filtering projects by tags: {cli_tags}")

        report = []
        overall_success = True
        common_params = cfg.get("common_params", {})

        dcc_config = cfg.get("dcc", {})
        
        # Determine Compilers to Run
        dcc_config = cfg.get("dcc", {})
        active_compilers = cfg.get("default_compilers", [])
        
        # If no specific list provided, use all active ones from config
        if not active_compilers:
            active_compilers = [k for k, v in dcc_config.items() if v.get("active", False)]
            
        # 1. Iterate Compilers
        for comp_id in active_compilers:
            comp_data = dcc_config.get(comp_id)
            
            if not comp_data:
                log(f"Compiler ID '{comp_id}' not found in config", "WARN")
                continue
                
            if not comp_data.get("active", False) and not args.compilers:
                 # Skip inactive unless explicitly requested via CLI
                 continue
            
            rsvars = comp_data["path"]

            if not os.path.exists(rsvars):
                log(f"Compiler {comp_id} rsvars not found", "WARN")
                continue

            log(f"--- Processing Delphi {comp_id} ---")
            comp_vars = comp_data.get("variables", {})

            # 2. Iterate Targets
            for platform in cfg["platforms"]:
                
                target_out_dir = os.path.join(build_dir, "DCC", platform, cfg["default_config"])
                log_file = os.path.join(build_dir, f"build_{comp_id}_{platform}.log")
                
                # We store successfully resolved/built projects here to iterate them for testing later
                projects_for_execution = []
                platform_build_failed = False

                # ==================================================================
                # PHASE 1: BUILD EVERYTHING
                # ==================================================================
                log(f"  [Phase 1] Building projects for {platform}...")
                
                for proj in cfg["projects"]:
                    # --- PRE-CHECKS ---
                    if cli_tags:
                        proj_tags = set(proj.get("tags", []))
                        if not cli_tags.intersection(proj_tags):
                            continue

                    try:
                        resolved_path = proj["path"].format(**comp_vars)
                    except KeyError as e:
                        log(f"    Skipping '{proj['name']}': missing variable {e}", "WARN")
                        continue

                    if not os.path.exists(resolved_path):
                        log(f"    Skipping '{proj['name']}': file not found", "WARN")
                        continue

                    step_name = f"{comp_id} | {platform} | {proj['name']}"
                    
                    # Create a resolved copy of the project config
                    resolved_proj = proj.copy()
                    resolved_proj["path"] = resolved_path

                    # --- EXECUTE BUILD ---
                    success = run_msbuild(
                        rsvars, resolved_proj, platform, 
                        cfg["default_config"], target_out_dir, log_file, cfg
                    )
                    
                    if not success:
                        log(f"    Build Failed: {step_name}", "FAIL")
                        report.append({"step": step_name, "status": "Build Failed"})
                        overall_success = False
                        platform_build_failed = True
                        # We continue building other projects to see all errors, 
                        # but we flag the platform as 'dirty'.
                    else:
                        # Store for Phase 2
                        projects_for_execution.append(resolved_proj)


                # ==================================================================
                # PHASE 2: RUN TESTS
                # Only run tests if the build phase for this platform was clean.
                # Running tests on partial builds often leads to misleading errors.
                # ==================================================================
                if not platform_build_failed and projects_for_execution:
                    log(f"  [Phase 2] Running tests for {platform}...")

                    for proj in projects_for_execution:
                        if proj.get("type") == "test":
                            step_name = f"{comp_id} | {platform} | {proj['name']}"

                            if "Win" in platform:
                                test_success = run_test_project(
                                    proj, 
                                    target_out_dir, 
                                    common_params, 
                                    build_id, 
                                    platform, 
                                    cfg["default_config"], 
                                    log_file
                                )
                                
                                if test_success:
                                    report.append({"step": step_name, "status": "Passed"})
                                else:
                                    log(f"    Test Failed: {step_name}", "FAIL")
                                    report.append({"step": step_name, "status": "Test Failed"})
                                    overall_success = False
                            else:
                                log(f"    Skipping execution for {platform} (Not supported locally)", "INFO")
                elif platform_build_failed:
                    log(f"  [Phase 2] Skipping tests for {platform} due to build failures.", "WARN")

        # 3. Final Report
        print("\n" + "="*80)
        print(f"{'STEP':<60} | STATUS")
        print("-" * 80)
        for item in report:
            print(f"{item['step']:<60} | {item['status']}")
        print("="*80)
        
        if overall_success and cfg["clean_on_success"]:
            log("Cleaning up...")
            try:
                shutil.rmtree(build_dir)
            except Exception as e:
                log(f"Cleanup error: {e}", "WARN")
                
        if not overall_success:
            sys.exit(1)

    finally:
        # 3. Restore Directory
        os.chdir(original_cwd)

if __name__ == "__main__":
    main()