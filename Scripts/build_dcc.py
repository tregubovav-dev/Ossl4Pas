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
        result = subprocess.run([git_exe, "rev-parse", "--abbrev-ref", "HEAD"],
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
        "default_compilers": [],
        "platforms": ["Win64"],
        "projects": [],
        "dependencies": {},
        "build_options": {"common": {"search_paths":[], "defines":[]}}
    }
    
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
        cfg["platforms"] =[p.strip() for p in args.platforms.split(',')]
    if args.compilers: 
        cfg["default_compilers"] = [c.strip() for c in args.compilers.split(',')]
    if args.build_config:
        cfg["default_config"] = args.build_config
    if args.clean is not None:
        cfg["clean_on_success"] = args.clean
        
    # NEW: Override OpenSSL Versions from CLI
    if args.openssl_versions:
        if "dependencies" not in cfg: cfg["dependencies"] = {}
        cfg["dependencies"]["openssl_versions"] =[v.strip() for v in args.openssl_versions.split(',')]

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
    defines = common_opts.get("defines", []) + config_opts.get("defines",[])
    define_arg = ""
    if defines:
        defines_joined = ";".join(defines)
        define_arg = f'/p:DCC_Define="{defines_joined};$(DCC_Define)"'

    # 4. Resolve Search Paths
    search_paths = common_opts.get("search_paths",[]) + config_opts.get("search_paths", [])
    search_path_args =[]
    
    if search_paths:
        abs_paths = [os.path.abspath(p) for p in search_paths]
        paths_joined = ";".join(abs_paths)
        search_path_args.append(f'/p:DCC_SysLibPath="{paths_joined};$(DCC_SysLibPath)"')
        search_path_args.append(f'/p:DCC_UnitSearchPath="{paths_joined};$(DCC_UnitSearchPath)"')

    # 5. Construct Command
    cmd =[
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
    ] + search_path_args
        
    full_cmd = " ".join(filter(None, cmd))

    with open(log_file, "a") as lf:
        lf.write(f"\n{'='*80}\nBUILDING: {project['name']} ({platform})\n{'='*80}\n")
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
# EXECUTION PROVIDERS
# ==============================================================================
class ExecutionProvider:
    """Abstract Base Class for running test executables across different environments."""
    def __init__(self, profile_name, profile_data):
        self.profile_name = profile_name
        self.profile_data = profile_data
        self.path_mapping = profile_data.get("path_mapping", {})

    def translate_path(self, path):
        if not path:
            return ""
        abs_path = os.path.abspath(path)
        for win_prefix, posix_prefix in self.path_mapping.items():
            if abs_path.lower().startswith(win_prefix.lower()):
                translated = abs_path[len(win_prefix):].replace('\\', '/')
                return posix_prefix.rstrip('/') + '/' + translated.lstrip('/')
        return abs_path.replace('\\', '/')

    def get_extension(self):
        return ""

    def get_lib_prefix(self):
        return "lib" if "Win" not in self.profile_name else ""

    def get_lib_ext(self):
        if "Win" in self.profile_name:
            return ".dll"
        if "OSX" in self.profile_name or "iOS" in self.profile_name:
            return ".dylib"
        return ".so"

    def pull_results(self, remote_file, local_file, log_file):
        return True

    def execute(self, cmd_args, log_file, work_dir=None):
        raise NotImplementedError()

class LocalExecutionProvider(ExecutionProvider):
    def get_extension(self):
        return ".exe"

    def execute(self, cmd_args, log_file, work_dir=None):
        return execute_test_process(cmd_args, log_file)

class WSLExecutionProvider(ExecutionProvider):
    def __init__(self, profile_name, profile_data):
        super().__init__(profile_name, profile_data)
        self.distro = profile_data.get("distribution", "ubuntu24.04")
        self.work_dir = profile_data.get("work_dir", "/tmp/ossl4pas_tests")

    def pull_results(self, remote_file, local_file, log_file):
        """Pulls results from WSL by streaming stdout to bypass read-only mounts."""
        log(f"    [WSL] Pulling results {remote_file} -> {local_file}", "INFO")
        
        # Command streams the file content to standard output
        wsl_cmd =["wsl", "-d", self.distro, "--", "cat", remote_file]
        
        try:
            os.makedirs(os.path.dirname(local_file), exist_ok=True)
            # Python natively catches the stream and writes it to the Windows disk
            with open(local_file, "wb") as f:
                result = subprocess.run(wsl_cmd, stdout=f, stderr=subprocess.PIPE)
                
            if result.returncode != 0:
                err_msg = result.stderr.decode('utf-8', errors='replace')
                execute_test_process(["echo", f"[WARN] WSL Pull Error: {err_msg}"], log_file)
                return False
                
            return True
        except Exception as e:
            execute_test_process(["echo", f"[WARN] WSL Pull Exception: {e}"], log_file)
            return False

    def execute(self, cmd_args, log_file, work_dir=None):
        mkdir_cmd =["wsl", "-d", self.distro, "--", "mkdir", "-p", self.work_dir]
        execute_test_process(mkdir_cmd, log_file)

        escaped_cmd = " ".join([f'"{arg}"' for arg in cmd_args])
        wsl_cmd =["wsl", "-d", self.distro, "--", "sh", "-c", escaped_cmd]
        
        return execute_test_process(wsl_cmd, log_file)

class SSHExecutionProvider(ExecutionProvider):
    def __init__(self, profile_name, profile_data):
        super().__init__(profile_name, profile_data)
        self.host = profile_data.get("host")
        self.user = profile_data.get("user")
        self.remote_root = profile_data.get("remote_root")
        self.identity_file = profile_data.get("identity_file")

    def get_ssh_base_args(self, is_scp=False):
        """Constructs base SSH/SCP command including the identity file if provided."""
        cmd = ["scp"] if is_scp else ["ssh"]
        if self.identity_file:
            expanded_path = os.path.expanduser(self.identity_file)
            cmd.extend(["-i", expanded_path])
        return cmd

    def sync_files(self, local_dir, log_file, exe_name=None):
        """Automatically syncs the compiled executable and mock libraries."""
        remote_path = self.translate_path(local_dir)

        # 1. Ensure remote directory exists
        ssh_base = self.get_ssh_base_args(is_scp=False)
        mkdir_cmd = ssh_base + [f"{self.user}@{self.host}", f"mkdir -p \"{remote_path}\""]
        if not execute_test_process(mkdir_cmd, log_file):
            return False

        # 2. Sync binaries automatically using wildcards
        scp_base = self.get_ssh_base_args(is_scp=True)
        targets = ["*.dylib", "*.so*", "*.dll"]
        if exe_name:
            targets.append(exe_name)

        import glob
        for pattern in targets:
            local_pattern = os.path.join(local_dir, pattern)
            for match in glob.glob(local_pattern):
                filename = os.path.basename(match)
                log(f"    [SSH] Uploading Artifact: {filename}", "INFO")
                scp_cmd = scp_base + [match, f"{self.user}@{self.host}:{remote_path}/"]
                execute_test_process(scp_cmd, log_file)
                
                # --- NEW: Set executable permissions for the main test binary ---
                if filename == exe_name:
                    log(f"    [SSH] Setting executable permissions for: {filename}", "DEBUG")
                    chmod_cmd = ssh_base +[f"{self.user}@{self.host}", f"chmod +x \"{remote_path}/{filename}\""]
                    execute_test_process(chmod_cmd, log_file)

        return True

    def sync_openssl(self, local_ossl_path, log_file):
        """Syncs OpenSSL dylibs to the remote host."""
        if not local_ossl_path or not os.path.exists(local_ossl_path):
            log(f"[WARN] OpenSSL path missing locally: {local_ossl_path}", "WARN")
            return True

        remote_ossl_path = self.translate_path(local_ossl_path)
        ssh_base = self.get_ssh_base_args(is_scp=False)
        scp_base = self.get_ssh_base_args(is_scp=True)

        mkdir_cmd = ssh_base +[f"{self.user}@{self.host}", f"mkdir -p \"{remote_ossl_path}\""]
        execute_test_process(mkdir_cmd, log_file)

        import glob
        for pattern in ["*.dylib", "*.so*", "*.dll"]:
            local_pattern = os.path.join(local_ossl_path, pattern)
            for match in glob.glob(local_pattern):
                log(f"    [SSH] Uploading OpenSSL: {os.path.basename(match)}", "INFO")
                # REMOVED literal quotes from the remote path here
                scp_cmd = scp_base +[match, f"{self.user}@{self.host}:{remote_ossl_path}/"]
                execute_test_process(scp_cmd, log_file)

        return True

    def pull_results(self, remote_file, local_file, log_file):
        """Pulls test result files from remote host."""
        ssh_base = self.get_ssh_base_args(is_scp=False)
        scp_base = self.get_ssh_base_args(is_scp=True)
        
        check_cmd = ssh_base +[f"{self.user}@{self.host}", f"test -f \"{remote_file}\""]
        if execute_test_process(check_cmd, log_file):
            log(f"    [SSH] Pulling results: {os.path.basename(local_file)}", "INFO")
            os.makedirs(os.path.dirname(local_file), exist_ok=True)
            # REMOVED literal quotes from both the remote file and local file paths here
            scp_cmd = scp_base +[f"{self.user}@{self.host}:{remote_file}", local_file]
            return execute_test_process(scp_cmd, log_file)
        return False

    def execute(self, cmd_args, log_file, work_dir=None):
        ssh_base = self.get_ssh_base_args(is_scp=False)
        remote_cmd = " ".join([f'"{arg}"' for arg in cmd_args])
        
        if self.remote_root:
            remote_cmd = f"mkdir -p \"{self.remote_root}\" && cd \"{self.remote_root}\" && {remote_cmd}"
            
        ssh_cmd = ssh_base +[f"{self.user}@{self.host}", remote_cmd]
        return execute_test_process(ssh_cmd, log_file)

def get_execution_provider(platform, config_data):
    """Factory to create the correct provider based on platform and config."""
    profiles = config_data.get("execution_profiles", {})
    profile = profiles.get(platform)
    
    if not profile:
        if "Win" in platform:
            return LocalExecutionProvider(platform, {"type": "local"})
        else:
            return None

    p_type = profile.get("type")
    if p_type == "local":
        return LocalExecutionProvider(platform, profile)
    elif p_type == "wsl":
        return WSLExecutionProvider(platform, profile)
    elif p_type == "ssh":
        return SSHExecutionProvider(platform, profile)
    
    return None

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

def run_test_project(project, output_dir, common_params, dependencies, build_id, platform, config_name, log_file, provider):
    """
    Runs the test executable using the provided ExecutionProvider.
    """
    ext = provider.get_extension()
    exe_name = os.path.splitext(os.path.basename(project["path"]))[0] + ext
    local_exe_path = os.path.join(output_dir, exe_name)
    
    if not os.path.exists(local_exe_path):
        log(f"Test executable missing: {local_exe_path}", "FAIL")
        return False

    # 1. Determine Versions
    versions =[]
    if project.get("matrix", False):
        versions = dependencies.get("openssl_versions", [])
        if not versions:
            log(f"    [WARN] Project requested matrix but 'openssl_versions' is empty.", "WARN")
            versions = [None] 
    else:
        versions = [None] 

    raw_ossl_path = dependencies.get("openssl_path", dependencies.get("openssl_root", ""))
    overall_success = True

    # 2. Iterate Versions
    for ver in versions:
        version_suffix = f"_{ver}" if ver else ""
        
        # --- A. Build Substitution Context ---
        context = {
            "build_id": build_id,
            "platform": platform,
            "config": config_name,
            "compiler": "DCC",
            "output_dir": output_dir,
            "exe_path": local_exe_path,
            "project_name": f"{project['name']}{version_suffix}",
            "version": ver if ver else "",
            "lib_prefix": provider.get_lib_prefix(),
            "lib_ext": provider.get_lib_ext(),
            "exe_ext": ext
        }

        # --- B. Resolve OpenSSL Path ---
        current_ossl_path = ""
        local_ossl_path_for_sync = ""
        if raw_ossl_path:
            try:
                substituted_path = raw_ossl_path.format(**context)
                substituted_path = os.path.abspath(os.path.normpath(substituted_path))
                
                # Auto-Fallback for macOS OSX vs OSX64 directory naming mismatch
                if not os.path.exists(substituted_path) and "OSX64" in substituted_path:
                    fallback = substituted_path.replace("OSX64", "OSX")
                    if os.path.exists(fallback):
                        substituted_path = fallback
                        
                local_ossl_path_for_sync = substituted_path
                current_ossl_path = provider.translate_path(substituted_path)
            except KeyError as e:
                log(f"    [WARN] openssl_path config missing variable {e}. Path ignored.", "WARN")

        if ver:
            log(f"    > Running {project['name']} [OpenSSL {ver}]...")
        else:
            log(f"    > Running {project['name']}...")

        # --- SSH Specific Transfer (AUTOMATED) ---
        if isinstance(provider, SSHExecutionProvider):
            # 1. Auto-upload executable and mock libraries
            if not provider.sync_files(output_dir, log_file, exe_name=exe_name):
                log(f"    [FAIL] SSH Sync failed for project: {project['name']}", "ERROR")
                overall_success = False
                continue
            
            # 2. Auto-upload OpenSSL
            if local_ossl_path_for_sync:
                provider.sync_openssl(local_ossl_path_for_sync, log_file)

        # --- C. Merge Parameters ---
        final_params = common_params.copy()
        final_params.update(project.get("params", {}))

        # --- D. Construct Command ---
        remote_exe_path = provider.translate_path(local_exe_path)
        cmd =[remote_exe_path]

        if current_ossl_path:
            cmd.append(f'-osp:{current_ossl_path}')

        PATH_SWITCHES =["-osp", "-mkw", "-xml", "-mkl", "-fmd", "-fml", "-rl", "-options", "--ossl-path", "--mock-workdir", "--xmlfile", "--mocklib-path", "--fastmmdebugdll", "--fastmmlogname", "--runlist", "--options"]

        for switch, value in final_params.items():
            if value:
                try:
                    formatted_value = value.format(**context)
                    is_path_param = any(switch == s or switch.startswith(s + ":") for s in PATH_SWITCHES)

                    if is_path_param:
                        if switch in["-mkw", "-xml", "--mock-workdir", "--xmlfile"] and hasattr(provider, "work_dir") and provider.work_dir:
                            filename = os.path.basename(formatted_value)
                            translated_value = f"{provider.work_dir.rstrip('/')}/{filename}"
                        else:
                            translated_value = provider.translate_path(formatted_value)
                    else:
                        translated_value = formatted_value
                        
                    cmd.append(f"{switch}:{translated_value}")
                except KeyError as e:
                    log(f"    [WARN] Parameter '{switch}' missing variable {e}. Using raw value.", "WARN")
                    cmd.append(f"{switch}:{value}")
            else:
                cmd.append(switch)

        # --- E. Execute ---
        if provider.execute(cmd, log_file):
            # --- F. Pull Results (Automated via parameters) ---
            for switch, value in final_params.items():
                if switch in ["-xml", "--xmlfile"]:
                    formatted_value = value.format(**context)
                    if hasattr(provider, "work_dir") and provider.work_dir:
                         filename = os.path.basename(formatted_value)
                         remote_result_path = f"{provider.work_dir.rstrip('/')}/{filename}"
                    else:
                         remote_result_path = provider.translate_path(formatted_value)
                    
                    local_result_path = os.path.abspath(formatted_value)
                    provider.pull_results(remote_result_path, local_result_path, log_file)

        else:
            log(f"[FAIL] Failed: {project['name']} {version_suffix}", "ERROR")
            overall_success = False

    return overall_success

# ==============================================================================
# MAIN
# ==============================================================================
def main():
    parser = argparse.ArgumentParser(description="Ossl4Pas Delphi Build Orchestrator")
    parser.add_argument("--config", help="Path to JSON config file")
    parser.add_argument("--platforms", help="Comma separated list (Win32,Win64)")
    parser.add_argument("--compilers", help="Comma separated list of compiler IDs (e.g. 11.0,12.0)")
    parser.add_argument("--openssl-versions", help="Comma separated list of OpenSSL versions (e.g. 3.0,3.3)")
    parser.add_argument("--build-config", help="Debug or Release")
    parser.add_argument("--tags", help="Comma separated list of tags to filter projects")
    parser.add_argument("--clean", action="store_true", help="Clean output on success")
    parser.add_argument("--no-clean", action="store_false", dest="clean")
    
    args = parser.parse_args()    

    config_file_path = args.config if args.config else DEFAULT_CONFIG_FILE
    if not os.path.isabs(config_file_path):
        config_file_path = os.path.abspath(config_file_path)

    cfg = load_config(args)

    original_cwd = os.getcwd()
    relative_root = cfg.get("root", ".") 
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

        report =[]
        overall_success = True
        common_params = cfg.get("common_params", {})

        dcc_config = cfg.get("dcc", {})
        active_compilers = cfg.get("default_compilers",[])
        
        if not active_compilers:
            active_compilers =[k for k, v in dcc_config.items() if v.get("active", False)]
            
        for comp_id in active_compilers:
            comp_data = dcc_config.get(comp_id)
            
            if not comp_data:
                log(f"Compiler ID '{comp_id}' not found in config", "WARN")
                continue
                
            if not comp_data.get("active", False) and not args.compilers:
                 continue
            
            rsvars = comp_data["path"]

            if not os.path.exists(rsvars):
                log(f"Compiler {comp_id} rsvars not found", "WARN")
                continue

            log(f"--- Processing Delphi {comp_id} ---")
            comp_vars = comp_data.get("variables", {})

            for platform in cfg["platforms"]:
                
                target_out_dir = os.path.join(build_dir, f"DCC_{comp_id}", platform, cfg["default_config"])
                log_file = os.path.join(build_dir, f"build_{comp_id}_{platform}.log")
                
                projects_for_execution = []
                platform_build_failed = False

                log(f"  [Phase 1] Building projects for {platform}...")
                
                for proj in cfg["projects"]:
                    if cli_tags:
                        proj_tags = set(proj.get("tags",[]))
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
                    
                    resolved_proj = proj.copy()
                    resolved_proj["path"] = resolved_path

                    success = run_msbuild(
                        rsvars, resolved_proj, platform, 
                        cfg["default_config"], target_out_dir, log_file, cfg
                    )
                    
                    if not success:
                        log(f"    Build Failed: {step_name}", "FAIL")
                        report.append({"step": step_name, "status": "Build Failed"})
                        overall_success = False
                        platform_build_failed = True
                    else:
                        projects_for_execution.append(resolved_proj)

                if not platform_build_failed and projects_for_execution:
                    log(f"  [Phase 2] Running tests for {platform}...")
                    
                    provider = get_execution_provider(platform, cfg)
                    if not provider:
                        log(f"    Skipping execution: No execution profile found for {platform}.", "INFO")
                        continue

                    for proj in projects_for_execution:
                        if proj.get("type") == "test":
                            step_name = f"{comp_id} | {platform} | {proj['name']}"

                            test_success = run_test_project(
                                proj, 
                                target_out_dir, 
                                common_params, 
                                cfg.get("dependencies", {}),
                                build_id, 
                                platform, 
                                cfg["default_config"], 
                                log_file,
                                provider
                            )                                
                            if test_success:
                                report.append({"step": step_name, "status": "Passed"})
                            else:
                                log(f"    Test Failed: {step_name}", "FAIL")
                                report.append({"step": step_name, "status": "Test Failed"})
                                overall_success = False
                elif platform_build_failed:
                    log(f"  [Phase 2] Skipping tests for {platform} due to build failures.", "WARN")

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
        os.chdir(original_cwd)

if __name__ == "__main__":
    main()
