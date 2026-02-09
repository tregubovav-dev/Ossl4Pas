import os
import sys
import shutil
import argparse

from ossl_build import utils
from ossl_build.context import BuildContext
from ossl_build.compilers.dcc import DccCompiler
from ossl_build.runners.test_runner import TestRunner

DEFAULT_CONFIG_FILE = "build_config_dcc.json"

def main():
    # 1. Parse Args & Load Config
    args = utils.parse_args()
    
    config_path = args.config if args.config else DEFAULT_CONFIG_FILE
    if not os.path.isabs(config_path):
        config_path = os.path.abspath(config_path)

    cfg = utils.load_config(config_path, args)

    # 2. Switch to Repo Root
    original_cwd = os.getcwd()
    relative_root = cfg.get("root", ".")
    config_dir = os.path.dirname(config_path)
    target_root = os.path.abspath(os.path.join(config_dir, relative_root))

    if not os.path.exists(target_root):
        utils.log(f"Configured root directory does not exist: {target_root}", "ERROR")
        sys.exit(1)

    utils.log(f"Switching Working Directory to: {target_root}")
    os.chdir(target_root)

    try:
        # 3. Global Initialization
        build_id = utils.generate_build_id(cfg["git_path"])
        root_out_dir = os.path.abspath(cfg["output_root"])
        build_base_dir = os.path.join(root_out_dir, build_id)
        
        utils.log(f"Starting Build: {build_id}")
        
        cli_tags = set(args.tags.split(',')) if args.tags else set()
        if cli_tags:
            utils.log(f"Filtering projects by tags: {cli_tags}")

        report = []
        overall_success = True
        
        # 4. Iterate DCC Versions
        dcc_config = cfg.get("dcc", {})
        active_compilers = cfg.get("default_compilers", [])
        
        # If no specific list provided (via CLI or Config), use all active ones
        if not active_compilers:
             active_compilers = [k for k, v in dcc_config.items() if v.get("active", False)]

        # --- COMPILER LOOP START ---
        for comp_id in active_compilers:
            comp_data = dcc_config.get(comp_id)
            
            if not comp_data:
                utils.log(f"Compiler ID '{comp_id}' not found in config", "WARN")
                continue

            # Check active status (unless forced via CLI, which sets active_compilers directly)
            # If the user explicitly passed --compilers, we ignore the 'active' flag in JSON
            if not args.compilers and not comp_data.get("active", False):
                 continue

            rsvars = comp_data["path"]
            if not os.path.exists(rsvars):
                utils.log(f"Compiler {comp_id} rsvars not found", "WARN")
                continue

            utils.log(f"--- Processing Delphi {comp_id} ---")
            comp_vars = comp_data.get("variables", {})

            # 5. Iterate Targets
            for platform in cfg["platforms"]:
                
                # --- PREPARE CONTEXT ---
                base_env = os.environ.copy()
                
                build_opts = cfg.get("build_options", {})
                common_opts = build_opts.get("common", {})
                config_opts = build_opts.get(cfg["default_config"], {})

                # Helper: Merge and Resolve Paths
                def merge_env_with_resolve(target_dict, source_dict):
                    for k, v in source_dict.items():
                        val_str = str(v)
                        if (os.sep in val_str or (os.altsep and os.altsep in val_str)) and \
                           "$(" not in val_str and "%" not in val_str:
                            if os.path.isabs(val_str):
                                target_dict[k] = val_str
                            else:
                                target_dict[k] = os.path.abspath(val_str)
                        else:
                            target_dict[k] = val_str

                merge_env_with_resolve(base_env, common_opts.get("env_vars", {}))
                merge_env_with_resolve(base_env, config_opts.get("env_vars", {}))
                
                ctx = BuildContext(
                    root_dir=target_root,
                    build_id=build_id,
                    compiler_id=comp_id,
                    compiler_path=rsvars,
                    platform=platform,
                    config_name=cfg["default_config"],
                    output_base=build_base_dir,
                    env_vars=base_env
                )

                compiler = DccCompiler(ctx)
                runner = TestRunner(ctx)
                
                projects_to_run = []
                platform_failed = False

                # ==============================================================
                # PHASE 1: BUILD
                # ==============================================================
                utils.log(f"  [Phase 1] Building projects for {platform}...")

                for proj in cfg["projects"]:
                    if cli_tags:
                        proj_tags = set(proj.get("tags", []))
                        if not cli_tags.intersection(proj_tags): continue

                    try:
                        resolved_path = proj["path"].format(**comp_vars)
                    except KeyError: continue
                    
                    if not os.path.exists(resolved_path): continue

                    step_name = f"{comp_id} | {platform} | {proj['name']}"
                    utils.log(f"    > Building {proj['name']}...")

                    # Project Specific Env
                    project_env = base_env.copy()
                    merge_env_with_resolve(project_env, proj.get("env_vars", {}))
                    ctx.env_vars = project_env

                    success = compiler.compile(
                        project=proj,
                        resolved_path=resolved_path,
                        build_opts=build_opts
                    )

                    if not success:
                        utils.log(f"    [FAIL] Build Failed: {step_name}", "ERROR")
                        report.append({"step": step_name, "status": "Build Failed"})
                        overall_success = False
                        platform_failed = True
                    else:
                        proj_copy = proj.copy()
                        proj_copy["path"] = resolved_path
                        proj_copy["_runtime_env"] = project_env 
                        projects_to_run.append(proj_copy)

                # ==============================================================
                # PHASE 2: TEST
                # ==============================================================
                if not platform_failed and projects_to_run:
                    has_tests = any(p.get("type") == "test" for p in projects_to_run)
                    if has_tests and "Win" in platform:
                        utils.log(f"  [Phase 2] Running tests for {platform}...")
                    
                    for proj in projects_to_run:
                        if proj.get("type") == "test":
                            step_name = f"{comp_id} | {platform} | {proj['name']}"
                            ctx.env_vars = proj["_runtime_env"]
                            
                            if "Win" in platform:
                                utils.log(f"    > Running {proj['name']}...")
                                success = runner.run(proj, cfg.get("common_params", {}))
                                if success:
                                    report.append({"step": step_name, "status": "Passed"})
                                else:
                                    utils.log(f"    [FAIL] Test Failed: {step_name}", "ERROR")
                                    report.append({"step": step_name, "status": "Test Failed"})
                                    overall_success = False
        # --- COMPILER LOOP END ---

        # 7. Reporting & Cleanup
        print("\n" + "="*60)
        print(f"{'STEP':<50} | STATUS")
        print("-" * 60)
        for item in report:
            print(f"{item['step']:<50} | {item['status']}")
        print("="*60)

        if overall_success and cfg["clean_on_success"]:
            utils.log("Cleaning up...")
            try:
                shutil.rmtree(build_base_dir)
            except Exception as e:
                utils.log(f"Cleanup error: {e}", "WARN")

        if not overall_success:
            sys.exit(1)

    finally:
        os.chdir(original_cwd)

if __name__ == "__main__":
    main()
