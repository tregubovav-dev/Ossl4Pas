import os
import sys
import json
import subprocess
import datetime
import random
import string
import argparse

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

def merge_configs(base, overlay):
    """Recursively merges overlay dict into base dict."""
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            merge_configs(base[key], value)
        else:
            base[key] = value
    return base

def load_config(config_path, cli_args):
    """
    Loads JSON config and applies CLI overrides.
    """
    # Default Structure
    cfg = {
        "root": "..\\..",
        "output_root": "_build_results",
        "git_path": "git",
        "clean_on_success": False,
        "default_config": "Debug",
        "default_compilers": [],
        "dcc": {},
        "platforms": ["Win64"],
        "projects": [],
        "common_params": {}, 
        "build_options": {"common": {"env_vars": {}, "defines": []}}
    }

    if os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                file_cfg = json.load(f)
                # Simple top-level update (for deep merge, use merge_configs if needed)
                cfg.update(file_cfg)
        except Exception as e:
            log(f"Error reading config file: {e}", "ERROR")
            sys.exit(1)

    # CLI Overrides
    if cli_args.platforms:
        cfg["platforms"] = [p.strip() for p in cli_args.platforms.split(',')]
    if cli_args.compilers:
        cfg["default_compilers"] = [c.strip() for c in cli_args.compilers.split(',')]
    if cli_args.build_config:
        cfg["default_config"] = cli_args.build_config
    if cli_args.clean is not None:
        cfg["clean_on_success"] = cli_args.clean

    return cfg

def parse_args():
    parser = argparse.ArgumentParser(description="Ossl4Pas Build System")
    parser.add_argument("--config", help="Path to JSON config file")
    parser.add_argument("--platforms", help="Comma separated list (Win32,Win64)")
    parser.add_argument("--compilers", help="Comma separated list of compiler IDs")
    parser.add_argument("--build-config", help="Debug or Release")
    parser.add_argument("--tags", help="Comma separated list of tags to filter projects")
    parser.add_argument("--clean", action="store_true", help="Clean output on success")
    parser.add_argument("--no-clean", action="store_false", dest="clean")
    return parser.parse_args()
