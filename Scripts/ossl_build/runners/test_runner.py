import os
import subprocess
import shlex
from typing import Dict, Any
from ..context import BuildContext
from ..utils import log

class TestRunner:
    def __init__(self, context: BuildContext):
        self.ctx = context

    def run(self, project: Dict[str, Any], common_params: Dict[str, str]) -> bool:
        """
        Runs the test executable defined in the project config.
        """
        # 1. Locate Executable
        exe_name = os.path.splitext(os.path.basename(project["path"]))[0] + ".exe"
        exe_path = os.path.join(self.ctx.output_dir, exe_name)
        
        if not os.path.exists(exe_path):
            log(f"Test executable missing: {exe_path}", "FAIL")
            return False

        # 2. Prepare Variable Context for Substitution
        # These variables can be used inside the JSON params values
        sub_context = {
            "build_id": self.ctx.build_id,
            "platform": self.ctx.platform,
            "config": self.ctx.config_name,
            "compiler": "DCC", # Hardcoded for this specific runner context
            "output_dir": self.ctx.output_dir,
            "exe_path": exe_path,
            "project_name": project["name"]
        }

        # 3. Merge Parameters
        # Project params override Common params
        final_params = common_params.copy()
        final_params.update(project.get("params", {}))

        # 4. Construct Command Line
        cmd = [exe_path]

        for switch, value in final_params.items():
            if value:
                try:
                    # Apply variable substitution
                    formatted_value = value.format(**sub_context)
                    # Normalize paths
                    formatted_value = os.path.normpath(formatted_value)
                    
                    # Add switch
                    cmd.append(f"{switch}:{formatted_value}")
                except KeyError as e:
                    log(f"    [WARN] Parameter '{switch}' missing variable {e}. Using raw value.", "WARN")
                    cmd.append(f"{switch}:{value}")
            else:
                # Flag only (e.g. "-verbose")
                cmd.append(switch)

        # 5. Execute
        with open(self.ctx.log_file, "a") as lf:
            lf.write(f"\n{'='*80}\nTESTING: {project['name']}\n{'='*80}\n")
            
            cmd_str = " ".join(cmd)
            lf.write(f"CMD: {cmd_str}\n")
            lf.flush()
            
            try:
                # Use the environment from context (contains injected vars)
                result = subprocess.run(
                    cmd, 
                    stdout=lf, 
                    stderr=subprocess.STDOUT,
                    env=self.ctx.env_vars
                )
                
                if result.returncode != 0:
                    lf.write(f"EXIT CODE: {result.returncode}\n")
                    return False
                return True
                
            except Exception as e:
                lf.write(f"EXECUTION ERROR: {e}\n")
                return False
            