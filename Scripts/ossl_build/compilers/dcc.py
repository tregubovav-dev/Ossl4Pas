import os
import subprocess
from ..context import BuildContext
from ..utils import log

class DccCompiler:
    def __init__(self, context: BuildContext):
        self.ctx = context

    def compile(self, project: dict, resolved_path: str, build_opts: dict) -> bool:
        """
        Runs MSBuild for the given project.
        """
        # Ensure directories
        os.makedirs(self.ctx.output_dir, exist_ok=True)
        os.makedirs(self.ctx.dcu_dir, exist_ok=True)

        # 1. Resolve Options (Common + Config Specific)
        common_opts = build_opts.get("common", {})
        config_opts = build_opts.get(self.ctx.config_name, {})

        # Note: Env vars are already merged into self.ctx.env_vars by the orchestrator
        
        # Merge Defines
        defines = common_opts.get("defines", []) + config_opts.get("defines", [])

        # 2. Construct Properties
        msbuild_props = [
            "/t:Build",
            "/v:minimal",
            "/p:DCC_Hints=false",
            f"/p:Config={self.ctx.config_name}",
            f"/p:Platform={self.ctx.platform}",
            f'/p:DCC_ExeOutput="{self.ctx.output_dir}"',
            f'/p:DCC_DcuOutput="{self.ctx.dcu_dir}"',
            f'/p:DCC_BplOutput="{self.ctx.output_dir}"',
            f'/p:DCC_DcpOutput="{self.ctx.output_dir}"'
        ]

        if defines:
            defines_joined = ";".join(defines)
            msbuild_props.append(f'/p:DCC_Define="{defines_joined};$(DCC_Define)"')

        # 3. Construct Command
        cmd = [
            f'"{self.ctx.compiler_path}"', # rsvars.bat
            "&&",
            "msbuild",
            f'"{resolved_path}"'
        ] + msbuild_props

        # 4. Execute
        # We append to the log file defined in context
        with open(self.ctx.log_file, "a") as lf:
            lf.write(f"\n{'='*80}\nBUILDING: {project['name']} ({self.ctx.platform})\n{'='*80}\n")
            
            # Log specific env vars for debugging
            if "FASTMM5" in self.ctx.env_vars:
                lf.write(f"  [ENV] FASTMM5={self.ctx.env_vars['FASTMM5']}\n")
            
            lf.flush()
            
            full_cmd = " ".join(filter(None, cmd))
            lf.write(f"  [CMD] {full_cmd}\n")
            lf.flush()

            try:
                result = subprocess.run(
                    full_cmd, 
                    shell=True, 
                    stdout=lf, 
                    stderr=subprocess.STDOUT,
                    env=self.ctx.env_vars
                )
                return result.returncode == 0
            except Exception as e:
                lf.write(f"  [EXCEPTION] {e}\n")
                return False