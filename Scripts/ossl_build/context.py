import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional

@dataclass
class BuildContext:
    """
    Holds the immutable state for a specific build/run operation iteration.
    """
    # Global settings
    root_dir: str
    build_id: str
    
    # Current Iteration details
    compiler_id: str      # e.g. "12.0"
    compiler_path: str    # Path to rsvars.bat
    platform: str         # e.g. "Win64"
    config_name: str      # e.g. "Debug"
    
    # Paths
    output_base: str      # Root output for this build_id
    
    # Environment variables to inject into subprocesses
    env_vars: Dict[str, str] = field(default_factory=dict)

    @property
    def output_dir(self) -> str:
        """
        Returns the specific output folder for this combo.
        Example: _build_results/2026.../DCC/Win64/Debug
        """
        # We hardcode "DCC" here for now, could be dynamic if we support FPC later in same context
        return os.path.join(self.output_base, "DCC", self.platform, self.config_name)

    @property
    def dcu_dir(self) -> str:
        return os.path.join(self.output_dir, "DCU")

    @property
    def log_file(self) -> str:
        return os.path.join(self.output_base, f"build_{self.compiler_id}_{self.platform}.log")
    