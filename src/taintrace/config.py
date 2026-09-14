"""Config loading for taintrace."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

CONFIG_FILE_NAMES = [".taintrace.toml", ".taintracerc"]


def load_config(cwd: Optional[Path] = None) -> dict:
    """Load config from file, return empty dict if none found."""
    if cwd is None:
        cwd = Path.cwd()
    
    for name in CONFIG_FILE_NAMES:
        config_path = cwd / name
        if config_path.exists():
            try:
                try:
                    import tomllib
                except ModuleNotFoundError:  # Python 3.10
                    import tomli as tomllib
                with open(config_path, "rb") as f:
                    data = tomllib.load(f)
                    return data.get("taintrace", {})
            except Exception:
                return {}
    return {}


def get_ignored_packages(cwd: Optional[Path] = None) -> list[str]:
    """Get list of ignored packages from config."""
    config = load_config(cwd)
    return config.get("ignore", [])
