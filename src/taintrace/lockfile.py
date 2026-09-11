"""Lockfile parsers for multiple ecosystems."""

from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional
import re


@dataclass
class Dependency:
    """A parsed dependency from any lockfile."""
    name: str
    version: str
    ecosystem: str  # "rust", "node", "python", "go"


class LockfileParser:
    """Parse lockfiles and extract dependency names."""

    def parse(self, path: Path) -> List[Dependency]:
        """Auto-detect lockfile type and parse accordingly."""
        name = path.name.lower()
        if name == "cargo.lock":
            return self._parse_cargo(path)
        elif name == "package-lock.json":
            return self._parse_package_lock(path)
        elif name == "requirements.txt":
            return self._parse_requirements(path)
        elif name == "go.sum":
            return self._parse_go_sum(path)
        else:
            # Try as Cargo.lock by default
            return self._parse_cargo(path)

    def _parse_cargo(self, path: Path) -> List[Dependency]:
        """Parse Cargo.lock TOML format."""
        deps = []
        content = path.read_text()
        # Match [[package]] blocks with name and version
        blocks = re.split(r'\[\[package\]\]', content)
        for block in blocks[1:]:  # skip preamble
            name_match = re.search(r'name\s*=\s*"([^"]+)"', block)
            version_match = re.search(r'version\s*=\s*"([^"]+)"', block)
            if name_match and version_match:
                deps.append(Dependency(
                    name=name_match.group(1),
                    version=version_match.group(1),
                    ecosystem="rust"
                ))
        return deps

    def _parse_package_lock(self, path: Path) -> List[Dependency]:
        """Parse package-lock.json (npm)."""
        import json
        deps = []
        try:
            data = json.loads(path.read_text())
            packages = data.get("packages", {})
            for pkg_path, pkg_info in packages.items():
                if not pkg_path.startswith("node_modules/"):
                    continue
                pkg_name = pkg_path.replace("node_modules/", "")
                version = pkg_info.get("version", "0.0.0")
                deps.append(Dependency(
                    name=pkg_name,
                    version=version,
                    ecosystem="node"
                ))
        except (json.JSONDecodeError, KeyError):
            pass
        return deps

    def _parse_requirements(self, path: Path) -> List[Dependency]:
        """Parse requirements.txt (pip)."""
        deps = []
        content = path.read_text()
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Handle "package==1.0.0", "package>=1.0", "package"
            match = re.match(r'^([a-zA-Z0-9_-]+)', line)
            if match:
                name = match.group(1)
                version_match = re.search(r'[=<>!]+\s*([0-9.]+)', line)
                version = version_match.group(1) if version_match else "0.0.0"
                deps.append(Dependency(
                    name=name,
                    version=version,
                    ecosystem="python"
                ))
        return deps

    def _parse_go_sum(self, path: Path) -> List[Dependency]:
        """Parse go.sum (Go)."""
        deps = []
        content = path.read_text()
        seen = set()
        for line in content.splitlines():
            parts = line.strip().split()
            if len(parts) >= 2:
                mod_name = parts[0]
                if mod_name not in seen:
                    seen.add(mod_name)
                    deps.append(Dependency(
                        name=mod_name,
                        version=parts[1],
                        ecosystem="go"
                    ))
        return deps
