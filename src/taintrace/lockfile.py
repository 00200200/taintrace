"""Lockfile parsers for multiple ecosystems."""

from __future__ import annotations

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


# Map of lowercase filenames to (parser_func, ecosystem)
EXTENDED_FORMATS = {
    "poetry.lock": ("python", "_parse_poetry"),
    "pnpm-lock.yaml": ("node", "_parse_pnpm"),
    "yarn.lock": ("node", "_parse_yarn"),
    "cargo.toml": ("rust", "_parse_cargo_toml"),
    "uv.lock": ("python", "_parse_uv_lock"),
}


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
        elif name in EXTENDED_FORMATS:
            _, method_name = EXTENDED_FORMATS[name]
            return getattr(self, method_name)(path)
        else:
            # Try as Cargo.lock by default
            return self._parse_cargo(path)

    def _parse_poetry(self, path: Path) -> List[Dependency]:
        """Parse Poetry lockfile (poetry.lock TOML format)."""
        deps = []
        content = path.read_text(encoding="utf-8", errors="replace")
        blocks = re.split(r"\[\[package\]\]", content)
        for block in blocks[1:]:
            name_match = re.search(r'name\s*=\s*"([^"]+)"', block)
            version_match = re.search(r'version\s*=\s*"([^"]+)"', block)
            if name_match and version_match:
                deps.append(Dependency(
                    name=name_match.group(1),
                    version=version_match.group(1),
                    ecosystem="python",
                ))
        return deps

    def _parse_pnpm(self, path: Path) -> List[Dependency]:
        """Parse pnpm lockfile (pnpm-lock.yaml) — handles v6/v9+ formats."""
        deps = []
        content = path.read_text(encoding="utf-8", errors="replace")

        # Modern pnpm (v9+) uses `packages:` with keys like "/package-name/1.0.0:"
        packages_match = re.search(
            r"^packages:\s*$(.+?)(?:\n^[a-z]|\Z)", content, re.MULTILINE | re.DOTALL
        )
        if packages_match:
            for line in packages_match.group(1).strip().splitlines():
                line = line.strip()
                if not line.startswith("/"):
                    continue
                pkg_key = line.rstrip(":")
                # "/name/version" or "/@scope/name/version"
                m = re.match(r"^/(?:@([^/]+)/)?(.+?)/([0-9][^/]+)$", pkg_key)
                if m:
                    scope, name, version = m.groups()
                    full_name = f"@{scope}/{name}" if scope else name
                    deps.append(Dependency(name=full_name, version=version, ecosystem="node"))
        else:
            # Older pnpm format: `dependencies:` section
            deps_match = re.search(
                r"^dependencies:\s*$(.+?)(?:\n^[a-z]|\Z)", content, re.MULTILINE | re.DOTALL
            )
            if deps_match:
                for line in deps_match.group(1).strip().splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    # Format: "package-name: version" or "@scope/package: version"
                    dep_match = re.match(r"^(.+?):\s+(.+)$", line)
                    if dep_match:
                        name = dep_match.group(1).strip()
                        version = dep_match.group(2).strip()
                        deps.append(Dependency(name=name, version=version, ecosystem="node"))
        return deps

    def _parse_yarn(self, path: Path) -> List[Dependency]:
        """Parse Yarn Classic lockfile (yarn.lock)."""
        deps = []
        content = path.read_text(encoding="utf-8", errors="replace")

        for block in re.split(r"\n\n+", content):
            if not block.strip():
                continue
            first_line = block.splitlines()[0].strip()
            if first_line.startswith("#"):
                continue

            spec_match = re.match(r'^"?([^"]+)"?\s*$', first_line)
            if not spec_match:
                continue

            spec = spec_match.group(1)
            name_ver = re.match(r"^(@?[^@]+)@(.+)$", spec)
            if not name_ver:
                continue

            name, version_spec = name_ver.group(1), name_ver.group(2)
            if "workspace:" in version_spec:
                continue

            version_match = re.search(r'^\s+version\s+"([^"]+)"', block, re.MULTILINE)
            resolved = version_match.group(1) if version_match else version_spec

            deps.append(Dependency(name=name, version=resolved, ecosystem="node"))
        return deps

    def _parse_cargo_toml(self, path: Path) -> List[Dependency]:
        """Parse Cargo.toml for dependency names (in addition to Cargo.lock)."""
        deps = []
        content = path.read_text(encoding="utf-8", errors="replace")

        sections = re.split(r"^\[(?:dev-|build-)?dependencies\]\s*$", content, flags=re.MULTILINE)
        for section in sections[1:]:
            for line in section.strip().splitlines():
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("["):
                    break
                name_match = re.match(r'^([a-zA-Z0-9_-]+)\s*=\s*', line)
                if name_match:
                    name = name_match.group(1)
                    ver_match = re.search(r'version\s*=\s*"([^"]+)"', line)
                    version = ver_match.group(1) if ver_match else "0.0.0"
                    deps.append(Dependency(name=name, version=version, ecosystem="rust"))
        return deps

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

    def _parse_uv_lock(self, path: Path) -> List[Dependency]:
        """Parse uv.lock (Astral uv package manager for Python).
        
        Format is TOML with [[package]] sections containing name and version.
        """
        deps = []
        content = path.read_text(encoding="utf-8", errors="replace")
        blocks = re.split(r'\[\[package\]\]', content)
        for block in blocks[1:]:
            name_match = re.search(r'name\s*=\s*"([^"]+)"', block)
            version_match = re.search(r'version\s*=\s*"([^"]+)"', block)
            if name_match and version_match:
                deps.append(Dependency(
                    name=name_match.group(1),
                    version=version_match.group(1),
                    ecosystem="python"
                ))
        return deps
