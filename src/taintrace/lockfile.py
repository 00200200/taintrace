"""Lockfile parsers for multiple ecosystems."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional
import json
import re


@dataclass
class Dependency:
    """A parsed dependency from any lockfile."""
    name: str
    version: str
    ecosystem: str  # Registry used for known-package comparisons


# Map of lowercase filenames to (parser_func, ecosystem)
EXTENDED_FORMATS = {
    "poetry.lock": ("python", "_parse_poetry"),
    "pnpm-lock.yaml": ("node", "_parse_pnpm"),
    "yarn.lock": ("node", "_parse_yarn"),
    "cargo.toml": ("rust", "_parse_cargo_toml"),
    "uv.lock": ("python", "_parse_uv_lock"),
    "pyproject.toml": ("python", "_parse_pyproject_toml"),
    "gemfile.lock": ("ruby", "_parse_gemfile_lock"),
    "pipfile.lock": ("python", "_parse_pipfile_lock"),
    "bun.lock": ("node", "_parse_bun_lock"),
    "bun.lockb": ("node", "_parse_bun_lockb"),
    "composer.json": ("php", "_parse_composer_json"),
    "composer.lock": ("php", "_parse_composer_lock"),
    "package.resolved": ("swift", "_parse_package_resolved"),
    "package.swift": ("swift", "_parse_package_swift"),
    "mix.lock": ("elixir", "_parse_mix_lock"),
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

    def _parse_pyproject_toml(self, path: Path) -> List[Dependency]:
        """Parse pyproject.toml (PEP 621) for dependency names.
        
        Extracts packages from:
        - [project].dependencies (PEP 621 standard)
        - [tool.poetry.dependencies] (Poetry format)
        
        Version specifiers (>=, <=, ==, ~=, etc.) are stripped to return
        only the package name for typosquat comparison.
        """
        deps = []
        content = path.read_text(encoding="utf-8", errors="replace")
        
        # Extract [project].dependencies section
        # Look for [project] followed by dependencies = [ ... ]
        project_deps_match = re.search(
            r'^\s*\[project\][^\[]*?dependencies\s*=\s*\[(.*?)\]',
            content, re.MULTILINE | re.DOTALL
        )
        if project_deps_match:
            deps_text = project_deps_match.group(1)
            for line in deps_text.splitlines():
                line = line.strip().strip(',').strip('"').strip("'")
                if not line or line.startswith('#'):
                    continue
                # Extract package name (before version specifier)
                # Handles: "package>=1.0", "package == 1.0.*", "package"
                name_match = re.match(r'^([a-zA-Z0-9_.-]+)', line)
                if name_match:
                    name = name_match.group(1)
                    deps.append(Dependency(name=name, version="", ecosystem="python"))
        
        # Extract [tool.poetry.dependencies] section
        poetry_match = re.search(
            r'\[tool\.poetry\.dependencies\](.*?)(?:^\[|\Z)',
            content, re.MULTILINE | re.DOTALL
        )
        if poetry_match:
            for line in poetry_match.group(1).strip().splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                # Format: name = "version" or name = {version = "..."}
                dep_match = re.match(r'^([a-zA-Z0-9_.-]+)\s*=\s*', line)
                if dep_match:
                    name = dep_match.group(1)
                    # Skip python version constraint
                    if name == 'python':
                        continue
                    deps.append(Dependency(name=name, version="", ecosystem="python"))
        
        return deps

    def _parse_gemfile_lock(self, path: Path) -> List[Dependency]:
        """Parse Bundler Gemfile.lock (Ruby).

        Format:
            GEM
              remote: https://rubygems.org/
              specs:
                rails (7.1.3)
                  actioncable (= 7.1.3)
                nokogiri (1.16.5)

            PLATFORMS
              ruby

            BUNDLED WITH
               2.5.11

        Only top-level specs (4-space indent) are included, not sub-dependencies.
        """
        deps = []
        content = path.read_text(encoding="utf-8", errors="replace")
        in_specs = False
        for line in content.splitlines():
            stripped = line.strip()
            if stripped == "specs:":
                in_specs = True
                continue
            if stripped in ("PLATFORMS", "DEPENDENCIES", "BUNDLED WITH", "GEM", "GIT"):
                in_specs = False
                continue
            if in_specs and stripped:
                # Top-level specs have 4-space indent, sub-deps have 6+
                indent = len(line) - len(line.lstrip())
                if indent == 4 and "(" in stripped:
                    match = re.match(r'^([a-zA-Z0-9_.-]+)\s+\(([^)]+)\)', stripped)
                    if match:
                        deps.append(Dependency(
                            name=match.group(1),
                            version=match.group(2),
                            ecosystem="ruby",
                        ))
        return deps

    def _parse_pipfile_lock(self, path: Path) -> List[Dependency]:
        """Parse Pipenv Pipfile.lock (JSON).

        Format:
            {
              "default": {
                "requests": {
                  "hashes": ["sha256:..."],
                  "version": "==2.31.0"
                }
              },
              "develop": { ... }
            }
        """
        deps = []
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (json.JSONDecodeError, FileNotFoundError):
            return deps
        for section in ("default", "develop"):
            if not isinstance(data.get(section), dict):
                continue
            for pkg_name, pkg_info in data[section].items():
                if not isinstance(pkg_info, dict):
                    continue
                version = pkg_info.get("version", "")
                # Strip leading == from version
                if version.startswith("=="):
                    version = version[2:]
                deps.append(Dependency(
                    name=pkg_name,
                    version=version,
                    ecosystem="python",
                ))
        return deps

    def _parse_bun_lock(self, path: Path) -> List[Dependency]:
        """Parse Bun text lockfile (bun.lock).

        Bun's text format (v1.0+) is JSON-like with a "packages" dict:
        {
          "packages": {
            "react": "18.2.0",
            "lodash": "4.17.21",
            "@types/react": "18.2.0"
          }
        }
        """
        deps = []
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (json.JSONDecodeError, FileNotFoundError):
            return deps
        packages = data.get("packages", {})
        if isinstance(packages, dict):
            for name, version in packages.items():
                if isinstance(version, str):
                    deps.append(Dependency(name=name, version=version, ecosystem="node"))
        return deps

    def _parse_bun_lockb(self, path: Path) -> List[Dependency]:
        """Parse Bun binary lockfile (bun.lockb).

        Binary format — cannot parse without Bun runtime.
        Return empty list with a warning.
        """
        import warnings
        warnings.warn(
            "bun.lockb is a binary format and cannot be parsed without Bun runtime. "
            "Use 'bun bun.lock' to convert to text format first.",
            UserWarning,
            stacklevel=2,
        )
        return []

    def _parse_composer_json(self, path: Path) -> List[Dependency]:
        """Parse composer.json require/require-dev sections.

        Format:
            {
              "require": {
                "guzzlehttp/guzzle": "^7.0",
                "symfony/console": "^6.0"
              },
              "require-dev": {
                "phpunit/phpunit": "^10.0"
              }
            }
        """
        deps = []
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (json.JSONDecodeError, FileNotFoundError):
            return deps
        for section in ("require", "require-dev"):
            if not isinstance(data.get(section), dict):
                continue
            for pkg_name, version_spec in data[section].items():
                # Skip the php version constraint
                if pkg_name == "php":
                    continue
                # Extract base version from constraint (e.g., "^7.0" -> "7.0")
                version = re.sub(r'^[~^>=<\s]+', '', str(version_spec)).strip()
                if not version:
                    version = "0.0.0"
                deps.append(Dependency(
                    name=pkg_name,
                    version=version,
                    ecosystem="php",
                ))
        return deps

    def _parse_composer_lock(self, path: Path) -> List[Dependency]:
        """Parse composer.lock packages array.

        Format:
            {
              "packages": [
                {
                  "name": "guzzlehttp/guzzle",
                  "version": "7.8.0",
                  ...
                },
                ...
              ],
              "packages-dev": [...]
            }
        """
        deps = []
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (json.JSONDecodeError, FileNotFoundError):
            return deps
        for section in ("packages", "packages-dev"):
            for pkg in data.get(section, []):
                if not isinstance(pkg, dict):
                    continue
                name = pkg.get("name", "")
                version = pkg.get("version", "0.0.0")
                if name:
                    deps.append(Dependency(name=name, version=version, ecosystem="php"))
        return deps

    def _parse_package_resolved(self, path: Path) -> List[Dependency]:
        """Parse Swift Package Manager's Package.resolved JSON format.

        SwiftPM v2 and v3 put ``pins`` at the document root, while v1 stores
        the same array under ``object``. GitHub dependencies use a stable
        ``github.com/owner/repository`` name so similarly named repositories
        remain distinguishable.
        """
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (json.JSONDecodeError, FileNotFoundError):
            return []

        pins = data.get("pins")
        if not isinstance(pins, list):
            legacy = data.get("object", {})
            pins = legacy.get("pins", []) if isinstance(legacy, dict) else []

        deps = []
        for pin in pins:
            if not isinstance(pin, dict):
                continue
            state = pin.get("state", {})
            if not isinstance(state, dict):
                state = {}
            location = pin.get("location") or pin.get("repositoryURL") or ""
            name = self._swift_package_name(
                str(location), str(pin.get("identity") or pin.get("package") or "")
            )
            if not name:
                continue
            version = state.get("version") or state.get("revision") or state.get("branch") or ""
            deps.append(Dependency(name=name, version=str(version), ecosystem="swift"))
        return deps

    def _parse_package_swift(self, path: Path) -> List[Dependency]:
        """Parse remote ``.package`` declarations from Package.swift."""
        content = path.read_text(encoding="utf-8", errors="replace")
        deps = []
        declarations = re.findall(r"\.package\s*\((.*?)\)", content, re.DOTALL)
        for declaration in declarations:
            location_match = re.search(
                r'(?:url|location)\s*:\s*"([^"]+)"', declaration
            )
            if not location_match:
                continue
            location = location_match.group(1)
            name = self._swift_package_name(location, "")
            if not name:
                continue
            version_match = re.search(
                r'(?:from|exact|branch|revision)\s*:\s*"([^"]+)"', declaration
            )
            version = version_match.group(1) if version_match else ""
            deps.append(Dependency(name=name, version=version, ecosystem="swift"))
        return deps

    @staticmethod
    def _swift_package_name(location: str, fallback: str) -> str:
        """Return a canonical name for a Swift package location."""
        github_match = re.search(
            r"github\.com[/:]([^/]+)/([^/#]+)", location, flags=re.IGNORECASE
        )
        if github_match:
            owner, repository = github_match.groups()
            return f"github.com/{owner}/{repository.removesuffix('.git')}"
        return fallback

    def _parse_mix_lock(self, path: Path) -> List[Dependency]:
        """Parse Hex package entries from an Elixir ``mix.lock`` file.

        ``mix.lock`` is an Elixir term rather than JSON. Each Hex entry starts
        with a package map key followed by ``{:hex, :package, "version", ...}``.
        Git and path entries are intentionally ignored because they are not
        packages published in the Hex registry.
        """
        content = path.read_text(encoding="utf-8", errors="replace")
        pattern = re.compile(
            r'["\']([a-zA-Z0-9_.-]+)["\']\s*:\s*'
            r'\{\s*:hex\s*,\s*:(?:"([^"\\]+)"|([a-zA-Z0-9_.-]+))\s*,\s*'
            r'"([^"\\]+)"',
            re.DOTALL,
        )
        deps = []
        for match in pattern.finditer(content):
            lock_name, quoted_package, atom_package, version = match.groups()
            package_name = quoted_package or atom_package or lock_name
            deps.append(Dependency(name=package_name, version=version, ecosystem="elixir"))
        return deps
