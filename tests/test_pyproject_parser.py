"""Tests for pyproject.toml parser (PEP 621 typosquat detection)."""

import tempfile
from pathlib import Path

from taintrace.lockfile import LockfileParser, Dependency


def _write_pyproject(content: str) -> Path:
    tmpdir = tempfile.mkdtemp()
    path = Path(tmpdir) / "pyproject.toml"
    path.write_text(content)
    return path


def test_pyproject_pep621_basic():
    """Parse basic PEP 621 dependencies."""
    content = """\
[project]
name = "my-project"
version = "0.1.0"
dependencies = [
    "requests>=2.28.0",
    "numpy>=1.24.0",
    "click",
]
"""
    path = _write_pyproject(content)
    parser = LockfileParser()
    deps = parser.parse(path)
    names = {d.name for d in deps}
    assert "requests" in names
    assert "numpy" in names
    assert "click" in names
    for d in deps:
        assert d.ecosystem == "python"


def test_pyproject_poetry_style():
    """Parse Poetry-style [tool.poetry.dependencies]."""
    content = """\
[tool.poetry]
name = "my-project"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.10"
requests = ">=2.28"
flask = "^2.0"
"""
    path = _write_pyproject(content)
    parser = LockfileParser()
    deps = parser.parse(path)
    names = {d.name for d in deps}
    # python should be skipped (it's the version constraint)
    assert "python" not in names
    assert "requests" in names
    assert "flask" in names


def test_pyproject_typosquat_example():
    """Real-world typosquat: 'requsts' instead of 'requests'."""
    content = """\
[project]
dependencies = [
    "requsts>=2.28.0",
    "numpy>=1.24.0",
]
"""
    path = _write_pyproject(content)
    parser = LockfileParser()
    deps = parser.parse(path)
    names = [d.name for d in deps]
    assert "requsts" in names  # the typosquat name is extracted as-is
    assert "numpy" in names


def test_pyproject_no_deps_section():
    """Handle pyproject.toml without dependencies gracefully."""
    content = """\
[project]
name = "my-project"
version = "0.1.0"

[tool.black]
line-length = 88
"""
    path = _write_pyproject(content)
    parser = LockfileParser()
    deps = parser.parse(path)
    assert deps == []


def test_pyproject_empty():
    """Handle empty pyproject.toml."""
    path = _write_pyproject("")
    parser = LockfileParser()
    deps = parser.parse(path)
    assert deps == []


def test_pyproject_mixed_styles():
    """Both PEP 621 and Poetry sections present (unusual but valid)."""
    content = """\
[project]
dependencies = ["requests>=2.28"]

[tool.poetry.dependencies]
flask = "^2.0"
"""
    path = _write_pyproject(content)
    parser = LockfileParser()
    deps = parser.parse(path)
    names = {d.name for d in deps}
    assert "requests" in names
    assert "flask" in names


def test_pyproject_auto_dispatch():
    """Auto-detection: pyproject.toml dispatches to _parse_pyproject_toml."""
    content = """\
[project]
dependencies = ["requests>=2.28"]
"""
    path = _write_pyproject(content)
    parser = LockfileParser()
    deps = parser.parse(path)
    assert len(deps) == 1
    assert deps[0].name == "requests"
    assert deps[0].ecosystem == "python"
