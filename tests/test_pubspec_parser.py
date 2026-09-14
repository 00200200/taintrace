"""Tests for Dart/Flutter pubspec.yaml dependency parsing."""

import json
from pathlib import Path

from click.testing import CliRunner

from taintrace.cli import _detect_ecosystem, _find_lockfiles, cli
from taintrace.lockfile import LockfileParser


def _write_pubspec(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "pubspec.yaml"
    path.write_text(content, encoding="utf-8")
    return path


def test_parse_pubspec_dependencies_skips_sdk_packages(tmp_path: Path) -> None:
    path = _write_pubspec(
        tmp_path,
        """name: sample_app
environment:
  sdk: ^3.5.0
dependencies:
  flutter:
    sdk: flutter
  http: ^1.1.0
  provider: ^6.1.2
""",
    )

    deps = LockfileParser().parse(path)

    assert [(dep.name, dep.version) for dep in deps] == [
        ("http", "^1.1.0"),
        ("provider", "^6.1.2"),
    ]
    assert all(dep.ecosystem == "dart" for dep in deps)


def test_parse_pubspec_dev_dependencies(tmp_path: Path) -> None:
    path = _write_pubspec(
        tmp_path,
        """name: sample_app
dev_dependencies:
  flutter_test:
    sdk: flutter
  test: ^1.25.0
  mockito: ^5.4.4
""",
    )

    names = [dep.name for dep in LockfileParser().parse(path)]

    assert names == ["test", "mockito"]


def test_parse_pubspec_dependency_overrides(tmp_path: Path) -> None:
    path = _write_pubspec(
        tmp_path,
        """name: sample_app
dependencies:
  http: ^1.1.0
dependency_overrides:
  provider: ^6.1.2
""",
    )

    names = [dep.name for dep in LockfileParser().parse(path)]

    assert names == ["http", "provider"]


def test_pubspec_is_auto_detected_and_discovered(tmp_path: Path) -> None:
    path = _write_pubspec(
        tmp_path,
        """name: sample_app
dependencies:
  http: ^1.1.0
""",
    )

    assert _detect_ecosystem(path) == "dart"
    assert _find_lockfiles(tmp_path) == [(path, "dart")]

    result = CliRunner().invoke(cli, ["check", str(path), "--format", "json"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["results"][0]["package"] == "http"
    assert payload["results"][0]["risk_level"] == "LOW"
