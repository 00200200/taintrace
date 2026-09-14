"""Tests for Elixir/Hex mix.lock dependency parsing."""

import json

from click.testing import CliRunner

from taintrace.cli import cli
from taintrace.lockfile import LockfileParser


def _write_mix_lock(tmp_path, body):
    path = tmp_path / "mix.lock"
    path.write_text("%{\n" + body + "\n}\n", encoding="utf-8")
    return path


def test_mix_lock_parses_multiple_hex_packages(tmp_path):
    path = _write_mix_lock(
        tmp_path,
        """
      "decimal": {:hex, :decimal, "2.1.1", "checksum", [:mix], [], "hexpm", "outer"},
      "jason": {:hex, :jason, "1.4.4", "checksum", [:mix], [], "hexpm", "outer"}
    """,
    )
    deps = LockfileParser().parse(path)
    assert [(dep.name, dep.version) for dep in deps] == [
        ("decimal", "2.1.1"),
        ("jason", "1.4.4"),
    ]


def test_mix_lock_marks_dependencies_as_elixir(tmp_path):
    path = _write_mix_lock(
        tmp_path,
        '"phoenix": {:hex, :phoenix, "1.7.21", "sum", [:mix], [], "hexpm", "sum"}',
    )
    assert LockfileParser().parse(path)[0].ecosystem == "elixir"


def test_mix_lock_preserves_prerelease_version(tmp_path):
    path = _write_mix_lock(
        tmp_path,
        '"phoenix": {:hex, :phoenix, "1.8.0-rc.3", "sum", [:mix], [], "hexpm", "sum"}',
    )
    assert LockfileParser().parse(path)[0].version == "1.8.0-rc.3"


def test_mix_lock_supports_hyphenated_package_name(tmp_path):
    path = _write_mix_lock(
        tmp_path,
        '"my-package": {:hex, :my_package, "1.2.3", "sum", [:mix], [], "hexpm", "sum"}',
    )
    assert LockfileParser().parse(path)[0].name == "my_package"


def test_mix_lock_supports_quoted_package_atom(tmp_path):
    path = _write_mix_lock(
        tmp_path,
        '\'my_package\': {:hex, :"my-package", "1.2.3", "sum", [:mix], [], "hexpm", "sum"}',
    )
    assert LockfileParser().parse(path)[0].name == "my-package"


def test_mix_lock_parses_multiline_hex_tuple(tmp_path):
    path = _write_mix_lock(
        tmp_path,
        """
      "plug": {
        :hex,
        :plug,
        "1.17.0",
        "checksum",
        [:mix],
        [],
        "hexpm",
        "outer"
      }
    """,
    )
    assert LockfileParser().parse(path)[0].name == "plug"


def test_mix_lock_ignores_git_dependency(tmp_path):
    path = _write_mix_lock(
        tmp_path,
        '"internal": {:git, "https://example.com/internal.git", "revision", []}',
    )
    assert LockfileParser().parse(path) == []


def test_mix_lock_ignores_path_dependency(tmp_path):
    path = _write_mix_lock(tmp_path, '"internal": {:path, "../internal", []}')
    assert LockfileParser().parse(path) == []


def test_mix_lock_empty_map_is_empty(tmp_path):
    assert LockfileParser().parse(_write_mix_lock(tmp_path, "")) == []


def test_mix_lock_malformed_hex_entry_is_ignored(tmp_path):
    path = _write_mix_lock(tmp_path, '"broken": {:hex, :broken}')
    assert LockfileParser().parse(path) == []


def test_mix_lock_uses_tuple_package_name(tmp_path):
    path = _write_mix_lock(
        tmp_path,
        '"renamed": {:hex, :canonical_name, "3.2.1", "sum", [:mix], [], "hexpm", "sum"}',
    )
    assert LockfileParser().parse(path)[0].name == "canonical_name"


def test_elixir_check_sarif_includes_suspect(tmp_path):
    path = _write_mix_lock(
        tmp_path,
        '"phoeniix": {:hex, :phoeniix, "1.0.0", "sum", [:mix], [], "hexpm", "sum"}',
    )
    result = CliRunner().invoke(
        cli, ["check", str(path), "--format", "sarif", "--threshold", "0.6"]
    )
    assert result.exit_code == 1
    sarif = json.loads(result.output)
    assert sarif["runs"][0]["results"][0]["ruleId"] == "TYPO001"


def test_elixir_check_json_includes_suspect(tmp_path):
    path = _write_mix_lock(
        tmp_path,
        '"phoeniix": {:hex, :phoeniix, "1.0.0", "sum", [:mix], [], "hexpm", "sum"}',
    )
    result = CliRunner().invoke(
        cli, ["check", str(path), "--format", "json", "--threshold", "0.6"]
    )
    assert result.exit_code == 1
    output = json.loads(result.output)
    assert output["summary"]["suspects"] == 1
    assert output["results"][0]["package"] == "phoeniix"
