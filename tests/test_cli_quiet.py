"""Tests for quiet CLI output."""

import json

from click.testing import CliRunner

from taintrace.cli import cli


def _cargo_lock(tmp_path, package_name: str) -> str:
    path = tmp_path / "Cargo.lock"
    path.write_text(f'[[package]]\nname = "{package_name}"\nversion = "1.0.0"\n')
    return str(path)


def test_check_quiet_prints_only_suspects(tmp_path):
    result = CliRunner().invoke(
        cli, ["check", _cargo_lock(tmp_path, "proc-macro1"), "--quiet"]
    )

    assert result.exit_code == 1
    assert "Scan Results" not in result.output
    output = json.loads(result.output)
    assert output["package"] == "proc-macro1"
    assert output["risk"] in {"HIGH", "CRITICAL"}


def test_check_quiet_is_silent_when_clean(tmp_path):
    result = CliRunner().invoke(cli, ["check", _cargo_lock(tmp_path, "serde"), "-q"])

    assert result.exit_code == 0
    assert result.output == ""


def test_scan_directory_quiet_json_has_no_panel(tmp_path):
    _cargo_lock(tmp_path, "serde")
    result = CliRunner().invoke(
        cli, ["scan-directory", str(tmp_path), "--quiet", "--format", "json"]
    )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["tool"] == "taintrace"
    assert "Scan Results" not in result.output


def test_scan_directory_quiet_suppresses_per_file_summary(tmp_path):
    _cargo_lock(tmp_path, "serde")
    nested = tmp_path / "nested"
    nested.mkdir()
    _cargo_lock(nested, "proc-macro1")

    result = CliRunner().invoke(cli, ["scan-directory", str(tmp_path), "-q"])

    assert result.exit_code == 1
    assert "Scanned" not in result.output
    records = [json.loads(line) for line in result.output.splitlines() if line]
    assert records
    assert records[0]["package"] == "proc-macro1"


def test_scan_directory_quiet_is_silent_without_lockfiles(tmp_path):
    result = CliRunner().invoke(cli, ["scan-directory", str(tmp_path), "--quiet"])

    assert result.exit_code == 0
    assert result.output == ""
