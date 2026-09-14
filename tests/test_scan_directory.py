"""Tests for taintrace scan-directory subcommand."""

import pytest
from pathlib import Path
import tempfile
import os

from click.testing import CliRunner
from taintrace.cli import cli, _find_lockfiles, LOCKFILE_NAMES


class TestFindLockfiles:
    """Test recursive lockfile discovery."""

    def test_empty_directory(self):
        """Empty directory returns no lockfiles."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = _find_lockfiles(Path(tmpdir))
        assert result == []

    def test_single_cargo_lock(self):
        """Find a single Cargo.lock."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cargo = Path(tmpdir) / "Cargo.lock"
            cargo.write_text("")
            result = _find_lockfiles(Path(tmpdir))
        assert len(result) == 1
        assert result[0][1] == "rust"

    def test_nested_lockfiles(self):
        """Find lockfiles in nested directories."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "Cargo.lock").write_text("")
            (root / "subproject").mkdir()
            (root / "subproject" / "package-lock.json").write_text("")
            result = _find_lockfiles(root)
        assert len(result) == 2
        ecosystems = {eco for _, eco in result}
        assert ecosystems == {"rust", "node"}

    def test_skips_node_modules(self):
        """node_modules directory is skipped."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "package-lock.json").write_text("")
            (root / "node_modules").mkdir()
            (root / "node_modules" / "package-lock.json").write_text("")
            result = _find_lockfiles(root)
        assert len(result) == 1

    def test_skips_git(self):
        """.git directory is skipped."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "Cargo.lock").write_text("")
            (root / ".git").mkdir()
            (root / ".git" / "Cargo.lock").write_text("")
            result = _find_lockfiles(root)
        assert len(result) == 1

    def test_all_known_lockfiles(self):
        """All known lockfile names are detected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            for name in LOCKFILE_NAMES:
                (root / name).write_text("")
            result = _find_lockfiles(root)
        assert len(result) == len(LOCKFILE_NAMES)

    def test_discovers_swift_and_elixir_lockfiles(self):
        """SwiftPM and Mix lockfiles are discovered with their ecosystems."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "Package.resolved").write_text('{"pins": [], "version": 2}')
            (root / "mix.lock").write_text("%{}")
            result = _find_lockfiles(root)
        assert {(path.name, ecosystem) for path, ecosystem in result} == {
            ("Package.resolved", "swift"),
            ("mix.lock", "elixir"),
        }


class TestScanDirectoryCommand:
    """Test the scan-directory CLI subcommand."""

    def test_no_lockfiles(self):
        """scan-directory with no lockfiles prints message."""
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmpdir:
            result = runner.invoke(cli, ["scan-directory", tmpdir])
        assert "No lockfiles found" in result.output

    def test_with_cargo_lock(self):
        """scan-directory finds and scans Cargo.lock."""
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmpdir:
            cargo = Path(tmpdir) / "Cargo.lock"
            cargo.write_text('[[package]]\nname = "serde"\nversion = "1.0.0"\n')
            result = runner.invoke(cli, ["scan-directory", tmpdir])
        # Should run without error (serde is not a typosquat)
        assert result.exit_code == 0

    def test_json_output(self):
        """scan-directory --format json produces valid JSON."""
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmpdir:
            cargo = Path(tmpdir) / "Cargo.lock"
            cargo.write_text('[[package]]\nname = "serde"\nversion = "1.0.0"\n')
            result = runner.invoke(cli, ["scan-directory", tmpdir, "--format", "json"])
        import json
        data = json.loads(result.output)
        assert "tool" in data
        assert data["tool"] == "taintrace"

    def test_sarif_output(self):
        """scan-directory --format sarif produces valid SARIF."""
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmpdir:
            cargo = Path(tmpdir) / "Cargo.lock"
            cargo.write_text('[[package]]\nname = "serde"\nversion = "1.0.0"\n')
            result = runner.invoke(cli, ["scan-directory", tmpdir, "--format", "sarif"])
        import json
        data = json.loads(result.output)
        assert data["version"] == "2.1.0"
        assert "runs" in data

    def test_multiple_lockfiles_summary(self):
        """scan-directory with multiple lockfiles shows per-file summary."""
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "Cargo.lock").write_text('[[package]]\nname = "serde"\nversion = "1.0.0"\n')
            (root / "sub").mkdir()
            (root / "sub" / "package-lock.json").write_text('{"dependencies": {"lodash": {"version": "4.0.0"}}}\n')
            result = runner.invoke(cli, ["scan-directory", tmpdir])
        assert "Scanned 2 lockfiles" in result.output
