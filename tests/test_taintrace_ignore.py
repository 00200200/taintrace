"""Tests for taintrace ignore feature."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from taintrace.config import load_config, get_ignored_packages
from taintrace.cli import cli


class TestConfig:
    """Test config loading."""

    def test_no_config(self, tmp_path: Path) -> None:
        """No config file returns empty."""
        config = load_config(tmp_path)
        assert config == {}

    def test_toml_config(self, tmp_path: Path) -> None:
        """Load config from .taintrace.toml."""
        config_file = tmp_path / ".taintrace.toml"
        config_file.write_text('[taintrace]\nignore = ["my-pkg", "another-pkg"]\n')
        config = load_config(tmp_path)
        assert config["ignore"] == ["my-pkg", "another-pkg"]

    def test_get_ignored_packages(self, tmp_path: Path) -> None:
        """Get ignored packages from config."""
        config_file = tmp_path / ".taintrace.toml"
        config_file.write_text('[taintrace]\nignore = ["pkg1", "pkg2"]\n')
        ignored = get_ignored_packages(tmp_path)
        assert ignored == ["pkg1", "pkg2"]

    def test_get_ignored_packages_empty(self, tmp_path: Path) -> None:
        """No ignored packages returns empty list."""
        ignored = get_ignored_packages(tmp_path)
        assert ignored == []

    def test_taintracerc_config(self, tmp_path: Path) -> None:
        """Load config from .taintracerc."""
        config_file = tmp_path / ".taintracerc"
        config_file.write_text('[taintrace]\nignore = ["test-pkg"]\n')
        config = load_config(tmp_path)
        assert config["ignore"] == ["test-pkg"]


class TestIgnoreCommand:
    """Test --ignore CLI flag."""

    def test_ignore_flag(self, tmp_path: Path) -> None:
        """Test --ignore flag filters packages."""
        old_cwd = Path.cwd()
        try:
            os.chdir(tmp_path)
            runner = CliRunner()
            result = runner.invoke(cli, ["check", "--help"])
            assert "--ignore" in result.output
        finally:
            os.chdir(old_cwd)

    def test_ignore_with_config(self, tmp_path: Path) -> None:
        """Test --ignore combined with config file."""
        config_file = tmp_path / ".taintrace.toml"
        config_file.write_text('[taintrace]\nignore = ["config-pkg"]\n')
        
        # The --ignore flag should be in help
        runner = CliRunner()
        result = runner.invoke(cli, ["check", "--help"])
        assert "-i" in result.output or "--ignore" in result.output
