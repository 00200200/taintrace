"""Tests for Gemfile.lock and Pipfile.lock parsers."""
import json
from pathlib import Path
from taintrace.lockfile import LockfileParser


def test_parse_gemfile_lock_basic(tmp_path):
    """Parse a basic Gemfile.lock."""
    gemfile = tmp_path / "Gemfile.lock"
    gemfile.write_text(
        "GEM\n"
        "  remote: https://rubygems.org/\n"
        "  specs:\n"
        "    rails (7.1.3)\n"
        "      actioncable (= 7.1.3)\n"
        "      actionmailbox (= 7.1.3)\n"
        "    nokogiri (1.16.5)\n"
        "      mini_portile2 (~> 2.8.2)\n"
        "\n"
        "PLATFORMS\n"
        "  ruby\n"
        "\n"
        "DEPENDENCIES\n"
        "  rails\n"
        "  nokogiri\n"
        "\n"
        "BUNDLED WITH\n"
        "   2.5.11\n"
    )
    parser = LockfileParser()
    deps = parser.parse(gemfile)
    names = {d.name for d in deps}
    assert "rails" in names
    assert "nokogiri" in names
    # Sub-deps should NOT be included (only top-level specs)
    assert "actioncable" not in names
    assert "actionmailbox" not in names
    for d in deps:
        assert d.ecosystem == "ruby"


def test_parse_gemfile_lock_empty(tmp_path):
    """Parse an empty/missing Gemfile.lock."""
    gemfile = tmp_path / "Gemfile.lock"
    gemfile.write_text("")
    parser = LockfileParser()
    deps = parser.parse(gemfile)
    assert deps == []


def test_parse_pipfile_lock_basic(tmp_path):
    """Parse a basic Pipfile.lock."""
    pipfile = tmp_path / "Pipfile.lock"
    data = {
        "default": {
            "requests": {
                "hashes": ["sha256:abc123"],
                "version": "==2.31.0",
            },
            "flask": {
                "hashes": ["sha256:def456"],
                "version": "==3.0.0",
            },
        },
        "develop": {
            "pytest": {
                "hashes": ["sha256:ghi789"],
                "version": "==7.4.0",
            },
        },
    }
    pipfile.write_text(json.dumps(data))
    parser = LockfileParser()
    deps = parser.parse(pipfile)
    names = {d.name: d for d in deps}
    assert "requests" in names
    assert names["requests"].version == "2.31.0"
    assert "flask" in names
    assert names["flask"].version == "3.0.0"
    assert "pytest" in names
    assert names["pytest"].version == "7.4.0"
    for d in deps:
        assert d.ecosystem == "python"


def test_parse_pipfile_lock_invalid_json(tmp_path):
    """Parse an invalid Pipfile.lock."""
    pipfile = tmp_path / "Pipfile.lock"
    pipfile.write_text("not valid json{{{")
    parser = LockfileParser()
    deps = parser.parse(pipfile)
    assert deps == []


def test_parse_pipfile_lock_missing(tmp_path):
    """Parse a missing Pipfile.lock (direct call)."""
    pipfile = tmp_path / "nonexistent.lock"
    parser = LockfileParser()
    # Direct call - parse() would default to cargo for unknown ext
    deps = parser._parse_pipfile_lock(pipfile)
    assert deps == []
