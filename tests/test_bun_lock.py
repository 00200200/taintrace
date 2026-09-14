"""Tests for Bun lockfile parser."""

from __future__ import annotations

import json
import warnings
from pathlib import Path

import pytest

from taintrace.lockfile import LockfileParser, Dependency


class TestBunLockParser:
    """Test Bun lockfile parsing."""

    def test_parse_bun_lock_basic(self, tmp_path: Path) -> None:
        """Parse a basic bun.lock file."""
        bun_lock = tmp_path / "bun.lock"
        bun_lock.write_text(json.dumps({
            "packages": {
                "react": "18.2.0",
                "lodash": "4.17.21",
                "@types/react": "18.2.0"
            }
        }))
        parser = LockfileParser()
        deps = parser.parse(bun_lock)
        names = [d.name for d in deps]
        assert "react" in names
        assert "lodash" in names
        assert "@types/react" in names
        assert len(deps) == 3
        for d in deps:
            assert d.ecosystem == "node"

    def test_parse_bun_lock_empty(self, tmp_path: Path) -> None:
        """Parse an empty bun.lock file."""
        bun_lock = tmp_path / "bun.lock"
        bun_lock.write_text(json.dumps({"packages": {}}))
        parser = LockfileParser()
        deps = parser.parse(bun_lock)
        assert len(deps) == 0

    def test_parse_bun_lock_with_suspect(self, tmp_path: Path) -> None:
        """Parse bun.lock with a typosquat suspect."""
        bun_lock = tmp_path / "bun.lock"
        bun_lock.write_text(json.dumps({
            "packages": {
                "react": "18.2.0",
                "lodahs": "4.17.21",  # typosquat
            }
        }))
        parser = LockfileParser()
        deps = parser.parse(bun_lock)
        names = [d.name for d in deps]
        assert "react" in names
        assert "lodahs" in names

    def test_parse_bun_lock_invalid_json(self, tmp_path: Path) -> None:
        """Handle invalid JSON gracefully."""
        bun_lock = tmp_path / "bun.lock"
        bun_lock.write_text("not valid json {{{")
        parser = LockfileParser()
        deps = parser.parse(bun_lock)
        assert len(deps) == 0

    def test_parse_bun_lock_missing_packages_key(self, tmp_path: Path) -> None:
        """Handle bun.lock without packages key."""
        bun_lock = tmp_path / "bun.lock"
        bun_lock.write_text(json.dumps({"lockfileVersion": 1}))
        parser = LockfileParser()
        deps = parser.parse(bun_lock)
        assert len(deps) == 0

    def test_parse_bun_lockb_binary(self, tmp_path: Path) -> None:
        """bun.lockb binary format returns empty with warning."""
        bun_lockb = tmp_path / "bun.lockb"
        bun_lockb.write_bytes(b"\x00\x01\x02\x03binary")
        parser = LockfileParser()
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            deps = parser.parse(bun_lockb)
            assert len(deps) == 0
            assert len(w) == 1
            assert "binary format" in str(w[0].message).lower()
