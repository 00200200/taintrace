"""Tests for PHP/Composer parser support in taintrace."""

import pytest
from pathlib import Path
from taintrace.lockfile import LockfileParser


class TestComposerJsonParser:
    """Parse composer.json for require/require-dev sections."""

    def test_parse_composer_json_basic(self, tmp_path):
        """Extracts packages from composer.json require section."""
        composer_json = tmp_path / "composer.json"
        composer_json.write_text("""{
  "require": {
    "guzzlehttp/guzzle": "^7.0",
    "symfony/console": "^6.0"
  },
  "require-dev": {
    "phpunit/phpunit": "^10.0"
  }
}""")
        parser = LockfileParser()
        deps = parser.parse(composer_json)
        names = [d.name for d in deps]
        assert "guzzlehttp/guzzle" in names
        assert "symfony/console" in names
        assert "phpunit/phpunit" in names
        assert all(d.ecosystem == "php" for d in deps)

    def test_skip_php_version_constraint(self, tmp_path):
        """Skips the php version constraint entry."""
        composer_json = tmp_path / "composer.json"
        composer_json.write_text("""{
  "require": {
    "php": "^8.1",
    "guzzlehttp/guzzle": "^7.0"
  }
}""")
        parser = LockfileParser()
        deps = parser.parse(composer_json)
        names = [d.name for d in deps]
        assert "php" not in names
        assert "guzzlehttp/guzzle" in names

    def test_parse_empty_composer_json(self, tmp_path):
        """Handles empty composer.json gracefully."""
        composer_json = tmp_path / "composer.json"
        composer_json.write_text("{}")
        parser = LockfileParser()
        deps = parser.parse(composer_json)
        assert len(deps) == 0

    def test_parse_invalid_json(self, tmp_path):
        """Handles invalid JSON gracefully."""
        composer_json = tmp_path / "composer.json"
        composer_json.write_text("{invalid json")
        parser = LockfileParser()
        deps = parser.parse(composer_json)
        assert len(deps) == 0


class TestComposerLockParser:
    """Parse composer.lock packages array."""

    def test_parse_composer_lock_basic(self, tmp_path):
        """Extracts packages from composer.lock packages array."""
        composer_lock = tmp_path / "composer.lock"
        composer_lock.write_text("""{
  "packages": [
    {
      "name": "guzzlehttp/guzzle",
      "version": "7.8.0"
    },
    {
      "name": "symfony/console",
      "version": "6.3.0"
    }
  ],
  "packages-dev": [
    {
      "name": "phpunit/phpunit",
      "version": "10.5.0"
    }
  ]
}""")
        parser = LockfileParser()
        deps = parser.parse(composer_lock)
        names = [d.name for d in deps]
        assert "guzzlehttp/guzzle" in names
        assert "symfony/console" in names
        assert "phpunit/phpunit" in names
        assert all(d.ecosystem == "php" for d in deps)

    def test_parse_empty_composer_lock(self, tmp_path):
        """Handles empty composer.lock gracefully."""
        composer_lock = tmp_path / "composer.lock"
        composer_lock.write_text('{"packages": [], "packages-dev": []}')
        parser = LockfileParser()
        deps = parser.parse(composer_lock)
        assert len(deps) == 0

    def test_parse_only_packages_dev(self, tmp_path):
        """Handles composer.lock with only packages-dev section."""
        composer_lock = tmp_path / "composer.lock"
        composer_lock.write_text("""{
  "packages-dev": [
    {
      "name": "phpunit/phpunit",
      "version": "10.5.0"
    }
  ]
}""")
        parser = LockfileParser()
        deps = parser.parse(composer_lock)
        assert len(deps) == 1
        assert deps[0].name == "phpunit/phpunit"
        assert deps[0].ecosystem == "php"
