"""Tests for Swift Package Manager dependency parsing."""

import json

from click.testing import CliRunner

from taintrace.cli import cli
from taintrace.lockfile import LockfileParser


def _write_resolved(tmp_path, pins, version=2):
    path = tmp_path / "Package.resolved"
    path.write_text(json.dumps({"pins": pins, "version": version}), encoding="utf-8")
    return path


def test_package_resolved_parses_multiple_pins(tmp_path):
    path = _write_resolved(
        tmp_path,
        [
            {
                "identity": "alamofire",
                "location": "https://github.com/Alamofire/Alamofire.git",
                "state": {"version": "5.10.2", "revision": "abc"},
            },
            {
                "identity": "swift-log",
                "location": "https://github.com/apple/swift-log.git",
                "state": {"version": "1.6.4", "revision": "def"},
            },
        ],
    )
    deps = LockfileParser().parse(path)
    assert [(dep.name, dep.version) for dep in deps] == [
        ("github.com/Alamofire/Alamofire", "5.10.2"),
        ("github.com/apple/swift-log", "1.6.4"),
    ]


def test_package_resolved_marks_dependencies_as_swift(tmp_path):
    path = _write_resolved(
        tmp_path,
        [
            {
                "identity": "swift-nio",
                "location": "https://github.com/apple/swift-nio.git",
                "state": {"version": "2.80.0"},
            },
        ],
    )
    assert LockfileParser().parse(path)[0].ecosystem == "swift"


def test_package_resolved_uses_revision_without_version(tmp_path):
    path = _write_resolved(
        tmp_path,
        [
            {
                "identity": "package",
                "location": "https://github.com/example/package.git",
                "state": {"revision": "0123456789abcdef"},
            },
        ],
    )
    assert LockfileParser().parse(path)[0].version == "0123456789abcdef"


def test_package_resolved_uses_branch_without_version_or_revision(tmp_path):
    path = _write_resolved(
        tmp_path,
        [
            {
                "identity": "package",
                "location": "https://github.com/example/package.git",
                "state": {"branch": "main"},
            },
        ],
    )
    assert LockfileParser().parse(path)[0].version == "main"


def test_package_resolved_supports_legacy_v1_shape(tmp_path):
    path = tmp_path / "Package.resolved"
    path.write_text(
        json.dumps(
            {
                "object": {
                    "pins": [
                        {
                            "package": "Alamofire",
                            "repositoryURL": "https://github.com/Alamofire/Alamofire.git",
                            "state": {"version": "5.4.0"},
                        }
                    ]
                },
                "version": 1,
            }
        ),
        encoding="utf-8",
    )
    dep = LockfileParser().parse(path)[0]
    assert (dep.name, dep.version) == ("github.com/Alamofire/Alamofire", "5.4.0")


def test_package_resolved_normalizes_ssh_github_location(tmp_path):
    path = _write_resolved(
        tmp_path,
        [
            {
                "identity": "swift-log",
                "location": "git@github.com:apple/swift-log.git",
                "state": {"version": "1.6.4"},
            },
        ],
    )
    assert LockfileParser().parse(path)[0].name == "github.com/apple/swift-log"


def test_package_resolved_falls_back_to_identity_for_non_github_location(tmp_path):
    path = _write_resolved(
        tmp_path,
        [
            {
                "identity": "internal-tools",
                "location": "https://git.example.com/tools/internal.git",
                "state": {"revision": "abc"},
            },
        ],
    )
    assert LockfileParser().parse(path)[0].name == "internal-tools"


def test_package_resolved_ignores_invalid_pins(tmp_path):
    path = _write_resolved(tmp_path, [None, "bad", {"state": {"version": "1.0.0"}}])
    assert LockfileParser().parse(path) == []


def test_package_resolved_invalid_json_is_empty(tmp_path):
    path = tmp_path / "Package.resolved"
    path.write_text("{not json", encoding="utf-8")
    assert LockfileParser().parse(path) == []


def test_package_resolved_empty_pins_is_empty(tmp_path):
    assert LockfileParser().parse(_write_resolved(tmp_path, [])) == []


def test_package_swift_parses_versioned_remote_dependencies(tmp_path):
    path = tmp_path / "Package.swift"
    path.write_text(
        """
        dependencies: [
            .package(url: "https://github.com/Alamofire/Alamofire.git", from: "5.10.0"),
            .package(url: "https://github.com/apple/swift-log.git", exact: "1.6.4"),
        ]
    """,
        encoding="utf-8",
    )
    deps = LockfileParser().parse(path)
    assert [(dep.name, dep.version) for dep in deps] == [
        ("github.com/Alamofire/Alamofire", "5.10.0"),
        ("github.com/apple/swift-log", "1.6.4"),
    ]


def test_package_swift_ignores_local_path_dependencies(tmp_path):
    path = tmp_path / "Package.swift"
    path.write_text('.package(path: "../LocalPackage")', encoding="utf-8")
    assert LockfileParser().parse(path) == []


def test_swift_check_json_includes_dependency(tmp_path):
    path = _write_resolved(
        tmp_path,
        [
            {
                "identity": "swift-log",
                "location": "https://github.com/apple/swift-log.git",
                "state": {"version": "1.6.4"},
            },
        ],
    )
    result = CliRunner().invoke(cli, ["check", str(path), "--format", "json"])
    assert result.exit_code == 0
    assert (
        json.loads(result.output)["results"][0]["package"]
        == "github.com/apple/swift-log"
    )


def test_swift_check_sarif_includes_suspect(tmp_path):
    path = _write_resolved(
        tmp_path,
        [
            {
                "identity": "swift-logg",
                "location": "https://github.com/apple/swift-logg.git",
                "state": {"version": "1.0.0"},
            }
        ],
    )
    result = CliRunner().invoke(
        cli, ["check", str(path), "--format", "sarif", "--threshold", "0.6"]
    )
    assert result.exit_code == 1
    sarif = json.loads(result.output)
    assert sarif["runs"][0]["results"][0]["ruleId"] == "TYPO001"
