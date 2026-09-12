# Changelog

All notable changes to taintrace will be documented in this file.

## [0.2.0] - 2026-09-11

### Added
- Initial release: typosquat detector for AI coding agent dependencies
- Multi-ecosystem lockfile parsing (Cargo.lock, package-lock.json, requirements.txt, go.sum, pnpm-lock.yaml, yarn.lock, poetry.lock)
- Fuzzy matching (Levenshtein + Soundex + substring) with risk scoring
- CLI, JSON, and SARIF output formats
- GitHub Actions composite action + Code Scanning integration
- Pre-commit hook support

### Added (2026-09-12)
- Integrated into driftcheck v0.1.44 as typosquat drift detector
