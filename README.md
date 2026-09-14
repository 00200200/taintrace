# taintrace

**Typosquat detector for AI coding agent dependencies.**

`taintrace` scans your lockfiles (Cargo.lock, package-lock.json, requirements.txt, go.sum) for package names that suspiciously resemble known legitimate packages — the exact vector used in the [arrayref@0.3.10 attack](https://github.com/rustsec/advisory-db/pull/2045) (August 2026), where `proc-macro1` imitated `proc-macro2` to execute arbitrary code during `cargo build`.

## The Problem

AI coding agents install dependencies automatically. Typosquats pass undetected by scanners like `cargo audit` or `npm audit` because they have **no known CVE** — they're brand new packages with malicious build.rs or proc-macros.

Traditional scanners check *known-bad*. `taintrace` checks *suspicious-similar*.

## Install

```bash
pip install taintrace
```

## Usage

### Scan lockfiles

```bash
taintrace check Cargo.lock
```

Multiple lockfiles at once:

```bash
taintrace check Cargo.lock package-lock.json requirements.txt
```

Scan PHP/Composer lockfiles:

```bash
taintrace check composer.lock
```

### Scan a lockfile

```bash
taintrace check Cargo.lock
```

```
╭──────────────────────────────────────────────╮
│ taintrace v0.2.1 — scanning Cargo.lock       │
│ Total deps: 42 | Suspects: 1                 │
╰──────────────────────────────────────────────╯

🚨 Typosquat Suspects
┏━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Package     ┃ Risk     ┃ Score ┃ Similar To     ┃ Reason                  ┃
┣━━━━━━━━━━━━━╋━━━━━━━━━━╋━━━━━━━╋━━━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ proc-macro1 ┃ CRITICAL ┃ 0.980 ┃ proc-macro2    ┃ Near-identical to...    ┃
┗━━━━━━━━━━━━━┻━━━━━━━━━━┻━━━━━━━┻━━━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━━━━━━━━━━━━┛

❌ 1 suspect(s) found — review required
```

### Scan directory tree

```bash
taintrace scan-directory .                # recursive scan of all lockfiles
taintrace scan-directory /path/to/repo    # scan specific path
taintrace scan-directory . --format sarif # SARIF output for CI/CD
```

Auto-discovers: Cargo.lock, package-lock.json, pnpm-lock.yaml, yarn.lock, bun.lock, bun.lockb, requirements.txt, Pipfile.lock, poetry.lock, uv.lock, go.sum, Gemfile.lock, composer.json, composer.lock, Package.resolved, Package.swift, mix.lock, pubspec.yaml.

### JSON output (CI/CD)

```bash
taintrace check Cargo.lock --format json
```

### SARIF output (GitHub Code Scanning)

```bash
taintrace check Cargo.lock --format sarif > results.sarif
```

### Score a single package

```bash
taintrace score proc-macro1
```

### Exit codes

- `0` — no suspects found
- `1` — one or more suspects detected (use in CI/CD gates)

## Ignoring False Positives

To permanently suppress false-positive typosquats, use a `.taintrace.toml` file in your project root:

```toml
# .taintrace.toml
[taintrace]
ignore = [
  "my-internal-mirror",
  "legit-package-with-similar-name"
]
```

Or ignore packages via CLI flag:

```bash
taintrace check Cargo.lock --ignore proc-macro1 --ignore some-legit-package
```

Ignored packages are excluded from CLI, JSON, and SARIF output.

## Algorithms

- **Levenshtein distance** — edit distance between names
- **Soundex phonetic** — catches homophones ("night" vs "nite")
- **Substring matching** — detects containment ("lodash" vs "lodash1")
- **Combined scoring** — weighted combination of all signals

## Multi-ecosystem

| Ecosystem | Lockfiles                              | Status |
|-----------|----------------------------------------|--------|
| Rust      | Cargo.lock, Cargo.toml                 | ✅     |
| Node.js   | package-lock.json, pnpm-lock.yaml, yarn.lock, bun.lock, bun.lockb | ✅     |
| Python    | requirements.txt, poetry.lock, pyproject.toml (PEP 621 + Poetry), uv.lock, Pipfile.lock | ✅     |
| Go        | go.sum                                 | ✅     |
| Ruby      | Gemfile.lock                           | ✅     |
| PHP       | composer.json, composer.lock           | ✅     |
| Swift     | Package.resolved, Package.swift         | ✅     |
| Elixir    | mix.lock                               | ✅     |
| Dart      | pubspec.yaml                           | ✅     |

## CI/CD integration

### GitHub Action

```yaml
- uses: yunaremaia/taintrace@main
  with:
    lockfile: Cargo.lock
    format: sarif
    sarif-output: taintrace.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: taintrace.sarif
```

Auto-detect lockfiles in your repo root:

```yaml
- uses: yunaremaia/taintrace@main
  with:
    format: cli
```

### Pre-commit hook

```yaml
repos:
  - repo: https://github.com/yunaremaia/taintrace
    rev: v0.2.1
    hooks:
      - id: taintrace
```

## Why taintrace?

- **AI-agent-aware** — built for the vector AI agents expose (automatic dep installation)
- **Zero config** — just point at your lockfile
- **Offline-first** — no API calls, no data leaves your machine
- **SARIF-native** — integrates with GitHub Code Scanning
- **Open source** — MIT licensed, no paywall

## How it differs

| Tool          | CVE-based | Typosquat | AI-aware | Open source |
|---------------|-----------|-----------|----------|-------------|
| cargo-audit   | ✅        | ❌        | ❌       | ✅          |
| npm audit     | ✅        | ❌        | ❌       | ✅          |
| Socket        | ✅        | Partial   | ❌       | ❌          |
| Phylum        | ✅        | Partial   | ❌       | ❌          |
| **taintrace** | ❌        | ✅        | ✅       | ✅          |

## License

MIT — see [LICENSE](LICENSE)
