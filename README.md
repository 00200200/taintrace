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

### Scan a lockfile

```bash
taintrace check Cargo.lock
```

```
╭──────────────────────────────────────────────╮
│ taintrace v0.1.0 — scanning Cargo.lock       │
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

## Algorithms

- **Levenshtein distance** — edit distance between names
- **Soundex phonetic** — catches homophones ("night" vs "nite")
- **Substring matching** — detects containment ("lodash" vs "lodash1")
- **Combined scoring** — weighted combination of all signals

## Multi-ecosystem

| Ecosystem | Lockfile           | Status |
|-----------|--------------------|--------|
| Rust      | Cargo.lock         | ✅     |
| Node.js   | package-lock.json  | ✅     |
| Python    | requirements.txt   | ✅     |
| Go        | go.sum             | ✅     |

## CI/CD integration

### GitHub Action

```yaml
- name: Check for typosquatting
  run: |
    pip install taintrace
    taintrace check Cargo.lock --format sarif > results.sarif
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### Pre-commit hook

```yaml
repos:
  - repo: local
    hooks:
      - id: taintrace
        name: taintrace
        entry: taintrace check
        language: system
        files: '(Cargo.lock|package-lock.json|requirements.txt|go.sum)$'
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
