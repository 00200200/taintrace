"""CLI for taintrace — typosquat detector for AI agent dependencies."""

import json
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from taintrace.detector import TyposquatDetector, DetectionResult
from taintrace.scorer import RiskLevel
from taintrace import __version__


console = Console()


@click.group()
@click.version_option(package_name="taintrace")
def cli():
    """taintrace — typosquat detector for AI coding agent dependencies."""
    pass


@cli.command()
@click.argument("lockfiles", nargs=-1, type=click.Path(exists=True, path_type=Path))
@click.option("--format", "-f", "output_format", 
              type=click.Choice(["cli", "json", "sarif"]), default="cli",
              help="Output format")
@click.option("--threshold", "-t", default=0.7, type=float,
              help="Similarity threshold (0.0-1.0)")
@click.option("--ecosystem", "-e", default="auto",
              type=click.Choice([
                  "auto", "rust", "node", "python", "go", "ruby", "php", "swift", "elixir"
              ]),
              help="Package ecosystem (auto-detect from filename by default)")
@click.option("--no-informational", is_flag=True,
              help="Suppress MEDIUM/LOW risk results (informational only)")
@click.option("--ignore", "-i", multiple=True, type=str,
              help="Ignore specific packages (repeatable, can also be set in .taintrace.toml)")
def check(lockfiles: tuple[Path, ...], output_format: str, threshold: float,
          ecosystem: str, no_informational: bool, ignore: tuple[str, ...]):
    """Check one or more lockfiles for typosquatting."""
    if not lockfiles:
        click.echo("Error: at least one lockfile required", err=True)
        sys.exit(2)
    
    all_results = []
    all_suspects = []
    
    for lockfile in lockfiles:
        # Auto-detect ecosystem from filename if not specified
        eco = ecosystem
        if eco == "auto":
            eco = _detect_ecosystem(lockfile)
        
        detector = TyposquatDetector(ecosystem=eco)
        results = detector.scan(lockfile)
        
        # Merge CLI --ignore with config file ignore list
        config_ignored = set()
        if lockfile.parent.exists():
            from taintrace.config import get_ignored_packages
            config_ignored = set(get_ignored_packages(lockfile.parent))
        cli_ignored = set(ignore)
        all_ignored = config_ignored | cli_ignored
        
        # Filter out ignored packages
        if all_ignored:
            results = [r for r in results if r.dependency.name not in all_ignored]
        
        # Filter by threshold
        suspects = [r for r in results if r.is_suspect and r.risk_score >= threshold]
        
        # Filter out informational (LOW/MEDIUM) if requested
        if no_informational:
            suspects = [r for r in suspects if r.risk_level in ("CRITICAL", "HIGH")]
        
        all_results.extend(results)
        all_suspects.extend(suspects)
    
    if output_format == "json":
        _output_json(all_results, all_suspects)
    elif output_format == "sarif":
        _output_sarif(all_results, all_suspects, lockfiles[0])
    else:
        _output_cli(all_results, all_suspects, list(lockfiles))
    
    # Exit code 1 if suspects found (CI/CD gate)
    if all_suspects:
        sys.exit(1)


@cli.command()
@click.argument("name")
@click.option("--ecosystem", "-e", default="rust",
              type=click.Choice(["rust", "node", "python", "go", "ruby", "php", "swift", "elixir"]),
              help="Package ecosystem")
def score(name: str, ecosystem: str):
    """Score a single package name for typosquat risk."""
    detector = TyposquatDetector(ecosystem=ecosystem)
    result = detector.scan_dependency(name, ecosystem=ecosystem)
    _output_single(result)


def _detect_ecosystem(lockfile: Path) -> str:
    """Detect ecosystem from lockfile filename."""
    name = lockfile.name.lower()
    if name in ("cargo.lock", "cargo.toml"):
        return "rust"
    elif name in ("package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb"):
        return "node"
    elif name in ("requirements.txt", "poetry.lock"):
        return "python"
    elif name == "go.sum":
        return "go"
    elif name in ("package.resolved", "package.swift"):
        return "swift"
    elif name == "mix.lock":
        return "elixir"
    return "rust"


def _output_cli(results: list, suspects: list, lockfiles: list[Path]):
    """Rich CLI output."""
    names = ", ".join(lf.name for lf in lockfiles)
    console.print(Panel(
        f"[bold]taintrace v{__version__}[/bold] — scanning [cyan]{names}[/cyan]\n"
        f"Total deps: {len(results)} | Suspects: {len(suspects)}",
        title="Scan Results"
    ))
    
    if not suspects:
        console.print("[green]✅ No typosquat suspects detected.[/green]")
        return
    
    table = Table(title="🚨 Typosquat Suspects")
    table.add_column("Package", style="cyan")
    table.add_column("Risk", style="red")
    table.add_column("Score", justify="right")
    table.add_column("Similar To", style="yellow")
    table.add_column("Reason", style="dim")
    
    for r in suspects:
        risk_style = "red bold" if r.risk_level == "CRITICAL" else "yellow"
        table.add_row(
            r.dependency.name,
            f"[{risk_style}]{r.risk_level}[/{risk_style}]",
            f"{r.risk_score:.2f}",
            ", ".join(r.similar_packages[:3]) or "—",
            r.reason
        )
    
    console.print(table)
    console.print(f"\n[red]❌ {len(suspects)} suspect(s) found — review required[/red]")


def _output_json(results: list, suspects: list):
    """JSON output."""
    output = {
        "tool": "taintrace",
        "version": __version__,
        "summary": {
            "total": len(results),
            "suspects": len(suspects),
            "risk_levels": {
                "CRITICAL": len([r for r in suspects if r.risk_level == "CRITICAL"]),
                "HIGH": len([r for r in suspects if r.risk_level == "HIGH"]),
                "MEDIUM": len([r for r in suspects if r.risk_level == "MEDIUM"]),
            }
        },
        "results": [
            {
                "package": r.dependency.name,
                "version": r.dependency.version,
                "risk_level": r.risk_level,
                "risk_score": round(r.risk_score, 3),
                "similar_to": r.similar_packages,
                "reason": r.reason,
            }
            for r in results
        ]
    }
    click.echo(json.dumps(output, indent=2))


def _output_sarif(results: list, suspects: list, lockfile: Path):
    """SARIF output for GitHub Code Scanning."""
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "taintrace",
                    "version": __version__,
                    "informationUri": "https://github.com/yunaremaia/taintrace",
                    "rules": [
                        {
                            "id": "TYPO001",
                            "name": "TyposquatDetector",
                            "shortDescription": {"text": "Package name is suspiciously similar to a known package"},
                            "fullDescription": {"text": "This package name closely resembles a known legitimate package, suggesting possible typosquatting."},
                            "defaultConfiguration": {"level": "error"}
                        },
                        {
                            "id": "TYPO002",
                            "name": "UnknownPackage",
                            "shortDescription": {"text": "Package not in known packages database"},
                            "fullDescription": {"text": "This package was not found in the known legitimate packages database."},
                            "defaultConfiguration": {"level": "warning"}
                        }
                    ]
                }
            },
            "results": [
                {
                    "ruleId": "TYPO001" if r.is_suspect else "TYPO002",
                    "level": "error" if r.risk_level in ("CRITICAL", "HIGH") else "warning",
                    "message": {"text": f"{r.reason} (score: {r.risk_score:.3f})"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": str(lockfile.name)},
                            "region": {"startLine": 1, "startColumn": 1}
                        }
                    }]
                }
                for r in suspects
            ]
        }]
    }
    click.echo(json.dumps(sarif, indent=2))


def _output_single(result: DetectionResult):
    """Output for single package scoring."""
    if result.is_suspect:
        console.print(f"[red bold]🚨 {result.dependency.name}[/red bold]")
        console.print(f"Risk: [yellow]{result.risk_level}[/yellow] | Score: {result.risk_score:.3f}")
        console.print(f"Similar to: {', '.join(result.similar_packages[:5])}")
        console.print(f"Reason: {result.reason}")
    else:
        console.print(f"[green]✅ {result.dependency.name}[/green] — {result.reason}")


# Known lockfile names for auto-discovery
LOCKFILE_NAMES = {
    "Cargo.lock": "rust",
    "Cargo.toml": "rust",
    "package-lock.json": "node",
    "pnpm-lock.yaml": "node",
    "yarn.lock": "node",
    "bun.lock": "node",
    "bun.lockb": "node",
    "requirements.txt": "python",
    "Pipfile.lock": "python",
    "poetry.lock": "python",
    "uv.lock": "python",
    "go.sum": "go",
    "Gemfile.lock": "ruby",
    "composer.json": "php",
    "composer.lock": "php",
    "Package.resolved": "swift",
    "Package.swift": "swift",
    "mix.lock": "elixir",
}

# Directories to skip during recursive walk
SKIP_DIRS = {".git", "node_modules", "vendor", ".vendor", "dist", "build", ".cache"}


def _find_lockfiles(path: Path) -> list[tuple[Path, str]]:
    """Recursively find lockfiles in a directory, returning (path, ecosystem) pairs."""
    lockfiles = []
    if not path.is_dir():
        return lockfiles
    
    for item in path.iterdir():
        if item.is_dir():
            if item.name in SKIP_DIRS:
                continue
            lockfiles.extend(_find_lockfiles(item))
        elif item.name in LOCKFILE_NAMES:
            lockfiles.append((item, LOCKFILE_NAMES[item.name]))
    
    return lockfiles


@cli.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path), default=".")
@click.option("--format", "-f", "output_format",
              type=click.Choice(["cli", "json", "sarif"]), default="cli",
              help="Output format")
@click.option("--threshold", "-t", default=0.7, type=float,
              help="Similarity threshold (0.0-1.0)")
@click.option("--no-informational", is_flag=True,
              help="Suppress MEDIUM/LOW risk results")
@click.option("--ignore", "-i", multiple=True, type=str,
              help="Ignore specific packages (repeatable)")
def scan_directory(path: Path, output_format: str, threshold: float,
                   no_informational: bool, ignore: tuple[str, ...]):
    """Recursively scan a directory tree for typosquatting in all lockfiles."""
    found = _find_lockfiles(path)
    
    if not found:
        console.print(f"[yellow]No lockfiles found in {path}[/yellow]")
        return
    
    # Sort for deterministic output
    found.sort(key=lambda x: str(x[0]))
    
    all_results = []
    all_suspects = []
    per_file = {}
    
    for lockfile, eco in found:
        detector = TyposquatDetector(ecosystem=eco)
        results = detector.scan(lockfile)
        
        # Merge ignores
        config_ignored = set()
        if lockfile.parent.exists():
            from taintrace.config import get_ignored_packages
            config_ignored = set(get_ignored_packages(lockfile.parent))
        all_ignored = config_ignored | set(ignore)
        
        if all_ignored:
            results = [r for r in results if r.dependency.name not in all_ignored]
        
        suspects = [r for r in results if r.is_suspect and r.risk_score >= threshold]
        if no_informational:
            suspects = [r for r in suspects if r.risk_level in ("CRITICAL", "HIGH")]
        
        all_results.extend(results)
        all_suspects.extend(suspects)
        per_file[lockfile] = (results, suspects)
    
    # Per-file summary
    if len(found) > 1:
        console.print(f"[dim]Scanned {len(found)} lockfiles in {path}[/dim]\n")
        for lockfile, (results, suspects) in per_file.items():
            rel = lockfile.relative_to(path) if lockfile.is_relative_to(path) else lockfile
            status = "[red]🚨[/red]" if suspects else "[green]✅[/green]"
            console.print(f"  {status} {rel} — {len(results)} deps, {len(suspects)} suspect(s)")
        console.print()
    
    if output_format == "json":
        _output_json(all_results, all_suspects)
    elif output_format == "sarif":
        _output_sarif(all_results, all_suspects, found[0][0])
    else:
        if len(found) > 1 and all_suspects:
            console.print(f"[bold]Aggregated suspects across {len(found)} lockfiles:[/bold]")
        _output_cli(all_results, all_suspects, [lf for lf, _ in found])
    
    if all_suspects:
        sys.exit(1)


if __name__ == "__main__":
    cli()
