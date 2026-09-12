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


console = Console()


@click.group()
@click.version_option(package_name="taintrace")
def cli():
    """taintrace — typosquat detector for AI coding agent dependencies."""
    pass


@cli.command()
@click.argument("lockfile", type=click.Path(exists=True, path_type=Path))
@click.option("--format", "-f", "output_format", 
              type=click.Choice(["cli", "json", "sarif"]), default="cli",
              help="Output format")
@click.option("--threshold", "-t", default=0.7, type=float,
              help="Similarity threshold (0.0-1.0)")
@click.option("--ecosystem", "-e", default="auto",
              type=click.Choice(["auto", "rust", "node", "python", "go"]),
              help="Package ecosystem (auto-detect from filename by default)")
def check(lockfile: Path, output_format: str, threshold: float, ecosystem: str):
    """Check a lockfile for typosquatting."""
    # Auto-detect ecosystem from filename if not specified
    if ecosystem == "auto":
        ecosystem = _detect_ecosystem(lockfile)
    
    detector = TyposquatDetector(ecosystem=ecosystem)
    results = detector.scan(lockfile)
    
    # Filter by threshold
    suspects = [r for r in results if r.is_suspect and r.risk_score >= threshold]
    
    if output_format == "json":
        _output_json(results, suspects)
    elif output_format == "sarif":
        _output_sarif(results, suspects, lockfile)
    else:
        _output_cli(results, suspects, lockfile)
    
    # Exit code 1 if suspects found (CI/CD gate)
    if suspects:
        sys.exit(1)


@cli.command()
@click.argument("name")
@click.option("--ecosystem", "-e", default="rust",
              type=click.Choice(["rust", "node", "python", "go"]),
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
    elif name in ("package-lock.json", "pnpm-lock.yaml", "yarn.lock"):
        return "node"
    elif name in ("requirements.txt", "poetry.lock"):
        return "python"
    elif name == "go.sum":
        return "go"
    return "rust"


def _output_cli(results: list, suspects: list, lockfile: Path):
    """Rich CLI output."""
    console.print(Panel(
        f"[bold]taintrace v0.1.0[/bold] — scanning [cyan]{lockfile.name}[/cyan]\n"
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
        "version": "0.1.0",
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
                    "version": "0.1.0",
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


if __name__ == "__main__":
    cli()
