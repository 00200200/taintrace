"""Main typosquat detection engine."""

from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional


@dataclass
class DetectionResult:
    """Result of scanning a dependency."""
    dependency: 'Dependency'  # Forward reference
    is_suspect: bool
    risk_level: str
    risk_score: float
    similar_packages: List[str]
    reason: str


class TyposquatDetector:
    """Detect typosquatting in lockfiles."""

    def __init__(self, ecosystem: str = "rust"):
        """Initialize detector for specific ecosystem."""
        from taintrace.db import KnownPackagesDB
        from taintrace.scorer import RiskScorer
        self.ecosystem = ecosystem
        self.db = KnownPackagesDB()
        self.scorer = RiskScorer(self.db)

    def scan(self, lockfile_path: Path) -> List[DetectionResult]:
        """Scan a lockfile for typosquatting."""
        from taintrace.lockfile import LockfileParser
        parser = LockfileParser()
        deps = parser.parse(lockfile_path)
        results = []

        for dep in deps:
            result = self._score_dep(dep)
            results.append(result)

        return results

    def scan_dependency(self, name: str, version: str = "0.0.0",
                        ecosystem: str = "rust") -> DetectionResult:
        """Scan a single dependency by name."""
        from taintrace.lockfile import Dependency
        dep = Dependency(name=name, version=version, ecosystem=ecosystem)
        return self._score_dep(dep)

    def _score_dep(self, dep) -> DetectionResult:
        """Score a single dependency for typosquat risk."""
        result = self.scorer.score(dep.name, dep.ecosystem)
        is_suspect = result.level.value >= 2  # HIGH or CRITICAL

        return DetectionResult(
            dependency=dep,
            is_suspect=is_suspect,
            risk_level=str(result.level),
            risk_score=result.score,
            similar_packages=[name for name, _ in result.similar_packages],
            reason=result.reason
        )
