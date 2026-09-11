"""Risk scoring for package names."""

from dataclasses import dataclass
from enum import Enum
from typing import List, Tuple


class RiskLevel(Enum):
    """Risk level for a package."""
    LOW = 0
    MEDIUM = 1
    HIGH = 2
    CRITICAL = 3

    def __str__(self):
        return self.name


@dataclass
class RiskResult:
    """Result of risk scoring for a package."""
    package_name: str
    level: RiskLevel
    score: float  # 0.0 to 1.0
    similar_packages: List[Tuple[str, float]]  # (name, similarity)
    reason: str


class RiskScorer:
    """Calculate risk score for a package name."""

    def __init__(self, db=None):
        """Initialize with known packages database."""
        if db is None:
            from taintrace.db import KnownPackagesDB
            db = KnownPackagesDB()
        self.db = db
        from taintrace.similarity import SimilarityEngine
        self.engine = SimilarityEngine()

    def score(self, package_name: str, ecosystem: str = "rust") -> RiskResult:
        """Calculate risk score for a package name."""
        # Check if it's a known package
        if self.db.is_known(package_name, ecosystem):
            return RiskResult(
                package_name=package_name,
                level=RiskLevel.LOW,
                score=0.0,
                similar_packages=[],
                reason="Known legitimate package"
            )

        # Find similar known packages
        similar = self.db.get_similar(package_name, threshold=0.7, ecosystem=ecosystem)

        if not similar:
            return RiskResult(
                package_name=package_name,
                level=RiskLevel.MEDIUM,
                score=0.3,
                similar_packages=[],
                reason="Unknown package — not in known packages list"
            )

        # Calculate max similarity
        max_similar = max(similar, key=lambda x: x[1])
        max_similarity = max_similar[1]

        # Determine risk level
        if max_similarity >= 0.95:
            level = RiskLevel.CRITICAL
            reason = f"Near-identical to '{max_similar[0]}' — likely typosquat"
        elif max_similarity >= 0.85:
            level = RiskLevel.HIGH
            reason = f"Very similar to '{max_similar[0]}' — possible typosquat"
        elif max_similarity >= 0.75:
            level = RiskLevel.MEDIUM
            reason = f"Somewhat similar to '{max_similar[0]}'"
        else:
            level = RiskLevel.LOW
            reason = f"Minor similarity to '{max_similar[0]}'"

        # Calculate numeric score
        score = max_similarity * (1.0 if level != RiskLevel.MEDIUM else 0.5)

        return RiskResult(
            package_name=package_name,
            level=level,
            score=score,
            similar_packages=similar,
            reason=reason
        )
