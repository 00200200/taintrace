"""taintrace public API."""

from taintrace.lockfile import LockfileParser, Dependency
from taintrace.similarity import SimilarityEngine
from taintrace.db import KnownPackagesDB
from taintrace.scorer import RiskScorer, RiskResult, RiskLevel
from taintrace.detector import TyposquatDetector, DetectionResult

__version__ = "0.1.0"

__all__ = [
    "LockfileParser",
    "Dependency",
    "SimilarityEngine",
    "KnownPackagesDB",
    "RiskScorer",
    "RiskResult",
    "RiskLevel",
    "TyposquatDetector",
    "DetectionResult",
]
