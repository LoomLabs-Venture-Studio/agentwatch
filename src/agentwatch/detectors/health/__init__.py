"""Health-focused detectors for agent behavioral issues."""

from .context import ContextPressureDetector, ContextRotDetector, RediscoveryDetector
from .errors import (
    ErrorBlindnessDetector,
    ErrorSpiralDetector,
    HighErrorRateDetector,
    SyntaxLoopDetector,
)
from .loops import LoopDetector, RereadDetector, StallDetector, ThrashDetector
from .stuck import (
    ErrorClassPersistenceDetector,
    ExplorationStallDetector,
    FileChurnDetector,
    SameOutcomeDetector,
)

__all__ = [
    # Loop/progress detectors
    "LoopDetector",
    "RereadDetector",
    "ThrashDetector",
    "StallDetector",
    # Stuck detectors (non-trivial loops)
    "SameOutcomeDetector",
    "FileChurnDetector",
    "ExplorationStallDetector",
    "ErrorClassPersistenceDetector",
    # Error detectors
    "ErrorSpiralDetector",
    "ErrorBlindnessDetector",
    "SyntaxLoopDetector",
    "HighErrorRateDetector",
    # Context detectors
    "ContextRotDetector",
    "ContextPressureDetector",
    "RediscoveryDetector",
]


def get_all_health_detectors():
    """Return instances of all health detectors with default settings."""
    return [
        LoopDetector(),
        RereadDetector(),
        ThrashDetector(),
        StallDetector(),
        SameOutcomeDetector(),
        FileChurnDetector(),
        ExplorationStallDetector(),
        ErrorClassPersistenceDetector(),
        ErrorSpiralDetector(),
        ErrorBlindnessDetector(),
        SyntaxLoopDetector(),
        HighErrorRateDetector(),
        ContextRotDetector(),
        ContextPressureDetector(),
        RediscoveryDetector(),
    ]
