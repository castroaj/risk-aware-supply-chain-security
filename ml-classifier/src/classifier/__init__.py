"""
classifier — ML risk classifier package for supply chain security.

Public API:
    Trainer        — trains a DecisionTreeClassifier on SBOM scan data
    Predictor      — loads saved model artifacts and predicts ALLOW/WARN/BLOCK
    TrainingConfig — hyperparameter dataclass for Trainer
    TrainingResult — output bundle from a training run (with visualization/reporting methods)

    SecurityMetric              — feature vector dataclass (9 features + scan_file)
    FEATURES                    — ordered list of feature names (single source of truth)
    classify_metric             — rule-based ALLOW/WARN/BLOCK classifier
    build_security_metric_from_sbom — extract a SecurityMetric from a CycloneDX JSON SBOM
"""

import logging
logging.getLogger("classifier").addHandler(logging.NullHandler())

from .results import TrainingConfig, TrainingResult
from .trainer import Trainer
from .predictor import Predictor
from .sbom_extractor import (
    SecurityMetric,
    FEATURES,
    classify_metric,
    build_security_metric_from_sbom,
)

__all__ = [
    "Trainer",
    "Predictor",
    "TrainingConfig",
    "TrainingResult",
    "SecurityMetric",
    "FEATURES",
    "classify_metric",
    "build_security_metric_from_sbom",
]
