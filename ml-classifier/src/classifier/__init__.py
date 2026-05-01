"""
classifier — ML risk classifier package for supply chain security.

Public API:
    Trainer        — trains a DecisionTreeClassifier on SBOM scan data
    Predictor      — loads saved model artifacts and predicts ALLOW/WARN/BLOCK
    TrainingConfig — hyperparameter dataclass for Trainer
    TrainingResult — output bundle from a training run (with visualization/reporting methods)

    SecurityMetric              — feature vector dataclass (8 features + scan_file)
    FEATURES                    — ordered list of feature names (single source of truth)
    LabelResult                 — structured label output (label, justification, confidence)
    classify_metric             — rule-based ALLOW/WARN/BLOCK classifier (returns str)
    classify_metric_threshold   — threshold labeler returning a LabelResult
    classify_metric_llm         — LLM-based labeler returning a LabelResult with justification
    build_security_metric_from_sbom — extract a SecurityMetric from a CycloneDX JSON SBOM
"""

import logging
logging.getLogger("classifier").addHandler(logging.NullHandler())

from .trainer import Trainer, TrainingConfig, TrainingResult
from .predictor import Predictor
from .sbom_extractor import (
    SecurityMetric,
    FEATURES,
    LabelResult,
    classify_metric,
    classify_metric_threshold,
    classify_metric_llm,
    build_security_metric_from_sbom,
)

__all__ = [
    "Trainer",
    "Predictor",
    "TrainingConfig",
    "TrainingResult",
    "SecurityMetric",
    "FEATURES",
    "LabelResult",
    "classify_metric",
    "classify_metric_threshold",
    "classify_metric_llm",
    "build_security_metric_from_sbom",
]
