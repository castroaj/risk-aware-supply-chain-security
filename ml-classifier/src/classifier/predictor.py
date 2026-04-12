"""
predictor.py
============
ML-based risk classifier backed by a trained DecisionTreeClassifier.

Loads saved model artifacts from a directory and exposes prediction via
SecurityMetric (the canonical feature vector type) or a raw dict.

This module does NOT re-implement rule-based classification; that remains in
sbom_extractor.classify_metric(). Use Predictor only when an ML-trained model
is required. If no model has been trained yet, call sbom_extractor.classify_metric()
directly.
"""

from dataclasses import dataclass
import logging
from pathlib import Path
from typing import List, Optional

import numpy as np
import joblib

from . import sbom_extractor as _extractor

_log = logging.getLogger(__name__)


@dataclass
class PredictionResult:
    """
    Output of a single ML-based prediction.

    WHAT:
        label:      Risk classification — one of "ALLOW", "WARN", "BLOCK".
        confidence: Probability of the predicted class from predict_proba(), or
                    None if the model does not support probability estimation.

    WHY:
        Wrapping label and confidence together lets callers pattern-match on the
        result type rather than unpacking a tuple, and makes the optional confidence
        field explicit rather than a hidden second return value.
    """

    label: str
    confidence: Optional[float]


class Predictor:
    """
    ML-based risk classifier backed by a trained DecisionTreeClassifier.

    WHAT:
        Loads decision_tree_model.pkl, label_encoder.pkl, and feature_names.pkl
        from a given artifact directory (written by Trainer.save_artifacts).
        Exposes predict() for SecurityMetric inputs and predict_from_dict() for
        raw feature dicts.

    WHY:
        Separates model loading (I/O, done once at construction) from prediction
        (pure, done many times). Caching the loaded model in instance state avoids
        reloading from disk on every call.

    Usage:
        predictor = Predictor(Path("analysis/"))
        metric = build_security_metric_from_sbom(scan_file, sbom)
        result = predictor.predict(metric)
        print(result.label, result.confidence)
    """

    _MODEL_FILE = "decision_tree_model.pkl"
    _ENCODER_FILE = "label_encoder.pkl"
    _FEATURES_FILE = "feature_names.pkl"

    def __init__(self, artifact_dir: Path) -> None:
        """
        Load the three model artifacts from artifact_dir.

        Args:
            artifact_dir: Directory containing decision_tree_model.pkl,
                          label_encoder.pkl, and feature_names.pkl.

        Raises:
            FileNotFoundError: If any of the three required pkl files is missing.
            RuntimeError: If joblib.load() fails for any artifact.
        """
        artifact_dir = Path(artifact_dir)

        for filename in (self._MODEL_FILE, self._ENCODER_FILE, self._FEATURES_FILE):
            path = artifact_dir / filename
            if not path.exists():
                raise FileNotFoundError(
                    f"Required artifact not found: {path}. "
                    f"Run 'risk-classifier train ...' to generate artifacts."
                )

        try:
            _log.debug("predictor: loading model from %s", artifact_dir / self._MODEL_FILE)
            self._model = joblib.load(artifact_dir / self._MODEL_FILE)
            _log.debug("predictor: loading label encoder from %s", artifact_dir / self._ENCODER_FILE)
            self._label_encoder = joblib.load(artifact_dir / self._ENCODER_FILE)
            _log.debug("predictor: loading feature names from %s", artifact_dir / self._FEATURES_FILE)
            self._feature_names: List[str] = joblib.load(
                artifact_dir / self._FEATURES_FILE
            )
            _log.info("predictor: artifacts loaded from %s — features: %s", artifact_dir, self._feature_names)
        except Exception as exc:
            raise RuntimeError(f"Failed to load model artifacts from {artifact_dir}: {exc}") from exc

    def predict(self, metric: "_extractor.SecurityMetric") -> PredictionResult:
        """
        Predict the risk label for a single SecurityMetric.

        WHAT:
            Builds a feature vector from the SecurityMetric fields in the order
            defined by self._feature_names (saved during training), calls the
            Decision Tree's predict() and predict_proba(), and returns a
            PredictionResult.

        WHY:
            Accepts SecurityMetric (the canonical feature vector type) so callers
            do not need to manually unpack fields or know the feature ordering.
            Uses self._feature_names from the pkl artifact to guard against
            field-order drift if SecurityMetric fields are ever reordered.

        Args:
            metric: A SecurityMetric dataclass instance.

        Returns:
            PredictionResult with label in {"ALLOW", "WARN", "BLOCK"} and
            confidence in [0.0, 1.0].
        """
        vec = np.array(
            [[getattr(metric, f, 0.0) for f in self._feature_names]], dtype=float
        )
        _log.debug("predictor: feature vector %s", dict(zip(self._feature_names, vec[0].tolist())))

        label_idx = int(self._model.predict(vec)[0])
        label = str(self._label_encoder.inverse_transform([label_idx])[0])

        confidence: Optional[float] = None
        if hasattr(self._model, "predict_proba"):
            proba = self._model.predict_proba(vec)[0]
            confidence = float(proba[label_idx])

        _log.info(
            "predictor: scan_file=%s label=%s confidence=%s",
            metric.scan_file, label,
            f"{confidence:.4f}" if confidence is not None else "N/A",
        )
        return PredictionResult(label=label, confidence=confidence)

    def predict_from_dict(self, feature_dict: dict) -> PredictionResult:
        """
        Predict the risk label from a plain feature dictionary.

        WHAT:
            Accepts a mapping of feature name → numeric value. Missing keys
            default to 0.0. Constructs a SecurityMetric internally and delegates
            to predict().

        WHY:
            Provides a convenience path for callers who have already extracted
            features into a dict (e.g., from a CSV row) without needing to
            construct a SecurityMetric manually. Defaulting missing values to 0.0
            matches the original predict_single() behaviour in train_classifier.

        Args:
            feature_dict: Mapping of feature name to numeric value.
                          Missing keys default to 0.0.

        Returns:
            PredictionResult.
        """
        metric = _extractor.SecurityMetric(
            scan_file="",
            **{f: float(feature_dict.get(f, 0.0)) for f in _extractor.FEATURES},
        )
        return self.predict(metric)
