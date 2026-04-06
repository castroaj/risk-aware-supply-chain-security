"""
test_predictor.py
=================
Unit tests for classifier.predictor.

Tests cover:
    - Predictor raises FileNotFoundError on missing artifacts
    - Predictor.predict() returns a valid label
    - Predictor.predict_from_dict() defaults missing features to 0.0
    - PredictionResult.confidence is in [0.0, 1.0]
"""

import numpy as np
import pandas as pd
import pytest

import sbom_extractor as _extractor
from classifier.predictor import Predictor, PredictionResult
from classifier.trainer import Trainer


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _synthetic_df(n_per_class: int = 10) -> pd.DataFrame:
    """Minimal labeled DataFrame — mirrors the fixture in test_trainer.py."""
    rng = np.random.default_rng(seed=1)
    rows = []
    for label, low, high in [("ALLOW", 0, 5), ("WARN", 15, 40), ("BLOCK", 55, 100)]:
        for _ in range(n_per_class):
            row = {f: rng.uniform(0, 5) for f in _extractor.FEATURES}
            row["critical_cve_count"] = rng.uniform(low, high)
            row["rule_label"] = label
            rows.append(row)
    df = pd.DataFrame(rows)
    df["scan_file"] = "fixture"
    return df


@pytest.fixture()
def artifact_dir(tmp_path):
    """Train a minimal model and persist artifacts; return the artifact directory."""
    df = _synthetic_df()
    trainer = Trainer(df)
    result = trainer.train()
    trainer.save_artifacts(result, tmp_path)
    return tmp_path


@pytest.fixture()
def predictor(artifact_dir):
    """Instantiate Predictor from the fixture artifact_dir."""
    return Predictor(artifact_dir)


@pytest.fixture()
def allow_metric():
    """A SecurityMetric with all-zero features (expected to classify as ALLOW)."""
    return _extractor.SecurityMetric(
        scan_file="test",
        **{f: 0.0 for f in _extractor.FEATURES},
    )


# ---------------------------------------------------------------------------
# Predictor.__init__
# ---------------------------------------------------------------------------

class TestPredictorInit:
    def test_raises_on_missing_artifacts(self, tmp_path):
        """FileNotFoundError is raised when the artifact directory has no pkl files."""
        with pytest.raises(FileNotFoundError):
            Predictor(tmp_path)

    def test_raises_on_missing_single_artifact(self, artifact_dir):
        """FileNotFoundError is raised when one of the three pkl files is absent."""
        (artifact_dir / "feature_names.pkl").unlink()
        with pytest.raises(FileNotFoundError, match="feature_names"):
            Predictor(artifact_dir)


# ---------------------------------------------------------------------------
# Predictor.predict()
# ---------------------------------------------------------------------------

class TestPredictorPredict:
    def test_returns_prediction_result(self, predictor, allow_metric):
        """predict() returns a PredictionResult instance."""
        result = predictor.predict(allow_metric)
        assert isinstance(result, PredictionResult)

    def test_label_is_valid_class(self, predictor, allow_metric):
        """Predicted label is one of the three valid classes."""
        result = predictor.predict(allow_metric)
        assert result.label in {"ALLOW", "WARN", "BLOCK"}

    def test_confidence_in_unit_interval(self, predictor, allow_metric):
        """confidence is in [0.0, 1.0] when the model supports predict_proba."""
        result = predictor.predict(allow_metric)
        if result.confidence is not None:
            assert 0.0 <= result.confidence <= 1.0


# ---------------------------------------------------------------------------
# Predictor.predict_from_dict()
# ---------------------------------------------------------------------------

class TestPredictorPredictFromDict:
    def test_full_dict_produces_valid_label(self, predictor):
        """predict_from_dict with all features returns a valid label."""
        feature_dict = {f: 0.0 for f in _extractor.FEATURES}
        result = predictor.predict_from_dict(feature_dict)
        assert result.label in {"ALLOW", "WARN", "BLOCK"}

    def test_partial_dict_does_not_raise(self, predictor):
        """Missing features default to 0.0 — no KeyError or other exception."""
        result = predictor.predict_from_dict({"critical_cve_count": 5.0})
        assert result.label in {"ALLOW", "WARN", "BLOCK"}

    def test_empty_dict_does_not_raise(self, predictor):
        """Empty dict (all features default to 0.0) does not raise."""
        result = predictor.predict_from_dict({})
        assert result.label in {"ALLOW", "WARN", "BLOCK"}
