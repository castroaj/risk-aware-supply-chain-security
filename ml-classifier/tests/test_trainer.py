"""
test_trainer.py
===============
Unit tests for classifier.trainer.

Tests cover:
    - TrainingConfig default values (reproducibility contract)
    - Trainer ValueError on missing columns or empty DataFrame
    - Trainer.train() output structure and value ranges
    - Trainer.save_artifacts() writes three pkl files
    - Saved artifacts are loadable and functional
"""

import numpy as np
import pandas as pd
import pytest
import joblib

from classifier.trainer import Trainer, TrainingConfig, TrainingResult
import sbom_extractor as _extractor


# ---------------------------------------------------------------------------
# Synthetic dataset factory
# ---------------------------------------------------------------------------

def _synthetic_df(n_per_class: int = 10) -> pd.DataFrame:
    """
    Build a minimal labeled DataFrame suitable for Trainer.

    Each class (ALLOW, WARN, BLOCK) gets n_per_class rows with
    feature values chosen so the Decision Tree can cleanly separate them.
    """
    rng = np.random.default_rng(seed=0)
    rows = []

    # ALLOW: all features low
    for _ in range(n_per_class):
        row = {f: rng.uniform(0, 5) for f in _extractor.FEATURES}
        row["rule_label"] = "ALLOW"
        rows.append(row)

    # WARN: moderate critical_cve_count
    for _ in range(n_per_class):
        row = {f: rng.uniform(0, 5) for f in _extractor.FEATURES}
        row["critical_cve_count"] = rng.uniform(15, 40)
        row["rule_label"] = "WARN"
        rows.append(row)

    # BLOCK: high critical_cve_count
    for _ in range(n_per_class):
        row = {f: rng.uniform(0, 5) for f in _extractor.FEATURES}
        row["critical_cve_count"] = rng.uniform(55, 100)
        row["rule_label"] = "BLOCK"
        rows.append(row)

    df = pd.DataFrame(rows)
    df["scan_file"] = "fixture"
    return df


# ---------------------------------------------------------------------------
# TrainingConfig
# ---------------------------------------------------------------------------

class TestTrainingConfig:
    def test_defaults_match_original_script(self):
        """Default hyperparameters reproduce the original train_classifier values."""
        cfg = TrainingConfig()
        assert cfg.criterion == "gini"
        assert cfg.max_depth == 5
        assert cfg.min_samples_split == 4
        assert cfg.min_samples_leaf == 2
        assert cfg.class_weight == "balanced"
        assert cfg.random_state == 42
        assert cfg.test_size == pytest.approx(0.20)
        assert cfg.cv_folds == 5


# ---------------------------------------------------------------------------
# Trainer.__init__
# ---------------------------------------------------------------------------

class TestTrainerInit:
    def test_raises_on_empty_dataframe(self):
        """ValueError is raised when the DataFrame is empty."""
        with pytest.raises(ValueError, match="empty"):
            Trainer(pd.DataFrame())

    def test_raises_on_missing_feature_column(self):
        """ValueError is raised when a required feature column is absent."""
        df = _synthetic_df()
        df = df.drop(columns=["critical_cve_count"])
        with pytest.raises(ValueError, match="critical_cve_count"):
            Trainer(df)

    def test_raises_on_missing_rule_label(self):
        """ValueError is raised when rule_label column is absent."""
        df = _synthetic_df().drop(columns=["rule_label"])
        with pytest.raises(ValueError, match="rule_label"):
            Trainer(df)


# ---------------------------------------------------------------------------
# Trainer.train()
# ---------------------------------------------------------------------------

class TestTrainerTrain:
    def test_returns_training_result(self):
        """train() returns a TrainingResult with all fields populated."""
        result = Trainer(_synthetic_df()).train()
        assert isinstance(result, TrainingResult)

    def test_test_accuracy_in_unit_interval(self):
        """test_accuracy is in [0.0, 1.0]."""
        result = Trainer(_synthetic_df()).train()
        assert 0.0 <= result.test_accuracy <= 1.0

    def test_cv_scores_length_matches_config(self):
        """cv_scores length equals TrainingConfig.cv_folds."""
        config = TrainingConfig(cv_folds=3)
        result = Trainer(_synthetic_df(), config).train()
        assert len(result.cv_scores) == 3

    def test_feature_names_match_extractor_features(self):
        """feature_names in result match sbom_extractor.FEATURES exactly."""
        result = Trainer(_synthetic_df()).train()
        assert result.feature_names == list(_extractor.FEATURES)

    def test_confusion_matrix_shape(self):
        """confusion_matrix is (n_classes, n_classes)."""
        df = _synthetic_df()
        n_classes = df["rule_label"].nunique()
        result = Trainer(df).train()
        assert result.confusion_matrix.shape == (n_classes, n_classes)

    def test_class_report_str_is_nonempty(self):
        """class_report_str is a non-empty string."""
        result = Trainer(_synthetic_df()).train()
        assert isinstance(result.class_report_str, str)
        assert len(result.class_report_str) > 0

    def test_train_test_sizes_sum_to_dataset(self):
        """train_size + test_size_actual == dataset_size."""
        result = Trainer(_synthetic_df()).train()
        assert result.train_size + result.test_size_actual == result.dataset_size


# ---------------------------------------------------------------------------
# Trainer.save_artifacts()
# ---------------------------------------------------------------------------

class TestTrainerSaveArtifacts:
    def test_writes_three_pkl_files(self, tmp_path):
        """save_artifacts writes decision_tree_model.pkl, label_encoder.pkl, feature_names.pkl."""
        result = Trainer(_synthetic_df()).train()
        Trainer(_synthetic_df()).save_artifacts(result, tmp_path)

        assert (tmp_path / "decision_tree_model.pkl").exists()
        assert (tmp_path / "label_encoder.pkl").exists()
        assert (tmp_path / "feature_names.pkl").exists()

    def test_creates_output_dir_if_missing(self, tmp_path):
        """save_artifacts creates the output directory if it does not exist."""
        result = Trainer(_synthetic_df()).train()
        new_dir = tmp_path / "new_subdir"
        assert not new_dir.exists()
        Trainer(_synthetic_df()).save_artifacts(result, new_dir)
        assert new_dir.exists()

    def test_saved_model_is_loadable_and_functional(self, tmp_path):
        """The saved decision_tree_model.pkl loads with joblib and predicts correctly."""
        df = _synthetic_df()
        trainer = Trainer(df)
        result = trainer.train()
        trainer.save_artifacts(result, tmp_path)

        model = joblib.load(tmp_path / "decision_tree_model.pkl")
        feature_names = joblib.load(tmp_path / "feature_names.pkl")
        label_encoder = joblib.load(tmp_path / "label_encoder.pkl")

        vec = np.zeros((1, len(feature_names)))
        raw_pred = model.predict(vec)
        label = label_encoder.inverse_transform(raw_pred)[0]

        assert label in {"ALLOW", "WARN", "BLOCK"}
