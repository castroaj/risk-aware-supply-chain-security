"""
trainer.py
==========
Decision Tree training pipeline for the risk classifier.

Exposes:
    Trainer  — orchestrates fit, evaluate, and artifact persistence

TrainingConfig and TrainingResult are defined in results.py and re-exported
here for backwards compatibility so callers can still import them from either
location.
"""

from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.tree import DecisionTreeClassifier
import joblib

from . import sbom_extractor as _extractor
from .results import TrainingConfig, TrainingResult

# Re-export so `from classifier.trainer import TrainingConfig, TrainingResult` still works.
__all__ = ["Trainer", "TrainingConfig", "TrainingResult"]


class Trainer:
    """
    Orchestrates the Decision Tree training pipeline.

    WHAT:
        Accepts a labeled DataFrame (from data_loader.load_dataset), trains a
        DecisionTreeClassifier, evaluates it on a held-out test set, and provides
        a method to persist the model artifacts to disk.

    WHY:
        Encapsulates the mutable state of a training run (fitted model, encoder) while
        keeping the training logic separate from data loading, visualization, and
        reporting. TrainingConfig makes hyperparameters introspectable and serializable
        without keyword-argument explosion.

    Usage:
        df = load_dataset(manifests_dir, data_root)
        trainer = Trainer(df)
        result = trainer.train()
        result.write_report(output_dir)
        result.save_visualizations(df, output_dir)
        trainer.save_artifacts(result, output_dir)
    """

    def __init__(self, df: pd.DataFrame, config: TrainingConfig = None) -> None:
        """
        Store the dataset and validate that all required feature columns are present.

        Args:
            df:     Labeled DataFrame returned by data_loader.load_dataset().
                    Must contain a 'rule_label' column and all columns in
                    sbom_extractor.FEATURES.
            config: Hyperparameter configuration. Defaults to TrainingConfig().

        Raises:
            ValueError: If df is empty or any required feature column is missing.
        """
        if config is None:
            config = TrainingConfig()
        self._config = config

        if df.empty:
            raise ValueError("Cannot train on an empty DataFrame.")

        missing = [f for f in _extractor.FEATURES if f not in df.columns]
        if missing:
            raise ValueError(
                f"DataFrame is missing required feature columns: {missing}"
            )
        if "rule_label" not in df.columns:
            raise ValueError("DataFrame must contain a 'rule_label' column.")

        self._df = df.copy()

    def train(self) -> TrainingResult:
        """
        Build X/y, split, fit, and evaluate the Decision Tree.

        WHAT:
            1. Constructs X (float64 array) from the FEATURES columns.
            2. Encodes rule_label with LabelEncoder (alphabetical order:
               ALLOW=0, BLOCK=1, WARN=2).
            3. Performs a stratified train/test split per TrainingConfig.
            4. Fits a DecisionTreeClassifier with the configured hyperparameters.
            5. Computes test accuracy, full classification report string, and
               confusion matrix on the held-out test set.
            6. Runs StratifiedKFold cross-validation on the full X/y.

        WHY:
            Separated from save_artifacts() so tests can verify training results
            without touching the filesystem, and so CLI can control output location.

        Returns:
            TrainingResult populated with all evaluation outputs.
        """
        config = self._config
        df = self._df

        X = df[_extractor.FEATURES].values.astype(float)
        y_raw = df["rule_label"].values

        le = LabelEncoder()
        y = le.fit_transform(y_raw)

        class_dist = dict(zip(le.classes_, np.bincount(y).tolist()))

        X_train, X_test, y_train, y_test = train_test_split(
            X,
            y,
            test_size=config.test_size,
            random_state=config.random_state,
            stratify=y,
        )

        clf = DecisionTreeClassifier(
            criterion=config.criterion,
            max_depth=config.max_depth,
            min_samples_split=config.min_samples_split,
            min_samples_leaf=config.min_samples_leaf,
            class_weight=config.class_weight,
            random_state=config.random_state,
        )
        clf.fit(X_train, y_train)

        y_pred = clf.predict(X_test)
        acc = float(accuracy_score(y_test, y_pred))
        report_str = classification_report(y_test, y_pred, target_names=le.classes_)
        cm = confusion_matrix(y_test, y_pred)

        cv = StratifiedKFold(
            n_splits=config.cv_folds, shuffle=True, random_state=config.random_state
        )
        cv_scores = cross_val_score(clf, X, y, cv=cv, scoring="accuracy")

        return TrainingResult(
            model=clf,
            label_encoder=le,
            feature_names=list(_extractor.FEATURES),
            X_test=X_test,
            y_test=y_test,
            y_pred=y_pred,
            test_accuracy=acc,
            cv_scores=cv_scores,
            class_report_str=report_str,
            confusion_matrix=cm,
            train_size=len(X_train),
            test_size_actual=len(X_test),
            dataset_size=len(df),
            class_distribution=class_dist,
        )

    def save_artifacts(self, result: TrainingResult, output_dir: Path) -> None:
        """
        Persist the three model artifacts to output_dir using joblib.

        WHAT:
            Writes decision_tree_model.pkl, label_encoder.pkl, and
            feature_names.pkl. Creates output_dir if it does not exist.

        WHY:
            Separated from train() so tests can verify training results without
            writing to disk, and so the CLI can control the output location.

        Args:
            result:     A TrainingResult returned by train().
            output_dir: Directory where the three pkl files will be written.
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        joblib.dump(result.model, output_dir / "decision_tree_model.pkl")
        joblib.dump(result.label_encoder, output_dir / "label_encoder.pkl")
        joblib.dump(result.feature_names, output_dir / "feature_names.pkl")
