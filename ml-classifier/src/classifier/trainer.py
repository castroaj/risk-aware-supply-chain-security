"""
trainer.py
==========
Decision Tree training pipeline for the risk classifier.

Exposes:
    TrainingConfig  — hyperparameters and split settings
    TrainingResult  — output bundle from a completed training run, with
                      methods for visualization and reporting
    Trainer         — orchestrates fit, evaluate, and artifact persistence

Visualization outputs (all saved as PNG):
    confusion_matrix.png             — heatmap of test-set predictions
    decision_tree.png                — rendered decision tree (max_depth=5)
    feature_importances.png          — bar chart of Gini importances (descending)
    feature_correlation_matrix.png   — lower-triangle Pearson correlation heatmap

Text report output:
    classification_report.txt        — dataset summary, accuracy metrics, sklearn
                                       classification report, decision tree rules
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Union

import logging
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    ConfusionMatrixDisplay,
    accuracy_score,
    classification_report,
    confusion_matrix,
)
from sklearn.model_selection import StratifiedKFold, cross_val_predict, train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.tree import DecisionTreeClassifier, export_text, plot_tree
import joblib

from . import sbom_extractor as _extractor
from .sbom_extractor import FEATURES
from .predictor import WARN_CONFIDENCE_THRESHOLD

_log = logging.getLogger(__name__)


# Short axis labels for the correlation heatmap so axis text doesn't overlap.
_SHORT_LABELS = [
    "dep_count", "vuln_total", "crit_cve", "high_cve",
    "cvss≥7", "max_cvss", "uniq_cwe", "top25_cwe"
]


# ======================================================================
# Configuration and result dataclasses
# ======================================================================

@dataclass
class TrainingConfig:
    """
    Hyperparameters and split settings for one training run.

    All fields default to the values used in the original train_classifier script
    to ensure reproducibility of existing results without explicit configuration.
    """

    criterion: str = "gini"
    max_depth: int = 5
    min_samples_split: int = 4
    min_samples_leaf: int = 2
    class_weight: Union[str, dict] = "balanced"
    random_state: int = 42
    test_size: float = 0.20
    cv_folds: int = 5


@dataclass
class TrainingResult:
    """
    Output bundle from a completed training run.

    WHAT:
        Holds the fitted model, encoder, evaluation metrics, and test-set arrays.
        Exposes methods for reporting and visualization so that callers interact
        with a single typed object rather than passing the result through a
        collection of module-level functions.

    WHY:
        The visualization and reporting functions all operate on the same result
        state — grouping them as methods makes the intent clearer and matches the
        pattern established by SecurityMetric and SecurityMetricsCollection in
        sbom_extractor.py.

    Usage:
        result = trainer.train()
        result.write_report(output_dir)
        result.plot_confusion_matrix(output_dir)
        result.save_visualizations(df, output_dir)
        trainer.save_artifacts(result, output_dir)
    """

    config: TrainingConfig
    model: DecisionTreeClassifier
    label_encoder: LabelEncoder
    feature_names: List[str]
    X_test: np.ndarray
    y_test: np.ndarray
    y_pred: np.ndarray
    test_accuracy: float
    cv_scores: np.ndarray
    class_report_str: str
    confusion_matrix: np.ndarray
    train_size: int
    test_size_actual: int
    dataset_size: int
    class_distribution: Dict[str, int]

    # Escalation policy metadata — documents the threshold applied during evaluation
    # and how many test-set predictions were affected.
    warn_escalated_count: int = 0
    warn_confidence_threshold: float = field(default_factory=lambda: WARN_CONFIDENCE_THRESHOLD)

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    def write_report(self, output_dir: Path) -> Path:
        """
        Write a human-readable evaluation report to output_dir/classification_report.txt.

        Args:
            output_dir: Directory to write classification_report.txt into.

        Returns:
            Path of the written file.
        """
        return write_classification_report(self, output_dir)

    # ------------------------------------------------------------------
    # Visualization — individual plots
    # ------------------------------------------------------------------

    def plot_confusion_matrix(self, output_dir: Path) -> Path:
        """
        Render a heatmap of the test-set confusion matrix.

        Args:
            output_dir: Directory to write confusion_matrix.png into.

        Returns:
            Path of the saved PNG file.
        """
        return plot_confusion_matrix(self, output_dir)

    def plot_decision_tree(self, output_dir: Path) -> Path:
        """
        Render the fitted decision tree.

        Args:
            output_dir: Directory to write decision_tree.png into.

        Returns:
            Path of the saved PNG file.
        """
        return plot_decision_tree(self, output_dir)

    def plot_feature_importances(self, output_dir: Path) -> Path:
        """
        Render a bar chart of Gini feature importances in descending order.

        Args:
            output_dir: Directory to write feature_importances.png into.

        Returns:
            Path of the saved PNG file.
        """
        return plot_feature_importances(self, output_dir)

    # ------------------------------------------------------------------
    # Visualization — full suite
    # ------------------------------------------------------------------

    def save_visualizations(self, df: pd.DataFrame, output_dir: Path) -> List[Path]:
        """
        Produce all four visualization PNGs and return their paths.

        WHAT:
            Calls plot_confusion_matrix, plot_decision_tree, plot_feature_importances,
            and plot_correlation_matrix (full dataset correlation — requires df).

        WHY:
            Convenience method so callers can produce all outputs in one call.
            Individual plot methods are still available when only a subset is needed.

        Args:
            df:         The full labeled DataFrame returned by data_loader.load_dataset().
                        Required for the correlation matrix (computed over all data,
                        not just the test set).
            output_dir: Directory to write all PNGs into.

        Returns:
            List of four Path objects for the saved PNG files.
        """
        return save_all(self, df, output_dir)


# ======================================================================
# Reporting
# ======================================================================

def write_classification_report(result: TrainingResult, output_dir: Path) -> Path:
    """
    Write a human-readable evaluation report to output_dir/classification_report.txt.

    WHAT:
        Sections written:
          1. Dataset summary (total images, train/test sizes, class distribution)
          2. Hyperparameters (all TrainingConfig fields)
          3. Test Accuracy (scalar, 4 decimal places)
          4. CV Accuracy (mean ± std across cv_folds folds)
          5. Full sklearn classification report (precision, recall, F1 per class)
          6. Decision Tree Rules (export_text representation of the fitted tree)

    WHY:
        Co-located with Trainer so training logic and report format are maintained
        together. Tests can verify report content without running a full training
        pipeline.

    Args:
        result:     A TrainingResult returned by Trainer.train().
        output_dir: Directory to write classification_report.txt into.
                    Created if it does not exist.

    Returns:
        Path of the written report file.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / "classification_report.txt"

    cv_mean = result.cv_scores.mean()
    cv_std = result.cv_scores.std()
    cv_folds = len(result.cv_scores)

    class_dist_str = ", ".join(
        f"{cls}={count}" for cls, count in sorted(result.class_distribution.items())
    )

    tree_rules = export_text(result.model, feature_names=result.feature_names)

    cfg = result.config
    lines = [
        "Risk-Aware Supply Chain Security — Decision Tree Classifier",
        "=" * 60,
        "",
        f"Dataset size       : {result.dataset_size} images",
        f"Train / Test split : {result.train_size} / {result.test_size_actual}",
        f"Class distribution : {class_dist_str}",
        "",
        "Hyperparameters:",
        f"  criterion         : {cfg.criterion}",
        f"  max_depth         : {cfg.max_depth}",
        f"  min_samples_split : {cfg.min_samples_split}",
        f"  min_samples_leaf  : {cfg.min_samples_leaf}",
        f"  class_weight      : {cfg.class_weight}",
        f"  random_state      : {cfg.random_state}",
        f"  test_size         : {cfg.test_size:.2f}",
        f"  cv_folds          : {cfg.cv_folds}",
        "",
        f"Test Accuracy      : {result.test_accuracy:.4f}",
        f"CV Accuracy        : {cv_mean:.4f} ± {cv_std:.4f} ({cv_folds}-fold stratified)",
        "",
        "Escalation Policy:",
        f"  WARN confidence threshold : {result.warn_confidence_threshold:.2f}",
        f"  WARNs escalated to BLOCK  : {result.warn_escalated_count} (test set)",
        "  BLOCK predictions         : never downgraded",
        "",
        "Classification Report:",
        result.class_report_str,
        "Decision Tree Rules:",
        tree_rules,
    ]

    report_path.write_text("\n".join(lines), encoding="utf-8")
    return report_path


# ======================================================================
# Visualization
# ======================================================================

def plot_confusion_matrix(result: TrainingResult, output_dir: Path) -> Path:
    """
    Render a heatmap of the test-set confusion matrix.

    WHAT:
        Uses sklearn.metrics.ConfusionMatrixDisplay to render result.confusion_matrix
        with class labels from result.label_encoder. Saves to
        output_dir/confusion_matrix.png at 150 dpi.

    Args:
        result:     A TrainingResult returned by Trainer.train().
        output_dir: Directory to write the PNG into. Created if missing.

    Returns:
        Path of the saved PNG file.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    out_path = output_dir / "confusion_matrix.png"

    fig, ax = plt.subplots(figsize=(6, 5))
    disp = ConfusionMatrixDisplay(
        confusion_matrix=result.confusion_matrix,
        display_labels=result.label_encoder.classes_,
    )
    disp.plot(ax=ax, colorbar=False, cmap="Blues")
    ax.set_title("Confusion Matrix — Decision Tree (Test Set)")
    plt.tight_layout()
    plt.savefig(out_path, dpi=150)
    plt.close()

    return out_path


def plot_decision_tree(result: TrainingResult, output_dir: Path) -> Path:
    """
    Render the fitted decision tree using sklearn.tree.plot_tree.

    WHAT:
        Renders the tree with filled nodes, class names, feature names, and
        impurity values. Saves to output_dir/decision_tree.png at 150 dpi
        with bbox_inches="tight" to prevent label clipping.

    Args:
        result:     A TrainingResult returned by Trainer.train().
        output_dir: Directory to write the PNG into. Created if missing.

    Returns:
        Path of the saved PNG file.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    out_path = output_dir / "decision_tree.png"

    fig, ax = plt.subplots(figsize=(20, 10))
    plot_tree(
        result.model,
        feature_names=result.feature_names,
        class_names=list(result.label_encoder.classes_),
        filled=True,
        rounded=True,
        fontsize=9,
        ax=ax,
        impurity=True,
        proportion=False,
    )
    ax.set_title(
        f"Decision Tree — Risk Classification (max_depth={result.model.max_depth})",
        fontsize=13,
    )
    plt.tight_layout()
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()

    return out_path


def plot_feature_importances(result: TrainingResult, output_dir: Path) -> Path:
    """
    Render a bar chart of Gini feature importances in descending order.

    WHAT:
        Reads result.model.feature_importances_, sorts descending, and renders
        a bar chart. Saves to output_dir/feature_importances.png at 150 dpi.

    Args:
        result:     A TrainingResult returned by Trainer.train().
        output_dir: Directory to write the PNG into. Created if missing.

    Returns:
        Path of the saved PNG file.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    out_path = output_dir / "feature_importances.png"

    importances = result.model.feature_importances_
    sorted_idx = np.argsort(importances)[::-1]

    fig, ax = plt.subplots(figsize=(9, 5))
    ax.bar(
        [result.feature_names[i] for i in sorted_idx],
        importances[sorted_idx],
        color="steelblue",
        edgecolor="white",
    )
    ax.set_title("Feature Importances — Decision Tree")
    ax.set_ylabel("Gini Importance")
    ax.set_xlabel("Feature")
    plt.xticks(rotation=35, ha="right", fontsize=9)
    plt.tight_layout()
    plt.savefig(out_path, dpi=150)
    plt.close()

    return out_path


def plot_correlation_matrix(df: pd.DataFrame, output_dir: Path) -> Path:
    """
    Render a lower-triangle Pearson correlation heatmap of the 9 FEATURES.

    WHAT:
        Computes the Pearson correlation matrix for the FEATURES columns of df
        and renders a lower-triangle seaborn heatmap with short axis labels.
        Saves to output_dir/feature_correlation_matrix.png at 150 dpi.

    WHY:
        Accepts df rather than TrainingResult because correlation is computed on
        the full dataset, not just the test set.

    Args:
        df:         The full labeled DataFrame returned by data_loader.load_dataset().
        output_dir: Directory to write the PNG into. Created if missing.

    Returns:
        Path of the saved PNG file.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    out_path = output_dir / "feature_correlation_matrix.png"

    corr = df[FEATURES].corr()

    mask = np.zeros_like(corr, dtype=bool)
    mask[np.triu_indices_from(mask)] = True  # hide upper triangle (redundant)

    fig, ax = plt.subplots(figsize=(10, 8))
    sns.heatmap(
        corr,
        mask=mask,
        annot=True,
        fmt=".2f",
        cmap="coolwarm",
        center=0,
        vmin=-1,
        vmax=1,
        linewidths=0.5,
        square=True,
        ax=ax,
        xticklabels=_SHORT_LABELS,
        yticklabels=_SHORT_LABELS,
        annot_kws={"size": 8},
    )
    ax.set_title("Feature Correlation Matrix", fontsize=13, pad=12)
    plt.xticks(rotation=40, ha="right", fontsize=9)
    plt.yticks(rotation=0, fontsize=9)
    plt.tight_layout()
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()

    return out_path


def save_all(
    result: TrainingResult, df: pd.DataFrame, output_dir: Path
) -> List[Path]:
    """
    Produce all four visualization PNGs and return their paths.

    WHAT:
        Calls plot_confusion_matrix, plot_decision_tree, plot_feature_importances,
        and plot_correlation_matrix in sequence.

    WHY:
        CLI can call this once rather than calling four functions; tests can call
        individual plot functions independently without invoking this wrapper.

    Args:
        result:     A TrainingResult returned by Trainer.train().
        df:         The full labeled DataFrame (needed for correlation matrix).
        output_dir: Directory to write all PNGs into.

    Returns:
        List of four Path objects for the saved PNG files.
    """
    return [
        plot_confusion_matrix(result, output_dir),
        plot_decision_tree(result, output_dir),
        plot_feature_importances(result, output_dir),
        plot_correlation_matrix(df, output_dir),
    ]


# ======================================================================
# Trainer
# ======================================================================

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
        _log.info("train: LabelEncoder mapping %s", dict(zip(le.classes_, range(len(le.classes_)))))

        class_dist = dict(zip(le.classes_, np.bincount(y).tolist()))
        _log.debug("train: class distribution %s", class_dist)

        X_train, X_test, y_train, y_test = train_test_split(
            X,
            y,
            test_size=config.test_size,
            random_state=config.random_state,
            stratify=y,
        )
        _log.info("train: stratified split train=%d test=%d", len(X_train), len(X_test))
        _log.debug("train: feature matrix shape X=%s", X.shape)

        # sklearn dict class_weight keys must be encoded integers, not class name strings.
        # Translate {"ALLOW": 1, "WARN": 2, "BLOCK": 4} → {0: 1, 2: 2, 1: 4} via the LabelEncoder.
        if isinstance(config.class_weight, dict):
            known = set(le.classes_)
            unknown = set(config.class_weight.keys()) - known
            if unknown:
                raise ValueError(
                    f"class_weight contains class names not present in the dataset: "
                    f"{sorted(unknown)}. Known classes: {sorted(known)}"
                )
            bad = {k: v for k, v in config.class_weight.items()
                   if not isinstance(v, (int, float)) or v <= 0}
            if bad:
                raise ValueError(
                    f"class_weight values must be positive numbers; got: {bad}"
                )
            class_weight_encoded = {
                int(le.transform([cls])[0]): w
                for cls, w in config.class_weight.items()
            }
        else:
            class_weight_encoded = config.class_weight

        clf = DecisionTreeClassifier(
            criterion=config.criterion,
            max_depth=config.max_depth,
            min_samples_split=config.min_samples_split,
            min_samples_leaf=config.min_samples_leaf,
            class_weight=class_weight_encoded,
            random_state=config.random_state,
        )
        _log.info(
            "train: DecisionTree criterion=%s max_depth=%s min_samples_split=%d "
            "min_samples_leaf=%d class_weight=%s",
            config.criterion, config.max_depth, config.min_samples_split,
            config.min_samples_leaf, config.class_weight,
        )
        _log.info("train: fitting on %d samples", len(X_train))
        clf.fit(X_train, y_train)
        _log.info("train: fit complete")

        # Encode the class indices needed for the escalation gate.
        # LabelEncoder sorts classes alphabetically: ALLOW=0, BLOCK=1, WARN=2.
        warn_idx = int(le.transform(["WARN"])[0])
        block_idx = int(le.transform(["BLOCK"])[0])

        # Apply the same escalation policy as Predictor.predict():
        # any WARN prediction whose confidence is below WARN_CONFIDENCE_THRESHOLD
        # is promoted to BLOCK. BLOCK predictions are never touched.
        # proba_test columns are ordered by clf.classes_ == [0, 1, 2], so
        # column warn_idx gives P(WARN) for each sample.
        y_pred_raw = clf.predict(X_test)
        proba_test = clf.predict_proba(X_test)
        escalate_mask = (y_pred_raw == warn_idx) & (proba_test[:, warn_idx] < WARN_CONFIDENCE_THRESHOLD)
        y_pred = np.where(escalate_mask, block_idx, y_pred_raw)
        warn_escalated_count = int(escalate_mask.sum())

        acc = float(accuracy_score(y_test, y_pred))
        _log.info(
            "train: test accuracy=%.4f (escalated=%d WARNs→BLOCK) on %d samples",
            acc, warn_escalated_count, len(X_test),
        )
        report_str = classification_report(y_test, y_pred, target_names=le.classes_)
        cm = confusion_matrix(y_test, y_pred)

        cv = StratifiedKFold(
            n_splits=config.cv_folds, shuffle=True, random_state=config.random_state
        )

        # Cross-validation: get out-of-fold (OOF) probabilities so the same
        # escalation gate can be applied, keeping CV accuracy comparable to
        # test accuracy. cross_val_predict fits a fresh model on each fold and
        # returns predictions only for the held-out samples, in dataset order.
        cv_proba = cross_val_predict(clf, X_train, y_train, cv=cv, method="predict_proba")
        cv_pred_raw = np.argmax(cv_proba, axis=1)
        cv_escalate_mask = (cv_pred_raw == warn_idx) & (cv_proba[:, warn_idx] < WARN_CONFIDENCE_THRESHOLD)
        cv_pred_esc = np.where(cv_escalate_mask, block_idx, cv_pred_raw)

        # Compute per-fold accuracy from the OOF predictions to get mean ± std.
        # val_idx indexes into X_train/y_train, which matches the OOF array order.
        cv_scores = np.array([
            accuracy_score(y_train[val_idx], cv_pred_esc[val_idx])
            for _, val_idx in cv.split(X_train, y_train)
        ])

        _log.info(
            "train: CV accuracy=%.4f ± %.4f (%d-fold)",
            cv_scores.mean(), cv_scores.std(), len(cv_scores),
        )
        _log.debug("train: per-fold CV scores %s", cv_scores.tolist())

        return TrainingResult(
            config=config,
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
            warn_escalated_count=warn_escalated_count,
            warn_confidence_threshold=WARN_CONFIDENCE_THRESHOLD,
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
