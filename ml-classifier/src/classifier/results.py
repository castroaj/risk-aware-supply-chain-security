"""
results.py
==========
Data classes for classifier configuration and training output, together with
the reporting and visualization functions that operate on them.

    TrainingConfig  — hyperparameters and split settings
    TrainingResult  — output bundle from a completed training run, with
                      methods for visualization and reporting

Visualization outputs (all saved as PNG):
    confusion_matrix.png             — heatmap of test-set predictions
    decision_tree.png                — rendered decision tree (max_depth=5)
    feature_importances.png          — bar chart of Gini importances (descending)
    feature_correlation_matrix.png   — lower-triangle Pearson correlation heatmap

Text report output:
    classification_report.txt        — dataset summary, accuracy metrics, sklearn
                                       classification report, decision tree rules
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import ConfusionMatrixDisplay
from sklearn.preprocessing import LabelEncoder
from sklearn.tree import DecisionTreeClassifier, export_text, plot_tree

from .sbom_extractor import FEATURES


# Short axis labels for the correlation heatmap so axis text doesn't overlap.
_SHORT_LABELS = [
    "dep_count", "vuln_total", "crit_cve", "high_cve",
    "cvss≥7", "max_cvss", "uniq_cwe", "top25_cwe", "img_age_days",
]


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
    class_weight: str = "balanced"
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
          2. Test Accuracy (scalar, 4 decimal places)
          3. CV Accuracy (mean ± std across cv_folds folds)
          4. Full sklearn classification report (precision, recall, F1 per class)
          5. Decision Tree Rules (export_text representation of the fitted tree)

    WHY:
        Isolated from trainer.py so the report format can be changed without
        touching training logic, and so tests can verify report content without
        running a full training pipeline.

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
