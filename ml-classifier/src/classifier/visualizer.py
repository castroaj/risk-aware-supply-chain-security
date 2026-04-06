"""
visualizer.py
=============
Visualization functions that produce PNG artifacts from a completed training run.

All functions are pure given a TrainingResult (and optionally a DataFrame) and
an output path — no model loading, no training. Each function creates, saves,
and closes its figure so callers do not need to manage matplotlib state.

Four outputs:
    confusion_matrix.png         — heatmap of test-set predictions
    decision_tree.png            — rendered decision tree (max_depth=5)
    feature_importances.png      — bar chart of Gini importances (descending)
    feature_correlation_matrix.png — lower-triangle Pearson correlation heatmap
"""

from pathlib import Path
from typing import List

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import ConfusionMatrixDisplay
from sklearn.tree import plot_tree

from .results import TrainingResult
import sbom_extractor as _extractor

# Short axis labels for the correlation heatmap so axis text doesn't overlap.
_SHORT_LABELS = [
    "dep_count", "vuln_total", "crit_cve", "high_cve",
    "cvss≥7", "max_cvss", "uniq_cwe", "top25_cwe", "img_age_days",
]


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

    corr = df[_extractor.FEATURES].corr()

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
