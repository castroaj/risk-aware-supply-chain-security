"""
results.py
==========
Data classes for classifier configuration and training output.

    TrainingConfig  — hyperparameters and split settings
    TrainingResult  — output bundle from a completed training run, with
                      methods for visualization and reporting

Separated from trainer.py so that visualizer.py and reporting.py can import
TrainingResult without creating a circular dependency.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Dict, List

import numpy as np
from sklearn.preprocessing import LabelEncoder
from sklearn.tree import DecisionTreeClassifier

if TYPE_CHECKING:
    import pandas as pd


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

        WHAT:
            Delegates to reporting.write_classification_report(). See that function
            for the full section breakdown.

        Args:
            output_dir: Directory to write classification_report.txt into.

        Returns:
            Path of the written file.
        """
        from .reporting import write_classification_report  # lazy — avoids circular import
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
        from .visualizer import plot_confusion_matrix  # lazy — avoids circular import
        return plot_confusion_matrix(self, output_dir)

    def plot_decision_tree(self, output_dir: Path) -> Path:
        """
        Render the fitted decision tree.

        Args:
            output_dir: Directory to write decision_tree.png into.

        Returns:
            Path of the saved PNG file.
        """
        from .visualizer import plot_decision_tree  # lazy — avoids circular import
        return plot_decision_tree(self, output_dir)

    def plot_feature_importances(self, output_dir: Path) -> Path:
        """
        Render a bar chart of Gini feature importances in descending order.

        Args:
            output_dir: Directory to write feature_importances.png into.

        Returns:
            Path of the saved PNG file.
        """
        from .visualizer import plot_feature_importances  # lazy — avoids circular import
        return plot_feature_importances(self, output_dir)

    # ------------------------------------------------------------------
    # Visualization — full suite
    # ------------------------------------------------------------------

    def save_visualizations(self, df: "pd.DataFrame", output_dir: Path) -> List[Path]:
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
        from .visualizer import save_all  # lazy — avoids circular import
        return save_all(self, df, output_dir)
