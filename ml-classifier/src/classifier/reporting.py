"""
reporting.py
============
Text report generation for a completed training run.

Produces classification_report.txt from a TrainingResult, including dataset
summary, accuracy metrics, the sklearn classification report, and the full
decision tree rules in text form.
"""

from pathlib import Path

from sklearn.tree import export_text

from .results import TrainingResult


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

    lines = [
        "Risk-Aware Supply Chain Security — Decision Tree Classifier",
        "=" * 60,
        "",
        f"Dataset size       : {result.dataset_size} images",
        f"Train / Test split : {result.train_size} / {result.test_size_actual}",
        f"Class distribution : {class_dist_str}",
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
