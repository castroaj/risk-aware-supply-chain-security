"""
cli.py
======
Command-line interface for the risk classifier package.

Two subcommands:

    train   — Load SBOM scan data, train a Decision Tree, save artifacts and reports.
    predict — Load saved model artifacts, classify one or more SBOM files.

Usage (run from the ml-classifier/ directory):

    # Train on all three buckets
    python src/classifier/cli.py train \\
        --manifests-dir data/image-lists/ \\
        --data-root data/scans/ \\
        --output-dir analysis/

    # Predict from a single SBOM file
    python src/classifier/cli.py predict \\
        --sbom data/scans/high-qual/alpine-3.18.json \\
        --artifact-dir analysis/ \\
        --format json

    # Predict from a directory of SBOMs, write CSV to file
    python src/classifier/cli.py predict \\
        --sbom data/scans/high-qual/ \\
        --artifact-dir analysis/ \\
        --format csv \\
        --output results.csv
"""

import json
import sys
from argparse import (
    ArgumentDefaultsHelpFormatter,
    ArgumentParser,
    ArgumentTypeError,
    Namespace,
)
from pathlib import Path

# Add src/ to sys.path so that `import classifier` works when this script
# is run directly (python src/classifier/cli.py) without installation.
_SRC_DIR = Path(__file__).parent.parent
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

from classifier import sbom_extractor as _extractor
from classifier.data_loader import load_dataset
from classifier.predictor import Predictor
from classifier.trainer import Trainer, TrainingConfig


# ---------------------------------------------------------------------------
# Argument-type validators
# ---------------------------------------------------------------------------

def _existing_dir(value: str) -> Path:
    """Validate that a CLI argument is an existing directory."""
    path = Path(value)
    if not path.is_dir():
        raise ArgumentTypeError(f"Directory not found: {value}")
    return path


def _existing_file_or_dir(value: str) -> Path:
    """Validate that a CLI argument is an existing file or directory."""
    path = Path(value)
    if not path.exists():
        raise ArgumentTypeError(f"Path does not exist: {value}")
    if not (path.is_file() or path.is_dir()):
        raise ArgumentTypeError(f"Path is neither a file nor a directory: {value}")
    return path


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def parse_args() -> Namespace:
    """
    Parse CLI arguments for the train and predict subcommands.

    Returns:
        Parsed Namespace. The 'subcommand' attribute is either 'train' or 'predict'.
    """
    parser = ArgumentParser(
        prog="python src/classifier/cli.py",
        description="Risk-Aware Supply Chain Security — ML Classifier",
        formatter_class=ArgumentDefaultsHelpFormatter,
    )
    sub = parser.add_subparsers(dest="subcommand", required=True)

    # --- train ---
    train_p = sub.add_parser(
        "train",
        help="Train the Decision Tree classifier on SBOM scan data.",
        formatter_class=ArgumentDefaultsHelpFormatter,
    )
    train_p.add_argument(
        "--manifests-dir",
        type=_existing_dir,
        required=True,
        metavar="DIR",
        help="Directory containing high-qual.csv, aged-stale.csv, known-vuln.csv.",
    )
    train_p.add_argument(
        "--data-root",
        type=_existing_dir,
        required=True,
        metavar="DIR",
        help="Root directory containing SBOM JSON files (organised by bucket subdir).",
    )
    train_p.add_argument(
        "--output-dir",
        type=Path,
        default=Path("analysis"),
        metavar="DIR",
        help="Directory to write pkl artifacts, PNG plots, and the text report.",
    )
    train_p.add_argument(
        "--max-depth",
        type=int,
        default=5,
        metavar="N",
        help="Maximum depth of the Decision Tree.",
    )
    train_p.add_argument(
        "--min-samples-split",
        type=int,
        default=4,
        metavar="N",
        help="Minimum samples required to split an internal node.",
    )
    train_p.add_argument(
        "--min-samples-leaf",
        type=int,
        default=2,
        metavar="N",
        help="Minimum samples required to be at a leaf node.",
    )
    train_p.add_argument(
        "--test-size",
        type=float,
        default=0.20,
        metavar="FRAC",
        help="Fraction of the dataset to hold out for testing (0 < FRAC < 1).",
    )
    train_p.add_argument(
        "--random-state",
        type=int,
        default=42,
        metavar="N",
        help="Random seed for reproducibility.",
    )
    train_p.add_argument(
        "--no-plots",
        action="store_true",
        default=False,
        help="Skip saving visualization PNGs.",
    )
    train_p.add_argument(
        "--no-report",
        action="store_true",
        default=False,
        help="Skip saving the text classification report.",
    )

    # --- predict ---
    predict_p = sub.add_parser(
        "predict",
        help="Classify one or more SBOMs using a trained model.",
        formatter_class=ArgumentDefaultsHelpFormatter,
    )
    predict_p.add_argument(
        "--sbom",
        type=_existing_file_or_dir,
        required=True,
        metavar="PATH",
        help="Path to a CycloneDX JSON SBOM file or a directory of SBOM files.",
    )
    predict_p.add_argument(
        "--artifact-dir",
        type=_existing_dir,
        required=True,
        metavar="DIR",
        help="Directory containing decision_tree_model.pkl, label_encoder.pkl, feature_names.pkl.",
    )
    predict_p.add_argument(
        "--format",
        choices=["json", "csv"],
        default="json",
        dest="output_format",
        help="Output format for predictions.",
    )
    predict_p.add_argument(
        "--output",
        type=Path,
        default=None,
        metavar="FILE",
        help="Write output to this file instead of stdout.",
    )

    return parser.parse_args()


# ---------------------------------------------------------------------------
# Subcommand handlers
# ---------------------------------------------------------------------------

def _run_train(args: Namespace) -> None:
    """Execute the train subcommand."""
    config = TrainingConfig(
        max_depth=args.max_depth,
        min_samples_split=args.min_samples_split,
        min_samples_leaf=args.min_samples_leaf,
        test_size=args.test_size,
        random_state=args.random_state,
    )

    print(f"Loading dataset from manifests: {args.manifests_dir}")
    df = load_dataset(args.manifests_dir, args.data_root)
    print(f"Loaded {len(df)} images across {df['bucket'].nunique()} buckets.")
    print(df.groupby(["bucket", "rule_label"]).size().unstack(fill_value=0))

    print("\nTraining Decision Tree classifier...")
    trainer = Trainer(df, config)
    result = trainer.train()

    print(f"\nTest Accuracy : {result.test_accuracy:.4f}")
    cv_mean = result.cv_scores.mean()
    cv_std = result.cv_scores.std()
    print(f"CV Accuracy   : {cv_mean:.4f} ± {cv_std:.4f} ({len(result.cv_scores)}-fold)")
    print("\nClassification Report:")
    print(result.class_report_str)

    print(f"\nSaving model artifacts to {args.output_dir}/")
    trainer.save_artifacts(result, args.output_dir)

    if not args.no_report:
        report_path = result.write_report(args.output_dir)
        print(f"Report saved → {report_path}")

    if not args.no_plots:
        print("Saving visualizations...")
        png_paths = result.save_visualizations(df, args.output_dir)
        for p in png_paths:
            print(f"  → {p}")

    print("\nDone.")


def _run_predict(args: Namespace) -> None:
    """Execute the predict subcommand."""
    predictor = Predictor(args.artifact_dir)

    sbom_pairs = _extractor.read_path_data(args.sbom)

    rows = []
    for file_path, sbom in sbom_pairs:
        try:
            metric = _extractor.build_security_metric_from_sbom(str(file_path), sbom)
        except Exception as exc:
            print(f"[WARN] feature extraction failed for {file_path}: {exc}", file=sys.stderr)
            continue

        prediction = predictor.predict(metric)
        row = {**metric.__dict__, "ml_label": prediction.label}
        if prediction.confidence is not None:
            row["ml_confidence"] = round(prediction.confidence, 4)
        rows.append(row)

    if not rows:
        print("[ERROR] No predictions produced.", file=sys.stderr)
        sys.exit(1)

    if args.output_format == "json":
        output_text = json.dumps(rows, indent=2)
    else:
        import csv
        import io
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
        output_text = buf.getvalue()

    if args.output:
        args.output.write_text(output_text, encoding="utf-8")
        print(f"Predictions written to {args.output}")
    else:
        print(output_text)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    args = parse_args()
    if args.subcommand == "train":
        _run_train(args)
    elif args.subcommand == "predict":
        _run_predict(args)


if __name__ == "__main__":
    main()
