"""
cli.py
======
CLI entry points for the risk-classifier toolkit.

Three independent commands are registered as separate console scripts:

    risk-classifier-label    — labeling workflow.
                               Extracts features from SBOM scan data and
                               assigns rule-based labels, writing one
                               <bucket>-labels.csv per bucket. Run once
                               after scanning to freeze labels for
                               reproducible training.

    risk-classifier-train    — data-science / model-development workflow.
                               Loads SBOM scan data (or pre-labeled CSVs),
                               trains a Decision Tree, and writes pkl
                               artifacts, a text report, visualizations,
                               and a dataset snapshot to an output directory.

    risk-classifier-predict  — CI/CD / runtime workflow.
                               Loads saved model artifacts and classifies one
                               or more CycloneDX SBOM files, writing
                               ALLOW/WARN/BLOCK predictions to stdout or a
                               file in JSON or CSV format.

The three entry points are intentionally separate because they serve different
users: pipeline operators label once after scanning, model developers train
on demand, and CI/CD consumers only need to point at an SBOM and an artifact
directory.

Both commands share the --log-level / --log-file logging flags defined in
_add_logging_args() and the _configure_logging() setup function.

Usage (from ml-classifier/ after pip install -e .):

    # Train on all three label buckets
    risk-classifier-train \\
        --manifests-dir data/image-lists/ \\
        --data-root data/scans/ \\
        --output-dir analysis/

    # Predict from a single SBOM file
    risk-classifier-predict \\
        --sbom data/scans/high-qual/alpine-3.18.json \\
        --artifact-dir analysis/ \\
        --format json

    # Predict from a directory of SBOMs, write CSV to file
    risk-classifier-predict \\
        --sbom data/scans/high-qual/ \\
        --artifact-dir analysis/ \\
        --format csv \\
        --output results.csv
"""

import json
import logging
import sys
from argparse import (
    ArgumentDefaultsHelpFormatter,
    ArgumentParser,
    ArgumentTypeError,
    Namespace,
)
from pathlib import Path

from classifier import sbom_extractor as _extractor
from classifier.data_loader import BUCKET_LABEL_MAP, load_bucket, load_dataset_from_labels, write_labels_csv, write_labels_json
from classifier.predictor import Predictor
from classifier.trainer import Trainer, TrainingConfig


# ---------------------------------------------------------------------------
# Argument-type validators
# ---------------------------------------------------------------------------

def _add_logging_args(parser) -> None:
    """Add --log-level and --log-file arguments to a subparser."""
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        metavar="LEVEL",
        help="Logging verbosity (default: INFO). INFO is sufficient for auditing; DEBUG shows per-feature detail.",
    )
    parser.add_argument(
        "--log-file",
        type=Path,
        default=None,
        metavar="FILE",
        help="Also write log records to this file (in addition to stdout).",
    )


def _configure_logging(level_str: str, log_file: "Path | None") -> None:
    """
    Configure the root 'classifier' logger for CLI use.

    Replaces the NullHandler installed by __init__.py with a StreamHandler
    writing to stdout at the requested level, plus an optional FileHandler
    when --log-file is given.
    """
    LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    level = getattr(logging, level_str)

    pkg_logger = logging.getLogger("classifier")
    pkg_logger.setLevel(level)
    pkg_logger.handlers.clear()

    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setLevel(level)
    stdout_handler.setFormatter(logging.Formatter(LOG_FORMAT))
    pkg_logger.addHandler(stdout_handler)

    if log_file is not None:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(level)
        file_handler.setFormatter(logging.Formatter(LOG_FORMAT))
        pkg_logger.addHandler(file_handler)


_VALID_CLASS_NAMES = {"ALLOW", "WARN", "BLOCK"}


def _parse_class_weight(raw: str):
    """
    Parse and validate the --class-weight argument.

    Accepts either:
      - A string shorthand accepted by sklearn (e.g. "balanced")
      - A JSON object mapping class names to positive weights
        (e.g. '{"ALLOW":1,"WARN":2,"BLOCK":4}')

    Raises ArgumentTypeError for malformed JSON objects, unknown class
    names, or non-positive weight values.
    """
    try:
        parsed = json.loads(raw)
    except (ValueError, TypeError):
        # Not valid JSON — treat as a string shorthand (e.g. "balanced")
        return raw

    if not isinstance(parsed, dict):
        raise ArgumentTypeError(
            f"--class-weight must be a JSON object or a string like 'balanced', "
            f"got {type(parsed).__name__}"
        )

    unknown = set(parsed.keys()) - _VALID_CLASS_NAMES
    if unknown:
        raise ArgumentTypeError(
            f"--class-weight contains unknown class names: {sorted(unknown)}. "
            f"Valid names are: {sorted(_VALID_CLASS_NAMES)}"
        )

    for cls, w in parsed.items():
        if not isinstance(w, (int, float)) or w <= 0:
            raise ArgumentTypeError(
                f"--class-weight values must be positive numbers; "
                f"got {cls!r}: {w!r}"
            )

    return parsed


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
# Argument parsing — one dedicated parser per entry point
# ---------------------------------------------------------------------------

def _parse_train_args() -> Namespace:
    """
    Parse arguments for the risk-classifier-train entry point.

    Returns:
        Parsed Namespace with all training configuration fields.
    """
    parser = ArgumentParser(
        prog="risk-classifier-train",
        description="Risk-Aware Supply Chain Security — Train the Decision Tree classifier.",
        formatter_class=ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--labels-dir",
        type=_existing_dir,
        required=True,
        metavar="DIR",
        help=(
            "Directory containing pre-labeled CSVs written by risk-classifier-label "
            "(high-qual-labels.csv, aged-stale-labels.csv, known-vuln-labels.csv). "
            "Run 'make label' to generate these before training."
        ),
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("training-runs"),
        metavar="DIR",
        help="Directory to write pkl artifacts, PNG plots, and the text report.",
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        default=5,
        metavar="N",
        help="Maximum depth of the Decision Tree.",
    )
    parser.add_argument(
        "--min-samples-split",
        type=int,
        default=4,
        metavar="N",
        help="Minimum samples required to split an internal node.",
    )
    parser.add_argument(
        "--min-samples-leaf",
        type=int,
        default=2,
        metavar="N",
        help="Minimum samples required to be at a leaf node.",
    )
    parser.add_argument(
        "--test-size",
        type=float,
        default=0.20,
        metavar="FRAC",
        help="Fraction of the dataset to hold out for testing (0 < FRAC < 1).",
    )
    parser.add_argument(
        "--random-state",
        type=int,
        default=42,
        metavar="N",
        help="Random seed for reproducibility.",
    )
    parser.add_argument(
        "--class-weight",
        type=_parse_class_weight,
        default="balanced",
        metavar="SCHEME",
        help=(
            'Class weight scheme passed to DecisionTreeClassifier. '
            'Use "balanced" for inverse-frequency weighting, '
            'or a JSON dict like \'{"ALLOW":1,"WARN":2,"BLOCK":4}\' for manual weights.'
        ),
    )
    parser.add_argument(
        "--no-plots",
        action="store_true",
        default=False,
        help="Skip saving visualization PNGs.",
    )
    parser.add_argument(
        "--no-report",
        action="store_true",
        default=False,
        help="Skip saving the text classification report.",
    )
    _add_logging_args(parser)
    return parser.parse_args()


def _parse_predict_args() -> Namespace:
    """
    Parse arguments for the risk-classifier-predict entry point.

    Returns:
        Parsed Namespace with all prediction configuration fields.
    """
    parser = ArgumentParser(
        prog="risk-classifier-predict",
        description="Risk-Aware Supply Chain Security — Classify SBOM files using a trained model.",
        formatter_class=ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--sbom",
        type=_existing_file_or_dir,
        required=True,
        metavar="PATH",
        help="Path to a CycloneDX JSON SBOM file or a directory of SBOM files.",
    )
    parser.add_argument(
        "--artifact-dir",
        type=_existing_dir,
        required=True,
        metavar="DIR",
        help="Directory containing decision_tree_model.pkl, label_encoder.pkl, feature_names.pkl.",
    )
    parser.add_argument(
        "--format",
        choices=["json", "csv"],
        default="json",
        dest="output_format",
        help="Output format for predictions.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        metavar="FILE",
        help="Write output to this file instead of stdout.",
    )
    _add_logging_args(parser)
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Subcommand handlers
# ---------------------------------------------------------------------------

def _run_train(args: Namespace) -> None:
    """Execute the train subcommand."""
    _log = logging.getLogger(__name__)

    config = TrainingConfig(
        max_depth=args.max_depth,
        min_samples_split=args.min_samples_split,
        min_samples_leaf=args.min_samples_leaf,
        test_size=args.test_size,
        random_state=args.random_state,
        class_weight=args.class_weight,
    )
    _log.info(
        "train: hyperparameters max_depth=%s min_samples_split=%d min_samples_leaf=%d "
        "test_size=%.2f random_state=%d class_weight=%s",
        config.max_depth, config.min_samples_split, config.min_samples_leaf,
        config.test_size, config.random_state, config.class_weight,
    )

    _log.info("train: loading dataset from labels: %s", args.labels_dir)
    df = load_dataset_from_labels(args.labels_dir)
    _log.info("train: dataset loaded — %d images, %d buckets", len(df), df["bucket"].nunique())
    _log.info(
        "train: label distribution\n%s",
        df.groupby(["bucket", "rule_label"]).size().unstack(fill_value=0).to_string(),
    )

    _log.info("train: fitting Decision Tree classifier")
    trainer = Trainer(df, config)
    result = trainer.train()

    cv_mean = result.cv_scores.mean()
    cv_std = result.cv_scores.std()
    _log.info(
        "train: test_accuracy=%.4f CV=%.4f±%.4f (%d-fold)",
        result.test_accuracy, cv_mean, cv_std, len(result.cv_scores),
    )
    _log.info("train: classification report\n%s", result.class_report_str)

    _log.info("train: saving artifacts to %s", args.output_dir)
    trainer.save_artifacts(result, args.output_dir)

    write_labels_csv(df, args.output_dir / "dataset_snapshot.csv")
    write_labels_json(df, args.output_dir / "dataset_snapshot.json")
    _log.info("train: dataset snapshot saved to %s (.csv + .json)", args.output_dir)

    if not args.no_report:
        report_path = result.write_report(args.output_dir)
        _log.info("train: report saved to %s", report_path)

    if not args.no_plots:
        _log.info("train: saving visualizations")
        png_paths = result.save_visualizations(df, args.output_dir)
        for p in png_paths:
            _log.info("train: visualization saved → %s", p)

    _log.info("train: done")


def _run_predict(args: Namespace) -> None:
    """Execute the predict subcommand."""
    _log = logging.getLogger(__name__)

    predictor = Predictor(args.artifact_dir)
    _log.info("predict: loaded artifacts from %s", args.artifact_dir)

    sbom_pairs = _extractor.read_path_data(args.sbom)

    rows = []
    for file_path, sbom in sbom_pairs:
        try:
            metric = _extractor.build_security_metric_from_sbom(str(file_path), sbom)
        except Exception as exc:
            _log.warning("predict: feature extraction failed for %s: %s", file_path, exc)
            continue

        prediction = predictor.predict(metric)
        row = {**metric.__dict__, "ml_label": prediction.label}
        if prediction.confidence is not None:
            row["ml_confidence"] = round(prediction.confidence, 4)
        rows.append(row)

    if not rows:
        _log.error("predict: no predictions produced — all SBOMs failed extraction")
        sys.exit(1)

    _log.info(
        "predict: processed %d SBOMs — format=%s destination=%s",
        len(rows), args.output_format, str(args.output) if args.output else "stdout",
    )

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
        _log.info("predict: predictions written to %s", args.output)
    else:
        print(output_text)


def _parse_label_args() -> Namespace:
    """
    Parse arguments for the risk-classifier-label entry point.

    Returns:
        Parsed Namespace with manifests_dir, data_root, output_dir, and logging fields.
    """
    parser = ArgumentParser(
        prog="risk-classifier-label",
        description=(
            "Risk-Aware Supply Chain Security — Extract features and assign rule labels "
            "from SBOM scan data. Writes one <bucket>-labels.csv per bucket to --output-dir "
            "so that subsequent training runs consume frozen, reproducible labels."
        ),
        formatter_class=ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--manifests-dir",
        type=_existing_dir,
        required=True,
        metavar="DIR",
        help="Directory containing high-qual.csv, aged-stale.csv, known-vuln.csv.",
    )
    parser.add_argument(
        "--data-root",
        type=_existing_dir,
        required=True,
        metavar="DIR",
        help="Root directory containing SBOM JSON files (organised by bucket subdir).",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        metavar="DIR",
        help="Directory to write per-bucket label CSVs (default: same as --data-root).",
    )
    _add_logging_args(parser)
    return parser.parse_args()


def _run_label(args: Namespace) -> None:
    """Execute the label subcommand."""
    _log = logging.getLogger(__name__)
    output_dir = args.output_dir if args.output_dir is not None else args.data_root

    for bucket_name in BUCKET_LABEL_MAP:
        manifest_csv = args.manifests_dir / f"{bucket_name}.csv"
        df = load_bucket(manifest_csv, bucket_name, args.data_root)
        if df.empty:
            _log.warning("label: bucket '%s' produced no records — skipping CSV write", bucket_name)
            continue
        out_path = output_dir / f"{bucket_name}-labels.csv"
        write_labels_csv(df, out_path)
        _log.info("label: bucket='%s' — %d records written to %s", bucket_name, len(df), out_path)

    _log.info("label: done")


# ---------------------------------------------------------------------------
# Entry points — registered as separate console scripts in pyproject.toml
# ---------------------------------------------------------------------------

def main_label() -> None:
    """
    Entry point for the risk-classifier-label command.

    Intended user: data scientists and pipeline operators who want reproducible
    training labels. Run once after scanning (or after threshold changes) to
    freeze feature values and rule labels into per-bucket CSVs. These CSVs are
    consumed by risk-classifier-train via --labels-dir.
    """
    args = _parse_label_args()
    _configure_logging(args.log_level, args.log_file)
    _run_label(args)


def main_train() -> None:
    """
    Entry point for the risk-classifier-train command.

    Intended user: data scientists and model developers who maintain and
    retrain the Decision Tree on updated SBOM scan datasets.
    """
    args = _parse_train_args()
    _configure_logging(args.log_level, args.log_file)
    _run_train(args)


def main_predict() -> None:
    """
    Entry point for the risk-classifier-predict command.

    Intended user: CI/CD pipeline operators and security engineers who
    classify container images at build or deploy time using a pre-trained
    model artifact.
    """
    args = _parse_predict_args()
    _configure_logging(args.log_level, args.log_file)
    _run_predict(args)
