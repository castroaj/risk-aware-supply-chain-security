"""
llm_labeler.py
==============
LLM-based labeling logic for SBOM security classification.

This module owns three concerns:
    1. load_system_prompt() — loads the labeling rubric from a versioned text
       file in config/. Defaults to the latest version via DEFAULT_SYSTEM_PROMPT_PATH.
    2. build_user_message() — converts a SecurityMetric into a compact JSON
       user message (~80–120 tokens) without ever sending raw SBOM content.
    3. parse_llm_response() — converts the model's raw text reply into a
       structured LabelResult, with graceful fallback on malformed output.

The actual LLM API call lives in the backend (e.g. AnthropicBackend.complete).
This module has no knowledge of which provider is used.

System prompt versioning:
    Prompt files live in config/system-prompt-vN.txt relative to the package root.
    The DEFAULT_SYSTEM_PROMPT_PATH constant points to the latest version.
    Changing the prompt file is a labeling-breaking change — commit the updated
    file, regenerate label CSVs, and bump the model version.

Token budget per image (approximate):
    System prompt : ~600 tokens
    User message  : ~80–120 tokens
    Response      : ~150–200 tokens
    -----------------------------------------------
    Total per call: ~750 in / ~175 out
"""

import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .sbom_extractor import SecurityMetric, LabelResult

_log = logging.getLogger(__name__)

# Root of the ml-classifier project (three levels up from this file:
# src/classifier/llm_labeler.py → src/classifier/ → src/ → ml-classifier/)
_PROJECT_ROOT = Path(__file__).parent.parent.parent

# Path to the latest versioned system prompt file.
# Update this constant when a new prompt version is added to config/.
DEFAULT_SYSTEM_PROMPT_PATH: Path = _PROJECT_ROOT / "config" / "system-prompt-v1.txt"


def load_system_prompt(path: Path = DEFAULT_SYSTEM_PROMPT_PATH) -> str:
    """
    Load the LLM labeling system prompt from a versioned text file.

    WHAT:
        Reads and returns the contents of the given prompt file. Raises
        FileNotFoundError with a clear message if the file does not exist,
        so misconfigured paths fail loudly before any API calls are made.

    WHY:
        Externalizing the prompt to a file means changes are visible as a
        plain-text git diff rather than buried in Python source. The versioned
        filename (system-prompt-v1.txt, v2.txt, ...) makes it explicit when
        the labeling rubric has changed and a re-labeling run is required.

    Args:
        path: Path to the system prompt file. Defaults to DEFAULT_SYSTEM_PROMPT_PATH
              (the latest version in config/).

    Returns:
        The full text of the system prompt, stripped of trailing whitespace.
    """
    if not path.exists():
        raise FileNotFoundError(
            f"System prompt file not found: {path}\n"
            "Ensure config/system-prompt-vN.txt exists or pass a valid --system-prompt path."
        )
    text = path.read_text(encoding="utf-8").rstrip()
    _log.debug("load_system_prompt: loaded %d chars from %s", len(text), path)
    return text


def build_user_message(metric: "SecurityMetric") -> str:
    """
    Convert a SecurityMetric feature vector into a compact JSON user message.

    WHAT:
        Serialises only the 8 numeric feature fields into a JSON string.
        The scan_file path is included as an identifier but no raw SBOM
        content, CVE descriptions, or component lists are ever included.

    WHY:
        Keeps the user message to ~80–120 tokens regardless of the underlying
        SBOM file size (which can be 50–500 KB). Token efficiency is critical
        when labeling 100+ images in a single run.

    Args:
        metric: A fully-populated SecurityMetric from build_security_metric_from_sbom().

    Returns:
        A compact JSON string ready to pass as the user message to backend.complete().
    """
    payload = {
        "image": metric.scan_file,
        "features": {
            "total_dependency_count": metric.total_dependency_count,
            "vuln_total":             metric.vuln_total,
            "critical_cve_count":     metric.critical_cve_count,
            "high_cve_count":         metric.high_cve_count,
            "cvss_ge_7_count":        metric.cvss_ge_7_count,
            "max_cvss":               metric.max_cvss,
            "unique_cwe_count":       metric.unique_cwe_count,
            "top25_cwe_count":        metric.top25_cwe_count,
        },
    }
    return json.dumps(payload, separators=(",", ":"))


def parse_llm_response(raw: str) -> "LabelResult":
    """
    Parse raw LLM response text into a structured LabelResult.

    WHAT:
        Strips any markdown code fences, parses the JSON payload, validates
        the label field, and merges key_signals into the justification string
        for a single-column persistence format. On any parse failure, returns
        a WARN label with low confidence and the error as the justification —
        so the label is always usable without crashing the labeling run.

    WHY:
        A single malformed response should not abort the entire labeling run
        for 100+ images. WARN is the safest fallback — it flags the image for
        human review without either silently allowing a risky image or
        over-blocking a safe one.

    Args:
        raw: Raw text returned by backend.complete().

    Returns:
        LabelResult with label, justification, and confidence populated.
    """
    from .sbom_extractor import LabelResult

    # Strip markdown code fences the model may emit despite instructions
    text = raw.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        # Drop the opening fence line and the closing ``` if present
        inner_lines = lines[1:]
        if inner_lines and inner_lines[-1].strip() == "```":
            inner_lines = inner_lines[:-1]
        text = "\n".join(inner_lines).strip()

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        _log.error("parse_llm_response: JSON parse failed (%s) — raw=%r", exc, raw[:300])
        return LabelResult(
            label="WARN",
            justification=f"LLM response could not be parsed as JSON: {exc}",
            confidence="low",
        )

    # Validate and normalise label
    label = str(data.get("label", "WARN")).strip().upper()
    if label not in {"ALLOW", "WARN", "BLOCK"}:
        _log.warning("parse_llm_response: unexpected label %r — defaulting to WARN", label)
        label = "WARN"

    justification = data.get("justification") or None
    confidence = data.get("confidence")

    _log.info("parse_llm_response: label=%s confidence=%s justification=%s", label, confidence, justification)
    return LabelResult(label=label, justification=justification or None, confidence=confidence)
