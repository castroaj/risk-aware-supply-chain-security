"""
llm_labeler.py
==============
LLM-based labeling logic for SBOM security classification.

This module owns three concerns:
    1. SYSTEM_PROMPT — the labeling rubric sent to the LLM on every call.
    2. build_user_message() — converts a SecurityMetric into a compact JSON
       user message (~80–120 tokens) without ever sending raw SBOM content.
    3. parse_llm_response() — converts the model's raw text reply into a
       structured LabelResult, with graceful fallback on malformed output.

The actual LLM API call lives in the backend (e.g. AnthropicBackend.complete).
This module has no knowledge of which provider is used.

Token budget per image (approximate):
    System prompt : ~600 tokens
    User message  : ~80–120 tokens
    Response      : ~150–200 tokens
    -----------------------------------------------
    Total per call: ~750 in / ~175 out
"""

import json
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .sbom_extractor import SecurityMetric, LabelResult

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# System prompt — versioned labeling rubric sent to the LLM on every call.
# Treat this as an immutable artifact for a given model version: changes here
# should trigger a full re-labeling run and a new model version commit.
# Version: v1
# ---------------------------------------------------------------------------
SYSTEM_PROMPT = """\
You are a supply chain security analyst responsible for classifying container \
images based on their vulnerability and dependency profiles. You will be given \
a structured feature vector extracted from a CycloneDX SBOM scan produced by Trivy.

Your task is to assign one of three deployment risk labels:
  ALLOW — The image meets acceptable security standards and may be deployed.
  WARN  — The image has moderate risk. It should be reviewed before deployment \
and may require remediation.
  BLOCK — The image has critical or systemic risk and must not be deployed \
without explicit security team approval and a remediation plan.

## Feature Definitions

Each feature vector contains exactly these fields:

| Feature                | Description                                                                  |
|------------------------|------------------------------------------------------------------------------|
| total_dependency_count | Total number of software components declared in the SBOM                     |
| vuln_total             | Total number of vulnerabilities detected across all components               |
| critical_cve_count     | Number of CVEs rated CRITICAL severity (highest across all rating sources)   |
| high_cve_count         | Number of CVEs rated HIGH severity                                           |
| cvss_ge_7_count        | Number of vulnerabilities with a CVSS score >= 7.0                           |
| max_cvss               | Highest single CVSS score found in the scan                                  |
| unique_cwe_count       | Number of distinct CWE weakness types present                                |
| top25_cwe_count        | Number of vulnerabilities matching the MITRE CWE Top 25 (2025 list)         |

## Labeling Guidance

Evaluate the full feature vector holistically. Do not evaluate any single \
feature in isolation.

BLOCK when:
- One or more CRITICAL CVEs exist alongside systemic weakness breadth (elevated \
unique_cwe_count or top25_cwe_count), suggesting the image is broadly \
compromised, not just incidentally vulnerable.
- The max_cvss is near or at 10.0 and is accompanied by a non-trivial \
critical_cve_count, indicating a directly exploitable, high-impact vulnerability.
- The combination of vuln_total, high_cve_count, and top25_cwe_count together \
indicate a pattern of known, actively exploited weaknesses at scale.

WARN when:
- The image has no CRITICAL CVEs but has multiple HIGH CVEs or a non-trivial \
cvss_ge_7_count, suggesting actionable but not immediately catastrophic risk.
- The unique_cwe_count or top25_cwe_count is elevated relative to \
total_dependency_count, indicating a disproportionate weakness density.
- The max_cvss is in the 7.0–9.9 range without accompanying CRITICAL counts.

ALLOW when:
- No CRITICAL CVEs are present, HIGH CVEs are minimal or absent, and max_cvss \
is below 7.0.
- Any vulnerabilities present are low-severity, low-density, and not part of \
the MITRE Top 25.

## Output Format

Respond only with a valid JSON object. Do not include any text outside the \
JSON block. Do not wrap the JSON in markdown code fences.

{
  "label": "ALLOW" | "WARN" | "BLOCK",
  "confidence": "high" | "medium" | "low",
  "justification": "<1-2 sentences citing specific numeric feature values from the input and why they indicate this risk level. Max 50 words.>"
}

The justification must reference specific feature values from the input. \
Do not produce generic reasoning.\
"""


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
