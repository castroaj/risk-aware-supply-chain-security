from json import load, dumps
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter, Namespace, ArgumentTypeError
import logging
from typing import Dict, Any, Generator, List, Set, Union, Optional
from urllib.request import urlopen
from urllib.error import URLError
from dataclasses import dataclass, fields as _dataclass_fields
from datetime import datetime
from pathlib import Path
from pandas import DataFrame, concat

_log = logging.getLogger(__name__)

# Constants
JSON_OUTPUT = "json"
CSV_OUTPUT = "csv"

# Standard MITRE Top 25 CWEs (2025)
# See https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html
TOP_25_CWES:Set[int] = {
    79, 89, 352, 862, 787, 22, 416, 125, 78, 94,
    120, 434, 476, 121, 502, 122, 863, 20, 284, 200,
    306, 918, 77, 639, 770
}

# Define the severity weights as a mapping
# of severity string to value
SEVERITY_WEIGHT:Dict[str, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
    "none": 0,
    "unknown": 0
}

# Threshold constants for rule-based classification.
# Keys match SecurityMetric field names exactly.
# BLOCK is evaluated before WARN. Any single breach triggers that level.
BLOCK_THRESHOLDS: Dict[str, float] = {
    "critical_cve_count":  50.0,
    "top25_cwe_count":     150.0,
    "base_image_age_days": 2000.0,
}

WARN_THRESHOLDS: Dict[str, float] = {
    "critical_cve_count":  10.0,
    "cvss_ge_7_count":     100.0,
    "unique_cwe_count":    40.0,
    "top25_cwe_count":     50.0,
    "base_image_age_days": 365.0,
}

# Define a series of fallback labels that may allow the date extraction
# for the each containers age
_LABEL_FALLBACK_CHAIN: List[str] = [
    "aquasecurity:trivy:Labels:build-date",
    "aquasecurity:trivy:Labels:org.opencontainers.image.created",
    "aquasecurity:trivy:Labels:org.label-schema.build-date",
    "aquasecurity:trivy:Labels:com.docker.dhi.created",
]

@dataclass
class SecurityMetric:
    """
    Feature vector for the ML Risk-Based Classification Model.
    """
    # Define some metadata for the scan
    scan_file:str

    # Define the feature vector
    total_dependency_count: float
    vuln_total: float
    critical_cve_count: float
    high_cve_count: float
    cvss_ge_7_count: float
    max_cvss: float
    unique_cwe_count: float
    top25_cwe_count: float
    base_image_age_days: float

    def to_json(self) -> str:
        return dumps(self.__dict__)

    def to_csv(self) -> str:
        return (
            f"{self.scan_file},{self.total_dependency_count},{self.vuln_total},"
            f"{self.critical_cve_count},{self.high_cve_count},"
            f"{self.cvss_ge_7_count},{self.max_cvss},"
            f"{self.unique_cwe_count},{self.top25_cwe_count},"
            f"{self.base_image_age_days}"
        )

    @staticmethod
    def get_csv_header() -> str:
        return (
            "scan_file,total_dependency_count,vuln_total,critical_cve_count,"
            "high_cve_count,cvss_ge_7_count,max_cvss,unique_cwe_count,"
            "top25_cwe_count,base_image_age_days"
        )

# Ordered list of feature names derived from SecurityMetric field definitions.
# This is the single source of truth for feature ordering — used by the classifier
# package to ensure training and prediction use the same feature order.
FEATURES: List[str] = [f.name for f in _dataclass_fields(SecurityMetric) if f.name != "scan_file"]

@dataclass
class SecurityMetricsCollection:
    """
    Collection of SecurityMetric objects.
    """
    df: DataFrame = None
    def __post_init__(self):
        if self.df is None:
            self.df = DataFrame()
    def append(self, metric: SecurityMetric) -> None:
        """
        Appends a SecurityMetric object to the collection.
        """
        new_row = DataFrame([metric.__dict__])
        if self.df.empty:
            self.df = new_row
        else:
            self.df = concat([self.df, new_row], ignore_index=True)
    def to_csv(self) -> str:
        """
        Exports all metrics in the collection to a CSV string.
        """
        if self.df.empty:
            return SecurityMetric.get_csv_header()
        return self.df.to_csv(index=False).strip()
    def to_json(self) -> str:
        """
        Exports all metrics in the collection to a JSON string.
        """
        if self.df.empty:
            return "[]"
        return self.df.to_json(orient="records", indent=4)

def extract_total_dependency_count(sbom: Dict[str, Any]) -> float:
    """
    **WHAT:**
    - The `total_dependency_count` is the number of software components within the software stack.
    - It is comprised of individual components each corresponding to an individual building block of the stack.
    - This includes applications, frameworks, libraries, and containers.

    **WHY:**
    - An increase in the number of dependencies will increase the attack surface of the application.
    - An increase in the number of dependencies increases the difficultly of maintaining software, which likely leads to more developer mistakes

    **WHERE:**
    - The `total_dependency_count` is derived from the length of the `.components` JSON array contained within the SBOM file.
    """
    try:
        return float(len(sbom.get("components", [])))
    except Exception as e:
        raise RuntimeError(f"Failed to extract total_dependency_count: {e}")

def extract_vuln_total(sbom: Dict[str, Any]) -> float:
    """
    **WHAT:**
    - The `vuln_total` represents the total number of individual CVEs found within the software stack.

    **WHY:**
    - The total number of vulnerabilities is a strong indicator that a software project is poorly maintained
    - It could mean that it has not been updated recently
    - It could mean that the developer relies on a software stack that is no longer maintained
    - It could mean that the developer choose the wrong software stack

    **WHERE:**
    - The `vuln_total` is derived from the length of the `.vulnerabilities` section of JSON array contained within the SBOM file.
    """
    try:
        return float(len(sbom.get("vulnerabilities", [])))
    except Exception as e:
        raise RuntimeError(f"Failed to extract vuln_total: {e}")

def extract_critical_cve_count(sbom: Dict[str, Any]) -> float:
    """
    **WHAT:**
    - Each vulnerability contains a series of ratings from a variety of sources, each of which should provide a severity level in that authority's opinion
    - The severity level is measured with a categorical word, including `critical` which is relevant for this feature

    **WHY:**
    - Severity level is the core indicator that a CVE poses a high level of risk to a system
    - CVEs marked as `critical` should not reach a production build, unless overwhelming contrary evidence is provided

    **WHERE:**
    - The `critical_cve_count` is derived by taking the highest `severity` score from the `.vulnerabilities.{VULN}.ratings.{SOURCE}.severity`.
    - If that severity is `critical`, than this count is incremented
    """
    try:
        count = 0
        for vuln in sbom.get("vulnerabilities", []):
            sev_weight:int = _get_highest_severity(vuln.get("ratings", []))
            if sev_weight >= SEVERITY_WEIGHT.get("critical", -1):
                count += 1
        return float(count)
    except Exception as e:
        raise RuntimeError(f"Failed to extract critical_cve_count: {e}")

def extract_high_cve_count(sbom: Dict[str, Any]) -> float:
    """
    **WHAT:**
    - Each vulnerability contains a series of ratings from a variety of sources, each of which should provide a severity level in that authority's opinion
    - The severity level is measured with a categorical word, including `high` which is relevant for this feature

    **WHY:**
    - Severity level is the core indicator that a CVE poses a high level of risk to a system
    - CVEs marked as `high` should be inspected and heavily scrutinized by the development team
    - An accumulation of many `high` severity CVEs may be put your system at more risk than if a single `critical` CVE was present

    **WHERE:**
    - The `critical_cve_count` is derived by taking the highest `severity` score from the `.vulnerabilities.{VULN}.ratings.{SOURCE}.severity`.
    - If that severity is `high`, than this count is incremented
    """
    try:
        count = 0
        for vuln in sbom.get("vulnerabilities", []):
            sev_weight:int = _get_highest_severity(vuln.get("ratings", []))
            if sev_weight >= SEVERITY_WEIGHT.get("high", -1):
                count += 1
        return float(count)
    except Exception as e:
        raise RuntimeError(f"Failed to extract high_cve_count: {e}")

def extract_cvss_ge_7_count(sbom: Dict[str, Any]) -> float:
    """
    **WHAT:**
    - Each vulnerability contains a series of ratings from a variety of sources, each of which should provide a CVSS score representing authority's opinion in numeric form
    **WHY:**
    - A CVSS score of 7.0 or higher corresponds to High and Critical severity vulnerabilities.
    - This metric provides a count of serious vulnerabilities based on the numeric score, removing ambiguity from categorical labels.

    **WHERE:**
    - The `cvss_ge_7_count` is derived by taking the highest `score` from the `.vulnerabilities.{VULN}.ratings.{SOURCE}.score`.
    - If that score is greater than or equal to `7.0`, than this count is incremented.
    """
    try:
        count = 0
        for vuln in sbom.get("vulnerabilities", []):
            if _get_highest_score(vuln.get("ratings", [])) >= 7.0:
                count += 1
        return float(count)
    except Exception as e:
        raise RuntimeError(f"Failed to extract cvss_ge_7_count: {e}")

def extract_max_cvss(sbom: Dict[str, Any]) -> float:
    """
    **WHAT:**
    - The `max_cvss` represents the highest Common Vulnerability Scoring System (CVSS) score found amongst all vulnerabilities in the software stack.
    - It pinpoints the single most severe flaw present in the system, rated on a scale of `0.0` to `10.0`.

    **WHY:**
    - This metric defines the ceiling of risk for the application as a system is often considered only as secure as its weakest link.
    - A high maximum score signals immediate urgency, whereas a lower maximum indicates that no individual flaw is catastrophic.

    **WHERE:**
    - The `max_cvss` is derived by iterating through all `.vulnerabilities`, extracting the highest value from `.vulnerabilities.{VULN}.ratings.{SOURCE}.score`, and determining the maximum.
    """
    try:
        max_cvss = 0.0
        for vuln in sbom.get("vulnerabilities", []):
            score = _get_highest_score(vuln.get("ratings", []))
            if score > max_cvss:
                max_cvss = score
        return float(max_cvss)
    except Exception as e:
        raise RuntimeError(f"Failed to extract max_cvss: {e}")

def extract_unique_cwe_count(sbom: Dict[str, Any]) -> float:
    """
    **WHAT:**
    - The `unique_cwe_count` identifies the number of distinct Common Weakness Enumeration (CWE) categories present within the identified vulnerabilities.
    - This metric focuses on the variety of weakness types rather than the raw count of specific CVEs.

    **WHY:**
    - Diverse weakness types suggest a broader attack surface
    - It can indicate systemic issues where multiple different coding or design patterns are failing security best practices.

    **WHERE:**
    - The `unique_cwe_count` is derived by extracting the `cwes` list from each item in the `.vulnerabilities` array, creating a set of unique values, and counting them.
    """
    try:
        unique_cwes: Set[int] = set()
        for vuln in sbom.get("vulnerabilities", []):
            for cwe in vuln.get("cwes", []):
                unique_cwes.add(int(cwe))
        return float(len(unique_cwes))
    except Exception as e:
        raise RuntimeError(f"Failed to extract unique_cwe_count: {e}")

def extract_top25_cwe_count(sbom: Dict[str, Any]) -> float:
    """
    **WHAT:**
    - The `top25_cwe_count` is the total number of vulnerabilities that are categorized under the MITRE "Top 25 Most Dangerous Software Weaknesses."
    - These weaknesses are demonstrably the most dangerous, frequent, and impactful issues currently facing the software industry.

    **WHY:**
    - Weaknesses on the Top 25 list are often the first targets for attackers because they are well-documented and effective.
    - A high count indicates that the software stack contains "low-hanging fruit" for potential exploits.

    **WHERE:**
    - The `top25_cwe_count` is derived by cross-referencing extracted `cwes` from the `.vulnerabilities` section against the standard list of Top 25 CWEs.
    """
    try:
        count = 0
        for vuln in sbom.get("vulnerabilities", []):
            cwes = vuln.get("cwes", [])
            if any(int(cwe) in TOP_25_CWES for cwe in cwes):
                count += 1
        return float(count)
    except Exception as e:
        raise RuntimeError(f"Failed to extract top25_cwe_count: {e}")

def extract_base_image_days(sbom: Dict[str, Any]) -> float:
    """
    **WHAT:**
    - The `base_image_age_days` represents the number of days that have elapsed since the container base image was created.
    - It acts as a temporal metric indicating the freshness of the underlying operating system and system-level dependencies.

    **WHY:**
    - Older base images are significantly more likely to contain unpatched vulnerabilities and security regressions.
    - A high age indicates that the project is not regularly ingesting upstream security patches and updates.

    **WHERE:**
    - Tier 1: label fallback chain from `.metadata.component.properties`
    - Tier 2: Docker Hub public API using the image reference from properties
    """
    try:
        properties = sbom.get("metadata", {}).get("component", {}).get("properties", [])
        prop_map: Dict[str, str] = {p.get("name", ""): p.get("value", "") for p in properties}

        # Determine scan time
        scan_timestamp_str = sbom.get("metadata", {}).get("timestamp")
        scan_time: datetime = (
            datetime.strptime(scan_timestamp_str[:19], "%Y-%m-%dT%H:%M:%S")
            if scan_timestamp_str
            else datetime.now()
        )

        # Tier 1 — label fallback chain
        build_date_str = None
        matched_label = None
        for label in _LABEL_FALLBACK_CHAIN:
            _log.debug("extract_base_image_days: trying Tier-1 label '%s'", label)
            if label in prop_map and prop_map[label]:
                build_date_str = prop_map[label]
                matched_label = label
                break

        if build_date_str:
            build_date = _parse_date_flexible(build_date_str)
            if build_date:
                age = float(max(0, (scan_time - build_date).days))
                _log.info("extract_base_image_days: Tier-1 succeeded label='%s' age_days=%.0f", matched_label, age)
                return age

        # Tier 2 — Docker Hub API fallback
        reference = prop_map.get("aquasecurity:trivy:Reference", "")
        _log.debug("extract_base_image_days: Tier-1 failed, trying Tier-2 (Docker Hub) reference='%s'", reference)
        if reference:
            hub_date_str = _query_dockerhub_tag_date(reference)
            if hub_date_str:
                hub_date = _parse_date_flexible(hub_date_str)
                if hub_date:
                    age = float(max(0, (scan_time - hub_date).days))
                    _log.info("extract_base_image_days: Tier-2 (Docker Hub) succeeded age_days=%.0f", age)
                    return age

        _log.info("extract_base_image_days: all tiers failed — returning 0.0")
        return 0.0

    except Exception as e:
        raise RuntimeError(f"Failed to extract base_image_age_days: {e}")

def _get_highest_severity(ratings: List[Dict[str, Any]]) -> int:
    """
    Helper function to find the highest severity weight from a list of ratings.
    """
    highest_weight = -1
    for r in ratings:
        sev = r.get("severity", "unknown").lower()
        weight = SEVERITY_WEIGHT.get(sev, 0)
        if weight > highest_weight:
            highest_weight = weight
    return highest_weight

def _get_highest_score(ratings: List[Dict[str, Any]]) -> float:
    """
    Helper function to find the highest score from a list of ratings.
    """
    max_score = 0.0
    for r in ratings:
        try:
            score = float(r.get("score", 0.0))
            if score > max_score:
                max_score = score
        except (ValueError, TypeError):
            continue
    return max_score

def _parse_date_flexible(date_str: str) -> Optional[datetime]:
    """Parse a date string in any of the formats observed in the scan corpus."""
    # Normalise: strip trailing Z, then truncate at + or . to get bare datetime
    s = date_str.strip()
    if s.endswith("Z"):
        s = s[:-1]
    # Drop sub-second precision and timezone offset
    s = s.split(".")[0].split("+")[0]

    for fmt in ["%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M", "%Y-%m-%d", "%Y%m%d"]:
        try:
            result = datetime.strptime(s, fmt)
            _log.debug("_parse_date_flexible: matched format='%s' input='%s'", fmt, date_str)
            return result
        except ValueError:
            continue
    return None

def _query_dockerhub_tag_date(reference: str) -> Optional[str]:
    """Query Docker Hub public API for the last_updated timestamp of a tag."""
    try:
        # Parse reference: [registry/][namespace/]image[:tag]
        # Strip any registry prefix (contains a dot or colon with port)
        parts = reference.split("/")
        if len(parts) >= 2 and ("." in parts[0] or ":" in parts[0]):
            parts = parts[1:]  # drop registry host

        if len(parts) == 1:
            namespace = "library"
            image_and_tag = parts[0]
        else:
            namespace = parts[0]
            image_and_tag = "/".join(parts[1:])

        if ":" in image_and_tag:
            image, tag = image_and_tag.rsplit(":", 1)
        else:
            image, tag = image_and_tag, "latest"

        url = f"https://hub.docker.com/v2/repositories/{namespace}/{image}/tags/{tag}"
        _log.debug("_query_dockerhub_tag_date: querying %s", url)
        with urlopen(url, timeout=5) as resp:
            data = load(resp)
            return data.get("last_updated")
    except (URLError, Exception) as exc:
        _log.debug("_query_dockerhub_tag_date: request failed url=%s error=%s", url, exc)
        return None

def classify_metric(metric: SecurityMetric) -> str:
    """
    Applies BLOCK_THRESHOLDS then WARN_THRESHOLDS to a SecurityMetric.
    Returns "BLOCK", "WARN", or "ALLOW".

    Can be called independently of the CLI for programmatic use.
    """
    values = metric.__dict__
    for field, threshold in BLOCK_THRESHOLDS.items():
        val = values.get(field, 0.0)
        _log.debug("classify_metric: BLOCK check field=%s value=%s threshold=%s", field, val, threshold)
        if val >= threshold:
            _log.info("classify_metric: BLOCK — field=%s value=%s threshold=%s scan_file=%s", field, val, threshold, metric.scan_file)
            return "BLOCK"
    for field, threshold in WARN_THRESHOLDS.items():
        val = values.get(field, 0.0)
        _log.debug("classify_metric: WARN check field=%s value=%s threshold=%s", field, val, threshold)
        if val >= threshold:
            _log.info("classify_metric: WARN — field=%s value=%s threshold=%s scan_file=%s", field, val, threshold, metric.scan_file)
            return "WARN"
    _log.info("classify_metric: ALLOW — all thresholds passed scan_file=%s", metric.scan_file)
    return "ALLOW"

def build_security_metric_from_sbom(
    scan_file:str,
    sbom:Dict[str, Any],
) -> SecurityMetric:
    """
    Ingests a Trivy CycloneDX JSON SBOM to create a formalized SecurityMetric vector.
    """
    try:
        total_dependency_count = extract_total_dependency_count(sbom)
        _log.debug("build_security_metric: %s total_dependency_count=%s", scan_file, total_dependency_count)
        vuln_total = extract_vuln_total(sbom)
        _log.debug("build_security_metric: %s vuln_total=%s", scan_file, vuln_total)
        critical_cve_count = extract_critical_cve_count(sbom)
        _log.debug("build_security_metric: %s critical_cve_count=%s", scan_file, critical_cve_count)
        high_cve_count = extract_high_cve_count(sbom)
        _log.debug("build_security_metric: %s high_cve_count=%s", scan_file, high_cve_count)
        cvss_ge_7_count = extract_cvss_ge_7_count(sbom)
        _log.debug("build_security_metric: %s cvss_ge_7_count=%s", scan_file, cvss_ge_7_count)
        max_cvss = extract_max_cvss(sbom)
        _log.debug("build_security_metric: %s max_cvss=%s", scan_file, max_cvss)
        unique_cwe_count = extract_unique_cwe_count(sbom)
        _log.debug("build_security_metric: %s unique_cwe_count=%s", scan_file, unique_cwe_count)
        top25_cwe_count = extract_top25_cwe_count(sbom)
        _log.debug("build_security_metric: %s top25_cwe_count=%s", scan_file, top25_cwe_count)
        base_image_age_days = extract_base_image_days(sbom)
        _log.debug("build_security_metric: %s base_image_age_days=%s", scan_file, base_image_age_days)
        return SecurityMetric(
            scan_file=scan_file,
            total_dependency_count=total_dependency_count,
            vuln_total=vuln_total,
            critical_cve_count=critical_cve_count,
            high_cve_count=high_cve_count,
            cvss_ge_7_count=cvss_ge_7_count,
            max_cvss=max_cvss,
            unique_cwe_count=unique_cwe_count,
            top25_cwe_count=top25_cwe_count,
            base_image_age_days=base_image_age_days,
        )
    except Exception as e:
        raise RuntimeError(f"Failed to extract features and construct SecurityMetric: {e}")

def read_path_data(path:Path) -> Union[List[tuple[Path, Any]], Generator[tuple[Path, Any], Any, None]]:
    """
    Wrapper function that processes a path depending on if it's a file or directory.
    """
    if path.is_file():
        # Operates as it does now: returns the JSON inside a size-1 list
        with open(path, 'r', encoding='utf-8') as f:
            return [(path, load(f))]

    elif path.is_dir():
        # Defines and returns a generator that yields JSON for each file
        def _dir_generator() -> Generator[tuple[Path, Any], Any, None]:

            # Iterating through .json files (adjust the glob pattern if needed)
            for file_path in path.glob('*.json'):
                if file_path.is_file():
                    with open(file_path, 'r', encoding='utf-8') as f:
                        yield (file_path, load(f))

        return _dir_generator()
    else:
        raise FileNotFoundError(f"Path does not exist or is invalid: {path}")

def validate_file_path(path_str: str) -> Path:
    """
    Validates that the provided path string points to an existing file or directory.
    """
    path = Path(path_str)
    if path.is_file():
        return path
    elif path.is_dir():
        return path
    else:
        raise ArgumentTypeError(f"The path '{path_str}' is not a file or directory")

def validate_output_path(path_str: str) -> str:
    """
    Validates that the provided output path is valid and its parent directory exists.
    """
    path = Path(path_str)
    if path.is_dir():
        raise ArgumentTypeError(f"The output path '{path_str}' is a directory, but must be a file")
    if not path.parent.exists():
        raise ArgumentTypeError(f"The parent directory '{path.parent}' does not exist")
    if path.parent.is_file():
        raise ArgumentTypeError(f"The parent is a file '{path.parent}'")
    return path_str

def parse_args() -> Namespace:
    """
    Parses command line arguments.
    """
    parser = ArgumentParser(description="Extract security metrics from an SBOM file",
                            formatter_class=ArgumentDefaultsHelpFormatter)
    parser.add_argument(
        "-s",
        "--sbom",
        type=validate_file_path,
        required=True,
        help="Path to the given SBOM directory/file"
    )
    parser.add_argument(
        "-f",
        "--format",
        type=str,
        choices=[JSON_OUTPUT, CSV_OUTPUT],
        default=JSON_OUTPUT,
        help="Format of the output sent to STDOUT by default"
    )
    parser.add_argument(
        "-o",
        "--output",
        type=validate_output_path,
        help="File path to redirect the output to a CSV or JSON file"
    )
    parser.add_argument(
        "-c",
        "--classify",
        action="store_true",
        default=False,
        help="Append a 'classification' column (ALLOW/WARN/BLOCK) to the output"
    )
    return parser.parse_args()

if __name__ == "__main__":
    args:Namespace = parse_args()
    metrics = SecurityMetricsCollection()
    for path, sbom in read_path_data(args.sbom):
        metrics.append(build_security_metric_from_sbom(
            scan_file=path.name,
            sbom=sbom,
        ))

    if args.classify and not metrics.df.empty:
        metrics.df["classification"] = metrics.df.apply(
            lambda row: classify_metric(SecurityMetric(**row.to_dict())), axis=1
        )

    if args.format == CSV_OUTPUT:
        output_data = metrics.to_csv()
    else:
        output_data = metrics.to_json()

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output_data)
    else:
        print(output_data)
