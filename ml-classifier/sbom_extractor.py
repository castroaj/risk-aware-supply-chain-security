from json import load, dumps
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter, Namespace, ArgumentTypeError
from typing import Dict, Any, Generator, List, Set, Union
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

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
    semgrep_total: float
    semgrep_high_count: float
    base_image_age_days: float

    def to_json(self) -> str:
        return dumps(self.__dict__)

    def to_csv(self) -> str:
        return (
            f"{self.scan_file},{self.total_dependency_count},{self.vuln_total},"
            f"{self.critical_cve_count},{self.high_cve_count},"
            f"{self.cvss_ge_7_count},{self.max_cvss},"
            f"{self.unique_cwe_count},{self.top25_cwe_count},"
            f"{self.semgrep_total},{self.semgrep_high_count},"
            f"{self.base_image_age_days}"
        )

    @staticmethod
    def get_csv_header() -> str:
        return (
            "scan_file,total_dependency_count,vuln_total,critical_cve_count,"
            "high_cve_count,cvss_ge_7_count,max_cvss,unique_cwe_count,"
            "top25_cwe_count,semgrep_total,semgrep_high_count,"
            "base_image_age_days"
        )

import pandas as pd

@dataclass
class SecurityMetricsCollection:
    """
    Collection of SecurityMetric objects.
    """
    df: pd.DataFrame = None
    def __post_init__(self):
        if self.df is None:
            self.df = pd.DataFrame()
    def append(self, metric: SecurityMetric) -> None:
        """
        Appends a SecurityMetric object to the collection.
        """
        new_row = pd.DataFrame([metric.__dict__])
        if self.df.empty:
            self.df = new_row
        else:
            self.df = pd.concat([self.df, new_row], ignore_index=True)
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
    - The `base_image_age_days` is derived by extracting the creation timestamp from the `.metadata.component.properties` array.
    """
    try:

        # Find the build date from the metadata        
        properties = sbom.get("metadata", {}).get("component", {}).get("properties", [])
        build_date_str = None
        for prop in properties:
            if prop.get("name") == "aquasecurity:trivy:Labels:build-date":
                build_date_str = prop.get("value")
                break
        if not build_date_str:
            return 0.0

        # Find the scan data from the metadata
        scan_timestamp_str = sbom.get("metadata", {}).get("timestamp")
        if scan_timestamp_str: scan_time:datetime = datetime.strptime(scan_timestamp_str[:19], "%Y-%m-%dT%H:%M:%S")
        else:                  scan_time:datetime = datetime.now()
        build_date = datetime.strptime(build_date_str[:19], "%Y-%m-%dT%H:%M:%S")
        delta = scan_time - build_date
        return float(max(0, delta.days))
    
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

def build_security_metric_from_sbom(
    scan_file:str,
    sbom:Dict[str, Any],
    semgrep_total: float,
    semgrep_high_count: float,
) -> SecurityMetric:
    """
    Ingests a Trivy CycloneDX JSON SBOM and external SAST/Metadata 
    to create a formalized SecurityMetric vector.
    """
    try:
        return SecurityMetric(
            scan_file=scan_file,
            total_dependency_count=extract_total_dependency_count(sbom),
            vuln_total=extract_vuln_total(sbom),
            critical_cve_count=extract_critical_cve_count(sbom),
            high_cve_count=extract_high_cve_count(sbom),
            cvss_ge_7_count=extract_cvss_ge_7_count(sbom),
            max_cvss=extract_max_cvss(sbom),
            unique_cwe_count=extract_unique_cwe_count(sbom),
            top25_cwe_count=extract_top25_cwe_count(sbom),
            semgrep_total=semgrep_total,
            semgrep_high_count=semgrep_high_count,
            base_image_age_days=extract_base_image_days(sbom)
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
    return parser.parse_args()

if __name__ == "__main__":
    args:Namespace = parse_args()
    metrics = SecurityMetricsCollection()
    for path, sbom in read_path_data(args.sbom):
        metrics.append(build_security_metric_from_sbom(
            scan_file=path.name,
            sbom=sbom,
            semgrep_high_count=0,
            semgrep_total=0
        ))
    
    if args.format == CSV_OUTPUT:
        output_data = metrics.to_csv()
    else:
        output_data = metrics.to_json()

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output_data)
    else:
        print(output_data)