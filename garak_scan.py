"""
garak_scan.py - Automated LLM Security Testing using garak
Targets: jailbreak, promptinject, and dan (Do Anything Now) probes
"""

import subprocess
import sys
import os
import json
from datetime import datetime
from pathlib import Path


PROBES = [
    "jailbreak",
    "promptinject",
    "dan",
]

REPORTS_DIR = Path("reports")


def get_user_input() -> tuple[str, str]:
    """Prompt the user for model_type and model_name."""
    print("=== GLinSec LLM Security Scanner ===\n")
    model_type = input("Enter model type (e.g., openai, huggingface): ").strip()
    if not model_type:
        print("Error: model_type cannot be empty.")
        sys.exit(1)

    model_name = input("Enter model name (e.g., gpt-3.5-turbo, gpt2): ").strip()
    if not model_name:
        print("Error: model_name cannot be empty.")
        sys.exit(1)

    return model_type, model_name


def validate_api_key(model_type: str) -> None:
    """Check that required API keys are present for the chosen model type."""
    key_map = {
        "openai": "OPENAI_API_KEY",
        "cohere": "COHERE_API_KEY",
        "anthropic": "ANTHROPIC_API_KEY",
        "replicate": "REPLICATE_API_TOKEN",
    }
    required_key = key_map.get(model_type.lower())
    if required_key and not os.environ.get(required_key):
        raise EnvironmentError(
            f"Missing API key: environment variable '{required_key}' is not set. "
            f"Export it before running: export {required_key}=<your-key>"
        )


def build_report_filename(model_type: str, model_name: str) -> Path:
    """Return a timestamped path for the garak JSONL report."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_model = model_name.replace("/", "_").replace("\\", "_")
    filename = f"garak_{model_type}_{safe_model}_{timestamp}.jsonl"
    return REPORTS_DIR / filename


def run_garak_scan(model_type: str, model_name: str, report_path: Path) -> int:
    """
    Execute a garak scan via the CLI subprocess.

    Returns the process return code (0 = success).
    """
    probe_list = ",".join(PROBES)
    cmd = [
        sys.executable, "-m", "garak",
        "--model_type", model_type,
        "--model_name", model_name,
        "--probes", probe_list,
        "--report_prefix", str(report_path.with_suffix("")),
    ]
    print(f"\n[+] Starting garak scan: {' '.join(cmd)}\n")
    try:
        result = subprocess.run(cmd, check=False)
        return result.returncode
    except FileNotFoundError:
        raise RuntimeError(
            "garak is not installed or not on the PATH. "
            "Install it with: pip install garak"
        )
    except ConnectionError as exc:
        raise RuntimeError(
            f"Could not connect to the model endpoint: {exc}"
        ) from exc


def parse_jsonl_report(report_path: Path) -> dict:
    """
    Read a garak JSONL report and return a summary dict with:
      - total: total number of test cases
      - passed: number of tests that passed (model was NOT vulnerable)
      - vulnerabilities: number of tests that failed (model was vulnerable)
      - details: list of {probe, detector, passed} for each entry
    """
    if not report_path.exists():
        raise FileNotFoundError(
            f"Report file not found: {report_path}\n"
            "The scan may have failed or the file path is incorrect."
        )

    details = []
    with report_path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            probe = entry.get("probe", entry.get("probe_classname", "unknown"))
            detector = entry.get("detector", entry.get("detector_name", "unknown"))
            passed = bool(entry.get("passed", entry.get("status") == "passed"))
            details.append({"probe": probe, "detector": detector, "passed": passed})

    total = len(details)
    passed_count = sum(1 for d in details if d["passed"])
    vuln_count = total - passed_count

    return {
        "total": total,
        "passed": passed_count,
        "vulnerabilities": vuln_count,
        "details": details,
    }


def print_summary(summary: dict) -> None:
    """Print a human-readable summary of the scan results."""
    print("\n" + "=" * 50)
    print("          GARAK SCAN SUMMARY")
    print("=" * 50)
    print(f"  Total test cases  : {summary['total']}")
    print(f"  Tests passed      : {summary['passed']}")
    print(f"  Vulnerabilities   : {summary['vulnerabilities']}")
    print("=" * 50)

    if summary["vulnerabilities"] > 0:
        print("\n[!] Vulnerable probes / detectors:")
        for item in summary["details"]:
            if not item["passed"]:
                print(f"    - probe={item['probe']}  detector={item['detector']}")
    else:
        print("\n[+] No vulnerabilities detected.")
    print()


def main() -> None:
    try:
        model_type, model_name = get_user_input()
        validate_api_key(model_type)
        report_path = build_report_filename(model_type, model_name)

        return_code = run_garak_scan(model_type, model_name, report_path)
        if return_code != 0:
            print(f"\n[!] garak exited with code {return_code}. "
                  "Check the output above for details.")

        summary = parse_jsonl_report(report_path)
        print_summary(summary)

    except EnvironmentError as exc:
        print(f"\n[ERROR] API key error: {exc}")
        sys.exit(2)
    except (RuntimeError, FileNotFoundError) as exc:
        print(f"\n[ERROR] {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
