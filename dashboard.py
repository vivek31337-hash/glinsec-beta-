"""
dashboard.py - Streamlit web frontend for GLinSec LLM Security Audit.

Features:
  - Text input for the API key
  - Dropdown for model type and model name selection
  - "Start Security Audit" button with a real-time progress bar
  - Inline display of results after the scan completes

Run with:
    streamlit run dashboard.py
"""

import os
import json
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

import streamlit as st

# ── Page config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="GLinSec – LLM Security Audit",
    page_icon="🔒",
    layout="centered",
)

REPORTS_DIR = Path("reports")
PROBES = ["jailbreak", "promptinject", "dan"]

MODEL_TYPES = [
    "openai",
    "huggingface",
    "cohere",
    "anthropic",
    "replicate",
    "rest",
    "litellm",
]

COMMON_MODELS: dict[str, list[str]] = {
    "openai": ["gpt-4o", "gpt-4-turbo", "gpt-3.5-turbo"],
    "huggingface": ["gpt2", "mistralai/Mistral-7B-v0.1", "meta-llama/Llama-2-7b-chat-hf"],
    "cohere": ["command-r-plus", "command-r", "command"],
    "anthropic": ["claude-3-5-sonnet-20241022", "claude-3-haiku-20240307"],
    "replicate": ["meta/llama-2-70b-chat", "mistralai/mixtral-8x7b-instruct-v0.1"],
    "rest": [],
    "litellm": [],
}

API_KEY_ENV_MAP = {
    "openai": "OPENAI_API_KEY",
    "cohere": "COHERE_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "replicate": "REPLICATE_API_TOKEN",
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def build_report_path(model_type: str, model_name: str) -> Path:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = model_name.replace("/", "_").replace("\\", "_")
    return REPORTS_DIR / f"garak_{model_type}_{safe}_{ts}.jsonl"


def run_scan(model_type: str, model_name: str, report_path: Path,
             env: dict, log_container) -> int:
    """Run garak in a subprocess, streaming stdout line-by-line."""
    cmd = [
        sys.executable, "-m", "garak",
        "--model_type", model_type,
        "--model_name", model_name,
        "--probes", ",".join(PROBES),
        "--report_prefix", str(report_path.with_suffix("")),
    ]
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=env,
    )
    log_lines: list[str] = []
    for line in proc.stdout:
        log_lines.append(line.rstrip())
        log_container.code("\n".join(log_lines[-40:]), language="")
    proc.wait()
    return proc.returncode


def parse_results(report_path: Path) -> dict:
    """Parse the garak JSONL report and return a summary dict."""
    if not report_path.exists():
        return {"error": f"Report not found: {report_path}"}
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


# ── UI Layout ─────────────────────────────────────────────────────────────────

st.title("🔒 GLinSec - LLM Security Audit")
st.markdown(
    "Automated security testing for Large Language Models using "
    "[garak](https://github.com/NVIDIA/garak). "
    "Targets **jailbreak**, **prompt injection**, and **DAN** probes."
)

st.divider()

# ── Sidebar – configuration ───────────────────────────────────────────────────
with st.sidebar:
    st.header("⚙️ Configuration")

    model_type = st.selectbox("Model type", MODEL_TYPES, index=0)

    preset_models = COMMON_MODELS.get(model_type, [])
    if preset_models:
        model_name = st.selectbox(
            "Model name",
            preset_models + ["(custom…)"],
            index=0,
        )
        if model_name == "(custom…)":
            model_name = st.text_input("Custom model name")
    else:
        model_name = st.text_input("Model name / endpoint", placeholder="e.g. http://localhost:8080/v1")

    env_var = API_KEY_ENV_MAP.get(model_type)
    if env_var:
        api_key = st.text_input(
            f"API Key ({env_var})",
            type="password",
            help=f"Will be exported as the {env_var} environment variable.",
        )
    else:
        api_key = ""

    st.divider()
    st.markdown(
        "**Probes:** " + ", ".join(f"`{p}`" for p in PROBES)
    )

# ── Main panel ────────────────────────────────────────────────────────────────

start_btn = st.button("🚀 Start Security Audit", type="primary", use_container_width=True)

if start_btn:
    if not model_name or model_name == "(custom…)":
        st.error("Please enter a model name before starting the audit.")
        st.stop()

    env_var_name = API_KEY_ENV_MAP.get(model_type)
    if env_var_name and not api_key:
        st.error(
            f"An API key is required for **{model_type}**. "
            f"Please enter the `{env_var_name}` value in the sidebar."
        )
        st.stop()

    # Build subprocess environment
    scan_env = os.environ.copy()
    if env_var_name and api_key:
        scan_env[env_var_name] = api_key

    report_path = build_report_path(model_type, model_name)

    st.info(
        f"Running garak against **{model_type}/{model_name}** …  \n"
        f"Report will be saved to `{report_path}`"
    )

    progress_bar = st.progress(0, text="Initializing scan...")
    log_box = st.empty()

    # Fake incremental progress while scan runs in a thread
    scan_result: dict = {}
    return_code_holder: list[int] = []

    def _scan_thread():
        rc = run_scan(model_type, model_name, report_path, scan_env, log_box)
        return_code_holder.append(rc)

    thread = threading.Thread(target=_scan_thread, daemon=True)
    thread.start()

    tick = 0
    while thread.is_alive():
        tick = min(tick + 2, 90)
        progress_bar.progress(tick, text=f"Scanning… ({tick}%)")
        time.sleep(1)

    thread.join()
    progress_bar.progress(100, text="Scan complete!")

    rc = return_code_holder[0] if return_code_holder else -1
    if rc != 0:
        st.warning(
            f"garak exited with code **{rc}**. "
            "The report may be incomplete – check the log above."
        )

    # ── Results ───────────────────────────────────────────────────────────────
    st.divider()
    st.subheader("📊 Scan Results")

    summary = parse_results(report_path)

    if "error" in summary:
        st.error(summary["error"])
    else:
        col1, col2, col3 = st.columns(3)
        col1.metric("Total tests", summary["total"])
        col2.metric("Passed", summary["passed"], delta=None)
        col3.metric(
            "Vulnerabilities",
            summary["vulnerabilities"],
            delta=f"-{summary['vulnerabilities']}" if summary["vulnerabilities"] else None,
            delta_color="inverse",
        )

        if summary["details"]:
            st.dataframe(
                summary["details"],
                use_container_width=True,
                column_config={
                    "probe": "Probe",
                    "detector": "Detector",
                    "passed": st.column_config.CheckboxColumn("Passed"),
                },
            )
        else:
            st.info("No individual test records found in the report.")

        st.download_button(
            "⬇️ Download JSONL report",
            data=report_path.read_bytes() if report_path.exists() else b"",
            file_name=report_path.name,
            mime="application/jsonl",
        )
