import json
import subprocess
import tempfile
import os
from state import ScanState


def _run_bandit(code: str, filename: str) -> list[dict]:
    if not filename.endswith(".py"):
        return []

    findings = []
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, encoding="utf-8") as f:
        f.write(code)
        tmp_path = f.name

    try:
        result = subprocess.run(
            ["bandit", "-f", "json", "-q", tmp_path],
            capture_output=True, text=True, timeout=20,
            encoding="utf-8", errors="replace"
        )
        if result.stdout:
            data = json.loads(result.stdout)
            for issue in data.get("results", []):
                findings.append({
                    "tool": "bandit",
                    "filename": filename,
                    "line": issue.get("line_number"),
                    "severity": issue.get("issue_severity", "").upper(),
                    "confidence": issue.get("issue_confidence", ""),
                    "test_id": issue.get("test_id"),
                    "issue_text": issue.get("issue_text"),
                    "code_snippet": issue.get("code", "")[:100],
                    "cwe": None
                })
    except subprocess.TimeoutExpired:
        print(f"[Scanner] Bandit timeout on {filename}")
    except FileNotFoundError:
        print(f"[Scanner] Bandit not installed")
    except Exception as e:
        print(f"[Scanner] Bandit error: {e}")
    finally:
        try:
            os.unlink(tmp_path)
        except:
            pass

    return findings


def scanner_node(state: ScanState) -> ScanState:
    print(f"[Scanner] Running Bandit on {len(state['files_changed'])} files")

    bandit_findings = []

    for file in state["files_changed"]:
        content = file.get("content", "")
        filename = file.get("filename", "")

        if not content or content.startswith("[Could not"):
            continue

        # Only scan Python files
        if not filename.endswith(".py"):
            continue

        print(f"[Scanner] Scanning {filename}")
        bandit_findings.extend(_run_bandit(content, filename))

    print(f"[Scanner] Found {len(bandit_findings)} issues")

    return {
        **state,
        "bandit_findings": bandit_findings,
        "semgrep_findings": [],  # skip semgrep on Windows
        "execution_log": state.get("execution_log", []) + ["scanner"],
        "status": "running"
    }