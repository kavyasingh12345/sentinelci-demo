import json
import subprocess
import tempfile
import os
from state import ScanState


def _run_bandit(code: str, filename: str) -> list[dict]:
    if not filename.endswith(".py"):
        return []

    findings = []
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(code)
        tmp_path = f.name

    try:
        result = subprocess.run(
            ["bandit", "-f", "json", "-q", tmp_path],
            capture_output=True, text=True, timeout=30
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
                    "code_snippet": issue.get("code", ""),
                    "cwe": issue.get("issue_cwe", {}).get("id") if issue.get("issue_cwe") else None
                })
    except subprocess.TimeoutExpired:
        findings.append({"tool": "bandit", "filename": filename, "error": "timeout"})
    except FileNotFoundError:
        findings.append({"tool": "bandit", "filename": filename, "error": "bandit not installed"})
    except Exception as e:
        findings.append({"tool": "bandit", "filename": filename, "error": str(e)})
    finally:
        os.unlink(tmp_path)

    return findings


def _run_semgrep(code: str, filename: str) -> list[dict]:
    findings = []
    ext_map = {".py": "python", ".js": "javascript", ".ts": "typescript",
               ".jsx": "javascript", ".tsx": "typescript", ".java": "java"}
    ext = os.path.splitext(filename)[1].lower()
    if ext not in ext_map:
        return []

    with tempfile.NamedTemporaryFile(mode="w", suffix=ext, delete=False) as f:
        f.write(code)
        tmp_path = f.name

    try:
        result = subprocess.run(
            ["semgrep", "--config=p/security-audit", "--json", "--quiet", tmp_path],
            capture_output=True, text=True, timeout=60
        )
        if result.stdout:
            data = json.loads(result.stdout)
            for match in data.get("results", []):
                findings.append({
                    "tool": "semgrep",
                    "filename": filename,
                    "line": match.get("start", {}).get("line"),
                    "severity": match.get("extra", {}).get("severity", "").upper(),
                    "rule_id": match.get("check_id"),
                    "message": match.get("extra", {}).get("message", ""),
                    "code_snippet": match.get("extra", {}).get("lines", ""),
                    "cwe": None
                })
    except subprocess.TimeoutExpired:
        findings.append({"tool": "semgrep", "filename": filename, "error": "timeout"})
    except FileNotFoundError:
        findings.append({"tool": "semgrep", "filename": filename, "error": "semgrep not installed"})
    except Exception as e:
        findings.append({"tool": "semgrep", "filename": filename, "error": str(e)})
    finally:
        os.unlink(tmp_path)

    return findings


def scanner_node(state: ScanState) -> ScanState:
    print(f"[Scanner] Running static analysis on {len(state['files_changed'])} files")

    bandit_findings = []
    semgrep_findings = []

    for file in state["files_changed"]:
        if not file.get("content") or file["content"].startswith("[Could not"):
            continue
        bandit_findings.extend(_run_bandit(file["content"], file["filename"]))
        semgrep_findings.extend(_run_semgrep(file["content"], file["filename"]))

    print(f"[Scanner] Found {len(bandit_findings)} Bandit issues, {len(semgrep_findings)} Semgrep issues")

    return {
        **state,
        "bandit_findings": bandit_findings,
        "semgrep_findings": semgrep_findings,
        "execution_log": state.get("execution_log", []) + ["scanner"],
        "status": "running"
    }