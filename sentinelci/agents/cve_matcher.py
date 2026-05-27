import re
import time
import requests
from state import ScanState
from config import NVD_API_URL


def _parse_requirements_txt(content: str) -> list[dict]:
    deps = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r"^([a-zA-Z0-9_\-]+)[=><~!]+([0-9][^\s;#]*)", line)
        if match:
            deps.append({"name": match.group(1).lower(), "version": match.group(2).strip()})
    return deps


def _parse_package_json(content: str) -> list[dict]:
    import json
    deps = []
    try:
        data = json.loads(content)
        all_deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
        for name, version in all_deps.items():
            clean_version = re.sub(r"[^0-9.]", "", version).strip(".")
            if clean_version:
                deps.append({"name": name.lower(), "version": clean_version})
    except Exception:
        pass
    return deps


def _query_nvd(package_name: str, version: str) -> list[dict]:
    cves = []
    try:
        params = {"keywordSearch": package_name, "resultsPerPage": 5}
        resp = requests.get(NVD_API_URL, params=params, timeout=10)
        if resp.status_code != 200:
            return []

        data = resp.json()
        for vuln in data.get("vulnerabilities", []):
            cve_data = vuln.get("cve", {})
            cve_id = cve_data.get("id", "")
            metrics = cve_data.get("metrics", {})
            score = None
            severity = "UNKNOWN"

            for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if metrics.get(metric_key):
                    cvss_data = metrics[metric_key][0].get("cvssData", {})
                    score = cvss_data.get("baseScore")
                    severity = cvss_data.get("baseSeverity", "UNKNOWN")
                    break

            descriptions = cve_data.get("descriptions", [])
            description = next((d["value"] for d in descriptions if d["lang"] == "en"), "No description")

            if score and score >= 6.0:
                cves.append({
                    "cve_id": cve_id,
                    "package": package_name,
                    "version_in_use": version,
                    "cvss_score": score,
                    "severity": severity,
                    "description": description[:300]
                })
    except Exception as e:
        print(f"[CVE Matcher] NVD query failed for {package_name}: {e}")
    return cves


def cve_matcher_node(state: ScanState) -> ScanState:
    print("[CVE Matcher] Checking dependencies against NVD database")

    all_deps = []
    cve_findings = []

    for file in state["files_changed"]:
        filename = file.get("filename", "")
        content = file.get("content", "")
        if "requirements" in filename and filename.endswith(".txt"):
            all_deps.extend(_parse_requirements_txt(content))
        elif filename.endswith("package.json") and "node_modules" not in filename:
            all_deps.extend(_parse_package_json(content))

    if not all_deps:
        return {
            **state,
            "cve_findings": [],
            "execution_log": state.get("execution_log", []) + ["cve_matcher"]
        }

    for dep in all_deps[:20]:
        cves = _query_nvd(dep["name"], dep["version"])
        cve_findings.extend(cves)
        time.sleep(0.5)

    print(f"[CVE Matcher] Total CVE findings: {len(cve_findings)}")

    return {
        **state,
        "cve_findings": cve_findings,
        "execution_log": state.get("execution_log", []) + ["cve_matcher"],
        "status": "running"
    }