from github import Github
from state import ScanState
from config import GITHUB_TOKEN


def _build_markdown_report(state: ScanState) -> str:
    score = state.get("security_score", 0)
    breakdown = state.get("severity_breakdown", {})
    remediations = state.get("remediation_suggestions", [])
    cve_findings = state.get("cve_findings", [])
    hitl_decision = state.get("hitl_decision")

    if score <= 2:
        badge = "🟢 PASSED"
        color_label = "Clean"
    elif score <= 5:
        badge = "🟡 WARNING"
        color_label = "Review Recommended"
    elif score <= 8:
        badge = "🔴 HIGH RISK"
        color_label = "Block Until Reviewed"
    else:
        badge = "⛔ CRITICAL"
        color_label = "Auto-Blocked"

    lines = [
        f"# SentinelCI Security Report {badge}",
        f"",
        f"**Security Score:** `{score}/10` — {color_label}",
        f"",
        f"| Severity | Count |",
        f"|----------|-------|",
        f"| 🔴 Critical | {breakdown.get('critical', 0)} |",
        f"| 🟠 High | {breakdown.get('high', 0)} |",
        f"| 🟡 Medium | {breakdown.get('medium', 0)} |",
        f"| 🟢 Low | {breakdown.get('low', 0)} |",
        f"",
        f"## AI Analysis",
        f"{state.get('ai_analysis', 'No analysis available.')}",
        f"",
    ]

    if remediations:
        lines.append("## Findings & Remediation")
        for i, finding in enumerate(remediations, 1):
            sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "ℹ️"}.get(finding.get("severity", ""), "•")
            exploitable = "⚠️ Exploitable" if finding.get("is_exploitable") else "ℹ️ Low risk"
            lines += [
                f"### {i}. {sev_icon} {finding.get('severity')} — `{finding.get('filename', 'unknown')}`",
                f"**Status:** {exploitable}",
                f"**Analysis:** {finding.get('exploitability_reasoning', '')}",
                f"**Fix:** {finding.get('fix', 'No fix suggested')}",
                f"",
            ]

    if cve_findings:
        lines.append("## Vulnerable Dependencies (CVEs)")
        for cve in cve_findings:
            lines += [
                f"- **{cve.get('cve_id')}** — `{cve.get('package')}@{cve.get('version_in_use')}` | CVSS: `{cve.get('cvss_score')}` | {cve.get('severity')}",
                f"  > {cve.get('description', '')[:200]}",
                f""
            ]

    if hitl_decision:
        decision_map = {
            "approve": "✅ Approved by human reviewer",
            "request_changes": "🔄 Changes requested by reviewer",
            "escalate": "📢 Escalated for further review",
            "auto_blocked": "⛔ Auto-blocked (score >= 9)"
        }
        lines += [
            "## Human Review Decision",
            f"**Decision:** {decision_map.get(hitl_decision, hitl_decision)}",
        ]
        if state.get("hitl_reviewer"):
            lines.append(f"**Reviewer:** {state['hitl_reviewer']}")
        if state.get("hitl_comment"):
            lines.append(f"**Comment:** {state['hitl_comment']}")
        lines.append("")

    lines += [
        "---",
        "*Powered by SentinelCI — Bandit · Semgrep · NVD CVE · LangGraph*"
    ]

    return "\n".join(lines)


def reporter_node(state: ScanState) -> ScanState:
    print("[Reporter] Building report and posting to GitHub")

    report_md = _build_markdown_report(state)
    score = state.get("security_score", 0)
    hitl_decision = state.get("hitl_decision")
    comment_url = None

    try:
        g = Github(GITHUB_TOKEN)
        repo = g.get_repo(f"{state['repo_owner']}/{state['repo_name']}")
        pr = repo.get_pull(state["pr_number"])

        comment = pr.create_issue_comment(report_md)
        comment_url = comment.html_url
        print(f"[Reporter] Comment posted: {comment_url}")

        commit = repo.get_commit(state.get("commit_sha", pr.head.sha))

        if score <= 5 and hitl_decision != "request_changes":
            gh_state = "success"
            description = f"SentinelCI passed (score: {score}/10)"
        elif hitl_decision == "approve":
            gh_state = "success"
            description = f"SentinelCI: approved by reviewer (score: {score}/10)"
        elif hitl_decision == "auto_blocked":
            gh_state = "failure"
            description = f"SentinelCI: CRITICAL — auto-blocked (score: {score}/10)"
        else:
            gh_state = "failure"
            description = f"SentinelCI failed (score: {score}/10) — review required"

        commit.create_status(
            state=gh_state,
            description=description,
            context="SentinelCI / security-scan",
            target_url=comment_url
        )

    except Exception as e:
        print(f"[Reporter] GitHub API error: {e}")

    if score >= 9 or hitl_decision == "auto_blocked":
        final_status = "blocked"
    elif hitl_decision == "request_changes":
        final_status = "changes_requested"
    else:
        final_status = "completed"

    return {
        **state,
        "final_report_markdown": report_md,
        "github_comment_url": comment_url,
        "status": final_status,
        "execution_log": state.get("execution_log", []) + ["reporter"]
    }