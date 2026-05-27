import json
import re
from langchain_core.messages import HumanMessage, SystemMessage
from state import ScanState
from config import llm, CRITICAL_SCORE_THRESHOLD, AUTO_BLOCK_THRESHOLD


SYSTEM_PROMPT = """You are SentinelCI, an expert security engineer reviewing code changes.
You receive findings from static analysis tools (Bandit, Semgrep) and CVE database matches.
Your job is to:
1. Reason about real exploitability — not just pattern matches
2. Assign an overall security score 0-10 (0=clean, 10=critical breach risk)
3. Write clear, actionable remediation for each finding
4. Be concise — developers need to act on this fast

Scoring guide:
0-2: No real issues or only informational findings
3-4: Low severity — good to fix but not urgent
5-6: Medium — should fix before merge
7-8: High — needs HITL review, block merge
9-10: Critical — auto-block, escalate immediately

Always respond in this exact JSON format:
{
  "security_score": <int 0-10>,
  "score_reasoning": "<1-2 sentences explaining the score>",
  "findings_analysis": [
    {
      "finding_id": "<tool>_<index>",
      "filename": "<file>",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "is_exploitable": true,
      "exploitability_reasoning": "<why/why not exploitable>",
      "fix": "<concrete code fix suggestion>"
    }
  ],
  "overall_summary": "<3-4 sentence plain-English summary for the PR author>"
}"""


def ai_reasoner_node(state: ScanState) -> ScanState:
    print("[AI Reasoner] Running LLM deep analysis")

    all_findings = []

    for i, f in enumerate(state.get("bandit_findings", [])):
        if "error" not in f:
            all_findings.append(f"BANDIT_{i}: [{f.get('severity','?')}] {f.get('filename')}:{f.get('line')} — {f.get('issue_text')} | Code: {f.get('code_snippet','')[:100]}")

    for i, f in enumerate(state.get("semgrep_findings", [])):
        if "error" not in f:
            all_findings.append(f"SEMGREP_{i}: [{f.get('severity','?')}] {f.get('filename')}:{f.get('line')} — {f.get('message')} | Code: {f.get('code_snippet','')[:100]}")

    for i, f in enumerate(state.get("cve_findings", [])):
        all_findings.append(f"CVE_{i}: [{f.get('severity','?')}] {f.get('package')}@{f.get('version_in_use')} — {f.get('cve_id')} CVSS:{f.get('cvss_score')} — {f.get('description','')[:150]}")

    code_context = []
    for file in state.get("files_changed", [])[:3]:
        snippet = file.get("content", "")[:500]
        if snippet:
            code_context.append(f"=== {file['filename']} ===\n{snippet}")

    if not all_findings:
        return {
            **state,
            "security_score": 0,
            "ai_analysis": "No security findings detected. Code appears clean.",
            "remediation_suggestions": [],
            "severity_breakdown": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "hitl_required": False,
            "execution_log": state.get("execution_log", []) + ["ai_reasoner"],
            "status": "running"
        }

    prompt = f"""Analyze these security findings from a GitHub PR:

STATIC ANALYSIS FINDINGS:
{chr(10).join(all_findings)}

CODE CONTEXT (first 500 chars of changed files):
{chr(10).join(code_context)}

Provide your analysis in the JSON format specified."""

    try:
        response = llm.invoke([
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(content=prompt)
        ])

        raw = response.content
        clean = re.sub(r"```json|```", "", raw).strip()
        analysis = json.loads(clean)

        score = analysis.get("security_score", 0)
        remediations = analysis.get("findings_analysis", [])

        breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in remediations:
            sev = f.get("severity", "LOW").lower()
            if sev in breakdown:
                breakdown[sev] += 1

        hitl_required = score >= CRITICAL_SCORE_THRESHOLD

        return {
            **state,
            "security_score": score,
            "ai_analysis": analysis.get("overall_summary", raw),
            "remediation_suggestions": remediations,
            "severity_breakdown": breakdown,
            "hitl_required": hitl_required,
            "status": "awaiting_human" if hitl_required else "running",
            "execution_log": state.get("execution_log", []) + ["ai_reasoner"]
        }

    except Exception as e:
        print(f"[AI Reasoner] LLM error: {e}")
        return {
            **state,
            "security_score": 5,
            "ai_analysis": f"AI analysis failed: {str(e)}. Manual review recommended.",
            "remediation_suggestions": [],
            "severity_breakdown": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "hitl_required": True,
            "status": "awaiting_human",
            "execution_log": state.get("execution_log", []) + ["ai_reasoner"]
        }