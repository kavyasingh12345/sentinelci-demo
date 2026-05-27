from langgraph.types import interrupt
from state import ScanState
from config import AUTO_BLOCK_THRESHOLD


def hitl_node(state: ScanState) -> ScanState:
    score = state.get("security_score", 0)

    if score >= AUTO_BLOCK_THRESHOLD:
        print(f"[HITL] Score {score} >= {AUTO_BLOCK_THRESHOLD} — AUTO BLOCKING")
        return {
            **state,
            "hitl_decision": "auto_blocked",
            "status": "blocked",
            "execution_log": state.get("execution_log", []) + ["hitl"]
        }

    if not state.get("hitl_required"):
        return {
            **state,
            "execution_log": state.get("execution_log", []) + ["hitl"]
        }

    print(f"[HITL] Score {score} — freezing for human review")

    human_decision = interrupt({
        "message": f"Security score {score}/10 detected. Review required.",
        "security_score": score,
        "severity_breakdown": state.get("severity_breakdown", {}),
        "ai_analysis": state.get("ai_analysis", ""),
        "thread_id": state.get("thread_id")
    })

    print(f"[HITL] Human decision received: {human_decision}")

    return {
        **state,
        "hitl_decision": human_decision.get("decision"),
        "hitl_reviewer": human_decision.get("reviewer_id"),
        "hitl_comment": human_decision.get("comment"),
        "status": "running",
        "execution_log": state.get("execution_log", []) + ["hitl"]
    }