import hashlib
import hmac
import json
import uuid
from fastapi import FastAPI, HTTPException, Request, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware

from state import ScanRequest, HITLResponse
from graph import app_graph
from config import WEBHOOK_SECRET

app = FastAPI(title="SentinelCI", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"]
)


def run_scan(thread_id: str, initial_state: dict):
    config = {"configurable": {"thread_id": thread_id}}
    try:
        for event in app_graph.stream(initial_state, config=config):
            node_name = list(event.keys())[0] if event else "unknown"
            print(f"[Graph] Node completed: {node_name}")
    except Exception as e:
        print(f"[Graph] Pipeline error: {e}")


def make_initial_state(repo_owner, repo_name, pr_number, commit_sha, thread_id):
    return {
        "repo_owner": repo_owner,
        "repo_name": repo_name,
        "pr_number": pr_number,
        "commit_sha": commit_sha,
        "thread_id": thread_id,
        "files_changed": [],
        "bandit_findings": [],
        "semgrep_findings": [],
        "cve_findings": [],
        "ai_analysis": "",
        "remediation_suggestions": [],
        "security_score": 0,
        "severity_breakdown": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "status": "running",
        "hitl_required": False,
        "hitl_decision": None,
        "hitl_reviewer": None,
        "hitl_comment": None,
        "execution_log": [],
        "final_report_markdown": "",
        "github_check_id": None,
        "github_comment_url": None,
        "error": None
    }


@app.get("/health")
def health():
    return {"status": "ok", "service": "SentinelCI"}


@app.post("/scan/trigger")
async def trigger_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    thread_id = f"scan-{uuid.uuid4().hex[:12]}"
    initial_state = make_initial_state(
        request.repo_owner, request.repo_name,
        request.pr_number, "", thread_id
    )
    background_tasks.add_task(run_scan, thread_id, initial_state)
    return {
        "thread_id": thread_id,
        "message": "Scan started",
        "poll_url": f"/scan/{thread_id}"
    }


@app.get("/scan/{thread_id}")
def get_scan_status(thread_id: str):
    config = {"configurable": {"thread_id": thread_id}}
    try:
        state = app_graph.get_state(config)
        if not state or not state.values:
            raise HTTPException(404, "Scan not found")
        values = state.values
        return {
            "thread_id": thread_id,
            "status": values.get("status", "running"),
            "security_score": values.get("security_score", 0),
            "severity_breakdown": values.get("severity_breakdown", {}),
            "hitl_required": values.get("hitl_required", False),
            "hitl_decision": values.get("hitl_decision"),
            "execution_log": values.get("execution_log", []),
            "ai_analysis": values.get("ai_analysis", ""),
            "final_report_markdown": values.get("final_report_markdown", ""),
            "github_comment_url": values.get("github_comment_url"),
            "cve_findings": values.get("cve_findings", []),
            "remediation_suggestions": values.get("remediation_suggestions", []),
            "error": values.get("error")
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Error fetching scan state: {str(e)}")


@app.post("/hitl/respond")
async def hitl_respond(response: HITLResponse, background_tasks: BackgroundTasks):
    valid_decisions = {"approve", "request_changes", "escalate"}
    if response.decision not in valid_decisions:
        raise HTTPException(400, f"Invalid decision. Must be one of: {valid_decisions}")

    config = {"configurable": {"thread_id": response.thread_id}}
    try:
        state = app_graph.get_state(config)
        if not state:
            raise HTTPException(404, "Scan thread not found")

        app_graph.update_state(
            config,
            {
                "hitl_decision": response.decision,
                "hitl_reviewer": response.reviewer_id,
                "hitl_comment": response.comment,
                "status": "running"
            },
            as_node="hitl"
        )

        background_tasks.add_task(
            lambda: list(app_graph.stream(None, config=config))
        )

        return {
            "message": f"Decision '{response.decision}' submitted. Pipeline resuming.",
            "thread_id": response.thread_id
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"HITL error: {str(e)}")


@app.post("/webhook/github")
async def github_webhook(request: Request, background_tasks: BackgroundTasks):
    signature = request.headers.get("X-Hub-Signature-256", "")
    body = await request.body()

    expected = "sha256=" + hmac.new(
        WEBHOOK_SECRET.encode(), body, hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(signature, expected):
        raise HTTPException(401, "Invalid webhook signature")

    payload = json.loads(body)
    event = request.headers.get("X-GitHub-Event")

    if event != "pull_request":
        return {"message": "Event ignored"}

    action = payload.get("action")
    if action not in ("opened", "synchronize", "reopened"):
        return {"message": f"PR action '{action}' ignored"}

    pr = payload.get("pull_request", {})
    repo = payload.get("repository", {})
    thread_id = f"scan-{uuid.uuid4().hex[:12]}"

    initial_state = make_initial_state(
        repo.get("owner", {}).get("login", ""),
        repo.get("name", ""),
        pr.get("number"),
        pr.get("head", {}).get("sha", ""),
        thread_id
    )

    background_tasks.add_task(run_scan, thread_id, initial_state)
    return {"message": "Scan triggered", "thread_id": thread_id}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)