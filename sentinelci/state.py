from typing import TypedDict, Optional
from pydantic import BaseModel


class ScanState(TypedDict):
    repo_owner: str
    repo_name: str
    pr_number: int
    commit_sha: str
    thread_id: str

    files_changed: list[dict]
    bandit_findings: list[dict]
    semgrep_findings: list[dict]
    cve_findings: list[dict]
    ai_analysis: str
    remediation_suggestions: list[dict]

    security_score: int
    severity_breakdown: dict

    status: str
    hitl_required: bool
    hitl_decision: Optional[str]
    hitl_reviewer: Optional[str]
    hitl_comment: Optional[str]
    execution_log: list[str]

    final_report_markdown: str
    github_check_id: Optional[int]
    github_comment_url: Optional[str]
    error: Optional[str]


class ScanRequest(BaseModel):
    repo_owner: str
    repo_name: str
    pr_number: int


class HITLResponse(BaseModel):
    thread_id: str
    decision: str
    reviewer_id: str
    comment: Optional[str] = None


class WebhookPayload(BaseModel):
    action: str
    number: Optional[int] = None
    pull_request: Optional[dict] = None
    repository: Optional[dict] = None