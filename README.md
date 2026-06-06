# SentinelCI 🛡️
### AI-Powered Security Scanner for GitHub Pull Requests

> Automatically scans every PR using a 6-agent LangGraph pipeline — catching vulnerabilities before code reaches production.

---

## Demo

| Dashboard — pipeline running | GitHub PR — security report posted |
|---|---|
| Score: **8/10 High Risk** detected | CVEs + AI analysis posted automatically |

**Live flow:**
1. Developer opens a PR with new code
2. SentinelCI auto-triggers via GitHub webhook
3. 6-agent pipeline runs in under 60 seconds
4. Security report posted directly on the PR
5. If score ≥ 7 → pipeline freezes for human review (HITL)
6. Human approves or blocks → GitHub check set to ✅ or ❌

---

## Architecture

```
GitHub PR opened
        ↓
  [Fetcher Agent]
  Pulls changed files via GitHub API
        ↓
  [Scanner Agent]
  Runs Bandit static analysis on code
  Finds: SQL injection, command injection,
  hardcoded credentials, unsafe pickle, weak hashing
        ↓
  [CVE Matcher Agent]
  Queries NVD database for vulnerable dependencies
  Found: CVE-2007-0404 (Django 2.0) CVSS 7.5
         CVE-1999-0168 (requests 2.18) CVSS 7.5
        ↓
  [AI Reasoner Agent]
  LLM reads all findings, scores exploitability 0-10
  Generates per-finding remediation advice
        ↓
  score ≥ 7 → [HITL Agent] ← pipeline freezes here
              Human reviews → approve / request changes / escalate
        ↓
  [Reporter Agent]
  Posts markdown report on GitHub PR
  Sets commit status ✅ or ❌
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Agent Orchestration | LangGraph (stateful, resumable pipelines) |
| Backend API | FastAPI + Python |
| Static Analysis | Bandit |
| CVE Database | NVD REST API (free, no key needed) |
| LLM | Groq (Llama 3.3 70B) / Google Gemini |
| GitHub Integration | PyGithub + Commit Status API + Webhooks |
| Frontend | Vanilla HTML/CSS/JS |

---

## Key Features

### Real Multi-Agent Pipeline
6 specialized agents, each with a single responsibility. State flows between them via a typed `ScanState` object — no agent calls another directly.

### HITL (Human-in-the-Loop)
When security score ≥ 7, LangGraph's `interrupt()` freezes execution mid-pipeline and saves a checkpoint. The pipeline resumes from exactly that point after a human submits a decision — no reprocessing.

### Real Static Analysis
Not just LLM guessing. Bandit catches SQL injection, command injection, unsafe deserialization, hardcoded credentials, and weak hashing with zero hallucination.

### Real CVE Matching
Queries the NVD (National Vulnerability Database) — the same database Dependabot and Snyk use. Checks exact dependency versions against known exploits.

### GitHub Native
Posts formatted security reports as PR comments. Sets commit status checks (the ✅/❌ you see on PRs) via the GitHub Commit Status API.

---

## Project Structure

```
sentinelci/
├── main.py              # FastAPI app — all API endpoints + webhook receiver
├── graph.py             # LangGraph pipeline — wires all 6 agents together
├── state.py             # ScanState TypedDict — shared data between agents
├── config.py            # LLM setup, env vars, thresholds
├── agents/
│   ├── fetcher.py       # Pulls changed files from GitHub PR
│   ├── scanner.py       # Runs Bandit static analysis
│   ├── cve_matcher.py   # Queries NVD vulnerability database
│   ├── ai_reasoner.py   # LLM scoring + exploitability analysis
│   ├── hitl.py          # Human-in-the-loop interrupt checkpoint
│   └── reporter.py      # Builds report + posts to GitHub
├── frontend/
│   └── index.html       # Dashboard UI
├── requirements.txt
└── .env.example
```

---

## API Reference

| Method | Endpoint | Description |
|---|---|---|
| GET | `/health` | Health check |
| POST | `/scan/trigger` | Manually trigger a scan |
| GET | `/scan/{thread_id}` | Poll scan status and results |
| POST | `/hitl/respond` | Submit human review decision |
| POST | `/webhook/github` | GitHub webhook — auto-triggers on PR |

---

## Setup

### Prerequisites
- Python 3.10+
- Groq API key (free at console.groq.com)
- GitHub Personal Access Token (repo scope)

### Install

```bash
cd sentinelci
pip install -r requirements.txt
pip install bandit
```

### Configure

```bash
cp .env.example .env
```

Fill in `.env`:
```
LLM_PROVIDER=groq
GROQ_API_KEY=gsk_xxxxxxxxxxxx
GITHUB_TOKEN=ghp_xxxxxxxxxxxx
WEBHOOK_SECRET=any_random_string
CRITICAL_SCORE_THRESHOLD=7
AUTO_BLOCK_THRESHOLD=9
```

### Run

```bash
python main.py
```

Open `frontend/index.html` in your browser. Green dot = backend online.

---

## GitHub Webhook Setup (Auto-trigger)

For SentinelCI to trigger automatically on every PR:

1. Expose your local server: `ngrok http 8000`
2. Go to your repo → Settings → Webhooks → Add webhook
3. Payload URL: `https://your-ngrok-url/webhook/github`
4. Content type: `application/json`
5. Secret: your `WEBHOOK_SECRET`
6. Events: Pull requests

---

## Interview Insights

**Why LangGraph over a simple chain?**
HITL requires the pipeline to pause mid-execution, save state, and resume after a human decision. LangGraph's `MemorySaver` checkpointer does this natively. A chain has no concept of pausing and resuming.

**Why Bandit + LLM, not just LLM?**
Static tools are deterministic — zero hallucination. The LLM adds context: it reasons about whether a pattern is actually exploitable in this specific codebase. Together they give the best of both — coverage from Bandit, precision from the LLM.

**How does HITL work exactly?**
`interrupt()` raises a special LangGraph exception that freezes execution and saves the checkpoint. `/hitl/respond` calls `update_state()` to inject the human decision, then `stream(None)` resumes from that exact node.

**What's the difference from Dependabot?**
Dependabot only checks dependencies. SentinelCI also analyzes code logic — SQL injections, command injections, unsafe deserialization — things dependency scanners can't see.

---

## Demo Repository

See [sentinelci-demo](https://github.com/kavyasingh12345/sentinelci-demo) for a live example with intentionally vulnerable code and real SentinelCI scan results on PR #3.

---

*Built with LangGraph · FastAPI · Bandit · NVD API · Groq*