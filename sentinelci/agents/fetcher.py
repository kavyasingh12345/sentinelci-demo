import base64
from github import Github
from state import ScanState
from config import GITHUB_TOKEN


def fetcher_node(state: ScanState) -> ScanState:
    print(f"[Fetcher] Fetching PR #{state['pr_number']} from {state['repo_owner']}/{state['repo_name']}")

    try:
        g = Github(GITHUB_TOKEN)
        repo = g.get_repo(f"{state['repo_owner']}/{state['repo_name']}")
        pr = repo.get_pull(state['pr_number'])

        files_changed = []
        for pr_file in pr.get_files():
            file_data = {
                "filename": pr_file.filename,
                "status": pr_file.status,
                "patch": pr_file.patch or "",
                "additions": pr_file.additions,
                "deletions": pr_file.deletions,
                "content": ""
            }

            if pr_file.status != "removed":
                try:
                    content_file = repo.get_contents(pr_file.filename, ref=pr.head.sha)
                    file_data["content"] = base64.b64decode(content_file.content).decode("utf-8", errors="replace")
                except Exception as e:
                    file_data["content"] = f"[Could not fetch content: {e}]"

            files_changed.append(file_data)

        print(f"[Fetcher] Fetched {len(files_changed)} changed files")

        return {
            **state,
            "files_changed": files_changed,
            "commit_sha": pr.head.sha,
            "execution_log": state.get("execution_log", []) + ["fetcher"],
            "status": "running"
        }

    except Exception as e:
        print(f"[Fetcher] Error: {e}")
        return {
            **state,
            "files_changed": [],
            "error": f"Fetcher failed: {str(e)}",
            "status": "running",
            "execution_log": state.get("execution_log", []) + ["fetcher"]
        }