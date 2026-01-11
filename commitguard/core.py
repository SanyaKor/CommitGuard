import argparse
import asyncio
from .leaks_parser import LeaksParser
from .githubclient import GitHubClient
from typing import List, Dict, Any
from .llm import run_llm
from .logging_config import get_logger
from collections import Counter
import os, json, urllib.request, urllib.error

log = get_logger(__name__)


def write_pr_msg(msg: str = ""):
    if os.getenv("GITHUB_ACTIONS") != "true":
        log.info("PR: LOCAL RUN. Exiting..")
        return

    try:
        repo = os.environ["REPO"]
        pr = os.environ["PR_NUMBER"]
        token = os.environ["GITHUB_TOKEN"]
        run_id = os.environ["GITHUB_RUN_ID"]
    except KeyError as e:
        raise RuntimeError(f"Missing required CI env var: {e}") from e


    run_url = f"https://github.com/{repo}/actions/runs/{run_id}"


    body = "\n".join([
        "📎 **Full analysis report:** available in workflow artifacts → `commitguard-report`",
        "",
        f"- View JSON report: {run_url}",
        "",
        "- Workflow artifacts: `commitguard-report`"
        "",
        "⚠️ **Recommendation:** review **High** and **Medium** findings before merging this PR."
    ])

    url = f"https://api.github.com/repos/{repo}/issues/{pr}/comments"

    pr_msg = "Leaks parser did not find anything suspicious. Exiting..." if not msg else "\n".join([msg.rstrip(), "", body])

    data = json.dumps({"body": pr_msg}).encode("utf-8")

    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "User-Agent": "ci-external-scripts"
        }
    )

    try:
        with urllib.request.urlopen(req) as r:
            log.info("Status:", r.status)
            log.info("Comment posted.") if r.status == 201 else print("Unexpected response.")
    except urllib.error.HTTPError as e:
        log.error("API error:", e.code, e.read().decode())
        raise SystemExit(1)


def save_results_to_file(suspicious_commits, filename="suspicious_commits.json"):
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(suspicious_commits, f, indent=4, ensure_ascii=False)
        log.info(f"Suspicious commits saved to {filename}")
    except Exception as e:
        log.error(f"Failed to save results: {e}")


def main():
    parser = argparse.ArgumentParser(prog="commitguard", description="Scan github repository for commits (searching for some leaks / weak / insecure places)")
    parser.add_argument("--repo", required=True, help="URL GitHub-repo (HTTPS or SSH)")
    parser.add_argument("--n", required=True, help="Amount of commits to fetch [1, 100]")

    parser.add_argument(
        "--out",
        default="suspicious_commits.json",
        help="Output json file name (default: suspicious_commits.json)"
    )

    parser.add_argument(
        "--nofile",
        action="store_true",
        help="Do not save output to file"
    )
    args = parser.parse_args()
    ghc = GitHubClient(args.repo)

    ghc.authorize_github_api()


    async def conc_part():
        commit_data = await ghc.run_fetching_async(int(args.n), 10)
        return commit_data


    c_data = asyncio.run(conc_part())
    leaksparser = LeaksParser()

    suspicious_commits: List[Dict[str, Any]] = []

    for commit_hash, details in c_data.items():

        c_details = ghc.get_commit_details(commit_hash)

        diffs = [
            (item["code"], item["location"])
            for section in ("additions", "deletions")
            for item in c_details[section]
        ]

        codes = [c for c, _ in diffs]
        suspicious_for_commit = leaksparser.run_scanner(codes)

        for s_commit in suspicious_for_commit:
            for code, loc in diffs:
                if code == s_commit:
                    record = {
                        "line": s_commit,
                        "location": loc,
                        "author": c_details["author"],
                        "date": c_details["date"],
                        "commit_message": c_details["commit_message"],
                        "commit_sha": c_details.get("sha") or commit_hash,
                    }
                    suspicious_commits.append(record)

    if not suspicious_commits:
        log.info("Leaks parser did not find anything suspicious. Exiting...")
        write_pr_msg()
        return None

    log.info(f"Leaks parser found {len(suspicious_commits)} suspicious line(s), sending to LLM for analysis")

    suspicious_texts: List[str] = [r["line"] for r in suspicious_commits]

    response = run_llm(suspicious_texts)
    lines = [l.strip() for l in response.splitlines() if l.strip()]
    levels = []

    for line in lines:
        if line.upper().startswith("HIGH"):
            levels.append("HIGH")
        elif line.upper().startswith("MEDIUM"):
            levels.append("MEDIUM")
        elif line.upper().startswith("LOW"):
            levels.append("LOW")
        elif line.lower().startswith("ok"):
            levels.append("OK")

    for line in lines:
        log.debug(f"LLM: {line}")

    stats = Counter(levels)

    log.info(
        f"LLM summary: "
        f"{stats.get('HIGH', 0)} HIGH, "
        f"{stats.get('MEDIUM', 0)} MEDIUM, "
        f"{stats.get('LOW', 0)} LOW, "
        f"{stats.get('OK', 0)} OK"
    )
    for result in response:
        for item in suspicious_commits:
            if item["line"] in result:
                item["llm_response"] = result
                break

    if args.nofile == False:
        save_results_to_file(suspicious_commits, args.out)

    order = ["HIGH", "MEDIUM", "LOW", "OK"]

    lines = []

    lines.append("## 🛡 CommitGuard — Security Scan Results")
    lines.append("")
    lines.append("### 🔍 Leaks Parser Report")
    lines.append("")
    lines.append(f"**Suspicious lines found:** `{len(suspicious_commits)}`")
    lines.append("")

    lines.append("| Severity | Count |")
    lines.append("|---------|--------|")

    for level in order:
        count = stats.get(level, 0)

        if level.lower() == "high":
            icon = "🔴"
        elif level.lower() == "medium":
            icon = "🟠"
        elif level.lower() == "low":
            icon = "🟡"
        else:
            icon = "🟢"

        lines.append(f"| {icon} {level.capitalize()} | {count} |")

    lines.append("")
    lines.append("All suspicious lines were forwarded to the LLM for further analysis (via LangChain).")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("### 🤖 LLM Severity Classification")
    lines.append("")
    lines.append("Findings were analyzed by an LLM to reduce false positives and assess real security risk.")
    lines.append("")

    summary = "\n".join(lines)

    write_pr_msg(summary)
    return None

if __name__ == "__main__":
    main()

