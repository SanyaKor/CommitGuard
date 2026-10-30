import argparse
import asyncio
from .leaks_parser import LeaksParser
from .githubclient import GitHubClient
from typing import List, Dict, Any
from .llm import run_llm, FindingsReport
from .logging_config import get_logger
from collections import Counter
import os, json, urllib.request, urllib.error

log = get_logger(__name__)



def attach_findings(records: list[dict[str, Any]], report: FindingsReport) -> list[dict[str, Any]]:

    records_by_id = {record["finding_id"]: record for record in records}

    if len(records_by_id) != len(records):
        raise ValueError("Input records contain duplicate finding IDs")

    findings_by_id: dict[str, list[dict[str, str]]] = { finding_id: [] for finding_id in records_by_id }

    for finding in report.findings:
        if finding.finding_id not in records_by_id:
            raise ValueError( f"LLM returned an unknown finding ID: {finding.finding_id}" )

        findings_by_id[finding.finding_id].append(
            {
                "level": finding.level,
                "message": finding.message,
                "evidence": finding.evidence
            }
        )

    results = []

    for record in records:
        finding_id = record["finding_id"]

        result = record.copy()
        result["llm_findings"] = findings_by_id[finding_id]

        results.append(result)

    return results

def build_pr_summary(report: FindingsReport, suspicious_count: int) -> str:
    stats = Counter(finding.level for finding in report.findings)

    lines = [
        "## CommitGuard — Security Scan Results",
        "",
        f"Suspicious lines detected: **{suspicious_count}**",
        f"LLM findings: **{len(report.findings)}**",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]

    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        lines.append(f"| {severity} | {stats[severity]} |")

    if not report.findings:
        lines.extend([
            "",
            "The LLM returned no findings for the submitted candidates."
        ])

    return "\n".join(lines)

def write_pr_msg(msg: str = "") -> None:
    if os.getenv("GITHUB_ACTIONS") != "true":
        return

    repo = os.environ["REPO"]
    pr = os.environ["PR_NUMBER"]
    token = os.environ["GITHUB_TOKEN"]
    run_id = os.environ["GITHUB_RUN_ID"]

    run_url = f"https://github.com/{repo}/actions/runs/{run_id}"
    url = f"https://api.github.com/repos/{repo}/issues/{pr}/comments"

    if msg.strip():
        body = (
            f"{msg.strip()}\n\n"
            f"Full report: `commitguard-report` artifact "
            f"in the [workflow run]({run_url})."
        )
    else:
        body = (
            "## CommitGuard — Security Scan Results\n\n"
            "The parser detected no suspicious lines."
        )

    request = urllib.request.Request(
        url,
        data=json.dumps({"body": body}).encode("utf-8"),
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "User-Agent": "commitguard"
        }
    )

    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            log.info("PR comment posted: HTTP %s", response.status)
    except urllib.error.URLError as error:
        log.error("Failed to post PR comment: %s", error)
        raise SystemExit(1) from error


def save_results_to_file(suspicious_commits, filename="suspicious_commits.json"):
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(suspicious_commits, f, indent=4, ensure_ascii=False)
        log.info(f"Suspicious commits saved to {filename}")
    except Exception as e:
        log.error(f"Failed to save results: {e}")


def main():
    parser = argparse.ArgumentParser(prog="commitguard", description="Scan github repository for commits (searching for some leaks / weak / insecure places)")

    parser.add_argument("--repo", required=True, help="GitHub repository URL (HTTPS or SSH)")

    mode = parser.add_mutually_exclusive_group(required=True)

    mode.add_argument("--n", type=int, help="Number of latest commits to scan [1, 100]")
    mode.add_argument("--pr", type=int, help="Pull request number to scan")

    parser.add_argument("--ref", help="Branch, tag, or commit SHA to start from (only with --n)")
    parser.add_argument("--out", default="suspicious_commits.json", help="Output JSON file name (default: suspicious_commits.json)")
    parser.add_argument("--nofile", action="store_true", help="Do not save output to file")

    args = parser.parse_args()

    if args.pr is not None and args.ref is not None:
        parser.error("--ref can only be used with --n")

    if args.n is not None and not 1 <= args.n <= 100:
        parser.error("--n must be between 1 and 100")

    if args.pr is not None and args.pr < 1:
        parser.error("--pr must be a positive integer")


    ghc = GitHubClient(args.repo)

    ghc.authorize_github_api()

    async def conc_part():
        return await ghc.run_fetching_async(
            number_of_commits=args.n,
            max_concurrency=10,
            ref=args.ref,
            pr_number=args.pr
        )


    c_data = asyncio.run(conc_part())

    if not c_data:
        log.info("No commits to analyze. Exiting.")
        return

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

    for index, record in enumerate(suspicious_commits):
        record["finding_id"] = f"finding-{index}"

    suspicious_texts = [
        json.dumps(
            {
                "finding_id": record["finding_id"],
                "code": record["line"],
            },
            ensure_ascii=False
        )
        for record in suspicious_commits
    ]

    report = run_llm(suspicious_texts)
    results = attach_findings(suspicious_commits, report)

    if not args.nofile:
        save_results_to_file(results, args.out)

    stats = Counter(finding.level for finding in report.findings)
    log.info(
        "LLM summary: %s CRITICAL, %s HIGH, %s MEDIUM, %s LOW",
        stats["CRITICAL"],
        stats["HIGH"],
        stats["MEDIUM"],
        stats["LOW"]
    )

    summary = build_pr_summary(
        report=report,
        suspicious_count=len(suspicious_commits)
    )

    write_pr_msg(summary)

    return None

if __name__ == "__main__":
    main()

