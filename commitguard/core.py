import argparse
import asyncio
import json
from .leaks_parser import LeaksParser
from .githubclient import GitHubClient
from typing import List, Dict, Any
from .llm import run_llm
from .logging_config import get_logger
from collections import Counter

log = get_logger(__name__)



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
    parser.add_argument("--out", required=True, help="Output json file name(default - suspicious_commits.json)")

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

    save_results_to_file(suspicious_commits, args.out)

    return None

if __name__ == "__main__":
    main()

