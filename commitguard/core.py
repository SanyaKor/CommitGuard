import argparse
import asyncio
import json
from .leaks_parser import LeaksParser
from .githubclient import GitHubClient
from typing import List
from .llm import run_single_querry, build_prompt, llm
from .logging_config import get_logger
from collections import Counter

log = get_logger(__name__)


def save_llm_results_to_json(commits_data, content: str, filepath: str = "output.json") -> None:
    results: List[dict] = []


    for line in content.splitlines():
        line = line.strip()
        if not line or line.lower().startswith("ok"):
            continue

        if ":" in line:
            level, msg = line.split(":", 1)
            results.append({
                "level": level.strip().upper(),
                "message": msg.strip()
            })
        else:
            results.append({"level": "UNKNOWN", "message": line})

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)


def main():
    parser = argparse.ArgumentParser(prog="commitguard", description="Scan github repository for commits (searching for some leaks / weak / insecure places)")
    parser.add_argument("--repo", required=True, help="URL GitHub-repo (HTTPS or SSH)")
    parser.add_argument("--n", required=True, help="Amount of commits to fetch [1, 100]")

    args = parser.parse_args()

    ghc = GitHubClient(args.repo)
    ghc.authorize_github_api()

    async def conc_part():
        commit_data = await ghc.run_fetching_async(int(args.n), 10)
        return commit_data


    c_data = asyncio.run(conc_part())
    leaksparser = LeaksParser()

    suspicious_lines_list :List[str] = []

    for commit_hash, details in c_data.items():
        c_diffs = ghc.get_commit_diffs(commit_hash)
        c_diffs_code = [item["code"] for group in ("additions", "deletions") for item in c_diffs[group]]
        suspicious_lines = leaksparser.run_scanner(c_diffs_code)
        suspicious_lines_list.extend(suspicious_lines)

    if not suspicious_lines_list:
        log.info("Leaks parser did not find anything suspicious")
        return

    log.info(f"Leaks parser found {len(suspicious_lines_list)} suspicious line(s), sending to LLM for analysis")
    query = build_prompt(suspicious_lines_list)
    response = run_single_querry(llm, query)

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
    log.debug(
        f"LLM summary: "
        f"{stats.get('HIGH', 0)} HIGH, "
        f"{stats.get('MEDIUM', 0)} MEDIUM, "
        f"{stats.get('LOW', 0)} LOW, "
        f"{stats.get('OK', 0)} OK"
    )
    print(response)

if __name__ == "__main__":
    main()

