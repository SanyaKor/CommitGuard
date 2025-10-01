import argparse
import asyncio
from .leaks_parser import LeaksParser
from .githubclient import GitHubClient
from typing import List
from .llm import run_single_querry, build_prompt, llm
from .logging_config import get_logger
from collections import Counter

log = get_logger(__name__)

def main():
    parser = argparse.ArgumentParser(prog="commitguard", description="Scan github repository for commits (searching for some leaks / weak / insecure places)")
    parser.add_argument("--repo", required=True, help="URL GitHub-repo (HTTPS or SSH)")
    parser.add_argument("--n", required=True, help="Amount of commits to fetch [1, 100]")

    args = parser.parse_args()

    ghc = GitHubClient(args.repo)
    ghc.authorize_github_api()

    async def conc_part():
        commit_hashes, commit_data, delta_time = await ghc.run_fetching_async(int(args.n), 10)
        return commit_hashes, commit_data, delta_time

    c_hashes, c_data, time = asyncio.run(conc_part())
    leaksparser = LeaksParser("")

    suspicious_text_commits = []
    all_suspicious_lines :List[str] = []

    for hash in c_hashes:
        c_diffs = ghc.get_commit_diffs(c_data, hash)
        diffs_text = ghc.get_commit_diffs_text(c_diffs, deletions_included = False)
        suspicious_lines = leaksparser.run_scanner(diffs_text)
        all_suspicious_lines.extend(suspicious_lines)
        suspicious_text_commits.append([hash, suspicious_lines])

    if not all_suspicious_lines:
        log.info("Leaks parser did not find anything suspicious")
        return

    log.info(f"Leaks parser found {len(all_suspicious_lines)} suspicious line(s), sending to LLM for analysis")
    query = build_prompt(all_suspicious_lines)
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

