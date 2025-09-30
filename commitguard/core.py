import argparse
import asyncio
from .leaks_parser import LeaksParser
from .githubclient import GitHubClient

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

    for hash in c_hashes:
        c_diffs = ghc.get_commit_diffs(c_data, hash)
        diffs_text = ghc.get_commit_diffs_text(c_diffs, deletions_included = False)
        leaks_text = leaksparser.run_scanner(diffs_text)


if __name__ == "__main__":
    main()

