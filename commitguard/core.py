import argparse
import asyncio
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
        commits = ghc.extract_commits_code(commit_data)
        return commit_hashes, commits, delta_time

    c_hashes, c_data, time = asyncio.run(conc_part())

if __name__ == "__main__":
    main()




