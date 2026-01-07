import re
import os
import sys
import requests
import asyncio
import time
from pathlib import Path
from typing import List, Dict, Tuple
from dotenv import load_dotenv
from .logging_config import get_logger

log = get_logger(__name__)



class GitHubClient:
    ALLOWED_EXTENSIONS = {
        ".py", ".js", ".java", ".go", ".rb", ".php", ".cs", ".c", ".cpp",
        ".yml", ".yaml", ".json", ".cfg",
        ".sh", ".bash", ".key", ".ipynb"
    }
    MAX_COMMITS = 100

    def __init__(self, repo_url: str):
        owner, repo = self.__parse_github_url(repo_url)
        self.__commits_lists_url = f"https://api.github.com/repos/{owner}/{repo}/commits"
        self.__commits_details_url = f"https://api.github.com/repos/{owner}/{repo}/commits/{{sha}}"
        self.__session = requests.Session()
        self.__commit_data = None

    #region PUBLIC methods
    def authorize_github_api(self):
        load_dotenv()
        github_token = os.getenv("BOT_PAT")

        self.__session = requests.Session()

        if not github_token:
            log.error("Error there is no GITHUB_TOKEN in environment")
            sys.exit(1)


        self.__session.headers.update({
            "Accept": "application/vnd.github+json",
            "User-Agent": "commitguard/1.0"
        })
        if github_token:
            self.__session.headers["Authorization"] = f"token {github_token}"


        resp = self.__session.get("https://api.github.com/user", timeout=10)

        if resp.status_code == 200:
            try:
                data = resp.json()
            except ValueError:
                log.error("Auth failed: response is not valid JSON")
                sys.exit(1)

            limit = resp.headers.get("X-RateLimit-Limit")
            remaining = resp.headers.get("X-RateLimit-Remaining")

            log.info(f"Auth in Github API successful [ User login = {data.get("login")}, rate_limits = {remaining}/{limit}, 1 commit - 1 token ]")

        else:
            body = str(getattr(resp, "text", ""))
            log.error("Auth failed")
            log.error(f"Status: {resp.status_code} Body: {body[:200]}")
            sys.exit(1)

    def run_fetching_sync(self, number_of_commits : int):

        if number_of_commits > self.MAX_COMMITS or number_of_commits < 1:
            log.error(f"Invalid number of commits [1:{self.MAX_COMMITS}], exiting ..")
            sys.exit(1)

        log.info(f"Fetching {number_of_commits} commit(s) ...")
        start_time = time.time()
        commit_hashes = self.__fetch_commits_list(number_of_commits)
        commit_data: Dict[str, Dict] = {}

        for commit_hash in commit_hashes:
            log.debug(f"Fetching commit {commit_hash}")
            commit_data[commit_hash] = self.__fetch_commit_details_sync(commit_hash)

        log.info(f"Successfully fetched {number_of_commits} commit(s)")
        delta_time = time.time() - start_time
        log.debug(f"Elapsed time: {delta_time} seconds")
        self.__commit_data = commit_data

        return commit_data

    async def run_fetching_async(self, number_of_commits : int, max_concurrency: int) :

        if number_of_commits > self.MAX_COMMITS or number_of_commits < 1:
            log.error(f"Invalid number of commits [1:{self.MAX_COMMITS}], exiting ..")
            sys.exit(1)

        log.info(f"Fetching {number_of_commits} commit(s) ...")

        start_time = time.time()
        commit_hashes = await asyncio.to_thread(self.__fetch_commits_list, number_of_commits)

        sem = asyncio.Semaphore(max_concurrency)

        async def guarded(commit_hash: str):
            log.debug(f"Fetching commit {commit_hash}")
            async with sem:
                return await self.__fetch_commit_details_async(commit_hash)

        results = await asyncio.gather(*(guarded(commit_hash) for commit_hash in commit_hashes))
        log.info(f"Successfully fetched {number_of_commits} commit(s)")


        commit_data: Dict[str, Dict] = {}
        for commit_hash, data in results:
            commit_data[commit_hash] = data

        delta_time = time.time() - start_time
        log.debug(f"Elapsed time: {delta_time} seconds")
        self.__commit_data = commit_data

        return commit_data

    ###TODO verification for async fetching

    def get_commit_details(self, commit_hash: str):

        c_data = None

        for sha, data in self.__commit_data.items():
            if sha == commit_hash:
                log.debug(f"Found commit {sha}")
                c_data = data
                break

        if not c_data:
            log.error(f"Not found commit {commit_hash}")
            return None

        line_regex = re.compile(
            r"@@ -(?P<old_start>\d+)(?:,(?P<old_count>\d+))? \+(?P<new_start>\d+)(?:,(?P<new_count>\d+))? @@")

        def right_filename_extension(filename: str):

            path = Path(filename)

            ext = path.suffix.lower()
            if ext in self.ALLOWED_EXTENSIONS:
                log.debug(f"{filename} allowed extension ")
                return True

            log.debug(f"{filename} ignored extension ")
            return False


        additions: List[Dict[str, str]] = []
        deletions: List[Dict[str, str]] = []


        for f in c_data.get("files", []):
            patch = f.get("patch")
            if not patch:
                continue

            filename = f["filename"]
            if not right_filename_extension(filename):
                continue

            addition_line_number = None
            deletion_line_number = None

            for line in patch.splitlines():
                m = line_regex.match(line)
                if m:
                    addition_line_number = int(m.group("new_start"))
                    deletion_line_number = int(m.group("old_start"))
                    continue

                if line.startswith("+") and not line.startswith("+++"):
                    location = f"{filename}:{addition_line_number if addition_line_number is not None else ''}"
                    text = line[1:]
                    additions.append({"location": location, "code": text})
                    if addition_line_number is not None:
                        addition_line_number += 1
                    continue

                if line.startswith("-") and not line.startswith("---"):
                    location = f"{filename}:{deletion_line_number if deletion_line_number is not None else ''}"
                    text = line[1:]
                    deletions.append({"location": location, "code": text})
                    if deletion_line_number is not None:
                        deletion_line_number += 1
                    continue

                if line.startswith(" "):
                    if addition_line_number is not None:
                        addition_line_number += 1
                    if deletion_line_number is not None:
                        deletion_line_number += 1
                    continue


        details = {
            "additions": additions,
            "deletions": deletions,
            "author": c_data.get("author_name"),
            "date": c_data.get("date"),
            "commit_message": c_data.get("commit_message"),
        }

        return details
    #endregion

    # region PRIVATE methods

    def __fetch_commits_list(self, number_of_commits: int) -> List[str]:

        if(number_of_commits > self.MAX_COMMITS or number_of_commits < 1):
            log.error(f"Invalid number of commits [1:{self.MAX_COMMITS}], exiting ..")
            sys.exit(1)

        params = {"per_page": number_of_commits}
        resp = self.__session.get(self.__commits_lists_url, params=params, timeout=20)

        resp.raise_for_status()
        data = resp.json()
        commit_hashes = [item["sha"] for item in data][:number_of_commits]

        if len(commit_hashes) < number_of_commits:
            log.warning(f"warning : fetched only {len(commit_hashes)} SHA")

        return commit_hashes

    def __fetch_commit_details_sync(self, commit_hash: str) -> Dict:

        log.debug(f"fetching commit details for {commit_hash}")
        url = self.__commits_details_url.format(sha=commit_hash)

        try:
            resp = self.__session.get(url, timeout=20)
            resp.raise_for_status()

        except requests.RequestException as e:
            log.error(f"Fetching failed for {commit_hash}")
            log.error(f"Request error: {e}")
            sys.exit(1)

        j = resp.json() or {}
        commit = j.get("commit") or {}
        author = commit.get("author") or {}
        files = j.get("files") or []

        msg = (commit.get("message") or "")
        first_line = msg.partition("\n")[0]

        return {
            "sha": j.get("sha"),
            "author_name": author.get("name"),
            "date": author.get("date"),
            "commit_message": first_line,
            "files": files,
        }

    async def __fetch_commit_details_async(self, commit_hash: str) -> Tuple[str, Dict]:
        data = await asyncio.to_thread(self.__fetch_commit_details_sync, commit_hash)
        return commit_hash, data

    def __parse_github_url(self, url: str):
        git_regex = re.compile(
            r"^(?:https://github\.com/|git@github\.com:)(?P<owner>[^/]+)/(?P<repo>[^/]+?)(?:\.git)?/?$",
            re.IGNORECASE,
        )
        m = git_regex.match(url)
        if not m:
            return None, None
        return m.group("owner"), m.group("repo")
    #endregion













