# CommitGuard


CommitGuard is a CLI tool to scan GitHub repositories for leaks, insecure configs, and weak spots in commit history. It fetches commits and checks them for **hardcoded secrets, API tokens, passwords, private keys, etc.**  

The analysis is **LLM-powered**, meaning suspicious findings can be further classified into risk levels (HIGH/MEDIUM/LOW) by a language model (via LangChain, with support for OpenAI or other providers).

---

## Requirements

- Python **3.12+**

Install dependencies and the tool locally:

```bash
pip install -r requirements.txt
pip install -e .
```


## Usage

Run via CLI:.

```bash
commitguard --repo <GITHUB_REPO_URL> --n <NUMBER_OF_COMMITS> --out <OUTPUT_JSON_FILE_NAME>
```

### Arguments
- `--repo` — GitHub repository URL (HTTPS or SSH)
- `--n` — number of commits to fetch (1–100)
- `--out` — Output json file name(default - suspicious_commits.json)
---

### Usage Examples

** Scan the last 5 commits of a repo via HTTPS**
```bash
commitguard --repo https://github.com/owner/repo.git --n 5 --out output.json
```

## Output
### JSON Logs

- Suspicious findings are reported with counts of **HIGH**, **MEDIUM**, and **LOW** threats.  
- Results are saved to `suspicious_commits.json`, including:  
  - code line  
  - file + line location  
  - commit metadata  
  - risk level (LLM)  
```bash
[
  {
    "line": "password = \"supersecret123\"",
    "location": "app/config.py:42",
    "author": "octocat",
    "date": "2025-09-30T12:00:00Z",
    "commit_message": "fix db connection",
    "llm_response": "HIGH: hardcoded password",
    "commit_sha": "xxxxxxxxxxxxxxxxxxxxxx"
  }
]
```

### Notes

This program requires a valid GitHub API key AND LLM key(openai), dont forget to set your own personal access token as an environment variable:

```bash
export GH_PAT="your_personal_access_token_here"
export OPENAI_API_KEY=sk-...
```

---
## LLM Configuration (pluggable via LangChain)

CommitGuard uses LangChain, so you can plug **any chat model** with a LangChain wrapper:
OpenAI, Ollama, AnthropicLLM, ... etc.

### Quick switch (env-based)
Set API key via env:
```bash
export OPEN_AI_API_KEY=sk-...
```

## Tests

CommitGuard includes a test suite to validate core functionality:
- GitHub API auth
- Commit fetching (sync/async)
- Leak parser (regex, test context, entropy)
- TODO: LLM integration flow

Run tests with:

```bash
pytest -v
```


---

## Further Development
Planned improvements and next steps for CommitGuard:

- Expand leak parser rules with more patterns (cloud provider keys, OAuth tokens, etc.)  
- Refine entropy-based detection to reduce false positives  
- Optimize LLM integration (batch processing, better scoring, MCP, data vectorisation + db hosting(chroma))  
- Add more tests for leak parser and LLM workflow  
- Provide GitHub Actions workflow for automatic scanning on pull requests  
