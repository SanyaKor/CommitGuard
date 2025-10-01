import logging
from collections import Counter
from langchain_openai import ChatOpenAI
import os
from dotenv import load_dotenv
from typing import List

load_dotenv()
log = logging.getLogger(__name__)

llm = ChatOpenAI(
    model="gpt-5",
    temperature=0,
    api_key=os.environ["OPEN_AI_API_KEY"],
    timeout=60,
    max_retries=2
)

PROMPT_TEMPLATE = """
You are a security analyzer.
Your task is to scan given code lines (for example, from GitHub commits) and classify them by security risk.

Rules:
- If the line contains sensitive information (like API keys, tokens, passwords, secrets, credentials, private keys, hardcoded access data, disabled TLS checks, etc.), classify it into one of 3 levels:
  - HIGH: Critical secrets (e.g., real API tokens, private keys, AWS keys, DB passwords, GitHub tokens).
  - MEDIUM: Potential secrets or risky configurations (e.g., test tokens, JWT-like strings, insecure flags like --insecure, disabling SSL verification).
  - LOW: Suspicious but not directly exploitable (e.g., sample/dummy secrets, references to “password” variables without actual secrets).
- If the line looks safe, return exactly:
  ok

Output format:
- For each input line, return either `ok` or `THREAT_LEVEL: <short explanation>`.

Example:

Input:
DB_PASSWORD=supersecret123
print("hello world")
requests.get(url, verify=False)

Output:
HIGH: hardcoded DB password - DB_PASSWORD=supersecret123
ok
MEDIUM: insecure TLS verification disabled - requests.get(url, verify=False)

Now analyze the following lines:

Input:
{lines}

Output:
"""

def build_prompt(lines: List[str]) -> str:
    return PROMPT_TEMPLATE.format(lines="\n".join(lines))

def run_single_querry(llm: ChatOpenAI, prompt: str) -> str:
    log.info(f"LLM request started [model={llm.model_name}]")
    try:
        r = llm.invoke(prompt)
        content = r.content.strip()
        return content

    except Exception as e:
        error_msg = f"[ERROR] {type(e).__name__}: {e}"
        log.error(error_msg)
        return error_msg