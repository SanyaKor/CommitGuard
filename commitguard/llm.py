import logging
from langchain_openai import ChatOpenAI
import os
from dotenv import load_dotenv
from typing import List
import asyncio
import sys


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


def run_batches_sequential(llm: ChatOpenAI, batches: List[str]):

    results: List[str] = []
    for i, batch in enumerate(batches, start=1):
        try:
            log.info(f"LLM: Running batch {i}/{len(batches)} sequentially")
            r = llm.invoke(batch)
            results.append(r.content)
        except Exception as e:
            log.error(f"LLM: Error while running query {type(e).__name__}: {e}")
            sys.exit(1)

    return results


async def run_batches_parallel(llm: ChatOpenAI, batches: List[str], concurrency: int = 10):

    if len(batches) < concurrency:
        concurrency = len(batches)

    async def call_batch(batch: str, i: int) -> str:
        try:
            log.info(f"LLM: batch {i}/{len(batches)} in parallel")
            r = await asyncio.to_thread(llm.invoke, batch)
            return r.content
        except Exception as e:
            log.error(f"LLM: Error while running query {type(e).__name__}: {e}")
            sys.exit(1)

    tasks = [call_batch(batch, i) for i, batch in enumerate(batches, start=1)]
    return await asyncio.gather(*tasks)


def make_batches(text: List[str],
                    batch_size: int = 6000,
                    token_factor: float = 0.3,
                    prompt_template: str = PROMPT_TEMPLATE):

    symbols_amount = len(PROMPT_TEMPLATE) * token_factor
    curr_batch = ""

    batches: List[str] = []

    for line in text:
        if symbols_amount + len(line) * token_factor > batch_size:
            batches.append(curr_batch)
            curr_batch = ""
            symbols_amount = len(PROMPT_TEMPLATE) * token_factor

        symbols_amount += (len(line) * token_factor)
        curr_batch += line + "\n"


    batches.append(curr_batch)

    batches = [build_prompt(b) for b in batches]

    return batches




def run_llm(text: List[str], async_requests = True):

    log.info("Using default prompt")
    batches = make_batches(text)

    if async_requests :
        response = asyncio.run(run_batches_parallel(llm, batches))
    else:
        response = run_batches_sequential(llm, batches)

    results = "\n".join(response)

def build_prompt(text: str) -> str:
    return PROMPT_TEMPLATE.format(lines=text)

def run_single_query(llm: ChatOpenAI, prompt: str) -> str:
    log.info(f"LLM request started [model={llm.model_name}]")
    try:
        r = llm.invoke(prompt)
        content = r.content.strip()
        return content

    except Exception as e:
        error_msg = f"[ERROR] {type(e).__name__}: {e}"
        log.error(error_msg)
        return error_msg

###TODO async requests