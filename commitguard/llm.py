import logging, os
import sys

import asyncio
from langchain_openai import ChatOpenAI
from dotenv import load_dotenv
from langchain_core.output_parsers import PydanticOutputParser
from langchain_core.prompts import ChatPromptTemplate

from typing import List, Literal
from pydantic import BaseModel, Field

load_dotenv()
log = logging.getLogger(__name__)



llm = ChatOpenAI(
    model="gpt-5",
    temperature=0,
    api_key=os.environ["OPENAI_API_KEY"],
    timeout=60,
    max_retries=2
)

Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class Finding(BaseModel):
    level: Severity = Field(description="Severity level")
    message: str = Field(description="Short title/description")
    evidence: str = Field(description="Exact matched snippet from input")


class FindingsReport(BaseModel):
    findings: List[Finding] = Field(default_factory=list)

parser = PydanticOutputParser(pydantic_object=FindingsReport)


txt = """
    DB_PASSWORD=supersecret123
    print("hello world")        
    requests.get(url, verify=False)
    """

prompt = ChatPromptTemplate.from_messages([
    ("system",
     "You are a deterministic security analyzer for code diffs.\n"
     "Classify security risk for the provided input.\n\n"
     "Severity:\n"
     "- HIGH: real secrets/credentials (API keys, tokens, passwords, private keys, AWS keys, GitHub tokens).\n"
     "- MEDIUM: risky configs or possible secrets (JWT-like strings, test tokens, --insecure, verify=False, disabling TLS checks).\n"
     "- LOW: suspicious but likely non-exploitable (dummy/sample secrets, password variable names without real secret).\n\n"
     "Output rules:\n"
     "- Return ONLY valid JSON.\n"
     "- JSON must strictly match the provided schema and types.\n"
     "- Do NOT include any extra keys, markdown, comments, or surrounding text.\n"
     "- If something is unclear, still produce the best possible JSON that matches the schema."),
    ("human",
     "Analyze this input:\n\n"
     "{input}\n\n"
     "{format_instructions}")
]).partial(format_instructions=parser.get_format_instructions())

chain = prompt | llm | parser

def run_batches_sequential(batches: List[str]):

    responses = []
    for i, b in enumerate(batches, start=1):
        try:
            log.info(f"LLM: Running batch {i}/{len(batches)} sequentially")
            report: FindingsReport = chain.invoke({"input": b})
            responses.extend(report.findings)
        except Exception as e:
            log.error(f"LLM: Error while running query {type(e).__name__}: {e}")
            sys.exit(1)

    return responses

async def run_batches_async(batches: List[str], concurrency: int = 10):

    total = len(batches)
    if total == 0:
        return []

    concurrency = max(1, min(concurrency, total))
    sem = asyncio.Semaphore(concurrency)

    async def call_batch(i: int, batch: str):
        async with sem:
            try:
                log.info(f"LLM: Running batch {i}/{total} in parallel")
                report = await asyncio.to_thread(chain.invoke, {"input": batch})
                return report
            except Exception as e:
                log.error(f"LLM: Error while running batch {i} ({type(e).__name__}): {e}")
                sys.exit(1)

    tasks = [asyncio.create_task(call_batch(i, batch)) for i, batch in enumerate(batches, start=1)]
    return await asyncio.gather(*tasks)


def run_llm(text: List[str], batch_size : int = 6000, token_factor : float = 0.3, async_requests = True):

    batches = make_batches(text, batch_size, token_factor)
    log.info(f"LLM Configuration - Batches:{len(batches)} (Batch Size:{batch_size}, Token factor: {token_factor}), Model:{llm.model_name})")
    log.info("LLM: Running using default prompt")

    if async_requests:
        response: List[FindingsReport] = asyncio.run(run_batches_async(batches, concurrency=10))
    else:
        response: List[FindingsReport] = run_batches_sequential(batches)

    merged = []
    for r in response:
        merged.extend(r.findings)

    return convert_to_str(FindingsReport(findings=merged))



def make_batches(text: List[str] , batch_size: int = 6000, token_factor: float = 0.3):

    symbols_amount = 0
    curr_batch = ""

    batches: List[str] = []

    for line in text:
        if symbols_amount + len(line) * token_factor > batch_size:
            batches.append(curr_batch)
            curr_batch = ""
            symbols_amount = 0

        symbols_amount += (len(line) * token_factor)
        curr_batch += line + "\n"

    batches.append(curr_batch)

    return batches

def convert_to_str(report: FindingsReport) -> str:
    if not report.findings:
        return "ok"

    lines = []
    for f in report.findings:
        lines.append(f"{f.level}: {f.message} - {f.evidence}")

    return "\n".join(lines)



## findings=[Finding(level='HIGH', message='Hardcoded database password', evidence='DB_PASSWORD=supersecret123'),
# Finding(level='MEDIUM', message='SSL/TLS certificate verification disabled', evidence='requests.get(url, verify=False)')]
