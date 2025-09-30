import re
from typing import List, Tuple
from .logging_config import get_logger
import math

log = get_logger(__name__)

class LeaksParser:
    TEST_WORDS = [
        "test", "tests", "example", "examples", "sample", "dummy", "sandbox",
        "dev", "staging", "local", "ci", "fixture", "mock", "demo", "placeholder"
    ]

    RULES: List[Tuple[str, str]] = [
        ("PrivateKeyBlock", r"-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----"),
        ("AWSAccessKeyID", r"\bAKIA[0-9A-Z]{16}\b"),
        ("GitHubToken", r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,251}\b"),
        ("GitHubFineGrainedToken", r"\bgithub_pat_[A-Za-z0-9_]{82,}\b"),
        ("GoogleAPIKey", r"\bAIza[0-9A-Za-z\-_]{35}\b"),
        ("SlackToken", r"\bxox(?:p|b|o|a|s)-[0-9A-Za-z\-]{10,}\b"),
        ("StripeLiveKey", r"\bsk_live_[0-9A-Za-z]{24,}\b"),
        ("TelegramBotToken", r"\b\d{9,}:[A-Za-z0-9_-]{35}\b"),
        ("JWT", r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        ("PasswordAssignment", r"(?i)\b(pass(word)?|secret|token|api[_-]?key)\b\s*[:=]\s*['\"][^'\"]{6,}['\"]"),
        ("BasicAuthInURL", r"(?i)\b[a-z][a-z0-9+\-.]*://[^/\s:@]+:[^@\s]+@"),
    ]
    COMPILED_RULES = [re.compile(rx) for _, rx in RULES]


    def __init__(self, filename : str):
        self.__filename = filename
        log.info("Initializing Leaks parser")

    def run_scanner(self, lines : List[str]):

        log.debug(f"Running scanner on {len(lines)} lines")
        rules_hits = self.__lines_matching_rules(lines)
        entropy_hits = self.__lines_matching_entropy(lines)
        test_hits = self.__lines_matching_test_words(lines)

        log.debug(f"Rule hits: {rules_hits}")
        log.debug(f"Entropy hits: {entropy_hits}")
        log.debug(f"Test hits: {test_hits}")

        results: List[str] = []

        for line in rules_hits:
            if line not in results and line not in test_hits:
                results.append(line)
                log.debug(f"  [+] added from RULES: {line}")

        for line in entropy_hits:
            if line not in results and line not in test_hits:
                results.append(line)
                log.debug(f"  [+] added from ENTROPY: {line}")

        if not results:
            log.info("Nothing suspicious detected")
        return results

    def __lines_matching_rules(self, lines: List[str]) -> List[str]:

        result: List[str] = []

        for line in lines:
            for rx in self.COMPILED_RULES:
                if rx.search(line):
                    result.append(line)
                    break

        return result

    def __lines_matching_test_words(self,lines: List[str]) -> List[str]:

        result: List[str] = []

        for line in lines:
            ln = line.lower()
            if any(w in ln for w in self.TEST_WORDS):
                result.append(line)

        return result

    def __lines_matching_entropy(self,lines: List[str], threshold: float = 4.0) -> List[str]:

        result: List[str] = []
        candidate = re.compile(r"[A-Za-z0-9_\-+/=]{20,}")

        for line in lines:
            for match in candidate.findall(line):
                if self.__shannon_entropy(match) >= threshold:
                    result.append(line)
                    break

        return result

    def __shannon_entropy(self, s: str) -> float:

        if not s:
            return 0.0

        freq = {ch: s.count(ch) for ch in set(s)}
        n = len(s)
        return -sum((c / n) * math.log2(c / n) for c in freq.values())



