import re
from typing import List, Tuple
from .logging_config import get_logger
import math

log = get_logger(__name__)

class LeaksParser:

    RULES: List[Tuple[str, str]] = [
        ("UnquotedSecretAssignment", r"""(?im)^\s*(?:export\s+)?(?:[a-z0-9]+_)*(?:pass(?:word|wd)?|secret|token|api[_-]?key)(?:_[a-z0-9]+)*\s*[:=]\s*(?P<secret>[^\s'"\#]+)\s*(?:#.*)?$"""),
        ("BearerAuthorization", r"""(?i)\bAuthorization\s*:\s*Bearer\s+(?P<secret>[A-Za-z0-9._~+/\-]+=*)"""),
        ("BasicAuthorization", r"""(?i)\bAuthorization\s*:\s*Basic\s+(?P<secret>[A-Za-z0-9+/]+={0,2})"""),
        ("PrivateKeyBlock", r"-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----"),
        ("AWSAccessKeyID", r"\bAKIA[0-9A-Z]{16}\b"),
        ("GitHubToken", r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,251}\b"),
        ("GitHubFineGrainedToken", r"\bgithub_pat_[A-Za-z0-9_]{82,}\b"),
        ("GoogleAPIKey", r"\bAIza[0-9A-Za-z\-_]{35}\b"),
        ("SlackToken", r"\bxox(?:p|b|o|a|s)-[0-9A-Za-z\-]{10,}\b"),
        ("StripeLiveKey", r"\bsk_live_[0-9A-Za-z]{24,}\b"),
        ("TelegramBotToken", r"\b\d{9,}:[A-Za-z0-9_-]{35}\b"),
        ("JWT", r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        ("PasswordAssignment", r"""(?i)\b(?:[a-z0-9]+_)*(?:pass(?:word|wd)?|secret|token|api[_-]?key)(?:_[a-z0-9]+)*\b\s*[:=]\s*(?P<quote>['"])(?P<secret>[^'"]+)(?P=quote)"""),
        ("BasicAuthInURL", r"(?i)\b[a-z][a-z0-9+\-.]*://[^/\s:@]+:[^@\s]+@"),
    ]
    COMPILED_RULES = [ (name, re.compile(pattern)) for name, pattern in RULES ]

    PLACEHOLDERS = {
        "example",
        "placeholder",
        "changeme",
        "your_token_here",
        "your_api_key_here",
        "test-placeholder"
    }

    ENTROPY_CANDIDATE = re.compile(r"[A-Za-z0-9_\-+/=]{20,}")

    def __init__(self):
        log.info("Initializing Leaks parser")

    def scan_line(self, line: str) -> dict | None:

        hits = self._find_rule_hits(line)
        hits.extend(self._find_entropy_hits(line, hits))

        if not hits:
            return None

        return {
            "redacted_code": self._redact(line, hits),
            "matches": [ self._describe_hit(line, hit) for hit in hits ]
        }

    def _find_rule_hits(self, line: str) -> list[dict]:

        hits = []

        for rule_name, pattern in self.COMPILED_RULES:
            for match in pattern.finditer(line):
                group = "secret" if "secret" in pattern.groupindex else 0
                start, end = match.span(group)

                hits.append({"rule": rule_name, "start": start, "end": end})

        return hits

    def _find_entropy_hits(self, line: str, rule_hits: list[dict]) -> list[dict]:

        hits = []

        for match in self.ENTROPY_CANDIDATE.finditer(line):
            if self.__shannon_entropy(match.group()) < 4.0:
                continue

            start, end = match.span()

            already_detected = any(
                hit["start"] <= start and end <= hit["end"]
                for hit in rule_hits
            )

            if already_detected:
                continue

            hits.append({"rule": "HighEntropy", "start": start, "end": end})

        return hits

    def _describe_hit(self, line: str, hit: dict) -> dict:
        value = line[hit["start"]:hit["end"]]

        return {
            "rule": hit["rule"],
            "length": len(value),
            "entropy": round(self.__shannon_entropy(value), 2),
            "matches_known_placeholder": (value.casefold() in self.PLACEHOLDERS)
        }

    def _redact(self, line: str, hits: list[dict]) -> str:
        spans = sorted( (hit["start"], hit["end"]) for hit in hits )
        merged = []

        for start, end in spans:
            if merged and start <= merged[-1][1]:
                previous_start, previous_end = merged[-1]
                merged[-1] = (previous_start, max(previous_end, end))
            else:
                merged.append((start, end))

        for start, end in reversed(merged):
            line = line[:start] + "<REDACTED>" + line[end:]

        return line

    def __shannon_entropy(self, s: str) -> float:

        if not s:
            return 0.0

        freq = {ch: s.count(ch) for ch in set(s)}
        n = len(s)
        return -sum((c / n) * math.log2(c / n) for c in freq.values())



