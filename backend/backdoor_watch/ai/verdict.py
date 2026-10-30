import re

from backdoor_watch.domain.ai import AiVerdict

_VERDICT_LINE = re.compile(r"VERDICT:\s*(COMPROMISE|SUSPICIOUS|CLEAR)", re.IGNORECASE)
_PHRASES = (
    (AiVerdict.COMPROMISE, re.compile(r"signs of compromise", re.IGNORECASE)),
    (AiVerdict.SUSPICIOUS, re.compile(r"suspicious\W+needs checking", re.IGNORECASE)),
    (AiVerdict.CLEAR, re.compile(r"no evidence of compromise", re.IGNORECASE)),
)
_VERDICT_SECTION_CHARS = 1500


def parse_verdict(markdown: str) -> AiVerdict:
    """Reads the verdict the system prompt asks for; falls back to the earliest verdict phrase."""
    explicit = _VERDICT_LINE.search(markdown)
    if explicit:
        return AiVerdict(explicit.group(1).lower())
    head = markdown[:_VERDICT_SECTION_CHARS]
    positions = [(match.start(), verdict) for verdict, pattern in _PHRASES if (match := pattern.search(head))]
    return min(positions)[1] if positions else AiVerdict.UNKNOWN
