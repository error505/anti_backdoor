from backdoor_watch.ai.verdict import parse_verdict
from backdoor_watch.domain.ai import AiVerdict


def test_reads_explicit_verdict_line():
    assert parse_verdict("VERDICT: SUSPICIOUS\n\n## Verdict\n...") == AiVerdict.SUSPICIOUS


def test_falls_back_to_verdict_phrase():
    text = "## Verdict\n**No evidence of compromise in this snapshot.** The flagged node.exe is Codex."
    assert parse_verdict(text) == AiVerdict.CLEAR


def test_compromise_phrase():
    assert parse_verdict("1. **Verdict**: Signs of compromise. InvisibleFerret folder present.") == AiVerdict.COMPROMISE


def test_unknown_when_no_verdict_given():
    assert parse_verdict("Here is some analysis without a verdict.") == AiVerdict.UNKNOWN
