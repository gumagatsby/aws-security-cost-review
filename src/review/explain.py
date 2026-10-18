"""The summary paragraph at the top of a report.

The rules find the problems; a model only writes the summary. Its text is checked before it's used: every finding it
cites must exist, and every number in it must come from the findings. If the check fails, or the model can't be
called, the plain summary is used and the report says which one it shows.
"""
import json
import re

from botocore.exceptions import BotoCoreError, ClientError

from .findings import Finding
from .rules import RULES

MODEL = "amazon.nova-lite-v1:0"

PROMPT = """You are writing the opening paragraph of an AWS review report for a manager who isn't an engineer.
Below are the findings, numbered. Write 3 to 5 plain sentences: what matters most and what to do first.
Rules: refer to findings only by their number in square brackets, like [2]. Use no number that isn't in the findings.
Don't add problems that aren't listed. No headings, no bullet points, no dashes.

Findings:
{findings}"""


def plain(findings: list[Finding]) -> str:
    open_ = [f for f in findings if not f.accepted]
    if not open_:
        return "No open findings. Every rule passed or was accepted on purpose, with its reason listed below."
    counts = {s: sum(RULES[f.rule].severity == s for f in open_) for s in ("high", "medium", "low")}
    parts = [f"{n} {s}" for s, n in counts.items() if n]
    high: dict[str, list[int]] = {}
    for i, f in enumerate(findings, 1):
        if not f.accepted and RULES[f.rule].severity == "high":
            high.setdefault(f.rule, []).append(i)
    text = f"{len(open_)} open findings: {', '.join(parts)}."
    if high:
        first = list(high.items())[:3]
        text += " Start with: " + "; ".join(f"{RULES[r].title} [{', '.join(map(str, ns))}]" for r, ns in first) + "."
    return text


def check_summary(text: str, findings: list[Finding]) -> list[str]:
    """Reasons the model's summary can't be used; empty if it can."""
    problems = []
    cited = {int(n) for group in re.findall(r"\[([\d, ]+)\]", text) for n in re.findall(r"\d+", group)}
    if bad := sorted(n for n in cited if not 1 <= n <= len(findings)):
        problems.append(f"cites findings that don't exist: {bad}")
    source = json.dumps([f.to_dict() for f in findings]) + f" {len(findings)}"
    allowed = set(re.findall(r"\d+", source)) | {str(n) for n in cited}
    stripped = re.sub(r"\[[\d, ]+\]", "", text)
    if bad := sorted(set(re.findall(r"\d+", stripped)) - allowed):
        problems.append(f"uses numbers not in the findings: {bad}")
    if "—" in text or "–" in text:
        problems.append("uses a dash")
    if not cited and findings:
        problems.append("cites no finding")
    return problems


def summarise(findings: list[Finding], bedrock=None) -> tuple[str, str]:
    """The summary, and where it came from: 'model', or 'plain' with the reason."""
    open_ = [f for f in findings if not f.accepted]
    if bedrock is None or not open_:
        return plain(findings), "plain"
    listing = "\n".join(f"[{i}] {RULES[f.rule].title} ({RULES[f.rule].severity}), {f.resource}"
                        + (f", {f.detail}" if f.detail else "") for i, f in enumerate(findings, 1) if not f.accepted)
    try:
        r = bedrock.converse(modelId=MODEL, messages=[{"role": "user", "content": [
            {"text": PROMPT.format(findings=listing)}]}], inferenceConfig={"temperature": 0, "maxTokens": 400})
        text = r["output"]["message"]["content"][0]["text"].strip()
    except (BotoCoreError, ClientError) as e:
        return plain(findings), f"plain: the model couldn't be called ({type(e).__name__})"
    if problems := check_summary(text, findings):
        return plain(findings), "plain: the model's summary failed its check (" + "; ".join(problems) + ")"
    return text, "model"
