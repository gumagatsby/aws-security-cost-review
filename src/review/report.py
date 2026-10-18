"""Writes the review as Markdown for people and JSON for tools."""
import json
from datetime import UTC, datetime

from .findings import Finding
from .rules import RULES, doc_url

PILLARS = ("Security", "Cost optimization", "Reliability")

LIMITS = {
    "terraform": "Read from the Terraform files alone. Values set by variables or other resources can't be known "
                 "without a plan, so a rule fires only on what a file states or on a setting that's missing. "
                 "Resources created by modules from a registry aren't read.",
    "account": "Read from the account through read-only API calls, in the regions listed. Only the rules below are "
               "checked; this isn't a full Well-Architected review, which also covers how the team operates.",
}


def _source_note(source: str) -> str:
    if source == "model":
        return "Summary written by Amazon Nova Lite and checked against the findings."
    if source.startswith("plain: "):
        return f"Summary written from the rules alone; {source[7:]}."
    return "Summary written from the rules alone."


def markdown(findings: list[Finding], scope: str, target: str, summary: str, summary_source: str,
             skipped: list[str] = ()) -> str:
    open_ = [f for f in findings if not f.accepted]
    accepted = [f for f in findings if f.accepted]
    lines = [
        "# AWS security and cost review", "",
        f"**Reviewed:** {target}  ",
        f"**Date:** {datetime.now(UTC):%d %B %Y}  ",
        f"**Rules:** {len(RULES)}, each mapped to an AWS Well-Architected best practice", "",
        "## Summary", "", summary, "",
        f"*{_source_note(summary_source)}*",
        "",
        "| Pillar | High | Medium | Low |", "|---|---|---|---|",
    ]
    for p in PILLARS:
        row = [sum(RULES[f.rule].pillar == p and RULES[f.rule].severity == s for f in open_) for s in ("high", "medium", "low")]
        lines.append(f"| {p} | {row[0]} | {row[1]} | {row[2]} |")
    lines += ["", "## Findings", ""]
    if not open_:
        lines += ["None open.", ""]
    for i, f in enumerate(findings, 1):
        if f.accepted:
            continue
        r = RULES[f.rule]
        lines += [
            f"### {i}. {r.title}", "",
            f"**{r.severity.capitalize()}** · {r.pillar} · `{f.resource}` · {f.where}" + (f" · {f.detail}" if f.detail else ""), "",
            f"**Why it matters:** {r.why}", "",
            f"**Fix:** {r.fix}", "",
            f"**Best practice:** [{r.practice} {r.practice_title}]({doc_url(r)})", "",
        ]
    if accepted:
        lines += ["## Accepted on purpose", "", "| # | Finding | Resource | Reason given |", "|---|---|---|---|"]
        for i, f in enumerate(findings, 1):
            if f.accepted:
                lines.append(f"| {i} | {RULES[f.rule].title} | `{f.resource}` ({f.where}) | {f.accepted} |")
        lines.append("")
    lines += ["## What this review didn't cover", "", LIMITS[scope], ""]
    if skipped:
        intro = ("These checks were refused by the account, usually by a service control policy or a missing "
                 "permission, so nothing is known about them:")
        lines += [intro, ""] + [f"- {s}" for s in skipped] + [""]
    return "\n".join(lines)


def as_json(findings: list[Finding], scope: str, target: str, summary_source: str, skipped: list[str] = ()) -> str:
    return json.dumps({"scope": scope, "target": target, "summary_source": summary_source, "not_checked": list(skipped),
                       "findings": [f.to_dict() for f in findings]}, indent=1) + "\n"
