from dataclasses import asdict, dataclass

from .rules import RULES, SEVERITY_ORDER


@dataclass(frozen=True)
class Finding:
    rule: str        # a key of RULES
    resource: str    # aws_s3_bucket.logs, or an ARN or id in a live account
    where: str       # file:line, or region
    detail: str = ""
    accepted: str | None = None   # the reason, when the owner has accepted this finding on purpose

    def to_dict(self) -> dict:
        r = RULES[self.rule]
        return asdict(self) | {"title": r.title, "pillar": r.pillar, "practice": r.practice, "severity": r.severity}


def ordered(findings: list[Finding]) -> list[Finding]:
    """Most severe first, then by rule and place, so a report is the same on every run."""
    return sorted(set(findings), key=lambda f: (SEVERITY_ORDER[RULES[f.rule].severity], f.rule, f.where, f.resource))
