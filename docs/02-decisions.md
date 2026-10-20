# Decisions

What was built, and why each choice was made. The requirements (F1 to F5, N1 to N6) are in [01-brief.md](01-brief.md).

## Trade-offs

Each row names the main alternative and what this choice gives up.

| Choice | Alternative | Why this one | What it gives up |
|---|---|---|---|
| Fixed rules find the problems; a model only writes the summary | A model reads the Terraform or the account and reports what it sees | A rule gives the same answer every time, can be tested, and can't invent a finding (N2) | Only what the rules cover is found. A model might notice something new; it might also report something that isn't there |
| The model's summary checked before it's used | Trust the model's summary | The check rejects any finding number that doesn't exist and any number that isn't in the findings, so a confident wrong figure can't reach a manager | A good summary that happens to round a number is rejected and the plain one is used |
| Own rules, mapped to Well-Architected best practices | Checkov or another scanner with hundreds of rules | Each rule explains why it matters to a non-engineer and links the AWS best practice; the same rule runs on Terraform and on a live account; cost rules are included | Far fewer rules. Checkov is the better tool for broad Terraform scanning, and the two can run side by side |
| Read Terraform as text with python-hcl2 | Run `terraform plan` and read the plan | Needs no AWS access, no state and no provider downloads, so it runs on any repository (F1) | Values from variables and other resources are unknown. A rule fires only on what a file states or a setting that's missing, and the report says so |
| AWS managed SecurityAudit policy for the live role | A custom read-only policy listing each call | AWS maintains it, clients' security teams recognise it, and every call the review makes was checked against it | It can read more than the review needs, such as configuration of services no rule looks at. It can't read data in buckets or tables |
| External id on the client's role | Trust the reviewer's account alone | Stops another customer of the same reviewer from pointing the tool at an account that isn't theirs (the confused deputy problem) | One more value to agree and keep safe |
| Refused checks listed, review continues | Stop at the first refused call | Accounts often restrict regions or services. A partial review that says what it couldn't see is useful; a crash isn't (N5) | A careless reader might miss the "not checked" list, so it sits under its own heading |
| Accept a finding with a comment in the resource | A separate suppression file | The reason sits next to the code it explains and is reviewed with it (F5) | Live-account findings can't be accepted this way |
| Amazon Nova Lite in London for the summary | A third-party model | The same choice and controls as project 08: Amazon's own model, invoked in the UK | The model-written summary is still to run; the plain summary is used meanwhile |

## Severity

High: an exposure someone outside could use, data that isn't protected at rest, or no record of what happened. Medium: a weakness that needs another mistake to matter. Low: waste, or a resilience choice worth making on purpose. The severity is a starting point for the reader, not a verdict; a single-AZ database is right for development and a risk for production.

## What a rule may not do

A rule states only what the configuration shows. It doesn't guess at intent, estimate a cost it can't read, or mark something as passed because it couldn't see it.
