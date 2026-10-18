# Brief: a first-pass review of an AWS setup

*The client is fictional. The rules, the AWS best practices they map to, and the accounts and code they were run on are real.*

## Background

A small company runs its product on AWS. Nobody there is a cloud specialist, the bill has crept up, and a customer's security questionnaire has asked whether their data is encrypted and who can reach it. They want to know three things: where they are exposed, where they are paying for nothing, and what would fail badly if something broke. A consultant can answer that by hand over several days. They want a first pass that takes minutes, which a person then reviews.

They have two things to show: the Terraform their infrastructure is written in, and the AWS account it runs in. Some resources were made by hand and exist only in the account.

## What it must do

| # | Requirement |
|---|---|
| F1 | Review Terraform files without running Terraform and without access to AWS |
| F2 | Review a live account through a role that can read configuration and change nothing |
| F3 | Report each finding with where it is (file and line, or resource and region), why it matters, the fix, and the AWS Well-Architected best practice it relates to |
| F4 | Put the most serious findings first, and summarise them in plain English for a manager |
| F5 | Let the owner accept a finding on purpose, with a reason, so a decision isn't reported as an oversight |

## How it will be judged

| # | Requirement |
|---|---|
| N1 | Every rule is shown finding its problem, and the Terraform rules passing correct configuration |
| N2 | A finding is never invented. The rules find the problems; a model may only write the summary, and its text is checked against the findings before it's used |
| N3 | The live review can't change anything: its role holds the AWS managed SecurityAudit policy, which every call it makes is checked against |
| N4 | Only the reviewer can assume the client's role, and only with an external id agreed with the client |
| N5 | A check the account refuses is reported as not checked, never as passed |
| N6 | Run on real code: the Terraform in this portfolio's own repositories, and its own AWS account |

## Scope

**In:** 24 rules across security, cost and reliability; Terraform and live-account reviews; a Markdown report and JSON findings; a model-written summary with a plain fallback; the client's review role in Terraform; CI that fails on open high findings.

**Out:** fixing anything automatically, the Operational Excellence, Performance Efficiency and Sustainability pillars, Terraform modules from a registry, CloudFormation, and a review of how the team works. A full Well-Architected review covers that; this is the first pass before one.
