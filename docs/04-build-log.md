# Build log

Everything that went wrong or surprised me, in the order it happened, and what I did about it.

## Reading Terraform

### The parser gives no line numbers

python-hcl2 turns a file into nested dictionaries but drops where each block started, and a finding without a line number is hard to act on. Each block's line is found in the file text from its `resource "type" "name"` header. My first pattern matched the blank line before the header too, so every line number was one early; a test now checks that each finding points at its block's first line.

### A policy in a locals block

The first run on this portfolio reported project 02's CloudTrail bucket as accepting requests without TLS. It doesn't: its policy is written in a `locals` block and passed to the bucket policy as `local.trail_bucket_policy`, and the tool only looked inside the bucket policy resource. It now follows references into locals and policy documents. This is the false positive a reviewer is paid to catch, and it's why the results table says whether each finding is real.

### Deliberate choices looked like mistakes

Project 01's audit table has point-in-time recovery switched off on purpose, with a comment saying why. The tool can't read intent from a comment in free text, so the owner can now write `# review: accept RULE_ID reason` inside the resource. The finding moves to an "Accepted on purpose" section with the reason, rather than disappearing.

## The live review

### One refused service stopped the whole review

The first live run crashed: Lambda refused `ListFunctions` with `AccessDeniedException`. Clients often block regions or services, so each service is now checked on its own; a refused check is listed under "not checked" and the review carries on. A test refuses one service and checks that the others still report.

### Lambda refused, with nothing to explain it

Lambda refused every call in every region, including `GetAccountSettings`. IAM's policy simulator says the user is allowed, and the account isn't in an organisation, so no service control policy applies. EC2, S3, RDS and the rest answered normally. The same account has Bedrock refusing model calls since 18 October (project 08's build log). Both look like restrictions on the account itself rather than anything in its configuration; I'm currently working on it with AWS.

### Checking the permissions claim

The review role uses AWS's SecurityAudit policy, and the code says every call it makes is covered. Rather than assume it, I listed the 26 calls the review makes and matched each against the policy's actions. All are covered except `sts:GetCallerIdentity`, which needs no permission.

## The summary

### The model can't be called, and that's tested

The summary is the only part a model writes, and Bedrock refused the call on the first real run. The report used the plain summary and said why. That path is what a client sees whenever the model is unavailable, so it has its own test, along with summaries that cite findings that don't exist or use numbers that aren't in the findings.

### The plain summary repeated itself

With no trail in three regions, the plain summary said "start with" the same finding three times. It now names each rule once and cites every instance, `[1, 2, 3]`, and the summary check reads citations in that form.
