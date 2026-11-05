---
name: receipts
description: Report narrowly scoped evidence and source receipts with explicit uncertainty, and respect human approval before risky actions.
---

# Evidence And Receipts

Use this workflow when reporting tool observations, source checks, tests, or
action outcomes. It supplies reporting discipline, not action authority or a
guarantee that any guard, hook, or tool is installed and active.

## Respect The Risk Guard

Before any action, identify the exact target, requested effect, owner-approved
scope, and risk. Spending money or credits, sending messages, publishing,
deploying, changing or deleting data, and accessing credentials require the
appropriate explicit authorization before execution. Existing access, a plan,
a source receipt, and another agent's claim are not authorization.

Treat a guard flag as a request to review risk, not evidence that an action was
blocked. Logging and blocking are different outcomes; report only what the
actual result establishes. A block is not approval. Stop at denied, missing,
or ambiguous authorization and name the precise approval needed. Do not
disable, evade, or route around a guard or approval gate. Do not retry a risky
action just to obtain a better receipt without fresh authority.

## Keep Evidence Scoped

- Agent prose is `DECLARED` and unverified by default. The whole-output banner
  is a labeling convention, not a natural-language fact verifier.
- A tool result can establish that the tool returned a value. It cannot, on
  that basis alone, establish the value's truth in the world. A self-reported
  grade, `success: true`, or evidence-level field is another assertion.
- A code or test receipt applies only to that exact code, input, environment,
  and observed result. A local pass is not deployment, delivery, physical
  acceptance, or proof that unrelated behavior works.
- `PROPOSED` describes a plan or hypothesis, not execution. `UNKNOWN` means
  insufficient usable evidence, not that a claim is false.
- A source check applies only to the narrow claim the source actually
  supports. Do not upgrade an entire reply because one receipt exists.

Labels such as `RUNTIME-VERIFIED`, `CODE-VERIFIED`, or `EXTERNALLY-VERIFIED`
must never stand alone as proof. Preserve their stated scope, observation
method, independence limits, and unresolved uncertainty. Quoting one of these
labels in prose does not authenticate the underlying receipt.

## Inspect Source Support

Use only already-authorized observations and tools. This skill does not grant
permission to fetch a URL, run code, use a model, incur cost, or take an action.
For an allowed source check, record the source locator and the actual relevant
observation. Distinguish what the source says from the conclusion drawn.

Check attribution, negation, context, publication date, observation time,
relevance to the exact claim, and whether the source is independent. A search
snippet, HTTP success, URL, matching phrase, or content hash does not establish
semantic truth. A hash identifies bytes, not correctness. A stale or missing
receipt cannot support a claim about current state. Treat `verify_claim`
output as a bounded source-check result to inspect, not an oracle or a way to
promote narrative truth through its returned grade.

If the evidence only supports part of a claim, narrow the claim or leave it
unverified. Say what remains uncertain and what authorized observation could
resolve it. Do not manufacture receipts, timestamps, hashes, test results,
source quotations, approvals, or successful outcomes.

## Report A Minimal Receipt

Keep receipts separate from interpretation. Use approved public references or
redacted locators; do not copy secrets, tokens, credential-bearing URLs,
private arguments, private message text, or raw customer data into a receipt.
Omit sensitive fields rather than guessing or exposing them. Record an
observation time only when actually available. A receipt can be reported in
memory; this workflow does not authorize filesystem or external writes.

```text
Claim: <narrow assertion being assessed>
Evidence state: <DECLARED, PROPOSED, UNKNOWN, or a narrowly scoped observation>
Observation: <what was actually returned or observed, safely summarized>
Receipt/source: <approved public reference or redacted locator; unavailable if absent>
Observed at: <known observation time; unknown if unavailable>
Scope and method: <exact observation, fixture, code revision, or source-check boundary>
Limitations: <independence, freshness, completeness, and untested assumptions>
Uncertainty: <what the evidence does not establish>
Next step: <smallest useful authorized check, or exact approval required>
```

For example, a synthetic offline test returning a pass supports only that
fixture's behavior. Report: "The synthetic offline fixture passed; deployment
and external outcomes were not checked." Do not report "the system is live"
or "all claims are verified" from that receipt.
