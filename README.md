# hermes-verify

Evidence labeling and configurable tool-risk interception for Hermes Agent.
Version 0.3.0 is a combined development candidate, not a truth oracle or a complete
security boundary. Source matching and tool names do not establish that a
claim is true or an action succeeded.

Built for the **Nous Research Hermes Agent Plugin Hackathon** (Nov 2026).
Core and subsequent hardening by Verity, with the output hook, bundled skill and offline output
fixtures contributed by Codex. These are AI-assisted contributions under
Brandon Ducar's direction. Native qualification and adversarial review are
separate from the offline fixtures; catalog submission is not yet complete.
This combines Verity's public `5c8cad5b1d45eee91deeebf6a48754c18c8fba0c`
with Codex's local `82141f73414d234c2e6af6b6978759e274bac33e`, retaining both histories.

## Held Output And Receipts

The `transform_llm_output` hook registers with `hold_stream=True`, requiring
Hermes 0.22.7 or newer. On host-supported held-output surfaces, the finished
reply is labeled before delivery instead of streaming the original first.
There is no fallback to unheld output on an older registration API.

The label is deliberately whole-message: **DECLARED / unverified agent
prose**. It preserves accepted text and code fences, is deterministic and
idempotent, and omits non-string or over-100,000-character bodies with a
bounded notice. It does not semantically fact-check individual sentences,
redact private data, sanitize Markdown, or promote prose because a tool or
quoted receipt calls itself verified. A host must actually load the plugin;
source code and unit tests alone do not prove stream delivery behavior.
Hermes uses the first nonempty output-transform result. A different plugin
registered ahead of this one can supply that result first; stream hold is
not a guarantee that this plugin wins every multi-plugin transform chain.
Tool progress and reasoning have separate host display controls.

Load the bundled workflow with `skill_view("hermes-verify:receipts")`.
It is namespaced and read-only; no existing memory or skills are overwritten.

## What it does

| Piece | How it works |
| --- | --- |
| **pre_tool_call guard** | Token-based classification of spend, send, publish, deploy, credential and generic execution tools. Default mode logs and allows; explicit blocking mode vetoes flagged calls. Exceptional paths remain under review. |
| **post_tool_call grader** | Writes result-grade metadata considering host status and structured errors. It does not independently verify action completion or rewrite model-bound tool results. |
| **transform_llm_output** | Holds the finished reply on supported Hermes surfaces and adds an explicit unverified-prose label. This is not per-claim truth verification. |
| **verify_claim tool** | Development-only lexical comparison against fetched source text. Returned legacy grades are untrusted metadata, not semantic support or independent factual verification. Missing sources and fetch failures return `UNKNOWN`. |
| **query_receipts tool** | Read-only access to the guard/grades audit logs (`log: "guard"` or `"grades"`, limit 1–100, default 20) so the agent can show receipts instead of claiming them from memory. |

## Evidence levels

| Level | Meaning |
| --- | --- |
| `EXTERNALLY-VERIFIED` | Checked against an independent live source that supports the claim. |
| `RUNTIME-VERIFIED` | The agent's own runtime observed it (a live tool result). Proves **"the tool returned X"** — never "X is true in the world". |
| `CODE-VERIFIED` | The runtime executed code and returned a result (a write/action completed). Not an independent observation. |
| `DECLARED` | Asserted by the agent or a tool, not checked. |
| `PROPOSED` | A hypothesis, or partially supported by a source. Needs checking. |
| `UNKNOWN` | No usable evidence either way. Absence of support is **not** proof a claim is false. |

The current scaffold's tool-name and phrase heuristics are development
metadata, not independent verification. In particular, a write tool returning
text is not proof of delivery, deployment or payment, and a phrase match is
not semantic source support. The grader currently writes to an audit log;
`post_tool_call` cannot rewrite what the model receives. Graded-result
enforcement and live source verification remain under review.

Legacy grading behavior retained from the scaffold:

- Read/observation tools (`read_file`, `web_search`, `web_fetch`, …) →
  `RUNTIME-VERIFIED` for the observation itself.
- Write/action tools (`write_file`, `send_email`, `terminal`, `stripe_checkout`, …) →
  `CODE-VERIFIED` for the execution. Action hints win over read hints.
- Empty results, host-reported errors (`status="error"`), or structured
  error reports → `UNKNOWN`.
- Anything unclassified → `DECLARED`.
- `verify_claim` results pass their own level through.

## Install

```bash
hermes plugins install <path-or-catalog-name>   # or drop the directory in ~/.hermes/plugins/
hermes plugins enable hermes-verify
```

No API keys, no Python dependencies (stdlib only), no privileged
capabilities requested. The plugin's only network access is the
`verify_claim` tool fetching a URL the user (or the agent) supplies,
10s timeout, 2 MiB cap, http(s) only, SSRF-guarded to public IPs
(including redirect targets). Residual SSRF note: DNS can change
between the guard's check and the connect (TOCTOU); closing that needs
connection-level IP pinning, which stdlib urllib does not offer.

The combined candidate retains `requires_hermes: ">=0.22.7"` because held output
requires that API. An unknown development-build identity must be resolved through
supported upstream discovery, not by removing the gate or faking a stamp.
Native validation of this combined candidate is pending.

## Config

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `blocking_mode` | bool | `false` | When `true`, flagged tool calls are **blocked** (`pre_tool_call` returns a block directive) and the user must approve them. When `false` (default), flagged calls are logged and allowed through. |

Blocking is a veto, not an approval interface or a one-time approval token.
This development mode does not implement an approval-and-resume workflow.
The combined candidate keeps a blocking decision when classification, receipt
writing or logging fails. Configuration must be an actual boolean; a read error
or malformed value does not silently turn an established strict mode off.
Host behavior when any plugin fails loading still needs native qualification.

Set it in the Desktop app (Settings → Plugins → hermes-verify) or in
`config.yaml` under `plugins.entries.hermes-verify.settings.blocking_mode`.

## Audit logs

Logs live in the plugin data dir (`<HERMES_HOME>/plugin-data/hermes-verify/`,
survives updates/removes) as JSONL, one record per line. Argument values are not
intentionally recorded, but arbitrary key names, identifiers and diagnostics
remain unqualified for privacy. Use synthetic inputs during qualification:

- `guard_log.jsonl` - newly flagged calls: timestamp, tool/task digests, fixed
  categories/reason codes, argument-key count and blocked yes/no. Arbitrary key
  names and exception messages are omitted from these new guard records.
- `grades_log.jsonl` — graded tool results: timestamp, tool, task id,
  level, receipt (tool, timestamp, duration, basis).

Read them live with the `query_receipts` tool instead of opening the
files by hand.
Old records are not rewritten. Digests can correlate identifiers and are not
anonymization; grader records and raw receipt queries remain separate privacy
review scope. This is not a universal privacy guarantee.

## Tests

Stdlib fixtures do not require a model or native Hermes. The raw core suite can
write log files and perform DNS resolution; isolated qualification must bind
temporary storage and synthetic resolution before executing it. Commands below
are suite entrypoints, not proof that those effects have been contained:

```bash
python3 test_verify.py
python3 test_output.py
python3 test_registration.py
```

The earlier local branch passed 75 synthetic cases: 35 legacy core, 34 output
and six fake-registration cases. Verity's later core reports 67 cases. These
are overlapping tests of different snapshots, not 142 independent cases. This
combined candidate needs its own source-bound run and independent review.
Native hooks, actual stream delivery, transport policy and catalog admission
remain separate checks. Existing unsafe-path findings are not closed by a banner
or by changing a test expectation to match inherited behavior.

## Files

- `plugin.yaml` - manifest v2, version0.3.0, declared tools/hooks and the retained
  `requires_hermes >=0.22.7` admission floor. No privileged override is requested.
- `__init__.py` — `register(ctx)`, hook wrappers, `verify_claim` and
  `query_receipts` handlers.
- `_verify.py` — pure-stdlib logic (guard classification, grading,
  claim verification, URL checks and receipt reads). Importable without Hermes.
- `_output.py` — bounded whole-output labeling; no I/O or evidence promotion.
- `skills/receipts/SKILL.md` — namespaced reporting workflow, not permission.
- `test_output.py` — pure output-label fixtures without importing the plugin.
- `test_verify.py` — offline test suite.
- `test_registration.py` - fake-context registration fixtures, not native checks.
- `validation-report.json` - historical peer-reported validation of the earlier
  core, not native CLI validation or acceptance of this combined candidate.
  Its current aggregate `ok` is null; original reported success is retained
  explicitly as historical evidence rather than reused as a current green gate.
