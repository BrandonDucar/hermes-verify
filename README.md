# hermes-verify

Evidence labeling and configurable tool-risk interception for Hermes Agent.
Version 0.2.0 is a development candidate, not a truth oracle or a complete
security boundary. Source matching and tool names do not establish that a
claim is true or an action succeeded.

Built for the **Nous Research Hermes Agent Plugin Hackathon** (Nov 2026).
Scaffold by Verity, with the output hook, bundled skill and offline output
fixtures contributed by Codex. These are AI-assisted contributions under
Brandon Ducar's direction. Native qualification and adversarial review are
separate from the offline fixtures; catalog submission is not yet complete.

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
| **pre_tool_call guard** | Inspects every tool call before it runs. Calls that spend money, send messages, publish, deploy, or touch credentials are **flagged and logged** (tool name, timestamp, category, reason) to the plugin data dir. By default the call still runs — flag-and-log. |
| **post_tool_call grader** | Grades every tool result with an evidence level and writes the grade + receipt to an audit log (`grades_log.jsonl`). |
| **transform_llm_output** | Holds the finished reply on supported Hermes surfaces and adds an explicit unverified-prose label. This is not per-claim truth verification. |
| **verify_claim tool** | Development-only lexical comparison against fetched source text. Returned legacy grades are untrusted metadata, not semantic support or independent factual verification. Missing sources and fetch failures return `UNKNOWN`. |

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
- Write/action tools (`write_file`, `send_email`, `terminal`, …) →
  `CODE-VERIFIED` for the execution.
- Empty or error-looking results → `UNKNOWN`.
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
10s timeout, 2 MiB cap, http(s) only.

## Config

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `blocking_mode` | bool | `false` | When `true`, flagged tool calls are **blocked** (`pre_tool_call` returns a block directive) and the user must approve them. When `false` (default), flagged calls are logged and allowed through. |

Blocking is a veto, not an approval interface or a one-time approval token.
This development mode does not implement an approval-and-resume workflow.

Set it in the Desktop app (Settings → Plugins → hermes-verify) or in
`config.yaml` under `plugins.entries.hermes-verify.settings.blocking_mode`.

## Audit logs

Logs live in the plugin data dir (`<HERMES_HOME>/plugin-data/hermes-verify/`,
survives updates/removes) as JSONL — one record per line, no argument
values ever recorded:

- `guard_log.jsonl` — flagged tool calls: timestamp, tool, task id,
  categories, reasons, arg key names only, blocked yes/no.
- `grades_log.jsonl` — graded tool results: timestamp, tool, task id,
  level, receipt (tool, timestamp, duration, basis).

## Tests

Stdlib only, no network, no Hermes needed:

```bash
python3 test_verify.py
python3 test_output.py
```

Prints PASS/FAIL per case and exits non-zero if anything fails.

## Files

- `plugin.yaml` — manifest (v2). No `capabilities` block: the plugin
  requests no privileged host surfaces.
- `__init__.py` — `register(ctx)`, hook wrappers, `verify_claim` handler.
- `_verify.py` — pure-stdlib logic (guard classification, grading,
  claim verification). Importable and testable without Hermes.
- `_output.py` — bounded whole-output labeling; no I/O or evidence promotion.
- `skills/receipts/SKILL.md` — namespaced reporting workflow, not permission.
- `test_output.py` — pure output-label fixtures without importing the plugin.
- `test_verify.py` — offline test suite.
