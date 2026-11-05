# hermes-verify

Evidence-level enforcement for Hermes Agent. An agent should not present
unverified claims as fact — this plugin makes that a platform property
instead of a prompt instruction.

Built for the **Nous Research Hermes Agent Plugin Hackathon** (Nov 2026).
Scaffold by Verity; the `transform_llm_output` reply-labeling hook is
Codex's lane (see the TODO stub in `__init__.py`).

## What it does

| Piece | How it works |
| --- | --- |
| **pre_tool_call guard** | Inspects every tool call before it runs. Calls that spend money, send messages, publish, deploy, or touch credentials are **flagged and logged** (tool name, timestamp, category, reason) to the plugin data dir. By default the call still runs — flag-and-log. |
| **post_tool_call grader** | Grades every tool result with an evidence level and writes the grade + receipt to an audit log (`grades_log.jsonl`). |
| **verify_claim tool** | Checks a claim against a live source URL and returns a graded verdict. Never fabricates: no source, a failed fetch, or a phrase mismatch all return `UNKNOWN` with the reason. |

## Evidence levels

| Level | Meaning |
| --- | --- |
| `EXTERNALLY-VERIFIED` | Checked against an independent live source that supports the claim. |
| `RUNTIME-VERIFIED` | The agent's own runtime observed it (a live tool result). Proves **"the tool returned X"** — never "X is true in the world". |
| `CODE-VERIFIED` | The runtime executed code and returned a result (a write/action completed). Not an independent observation. |
| `DECLARED` | Asserted by the agent or a tool, not checked. |
| `PROPOSED` | A hypothesis, or partially supported by a source. Needs checking. |
| `UNKNOWN` | No usable evidence either way. Absence of support is **not** proof a claim is false. |

Grading is deterministic and conservative:

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
```

Prints PASS/FAIL per case and exits non-zero if anything fails.

## Files

- `plugin.yaml` — manifest (v2). No `capabilities` block: the plugin
  requests no privileged host surfaces.
- `__init__.py` — `register(ctx)`, hook wrappers, `verify_claim` handler.
- `_verify.py` — pure-stdlib logic (guard classification, grading,
  claim verification). Importable and testable without Hermes.
- `test_verify.py` — offline test suite.
