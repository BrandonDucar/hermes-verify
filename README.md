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
| **pre_tool_call guard** | Inspects every tool call before it runs. Calls that spend money, send messages, publish, deploy, touch credentials, or execute arbitrary code (generic shell/run tools — a shell can do all of the above, so it is flagged as its own `exec` category) are **flagged and logged** (tool name, timestamp, category, reason) to the plugin data dir. By default the call still runs — flag-and-log. Matching is token-based (split on separators and camelCase), so `checkout` is not `check`, `reorder` is not `order`, and `retarget` is not `get`. |
| **post_tool_call grader** | Grades every tool result with an evidence level and writes the grade + receipt to an audit log (`grades_log.jsonl`). Error detection trusts Hermes' own `status` field first; without it only structured error evidence counts (a leading `Error:`/`Traceback`, or a dict/JSON `{"error": …}` field) — a result that merely mentions "failed" is graded normally. Exec hints are checked before read hints, so a tool that both reads and acts is graded as an action (understating evidence is safe, overstating it is not). |
| **verify_claim tool** | Checks a claim against a live source URL and returns a graded verdict. Support is measured per sentence: the score is the fraction of the claim's key phrases in the single best sentence — words scattered across a page do not count. An SSRF guard runs before any fetch: only http(s) URLs whose host resolves entirely to public IPs are fetched (localhost, private ranges, link-local, and the cloud metadata endpoint are blocked, including via redirects). Never fabricates: no source, a failed fetch, or a phrase mismatch all return `UNKNOWN` with the reason. |
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

Grading is deterministic and conservative:

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

No `requires_hermes` floor is declared, deliberately: verified against
the Hermes source, `running_hermes_version()` returns `"unknown"` on
dev builds, and any floor spec fails against `"unknown"` — declaring
one would block loading on every dev build. The APIs used here are all
present in the current tree.

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

Read them live with the `query_receipts` tool instead of opening the
files by hand.

## Tests

Stdlib only, no network, no Hermes needed:

```bash
python3 test_verify.py
```

Prints PASS/FAIL per case and exits non-zero if anything fails. 67 cases
including the adversarial-teardown regressions (exec bypass, substring
false positives, scattered-word verification, SSRF, error-mention
grading, receipts tool). Test URLs use literal public IPs
(`93.184.216.34`, example.com) because the sandbox's DNS answers
public hostnames with CGNAT addresses — the SSRF guard correctly
blocks those here; on a normal network they resolve publicly.

## Files

- `plugin.yaml` — manifest (v2). No `capabilities` block: the plugin
  requests no privileged host surfaces. No `requires_hermes` floor: see
  above — declaring one would block loading on dev builds.
- `__init__.py` — `register(ctx)`, hook wrappers, `verify_claim` and
  `query_receipts` handlers.
- `_verify.py` — pure-stdlib logic (guard classification, grading,
  claim verification, SSRF guard, receipts reads). Importable and
  testable without Hermes.
- `test_verify.py` — offline test suite (67 cases).
- `validation-report.json` — latest `validate_plugin_dir()` run
  (15/15 checks, 0 warnings, in-process; the `hermes` CLI cannot run
  in this sandbox).
