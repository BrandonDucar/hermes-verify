# hermes-verify

Evidence labeling and configurable tool-risk interception for Hermes Agent.
Version 0.5.0 is a combined development candidate, not a truth oracle or a complete
security boundary. Source matching and tool names do not establish that a
claim is true or an action succeeded.

Built for the **Nous Research Hermes Agent Plugin Hackathon** (Nov 2026).
Core and subsequent hardening by Verity, with the output hook, bundled skill and offline output
fixtures contributed by Codex. These are AI-assisted contributions under
Brandon Ducar's direction. Native qualification and adversarial review are
separate from the offline fixtures; catalog submission is not yet complete.
This combines Verity's public `5c8cad5b1d45eee91deeebf6a48754c18c8fba0c`
with Codex's local `82141f73414d234c2e6af6b6978759e274bac33e`, retaining both histories.
The v0.4 corrections build on their combined `ed45cc4` checkpoint. Verity's
classifier, token matching and sentence-locality work remain; Codex's later
corrections separate those observations from factual verification.

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
| **verify_claim tool** | Bounded sentence-window lexical comparison. Matching returns at most `PROPOSED`, with `scope=LEXICAL_SOURCE_TEXT_ONLY` and `verified=false`. Missing sources and fetch failures are `UNKNOWN`, not proof of falsity. |
| **query_receipts tool** | Read-only access to the guard/grades audit logs (`log: "guard"` or `"grades"`, limit 1–100, default 20) so the agent can show receipts instead of claiming them from memory. |

## Evidence levels

| Level | Meaning |
| --- | --- |
| `EXTERNALLY-VERIFIED` | Reserved legacy vocabulary; this lexical checker never grants it. A reported label is not authenticated evidence. |
| `RUNTIME-VERIFIED` | The agent's own runtime observed it (a live tool result). Proves **"the tool returned X"** — never "X is true in the world". |
| `CODE-VERIFIED` | Legacy action-tool return category, not proof of successful completion, delivery, payment or deployment. |
| `DECLARED` | Asserted by the agent or a tool, not checked. |
| `PROPOSED` | A hypothesis, or partially supported by a source. Needs checking. |
| `UNKNOWN` | No usable evidence either way. Absence of support is **not** proof a claim is false. |

The current core's tool-name and phrase heuristics are development
metadata, not independent verification. In particular, a write tool returning
text is not proof of delivery, deployment or payment, and a phrase match is
not semantic source support. The grader currently writes to an audit log;
`post_tool_call` cannot rewrite what the model receives. Graded-result
enforcement and live source verification remain under review.

Grading behavior:

- Read/observation tools (`read_file`, `web_search`, `web_fetch`, …) →
  `RUNTIME-VERIFIED` for the observation itself.
- Write/action tools (`write_file`, `send_email`, `terminal`, `stripe_checkout`, …) →
  `CODE-VERIFIED` for the reported return, not completed execution. Action hints win.
- Empty or uninspectable results, reported errors/denial/cancellation, explicit
  false success or nonzero exit states are `UNKNOWN`, even with host `status=ok`.
  A sentence merely mentioning failure is not automatically an error.
- Anything unclassified → `DECLARED`.
- A verifier's reported level is separate metadata, never promoted to an
  independently verified grade. A bare `EXTERNALLY-VERIFIED` result is `DECLARED`.
- Observed-return grades explicitly state that they do not establish completion.

## Install

```bash
hermes plugins install <path-or-catalog-name>   # or drop the directory in ~/.hermes/plugins/
hermes plugins enable hermes-verify
```

No API keys, no Python dependencies (stdlib only), no privileged
capabilities requested. The plugin's only network access is the
`verify_claim` tool fetching a URL the user (or the agent) supplies,
with a shared 10s monotonic network-wait budget, a 2 MiB body cap and at most ten
redirects. HTTP and HTTPS connect directly to numeric addresses from a validated
public-only DNS snapshot; redirects are resolved and validated separately within
the same budget. The original hostname remains the HTTP Host and HTTPS certificate
verification/SNI identity. Ambient proxies are not used. Userinfo, scoped IPv6,
port zero and non-global/shared addresses are refused. HTTPS requires verified
certificates and default system trust, not an unverified TLS fallback.

Each raw receive, send, connect and TLS handshake uses the remaining budget,
including reads performed inside the standard-library HTTP parser. Resolver wait
is bounded, but an OS resolver already running cannot be cancelled. At most four
resolver threads per loaded module can remain outstanding; their slots are held
until completion, so additional requests fail closed while saturated. This is
cooperative timing, not hard real-time cancellation of OS, certificate-store,
scheduler or CPU work. Proxy-only networks may fail rather than bypass this policy.
Address checks are not an egress firewall or permission to access a source;
local routing, NAT infrastructure and endpoint authorization remain external controls.

The combined candidate retains `requires_hermes: ">=0.22.7"` because held output
requires that API. An unknown development-build identity must be resolved through
supported upstream discovery, not by removing the gate or faking a stamp.
The v0.5 executable source passed a fresh real SDK Doctor registration check and
six registered callback/receipt cases against Hermes 0.22.7 in an isolated
source-import environment. Doctor observed two tools, three hooks and no findings;
each native run reported two warnings whose details were not captured. These are
scoped native results, not installed-runtime or full-validation certification.
The SDK tracked-dirty observation timed out, so no clean-tree claim follows.
The unchanged upstream validator from Hermes SDK commit
`b200f5bc60e31588ba2cb60e288029c4a54ba5fa` subsequently passed all 15 applicable
Python-plugin report checks in an isolated native run. This included its actual
capability-probe subprocess, source/security checks and built-in collision
discovery. Its validation warning list was empty; an upstream Python
DeprecationWarning and two capability-recorder registration notices were
retained separately. The static isolation audit reported host-ready, not proof
of an operating isolated host. Desktop and language-pack checker functions ran,
but this plugin declares neither surface; no synthetic check result was added.
Agent-stream delivery, strict-mode integration and the installed CLI environment
remain unqualified. The earlier v0.4 results remain historical rather than reused.

## Config

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `blocking_mode` | bool | `false` | When `true`, flagged tool calls are vetoed (`pre_tool_call` returns a block directive). No approval UI, one-time approval token or automatic resume is supplied. When `false` (default), flagged calls are logged and allowed through. |

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
survives updates/removes) as JSONL, one record per line. New guard and grade
records omit raw arguments, identifiers and error messages. Use synthetic inputs
during qualification; this is not a general-purpose privacy scrubber:

Storage caveat: if importing or calling the host's `plugin_data_dir` helper
raises, the implementation falls back to `HERMES_VERIFY_DATA_DIR`, when set,
or `<user-home>/.hermes-verify`. That can happen inside Hermes as well as in a
standalone test. This fallback is not guaranteed to follow the active profile;
host storage errors must not be mistaken for verified profile isolation.

- `guard_log.jsonl` - newly flagged calls: timestamp, tool/task digests, fixed
  categories/reason codes, argument-key count and blocked yes/no. Arbitrary key
  names and exception messages are omitted from these new guard records.
- `grades_log.jsonl` - timestamps, identifier digests, scoped grade/outcome and
  fixed receipt basis codes. A host error's text is not copied into the receipt.

Read them live with the `query_receipts` tool instead of opening the
files by hand.
Queries read at most 256 KiB from the log tail, skip lines over 16 KiB and return
at most 100 allowlisted metadata records, never raw legacy keys/errors/content.
Truncation and skipped records are explicit; the query is not a full-log audit.
Old files are not rewritten or deleted. Digests correlate data and are not
anonymization or authentication. File races, retention and audience access remain
host responsibilities, not an OS sandbox or universal privacy guarantee.

Argument/result inspection accepts bounded plain JSON: 4,096 visited values,
depth 12, 131,072 characters per value string and 262,144 aggregate key/value
characters. Dictionary and list containers are inspected. Non-JSON objects,
cycles, nonfinite numbers and exhausted budgets cannot appear safely inspected;
strict mode blocks classifier failure, while observation mode remains nonblocking.

## Tests

Stdlib fixtures do not require a model or native Hermes. The raw core suite can
write log files and perform DNS resolution; isolated qualification must bind
temporary storage and synthetic resolution before executing it. Commands below
are suite entrypoints, not proof that those effects have been contained:

```bash
python3 test_verify.py
python3 test_output.py
python3 test_registration.py
python3 test_core_boundaries.py
python3 test_url_admission.py
python3 test_transport_boundaries.py
```

The earlier local branch passed 75 synthetic cases: 35 legacy core, 34 output
and six fake-registration cases. Verity's later core reports 67 cases. These
are overlapping tests of different snapshots, not 142 independent cases. This
v0.3 combined candidate passed 121 synthetic cases. The v0.4 candidate passed
161 offline cases: 69 core, 34 output, six fake-registration, 31 core-boundary,
nine URL-admission and 12 private guard challenges. These overlap the earlier
121; they are not 282 unique cases. The 12 private guard challenges are retained
in the local qualification audit, not included in the public commands above.
The frozen 30-case core challenge set produced three passing and 27 failing
assertions against the retained parent, with five denied read attempts reported
separately by the audit guard. That baseline is not clean runtime qualification
or a count of independent vulnerabilities. The candidate had zero denied attempts.
The 31st core-boundary case covers the review-discovered empty-log v2 envelope;
it failed against the pre-fix wrapper and passed after correction.
The v0.5 transport suite uses synthetic DNS, socket, TLS, thread and clock boundaries
with the real standard-library HTTP parser; it is not a live-network or TLS-peer
certification. Qualification results must be bound to exact source and fixture pins.
The pre-review candidate passed 174 cases in the six public suites above plus the
same twelve private guard cases, 186 total. Review found three additional edges;
four added regressions extend the transport suite to 29 cases, 190 overall.
Execution results must name the exact source snapshot; repeated qualification
is not another set of unique cases, and a pre-repair pass does not close a finding.
Native hooks, actual stream delivery, transport policy and catalog admission
remain separate checks. Existing unsafe-path findings are not closed by a banner
or by changing a test expectation to match inherited behavior.

## Files

- `plugin.yaml` - manifest v2, version0.5.0, declared tools/hooks and the retained
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
- `test_transport_boundaries.py` - offline pinned-connection, proxy, redirect,
  shared-deadline and resolver-capacity challenges; no real network operations.
- `validation-report.json` - historical peer-reported validation of the earlier
  core, not native CLI validation or acceptance of this combined candidate.
  Its current aggregate `ok` is null; original reported success is retained
  explicitly as historical evidence rather than reused as a current green gate.
