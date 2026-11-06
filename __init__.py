"""hermes-verify — evidence-level enforcement for Hermes Agent.

Scaffold for the Nous Research Hermes Agent Plugin Hackathon (Nov 2026).

What it does
------------
* ``pre_tool_call`` guard: flags tool calls that spend money, send messages,
  publish, deploy, touch credentials, or execute arbitrary code (generic
  shell/run tools). Flag-and-log by default; an opt-in ``blocking_mode``
  config turns flags into hard blocks.
* ``post_tool_call`` grader: attaches an evidence level to every tool result
  (RUNTIME-VERIFIED / CODE-VERIFIED / DECLARED / UNKNOWN) and writes the
  grade + receipt to the plugin data dir for audit. Host-reported errors
  and structured error evidence are distinguished from text mentioning failure.
* ``verify_claim`` tool: development-only lexical comparison against fetched
  text. Legacy grade labels are untrusted metadata, not semantic support or
  independent factual verification.
* ``query_receipts`` tool: read-only access to the guard/grades audit logs
  so the agent can show receipts instead of claiming them from memory.

Design rules
------------
* Stdlib only. New guard records omit raw keys, identifiers and exceptions;
  grader records and historical receipt queries remain separate privacy scope.
* Guard errors retain an explicit blocking-mode veto. Observation mode remains
  nonblocking. Invalid startup configuration raises without silently resetting
  a known strict mode; native host load-failure behavior remains unqualified.
* A live tool result is RUNTIME-VERIFIED for "the tool returned X" — never
  for "X is true in the world".
"""

import json
import hashlib
import logging
from pathlib import Path

try:  # package import (Hermes loads the plugin directory as a package)
    from . import _verify as _v
    from ._output import label_output
except ImportError:  # standalone / test loading
    import _verify as _v
    from _output import label_output

logger = logging.getLogger(__name__)

PLUGIN_ID = "hermes-verify"

# Set by register() from the plugin config; default False (flag-and-log).
_BLOCKING_MODE = False


def _log_safely(level, code):
    try:
        getattr(logger, level)(code)
    except Exception:
        pass


def _identifier_digest(value):
    if type(value) is not str:
        return None
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def _block_directive():
    return {
        "action": "block",
        "message": "hermes-verify blocked this call; current host approval is required.",
    }


# ---------------------------------------------------------------------------
# Durable state — the sanctioned plugin data dir, with a safe fallback
# ---------------------------------------------------------------------------

def _data_dir():
    """Plugin data dir that survives updates/removes; falls back to
    ~/.hermes-verify when running outside Hermes (tests, doctor)."""
    try:
        from plugins.plugin_storage import plugin_data_dir
        return Path(plugin_data_dir(PLUGIN_ID))
    except Exception:
        import os
        override = os.environ.get("HERMES_VERIFY_DATA_DIR")
        base = Path(override) if override else Path.home() / ".hermes-verify"
        return base


def _append_jsonl(filename, record):
    """Append one JSON record to the plugin data dir. Never raises."""
    try:
        d = _data_dir()
        d.mkdir(parents=True, exist_ok=True)
        with open(d / filename, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, default=str) + "\n")
    except Exception:  # Best-effort storage cannot change a guard decision.
        _log_safely("warning", "HERMES_VERIFY_RECEIPT_WRITE_FAILED")


# ---------------------------------------------------------------------------
# Hooks
# ---------------------------------------------------------------------------

def _on_pre_tool_call(tool_name, args, task_id, **kwargs):
    """Guard hook: flag risky calls, log them, optionally block.

    Returns None (allow) by default. In blocking_mode returns the Hermes
    block directive {"action": "block", "message": ...}.
    """
    try:
        if args is None:
            args = {}
        if type(tool_name) is not str or type(args) is not dict:
            raise TypeError("HERMES_VERIFY_CALL_SHAPE_INVALID")
        flags = _v.classify_tool_call(tool_name, args)
        if not flags:
            return None
        decision = _block_directive() if _BLOCKING_MODE else None
        categories = sorted({f["category"] for f in flags if f["category"] in
                             {"spend", "send", "publish", "deploy", "credentials", "exec"}})
        record = {
            "ts": _v.utc_now(),
            "event": "flagged_tool_call",
            "tool_digest": _identifier_digest(tool_name),
            "task_digest": _identifier_digest(task_id),
            "categories": categories,
            "reason_codes": ["RISK_" + category.upper() for category in categories],
            "arg_key_count": len(args),
            "blocked": bool(_BLOCKING_MODE),
        }
        _append_jsonl("guard_log.jsonl", record)
        _log_safely("warning", "HERMES_VERIFY_CALL_FLAGGED")
        return decision
    except Exception:
        _log_safely("warning", "HERMES_VERIFY_GUARD_FAILED")
        return _block_directive() if _BLOCKING_MODE else None


def _on_post_tool_call(tool_name, args, result, task_id, duration_ms=None,
                      status=None, error_type=None, error_message=None, **kwargs):
    """Grader hook: grade the result and write the receipt to the audit log.

    ``status``/``error_type``/``error_message`` come from Hermes itself
    (model_tools._tool_result_observer_fields): ``status`` is "ok" or
    "error", derived from the result — the grader trusts that signal over
    its own text heuristics. Return value is ignored by Hermes — the grade
    lives in the log, and verify_claim verdicts reach the model directly
    as tool results.
    """
    try:
        grade = _v.grade_tool_result(
            tool_name, result, duration_ms=duration_ms,
            status=status, error_message=error_message,
        )
        record = {
            "ts": _v.utc_now(),
            "event": "graded_tool_result",
            "tool": tool_name,
            "task_id": task_id,
            "level": grade["level"],
            "receipt": grade["receipt"],
        }
        _append_jsonl("grades_log.jsonl", record)
        _log_safely("debug", "HERMES_VERIFY_RESULT_GRADED")
    except Exception:
        _log_safely("warning", "HERMES_VERIFY_GRADER_FAILED")
    return None


# ---------------------------------------------------------------------------
# Tool: verify_claim
# ---------------------------------------------------------------------------

VERIFY_CLAIM_SCHEMA = {
    "name": "verify_claim",
    "description": (
        "Development-only keyword comparison against fetched source text. "
        "Returns {level, verdict, evidence}, but legacy grades including "
        "EXTERNALLY-VERIFIED are untrusted metadata: matching words do NOT "
        "establish semantic support, source independence or factual truth. "
        "Do not present a claim as verified based on this tool. Missing "
        "sources or fetch failures return UNKNOWN, not proof of falsity."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "claim": {
                "type": "string",
                "description": "The factual claim to check, as a plain sentence.",
            },
            "source_url": {
                "type": "string",
                "description": (
                    "Optional http(s) URL of a page that should state the claim. "
                    "Without it the verdict is UNKNOWN."
                ),
            },
        },
        "required": ["claim"],
    },
}


def _verify_claim_handler(args, **kwargs):
    """Tool handler: always returns a JSON string, never raises."""
    try:
        result = _v.verify_claim(
            (args or {}).get("claim", ""),
            (args or {}).get("source_url"),
        )
        return json.dumps(result)
    except Exception as exc:  # noqa: BLE001 — handlers must return error JSON
        return json.dumps({"level": "UNKNOWN", "verdict": "verification error",
                           "evidence": {"reason": f"{type(exc).__name__}"}})


# ---------------------------------------------------------------------------
# Tool: query_receipts — read-only access to the audit trail
# ---------------------------------------------------------------------------

QUERY_RECEIPTS_SCHEMA = {
    "name": "query_receipts",
    "description": (
        "Read the plugin's own audit logs (read-only). Pass log 'guard' for "
        "flagged tool calls or 'grades' for graded tool results, and a limit "
        "(default 20, max 100). Returns the most recent records as JSON. "
        "Use this to show receipts for what the guard flagged or how a "
        "result was graded, instead of claiming it from memory."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "log": {
                "type": "string",
                "description": "Which audit log: 'guard' or 'grades'.",
            },
            "limit": {
                "type": "integer",
                "description": "How many of the most recent records (1-100, default 20).",
            },
        },
        "required": ["log"],
    },
}


def _query_receipts_handler(args, **kwargs):
    """Tool handler: read-only log query, always returns a JSON string."""
    try:
        args = args or {}
        result = _v.read_receipts(
            str(args.get("log", "")),
            int(args.get("limit") or 20),
            data_dir=_data_dir(),
        )
        return json.dumps(result)
    except FileNotFoundError:
        return json.dumps({"log": str((args or {}).get("log", "")),
                           "limit": 20, "count": 0, "records": []})
    except Exception:
        return json.dumps({"error": "HERMES_VERIFY_RECEIPT_QUERY_FAILED"})


# ---------------------------------------------------------------------------
# Output labeling
# ---------------------------------------------------------------------------
def _on_transform_llm_output(response_text, **kwargs):
    """Label finished prose without trusting quoted grades as verification."""
    return label_output(response_text)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def register(ctx):
    """Wire the tools and hooks. Called exactly once at Hermes startup."""
    global _BLOCKING_MODE
    configured_mode = ctx.get_config("blocking_mode", default=False)
    if type(configured_mode) is not bool:
        raise ValueError("HERMES_VERIFY_BLOCKING_MODE_INVALID")
    _BLOCKING_MODE = configured_mode

    # No compatibility fallback: a host without stream hold must refuse loading.
    ctx.register_hook(
        "transform_llm_output", _on_transform_llm_output, hold_stream=True,
    )
    ctx.register_skill("receipts", Path(__file__).parent / "skills" / "receipts" / "SKILL.md")
    # register_tool returns None when the name is already claimed without
    # override — warn loudly instead of silently running half-registered.
    if ctx.register_tool(
        name="verify_claim",
        toolset="hermes_verify",
        schema=VERIFY_CLAIM_SCHEMA,
        handler=_verify_claim_handler,
    ) is None:
        _log_safely("warning", "HERMES_VERIFY_CLAIM_TOOL_REGISTRATION_UNCONFIRMED")
    if ctx.register_tool(
        name="query_receipts",
        toolset="hermes_verify",
        schema=QUERY_RECEIPTS_SCHEMA,
        handler=_query_receipts_handler,
    ) is None:
        _log_safely("warning", "HERMES_VERIFY_QUERY_TOOL_REGISTRATION_UNCONFIRMED")
    ctx.register_hook("pre_tool_call", _on_pre_tool_call)
    ctx.register_hook("post_tool_call", _on_post_tool_call)
    _log_safely("info", "HERMES_VERIFY_REGISTERED")
