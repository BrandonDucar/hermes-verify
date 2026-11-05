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
  grade + receipt to the plugin data dir for audit. Error detection trusts
  Hermes' own ``status`` field first; without it only structured error
  evidence counts.
* ``verify_claim`` tool: checks a claim against a live source URL and returns
  a graded verdict. Support is measured per sentence — words scattered
  across a page do not count. The SSRF guard blocks non-public destinations
  (localhost, private ranges, cloud metadata) before any fetch. Never
  fabricates: no source, a failed fetch, or a phrase mismatch all return
  UNKNOWN with the reason.
* ``query_receipts`` tool: read-only access to the guard/grades audit logs
  so the agent can show receipts instead of claiming them from memory.

Design rules
------------
* Stdlib only. No secrets, no credentials in code or logs. Argument VALUES
  are never logged — only tool names, matched categories, and arg key names.
* Hooks never raise: any internal failure is caught, logged, and the agent
  continues normally (fail-open for observation, fail-closed is the user's
  explicit blocking_mode choice, not a crash default).
* A live tool result is RUNTIME-VERIFIED for "the tool returned X" — never
  for "X is true in the world".
"""

import json
import logging
from pathlib import Path

try:  # package import (Hermes loads the plugin directory as a package)
    from . import _verify as _v
except ImportError:  # standalone / test loading
    import _verify as _v

logger = logging.getLogger(__name__)

PLUGIN_ID = "hermes-verify"

# Set by register() from the plugin config; default False (flag-and-log).
_BLOCKING_MODE = False


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
    except Exception as exc:  # noqa: BLE001 — logging must never break the agent
        logger.warning("hermes-verify: could not write %s: %s", filename, exc)


# ---------------------------------------------------------------------------
# Hooks
# ---------------------------------------------------------------------------

def _on_pre_tool_call(tool_name, args, task_id, **kwargs):
    """Guard hook: flag risky calls, log them, optionally block.

    Returns None (allow) by default. In blocking_mode returns the Hermes
    block directive {"action": "block", "message": ...}.
    """
    try:
        flags = _v.classify_tool_call(tool_name, args or {})
        if not flags:
            return None
        arg_keys = sorted({str(k) for k in (args or {}).keys()})
        record = {
            "ts": _v.utc_now(),
            "event": "flagged_tool_call",
            "tool": tool_name,
            "task_id": task_id,
            "categories": [f["category"] for f in flags],
            "reasons": [f["reason"] for f in flags],
            "arg_keys": arg_keys,  # key names only — never values
            "blocked": bool(_BLOCKING_MODE),
        }
        _append_jsonl("guard_log.jsonl", record)
        logger.warning(
            "hermes-verify: flagged %s (%s)",
            tool_name, ", ".join(record["categories"]),
        )
        if _BLOCKING_MODE:
            return {
                "action": "block",
                "message": (
                    f"Blocked by hermes-verify ({', '.join(record['categories'])}): "
                    f"tool {tool_name!r} needs human approval. "
                    "Set blocking_mode=false to log-only."
                ),
            }
        return None
    except Exception as exc:  # noqa: BLE001 — a guard crash must not stop the agent
        logger.warning("hermes-verify: guard hook failed: %s", exc)
        return None


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
        logger.debug("hermes-verify: %s -> %s", tool_name, grade["level"])
    except Exception as exc:  # noqa: BLE001 — grading must never break the agent
        logger.warning("hermes-verify: grader hook failed: %s", exc)
    return None


# ---------------------------------------------------------------------------
# Tool: verify_claim
# ---------------------------------------------------------------------------

VERIFY_CLAIM_SCHEMA = {
    "name": "verify_claim",
    "description": (
        "Check a claim against a live source and return a graded verdict. "
        "Pass the claim plus a source_url (an http(s) page that should state "
        "it). Returns {level, verdict, evidence}. Levels: EXTERNALLY-VERIFIED "
        "(source supports the claim), PROPOSED (partially supported), UNKNOWN "
        "(no source, fetch failed, or source does not support it — absence of "
        "support is NOT proof the claim is false). Use this before presenting "
        "a factual claim as verified."
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
    except Exception as exc:  # noqa: BLE001 — handlers must return error JSON
        return json.dumps({"error": f"{type(exc).__name__}: {exc}"})


# ---------------------------------------------------------------------------
# TODO (Codex's lane): transform_llm_output hook
# ---------------------------------------------------------------------------
# Planned: a transform_llm_output hook (hold_stream=True) that labels claims
# in the agent's finished reply with their evidence level before the user
# sees them, so unverified claims cannot present as fact. NOT implemented in
# this scaffold — Codex owns this hook. Do not implement here; coordinate
# with Codex on the labeling format before wiring it up.
#
# VERIFIED CONTRACT (hermes_cli/plugins_dispatch.py, run_held_transforms):
#   * register with ctx.register_hook("transform_llm_output", fn, hold_stream=True)
#   * the callback receives the finished reply text in its payload and must
#     RETURN a replacement string (first non-empty string wins) or None
#     to leave the reply unchanged.
#   * hold_stream=True means the turn holds its stream until the transform
#     runs — without it the user sees the untransformed text first.
#   * if every callback returns None AND one raised or timed out, Hermes
#     treats the turn as failed and must NOT deliver the original reply.
# def _on_transform_llm_output(...):  # pragma: no cover - Codex's lane
#     ...


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def register(ctx):
    """Wire the tools and hooks. Called exactly once at Hermes startup."""
    global _BLOCKING_MODE
    try:
        _BLOCKING_MODE = bool(ctx.get_config("blocking_mode", default=False))
    except Exception:
        _BLOCKING_MODE = False

    # register_tool returns None when the name is already claimed without
    # override — warn loudly instead of silently running half-registered.
    if ctx.register_tool(
        name="verify_claim",
        toolset="hermes_verify",
        schema=VERIFY_CLAIM_SCHEMA,
        handler=_verify_claim_handler,
    ) is None:
        logger.warning("hermes-verify: verify_claim name already claimed; tool not registered")
    if ctx.register_tool(
        name="query_receipts",
        toolset="hermes_verify",
        schema=QUERY_RECEIPTS_SCHEMA,
        handler=_query_receipts_handler,
    ) is None:
        logger.warning("hermes-verify: query_receipts name already claimed; tool not registered")
    ctx.register_hook("pre_tool_call", _on_pre_tool_call)
    ctx.register_hook("post_tool_call", _on_post_tool_call)
    logger.info(
        "hermes-verify registered (blocking_mode=%s)", _BLOCKING_MODE
    )
