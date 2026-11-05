"""hermes-verify — evidence-level enforcement for Hermes Agent.

Scaffold for the Nous Research Hermes Agent Plugin Hackathon (Nov 2026).

What it does
------------
* ``pre_tool_call`` guard: flags tool calls that spend money, send messages,
  publish, deploy, or touch credentials. Flag-and-log by default; an opt-in
  ``blocking_mode`` config turns flags into hard blocks.
* ``post_tool_call`` grader: attaches an evidence level to every tool result
  (RUNTIME-VERIFIED / CODE-VERIFIED / DECLARED / UNKNOWN) and writes the
  grade + receipt to the plugin data dir for audit.
* ``verify_claim`` tool: development-only lexical comparison against fetched
  text. Legacy grade labels are untrusted metadata, not semantic support or
  independent factual verification.

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
    from ._output import label_output
except ImportError:  # standalone / test loading
    import _verify as _v
    from _output import label_output

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


def _on_post_tool_call(tool_name, args, result, task_id, duration_ms=None, **kwargs):
    """Grader hook: grade the result and write the receipt to the audit log.

    Return value is ignored by Hermes — the grade lives in the log, and
    verify_claim verdicts reach the model directly as tool results.
    """
    try:
        grade = _v.grade_tool_result(tool_name, result, duration_ms=duration_ms)
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
# Output labeling
# ---------------------------------------------------------------------------
def _on_transform_llm_output(response_text, **kwargs):
    """Label finished prose without trusting quoted grades as verification."""
    return label_output(response_text)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def register(ctx):
    """Wire the tool and hooks. Called exactly once at Hermes startup."""
    global _BLOCKING_MODE
    try:
        _BLOCKING_MODE = bool(ctx.get_config("blocking_mode", default=False))
    except Exception:
        _BLOCKING_MODE = False

    # No compatibility fallback: a host without stream hold must refuse loading.
    ctx.register_hook(
        "transform_llm_output", _on_transform_llm_output, hold_stream=True,
    )
    ctx.register_skill("receipts", Path(__file__).parent / "skills" / "receipts" / "SKILL.md")
    ctx.register_tool(
        name="verify_claim",
        toolset="hermes_verify",
        schema=VERIFY_CLAIM_SCHEMA,
        handler=_verify_claim_handler,
    )
    ctx.register_hook("pre_tool_call", _on_pre_tool_call)
    ctx.register_hook("post_tool_call", _on_post_tool_call)
    logger.info(
        "hermes-verify registered (blocking_mode=%s)", _BLOCKING_MODE
    )
