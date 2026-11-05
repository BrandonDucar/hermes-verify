#!/usr/bin/env python3
"""Offline test suite for hermes-verify. Stdlib only, no network, no Hermes.

Exercises the guard classification, the evidence grader, verify_claim
(with a fake fetch), and register() with a fake ctx. Prints PASS/FAIL per
case; exit code 0 iff all pass.

Usage: python3 test_verify.py
"""

import importlib.util
import json
import sys
from pathlib import Path

PLUGIN_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(PLUGIN_DIR))

import _verify as v  # noqa: E402

# Load __init__.py as a package so its relative import works.
_spec = importlib.util.spec_from_file_location(
    "hermes_verify", PLUGIN_DIR / "__init__.py",
    submodule_search_locations=[str(PLUGIN_DIR)],
)
pkg = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pkg)

RESULTS = []


def check(name, cond, detail=""):
    RESULTS.append((name, bool(cond), detail))
    print(f"{'PASS' if cond else 'FAIL'}  {name}" + (f"  — {detail}" if detail and not cond else ""))


# --- Fake ctx that records registrations, mimicking the Hermes API surface.
class FakeCtx:
    def __init__(self):
        self.tools = {}
        self.hooks = {}
        self._config = {}

    def get_config(self, key, default=None):
        return self._config.get(key, default)

    def set_config(self, key, value):
        self._config[key] = value

    def register_tool(self, name, toolset, schema, handler, **kwargs):
        self.tools[name] = {"toolset": toolset, "schema": schema, "handler": handler}

    def register_hook(self, event, fn, **kwargs):
        self.hooks.setdefault(event, []).append(fn)


# ---------------------------------------------------------------- guard
def test_guard():
    flags = v.classify_tool_call("stripe_charge", {"amount": 499, "currency": "usd"})
    check("guard: stripe_charge flagged spend",
          any(f["category"] == "spend" for f in flags), str(flags))

    flags = v.classify_tool_call("send_email", {"to": "a@b.com", "subject": "hi"})
    check("guard: send_email flagged send",
          any(f["category"] == "send" for f in flags), str(flags))

    flags = v.classify_tool_call("publish_post", {"channel": "x", "public": True})
    check("guard: publish_post flagged publish",
          any(f["category"] == "publish" for f in flags), str(flags))

    flags = v.classify_tool_call("deploy_app", {"env": "prod"})
    check("guard: deploy_app flagged deploy",
          any(f["category"] == "deploy" for f in flags), str(flags))

    flags = v.classify_tool_call("read_file", {"api_key": "sk-test1234567890"})
    check("guard: api_key arg flagged credentials",
          any(f["category"] == "credentials" for f in flags), str(flags))
    check("guard: secret value never in flag reason",
          not any("sk-test" in f["reason"] for f in flags), str(flags))

    flags = v.classify_tool_call("read_file", {"path": "notes.md"})
    check("guard: read_file benign (no flags)", flags == [], str(flags))

    flags = v.classify_tool_call("terminal", {"command": "ls"})
    check("guard: terminal flagged exec (generic execution tool)",
          any(f["category"] == "exec" for f in flags), str(flags))


def test_guard_hook_modes():
    # Default (blocking off): flagged call returns None (allowed through).
    pkg._BLOCKING_MODE = False
    ret = pkg._on_pre_tool_call("stripe_charge", {"amount": 10}, "task-1")
    check("guard hook: flag-and-log returns None when blocking off", ret is None, str(ret))

    # Blocking on: flagged call returns a block directive.
    pkg._BLOCKING_MODE = True
    ret = pkg._on_pre_tool_call("stripe_charge", {"amount": 10}, "task-1")
    check("guard hook: blocking on returns block directive",
          isinstance(ret, dict) and ret.get("action") == "block", str(ret))

    # Benign call is never blocked, even in blocking mode.
    ret = pkg._on_pre_tool_call("read_file", {"path": "a.md"}, "task-1")
    check("guard hook: benign call allowed in blocking mode", ret is None, str(ret))
    pkg._BLOCKING_MODE = False


# ---------------------------------------------------------------- grading
def test_grading():
    g = v.grade_tool_result("read_file", "contents of notes.md", duration_ms=12)
    check("grade: read_file -> RUNTIME-VERIFIED",
          g["level"] == "RUNTIME-VERIFIED", str(g))

    g = v.grade_tool_result("web_search", "10 results...", duration_ms=300)
    check("grade: web_search -> RUNTIME-VERIFIED",
          g["level"] == "RUNTIME-VERIFIED", str(g))

    g = v.grade_tool_result("write_file", "wrote 42 bytes", duration_ms=5)
    check("grade: write_file -> CODE-VERIFIED",
          g["level"] == "CODE-VERIFIED", str(g))

    g = v.grade_tool_result("send_email", "message queued", duration_ms=80)
    check("grade: send_email -> CODE-VERIFIED",
          g["level"] == "CODE-VERIFIED", str(g))

    g = v.grade_tool_result("read_file", "", duration_ms=1)
    check("grade: empty result -> UNKNOWN", g["level"] == "UNKNOWN", str(g))

    g = v.grade_tool_result("read_file", "Error: file not found", duration_ms=1)
    check("grade: error result -> UNKNOWN", g["level"] == "UNKNOWN", str(g))

    g = v.grade_tool_result("mystery_tool", "some output", duration_ms=1)
    check("grade: unclassified tool -> DECLARED",
          g["level"] == "DECLARED", str(g))

    inner = json.dumps({"level": "EXTERNALLY-VERIFIED", "verdict": "supported"})
    g = v.grade_tool_result("verify_claim", inner, duration_ms=1)
    check("grade: verify_claim passes level through",
          g["level"] == "EXTERNALLY-VERIFIED", str(g))


# ---------------------------------------------------------------- verify_claim
PAGE = """
<html><head><title>Test</title></head><body>
<p>The Hermes Agent plugin system lets developers add tools and hooks.
A plugin is a directory with a plugin.yaml manifest and Python code.</p>
</body></html>
"""


def test_verify_claim():
    r = v.verify_claim("The Hermes plugin system lets developers add tools and hooks",
                       "https://93.184.216.34/plugins",
                       fetch_fn=lambda url: PAGE.lower())
    check("verify_claim: matching source -> EXTERNALLY-VERIFIED",
          r["level"] == "EXTERNALLY-VERIFIED", str(r))

    r = v.verify_claim("Quantum entanglement breaks causality in dolphins",
                       "https://93.184.216.34/plugins",
                       fetch_fn=lambda url: PAGE.lower())
    check("verify_claim: no phrase match -> UNKNOWN (never false)",
          r["level"] == "UNKNOWN" and "false" not in r["verdict"].lower(), str(r))

    r = v.verify_claim("The plugin system lets developers add tools and hooks",
                       "https://93.184.216.34/plugins",
                       fetch_fn=lambda url: "the plugin system lets developers build things")
    check("verify_claim: partial match -> PROPOSED",
          r["level"] == "PROPOSED", str(r))

    r = v.verify_claim("Some claim", None)
    check("verify_claim: no URL -> UNKNOWN",
          r["level"] == "UNKNOWN" and "without a source" in r["verdict"].lower(), str(r))

    r = v.verify_claim("Some claim", "ftp://example.com/x")
    check("verify_claim: non-http URL -> UNKNOWN",
          r["level"] == "UNKNOWN", str(r))

    def _boom(url):
        raise ConnectionError("network down")

    r = v.verify_claim("Some claim", "https://93.184.216.34/x", fetch_fn=_boom)
    check("verify_claim: fetch failure -> UNKNOWN",
          r["level"] == "UNKNOWN" and "fetch failed" in r["evidence"]["reason"], str(r))

    r = v.verify_claim("", "https://93.184.216.34/x")
    check("verify_claim: empty claim -> UNKNOWN", r["level"] == "UNKNOWN", str(r))

    # Handler path: always JSON string, never raises.
    out = pkg._verify_claim_handler({"claim": "x"}, source_url=None)
    parsed = json.loads(out)
    check("handler: returns JSON string with UNKNOWN for missing source",
          parsed["level"] == "UNKNOWN", out)


# ---------------------------------------------------------------- register
def test_register():
    ctx = FakeCtx()
    pkg.register(ctx)
    check("register: verify_claim tool registered",
          "verify_claim" in ctx.tools, str(sorted(ctx.tools)))
    check("register: pre_tool_call hook registered",
          "pre_tool_call" in ctx.hooks, str(sorted(ctx.hooks)))
    check("register: post_tool_call hook registered",
          "post_tool_call" in ctx.hooks, str(sorted(ctx.hooks)))
    check("register: transform_llm_output NOT registered (Codex's lane)",
          "transform_llm_output" not in ctx.hooks, str(sorted(ctx.hooks)))
    schema = ctx.tools["verify_claim"]["schema"]
    check("register: schema requires claim",
          schema["parameters"]["required"] == ["claim"], str(schema))

    ctx2 = FakeCtx()
    ctx2._config["blocking_mode"] = True
    pkg.register(ctx2)
    check("register: blocking_mode read from config",
          pkg._BLOCKING_MODE is True, str(pkg._BLOCKING_MODE))
    pkg._BLOCKING_MODE = False


# ---------------------------------------------------------------- teardown
# Failing-first tests for the holes found in the adversarial teardown.
# Each test below documents a real bypass / false positive / weak check.
def test_exec_bypass():
    # A shell tool carrying a spend payload sailed through unflagged: the
    # guard only matched tool names + arg keys against spend/send patterns.
    flags = v.classify_tool_call(
        "terminal",
        {"command": "curl -X POST https://payments.example.com/charge -d amount=499"},
    )
    check("teardown: terminal with spend payload flagged exec",
          any(f["category"] == "exec" for f in flags), str(flags))

    for name in ("run_shell", "exec_command", "bash", "run_command", "powershell"):
        flags = v.classify_tool_call(name, {"command": "echo hi"})
        check(f"teardown: {name} flagged exec",
              any(f["category"] == "exec" for f in flags), str(flags))

    # Exec flags must still log-and-allow by default, and block in blocking mode.
    pkg._BLOCKING_MODE = False
    ret = pkg._on_pre_tool_call("terminal", {"command": "ls"}, "task-1")
    check("teardown: exec call allowed when blocking off", ret is None, str(ret))
    pkg._BLOCKING_MODE = True
    ret = pkg._on_pre_tool_call("terminal", {"command": "ls"}, "task-1")
    check("teardown: exec call blocked when blocking on",
          isinstance(ret, dict) and ret.get("action") == "block", str(ret))
    pkg._BLOCKING_MODE = False


def test_substring_matching():
    # "checkout" contains "check" -> old grader called a spend tool
    # RUNTIME-VERIFIED (read hints checked before exec hints).
    g = v.grade_tool_result("stripe_checkout", "charged $10", duration_ms=5)
    check("teardown: stripe_checkout is an action, not a read",
          g["level"] == "CODE-VERIFIED", str(g))

    # "target" contains "get" -> old grader called a retarget tool a read.
    g = v.grade_tool_result("retarget_audience", "audience updated", duration_ms=5)
    check("teardown: retarget_audience is not a read",
          g["level"] != "RUNTIME-VERIFIED", str(g))

    # "reorder" contains "order" -> old guard flagged it as spend.
    flags = v.classify_tool_call("reorder_items", {"items": ["a", "b"]})
    check("teardown: reorder_items is not spend",
          not any(f["category"] == "spend" for f in flags), str(flags))

    # Real matches must still fire: checkout IS spend, get_target IS a read.
    flags = v.classify_tool_call("stripe_checkout", {"total": 10})
    check("teardown: stripe_checkout still flagged spend",
          any(f["category"] == "spend" for f in flags), str(flags))
    g = v.grade_tool_result("get_target", "target data", duration_ms=5)
    check("teardown: get_target still a read",
          g["level"] == "RUNTIME-VERIFIED", str(g))


def test_sentence_window():
    # All key phrases present on the page, but scattered across sentences:
    # that is NOT a page stating the claim.
    scattered = (
        "The Hermes manual is long. The plugin registry is public. "
        "Developers write the system docs. Agents add tools daily. "
        "Hooks run on every call. The agent framework is documented."
    )
    r = v.verify_claim(
        "The Hermes plugin system lets developers add tools and hooks",
        "https://93.184.216.34/docs",
        fetch_fn=lambda url: scattered.lower(),
    )
    check("teardown: scattered words are not support -> UNKNOWN",
          r["level"] == "UNKNOWN", str(r))

    # Same phrases, one sentence stating the claim -> verified.
    together = (
        "Unrelated preamble here. The Hermes plugin system lets developers "
        "add tools and hooks in one directory. More unrelated text follows."
    )
    r = v.verify_claim(
        "The Hermes plugin system lets developers add tools and hooks",
        "https://93.184.216.34/docs",
        fetch_fn=lambda url: together.lower(),
    )
    check("teardown: one sentence stating the claim -> EXTERNALLY-VERIFIED",
          r["level"] == "EXTERNALLY-VERIFIED", str(r))


def test_ssrf_guard():
    called = []

    def _recording_fetch(url):
        called.append(url)
        return "the plugin system lets developers add tools and hooks"

    for bad_url in (
        "http://169.254.169.254/latest/meta-data",
        "http://localhost:8080/admin",
        "http://127.0.0.1/secret",
        "http://10.0.0.5/internal",
        "http://192.168.1.1/router",
        "http://[::1]/admin",
    ):
        called.clear()
        r = v.verify_claim("The plugin system lets developers add tools",
                           bad_url, fetch_fn=_recording_fetch)
        check(f"teardown: SSRF blocked for {bad_url}",
              r["level"] == "UNKNOWN" and not called, str(r))

    # A literal public IP must pass the guard and reach the fetcher.
    called.clear()
    r = v.verify_claim("The plugin system lets developers add tools",
                       "http://93.184.216.34/docs",
                       fetch_fn=_recording_fetch)
    check("teardown: public IP passes SSRF guard, fetcher called",
          called == ["http://93.184.216.34/docs"], str(r))

    # A redirect to a private destination must be refused before following.
    import urllib.request
    handler = v._SSRFRedirectHandler()
    req = urllib.request.Request("http://93.184.216.34/start")
    try:
        handler.redirect_request(req, None, 302, "Found", {},
                                 "http://169.254.169.254/latest/meta-data")
        check("teardown: redirect to metadata endpoint refused", False,
              "redirect_request did not raise")
    except v._UnsafeURL:
        check("teardown: redirect to metadata endpoint refused", True)


def test_grader_error_detection():
    # A result that merely MENTIONS failure is not an error report.
    g = v.grade_tool_result("read_file", "3 failed logins blocked by the firewall",
                            duration_ms=5, status="ok")
    check("teardown: 'failed logins blocked' with status=ok is not an error",
          g["level"] == "RUNTIME-VERIFIED", str(g))

    # Host-reported error status wins.
    g = v.grade_tool_result("read_file", "Error: file not found",
                            duration_ms=5, status="error")
    check("teardown: status=error -> UNKNOWN",
          g["level"] == "UNKNOWN", str(g))

    # Without a status, only STRUCTURED error evidence counts.
    g = v.grade_tool_result("read_file", "Error: file not found", duration_ms=5)
    check("teardown: leading 'Error:' without status -> UNKNOWN",
          g["level"] == "UNKNOWN", str(g))
    g = v.grade_tool_result("read_file", '{"error": "boom"}', duration_ms=5)
    check("teardown: JSON {error} without status -> UNKNOWN",
          g["level"] == "UNKNOWN", str(g))
    g = v.grade_tool_result("read_file", "the operation failed gracefully",
                            duration_ms=5)
    check("teardown: 'failed' mid-sentence without status is not an error",
          g["level"] == "RUNTIME-VERIFIED", str(g))


def test_receipts_tool():
    import os
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        os.environ["HERMES_VERIFY_DATA_DIR"] = tmp
        try:
            pkg._append_jsonl("guard_log.jsonl", {"event": "flagged_tool_call", "tool": "a"})
            pkg._append_jsonl("guard_log.jsonl", {"event": "flagged_tool_call", "tool": "b"})
            pkg._append_jsonl("guard_log.jsonl", {"event": "flagged_tool_call", "tool": "c"})
            out = pkg._query_receipts_handler({"log": "guard", "limit": 2})
            parsed = json.loads(out)
            check("teardown: query_receipts returns last N guard records",
                  [r["tool"] for r in parsed["records"]] == ["b", "c"], out)

            out = pkg._query_receipts_handler({"log": "guard", "limit": 500})
            parsed = json.loads(out)
            check("teardown: query_receipts clamps limit to 100",
                  parsed["limit"] == 100, out)

            out = pkg._query_receipts_handler({"log": "bogus"})
            parsed = json.loads(out)
            check("teardown: query_receipts rejects unknown log name",
                  "error" in parsed, out)

            out = pkg._query_receipts_handler({"log": "grades"})
            parsed = json.loads(out)
            check("teardown: query_receipts grades log empty -> empty list",
                  parsed["records"] == [], out)
        finally:
            del os.environ["HERMES_VERIFY_DATA_DIR"]

    # The tool must be registered and declared in the manifest.
    ctx = FakeCtx()
    pkg.register(ctx)
    check("teardown: query_receipts tool registered",
          "query_receipts" in ctx.tools, str(sorted(ctx.tools)))
    manifest = Path(PLUGIN_DIR / "plugin.yaml").read_text()
    check("teardown: plugin.yaml declares query_receipts",
          "query_receipts" in manifest, manifest)
    pkg._BLOCKING_MODE = False


def main():
    test_guard()
    test_guard_hook_modes()
    test_grading()
    test_verify_claim()
    test_register()
    test_exec_bypass()
    test_substring_matching()
    test_sentence_window()
    test_ssrf_guard()
    test_grader_error_detection()
    test_receipts_tool()
    failed = [r for r in RESULTS if not r[1]]
    print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} passed")
    if failed:
        print("FAILED:", ", ".join(r[0] for r in failed))
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
