"""hermes-verify — pure-stdlib logic for evidence-level enforcement.

This module has NO Hermes dependency on purpose: every function here is
testable without Hermes running. ``__init__.py`` is the thin Hermes-facing
layer (register + hook wrappers) over these functions.

Evidence levels (strongest -> weakest claim about a statement):
  EXTERNALLY-VERIFIED — checked against an independent live source.
  RUNTIME-VERIFIED    — the agent's own runtime observed it (a live tool
                        result). Proves "the tool returned X", NEVER
                        "X is true in the world".
  CODE-VERIFIED       — the runtime executed code and returned a result
                        (a write/action completed). Not an observation.
  DECLARED            — asserted by the agent or a tool, not checked.
  PROPOSED            — a hypothesis / partial support; needs checking.
  UNKNOWN             — no usable evidence either way. Never fabricate.
"""

import html
import json
import re
import urllib.error
import urllib.request
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Evidence levels
# ---------------------------------------------------------------------------

LEVELS = (
    "EXTERNALLY-VERIFIED",
    "RUNTIME-VERIFIED",
    "CODE-VERIFIED",
    "DECLARED",
    "PROPOSED",
    "UNKNOWN",
)

FETCH_TIMEOUT_S = 10
MAX_FETCH_BYTES = 2 * 1024 * 1024  # 2 MiB cap on fetched pages


def utc_now() -> str:
    """ISO-8601 UTC timestamp for receipts."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# pre_tool_call guard — classify risky tool calls
# ---------------------------------------------------------------------------

# Patterns are matched case-insensitively against the tool name and (for
# arg_keys) against argument key names. Values are NEVER matched or logged
# except for the credential value-pattern check, which records only the
# key name, never the value itself.
_RISK_PATTERNS = {
    "spend": {
        "name": ["pay", "charge", "purchase", "buy", "checkout", "stripe",
                 "billing", "subscribe", "invoice", "transfer", "withdraw",
                 "order", "spend", "refund"],
        "arg_keys": ["amount", "price", "currency", "payment_method",
                     "card_number", "total"],
    },
    "send": {
        "name": ["send", "email", "sms", "message", "dm", "notify",
                 "telegram", "discord", "slack", "post_message"],
        "arg_keys": ["to", "recipient", "channel"],
    },
    "publish": {
        "name": ["publish", "upload", "share", "release", "post"],
        "arg_keys": ["public", "publish"],
    },
    "deploy": {
        "name": ["deploy", "release", "push", "terraform", "apply",
                 "rollout", "promote"],
        "arg_keys": [],
    },
    "credentials": {
        "name": ["secret", "credential", "token", "password", "apikey",
                 "api_key", "auth", "vault", "passwd"],
        "arg_keys": ["api_key", "apikey", "token", "secret", "password",
                     "credential", "auth", "passwd"],
    },
}

# Value shapes that look like a secret. Only the ARG KEY is ever recorded.
_SECRET_VALUE_RE = re.compile(
    r"^(sk-[A-Za-z0-9]|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|"
    r"xox[baprs]-[A-Za-z0-9-]{10,}|Bearer\s+\S+)"
)


def _iter_arg_keys(args, _depth=0):
    """Yield (key, value) pairs from nested arg dicts, depth-capped."""
    if not isinstance(args, dict) or _depth > 3:
        return
    for key, value in args.items():
        yield str(key), value
        if isinstance(value, dict):
            yield from _iter_arg_keys(value, _depth + 1)


def classify_tool_call(tool_name, args):
    """Classify a tool call into risk categories.

    Returns a list of {"category": ..., "reason": ...} dicts (empty = benign).
    Matching is on tool name + argument KEY names only. No argument value
    is ever returned or logged.
    """
    name = (tool_name or "").lower()
    flags = []
    arg_pairs = list(_iter_arg_keys(args or {}))
    arg_keys = [k.lower() for k, _ in arg_pairs]

    for category, patterns in _RISK_PATTERNS.items():
        matched = None
        for pat in patterns["name"]:
            if pat in name:
                matched = f"tool name {tool_name!r} matches {category} pattern {pat!r}"
                break
        if matched is None:
            for pat in patterns["arg_keys"]:
                if any(pat in k for k in arg_keys):
                    matched = (
                        f"argument key matches {category} pattern {pat!r} "
                        f"on tool {tool_name!r}"
                    )
                    break
        if matched is None and category == "credentials":
            for key, value in arg_pairs:
                if isinstance(value, str) and _SECRET_VALUE_RE.match(value.strip()):
                    matched = (
                        f"argument {key!r} on tool {tool_name!r} looks like "
                        "a secret value (recorded key only, value withheld)"
                    )
                    break
        if matched:
            flags.append({"category": category, "reason": matched})
    return flags


# ---------------------------------------------------------------------------
# post_tool_call grading — evidence level for a tool result
# ---------------------------------------------------------------------------

_READ_NAME_HINTS = ["read", "fetch", "search", "list", "get", "query",
                    "inspect", "show", "view", "describe", "status",
                    "lookup", "find", "check", "download"]
_EXEC_NAME_HINTS = ["write", "create", "update", "delete", "send", "post",
                    "publish", "deploy", "run", "exec", "terminal", "shell",
                    "charge", "pay", "move", "remove", "install"]

_ERROR_HINTS = ("traceback", "error:", "failed", "exception", "timed out")


def grade_tool_result(tool_name, result, duration_ms=None):
    """Grade a tool result with an evidence level.

    Deterministic and conservative:
      * empty / error-looking result -> UNKNOWN
      * our own verify_claim result -> pass its level through
      * read/observation tool -> RUNTIME-VERIFIED (proves the tool
        returned X, never that X is true in the world)
      * write/action tool -> CODE-VERIFIED (the runtime ran it)
      * anything else -> DECLARED
    """
    ts = utc_now()
    name = (tool_name or "").lower()

    def receipt(level, basis):
        return {
            "level": level,
            "receipt": {
                "tool": tool_name,
                "checked_at": ts,
                "duration_ms": duration_ms,
                "basis": basis,
            },
        }

    if result is None or (isinstance(result, str) and not result.strip()):
        return receipt("UNKNOWN", "empty tool result — no evidence to grade")
    text = result if isinstance(result, str) else json.dumps(result, default=str)
    lowered = text.strip().lower()
    if any(h in lowered for h in _ERROR_HINTS):
        return receipt("UNKNOWN", "tool result reports an error — no evidence to grade")

    if name == "verify_claim":
        try:
            verdict = json.loads(text)
            level = verdict.get("level", "DECLARED")
            if level not in LEVELS:
                level = "DECLARED"
            return receipt(level, "level passed through from verify_claim verdict")
        except Exception:
            return receipt("DECLARED", "verify_claim result unparsable — treated as declared")

    if any(h in name for h in _READ_NAME_HINTS):
        return receipt(
            "RUNTIME-VERIFIED",
            "live read/observation tool returned this result; it proves the "
            "tool returned X, not that X is true in the world",
        )
    if any(h in name for h in _EXEC_NAME_HINTS):
        return receipt(
            "CODE-VERIFIED",
            "runtime executed the action and returned this result; it is not "
            "an independent observation",
        )
    return receipt(
        "DECLARED",
        "unclassified tool result — treat as the agent's report, not verified evidence",
    )


# ---------------------------------------------------------------------------
# verify_claim — check a claim against a live source
# ---------------------------------------------------------------------------

_STOPWORDS = frozenset("""
a an the and or but if then else when at by for with about against between
into through during before after above below to from up down in out on off
over under again further once here there all any both each few more most
other some such no nor not only own same so than too very can will just
should now is are was were be been being have has had do does did would
could shall may might must of as it its this that these those he she they
we you i me my our your his her their what which who whom how why where
""".split())


def _key_phrases(claim, limit=8):
    """Content words of the claim (len>=4, not stopwords), order-preserved."""
    words = re.findall(r"[a-z0-9][a-z0-9\-']{2,}", (claim or "").lower())
    seen = []
    for w in words:
        if len(w) >= 4 and w not in _STOPWORDS and w not in seen:
            seen.append(w)
        if len(seen) >= limit:
            break
    return seen


def _fetch_text(url):
    """Fetch a URL as text. Raises on any failure. Stdlib only."""
    req = urllib.request.Request(
        url, headers={"User-Agent": "hermes-verify/0.1.0 (+evidence check)"}
    )
    with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT_S) as resp:
        raw = resp.read(MAX_FETCH_BYTES + 1)
    if len(raw) > MAX_FETCH_BYTES:
        raw = raw[:MAX_FETCH_BYTES]
    text = raw.decode("utf-8", errors="replace")
    # Strip HTML tags and entities to plain text for phrase matching.
    text = re.sub(r"<script.*?</script>", " ", text, flags=re.S | re.I)
    text = re.sub(r"<style.*?</style>", " ", text, flags=re.S | re.I)
    text = re.sub(r"<[^>]+>", " ", text)
    return html.unescape(text).lower()


def verify_claim(claim, source_url=None, fetch_fn=None):
    """Verify a claim against a live source.

    fetch_fn (optional, for tests): callable(url) -> page text. Defaults
    to the real urllib fetch.

    Returns a dict: {claim, source_url, level, verdict, evidence{...}}.
    Never fabricates a verification: no URL, a bad URL, a failed fetch,
    or a phrase mismatch all return UNKNOWN with the reason stated.
    """
    ts = utc_now()
    claim = (claim or "").strip()

    def out(level, verdict, evidence):
        return {
            "claim": claim,
            "source_url": source_url,
            "level": level,
            "verdict": verdict,
            "evidence": evidence,
            "checked_at": ts,
        }

    if not claim:
        return out("UNKNOWN", "no claim provided",
                   {"reason": "empty claim"})
    if not source_url:
        return out("UNKNOWN", "cannot verify without a source",
                   {"reason": "no source_url provided"})
    if not re.match(r"^https?://", source_url.strip(), re.I):
        return out("UNKNOWN", "unsupported source URL",
                   {"reason": "only http(s) source URLs are supported"})

    phrases = _key_phrases(claim)
    if not phrases:
        return out("UNKNOWN", "claim has no checkable content words",
                   {"reason": "no key phrases extracted from claim"})

    fetcher = fetch_fn or _fetch_text
    try:
        page = fetcher(source_url)
    except Exception as exc:  # noqa: BLE001 — any fetch failure is UNKNOWN
        return out("UNKNOWN", "source fetch failed",
                   {"reason": f"fetch failed: {type(exc).__name__}"})

    found = [p for p in phrases if p in page]
    ratio = len(found) / len(phrases)
    evidence = {
        "phrases_checked": phrases,
        "phrases_found": found,
        "match_ratio": round(ratio, 2),
        "fetched_chars": len(page),
    }
    if ratio >= 0.8:
        return out("EXTERNALLY-VERIFIED", "supported by source", evidence)
    if ratio >= 0.5:
        return out("PROPOSED", "partially supported by source", evidence)
    # Absence of the phrases in this source does NOT prove the claim false.
    return out("UNKNOWN", "not supported by the fetched source", evidence)
