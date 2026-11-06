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

Matching rules (hardened, Nov 5 teardown)
------------------------------------------
Tool-name and argument-key matching is TOKEN based, not substring based:
names are split on separators and camelCase humps, and a pattern matches
only when its tokens appear as a contiguous run of the name's tokens.
That kills the old false positives ("checkout" is not "check",
"reorder" is not "order", "retarget" is not "get") while keeping real
matches ("stripe_checkout" is spend, "get_target" is a read).

Grading order is exec-first: a tool that both reads and acts is graded
as an action (CODE-VERIFIED), because understating evidence is safe and
overstating it is not.
"""

import html
import ipaddress
import json
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

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
MAX_RECEIPT_LIMIT = 100


def utc_now() -> str:
    """ISO-8601 UTC timestamp for receipts."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# Token matching — the fix for substring false positives/negatives
# ---------------------------------------------------------------------------

_CAMEL_SPLIT_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")
_SEPARATOR_RE = re.compile(r"[^a-zA-Z0-9]+")


def _tokens(name: str) -> list[str]:
    """Split a tool/arg name into lowercase tokens.

    Splits on separators (``_``, ``-``, ``.``, …) and on camelCase humps:
    ``"stripeCheckout"`` -> ``["stripe", "checkout"]``,
    ``"get_target"`` -> ``["get", "target"]``.
    """
    parts: list[str] = []
    for chunk in _SEPARATOR_RE.split(name or ""):
        if not chunk:
            continue
        parts.extend(_CAMEL_SPLIT_RE.split(chunk))
    return [p.lower() for p in parts if p]


def _pattern_matches(name_tokens: list[str], pattern: str) -> bool:
    """True when the pattern's tokens appear as a contiguous run of the
    name's tokens. ``"post_message"`` matches ``post_message`` and
    ``send_post_message`` but not ``post`` alone; ``"check"`` matches
    ``check_status`` but not ``checkout``."""
    pat = _tokens(pattern)
    if not pat or len(pat) > len(name_tokens):
        return False
    return any(
        name_tokens[i:i + len(pat)] == pat
        for i in range(len(name_tokens) - len(pat) + 1)
    )


def _any_pattern_matches(name: str, patterns: list[str]) -> Optional[str]:
    """First pattern that token-matches ``name``, or None."""
    toks = _tokens(name)
    for pat in patterns:
        if _pattern_matches(toks, pat):
            return pat
    return None


# ---------------------------------------------------------------------------
# pre_tool_call guard — classify risky tool calls
# ---------------------------------------------------------------------------

# Patterns are matched TOKEN-wise against the tool name and argument KEY
# names. Values are NEVER matched or logged except for the credential
# value-pattern check, which records only the key name, never the value.
_RISK_PATTERNS: dict[str, dict[str, list[str]]] = {
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
    # Generic execution tools can do ANYTHING the other categories cover
    # (a shell can spend, send, publish, deploy, and exfiltrate) but their
    # payload is opaque to name matching. Flag them as their own category:
    # always logged, blocked in blocking_mode. A flag here says "this tool
    # can do anything", not "this call did something risky".
    "exec": {
        "name": ["terminal", "shell", "exec", "execute", "bash", "zsh",
                 "powershell", "cmd", "run", "command", "console",
                 "subprocess", "repl", "sh"],
        "arg_keys": ["command", "script", "shell_command"],
    },
}

# Value shapes that look like a secret. Only the ARG KEY is ever recorded.
_SECRET_VALUE_RE = re.compile(
    r"^(sk-[A-Za-z0-9]|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|"
    r"xox[baprs]-[A-Za-z0-9-]{10,}|Bearer\s+\S+)"
)


def _iter_arg_keys(args: Any, _depth: int = 0):
    """Yield (key, value) pairs from nested arg dicts, depth-capped."""
    if not isinstance(args, dict) or _depth > 3:
        return
    for key, value in args.items():
        yield str(key), value
        if isinstance(value, dict):
            yield from _iter_arg_keys(value, _depth + 1)


def classify_tool_call(tool_name: str, args: Any) -> list[dict[str, str]]:
    """Classify a tool call into risk categories.

    Returns a list of {"category": ..., "reason": ...} dicts (empty = benign).
    Matching is token-based on tool name + argument KEY names only. No
    argument value is ever returned or logged.
    """
    name = tool_name or ""
    flags: list[dict[str, str]] = []
    arg_pairs = list(_iter_arg_keys(args or {}))
    arg_key_tokens = [_tokens(k) for k, _ in arg_pairs]

    for category, patterns in _RISK_PATTERNS.items():
        matched: Optional[str] = None
        pat = _any_pattern_matches(name, patterns["name"])
        if pat is not None:
            matched = f"tool name {tool_name!r} matches {category} pattern {pat!r}"
        if matched is None:
            for key_toks, (key, _v) in zip(arg_key_tokens, arg_pairs):
                pat = next(
                    (p for p in patterns["arg_keys"]
                     if _pattern_matches(key_toks, p)),
                    None,
                )
                if pat is not None:
                    matched = (
                        f"argument key {key!r} matches {category} "
                        f"pattern {pat!r} on tool {tool_name!r}"
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
                    "charge", "pay", "move", "remove", "install",
                    "checkout", "purchase", "order", "transfer", "refund"]

# Structured error evidence only: a result IS an error when it starts with
# an error marker or carries a machine-readable error field. A result that
# merely MENTIONS failure ("3 failed logins blocked") is not an error.
_ERROR_PREFIXES = ("error:", "traceback", "exception:")


def _result_is_structured_error(result: Any) -> bool:
    """True when the result IS an error report, not when it mentions one."""
    if isinstance(result, dict):
        return bool(result.get("error"))
    if not isinstance(result, str):
        return False
    text = result.strip()
    if text.lower().startswith(_ERROR_PREFIXES):
        return True
    try:
        parsed = json.loads(text)
    except Exception:
        return False
    return isinstance(parsed, dict) and bool(parsed.get("error"))


def grade_tool_result(
    tool_name: str,
    result: Any,
    duration_ms: Optional[int] = None,
    status: Optional[str] = None,
    error_message: Optional[str] = None,
) -> dict[str, Any]:
    """Grade a tool result with an evidence level.

    Deterministic and conservative:
      * empty result -> UNKNOWN
      * host-reported ``status="error"`` (the post_tool_call payload's own
        ``status``/``error_type``/``error_message`` fields, derived by Hermes
        from the result) -> UNKNOWN. Without a status, only STRUCTURED
        error evidence counts (leading "Error:"/"Traceback", or a dict/JSON
        ``{"error": ...}`` field) — a result that merely mentions "failed"
        is graded normally.
      * our own verify_claim result -> pass its level through
      * action tool (exec hints checked FIRST) -> CODE-VERIFIED
      * read/observation tool -> RUNTIME-VERIFIED (proves the tool
        returned X, never that X is true in the world)
      * anything else -> DECLARED

    Exec-before-read ordering is deliberate: a tool that both reads and
    acts (``get_order``) is graded as an action, understating evidence
    rather than overstating it.
    """
    ts = utc_now()
    name = tool_name or ""

    def receipt(level: str, basis: str) -> dict[str, Any]:
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
    if status == "error":
        basis = "host reported an error for this tool call"
        if error_message:
            basis += f": {error_message[:200]}"
        return receipt("UNKNOWN", basis)
    if status is None and _result_is_structured_error(result):
        return receipt("UNKNOWN", "tool result IS an error report — no evidence to grade")

    text = result if isinstance(result, str) else json.dumps(result, default=str)

    if name == "verify_claim":
        try:
            verdict = json.loads(text)
            level = verdict.get("level", "DECLARED")
            if level not in LEVELS:
                level = "DECLARED"
            return receipt(level, "level passed through from verify_claim verdict")
        except Exception:
            return receipt("DECLARED", "verify_claim result unparsable — treated as declared")

    if _any_pattern_matches(name, _EXEC_NAME_HINTS) is not None:
        return receipt(
            "CODE-VERIFIED",
            "runtime executed the action and returned this result; it is not "
            "an independent observation",
        )
    if _any_pattern_matches(name, _READ_NAME_HINTS) is not None:
        return receipt(
            "RUNTIME-VERIFIED",
            "live read/observation tool returned this result; it proves the "
            "tool returned X, not that X is true in the world",
        )
    return receipt(
        "DECLARED",
        "unclassified tool result — treat as the agent's report, not verified evidence",
    )


# ---------------------------------------------------------------------------
# Receipts — read-only access to the audit logs
# ---------------------------------------------------------------------------

_RECEIPT_LOGS = {"guard": "guard_log.jsonl", "grades": "grades_log.jsonl"}


def read_receipts(log_name: str, limit: int = 20,
                  data_dir: Optional[Path] = None) -> dict[str, Any]:
    """Read the last ``limit`` records from an audit log (read-only).

    ``log_name`` is "guard" or "grades". ``limit`` clamps to 1..100.
    Returns {"log", "limit", "count", "records"}; raises ValueError for an
    unknown log name and FileNotFoundError when the log does not exist yet
    (callers turn that into an empty result, not a crash).
    """
    filename = _RECEIPT_LOGS.get((log_name or "").lower())
    if filename is None:
        raise ValueError(
            f"unknown log {log_name!r}; expected one of {sorted(_RECEIPT_LOGS)}"
        )
    limit = max(1, min(int(limit or 20), MAX_RECEIPT_LIMIT))
    if data_dir is None:
        data_dir = Path.home() / ".hermes-verify"
    path = Path(data_dir) / filename
    lines = path.read_text(encoding="utf-8").splitlines()
    records = []
    for line in lines[-limit:]:
        try:
            records.append(json.loads(line))
        except Exception:
            continue  # a torn line never breaks the read
    return {"log": log_name.lower(), "limit": limit,
            "count": len(records), "records": records}


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


class _UnsafeURL(ValueError):
    """A fetch URL that fails the SSRF guard (non-public destination)."""


def _validate_fetch_url(url: str) -> None:
    """SSRF guard: allow only http(s) URLs whose host resolves entirely to
    public IPs. Raises _UnsafeURL for anything else — private, loopback,
    link-local, reserved, multicast, unspecified, unresolvable, or a
    non-http(s) scheme. Literal IPs are checked without DNS; hostnames are
    resolved with getaddrinfo and EVERY resolved address must be public.

    Residual risk (documented, not hidden): DNS can change between this
    check and the connect (TOCTOU / DNS rebinding). Closing that needs
    connection-level IP pinning, which stdlib urllib does not offer without
    a custom transport — out of scope for this plugin.
    """
    parsed = urllib.parse.urlparse((url or "").strip())
    if parsed.scheme.lower() not in ("http", "https"):
        raise _UnsafeURL(f"unsupported scheme {parsed.scheme!r}; only http(s) allowed")
    host = parsed.hostname
    if not host:
        raise _UnsafeURL("URL has no host")
    try:
        port = parsed.port
    except ValueError:
        raise _UnsafeURL("URL has an invalid port")
    try:
        infos = socket.getaddrinfo(host, port or (443 if parsed.scheme == "https" else 80),
                                   type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise _UnsafeURL(f"cannot resolve host {host!r}")
    if not infos:
        raise _UnsafeURL(f"cannot resolve host {host!r}")
    for _family, _type, _proto, _canon, sockaddr in infos:
        ip = ipaddress.ip_address(sockaddr[0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            raise _UnsafeURL(f"host {host!r} resolves to non-public address {ip}")


class _SSRFRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Re-validate every redirect target with the SSRF guard before
    following it — a public URL must not smuggle the fetch to localhost
    or the cloud metadata endpoint via a 3xx."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        _validate_fetch_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _key_phrases(claim: str, limit: int = 8) -> list[str]:
    """Content words of the claim (len>=4, not stopwords), order-preserved."""
    words = re.findall(r"[a-z0-9][a-z0-9\-']{2,}", (claim or "").lower())
    seen: list[str] = []
    for w in words:
        if len(w) >= 4 and w not in _STOPWORDS and w not in seen:
            seen.append(w)
        if len(seen) >= limit:
            break
    return seen


_SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+|\n+")
_MAX_SENTENCES = 5000


def _sentences(page: str) -> list[str]:
    """Split page text into sentences (punctuation or newline boundaries)."""
    parts = [s.strip() for s in _SENTENCE_SPLIT_RE.split(page or "") if s.strip()]
    return parts[:_MAX_SENTENCES]


def _best_sentence(page: str, phrases: list[str]) -> tuple[int, str]:
    """The sentence containing the most key phrases, and how many it holds.

    A claim is supported only when ONE sentence states it — words scattered
    across the page ("Hermes" in the header, "tools" in the footer) are not
    a page stating the claim.
    """
    best_hits = 0
    best_text = ""
    for sent in _sentences(page):
        hits = sum(1 for p in phrases if p in sent)
        if hits > best_hits:
            best_hits, best_text = hits, sent
    return best_hits, best_text


def _fetch_text(url: str) -> str:
    """Fetch a URL as text through the SSRF-guarded opener (redirects
    re-validated). Raises on any failure. Stdlib only."""
    _validate_fetch_url(url)
    opener = urllib.request.build_opener(_SSRFRedirectHandler())
    req = urllib.request.Request(
        url, headers={"User-Agent": "hermes-verify/0.1.0 (+evidence check)"}
    )
    with opener.open(req, timeout=FETCH_TIMEOUT_S) as resp:
        raw = resp.read(MAX_FETCH_BYTES + 1)
    if len(raw) > MAX_FETCH_BYTES:
        raw = raw[:MAX_FETCH_BYTES]
    text = raw.decode("utf-8", errors="replace")
    # Strip HTML tags and entities to plain text for phrase matching.
    text = re.sub(r"<script.*?</script>", " ", text, flags=re.S | re.I)
    text = re.sub(r"<style.*?</style>", " ", text, flags=re.S | re.I)
    text = re.sub(r"<[^>]+>", " ", text)
    return html.unescape(text).lower()


def verify_claim(
    claim: str,
    source_url: Optional[str] = None,
    fetch_fn: Optional[Callable[[str], str]] = None,
) -> dict[str, Any]:
    """Verify a claim against a live source.

    fetch_fn (optional, for tests): callable(url) -> page text. Defaults
    to the real urllib fetch. The SSRF guard runs BEFORE any fetcher, so
    even an injected fetch_fn never sees a non-public URL.

    Support is measured per sentence: the score is the fraction of the
    claim's key phrases present in the SINGLE best sentence. Scattered
    words across the page do not count.

    Returns a dict: {claim, source_url, level, verdict, evidence{...}}.
    Never fabricates a verification: no URL, a bad URL, a blocked URL,
    a failed fetch, or a phrase mismatch all return UNKNOWN with the
    reason stated.
    """
    ts = utc_now()
    claim = (claim or "").strip()

    def out(level: str, verdict: str, evidence: dict[str, Any]) -> dict[str, Any]:
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
    try:
        _validate_fetch_url(source_url)
    except _UnsafeURL as exc:
        return out("UNKNOWN", "source URL blocked by SSRF guard",
                   {"reason": str(exc)})

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

    best_hits, best_text = _best_sentence(page, phrases)
    ratio = best_hits / len(phrases)
    evidence = {
        "phrases_checked": phrases,
        "phrases_found": [p for p in phrases if p in best_text],
        "match_ratio": round(ratio, 2),
        "best_sentence_hits": best_hits,
        "supporting_sentence": best_text[:200],
        "fetched_chars": len(page),
    }
    if ratio >= 0.8:
        return out("EXTERNALLY-VERIFIED", "supported by source", evidence)
    if ratio >= 0.5:
        return out("PROPOSED", "partially supported by source", evidence)
    # Absence of the phrases in one sentence does NOT prove the claim false.
    return out("UNKNOWN", "not supported by the fetched source", evidence)
