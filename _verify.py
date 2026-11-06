"""hermes-verify — pure-stdlib logic for evidence-level enforcement.

This module has NO Hermes dependency on purpose: every function here is
testable without Hermes running. ``__init__.py`` is the thin Hermes-facing
layer (register + hook wrappers) over these functions.

Evidence levels (strongest -> weakest claim about a statement):
  EXTERNALLY-VERIFIED — reserved legacy vocabulary, never granted here.
  RUNTIME-VERIFIED    — the agent's own runtime observed it (a live tool
                        result). Proves "the tool returned X", NEVER
                        "X is true in the world".
  CODE-VERIFIED       — legacy action-tool return category, not completed
                        execution, delivery or payment.
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
import hashlib
import ipaddress
import json
import math
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
MAX_JSON_NODES = 4096
MAX_JSON_DEPTH = 12
MAX_JSON_STRING_CHARS = 131072
MAX_JSON_TOTAL_CHARS = 262144
MAX_RECEIPT_SCAN_BYTES = 262144
MAX_RECEIPT_LINE_BYTES = 16384


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
# names. The credential value-shape check returns a fixed reason code;
# neither the matched value nor its key name is placed in that reason.
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

# Value shapes that look like a secret; only a fixed reason code is returned.
_SECRET_VALUE_RE = re.compile(
    r"^(sk-[A-Za-z0-9]|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|"
    r"xox[baprs]-[A-Za-z0-9-]{10,}|Bearer\s+\S+)"
)


def _json_key_values(value: Any):
    """Inspect bounded plain JSON without coercing caller objects."""
    stack = [(value, 0, frozenset())]
    remaining = MAX_JSON_NODES
    characters = MAX_JSON_TOTAL_CHARS
    while stack:
        current, depth, ancestors = stack.pop()
        remaining -= 1
        if remaining < 0 or depth > MAX_JSON_DEPTH:
            raise ValueError("HERMES_VERIFY_JSON_BUDGET")
        kind = type(current)
        if kind in (dict, list):
            if id(current) in ancestors or len(current) > MAX_JSON_NODES:
                raise ValueError("HERMES_VERIFY_JSON_SHAPE")
            parents = ancestors | {id(current)}
            if kind is dict:
                for key, child in current.items():
                    if type(key) is not str or len(key) > 256:
                        raise ValueError("HERMES_VERIFY_JSON_KEY")
                    characters -= len(key)
                    yield key, child
                    stack.append((child, depth + 1, parents))
            else:
                stack.extend((child, depth + 1, parents) for child in current)
        elif kind is str:
            if len(current) > MAX_JSON_STRING_CHARS:
                raise ValueError("HERMES_VERIFY_JSON_STRING")
            characters -= len(current)
        elif kind is float:
            if not math.isfinite(current):
                raise ValueError("HERMES_VERIFY_JSON_NUMBER")
        elif kind is int:
            if current.bit_length() > 1024:
                raise ValueError("HERMES_VERIFY_JSON_NUMBER")
        elif current is not None and kind is not bool:
            raise ValueError("HERMES_VERIFY_JSON_TYPE")
        if characters < 0:
            raise ValueError("HERMES_VERIFY_JSON_BUDGET")


def _iter_arg_keys(args: Any, _depth: int = 0):
    if _depth != 0 or type(args) is not dict:
        raise ValueError("HERMES_VERIFY_ARGUMENT_SHAPE")
    yield from _json_key_values(args)


def classify_tool_call(tool_name: str, args: Any) -> list[dict[str, str]]:
    """Classify a tool call into risk categories.

    Returns a list of {"category": ..., "reason": ...} dicts (empty = benign).
    Matching is token-based on tool name + argument KEY names only. No
    argument value is ever returned or logged.
    """
    if type(tool_name) is not str or not tool_name or len(tool_name) > 128:
        raise ValueError("HERMES_VERIFY_TOOL_ID")
    name = tool_name
    flags: list[dict[str, str]] = []
    arg_pairs = list(_iter_arg_keys({} if args is None else args))
    arg_key_tokens = [_tokens(k) for k, _ in arg_pairs]

    for category, patterns in _RISK_PATTERNS.items():
        matched: Optional[str] = None
        pat = _any_pattern_matches(name, patterns["name"])
        if pat is not None:
            matched = "RISK_TOOL_" + category.upper()
        if matched is None:
            for key_toks, (key, _v) in zip(arg_key_tokens, arg_pairs):
                pat = next(
                    (p for p in patterns["arg_keys"]
                     if _pattern_matches(key_toks, p)),
                    None,
                )
                if pat is not None:
                    matched = "RISK_ARGUMENT_" + category.upper()
                    break
        if matched is None and category == "credentials":
            for key, value in arg_pairs:
                if isinstance(value, str) and _SECRET_VALUE_RE.match(value.strip()):
                    matched = "RISK_SECRET_VALUE_SHAPE"
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
    """Recognize reported failure, not absence of proof of success."""
    list(_json_key_values(result))
    payload = result
    if type(result) is str:
        text = result.strip()
        if text.lower().startswith(_ERROR_PREFIXES):
            return True
        try:
            payload = json.loads(text)
        except (ValueError, RecursionError):
            return False
        list(_json_key_values(payload))
    if type(payload) is not dict:
        return False
    if payload.get("error") or payload.get("success") is False or payload.get("ok") is False:
        return True
    state = payload.get("status")
    if type(state) is str and state.lower() in {
        "error", "failed", "failure", "denied", "blocked", "cancelled", "canceled", "timeout", "timed_out",
    }:
        return True
    if any(payload.get(key) is True for key in ("denied", "blocked", "cancelled", "canceled")):
        return True
    for key in ("exit_code", "exitCode", "returncode", "return_code", "exit_status"):
        if key in payload:
            code = payload[key]
            if type(code) not in (int, float) or not math.isfinite(code) or code != 0:
                return True
    return False


def grade_tool_result(
    tool_name: str,
    result: Any,
    duration_ms: Optional[int] = None,
    status: Optional[str] = None,
    error_message: Optional[str] = None,
) -> dict[str, Any]:
    """Classify observed returns without authenticating truth or completion."""
    ts = utc_now()
    name = tool_name if type(tool_name) is str and len(tool_name) <= 128 else ""
    safe_duration = duration_ms if type(duration_ms) in (int, float) and 0 <= duration_ms <= 604800000 else None

    def receipt(level: str, basis: str) -> dict[str, Any]:
        return {
            "schema_version": "hermes-verify.tool-grade.v2",
            "level": level,
            "outcome": "OBSERVED_RETURN_NOT_COMPLETION" if level != "UNKNOWN" else "UNKNOWN",
            "receipt": {
                "tool_digest": hashlib.sha256(name.encode("utf-8", errors="replace")).hexdigest() if name else None,
                "checked_at": ts,
                "duration_ms": safe_duration,
                "basis": basis,
            },
        }

    if not name:
        return receipt("UNKNOWN", "INVALID_TOOL_ID")
    if status is not None and (type(status) is not str or len(status) > 32):
        return receipt("UNKNOWN", "INVALID_HOST_STATUS")
    if type(status) is str and status.lower() in {"error", "failed", "failure", "denied", "blocked", "cancelled", "canceled", "timeout", "timed_out"}:
        return receipt("UNKNOWN", "HOST_REPORTED_FAILURE")
    try:
        reported_failure = _result_is_structured_error(result)
    except (ValueError, TypeError, RecursionError, OverflowError):
        return receipt("UNKNOWN", "UNINSPECTABLE_RESULT")
    if result is None or (type(result) is str and not result.strip()):
        return receipt("UNKNOWN", "EMPTY_RESULT")
    if reported_failure:
        return receipt("UNKNOWN", "RESULT_REPORTED_FAILURE")

    if name == "verify_claim":
        try:
            verdict = json.loads(result) if type(result) is str else result
            reported = verdict.get("level") if type(verdict) is dict else None
            reported = reported if type(reported) is str and reported in LEVELS else None
        except (ValueError, RecursionError):
            reported = None
        graded = receipt("UNKNOWN" if reported == "UNKNOWN" else "DECLARED", "UNTRUSTED_VERIFIER_RESULT")
        if reported is not None:
            graded["reported_level"] = reported
        return graded

    if _any_pattern_matches(name, _EXEC_NAME_HINTS) is not None:
        return receipt(
            "CODE-VERIFIED",
            "OBSERVED_ACTION_RETURN_NOT_COMPLETION",
        )
    if _any_pattern_matches(name, _READ_NAME_HINTS) is not None:
        return receipt(
            "RUNTIME-VERIFIED",
            "OBSERVED_READ_RETURN_NOT_WORLD_TRUTH",
        )
    return receipt(
        "DECLARED",
        "UNCLASSIFIED_REPORTED_RESULT",
    )


# ---------------------------------------------------------------------------
# Receipts — read-only access to the audit logs
# ---------------------------------------------------------------------------

_RECEIPT_LOGS = {"guard": "guard_log.jsonl", "grades": "grades_log.jsonl"}
_CATEGORIES = frozenset(_RISK_PATTERNS)
_BASIS_CODES = frozenset({
    "INVALID_TOOL_ID", "INVALID_HOST_STATUS", "HOST_REPORTED_FAILURE",
    "UNINSPECTABLE_RESULT", "EMPTY_RESULT", "RESULT_REPORTED_FAILURE",
    "UNTRUSTED_VERIFIER_RESULT", "OBSERVED_ACTION_RETURN_NOT_COMPLETION",
    "OBSERVED_READ_RETURN_NOT_WORLD_TRUTH", "UNCLASSIFIED_REPORTED_RESULT",
})


def _digest_identifier(value: Any) -> Optional[str]:
    if type(value) is not str or len(value) > 4096:
        return None
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def _safe_record(record: Any, raw_line: bytes) -> dict[str, Any]:
    if type(record) is not dict:
        raise ValueError("HERMES_VERIFY_RECEIPT_SHAPE")
    list(_json_key_values(record))
    projected: dict[str, Any] = {
        "schema_version": "hermes-verify.receipt-projection.v1",
        "record_digest": hashlib.sha256(raw_line).hexdigest(),
        "evidence_stage": "UNAUTHENTICATED_LOCAL_RECORD",
    }
    event = record.get("event")
    projected["event"] = event if event in ("flagged_tool_call", "graded_tool_result") else "UNCLASSIFIED_RECORD"
    for label, legacy in (("tool_digest", "tool"), ("task_digest", "task_id")):
        digest = record.get(label)
        projected[label] = digest if type(digest) is str and re.fullmatch(r"[0-9a-f]{64}", digest) else _digest_identifier(record.get(legacy))
    timestamp = record.get("ts")
    if type(timestamp) is str and len(timestamp) <= 40:
        try:
            parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            if parsed.tzinfo is not None:
                projected["ts"] = parsed.astimezone(timezone.utc).isoformat(timespec="seconds")
        except ValueError:
            pass
    if type(record.get("blocked")) is bool:
        projected["blocked"] = record["blocked"]
    categories = record.get("categories")
    if type(categories) is list:
        projected["categories"] = sorted({v for v in categories if type(v) is str and v in _CATEGORIES})
        projected["reason_codes"] = ["RISK_" + v.upper() for v in projected["categories"]]
    count = record.get("arg_key_count")
    if type(count) is int and 0 <= count <= MAX_JSON_NODES:
        projected["arg_key_count"] = count
    level = record.get("level")
    if type(level) is str and level in LEVELS:
        projected["reported_level"] = level
        projected["level"] = "UNKNOWN" if level == "UNKNOWN" else "DECLARED"
    receipt = record.get("receipt")
    if type(receipt) is dict:
        basis = receipt.get("basis")
        projected["receipt"] = {"basis": basis if type(basis) is str and basis in _BASIS_CODES else "LEGACY_UNVERIFIED_BASIS"}
    return projected


def read_receipts(log_name: str, limit: int = 20,
                  data_dir: Optional[Path] = None) -> dict[str, Any]:
    """Read a bounded byte tail and return allowlisted unverified metadata."""
    if type(log_name) is not str or len(log_name) > 16 or type(limit) is not int:
        raise ValueError("HERMES_VERIFY_RECEIPT_QUERY_INVALID")
    filename = _RECEIPT_LOGS.get(log_name.lower())
    if filename is None:
        raise ValueError("HERMES_VERIFY_RECEIPT_LOG_UNKNOWN")
    limit = max(1, min(limit, MAX_RECEIPT_LIMIT))
    if data_dir is None:
        data_dir = Path.home() / ".hermes-verify"
    base = Path(data_dir).resolve()
    path = base / filename
    if path.is_symlink() or not path.resolve().is_relative_to(base):
        raise ValueError("HERMES_VERIFY_RECEIPT_PATH_REJECTED")
    with path.open("rb") as stream:
        stream.seek(0, 2)
        size = stream.tell()
        start = max(0, size - MAX_RECEIPT_SCAN_BYTES)
        stream.seek(start)
        raw = stream.read(size - start)
    lines = raw.splitlines()
    skipped = 0
    if start and lines:
        lines = lines[1:]
        skipped += 1
    records = []
    for line in lines:
        if not line or len(line) > MAX_RECEIPT_LINE_BYTES:
            skipped += 1
            continue
        try:
            record = json.loads(line)
            records.append(_safe_record(record, line))
            if len(records) > limit:
                del records[0]
        except (ValueError, TypeError, RecursionError, OverflowError):
            skipped += 1
    return {"schema_version": "hermes-verify.receipt-query.v2", "log": log_name.lower(), "limit": limit,
            "count": len(records), "records": records,
            "bytes_read": len(raw), "truncated": start > 0,
            "skipped": skipped,
            "evidence_stage": "UNAUTHENTICATED_LOCAL_RECORDS"}


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
    a custom transport. Connection binding and proxy behavior remain pending
    transport qualification, not certified by this address check.
    """
    if type(url) is not str or len(url) > 4096 or any(ord(c) < 33 or ord(c) == 127 for c in url):
        raise _UnsafeURL("SOURCE_URL_REJECTED")
    try:
        parsed = urllib.parse.urlparse(url)
    except ValueError:
        raise _UnsafeURL("SOURCE_URL_REJECTED") from None
    if parsed.scheme.lower() not in ("http", "https"):
        raise _UnsafeURL(f"unsupported scheme {parsed.scheme!r}; only http(s) allowed")
    host = parsed.hostname
    if not host or len(host) > 253 or parsed.username is not None or parsed.password is not None:
        raise _UnsafeURL("URL has no host")
    try:
        port = parsed.port
    except ValueError:
        raise _UnsafeURL("URL has an invalid port")
    if port == 0:
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
        mapped = ip.ipv4_mapped if isinstance(ip, ipaddress.IPv6Address) else None
        if (not ip.is_global or (mapped is not None and not mapped.is_global)
                or ip.is_private or ip.is_loopback or ip.is_link_local
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

    This is sentence-local lexical overlap only, not proof that the sentence
    states or supports the claim. Negation and quantities need separate review.
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
        url, headers={"User-Agent": "hermes-verify/0.4.0 (+source text check)"}
    )
    with opener.open(req, timeout=FETCH_TIMEOUT_S) as resp:
        raw = resp.read(MAX_FETCH_BYTES + 1)
    if len(raw) > MAX_FETCH_BYTES:
        raise ValueError("HERMES_VERIFY_SOURCE_BODY_LIMIT")
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
    """Compare bounded source text; lexical overlap never verifies world truth.

    fetch_fn (optional, for tests): callable(url) -> page text. Defaults
    to the real urllib fetch. The SSRF guard runs BEFORE any fetcher, so
    even an injected fetch_fn never sees a non-public URL.

    Support is measured per sentence: the score is the fraction of the
    claim's key phrases present in the SINGLE best sentence. Scattered
    words across the page do not count.

    Returns a dict: {claim, source_url, level, verdict, evidence{...}}.
    Matching yields at most PROPOSED. Missing, inaccessible or unmatched
    evidence is UNKNOWN, never proof that a claim is false.
    """
    ts = utc_now()
    valid_claim = type(claim) is str and len(claim) <= MAX_JSON_STRING_CHARS
    claim = claim.strip() if valid_claim else ""
    safe_source_url = None

    def out(level: str, verdict: str, evidence: dict[str, Any]) -> dict[str, Any]:
        return {
            "schema_version": "hermes-verify.source-text.v2",
            "claim": claim,
            "source_url": safe_source_url,
            "level": level,
            "scope": "LEXICAL_SOURCE_TEXT_ONLY",
            "verified": False,
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
    except _UnsafeURL:
        return out("UNKNOWN", "source URL blocked by SSRF guard",
                   {"reason": "SOURCE_URL_REJECTED"})
    safe_source_url = source_url

    phrases = _key_phrases(claim)
    if not phrases:
        return out("UNKNOWN", "claim has no checkable content words",
                   {"reason": "no key phrases extracted from claim"})

    fetcher = fetch_fn or _fetch_text
    try:
        page = fetcher(source_url)
        if type(page) is not str or len(page) > MAX_FETCH_BYTES:
            raise ValueError("HERMES_VERIFY_SOURCE_TEXT_LIMIT")
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
        return out("PROPOSED", "lexical overlap only; truth is unverified", evidence)
    if ratio >= 0.5:
        return out("PROPOSED", "partial lexical overlap only; truth is unverified", evidence)
    # Absence of the phrases in one sentence does NOT prove the claim false.
    return out("UNKNOWN", "insufficient lexical overlap in fetched text", evidence)
