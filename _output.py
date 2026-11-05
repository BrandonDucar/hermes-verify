"""Pure, conservative whole-output evidence labeling (Python 3.11+).

``label_output(text)`` labels agent prose; it does not verify natural-language
claims, sources, code execution, or action outcomes. It intentionally accepts
no grades, receipts, or source text as authority inputs. A tool's self-reported
level or a source phrase match cannot promote the narrative to verified truth.

Accepted plain strings are preserved character-for-character after a fixed
banner. Non-strings (including str subclasses) and oversized bodies produce a
bounded omission notice instead of coercion, partial output, or silent bypass.
The body limit counts Python string characters, not encoded bytes or tokens.
There is no I/O, logging, clock, mutable state, SDK import, or inference here.

Parent-owned integration must pass the public hook's ``response_text`` to this
helper and register ``transform_llm_output`` with ``hold_stream=True``. This
module neither registers the hook nor proves delivery. It is not a redactor,
Markdown sanitizer, approval gate, or authenticity check for quoted receipts.
"""

MAX_OUTPUT_CHARS = 100_000

OUTPUT_BANNER = (
    "[hermes-verify] DECLARED / unverified agent prose\n"
    "Scope: Whole-output label only; no semantic fact verification performed.\n"
    "Tool grades, source phrase overlap, and quoted receipts do not verify this narrative.\n\n"
)

NON_STRING_NOTICE = (
    "[Content omitted: expected a plain string; no content inspected.]"
)
OVERSIZED_NOTICE = (
    "[Content omitted: output exceeds the 100000-character body limit; "
    "no content verified.]"
)


def label_output(text: object) -> str:
    """Return a nonempty DECLARED/unverified label plus text or an omission.

    For accepted bodies, do not strip, split, parse, reflow, or rewrite content,
    including code fences and existing evidence assertions. An exact leading
    banner is retained for idempotence only; it authenticates nothing. A marker
    elsewhere, a partial banner, or a different label never suppresses ours.

    A previously labeled body's allowance excludes exactly one leading banner,
    so an at-limit body remains unchanged on repeat application. Every result
    fits within ``len(OUTPUT_BANNER) + MAX_OUTPUT_CHARS`` characters. Rejected
    inputs are never formatted, decoded, inspected via user-defined methods,
    or echoed in the omission notice.
    """
    if type(text) is not str:
        return OUTPUT_BANNER + NON_STRING_NOTICE

    already_labeled = text.startswith(OUTPUT_BANNER)
    body_chars = len(text) - (len(OUTPUT_BANNER) if already_labeled else 0)
    if body_chars > MAX_OUTPUT_CHARS:
        return OUTPUT_BANNER + OVERSIZED_NOTICE
    if already_labeled:
        return text
    return OUTPUT_BANNER + text
