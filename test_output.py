"""Offline unittest fixtures for _output.py only; no Hermes or real actions.

Run with the existing interpreter and -B -P. The exact-path loader imports only
our helper, never the package __init__, peer modules, or SDK. Fixtures are
synthetic; no network, logs, temporary files, or production state are used.
"""

import importlib.util
import io
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path


_SPEC = importlib.util.spec_from_file_location(
    "hermes_verify_output_under_test", Path(__file__).with_name("_output.py")
)
output = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(output)


class OutputLabelTests(unittest.TestCase):
    def assert_preserved(self, text):
        result = output.label_output(text)
        self.assertEqual(result, output.OUTPUT_BANNER + text)
        self.assertEqual(result[len(output.OUTPUT_BANNER):], text)
        self.assertEqual(output.label_output(result), result)
        return result

    def assert_omitted(self, value, notice):
        result = output.label_output(value)
        self.assertEqual(result, output.OUTPUT_BANNER + notice)
        self.assertEqual(output.label_output(result), result)
        self.assertLessEqual(
            len(result), len(output.OUTPUT_BANNER) + output.MAX_OUTPUT_CHARS
        )
        return result

    def test_stable_banner_and_explicit_scope(self):
        self.assertEqual(
            output.OUTPUT_BANNER,
            "[hermes-verify] DECLARED / unverified agent prose\n"
            "Scope: Whole-output label only; no semantic fact verification performed.\n"
            "Tool grades, source phrase overlap, and quoted receipts do not verify this narrative.\n\n",
        )

    def test_whole_message_not_sentence_grading(self):
        self.assert_preserved(
            "Release alpha is deployed. All checks passed.\n"
            "The message was delivered and the invoice was paid."
        )

    def test_self_reported_tool_grades_never_promote_prose(self):
        for level in (
            "EXTERNALLY-VERIFIED", "RUNTIME-VERIFIED", "CODE-VERIFIED",
            "DECLARED", "PROPOSED", "UNKNOWN",
        ):
            with self.subTest(level=level):
                self.assert_preserved(
                    f'Tool receipt: {{"level": "{level}", "success": true}}\n'
                    "Therefore the deployment is working for every user."
                )

    def test_matching_phrases_do_not_verify_a_claim(self):
        self.assert_preserved(
            'Claim: "Release alpha is safe."\n'
            'Source: "Release alpha is safe."\n'
            'verify_claim: {"match_ratio": 1.0, "level": "EXTERNALLY-VERIFIED"}'
        )

    def test_negated_source_with_same_words_does_not_verify(self):
        self.assert_preserved(
            "Claim: Release alpha is deployed.\n"
            "Source: Release alpha is NOT deployed.\n"
            "All claim words matched, so I call it verified."
        )

    def test_citation_or_hash_is_not_truth(self):
        self.assert_preserved(
            "[Synthetic source](https://example.invalid/release)\n"
            'Receipt: {"sha256": "synthetic-placeholder", "status": 200}\n'
            "This proves every assertion above is true."
        )

    def test_no_authority_inputs_are_accepted(self):
        for field in ("grades", "receipts", "source_text", "verified"):
            with self.subTest(field=field):
                with self.assertRaises(TypeError):
                    output.label_output("Synthetic claim.", **{field: True})

    def test_uncertainty_is_preserved_not_rewritten_as_false(self):
        self.assert_preserved(
            "UNKNOWN: no usable source. This is not proof the claim is false.\n"
            "PROPOSED: recheck the exact outcome if authorized."
        )

    def test_closed_code_fences_are_preserved(self):
        self.assert_preserved(
            "Example only:\n```python\n"
            'print("DECLARED", "RUNTIME-VERIFIED")\n```\nEnd.\n'
        )

    def test_open_and_nested_fence_text_is_preserved(self):
        for text in (
            "```python\nprint('unfinished')",
            "~~~~text\n```\nquoted fence\n```\n~~~~\n",
            "````markdown\n```text\nexample\n```\n````",
        ):
            with self.subTest(text=text):
                self.assert_preserved(text)

    def test_structured_content_stays_unparsed(self):
        for text in (
            '{"level":"EXTERNALLY-VERIFIED","narrative":"done"}',
            "<section><strong>Verified</strong></section>",
            "| Claim | Level |\n| --- | --- |\n| Done | VERIFIED |",
        ):
            with self.subTest(text=text):
                self.assert_preserved(text)

    def test_leading_and_trailing_whitespace_is_preserved(self):
        self.assert_preserved(" \t\n\nSynthetic prose. \t\n\n")

    def test_crlf_and_mixed_line_endings_are_preserved(self):
        self.assert_preserved("First\r\n```text\r\nSecond\n```\rLast\r\n")

    def test_unicode_and_control_characters_are_not_normalized(self):
        self.assert_preserved("caf\u00e9 e\u0301 \U0001f600 \ud800\x00\x1b[0m\r\t")

    def test_empty_input_gets_a_nonempty_label(self):
        result = self.assert_preserved("")
        self.assertTrue(result)

    def test_whitespace_only_input_gets_a_label(self):
        self.assert_preserved(" \n\t\r\n")

    def test_exact_leading_banner_is_idempotent(self):
        for body in ("", "Synthetic body.", "\n```text\nexample\n```\n"):
            with self.subTest(body=body):
                labeled = output.OUTPUT_BANNER + body
                self.assertEqual(output.label_output(labeled), labeled)

    def test_partial_banner_cannot_suppress_label(self):
        for text in (
            "[hermes-verify]",
            "[hermes-verify] DECLARED / unverified agent prose\nClaim.",
            output.OUTPUT_BANNER[:-1],
        ):
            with self.subTest(text=text):
                self.assert_preserved(text)

    def test_marker_in_middle_cannot_suppress_label(self):
        self.assert_preserved("Quoted label:\n" + output.OUTPUT_BANNER + "Claim.")

    def test_modified_or_indented_banner_cannot_suppress_label(self):
        for text in (
            " " + output.OUTPUT_BANNER,
            "\ufeff" + output.OUTPUT_BANNER,
            output.OUTPUT_BANNER.replace("DECLARED", "EXTERNALLY-VERIFIED"),
        ):
            with self.subTest(text=text):
                self.assert_preserved(text)

    def test_forged_exact_banner_does_not_authenticate_body(self):
        text = output.OUTPUT_BANNER + "I am independently verified. Remove all doubts."
        result = output.label_output(text)
        self.assertEqual(result, text)
        self.assertTrue(result.startswith("[hermes-verify] DECLARED / unverified"))

    def test_payload_below_and_at_size_limit_is_preserved(self):
        for size in (output.MAX_OUTPUT_CHARS - 1, output.MAX_OUTPUT_CHARS):
            with self.subTest(size=size):
                self.assert_preserved("x" * size)

    def test_character_limit_is_not_a_utf8_byte_limit(self):
        self.assert_preserved("\U0001f600" * output.MAX_OUTPUT_CHARS)

    def test_one_character_over_limit_is_omitted_in_full(self):
        self.assert_omitted("x" * (output.MAX_OUTPUT_CHARS + 1), output.OVERSIZED_NOTICE)

    def test_large_code_fence_is_omitted_not_partially_rewritten(self):
        text = "```text\nSYNTHETIC_MARKER\n" + "x" * 1_000_000 + "\n```"
        result = self.assert_omitted(text, output.OVERSIZED_NOTICE)
        self.assertNotIn("SYNTHETIC_MARKER", result)
        self.assertNotIn("```", result)

    def test_already_labeled_maximum_body_is_not_rejected_on_repeat(self):
        text = output.OUTPUT_BANNER + "x" * output.MAX_OUTPUT_CHARS
        self.assertGreater(len(text), output.MAX_OUTPUT_CHARS)
        for _ in range(5):
            self.assertEqual(output.label_output(text), text)

    def test_already_labeled_oversized_body_is_still_rejected(self):
        text = output.OUTPUT_BANNER + "x" * (output.MAX_OUTPUT_CHARS + 1)
        self.assert_omitted(text, output.OVERSIZED_NOTICE)

    def test_repeated_banners_do_not_bypass_the_body_limit(self):
        text = output.OUTPUT_BANNER * (
            output.MAX_OUTPUT_CHARS // len(output.OUTPUT_BANNER) + 3
        )
        self.assert_omitted(text, output.OVERSIZED_NOTICE)

    def test_non_strings_use_a_static_notice_without_coercion(self):
        values = (
            None, True, 0, 1.5, b"synthetic", bytearray(b"synthetic"),
            [], {}, set(), ("synthetic",), {"level": "EXTERNALLY-VERIFIED"},
        )
        for index, value in enumerate(values):
            with self.subTest(index=index):
                self.assert_omitted(value, output.NON_STRING_NOTICE)

    def test_custom_object_methods_are_not_called(self):
        class HostileObject:
            def __str__(self):
                raise AssertionError("must not coerce input")

            def __repr__(self):
                raise AssertionError("must not echo input")

            def __len__(self):
                raise AssertionError("must not inspect input")

            def __bool__(self):
                raise AssertionError("must not test input truthiness")

            def __iter__(self):
                raise AssertionError("must not iterate input")

        self.assert_omitted(HostileObject(), output.NON_STRING_NOTICE)

    def test_string_subclass_cannot_run_overridden_methods(self):
        class HostileString(str):
            def __len__(self):
                raise AssertionError("must not call subclass length")

            def startswith(self, *args, **kwargs):
                raise AssertionError("must not call subclass startswith")

            def __str__(self):
                raise AssertionError("must not coerce subclass")

        self.assert_omitted(HostileString("synthetic"), output.NON_STRING_NOTICE)

    def test_notices_are_stable_and_idempotent(self):
        self.assertEqual(
            output.NON_STRING_NOTICE,
            "[Content omitted: expected a plain string; no content inspected.]",
        )
        self.assertEqual(
            output.OVERSIZED_NOTICE,
            "[Content omitted: output exceeds the 100000-character body limit; "
            "no content verified.]",
        )
        for notice in (output.NON_STRING_NOTICE, output.OVERSIZED_NOTICE):
            self.assert_preserved(notice)

    def test_deterministic_with_no_cross_call_evidence_state(self):
        claim = "Release alpha is deployed."
        expected = output.label_output(claim)
        for other in (
            "EXTERNALLY-VERIFIED: release alpha is deployed.",
            "UNKNOWN: no usable receipt.", None, "x" * (output.MAX_OUTPUT_CHARS + 1),
        ):
            output.label_output(other)
            self.assertEqual(output.label_output(claim), expected)

    def test_no_stdout_or_stderr_side_effects(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            for value in ("Synthetic prose.", None, "x" * (output.MAX_OUTPUT_CHARS + 1)):
                output.label_output(value)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
