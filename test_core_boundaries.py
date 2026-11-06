"""Independent synthetic core challenges retained with the plugin source.

Use an isolated source snapshot under the qualification audit runner.
ROOT is this file's directory, with no fallback to another checkout.
The fixture uses inert data, injected pages, in-memory hook captures, and
temporary receipt files beneath the runner's tempfile root. It is not an OS
sandbox, native qualification, source-independence proof or URL-policy test.
"""

import builtins
import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).parent
PACKAGE_NAME = "_hermes_verify_core_boundary_snapshot"
LEVELS = {"EXTERNALLY-VERIFIED", "RUNTIME-VERIFIED", "CODE-VERIFIED",
          "DECLARED", "PROPOSED", "UNKNOWN"}
URL = "https://93.184.216.34/inert-fixture"
STAMP = "2026-11-06T18:50:00+00:00"
TAIL_BYTES = 256 * 1024
LINE_BYTES = 16 * 1024
MARKER = "INERT_CORE_PRIVATE_SENTINEL_20261106"
TOOL_MARKER = "read_INERT_TOOL_SENTINEL_20261106"
TASK_MARKER = "INERT_TASK_SENTINEL_20261106"
KEY_MARKER = "INERT_KEY_SENTINEL_20261106"


class StringTrap:
    def __init__(self, calls):
        self.calls = calls

    def __str__(self):
        self.calls.append("str")
        return MARKER


class DictTrap(dict):
    def __init__(self, calls):
        super().__init__({"value": "inert"})
        self.calls = calls

    def get(self, *args):
        self.calls.append("get")
        return super().get(*args)

    def items(self):
        self.calls.append("items")
        return super().items()

    def __str__(self):
        self.calls.append("str")
        return MARKER


class AccessorTrap(dict):
    def __init__(self, calls):
        super().__init__({"value": "inert"})
        self.calls = calls

    @property
    def get(self):
        self.calls.append("get_accessor")
        return lambda *args: None


class BoundedReader:
    """Count bytes through the receipt reader's file interface, not its output."""

    def __init__(self, raw, ledger):
        self._handle = raw
        self.ledger = ledger

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return self._handle.__exit__(*args)

    def account(self, value):
        count = len(value.encode("utf-8")) if isinstance(value, str) else len(value)
        self.ledger["read_bytes"] += count
        if self.ledger["read_bytes"] > TAIL_BYTES + 1:
            raise AssertionError("Receipt read exceeded tail byte budget")
        return value

    def read(self, size=-1):
        if size < 0 or size > TAIL_BYTES + 1:
            raise AssertionError("Unbounded receipt read forbidden")
        return self.account(self._handle.read(size))

    def read1(self, size=-1):
        return self.read(size)

    def readline(self, size=-1):
        if size < 0 or size > LINE_BYTES + 1:
            raise AssertionError("Unbounded receipt line read forbidden")
        return self.account(self._handle.readline(size))

    def readinto(self, buffer):
        if len(buffer) > TAIL_BYTES + 1:
            raise AssertionError("Oversized receipt read buffer")
        count = self._handle.readinto(buffer)
        self.ledger["read_bytes"] += count or 0
        if self.ledger["read_bytes"] > TAIL_BYTES + 1:
            raise AssertionError("Receipt read exceeded tail byte budget")
        return count

    def readlines(self, *args):
        raise AssertionError("Unbounded receipt readlines forbidden")

    def __iter__(self):
        return self

    def __next__(self):
        line = self.readline(LINE_BYTES + 1)
        if not line:
            raise StopIteration
        return line

    def __getattr__(self, name):
        if name in {"buffer", "raw", "readall", "fileno"}:
            raise AssertionError("Receipt read accounting bypass forbidden")
        return getattr(self._handle, name)


class CoreBoundaryChallenges(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.records = []
        self.logger = mock.Mock(name="core_memory_only_logger")
        root = ROOT.resolve(strict=True)
        for filename in ("__init__.py", "_verify.py", "_output.py"):
            path = root / filename
            self.assertTrue(path.is_file(), "Copy fixture into snapshot root")
            self.assertEqual(path.resolve(strict=True).parent, root)
        self.assertFalse(any(name == PACKAGE_NAME or name.startswith(PACKAGE_NAME + ".")
                             for name in sys.modules))

        def cleanup_modules():
            for name in list(sys.modules):
                if name == PACKAGE_NAME or name.startswith(PACKAGE_NAME + "."):
                    del sys.modules[name]

        self.addCleanup(cleanup_modules)
        self.stack.enter_context(mock.patch.object(sys, "dont_write_bytecode", True))
        original_import = builtins.__import__

        def snapshot_import(name, globals=None, locals=None, fromlist=(), level=0):
            if level == 0 and name.split(".", 1)[0] in {"_verify", "_output"}:
                raise ImportError("Absolute plugin fallback forbidden by core fixture")
            return original_import(name, globals, locals, fromlist, level)

        spec = importlib.util.spec_from_file_location(
            PACKAGE_NAME, root / "__init__.py", submodule_search_locations=[str(root)],
        )
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        self.pkg = importlib.util.module_from_spec(spec)
        sys.modules[PACKAGE_NAME] = self.pkg
        with mock.patch.object(builtins, "__import__", snapshot_import):
            spec.loader.exec_module(self.pkg)
        self.v = self.pkg._v
        self.assertEqual(Path(self.pkg.__file__).resolve(), root / "__init__.py")
        self.assertEqual(Path(self.v.__file__).resolve(), root / "_verify.py")
        output = sys.modules.get(PACKAGE_NAME + "._output")
        self.assertIsNotNone(output)
        self.assertEqual(Path(output.__file__).resolve(), root / "_output.py")
        self.assertEqual(set(self.v.LEVELS), LEVELS, "Preserve six legacy label names")
        self.stack.enter_context(mock.patch.object(self.pkg, "logger", self.logger))
        self.stack.enter_context(mock.patch.object(self.pkg, "_append_jsonl",
                                                  side_effect=self.capture_record))
        self.stack.enter_context(mock.patch.object(
            self.pkg, "_data_dir", side_effect=AssertionError("Real plugin storage forbidden"),
        ))
        self.stack.enter_context(mock.patch.object(
            self.v, "_fetch_text", side_effect=AssertionError("Default fetch forbidden"),
        ))
        temp_root = Path(tempfile.gettempdir()).resolve(strict=True)
        self.assertFalse(temp_root.is_relative_to(root) or root.is_relative_to(temp_root),
                         "Runner temp and snapshot must be disjoint")
        self.data = Path(self.stack.enter_context(
            tempfile.TemporaryDirectory(prefix="hermes-core-challenge-", dir=temp_root),
        ))
        self.pkg._BLOCKING_MODE = True

    def capture_record(self, filename, record):
        self.records.append((filename, json.loads(json.dumps(record))))

    def captured_text(self):
        return json.dumps({"records": self.records,
                           "logger_calls": repr(self.logger.mock_calls)})

    def grade(self, tool, result, **kwargs):
        try:
            value = self.v.grade_tool_result(tool, result, **kwargs)
        except Exception as exc:
            self.fail("Grader raised instead of returning conservative metadata: " +
                      type(exc).__name__)
        self.assertIs(type(value), dict)
        self.assertIn(value.get("level"), LEVELS)
        if "reported_level" in value:
            self.assertIn(value["reported_level"], LEVELS)
        return value

    def lexical(self, claim, page=None, failure=False, url=URL):
        def fake_fetch(_url):
            if failure:
                raise ConnectionError(MARKER)
            return page or ""

        # This patch isolates claim semantics, deliberately not URL transport policy.
        with mock.patch.object(self.v, "_validate_fetch_url", return_value=None):
            value = self.v.verify_claim(claim, url, fetch_fn=fake_fetch)
        self.assertIs(type(value), dict)
        self.assertIn(value.get("level"), LEVELS)
        return value

    def assert_unknown(self, tool, result, **kwargs):
        self.assertEqual(self.grade(tool, result, **kwargs)["level"], "UNKNOWN")

    def assert_budget_rejected_and_blocked(self, args):
        with self.assertRaises((ValueError, TypeError, RuntimeError)):
            self.v.classify_tool_call("read_file", args)
        directive = self.pkg._on_pre_tool_call("read_file", args, "inert-task")
        self.assertIs(type(directive), dict)
        self.assertEqual(directive.get("action"), "block")
        self.assertTrue(directive.get("message"))

    def write_lines(self, log, records):
        path = self.data / ("guard_log.jsonl" if log == "guard" else "grades_log.jsonl")
        path.write_bytes(b"".join((json.dumps(record) + "\n").encode("utf-8")
                                  for record in records))
        return path

    def read(self, log="grades", limit=20):
        value = self.v.read_receipts(log, limit=limit, data_dir=self.data)
        self.assertIs(type(value), dict)
        self.assertIs(type(value.get("records")), list)
        self.assertIs(type(value.get("truncated")), bool)
        self.assertIs(type(value.get("skipped")), int)
        self.assertGreaterEqual(value["skipped"], 0)
        self.assertEqual(value.get("count"), len(value["records"]))
        return value

    def safe_guard(self, count=1):
        return {"ts": STAMP, "event": "flagged_tool_call",
                "tool_digest": hashlib.sha256(b"inert-tool").hexdigest(),
                "task_digest": hashlib.sha256(b"inert-task").hexdigest(),
                "categories": ["exec"], "reason_codes": ["RISK_EXEC"],
                "arg_key_count": count, "blocked": True}

    def test_01_exact_lexical_match_is_not_external_truth(self):
        value = self.lexical("The company approved the payment", "the company approved the payment")
        self.assertIn(value["level"], {"PROPOSED", "UNKNOWN", "DECLARED"})

    def test_02_negation_overlap_is_not_external_truth(self):
        value = self.lexical("The company has not approved the payment",
                             "the company has approved the payment")
        self.assertNotEqual(value["level"], "EXTERNALLY-VERIFIED")

    def test_03_quantity_overlap_is_not_external_truth(self):
        value = self.lexical("The company delivered 900 electric vehicles",
                             "the company delivered 100 electric vehicles")
        self.assertNotEqual(value["level"], "EXTERNALLY-VERIFIED")

    def test_04_missing_source_is_unknown(self):
        self.assertEqual(self.lexical("The company approved payment", url=None)["level"],
                         "UNKNOWN")

    def test_05_failed_source_is_unknown_and_error_payload_is_withheld(self):
        value = self.lexical("The company approved payment", failure=True)
        self.assertEqual(value["level"], "UNKNOWN")
        self.assertNotIn(MARKER, json.dumps(value))

    def test_06_bare_reported_external_level_cannot_promote(self):
        value = self.grade("verify_claim", '{"level":"EXTERNALLY-VERIFIED"}', status="ok")
        self.assertIn(value["level"], {"DECLARED", "UNKNOWN"})

    def test_07_inconsistent_verifier_envelope_cannot_promote(self):
        value = self.grade("verify_claim", {"level": "EXTERNALLY-VERIFIED",
                           "claim": "payment approved", "verdict": "unsupported",
                           "evidence": {"match_ratio": 0, "claim": "payment refused"}},
                           status="ok")
        self.assertIn(value["level"], {"DECLARED", "UNKNOWN"})

    def test_08_explicit_error_beats_host_ok(self):
        for result in ({"error": MARKER}, json.dumps({"error": MARKER}), "Error: " + MARKER):
            self.assert_unknown("write_file", result, status="ok")

    def test_09_success_false_beats_host_ok(self):
        self.assert_unknown("send_email", {"success": False}, status="ok")

    def test_10_ok_false_beats_host_ok(self):
        self.assert_unknown("write_file", {"ok": False}, status="ok")

    def test_11_denial_and_cancellation_beat_host_ok(self):
        for state in ("denied", "cancelled", "canceled"):
            self.assert_unknown("send_email", {"status": state}, status="ok")

    def test_12_nonzero_exit_beats_host_ok(self):
        for result in ({"exit_code": 23}, {"returncode": 7}):
            self.assert_unknown("terminal", result, status="ok")

    def test_13_failure_mentions_are_observation_not_automatic_errors(self):
        for result in ("3 failed logins blocked by the firewall",
                       ["ordinary read data"], '{"error":'):
            value = self.grade("read_file", result, status="ok")
            self.assertEqual(value["level"], "RUNTIME-VERIFIED")
            self.assertEqual(value.get("outcome"), "OBSERVED_RETURN_NOT_COMPLETION")
            self.assertIsNot(value.get("action_succeeded"), True)
            self.assertIsNot(value.get("claim_truth_verified"), True)
        action = self.grade("send_email", "queued", status="ok")
        self.assertNotEqual(action["level"], "EXTERNALLY-VERIFIED")
        self.assertIsNot(action.get("action_succeeded"), True)

    def test_14_arbitrary_result_stringification_is_not_invoked(self):
        calls = []
        value = self.grade("read_file", StringTrap(calls), status="ok")
        self.assertEqual(calls, [])
        self.assertEqual(value["level"], "UNKNOWN")

    def test_15_dict_subclass_and_accessor_are_not_invoked(self):
        for cls in (DictTrap, AccessorTrap):
            for nested in (False, True):
                calls = []
                result = {"envelope": cls(calls)} if nested else cls(calls)
                value = self.grade("read_file", result)
                self.assertEqual(calls, [])
                self.assertEqual(value["level"], "UNKNOWN")

    def test_16_malformed_result_containers_are_unknown(self):
        for result in (b"not a supported result", ("unsupported tuple",),
                       {"unsupported set"}, {"bad": object()}):
            self.assert_unknown("read_file", result, status="ok")

    def test_17_result_budget_exhaustion_is_unknown(self):
        self.assert_unknown("read_file", "x" * (1024 * 1024 + 1), status="ok")

    def test_18_host_error_text_is_not_persisted(self):
        self.pkg._on_post_tool_call("read_file", {}, '{"error":"synthetic"}', "inert-task",
                                    status="error", error_message=MARKER)
        self.assertTrue(any(name == "grades_log.jsonl" for name, _ in self.records))
        self.assertNotIn(MARKER, self.captured_text())

    def test_19_grade_identifiers_and_argument_keys_are_not_persisted(self):
        self.pkg._on_post_tool_call(TOOL_MARKER, {KEY_MARKER: "inert"},
                                    "inert read result", TASK_MARKER, status="ok")
        grades = [record for name, record in self.records if name == "grades_log.jsonl"]
        self.assertEqual(len(grades), 1, "Retain a useful safe grade audit record")
        captured = self.captured_text()
        for marker in (TOOL_MARKER, TASK_MARKER, KEY_MARKER):
            self.assertNotIn(marker, captured)
        self.assertEqual(grades[0].get("tool_digest"),
                         hashlib.sha256(TOOL_MARKER.encode("utf-8")).hexdigest())
        self.assertEqual(grades[0].get("task_digest"),
                         hashlib.sha256(TASK_MARKER.encode("utf-8")).hexdigest())

    def test_20_credentials_inside_nested_lists_are_flagged(self):
        flags = self.v.classify_tool_call("read_file", {"rows": [{"api_key": "sk-INERT_VALUE"}]})
        self.assertTrue(any(flag.get("category") == "credentials" for flag in flags))

    def test_21_depth_budget_is_explicit_and_strictly_blocked(self):
        args = {"value": "inert"}
        for _ in range(129):
            args = {"nested": args}
        self.assert_budget_rejected_and_blocked(args)

    def test_22_node_budget_is_explicit_and_strictly_blocked(self):
        self.assert_budget_rejected_and_blocked({"rows": [{"value": "x"} for _ in range(8193)]})

    def test_23_string_budget_is_explicit_and_strictly_blocked(self):
        self.assert_budget_rejected_and_blocked({"value": "x" * (TAIL_BYTES + 1)})

    def test_24_classifier_rejects_dict_subclass_without_effects(self):
        calls = []
        with self.assertRaises((ValueError, TypeError, RuntimeError)):
            self.v.classify_tool_call("read_file", DictTrap(calls))
        self.assertEqual(calls, [])

    def test_25_legacy_receipts_are_projected_without_deletion(self):
        record = {"ts": STAMP, "event": "graded_tool_result", "tool": TOOL_MARKER,
                  "task_id": TASK_MARKER, "level": "DECLARED", "unknown": MARKER,
                  "receipt": {"tool": TOOL_MARKER, "basis": MARKER,
                              "checked_at": STAMP, "duration_ms": 1}}
        path = self.write_lines("grades", [record])
        before = path.read_bytes()
        result = self.read()
        self.assertEqual(len(result["records"]), 1, "Keep safe metadata from a valid legacy row")
        self.assertEqual(result["records"][0].get("level"), "DECLARED")
        for marker in (TOOL_MARKER, TASK_MARKER, MARKER):
            self.assertNotIn(marker, json.dumps(result))
        self.assertEqual(path.read_bytes(), before, "Query must not rewrite/delete logs")

    def test_26_receipt_tail_io_is_bounded_not_whole_file(self):
        self.write_lines("guard", [self.safe_guard(i) for i in range(2000)])
        ledger = {"read_bytes": 0}
        real_path_open = Path.open
        real_open = builtins.open

        def path_open(path, *args, **kwargs):
            return BoundedReader(real_path_open(path, *args, **kwargs), ledger)

        def builtin_open(*args, **kwargs):
            return BoundedReader(real_open(*args, **kwargs), ledger)

        with mock.patch.object(Path, "read_text", side_effect=AssertionError("Whole-file read_text")), \
                mock.patch.object(Path, "open", path_open), \
                mock.patch.object(builtins, "open", builtin_open):
            result = self.read("guard", limit=3)
        self.assertEqual(result["count"], 3)
        self.assertEqual(result["records"][-1].get("arg_key_count"), 1999)
        self.assertTrue(result["truncated"])
        self.assertGreater(ledger["read_bytes"], 0)
        self.assertLessEqual(ledger["read_bytes"], TAIL_BYTES + 1)

    def test_27_oversized_and_torn_lines_are_counted_as_skipped(self):
        safe = {"ts": STAMP, "event": "graded_tool_result", "level": "DECLARED"}
        path = self.write_lines("grades", [safe])
        with path.open("ab") as stream:
            stream.write((json.dumps({"level": "DECLARED", "unknown": "x" * (LINE_BYTES + 1)}) +
                          "\n{\"level\":\n" + json.dumps(safe) + "\n").encode("utf-8"))
        result = self.read()
        self.assertEqual(result["count"], 2)
        self.assertGreaterEqual(result["skipped"], 2)

    def test_28_unknown_receipt_log_cannot_select_a_path(self):
        with mock.patch.object(Path, "open", side_effect=AssertionError("Unexpected file read")), \
                mock.patch.object(builtins, "open", side_effect=AssertionError("Unexpected file read")):
            with self.assertRaises(ValueError):
                self.v.read_receipts("../guard_log.jsonl", data_dir=self.data)

    def test_29_poisoned_allowlisted_receipt_fields_do_not_echo(self):
        record = {"ts": MARKER, "event": MARKER, "level": MARKER,
                  "tool_digest": MARKER, "task_digest": MARKER,
                  "categories": [MARKER], "reason_codes": [MARKER],
                  "receipt": {"checked_at": MARKER, "duration_ms": MARKER}}
        self.write_lines("grades", [record])
        result = self.read()
        self.assertNotIn(MARKER, json.dumps(result))

    def test_30_safe_receipt_metadata_survives_and_limit_is_bounded(self):
        safe = self.safe_guard()
        self.write_lines("guard", [safe])
        result = self.read("guard", limit=1000)
        self.assertEqual(result["limit"], 100)
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["records"][0].get("tool_digest"), safe["tool_digest"])
        self.assertEqual(result["records"][0].get("categories"), ["exec"])
        self.assertFalse(result["truncated"])
        self.assertEqual(result["skipped"], 0)

    def test_31_missing_log_has_v2_query_envelope(self):
        with mock.patch.object(self.pkg, "_data_dir", return_value=self.data):
            result = json.loads(self.pkg._query_receipts_handler({"log": "GRADES", "limit": 7}))
        self.assertEqual(result["schema_version"], "hermes-verify.receipt-query.v2")
        self.assertEqual(result["log"], "grades")
        self.assertEqual(result["limit"], 7)
        self.assertEqual(result["count"], 0)
        self.assertEqual(result["records"], [])
        self.assertEqual(result["bytes_read"], 0)
        self.assertIs(result["truncated"], False)
        self.assertEqual(result["skipped"], 0)
        self.assertEqual(result["evidence_stage"], "UNAUTHENTICATED_LOCAL_RECORDS")


if __name__ == "__main__":
    unittest.main(verbosity=2)
