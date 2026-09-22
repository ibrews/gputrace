import importlib.util
import os
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT_PATH = Path(
    os.environ.get("GPUTRACE_SCRIPT", Path(__file__).parents[1] / "gputrace.py")
).resolve()
SPEC = importlib.util.spec_from_file_location("gputrace_under_test", SCRIPT_PATH)
GPUTRACE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GPUTRACE)

PREAMBLE = b"MTSP\0\0\0\0"
FIXED_PREFIX = struct.Struct("<Ii24sI")


def make_record(signature=b"", payload=b"", selector=-1, kind=7):
    signature_field = signature + b"\0"
    signature_field += b"\0" * (-len(signature_field) % 4)
    length = FIXED_PREFIX.size + len(signature_field) + len(payload)
    return FIXED_PREFIX.pack(length, selector, b"\0" * 24, kind) + signature_field + payload


class RecordBoundaryTests(unittest.TestCase):
    def test_self_declared_32_byte_record_resyncs_to_following_record(self):
        malformed = struct.pack("<I", 32) + b"\0" * 28
        valid = make_record(selector=-6, kind=15)

        rows = list(GPUTRACE.records(PREAMBLE + malformed + valid))

        self.assertEqual(1, len(rows))
        self.assertEqual((8 + len(malformed), 40, -6, 15, "", b""), rows[0])

    def test_unterminated_signature_does_not_consume_following_record(self):
        malformed = FIXED_PREFIX.pack(40, -2, b"\0" * 24, 3) + b"CCCC"
        valid = make_record(signature=b"C", selector=-3, kind=9)

        rows = list(GPUTRACE.records(PREAMBLE + malformed + valid))

        self.assertEqual(1, len(rows))
        self.assertEqual(8 + len(malformed), rows[0][0])
        self.assertEqual((-3, 9, "C"), (rows[0][2], rows[0][3], rows[0][4]))

    def test_signature_padding_must_fit_declared_record(self):
        malformed = FIXED_PREFIX.pack(41, -2, b"\0" * 24, 3) + b"CCCC\0"
        valid = make_record(selector=-4, kind=11)

        rows = list(GPUTRACE.records(PREAMBLE + malformed + valid))

        self.assertEqual(1, len(rows))
        self.assertEqual(8 + len(malformed), rows[0][0])
        self.assertEqual((-4, 11, "", b""), (rows[0][2], rows[0][3], rows[0][4], rows[0][5]))

    def test_minimal_40_byte_record_parses(self):
        record = make_record(selector=-5, kind=13)
        self.assertEqual(40, len(record))

        rows = list(GPUTRACE.records(PREAMBLE + record))

        self.assertEqual(1, len(rows))
        self.assertEqual((8, 40, -5, 13, "", b""), rows[0])

    def test_pathological_length_cannot_read_past_buffer(self):
        malformed = struct.pack("<I", 0xFFFFFFFF) + b"\0" * 36
        self.assertEqual([], list(GPUTRACE.records(PREAMBLE + malformed)))

    def test_records_cli_skips_truncated_record_without_traceback(self):
        scratch = os.environ.get("GPUTRACE_TEST_TMPDIR")
        if scratch:
            Path(scratch).mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temp_dir:
            trace = Path(temp_dir) / "synthetic.gputrace"
            trace.mkdir()
            member = trace / "truncated"
            member.write_bytes(PREAMBLE + struct.pack("<I", 32) + b"\0" * 28)

            result = subprocess.run(
                [sys.executable, "-B", str(SCRIPT_PATH), str(trace), "records", member.name],
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertEqual(0, result.returncode)
        self.assertEqual("", result.stdout)
        self.assertEqual("", result.stderr)


if __name__ == "__main__":
    unittest.main()
