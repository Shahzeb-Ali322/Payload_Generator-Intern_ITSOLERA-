import base64
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from urllib.parse import unquote

from safe_input_tests import (
    ALL_CATEGORIES,
    encode_value,
    generate_cases,
    main,
    render_cases,
)


class SafeInputTestsTest(unittest.TestCase):
    def test_all_categories_have_small_fixed_probe_sets(self):
        self.assertEqual(ALL_CATEGORIES, ("xss", "sqli", "command"))
        self.assertEqual(len(generate_cases("xss", token="AB12")), 2)
        self.assertEqual(len(generate_cases("sqli", token="AB12")), 4)
        self.assertEqual(len(generate_cases("command", token="AB12")), 3)

    def test_cases_include_a_correlatable_token_and_lab_warning(self):
        cases = generate_cases("xss", token="AB12")
        self.assertTrue(all("AB12" in case["input"] for case in cases))
        self.assertTrue(all(case["requires_authorized_lab"] is True for case in cases))
        self.assertTrue(all(case["encoding"] == "none" for case in cases))

    def test_cli_tokens_cannot_inject_arbitrary_text(self):
        with self.assertRaises(ValueError):
            generate_cases("xss", token="<script>")

    def test_only_known_categories_and_encodings_are_accepted(self):
        with self.assertRaises(ValueError):
            generate_cases("unknown", token="AB12")
        with self.assertRaises(ValueError):
            encode_value("safe marker", "unknown")

    def test_encoders_transform_only_the_supplied_marker_string(self):
        self.assertEqual(encode_value("a b", "url"), "a%20b")
        self.assertEqual(base64.b64decode(encode_value("SAFE", "base64")), b"SAFE")
        self.assertEqual(bytes.fromhex(encode_value("SAFE", "hex")), b"SAFE")
        self.assertEqual(unquote(encode_value("a b", "url")), "a b")
        self.assertEqual(encode_value("<", "unicode"), r"\u003c")

    def test_json_export_is_valid_and_marks_scope(self):
        cases = generate_cases("sqli", token="AB12")
        output = render_cases(cases, "json")
        parsed = json.loads(output)
        self.assertEqual(len(parsed), 4)
        self.assertTrue(all(item["requires_authorized_lab"] for item in parsed))

    def test_text_export_is_readable(self):
        output = render_cases(generate_cases("xss", token="AB12"), "text")
        self.assertIn("XSS", output)
        self.assertIn("AB12", output)

    def test_cli_exports_json_to_a_new_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "cases.json"
            with contextlib.redirect_stdout(io.StringIO()):
                status = main(["--xss", "--encode", "url", "--format", "json", "--output", str(output_path)])
            self.assertEqual(status, 0)
            data = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(len(data), 2)
            self.assertTrue(all(item["encoding"] == "url" for item in data))

    def test_cli_refuses_to_overwrite_an_existing_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "keep.json"
            output_path.write_text("keep", encoding="utf-8")
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    main(["--xss", "--format", "json", "--output", str(output_path)])
            self.assertEqual(raised.exception.code, 2)
            self.assertEqual(output_path.read_text(encoding="utf-8"), "keep")


if __name__ == "__main__":
    unittest.main()
