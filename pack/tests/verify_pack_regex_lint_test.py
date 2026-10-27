from __future__ import annotations

import contextlib
import importlib.util
import io
from pathlib import Path
import unittest


VERIFY_PACK_PATH = Path(__file__).with_name("verify_pack.py")
SPEC = importlib.util.spec_from_file_location("verify_pack", VERIFY_PACK_PATH)
verify_pack = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(verify_pack)


class PromptRegexLintTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.dlp_path = verify_pack.PACK_DIR / verify_pack.OPENCLAW_DLP_FILE
        cls.shipped_primitive = verify_pack.load_yaml(cls.dlp_path)["prompt_pii_redact"]
        cls.shipped_patterns = cls.shipped_primitive["patterns"]

    def validate_patterns(self, patterns: list) -> None:
        verify_pack.validate_prompt_pii_primitive(
            {**self.shipped_primitive, "patterns": patterns}, self.dlp_path
        )

    def assertPatternRejected(self, name: str, regex: str, reason_fragment: str) -> None:
        stderr = io.StringIO()
        pattern = {
            "name": name,
            "regex": regex,
            "placeholder": f"<REDACTED-{name}>",
        }
        with contextlib.redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as raised:
                self.validate_patterns([pattern, *self.shipped_patterns])
        self.assertEqual(raised.exception.code, 1)
        message = stderr.getvalue()
        self.assertIn(name, message)
        self.assertIn(reason_fragment, message)
        self.assertNotIn("sk-TESTKEY-DONTLEAK", message)

    def test_rejects_obvious_whole_prompt_wildcards(self) -> None:
        for name, regex in (
            ("BROAD_DOT_STAR", ".*"),
            ("BROAD_DOT_PLUS", ".+"),
            ("BROAD_ANCHORED_DOT_STAR", "^.*$"),
            ("BROAD_DOTALL_DOT_STAR", "(?s).*"),
        ):
            with self.subTest(regex=regex):
                self.assertPatternRejected(name, regex, "overly broad")

    def test_rejects_empty_match_patterns(self) -> None:
        for name, regex in (
            ("EMPTY_STAR", "a*"),
            ("EMPTY_OPTIONAL_PREFIX", "(?:sk-)?"),
        ):
            with self.subTest(regex=regex):
                self.assertPatternRejected(name, regex, "matches empty string")

    def test_rejects_nested_quantifiers(self) -> None:
        for name, regex in (
            ("NESTED_PLUS", "(a+)+$"),
            ("NESTED_CLASS", "([A-Za-z]+)*"),
            ("NESTED_ANY", "(.*)+"),
        ):
            with self.subTest(regex=regex):
                self.assertPatternRejected(name, regex, "nested quantifier")

    def test_shipped_prompt_patterns_pass_lint(self) -> None:
        self.validate_patterns(self.shipped_patterns)


if __name__ == "__main__":
    unittest.main()
