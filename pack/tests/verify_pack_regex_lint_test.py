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
        cls.shipped_policy = verify_pack.load_yaml(
            verify_pack.PACK_DIR / "policies" / "openclaw-safety.yaml"
        )
        cls.shipped_patterns = cls.shipped_policy["prompt_pii_redact"]["patterns"]

    def pack_with_prompt_policy_registered(self) -> dict:
        return {
            "overlays": {"policy": [{"path": "policies/openclaw-safety.yaml"}]},
            "resources": {"schemas": [{"id": "cordclaw/PromptPIIRedact"}]},
        }

    def prompt_policy_with(self, extra_pattern: dict | None = None) -> dict:
        patterns = list(self.shipped_patterns)
        if extra_pattern is not None:
            patterns.insert(0, extra_pattern)
        return {
            "prompt_pii_redact": {
                "action": "CONSTRAIN",
                "reason": "redact provider-side credential leakage in agent prompts",
                "include_email": False,
                "patterns": patterns,
            }
        }

    def validate_policy(self, policy: dict) -> None:
        old_load_yaml = verify_pack.load_yaml
        old_expect_file = verify_pack.expect_file
        try:
            verify_pack.load_yaml = lambda _path: policy
            verify_pack.expect_file = lambda _path: None
            verify_pack.validate_prompt_pii_policy(self.pack_with_prompt_policy_registered())
        finally:
            verify_pack.load_yaml = old_load_yaml
            verify_pack.expect_file = old_expect_file

    def assertPatternRejected(self, name: str, regex: str, reason_fragment: str) -> None:
        stderr = io.StringIO()
        pattern = {
            "name": name,
            "regex": regex,
            "placeholder": f"<REDACTED-{name}>",
        }
        with contextlib.redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as raised:
                self.validate_policy(self.prompt_policy_with(pattern))
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
        self.validate_policy(self.shipped_policy)


if __name__ == "__main__":
    unittest.main()
