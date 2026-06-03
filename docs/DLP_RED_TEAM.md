# CordClaw DLP Red-Team Playbook

Task: `task-6f85494c`  
Scope: adversarial review of `daemon/internal/redact` after `task-341c3570`.

## Executive summary

This document is the source of truth for the security test corpus in
`daemon/test/security/dlp_bypass_test.go`. The current DLP scanner is a
deterministic regex scanner over prompt text. It is useful as a fail-closed
guardrail, but it is not a full decoder/canonicalizer. Bypasses that require
Unicode normalization, decoding, or semantic reconstruction are documented as
known limitations and cross-referenced to hardening tasks.

Final review counts:

| Metric | Count |
| --- | ---: |
| Technique rows | 32 |
| Expected catches | 8 |
| Caught expected rows | 8 |
| Documented limitations | 24 |
| Unexpected bypasses | 0 |
| Catch-eligible false-negative rate | 0.0% |
| Benign corpus false-positive rate | 0/1000 = 0.0% |
| Senior-review P0 findings | 0 |
| Senior-review P1 findings | 1 |
| Senior-review P2 findings | 1 |

Verdict for this review: **APPROVE WITH DOCUMENTED PRE-GA MITIGATIONS**. The
security suite reports zero unexpected bypasses for `CATCH` rows and zero
unresolved P0 senior-review findings. The scanner remains regex-only; the
documented limitation classes must be closed or explicitly scoped before GA
claims about Unicode, encoded, or obfuscated secret coverage.

## Scope

The review covers the built-in patterns from `daemon/internal/redact/patterns.go`
plus the optional email pattern:

| Pattern | Regex shape | Review focus |
| --- | --- | --- |
| `OPENAI_KEY` | `\bsk-[A-Za-z0-9_-]{10,}\b` | Word-boundary and prefix obfuscation bypasses |
| `SLACK_BOT` | `\bxoxb-[A-Za-z0-9-]{20,}\b` | Wrapped/encoded token forms |
| `AWS_ACCESS_KEY` | `\bAKIA[0-9A-Z]{16}\b` | Exact fixed-length access key form |
| `GITHUB_PAT` | `\bgh[psu]_[A-Za-z0-9]{36,}\b` | Prefix and base64/ROT13 bypasses |
| `AWS_SECRET` | `\b[A-Za-z0-9+/]{40}\b` | Over-broad 40-char form, gated by context |
| `EMAIL` | `\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b` | Optional PII pattern, dotless-host negative case |

## Threat model

Assume an adversary has read `dlp.go` and `patterns.go`. The adversary knows
the scanner:

- compiles raw Go regexes once in `NewScanner`;
- sorts patterns by name;
- scans the prompt string as received, without Unicode normalization, decoding,
  token reassembly, or HTML/entity expansion;
- redacts selected non-overlapping byte spans in reverse order;
- only reports `AWS_SECRET` when `aws_secret_access_key` or
  `aws secret access key` appears within 96 bytes before the match.

Attacker goal: place credential-shaped material in an agent prompt while causing
`Scanner.Scan` to return `ALLOW` or leave the sensitive material unredacted.

Defender goal for this task: make expected behavior explicit. A row is either:

- `CATCH`: the current scanner must detect and constrain/deny it; a miss is a
  regression and a P0 for this review.
- `DOCUMENTED_LIMITATION`: the current scanner is not expected to catch it yet,
  but this document names the mitigation task that must close the class before
  GA security positioning.

Synthetic examples below are deliberately fake (`TEST`, `DONOTLEAK`,
`EXAMPLE`) and must never be replaced with real secrets.

## Technique catalog

| ID | Class | Sanitized example | Expected | Mitigation |
| --- | --- | --- | --- | --- |
| A1-unicode-cyrillic-s | Unicode homoglyph | `ѕk-TESTKEY-DONOTLEAK-1234567890` (Cyrillic small letter dze at prefix) | `DOCUMENTED_LIMITATION` | `task-4c48bc3a` |
| A2-unicode-fullwidth-prefix | Unicode homoglyph | `ｓｋ-TESTKEY-DONOTLEAK-1234567890` | `DOCUMENTED_LIMITATION` | `task-4c48bc3a` |
| A3-unicode-zero-width-joiner | Unicode homoglyph | `s‍k-TESTKEY-DONOTLEAK-1234567890` | `DOCUMENTED_LIMITATION` | `task-4c48bc3a` |
| A4-unicode-rtl-mark | Unicode homoglyph | `s‮k-TESTKEY-DONOTLEAK-1234567890` | `DOCUMENTED_LIMITATION` | `task-4c48bc3a` |
| B1-base64-standard | Base64 | `base64("sk-TESTKEY-DONOTLEAK-1234567890")` | `DOCUMENTED_LIMITATION` | `task-ff10cb69` |
| B2-base64-url-safe | Base64 | `base64url("sk-TESTKEY-DONOTLEAK-1234567890")` | `DOCUMENTED_LIMITATION` | `task-ff10cb69` |
| B3-base64-unpadded | Base64 | `base64-raw("sk-TESTKEY-DONOTLEAK-1234567890")` | `DOCUMENTED_LIMITATION` | `task-ff10cb69` |
| B4-base64-gzip-wrapped | Base64 | `base64(gzip("sk-TESTKEY-DONOTLEAK-1234567890"))` | `DOCUMENTED_LIMITATION` | `task-ff10cb69` |
| C1-rot13-openai-prefix | ROT13 | `fx-GRFGXRL-QBABGYRNX-1234567890` | `DOCUMENTED_LIMITATION` | `task-011f0cf1` |
| C2-rot13-slack-prefix | ROT13 | `kbko-GRFG-QBABGYRNX-123456789012345` | `DOCUMENTED_LIMITATION` | `task-011f0cf1` |
| C3-rot13-github-prefix | ROT13 | `tuc_GRFGQBABGYRNX123456789012345678901234567890` | `DOCUMENTED_LIMITATION` | `task-011f0cf1` |
| C4-rot13-aws-context | ROT13 | `njf_frperg_npprff_xrl=<rot13 40-char value>` | `DOCUMENTED_LIMITATION` | `task-011f0cf1` |
| D1-split-space-prefix | Split across tokens | `s k-TESTKEY-DONOTLEAK-1234567890` | `DOCUMENTED_LIMITATION` | `task-011f0cf1` |
| D2-split-json-array | Split across tokens | `["s", "k-TESTKEY-DONOTLEAK-1234567890"]` | `DOCUMENTED_LIMITATION` | `task-011f0cf1` |
| D3-split-line-break | Split across tokens | `s\nk-TESTKEY-DONOTLEAK-1234567890` | `DOCUMENTED_LIMITATION` | `task-011f0cf1` |
| D4-split-template-concat | Split across tokens | `"s" + "k-TESTKEY-DONOTLEAK-1234567890"` | `DOCUMENTED_LIMITATION` | `task-011f0cf1` |
| E1-whitespace-prefix | Whitespace padding | `s k - TESTKEY - DONOTLEAK - 1234567890` | `DOCUMENTED_LIMITATION` | `task-011f0cf1` |
| E2-whitespace-tabs | Whitespace padding | `s\tk-\tTESTKEY-DONOTLEAK-1234567890` | `DOCUMENTED_LIMITATION` | `task-011f0cf1` |
| E3-whitespace-nbsp | Whitespace padding | `s k-TESTKEY-DONOTLEAK-1234567890` | `DOCUMENTED_LIMITATION` | `task-011f0cf1` |
| E4-whitespace-thin-space | Whitespace padding | `s k-TESTKEY-DONOTLEAK-1234567890` | `DOCUMENTED_LIMITATION` | `task-011f0cf1` |
| F1-html-decimal-entities | HTML entity encoding | `&#115;&#107;&#45;TESTKEY-DONOTLEAK-1234567890` | `DOCUMENTED_LIMITATION` | `task-011f0cf1` |
| F2-html-hex-entities | HTML entity encoding | `&#x73;&#x6b;&#x2d;TESTKEY-DONOTLEAK-1234567890` | `DOCUMENTED_LIMITATION` | `task-011f0cf1` |
| F3-html-mixed-entities | HTML entity encoding | `s&#107;&#45;TESTKEY-DONOTLEAK-1234567890` | `DOCUMENTED_LIMITATION` | `task-011f0cf1` |
| F4-html-named-separator | HTML entity encoding | `sk&hyphen;TESTKEY-DONOTLEAK-1234567890` | `DOCUMENTED_LIMITATION` | `task-011f0cf1` |
| G1-json-escaped-openai-post-decode | JSON string escapes | JSON `"\u0073\u006b\u002d..."` after decode becomes `sk-...` | `CATCH` | current scanner |
| G2-json-escaped-slack-post-decode | JSON string escapes | JSON `"\u0078\u006f\u0078\u0062\u002d..."` after decode becomes `xoxb-...` | `CATCH` | current scanner |
| G3-json-escaped-github-post-decode | JSON string escapes | JSON `"\u0067\u0068\u0070\u005f..."` after decode becomes `ghp_...` | `CATCH` | current scanner |
| G4-json-escaped-aws-post-decode | JSON string escapes | JSON `"\u0041\u004b\u0049\u0041..."` after decode becomes `AKIA...` | `CATCH` | current scanner |
| H1-backtick-inline-openai | Backtick/code fence wrapping | `` `sk-TESTKEY-DONOTLEAK-1234567890` `` | `CATCH` | current scanner |
| H2-backtick-fence-slack | Backtick/code fence wrapping | fenced code block containing `xoxb-...` | `CATCH` | current scanner |
| H3-backtick-quote-github | Backtick/code fence wrapping | blockquote/code containing `ghp_...` | `CATCH` | current scanner |
| H4-backtick-fence-aws-access | Backtick/code fence wrapping | fenced code block containing `AKIA...` | `CATCH` | current scanner |

## Per-pattern targeted checks

These are not counted in the 32-row bypass catalog, but they prevent regressions
in security-critical edges.

| ID | Pattern | Case | Expected | Reason |
| --- | --- | --- | --- | --- |
| T1-aws-secret-without-context | `AWS_SECRET` | 40-character base64-like value with no `aws_secret_access_key` nearby | `ALLOW` | The context gate prevents broad false positives. |
| T2-aws-secret-with-context | `AWS_SECRET` | `aws_secret_access_key=` followed by a 40-character value | `CATCH` | The same value must be caught when context is present. |
| T3-email-dotless-host | `EMAIL` | `user@host` | `ALLOW` | Dotless host is intentionally not an email match. |
| T4-email-valid-tld | `EMAIL` | `user@example.test` | `CATCH` | Optional PII pattern must still redact normal email addresses. |

## Follow-up mitigation map

| Task | Coverage |
| --- | --- |
| `task-4c48bc3a` | Unicode normalization and homoglyph-resistant prompt scanning. |
| `task-ff10cb69` | Decode base64-encoded secrets before prompt scanning. |
| `task-011f0cf1` | Canonicalization before regex tagging, covering ROT13, split-token, whitespace, and entity-decoding classes. |
| `task-2eff8a3c` | Pack lint and regex-quality checks for broad or unsafe redaction patterns, including AWS-secret FP risk. |
| `task-0d9d7ee4` | CI scan to ensure benign DLP corpora never contain accidental real secrets. |

## Ongoing testing procedure

1. Add each newly discovered bypass to the catalog before writing code.
2. Classify it as `CATCH` or `DOCUMENTED_LIMITATION`.
3. If it is `DOCUMENTED_LIMITATION`, link an existing hardening task or create one
   before merging.
4. Add/extend a row in `daemon/test/security/dlp_bypass_test.go`.
5. Run the dedicated security suite:

   ```bash
   cd daemon
   go test -tags=security -count=3 -timeout 90s ./test/security/...
   ```

6. Keep security test examples synthetic. Do not paste production credentials,
   customer data, or leaked examples into this repository.
7. Release notes for DLP changes must state: rows added, expected catches,
   documented limitations, unexpected bypasses, false-positive rate, and any
   new P0/P1/P2 senior-review findings.

## Senior Code Review

Review date: 2026-04-26. Files traced line by line:
`daemon/internal/redact/dlp.go`, `patterns.go`, and `policy.go`.

| ID | Severity | Area | Finding | Evidence | Remediation / disposition |
| --- | --- | --- | --- | --- | --- |
| SCR-1 | PASS | Concurrency | `Scanner` is immutable after construction; concurrent `Scan` calls allocate local slices/maps and do not mutate shared state. | `Scanner` fields are only `patterns []Pattern` and `policyAction string` (`dlp.go:37-40`); `Scan` locals at `dlp.go:86-107`; Go `regexp.Regexp` is safe for concurrent matching after compile. | No code change required. Add race tests only if future scanner state/counters are introduced. |
| SCR-2 | PASS | Regex DoS | Built-in patterns do not contain nested quantifiers or backtracking-prone alternation; Go's RE2-style engine avoids catastrophic backtracking. | `patterns.go:3-31`; `AWS_SECRET` uses bounded `{40}`; other credential suffixes are linear character classes. `TestDLPRegexDoS` exercises 100KB near-misses. | Keep `task-2eff8a3c` regex-lint follow-up for pack-supplied custom patterns. |
| SCR-3 | PASS | Input mutation | ALLOW decisions do not return a modified prompt; CONSTRAIN returns a new redacted string and leaves the original prompt value untouched. | ALLOW returns at `dlp.go:82-89`; redaction starts from `redacted := prompt` and reverse-splices into a new string at `dlp.go:96-110`. | No code change required. |
| SCR-4 | PASS | Nil/empty handling | Nil scanner, `ActionAllow`, and empty pattern sets fail open with `ALLOW`; oversize prompt fails closed with `DENY`. Empty prompt has no candidates and returns `ALLOW`. | `dlp.go:78-90`; `MaxPromptBytes` at `dlp.go:15`. | No P0. Fail-open for nil scanner is acceptable only because server construction must fail closed on scanner creation errors. |
| SCR-5 | P-INFO | Placeholder collision | Prompt text can already contain strings such as `<REDACTED-OPENAI_KEY>`. The scanner will not double-replace them because they are not regex matches and replacements walk only selected match spans. | Replacement loop `dlp.go:101-107`; candidate spans come only from regex matches at `dlp.go:116-123`. | Treat placeholder strings as reserved tokens in downstream display/audit UX; no task blocker. |
| SCR-6 | PASS | Deterministic ordering | Match resolution is deterministic: patterns are sorted by `Name`, candidates are sorted by start byte, longer end byte first on ties, then `Name`, and `nonOverlapping` keeps the first non-overlapping match. | `NewScanner` sort at `dlp.go:71-73`; candidate sort at `dlp.go:126-134`; overlap filter at `dlp.go:138-149`. | No code change required. Keep this rule documented because new patterns can change which placeholder wins on overlap. |
| SCR-7 | P2 | Panic safety | `Scan` has no `defer`/`recover`. The current code has no obvious panic path for valid regex locations, but a future custom matcher/span mapper could expose prompt text in a panic stack if not contained. | No recover wrapper in `dlp.go:78-110`; slicing uses regex-provided byte spans at `dlp.go:107`. | Add a future hardening task if scanner complexity grows: recover internally, return `DENY` with prompt-free reason, and never log prompt text. Not a current P0. |
| SCR-8 | PASS | AWS secret context gate | The 96-byte lookback cannot slice below zero; context comparison lowercases a bounded substring and checks only fixed labels. | `hasAWSSecretContext` at `dlp.go:151-158`; low bound guard at `dlp.go:152-155`. | No code change required. Keep targeted tests T1/T2. |
| SCR-9 | P1 | AWS secret broadness | `AWS_SECRET` is intentionally broad: any 40-character base64-like word can be a candidate. The context gate prevents many false positives but this remains a risky regex for custom contexts. | `patterns.go:26-28`; gate at `dlp.go:120-121`. | Track in `task-2eff8a3c` (regex lint / broad-pattern review). Ship this review with documented mitigation. |
| SCR-10 | PASS | Policy loading | Policy file parsing trims names/regexes, requires action, requires at least one pattern, and compiles via `NewScanner`; no prompt text is read or logged here. | `policy.go:25-76`; pattern validation at `policy.go:52-68`. | No code change required. |

P0 findings: **0**. P1 findings: **1** (`SCR-9`, mitigated by
`task-2eff8a3c`). P2 findings: **1** (`SCR-7`, future hardening only). The
review found no race, regex-DOS, or unintended prompt-mutation blocker in the
current implementation.

## CVE and dependency review

Review date: 2026-04-26 from `Cord-Claw/daemon/`.

| Check | Result |
| --- | --- |
| Go toolchain | `go version go1.25.9 windows/amd64` |
| `go.mod` directive | `go 1.25.9` (meets Go 1.24+ requirement) |
| Module count | 55 modules from `go list -m all` |
| DLP-related third-party libraries | None matched `presidio|secret|gitleaks|dlp|scanner` |
| DLP implementation dependency posture | Scanner uses Go stdlib `regexp`, `sort`, and `strings`; policy YAML parsing uses existing `gopkg.in/yaml.v3` config dependency. No Presidio/Gitleaks/secret-scanner runtime dependency to pin. |
| govulncheck version | `govulncheck@v1.1.4`, vulnerability DB updated `2026-04-21 18:59:51 +0000 UTC` |
| govulncheck result | `No vulnerabilities found.` for `govulncheck ./...` |

No CVEs were flagged, so there are no fix-available/no-fix classifications in
this PR. Because the DLP scanner has no third-party DLP library dependency,
there is no transitive DLP-library CVE exposure and no DLP-library version pin
needed beyond the Go toolchain and existing module lockfiles.

## Mitigations Required Before GA

The current regex-only scanner should not be marketed as complete DLP until the
documented limitation classes above are closed or explicitly scoped out in the
product security documentation. At minimum, complete `task-4c48bc3a`,
`task-ff10cb69`, and `task-011f0cf1` before claiming Unicode/encoded/obfuscated
secret coverage.
