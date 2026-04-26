package redact

import (
	"strings"
	"testing"
)

func TestNormalizeForScanBuildsShadowAndOriginalByteMap(t *testing.T) {
	t.Parallel()

	prompt := "prefix café ѕк-ｔｅｓｔ suffix"

	normalized := normalizeForScan(prompt)

	if !strings.Contains(normalized.shadow, "sk-test") {
		t.Fatalf("normalized shadow missing folded credential prefix")
	}
	shadowStart := strings.Index(normalized.shadow, "sk-test")
	if shadowStart < 0 {
		t.Fatalf("normalized credential span not found")
	}
	originalStart, originalEnd, ok := normalized.originalRange(shadowStart, shadowStart+len("sk-test"))
	if !ok {
		t.Fatalf("original range lookup failed")
	}
	if got := prompt[originalStart:originalEnd]; got != "ѕк-ｔｅｓｔ" {
		t.Fatalf("original range = %q, want obfuscated literal", got)
	}
	if got := prompt[:originalStart]; got != "prefix café " {
		t.Fatalf("prefix = %q, want preserved unicode prefix", got)
	}
	if got := prompt[originalEnd:]; got != " suffix" {
		t.Fatalf("suffix = %q, want preserved suffix", got)
	}
}

func TestNormalizeForScanMapsNFKCExpansionsToOriginalRune(t *testing.T) {
	t.Parallel()

	prompt := "before ﬃ after"

	normalized := normalizeForScan(prompt)

	shadowStart := strings.Index(normalized.shadow, "ffi")
	if shadowStart < 0 {
		t.Fatalf("normalized expansion not found")
	}
	originalStart, originalEnd, ok := normalized.originalRange(shadowStart, shadowStart+len("ffi"))
	if !ok {
		t.Fatalf("original range lookup failed")
	}
	if got := prompt[originalStart:originalEnd]; got != "ﬃ" {
		t.Fatalf("expanded range = %q, want original ligature", got)
	}
}

func TestNormalizeForScanRejectsInvalidRanges(t *testing.T) {
	t.Parallel()

	normalized := normalizeForScan("abc")

	cases := [][2]int{
		{-1, 1},
		{0, 0},
		{2, 1},
		{0, len(normalized.shadow) + 1},
	}
	for _, tc := range cases {
		if _, _, ok := normalized.originalRange(tc[0], tc[1]); ok {
			t.Fatalf("range %v unexpectedly mapped", tc)
		}
	}
}
