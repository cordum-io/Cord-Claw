package redact

import (
	"bufio"
	"os"
	"path/filepath"
	"testing"
)

func TestBenignPromptCorpusFalsePositiveRate(t *testing.T) {
	t.Parallel()

	scanner, err := NewScanner(BuiltInPatterns(), ActionConstrain)
	if err != nil {
		t.Fatalf("new scanner: %v", err)
	}

	files, err := filepath.Glob(filepath.Join("testdata", "benign-prompts", "*.txt"))
	if err != nil {
		t.Fatalf("glob corpus: %v", err)
	}
	if len(files) == 0 {
		t.Fatalf("expected benign corpus files")
	}

	total := 0
	falsePositives := 0
	for _, file := range files {
		fh, err := os.Open(file)
		if err != nil {
			t.Fatalf("open corpus file %s: %v", file, err)
		}
		scannerLines := bufio.NewScanner(fh)
		for scannerLines.Scan() {
			total++
			decision, _ := scanner.Scan(scannerLines.Text())
			if decision.Action != ActionAllow {
				falsePositives++
			}
		}
		if err := scannerLines.Err(); err != nil {
			_ = fh.Close()
			t.Fatalf("scan corpus file %s: %v", file, err)
		}
		if err := fh.Close(); err != nil {
			t.Fatalf("close corpus file %s: %v", file, err)
		}
	}
	if total != 1000 {
		t.Fatalf("corpus size = %d, want 1000", total)
	}
	t.Logf("false positives = %d/%d", falsePositives, total)
	if falsePositives > 5 {
		t.Fatalf("false positives = %d/%d, want <=5", falsePositives, total)
	}
}
