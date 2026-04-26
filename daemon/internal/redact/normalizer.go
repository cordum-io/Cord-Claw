package redact

import (
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

type originalSpan struct {
	start int
	end   int
}

type normalizedPrompt struct {
	shadow string
	spans  []originalSpan
}

func normalizeForScan(prompt string) normalizedPrompt {
	var builder strings.Builder
	builder.Grow(len(prompt))
	spans := make([]originalSpan, 0, len(prompt))

	for start := 0; start < len(prompt); {
		r, size := utf8.DecodeRuneInString(prompt[start:])
		if size == 0 {
			break
		}
		end := start + size
		segment := norm.NFKC.String(string(r))
		for _, normalizedRune := range segment {
			folded := foldCredentialConfusable(normalizedRune)
			emitted := string(folded)
			builder.WriteString(emitted)
			for i := 0; i < len(emitted); i++ {
				spans = append(spans, originalSpan{start: start, end: end})
			}
		}
		start = end
	}

	return normalizedPrompt{shadow: builder.String(), spans: spans}
}

func (n normalizedPrompt) originalRange(shadowStart, shadowEnd int) (int, int, bool) {
	if shadowStart < 0 || shadowEnd <= shadowStart || shadowEnd > len(n.spans) {
		return 0, 0, false
	}
	return n.spans[shadowStart].start, n.spans[shadowEnd-1].end, true
}

func foldCredentialConfusable(r rune) rune {
	switch r {
	case 'ѕ': // Cyrillic small letter dze.
		return 's'
	case 'к', 'κ': // Cyrillic small ka, Greek small kappa.
		return 'k'
	case 'а', 'α': // Cyrillic small a, Greek small alpha.
		return 'a'
	case 'в', 'β': // Cyrillic small ve, Greek small beta.
		return 'b'
	case 'г', 'ɡ': // Cyrillic small ghe, Latin script g.
		return 'g'
	case 'н', 'η': // Cyrillic small en, Greek small eta.
		return 'h'
	case 'і', 'ι': // Cyrillic small byelorussian-ukrainian i, Greek small iota.
		return 'i'
	case 'о', 'ο': // Cyrillic small o, Greek small omicron.
		return 'o'
	case 'р', 'ρ': // Cyrillic small er, Greek small rho.
		return 'p'
	case 'σ', 'ς': // Greek small sigma variants.
		return 's'
	case 'х', 'χ': // Cyrillic small ha, Greek small chi.
		return 'x'
	case 'А':
		return 'A'
	case 'К', 'Κ':
		return 'K'
	case 'І':
		return 'I'
	default:
		return r
	}
}
