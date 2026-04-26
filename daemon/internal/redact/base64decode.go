package redact

import (
	"encoding/base64"
	"regexp"
)

const (
	MaxBase64Candidates = 100
	MaxBase64TokenLen   = 2048
	MinBase64TokenLen   = 16
)

var base64TokenRe = regexp.MustCompile(`[A-Za-z0-9+/=_-]{16,1000}[A-Za-z0-9+/=_-]{0,1000}[A-Za-z0-9+/=_-]{0,48}`)

type candidatePos struct {
	Start int
	End   int
}

func extractBase64Candidates(prompt string) []candidatePos {
	positions := make([]candidatePos, 0, MaxBase64Candidates)
	for offset := 0; offset < len(prompt) && len(positions) < MaxBase64Candidates; {
		loc := base64TokenRe.FindStringIndex(prompt[offset:])
		if len(loc) != 2 {
			break
		}

		start := offset + loc[0]
		end := offset + loc[1]
		offset = end

		if end-start < MinBase64TokenLen || end-start > MaxBase64TokenLen {
			continue
		}
		if start > 0 && isBase64TokenByte(prompt[start-1]) {
			continue
		}
		if end < len(prompt) && isBase64TokenByte(prompt[end]) {
			continue
		}
		positions = append(positions, candidatePos{Start: start, End: end})
	}
	return positions
}

func tryDecodeBase64Token(token string) ([]byte, bool) {
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	for _, encoding := range encodings {
		decoded, err := encoding.DecodeString(token)
		if err == nil {
			return decoded, true
		}
	}
	return nil, false
}

func (s *Scanner) base64Candidates(prompt string) []Match {
	if s == nil || len(s.patterns) == 0 {
		return nil
	}

	positions := extractBase64Candidates(prompt)
	matches := make([]Match, 0, len(positions))
	for _, pos := range positions {
		token := prompt[pos.Start:pos.End]
		decoded, ok := tryDecodeBase64Token(token)
		if !ok {
			continue
		}

		decodedNormalized := normalizeForScan(string(decoded))
		for _, pattern := range s.patterns {
			loc := pattern.Compiled.FindStringIndex(decodedNormalized.shadow)
			if len(loc) != 2 {
				continue
			}
			if pattern.Name == "AWS_SECRET" && !hasAWSSecretContext(decodedNormalized.shadow, loc[0]) {
				continue
			}
			matches = append(matches, Match{Name: pattern.Name, Start: pos.Start, End: pos.End, Base64Decoded: true})
			break
		}
	}
	return matches
}

func isBase64TokenByte(b byte) bool {
	return b >= 'A' && b <= 'Z' ||
		b >= 'a' && b <= 'z' ||
		b >= '0' && b <= '9' ||
		b == '+' ||
		b == '/' ||
		b == '=' ||
		b == '_' ||
		b == '-'
}
