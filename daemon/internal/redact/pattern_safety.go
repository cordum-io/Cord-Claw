package redact

import (
	"fmt"
	"regexp"
	"regexp/syntax"
	"strings"
)

func validatePatternSafety(pattern Pattern) error {
	name := strings.TrimSpace(pattern.Name)
	if name == "" {
		name = "<unnamed>"
	}
	regex := strings.TrimSpace(pattern.Regex)
	if regex == "" {
		return fmt.Errorf("redact: pattern %s is unsafe: empty regex", name)
	}

	parsed, err := syntax.Parse(regex, syntax.Perl)
	if err != nil {
		return fmt.Errorf("redact: compile %s: %w", name, err)
	}
	parsed = parsed.Simplify()
	if hasNestedRepeat(parsed) {
		return fmt.Errorf("redact: pattern %s is unsafe: nested quantifier", name)
	}
	if isWholePatternWildcard(parsed) {
		return fmt.Errorf("redact: pattern %s is unsafe: overly broad wildcard", name)
	}

	compiled, err := regexp.Compile(regex)
	if err != nil {
		return fmt.Errorf("redact: compile %s: %w", name, err)
	}
	if compiled.MatchString("") {
		return fmt.Errorf("redact: pattern %s is unsafe: matches empty string", name)
	}
	return nil
}

func hasNestedRepeat(re *syntax.Regexp) bool {
	if re == nil {
		return false
	}
	if isRepeatOp(re.Op) {
		for _, sub := range re.Sub {
			if containsRepeat(sub) {
				return true
			}
		}
	}
	for _, sub := range re.Sub {
		if hasNestedRepeat(sub) {
			return true
		}
	}
	return false
}

func containsRepeat(re *syntax.Regexp) bool {
	if re == nil {
		return false
	}
	if isRepeatOp(re.Op) {
		return true
	}
	for _, sub := range re.Sub {
		if containsRepeat(sub) {
			return true
		}
	}
	return false
}

func isRepeatOp(op syntax.Op) bool {
	switch op {
	case syntax.OpStar, syntax.OpPlus, syntax.OpQuest, syntax.OpRepeat:
		return true
	default:
		return false
	}
}

func isWholePatternWildcard(re *syntax.Regexp) bool {
	body := trimPatternAnchors(re)
	for body != nil && body.Op == syntax.OpCapture && len(body.Sub) == 1 {
		body = body.Sub[0]
	}
	if body == nil || !isRepeatOp(body.Op) || len(body.Sub) != 1 {
		return false
	}
	if body.Op != syntax.OpStar && body.Op != syntax.OpPlus {
		return false
	}
	switch body.Sub[0].Op {
	case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return true
	default:
		return false
	}
}

func trimPatternAnchors(re *syntax.Regexp) *syntax.Regexp {
	if re == nil {
		return nil
	}
	if re.Op != syntax.OpConcat {
		return re
	}
	start := 0
	end := len(re.Sub)
	for start < end && isPatternAnchor(re.Sub[start].Op) {
		start++
	}
	for end > start && isPatternAnchor(re.Sub[end-1].Op) {
		end--
	}
	if end-start != 1 {
		return nil
	}
	return re.Sub[start]
}

func isPatternAnchor(op syntax.Op) bool {
	switch op {
	case syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText, syntax.OpEndText, syntax.OpEmptyMatch:
		return true
	default:
		return false
	}
}
