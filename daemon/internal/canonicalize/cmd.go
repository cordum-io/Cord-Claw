package canonicalize

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"
)

const genericBase64MinLen = 16

type Operation struct {
	Kind   string `json:"kind"`
	Input  string `json:"input,omitempty"`
	Output string `json:"output,omitempty"`
	Reason string `json:"reason,omitempty"`
}

type Result struct {
	Original   string      `json:"original"`
	Canonical  string      `json:"canonical"`
	Operations []Operation `json:"operations,omitempty"`
}

type Option func(*commandOptions)

type commandOptions struct {
	env             map[string]string
	pathRoot        string
	maxSymlinkHops  int
	genericMinBytes int
}

func WithEnv(env map[string]string) Option {
	return func(opts *commandOptions) {
		opts.env = make(map[string]string, len(env))
		for key, value := range env {
			opts.env[key] = value
		}
	}
}

func WithPathRoot(root string) Option {
	return func(opts *commandOptions) {
		opts.pathRoot = strings.TrimSpace(root)
	}
}

func DecodeBase64Blobs(command string, opts ...Option) Result {
	options := newCommandOptions(opts...)
	result := Result{Original: command, Canonical: command}
	if !hasBase64Signals(command, options.genericMinBytes) {
		return result
	}
	seen := map[string]struct{}{}

	for _, match := range base64PipelinePattern.FindAllStringSubmatch(command, -1) {
		blob := firstNonEmpty(match[1:]...)
		decoded, ok := decodePrintableBase64(blob)
		if !ok {
			continue
		}
		key := "pipeline\x00" + blob + "\x00" + decoded
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result.Canonical = appendCanonical(result.Canonical, "base64_pipeline", decoded)
		result.Operations = append(result.Operations, Operation{
			Kind:   "base64_pipeline",
			Input:  blob,
			Output: decoded,
		})
	}

	for _, match := range genericBase64Pattern.FindAllStringSubmatch(command, -1) {
		blob := match[1]
		if len(blob) < options.genericMinBytes {
			continue
		}
		decoded, ok := decodePrintableBase64(blob)
		if !ok {
			continue
		}
		key := "blob\x00" + blob + "\x00" + decoded
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result.Canonical = appendCanonical(result.Canonical, "base64_blob", decoded)
		result.Operations = append(result.Operations, Operation{
			Kind:   "base64_blob",
			Input:  blob,
			Output: decoded,
		})
	}

	return result
}

func ExpandShellVars(command string, opts ...Option) Result {
	options := newCommandOptions(opts...)
	result := Result{Original: command, Canonical: command}
	if !strings.Contains(command, "$") && !strings.Contains(command, "`") {
		return result
	}
	vars := make(map[string]string, len(options.env))
	for key, value := range options.env {
		vars[key] = value
	}
	for key, value := range commandLocalAssignments(command) {
		vars[key] = value
	}

	expanded, operations := expandVariables(command, vars)
	if len(operations) > 0 && expanded != command {
		result.Canonical = appendCanonical(result.Canonical, "shell_var", expanded)
		result.Operations = append(result.Operations, operations...)
	}

	for _, match := range commandSubstitutionPattern.FindAllStringSubmatch(command, -1) {
		body := strings.TrimSpace(match[1])
		if body == "" {
			continue
		}
		result.Canonical = appendCanonical(result.Canonical, "command_substitution", body)
		result.Operations = append(result.Operations, Operation{
			Kind:   "command_substitution",
			Input:  match[0],
			Output: body,
		})
	}
	for _, match := range backtickSubstitutionPattern.FindAllStringSubmatch(command, -1) {
		body := strings.TrimSpace(match[1])
		if body == "" {
			continue
		}
		result.Canonical = appendCanonical(result.Canonical, "command_substitution", body)
		result.Operations = append(result.Operations, Operation{
			Kind:   "command_substitution",
			Input:  match[0],
			Output: body,
		})
	}

	return result
}

func ResolveSymlinks(command string, opts ...Option) Result {
	options := newCommandOptions(opts...)
	result := Result{Original: command, Canonical: command}
	if !hasPathSignals(command) {
		return result
	}
	root := cleanPathRoot(options.pathRoot)

	for _, token := range commandPathTokens(command) {
		candidate, ok := pathCandidate(token, root)
		if !ok {
			continue
		}
		if isDeniedPath(candidate) || isDeniedPath(token) {
			result.Operations = append(result.Operations, Operation{
				Kind:   "symlink_skipped",
				Input:  token,
				Reason: "denied_path",
			})
			continue
		}
		if root != "" && !pathWithinRoot(candidate, root) {
			result.Operations = append(result.Operations, Operation{
				Kind:   "symlink_skipped",
				Input:  token,
				Reason: "outside_path_root",
			})
			continue
		}
		resolved, reason, ok := resolveSymlink(candidate, root, options.maxSymlinkHops)
		if !ok {
			if reason != "" {
				result.Operations = append(result.Operations, Operation{
					Kind:   "symlink_skipped",
					Input:  token,
					Reason: reason,
				})
			}
			continue
		}
		if sameCleanPath(candidate, resolved) {
			continue
		}
		result.Canonical = appendCanonical(result.Canonical, "symlink_resolved", token+" -> "+resolved)
		result.Operations = append(result.Operations, Operation{
			Kind:   "symlink_resolved",
			Input:  token,
			Output: resolved,
		})
	}

	return result
}

func Normalize(command string, opts ...Option) Result {
	options := newCommandOptions(opts...)

	expanded := Result{Original: command, Canonical: command}
	if strings.Contains(command, "$") || strings.Contains(command, "`") {
		expanded = ExpandShellVars(command, opts...)
	}

	decoded := Result{Original: expanded.Canonical, Canonical: expanded.Canonical}
	if hasBase64Signals(expanded.Canonical, options.genericMinBytes) {
		decoded = DecodeBase64Blobs(expanded.Canonical, opts...)
	}

	resolved := Result{Original: decoded.Canonical, Canonical: decoded.Canonical}
	if hasPathSignals(decoded.Canonical) {
		resolved = ResolveSymlinks(decoded.Canonical, opts...)
	}

	operations := make([]Operation, 0, len(expanded.Operations)+len(decoded.Operations)+len(resolved.Operations))
	operations = append(operations, expanded.Operations...)
	operations = append(operations, decoded.Operations...)
	operations = append(operations, resolved.Operations...)

	return Result{
		Original:   command,
		Canonical:  resolved.Canonical,
		Operations: operations,
	}
}

var (
	base64PipelinePattern = regexp.MustCompile(`(?is)\b(?:echo|printf)\s+(?:-n\s+)?(?:"([^"]+)"|'([^']+)'|([A-Za-z0-9+/_=-]{4,}))\s*\|\s*base64\s+(?:-[A-Za-z]*d[A-Za-z]*|--decode)\b`)
	genericBase64Pattern  = regexp.MustCompile(`(?:^|[^A-Za-z0-9+/_=-])([A-Za-z0-9+/_-]{16,}={0,2})(?:$|[^A-Za-z0-9+/_=-])`)
	localAssignPattern    = regexp.MustCompile(`(?:^|[;&]\s*)([A-Za-z_][A-Za-z0-9_]*)=("[^"]*"|'[^']*'|[^\s;|&]+)`)
	shellVarPattern       = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)`)

	commandSubstitutionPattern  = regexp.MustCompile(`\$\(([^()]*)\)`)
	backtickSubstitutionPattern = regexp.MustCompile("`([^`]*)`")
)

func newCommandOptions(opts ...Option) commandOptions {
	options := commandOptions{
		env:             map[string]string{},
		maxSymlinkHops:  32,
		genericMinBytes: genericBase64MinLen,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(&options)
		}
	}
	if options.maxSymlinkHops <= 0 {
		options.maxSymlinkHops = 32
	}
	if options.genericMinBytes < genericBase64MinLen {
		options.genericMinBytes = genericBase64MinLen
	}
	return options
}

func commandLocalAssignments(command string) map[string]string {
	assignments := map[string]string{}
	for _, match := range localAssignPattern.FindAllStringSubmatch(command, -1) {
		assignments[match[1]] = unquoteShellToken(match[2])
	}
	return assignments
}

func expandVariables(command string, vars map[string]string) (string, []Operation) {
	var b strings.Builder
	ops := []Operation{}
	seenOps := map[string]struct{}{}
	last := 0

	for _, loc := range shellVarPattern.FindAllStringSubmatchIndex(command, -1) {
		name := ""
		if loc[2] >= 0 {
			name = command[loc[2]:loc[3]]
		} else if loc[4] >= 0 {
			name = command[loc[4]:loc[5]]
		}
		value, ok := vars[name]
		if !ok {
			continue
		}
		b.WriteString(command[last:loc[0]])
		b.WriteString(value)
		last = loc[1]

		if _, exists := seenOps[name]; !exists {
			seenOps[name] = struct{}{}
			ops = append(ops, Operation{Kind: "shell_var", Input: name, Output: value})
		}
	}
	if len(ops) == 0 {
		return command, nil
	}
	b.WriteString(command[last:])
	return b.String(), ops
}

func decodePrintableBase64(blob string) (string, bool) {
	candidate := strings.TrimSpace(blob)
	candidate = strings.Trim(candidate, `"'`)
	if candidate == "" {
		return "", false
	}
	decoders := []struct {
		name     string
		encoding *base64.Encoding
		raw      bool
	}{
		{encoding: base64.StdEncoding},
		{encoding: base64.URLEncoding},
		{encoding: base64.RawStdEncoding, raw: true},
		{encoding: base64.RawURLEncoding, raw: true},
	}
	for _, decoder := range decoders {
		input := candidate
		if !decoder.raw {
			input = padBase64(input)
		}
		decoded, err := decoder.encoding.DecodeString(input)
		if err != nil {
			continue
		}
		text := string(decoded)
		if text == "" || text == candidate || !isPrintableText(text) {
			continue
		}
		return text, true
	}
	return "", false
}

func padBase64(input string) string {
	if remainder := len(input) % 4; remainder != 0 {
		return input + strings.Repeat("=", 4-remainder)
	}
	return input
}

func isPrintableText(text string) bool {
	if !utf8.ValidString(text) {
		return false
	}
	printable := 0
	for _, r := range text {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			printable++
		case r >= 0x20 && r != 0x7f:
			printable++
		default:
			return false
		}
	}
	return printable > 0
}

func commandPathTokens(command string) []string {
	fields := strings.Fields(command)
	tokens := make([]string, 0, len(fields))
	for _, field := range fields {
		token := strings.Trim(field, `"'()[]{}<>,;|&`)
		token = strings.TrimSpace(token)
		if token == "" || !isPathLike(token) {
			continue
		}
		tokens = append(tokens, token)
	}
	return tokens
}

func isPathLike(token string) bool {
	if strings.HasPrefix(token, "/") || strings.HasPrefix(token, `\`) || strings.HasPrefix(token, "./") || strings.HasPrefix(token, "../") {
		return true
	}
	if filepath.IsAbs(token) {
		return true
	}
	return strings.Contains(token, "/") || strings.Contains(token, `\`)
}

func hasBase64Signals(command string, minBytes int) bool {
	if strings.Contains(strings.ToLower(command), "base64") {
		return true
	}
	for _, field := range strings.Fields(command) {
		token := strings.Trim(field, `"'()[]{}<>,;|&`)
		if len(token) >= minBytes && isBase64Candidate(token) {
			return true
		}
	}
	return false
}

func isBase64Candidate(token string) bool {
	for _, r := range token {
		switch {
		case r >= 'A' && r <= 'Z':
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '+' || r == '/' || r == '_' || r == '-' || r == '=':
		default:
			return false
		}
	}
	return true
}

func hasPathSignals(command string) bool {
	return strings.Contains(command, "/") || strings.Contains(command, `\`) || strings.Contains(command, "./") || strings.Contains(command, "../")
}

func pathCandidate(token string, root string) (string, bool) {
	if isDeniedPath(token) {
		return filepath.Clean(token), true
	}
	if filepath.IsAbs(token) {
		return filepath.Clean(token), true
	}
	if root == "" {
		return "", false
	}
	return filepath.Join(root, filepath.FromSlash(token)), true
}

func resolveSymlink(candidate string, root string, maxHops int) (string, string, bool) {
	if maxHops <= 0 {
		return "", "max_hops", false
	}
	resolved, followed, reason := resolvePathBounded(filepath.Clean(candidate), maxHops)
	if reason != "" {
		return "", reason, false
	}
	if !followed {
		return "", "", false
	}
	if isDeniedPath(resolved) {
		return "", "denied_path", false
	}
	if root != "" && !pathWithinRoot(resolved, root) {
		return "", "outside_path_root", false
	}
	if !sameMount(candidate, resolved) {
		return "", "cross_mount", false
	}
	return filepath.Clean(resolved), "", true
}

func resolvePathBounded(candidate string, maxHops int) (string, bool, string) {
	base, parts := splitCleanPath(candidate)
	current := base
	followed := false
	hops := 0
	seen := map[string]struct{}{}

	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}
		next := filepath.Join(current, part)
		for {
			info, err := os.Lstat(next)
			if err != nil {
				return "", followed, ""
			}
			if info.Mode()&os.ModeSymlink == 0 {
				break
			}
			hops++
			if hops > maxHops {
				return "", true, "max_hops"
			}
			target, err := os.Readlink(next)
			if err != nil {
				return "", true, "readlink_failed"
			}
			if !filepath.IsAbs(target) {
				target = filepath.Join(filepath.Dir(next), target)
			}
			target = filepath.Clean(target)
			if isDeniedPath(target) {
				return "", true, "denied_path"
			}
			if _, ok := seen[target]; ok {
				return "", true, "cycle"
			}
			seen[target] = struct{}{}
			next = target
			followed = true
		}
		current = next
	}

	return filepath.Clean(current), followed, ""
}

func splitCleanPath(path string) (string, []string) {
	clean := filepath.Clean(path)
	volume := filepath.VolumeName(clean)
	rest := strings.TrimPrefix(clean, volume)
	separator := string(filepath.Separator)

	base := volume
	if strings.HasPrefix(rest, separator) {
		base += separator
		rest = strings.TrimPrefix(rest, separator)
	}
	if base == "" {
		base = "."
	}
	if rest == "" {
		return base, nil
	}
	return base, strings.Split(rest, separator)
}

func cleanPathRoot(root string) string {
	if strings.TrimSpace(root) == "" {
		return ""
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return filepath.Clean(root)
	}
	return filepath.Clean(abs)
}

func pathWithinRoot(path string, root string) bool {
	if root == "" {
		return true
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		absPath = filepath.Clean(path)
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		absRoot = filepath.Clean(root)
	}
	rel, err := filepath.Rel(absRoot, absPath)
	if err != nil {
		return false
	}
	return rel == "." || (!strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != "..")
}

func isDeniedPath(path string) bool {
	normalized := strings.ToLower(filepath.ToSlash(filepath.Clean(path)))
	for _, denied := range []string{"/proc", "/sys", "/dev"} {
		if normalized == denied || strings.HasPrefix(normalized, denied+"/") {
			return true
		}
	}
	return false
}

func sameCleanPath(left string, right string) bool {
	return filepath.Clean(left) == filepath.Clean(right)
}

func appendCanonical(existing string, kind string, text string) string {
	text = strings.TrimSpace(text)
	if text == "" || strings.Contains(existing, text) {
		return existing
	}
	return existing + "\n[canonical:" + kind + "] " + text
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func unquoteShellToken(token string) string {
	token = strings.TrimSpace(token)
	if len(token) >= 2 {
		if (token[0] == '"' && token[len(token)-1] == '"') || (token[0] == '\'' && token[len(token)-1] == '\'') {
			return token[1 : len(token)-1]
		}
	}
	return token
}
