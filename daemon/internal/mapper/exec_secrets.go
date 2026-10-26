package mapper

import (
	"regexp"
	"slices"
	"strings"
	"unicode"

	"github.com/cordum-io/cordclaw/daemon/internal/canonicalize"
)

// The read tool tags a secret path directly. These tables give an exec
// command that reads one ("cat ~/.ssh/id_rsa", "curl -F f=@.env URL") the
// same secrets tag.

// secretReaders print, copy, archive or send the files their operands name.
var secretReaders = wordSet("cat tac nl less more head tail bat strings od xxd hexdump base64 base32 " +
	"grep egrep fgrep rg sed awk sort cut cp mv ln tar scp rsync nc ncat netcat socat curl wget")

// launchers run a program named later on the line; shells run a -c string.
var launchers = wordSet("sudo doas env nohup nice time timeout command exec xargs find { ! if then else elif do while until")
var shells = wordSet("sh bash dash zsh ksh")

// patternFirst readers take a pattern or script before their files.
var patternFirst = wordSet("grep egrep fgrep rg sed awk")

// valueOptions take a value that is not a file the program reads: scp's
// identity, config and -o options (scp -i KEY uses the key, it does not copy
// it), rsync's remote shell (-e "ssh -i KEY") and filters, tar's excludes.
var valueOptions = map[string]map[string]bool{
	"scp":   wordSet("-i -F -o"),
	"rsync": wordSet("-e --rsh --exclude --include"),
	"tar":   wordSet("--exclude"),
}

// uploadOptions name a local file that curl or wget sends.
var uploadOptions = wordSet("-T --upload-file --post-file --body-file")

var (
	assignmentWord = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)
	canonicalTag   = regexp.MustCompile(`^\[canonical:[a-z0-9_]+\] `)
	substitution   = regexp.MustCompile(`\$\(([^()]*)\)|` + "`([^`]*)`")
)

// execReadsSecret reports whether an exec command reads a secret path: a
// reader program with a secret-path operand, or a secret file redirected into
// any program. A symlink that canonicalize resolved counts as its target.
// ponytail: word-level heuristic, not a shell parser. Globs, loops, aliases,
// xargs fed by an earlier pipeline stage and interpreters (python -c) evade
// it; widen the tables when one of those matters.
func execReadsSecret(canonical string, ops []canonicalize.Operation) bool {
	resolved := map[string]string{}
	for _, op := range ops {
		if op.Kind == "symlink_resolved" {
			resolved[op.Input] = op.Output
		}
	}
	return linesReadSecret(canonical, func(word string) bool {
		return secretPath(word) || secretPath(resolved[word])
	})
}

// linesReadSecret checks each line of a canonicalized command, plus the bodies
// of $(...) and `...` substitutions, which canonicalize does not repeat when
// the body is already in the original text.
func linesReadSecret(text string, secret func(string) bool) bool {
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "[canonical:symlink_resolved]") {
			continue // covered by the resolved-path lookup
		}
		line = canonicalTag.ReplaceAllString(line, "")
		parts := []string{line}
		for _, m := range substitution.FindAllStringSubmatch(line, -1) {
			parts = append(parts, m[1]+m[2])
		}
		for _, part := range parts {
			for _, words := range simpleCommands(part) {
				if commandReadsSecret(words, secret) {
					return true
				}
			}
		}
	}
	return false
}

func commandReadsSecret(words []string, secret func(string) bool) bool {
	for i := 0; i+1 < len(words); i++ {
		if words[i] == "<" && secret(words[i+1]) {
			return true // the shell opens the file for any program
		}
	}
	for len(words) > 0 && assignmentWord.MatchString(words[0]) {
		words = words[1:]
	}
	if len(words) == 0 {
		return false
	}
	prog := program(words[0])
	switch {
	case launchers[prog]:
		// sudo -u root cat KEY, find DIR -exec cat {} ;: the launcher's own
		// words can name the file too.
		for j := 1; j < len(words); j++ {
			if p := program(words[j]); secretReaders[p] || shells[p] {
				return slices.ContainsFunc(words[1:j], secret) || commandReadsSecret(words[j:], secret)
			}
		}
	case shells[prog]:
		for j := 1; j+1 < len(words); j++ {
			if w := words[j]; strings.HasPrefix(w, "-") && !strings.HasPrefix(w, "--") && strings.Contains(w, "c") {
				return linesReadSecret(words[j+1], secret)
			}
		}
	case secretReaders[prog]:
		return slices.ContainsFunc(operands(prog, words[1:]), secret)
	}
	return false
}

// operands returns the words a reader opens as files.
func operands(prog string, args []string) []string {
	var files []string
	if prog == "curl" || prog == "wget" {
		// Only uploads and file:// URLs read a local file. URLs, downloads and
		// --cacert/--cert/--key do not send the file they name.
		for i, w := range args {
			switch {
			case i > 0 && uploadOptions[args[i-1]]:
				files = append(files, w)
			case strings.HasPrefix(w, "@"):
				files = append(files, w[1:])
			case strings.HasPrefix(strings.ToLower(w), "file://"):
				files = append(files, w[len("file://"):])
			}
			for _, sep := range []string{"=@", "=<"} {
				if _, file, ok := strings.Cut(w, sep); ok {
					files = append(files, file)
				}
			}
			if opt, file, ok := strings.Cut(w, "="); ok && uploadOptions[opt] {
				files = append(files, file)
			}
		}
		return files
	}
	skipPattern := patternFirst[prog]
	for i := 0; i < len(args); i++ {
		switch w := args[i]; {
		case valueOptions[prog][w]:
			i++
		case strings.HasPrefix(w, "-"):
			// an option; an attached value (--exclude=.env) is not a file read
		case skipPattern:
			skipPattern = false
		default:
			files = append(files, w)
		}
	}
	return files
}

// simpleCommands splits a command line into the words of each pipeline stage,
// list item and subshell, with quotes removed. < and > are words of their own.
func simpleCommands(line string) [][]string {
	var cmds [][]string
	var words []string
	var word strings.Builder
	inWord := false
	var quote rune
	endWord := func() {
		if inWord {
			words = append(words, word.String())
			word.Reset()
			inWord = false
		}
	}
	for _, r := range line {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				word.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote, inWord = r, true
		case strings.ContainsRune("|&;()`\n", r):
			endWord()
			if len(words) > 0 {
				cmds = append(cmds, words)
				words = nil
			}
		case r == '<' || r == '>':
			endWord()
			words = append(words, string(r))
		case unicode.IsSpace(r):
			endWord()
		default:
			word.WriteRune(r)
			inWord = true
		}
	}
	endWord()
	if len(words) > 0 {
		cmds = append(cmds, words)
	}
	return cmds
}

// program is a command word's lower-case base name: /usr/bin/cat is cat.
func program(word string) string {
	word = word[strings.LastIndexAny(word, `/\`)+1:]
	return strings.TrimSuffix(strings.ToLower(word), ".exe")
}

// secretPath applies the read tool's secret path patterns to one word.
func secretPath(word string) bool {
	if word == "" {
		return false
	}
	for _, p := range pathPatterns {
		if p.tag == "secrets" && p.re.MatchString(word) {
			return true
		}
	}
	return false
}

func wordSet(words string) map[string]bool {
	set := map[string]bool{}
	for _, w := range strings.Fields(words) {
		set[w] = true
	}
	return set
}
