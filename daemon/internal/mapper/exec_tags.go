package mapper

import (
	"regexp"
	"slices"
	"strings"
	"unicode"

	"github.com/cordum-io/cordclaw/daemon/internal/canonicalize"
)

// The exec word parser tags what a command does by program, not by any
// matching substring: remote-access for an SSH client, and secrets when it
// reads a secret path ("cat ~/.ssh/id_rsa", "curl -F f=@.env URL", the same
// paths the read tool tags) or prints the environment ("printenv").

// secretReaders print, copy, archive or send the files their operands name.
var secretReaders = wordSet("cat tac nl less more head tail bat strings od xxd hexdump base64 base32 " +
	"grep egrep fgrep rg sed awk sort cut cp mv ln tar scp rsync nc ncat netcat socat curl wget")

// remotePrograms open a shell on, or copy files to or from, another host.
var remotePrograms = wordSet("ssh scp sftp rsync ssh-copy-id")

// launchers run a program named later on the line; shells run a -c string.
var launchers = wordSet("sudo doas env nohup nice time timeout watch sshpass command exec xargs find " +
	"{ ! if then else elif do while until")
var shells = wordSet("sh bash dash zsh ksh")

// envDumpers can print environment or shell variables; see dumpsEnv.
var envDumpers = wordSet("env printenv set export declare typeset")

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

// execTags returns the tags an exec command earns word by word:
// remote-access when it runs an SSH client, and secrets when it reads a
// secret path (a reader program with a secret-path operand, or a secret file
// redirected into any program) or prints the environment. A symlink that
// canonicalize resolved counts as its target.
// ponytail: word-level heuristic, not a shell parser. Globs, loops, aliases,
// xargs fed by an earlier pipeline stage and interpreters (python -c) evade
// it; widen the tables when one of those matters.
func execTags(canonical string, ops []canonicalize.Operation) map[string]bool {
	resolved := map[string]string{}
	for _, op := range ops {
		if op.Kind == "symlink_resolved" {
			resolved[op.Input] = op.Output
		}
	}
	tags := map[string]bool{}
	linesTags(canonical, func(word string) bool {
		return secretPath(word) || secretPath(resolved[word])
	}, tags)
	return tags
}

// linesTags checks each line of a canonicalized command, plus the bodies of
// $(...) and `...` substitutions, which canonicalize does not repeat when the
// body is already in the original text.
func linesTags(text string, secret func(string) bool, tags map[string]bool) {
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
				commandTags(words, secret, tags)
			}
		}
	}
}

func commandTags(words []string, secret func(string) bool, tags map[string]bool) {
	for i := 0; i+1 < len(words); i++ {
		if words[i] == "<" && secret(words[i+1]) {
			tags["secrets"] = true // the shell opens the file for any program
		}
	}
	for len(words) > 0 && assignmentWord.MatchString(words[0]) {
		words = words[1:]
	}
	if len(words) == 0 {
		return
	}
	prog, args := program(words[0]), words[1:]
	if remotePrograms[prog] {
		tags["remote-access"] = true
	}
	if dumpsEnv(prog, args) {
		tags["secrets"] = true
	}
	switch {
	case prog == "source" || prog == ".":
		// source FILE loads the file's values into the shell.
		if len(args) > 0 && secret(args[0]) {
			tags["secrets"] = true
		}
	case launchers[prog]:
		start := 0
		if prog == "find" {
			// find runs only what follows -exec, -execdir, -ok or -okdir.
			start = slices.IndexFunc(args, func(w string) bool {
				return strings.HasPrefix(w, "-exec") || strings.HasPrefix(w, "-ok")
			}) + 1
			if start == 0 {
				return
			}
		}
		for j := start; j < len(args); j++ {
			if prog == "command" && (args[j] == "-v" || args[j] == "-V") {
				return // command -v only looks the program up
			}
			if p := program(args[j]); secretReaders[p] || shells[p] || remotePrograms[p] || p == "env" || p == "printenv" {
				// sudo -u root cat KEY, find DIR -exec cat {} ;: the
				// launcher's own words can name the file too.
				if slices.ContainsFunc(args[:j], secret) {
					tags["secrets"] = true
				}
				commandTags(args[j:], secret, tags)
				return
			}
		}
	case shells[prog]:
		for j := 0; j+1 < len(args); j++ {
			if w := args[j]; strings.HasPrefix(w, "-") && !strings.HasPrefix(w, "--") && strings.Contains(w, "c") {
				linesTags(args[j+1], secret, tags)
				return
			}
		}
	case secretReaders[prog]:
		if slices.ContainsFunc(operands(prog, args), secret) {
			tags["secrets"] = true
		}
	}
}

// dumpsEnv reports whether a command prints the environment: printenv, env
// with no command to run, export/declare/typeset given no variable names, or
// a bare set (set -e only sets shell options).
func dumpsEnv(prog string, args []string) bool {
	if !envDumpers[prog] {
		return false
	}
	flags, names := 0, 0
	for i := 0; i < len(args); i++ {
		switch w := args[i]; {
		case isRedirect(w), prog == "env" && (w == "-u" || w == "--unset"):
			i++ // a redirect target, or the variable env leaves out
		case strings.HasPrefix(w, "-"):
			flags++
		case prog == "env" && assignmentWord.MatchString(w):
		default:
			names++ // the command env runs, or a name or argument for the rest
		}
	}
	switch prog {
	case "printenv":
		return true
	case "set":
		return flags == 0 && names == 0
	default:
		return names == 0
	}
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
		for i := range files {
			files[i], _, _ = strings.Cut(files[i], ";") // -F name=@file;type=text/plain
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
// list item and subshell, with quotes removed. A redirect operator (<, >, >>,
// <<) is a word of its own, without its file descriptor number.
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
	afterRedirect := false
	for _, r := range line {
		wasRedirect := afterRedirect
		afterRedirect = false
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
			if inWord && strings.Trim(word.String(), "0123456789") == "" {
				word.Reset() // the file descriptor in 2>file
				inWord = false
			}
			endWord()
			if wasRedirect {
				words[len(words)-1] += string(r)
			} else {
				words = append(words, string(r))
			}
			afterRedirect = true
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

func isRedirect(word string) bool {
	return word != "" && strings.Trim(word, "<>") == ""
}

// program is a command word's lower-case base name: /usr/bin/cat is cat.
func program(word string) string {
	word = word[strings.LastIndexAny(word, `/\`)+1:]
	return strings.TrimSuffix(strings.ToLower(word), ".exe")
}

func wordSet(words string) map[string]bool {
	set := map[string]bool{}
	for _, w := range strings.Fields(words) {
		set[w] = true
	}
	return set
}
