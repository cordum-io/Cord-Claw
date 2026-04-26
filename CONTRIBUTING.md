# Contributing to CordClaw

Thanks for contributing to CordClaw.

## Prerequisites

- Go `1.24+`
- Node.js `20+`
- npm `10+`

## Local Development

### Daemon

```bash
cd daemon
make tidy
make test
make build
```

### DLP corpus secret scanning

The benign DLP prompt corpus under `daemon/internal/redact/testdata/benign-prompts`
is used to measure false positives. It must never contain real credentials.

Install gitleaks locally before updating the corpus:

```bash
go install github.com/zricethezav/gitleaks/v8@latest
```

Run the same redacted no-git scan used by CI:

```bash
gitleaks detect --no-git --redact --source daemon/internal/redact/testdata/benign-prompts --exit-code 1
```

If a legitimate false positive must be exempted, add the finding fingerprint to
`daemon/internal/redact/testdata/benign-prompts/.gitleaksignore`. Do not print
or paste suspected secret values in issues, CI logs, or PR comments; report only
the file, line, and rule ID.

### Plugin

```bash
cd plugin
npm install
npm test
npm run build
```

## Pull Request Guidelines

- Open an issue first for major changes.
- Keep PRs focused and easy to review.
- Include tests for behavior changes.
- Update docs when user-facing behavior changes.

## Commit Guidance

- Use clear, imperative commit messages.
- Reference relevant issues (for example: `COR-21`) in PR descriptions.

## Reporting Security Issues

Do not open public security issues for exploitable findings.
Email the Cordum security contact listed in the organization security policy.
