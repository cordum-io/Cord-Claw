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
