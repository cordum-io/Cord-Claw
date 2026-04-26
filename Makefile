.PHONY: corpus-scan

corpus-scan:
	gitleaks detect --no-git --redact --source daemon/internal/redact/testdata/benign-prompts --exit-code 1
