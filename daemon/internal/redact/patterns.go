package redact

func BuiltInPatterns() []Pattern {
	return []Pattern{
		{
			Name:        "OPENAI_KEY",
			Regex:       `\bsk-[A-Za-z0-9_-]{10,}\b`,
			Placeholder: "<REDACTED-OPENAI_KEY>",
		},
		{
			Name:        "SLACK_BOT",
			Regex:       `\bxoxb-[A-Za-z0-9-]{20,}\b`,
			Placeholder: "<REDACTED-SLACK_BOT>",
		},
		{
			Name:        "AWS_ACCESS_KEY",
			Regex:       `\bAKIA[0-9A-Z]{16}\b`,
			Placeholder: "<REDACTED-AWS_ACCESS_KEY>",
		},
		{
			Name:        "GITHUB_PAT",
			Regex:       `\bgh[psu]_[A-Za-z0-9]{36,}\b`,
			Placeholder: "<REDACTED-GITHUB_PAT>",
		},
		{
			Name:        "AWS_SECRET",
			Regex:       `\b[A-Za-z0-9+/]{40}\b`,
			Placeholder: "<REDACTED-AWS_SECRET>",
		},
	}
}

func EmailPattern() Pattern {
	return Pattern{
		Name:        "EMAIL",
		Regex:       `\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`,
		Placeholder: "<REDACTED-EMAIL>",
	}
}
