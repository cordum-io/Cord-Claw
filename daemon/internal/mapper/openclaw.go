package mapper

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

type OpenClawAction struct {
	Tool    string `json:"tool"`
	Command string `json:"command,omitempty"`
	Path    string `json:"path,omitempty"`
	URL     string `json:"url,omitempty"`
	Channel string `json:"channel,omitempty"`
	Agent   string `json:"agent,omitempty"`
	Session string `json:"session,omitempty"`
	Model   string `json:"model,omitempty"`
}

type PolicyCheckRequest struct {
	Topic      string   `json:"topic"`
	Capability string   `json:"capability"`
	Tool       string   `json:"tool"`
	Command    string   `json:"command,omitempty"`
	Path       string   `json:"path,omitempty"`
	URL        string   `json:"url,omitempty"`
	Channel    string   `json:"channel,omitempty"`
	Agent      string   `json:"agent,omitempty"`
	Session    string   `json:"session,omitempty"`
	Model      string   `json:"model,omitempty"`
	RiskTags   []string `json:"riskTags"`
}

type mapping struct {
	topic      string
	capability string
	tags       []string
}

var toolMappings = map[string]mapping{
	"exec":             {topic: "job.cordclaw.exec", capability: "cordclaw.shell-execute", tags: []string{"exec", "system", "write"}},
	"read":             {topic: "job.cordclaw.file-read", capability: "cordclaw.file-read", tags: []string{"filesystem", "read"}},
	"write":            {topic: "job.cordclaw.file-write", capability: "cordclaw.file-write", tags: []string{"filesystem", "write"}},
	"browser.navigate": {topic: "job.cordclaw.browser", capability: "cordclaw.browser-navigate", tags: []string{"network", "browser"}},
	"browser.action":   {topic: "job.cordclaw.browser-action", capability: "cordclaw.browser-interact", tags: []string{"network", "browser", "write"}},
	"web_search":       {topic: "job.cordclaw.web-search", capability: "cordclaw.web-search", tags: []string{"network", "read"}},
	"web_fetch":        {topic: "job.cordclaw.web-fetch", capability: "cordclaw.web-fetch", tags: []string{"network", "read"}},
	"sessions_send":    {topic: "job.cordclaw.message-send", capability: "cordclaw.message-send", tags: []string{"messaging", "write", "external"}},
	"memory_write":     {topic: "job.cordclaw.memory-write", capability: "cordclaw.memory-write", tags: []string{"memory", "write", "persistence"}},
	"cron.create":      {topic: "job.cordclaw.cron-create", capability: "cordclaw.schedule-create", tags: []string{"schedule", "write", "autonomy"}},
}

var commandPatterns = []struct {
	re  *regexp.Regexp
	tag string
}{
	{re: regexp.MustCompile(`(?i)\b(rm\s+-rf|sudo|chmod|mkfs|dd\s+if)\b`), tag: "destructive"},
	{re: regexp.MustCompile(`(?i)\b(curl|wget|nc|ncat)\b`), tag: "network"},
	{re: regexp.MustCompile(`(?i)\b(pip\s+install|npm\s+install|apt\s+install)\b`), tag: "package-install"},
	{re: regexp.MustCompile(`(?i)\b(ssh|scp|rsync)\b`), tag: "remote-access"},
	{re: regexp.MustCompile(`(?i)\b(docker|kubectl|helm)\b`), tag: "infrastructure"},
	{re: regexp.MustCompile(`(?i)\b(git\s+push|git\s+force)\b`), tag: "code-deploy"},
	{re: regexp.MustCompile(`(?i)\b(aws|gcloud|az)\b`), tag: "cloud"},
	{re: regexp.MustCompile(`(?i)\b(env|export|printenv)\b`), tag: "secrets"},
}

var pathPatterns = []struct {
	re  *regexp.Regexp
	tag string
}{
	{re: regexp.MustCompile(`(?i)(\.env|\.pem|\.key|\.crt|\.pfx|\.p12)`), tag: "secrets"},
	{re: regexp.MustCompile(`(?i)(/etc/|/root/|~/.ssh)`), tag: "system-config"},
	{re: regexp.MustCompile(`(?i)(credentials|tokens|passwords)`), tag: "secrets"},
}

func Map(action OpenClawAction) (PolicyCheckRequest, error) {
	m, ok := toolMappings[action.Tool]
	if !ok {
		return PolicyCheckRequest{}, fmt.Errorf("unknown tool: %s", action.Tool)
	}

	tagSet := map[string]struct{}{}
	for _, tag := range m.tags {
		tagSet[tag] = struct{}{}
	}

	if action.Tool == "exec" {
		for _, pat := range commandPatterns {
			if pat.re.MatchString(action.Command) {
				tagSet[pat.tag] = struct{}{}
			}
		}
	}

	if action.Tool == "read" || action.Tool == "write" {
		for _, pat := range pathPatterns {
			if pat.re.MatchString(action.Path) {
				tagSet[pat.tag] = struct{}{}
			}
		}
	}

	if strings.TrimSpace(action.URL) != "" {
		parsed, err := url.Parse(action.URL)
		if err == nil && !strings.EqualFold(parsed.Scheme, "https") {
			tagSet["insecure-transport"] = struct{}{}
		}
	}

	riskTags := make([]string, 0, len(tagSet))
	for tag := range tagSet {
		riskTags = append(riskTags, tag)
	}
	sort.Strings(riskTags)

	return PolicyCheckRequest{
		Topic:      m.topic,
		Capability: m.capability,
		Tool:       action.Tool,
		Command:    action.Command,
		Path:       action.Path,
		URL:        action.URL,
		Channel:    action.Channel,
		Agent:      action.Agent,
		Session:    action.Session,
		Model:      action.Model,
		RiskTags:   riskTags,
	}, nil
}
