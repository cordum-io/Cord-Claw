package mapper

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/cordum-io/cordclaw/daemon/internal/canonicalize"
)

type OpenClawAction struct {
	Tool                string   `json:"tool"`
	HookType            string   `json:"hookType,omitempty"`
	Command             string   `json:"command,omitempty"`
	Path                string   `json:"path,omitempty"`
	URL                 string   `json:"url,omitempty"`
	Channel             string   `json:"channel,omitempty"`
	ChannelProvider     string   `json:"channel_provider,omitempty"`
	ChannelID           string   `json:"channel_id,omitempty"`
	ChannelAction       string   `json:"action,omitempty"`
	MessagePreview      string   `json:"message_preview,omitempty"`
	Agent               string   `json:"agent,omitempty"`
	Session             string   `json:"session,omitempty"`
	Model               string   `json:"model,omitempty"`
	TurnOrigin          string   `json:"turnOrigin,omitempty"`
	CronJobID           string   `json:"cronJobId,omitempty"`
	ParentSession       string   `json:"parentSession,omitempty"`
	AllowedTools        []string `json:"allowedTools,omitempty"`
	AllowedCapabilities []string `json:"allowedCapabilities,omitempty"`
}

type PolicyCheckRequest struct {
	Topic               string                   `json:"topic"`
	Capability          string                   `json:"capability"`
	Tool                string                   `json:"tool"`
	HookType            string                   `json:"hookType,omitempty"`
	Command             string                   `json:"command,omitempty"`
	Path                string                   `json:"path,omitempty"`
	URL                 string                   `json:"url,omitempty"`
	Channel             string                   `json:"channel,omitempty"`
	ChannelProvider     string                   `json:"channel_provider,omitempty"`
	ChannelID           string                   `json:"channel_id,omitempty"`
	ChannelAction       string                   `json:"action,omitempty"`
	MessagePreview      string                   `json:"message_preview,omitempty"`
	Agent               string                   `json:"agent,omitempty"`
	Session             string                   `json:"session,omitempty"`
	Model               string                   `json:"model,omitempty"`
	TurnOrigin          string                   `json:"turnOrigin,omitempty"`
	CronJobID           string                   `json:"cronJobId,omitempty"`
	ParentSession       string                   `json:"parentSession,omitempty"`
	AllowedTools        []string                 `json:"allowedTools,omitempty"`
	AllowedCapabilities []string                 `json:"allowedCapabilities,omitempty"`
	Labels              map[string]string        `json:"labels,omitempty"`
	RiskTags            []string                 `json:"riskTags"`
	CanonicalCommand    string                   `json:"canonical_command,omitempty"`
	CanonicalOperations []canonicalize.Operation `json:"canonical_operations,omitempty"`
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

var hookMappings = map[string]mapping{
	"before_agent_start": {topic: "job.openclaw.agent_start", capability: "openclaw.agent-start", tags: []string{"agent_lifecycle"}},
}

var commandPatterns = []struct {
	re  *regexp.Regexp
	tag string
}{
	{re: regexp.MustCompile(`(?i)(\b(rm\s+-rf|sudo|chmod|mkfs|dd\s+if)\b|(^|\s)--drop(\s|$))`), tag: "destructive"},
	{re: regexp.MustCompile(`(?i)\b(curl|wget|nc|ncat)\b`), tag: "network"},
	{re: regexp.MustCompile(`(?i)\b(pip\s+install|npm\s+install|apt\s+install)\b`), tag: "package-install"},
	{re: regexp.MustCompile(`(?i)\b(docker|kubectl|helm)\b`), tag: "infrastructure"},
	{re: regexp.MustCompile(`(?i)\b(git\s+push|git\s+force)\b`), tag: "code-deploy"},
	{re: regexp.MustCompile(`(?i)\b(aws|gcloud|az)\b`), tag: "cloud"},
}

var pathPatterns = []struct {
	re  *regexp.Regexp
	tag string
}{
	{re: regexp.MustCompile(`(?i)(/etc/|/root/|~/.ssh)`), tag: "system-config"},
}

// Secret files, for the read and write tools and for exec reader operands.
// secretFile matches the whole lower-case path (with / separators), the
// other two its base name.
var (
	secretFile = regexp.MustCompile(`(^|[/:])(\.ssh(/|$)|\.kube/config$|\.docker/config\.json$|\.config/gh/hosts\.yml$|proc/[^/]+/environ$)`)
	secretName = regexp.MustCompile(`^(id_(rsa|dsa|ecdsa|ed25519)(_sk)?\b.*|\.env(rc)?(\..+)?|.+\.(env|pem|key|pfx|p12)|` +
		`\.netrc|_netrc|\.npmrc|\.pypirc|(.*[._-])?(credentials|tokens|passwords)(\.(json|ya?ml|txt|csv|xml|ini|toml|db))?)$`)
	publicName = regexp.MustCompile(`\.pub$|^\.env\.(example|sample|template|dist)$`)
)

// secretPath reports whether a path, or an exec operand naming one, is
// secret material: anything under .ssh but public keys, private key files,
// dotenv files but templates, credential stores (credentials,
// credentials.json, tokens.json, .git-credentials, .netrc), the kube, docker,
// gh, npm and pypi auth configs, and a process environment (/proc/*/environ).
// Source files such as tokens.go or credentials.ts are not.
func secretPath(word string) bool {
	path := strings.ToLower(strings.ReplaceAll(word, `\`, "/"))
	base := path[strings.LastIndexAny(path, "/:")+1:]
	if word == "" || publicName.MatchString(base) {
		return false
	}
	return secretFile.MatchString(path) || secretName.MatchString(base)
}

func Map(action OpenClawAction) (PolicyCheckRequest, error) {
	hookType := strings.TrimSpace(action.HookType)
	switch hookType {
	case "", "before_tool_execution":
		return mapTool(action)
	case "before_agent_start":
		return mapHook(action, hookType)
	case "before_message_write":
		return mapMessageWrite(action, hookType)
	default:
		return PolicyCheckRequest{}, fmt.Errorf("unknown hook type: %s", hookType)
	}
}

func mapTool(action OpenClawAction) (PolicyCheckRequest, error) {
	m, ok := toolMappings[action.Tool]
	if !ok {
		return PolicyCheckRequest{}, fmt.Errorf("unknown tool: %s", action.Tool)
	}

	tagSet := map[string]struct{}{}
	for _, tag := range m.tags {
		tagSet[tag] = struct{}{}
	}

	canonicalCommand := ""
	var canonicalOperations []canonicalize.Operation
	commandForTagging := action.Command
	if action.Tool == "exec" && strings.TrimSpace(action.Command) != "" {
		canonical := canonicalize.Normalize(action.Command)
		canonicalCommand = canonical.Canonical
		canonicalOperations = canonical.Operations
		commandForTagging = canonical.Canonical
	}

	if action.Tool == "exec" {
		for _, pat := range commandPatterns {
			if pat.re.MatchString(commandForTagging) {
				tagSet[pat.tag] = struct{}{}
			}
		}
		for tag := range execTags(commandForTagging, canonicalOperations) {
			tagSet[tag] = struct{}{}
		}
	}

	if action.Tool == "read" || action.Tool == "write" {
		for _, pat := range pathPatterns {
			if pat.re.MatchString(action.Path) {
				tagSet[pat.tag] = struct{}{}
			}
		}
		if secretPath(action.Path) {
			tagSet["secrets"] = struct{}{}
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
		Topic:               m.topic,
		Capability:          m.capability,
		Tool:                action.Tool,
		HookType:            strings.TrimSpace(action.HookType),
		Command:             action.Command,
		Path:                action.Path,
		URL:                 action.URL,
		Channel:             action.Channel,
		Agent:               action.Agent,
		Session:             action.Session,
		Model:               action.Model,
		TurnOrigin:          strings.TrimSpace(action.TurnOrigin),
		CronJobID:           strings.TrimSpace(action.CronJobID),
		AllowedTools:        normalizeAllowedList(action.AllowedTools),
		AllowedCapabilities: normalizeAllowedList(action.AllowedCapabilities),
		RiskTags:            riskTags,
		CanonicalCommand:    canonicalCommand,
		CanonicalOperations: canonicalOperations,
	}, nil
}

func mapMessageWrite(action OpenClawAction, hookType string) (PolicyCheckRequest, error) {
	normalized, err := canonicalize.NormalizeMessageWrite(
		action.ChannelProvider,
		action.ChannelID,
		action.ChannelAction,
		action.MessagePreview,
	)
	if err != nil {
		return PolicyCheckRequest{}, err
	}

	return PolicyCheckRequest{
		Topic:           "job.openclaw.message_write",
		Capability:      "openclaw.message-write",
		Tool:            "message_write",
		HookType:        hookType,
		Channel:         action.Channel,
		ChannelProvider: normalized.Provider,
		ChannelID:       normalized.ChannelID,
		ChannelAction:   normalized.Action,
		MessagePreview:  normalized.MessagePreview,
		Agent:           action.Agent,
		Session:         action.Session,
		Model:           action.Model,
		Labels:          normalized.Labels,
		RiskTags:        normalized.RiskTags,
	}, nil
}

func mapHook(action OpenClawAction, hookType string) (PolicyCheckRequest, error) {
	m, ok := hookMappings[hookType]
	if !ok {
		return PolicyCheckRequest{}, fmt.Errorf("unknown hook type: %s", hookType)
	}

	tagSet := map[string]struct{}{}
	for _, tag := range m.tags {
		tagSet[tag] = struct{}{}
	}

	turnOrigin := strings.TrimSpace(action.TurnOrigin)
	switch turnOrigin {
	case "user", "pairing":
	case "cron":
		tagSet["cron_fire"] = struct{}{}
	case "webhook":
		tagSet["webhook_fire"] = struct{}{}
	default:
		return PolicyCheckRequest{}, fmt.Errorf("unknown turn origin: %s", turnOrigin)
	}

	riskTags := make([]string, 0, len(tagSet))
	for tag := range tagSet {
		riskTags = append(riskTags, tag)
	}
	sort.Strings(riskTags)

	return PolicyCheckRequest{
		Topic:               m.topic,
		Capability:          m.capability,
		Tool:                "agent_start",
		HookType:            hookType,
		Agent:               action.Agent,
		Session:             action.Session,
		Model:               action.Model,
		TurnOrigin:          turnOrigin,
		CronJobID:           action.CronJobID,
		ParentSession:       action.ParentSession,
		AllowedTools:        normalizeAllowedList(action.AllowedTools),
		AllowedCapabilities: normalizeAllowedList(action.AllowedCapabilities),
		RiskTags:            riskTags,
	}, nil
}

func normalizeAllowedList(items []string) []string {
	if len(items) == 0 {
		return []string{}
	}
	itemSet := make(map[string]struct{}, len(items))
	for _, item := range items {
		item = strings.ToLower(strings.TrimSpace(item))
		if item == "" {
			continue
		}
		itemSet[item] = struct{}{}
	}
	out := make([]string, 0, len(itemSet))
	for item := range itemSet {
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}
