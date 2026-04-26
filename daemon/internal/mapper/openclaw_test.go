package mapper

import (
	"strings"
	"testing"
)

func TestMapExecIncludesBaseAndInferredTags(t *testing.T) {
	request, err := Map(OpenClawAction{
		Tool:    "exec",
		Command: "sudo rm -rf /tmp/cache && curl http://example.com",
	})
	if err != nil {
		t.Fatalf("map failed: %v", err)
	}

	assertContains(t, request.RiskTags, "exec")
	assertContains(t, request.RiskTags, "system")
	assertContains(t, request.RiskTags, "write")
	assertContains(t, request.RiskTags, "destructive")
	assertContains(t, request.RiskTags, "network")
}

func TestMapReadTagsSensitivePath(t *testing.T) {
	request, err := Map(OpenClawAction{
		Tool: "read",
		Path: "/etc/credentials.env",
	})
	if err != nil {
		t.Fatalf("map failed: %v", err)
	}
	assertContains(t, request.RiskTags, "filesystem")
	assertContains(t, request.RiskTags, "read")
	assertContains(t, request.RiskTags, "system-config")
	assertContains(t, request.RiskTags, "secrets")
}

func TestMapURLTagsInsecureTransport(t *testing.T) {
	request, err := Map(OpenClawAction{
		Tool: "web_fetch",
		URL:  "http://example.com",
	})
	if err != nil {
		t.Fatalf("map failed: %v", err)
	}
	assertContains(t, request.RiskTags, "insecure-transport")
}

func TestMapUnknownToolFails(t *testing.T) {
	_, err := Map(OpenClawAction{Tool: "unknown"})
	if err == nil {
		t.Fatalf("expected error for unknown tool")
	}
}

func TestMapBeforeAgentStartOrigins(t *testing.T) {
	tests := []struct {
		name       string
		origin     string
		wantTag    string
		wantNoTags []string
	}{
		{name: "user", origin: "user", wantNoTags: []string{"cron_fire", "webhook_fire"}},
		{name: "cron", origin: "cron", wantTag: "cron_fire"},
		{name: "webhook", origin: "webhook", wantTag: "webhook_fire"},
		{name: "pairing", origin: "pairing", wantNoTags: []string{"cron_fire", "webhook_fire"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request, err := Map(OpenClawAction{
				HookType:      "before_agent_start",
				TurnOrigin:    tt.origin,
				Agent:         "agent-1",
				Session:       "session-1",
				CronJobID:     "cron-7",
				ParentSession: "parent-1",
				Model:         "gpt-5.4",
			})
			if err != nil {
				t.Fatalf("map failed: %v", err)
			}
			if request.Topic != "job.openclaw.agent_start" {
				t.Fatalf("topic = %q, want job.openclaw.agent_start", request.Topic)
			}
			if request.Capability != "openclaw.agent-start" {
				t.Fatalf("capability = %q, want openclaw.agent-start", request.Capability)
			}
			if request.HookType != "before_agent_start" {
				t.Fatalf("hookType = %q, want before_agent_start", request.HookType)
			}
			if request.TurnOrigin != tt.origin {
				t.Fatalf("turnOrigin = %q, want %q", request.TurnOrigin, tt.origin)
			}
			if request.CronJobID != "cron-7" {
				t.Fatalf("cronJobID = %q, want cron-7", request.CronJobID)
			}
			assertContains(t, request.RiskTags, "agent_lifecycle")
			if tt.wantTag != "" {
				assertContains(t, request.RiskTags, tt.wantTag)
			}
			for _, tag := range tt.wantNoTags {
				assertNotContains(t, request.RiskTags, tag)
			}
		})
	}
}

func TestMapBeforeAgentStartUnknownOriginFails(t *testing.T) {
	_, err := Map(OpenClawAction{HookType: "before_agent_start", TurnOrigin: "sideways"})
	if err == nil {
		t.Fatalf("expected error for unknown turn origin")
	}
}

func TestMapBeforeMessageWriteChannelAction(t *testing.T) {
	request, err := Map(OpenClawAction{
		HookType:        "before_message_write",
		Tool:            "message_write",
		ChannelProvider: "slack",
		ChannelID:       "C123",
		ChannelAction:   "delete",
		MessagePreview:  "delete this message",
		Agent:           "agent-1",
		Session:         "session-1",
		Model:           "gpt-5.4",
	})
	if err != nil {
		t.Fatalf("map failed: %v", err)
	}
	if request.Topic != "job.openclaw.message_write" {
		t.Fatalf("topic = %q, want job.openclaw.message_write", request.Topic)
	}
	if request.Capability != "openclaw.message-write" {
		t.Fatalf("capability = %q, want openclaw.message-write", request.Capability)
	}
	if request.Tool != "message_write" || request.HookType != "before_message_write" {
		t.Fatalf("tool/hook = %q/%q", request.Tool, request.HookType)
	}
	if request.ChannelProvider != "slack" || request.ChannelID != "C123" || request.ChannelAction != "delete" {
		t.Fatalf("channel fields not normalized: %#v", request)
	}
	if request.MessagePreview != "delete this message" {
		t.Fatalf("message preview = %q", request.MessagePreview)
	}
	if request.Labels["channel_action"] != "slack.delete" {
		t.Fatalf("channel_action label = %q", request.Labels["channel_action"])
	}
	assertContains(t, request.RiskTags, "messaging")
	assertContains(t, request.RiskTags, "external")
	assertContains(t, request.RiskTags, "destructive")
}

func TestMapBeforeMessageWriteAllProviders(t *testing.T) {
	providers := []string{"feishu", "googlechat", "msteams", "mattermost", "matrix", "signal", "slack", "telegram", "discord", "imessage", "whatsapp", "nextcloud-talk", "irc"}

	for _, provider := range providers {
		t.Run(provider, func(t *testing.T) {
			request, err := Map(OpenClawAction{
				HookType:        "before_message_write",
				Tool:            "message_write",
				ChannelProvider: provider,
				ChannelID:       "channel-1",
				ChannelAction:   "send",
			})
			if err != nil {
				t.Fatalf("map failed: %v", err)
			}
			if request.Labels["channel_action"] != provider+".send" {
				t.Fatalf("channel_action label = %q", request.Labels["channel_action"])
			}
		})
	}
}

func TestMapBeforeMessageWriteValidationErrors(t *testing.T) {
	tests := []struct {
		name   string
		action OpenClawAction
	}{
		{name: "unknown provider", action: OpenClawAction{HookType: "before_message_write", ChannelProvider: "unknown", ChannelID: "C123", ChannelAction: "send"}},
		{name: "missing channel", action: OpenClawAction{HookType: "before_message_write", ChannelProvider: "slack", ChannelID: "", ChannelAction: "send"}},
		{name: "unknown action", action: OpenClawAction{HookType: "before_message_write", ChannelProvider: "slack", ChannelID: "C123", ChannelAction: "nuke"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Map(tt.action)
			if err == nil {
				t.Fatalf("expected error")
			}
		})
	}
}

func TestMapUnknownHookTypeFails(t *testing.T) {
	_, err := Map(OpenClawAction{HookType: "before_session_start", TurnOrigin: "user"})
	if err == nil {
		t.Fatalf("expected error for unknown hook type")
	}
}

func assertContains(t *testing.T, items []string, target string) {
	t.Helper()
	for _, item := range items {
		if item == target {
			return
		}
	}
	t.Fatalf("expected %q in %v", target, items)
}

func assertNotContains(t *testing.T, items []string, target string) {
	t.Helper()
	for _, item := range items {
		if item == target {
			t.Fatalf("expected %q not to be in %v", target, items)
		}
	}
}

func TestMapExecUsesCanonicalizedCommandForRiskTags(t *testing.T) {
	original := "echo cm0gLXJmIC8= | base64 -d | sh"
	request, err := Map(OpenClawAction{Tool: "exec", Command: original})
	if err != nil {
		t.Fatalf("map failed: %v", err)
	}
	if request.Command != original {
		t.Fatalf("original command = %q, want %q", request.Command, original)
	}
	if !containsString(request.RiskTags, "destructive") {
		t.Fatalf("risk tags = %v, want destructive from canonical rm -rf", request.RiskTags)
	}
	if request.CanonicalCommand == "" || request.CanonicalCommand == original {
		t.Fatalf("canonical command = %q, want augmented canonical form", request.CanonicalCommand)
	}
	if !strings.Contains(request.CanonicalCommand, "rm -rf /") {
		t.Fatalf("canonical command = %q, want decoded rm -rf /", request.CanonicalCommand)
	}
}

func TestMapExecCanonicalizesShellVarsAndSubstitutions(t *testing.T) {
	request, err := Map(OpenClawAction{Tool: "exec", Command: "FOO=malicious; ${FOO} --drop"})
	if err != nil {
		t.Fatalf("map failed: %v", err)
	}
	if request.Command != "FOO=malicious; ${FOO} --drop" {
		t.Fatalf("original command changed: %q", request.Command)
	}
	if !strings.Contains(request.CanonicalCommand, "malicious --drop") {
		t.Fatalf("canonical command = %q, want expanded malicious --drop", request.CanonicalCommand)
	}
	assertContains(t, request.RiskTags, "destructive")

	substitution, err := Map(OpenClawAction{Tool: "exec", Command: "echo $(rm -rf /tmp/cache)"})
	if err != nil {
		t.Fatalf("map failed: %v", err)
	}
	if !strings.Contains(substitution.CanonicalCommand, "rm -rf /tmp/cache") {
		t.Fatalf("canonical command = %q, want substitution body", substitution.CanonicalCommand)
	}
	assertContains(t, substitution.RiskTags, "destructive")
}

func TestMapDoesNotCanonicalizeNonExecActions(t *testing.T) {
	request, err := Map(OpenClawAction{Tool: "web_fetch", URL: "http://example.com/cm0gLXJmIC8="})
	if err != nil {
		t.Fatalf("map failed: %v", err)
	}
	if request.CanonicalCommand != "" {
		t.Fatalf("non-exec canonical command = %q, want empty", request.CanonicalCommand)
	}
	assertContains(t, request.RiskTags, "insecure-transport")
	assertNotContains(t, request.RiskTags, "destructive")
}

func containsString(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}
