package mapper

import "testing"

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
