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

func TestMapNormalizesAllowedIntentMetadata(t *testing.T) {
	request, err := Map(OpenClawAction{
		Tool:                "cron.create",
		AllowedTools:        []string{" Web_Fetch ", "web_fetch", "EXEC", ""},
		AllowedCapabilities: []string{" CordClaw.Web-Fetch ", "cordclaw.web-fetch", "CORDCLAW.SHELL-EXECUTE"},
	})
	if err != nil {
		t.Fatalf("map failed: %v", err)
	}

	assertStringSlicesEqual(t, request.AllowedTools, []string{"exec", "web_fetch"})
	assertStringSlicesEqual(t, request.AllowedCapabilities, []string{"cordclaw.shell-execute", "cordclaw.web-fetch"})
}

func TestMapEmptyAllowedIntentMetadataIsExplicitEmpty(t *testing.T) {
	request, err := Map(OpenClawAction{
		Tool:                "cron.create",
		AllowedTools:        []string{" ", ""},
		AllowedCapabilities: nil,
	})
	if err != nil {
		t.Fatalf("map failed: %v", err)
	}

	if request.AllowedTools == nil {
		t.Fatalf("AllowedTools = nil, want explicit empty slice")
	}
	if request.AllowedCapabilities == nil {
		t.Fatalf("AllowedCapabilities = nil, want explicit empty slice")
	}
	if len(request.AllowedTools) != 0 {
		t.Fatalf("AllowedTools = %v, want empty", request.AllowedTools)
	}
	if len(request.AllowedCapabilities) != 0 {
		t.Fatalf("AllowedCapabilities = %v, want empty", request.AllowedCapabilities)
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

func assertStringSlicesEqual(t *testing.T, got []string, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("slice = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("slice = %v, want %v", got, want)
		}
	}
}
