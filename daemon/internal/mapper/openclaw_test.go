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

func assertContains(t *testing.T, items []string, target string) {
	t.Helper()
	for _, item := range items {
		if item == target {
			return
		}
	}
	t.Fatalf("expected %q in %v", target, items)
}
