package mapper

import "testing"

func TestTopicForHook(t *testing.T) {
	tests := []struct {
		name string
		hook string
		want string
	}{
		{name: "before tool execution", hook: "before_tool_execution", want: "job.openclaw.tool_call"},
		{name: "after tool execution", hook: "after_tool_execution", want: "job.openclaw.result_gating"},
		{name: "before prompt build", hook: "before_prompt_build", want: "job.openclaw.prompt_build"},
		{name: "before agent start", hook: "before_agent_start", want: "job.openclaw.agent_start"},
		{name: "before message write", hook: "before_message_write", want: "job.openclaw.message_write"},
		{name: "before cron fire", hook: "before_cron_fire", want: "job.openclaw.cron_fire"},
		{name: "rate limit summary", hook: "rate_limit_summary", want: "job.openclaw.rate_limit_summary"},
		{name: "empty", hook: "", want: "job.openclaw.unknown"},
		{name: "whitespace", hook: "  ", want: "job.openclaw.unknown"},
		{name: "path traversal", hook: "../foo", want: "job.openclaw.unknown"},
		{name: "sql-ish injection", hook: "foo;DROP", want: "job.openclaw.unknown"},
		{name: "camel case unknown", hook: "UnknownHookXyz", want: "job.openclaw.unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := TopicForHook(tt.hook); got != tt.want {
				t.Fatalf("TopicForHook(%q) = %q, want %q", tt.hook, got, tt.want)
			}
		})
	}
}
func TestMapSetsCanonicalTopic(t *testing.T) {
	tests := []struct {
		name   string
		action OpenClawAction
		want   string
	}{
		{
			name: "tool execution hook maps to canonical tool_call topic",
			action: OpenClawAction{
				HookName: "before_tool_execution",
				Tool:     "exec",
				Command:  "echo hi",
			},
			want: "job.openclaw.tool_call",
		},
		{
			name: "agent start hook preserves canonical agent_start topic",
			action: OpenClawAction{
				HookName:   "before_agent_start",
				TurnOrigin: "user",
			},
			want: "job.openclaw.agent_start",
		},
		{
			name: "empty hook defaults through tool execution to tool_call topic",
			action: OpenClawAction{
				Tool: "web_fetch",
				URL:  "https://example.test/report",
			},
			want: "job.openclaw.tool_call",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := Map(tt.action)
			if err != nil {
				t.Fatalf("Map() error = %v", err)
			}
			if req.Topic != tt.want {
				t.Fatalf("Topic = %q, want %q", req.Topic, tt.want)
			}
		})
	}
}
