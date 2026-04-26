package canonicalize

import (
	"errors"
	"testing"
)

func TestNormalizeMessageWriteSupportsProvidersAndActions(t *testing.T) {
	providers := []string{
		"feishu",
		"googlechat",
		"msteams",
		"mattermost",
		"matrix",
		"signal",
		"slack",
		"telegram",
		"discord",
		"imessage",
		"whatsapp",
		"nextcloud-talk",
		"irc",
	}
	actions := []string{"send", "broadcast", "react", "upload_file", "download_file", "edit", "poll", "delete", "pin"}

	for _, provider := range providers {
		for _, action := range actions {
			t.Run(provider+"_"+action, func(t *testing.T) {
				got, err := NormalizeMessageWrite(provider, " C123 ", action, "hello")
				if err != nil {
					t.Fatalf("normalize failed: %v", err)
				}
				if got.Provider != provider {
					t.Fatalf("provider = %q, want %q", got.Provider, provider)
				}
				if got.Action != action {
					t.Fatalf("action = %q, want %q", got.Action, action)
				}
				if got.ChannelID != "C123" {
					t.Fatalf("channelID = %q, want C123", got.ChannelID)
				}
				if got.Labels["channel_action"] != provider+"."+action {
					t.Fatalf("channel_action label = %q", got.Labels["channel_action"])
				}
				assertHasTag(t, got.RiskTags, "messaging")
				assertHasTag(t, got.RiskTags, "external")
			})
		}
	}
}

func TestNormalizeMessageWriteAliasesAndRiskTags(t *testing.T) {
	got, err := NormalizeMessageWrite("MS Teams", "room-1", "file-upload", "preview")
	if err != nil {
		t.Fatalf("normalize failed: %v", err)
	}
	if got.Provider != "msteams" {
		t.Fatalf("provider = %q, want msteams", got.Provider)
	}
	if got.Action != "upload_file" {
		t.Fatalf("action = %q, want upload_file", got.Action)
	}
	assertHasTag(t, got.RiskTags, "write")
	assertHasTag(t, got.RiskTags, "exfil-risk")
	if got.Labels["channel_provider"] != "msteams" || got.Labels["channel_action"] != "msteams.upload_file" {
		t.Fatalf("unexpected labels: %#v", got.Labels)
	}
}

func TestNormalizeMessageWriteDestructiveAndReadRiskTags(t *testing.T) {
	deleteAction, err := NormalizeMessageWrite("slack", "C123", "delete", "delete it")
	if err != nil {
		t.Fatalf("normalize delete failed: %v", err)
	}
	assertHasTag(t, deleteAction.RiskTags, "destructive")
	assertHasTag(t, deleteAction.RiskTags, "write")

	downloadAction, err := NormalizeMessageWrite("slack", "C123", "download_file", "download it")
	if err != nil {
		t.Fatalf("normalize download failed: %v", err)
	}
	assertHasTag(t, downloadAction.RiskTags, "read")
	assertHasTag(t, downloadAction.RiskTags, "exfil-risk")
}

func TestNormalizeMessageWriteTypedErrors(t *testing.T) {
	tests := []struct {
		name string
		err  ChannelErrorKind
		args []string
	}{
		{name: "provider", err: ErrUnknownProvider, args: []string{"unknown", "C123", "send"}},
		{name: "channel", err: ErrMissingChannelID, args: []string{"slack", "   ", "send"}},
		{name: "action", err: ErrUnknownAction, args: []string{"slack", "C123", "nuke"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NormalizeMessageWrite(tt.args[0], tt.args[1], tt.args[2], "hello")
			var channelErr *ChannelError
			if !errors.As(err, &channelErr) {
				t.Fatalf("expected ChannelError, got %T %v", err, err)
			}
			if channelErr.Kind != tt.err {
				t.Fatalf("kind = %q, want %q", channelErr.Kind, tt.err)
			}
		})
	}
}

func assertHasTag(t *testing.T, tags []string, want string) {
	t.Helper()
	for _, tag := range tags {
		if tag == want {
			return
		}
	}
	t.Fatalf("expected tag %q in %v", want, tags)
}
