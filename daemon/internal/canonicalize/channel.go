package canonicalize

import (
	"fmt"
	"sort"
	"strings"
)

type ChannelErrorKind string

const (
	ErrUnknownProvider  ChannelErrorKind = "unknown_provider"
	ErrUnknownAction    ChannelErrorKind = "unknown_action"
	ErrMissingChannelID ChannelErrorKind = "missing_channel_id"
)

type ChannelError struct {
	Kind      ChannelErrorKind
	Provider  string
	Action    string
	ChannelID string
}

func (e *ChannelError) Error() string {
	switch e.Kind {
	case ErrUnknownProvider:
		return fmt.Sprintf("unsupported channel provider: %s", e.Provider)
	case ErrUnknownAction:
		return fmt.Sprintf("unsupported channel action: provider=%s action=%s", e.Provider, e.Action)
	case ErrMissingChannelID:
		return fmt.Sprintf("before_message_write envelope missing channel_id provider=%s action=%s", e.Provider, e.Action)
	default:
		return fmt.Sprintf("invalid channel action provider=%s action=%s", e.Provider, e.Action)
	}
}

type MessageWrite struct {
	Provider       string
	ChannelID      string
	Action         string
	MessagePreview string
	RiskTags       []string
	Labels         map[string]string
}

var providers = map[string]struct{}{
	"feishu":         {},
	"googlechat":     {},
	"msteams":        {},
	"mattermost":     {},
	"matrix":         {},
	"signal":         {},
	"slack":          {},
	"telegram":       {},
	"discord":        {},
	"imessage":       {},
	"whatsapp":       {},
	"nextcloud-talk": {},
	"irc":            {},
}

var actions = map[string][]string{
	"send":          {"write"},
	"broadcast":     {"write", "broadcast"},
	"delete":        {"write", "destructive"},
	"upload_file":   {"write", "exfil-risk"},
	"download_file": {"read", "exfil-risk"},
	"react":         {"write", "reaction"},
	"pin":           {"write", "channel-admin"},
	"edit":          {"write", "destructive"},
	"poll":          {"write", "poll"},
}

func NormalizeMessageWrite(provider string, channelID string, action string, messagePreview string) (MessageWrite, error) {
	normalizedProvider := normalizeProvider(provider)
	normalizedAction := normalizeAction(action)
	normalizedChannelID := strings.TrimSpace(channelID)

	if _, ok := providers[normalizedProvider]; !ok {
		return MessageWrite{}, &ChannelError{Kind: ErrUnknownProvider, Provider: normalizedProvider, Action: normalizedAction, ChannelID: normalizedChannelID}
	}
	if normalizedChannelID == "" {
		return MessageWrite{}, &ChannelError{Kind: ErrMissingChannelID, Provider: normalizedProvider, Action: normalizedAction, ChannelID: normalizedChannelID}
	}
	actionTags, ok := actions[normalizedAction]
	if !ok {
		return MessageWrite{}, &ChannelError{Kind: ErrUnknownAction, Provider: normalizedProvider, Action: normalizedAction, ChannelID: normalizedChannelID}
	}

	tagSet := map[string]struct{}{
		"messaging":                      {},
		"external":                       {},
		"channel_action":                 {},
		"provider:" + normalizedProvider: {},
		"action:" + normalizedAction:     {},
	}
	for _, tag := range actionTags {
		tagSet[tag] = struct{}{}
	}
	riskTags := make([]string, 0, len(tagSet))
	for tag := range tagSet {
		riskTags = append(riskTags, tag)
	}
	sort.Strings(riskTags)

	preview := strings.TrimSpace(messagePreview)
	if len(preview) > 200 {
		preview = preview[:200]
	}

	return MessageWrite{
		Provider:       normalizedProvider,
		ChannelID:      normalizedChannelID,
		Action:         normalizedAction,
		MessagePreview: preview,
		RiskTags:       riskTags,
		Labels: map[string]string{
			"channel_provider": normalizedProvider,
			"channel_id":       normalizedChannelID,
			"channel_action":   normalizedProvider + "." + normalizedAction,
		},
	}, nil
}

func normalizeProvider(provider string) string {
	normalized := strings.ToLower(strings.TrimSpace(provider))
	normalized = strings.NewReplacer("_", "-", " ", "-").Replace(normalized)
	switch normalized {
	case "google-chat":
		return "googlechat"
	case "ms-teams", "teams":
		return "msteams"
	case "i-message":
		return "imessage"
	case "whats-app":
		return "whatsapp"
	case "nextcloudtalk", "nextcloud-talk":
		return "nextcloud-talk"
	default:
		return normalized
	}
}

func normalizeAction(action string) string {
	normalized := strings.ToLower(strings.TrimSpace(action))
	normalized = strings.NewReplacer("-", "_", " ", "_").Replace(normalized)
	switch normalized {
	case "send_message", "message", "reply":
		return "send"
	case "broadcast_message":
		return "broadcast"
	case "upload", "file_upload", "attach", "attachment":
		return "upload_file"
	case "download", "file_download":
		return "download_file"
	case "reaction":
		return "react"
	case "delete_message", "remove", "destroy":
		return "delete"
	case "edit_message":
		return "edit"
	case "create_poll", "poll_create":
		return "poll"
	default:
		return normalized
	}
}
