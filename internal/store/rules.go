package store

import (
	"encoding/json"
	"strings"
)

// RuleDecision describes how Emit should treat a given alert kind.
type RuleDecision struct {
	// Allow is false when at least one rule of this kind exists and every matching rule is disabled.
	Allow bool
	// Channels is the union of notify_channels from enabled rules; empty means all configured channels.
	Channels []string
	// Threshold is from the first enabled rule that sets it (disk %, mem %, load, etc.).
	Threshold *float64
	// DaysBefore from the first enabled rule (cert/expiry).
	DaysBefore int
}

// DecideAlertRule inspects persisted rules for kind.
// No rules → allow with defaults. Only disabled rules → deny. Else allow with merged channels.
func DecideAlertRule(rules []AlertRule, kind string) RuleDecision {
	d := RuleDecision{Allow: true, DaysBefore: 0}
	var matched, enabledN int
	seen := map[string]struct{}{}
	for _, r := range rules {
		if r.Kind != kind {
			continue
		}
		matched++
		if !r.Enabled {
			continue
		}
		enabledN++
		if d.Threshold == nil && r.Threshold != nil {
			v := *r.Threshold
			d.Threshold = &v
		}
		if d.DaysBefore == 0 && r.DaysBefore > 0 {
			d.DaysBefore = r.DaysBefore
		}
		var ch []string
		_ = json.Unmarshal([]byte(r.NotifyChannels), &ch)
		for _, c := range ch {
			c = strings.ToLower(strings.TrimSpace(c))
			if c == "" || c == "*" {
				continue
			}
			if _, ok := seen[c]; ok {
				continue
			}
			seen[c] = struct{}{}
			d.Channels = append(d.Channels, c)
		}
	}
	if matched > 0 && enabledN == 0 {
		d.Allow = false
	}
	return d
}
