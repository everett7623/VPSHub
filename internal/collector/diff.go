package collector

import (
	"encoding/json"
	"sort"
	"strings"
)

// FieldChange is one difference between two scan payloads.
type FieldChange struct {
	Field  string `json:"field"`
	Before string `json:"before"`
	After  string `json:"after"`
}

var scalarFields = []string{
	"os_id", "os_version", "kernel", "docker_version", "compose_version", "need_reboot",
	"loadavg", "mem_avail_kb", "disk",
}

var setFields = []string{"ports", "systemd_running", "containers", "config_sha256", "systemd_failed"}

// DiffPayloads compares two scan JSON documents. List order is newest-last in the inputs:
// before is the older scan, after is the newer one.
func DiffPayloads(before, after string) ([]FieldChange, error) {
	var a, b map[string]any
	if err := json.Unmarshal([]byte(before), &a); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(after), &b); err != nil {
		return nil, err
	}
	var out []FieldChange
	for _, f := range scalarFields {
		bs, as := stringify(a[f]), stringify(b[f])
		if bs != as {
			out = append(out, FieldChange{Field: f, Before: bs, After: as})
		}
	}
	for _, f := range setFields {
		removed, added := setDelta(stringify(a[f]), stringify(b[f]))
		if removed != "" || added != "" {
			out = append(out, FieldChange{Field: f, Before: removed, After: added})
		}
	}
	return out, nil
}

func stringify(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	default:
		b, _ := json.Marshal(t)
		return string(b)
	}
}

func setDelta(before, after string) (removed, added string) {
	b := splitSet(before)
	a := splitSet(after)
	var gone, came []string
	for k := range b {
		if _, ok := a[k]; !ok {
			gone = append(gone, k)
		}
	}
	for k := range a {
		if _, ok := b[k]; !ok {
			came = append(came, k)
		}
	}
	sort.Strings(gone)
	sort.Strings(came)
	return strings.Join(gone, ";"), strings.Join(came, ";")
}

func splitSet(s string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, p := range strings.Split(s, ";") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out[p] = struct{}{}
	}
	return out
}
