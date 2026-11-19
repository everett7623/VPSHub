package scripts

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ParamDef is one entry in a script's params_schema JSON array.
type ParamDef struct {
	Name     string `json:"name"`
	Required bool   `json:"required"`
}

// ParseParamsSchema reads [{"name":"FOO","required":true}, ...] or ["FOO"].
func ParseParamsSchema(raw string) ([]ParamDef, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "[]" {
		return nil, nil
	}
	var objs []ParamDef
	if err := json.Unmarshal([]byte(raw), &objs); err == nil {
		for i := range objs {
			objs[i].Name = sanitizeEnvKey(objs[i].Name)
		}
		var out []ParamDef
		for _, d := range objs {
			if d.Name == "" {
				continue
			}
			out = append(out, d)
		}
		return out, nil
	}
	var names []string
	if err := json.Unmarshal([]byte(raw), &names); err != nil {
		return nil, fmt.Errorf("invalid params_schema")
	}
	var out []ParamDef
	for _, n := range names {
		n = sanitizeEnvKey(n)
		if n == "" {
			continue
		}
		out = append(out, ParamDef{Name: n})
	}
	return out, nil
}

// BuildScriptEnv keeps only keys declared in params_schema.
// Unknown keys are rejected. Values are passed as env via WrapWithEnv (quoted).
func BuildScriptEnv(schemaJSON string, params map[string]string) (map[string]string, error) {
	defs, err := ParseParamsSchema(schemaJSON)
	if err != nil {
		return nil, err
	}
	if len(defs) == 0 {
		if len(params) > 0 {
			return nil, fmt.Errorf("script accepts no parameters")
		}
		return map[string]string{}, nil
	}
	allowed := map[string]ParamDef{}
	for _, d := range defs {
		allowed[d.Name] = d
	}
	out := map[string]string{}
	for k, v := range params {
		key := sanitizeEnvKey(k)
		if key == "" {
			return nil, fmt.Errorf("invalid param name")
		}
		if _, ok := allowed[key]; !ok {
			return nil, fmt.Errorf("unknown param: %s", key)
		}
		out[key] = v
	}
	for _, d := range defs {
		if d.Required {
			if _, ok := out[d.Name]; !ok {
				return nil, fmt.Errorf("missing required param: %s", d.Name)
			}
		}
	}
	return out, nil
}

func sanitizeEnvKey(k string) string {
	k = strings.TrimSpace(k)
	var b strings.Builder
	for _, r := range k {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_':
			b.WriteRune(r)
		default:
			return ""
		}
	}
	s := b.String()
	if s == "" || (s[0] >= '0' && s[0] <= '9') {
		return ""
	}
	return s
}
