package services

import (
	"encoding/json"
	"sort"
)

// Impact describes dependency edges for a module or service type.
type Impact struct {
	Name         string   `json:"name"`
	DependsOn    []string `json:"depends_on"`
	DependedOnBy []string `json:"depended_on_by"`
}

// ServiceImpact returns what name depends on, and which registered modules depend on name.
// name may be a module key (nginx) or a dependency label (docker, certificates).
func ServiceImpact(name string) Impact {
	out := Impact{Name: name, DependsOn: []string{}, DependedOnBy: []string{}}
	if m, ok := Registry[name]; ok {
		if len(m.Dependencies) > 0 {
			out.DependsOn = append([]string{}, m.Dependencies...)
		}
	}
	seen := map[string]struct{}{}
	for key, m := range Registry {
		for _, d := range m.Dependencies {
			if d == name {
				if _, ok := seen[key]; !ok {
					seen[key] = struct{}{}
					out.DependedOnBy = append(out.DependedOnBy, key)
				}
			}
		}
	}
	sort.Strings(out.DependsOn)
	sort.Strings(out.DependedOnBy)
	return out
}

// TemplateImpact merges registry impact for serviceType with a template dependencies JSON array.
func TemplateImpact(serviceType, depsJSON string) Impact {
	out := ServiceImpact(serviceType)
	var extra []string
	_ = json.Unmarshal([]byte(depsJSON), &extra)
	seen := map[string]struct{}{}
	for _, d := range out.DependsOn {
		seen[d] = struct{}{}
	}
	for _, d := range extra {
		if d == "" {
			continue
		}
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		out.DependsOn = append(out.DependsOn, d)
	}
	sort.Strings(out.DependsOn)
	return out
}
