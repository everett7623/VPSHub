package services

import "testing"

func TestServiceImpactNginxDocker(t *testing.T) {
	n := ServiceImpact("nginx")
	if len(n.DependsOn) == 0 || n.DependsOn[0] != "docker" {
		t.Fatalf("nginx should depend on docker: %#v", n)
	}
	d := ServiceImpact("docker")
	found := false
	for _, x := range d.DependedOnBy {
		if x == "nginx" {
			found = true
		}
	}
	if !found {
		t.Fatalf("docker should list nginx as dependent: %#v", d)
	}
	x := ServiceImpact("certificates")
	found = false
	for _, n := range x.DependedOnBy {
		if n == "xray" {
			found = true
		}
	}
	if !found {
		t.Fatalf("certificates should list xray: %#v", x)
	}
}

func TestTemplateImpactMergesDeps(t *testing.T) {
	imp := TemplateImpact("nginx", `["certificates","custom-dep"]`)
	want := map[string]bool{"docker": true, "certificates": true, "custom-dep": true}
	for _, d := range imp.DependsOn {
		delete(want, d)
	}
	if len(want) != 0 {
		t.Fatalf("missing deps %v in %#v", want, imp.DependsOn)
	}
}
