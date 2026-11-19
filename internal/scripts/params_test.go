package scripts

import "testing"

func TestBuildScriptEnvSchema(t *testing.T) {
	schema := `[{"name":"TARGET","required":true},{"name":"MODE"}]`
	env, err := BuildScriptEnv(schema, map[string]string{"TARGET": "/opt/app", "MODE": "check"})
	if err != nil {
		t.Fatal(err)
	}
	if env["TARGET"] != "/opt/app" || env["MODE"] != "check" {
		t.Fatalf("%#v", env)
	}
	if _, err := BuildScriptEnv(schema, map[string]string{"MODE": "x"}); err == nil {
		t.Fatal("required missing")
	}
	if _, err := BuildScriptEnv(schema, map[string]string{"TARGET": "a", "EVIL": "1"}); err == nil {
		t.Fatal("unknown param")
	}
	if _, err := BuildScriptEnv("[]", map[string]string{"A": "1"}); err == nil {
		t.Fatal("empty schema must reject params")
	}
	env, err = BuildScriptEnv(`["MSG"]`, map[string]string{"MSG": "hi"})
	if err != nil || env["MSG"] != "hi" {
		t.Fatalf("%v %#v", err, env)
	}
}
