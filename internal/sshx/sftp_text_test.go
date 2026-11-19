package sshx

import "testing"

func TestInspectText(t *testing.T) {
	text, sum, err := InspectText([]byte("hello\n"))
	if err != nil || text != "hello\n" || len(sum) != 64 {
		t.Fatalf("%q %s %v", text, sum, err)
	}
	if _, _, err := InspectText([]byte{'a', 0, 'b'}); err == nil {
		t.Fatal("binary accepted")
	}
	big := make([]byte, textMax+1)
	if _, _, err := InspectText(big); err == nil {
		t.Fatal("oversize accepted")
	}
}
