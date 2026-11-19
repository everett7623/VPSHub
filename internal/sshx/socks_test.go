package sshx

import "testing"

func TestParseSocksProxy(t *testing.T) {
	got, err := ParseSocksProxy("127.0.0.1:1080")
	if err != nil || got != "127.0.0.1:1080" {
		t.Fatalf("got %q %v", got, err)
	}
	got, err = ParseSocksProxy(" [::1]:1080 ")
	if err != nil || got != "[::1]:1080" {
		t.Fatalf("ipv6 got %q %v", got, err)
	}
	if _, err := ParseSocksProxy(""); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"socks5://127.0.0.1:1080", "user:pass@127.0.0.1:1080", "127.0.0.1", "127.0.0.1:0"} {
		if _, err := ParseSocksProxy(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}
