package collector

import "testing"

func TestDiffPayloads(t *testing.T) {
	before := `{"kernel":"6.1","ports":"tcp,1.2.3.4:22;tcp,1.2.3.4:80","systemd_running":"nginx.service;ssh.service","need_reboot":false,"config_sha256":"/etc/nginx/nginx.conf=aaa;","mem_avail_kb":1000}`
	after := `{"kernel":"6.6","ports":"tcp,1.2.3.4:22;tcp,1.2.3.4:443","systemd_running":"nginx.service;ssh.service","need_reboot":true,"config_sha256":"/etc/nginx/nginx.conf=bbb;","mem_avail_kb":900}`
	ch, err := DiffPayloads(before, after)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]FieldChange{}
	for _, c := range ch {
		got[c.Field] = c
	}
	if got["kernel"].After != "6.6" || got["kernel"].Before != "6.1" {
		t.Fatalf("kernel: %+v", got["kernel"])
	}
	if got["ports"].Before != "tcp,1.2.3.4:80" || got["ports"].After != "tcp,1.2.3.4:443" {
		t.Fatalf("ports: %+v", got["ports"])
	}
	if got["need_reboot"].After != "true" {
		t.Fatalf("reboot: %+v", got["need_reboot"])
	}
	if got["config_sha256"].Before != "/etc/nginx/nginx.conf=aaa" || got["config_sha256"].After != "/etc/nginx/nginx.conf=bbb" {
		t.Fatalf("config_sha256: %+v", got["config_sha256"])
	}
	if got["mem_avail_kb"].Before != "1000" || got["mem_avail_kb"].After != "900" {
		t.Fatalf("mem: %+v", got["mem_avail_kb"])
	}
	if _, ok := got["systemd_running"]; ok {
		t.Fatal("unchanged systemd should be omitted")
	}
}
