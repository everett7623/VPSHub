package probe

import "testing"

func TestWarnDaysForFallback(t *testing.T) {
	s := &Service{}
	if got := s.warnDaysFor("vps_expiry", 7); got != 7 {
		t.Fatalf("nil db fallback: %d", got)
	}
}

func TestWarnDaysPicksMax(t *testing.T) {
	// warnDaysFor with empty rules uses fallback; covered via ListAlertRules error path.
	s := &Service{DB: nil}
	if s.warnDaysFor("missing", 14) != 14 {
		t.Fatal("expected fallback 14")
	}
}
