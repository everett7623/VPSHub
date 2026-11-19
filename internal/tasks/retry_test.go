package tasks

import "testing"

func TestRetryTries(t *testing.T) {
	cases := []struct {
		retryMax int
		want     int
	}{
		{0, 1},
		{1, 2},
		{3, 4},
		{20, 10},
		{-1, 1},
	}
	for _, c := range cases {
		if got := retryTries(c.retryMax); got != c.want {
			t.Fatalf("retryTries(%d)=%d want %d", c.retryMax, got, c.want)
		}
	}
}
