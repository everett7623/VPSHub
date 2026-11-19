package alert

import (
	"log/slog"
	"testing"

	"github.com/evenfrank/vpshub/internal/config"
)

func TestNotifyEmptyChannelsNoPanic(t *testing.T) {
	s := &Service{Cfg: config.Default(), Log: slog.Default()}
	s.notify("test", "info", "hello", nil)
	s.notify("test", "info", "hello", []string{"webhook"})
}
