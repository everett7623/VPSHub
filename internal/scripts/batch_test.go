package scripts

import (
	"testing"

	"github.com/evenfrank/vpshub/internal/store"
)

func TestCanBatch(t *testing.T) {
	sc := &store.Script{Status: "approved", AllowBatch: false}
	if err := CanBatch(sc, 1); err != nil {
		t.Fatal(err)
	}
	if err := CanBatch(sc, 2); err == nil {
		t.Fatal("batch without allow_batch")
	}
	sc.AllowBatch = true
	if err := CanBatch(sc, 5); err != nil {
		t.Fatal(err)
	}
}
