package sync

import (
	"errors"
	"testing"

	"github.com/pocketbase/pocketbase/core"
	"github.com/skeeeon/pb-nebula/internal/types"
)

func hostRecord(active, renew bool) *core.Record {
	collection := core.NewBaseCollection("nebula_hosts")
	collection.Fields.Add(
		&core.TextField{Name: "hostname"},
		&core.BoolField{Name: "active"},
		&core.BoolField{Name: "renew"},
	)
	record := core.NewRecord(collection)
	record.Set("hostname", "h1")
	record.Set("active", active)
	record.Set("renew", renew)
	return record
}

// TestCheckHostRenew pins which saves count as a renew request on an inactive
// host. The live tests in the root package prove the refusal reaches a caller;
// this pins the edges, in particular the one that must NOT be refused: a
// deactivation that carries a renew left set by a failed regeneration. Refusing
// that would refuse the revocation itself.
func TestCheckHostRenew(t *testing.T) {
	tests := []struct {
		name     string
		original *core.Record
		record   *core.Record
		refused  bool
	}{
		{"renew on an inactive host", hostRecord(false, false), hostRecord(false, true), true},
		{"renew in the save that deactivates", hostRecord(true, false), hostRecord(false, true), true},
		{"renew on an active host", hostRecord(true, false), hostRecord(true, true), false},
		{"renew in the save that reactivates", hostRecord(false, false), hostRecord(true, true), false},
		{"deactivation carrying a stale renew", hostRecord(true, true), hostRecord(false, true), false},
		{"inactive host, no renew", hostRecord(false, false), hostRecord(false, false), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkHostRenew(tt.record, tt.original)
			if refused := err != nil; refused != tt.refused {
				t.Fatalf("refused = %v (%v), want %v", refused, err, tt.refused)
			}
			if tt.refused && !errors.Is(err, types.ErrHostInactive) {
				t.Fatalf("refusal %v does not wrap ErrHostInactive", err)
			}
		})
	}
}
