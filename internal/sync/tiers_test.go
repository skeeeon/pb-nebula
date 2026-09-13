package sync

import (
	"slices"
	"testing"

	"github.com/pocketbase/pocketbase/core"
)

// hostRecordPair builds two detached host records with the real field types, so
// the comparison is exercised against what PocketBase actually stores rather
// than against strings that happen to look right.
func hostRecordPair(t *testing.T, before, after map[string]any) (*core.Record, *core.Record) {
	t.Helper()
	collection := core.NewBaseCollection("nebula_hosts")
	collection.Fields.Add(
		&core.TextField{Name: "hostname", Max: 100},
		&core.TextField{Name: "overlay_ip", Max: 50},
		&core.JSONField{Name: "groups"},
		&core.JSONField{Name: "unsafe_networks"},
		&core.JSONField{Name: "unsafe_routes"},
		&core.BoolField{Name: "is_lighthouse"},
		&core.BoolField{Name: "is_relay"},
		&core.TextField{Name: "public_host_port", Max: 100},
		&core.JSONField{Name: "firewall_outbound"},
		&core.JSONField{Name: "firewall_inbound"},
		&core.NumberField{Name: "mtu"},
		&core.TextField{Name: "tun_device", Max: 15},
		&core.JSONField{Name: "preferred_ranges"},
	)

	build := func(fields map[string]any) *core.Record {
		r := core.NewRecord(collection)
		for k, v := range fields {
			r.Set(k, v)
		}
		return r
	}
	return build(before), build(after)
}

// TestChangedFieldsDetectsEveryFieldType is the guard that makes the tier
// tables safe to compare through GetString.
//
// The tables are what a new host field gets slotted into, and the failure mode
// of a comparison that silently never fires is the worst one available: a field
// that looks edited in the Admin UI and reaches no certificate and no config.
// Bools and numbers are the cases worth proving, because "compare everything as
// a string" is only correct if PocketBase renders them the way this assumes.
func TestChangedFieldsDetectsEveryFieldType(t *testing.T) {
	tests := []struct {
		name   string
		before map[string]any
		after  map[string]any
		fields []string
		want   []string
	}{
		{
			name:   "text field",
			before: map[string]any{"hostname": "web-01"},
			after:  map[string]any{"hostname": "web-02"},
			fields: certFields,
			want:   []string{"hostname"},
		},
		{
			// The type that would silently break a naive string comparison.
			name:   "bool field false to true",
			before: map[string]any{"is_relay": false},
			after:  map[string]any{"is_relay": true},
			fields: configFields,
			want:   []string{"is_relay"},
		},
		{
			// And back again -- the direction that shipped broken once, where
			// a host kept am_relay: true after the flag was cleared.
			name:   "bool field true to false",
			before: map[string]any{"is_relay": true},
			after:  map[string]any{"is_relay": false},
			fields: configFields,
			want:   []string{"is_relay"},
		},
		{
			name:   "number field",
			before: map[string]any{"mtu": 1300},
			after:  map[string]any{"mtu": 9000},
			fields: configFields,
			want:   []string{"mtu"},
		},
		{
			// An unset number and an explicit zero both mean "inherit the
			// default", and must not read as a change.
			name:   "number field unset versus zero",
			before: map[string]any{},
			after:  map[string]any{"mtu": 0},
			fields: configFields,
			want:   nil,
		},
		{
			name:   "json field",
			before: map[string]any{"groups": `["web"]`},
			after:  map[string]any{"groups": `["web","ssh"]`},
			fields: certFields,
			want:   []string{"groups"},
		},
		{
			name:   "no change",
			before: map[string]any{"hostname": "web-01", "overlay_ip": "10.128.0.5"},
			after:  map[string]any{"hostname": "web-01", "overlay_ip": "10.128.0.5"},
			fields: certFields,
			want:   nil,
		},
		{
			// Reported in table order, so the log line reads the same way twice.
			name:   "several at once",
			before: map[string]any{"is_lighthouse": false, "public_host_port": "", "tun_device": ""},
			after:  map[string]any{"is_lighthouse": true, "public_host_port": "1.2.3.4:4242", "tun_device": "neb0"},
			fields: configFields,
			want:   []string{"is_lighthouse", "public_host_port", "tun_device"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orig, record := hostRecordPair(t, tt.before, tt.after)
			got := changedFields(orig, record, tt.fields)
			if !slices.Equal(got, tt.want) {
				t.Errorf("changedFields() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestTiersAreDisjointAndComplete pins the two properties the tables exist to
// guarantee.
//
// A field in both tiers would re-issue a certificate for a config-only edit,
// which is the expensive mistake. A field in neither is the silent one: it
// would look editable and reach nothing. The literal list here is deliberately
// a second copy -- adding a field to a tier without deciding it belongs there
// should fail a test, not pass by construction.
func TestTiersAreDisjointAndComplete(t *testing.T) {
	for _, field := range certFields {
		if slices.Contains(configFields, field) {
			t.Errorf("%q is in both tiers; a config-only edit would re-issue a certificate", field)
		}
	}

	want := []string{
		// Certificate tier
		"hostname", "overlay_ip", "groups", "unsafe_networks",
		// Config tier
		"is_lighthouse", "is_relay", "public_host_port",
		"firewall_outbound", "firewall_inbound", "mtu", "tun_device", "unsafe_routes",
		"preferred_ranges",
	}

	got := append(append([]string{}, certFields...), configFields...)
	slices.Sort(got)
	slices.Sort(want)

	if !slices.Equal(got, want) {
		t.Errorf("tier membership changed.\n got: %v\nwant: %v\n"+
			"If this is deliberate, update the list here after deciding which tier the field belongs in "+
			"-- and remember a fan-out field needs a config-tier entry too.", got, want)
	}
}
