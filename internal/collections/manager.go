package collections

import (
	"fmt"

	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/types"
	pbtypes "github.com/skeeeon/pb-nebula/internal/types"
)

type Manager struct {
	app *pocketbase.PocketBase
}

func NewManager(app *pocketbase.PocketBase) *Manager {
	return &Manager{app: app}
}

func (m *Manager) InitializeCollections() error {
	if err := m.createAuthorities(); err != nil {
		return err
	}
	if err := m.createGroups(); err != nil {
		return err
	}
	// Groups and Authorities must exist before Nodes/Rules due to relations
	if err := m.createNodes(); err != nil {
		return err
	}
	if err := m.createRules(); err != nil {
		return err
	}
	return nil
}

func (m *Manager) createAuthorities() error {
	if _, err := m.app.FindCollectionByNameOrId(pbtypes.DefaultAuthorityCollection); err == nil {
		return nil
	}

	col := core.NewBaseCollection(pbtypes.DefaultAuthorityCollection)
	col.ListRule = types.Pointer("@request.auth.id != ''") // Only auth users
	
	col.Fields.Add(&core.TextField{Name: "name", Required: true})
	col.Fields.Add(&core.TextField{Name: "cidr", Required: true}) // e.g. 10.0.0.0/24
	col.Fields.Add(&core.NumberField{Name: "port", Required: true})
	col.Fields.Add(&core.TextField{Name: "ca_public_key"})
	col.Fields.Add(&core.TextField{Name: "ca_private_key"}) // Protected in real app, accessible for now

	return m.app.Save(col)
}

func (m *Manager) createGroups() error {
	if _, err := m.app.FindCollectionByNameOrId(pbtypes.DefaultGroupCollection); err == nil {
		return nil
	}

	authCol, _ := m.app.FindCollectionByNameOrId(pbtypes.DefaultAuthorityCollection)

	col := core.NewBaseCollection(pbtypes.DefaultGroupCollection)
	col.ListRule = types.Pointer("@request.auth.id != ''")

	col.Fields.Add(&core.TextField{Name: "name", Required: true})
	col.Fields.Add(&core.RelationField{
		Name: "authority_id", CollectionId: authCol.Id, Required: true, MaxSelect: 1,
	})

	return m.app.Save(col)
}

func (m *Manager) createNodes() error {
	if _, err := m.app.FindCollectionByNameOrId(pbtypes.DefaultNodeCollection); err == nil {
		return nil
	}

	authCol, _ := m.app.FindCollectionByNameOrId(pbtypes.DefaultAuthorityCollection)
	groupCol, _ := m.app.FindCollectionByNameOrId(pbtypes.DefaultGroupCollection)

	col := core.NewAuthCollection(pbtypes.DefaultNodeCollection)
	// Nodes can view themselves and their authority info
	col.ListRule = types.Pointer("@request.auth.id = id") 
	col.ViewRule = types.Pointer("@request.auth.id = id")

	col.Fields.Add(&core.RelationField{
		Name: "authority_id", CollectionId: authCol.Id, Required: true, MaxSelect: 1,
	})
	col.Fields.Add(&core.RelationField{
		Name: "groups", CollectionId: groupCol.Id, MaxSelect: 99,
	})
	
	col.Fields.Add(&core.TextField{Name: "ip_address"}) // Auto-assigned if empty
	col.Fields.Add(&core.BoolField{Name: "is_lighthouse"})
	col.Fields.Add(&core.JSONField{Name: "static_ips"}) // For lighthouses: ["1.2.3.4"]
	col.Fields.Add(&core.JSONField{Name: "subnets"})    // Unsafe routes
	
	// Crypto fields
	col.Fields.Add(&core.TextField{Name: "public_key"})
	col.Fields.Add(&core.TextField{Name: "private_key"})
	col.Fields.Add(&core.TextField{Name: "certificate"})
	
	// Generated Config
	col.Fields.Add(&core.TextField{Name: "config"})
	
	// Triggers
	col.Fields.Add(&core.BoolField{Name: "regenerate"})
	col.Fields.Add(&core.BoolField{Name: "active"})

	// Unique constraint on IP within an Authority is crucial
	// PocketBase doesn't support composite unique indexes via Go API easily yet, 
	// typically enforced via Hooks or raw SQL. We will enforce via Hooks.

	return m.app.Save(col)
}

func (m *Manager) createRules() error {
	if _, err := m.app.FindCollectionByNameOrId(pbtypes.DefaultRuleCollection); err == nil {
		return nil
	}

	authCol, _ := m.app.FindCollectionByNameOrId(pbtypes.DefaultAuthorityCollection)
	groupCol, _ := m.app.FindCollectionByNameOrId(pbtypes.DefaultGroupCollection)

	col := core.NewBaseCollection(pbtypes.DefaultRuleCollection)
	col.ListRule = types.Pointer("@request.auth.id != ''")

	col.Fields.Add(&core.RelationField{
		Name: "authority_id", CollectionId: authCol.Id, Required: true, MaxSelect: 1,
	})
	col.Fields.Add(&core.SelectField{
		Name: "direction", Values: []string{"inbound", "outbound"}, Required: true, MaxSelect: 1,
	})
	col.Fields.Add(&core.SelectField{
		Name: "proto", Values: []string{"tcp", "udp", "icmp", "any"}, Required: true, MaxSelect: 1,
	})
	col.Fields.Add(&core.TextField{Name: "port", Required: true}) // "80", "any"
	
	col.Fields.Add(&core.RelationField{
		Name: "source_groups", CollectionId: groupCol.Id, MaxSelect: 99,
	})
	col.Fields.Add(&core.RelationField{
		Name: "dest_groups", CollectionId: groupCol.Id, MaxSelect: 99,
	})
	col.Fields.Add(&core.TextField{Name: "ca_name"})

	return m.app.Save(col)
}
