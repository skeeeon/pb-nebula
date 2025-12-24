package pbnebula

import (
	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/core"
	"github.com/skeeeon/pb-nebula/internal/collections"
	"github.com/skeeeon/pb-nebula/internal/hooks"
)

// Setup initializes the Nebula management system
func Setup(app *pocketbase.PocketBase, opts Options) error {
	// 1. Initialize Collections on Bootstrap
	app.OnBootstrap().BindFunc(func(e *core.BootstrapEvent) error {
		if err := e.Next(); err != nil {
			return err
		}

		cm := collections.NewManager(app)
		if err := cm.InitializeCollections(); err != nil {
			return err
		}
		
		return nil
	})

	// 2. Register Hooks
	hm := hooks.NewManager(app)
	hm.Register()

	return nil
}
