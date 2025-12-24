package main

import (
	"log"
	"os"

	"github.com/pocketbase/pocketbase"
	"github.com/skeeeon/pb-nebula"
)

// This example demonstrates basic pb-nebula setup with default options.
// The application will:
// 1. Create Nebula collections on first run
// 2. Automatically generate CA certificates when created
// 3. Automatically generate host certificates and configs
// 4. Regenerate configs when networks or hosts are updated
//
// USAGE:
//   go run main.go serve
//
// WORKFLOW:
//   1. Access admin UI: http://127.0.0.1:8090/_/
//   2. Create CA record (certificate generated automatically)
//   3. Create network with CIDR range
//   4. Create lighthouse host (with public_host_port)
//   5. Create regular hosts (configs reference lighthouse)
//   6. Hosts authenticate and download their config_yaml
//
// TESTING:
//   # Create CA via API
//   curl -X POST http://127.0.0.1:8090/api/collections/nebula_ca/records \
//     -H "Content-Type: application/json" \
//     -u "admin@example.com:password123" \
//     -d '{"name":"my-ca","validity_years":10}'
//
//   # Create network
//   curl -X POST http://127.0.0.1:8090/api/collections/nebula_networks/records \
//     -H "Content-Type: application/json" \
//     -u "admin@example.com:password123" \
//     -d '{"name":"prod","cidr_range":"10.128.0.0/16","ca_id":"<ca_id>","active":true}'
//
//   # Create lighthouse
//   curl -X POST http://127.0.0.1:8090/api/collections/nebula_hosts/records \
//     -H "Content-Type: application/json" \
//     -u "admin@example.com:password123" \
//     -d '{"email":"lh@example.com","password":"secure123","hostname":"lighthouse-01","network_id":"<network_id>","overlay_ip":"10.128.0.1","groups":["lighthouse"],"is_lighthouse":true,"public_host_port":"1.2.3.4:4242","validity_years":1}'
//
//   # Create regular host
//   curl -X POST http://127.0.0.1:8090/api/collections/nebula_hosts/records \
//     -H "Content-Type: application/json" \
//     -u "admin@example.com:password123" \
//     -d '{"email":"web01@example.com","password":"secure123","hostname":"web-01","network_id":"<network_id>","overlay_ip":"10.128.0.100","groups":["web"],"is_lighthouse":false,"validity_years":1}'
func main() {
	// Create PocketBase app
	app := pocketbase.New()

	// Configure pb-nebula with defaults
	options := pbnebula.DefaultOptions()
	options.LogToConsole = true // Enable logging for visibility

	// Optional: Customize collection names
	// options.CACollectionName = "my_ca"
	// options.NetworkCollectionName = "my_networks"
	// options.HostCollectionName = "my_hosts"

	// Optional: Customize validity periods
	// options.DefaultCAValidityYears = 20
	// options.DefaultHostValidityYears = 2

	// Optional: Filter events (e.g., disable network update regeneration)
	// options.EventFilter = func(collectionName, eventType string) bool {
	//     if eventType == pbnebula.EventTypeNetworkUpdate {
	//         return false // Don't regenerate on network updates
	//     }
	//     return true
	// }

	// Initialize pb-nebula
	if err := pbnebula.Setup(app, options); err != nil {
		log.Fatal("Failed to setup pb-nebula:", err)
	}

	// Start PocketBase
	if err := app.Start(); err != nil {
		log.Fatal("Failed to start PocketBase:", err)
	}
}

// Example: Advanced usage with custom event handling
func advancedExample() {
	app := pocketbase.New()

	options := pbnebula.DefaultOptions()
	options.LogToConsole = true

	// Custom event filter - only regenerate configs during business hours
	options.EventFilter = func(collectionName, eventType string) bool {
		// Check if current hour is within business hours (9 AM - 5 PM)
		// This could prevent excessive regeneration during peak hours
		// (Note: This is just an example, adjust logic as needed)
		return true
	}

	if err := pbnebula.Setup(app, options); err != nil {
		log.Fatal(err)
	}

	// Add custom routes or hooks here if needed
	// app.OnBeforeServe().Add(func(e *core.ServeEvent) error {
	//     // Custom logic
	//     return nil
	// })

	if err := app.Start(); err != nil {
		log.Fatal(err)
	}
}

// Example: Minimal setup (one-liner)
func minimalExample() {
	app := pocketbase.New()

	// Single line setup with defaults
	if err := pbnebula.Setup(app, pbnebula.DefaultOptions()); err != nil {
		log.Fatal(err)
	}

	if err := app.Start(); err != nil {
		log.Fatal(err)
	}
}

// Example: Custom collection names for multi-tenant setup
func multiTenantExample() {
	app := pocketbase.New()

	// Setup multiple Nebula instances with different collection prefixes
	// Tenant 1
	options1 := pbnebula.DefaultOptions()
	options1.CACollectionName = "tenant1_nebula_ca"
	options1.NetworkCollectionName = "tenant1_nebula_networks"
	options1.HostCollectionName = "tenant1_nebula_hosts"
	if err := pbnebula.Setup(app, options1); err != nil {
		log.Fatal(err)
	}

	// Tenant 2
	options2 := pbnebula.DefaultOptions()
	options2.CACollectionName = "tenant2_nebula_ca"
	options2.NetworkCollectionName = "tenant2_nebula_networks"
	options2.HostCollectionName = "tenant2_nebula_hosts"
	if err := pbnebula.Setup(app, options2); err != nil {
		log.Fatal(err)
	}

	if err := app.Start(); err != nil {
		log.Fatal(err)
	}
}

// init is called before main, useful for environment setup
func init() {
	// Example: Set default data directory if not specified
	if os.Getenv("PB_DATA_DIR") == "" {
		os.Setenv("PB_DATA_DIR", "./pb_data")
	}
}
