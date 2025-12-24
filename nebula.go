// Package pbnebula provides Nebula mesh VPN certificate and configuration management for PocketBase.
//
// This library enables automatic Nebula overlay network provisioning with PocketBase as the
// certificate authority and host management system. It handles CA generation, host certificate
// signing, and complete Nebula config generation with zero manual intervention.
//
// DESIGN PHILOSOPHY (Grug-Brained):
// - Simple, predictable behavior
// - Automatic certificate generation on record creation
// - Real-time config regeneration on updates
// - No clever optimizations, just straightforward logic
//
// USAGE:
//
//	app := pocketbase.New()
//
//	options := pbnebula.DefaultOptions()
//	options.LogToConsole = true
//
//	if err := pbnebula.Setup(app, options); err != nil {
//	    log.Fatal(err)
//	}
//
//	if err := app.Start(); err != nil {
//	    log.Fatal(err)
//	}
package pbnebula

import (
	"fmt"

	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/core"
	"github.com/skeeeon/pb-nebula/internal/cert"
	"github.com/skeeeon/pb-nebula/internal/collections"
	"github.com/skeeeon/pb-nebula/internal/config"
	"github.com/skeeeon/pb-nebula/internal/ipam"
	"github.com/skeeeon/pb-nebula/internal/sync"
	"github.com/skeeeon/pb-nebula/internal/utils"
)

// Setup initializes pb-nebula with the provided PocketBase application and options.
// This is the main entry point for the library.
//
// INITIALIZATION SEQUENCE:
// 1. Validate and apply default options
// 2. Register OnBootstrap hook for component initialization
// 3. On bootstrap: Create collections → Initialize managers → Setup sync hooks
//
// COMPONENT INITIALIZATION ORDER:
// Collections must exist before managers can use them:
// 1. Collections (CA → Networks → Hosts)
// 2. Certificate manager (stateless)
// 3. Config generator (stateless)
// 4. IPAM manager (needs collections)
// 5. Sync manager (needs all components)
//
// PARAMETERS:
//   - app: PocketBase application instance
//   - options: Configuration options (use DefaultOptions() for sensible defaults)
//
// RETURNS:
// - nil on success
// - error if validation fails or initialization encounters issues
//
// SIDE EFFECTS:
// - Registers PocketBase OnBootstrap hook
// - Creates collections on first run
// - Registers event hooks for automatic certificate/config generation
//
// EXAMPLE:
//
//	app := pocketbase.New()
//	if err := pbnebula.Setup(app, pbnebula.DefaultOptions()); err != nil {
//	    log.Fatal(err)
//	}
func Setup(app *pocketbase.PocketBase, options Options) error {
	// Apply defaults to any missing options
	options = applyDefaultOptions(options)

	// Validate options
	if err := validateOptions(options); err != nil {
		return WrapError(err, "invalid options")
	}

	// Register bootstrap hook for initialization
	app.OnBootstrap().BindFunc(func(e *core.BootstrapEvent) error {
		if err := e.Next(); err != nil {
			return err
		}

		return initializeComponents(app, options)
	})

	return nil
}

// initializeComponents creates and wires together all pb-nebula components.
// This function is called during PocketBase bootstrap.
//
// INITIALIZATION FLOW:
// 1. Create logger for consistent output
// 2. Initialize collections (creates database schema)
// 3. Create stateless managers (cert, config)
// 4. Create stateful manager (IPAM - needs database access)
// 5. Setup sync manager (coordinates everything)
// 6. Register PocketBase hooks (automatic behavior)
//
// PARAMETERS:
//   - app: PocketBase application instance
//   - options: Validated configuration options
//
// RETURNS:
// - nil on successful initialization
// - error if any component fails to initialize
func initializeComponents(app *pocketbase.PocketBase, options Options) error {
	// Create logger for consistent output
	logger := utils.NewLogger(options.LogToConsole)
	logger.Start("Initializing pb-nebula...")

	// Step 1: Initialize collections (must happen first)
	logger.Info("Creating Nebula collections...")
	collectionManager := collections.NewManager(app, options)
	if err := collectionManager.InitializeCollections(); err != nil {
		return WrapError(err, "failed to initialize collections")
	}
	logger.Success("Collections initialized: %s, %s, %s",
		options.CACollectionName,
		options.NetworkCollectionName,
		options.HostCollectionName)

	// Step 2: Create certificate manager (stateless)
	logger.Info("Initializing certificate manager...")
	certManager := cert.NewManager()
	logger.Success("Certificate manager ready")

	// Step 3: Create config generator (stateless)
	logger.Info("Initializing config generator...")
	configGen := config.NewGenerator()
	logger.Success("Config generator ready")

	// Step 4: Create IPAM manager (needs database access)
	logger.Info("Initializing IPAM manager...")
	ipamManager := ipam.NewManager(app, options)
	logger.Success("IPAM manager ready")

	// Step 5: Create sync manager (coordinates all components)
	logger.Info("Initializing sync manager...")
	syncManager := sync.NewManager(app, certManager, configGen, ipamManager, options, logger)
	logger.Success("Sync manager ready")

	// Step 6: Setup PocketBase hooks (automatic behavior)
	logger.Info("Registering PocketBase hooks...")
	if err := syncManager.SetupHooks(); err != nil {
		return WrapError(err, "failed to setup hooks")
	}
	logger.Success("PocketBase hooks registered")

	logger.Success("🎉 pb-nebula initialized successfully!")
	logger.Info("Collections: %s, %s, %s",
		options.CACollectionName,
		options.NetworkCollectionName,
		options.HostCollectionName)
	logger.Info("Default CA validity: %d years", options.DefaultCAValidityYears)
	logger.Info("Default host validity: %d years", options.DefaultHostValidityYears)

	return nil
}

// validateOptions checks that all required options are valid.
// This prevents runtime errors from invalid configuration.
//
// VALIDATION CHECKS:
// - Collection names are not empty
// - Validity periods are positive
// - Collection names don't conflict
//
// PARAMETERS:
//   - options: Options struct to validate
//
// RETURNS:
// - nil if options are valid
// - error describing the first validation failure
func validateOptions(options Options) error {
	// Validate collection names
	if err := ValidateRequired(options.CACollectionName, "CACollectionName"); err != nil {
		return err
	}
	if err := ValidateRequired(options.NetworkCollectionName, "NetworkCollectionName"); err != nil {
		return err
	}
	if err := ValidateRequired(options.HostCollectionName, "HostCollectionName"); err != nil {
		return err
	}

	// Ensure collection names are unique
	if options.CACollectionName == options.NetworkCollectionName ||
		options.CACollectionName == options.HostCollectionName ||
		options.NetworkCollectionName == options.HostCollectionName {
		return fmt.Errorf("collection names must be unique")
	}

	// Validate validity periods
	if options.DefaultCAValidityYears <= 0 {
		return fmt.Errorf("DefaultCAValidityYears must be positive, got %d", options.DefaultCAValidityYears)
	}
	if options.DefaultHostValidityYears <= 0 {
		return fmt.Errorf("DefaultHostValidityYears must be positive, got %d", options.DefaultHostValidityYears)
	}

	// Ensure host validity doesn't exceed CA validity
	if options.DefaultHostValidityYears > options.DefaultCAValidityYears {
		return fmt.Errorf("DefaultHostValidityYears (%d) cannot exceed DefaultCAValidityYears (%d)",
			options.DefaultHostValidityYears, options.DefaultCAValidityYears)
	}

	return nil
}
