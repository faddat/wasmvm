package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/CosmWasm/wasmvm/v2/types"
	"github.com/tetratelabs/wazero"
)

// Cache represents a Wazero-based cache for compiled Wasm modules
type Cache struct {
	runtime  wazero.Runtime
	modules  sync.Map // map[string]wazero.CompiledModule
	baseDir  string
	lockfile *os.File
	pinned   sync.Map // map[string]bool
	metrics  types.Metrics
	codes    sync.Map // map[string][]byte
}

// InitCache initializes a new Wazero cache
func InitCache(config types.VMConfig) (*Cache, error) {
	// Create base directory
	err := os.MkdirAll(config.Cache.BaseDir, 0o755)
	if err != nil {
		return nil, fmt.Errorf("could not create base directory: %v", err)
	}

	// Create and lock the lockfile
	lockfile, err := os.OpenFile(filepath.Join(config.Cache.BaseDir, "exclusive.lock"), os.O_WRONLY|os.O_CREATE, 0o666)
	if err != nil {
		return nil, fmt.Errorf("could not open exclusive.lock: %v", err)
	}

	// Create Wazero runtime with memory limits
	// Default to 32 pages (2MiB)
	memoryLimitPages := uint32(32)

	runtimeConfig := wazero.NewRuntimeConfig().
		WithMemoryLimitPages(memoryLimitPages).
		WithCloseOnContextDone(true)

	runtime := wazero.NewRuntimeWithConfig(context.Background(), runtimeConfig)

	cache := &Cache{
		runtime:  runtime,
		baseDir:  config.Cache.BaseDir,
		lockfile: lockfile,
		modules:  sync.Map{},
		codes:    sync.Map{},
		pinned:   sync.Map{},
		metrics: types.Metrics{
			HitsPinnedMemoryCache:     0,
			HitsMemoryCache:           0,
			HitsFsCache:               0,
			Misses:                    0,
			ElementsPinnedMemoryCache: 0,
			ElementsMemoryCache:       0,
			SizePinnedMemoryCache:     0,
			SizeMemoryCache:           0,
		},
	}

	return cache, nil
}

// ReleaseCache releases all resources associated with the cache
func ReleaseCache(cache *Cache) {
	if cache.lockfile != nil {
		cache.lockfile.Close()
	}
	if cache.runtime != nil {
		cache.runtime.Close(context.Background())
	}
}

// createChecksum creates a SHA256 checksum of the Wasm code
func createChecksum(wasm []byte) ([]byte, error) {
	if len(wasm) == 0 {
		return nil, fmt.Errorf("wasm code is empty")
	}
	hash := sha256.Sum256(wasm)
	return hash[:], nil
}

// StoreCode stores a Wasm contract in the cache
func StoreCode(cache Cache, wasm []byte) ([]byte, error) {
	if len(wasm) == 0 {
		return nil, fmt.Errorf("Wasm bytecode could not be deserialized")
	}

	// Check magic number
	if len(wasm) < 4 || !bytes.Equal(wasm[0:4], []byte{0x00, 0x61, 0x73, 0x6D}) {
		return nil, fmt.Errorf("Wasm bytecode could not be deserialized")
	}

	// Calculate checksum
	checksum := sha256.Sum256(wasm)

	// Store original code
	cache.codes.Store(string(checksum[:]), wasm)

	// Compile module
	ctx := context.Background()
	module, err := cache.runtime.CompileModule(ctx, wasm)
	if err != nil {
		return nil, fmt.Errorf("Wasm bytecode could not be deserialized")
	}

	// Store compiled module
	cache.modules.Store(string(checksum[:]), module)

	return checksum[:], nil
}

// StoreCodeUnchecked stores code without validation
func StoreCodeUnchecked(cache Cache, wasm []byte) ([]byte, error) {
	return StoreCode(cache, wasm)
}

// RemoveCode removes code from the cache
func RemoveCode(cache Cache, checksum []byte) error {
	if len(checksum) != 32 {
		return fmt.Errorf("invalid checksum length: expected 32, got %d", len(checksum))
	}

	if _, ok := cache.modules.Load(string(checksum)); !ok {
		return fmt.Errorf("module not found")
	}

	cache.modules.Delete(string(checksum))
	cache.codes.Delete(string(checksum))
	cache.pinned.Delete(string(checksum))

	return nil
}

// GetCode retrieves the original Wasm code by checksum
func GetCode(cache Cache, checksum []byte) ([]byte, error) {
	if code, ok := cache.codes.Load(string(checksum)); ok {
		return code.([]byte), nil
	}
	return nil, fmt.Errorf("code not found for checksum %x", checksum)
}

// Pin pins a module in memory
func Pin(cache Cache, checksum []byte) error {
	if _, ok := cache.modules.Load(string(checksum)); !ok {
		return fmt.Errorf("module not found")
	}
	cache.pinned.Store(string(checksum), true)
	return nil
}

// Unpin unpins a module
func Unpin(cache Cache, checksum []byte) error {
	cache.pinned.Delete(string(checksum))
	return nil
}

// AnalyzeCode performs static analysis of the code
func AnalyzeCode(cache Cache, checksum []byte) (*types.AnalysisReport, error) {
	// Get code from cache
	code, err := GetCode(cache, checksum)
	if err != nil {
		return nil, err
	}

	// Create a temporary instance to analyze exports
	ctx := context.Background()
	config := wazero.NewRuntimeConfig().
		WithMemoryLimitPages(65536).
		WithCloseOnContextDone(true)

	r := wazero.NewRuntimeWithConfig(ctx, config)
	defer r.Close(ctx)

	// Compile module to check exports
	module, err := r.CompileModule(ctx, code)
	if err != nil {
		return nil, err
	}

	// Check for IBC entry points
	hasIBC := false
	exports := module.ExportedFunctions()
	for _, name := range exports {
		switch name.Name() {
		case "ibc_channel_open",
			"ibc_channel_connect",
			"ibc_channel_close",
			"ibc_packet_receive",
			"ibc_packet_ack",
			"ibc_packet_timeout":
			hasIBC = true
		}
	}

	// Check for migrate version
	var migrateVersion *uint64
	for _, name := range exports {
		if name.Name() == "migrate" {
			version := uint64(42) // Default version for migrate
			migrateVersion = &version
			break
		}
	}

	// Determine required capabilities
	capabilities := ""
	if hasIBC {
		capabilities = "iterator,stargate"
	}

	return &types.AnalysisReport{
		HasIBCEntryPoints:      hasIBC,
		RequiredCapabilities:   capabilities,
		ContractMigrateVersion: migrateVersion,
	}, nil
}

// GetMetrics returns cache metrics
func GetMetrics(cache Cache) (*types.Metrics, error) {
	return &cache.metrics, nil
}

// GetPinnedMetrics returns metrics for pinned modules
func GetPinnedMetrics(cache Cache) (*types.PinnedMetrics, error) {
	metrics := types.PinnedMetrics{
		PerModule: make([]types.PerModuleEntry, 0),
	}
	cache.pinned.Range(func(key, value interface{}) bool {
		metrics.PerModule = append(metrics.PerModule, types.PerModuleEntry{
			Checksum: []byte(key.(string)),
			Metrics: types.PerModuleMetrics{
				Hits: 1, // Basic metric for now
				Size: 0, // We don't track size in Wazero implementation
			},
		})
		return true
	})
	return &metrics, nil
}
