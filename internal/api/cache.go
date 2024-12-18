package api

import (
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
func InitCache(config types.VMConfig) (Cache, error) {
	// Create base directory
	err := os.MkdirAll(config.Cache.BaseDir, 0o755)
	if err != nil {
		return Cache{}, fmt.Errorf("could not create base directory: %v", err)
	}

	// Create and lock the lockfile
	lockfile, err := os.OpenFile(filepath.Join(config.Cache.BaseDir, "exclusive.lock"), os.O_WRONLY|os.O_CREATE, 0o666)
	if err != nil {
		return Cache{}, fmt.Errorf("could not open exclusive.lock: %v", err)
	}

	// Create Wazero runtime
	runtime := wazero.NewRuntime(context.Background())

	return Cache{
		runtime:  runtime,
		baseDir:  config.Cache.BaseDir,
		lockfile: lockfile,
	}, nil
}

// ReleaseCache releases all resources associated with the cache
func ReleaseCache(cache Cache) {
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
	// Calculate checksum
	checksum := sha256.Sum256(wasm)

	// Store the original code
	cache.codes.Store(string(checksum[:]), wasm)

	// Compile the module
	compiled, err := cache.runtime.CompileModule(context.Background(), wasm)
	if err != nil {
		return nil, fmt.Errorf("failed to compile module: %w", err)
	}

	// Store the compiled module
	cache.modules.Store(string(checksum[:]), compiled)

	return checksum[:], nil
}

// StoreCodeUnchecked stores code without validation
func StoreCodeUnchecked(cache Cache, wasm []byte) ([]byte, error) {
	return StoreCode(cache, wasm)
}

// RemoveCode removes code from the cache
func RemoveCode(cache Cache, checksum []byte) error {
	if _, ok := cache.modules.LoadAndDelete(string(checksum)); !ok {
		return fmt.Errorf("module not found")
	}
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
	// Get the code from cache
	code, err := GetCode(cache, checksum)
	if err != nil {
		return nil, err
	}

	// Compile the module to analyze exports
	compiled, err := cache.runtime.CompileModule(context.Background(), code)
	if err != nil {
		return nil, fmt.Errorf("failed to compile module for analysis: %w", err)
	}

	// Check for IBC entry points
	hasIBC := false
	entrypoints := make([]string, 0)

	// Standard entry points
	standardEntryPoints := []string{"instantiate", "execute", "query", "migrate"}
	for _, ep := range standardEntryPoints {
		if _, ok := compiled.ExportedFunctions()[ep]; ok {
			entrypoints = append(entrypoints, ep)
		}
	}

	// IBC entry points
	ibcEntryPoints := []string{
		"ibc_channel_open",
		"ibc_channel_connect",
		"ibc_channel_close",
		"ibc_packet_receive",
		"ibc_packet_ack",
		"ibc_packet_timeout",
	}

	for _, ep := range ibcEntryPoints {
		if _, ok := compiled.ExportedFunctions()[ep]; ok {
			hasIBC = true
			entrypoints = append(entrypoints, ep)
		}
	}

	// For now, we don't track required capabilities in Wazero
	return &types.AnalysisReport{
		HasIBCEntryPoints:      hasIBC,
		RequiredCapabilities:   "",
		Entrypoints:            entrypoints,
		ContractMigrateVersion: nil,
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
