package wazeroimpl

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"github.com/tetratelabs/wazero"
	"golang.org/x/sys/unix"

	"github.com/CosmWasm/wasmvm/v3/types"
)

// InitCache creates a new wazero Runtime with memory limits similar to api.InitCache.
func InitCache(config types.VMConfig) (*Cache, error) {
	// Prepare in-memory storage, lockfile handle, and base directory
	raw := make(map[string][]byte)
	var lf *os.File
	base := config.Cache.BaseDir
	if base != "" {
		// Create base and code directories
		if strings.Contains(base, ":") && runtime.GOOS != "windows" {
			return nil, fmt.Errorf("invalid base directory: %s", base)
		}
		if err := os.MkdirAll(base, 0o755); err != nil {
			return nil, fmt.Errorf("could not create base directory: %w", err)
		}
		codeDir := filepath.Join(base, "code")
		if err := os.MkdirAll(codeDir, 0o755); err != nil {
			return nil, fmt.Errorf("could not create code directory: %w", err)
		}
		// Acquire exclusive lock
		lockPath := filepath.Join(base, "exclusive.lock")
		var err error
		lf, err = os.OpenFile(lockPath, os.O_WRONLY|os.O_CREATE, 0o666)
		if err != nil {
			return nil, fmt.Errorf("could not open exclusive.lock: %w", err)
		}
		_, err = lf.WriteString("exclusive lock for wazero VM\n")
		if err != nil {
			lf.Close()
			return nil, fmt.Errorf("error writing to exclusive.lock: %w", err)
		}
		if err := unix.Flock(int(lf.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
			lf.Close()
			return nil, fmt.Errorf("could not lock exclusive.lock; is another VM running? %w", err)
		}
		// Pre-load existing Wasm blobs
		patterns := filepath.Join(codeDir, "*.wasm")
		files, err := filepath.Glob(patterns)
		if err != nil {
			lf.Close()
			return nil, fmt.Errorf("failed scanning code directory: %w", err)
		}
		for _, p := range files {
			data, err := os.ReadFile(p)
			if err != nil {
				lf.Close()
				return nil, fmt.Errorf("failed reading existing code %s: %w", p, err)
			}
			name := filepath.Base(p)
			key := strings.TrimSuffix(name, ".wasm")
			raw[key] = data
		}
	}

	ctx := context.Background()
	limitBytes := *(*uint32)(unsafe.Pointer(&config.Cache.InstanceMemoryLimitBytes))
	r := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().WithMemoryLimitPages(limitBytes/65536))
	return &Cache{
		runtime:  r,
		modules:  make(map[string]wazero.CompiledModule),
		raw:      raw,
		lockfile: lf,
		baseDir:  base,
	}, nil
}
