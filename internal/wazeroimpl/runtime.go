package wazeroimpl

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"

	"github.com/CosmWasm/wasmvm/v3/types"
)

// helper to read little-endian uint32 from guest memory safely.
func memReadU32(mem api.Memory, ptr uint32) uint32 {
	b, ok := mem.Read(ptr, 4)
	if !ok {
		return 0
	}
	return binary.LittleEndian.Uint32(b)
}

// readRegion interprets ptr as a *Region {offset, capacity, length} in guest
// memory and returns (offset,length). If memory reads fail, (0,0) is returned.
func readRegion(mem api.Memory, ptr uint32) (uint32, uint32) {
	off := memReadU32(mem, ptr)
	length := memReadU32(mem, ptr+8)
	return off, length
}

// makeRegion copies data into guest memory via locateData and writes a Region
// struct into guest memory, returning the pointer to that Region.
func makeRegion(ctx context.Context, mod api.Module, data []byte) uint32 {
	if len(data) == 0 {
		return 0
	}
	off, length := locateData(ctx, mod, data)
	regionBytes := make([]byte, 12)
	binary.LittleEndian.PutUint32(regionBytes[0:], off)
	binary.LittleEndian.PutUint32(regionBytes[4:], length) // capacity = length
	binary.LittleEndian.PutUint32(regionBytes[8:], length)
	regionPtr, _ := locateData(ctx, mod, regionBytes)
	return regionPtr
}

// Cache manages a wazero runtime, compiled modules, and on-disk code storage.
type Cache struct {
	runtime wazero.Runtime
	modules map[string]wazero.CompiledModule
	// raw stores the original Wasm bytes by checksum hex
	raw map[string][]byte
	// lockfile holds the exclusive lock on BaseDir
	lockfile *os.File
	// baseDir is the root directory for on-disk cache
	baseDir string
}

// locateData allocates memory in the given module using its "allocate" export
// and writes the provided data slice there. It returns the pointer and length
// of the written data within the module's linear memory. Any allocation or
// write failure results in a panic, as this indicates the guest module does
// not follow the expected CosmWasm ABI.
func locateData(ctx context.Context, mod api.Module, data []byte) (uint32, uint32) {
	if len(data) == 0 {
		return 0, 0
	}

	alloc := mod.ExportedFunction("allocate")
	if alloc == nil {
		panic("guest module does not export an 'allocate' function required by CosmWasm ABI")
	}

	// Call allocate with the size (i32). The function returns a pointer (i32).
	res, err := alloc.Call(ctx, uint64(len(data)))
	if err != nil {
		panic(fmt.Sprintf("allocate() failed: %v", err))
	}
	if len(res) == 0 {
		panic("allocate() returned no results")
	}

	ptr := uint32(res[0])

	mem := mod.Memory()
	if ok := mem.Write(ptr, data); !ok {
		panic("failed to write data into guest memory")
	}

	return ptr, uint32(len(data))
}

// RemoveCode removes stored Wasm and compiled module for the given checksum.
func (c *Cache) RemoveCode(checksum types.Checksum) error {
	key := hex.EncodeToString(checksum)
	if _, ok := c.raw[key]; !ok {
		return fmt.Errorf("code '%s' not found", key)
	}
	// Remove on-disk Wasm file if persisted
	if c.baseDir != "" {
		filePath := filepath.Join(c.baseDir, "code", key+".wasm")
		if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove wasm file: %w", err)
		}
	}
	delete(c.raw, key)
	delete(c.modules, key)
	return nil
}

// GetCode returns the original Wasm bytes for the given checksum.
func (c *Cache) GetCode(checksum types.Checksum) ([]byte, error) {
	key := hex.EncodeToString(checksum)
	data, ok := c.raw[key]
	if !ok {
		return nil, fmt.Errorf("code '%s' not found", key)
	}
	return append([]byte(nil), data...), nil
}

// Close releases the runtime and the directory lock.
func (c *Cache) Close(ctx context.Context) error {
	if c.runtime != nil {
		c.runtime.Close(ctx)
	}
	if c.lockfile != nil {
		c.lockfile.Close()
	}
	return nil
}

// Compile stores a compiled module under the given checksum.
func (c *Cache) Compile(ctx context.Context, checksum types.Checksum, wasm []byte) error {
	key := hex.EncodeToString(checksum)
	// Persist Wasm blob to disk if enabled
	if c.baseDir != "" {
		codeDir := filepath.Join(c.baseDir, "code")
		if err := os.MkdirAll(codeDir, 0o755); err != nil {
			return fmt.Errorf("could not create code directory: %w", err)
		}
		filePath := filepath.Join(codeDir, key+".wasm")
		if err := os.WriteFile(filePath, wasm, 0o644); err != nil {
			return fmt.Errorf("failed to write wasm file: %w", err)
		}
	}
	// Store raw Wasm bytes in memory
	c.raw[key] = append([]byte(nil), wasm...)
	// Compile module
	mod, err := c.runtime.CompileModule(ctx, wasm)
	if err != nil {
		return err
	}
	c.modules[key] = mod
	return nil
}

// getModule returns the compiled module for the checksum.
func (c *Cache) getModule(checksum types.Checksum) (wazero.CompiledModule, bool) {
	mod, ok := c.modules[hex.EncodeToString(checksum)]
	return mod, ok
}
