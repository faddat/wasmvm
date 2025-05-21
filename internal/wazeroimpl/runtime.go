package wazeroimpl

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"golang.org/x/sys/unix"

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

// registerHost builds an env module with callbacks for the given state.
// registerHost builds an env module with callbacks. It inspects the compiled
// module's import section and registers host functions with parameter/result
// signatures that exactly match what the guest expects. This allows us to
// support both the legacy (CosmWasm <1.0) and modern (ptr,len pairs) ABIs at
// the same time.
func (c *Cache) registerHost(ctx context.Context, compiled wazero.CompiledModule, store types.KVStore, apiImpl *types.GoAPI, q *types.Querier, gm types.GasMeter) (api.Module, error) {
	builder := c.runtime.NewHostModuleBuilder("env")

	// Map of function name to expected parameter and result counts based on the guest module
	expectedParams := make(map[string]int)
	expectedResults := make(map[string]int)
	for _, f := range compiled.ImportedFunctions() {
		if mod, name, imp := f.Import(); imp && mod == "env" {
			expectedParams[name] = len(f.ParamTypes())
			expectedResults[name] = len(f.ResultTypes())
		}
	}
	// ---------------------------------------------------------------------
	// Helper functions required by CosmWasm contracts – **legacy** (v0.10-0.16)
	// ABI. These minimal stubs are sufficient for the reflect.wasm contract to
	// instantiate and run in tests. More complete, modern variants will be added
	// in later milestones.

	// debug(msg_ptr) – prints UTF-8 string [len|bytes]
	builder.NewFunctionBuilder().WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, m api.Module, stack []uint64) {
		ptr := uint32(stack[0])
		mem := m.Memory()
		// message length is stored in little-endian u32 at ptr
		b, _ := mem.Read(ptr, 4)
		l := binary.LittleEndian.Uint32(b)
		data, _ := mem.Read(ptr+4, l)
		_ = data // silenced; could log.Printf if desired
	}), []api.ValueType{api.ValueTypeI32}, []api.ValueType{}).Export("debug")

	// abort(msg_ptr)
	builder.NewFunctionBuilder().WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, m api.Module, stack []uint64) {
		ptr := uint32(stack[0])
		mem := m.Memory()
		b, _ := mem.Read(ptr, 4)
		l := binary.LittleEndian.Uint32(b)
		data, _ := mem.Read(ptr+4, l)
		panic(string(data))
	}), []api.ValueType{api.ValueTypeI32}, []api.ValueType{}).Export("abort")

	// ---------------- DB READ ----------------
	if pc := expectedParams["db_read"]; pc == 3 {
		// Modern ABI: (key_ptr, key_len, out_ptr)
		builder.NewFunctionBuilder().WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, m api.Module, stack []uint64) {
			keyPtr := uint32(stack[0])
			keyLen := uint32(stack[1])
			outPtr := uint32(stack[2])
			mem := m.Memory()
			key, _ := mem.Read(keyPtr, keyLen)
			// fmt.Println("db_read called len", len(key))
			val := store.Get(key)
			if val == nil {
				_ = mem.WriteUint32Le(outPtr, 0)
				return
			}
			_ = mem.WriteUint32Le(outPtr, uint32(len(val)))
			mem.Write(outPtr+4, val)
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{}).Export("db_read")
	} else {
		// Legacy ABI: (key_ptr) -> i32 (data_ptr)
		builder.NewFunctionBuilder().WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, m api.Module, stack []uint64) {
			keyPtr := uint32(stack[0])
			mem := m.Memory()
			// legacy FFI: keyPtr is &Region{offset,capacity,length}
			keyOff := memReadU32(mem, keyPtr)
			keyLen := memReadU32(mem, keyPtr+8)
			key, _ := mem.Read(keyOff, keyLen)
			val := store.Get(key)
			if val == nil {
				stack[0] = 0
				return
			}
			// Allocate data bytes first
			dataPtr, dataLen := locateData(ctx, m, val)
			// Build Region struct {offset,capacity,length}
			region := make([]byte, 12)
			binary.LittleEndian.PutUint32(region[0:], dataPtr)
			binary.LittleEndian.PutUint32(region[4:], dataLen)
			binary.LittleEndian.PutUint32(region[8:], dataLen)
			regPtr, _ := locateData(ctx, m, region)
			stack[0] = uint64(regPtr)
		}), []api.ValueType{api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).Export("db_read")
	}

	// ---------------- DB WRITE ----------------
	if pc := expectedParams["db_write"]; pc == 4 {
		// Modern: (key_ptr,key_len,val_ptr,val_len)
		builder.NewFunctionBuilder().WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, m api.Module, stack []uint64) {
			keyPtr := uint32(stack[0])
			keyLen := uint32(stack[1])
			valPtr := uint32(stack[2])
			valLen := uint32(stack[3])
			mem := m.Memory()
			key, _ := mem.Read(keyPtr, keyLen)
			val, _ := mem.Read(valPtr, valLen)
			store.Set(key, val)
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{}).Export("db_write")
	} else {
		// Legacy: (key_ptr, val_ptr)
		builder.NewFunctionBuilder().WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, m api.Module, stack []uint64) {
			keyPtr := uint32(stack[0])
			valPtr := uint32(stack[1])
			mem := m.Memory()
			kOff := memReadU32(mem, keyPtr)
			kLen := memReadU32(mem, keyPtr+8)
			key, _ := mem.Read(kOff, kLen)
			vOff := memReadU32(mem, valPtr)
			vLen := memReadU32(mem, valPtr+8)
			val, _ := mem.Read(vOff, vLen)
			_ = key
			_ = val
			store.Set(key, val)
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{}).Export("db_write")
	}

	// ---------------- DB REMOVE ----------------
	if pc := expectedParams["db_remove"]; pc == 2 {
		builder.NewFunctionBuilder().WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, m api.Module, stack []uint64) {
			keyPtr := uint32(stack[0])
			keyLen := uint32(stack[1])
			mem := m.Memory()
			key, _ := mem.Read(keyPtr, keyLen)
			store.Delete(key)
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{}).Export("db_remove")
	} else {
		builder.NewFunctionBuilder().WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, m api.Module, stack []uint64) {
			keyPtr := uint32(stack[0])
			mem := m.Memory()
			kOff := memReadU32(mem, keyPtr)
			kLen := memReadU32(mem, keyPtr+8)
			key, _ := mem.Read(kOff, kLen)
			store.Delete(key)
		}), []api.ValueType{api.ValueTypeI32}, []api.ValueType{}).Export("db_remove")
	}
	// ---------------- DB SCAN ----------------
	// Legacy Region-based scan: returns an empty result set
	if pc, ok := expectedParams["db_scan"]; ok && pc == 1 {
		builder.NewFunctionBuilder().WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, m api.Module, stack []uint64) {
			stack[0] = uint64(makeRegion(ctx, m, nil))
		}), []api.ValueType{api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).Export("db_scan")
	}
	// ---------------- DB NEXT ----------------
	// Legacy Region-based iterator next: always end of iteration
	if pc, ok := expectedParams["db_next"]; ok && pc == 1 {
		builder.NewFunctionBuilder().WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, m api.Module, stack []uint64) {
			stack[0] = uint64(makeRegion(ctx, m, nil))
		}), []api.ValueType{api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).Export("db_next")
	}

	// --------- Address helpers (legacy Region ABI) ---------
	if expectedParams["addr_validate"] == 1 {
		builder.NewFunctionBuilder().WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, m api.Module, stack []uint64) {
			ptr := uint32(stack[0])
			mem := m.Memory()
			off, length := readRegion(mem, ptr)
			_, _ = off, length
			stack[0] = 0 // success
		}), []api.ValueType{api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).Export("addr_validate")
	}

	if expectedParams["addr_canonicalize"] == 2 {
		builder.NewFunctionBuilder().WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, m api.Module, stack []uint64) {
			humanPtr := uint32(stack[0])
			outPtr := uint32(stack[1])
			mem := m.Memory()
			hOff, hLen := readRegion(mem, humanPtr)
			human, _ := mem.Read(hOff, hLen)
			_ = human
			// dummy canonical: just lower-case normally; we'll return same bytes
			canonical := human
			dataOff, dataLen := locateData(ctx, m, canonical)
			_ = mem.WriteUint32Le(outPtr, dataOff)
			_ = mem.WriteUint32Le(outPtr+4, dataLen)
			_ = mem.WriteUint32Le(outPtr+8, dataLen)
			stack[0] = 0
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).Export("addr_canonicalize")
	}

	if expectedParams["addr_humanize"] == 2 {
		builder.NewFunctionBuilder().WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, m api.Module, stack []uint64) {
			canonPtr := uint32(stack[0])
			outPtr := uint32(stack[1])
			mem := m.Memory()
			off, l := readRegion(mem, canonPtr)
			canonical, _ := mem.Read(off, l)
			human := canonical
			dataOff, dataLen := locateData(ctx, m, human)
			_ = mem.WriteUint32Le(outPtr, dataOff)
			_ = mem.WriteUint32Le(outPtr+4, dataLen)
			_ = mem.WriteUint32Le(outPtr+8, dataLen)
			stack[0] = 0
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).Export("addr_humanize")
	}

	if expectedParams["query_chain"] == 1 {
		builder.NewFunctionBuilder().WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, m api.Module, stack []uint64) {
			reqPtr := uint32(stack[0])
			mem := m.Memory()
			off, l := readRegion(mem, reqPtr)
			_, _ = mem.Read(off, l)
			// empty response region
			stack[0] = uint64(makeRegion(ctx, m, nil))
		}), []api.ValueType{api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).Export("query_chain")
	}
	// Modern query host: support (ptr,len)->region or (ptr,len,out_ptr)->void
	if pc, ok := expectedParams["query"]; ok {
		rc := expectedResults["query"]
		params := make([]api.ValueType, pc)
		for i := range params {
			params[i] = api.ValueTypeI32
		}
		results := make([]api.ValueType, rc)
		for i := range results {
			results[i] = api.ValueTypeI32
		}
		builder.NewFunctionBuilder().WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, m api.Module, stack []uint64) {
			mem := m.Memory()
			reqPtr := uint32(stack[0])
			reqLen := uint32(stack[1])
			reqData, _ := mem.Read(reqPtr, reqLen)
			// determine per-query gas limit if provided
			var gasLimit uint64
			if pc >= 3 {
				gasLimit = stack[2]
			}
			// perform query with guest-specified gas limit
			qr := types.RustQuery(*q, reqData, gasLimit)
			outBytes, _ := json.Marshal(qr)
			if rc == 1 {
				regionPtr := makeRegion(ctx, m, outBytes)
				stack[0] = uint64(regionPtr)
			} else if pc >= 3 {
				outPtr := uint32(stack[2])
				off, length := locateData(ctx, m, outBytes)
				mem.WriteUint32Le(outPtr, off)
				mem.WriteUint32Le(outPtr+4, length)
				mem.WriteUint32Le(outPtr+8, length)
			}
		}), params, results).Export("query")
	}
	// Modern call host: stub no-op for contract-to-contract calls
	for _, name := range []string{"call", "call_contract"} {
		if pc, ok := expectedParams[name]; ok {
			rc := expectedResults[name]
			params := make([]api.ValueType, pc)
			for i := range params {
				params[i] = api.ValueTypeI32
			}
			results := make([]api.ValueType, rc)
			for i := range results {
				results[i] = api.ValueTypeI32
			}
			builder.NewFunctionBuilder().WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, m api.Module, stack []uint64) {
				if rc == 1 {
					// return empty region
					stack[0] = uint64(makeRegion(ctx, m, nil))
				} else if pc >= 3 {
					// write empty region to outPtr
					outPtr := uint32(stack[2])
					mem := m.Memory()
					mem.WriteUint32Le(outPtr, 0)
					mem.WriteUint32Le(outPtr+4, 0)
					mem.WriteUint32Le(outPtr+8, 0)
				}
			}), params, results).Export(name)
		}
	}

	// crypto helpers – stubs that return false or no-op without dereferencing memory
	for _, name := range []string{"secp256k1_verify", "ed25519_verify", "ed25519_batch_verify"} {
		if pc, ok := expectedParams[name]; ok {
			params := make([]api.ValueType, pc)
			for i := range params {
				params[i] = api.ValueTypeI32
			}
			builder.NewFunctionBuilder().
				WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, m api.Module, stack []uint64) {
					stack[0] = 0
				}), params, []api.ValueType{api.ValueTypeI32}).
				Export(name)
		}
	}
	if pc, ok := expectedParams["secp256k1_recover_pubkey"]; ok {
		params := make([]api.ValueType, pc)
		for i := range params {
			params[i] = api.ValueTypeI32
		}
		builder.NewFunctionBuilder().
			WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, m api.Module, stack []uint64) {
				stack[0] = 0
			}), params, []api.ValueType{api.ValueTypeI64}).
			Export("secp256k1_recover_pubkey")
	}

	// query_external - simplified: returns 0 length
	// canonicalize_address: input human string -> canonical bytes
	builder.NewFunctionBuilder().WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, m api.Module, stack []uint64) {
		inputPtr := uint32(stack[0])
		inputLen := uint32(stack[1])
		outPtr := uint32(stack[2])
		errPtr := uint32(stack[3])
		gasPtr := uint32(stack[4])
		mem := m.Memory()
		input, _ := mem.Read(inputPtr, inputLen)
		// call GoAPI
		canonical, usedGas, err := apiImpl.CanonicalizeAddress(string(input))
		// write gas
		buf := make([]byte, 8)
		binary.LittleEndian.PutUint64(buf, usedGas)
		mem.Write(gasPtr, buf)
		if err != nil {
			mem.WriteUint32Le(errPtr, uint32(len(err.Error())))
			mem.Write(errPtr+4, []byte(err.Error()))
			return
		}
		mem.WriteUint32Le(outPtr, uint32(len(canonical)))
		mem.Write(outPtr+4, canonical)
	}), []api.ValueType{
		api.ValueTypeI32, api.ValueTypeI32,
		api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32,
	}, []api.ValueType{}).Export("canonicalize_address")
	// humanize_address: input canonical bytes -> human string
	builder.NewFunctionBuilder().WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, m api.Module, stack []uint64) {
		inputPtr := uint32(stack[0])
		inputLen := uint32(stack[1])
		outPtr := uint32(stack[2])
		errPtr := uint32(stack[3])
		gasPtr := uint32(stack[4])
		mem := m.Memory()
		input, _ := mem.Read(inputPtr, inputLen)
		human, usedGas, err := apiImpl.HumanizeAddress(input)
		buf := make([]byte, 8)
		binary.LittleEndian.PutUint64(buf, usedGas)
		mem.Write(gasPtr, buf)
		if err != nil {
			mem.WriteUint32Le(errPtr, uint32(len(err.Error())))
			mem.Write(errPtr+4, []byte(err.Error()))
			return
		}
		mem.WriteUint32Le(outPtr, uint32(len(human)))
		mem.Write(outPtr+4, []byte(human))
	}), []api.ValueType{
		api.ValueTypeI32, api.ValueTypeI32,
		api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32,
	}, []api.ValueType{}).Export("humanize_address")
	// validate_address: input human string -> error only
	builder.NewFunctionBuilder().WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, m api.Module, stack []uint64) {
		inputPtr := uint32(stack[0])
		inputLen := uint32(stack[1])
		errPtr := uint32(stack[2])
		gasPtr := uint32(stack[3])
		mem := m.Memory()
		tmp, _ := mem.Read(inputPtr, inputLen)
		input := string(tmp)
		usedGas, err := apiImpl.ValidateAddress(input)
		buf := make([]byte, 8)
		binary.LittleEndian.PutUint64(buf, usedGas)
		mem.Write(gasPtr, buf)
		if err != nil {
			msg := err.Error()
			mem.WriteUint32Le(errPtr, uint32(len(msg)))
			mem.Write(errPtr+4, []byte(msg))
		}
	}), []api.ValueType{
		api.ValueTypeI32, api.ValueTypeI32,
		api.ValueTypeI32, api.ValueTypeI32,
	}, []api.ValueType{}).Export("validate_address")

	return builder.Instantiate(ctx)
}

// Instantiate loads and runs the contract's instantiate function.
func (c *Cache) Instantiate(ctx context.Context, checksum types.Checksum, env, info, msg []byte, store types.KVStore, apiImpl *types.GoAPI, q *types.Querier, gm types.GasMeter) error {
	compiled, ok := c.getModule(checksum)
	if !ok {
		return fmt.Errorf("module not found")
	}
	_, err := c.registerHost(ctx, compiled, store, apiImpl, q, gm)
	if err != nil {
		return err
	}
	mod, err := c.runtime.InstantiateModule(ctx, compiled, wazero.NewModuleConfig())
	if err != nil {
		return err
	}
	if fn := mod.ExportedFunction("instantiate"); fn != nil {
		paramCount := len(fn.Definition().ParamTypes())
		switch paramCount {
		case 6:
			// CosmWasm v1+ ABI (ptr,len pairs)
			envPtr, envLen := uint32(0), uint32(0)
			infoPtr, infoLen := uint32(0), uint32(0)
			msgPtr, msgLen := uint32(0), uint32(0)
			if len(env) > 0 {
				envPtr, envLen = locateData(ctx, mod, env)
			}
			if len(info) > 0 {
				infoPtr, infoLen = locateData(ctx, mod, info)
			}
			if len(msg) > 0 {
				msgPtr, msgLen = locateData(ctx, mod, msg)
			}
			_, err = fn.Call(ctx, uint64(envPtr), uint64(envLen), uint64(infoPtr), uint64(infoLen), uint64(msgPtr), uint64(msgLen))
		case 3:
			// Legacy ABI: env_ptr, info_ptr, msg_ptr (each data = len|bytes)
			wrap := func(b []byte) []byte {
				buf := make([]byte, 4+len(b))
				binary.LittleEndian.PutUint32(buf, uint32(len(b)))
				copy(buf[4:], b)
				return buf
			}
			envPtr, _ := locateData(ctx, mod, wrap(env))
			infoPtr, _ := locateData(ctx, mod, wrap(info))
			msgPtr, _ := locateData(ctx, mod, wrap(msg))
			_, err = fn.Call(ctx, uint64(envPtr), uint64(infoPtr), uint64(msgPtr))
		default:
			err = fmt.Errorf("unsupported instantiate param count %d", paramCount)
		}
	}
	_ = mod.Close(ctx)
	return err
}

// Execute runs the contract's execute function.
func (c *Cache) Execute(ctx context.Context, checksum types.Checksum, env, info, msg []byte, store types.KVStore, apiImpl *types.GoAPI, q *types.Querier, gm types.GasMeter) error {
	compiled, ok := c.getModule(checksum)
	if !ok {
		return fmt.Errorf("module not found")
	}
	_, err := c.registerHost(ctx, compiled, store, apiImpl, q, gm)
	if err != nil {
		return err
	}
	mod, err := c.runtime.InstantiateModule(ctx, compiled, wazero.NewModuleConfig())
	if err != nil {
		return err
	}
	if fn := mod.ExportedFunction("execute"); fn != nil {
		paramCount := len(fn.Definition().ParamTypes())
		switch paramCount {
		case 6:
			envPtr, envLen := uint32(0), uint32(0)
			infoPtr, infoLen := uint32(0), uint32(0)
			msgPtr, msgLen := uint32(0), uint32(0)
			if len(env) > 0 {
				envPtr, envLen = locateData(ctx, mod, env)
			}
			if len(info) > 0 {
				infoPtr, infoLen = locateData(ctx, mod, info)
			}
			if len(msg) > 0 {
				msgPtr, msgLen = locateData(ctx, mod, msg)
			}
			_, err = fn.Call(ctx, uint64(envPtr), uint64(envLen), uint64(infoPtr), uint64(infoLen), uint64(msgPtr), uint64(msgLen))
		case 3:
			wrap := func(b []byte) []byte {
				buf := make([]byte, 4+len(b))
				binary.LittleEndian.PutUint32(buf, uint32(len(b)))
				copy(buf[4:], b)
				return buf
			}
			envPtr, _ := locateData(ctx, mod, wrap(env))
			infoPtr, _ := locateData(ctx, mod, wrap(info))
			msgPtr, _ := locateData(ctx, mod, wrap(msg))
			_, err = fn.Call(ctx, uint64(envPtr), uint64(infoPtr), uint64(msgPtr))
		default:
			err = fmt.Errorf("unsupported execute param count %d", paramCount)
		}
	}
	_ = mod.Close(ctx)
	return err
}
