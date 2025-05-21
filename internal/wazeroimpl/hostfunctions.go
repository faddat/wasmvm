package wazeroimpl

import (
	"context"
	"encoding/binary"
	"encoding/json"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"

	"github.com/CosmWasm/wasmvm/v3/types"
)

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
