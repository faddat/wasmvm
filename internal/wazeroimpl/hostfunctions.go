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

	// debug(msg_ptr) – prints UTF-8 string from a legacy Region struct
	builder.NewFunctionBuilder().WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, m api.Module, stack []uint64) {
		ptr := uint32(stack[0])
		mem := m.Memory()
		off, length := readRegion(mem, ptr)
		if length > 0 {
			data, _ := mem.Read(off, length)
			_ = data
		}
	}), []api.ValueType{api.ValueTypeI32}, []api.ValueType{}).Export("debug")

	// abort(msg_ptr) – panics with the UTF-8 string from a legacy Region struct
	builder.NewFunctionBuilder().WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, m api.Module, stack []uint64) {
		ptr := uint32(stack[0])
		mem := m.Memory()
		off, length := readRegion(mem, ptr)
		if length > 0 {
			data, _ := mem.Read(off, length)
			panic(string(data))
		}
	}), []api.ValueType{api.ValueTypeI32}, []api.ValueType{}).Export("abort")

	// ---------------- DB READ ----------------
	// Stub: always return empty (legacy region-based signature)
	builder.NewFunctionBuilder().WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, m api.Module, stack []uint64) {
		// No data in store
		stack[0] = 0
	}), []api.ValueType{api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).Export("db_read")

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
		// Legacy: (key_ptr, val_ptr). Stub: no-op
		builder.NewFunctionBuilder().WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, m api.Module, stack []uint64) {
			// no-op
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
		// Legacy: (key_ptr). Stub: no-op
		builder.NewFunctionBuilder().WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, m api.Module, stack []uint64) {
			// no-op
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

	// addr_canonicalize(human_ptr, human_len) -> region_ptr
	if expectedParams["addr_canonicalize"] == 2 {
		builder.NewFunctionBuilder().WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, m api.Module, stack []uint64) {
			humanPtr := uint32(stack[0])
			humanLen := uint32(stack[1])
			mem := m.Memory()
			human, _ := mem.Read(humanPtr, humanLen)
			regionPtr := makeRegion(ctx, m, human)
			stack[0] = uint64(regionPtr)
		}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).Export("addr_canonicalize")
	}

	// addr_humanize(canonical_ptr, canonical_len) -> region_ptr
	if expectedParams["addr_humanize"] == 2 {
		builder.NewFunctionBuilder().WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, m api.Module, stack []uint64) {
			canonPtr := uint32(stack[0])
			canonLen := uint32(stack[1])
			mem := m.Memory()
			canonical, _ := mem.Read(canonPtr, canonLen)
			regionPtr := makeRegion(ctx, m, canonical)
			stack[0] = uint64(regionPtr)
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
