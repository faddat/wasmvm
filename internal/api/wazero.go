package api

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/CosmWasm/wasmvm/v2/types"
	"github.com/tetratelabs/wazero"
	wazeroapi "github.com/tetratelabs/wazero/api"
)

// WazeroInstance represents a Wazero instance
type WazeroInstance struct {
	ctx    context.Context
	module wazeroapi.Module
	env    *Environment
}

// WazeroGasMeter implements types.GasMeter
type WazeroGasMeter struct {
	consumed types.Gas
}

func (g *WazeroGasMeter) GasConsumed() types.Gas {
	return g.consumed
}

func (g *WazeroGasMeter) ConsumeGas(amount types.Gas, reason string) {
	g.consumed += amount
}

// createModule creates a new Wazero module
func createModule(ctx context.Context, code []byte, env *Environment, gasMeter *WazeroGasMeter, gasLimit uint64) (wazeroapi.Module, error) {
	// Create runtime
	config := wazero.NewRuntimeConfig().
		WithMemoryLimitPages(65536).
		WithCloseOnContextDone(true)

	r := wazero.NewRuntimeWithConfig(ctx, config)

	// Build host module
	builder := r.NewHostModuleBuilder("env")

	// Add host functions
	builder.NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m wazeroapi.Module, stack []uint64) {
			// db_read implementation
			keyPtr := uint32(stack[0])
			keyLen := uint32(stack[1])
			valPtr := uint32(stack[2])

			// Read key from memory
			mem := m.Memory()
			if mem == nil {
				stack[0] = 1 // Error
				return
			}

			key, ok := mem.Read(keyPtr, keyLen)
			if !ok {
				stack[0] = 1 // Error
				return
			}

			// Call store.Get
			value := env.Store.Get(key)
			if value == nil {
				stack[0] = 1 // Error
				return
			}

			// Write value to memory
			if !mem.Write(valPtr, value) {
				stack[0] = 1 // Error
				return
			}

			stack[0] = 0 // Success
		}).
		WithParameterNames("key_ptr", "key_len", "val_ptr").
		Export("db_read")

	builder.NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m wazeroapi.Module, stack []uint64) {
			// db_write implementation
			keyPtr := uint32(stack[0])
			keyLen := uint32(stack[1])
			valPtr := uint32(stack[2])
			valLen := uint32(stack[3])

			// Read key and value from memory
			mem := m.Memory()
			if mem == nil {
				stack[0] = 1 // Error
				return
			}

			key, ok := mem.Read(keyPtr, keyLen)
			if !ok {
				stack[0] = 1 // Error
				return
			}

			value, ok := mem.Read(valPtr, valLen)
			if !ok {
				stack[0] = 1 // Error
				return
			}

			// Call store.Set
			env.Store.Set(key, value)
			stack[0] = 0 // Success
		}).
		WithParameterNames("key_ptr", "key_len", "val_ptr", "val_len").
		Export("db_write")

	builder.NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m wazeroapi.Module, stack []uint64) {
			// db_remove implementation
			keyPtr := uint32(stack[0])
			keyLen := uint32(stack[1])

			// Read key from memory
			mem := m.Memory()
			if mem == nil {
				stack[0] = 1 // Error
				return
			}

			key, ok := mem.Read(keyPtr, keyLen)
			if !ok {
				stack[0] = 1 // Error
				return
			}

			// Call store.Delete
			env.Store.Delete(key)
			stack[0] = 0 // Success
		}).
		WithParameterNames("key_ptr", "key_len").
		Export("db_remove")

	builder.NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m wazeroapi.Module, stack []uint64) {
			// gas_consume implementation
			amount := uint64(stack[0])
			gasMeter.ConsumeGas(amount, "wasm gas")
		}).
		WithParameterNames("amount").
		Export("gas_consume")

	// Create host module
	if _, err := builder.Instantiate(ctx); err != nil {
		return nil, fmt.Errorf("failed to create host module: %w", err)
	}

	// Compile module
	compiled, err := r.CompileModule(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("failed to compile module: %w", err)
	}

	// Instantiate module
	module, err := r.InstantiateModule(ctx, compiled, wazero.NewModuleConfig().WithName("env"))
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate module: %w", err)
	}

	return module, nil
}

// NewWazeroInstance creates a new WazeroInstance
func NewWazeroInstance(env *Environment, code []byte, gasMeter *WazeroGasMeter, gasLimit uint64) (*WazeroInstance, error) {
	// Initialize context
	ctx := context.Background()

	// Create module
	module, err := createModule(ctx, code, env, gasMeter, gasLimit)
	if err != nil {
		return nil, err
	}

	return &WazeroInstance{
		ctx:    ctx,
		module: module,
		env:    env,
	}, nil
}

// Close releases resources associated with the instance
func (i *WazeroInstance) Close() error {
	if i.module != nil {
		return i.module.Close(i.ctx)
	}
	return nil
}

// allocateAndWrite allocates memory and writes data to it
func (i *WazeroInstance) allocateAndWrite(data []byte) (uint64, error) {
	// Allocate memory
	size := uint32(len(data))
	ptr, err := i.module.ExportedFunction("allocate").Call(i.ctx, uint64(size))
	if err != nil {
		return 0, err
	}

	// Write data to memory
	mem := i.module.Memory()
	if mem == nil {
		return 0, fmt.Errorf("no memory exported")
	}

	if !mem.Write(uint32(ptr[0]), data) {
		return 0, fmt.Errorf("failed to write to memory")
	}

	return ptr[0], nil
}

// readResult reads a result from memory
func (i *WazeroInstance) readResult(ptr uint64) ([]byte, error) {
	mem := i.module.Memory()
	if mem == nil {
		return nil, fmt.Errorf("no memory exported")
	}

	// Read length
	lenPtr := ptr + 4
	lenBytes, ok := mem.Read(uint32(lenPtr), 4)
	if !ok {
		return nil, fmt.Errorf("failed to read result length")
	}
	length := binary.LittleEndian.Uint32(lenBytes)

	// Read data
	dataPtr := ptr + 8
	data, ok := mem.Read(uint32(dataPtr), length)
	if !ok {
		return nil, fmt.Errorf("failed to read result data")
	}

	return data, nil
}

// callFunction calls a Wasm function
func (i *WazeroInstance) callFunction(name string, args ...uint64) (uint64, error) {
	fn := i.module.ExportedFunction(name)
	if fn == nil {
		return 0, fmt.Errorf("function %s not found", name)
	}

	result, err := fn.Call(i.ctx, args...)
	if err != nil {
		return 0, err
	}

	return result[0], nil
}

// AnalyzeCode analyzes the code for capabilities
func (i *WazeroInstance) AnalyzeCode() (*types.AnalysisReport, error) {
	report := &types.AnalysisReport{
		HasIBCEntryPoints: false,
	}

	// Check for IBC entry points
	ibcFunctions := []string{
		"ibc_channel_open",
		"ibc_channel_connect",
		"ibc_channel_close",
		"ibc_packet_receive",
		"ibc_packet_ack",
		"ibc_packet_timeout",
	}

	hasAllIBCFunctions := true
	for _, name := range ibcFunctions {
		if i.module.ExportedFunction(name) == nil {
			hasAllIBCFunctions = false
			break
		}
	}

	report.HasIBCEntryPoints = hasAllIBCFunctions
	return report, nil
}

// IBCPacketTimeout handles an IBC packet timeout
func (i *WazeroInstance) IBCPacketTimeout(code []byte, msg []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	// Write message to memory
	msgPtr, err := i.allocateAndWrite(msg)
	if err != nil {
		return nil, types.GasReport{}, err
	}

	// Call the Wasm function
	result, err := i.callFunction("ibc_packet_timeout", msgPtr)
	if err != nil {
		return nil, types.GasReport{}, err
	}

	// Read result from memory
	data, err := i.readResult(result)
	if err != nil {
		return nil, types.GasReport{}, err
	}

	return data, types.GasReport{}, nil
}

// IBCChannelOpen handles IBC channel open
func (i *WazeroInstance) IBCChannelOpen(code []byte, msg []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	msgPtr, err := i.allocateAndWrite(msg)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	result, err := i.callFunction("ibc_channel_open", msgPtr)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	data, err := i.readResult(result)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	return data, types.GasReport{}, nil
}

// IBCChannelConnect handles IBC channel connect
func (i *WazeroInstance) IBCChannelConnect(code []byte, msg []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	msgPtr, err := i.allocateAndWrite(msg)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	result, err := i.callFunction("ibc_channel_connect", msgPtr)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	data, err := i.readResult(result)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	return data, types.GasReport{}, nil
}

// IBCChannelClose handles IBC channel close
func (i *WazeroInstance) IBCChannelClose(code []byte, msg []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	msgPtr, err := i.allocateAndWrite(msg)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	result, err := i.callFunction("ibc_channel_close", msgPtr)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	data, err := i.readResult(result)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	return data, types.GasReport{}, nil
}

// IBCPacketReceive handles IBC packet receive
func (i *WazeroInstance) IBCPacketReceive(code []byte, msg []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	msgPtr, err := i.allocateAndWrite(msg)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	result, err := i.callFunction("ibc_packet_receive", msgPtr)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	data, err := i.readResult(result)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	return data, types.GasReport{}, nil
}

// IBCPacketAck handles IBC packet ack
func (i *WazeroInstance) IBCPacketAck(code []byte, msg []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	msgPtr, err := i.allocateAndWrite(msg)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	result, err := i.callFunction("ibc_packet_ack", msgPtr)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	data, err := i.readResult(result)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	return data, types.GasReport{}, nil
}

// IBCSourceCallback handles IBC source callback
func (i *WazeroInstance) IBCSourceCallback(code []byte, msg []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	msgPtr, err := i.allocateAndWrite(msg)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	result, err := i.callFunction("ibc_source_callback", msgPtr)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	data, err := i.readResult(result)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	return data, types.GasReport{}, nil
}

// IBCDestinationCallback handles IBC destination callback
func (i *WazeroInstance) IBCDestinationCallback(code []byte, msg []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	msgPtr, err := i.allocateAndWrite(msg)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	result, err := i.callFunction("ibc_destination_callback", msgPtr)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	data, err := i.readResult(result)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	return data, types.GasReport{}, nil
}

// Execute executes a contract with the given parameters
func (i *WazeroInstance) Execute(code []byte, info []byte, msg []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	// Write parameters to memory
	infoPtr, err := i.allocateAndWrite(info)
	if err != nil {
		return nil, types.GasReport{}, err
	}

	msgPtr, err := i.allocateAndWrite(msg)
	if err != nil {
		return nil, types.GasReport{}, err
	}

	// Call execute function
	resultPtr, err := i.callFunction("execute", infoPtr, msgPtr)
	if err != nil {
		return nil, types.GasReport{}, err
	}

	// Read result
	result, err := i.readResult(resultPtr)
	if err != nil {
		return nil, types.GasReport{}, err
	}

	return result, types.GasReport{}, nil
}

// Instantiate creates a new instance of a contract
func (i *WazeroInstance) Instantiate(code []byte, info []byte, msg []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	// Write parameters to memory
	infoPtr, err := i.allocateAndWrite(info)
	if err != nil {
		return nil, types.GasReport{}, err
	}

	msgPtr, err := i.allocateAndWrite(msg)
	if err != nil {
		return nil, types.GasReport{}, err
	}

	// Call instantiate function
	resultPtr, err := i.callFunction("instantiate", infoPtr, msgPtr)
	if err != nil {
		return nil, types.GasReport{}, err
	}

	// Read result
	result, err := i.readResult(resultPtr)
	if err != nil {
		return nil, types.GasReport{}, err
	}

	return result, types.GasReport{}, nil
}

// Query executes a query on a contract
func (i *WazeroInstance) Query(code []byte, msg []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	msgPtr, err := i.allocateAndWrite(msg)
	if err != nil {
		return nil, types.GasReport{}, err
	}

	resultPtr, err := i.callFunction("query", msgPtr)
	if err != nil {
		return nil, types.GasReport{}, err
	}

	result, err := i.readResult(resultPtr)
	if err != nil {
		return nil, types.GasReport{}, err
	}

	return result, types.GasReport{}, nil
}

// Migrate executes a migration on a contract
func (i *WazeroInstance) Migrate(code []byte, msg []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	msgPtr, err := i.allocateAndWrite(msg)
	if err != nil {
		return nil, types.GasReport{}, err
	}

	resultPtr, err := i.callFunction("migrate", msgPtr)
	if err != nil {
		return nil, types.GasReport{}, err
	}

	result, err := i.readResult(resultPtr)
	if err != nil {
		return nil, types.GasReport{}, err
	}

	return result, types.GasReport{}, nil
}

// MigrateWithInfo executes a migration with additional info
func (i *WazeroInstance) MigrateWithInfo(code []byte, msg []byte, migrateInfo []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	msgPtr, err := i.allocateAndWrite(msg)
	if err != nil {
		return nil, types.GasReport{}, err
	}

	infoPtr, err := i.allocateAndWrite(migrateInfo)
	if err != nil {
		return nil, types.GasReport{}, err
	}

	resultPtr, err := i.callFunction("migrate_with_info", msgPtr, infoPtr)
	if err != nil {
		return nil, types.GasReport{}, err
	}

	result, err := i.readResult(resultPtr)
	if err != nil {
		return nil, types.GasReport{}, err
	}

	return result, types.GasReport{}, nil
}

// Sudo executes a privileged operation
func (i *WazeroInstance) Sudo(code []byte, msg []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	msgPtr, err := i.allocateAndWrite(msg)
	if err != nil {
		return nil, types.GasReport{}, err
	}

	resultPtr, err := i.callFunction("sudo", msgPtr)
	if err != nil {
		return nil, types.GasReport{}, err
	}

	result, err := i.readResult(resultPtr)
	if err != nil {
		return nil, types.GasReport{}, err
	}

	return result, types.GasReport{}, nil
}

// Reply handles a reply callback
func (i *WazeroInstance) Reply(code []byte, msg []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	msgPtr, err := i.allocateAndWrite(msg)
	if err != nil {
		return nil, types.GasReport{}, err
	}

	resultPtr, err := i.callFunction("reply", msgPtr)
	if err != nil {
		return nil, types.GasReport{}, err
	}

	result, err := i.readResult(resultPtr)
	if err != nil {
		return nil, types.GasReport{}, err
	}

	return result, types.GasReport{}, nil
}
