package api

import (
	"context"
	"fmt"

	"github.com/CosmWasm/wasmvm/v2/types"
	"github.com/tetratelabs/wazero"
	wazeroapi "github.com/tetratelabs/wazero/api"
)

// NewWazeroVM wraps creation of a WazeroInstance. Validate the environment, then
// compile and instantiate the WASM module from env.Code.
func NewWazeroVM(env *Environment, gasMeter types.GasMeter, gasLimit uint64) (*WazeroInstance, error) {
	// Ensure all required fields are valid
	if err := env.Validate(); err != nil {
		return nil, err
	}
	if len(env.Code) == 0 {
		return nil, fmt.Errorf("no wasm code found in Environment.Code")
	}

	instance, err := NewWazeroInstance(env, env.Code, gasLimit)
	if err != nil {
		return nil, err
	}
	instance.env = env
	return instance, nil
}

// WazeroInstance represents a Wazero instance of a WebAssembly module
type WazeroInstance struct {
	module wazeroapi.Module
	env    *Environment
}

// NewWazeroInstance compiles and instantiates the given WASM code with a memory limit.
func NewWazeroInstance(env *Environment, code []byte, gasLimit uint64) (*WazeroInstance, error) {
	ctx := context.Background()

	// Example: This runtime config might be updated to reflect memory or compiler settings
	config := wazero.NewRuntimeConfig().
		WithMemoryLimitPages(65536).
		WithCloseOnContextDone(true)

	r := wazero.NewRuntimeWithConfig(ctx, config)
	instance := &WazeroInstance{module: nil, env: env}

	// Build a host module named "env" for the host functions
	builder := r.NewHostModuleBuilder("env")

	// Register host functions (db_read, db_write, etc.). For brevity, we show only db_read:
	for name, fn := range instance.hostFuncs() {
		builder.
			NewFunctionBuilder().
			WithGoModuleFunction(fn, []wazeroapi.ValueType{
				wazeroapi.ValueTypeI32, wazeroapi.ValueTypeI32, wazeroapi.ValueTypeI32, wazeroapi.ValueTypeI32,
			}, []wazeroapi.ValueType{
				wazeroapi.ValueTypeI64, wazeroapi.ValueTypeI64,
			}).
			Export(name)
	}

	if _, err := builder.Instantiate(ctx); err != nil {
		return nil, fmt.Errorf("failed to create host module: %w", err)
	}

	// Compile module
	compiled, err := r.CompileModule(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("failed to compile module: %w", err)
	}

	// Instantiate the module with default module config
	mod, err := r.InstantiateModule(ctx, compiled, wazero.NewModuleConfig().WithName("env"))
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate module: %w", err)
	}

	instance.module = mod
	return instance, nil
}

// Close releases the underlying module. This should be deferred.
func (i *WazeroInstance) Close() error {
	if i.module == nil {
		return nil
	}
	return i.module.Close(context.Background())
}

// Memory returns the default memory exported by the module (if any)
func (i *WazeroInstance) Memory() wazeroapi.Memory {
	if i.module == nil {
		return nil
	}
	return i.module.Memory()
}

// hostFuncs creates a set of host function mappings
func (i *WazeroInstance) hostFuncs() map[string]wazeroapi.GoModuleFunction {
	return map[string]wazeroapi.GoModuleFunction{
		"db_read": wazeroapi.GoModuleFunc(func(ctx context.Context, mod wazeroapi.Module, stack []uint64) {
			i.db_read(ctx, mod, stack)
		}),
		// db_write, db_remove, gasConsume, etc. could be added similarly
	}
}

// Example host function. Adjust logic and param usage as needed.
func (i *WazeroInstance) db_read(ctx context.Context, mod wazeroapi.Module, stack []uint64) {
	// Typically, decode offset and length from stack
	keyPtr := DecodeU32(stack[0])
	keyLen := DecodeU32(stack[1])

	// Perform read logic, handle errors, etc.
	if i.env == nil || i.env.Store == nil {
		stack[0] = EncodeI32(-1)
		return
	}

	// Example usage of i.Memory() to read the key
	keyBytes, ok := i.Memory().Read(keyPtr, keyLen)
	if !ok {
		stack[0] = EncodeI32(-1)
		return
	}

	valueBytes := i.env.Store.Get(keyBytes)
	if valueBytes == nil {
		stack[0] = EncodeI32(-1)
		return
	}

	// If read success, push success code
	stack[0] = EncodeI32(0)
}

// allocate extends the memory if needed, returning the start offset
func (i *WazeroInstance) allocate(size uint64) (uint64, error) {
	mem := i.Memory()
	if mem == nil {
		return 0, fmt.Errorf("no memory exported")
	}
	currentPages := uint64(mem.Size() / 65536)
	requiredPages := (size + 65535) / 65536
	if requiredPages > currentPages {
		_, ok := mem.Grow(uint32(requiredPages - currentPages))
		if !ok {
			return 0, fmt.Errorf("failed to grow memory to accommodate %d bytes", size)
		}
	}
	// Return the offset as currentPages * 65536
	return currentPages * 65536, nil
}

// deallocate is a no-op, but can be extended to do free-lists or other logic
func (i *WazeroInstance) deallocate(_ uint64) error {
	return nil
}

// ReadMemory reads bytes from WASM memory
func (i *WazeroInstance) ReadMemory(offset uint32, size uint32) ([]byte, error) {
	mem := i.Memory()
	if mem == nil {
		return nil, fmt.Errorf("no memory exported")
	}
	data, ok := mem.Read(offset, size)
	if !ok {
		return nil, fmt.Errorf("failed to read memory at offset %d with size %d", offset, size)
	}
	return data, nil
}

// WriteMemory writes bytes to WASM memory
func (i *WazeroInstance) WriteMemory(offset uint32, data []byte) error {
	mem := i.Memory()
	if mem == nil {
		return fmt.Errorf("no memory exported")
	}
	if !mem.Write(offset, data) {
		return fmt.Errorf("failed to write memory at offset %d with size %d", offset, len(data))
	}
	return nil
}

// AllocateMemory allocates memory for size bytes
func (i *WazeroInstance) AllocateMemory(size uint64) (uint64, error) {
	return i.allocate(size)
}

// DeallocateMemory frees allocated memory (no-op here)
func (i *WazeroInstance) DeallocateMemory(ptr uint64) error {
	return i.deallocate(ptr)
}

// EncodeI32 encodes an int32 for WebAssembly
func EncodeI32(x int32) uint64 {
	return uint64(uint32(x))
}

// DecodeU32 decodes a uint32 from WebAssembly
func DecodeU32(x uint64) uint32 {
	return uint32(x)
}

// EncodeI64 encodes an int64 for WebAssembly
func EncodeI64(x int64) uint64 {
	return uint64(x)
}

// DecodeI64 decodes an int64 from WebAssembly
func DecodeI64(x uint64) int64 {
	return int64(x)
}

// Instantiate calls the instantiate function in the Wasm module
func (i *WazeroInstance) Instantiate(env []byte, info []byte, msg []byte,
	gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI,
	querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {

	// Write environment data to memory
	envPtr, err := i.AllocateMemory(uint64(len(env)))
	if err != nil {
		return nil, types.GasReport{}, err
	}
	if err := i.WriteMemory(uint32(envPtr), env); err != nil {
		return nil, types.GasReport{}, err
	}

	// Write info data to memory
	infoPtr, err := i.AllocateMemory(uint64(len(info)))
	if err != nil {
		return nil, types.GasReport{}, err
	}
	if err := i.WriteMemory(uint32(infoPtr), info); err != nil {
		return nil, types.GasReport{}, err
	}

	// Write message data to memory
	msgPtr, err := i.AllocateMemory(uint64(len(msg)))
	if err != nil {
		return nil, types.GasReport{}, err
	}
	if err := i.WriteMemory(uint32(msgPtr), msg); err != nil {
		return nil, types.GasReport{}, err
	}

	// Call instantiate function
	results, err := i.module.ExportedFunction("instantiate").Call(context.Background(), envPtr, infoPtr, msgPtr)
	if err != nil {
		return nil, types.GasReport{}, err
	}

	// Read result from memory
	resultPtr := DecodeU32(results[0])
	resultLen := DecodeU32(results[1])
	result, err := i.ReadMemory(resultPtr, resultLen)
	if err != nil {
		return nil, types.GasReport{}, err
	}

	return result, types.GasReport{}, nil
}

// Execute calls the execute function in the Wasm module
func (i *WazeroInstance) Execute(env []byte, info []byte, msg []byte,
	gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI,
	querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {

	// Write environment data to memory
	envPtr, err := i.AllocateMemory(uint64(len(env)))
	if err != nil {
		return nil, types.GasReport{}, err
	}
	if err := i.WriteMemory(uint32(envPtr), env); err != nil {
		return nil, types.GasReport{}, err
	}

	// Write info data to memory
	infoPtr, err := i.AllocateMemory(uint64(len(info)))
	if err != nil {
		return nil, types.GasReport{}, err
	}
	if err := i.WriteMemory(uint32(infoPtr), info); err != nil {
		return nil, types.GasReport{}, err
	}

	// Write message data to memory
	msgPtr, err := i.AllocateMemory(uint64(len(msg)))
	if err != nil {
		return nil, types.GasReport{}, err
	}
	if err := i.WriteMemory(uint32(msgPtr), msg); err != nil {
		return nil, types.GasReport{}, err
	}

	// Call execute function
	results, err := i.module.ExportedFunction("execute").Call(context.Background(), envPtr, infoPtr, msgPtr)
	if err != nil {
		return nil, types.GasReport{}, err
	}

	// Read result from memory
	resultPtr := DecodeU32(results[0])
	resultLen := DecodeU32(results[1])
	result, err := i.ReadMemory(resultPtr, resultLen)
	if err != nil {
		return nil, types.GasReport{}, err
	}

	return result, types.GasReport{}, nil
}

// Query calls the query function in the Wasm module
func (i *WazeroInstance) Query(env []byte, msg []byte,
	gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI,
	querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {

	// Write environment data to memory
	envPtr, err := i.AllocateMemory(uint64(len(env)))
	if err != nil {
		return nil, types.GasReport{}, err
	}
	if err := i.WriteMemory(uint32(envPtr), env); err != nil {
		return nil, types.GasReport{}, err
	}

	// Write message data to memory
	msgPtr, err := i.AllocateMemory(uint64(len(msg)))
	if err != nil {
		return nil, types.GasReport{}, err
	}
	if err := i.WriteMemory(uint32(msgPtr), msg); err != nil {
		return nil, types.GasReport{}, err
	}

	// Call query function
	results, err := i.module.ExportedFunction("query").Call(context.Background(), envPtr, msgPtr)
	if err != nil {
		return nil, types.GasReport{}, err
	}

	// Read result from memory
	resultPtr := DecodeU32(results[0])
	resultLen := DecodeU32(results[1])
	result, err := i.ReadMemory(resultPtr, resultLen)
	if err != nil {
		return nil, types.GasReport{}, err
	}

	return result, types.GasReport{}, nil
}

// Migrate calls the migrate function in the Wasm module
func (i *WazeroInstance) Migrate(env []byte, msg []byte,
	gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI,
	querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {

	// Write environment data to memory
	envPtr, err := i.AllocateMemory(uint64(len(env)))
	if err != nil {
		return nil, types.GasReport{}, err
	}
	if err := i.WriteMemory(uint32(envPtr), env); err != nil {
		return nil, types.GasReport{}, err
	}

	// Write message data to memory
	msgPtr, err := i.AllocateMemory(uint64(len(msg)))
	if err != nil {
		return nil, types.GasReport{}, err
	}
	if err := i.WriteMemory(uint32(msgPtr), msg); err != nil {
		return nil, types.GasReport{}, err
	}

	// Call migrate function
	results, err := i.module.ExportedFunction("migrate").Call(context.Background(), envPtr, msgPtr)
	if err != nil {
		return nil, types.GasReport{}, err
	}

	// Read result from memory
	resultPtr := DecodeU32(results[0])
	resultLen := DecodeU32(results[1])
	result, err := i.ReadMemory(resultPtr, resultLen)
	if err != nil {
		return nil, types.GasReport{}, err
	}

	return result, types.GasReport{}, nil
}

// IBCChannelOpen calls the ibc_channel_open function in the Wasm module
func (i *WazeroInstance) IBCChannelOpen(env []byte, msg []byte,
	gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI,
	querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {

	// Write environment data to memory
	envPtr, err := i.AllocateMemory(uint64(len(env)))
	if err != nil {
		return nil, types.GasReport{}, err
	}
	if err := i.WriteMemory(uint32(envPtr), env); err != nil {
		return nil, types.GasReport{}, err
	}

	// Write message data to memory
	msgPtr, err := i.AllocateMemory(uint64(len(msg)))
	if err != nil {
		return nil, types.GasReport{}, err
	}
	if err := i.WriteMemory(uint32(msgPtr), msg); err != nil {
		return nil, types.GasReport{}, err
	}

	// Call ibc_channel_open function
	results, err := i.module.ExportedFunction("ibc_channel_open").Call(context.Background(), envPtr, msgPtr)
	if err != nil {
		return nil, types.GasReport{}, err
	}

	// Read result from memory
	resultPtr := DecodeU32(results[0])
	resultLen := DecodeU32(results[1])
	result, err := i.ReadMemory(resultPtr, resultLen)
	if err != nil {
		return nil, types.GasReport{}, err
	}

	return result, types.GasReport{}, nil
}

// IBCChannelConnect calls the ibc_channel_connect function in the Wasm module
func (i *WazeroInstance) IBCChannelConnect(env []byte, msg []byte,
	gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI,
	querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {

	// Write environment data to memory
	envPtr, err := i.AllocateMemory(uint64(len(env)))
	if err != nil {
		return nil, types.GasReport{}, err
	}
	if err := i.WriteMemory(uint32(envPtr), env); err != nil {
		return nil, types.GasReport{}, err
	}

	// Write message data to memory
	msgPtr, err := i.AllocateMemory(uint64(len(msg)))
	if err != nil {
		return nil, types.GasReport{}, err
	}
	if err := i.WriteMemory(uint32(msgPtr), msg); err != nil {
		return nil, types.GasReport{}, err
	}

	// Call ibc_channel_connect function
	results, err := i.module.ExportedFunction("ibc_channel_connect").Call(context.Background(), envPtr, msgPtr)
	if err != nil {
		return nil, types.GasReport{}, err
	}

	// Read result from memory
	resultPtr := DecodeU32(results[0])
	resultLen := DecodeU32(results[1])
	result, err := i.ReadMemory(resultPtr, resultLen)
	if err != nil {
		return nil, types.GasReport{}, err
	}

	return result, types.GasReport{}, nil
}

// IBCChannelClose calls the ibc_channel_close function in the Wasm module
func (i *WazeroInstance) IBCChannelClose(env []byte, msg []byte,
	gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI,
	querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {

	// Write environment data to memory
	envPtr, err := i.AllocateMemory(uint64(len(env)))
	if err != nil {
		return nil, types.GasReport{}, err
	}
	if err := i.WriteMemory(uint32(envPtr), env); err != nil {
		return nil, types.GasReport{}, err
	}

	// Write message data to memory
	msgPtr, err := i.AllocateMemory(uint64(len(msg)))
	if err != nil {
		return nil, types.GasReport{}, err
	}
	if err := i.WriteMemory(uint32(msgPtr), msg); err != nil {
		return nil, types.GasReport{}, err
	}

	// Call ibc_channel_close function
	results, err := i.module.ExportedFunction("ibc_channel_close").Call(context.Background(), envPtr, msgPtr)
	if err != nil {
		return nil, types.GasReport{}, err
	}

	// Read result from memory
	resultPtr := DecodeU32(results[0])
	resultLen := DecodeU32(results[1])
	result, err := i.ReadMemory(resultPtr, resultLen)
	if err != nil {
		return nil, types.GasReport{}, err
	}

	return result, types.GasReport{}, nil
}

// IBCPacketReceive calls the ibc_packet_receive function in the Wasm module
func (i *WazeroInstance) IBCPacketReceive(env []byte, msg []byte,
	gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI,
	querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {

	// Write environment data to memory
	envPtr, err := i.AllocateMemory(uint64(len(env)))
	if err != nil {
		return nil, types.GasReport{}, err
	}
	if err := i.WriteMemory(uint32(envPtr), env); err != nil {
		return nil, types.GasReport{}, err
	}

	// Write message data to memory
	msgPtr, err := i.AllocateMemory(uint64(len(msg)))
	if err != nil {
		return nil, types.GasReport{}, err
	}
	if err := i.WriteMemory(uint32(msgPtr), msg); err != nil {
		return nil, types.GasReport{}, err
	}

	// Call ibc_packet_receive function
	results, err := i.module.ExportedFunction("ibc_packet_receive").Call(context.Background(), envPtr, msgPtr)
	if err != nil {
		return nil, types.GasReport{}, err
	}

	// Read result from memory
	resultPtr := DecodeU32(results[0])
	resultLen := DecodeU32(results[1])
	result, err := i.ReadMemory(resultPtr, resultLen)
	if err != nil {
		return nil, types.GasReport{}, err
	}

	return result, types.GasReport{}, nil
}

// IBCPacketAck calls the ibc_packet_ack function in the Wasm module
func (i *WazeroInstance) IBCPacketAck(env []byte, msg []byte,
	gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI,
	querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {

	// Write environment data to memory
	envPtr, err := i.AllocateMemory(uint64(len(env)))
	if err != nil {
		return nil, types.GasReport{}, err
	}
	if err := i.WriteMemory(uint32(envPtr), env); err != nil {
		return nil, types.GasReport{}, err
	}

	// Write message data to memory
	msgPtr, err := i.AllocateMemory(uint64(len(msg)))
	if err != nil {
		return nil, types.GasReport{}, err
	}
	if err := i.WriteMemory(uint32(msgPtr), msg); err != nil {
		return nil, types.GasReport{}, err
	}

	// Call ibc_packet_ack function
	results, err := i.module.ExportedFunction("ibc_packet_ack").Call(context.Background(), envPtr, msgPtr)
	if err != nil {
		return nil, types.GasReport{}, err
	}

	// Read result from memory
	resultPtr := DecodeU32(results[0])
	resultLen := DecodeU32(results[1])
	result, err := i.ReadMemory(resultPtr, resultLen)
	if err != nil {
		return nil, types.GasReport{}, err
	}

	return result, types.GasReport{}, nil
}

// IBCPacketTimeout calls the ibc_packet_timeout function in the Wasm module
func (i *WazeroInstance) IBCPacketTimeout(env []byte, msg []byte,
	gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI,
	querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {

	// Write environment data to memory
	envPtr, err := i.AllocateMemory(uint64(len(env)))
	if err != nil {
		return nil, types.GasReport{}, err
	}
	if err := i.WriteMemory(uint32(envPtr), env); err != nil {
		return nil, types.GasReport{}, err
	}

	// Write message data to memory
	msgPtr, err := i.AllocateMemory(uint64(len(msg)))
	if err != nil {
		return nil, types.GasReport{}, err
	}
	if err := i.WriteMemory(uint32(msgPtr), msg); err != nil {
		return nil, types.GasReport{}, err
	}

	// Call ibc_packet_timeout function
	results, err := i.module.ExportedFunction("ibc_packet_timeout").Call(context.Background(), envPtr, msgPtr)
	if err != nil {
		return nil, types.GasReport{}, err
	}

	// Read result from memory
	resultPtr := DecodeU32(results[0])
	resultLen := DecodeU32(results[1])
	result, err := i.ReadMemory(resultPtr, resultLen)
	if err != nil {
		return nil, types.GasReport{}, err
	}

	return result, types.GasReport{}, nil
}

// MigrateWithInfo calls the migrate_with_info function in the Wasm module
func (i *WazeroInstance) MigrateWithInfo(checksum []byte, env []byte, msg []byte, migrateInfo []byte,
	gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI,
	querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {

	// Write environment data to memory
	envPtr, err := i.AllocateMemory(uint64(len(env)))
	if err != nil {
		return nil, types.GasReport{}, err
	}
	if err := i.WriteMemory(uint32(envPtr), env); err != nil {
		return nil, types.GasReport{}, err
	}

	// Write message data to memory
	msgPtr, err := i.AllocateMemory(uint64(len(msg)))
	if err != nil {
		return nil, types.GasReport{}, err
	}
	if err := i.WriteMemory(uint32(msgPtr), msg); err != nil {
		return nil, types.GasReport{}, err
	}

	// Write migrate info to memory
	infoPtr, err := i.AllocateMemory(uint64(len(migrateInfo)))
	if err != nil {
		return nil, types.GasReport{}, err
	}
	if err := i.WriteMemory(uint32(infoPtr), migrateInfo); err != nil {
		return nil, types.GasReport{}, err
	}

	// Call migrate_with_info function
	results, err := i.module.ExportedFunction("migrate_with_info").Call(context.Background(), envPtr, msgPtr, infoPtr)
	if err != nil {
		return nil, types.GasReport{}, err
	}

	// Read result from memory
	resultPtr := DecodeU32(results[0])
	resultLen := DecodeU32(results[1])
	result, err := i.ReadMemory(resultPtr, resultLen)
	if err != nil {
		return nil, types.GasReport{}, err
	}

	return result, types.GasReport{}, nil
}

// Sudo calls the sudo function in the Wasm module
func (i *WazeroInstance) Sudo(env []byte, msg []byte,
	gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI,
	querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {

	// Write environment data to memory
	envPtr, err := i.AllocateMemory(uint64(len(env)))
	if err != nil {
		return nil, types.GasReport{}, err
	}
	if err := i.WriteMemory(uint32(envPtr), env); err != nil {
		return nil, types.GasReport{}, err
	}

	// Write message data to memory
	msgPtr, err := i.AllocateMemory(uint64(len(msg)))
	if err != nil {
		return nil, types.GasReport{}, err
	}
	if err := i.WriteMemory(uint32(msgPtr), msg); err != nil {
		return nil, types.GasReport{}, err
	}

	// Call sudo function
	results, err := i.module.ExportedFunction("sudo").Call(context.Background(), envPtr, msgPtr)
	if err != nil {
		return nil, types.GasReport{}, err
	}

	// Read result from memory
	resultPtr := DecodeU32(results[0])
	resultLen := DecodeU32(results[1])
	result, err := i.ReadMemory(resultPtr, resultLen)
	if err != nil {
		return nil, types.GasReport{}, err
	}

	return result, types.GasReport{}, nil
}

// Reply calls the reply function in the Wasm module
func (i *WazeroInstance) Reply(env []byte, reply []byte,
	gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI,
	querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {

	// Write environment data to memory
	envPtr, err := i.AllocateMemory(uint64(len(env)))
	if err != nil {
		return nil, types.GasReport{}, err
	}
	if err := i.WriteMemory(uint32(envPtr), env); err != nil {
		return nil, types.GasReport{}, err
	}

	// Write reply data to memory
	replyPtr, err := i.AllocateMemory(uint64(len(reply)))
	if err != nil {
		return nil, types.GasReport{}, err
	}
	if err := i.WriteMemory(uint32(replyPtr), reply); err != nil {
		return nil, types.GasReport{}, err
	}

	// Call reply function
	results, err := i.module.ExportedFunction("reply").Call(context.Background(), envPtr, replyPtr)
	if err != nil {
		return nil, types.GasReport{}, err
	}

	// Read result from memory
	resultPtr := DecodeU32(results[0])
	resultLen := DecodeU32(results[1])
	result, err := i.ReadMemory(resultPtr, resultLen)
	if err != nil {
		return nil, types.GasReport{}, err
	}

	return result, types.GasReport{}, nil
}

// IBCSourceCallback calls the ibc_source_callback function in the Wasm module
func (i *WazeroInstance) IBCSourceCallback(env []byte, msg []byte,
	gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI,
	querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {

	// Write environment data to memory
	envPtr, err := i.AllocateMemory(uint64(len(env)))
	if err != nil {
		return nil, types.GasReport{}, err
	}
	if err := i.WriteMemory(uint32(envPtr), env); err != nil {
		return nil, types.GasReport{}, err
	}

	// Write message data to memory
	msgPtr, err := i.AllocateMemory(uint64(len(msg)))
	if err != nil {
		return nil, types.GasReport{}, err
	}
	if err := i.WriteMemory(uint32(msgPtr), msg); err != nil {
		return nil, types.GasReport{}, err
	}

	// Call ibc_source_callback function
	results, err := i.module.ExportedFunction("ibc_source_callback").Call(context.Background(), envPtr, msgPtr)
	if err != nil {
		return nil, types.GasReport{}, err
	}

	// Read result from memory
	resultPtr := DecodeU32(results[0])
	resultLen := DecodeU32(results[1])
	result, err := i.ReadMemory(resultPtr, resultLen)
	if err != nil {
		return nil, types.GasReport{}, err
	}

	return result, types.GasReport{}, nil
}

// IBCDestinationCallback calls the ibc_destination_callback function in the Wasm module
func (i *WazeroInstance) IBCDestinationCallback(env []byte, msg []byte,
	gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI,
	querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {

	// Write environment data to memory
	envPtr, err := i.AllocateMemory(uint64(len(env)))
	if err != nil {
		return nil, types.GasReport{}, err
	}
	if err := i.WriteMemory(uint32(envPtr), env); err != nil {
		return nil, types.GasReport{}, err
	}

	// Write message data to memory
	msgPtr, err := i.AllocateMemory(uint64(len(msg)))
	if err != nil {
		return nil, types.GasReport{}, err
	}
	if err := i.WriteMemory(uint32(msgPtr), msg); err != nil {
		return nil, types.GasReport{}, err
	}

	// Call ibc_destination_callback function
	results, err := i.module.ExportedFunction("ibc_destination_callback").Call(context.Background(), envPtr, msgPtr)
	if err != nil {
		return nil, types.GasReport{}, err
	}

	// Read result from memory
	resultPtr := DecodeU32(results[0])
	resultLen := DecodeU32(results[1])
	result, err := i.ReadMemory(resultPtr, resultLen)
	if err != nil {
		return nil, types.GasReport{}, err
	}

	return result, types.GasReport{}, nil
}
