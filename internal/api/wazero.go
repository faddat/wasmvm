package api

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/CosmWasm/wasmvm/v2/types"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// WazeroInstance represents a Wazero instance of a WebAssembly module
type WazeroInstance struct {
	module api.Module
	env    *Environment
}

// GetModule returns the underlying Wazero module
func (i *WazeroInstance) GetModule() api.Module {
	return i.module
}

// CallFunction calls a function in the Wazero module
func (i *WazeroInstance) CallFunction(name string, params ...uint64) ([]uint64, error) {
	fn := i.module.ExportedFunction(name)
	if fn == nil {
		return nil, fmt.Errorf("function %s not found", name)
	}
	return fn.Call(context.Background(), params...)
}

// Memory returns the module's memory
func (i *WazeroInstance) Memory() api.Memory {
	return i.module.Memory()
}

// Host functions

func (i *WazeroInstance) db_read(ctx context.Context, stack []uint64) {
	key_ptr := api.DecodeU32(stack[0])
	key_len := api.DecodeU32(stack[1])
	val_ptr := api.DecodeU32(stack[2])

	// Read key from memory
	mem := i.Memory()
	key, ok := mem.Read(key_ptr, key_len)
	if !ok {
		stack[0] = 0 // Return 0 on error
		return
	}

	// Call db_read
	val := i.env.Store.Get(key)

	// Write value to memory
	if !mem.Write(val_ptr, val) {
		stack[0] = 0 // Return 0 on error
		return
	}

	stack[0] = uint64(len(val))
}

func (i *WazeroInstance) db_write(ctx context.Context, stack []uint64) {
	key_ptr := api.DecodeU32(stack[0])
	key_len := api.DecodeU32(stack[1])
	val_ptr := api.DecodeU32(stack[2])
	val_len := api.DecodeU32(stack[3])

	// Read key and value from memory
	mem := i.Memory()
	key, ok := mem.Read(key_ptr, key_len)
	if !ok {
		return
	}
	val, ok := mem.Read(val_ptr, val_len)
	if !ok {
		return
	}

	// Call db_write
	i.env.Store.Set(key, val)
}

func (i *WazeroInstance) db_remove(ctx context.Context, stack []uint64) {
	key_ptr := api.DecodeU32(stack[0])
	key_len := api.DecodeU32(stack[1])

	// Read key from memory
	mem := i.Memory()
	key, ok := mem.Read(key_ptr, key_len)
	if !ok {
		return
	}

	// Call db_remove
	i.env.Store.Delete(key)
}

func (i *WazeroInstance) gas_consume(ctx context.Context, stack []uint64) {
	// Gas consumption is tracked by the VM and environment
	// This is a no-op in the Wazero implementation
}

func (i *WazeroInstance) query_chain(ctx context.Context, stack []uint64) {
	request_ptr := api.DecodeU32(stack[0])
	request_len := api.DecodeU32(stack[1])

	// Read request from memory
	mem := i.Memory()
	request, ok := mem.Read(request_ptr, request_len)
	if !ok {
		stack[0] = 0 // Return 0 on error
		return
	}

	// Call query_chain
	var queryRequest types.QueryRequest
	err := json.Unmarshal(request, &queryRequest)
	if err != nil {
		stack[0] = 0 // Return 0 on error
		return
	}

	// Get gas consumed before query
	gasConsumed := i.env.Querier.GasConsumed()

	// Execute query with remaining gas
	response, err := i.env.Querier.Query(queryRequest, gasConsumed)
	if err != nil {
		stack[0] = 0 // Return 0 on error
		return
	}

	// Allocate memory for response
	response_len := uint32(len(response))
	response_ptr, err := i.allocate(uint64(response_len))
	if err != nil {
		stack[0] = 0 // Return 0 on error
		return
	}

	// Write response to memory
	if !mem.Write(uint32(response_ptr), response) {
		stack[0] = 0 // Return 0 on error
		return
	}

	stack[0] = uint64(response_len)
}

// Memory management

func (i *WazeroInstance) allocate(size uint64) (uint64, error) {
	mem := i.Memory()
	if mem == nil {
		return 0, fmt.Errorf("no memory exported")
	}

	// Get current memory size
	currentSize := uint64(mem.Size())
	requiredPages := (size + 65535) / 65536 // Round up to nearest page

	// Grow memory if needed
	if currentSize < requiredPages*65536 {
		pages := uint32(requiredPages - currentSize/65536)
		if _, ok := mem.Grow(pages); !ok {
			return 0, fmt.Errorf("failed to grow memory")
		}
	}

	// For now, just return the next available position
	return currentSize, nil
}

func (i *WazeroInstance) deallocate(ptr uint64) error {
	// In Wazero, we don't actually free memory
	// This is a no-op for now
	return nil
}

// IBC host functions

func (i *WazeroInstance) ibc_channel_open(ctx context.Context, stack []uint64) {
	env_ptr := api.DecodeU32(stack[0])
	msg_ptr := api.DecodeU32(stack[1])

	// Read env and msg from memory
	mem := i.Memory()
	envBytes, ok := mem.Read(env_ptr, 1024) // Use a reasonable buffer size
	if !ok {
		stack[0] = 0 // Return 0 on error
		return
	}

	msg, ok := mem.Read(msg_ptr, 1024)
	if !ok {
		stack[0] = 0 // Return 0 on error
		return
	}

	// Parse the environment and message
	var env types.Env
	err := json.Unmarshal(envBytes, &env)
	if err != nil {
		stack[0] = 0 // Return 0 on error
		return
	}

	var channelMsg types.IBCChannelOpenMsg
	err = json.Unmarshal(msg, &channelMsg)
	if err != nil {
		stack[0] = 0 // Return 0 on error
		return
	}

	// Return success
	stack[0] = 1
}

func (i *WazeroInstance) ibc_channel_connect(ctx context.Context, stack []uint64) {
	env_ptr := api.DecodeU32(stack[0])
	msg_ptr := api.DecodeU32(stack[1])

	// Read env and msg from memory
	mem := i.Memory()
	envBytes, ok := mem.Read(env_ptr, 1024)
	if !ok {
		stack[0] = 0 // Return 0 on error
		return
	}

	msg, ok := mem.Read(msg_ptr, 1024)
	if !ok {
		stack[0] = 0 // Return 0 on error
		return
	}

	// Parse the environment and message
	var env types.Env
	err := json.Unmarshal(envBytes, &env)
	if err != nil {
		stack[0] = 0 // Return 0 on error
		return
	}

	var channelMsg types.IBCChannelConnectMsg
	err = json.Unmarshal(msg, &channelMsg)
	if err != nil {
		stack[0] = 0 // Return 0 on error
		return
	}

	// Return success
	stack[0] = 1
}

func (i *WazeroInstance) ibc_channel_close(ctx context.Context, stack []uint64) {
	env_ptr := api.DecodeU32(stack[0])
	msg_ptr := api.DecodeU32(stack[1])

	// Read env and msg from memory
	mem := i.Memory()
	envBytes, ok := mem.Read(env_ptr, 1024)
	if !ok {
		stack[0] = 0 // Return 0 on error
		return
	}

	msg, ok := mem.Read(msg_ptr, 1024)
	if !ok {
		stack[0] = 0 // Return 0 on error
		return
	}

	// Parse the environment and message
	var env types.Env
	err := json.Unmarshal(envBytes, &env)
	if err != nil {
		stack[0] = 0 // Return 0 on error
		return
	}

	var channelMsg types.IBCChannelCloseMsg
	err = json.Unmarshal(msg, &channelMsg)
	if err != nil {
		stack[0] = 0 // Return 0 on error
		return
	}

	// Return success
	stack[0] = 1
}

func (i *WazeroInstance) ibc_packet_receive(ctx context.Context, stack []uint64) {
	env_ptr := api.DecodeU32(stack[0])
	msg_ptr := api.DecodeU32(stack[1])

	// Read env and msg from memory
	mem := i.Memory()
	envBytes, ok := mem.Read(env_ptr, 1024)
	if !ok {
		stack[0] = 0 // Return 0 on error
		return
	}

	msg, ok := mem.Read(msg_ptr, 1024)
	if !ok {
		stack[0] = 0 // Return 0 on error
		return
	}

	// Parse the environment and message
	var env types.Env
	err := json.Unmarshal(envBytes, &env)
	if err != nil {
		stack[0] = 0 // Return 0 on error
		return
	}

	var packetMsg types.IBCPacketReceiveMsg
	err = json.Unmarshal(msg, &packetMsg)
	if err != nil {
		stack[0] = 0 // Return 0 on error
		return
	}

	// Return success
	stack[0] = 1
}

func (i *WazeroInstance) ibc_packet_ack(ctx context.Context, stack []uint64) {
	env_ptr := api.DecodeU32(stack[0])
	msg_ptr := api.DecodeU32(stack[1])

	// Read env and msg from memory
	mem := i.Memory()
	envBytes, ok := mem.Read(env_ptr, 1024)
	if !ok {
		stack[0] = 0 // Return 0 on error
		return
	}

	msg, ok := mem.Read(msg_ptr, 1024)
	if !ok {
		stack[0] = 0 // Return 0 on error
		return
	}

	// Parse the environment and message
	var env types.Env
	err := json.Unmarshal(envBytes, &env)
	if err != nil {
		stack[0] = 0 // Return 0 on error
		return
	}

	var ackMsg types.IBCPacketAckMsg
	err = json.Unmarshal(msg, &ackMsg)
	if err != nil {
		stack[0] = 0 // Return 0 on error
		return
	}

	// Return success
	stack[0] = 1
}

func (i *WazeroInstance) ibc_packet_timeout(ctx context.Context, stack []uint64) {
	env_ptr := api.DecodeU32(stack[0])
	msg_ptr := api.DecodeU32(stack[1])

	// Read env and msg from memory
	mem := i.Memory()
	envBytes, ok := mem.Read(env_ptr, 1024)
	if !ok {
		stack[0] = 0 // Return 0 on error
		return
	}

	msg, ok := mem.Read(msg_ptr, 1024)
	if !ok {
		stack[0] = 0 // Return 0 on error
		return
	}

	// Parse the environment and message
	var env types.Env
	err := json.Unmarshal(envBytes, &env)
	if err != nil {
		stack[0] = 0 // Return 0 on error
		return
	}

	var timeoutMsg types.IBCPacketTimeoutMsg
	err = json.Unmarshal(msg, &timeoutMsg)
	if err != nil {
		stack[0] = 0 // Return 0 on error
		return
	}

	// Return success
	stack[0] = 1
}

// Environment and API host functions

func (i *WazeroInstance) env_get(ctx context.Context, stack []uint64) {
	key_ptr := api.DecodeU32(stack[0])
	key_len := api.DecodeU32(stack[1])
	val_ptr := api.DecodeU32(stack[2])

	// Read key from memory
	mem := i.Memory()
	keyBytes, ok := mem.Read(key_ptr, key_len)
	if !ok {
		stack[0] = 0 // Return 0 on error
		return
	}

	// Get value from environment based on key
	var valBytes []byte
	key := string(keyBytes)
	switch key {
	case "block.height":
		valBytes = []byte(fmt.Sprintf("%d", i.env.Block.Height))
	case "block.time":
		valBytes = []byte(fmt.Sprintf("%d", i.env.Block.Time))
	case "block.chain_id":
		valBytes = []byte(i.env.Block.ChainID)
	case "contract.address":
		valBytes = []byte(i.env.Contract.Address)
	case "contract.creator":
		valBytes = []byte(i.env.Contract.Creator)
	case "transaction.index":
		if i.env.Transaction != nil {
			valBytes = []byte(fmt.Sprintf("%d", i.env.Transaction.Index))
		} else {
			stack[0] = 0 // Return 0 if transaction info is not available
			return
		}
	default:
		stack[0] = 0 // Return 0 if key not found
		return
	}

	// Write value to memory
	if !mem.Write(val_ptr, valBytes) {
		stack[0] = 0 // Return 0 on error
		return
	}

	stack[0] = uint64(len(valBytes))
}

func (i *WazeroInstance) humanize_address(ctx context.Context, stack []uint64) {
	addr_ptr := api.DecodeU32(stack[0])
	addr_len := api.DecodeU32(stack[1])
	out_ptr := api.DecodeU32(stack[2])

	// Read address from memory
	mem := i.Memory()
	addr, ok := mem.Read(addr_ptr, addr_len)
	if !ok {
		stack[0] = 0 // Return 0 on error
		return
	}

	// Call humanize_address
	humanAddr, gasCost, err := i.env.API.HumanizeAddress(addr)
	if err != nil {
		stack[0] = 0 // Return 0 on error
		return
	}

	// Write result to memory
	if !mem.Write(out_ptr, []byte(humanAddr)) {
		stack[0] = 0 // Return 0 on error
		return
	}

	stack[0] = uint64(len(humanAddr))
	stack[1] = gasCost
}

func (i *WazeroInstance) canonicalize_address(ctx context.Context, stack []uint64) {
	addr_ptr := api.DecodeU32(stack[0])
	addr_len := api.DecodeU32(stack[1])
	out_ptr := api.DecodeU32(stack[2])

	// Read address from memory
	mem := i.Memory()
	addr, ok := mem.Read(addr_ptr, addr_len)
	if !ok {
		stack[0] = 0 // Return 0 on error
		return
	}

	// Call canonicalize_address
	canonAddr, gasCost, err := i.env.API.CanonicalizeAddress(string(addr))
	if err != nil {
		stack[0] = 0 // Return 0 on error
		return
	}

	// Write result to memory
	if !mem.Write(out_ptr, canonAddr) {
		stack[0] = 0 // Return 0 on error
		return
	}

	stack[0] = uint64(len(canonAddr))
	stack[1] = gasCost
}

func (i *WazeroInstance) validate_address(ctx context.Context, stack []uint64) {
	addr_ptr := api.DecodeU32(stack[0])
	addr_len := api.DecodeU32(stack[1])

	// Read address from memory
	mem := i.Memory()
	addr, ok := mem.Read(addr_ptr, addr_len)
	if !ok {
		stack[0] = 0 // Return 0 on error
		return
	}

	// Call validate_address
	gasCost, err := i.env.API.ValidateAddress(string(addr))
	if err != nil {
		stack[0] = 0 // Return 0 on error
		return
	}

	stack[0] = 1 // Return 1 on success
	stack[1] = gasCost
}

// Memory management host functions

func (i *WazeroInstance) alloc(ctx context.Context, stack []uint64) {
	size := stack[0]

	// Allocate memory
	ptr, err := i.allocate(size)
	if err != nil {
		stack[0] = 0 // Return 0 on error
		return
	}

	stack[0] = ptr
}

func (i *WazeroInstance) dealloc(ctx context.Context, stack []uint64) {
	ptr := stack[0]

	// Deallocate memory
	err := i.deallocate(ptr)
	if err != nil {
		return
	}
}

// NewWazeroInstance creates a new Wazero instance
func NewWazeroInstance(code []byte, gasLimit uint64) (*WazeroInstance, error) {
	// Create a new context
	ctx := context.Background()

	// Create a new runtime configuration
	config := wazero.NewRuntimeConfig().
		WithMemoryLimitPages(65536). // 4GB max memory
		WithCloseOnContextDone(true)

	// Create a new runtime
	r := wazero.NewRuntimeWithConfig(ctx, config)

	// Create a new instance
	instance := &WazeroInstance{
		module: nil,
		env:    nil, // Will be set by the VM
	}

	// Create module configuration
	moduleConfig := wazero.NewModuleConfig().
		WithName("env") // Required for WASM modules

	// Create the host module with all our functions
	builder := r.NewHostModuleBuilder("env")

	// Add host functions with their signatures
	builder.NewFunctionBuilder().WithFunc(instance.db_read).Export("db_read")
	builder.NewFunctionBuilder().WithFunc(instance.db_write).Export("db_write")
	builder.NewFunctionBuilder().WithFunc(instance.db_remove).Export("db_remove")
	builder.NewFunctionBuilder().WithFunc(instance.gas_consume).Export("gas_consume")
	builder.NewFunctionBuilder().WithFunc(instance.query_chain).Export("query_chain")
	builder.NewFunctionBuilder().WithFunc(instance.env_get).Export("env_get")
	builder.NewFunctionBuilder().WithFunc(instance.humanize_address).Export("humanize_address")
	builder.NewFunctionBuilder().WithFunc(instance.canonicalize_address).Export("canonicalize_address")
	builder.NewFunctionBuilder().WithFunc(instance.validate_address).Export("validate_address")
	builder.NewFunctionBuilder().WithFunc(instance.alloc).Export("alloc")
	builder.NewFunctionBuilder().WithFunc(instance.dealloc).Export("dealloc")
	builder.NewFunctionBuilder().WithFunc(instance.ibc_channel_open).Export("ibc_channel_open")
	builder.NewFunctionBuilder().WithFunc(instance.ibc_channel_connect).Export("ibc_channel_connect")
	builder.NewFunctionBuilder().WithFunc(instance.ibc_channel_close).Export("ibc_channel_close")
	builder.NewFunctionBuilder().WithFunc(instance.ibc_packet_receive).Export("ibc_packet_receive")
	builder.NewFunctionBuilder().WithFunc(instance.ibc_packet_ack).Export("ibc_packet_ack")
	builder.NewFunctionBuilder().WithFunc(instance.ibc_packet_timeout).Export("ibc_packet_timeout")

	// Instantiate the host module
	_, err := builder.Instantiate(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create host module: %v", err)
	}

	// Compile the module
	compiled, err := r.CompileModule(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("failed to compile module: %v", err)
	}

	// Instantiate the module
	module, err := r.InstantiateModule(ctx, compiled, moduleConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate module: %v", err)
	}

	// Set the module in the instance
	instance.module = module

	return instance, nil
}

// Close releases all resources associated with the instance
func (i *WazeroInstance) Close() error {
	if i.module != nil {
		return i.module.Close(context.Background())
	}
	return nil
}

// Memory management methods

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

func (i *WazeroInstance) AllocateMemory(size uint64) (uint64, error) {
	return i.allocate(size)
}

func (i *WazeroInstance) DeallocateMemory(ptr uint64) error {
	return i.deallocate(ptr)
}
