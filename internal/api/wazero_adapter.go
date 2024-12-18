package api

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strings"

	"github.com/CosmWasm/wasmvm/v2/types"
	"github.com/tetratelabs/wazero/api"
)

// Querier is an alias for types.Querier
type Querier = types.Querier

// WazeroVM represents a Wazero-based WebAssembly virtual machine
type WazeroVM struct {
	instance  *WazeroInstance
	env       *Environment
	gasMeter  types.GasMeter
	gasLimit  uint64
	gasConfig GasConfig
	gasUsed   uint64
}

// GasConfig defines gas costs for various operations
type GasConfig struct {
	GetCost    uint64
	SetCost    uint64
	RemoveCost uint64
	RangePrice uint64
}

// DefaultGasConfig returns default gas costs
func DefaultGasConfig() GasConfig {
	return GasConfig{
		GetCost:    100,
		SetCost:    200,
		RemoveCost: 100,
		RangePrice: 50,
	}
}

// NewWazeroVM creates a new Wazero-based VM with the given gas meter
func NewWazeroVM(env *Environment, gasMeter types.GasMeter, gasLimit uint64) (*WazeroVM, error) {
	if env == nil {
		return nil, fmt.Errorf("environment is required")
	}

	instance, err := NewWazeroInstance(env.Code, gasLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to create wazero instance: %v", err)
	}

	vm := &WazeroVM{
		instance:  instance,
		env:       env,
		gasMeter:  gasMeter,
		gasLimit:  gasLimit,
		gasConfig: DefaultGasConfig(),
		gasUsed:   0,
	}

	return vm, nil
}

// Close releases all resources associated with the VM
func (vm *WazeroVM) Close() error {
	if vm.instance != nil {
		return vm.instance.Close()
	}
	return nil
}

// Implementation of host functions

func (vm *WazeroVM) dbRead(ctx context.Context, mod api.Module, stack []uint64) {
	// Read parameters from stack
	keyPtr := api.DecodeU32(stack[0])
	keyLen := api.DecodeU32(stack[1])
	valuePtr := api.DecodeU32(stack[2])

	// Charge gas for the read operation
	vm.consumeGas(vm.gasConfig.GetCost, "db_read")

	// Read key from Wasm memory
	key, err := vm.instance.ReadMemory(keyPtr, keyLen)
	if err != nil {
		stack[0] = api.EncodeI32(-1)
		return
	}

	// Get value from store
	value := vm.env.Store.Get(key)
	if value == nil {
		stack[0] = api.EncodeI32(0)
		return
	}

	// Write value to Wasm memory
	if err := vm.instance.WriteMemory(valuePtr, value); err != nil {
		stack[0] = api.EncodeI32(-1)
		return
	}

	stack[0] = api.EncodeI32(1)
}

func (vm *WazeroVM) dbWrite(ctx context.Context, mod api.Module, stack []uint64) {
	// Read parameters from stack
	keyPtr := api.DecodeU32(stack[0])
	keyLen := api.DecodeU32(stack[1])
	valuePtr := api.DecodeU32(stack[2])
	valueLen := api.DecodeU32(stack[3])

	// Charge gas for the write operation
	vm.consumeGas(vm.gasConfig.SetCost, "db_write")

	// Read key and value from Wasm memory
	key, err := vm.instance.ReadMemory(keyPtr, keyLen)
	if err != nil {
		stack[0] = api.EncodeI32(-1)
		return
	}

	value, err := vm.instance.ReadMemory(valuePtr, valueLen)
	if err != nil {
		stack[0] = api.EncodeI32(-1)
		return
	}

	// Set value in store
	vm.env.Store.Set(key, value)
	stack[0] = api.EncodeI32(0)
}

func (vm *WazeroVM) dbRemove(ctx context.Context, mod api.Module, stack []uint64) {
	// Read parameters from stack
	keyPtr := api.DecodeU32(stack[0])
	keyLen := api.DecodeU32(stack[1])

	// Charge gas for the remove operation
	vm.consumeGas(vm.gasConfig.RemoveCost, "db_remove")

	// Read key from Wasm memory
	key, err := vm.instance.ReadMemory(keyPtr, keyLen)
	if err != nil {
		stack[0] = api.EncodeI32(-1)
		return
	}

	// Delete from store
	vm.env.Store.Delete(key)
	stack[0] = api.EncodeI32(0)
}

func (vm *WazeroVM) gasConsume(ctx context.Context, mod api.Module, stack []uint64) {
	amount := uint64(api.DecodeU32(stack[0]))
	vm.consumeGas(amount, "wasm gas")
}

func (vm *WazeroVM) envGet(ctx context.Context, mod api.Module, stack []uint64) {
	// Read parameters from stack
	keyPtr := api.DecodeU32(stack[0])
	keyLen := api.DecodeU32(stack[1])
	valuePtr := api.DecodeU32(stack[2])

	// Read key from Wasm memory
	key, err := vm.instance.ReadMemory(keyPtr, keyLen)
	if err != nil {
		stack[0] = api.EncodeU32(0)
		return
	}

	// Get value from environment
	keyStr := string(key)
	var value string
	switch keyStr {
	case "block.height":
		value = fmt.Sprintf("%d", vm.env.Block.Height)
	case "block.time":
		value = fmt.Sprintf("%d", vm.env.Block.Time)
	case "block.chain_id":
		value = vm.env.Block.ChainID
	case "contract.address":
		value = vm.env.Contract.Address
	case "contract.creator":
		value = vm.env.Contract.Creator
	default:
		stack[0] = api.EncodeU32(0)
		return
	}

	// Write value to Wasm memory
	if err := vm.instance.WriteMemory(valuePtr, []byte(value)); err != nil {
		stack[0] = api.EncodeU32(0)
		return
	}

	stack[0] = api.EncodeU32(uint32(len(value)))
}

func (vm *WazeroVM) queryChain(ctx context.Context, mod api.Module, stack []uint64) {
	// Read parameters from stack
	requestPtr := api.DecodeU32(stack[0])
	requestLen := api.DecodeU32(stack[1])

	// Read request from Wasm memory
	request, err := vm.instance.ReadMemory(requestPtr, requestLen)
	if err != nil {
		stack[0] = api.EncodeU32(0)
		return
	}

	// Parse request
	var queryRequest types.QueryRequest
	if err := json.Unmarshal(request, &queryRequest); err != nil {
		stack[0] = api.EncodeU32(0)
		return
	}

	// Execute query
	result, err := vm.env.Querier.Query(queryRequest, vm.gasLimit)
	if err != nil {
		stack[0] = api.EncodeU32(0)
		return
	}

	// Allocate memory for result
	results, err := vm.instance.CallFunction("allocate", api.EncodeU32(uint32(len(result))))
	if err != nil || len(results) != 1 {
		stack[0] = api.EncodeU32(0)
		return
	}

	resultPtr := api.DecodeU32(results[0])

	// Write result to memory
	if err := vm.instance.WriteMemory(resultPtr, result); err != nil {
		stack[0] = api.EncodeU32(0)
		return
	}

	// Return pointer and length as a single uint32
	stack[0] = api.EncodeU32((resultPtr << 16) | uint32(len(result)))
}

// consumeGas consumes the specified amount of gas
func (vm *WazeroVM) consumeGas(amount uint64, descriptor string) {
	// Get current gas usage
	currentGas := vm.gasUsed

	// Check for overflow
	if amount > math.MaxUint64-currentGas {
		panic(types.OutOfGasError{})
	}

	// Check if we would exceed the limit
	newGas := currentGas + amount
	if newGas > vm.gasLimit {
		panic(types.OutOfGasError{})
	}

	// Consume the gas
	vm.gasUsed = newGas
	vm.instance.ConsumeGas(amount)
}

// GetGasReport returns a report of gas usage
func (vm *WazeroVM) GetGasReport() types.GasReport {
	return types.GasReport{
		Limit:          vm.gasLimit,
		Remaining:      vm.gasLimit - vm.gasUsed,
		UsedExternally: vm.gasUsed,
		UsedInternally: 0, // Wazero doesn't track internal gas separately
	}
}

// handleWasmResult reads and processes the result from a Wasm function call
func (vm *WazeroVM) handleWasmResult(resultPtr uint64) ([]byte, error) {
	// The result pointer is encoded as (ptr << 32) | length
	ptr := uint32(resultPtr >> 32)
	length := uint32(resultPtr & 0xFFFFFFFF)

	// Read the result from memory
	result, err := vm.instance.ReadMemory(ptr, length)
	if err != nil {
		return nil, fmt.Errorf("failed to read result from memory: %v", err)
	}

	return result, nil
}

// Instantiate creates a new instance of the contract
func (vm *WazeroVM) Instantiate(env []byte, info []byte, msg []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	if err := vm.updateState(gasMeter, store, api, querier, gasLimit); err != nil {
		return nil, vm.GetGasReport(), vm.errorWithMessage(err, nil)
	}

	// Prepare the environment
	envPtr, err := vm.allocateAndWrite(env)
	if err != nil {
		return nil, vm.GetGasReport(), vm.errorWithMessage(err, nil)
	}

	// Prepare the info
	infoPtr, err := vm.allocateAndWrite(info)
	if err != nil {
		return nil, vm.GetGasReport(), vm.errorWithMessage(err, nil)
	}

	// Prepare the message
	msgPtr, err := vm.allocateAndWrite(msg)
	if err != nil {
		return nil, vm.GetGasReport(), vm.errorWithMessage(err, nil)
	}

	// Call the instantiate function
	results, err := vm.instance.CallFunction("instantiate", envPtr, infoPtr, msgPtr)
	if err != nil {
		return nil, vm.GetGasReport(), vm.checkOutOfGas(err)
	}

	// Handle the result
	if len(results) != 1 {
		return nil, vm.GetGasReport(), fmt.Errorf("unexpected number of results from instantiate")
	}

	// Process the result
	result, err := vm.handleWasmResult(results[0])
	if err != nil {
		return nil, vm.GetGasReport(), vm.errorWithMessage(err, result)
	}

	return result, vm.GetGasReport(), nil
}

// Execute executes a contract with the given message
func (vm *WazeroVM) Execute(env []byte, info []byte, msg []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	if err := vm.updateState(gasMeter, store, api, querier, gasLimit); err != nil {
		return nil, vm.GetGasReport(), vm.errorWithMessage(err, nil)
	}

	// Prepare the environment
	envPtr, err := vm.allocateAndWrite(env)
	if err != nil {
		return nil, vm.GetGasReport(), vm.errorWithMessage(err, nil)
	}

	// Prepare the info
	infoPtr, err := vm.allocateAndWrite(info)
	if err != nil {
		return nil, vm.GetGasReport(), vm.errorWithMessage(err, nil)
	}

	// Prepare the message
	msgPtr, err := vm.allocateAndWrite(msg)
	if err != nil {
		return nil, vm.GetGasReport(), vm.errorWithMessage(err, nil)
	}

	// Call the execute function
	results, err := vm.instance.CallFunction("execute", envPtr, infoPtr, msgPtr)
	if err != nil {
		return nil, vm.GetGasReport(), vm.checkOutOfGas(err)
	}

	// Handle the result
	if len(results) != 1 {
		return nil, vm.GetGasReport(), fmt.Errorf("unexpected number of results from execute")
	}

	// Process the result
	result, err := vm.handleWasmResult(results[0])
	if err != nil {
		return nil, vm.GetGasReport(), vm.errorWithMessage(err, result)
	}

	return result, vm.GetGasReport(), nil
}

// Migrate migrates a contract to a new code version
func (vm *WazeroVM) Migrate() (types.GasReport, error) {
	// Prepare the message
	msg, err := json.Marshal(vm.env)
	if err != nil {
		return vm.GetGasReport(), fmt.Errorf("failed to marshal env: %v", err)
	}

	// Allocate memory for the message
	results, err := vm.instance.CallFunction("allocate", uint64(len(msg)))
	if err != nil {
		return vm.GetGasReport(), fmt.Errorf("failed to allocate memory: %v", err)
	}
	msgPtr := results[0]

	// Write message to memory
	if err := vm.instance.WriteMemory(uint32(msgPtr), msg); err != nil {
		return vm.GetGasReport(), fmt.Errorf("failed to write message to memory: %v", err)
	}

	// Call the migrate function
	results, err = vm.instance.CallFunction("migrate", msgPtr)
	if err != nil {
		return vm.GetGasReport(), fmt.Errorf("failed to migrate contract: %v", err)
	}

	// Handle the result
	if len(results) != 1 {
		return vm.GetGasReport(), fmt.Errorf("unexpected number of results from migrate")
	}

	// Process the result
	_, err = vm.handleWasmResult(results[0])
	if err != nil {
		return vm.GetGasReport(), fmt.Errorf("failed to process migrate result: %v", err)
	}

	return vm.GetGasReport(), nil
}

// Sudo executes privileged operations on a contract
func (vm *WazeroVM) Sudo() (types.GasReport, error) {
	// Prepare the message
	msg, err := json.Marshal(vm.env)
	if err != nil {
		return vm.GetGasReport(), fmt.Errorf("failed to marshal env: %v", err)
	}

	// Allocate memory for the message
	results, err := vm.instance.CallFunction("allocate", uint64(len(msg)))
	if err != nil {
		return vm.GetGasReport(), fmt.Errorf("failed to allocate memory: %v", err)
	}
	msgPtr := results[0]

	// Write message to memory
	if err := vm.instance.WriteMemory(uint32(msgPtr), msg); err != nil {
		return vm.GetGasReport(), fmt.Errorf("failed to write message to memory: %v", err)
	}

	// Call the sudo function
	results, err = vm.instance.CallFunction("sudo", msgPtr)
	if err != nil {
		return vm.GetGasReport(), fmt.Errorf("failed to sudo contract: %v", err)
	}

	// Handle the result
	if len(results) != 1 {
		return vm.GetGasReport(), fmt.Errorf("unexpected number of results from sudo")
	}

	// Process the result
	_, err = vm.handleWasmResult(results[0])
	if err != nil {
		return vm.GetGasReport(), fmt.Errorf("failed to process sudo result: %v", err)
	}

	return vm.GetGasReport(), nil
}

// Query executes a read-only query on a contract
func (vm *WazeroVM) Query() (types.GasReport, error) {
	// Prepare the message
	msg, err := json.Marshal(vm.env)
	if err != nil {
		return vm.GetGasReport(), fmt.Errorf("failed to marshal env: %v", err)
	}

	// Allocate memory for the message
	results, err := vm.instance.CallFunction("allocate", uint64(len(msg)))
	if err != nil {
		return vm.GetGasReport(), fmt.Errorf("failed to allocate memory: %v", err)
	}
	msgPtr := results[0]

	// Write message to memory
	if err := vm.instance.WriteMemory(uint32(msgPtr), msg); err != nil {
		return vm.GetGasReport(), fmt.Errorf("failed to write message to memory: %v", err)
	}

	// Call the query function
	results, err = vm.instance.CallFunction("query", msgPtr)
	if err != nil {
		return vm.GetGasReport(), fmt.Errorf("failed to query contract: %v", err)
	}

	// Handle the result
	if len(results) != 1 {
		return vm.GetGasReport(), fmt.Errorf("unexpected number of results from query")
	}

	// Process the result
	_, err = vm.handleWasmResult(results[0])
	if err != nil {
		return vm.GetGasReport(), fmt.Errorf("failed to process query result: %v", err)
	}

	return vm.GetGasReport(), nil
}

// Reply handles a reply from a submessage
func (vm *WazeroVM) Reply() (types.GasReport, error) {
	// Prepare the message
	msg, err := json.Marshal(vm.env)
	if err != nil {
		return vm.GetGasReport(), fmt.Errorf("failed to marshal env: %v", err)
	}

	// Allocate memory for the message
	results, err := vm.instance.CallFunction("allocate", uint64(len(msg)))
	if err != nil {
		return vm.GetGasReport(), fmt.Errorf("failed to allocate memory: %v", err)
	}
	msgPtr := results[0]

	// Write message to memory
	if err := vm.instance.WriteMemory(uint32(msgPtr), msg); err != nil {
		return vm.GetGasReport(), fmt.Errorf("failed to write message to memory: %v", err)
	}

	// Call the reply function
	results, err = vm.instance.CallFunction("reply", msgPtr)
	if err != nil {
		return vm.GetGasReport(), fmt.Errorf("failed to handle reply: %v", err)
	}

	// Handle the result
	if len(results) != 1 {
		return vm.GetGasReport(), fmt.Errorf("unexpected number of results from reply")
	}

	// Process the result
	_, err = vm.handleWasmResult(results[0])
	if err != nil {
		return vm.GetGasReport(), fmt.Errorf("failed to process reply result: %v", err)
	}

	return vm.GetGasReport(), nil
}

// Helper function to update VM state with new parameters
func (vm *WazeroVM) updateState(gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *types.Querier, gasLimit uint64) error {
	if gasMeter != nil {
		vm.gasMeter = *gasMeter
	}
	vm.gasLimit = gasLimit

	// Initialize environment if it doesn't exist
	if vm.env == nil {
		vm.env = &Environment{
			Store:    store,
			API:      *api,
			Querier:  *querier,
			Block:    BlockInfo{},
			Contract: ContractInfo{},
		}
		return nil
	}

	// Update existing environment
	return vm.env.UpdateEnvironment(store, api, querier)
}

// IBCChannelOpen handles the IBC channel open callback
func (vm *WazeroVM) IBCChannelOpen(env []byte, msg []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	if err := vm.updateState(gasMeter, store, api, querier, gasLimit); err != nil {
		return nil, vm.GetGasReport(), vm.errorWithMessage(err, nil)
	}

	// Prepare the environment
	envPtr, err := vm.allocateAndWrite(env)
	if err != nil {
		return nil, vm.GetGasReport(), vm.errorWithMessage(err, nil)
	}

	// Prepare the message
	msgPtr, err := vm.allocateAndWrite(msg)
	if err != nil {
		return nil, vm.GetGasReport(), vm.errorWithMessage(err, nil)
	}

	// Call the ibc_channel_open function
	results, err := vm.instance.CallFunction("ibc_channel_open", envPtr, msgPtr)
	if err != nil {
		return nil, vm.GetGasReport(), vm.checkOutOfGas(err)
	}

	// Handle the result
	if len(results) != 1 {
		return nil, vm.GetGasReport(), fmt.Errorf("unexpected number of results from ibc_channel_open")
	}

	// Process the result
	result, err := vm.handleIBCResult(results[0])
	if err != nil {
		return nil, vm.GetGasReport(), vm.errorWithMessage(err, result)
	}

	return result, vm.GetGasReport(), nil
}

// IBCChannelConnect handles the IBC channel connect callback
func (vm *WazeroVM) IBCChannelConnect(env []byte, msg []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	if err := vm.updateState(gasMeter, store, api, querier, gasLimit); err != nil {
		return nil, vm.GetGasReport(), vm.errorWithMessage(err, nil)
	}

	// Prepare the environment
	envPtr, err := vm.allocateAndWrite(env)
	if err != nil {
		return nil, vm.GetGasReport(), vm.errorWithMessage(err, nil)
	}

	// Prepare the message
	msgPtr, err := vm.allocateAndWrite(msg)
	if err != nil {
		return nil, vm.GetGasReport(), vm.errorWithMessage(err, nil)
	}

	// Call the ibc_channel_connect function
	results, err := vm.instance.CallFunction("ibc_channel_connect", envPtr, msgPtr)
	if err != nil {
		return nil, vm.GetGasReport(), vm.checkOutOfGas(err)
	}

	// Handle the result
	if len(results) != 1 {
		return nil, vm.GetGasReport(), fmt.Errorf("unexpected number of results from ibc_channel_connect")
	}

	// Process the result
	result, err := vm.handleIBCResult(results[0])
	if err != nil {
		return nil, vm.GetGasReport(), vm.errorWithMessage(err, result)
	}

	return result, vm.GetGasReport(), nil
}

// IBCChannelClose handles the IBC channel close callback
func (vm *WazeroVM) IBCChannelClose(env []byte, msg []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	if err := vm.updateState(gasMeter, store, api, querier, gasLimit); err != nil {
		return nil, vm.GetGasReport(), vm.errorWithMessage(err, nil)
	}

	// Prepare the environment
	envPtr, err := vm.allocateAndWrite(env)
	if err != nil {
		return nil, vm.GetGasReport(), vm.errorWithMessage(err, nil)
	}

	// Prepare the message
	msgPtr, err := vm.allocateAndWrite(msg)
	if err != nil {
		return nil, vm.GetGasReport(), vm.errorWithMessage(err, nil)
	}

	// Call the ibc_channel_close function
	results, err := vm.instance.CallFunction("ibc_channel_close", envPtr, msgPtr)
	if err != nil {
		return nil, vm.GetGasReport(), vm.checkOutOfGas(err)
	}

	// Handle the result
	if len(results) != 1 {
		return nil, vm.GetGasReport(), fmt.Errorf("unexpected number of results from ibc_channel_close")
	}

	// Process the result
	result, err := vm.handleIBCResult(results[0])
	if err != nil {
		return nil, vm.GetGasReport(), vm.errorWithMessage(err, result)
	}

	return result, vm.GetGasReport(), nil
}

// IBCPacketReceive handles the IBC packet receive callback
func (vm *WazeroVM) IBCPacketReceive(env []byte, msg []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	if err := vm.updateState(gasMeter, store, api, querier, gasLimit); err != nil {
		return nil, vm.GetGasReport(), vm.errorWithMessage(err, nil)
	}

	// Prepare the environment
	envPtr, err := vm.allocateAndWrite(env)
	if err != nil {
		return nil, vm.GetGasReport(), vm.errorWithMessage(err, nil)
	}

	// Prepare the message
	msgPtr, err := vm.allocateAndWrite(msg)
	if err != nil {
		return nil, vm.GetGasReport(), vm.errorWithMessage(err, nil)
	}

	// Call the ibc_packet_receive function
	results, err := vm.instance.CallFunction("ibc_packet_receive", envPtr, msgPtr)
	if err != nil {
		return nil, vm.GetGasReport(), vm.checkOutOfGas(err)
	}

	// Handle the result
	if len(results) != 1 {
		return nil, vm.GetGasReport(), fmt.Errorf("unexpected number of results from ibc_packet_receive")
	}

	// Process the result
	result, err := vm.handleIBCResult(results[0])
	if err != nil {
		return nil, vm.GetGasReport(), vm.errorWithMessage(err, result)
	}

	return result, vm.GetGasReport(), nil
}

// IBCPacketAck handles the IBC packet acknowledgment callback
func (vm *WazeroVM) IBCPacketAck(env []byte, msg []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	if err := vm.updateState(gasMeter, store, api, querier, gasLimit); err != nil {
		return nil, vm.GetGasReport(), vm.errorWithMessage(err, nil)
	}

	// Prepare the environment
	envPtr, err := vm.allocateAndWrite(env)
	if err != nil {
		return nil, vm.GetGasReport(), vm.errorWithMessage(err, nil)
	}

	// Prepare the message
	msgPtr, err := vm.allocateAndWrite(msg)
	if err != nil {
		return nil, vm.GetGasReport(), vm.errorWithMessage(err, nil)
	}

	// Call the ibc_packet_ack function
	results, err := vm.instance.CallFunction("ibc_packet_ack", envPtr, msgPtr)
	if err != nil {
		return nil, vm.GetGasReport(), vm.checkOutOfGas(err)
	}

	// Handle the result
	if len(results) != 1 {
		return nil, vm.GetGasReport(), fmt.Errorf("unexpected number of results from ibc_packet_ack")
	}

	// Process the result
	result, err := vm.handleIBCResult(results[0])
	if err != nil {
		return nil, vm.GetGasReport(), vm.errorWithMessage(err, result)
	}

	return result, vm.GetGasReport(), nil
}

// IBCPacketTimeout handles the IBC packet timeout callback
func (vm *WazeroVM) IBCPacketTimeout(env []byte, msg []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	if err := vm.updateState(gasMeter, store, api, querier, gasLimit); err != nil {
		return nil, vm.GetGasReport(), vm.errorWithMessage(err, nil)
	}

	// Prepare the environment
	envPtr, err := vm.allocateAndWrite(env)
	if err != nil {
		return nil, vm.GetGasReport(), vm.errorWithMessage(err, nil)
	}

	// Prepare the message
	msgPtr, err := vm.allocateAndWrite(msg)
	if err != nil {
		return nil, vm.GetGasReport(), vm.errorWithMessage(err, nil)
	}

	// Call the ibc_packet_timeout function
	results, err := vm.instance.CallFunction("ibc_packet_timeout", envPtr, msgPtr)
	if err != nil {
		return nil, vm.GetGasReport(), vm.checkOutOfGas(err)
	}

	// Handle the result
	if len(results) != 1 {
		return nil, vm.GetGasReport(), fmt.Errorf("unexpected number of results from ibc_packet_timeout")
	}

	// Process the result
	result, err := vm.handleIBCResult(results[0])
	if err != nil {
		return nil, vm.GetGasReport(), vm.errorWithMessage(err, result)
	}

	return result, vm.GetGasReport(), nil
}

// IBCSourceCallback handles the IBC source callback
func (vm *WazeroVM) IBCSourceCallback(env []byte, msg []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	if err := vm.updateState(gasMeter, store, api, querier, gasLimit); err != nil {
		return nil, vm.GetGasReport(), vm.errorWithMessage(err, nil)
	}

	// Prepare the environment
	envPtr, err := vm.allocateAndWrite(env)
	if err != nil {
		return nil, vm.GetGasReport(), vm.errorWithMessage(err, nil)
	}

	// Prepare the message
	msgPtr, err := vm.allocateAndWrite(msg)
	if err != nil {
		return nil, vm.GetGasReport(), vm.errorWithMessage(err, nil)
	}

	// Call the ibc_source_callback function
	results, err := vm.instance.CallFunction("ibc_source_callback", envPtr, msgPtr)
	if err != nil {
		return nil, vm.GetGasReport(), vm.checkOutOfGas(err)
	}

	// Handle the result
	if len(results) != 1 {
		return nil, vm.GetGasReport(), fmt.Errorf("unexpected number of results from ibc_source_callback")
	}

	// Process the result
	result, err := vm.handleIBCResult(results[0])
	if err != nil {
		return nil, vm.GetGasReport(), vm.errorWithMessage(err, result)
	}

	return result, vm.GetGasReport(), nil
}

// IBCDestinationCallback handles the IBC destination callback
func (vm *WazeroVM) IBCDestinationCallback(env []byte, msg []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	if err := vm.updateState(gasMeter, store, api, querier, gasLimit); err != nil {
		return nil, vm.GetGasReport(), vm.errorWithMessage(err, nil)
	}

	// Prepare the environment
	envPtr, err := vm.allocateAndWrite(env)
	if err != nil {
		return nil, vm.GetGasReport(), vm.errorWithMessage(err, nil)
	}

	// Prepare the message
	msgPtr, err := vm.allocateAndWrite(msg)
	if err != nil {
		return nil, vm.GetGasReport(), vm.errorWithMessage(err, nil)
	}

	// Call the ibc_destination_callback function
	results, err := vm.instance.CallFunction("ibc_destination_callback", envPtr, msgPtr)
	if err != nil {
		return nil, vm.GetGasReport(), vm.checkOutOfGas(err)
	}

	// Handle the result
	if len(results) != 1 {
		return nil, vm.GetGasReport(), fmt.Errorf("unexpected number of results from ibc_destination_callback")
	}

	// Process the result
	result, err := vm.handleIBCResult(results[0])
	if err != nil {
		return nil, vm.GetGasReport(), vm.errorWithMessage(err, result)
	}

	return result, vm.GetGasReport(), nil
}

// Helper function to allocate memory and write data
func (vm *WazeroVM) allocateAndWrite(data []byte) (uint64, error) {
	// Allocate memory for the data
	results, err := vm.instance.CallFunction("allocate", uint64(len(data)))
	if err != nil {
		return 0, fmt.Errorf("failed to allocate memory: %v", err)
	}
	if len(results) != 1 {
		return 0, fmt.Errorf("unexpected number of results from allocate")
	}
	ptr := results[0]

	// Write data to memory
	if err := vm.instance.WriteMemory(uint32(ptr), data); err != nil {
		return 0, fmt.Errorf("failed to write to memory: %v", err)
	}

	return ptr, nil
}

// handleIBCResult processes the result from an IBC function call
func (vm *WazeroVM) handleIBCResult(result uint64) ([]byte, error) {
	// The result is encoded as (ptr << 32) | length
	ptr := uint32(result >> 32)
	length := uint32(result & 0xFFFFFFFF)

	// Read the result from memory
	data, err := vm.instance.ReadMemory(ptr, length)
	if err != nil {
		return nil, fmt.Errorf("failed to read result from memory: %v", err)
	}

	return data, nil
}

// MigrateWithInfo migrates a contract with additional migration info
func (vm *WazeroVM) MigrateWithInfo(env []byte, msg []byte, migrateInfo []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	if err := vm.updateState(gasMeter, store, api, querier, gasLimit); err != nil {
		return nil, vm.GetGasReport(), fmt.Errorf("failed to update state: %v", err)
	}

	// Prepare the environment
	envPtr, err := vm.allocateAndWrite(env)
	if err != nil {
		return nil, vm.GetGasReport(), fmt.Errorf("failed to prepare environment: %v", err)
	}

	// Prepare the message
	msgPtr, err := vm.allocateAndWrite(msg)
	if err != nil {
		return nil, vm.GetGasReport(), fmt.Errorf("failed to prepare message: %v", err)
	}

	// Prepare the migrate info
	infoPtr, err := vm.allocateAndWrite(migrateInfo)
	if err != nil {
		return nil, vm.GetGasReport(), fmt.Errorf("failed to prepare migrate info: %v", err)
	}

	// Call the migrate_with_info function
	results, err := vm.instance.CallFunction("migrate_with_info", envPtr, msgPtr, infoPtr)
	if err != nil {
		return nil, vm.GetGasReport(), fmt.Errorf("failed to call migrate_with_info: %v", err)
	}

	// Handle the result
	if len(results) != 1 {
		return nil, vm.GetGasReport(), fmt.Errorf("unexpected number of results from migrate_with_info")
	}

	// Process the result
	result, err := vm.handleWasmResult(results[0])
	if err != nil {
		return nil, vm.GetGasReport(), fmt.Errorf("failed to process migrate_with_info result: %v", err)
	}

	return result, vm.GetGasReport(), nil
}

// errorWithMessage creates an error with a message, handling special cases like out-of-gas
func (vm *WazeroVM) errorWithMessage(err error, msg []byte) error {
	// Check for out of gas as a special case
	if _, ok := err.(types.OutOfGasError); ok {
		return err
	}
	if msg == nil {
		return err
	}
	return fmt.Errorf("%s", string(msg))
}

// checkOutOfGas checks if the error is an out-of-gas error
func (vm *WazeroVM) checkOutOfGas(err error) error {
	if err == nil {
		return nil
	}

	// Check if the error message contains out of gas indicators
	errMsg := err.Error()
	if strings.Contains(errMsg, "out of gas") || strings.Contains(errMsg, "gas limit exceeded") {
		return types.OutOfGasError{}
	}
	return err
}
