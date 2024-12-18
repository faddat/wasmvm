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
	if vm.gasMeter != nil {
		_ = vm.gasMeter.GasConsumed() // Just read the gas consumed, as we can't modify it directly
	}
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
func (vm *WazeroVM) Instantiate(env []byte, info []byte, msg []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	if err := vm.updateState(gasMeter, store, api, querier, gasLimit); err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	// Prepare the environment
	envPtr, err := vm.allocateAndWrite(env)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	// Prepare the info
	infoPtr, err := vm.allocateAndWrite(info)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	// Prepare the message
	msgPtr, err := vm.allocateAndWrite(msg)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	// Call the instantiate function with uint64 conversions
	results, err := vm.instance.CallFunction("instantiate", uint64(envPtr), uint64(infoPtr), uint64(msgPtr))
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	// Handle the result
	if len(results) != 1 {
		return nil, vm.GetGasReport(), fmt.Errorf("unexpected number of results from instantiate")
	}

	// Process the result
	result, err := vm.handleWasmResult(results[0])
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	return result, vm.GetGasReport(), nil
}

// Execute executes a contract with the given message
func (vm *WazeroVM) Execute(env []byte, info []byte, msg []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	if err := vm.updateState(gasMeter, store, api, querier, gasLimit); err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	// Prepare the environment
	envPtr, err := vm.allocateAndWrite(env)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	// Prepare the info
	infoPtr, err := vm.allocateAndWrite(info)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	// Prepare the message
	msgPtr, err := vm.allocateAndWrite(msg)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	// Call the execute function with uint64 conversions
	results, err := vm.instance.CallFunction("execute", uint64(envPtr), uint64(infoPtr), uint64(msgPtr))
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	// Handle the result
	if len(results) != 1 {
		return nil, vm.GetGasReport(), fmt.Errorf("unexpected number of results from execute")
	}

	// Process the result
	result, err := vm.handleWasmResult(results[0])
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	return result, vm.GetGasReport(), nil
}

// Migrate migrates a contract to a new code version
func (vm *WazeroVM) Migrate(env []byte, msg []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	if err := vm.updateState(gasMeter, store, api, querier, gasLimit); err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	// Prepare the environment
	envPtr, err := vm.allocateAndWrite(env)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	// Prepare the message
	msgPtr, err := vm.allocateAndWrite(msg)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	// Call the migrate function with uint64 conversions
	results, err := vm.instance.CallFunction("migrate", uint64(envPtr), uint64(msgPtr))
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	// Handle the result
	if len(results) != 1 {
		return nil, vm.GetGasReport(), fmt.Errorf("unexpected number of results from migrate")
	}

	// Process the result
	result, err := vm.handleWasmResult(results[0])
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	return result, vm.GetGasReport(), nil
}

// Sudo executes privileged operations on a contract
func (vm *WazeroVM) Sudo(env []byte, msg []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	if err := vm.updateState(gasMeter, store, api, querier, gasLimit); err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	// Prepare the environment
	envPtr, err := vm.allocateAndWrite(env)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	// Prepare the message
	msgPtr, err := vm.allocateAndWrite(msg)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	// Call the sudo function
	results, err := vm.instance.CallFunction("sudo", envPtr, msgPtr)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	// Handle the result
	if len(results) != 1 {
		return nil, vm.GetGasReport(), fmt.Errorf("unexpected number of results from sudo")
	}

	// Process the result
	result, err := vm.handleWasmResult(results[0])
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	return result, vm.GetGasReport(), nil
}

// Query executes a read-only query on a contract
func (vm *WazeroVM) Query(env []byte, msg []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	if err := vm.updateState(gasMeter, store, api, querier, gasLimit); err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	// Prepare the environment
	envPtr, err := vm.allocateAndWrite(env)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	// Prepare the message
	msgPtr, err := vm.allocateAndWrite(msg)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	// Call the query function
	results, err := vm.instance.CallFunction("query", envPtr, msgPtr)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	// Handle the result
	if len(results) != 1 {
		return nil, vm.GetGasReport(), fmt.Errorf("unexpected number of results from query")
	}

	// Process the result
	result, err := vm.handleWasmResult(results[0])
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	return result, vm.GetGasReport(), nil
}

// Reply handles a reply from a submessage
func (vm *WazeroVM) Reply(env []byte, reply []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	if err := vm.updateState(gasMeter, store, api, querier, gasLimit); err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	// Prepare the environment
	envPtr, err := vm.allocateAndWrite(env)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	// Prepare the reply
	replyPtr, err := vm.allocateAndWrite(reply)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	// Call the reply function
	results, err := vm.instance.CallFunction("reply", envPtr, replyPtr)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	// Handle the result
	if len(results) != 1 {
		return nil, vm.GetGasReport(), fmt.Errorf("unexpected number of results from reply")
	}

	// Process the result
	result, err := vm.handleWasmResult(results[0])
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	return result, vm.GetGasReport(), nil
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
			Store:       store,
			API:         *api,
			Querier:     *querier,
			Block:       BlockInfo{},
			Contract:    ContractInfo{},
			Transaction: nil,
		}
		return nil
	}

	// Update existing environment
	return vm.env.UpdateEnvironment(store, api, querier, vm.env.Transaction)
}

// IBCChannelOpen handles the IBC channel open callback
func (vm *WazeroVM) IBCChannelOpen(env []byte, msg []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	if err := vm.updateState(gasMeter, store, api, querier, gasLimit); err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	// Prepare the environment
	envPtr, err := vm.allocateAndWrite(env)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	// Prepare the message
	msgPtr, err := vm.allocateAndWrite(msg)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	// Call the ibc_channel_open function
	results, err := vm.instance.CallFunction("ibc_channel_open", envPtr, msgPtr)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	// Handle the result
	if len(results) != 1 {
		return nil, vm.GetGasReport(), fmt.Errorf("unexpected number of results from ibc_channel_open")
	}

	// Process the result
	result, err := vm.handleIBCResult(results[0])
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	return result, vm.GetGasReport(), nil
}

// IBCChannelConnect handles the IBC channel connect callback
func (vm *WazeroVM) IBCChannelConnect(env []byte, msg []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	if err := vm.updateState(gasMeter, store, api, querier, gasLimit); err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	// Prepare the environment
	envPtr, err := vm.allocateAndWrite(env)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	// Prepare the message
	msgPtr, err := vm.allocateAndWrite(msg)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	// Call the ibc_channel_connect function
	results, err := vm.instance.CallFunction("ibc_channel_connect", envPtr, msgPtr)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	// Handle the result
	if len(results) != 1 {
		return nil, vm.GetGasReport(), fmt.Errorf("unexpected number of results from ibc_channel_connect")
	}

	// Process the result
	result, err := vm.handleIBCResult(results[0])
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	return result, vm.GetGasReport(), nil
}

// IBCChannelClose handles the IBC channel close callback
func (vm *WazeroVM) IBCChannelClose(env []byte, msg []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	if err := vm.updateState(gasMeter, store, api, querier, gasLimit); err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	// Prepare the environment
	envPtr, err := vm.allocateAndWrite(env)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	// Prepare the message
	msgPtr, err := vm.allocateAndWrite(msg)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	// Call the ibc_channel_close function
	results, err := vm.instance.CallFunction("ibc_channel_close", envPtr, msgPtr)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	// Handle the result
	if len(results) != 1 {
		return nil, vm.GetGasReport(), fmt.Errorf("unexpected number of results from ibc_channel_close")
	}

	// Process the result
	result, err := vm.handleIBCResult(results[0])
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	return result, vm.GetGasReport(), nil
}

// IBCPacketReceive handles the IBC packet receive callback
func (vm *WazeroVM) IBCPacketReceive(env []byte, msg []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	if err := vm.updateState(gasMeter, store, api, querier, gasLimit); err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	// Prepare the environment
	envPtr, err := vm.allocateAndWrite(env)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	// Prepare the message
	msgPtr, err := vm.allocateAndWrite(msg)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	// Call the ibc_packet_receive function
	results, err := vm.instance.CallFunction("ibc_packet_receive", envPtr, msgPtr)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	// Handle the result
	if len(results) != 1 {
		return nil, vm.GetGasReport(), fmt.Errorf("unexpected number of results from ibc_packet_receive")
	}

	// Process the result
	result, err := vm.handleIBCResult(results[0])
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	return result, vm.GetGasReport(), nil
}

// IBCPacketAck handles the IBC packet acknowledgment callback
func (vm *WazeroVM) IBCPacketAck(env []byte, msg []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	if err := vm.updateState(gasMeter, store, api, querier, gasLimit); err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	// Prepare the environment
	envPtr, err := vm.allocateAndWrite(env)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	// Prepare the message
	msgPtr, err := vm.allocateAndWrite(msg)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	// Call the ibc_packet_ack function
	results, err := vm.instance.CallFunction("ibc_packet_ack", envPtr, msgPtr)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	// Handle the result
	if len(results) != 1 {
		return nil, vm.GetGasReport(), fmt.Errorf("unexpected number of results from ibc_packet_ack")
	}

	// Process the result
	result, err := vm.handleIBCResult(results[0])
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	return result, vm.GetGasReport(), nil
}

// IBCPacketTimeout handles the IBC packet timeout callback
func (vm *WazeroVM) IBCPacketTimeout(env []byte, msg []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	if err := vm.updateState(gasMeter, store, api, querier, gasLimit); err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	// Prepare the environment
	envPtr, err := vm.allocateAndWrite(env)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	// Prepare the message
	msgPtr, err := vm.allocateAndWrite(msg)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	// Call the ibc_packet_timeout function
	results, err := vm.instance.CallFunction("ibc_packet_timeout", envPtr, msgPtr)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	// Handle the result
	if len(results) != 1 {
		return nil, vm.GetGasReport(), fmt.Errorf("unexpected number of results from ibc_packet_timeout")
	}

	// Process the result
	result, err := vm.handleIBCResult(results[0])
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	return result, vm.GetGasReport(), nil
}

// IBCSourceCallback handles the IBC source callback
func (vm *WazeroVM) IBCSourceCallback(env []byte, msg []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	if err := vm.updateState(gasMeter, store, api, querier, gasLimit); err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	// Prepare the environment
	envPtr, err := vm.allocateAndWrite(env)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	// Prepare the message
	msgPtr, err := vm.allocateAndWrite(msg)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	// Call the ibc_source_callback function
	results, err := vm.instance.CallFunction("ibc_source_callback", envPtr, msgPtr)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	// Handle the result
	if len(results) != 1 {
		return nil, vm.GetGasReport(), fmt.Errorf("unexpected number of results from ibc_source_callback")
	}

	// Process the result
	result, err := vm.handleIBCResult(results[0])
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	return result, vm.GetGasReport(), nil
}

// IBCDestinationCallback handles the IBC destination callback
func (vm *WazeroVM) IBCDestinationCallback(env []byte, msg []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	if err := vm.updateState(gasMeter, store, api, querier, gasLimit); err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	// Prepare the environment
	envPtr, err := vm.allocateAndWrite(env)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	// Prepare the message
	msgPtr, err := vm.allocateAndWrite(msg)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	// Call the ibc_destination_callback function
	results, err := vm.instance.CallFunction("ibc_destination_callback", envPtr, msgPtr)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	// Handle the result
	if len(results) != 1 {
		return nil, vm.GetGasReport(), fmt.Errorf("unexpected number of results from ibc_destination_callback")
	}

	// Process the result
	result, err := vm.handleIBCResult(results[0])
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	return result, vm.GetGasReport(), nil
}

// allocateAndWrite allocates memory and writes data to it
func (vm *WazeroVM) allocateAndWrite(data []byte) (uint64, error) {
	if data == nil {
		return 0, nil
	}

	// Allocate memory for the data
	ptr, err := vm.instance.AllocateMemory(uint64(len(data)))
	if err != nil {
		return 0, fmt.Errorf("failed to allocate memory: %v", err)
	}

	// Write data to memory
	if err := vm.instance.WriteMemory(uint32(ptr), data); err != nil {
		// Try to deallocate on error
		_ = vm.instance.DeallocateMemory(ptr)
		return 0, fmt.Errorf("failed to write to memory: %v", err)
	}

	return ptr, nil
}

// handleIBCResult processes the result from an IBC function call
func (vm *WazeroVM) handleIBCResult(resultPtr uint64) ([]byte, error) {
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

// MigrateWithInfo migrates a contract with additional migration info
func (vm *WazeroVM) MigrateWithInfo(env []byte, msg []byte, migrateInfo []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	if err := vm.updateState(gasMeter, store, api, querier, gasLimit); err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	// Prepare the environment
	envPtr, err := vm.allocateAndWrite(env)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	// Prepare the message
	msgPtr, err := vm.allocateAndWrite(msg)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	// Prepare the migrate info
	infoPtr, err := vm.allocateAndWrite(migrateInfo)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	// Call the migrate_with_info function
	results, err := vm.instance.CallFunction("migrate_with_info", envPtr, msgPtr, infoPtr)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	// Handle the result
	if len(results) != 1 {
		return nil, vm.GetGasReport(), fmt.Errorf("unexpected number of results from migrate_with_info")
	}

	// Process the result
	result, err := vm.handleWasmResult(results[0])
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	return result, vm.GetGasReport(), nil
}

// errorWithMessage creates an error with a message, handling special cases like out-of-gas
func (vm *WazeroVM) errorWithMessage(err error, msg []byte) error {
	if err == nil {
		return nil
	}

	// Check for out of gas as a special case
	if _, ok := err.(types.OutOfGasError); ok {
		return err
	}

	// Check if we've exceeded our gas limit or if the error indicates out of gas
	if vm.checkOutOfGas(err) {
		return types.OutOfGasError{}
	}

	if msg == nil {
		return err
	}
	return fmt.Errorf("%s", string(msg))
}

// checkOutOfGas checks if the error is an out-of-gas error
func (vm *WazeroVM) checkOutOfGas(err error) bool {
	if err == nil {
		return false
	}

	// Check if we've exceeded our gas limit
	if vm.gasUsed > vm.gasLimit {
		return true
	}

	// Check if the error message contains out of gas indicators
	errMsg := err.Error()
	return strings.Contains(errMsg, "out of gas") ||
		strings.Contains(errMsg, "gas limit exceeded") ||
		strings.Contains(errMsg, "insufficient gas")
}

// handleError processes an error, converting it to an OutOfGasError if appropriate
func (vm *WazeroVM) handleError(err error) error {
	if err == nil {
		return nil
	}

	if vm.checkOutOfGas(err) {
		return types.OutOfGasError{}
	}

	return err
}

// allocate allocates memory in the Wasm instance
func (vm *WazeroVM) allocate(size uint64) (uint64, error) {
	memory := vm.instance.GetModule().Memory()
	if memory == nil {
		return 0, fmt.Errorf("no memory exported")
	}

	// Get current memory size
	currentSize := uint64(memory.Size())
	requiredPages := (size + 65535) / 65536 // Round up to nearest page

	// Grow memory if needed
	if currentSize < requiredPages {
		if _, ok := memory.Grow(uint32(requiredPages - currentSize)); !ok {
			return 0, fmt.Errorf("failed to grow memory")
		}
	}

	// For now, just return the next available position
	// In a real implementation, we would need a proper memory allocator
	return currentSize * 65536, nil
}

// deallocate frees memory in the Wasm instance
func (vm *WazeroVM) deallocate(ptr uint64) error {
	// In Wazero, we don't actually free memory
	// This is a no-op for now
	return nil
}

// AnalyzeCode returns static analysis info about the contract
func (vm *WazeroVM) AnalyzeCode() (*types.AnalysisReport, error) {
	if vm == nil || vm.instance == nil || vm.instance.GetModule() == nil {
		return &types.AnalysisReport{
			HasIBCEntryPoints:      false,
			RequiredCapabilities:   "",
			Entrypoints:            []string{},
			ContractMigrateVersion: nil,
		}, nil
	}

	// Check for IBC entrypoints
	hasIBC := false
	entrypoints := []string{}

	// Check for standard entrypoints
	standardEntrypoints := []string{
		"instantiate",
		"execute",
		"query",
		"migrate",
		"sudo",
		"reply",
	}

	for _, name := range standardEntrypoints {
		if fn := vm.instance.GetModule().ExportedFunction(name); fn != nil {
			entrypoints = append(entrypoints, name)
		}
	}

	// Check for IBC entrypoints
	ibcEntrypoints := []string{
		"ibc_channel_open",
		"ibc_channel_connect",
		"ibc_channel_close",
		"ibc_packet_receive",
		"ibc_packet_ack",
		"ibc_packet_timeout",
		"ibc_source_callback",
		"ibc_destination_callback",
	}

	for _, name := range ibcEntrypoints {
		if fn := vm.instance.GetModule().ExportedFunction(name); fn != nil {
			hasIBC = true
			entrypoints = append(entrypoints, name)
		}
	}

	// Check for migrate version
	var migrateVersion *uint64
	if fn := vm.instance.GetModule().ExportedFunction("migrate_version"); fn != nil {
		results, err := vm.instance.CallFunction("migrate_version")
		if err == nil && len(results) == 1 {
			version := results[0]
			migrateVersion = &version
		}
	}

	return &types.AnalysisReport{
		HasIBCEntryPoints:      hasIBC,
		RequiredCapabilities:   "", // No capabilities required for Wazero
		Entrypoints:            entrypoints,
		ContractMigrateVersion: migrateVersion,
	}, nil
}

// GetMetrics returns cache metrics
func (vm *WazeroVM) GetMetrics() *types.Metrics {
	// Wazero doesn't have a cache, so return empty metrics
	return &types.Metrics{}
}

// Pin marks the contract as pinned in cache
func (vm *WazeroVM) Pin() error {
	// Wazero doesn't have a cache, so this is a no-op
	return nil
}

// Unpin marks the contract as unpinned in cache
func (vm *WazeroVM) Unpin() error {
	// Wazero doesn't have a cache, so this is a no-op
	return nil
}

// GetPinnedMetrics returns metrics about pinned contracts
func (vm *WazeroVM) GetPinnedMetrics() (*types.PinnedMetrics, error) {
	// Wazero doesn't have a cache, so return empty metrics
	return &types.PinnedMetrics{}, nil
}

// Cleanup performs any necessary cleanup
func (vm *WazeroVM) Cleanup() {
	// Close the instance
	if vm.instance != nil {
		_ = vm.instance.Close()
	}
}
