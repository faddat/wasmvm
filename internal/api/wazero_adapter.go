package api

import (
	"context"
	"fmt"
	"strings"

	"github.com/CosmWasm/wasmvm/v2/types"
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
	cache     Cache
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
		RemoveCost: 150,
		RangePrice: 1,
	}
}

// allocateAndWrite reserves len(data) bytes in Wasm memory, writes data, and returns the pointer
func (vm *WazeroVM) allocateAndWrite(data []byte) (uint64, error) {
	if len(data) == 0 {
		return 0, nil
	}
	ptr, err := vm.instance.AllocateMemory(uint64(len(data)))
	if err != nil {
		return 0, err
	}
	if err := vm.instance.WriteMemory(uint32(ptr), data); err != nil {
		return 0, err
	}
	return ptr, nil
}

// CallFunction calls a Wasm-exported function by name with given parameters
func (vm *WazeroVM) CallFunction(fnName string, params ...uint64) ([]uint64, error) {
	if vm.instance == nil || vm.instance.module == nil {
		return nil, fmt.Errorf("instance or module is nil")
	}
	f := vm.instance.module.ExportedFunction(fnName)
	if f == nil {
		return nil, fmt.Errorf("function not found: %s", fnName)
	}
	results, err := f.Call(context.Background(), params...)
	if err != nil {
		return nil, vm.handleError(err)
	}
	return results, nil
}

// Instantiate calls the "instantiate" function in the contract (if provided)
func (vm *WazeroVM) Instantiate(env []byte, info []byte, msg []byte,
	gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI,
	querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {

	if err := vm.updateState(gasMeter, store, api, querier, gasLimit); err != nil {
		return nil, vm.GetGasReport(), fmt.Errorf("failed to update state: %v", err)
	}

	envPtr, err := vm.allocateAndWrite(env)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}
	infoPtr, err := vm.allocateAndWrite(info)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}
	msgPtr, err := vm.allocateAndWrite(msg)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	results, err := vm.CallFunction("instantiate", envPtr, infoPtr, msgPtr)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	if len(results) != 1 {
		return nil, vm.GetGasReport(), fmt.Errorf("unexpected number of results from instantiate")
	}

	result, err := vm.handleWasmResult(results[0])
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	return result, vm.GetGasReport(), nil
}

// Query calls the "query" function in the contract (if provided)
func (vm *WazeroVM) Query(env []byte, msg []byte,
	gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI,
	querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {

	if err := vm.updateState(gasMeter, store, api, querier, gasLimit); err != nil {
		return nil, vm.GetGasReport(), fmt.Errorf("failed to update state: %v", err)
	}

	envPtr, err := vm.allocateAndWrite(env)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}
	msgPtr, err := vm.allocateAndWrite(msg)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	results, err := vm.CallFunction("query", envPtr, msgPtr)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}
	if len(results) != 1 {
		return nil, vm.GetGasReport(), fmt.Errorf("unexpected number of results from query")
	}

	result, err := vm.handleWasmResult(results[0])
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}
	return result, vm.GetGasReport(), nil
}

// Execute calls the "execute" function in the contract (if provided)
func (vm *WazeroVM) Execute(env []byte, info []byte, msg []byte,
	gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI,
	querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {

	if err := vm.updateState(gasMeter, store, api, querier, gasLimit); err != nil {
		return nil, vm.GetGasReport(), fmt.Errorf("failed to update state: %v", err)
	}

	envPtr, err := vm.allocateAndWrite(env)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}
	infoPtr, err := vm.allocateAndWrite(info)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}
	msgPtr, err := vm.allocateAndWrite(msg)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	results, err := vm.CallFunction("execute", envPtr, infoPtr, msgPtr)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}
	if len(results) != 1 {
		return nil, vm.GetGasReport(), fmt.Errorf("unexpected number of results from execute")
	}

	result, err := vm.handleWasmResult(results[0])
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}
	return result, vm.GetGasReport(), nil
}

// Migrate calls the "migrate" function in the contract (if provided)
func (vm *WazeroVM) Migrate(env []byte, msg []byte,
	gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI,
	querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {

	if err := vm.updateState(gasMeter, store, api, querier, gasLimit); err != nil {
		return nil, vm.GetGasReport(), fmt.Errorf("failed to update state: %v", err)
	}

	envPtr, err := vm.allocateAndWrite(env)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}
	msgPtr, err := vm.allocateAndWrite(msg)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	results, err := vm.CallFunction("migrate", envPtr, msgPtr)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}
	if len(results) != 1 {
		return nil, vm.GetGasReport(), fmt.Errorf("unexpected number of results from migrate")
	}

	result, err := vm.handleWasmResult(results[0])
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}
	return result, vm.GetGasReport(), nil
}

// IBCSourceCallback calls the "ibc_source_callback" or similar contract function
func (vm *WazeroVM) IBCSourceCallback(env []byte, msg []byte,
	gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI,
	querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {

	if err := vm.updateState(gasMeter, store, api, querier, gasLimit); err != nil {
		return nil, vm.GetGasReport(), fmt.Errorf("failed to update state: %v", err)
	}

	result, gasReport, err := vm.instance.IBCSourceCallback(env, msg, gasMeter, store, api, querier, gasLimit, printDebug)
	if err != nil {
		return nil, gasReport, vm.handleError(err)
	}

	return result, gasReport, nil
}

// IBCDestinationCallback calls the "ibc_destination_callback" or similar contract function
func (vm *WazeroVM) IBCDestinationCallback(env []byte, msg []byte,
	gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI,
	querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {

	if err := vm.updateState(gasMeter, store, api, querier, gasLimit); err != nil {
		return nil, vm.GetGasReport(), fmt.Errorf("failed to update state: %v", err)
	}

	result, gasReport, err := vm.instance.IBCDestinationCallback(env, msg, gasMeter, store, api, querier, gasLimit, printDebug)
	if err != nil {
		return nil, gasReport, vm.handleError(err)
	}

	return result, gasReport, nil
}

// updateState updates references to store, api, etc. before contract calls
func (vm *WazeroVM) updateState(gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI,
	querier *types.Querier, gasLimit uint64) error {

	if vm.env == nil {
		vm.env = &Environment{
			Store:       store,
			API:         *api,
			Querier:     *querier,
			Block:       BlockInfo{},
			Contract:    ContractInfo{},
			Transaction: nil,
			Code:        nil,
		}
		return nil
	}
	// Update existing environment
	return vm.env.UpdateEnvironment(store, api, querier, vm.env.Transaction)
}

// handleWasmResult handles the pointer to the Wasm-encoded result
func (vm *WazeroVM) handleWasmResult(ptr uint64) ([]byte, error) {
	// We interpret results as pointers to offset/length. Real logic uses your calling convention:
	// e.g., read a length, read data, etc.
	// For brevity, assume 'ptr' is an offset to a string or slice.
	offset := uint32(ptr)
	// Example: read a 4-byte length, then read the actual data
	lengthBytes, err := vm.instance.ReadMemory(offset, 4)
	if err != nil {
		return nil, err
	}
	length := (uint32(lengthBytes[0])) |
		(uint32(lengthBytes[1]) << 8) |
		(uint32(lengthBytes[2]) << 16) |
		(uint32(lengthBytes[3]) << 24)
	data, err := vm.instance.ReadMemory(offset+4, length)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// handleError processes an error, converting out-of-gas cases to OutOfGasError if needed
func (vm *WazeroVM) handleError(err error) error {
	if err == nil {
		return nil
	}
	if vm.checkOutOfGas(err) {
		return types.OutOfGasError{}
	}
	return err
}

// checkOutOfGas checks if the error or usage indicates out of gas
func (vm *WazeroVM) checkOutOfGas(err error) bool {
	if err == nil {
		return false
	}
	if vm.gasUsed > vm.gasLimit {
		return true
	}
	errMsg := err.Error()
	return strings.Contains(errMsg, "out of gas") ||
		strings.Contains(errMsg, "gas limit exceeded") ||
		strings.Contains(errMsg, "insufficient gas")
}

// GetGasReport returns a stub GasReport (expand as needed to track usage).
func (vm *WazeroVM) GetGasReport() types.GasReport {
	return types.GasReport{}
}

// MigrateWithInfo calls the migrate_with_info function in the Wasm module
func (vm *WazeroVM) MigrateWithInfo(
	checksum []byte,
	env []byte,
	msg []byte,
	migrateInfo []byte,
	gasMeter *types.GasMeter,
	store types.KVStore,
	api *types.GoAPI,
	querier *types.Querier,
	gasLimit uint64,
	printDebug bool,
) ([]byte, types.GasReport, error) {
	if err := vm.updateState(gasMeter, store, api, querier, gasLimit); err != nil {
		return nil, vm.GetGasReport(), fmt.Errorf("failed to update state: %v", err)
	}

	envPtr, err := vm.allocateAndWrite(env)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}
	msgPtr, err := vm.allocateAndWrite(msg)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}
	infoPtr, err := vm.allocateAndWrite(migrateInfo)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	results, err := vm.CallFunction("migrate_with_info", envPtr, msgPtr, infoPtr)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	if len(results) != 1 {
		return nil, vm.GetGasReport(), fmt.Errorf("unexpected number of results from migrate_with_info")
	}

	result, err := vm.handleWasmResult(results[0])
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	return result, vm.GetGasReport(), nil
}

// Sudo calls the sudo function in the Wasm module
func (vm *WazeroVM) Sudo(
	env []byte,
	msg []byte,
	gasMeter *types.GasMeter,
	store types.KVStore,
	api *types.GoAPI,
	querier *types.Querier,
	gasLimit uint64,
	printDebug bool,
) ([]byte, types.GasReport, error) {
	if err := vm.updateState(gasMeter, store, api, querier, gasLimit); err != nil {
		return nil, vm.GetGasReport(), fmt.Errorf("failed to update state: %v", err)
	}

	envPtr, err := vm.allocateAndWrite(env)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}
	msgPtr, err := vm.allocateAndWrite(msg)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	results, err := vm.CallFunction("sudo", envPtr, msgPtr)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	if len(results) != 1 {
		return nil, vm.GetGasReport(), fmt.Errorf("unexpected number of results from sudo")
	}

	result, err := vm.handleWasmResult(results[0])
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	return result, vm.GetGasReport(), nil
}

// Reply calls the reply function in the Wasm module
func (vm *WazeroVM) Reply(
	env []byte,
	reply []byte,
	gasMeter *types.GasMeter,
	store types.KVStore,
	api *types.GoAPI,
	querier *types.Querier,
	gasLimit uint64,
	printDebug bool,
) ([]byte, types.GasReport, error) {
	if err := vm.updateState(gasMeter, store, api, querier, gasLimit); err != nil {
		return nil, vm.GetGasReport(), fmt.Errorf("failed to update state: %v", err)
	}

	envPtr, err := vm.allocateAndWrite(env)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}
	replyPtr, err := vm.allocateAndWrite(reply)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	results, err := vm.CallFunction("reply", envPtr, replyPtr)
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	if len(results) != 1 {
		return nil, vm.GetGasReport(), fmt.Errorf("unexpected number of results from reply")
	}

	result, err := vm.handleWasmResult(results[0])
	if err != nil {
		return nil, vm.GetGasReport(), vm.handleError(err)
	}

	return result, vm.GetGasReport(), nil
}
