package api

import (
	"fmt"

	"github.com/CosmWasm/wasmvm/v2/types"
)

// Instantiate creates a new instance of a contract
func Instantiate(
	cache Cache,
	checksum []byte,
	env []byte,
	info []byte,
	msg []byte,
	gasMeter *types.GasMeter,
	store types.KVStore,
	api *types.GoAPI,
	querier *types.Querier,
	gasLimit uint64,
	printDebug bool,
) ([]byte, types.GasReport, error) {
	// Load WASM code from cache
	code, err := GetCode(cache, checksum)
	if err != nil {
		return nil, types.GasReport{}, fmt.Errorf("failed to load code from cache: %w", err)
	}

	// Build environment
	envObj := &Environment{
		Code:    code,
		Store:   store,
		API:     *api,
		Querier: *querier,
	}

	// Create VM instance
	vm, err := NewWazeroVM(envObj, *gasMeter, gasLimit)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	defer vm.Close()

	// Call instantiate
	result, gasReport, err := vm.Instantiate(env, info, msg, gasMeter, store, api, querier, gasLimit, printDebug)
	if err != nil {
		return nil, gasReport, err
	}

	return result, gasReport, nil
}

// Execute calls a given contract
func Execute(
	cache Cache,
	checksum []byte,
	env []byte,
	info []byte,
	msg []byte,
	gasMeter *types.GasMeter,
	store types.KVStore,
	api *types.GoAPI,
	querier *types.Querier,
	gasLimit uint64,
	printDebug bool,
) ([]byte, types.GasReport, error) {
	code, err := GetCode(cache, checksum)
	if err != nil {
		return nil, types.GasReport{}, fmt.Errorf("failed to load code from cache: %w", err)
	}

	envObj := &Environment{
		Code:    code,
		Store:   store,
		API:     *api,
		Querier: *querier,
	}

	vm, err := NewWazeroVM(envObj, *gasMeter, gasLimit)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	defer vm.Close()

	result, gasReport, err := vm.Execute(env, info, msg, gasMeter, store, api, querier, gasLimit, printDebug)
	if err != nil {
		return nil, gasReport, err
	}

	return result, gasReport, nil
}

// Query calls a contract's query method
func Query(
	cache Cache,
	checksum []byte,
	env []byte,
	msg []byte,
	gasMeter *types.GasMeter,
	store types.KVStore,
	api *types.GoAPI,
	querier *types.Querier,
	gasLimit uint64,
	printDebug bool,
) ([]byte, types.GasReport, error) {
	code, err := GetCode(cache, checksum)
	if err != nil {
		return nil, types.GasReport{}, fmt.Errorf("failed to load code from cache: %w", err)
	}

	envObj := &Environment{
		Code:    code,
		Store:   store,
		API:     *api,
		Querier: *querier,
	}

	vm, err := NewWazeroVM(envObj, *gasMeter, gasLimit)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	defer vm.Close()

	result, gasReport, err := vm.Query(env, msg, gasMeter, store, api, querier, gasLimit, printDebug)
	if err != nil {
		return nil, gasReport, err
	}

	return result, gasReport, nil
}

// Migrate migrates a contract to a new code version
func Migrate(
	cache Cache,
	checksum []byte,
	env []byte,
	msg []byte,
	gasMeter *types.GasMeter,
	store types.KVStore,
	api *types.GoAPI,
	querier *types.Querier,
	gasLimit uint64,
	printDebug bool,
) ([]byte, types.GasReport, error) {
	code, err := GetCode(cache, checksum)
	if err != nil {
		return nil, types.GasReport{}, fmt.Errorf("failed to load code from cache: %w", err)
	}

	envObj := &Environment{
		Code:    code,
		Store:   store,
		API:     *api,
		Querier: *querier,
	}

	vm, err := NewWazeroVM(envObj, *gasMeter, gasLimit)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	defer vm.Close()

	result, gasReport, err := vm.Migrate(env, msg, gasMeter, store, api, querier, gasLimit, printDebug)
	if err != nil {
		return nil, gasReport, err
	}

	return result, gasReport, nil
}

// IBCChannelOpen handles an IBC channel opening
func IBCChannelOpen(
	cache Cache,
	checksum []byte,
	env []byte,
	msg []byte,
	gasMeter *types.GasMeter,
	store types.KVStore,
	api *types.GoAPI,
	querier *types.Querier,
	gasLimit uint64,
	printDebug bool,
) ([]byte, types.GasReport, error) {
	code, err := GetCode(cache, checksum)
	if err != nil {
		return nil, types.GasReport{}, fmt.Errorf("failed to load code from cache: %w", err)
	}

	envObj := &Environment{
		Code:    code,
		Store:   store,
		API:     *api,
		Querier: *querier,
	}

	vm, err := NewWazeroVM(envObj, *gasMeter, gasLimit)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	defer vm.Close()

	result, gasReport, err := vm.IBCChannelOpen(env, msg, gasMeter, store, api, querier, gasLimit, printDebug)
	if err != nil {
		return nil, gasReport, err
	}

	return result, gasReport, nil
}

// IBCChannelConnect handles an IBC channel connection
func IBCChannelConnect(
	cache Cache,
	checksum []byte,
	env []byte,
	msg []byte,
	gasMeter *types.GasMeter,
	store types.KVStore,
	api *types.GoAPI,
	querier *types.Querier,
	gasLimit uint64,
	printDebug bool,
) ([]byte, types.GasReport, error) {
	code, err := GetCode(cache, checksum)
	if err != nil {
		return nil, types.GasReport{}, fmt.Errorf("failed to load code from cache: %w", err)
	}

	envObj := &Environment{
		Code:    code,
		Store:   store,
		API:     *api,
		Querier: *querier,
	}

	vm, err := NewWazeroVM(envObj, *gasMeter, gasLimit)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	defer vm.Close()

	result, gasReport, err := vm.IBCChannelConnect(env, msg, gasMeter, store, api, querier, gasLimit, printDebug)
	if err != nil {
		return nil, gasReport, err
	}

	return result, gasReport, nil
}

// IBCChannelClose handles an IBC channel closing
func IBCChannelClose(
	cache Cache,
	checksum []byte,
	env []byte,
	msg []byte,
	gasMeter *types.GasMeter,
	store types.KVStore,
	api *types.GoAPI,
	querier *types.Querier,
	gasLimit uint64,
	printDebug bool,
) ([]byte, types.GasReport, error) {
	code, err := GetCode(cache, checksum)
	if err != nil {
		return nil, types.GasReport{}, fmt.Errorf("failed to load code from cache: %w", err)
	}

	envObj := &Environment{
		Code:    code,
		Store:   store,
		API:     *api,
		Querier: *querier,
	}

	vm, err := NewWazeroVM(envObj, *gasMeter, gasLimit)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	defer vm.Close()

	result, gasReport, err := vm.IBCChannelClose(env, msg, gasMeter, store, api, querier, gasLimit, printDebug)
	if err != nil {
		return nil, gasReport, err
	}

	return result, gasReport, nil
}

// IBCPacketReceive handles an IBC packet receipt
func IBCPacketReceive(
	cache Cache,
	checksum []byte,
	env []byte,
	msg []byte,
	gasMeter *types.GasMeter,
	store types.KVStore,
	api *types.GoAPI,
	querier *types.Querier,
	gasLimit uint64,
	printDebug bool,
) ([]byte, types.GasReport, error) {
	code, err := GetCode(cache, checksum)
	if err != nil {
		return nil, types.GasReport{}, fmt.Errorf("failed to load code from cache: %w", err)
	}

	envObj := &Environment{
		Code:    code,
		Store:   store,
		API:     *api,
		Querier: *querier,
	}

	vm, err := NewWazeroVM(envObj, *gasMeter, gasLimit)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	defer vm.Close()

	result, gasReport, err := vm.IBCPacketReceive(env, msg, gasMeter, store, api, querier, gasLimit, printDebug)
	if err != nil {
		return nil, gasReport, err
	}

	return result, gasReport, nil
}

// IBCPacketAck handles an IBC packet acknowledgment
func IBCPacketAck(
	cache Cache,
	checksum []byte,
	env []byte,
	msg []byte,
	gasMeter *types.GasMeter,
	store types.KVStore,
	api *types.GoAPI,
	querier *types.Querier,
	gasLimit uint64,
	printDebug bool,
) ([]byte, types.GasReport, error) {
	code, err := GetCode(cache, checksum)
	if err != nil {
		return nil, types.GasReport{}, fmt.Errorf("failed to load code from cache: %w", err)
	}

	envObj := &Environment{
		Code:    code,
		Store:   store,
		API:     *api,
		Querier: *querier,
	}

	vm, err := NewWazeroVM(envObj, *gasMeter, gasLimit)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	defer vm.Close()

	result, gasReport, err := vm.IBCPacketAck(env, msg, gasMeter, store, api, querier, gasLimit, printDebug)
	if err != nil {
		return nil, gasReport, err
	}

	return result, gasReport, nil
}

// IBCPacketTimeout handles an IBC packet timeout
func IBCPacketTimeout(
	cache Cache,
	checksum []byte,
	env []byte,
	msg []byte,
	gasMeter *types.GasMeter,
	store types.KVStore,
	api *types.GoAPI,
	querier *types.Querier,
	gasLimit uint64,
	printDebug bool,
) ([]byte, types.GasReport, error) {
	code, err := GetCode(cache, checksum)
	if err != nil {
		return nil, types.GasReport{}, fmt.Errorf("failed to load code from cache: %w", err)
	}

	envObj := &Environment{
		Code:    code,
		Store:   store,
		API:     *api,
		Querier: *querier,
	}

	vm, err := NewWazeroVM(envObj, *gasMeter, gasLimit)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	defer vm.Close()

	result, gasReport, err := vm.IBCPacketTimeout(env, msg, gasMeter, store, api, querier, gasLimit, printDebug)
	if err != nil {
		return nil, gasReport, err
	}

	return result, gasReport, nil
}

// MigrateWithInfo migrates a contract with additional info
func MigrateWithInfo(
	cache Cache,
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
	code, err := GetCode(cache, checksum)
	if err != nil {
		return nil, types.GasReport{}, fmt.Errorf("failed to load code from cache: %w", err)
	}

	envObj := &Environment{
		Code:    code,
		Store:   store,
		API:     *api,
		Querier: *querier,
	}

	vm, err := NewWazeroVM(envObj, *gasMeter, gasLimit)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	defer vm.Close()

	result, gasReport, err := vm.MigrateWithInfo(checksum, env, msg, migrateInfo, gasMeter, store, api, querier, gasLimit, printDebug)
	if err != nil {
		return nil, gasReport, err
	}

	return result, gasReport, nil
}

// Sudo executes privileged operations
func Sudo(
	cache Cache,
	checksum []byte,
	env []byte,
	msg []byte,
	gasMeter *types.GasMeter,
	store types.KVStore,
	api *types.GoAPI,
	querier *types.Querier,
	gasLimit uint64,
	printDebug bool,
) ([]byte, types.GasReport, error) {
	code, err := GetCode(cache, checksum)
	if err != nil {
		return nil, types.GasReport{}, fmt.Errorf("failed to load code from cache: %w", err)
	}

	envObj := &Environment{
		Code:    code,
		Store:   store,
		API:     *api,
		Querier: *querier,
	}

	vm, err := NewWazeroVM(envObj, *gasMeter, gasLimit)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	defer vm.Close()

	result, gasReport, err := vm.Sudo(env, msg, gasMeter, store, api, querier, gasLimit, printDebug)
	if err != nil {
		return nil, gasReport, err
	}

	return result, gasReport, nil
}

// Reply handles a reply to a submessage
func Reply(
	cache Cache,
	checksum []byte,
	env []byte,
	reply []byte,
	gasMeter *types.GasMeter,
	store types.KVStore,
	api *types.GoAPI,
	querier *types.Querier,
	gasLimit uint64,
	printDebug bool,
) ([]byte, types.GasReport, error) {
	code, err := GetCode(cache, checksum)
	if err != nil {
		return nil, types.GasReport{}, fmt.Errorf("failed to load code from cache: %w", err)
	}

	envObj := &Environment{
		Code:    code,
		Store:   store,
		API:     *api,
		Querier: *querier,
	}

	vm, err := NewWazeroVM(envObj, *gasMeter, gasLimit)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	defer vm.Close()

	result, gasReport, err := vm.Reply(env, reply, gasMeter, store, api, querier, gasLimit, printDebug)
	if err != nil {
		return nil, gasReport, err
	}

	return result, gasReport, nil
}

// IBCDestinationCallback handles an IBC destination callback
func IBCDestinationCallback(
	cache Cache,
	checksum []byte,
	env []byte,
	msg []byte,
	gasMeter *types.GasMeter,
	store types.KVStore,
	api *types.GoAPI,
	querier *types.Querier,
	gasLimit uint64,
	printDebug bool,
) ([]byte, types.GasReport, error) {
	code, err := GetCode(cache, checksum)
	if err != nil {
		return nil, types.GasReport{}, fmt.Errorf("failed to load code from cache: %w", err)
	}

	envObj := &Environment{
		Code:    code,
		Store:   store,
		API:     *api,
		Querier: *querier,
	}

	vm, err := NewWazeroVM(envObj, *gasMeter, gasLimit)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	defer vm.Close()

	result, gasReport, err := vm.IBCDestinationCallback(env, msg, gasMeter, store, api, querier, gasLimit, printDebug)
	if err != nil {
		return nil, gasReport, err
	}

	return result, gasReport, nil
}

// IBCSourceCallback handles an IBC source callback
func IBCSourceCallback(
	cache Cache,
	checksum []byte,
	env []byte,
	msg []byte,
	gasMeter *types.GasMeter,
	store types.KVStore,
	api *types.GoAPI,
	querier *types.Querier,
	gasLimit uint64,
	printDebug bool,
) ([]byte, types.GasReport, error) {
	code, err := GetCode(cache, checksum)
	if err != nil {
		return nil, types.GasReport{}, fmt.Errorf("failed to load code from cache: %w", err)
	}

	envObj := &Environment{
		Code:    code,
		Store:   store,
		API:     *api,
		Querier: *querier,
	}

	vm, err := NewWazeroVM(envObj, *gasMeter, gasLimit)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	defer vm.Close()

	result, gasReport, err := vm.IBCSourceCallback(env, msg, gasMeter, store, api, querier, gasLimit, printDebug)
	if err != nil {
		return nil, gasReport, err
	}

	return result, gasReport, nil
}
