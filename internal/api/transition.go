package api

import (
	"fmt"

	"github.com/CosmWasm/wasmvm/v2/types"
)

// Instantiate creates a new instance of a contract
func Instantiate(
	cache *Cache,
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
	code, err := GetCode(*cache, checksum)
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
	vm := NewWazeroVMWithCache(*cache)

	// Call instantiate
	result, gasReport, err := vm.Execute(envObj, info, msg, gasMeter, store, api, querier, gasLimit, printDebug)
	if err != nil {
		return nil, gasReport, err
	}

	return result, gasReport, nil
}

// Execute creates a new instance and executes the given function
func Execute(
	cache *Cache,
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
	code, err := GetCode(*cache, checksum)
	if err != nil {
		return nil, types.GasReport{}, fmt.Errorf("failed to load code from cache: %w", err)
	}

	envObj := &Environment{
		Code:    code,
		Store:   store,
		API:     *api,
		Querier: *querier,
	}

	vm := NewWazeroVMWithCache(*cache)

	result, gasReport, err := vm.Execute(envObj, info, msg, gasMeter, store, api, querier, gasLimit, printDebug)
	if err != nil {
		return nil, gasReport, err
	}

	return result, gasReport, nil
}

// Query creates a new instance and executes a query
func Query(
	cache *Cache,
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
	code, err := GetCode(*cache, checksum)
	if err != nil {
		return nil, types.GasReport{}, fmt.Errorf("failed to load code from cache: %w", err)
	}

	envObj := &Environment{
		Code:    code,
		Store:   store,
		API:     *api,
		Querier: *querier,
	}

	vm := NewWazeroVMWithCache(*cache)

	result, gasReport, err := vm.Query(envObj, msg, gasMeter, store, api, querier, gasLimit, printDebug)
	if err != nil {
		return nil, gasReport, err
	}

	return result, gasReport, nil
}

// Migrate creates a new instance and executes a migration
func Migrate(
	cache *Cache,
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
	code, err := GetCode(*cache, checksum)
	if err != nil {
		return nil, types.GasReport{}, fmt.Errorf("failed to load code from cache: %w", err)
	}

	envObj := &Environment{
		Code:    code,
		Store:   store,
		API:     *api,
		Querier: *querier,
	}

	vm := NewWazeroVMWithCache(*cache)

	result, gasReport, err := vm.Migrate(envObj, msg, gasMeter, store, api, querier, gasLimit, printDebug)
	if err != nil {
		return nil, gasReport, err
	}

	return result, gasReport, nil
}

// MigrateWithInfo creates a new instance and executes a migration with additional info
func MigrateWithInfo(
	cache *Cache,
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
	code, err := GetCode(*cache, checksum)
	if err != nil {
		return nil, types.GasReport{}, fmt.Errorf("failed to load code from cache: %w", err)
	}

	envObj := &Environment{
		Code:    code,
		Store:   store,
		API:     *api,
		Querier: *querier,
	}

	vm := NewWazeroVMWithCache(*cache)

	result, gasReport, err := vm.MigrateWithInfo(envObj, msg, migrateInfo, gasMeter, store, api, querier, gasLimit, printDebug)
	if err != nil {
		return nil, gasReport, err
	}

	return result, gasReport, nil
}

// Sudo creates a new instance and executes a privileged operation
func Sudo(
	cache *Cache,
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
	code, err := GetCode(*cache, checksum)
	if err != nil {
		return nil, types.GasReport{}, fmt.Errorf("failed to load code from cache: %w", err)
	}

	envObj := &Environment{
		Code:    code,
		Store:   store,
		API:     *api,
		Querier: *querier,
	}

	vm := NewWazeroVMWithCache(*cache)

	result, gasReport, err := vm.Sudo(envObj, msg, gasMeter, store, api, querier, gasLimit, printDebug)
	if err != nil {
		return nil, gasReport, err
	}

	return result, gasReport, nil
}

// Reply creates a new instance and executes a reply callback
func Reply(
	cache *Cache,
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
	code, err := GetCode(*cache, checksum)
	if err != nil {
		return nil, types.GasReport{}, fmt.Errorf("failed to load code from cache: %w", err)
	}

	envObj := &Environment{
		Code:    code,
		Store:   store,
		API:     *api,
		Querier: *querier,
	}

	vm := NewWazeroVMWithCache(*cache)

	result, gasReport, err := vm.Reply(envObj, msg, gasMeter, store, api, querier, gasLimit, printDebug)
	if err != nil {
		return nil, gasReport, err
	}

	return result, gasReport, nil
}

// IBCChannelOpen creates a new instance and executes an IBC channel open
func IBCChannelOpen(
	cache *Cache,
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
	code, err := GetCode(*cache, checksum)
	if err != nil {
		return nil, types.GasReport{}, fmt.Errorf("failed to load code from cache: %w", err)
	}

	envObj := &Environment{
		Code:    code,
		Store:   store,
		API:     *api,
		Querier: *querier,
	}

	vm := NewWazeroVMWithCache(*cache)

	result, gasReport, err := vm.IBCChannelOpen(envObj, msg, gasMeter, store, api, querier, gasLimit, printDebug)
	if err != nil {
		return nil, gasReport, err
	}

	return result, gasReport, nil
}

// IBCChannelConnect creates a new instance and executes an IBC channel connect
func IBCChannelConnect(
	cache *Cache,
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
	code, err := GetCode(*cache, checksum)
	if err != nil {
		return nil, types.GasReport{}, fmt.Errorf("failed to load code from cache: %w", err)
	}

	envObj := &Environment{
		Code:    code,
		Store:   store,
		API:     *api,
		Querier: *querier,
	}

	vm := NewWazeroVMWithCache(*cache)

	result, gasReport, err := vm.IBCChannelConnect(envObj, msg, gasMeter, store, api, querier, gasLimit, printDebug)
	if err != nil {
		return nil, gasReport, err
	}

	return result, gasReport, nil
}

// IBCChannelClose creates a new instance and executes an IBC channel close
func IBCChannelClose(
	cache *Cache,
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
	code, err := GetCode(*cache, checksum)
	if err != nil {
		return nil, types.GasReport{}, fmt.Errorf("failed to load code from cache: %w", err)
	}

	envObj := &Environment{
		Code:    code,
		Store:   store,
		API:     *api,
		Querier: *querier,
	}

	vm := NewWazeroVMWithCache(*cache)

	result, gasReport, err := vm.IBCChannelClose(envObj, msg, gasMeter, store, api, querier, gasLimit, printDebug)
	if err != nil {
		return nil, gasReport, err
	}

	return result, gasReport, nil
}

// IBCPacketReceive creates a new instance and executes an IBC packet receive
func IBCPacketReceive(
	cache *Cache,
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
	code, err := GetCode(*cache, checksum)
	if err != nil {
		return nil, types.GasReport{}, fmt.Errorf("failed to load code from cache: %w", err)
	}

	envObj := &Environment{
		Code:    code,
		Store:   store,
		API:     *api,
		Querier: *querier,
	}

	vm := NewWazeroVMWithCache(*cache)

	result, gasReport, err := vm.IBCPacketReceive(envObj, msg, gasMeter, store, api, querier, gasLimit, printDebug)
	if err != nil {
		return nil, gasReport, err
	}

	return result, gasReport, nil
}

// IBCPacketAck creates a new instance and executes an IBC packet ack
func IBCPacketAck(
	cache *Cache,
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
	code, err := GetCode(*cache, checksum)
	if err != nil {
		return nil, types.GasReport{}, fmt.Errorf("failed to load code from cache: %w", err)
	}

	envObj := &Environment{
		Code:    code,
		Store:   store,
		API:     *api,
		Querier: *querier,
	}

	vm := NewWazeroVMWithCache(*cache)

	result, gasReport, err := vm.IBCPacketAck(envObj, msg, gasMeter, store, api, querier, gasLimit, printDebug)
	if err != nil {
		return nil, gasReport, err
	}

	return result, gasReport, nil
}

// IBCPacketTimeout creates a new instance and executes an IBC packet timeout
func IBCPacketTimeout(
	cache *Cache,
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
	code, err := GetCode(*cache, checksum)
	if err != nil {
		return nil, types.GasReport{}, fmt.Errorf("failed to load code from cache: %w", err)
	}

	envObj := &Environment{
		Code:    code,
		Store:   store,
		API:     *api,
		Querier: *querier,
	}

	vm := NewWazeroVMWithCache(*cache)

	result, gasReport, err := vm.IBCPacketTimeout(envObj, msg, gasMeter, store, api, querier, gasLimit, printDebug)
	if err != nil {
		return nil, gasReport, err
	}

	return result, gasReport, nil
}

// IBCSourceCallback creates a new instance and executes an IBC source callback
func IBCSourceCallback(
	cache *Cache,
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
	code, err := GetCode(*cache, checksum)
	if err != nil {
		return nil, types.GasReport{}, fmt.Errorf("failed to load code from cache: %w", err)
	}

	envObj := &Environment{
		Code:    code,
		Store:   store,
		API:     *api,
		Querier: *querier,
	}

	vm := NewWazeroVMWithCache(*cache)

	result, gasReport, err := vm.IBCSourceCallback(envObj, msg, gasMeter, store, api, querier, gasLimit, printDebug)
	if err != nil {
		return nil, gasReport, err
	}

	return result, gasReport, nil
}

// IBCDestinationCallback creates a new instance and executes an IBC destination callback
func IBCDestinationCallback(
	cache *Cache,
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
	code, err := GetCode(*cache, checksum)
	if err != nil {
		return nil, types.GasReport{}, fmt.Errorf("failed to load code from cache: %w", err)
	}

	envObj := &Environment{
		Code:    code,
		Store:   store,
		API:     *api,
		Querier: *querier,
	}

	vm := NewWazeroVMWithCache(*cache)

	result, gasReport, err := vm.IBCDestinationCallback(envObj, msg, gasMeter, store, api, querier, gasLimit, printDebug)
	if err != nil {
		return nil, gasReport, err
	}

	return result, gasReport, nil
}
