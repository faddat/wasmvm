package api

import (
	"github.com/CosmWasm/wasmvm/v2/types"
)

// Instantiate creates a new instance of a contract
func Instantiate(cache Cache, checksum []byte, env []byte, info []byte, msg []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	vm, err := NewWazeroVM(&Environment{Store: store, API: *api, Querier: *querier}, *gasMeter, gasLimit)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	defer vm.Close()
	return vm.Instantiate(env, info, msg, gasMeter, store, api, querier, gasLimit, printDebug)
}

// Execute calls a given contract
func Execute(cache Cache, checksum []byte, env []byte, info []byte, msg []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	vm, err := NewWazeroVM(&Environment{Store: store, API: *api, Querier: *querier}, *gasMeter, gasLimit)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	defer vm.Close()
	return vm.Execute(env, info, msg, gasMeter, store, api, querier, gasLimit, printDebug)
}

// Query allows a client to execute a contract-specific query
func Query(cache Cache, checksum []byte, env []byte, msg []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	vm, err := NewWazeroVM(&Environment{Store: store, API: *api, Querier: *querier}, *gasMeter, gasLimit)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	defer vm.Close()
	return vm.Query(env, msg, gasMeter, store, api, querier, gasLimit, printDebug)
}

// Migrate migrates a contract to a new code version
func Migrate(cache Cache, checksum []byte, env []byte, msg []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	vm, err := NewWazeroVM(&Environment{Store: store, API: *api, Querier: *querier}, *gasMeter, gasLimit)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	defer vm.Close()
	return vm.Migrate(env, msg, gasMeter, store, api, querier, gasLimit, printDebug)
}

// MigrateWithInfo migrates a contract with additional info
func MigrateWithInfo(cache Cache, checksum []byte, env []byte, msg []byte, migrateInfo []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	vm, err := NewWazeroVM(&Environment{Store: store, API: *api, Querier: *querier}, *gasMeter, gasLimit)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	defer vm.Close()
	return vm.MigrateWithInfo(env, msg, migrateInfo, gasMeter, store, api, querier, gasLimit, printDebug)
}

// Sudo makes privileged operations
func Sudo(cache Cache, checksum []byte, env []byte, msg []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	vm, err := NewWazeroVM(&Environment{Store: store, API: *api, Querier: *querier}, *gasMeter, gasLimit)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	defer vm.Close()
	return vm.Sudo(env, msg, gasMeter, store, api, querier, gasLimit, printDebug)
}

// Reply handles submessage responses
func Reply(cache Cache, checksum []byte, env []byte, reply []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	vm, err := NewWazeroVM(&Environment{Store: store, API: *api, Querier: *querier}, *gasMeter, gasLimit)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	defer vm.Close()
	return vm.Reply(env, reply, gasMeter, store, api, querier, gasLimit, printDebug)
}

// IBCChannelOpen handles IBC channel open
func IBCChannelOpen(cache Cache, checksum []byte, env []byte, msg []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	vm, err := NewWazeroVM(&Environment{Store: store, API: *api, Querier: *querier}, *gasMeter, gasLimit)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	defer vm.Close()
	return vm.IBCChannelOpen(env, msg, gasMeter, store, api, querier, gasLimit, printDebug)
}

// IBCChannelConnect handles IBC channel connect
func IBCChannelConnect(cache Cache, checksum []byte, env []byte, msg []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	vm, err := NewWazeroVM(&Environment{Store: store, API: *api, Querier: *querier}, *gasMeter, gasLimit)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	defer vm.Close()
	return vm.IBCChannelConnect(env, msg, gasMeter, store, api, querier, gasLimit, printDebug)
}

// IBCChannelClose handles IBC channel close
func IBCChannelClose(cache Cache, checksum []byte, env []byte, msg []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	vm, err := NewWazeroVM(&Environment{Store: store, API: *api, Querier: *querier}, *gasMeter, gasLimit)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	defer vm.Close()
	return vm.IBCChannelClose(env, msg, gasMeter, store, api, querier, gasLimit, printDebug)
}

// IBCPacketReceive handles IBC packet receive
func IBCPacketReceive(cache Cache, checksum []byte, env []byte, msg []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	vm, err := NewWazeroVM(&Environment{Store: store, API: *api, Querier: *querier}, *gasMeter, gasLimit)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	defer vm.Close()
	return vm.IBCPacketReceive(env, msg, gasMeter, store, api, querier, gasLimit, printDebug)
}

// IBCPacketAck handles IBC packet acknowledgment
func IBCPacketAck(cache Cache, checksum []byte, env []byte, msg []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	vm, err := NewWazeroVM(&Environment{Store: store, API: *api, Querier: *querier}, *gasMeter, gasLimit)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	defer vm.Close()
	return vm.IBCPacketAck(env, msg, gasMeter, store, api, querier, gasLimit, printDebug)
}

// IBCPacketTimeout handles IBC packet timeout
func IBCPacketTimeout(cache Cache, checksum []byte, env []byte, msg []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	vm, err := NewWazeroVM(&Environment{Store: store, API: *api, Querier: *querier}, *gasMeter, gasLimit)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	defer vm.Close()
	return vm.IBCPacketTimeout(env, msg, gasMeter, store, api, querier, gasLimit, printDebug)
}

// IBCSourceCallback handles IBC source callback
func IBCSourceCallback(cache Cache, checksum []byte, env []byte, msg []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	vm, err := NewWazeroVM(&Environment{Store: store, API: *api, Querier: *querier}, *gasMeter, gasLimit)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	defer vm.Close()
	return vm.IBCSourceCallback(env, msg, gasMeter, store, api, querier, gasLimit, printDebug)
}

// IBCDestinationCallback handles IBC destination callback
func IBCDestinationCallback(cache Cache, checksum []byte, env []byte, msg []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *types.Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	vm, err := NewWazeroVM(&Environment{Store: store, API: *api, Querier: *querier}, *gasMeter, gasLimit)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	defer vm.Close()
	return vm.IBCDestinationCallback(env, msg, gasMeter, store, api, querier, gasLimit, printDebug)
}
