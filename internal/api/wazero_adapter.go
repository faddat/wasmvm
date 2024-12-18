package api

import (
	"github.com/CosmWasm/wasmvm/v2/types"
)

// Querier is an alias for types.Querier
type Querier = types.Querier

// WazeroVM represents a Wazero-based VM
type WazeroVM struct {
	cache      Cache
	env        *Environment
	printDebug bool
}

// NewWazeroVMWithCache creates a new WazeroVM instance with a given cache
func NewWazeroVMWithCache(cache Cache) *WazeroVM {
	return &WazeroVM{
		cache: cache,
	}
}

// CreateInstance creates a new WazeroInstance with the given environment and gas limit
func (vm *WazeroVM) CreateInstance(env *Environment, gasLimit uint64) (*WazeroInstance, error) {
	gasMeter := &WazeroGasMeter{}
	instance, err := NewWazeroInstance(env, env.Code, gasMeter, gasLimit)
	if err != nil {
		return nil, err
	}
	return instance, nil
}

// Execute creates a new instance and executes the given function
func (vm *WazeroVM) Execute(env *Environment, info []byte, msg []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	instance, err := vm.CreateInstance(env, gasLimit)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	defer instance.Close()
	return instance.Execute(env.Code, info, msg, gasMeter, store, api, querier, gasLimit, printDebug)
}

// Query creates a new instance and executes a query
func (vm *WazeroVM) Query(env *Environment, msg []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	instance, err := vm.CreateInstance(env, gasLimit)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	defer instance.Close()
	return instance.Query(env.Code, msg, gasMeter, store, api, querier, gasLimit, printDebug)
}

// Migrate creates a new instance and executes a migration
func (vm *WazeroVM) Migrate(env *Environment, msg []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	instance, err := vm.CreateInstance(env, gasLimit)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	defer instance.Close()
	return instance.Migrate(env.Code, msg, gasMeter, store, api, querier, gasLimit, printDebug)
}

// MigrateWithInfo creates a new instance and executes a migration with additional info
func (vm *WazeroVM) MigrateWithInfo(env *Environment, msg []byte, migrateInfo []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	instance, err := vm.CreateInstance(env, gasLimit)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	defer instance.Close()
	return instance.MigrateWithInfo(env.Code, msg, migrateInfo, gasMeter, store, api, querier, gasLimit, printDebug)
}

// Sudo creates a new instance and executes a privileged function
func (vm *WazeroVM) Sudo(env *Environment, msg []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	instance, err := vm.CreateInstance(env, gasLimit)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	defer instance.Close()
	return instance.Sudo(env.Code, msg, gasMeter, store, api, querier, gasLimit, printDebug)
}

// Reply creates a new instance and executes a reply callback
func (vm *WazeroVM) Reply(env *Environment, reply []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	instance, err := vm.CreateInstance(env, gasLimit)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	defer instance.Close()
	return instance.Reply(env.Code, reply, gasMeter, store, api, querier, gasLimit, printDebug)
}

// IBCChannelOpen creates a new instance and executes an IBC channel open
func (vm *WazeroVM) IBCChannelOpen(env *Environment, msg []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	instance, err := vm.CreateInstance(env, gasLimit)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	defer instance.Close()
	return instance.IBCChannelOpen(env.Code, msg, gasMeter, store, api, querier, gasLimit, printDebug)
}

// IBCChannelConnect creates a new instance and executes an IBC channel connect
func (vm *WazeroVM) IBCChannelConnect(env *Environment, msg []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	instance, err := vm.CreateInstance(env, gasLimit)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	defer instance.Close()
	return instance.IBCChannelConnect(env.Code, msg, gasMeter, store, api, querier, gasLimit, printDebug)
}

// IBCChannelClose creates a new instance and executes an IBC channel close
func (vm *WazeroVM) IBCChannelClose(env *Environment, msg []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	instance, err := vm.CreateInstance(env, gasLimit)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	defer instance.Close()
	return instance.IBCChannelClose(env.Code, msg, gasMeter, store, api, querier, gasLimit, printDebug)
}

// IBCPacketReceive creates a new instance and executes an IBC packet receive
func (vm *WazeroVM) IBCPacketReceive(env *Environment, msg []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	instance, err := vm.CreateInstance(env, gasLimit)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	defer instance.Close()
	return instance.IBCPacketReceive(env.Code, msg, gasMeter, store, api, querier, gasLimit, printDebug)
}

// IBCPacketAck creates a new instance and executes an IBC packet ack
func (vm *WazeroVM) IBCPacketAck(env *Environment, msg []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	instance, err := vm.CreateInstance(env, gasLimit)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	defer instance.Close()
	return instance.IBCPacketAck(env.Code, msg, gasMeter, store, api, querier, gasLimit, printDebug)
}

// IBCPacketTimeout creates a new instance and executes an IBC packet timeout
func (vm *WazeroVM) IBCPacketTimeout(env *Environment, msg []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	instance, err := vm.CreateInstance(env, gasLimit)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	defer instance.Close()
	return instance.IBCPacketTimeout(env.Code, msg, gasMeter, store, api, querier, gasLimit, printDebug)
}

// IBCSourceCallback creates a new instance and executes an IBC source callback
func (vm *WazeroVM) IBCSourceCallback(env *Environment, msg []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	instance, err := vm.CreateInstance(env, gasLimit)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	defer instance.Close()
	return instance.IBCSourceCallback(env.Code, msg, gasMeter, store, api, querier, gasLimit, printDebug)
}

// IBCDestinationCallback creates a new instance and executes an IBC destination callback
func (vm *WazeroVM) IBCDestinationCallback(env *Environment, msg []byte, gasMeter *types.GasMeter, store types.KVStore, api *types.GoAPI, querier *Querier, gasLimit uint64, printDebug bool) ([]byte, types.GasReport, error) {
	instance, err := vm.CreateInstance(env, gasLimit)
	if err != nil {
		return nil, types.GasReport{}, err
	}
	defer instance.Close()
	return instance.IBCDestinationCallback(env.Code, msg, gasMeter, store, api, querier, gasLimit, printDebug)
}

// AnalyzeCode returns a report about the given code
func (vm *WazeroVM) AnalyzeCode(checksum []byte) (*types.AnalysisReport, error) {
	code, err := GetCode(vm.cache, checksum)
	if err != nil {
		return nil, err
	}

	env := &Environment{
		Code: code,
	}

	instance, err := NewWazeroInstance(env, code, &WazeroGasMeter{}, 0)
	if err != nil {
		return nil, err
	}
	defer instance.Close()

	return instance.AnalyzeCode()
}

// GetMetrics returns metrics about the VM
func (vm *WazeroVM) GetMetrics() (*types.Metrics, error) {
	return &types.Metrics{}, nil
}

// GetPinnedMetrics returns metrics about pinned contracts
func (vm *WazeroVM) GetPinnedMetrics() (*types.PinnedMetrics, error) {
	return &types.PinnedMetrics{}, nil
}

// Pin pins a contract in memory
func (vm *WazeroVM) Pin(checksum []byte) error {
	return nil
}

// Unpin unpins a contract from memory
func (vm *WazeroVM) Unpin(checksum []byte) error {
	return nil
}
