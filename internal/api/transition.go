package api

import (
	"fmt"

	"github.com/CosmWasm/wasmvm/v2/types"
)

// InstantiateContract creates a new instance of a contract
func InstantiateContract(
	env *Environment,
	gasMeter types.GasMeter,
	gasLimit uint64,
) (types.GasReport, error) {
	vm, err := NewWazeroVM(env, gasMeter, gasLimit)
	if err != nil {
		return types.EmptyGasReport(gasLimit), fmt.Errorf("failed to create wazero vm: %v", err)
	}
	defer vm.Close()

	return vm.Instantiate()
}

// ExecuteContract executes a contract
func ExecuteContract(
	env *Environment,
	gasMeter types.GasMeter,
	gasLimit uint64,
) (types.GasReport, error) {
	vm, err := NewWazeroVM(env, gasMeter, gasLimit)
	if err != nil {
		return types.EmptyGasReport(gasLimit), fmt.Errorf("failed to create wazero vm: %v", err)
	}
	defer vm.Close()

	return vm.Execute()
}

// MigrateContract migrates a contract to a new code version
func MigrateContract(
	env *Environment,
	gasMeter types.GasMeter,
	gasLimit uint64,
) (types.GasReport, error) {
	vm, err := NewWazeroVM(env, gasMeter, gasLimit)
	if err != nil {
		return types.EmptyGasReport(gasLimit), fmt.Errorf("failed to create wazero vm: %v", err)
	}
	defer vm.Close()

	return vm.Migrate()
}

// SudoContract executes privileged operations on a contract
func SudoContract(
	env *Environment,
	gasMeter types.GasMeter,
	gasLimit uint64,
) (types.GasReport, error) {
	vm, err := NewWazeroVM(env, gasMeter, gasLimit)
	if err != nil {
		return types.EmptyGasReport(gasLimit), fmt.Errorf("failed to create wazero vm: %v", err)
	}
	defer vm.Close()

	return vm.Sudo()
}

// QueryContract executes a read-only query on a contract
func QueryContract(
	env *Environment,
	gasMeter types.GasMeter,
	gasLimit uint64,
) (types.GasReport, error) {
	vm, err := NewWazeroVM(env, gasMeter, gasLimit)
	if err != nil {
		return types.EmptyGasReport(gasLimit), fmt.Errorf("failed to create wazero vm: %v", err)
	}
	defer vm.Close()

	return vm.Query()
}

// ReplyContract handles a reply from a submessage
func ReplyContract(
	env *Environment,
	gasMeter types.GasMeter,
	gasLimit uint64,
) (types.GasReport, error) {
	vm, err := NewWazeroVM(env, gasMeter, gasLimit)
	if err != nil {
		return types.EmptyGasReport(gasLimit), fmt.Errorf("failed to create wazero vm: %v", err)
	}
	defer vm.Close()

	return vm.Reply()
}
