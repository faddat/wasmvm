package api

import (
	"fmt"

	"github.com/CosmWasm/wasmvm/v2/types"
)

// Environment represents the environment for a Wasm contract
type Environment struct {
	Code        []byte
	Store       types.KVStore
	API         types.GoAPI
	Querier     types.Querier
	Block       BlockInfo
	Contract    ContractInfo
	Transaction *TransactionInfo
}

// BlockInfo contains information about the current block
type BlockInfo struct {
	Height  int64
	Time    int64
	ChainID string
}

// ContractInfo contains information about the contract
type ContractInfo struct {
	Address string
	Creator string
}

// TransactionInfo contains information about the current transaction
type TransactionInfo struct {
	Index uint32
}

// Validate checks if all required fields are set
func (e *Environment) Validate() error {
	if e == nil {
		return fmt.Errorf("environment cannot be nil")
	}
	if e.Code == nil {
		return fmt.Errorf("code is required")
	}
	if e.Store == nil {
		return fmt.Errorf("store is required")
	}
	if e.API.HumanizeAddress == nil || e.API.CanonicalizeAddress == nil || e.API.ValidateAddress == nil {
		return fmt.Errorf("all API functions must be set (HumanizeAddress, CanonicalizeAddress, ValidateAddress)")
	}
	var nilQuerier types.Querier
	if e.Querier == nilQuerier {
		return fmt.Errorf("querier is required")
	}
	return nil
}

// NewEnvironment creates a new environment with the given parameters
func NewEnvironment(code []byte, store types.KVStore, api *types.GoAPI, querier *types.Querier, block BlockInfo, contract ContractInfo, transaction *TransactionInfo) (*Environment, error) {
	if api == nil {
		return nil, fmt.Errorf("api is required")
	}
	if querier == nil {
		return nil, fmt.Errorf("querier is required")
	}

	env := &Environment{
		Code:        code,
		Store:       store,
		API:         *api,
		Querier:     *querier,
		Block:       block,
		Contract:    contract,
		Transaction: transaction,
	}

	if err := env.Validate(); err != nil {
		return nil, err
	}

	return env, nil
}

// UpdateEnvironment updates the environment with new parameters
func (e *Environment) UpdateEnvironment(store types.KVStore, api *types.GoAPI, querier *types.Querier, transaction *TransactionInfo) error {
	if api == nil {
		return fmt.Errorf("api is required")
	}
	if querier == nil {
		return fmt.Errorf("querier is required")
	}

	e.Store = store
	e.API = *api
	e.Querier = *querier
	e.Transaction = transaction

	return e.Validate()
}
