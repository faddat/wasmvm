package api

import (
	"fmt"
	"reflect"

	"github.com/CosmWasm/wasmvm/v2/types"
)

// Environment represents the environment for a Wasm contract
type Environment struct {
	Code     []byte
	Store    types.KVStore
	API      types.GoAPI
	Querier  types.Querier
	Block    BlockInfo
	Contract ContractInfo
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

// Validate checks if all required fields are set
func (e *Environment) Validate() error {
	if e.Code == nil {
		return fmt.Errorf("code is required")
	}
	if e.Store == nil {
		return fmt.Errorf("store is required")
	}
	if reflect.ValueOf(e.API).IsNil() {
		return fmt.Errorf("api is required")
	}
	if reflect.ValueOf(e.Querier).IsNil() {
		return fmt.Errorf("querier is required")
	}
	return nil
}

// NewEnvironment creates a new environment with the given parameters
func NewEnvironment(code []byte, store types.KVStore, api *types.GoAPI, querier *types.Querier, block BlockInfo, contract ContractInfo) (*Environment, error) {
	if api == nil {
		return nil, fmt.Errorf("api is required")
	}
	if querier == nil {
		return nil, fmt.Errorf("querier is required")
	}

	env := &Environment{
		Code:     code,
		Store:    store,
		API:      *api,
		Querier:  *querier,
		Block:    block,
		Contract: contract,
	}

	if err := env.Validate(); err != nil {
		return nil, err
	}

	return env, nil
}

// UpdateEnvironment updates the environment with new parameters
func (e *Environment) UpdateEnvironment(store types.KVStore, api *types.GoAPI, querier *types.Querier) error {
	if api == nil {
		return fmt.Errorf("api is required")
	}
	if querier == nil {
		return fmt.Errorf("querier is required")
	}

	e.Store = store
	e.API = *api
	e.Querier = *querier

	return e.Validate()
}
