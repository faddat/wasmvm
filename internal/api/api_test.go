package api

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/CosmWasm/wasmvm/v2/types"
)

func TestWazeroVM(t *testing.T) {
	// Create environment
	gasMeter := NewMockGasMeter(1000000)
	store := NewLookup(gasMeter)
	api := NewMockAPI()
	querier := DefaultQuerier(MOCK_CONTRACT_ADDR, types.Array[types.Coin]{types.NewCoin(100, "ATOM")})

	env := &Environment{
		Code:    []byte("test code"),
		Store:   store,
		API:     api,
		Querier: querier,
	}

	// Create VM
	vm, err := NewWazeroVM(env, gasMeter, 1000000)
	require.NoError(t, err)
	defer vm.Close()

	// Test gas consumption
	require.Equal(t, uint64(0), vm.gasUsed)

	// Test store operations
	store.Set([]byte("key"), []byte("value"))
	value := store.Get([]byte("key"))
	require.Equal(t, []byte("value"), value)

	// Test gas consumption after operations
	require.True(t, gasMeter.GasConsumed() > 0)
}
