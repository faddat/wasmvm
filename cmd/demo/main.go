package main

import (
	"fmt"
	"os"

	wasmvm "github.com/CosmWasm/wasmvm/v2"
	"github.com/CosmWasm/wasmvm/v2/types"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <wasmFile>\n", os.Args[0])
		os.Exit(1)
	}
	wasmFile := os.Args[1]

	config := types.VMConfig{
		WasmLimits: types.WasmLimits{},
		Cache: types.CacheOptions{
			BaseDir:                  os.TempDir(),
			AvailableCapabilities:    []string{"staking", "stargate", "iterator"},
			MemoryCacheSizeBytes:     types.NewSizeKibi(100 * 1024), // 100 MiB
			InstanceMemoryLimitBytes: types.NewSizeKibi(32 * 1024),  // 32 MiB
		},
	}

	vm, err := wasmvm.NewVM(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create VM: %v\n", err)
		os.Exit(1)
	}
	defer vm.Cleanup()

	code, err := os.ReadFile(wasmFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read Wasm file: %v\n", err)
		os.Exit(1)
	}

	checksum, _, err := vm.StoreCode(code, 500_000_000_000)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to store code: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Code stored with checksum: %X\n", checksum)
}
