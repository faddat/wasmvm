package api

import (
	"context"
	"fmt"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// WazeroInstance represents a Wazero WebAssembly instance
type WazeroInstance struct {
	runtime    wazero.Runtime
	module     api.Module
	hostModule api.Module
	gasLimit   uint64
}

// NewWazeroInstance creates a new Wazero instance
func NewWazeroInstance(code []byte, gasLimit uint64) (*WazeroInstance, error) {
	ctx := context.Background()

	// Create runtime
	runtime := wazero.NewRuntime(ctx)

	// Create host module with environment functions
	builder := runtime.NewHostModuleBuilder("env")

	// Add db_read function
	builder.NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m api.Module, keyPtr, keyLen, valuePtr uint32) uint32 {
			// Implementation will be provided by the VM
			return 0
		}).
		WithParameterNames("key_ptr", "key_len", "value_ptr").
		Export("db_read")

	// Add db_write function
	builder.NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m api.Module, keyPtr, keyLen, valuePtr, valueLen uint32) uint32 {
			// Implementation will be provided by the VM
			return 0
		}).
		WithParameterNames("key_ptr", "key_len", "value_ptr", "value_len").
		Export("db_write")

	// Add db_remove function
	builder.NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m api.Module, keyPtr, keyLen uint32) uint32 {
			// Implementation will be provided by the VM
			return 0
		}).
		WithParameterNames("key_ptr", "key_len").
		Export("db_remove")

	// Add gas_consume function
	builder.NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m api.Module, amount uint64) {
			// Implementation will be provided by the VM
		}).
		WithParameterNames("amount").
		Export("gas_consume")

	// Add env_get function
	builder.NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m api.Module, keyPtr, keyLen, valuePtr uint32) uint32 {
			// Implementation will be provided by the VM
			return 0
		}).
		WithParameterNames("key_ptr", "key_len", "value_ptr").
		Export("env_get")

	// Add query_chain function
	builder.NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m api.Module, requestPtr, requestLen uint32) uint64 {
			// Implementation will be provided by the VM
			return 0
		}).
		WithParameterNames("request_ptr", "request_len").
		Export("query_chain")

	// Add ibc_channel_open function
	builder.NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m api.Module, envPtr, msgPtr uint32) uint64 {
			// Implementation will be provided by the VM
			return 0
		}).
		WithParameterNames("env_ptr", "msg_ptr").
		Export("ibc_channel_open")

	// Add ibc_channel_connect function
	builder.NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m api.Module, envPtr, msgPtr uint32) uint64 {
			// Implementation will be provided by the VM
			return 0
		}).
		WithParameterNames("env_ptr", "msg_ptr").
		Export("ibc_channel_connect")

	// Add ibc_channel_close function
	builder.NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m api.Module, envPtr, msgPtr uint32) uint64 {
			// Implementation will be provided by the VM
			return 0
		}).
		WithParameterNames("env_ptr", "msg_ptr").
		Export("ibc_channel_close")

	// Add ibc_packet_receive function
	builder.NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m api.Module, envPtr, msgPtr uint32) uint64 {
			// Implementation will be provided by the VM
			return 0
		}).
		WithParameterNames("env_ptr", "msg_ptr").
		Export("ibc_packet_receive")

	// Add ibc_packet_ack function
	builder.NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m api.Module, envPtr, msgPtr uint32) uint64 {
			// Implementation will be provided by the VM
			return 0
		}).
		WithParameterNames("env_ptr", "msg_ptr").
		Export("ibc_packet_ack")

	// Add ibc_packet_timeout function
	builder.NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m api.Module, envPtr, msgPtr uint32) uint64 {
			// Implementation will be provided by the VM
			return 0
		}).
		WithParameterNames("env_ptr", "msg_ptr").
		Export("ibc_packet_timeout")

	// Add ibc_source_callback function
	builder.NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m api.Module, envPtr, msgPtr uint32) uint64 {
			// Implementation will be provided by the VM
			return 0
		}).
		WithParameterNames("env_ptr", "msg_ptr").
		Export("ibc_source_callback")

	// Add ibc_destination_callback function
	builder.NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m api.Module, envPtr, msgPtr uint32) uint64 {
			// Implementation will be provided by the VM
			return 0
		}).
		WithParameterNames("env_ptr", "msg_ptr").
		Export("ibc_destination_callback")

	// Add migrate_with_info function
	builder.NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m api.Module, envPtr, msgPtr, infoPtr uint32) uint64 {
			// Implementation will be provided by the VM
			return 0
		}).
		WithParameterNames("env_ptr", "msg_ptr", "info_ptr").
		Export("migrate_with_info")

	// Instantiate the host module
	hostModule, err := builder.Instantiate(ctx)
	if err != nil {
		runtime.Close(ctx)
		return nil, fmt.Errorf("failed to create host module: %v", err)
	}

	// Compile module
	compiled, err := runtime.CompileModule(ctx, code)
	if err != nil {
		runtime.Close(ctx)
		return nil, fmt.Errorf("failed to compile module: %v", err)
	}

	// Create module configuration
	config := wazero.NewModuleConfig().
		WithName("wasm").
		WithStartFunctions() // Don't automatically run start function

	// Instantiate the module with the host module
	module, err := runtime.InstantiateModule(ctx, compiled, config)
	if err != nil {
		runtime.Close(ctx)
		return nil, fmt.Errorf("failed to instantiate module: %v", err)
	}

	return &WazeroInstance{
		runtime:    runtime,
		module:     module,
		hostModule: hostModule,
		gasLimit:   gasLimit,
	}, nil
}

// Close releases all resources associated with the instance
func (i *WazeroInstance) Close() error {
	if i.module != nil {
		i.module.Close(context.Background())
	}
	if i.hostModule != nil {
		i.hostModule.Close(context.Background())
	}
	if i.runtime != nil {
		i.runtime.Close(context.Background())
	}
	return nil
}

// CallFunction calls a function in the Wasm module
func (i *WazeroInstance) CallFunction(name string, params ...uint64) ([]uint64, error) {
	fn := i.module.ExportedFunction(name)
	if fn == nil {
		return nil, fmt.Errorf("function %s not found", name)
	}

	results, err := fn.Call(context.Background(), params...)
	if err != nil {
		return nil, fmt.Errorf("failed to call function %s: %v", name, err)
	}

	return results, nil
}

// ReadMemory reads from the Wasm module's memory
func (i *WazeroInstance) ReadMemory(offset uint32, size uint32) ([]byte, error) {
	memory := i.module.Memory()
	if memory == nil {
		return nil, fmt.Errorf("no memory exported")
	}

	data, ok := memory.Read(offset, size)
	if !ok {
		return nil, fmt.Errorf("failed to read memory at offset %d with size %d", offset, size)
	}

	return data, nil
}

// WriteMemory writes to the Wasm module's memory
func (i *WazeroInstance) WriteMemory(offset uint32, data []byte) error {
	memory := i.module.Memory()
	if memory == nil {
		return fmt.Errorf("no memory exported")
	}

	ok := memory.Write(offset, data)
	if !ok {
		return fmt.Errorf("failed to write memory at offset %d with size %d", offset, len(data))
	}

	return nil
}

// ConsumeGas consumes the specified amount of gas
func (i *WazeroInstance) ConsumeGas(amount uint64) {
	// Wazero doesn't have built-in gas metering, so we just track it in the VM
}

// GetGasLimit returns the gas limit for this instance
func (i *WazeroInstance) GetGasLimit() uint64 {
	return i.gasLimit
}

// GetModule returns the underlying Wazero module
func (i *WazeroInstance) GetModule() api.Module {
	return i.module
}

// GetRuntime returns the underlying Wazero runtime
func (i *WazeroInstance) GetRuntime() wazero.Runtime {
	return i.runtime
}
