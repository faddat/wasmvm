package wazeroimpl

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"
	"unsafe"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"

	"github.com/CosmWasm/wasmvm/v3/types"
)

// Cache manages a wazero runtime and compiled modules.
type Cache struct {
	runtime wazero.Runtime
	modules map[string]wazero.CompiledModule
}

// InitCache creates a new wazero Runtime with memory limits similar to api.InitCache.
func InitCache(config types.VMConfig) (*Cache, error) {
	if base := config.Cache.BaseDir; base != "" {
		if strings.Contains(base, ":") && runtime.GOOS != "windows" {
			return nil, fmt.Errorf("could not create base directory")
		}
		if err := os.MkdirAll(base, 0o700); err != nil {
			return nil, fmt.Errorf("could not create base directory: %w", err)
		}
	}

	ctx := context.Background()
	limitBytes := *(*uint32)(unsafe.Pointer(&config.Cache.InstanceMemoryLimitBytes))
	r := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().WithMemoryLimitPages(limitBytes/65536))
	return &Cache{
		runtime: r,
		modules: make(map[string]wazero.CompiledModule),
	}, nil
}

// Close releases all resources of the runtime.
func (c *Cache) Close(ctx context.Context) error {
	if c.runtime != nil {
		return c.runtime.Close(ctx)
	}
	return nil
}

// Compile stores a compiled module under the given checksum.
func (c *Cache) Compile(ctx context.Context, checksum types.Checksum, wasm []byte) error {
	mod, err := c.runtime.CompileModule(ctx, wasm)
	if err != nil {
		return err
	}
	c.modules[hex.EncodeToString(checksum)] = mod
	return nil
}

// getModule returns the compiled module for the checksum.
func (c *Cache) getModule(checksum types.Checksum) (wazero.CompiledModule, bool) {
	mod, ok := c.modules[hex.EncodeToString(checksum)]
	return mod, ok
}

// registerHost builds an env module with callbacks for the given state.
func (c *Cache) registerHost(ctx context.Context, store types.KVStore, apiImpl *types.GoAPI, q *types.Querier, gm types.GasMeter) (api.Module, error) {
	builder := c.runtime.NewHostModuleBuilder("env")

	// db_read
	builder.NewFunctionBuilder().WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, m api.Module, stack []uint64) {
		keyPtr := uint32(stack[0])
		keyLen := uint32(stack[1])
		outPtr := uint32(stack[2])
		mem := m.Memory()
		key, _ := mem.Read(keyPtr, keyLen)
		value := store.Get(key)
		if value == nil {
			_ = mem.WriteUint32Le(outPtr, 0)
			return
		}
		_ = mem.WriteUint32Le(outPtr, uint32(len(value)))
		mem.Write(outPtr+4, value)
	}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{}).Export("db_read")

	// db_write
	builder.NewFunctionBuilder().WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, m api.Module, stack []uint64) {
		keyPtr := uint32(stack[0])
		keyLen := uint32(stack[1])
		valPtr := uint32(stack[2])
		valLen := uint32(stack[3])
		mem := m.Memory()
		key, _ := mem.Read(keyPtr, keyLen)
		val, _ := mem.Read(valPtr, valLen)
		store.Set(key, val)
	}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{}).Export("db_write")

	// db_remove
	builder.NewFunctionBuilder().WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, m api.Module, stack []uint64) {
		keyPtr := uint32(stack[0])
		keyLen := uint32(stack[1])
		mem := m.Memory()
		key, _ := mem.Read(keyPtr, keyLen)
		store.Delete(key)
	}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{}).Export("db_remove")

	// query_external - calls into the Go querier
	builder.NewFunctionBuilder().WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, m api.Module, stack []uint64) {
		gasLimit := uint64(stack[0])
		reqPtr := uint32(stack[1])
		reqLen := uint32(stack[2])
		outPtr := uint32(stack[3])
		mem := m.Memory()
		req, _ := mem.Read(reqPtr, reqLen)
		if q != nil {
			res := types.RustQuery(*q, req, gasLimit)
			bz, _ := json.Marshal(res)
			_ = mem.WriteUint32Le(outPtr, uint32(len(bz)))
			mem.Write(outPtr+4, bz)
		} else {
			_ = mem.WriteUint32Le(outPtr, 0)
		}
	}), []api.ValueType{api.ValueTypeI64, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{}).Export("query_external")

	// humanize_address
	builder.NewFunctionBuilder().WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, m api.Module, stack []uint64) {
		srcPtr := uint32(stack[0])
		srcLen := uint32(stack[1])
		outPtr := uint32(stack[2])
		mem := m.Memory()
		addr, _ := mem.Read(srcPtr, srcLen)
		if apiImpl != nil {
			res, _, err := apiImpl.HumanizeAddress(addr)
			if err == nil {
				_ = mem.WriteUint32Le(outPtr, uint32(len(res)))
				mem.Write(outPtr+4, []byte(res))
				return
			}
		}
		_ = mem.WriteUint32Le(outPtr, 0)
	}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{}).Export("humanize_address")

	// canonicalize_address
	builder.NewFunctionBuilder().WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, m api.Module, stack []uint64) {
		srcPtr := uint32(stack[0])
		srcLen := uint32(stack[1])
		outPtr := uint32(stack[2])
		mem := m.Memory()
		addrBytes, _ := mem.Read(srcPtr, srcLen)
		if apiImpl != nil {
			res, _, err := apiImpl.CanonicalizeAddress(string(addrBytes))
			if err == nil {
				_ = mem.WriteUint32Le(outPtr, uint32(len(res)))
				mem.Write(outPtr+4, res)
				return
			}
		}
		_ = mem.WriteUint32Le(outPtr, 0)
	}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{}).Export("canonicalize_address")

	// validate_address
	builder.NewFunctionBuilder().WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, m api.Module, stack []uint64) {
		srcPtr := uint32(stack[0])
		srcLen := uint32(stack[1])
		mem := m.Memory()
		addrBytes, _ := mem.Read(srcPtr, srcLen)
		if apiImpl != nil {
			_, _ = apiImpl.ValidateAddress(string(addrBytes))
		}
	}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{}).Export("validate_address")

	return builder.Instantiate(ctx)
}

// Instantiate loads and runs the contract's instantiate function.
func (c *Cache) Instantiate(ctx context.Context, checksum types.Checksum, env, info, msg []byte, store types.KVStore, apiImpl *types.GoAPI, q *types.Querier, gm types.GasMeter) error {
	compiled, ok := c.getModule(checksum)
	if !ok {
		return fmt.Errorf("module not found")
	}
	_, err := c.registerHost(ctx, store, apiImpl, q, gm)
	if err != nil {
		return err
	}
	mod, err := c.runtime.InstantiateModule(ctx, compiled, wazero.NewModuleConfig())
	if err != nil {
		return err
	}
	if fn := mod.ExportedFunction("instantiate"); fn != nil {
		_, err = fn.Call(ctx)
	}
	return err
}

// Execute runs the contract's execute function.
func (c *Cache) Execute(ctx context.Context, checksum types.Checksum, env, info, msg []byte, store types.KVStore, apiImpl *types.GoAPI, q *types.Querier, gm types.GasMeter) error {
	compiled, ok := c.getModule(checksum)
	if !ok {
		return fmt.Errorf("module not found")
	}
	_, err := c.registerHost(ctx, store, apiImpl, q, gm)
	if err != nil {
		return err
	}
	mod, err := c.runtime.InstantiateModule(ctx, compiled, wazero.NewModuleConfig())
	if err != nil {
		return err
	}
	if fn := mod.ExportedFunction("execute"); fn != nil {
		_, err = fn.Call(ctx)
	}
	return err
}

// callFunc instantiates the module and executes the given exported function name.
func (c *Cache) callFunc(ctx context.Context, checksum types.Checksum, funcName string, store types.KVStore, apiImpl *types.GoAPI, q *types.Querier, gm types.GasMeter) error {
	compiled, ok := c.getModule(checksum)
	if !ok {
		return fmt.Errorf("module not found")
	}
	_, err := c.registerHost(ctx, store, apiImpl, q, gm)
	if err != nil {
		return err
	}
	mod, err := c.runtime.InstantiateModule(ctx, compiled, wazero.NewModuleConfig())
	if err != nil {
		return err
	}
	if fn := mod.ExportedFunction(funcName); fn != nil {
		_, err = fn.Call(ctx)
	}
	return err
}

func (c *Cache) Query(ctx context.Context, checksum types.Checksum, store types.KVStore, apiImpl *types.GoAPI, q *types.Querier, gm types.GasMeter) error {
	return c.callFunc(ctx, checksum, "query", store, apiImpl, q, gm)
}

func (c *Cache) Migrate(ctx context.Context, checksum types.Checksum, store types.KVStore, apiImpl *types.GoAPI, q *types.Querier, gm types.GasMeter) error {
	return c.callFunc(ctx, checksum, "migrate", store, apiImpl, q, gm)
}

func (c *Cache) Sudo(ctx context.Context, checksum types.Checksum, store types.KVStore, apiImpl *types.GoAPI, q *types.Querier, gm types.GasMeter) error {
	return c.callFunc(ctx, checksum, "sudo", store, apiImpl, q, gm)
}

func (c *Cache) Reply(ctx context.Context, checksum types.Checksum, store types.KVStore, apiImpl *types.GoAPI, q *types.Querier, gm types.GasMeter) error {
	return c.callFunc(ctx, checksum, "reply", store, apiImpl, q, gm)
}

func (c *Cache) IBCChannelOpen(ctx context.Context, checksum types.Checksum, store types.KVStore, apiImpl *types.GoAPI, q *types.Querier, gm types.GasMeter) error {
	return c.callFunc(ctx, checksum, "ibc_channel_open", store, apiImpl, q, gm)
}

func (c *Cache) IBCChannelConnect(ctx context.Context, checksum types.Checksum, store types.KVStore, apiImpl *types.GoAPI, q *types.Querier, gm types.GasMeter) error {
	return c.callFunc(ctx, checksum, "ibc_channel_connect", store, apiImpl, q, gm)
}

func (c *Cache) IBCChannelClose(ctx context.Context, checksum types.Checksum, store types.KVStore, apiImpl *types.GoAPI, q *types.Querier, gm types.GasMeter) error {
	return c.callFunc(ctx, checksum, "ibc_channel_close", store, apiImpl, q, gm)
}

func (c *Cache) IBCPacketReceive(ctx context.Context, checksum types.Checksum, store types.KVStore, apiImpl *types.GoAPI, q *types.Querier, gm types.GasMeter) error {
	return c.callFunc(ctx, checksum, "ibc_packet_receive", store, apiImpl, q, gm)
}

func (c *Cache) IBCPacketAck(ctx context.Context, checksum types.Checksum, store types.KVStore, apiImpl *types.GoAPI, q *types.Querier, gm types.GasMeter) error {
	return c.callFunc(ctx, checksum, "ibc_packet_ack", store, apiImpl, q, gm)
}

func (c *Cache) IBCPacketTimeout(ctx context.Context, checksum types.Checksum, store types.KVStore, apiImpl *types.GoAPI, q *types.Querier, gm types.GasMeter) error {
	return c.callFunc(ctx, checksum, "ibc_packet_timeout", store, apiImpl, q, gm)
}

func (c *Cache) IBCSourceCallback(ctx context.Context, checksum types.Checksum, store types.KVStore, apiImpl *types.GoAPI, q *types.Querier, gm types.GasMeter) error {
	return c.callFunc(ctx, checksum, "ibc_source_callback", store, apiImpl, q, gm)
}

func (c *Cache) IBCDestinationCallback(ctx context.Context, checksum types.Checksum, store types.KVStore, apiImpl *types.GoAPI, q *types.Querier, gm types.GasMeter) error {
	return c.callFunc(ctx, checksum, "ibc_destination_callback", store, apiImpl, q, gm)
}

func (c *Cache) IBC2PacketReceive(ctx context.Context, checksum types.Checksum, store types.KVStore, apiImpl *types.GoAPI, q *types.Querier, gm types.GasMeter) error {
	return c.callFunc(ctx, checksum, "ibc2_packet_receive", store, apiImpl, q, gm)
}

func (c *Cache) IBC2PacketAck(ctx context.Context, checksum types.Checksum, store types.KVStore, apiImpl *types.GoAPI, q *types.Querier, gm types.GasMeter) error {
	return c.callFunc(ctx, checksum, "ibc2_packet_ack", store, apiImpl, q, gm)
}

func (c *Cache) IBC2PacketTimeout(ctx context.Context, checksum types.Checksum, store types.KVStore, apiImpl *types.GoAPI, q *types.Querier, gm types.GasMeter) error {
	return c.callFunc(ctx, checksum, "ibc2_packet_timeout", store, apiImpl, q, gm)
}

func (c *Cache) IBC2PacketSend(ctx context.Context, checksum types.Checksum, store types.KVStore, apiImpl *types.GoAPI, q *types.Querier, gm types.GasMeter) error {
	return c.callFunc(ctx, checksum, "ibc2_packet_send", store, apiImpl, q, gm)
}
