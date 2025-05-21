package wazeroimpl

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/tetratelabs/wazero"

	"github.com/CosmWasm/wasmvm/v3/types"
)

// Execute runs the contract's execute function.
func (c *Cache) Execute(ctx context.Context, checksum types.Checksum, env, info, msg []byte, store types.KVStore, apiImpl *types.GoAPI, q *types.Querier, gm types.GasMeter) error {
	compiled, ok := c.getModule(checksum)
	if !ok {
		return fmt.Errorf("module not found")
	}
	_, err := c.registerHost(ctx, compiled, store, apiImpl, q, gm)
	if err != nil {
		return err
	}
	mod, err := c.runtime.InstantiateModule(ctx, compiled, wazero.NewModuleConfig())
	if err != nil {
		return err
	}
	if fn := mod.ExportedFunction("execute"); fn != nil {
		paramCount := len(fn.Definition().ParamTypes())
		switch paramCount {
		case 6:
			envPtr, envLen := uint32(0), uint32(0)
			infoPtr, infoLen := uint32(0), uint32(0)
			msgPtr, msgLen := uint32(0), uint32(0)
			if len(env) > 0 {
				envPtr, envLen = locateData(ctx, mod, env)
			}
			if len(info) > 0 {
				infoPtr, infoLen = locateData(ctx, mod, info)
			}
			if len(msg) > 0 {
				msgPtr, msgLen = locateData(ctx, mod, msg)
			}
			_, err = fn.Call(ctx, uint64(envPtr), uint64(envLen), uint64(infoPtr), uint64(infoLen), uint64(msgPtr), uint64(msgLen))
		case 3:
			wrap := func(b []byte) []byte {
				buf := make([]byte, 4+len(b))
				binary.LittleEndian.PutUint32(buf, uint32(len(b)))
				copy(buf[4:], b)
				return buf
			}
			envPtr, _ := locateData(ctx, mod, wrap(env))
			infoPtr, _ := locateData(ctx, mod, wrap(info))
			msgPtr, _ := locateData(ctx, mod, wrap(msg))
			_, err = fn.Call(ctx, uint64(envPtr), uint64(infoPtr), uint64(msgPtr))
		default:
			err = fmt.Errorf("unsupported execute param count %d", paramCount)
		}
	}
	_ = mod.Close(ctx)
	return err
}
