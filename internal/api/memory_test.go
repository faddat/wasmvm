package api

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
)

func TestMemory(t *testing.T) {
	// Create a test buffer
	data := []byte{0xaa, 0xbb, 0x64}
	mem := NewMemory(unsafe.Pointer(&data[0]), len(data))

	// Test ReadByte
	b, err := mem.ReadByte(0)
	require.NoError(t, err)
	require.Equal(t, byte(0xaa), b)

	b, err = mem.ReadByte(1)
	require.NoError(t, err)
	require.Equal(t, byte(0xbb), b)

	// Test out of bounds
	_, err = mem.ReadByte(-1)
	require.Error(t, err)
	_, err = mem.ReadByte(3)
	require.Error(t, err)

	// Test ReadBytes
	bytes, err := mem.ReadBytes(0, 3)
	require.NoError(t, err)
	require.Equal(t, data, bytes)

	// Test out of bounds
	_, err = mem.ReadBytes(-1, 1)
	require.Error(t, err)
	_, err = mem.ReadBytes(0, 4)
	require.Error(t, err)

	// Test Write
	newData := []byte{0x11, 0x22, 0x33}
	err = mem.Write(0, newData)
	require.NoError(t, err)
	bytes, err = mem.ReadBytes(0, 3)
	require.NoError(t, err)
	require.Equal(t, newData, bytes)

	// Test out of bounds
	err = mem.Write(-1, newData)
	require.Error(t, err)
	err = mem.Write(1, newData)
	require.Error(t, err)

	// Test WriteByte
	err = mem.WriteByte(0, 0xff)
	require.NoError(t, err)
	b, err = mem.ReadByte(0)
	require.NoError(t, err)
	require.Equal(t, byte(0xff), b)

	// Test out of bounds
	err = mem.WriteByte(-1, 0xff)
	require.Error(t, err)
	err = mem.WriteByte(3, 0xff)
	require.Error(t, err)

	// Test Length
	require.Equal(t, 3, mem.Length())

	// Test Pointer
	require.NotNil(t, mem.Pointer())
}
