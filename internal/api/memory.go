package api

import (
	"fmt"
	"unsafe"
)

// Memory represents a block of memory in the Wasm instance
type Memory struct {
	ptr unsafe.Pointer
	len int
}

// NewMemory creates a new Memory instance
func NewMemory(ptr unsafe.Pointer, len int) Memory {
	return Memory{
		ptr: ptr,
		len: len,
	}
}

// ReadByte reads a single byte from memory at the given offset
func (m Memory) ReadByte(offset int) (byte, error) {
	if offset < 0 || offset >= m.len {
		return 0, fmt.Errorf("offset out of bounds: %d", offset)
	}
	return *(*byte)(unsafe.Pointer(uintptr(m.ptr) + uintptr(offset))), nil
}

// ReadBytes reads a slice of bytes from memory at the given offset
func (m Memory) ReadBytes(offset int, length int) ([]byte, error) {
	if offset < 0 || length < 0 || offset+length > m.len {
		return nil, fmt.Errorf("read out of bounds: offset=%d length=%d", offset, length)
	}
	data := make([]byte, length)
	src := unsafe.Slice((*byte)(unsafe.Pointer(uintptr(m.ptr)+uintptr(offset))), length)
	copy(data, src)
	return data, nil
}

// Write writes a slice of bytes to memory at the given offset
func (m Memory) Write(offset int, data []byte) error {
	if offset < 0 || offset+len(data) > m.len {
		return fmt.Errorf("write out of bounds: offset=%d length=%d", offset, len(data))
	}
	dest := unsafe.Slice((*byte)(unsafe.Pointer(uintptr(m.ptr)+uintptr(offset))), len(data))
	copy(dest, data)
	return nil
}

// WriteByte writes a single byte to memory at the given offset
func (m Memory) WriteByte(offset int, b byte) error {
	if offset < 0 || offset >= m.len {
		return fmt.Errorf("offset out of bounds: %d", offset)
	}
	*(*byte)(unsafe.Pointer(uintptr(m.ptr) + uintptr(offset))) = b
	return nil
}

// Length returns the total length of the memory block
func (m Memory) Length() int {
	return m.len
}

// Pointer returns the raw pointer to the memory block
func (m Memory) Pointer() unsafe.Pointer {
	return m.ptr
}
