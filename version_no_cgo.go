//go:build (!cgo && !wazero) || nolink_libwasmvm

package cosmwasm

import (
	"fmt"
)

func libwasmvmVersionImpl() (string, error) {
	return "", fmt.Errorf("libwasmvm unavailable since cgo is disabled")
}
