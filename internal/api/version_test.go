package api

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetVersion(t *testing.T) {
	version := GetVersion()
	require.Regexp(t, regexp.MustCompile(`^v([0-9]+)\.([0-9]+)\.([0-9]+)(-[a-z0-9.]+)?$`), version)
}
