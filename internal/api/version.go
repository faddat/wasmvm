package api

// Version represents the version of the Wazero runtime
const Version = "v2.0.0"

// GetVersion returns the version of the Wazero runtime
func GetVersion() string {
	return Version
}
