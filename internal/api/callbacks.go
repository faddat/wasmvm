package api

// DBState contains the state for database operations
type DBState struct {
	Get    func(key []byte) ([]byte, error)
	Set    func(key []byte, value []byte) error
	Delete func(key []byte) error
	Scan   func(start []byte, end []byte, order int32) (Iterator, error)
}

// APIState contains the state for API operations
type APIState struct {
	HumanAddress     func(canonicalAddress []byte) (string, error)
	CanonicalAddress func(humanAddress string) ([]byte, error)
	ValidateAddress  func(address string) error
}

// QuerierState contains the state for querier operations
type QuerierState struct {
	Query func(request []byte) ([]byte, error)
}

// GoIter is a Go implementation of the iterator interface
type GoIter struct {
	state Iterator
}

// Iterator defines an interface for iterating over key-value pairs
type Iterator interface {
	Next() bool
	Key() []byte
	Value() []byte
	Error() error
	Close()
}

// DBError represents a database error
type DBError struct {
	Msg string
}

func (e DBError) Error() string {
	return e.Msg
}

// APIError represents an API error
type APIError struct {
	Msg string
}

func (e APIError) Error() string {
	return e.Msg
}

// QuerierError represents a querier error
type QuerierError struct {
	Msg string
}

func (e QuerierError) Error() string {
	return e.Msg
}

// GasError represents a gas error
type GasError struct {
	Msg string
}

func (e GasError) Error() string {
	return e.Msg
}

// GetDBState returns a new DBState with the given functions
func GetDBState(get func([]byte) ([]byte, error), set func([]byte, []byte) error, delete func([]byte) error, scan func([]byte, []byte, int32) (Iterator, error)) DBState {
	return DBState{
		Get:    get,
		Set:    set,
		Delete: delete,
		Scan:   scan,
	}
}

// GetAPIState returns a new APIState with the given functions
func GetAPIState(humanAddress func([]byte) (string, error), canonicalAddress func(string) ([]byte, error), validateAddress func(string) error) APIState {
	return APIState{
		HumanAddress:     humanAddress,
		CanonicalAddress: canonicalAddress,
		ValidateAddress:  validateAddress,
	}
}

// GetQuerierState returns a new QuerierState with the given function
func GetQuerierState(query func([]byte) ([]byte, error)) QuerierState {
	return QuerierState{
		Query: query,
	}
}
