package main

// State is the narrow ledger surface the business logic needs. Production
// uses stubState (Fabric); tests use an in-memory implementation.

// KV is one scan result: the composite-key attributes and the stored value.
type KV struct {
	Attrs []string
	Value []byte
}

// Caller is the transaction submitter's identity.
type Caller struct {
	MSPID string
	Admin bool // client certificate carries OU "admin"
}

type State interface {
	Key(objectType string, attrs ...string) (string, error)
	Get(key string) ([]byte, error)
	Put(key string, value []byte) error
	Del(key string) error
	// Scan lists entries whose composite key starts with (objectType, attrs...).
	// It returns the next bookmark, or "" when there are no more pages.
	Scan(objectType string, attrs []string, pageSize int, bookmark string) ([]KV, string, error)
	TxID() string
	TxTime() (int64, error) // Fabric transaction timestamp, unix seconds
	Emit(name string, payload []byte) error
	Caller() (Caller, error)
}

// keyer builds composite keys and remembers the first error.
type keyer struct {
	st  State
	err error
}

func (k *keyer) key(objectType string, attrs ...string) string {
	if k.err != nil {
		return ""
	}
	s, err := k.st.Key(objectType, attrs...)
	if err != nil {
		k.err = err
	}
	return s
}
