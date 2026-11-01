package main

import (
	"fmt"
	"sort"
	"strings"
)

// memState is an in-memory State for unit tests. Keys use Fabric's composite
// key layout: 0x00 + objectType + 0x00 + attr 0x00 ...
type memState struct {
	data   map[string][]byte
	caller Caller
	txID   string
	txTime int64
	events []string
}

func newMemState() *memState {
	return &memState{
		data:   map[string][]byte{},
		caller: Caller{MSPID: "AttestaMSP", Admin: true},
		txID:   "tx-0001",
		txTime: 1_700_000_000,
	}
}

func (m *memState) Key(objectType string, attrs ...string) (string, error) {
	for _, a := range append([]string{objectType}, attrs...) {
		if strings.ContainsRune(a, 0) || strings.ContainsRune(a, 0x10FFFF) {
			return "", fmt.Errorf("invalid composite key attribute")
		}
	}
	k := "\x00" + objectType + "\x00"
	for _, a := range attrs {
		k += a + "\x00"
	}
	return k, nil
}

func (m *memState) Get(key string) ([]byte, error) { return m.data[key], nil }

func (m *memState) Put(key string, value []byte) error {
	if len(value) == 0 {
		return fmt.Errorf("empty value for %q", key)
	}
	m.data[key] = append([]byte(nil), value...)
	return nil
}

func (m *memState) Del(key string) error { delete(m.data, key); return nil }

func (m *memState) Scan(objectType string, attrs []string, pageSize int, bookmark string) ([]KV, string, error) {
	prefix, err := m.Key(objectType, attrs...)
	if err != nil {
		return nil, "", err
	}
	var keys []string
	for k := range m.data {
		if strings.HasPrefix(k, prefix) && k > bookmark {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	next := ""
	if len(keys) > pageSize {
		keys = keys[:pageSize]
		next = keys[len(keys)-1]
	}
	out := make([]KV, 0, len(keys))
	for _, k := range keys {
		parts := strings.Split(strings.TrimSuffix(strings.TrimPrefix(k, "\x00"), "\x00"), "\x00")
		out = append(out, KV{Attrs: parts[1:], Value: m.data[k]})
	}
	return out, next, nil
}

func (m *memState) TxID() string            { return m.txID }
func (m *memState) TxTime() (int64, error)  { return m.txTime, nil }
func (m *memState) Caller() (Caller, error) { return m.caller, nil }

func (m *memState) Emit(name string, payload []byte) error {
	m.events = append(m.events, name)
	return nil
}
