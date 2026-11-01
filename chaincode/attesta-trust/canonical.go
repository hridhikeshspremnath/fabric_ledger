package main

// Canonical JSON identical to the Python side (attesta.records.canonical):
// sorted keys, no whitespace, ASCII-only output (\uXXXX, surrogate pairs for
// astral runes), integers only. Floats are rejected.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sort"
	"strconv"
	"strings"
)

// ParseJSON decodes JSON keeping numbers as json.Number and rejects trailing data.
func ParseJSON(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("invalid JSON: trailing data")
	}
	return v, nil
}

// Canonicalize parses raw JSON and returns its canonical encoding.
func Canonicalize(raw []byte) ([]byte, error) {
	v, err := ParseJSON(raw)
	if err != nil {
		return nil, err
	}
	return EncodeCanonical(v)
}

// EncodeCanonical encodes a value produced by ParseJSON (or built by hand).
func EncodeCanonical(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := encodeValue(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func encodeValue(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		buf.WriteString(strconv.FormatBool(t))
	case string:
		encodeString(buf, t)
	case json.Number:
		return encodeNumber(buf, t.String())
	case int:
		buf.WriteString(strconv.Itoa(t))
	case int64:
		buf.WriteString(strconv.FormatInt(t, 10))
	case float32, float64:
		return errors.New("floats are not allowed in canonical JSON")
	case []any:
		buf.WriteByte('[')
		for i, item := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := encodeValue(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			encodeString(buf, k)
			buf.WriteByte(':')
			if err := encodeValue(buf, t[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("unsupported type %T in canonical JSON", v)
	}
	return nil
}

func encodeNumber(buf *bytes.Buffer, lit string) error {
	if strings.ContainsAny(lit, ".eE") {
		return fmt.Errorf("floats are not allowed in canonical JSON: %s", lit)
	}
	n, ok := new(big.Int).SetString(lit, 10)
	if !ok {
		return fmt.Errorf("invalid integer literal: %s", lit)
	}
	buf.WriteString(n.String()) // normalises "-0" to "0", like Python ints
	return nil
}

func encodeString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			buf.WriteString(`\"`)
		case r == '\\':
			buf.WriteString(`\\`)
		case r == '\n':
			buf.WriteString(`\n`)
		case r == '\r':
			buf.WriteString(`\r`)
		case r == '\t':
			buf.WriteString(`\t`)
		case r == '\b':
			buf.WriteString(`\b`)
		case r == '\f':
			buf.WriteString(`\f`)
		case r < 0x20 || r > 0x7e: // Python ensure_ascii escapes everything outside ' '..'~'
			if r > 0xffff {
				r -= 0x10000
				fmt.Fprintf(buf, `\u%04x\u%04x`, 0xd800+(r>>10), 0xdc00+(r&0x3ff))
			} else {
				fmt.Fprintf(buf, `\u%04x`, r)
			}
		default:
			buf.WriteRune(r)
		}
	}
	buf.WriteByte('"')
}
