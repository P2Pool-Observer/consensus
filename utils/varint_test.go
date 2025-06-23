package utils

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func FuzzCanonicalUvarint(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var buf [binary.MaxVarintLen64]byte
		value, n := CanonicalUvarint(data)
		if n <= 0 {
			t.SkipNow()
		}
		if n != len(data) {
			t.SkipNow()
		}
		encoded := binary.AppendUvarint(buf[:0], value)
		if !bytes.Equal(encoded, data) {
			t.Fatalf("canonical encoding mismatch: have %x, want %x", encoded, data)
		}
	})
}
