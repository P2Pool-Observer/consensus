package block

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func FuzzMainBlockRoundTrip(f *testing.F) {
	f.Fuzz(func(t *testing.T, buf []byte) {
		b := &Block{}
		if err := b.UnmarshalBinary(buf, false, nil); err != nil {
			t.Skipf("leftover error: %s", err)
			return
		}
		data, err := b.MarshalBinary()
		if err != nil {
			t.Fatalf("failed to marshal decoded block: %s", err)
			return
		}
		if !bytes.Equal(data, buf) {
			t.Logf("EXPECTED (len %d):\n%s", len(buf), hex.Dump(buf))
			t.Logf("ACTUAL (len %d):\n%s", len(data), hex.Dump(data))
			t.Fatalf("mismatched roundtrip")
		}
	})
}
