package transaction

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func FuzzCoinbaseTransactionExtraTagRoundTrip(f *testing.F) {
	f.Fuzz(func(t *testing.T, buf []byte) {
		tag := &ExtraTag{}
		if err := tag.UnmarshalBinary(buf); err != nil {
			t.Skipf("leftover error: %s", err)
			return
		}
		data, err := tag.MarshalBinary()
		if err != nil {
			t.Fatalf("failed to marshal decoded tag: %s", err)
			return
		}
		if !bytes.Equal(data, buf) {
			t.Logf("EXPECTED (len %d):\n%s", len(buf), hex.Dump(buf))
			t.Logf("ACTUAL (len %d):\n%s", len(data), hex.Dump(data))
			t.Fatalf("mismatched roundtrip")
		}
	})
}
