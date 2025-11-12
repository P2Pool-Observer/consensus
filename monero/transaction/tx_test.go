package transaction

import (
	"bytes"
	"fmt"
	"os"
	"testing"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/client"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	"git.gammaspectra.live/P2Pool/consensus/v5/utils"
)

func init() {
	client.SetDefaultClientSettings(os.Getenv("MONEROD_RPC_URL"))
}

var testTransactions = []types.Hash{
	// cuprate v1 transactions
	types.MustHashFromString("2180a87f724702d37af087e22476297e818a73579ef7b7da947da963245202a3"),
	types.MustHashFromString("d7febd16293799d9c6a8e0fe9199b8a0a3e0da5a8a165098937b60f0bbd582df"),
	types.MustHashFromString("9e3f73e66d7c7293af59c59c1ff5d6aae047289f49e5884c66caaf4aea49fb34"),

	// some v2 txs
	// mlsag aggregate borromean
	types.MustHashFromString("618ae0d58ab6432e7438bf2dce33784bb540a0f3d9ebddf1f3ad7fb303380ca3"),
	// mlsag borromean (with clear inputs)
	types.MustHashFromString("3fbb553cf23e9c2d706507dff7f3177c92ff39d03a951787cab9973726fc6970"),
	// mlsag borromean (with hidden inputs)
	types.MustHashFromString("cbddbd1eadc3fc2c3094627788c57a99a187f9e91e2409f66f82500ba757197b"),

	// cuprate v2 transactions
	// mlsag bulletproofs
	types.MustHashFromString("e2d39395dd1625b2d707b98af789e7eab9d24c2bd2978ec38ef910961a8cdcee"),
	types.MustHashFromString("e57440ec66d2f3b2a5fa2081af40128868973e7c021bb3877290db3066317474"),
	types.MustHashFromString("b6b4394d4ec5f08ad63267c07962550064caa8d225dd9ad6d739ebf60291c169"),
	types.MustHashFromString("84d48dc11ec91950f8b70a85af9db91fe0c8abef71ef5db08304f7344b99ea66"),

	// mlsag bulletproofs compact amount
	types.MustHashFromString("a8fcc15255f278748d08ade8618688b1634fa800752c958b0c3f57168816372a"),
	// clsag bulletproofs
	types.MustHashFromString("951222d863d97bd21296cfd7a8631cf1c1018bf609edbb957f2671bf7e842329"),

	// clsag bulletproofs+
	types.MustHashFromString("81e80ad39374105ab94363bc1315a96fd52cc3f8f81e0425c718df164a72975c"),
}

func TestTransactions(t *testing.T) {
	rpc := client.GetDefaultClient()

	for _, txId := range testTransactions {
		t.Run(fmt.Sprintf("%s...", txId.String()[:8]), func(t *testing.T) {

			data, _, err := rpc.GetTransactions(txId)
			if err != nil {
				t.Fatal(err)
			}

			r := bytes.NewReader(data[0])

			tx, err := NewTransactionFromReader(r)
			if err != nil {
				t.Fatal(err)
			}

			if r.Len() > 0 {
				t.Fatal("leftover bytes")
			}

			prefixHash := tx.PrefixHash()
			calculatedId := tx.Hash()

			bufLength := tx.BufferLength()

			buf, err := tx.AppendBinary(make([]byte, 0, bufLength))
			if err != nil {
				t.Fatal(err)
			}
			if bufLength != len(buf) {
				t.Fatalf("expected %d, got %d", bufLength, len(buf))
			}
			if bytes.Compare(data[0], buf) != 0 {
				t.Fatal("tx buffer data mismatch")
			}

			t.Logf("version = %d", tx.Version())
			t.Logf("ringct  = %d", tx.Proofs().ProofType())
			t.Logf("id      = %s", calculatedId)
			t.Logf("prefix  = %s", prefixHash)
			t.Logf("fee     = %s XMR", utils.XMRUnits(tx.Fee()))

			if calculatedId != txId {
				t.Fatalf("expected %s, got %s", txId, calculatedId)
			}

			rings, images, err := GetTransactionInputsData(tx, rpc.GetOuts)
			if err != nil {
				t.Fatal(err)
			}

			for i, ring := range rings {
				t.Logf("ring[%d] ki=%s  amount=%s\n", i, images[i].String(), utils.XMRUnits(tx.Inputs()[i].Amount))
				for j, e := range ring {
					t.Logf("    [%d] key=%s mask=%s\n", j, e[0].String(), e[1].String())
				}
			}

			if err = tx.Proofs().Verify(tx.SignatureHash(), rings, images); err != nil {
				t.Fatalf("tx proof failed: %v", err)
			}

			jsonBuf, err := utils.MarshalJSONIndent(tx, " ")
			if err != nil {
				t.Fatal(err)
			}

			t.Logf("JSON: %s", string(jsonBuf))
		})
	}
}

func BenchmarkTransactionsVerify(b *testing.B) {

	rpc := client.GetDefaultClient()

	for _, txId := range testTransactions {
		b.Run(fmt.Sprintf("%s...", txId.String()[:8]), func(b *testing.B) {
			data, _, err := rpc.GetTransactions(txId)
			if err != nil {
				b.Fatal(err)
			}

			tx, err := NewTransactionFromReader(bytes.NewReader(data[0]))
			if err != nil {
				b.Fatal(err)
			}

			rings, images, err := GetTransactionInputsData(tx, rpc.GetOuts)
			if err != nil {
				b.Fatal(err)
			}

			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if err = tx.Proofs().Verify(tx.SignatureHash(), rings, images); err != nil {
					b.Fatalf("tx proof failed: %v", err)
				}
			}
		})
	}
}
