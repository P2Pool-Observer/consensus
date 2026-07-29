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

	// mlsag borromean (with unreduced scalars)
	// see https://github.com/monero-project/monero/issues/8438 or https://www.moneroinflation.com/static/data_py/report_scalars_df.pdf
	types.MustHashFromString("0647d386365f6bfd312b0fbe966f5c85f19159ccf9003af8387f332451e6c94c"),
	types.MustHashFromString("d5d725e7a76dab7e2ca97d941403936a0fbf5e8874e9ef3becd973e4598a8cb1"),
	types.MustHashFromString("991712d33cdff510254ffacfb9e04f9cd54a4f08bf53388c107f72383f03c462"),
	types.MustHashFromString("475c008c48520949843a00701fdd15b6db76bdf24b3f635bdaeb9f4a684700f8"),
	types.MustHashFromString("2fecc6f9269264fb0f036de586451f4ae0d0c7cec8ace89d93135b90bbdc6263"),
	types.MustHashFromString("0aba657035c498037e00d8597eee74b06f6d89c900a74af21fc717bb86002c8d"),
	types.MustHashFromString("a6dc6d18d493e9f2749e5d0991b7703b26779d25b286de55b99a72d927d102bb"),
	types.MustHashFromString("93c42d7938a6534816e8583e6d4accac1cff200fa4d2b51daddab91456e7f9eb"),
	types.MustHashFromString("8171e8ac8154a20d1d345ef5b872ab2b019096efde220c67cce893b1ea25cc76"),
	types.MustHashFromString("3f7beae73b73e3b0864a16f9950f5bb80ab7cc74498fc50e747b301b2ecb77a7"),
	types.MustHashFromString("d21685edb1b6911b0bbe995749608b84aebb42cd99cb1487dfef4f9a8253eebb"),
	types.MustHashFromString("37ef3484d72ac43e14d49cf5d8058607553c2018fc795c1e8dcb39b9d033a1e6"),
	types.MustHashFromString("d1ea609d17125f407fa8b80d5fc74add85f12efa242d16509bc9d18a292f641f"),
	types.MustHashFromString("3d407ce4a7b7f22f923987f501a7d07dc9fa9bb9568c3c8e1a2c891501597b60"),
	types.MustHashFromString("195a9d291477b6d0c95a9c006c42a324a89dc4ffae529bc894b94284ab248359"),
	types.MustHashFromString("e9f0234705be100032dcd1e9c631822f00b0a3d7e5748b6e6533e8eec47f2644"),
	types.MustHashFromString("cc3ebd46fa3f85d6a2aa444d82afb5331d9bd8d6d53fcea5e6920c448c57d72a"),
	types.MustHashFromString("d6187b450e32eb1392b0b5b211cbcb8d66aecaf90705bd1235f1a99de82577dc"),
	types.MustHashFromString("7a47b4e8261679fc74a419bf23823b8f25cc74a67509836760e8cb0bc463438b"),
	types.MustHashFromString("3037b7c0bdb7019ab45d726c4f0354bdd0b1a025ac88b08752af1fd9b4ca7f81"),
	types.MustHashFromString("f5b60a9e22177f6ca68d413ceb39db40d4d43aacddf70191c0dbc3c36be7c588"),
	types.MustHashFromString("e4b7982b081a17892525f1b1d3011ec06a0820cbf451d3a64f8ea998104a753c"),

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
	types.MustHashFromString("32e66dcf37b87703ebff69a0bd93a3cdc8fb919463085778d046bdda900efe52"),

	// custom tool outputs

	// mysterious minergate tag
	types.MustHashFromString("c67bff93bfb1ddad87994b44461be681b4ffb3c9b2c75ef7bffc2c52b880e4a3"),

	// first p2pool coinbase
	types.MustHashFromString("55f934195bd4450fa210304f51fd6687a4cb9eda58fe593a9cf704116daac48b"),
	// recent p2pool coinbase
	types.MustHashFromString("8a72317bee39b1b6d8bd941607485986c7e4a50ebc440b9c144334feffd6fbfd"),

	// mordinals
	types.MustHashFromString("baa3f1fa73942366c19471aac73b78dd2664eefe634bdbd260d58d09d2a0e259"),
	types.MustHashFromString("04a69ae5e9fb51327997f1a809604b4992ab9561680bab47e2f967f5c6129d72"),

	// xns
	types.MustHashFromString("39d4fa93dc0b646dbef792d0c6ec0321ff057e3e4fb3d856464385144c48a159"),

	// fcmp++ beta stressnet tx
	// this transaction is stored in this test file.
	// TODO: get a new TX after changes are merged
	// types.MustHashFromString("332691761f1ded0d74c80b223a7266f3568f472fe67f33f97d8390a48d9caa29"),
}

func TestTransactions(t *testing.T) {
	rpc := client.GetDefaultClient()

	for _, txId := range testTransactions {
		t.Run(fmt.Sprintf("%s...", txId.String()[:8]), func(t *testing.T) {

			var data []byte
			if buf, ok := testTransactionsData[txId]; ok {
				data = buf
			} else {
				result, _, err := rpc.GetTransactions(txId)
				if err != nil {
					t.Fatal(err)
				}
				data = result[0]
			}

			tx, err := NewTransactionFromBytes(data)
			if err != nil {
				t.Fatal(err)
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
			if bytes.Compare(data, buf) != 0 {
				t.Fatal("tx buffer data mismatch")
			}

			t.Logf("version = %d", tx.Version())
			if tx.Proofs() != nil {
				t.Logf("ringct  = %d", tx.Proofs().ProofType())
			} else {
				t.Logf("ringct  = <nil>")
			}
			t.Logf("id      = %s", calculatedId)
			t.Logf("prefix  = %s", prefixHash)
			t.Logf("size    = %d", tx.BufferLength())
			t.Logf("weight  = %d", tx.Weight())
			t.Logf("fee     = %s XMR", utils.XMRUnits(tx.Fee()))
			t.Logf("unlock  = %d", tx.UnlockTime())
			t.Logf("inputs  = %d", len(tx.Inputs()))
			t.Logf("outputs = %d", len(tx.Outputs()))

			if calculatedId != txId {
				t.Fatalf("expected %s, got %s", txId, calculatedId)
			}

			extra := tx.ExtraTags()
			if extra == nil {
				t.Error("missing extra tags")
			} else {
				for _, tag := range extra {
					t.Logf("tag[0x%02x] vi=%d data=%s", tag.Tag, tag.VarInt, tag.Data.String())
				}
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

			if tx.Proofs() != nil {
				if err = tx.Proofs().Verify(tx.SignatureHash(), rings, images); err != nil {
					t.Fatalf("tx proof failed: %v", err)
				}
			}
		})
	}
}

func FuzzTransactionRoundTrip(f *testing.F) {
	rpc := client.GetDefaultClient()

	for _, txId := range testTransactions {
		var data []byte
		if buf, ok := testTransactionsData[txId]; ok {
			data = buf
		} else {
			result, _, err := rpc.GetTransactions(txId)
			if err != nil {
				f.Fatal(err)
			}
			data = result[0]
		}
		f.Add(data)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		tx, err := NewTransactionFromBytes(data)
		if err != nil {
			t.Skipf("leftover error: %s", err)
		}

		if tags := tx.ExtraTags(); tags == nil {
			t.Skipf("missing extra tags")
		}

		_ = tx.PrefixHash()
		_ = tx.Hash()

		bufLength := tx.BufferLength()

		buf, err := tx.AppendBinary(make([]byte, 0, bufLength))
		if err != nil {
			t.Fatal(err)
		}
		if bufLength != len(buf) {
			t.Fatalf("expected %d, got %d", bufLength, len(buf))
		}
		if bytes.Compare(data[:len(buf)], buf) != 0 {
			t.Fatal("tx buffer data mismatch")
		}
	})
}

func TestPrunedTransactions(t *testing.T) {
	rpc := client.GetDefaultClient()

	for _, txId := range testTransactions {
		t.Run(fmt.Sprintf("%s...", txId.String()[:8]), func(t *testing.T) {

			var data []byte
			if buf, ok := testPrunedTransactionsData[txId]; ok {
				data = buf
			} else {
				result, _, err := rpc.GetPrunedTransactions(txId)
				if err != nil {
					t.Fatal(err)
				}
				data = result[0]
			}

			tx, err := NewPrunedTransactionFromBytes(data)
			if err != nil {
				t.Fatal(err)
			}

			prefixHash := tx.PrefixHash()

			bufLength := tx.PrunedBufferLength()

			buf, err := tx.AppendPrunedBinary(make([]byte, 0, bufLength))
			if err != nil {
				t.Fatal(err)
			}
			if bufLength != len(buf) {
				t.Fatalf("expected %d, got %d", bufLength, len(buf))
			}
			if bytes.Compare(data, buf) != 0 {
				t.Fatal("tx buffer data mismatch")
			}

			t.Logf("version = %d", tx.Version())
			if tx.Proofs() != nil {
				t.Logf("ringct  = %d", tx.Proofs().ProofType())
			} else {
				t.Logf("ringct  = <nil>")
			}
			t.Logf("id      = %s (not verified)", txId)
			t.Logf("prefix  = %s", prefixHash)
			t.Logf("size    = %d", tx.PrunedBufferLength())
			t.Logf("fee     = %s XMR", utils.XMRUnits(tx.Fee()))
			t.Logf("unlock  = %d", tx.UnlockTime())
			t.Logf("inputs  = %d", len(tx.Inputs()))
			t.Logf("outputs = %d", len(tx.Outputs()))

			if tags := tx.ExtraTags(); tags == nil {
				t.Error("missing extra tags")
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

			tx, err := NewTransactionFromBytes(data[0])
			if err != nil {
				b.Fatal(err)
			}

			if tx.Proofs() == nil {
				b.Skip("no proofs")
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

var testTransactionsData = map[types.Hash][]byte{}

var testPrunedTransactionsData = map[types.Hash][]byte{}
