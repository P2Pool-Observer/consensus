package wallet

import (
	"fmt"
	"os"
	"testing"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address/carrot"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/client"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/transaction"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	"git.gammaspectra.live/P2Pool/consensus/v5/utils"
)

func init() {
	client.SetDefaultClientSettings(os.Getenv("MONEROD_RPC_URL"))
}

var matchTransactions = []types.Hash{
	// some v2 txs legacy
	types.MustHashFromString("0b0ff5efc5e1a277f256501a4df8e86eb3387828c1cf235a93702a9c16548965"),
	types.MustHashFromString("d6f518d8131472aac362f1f22a99da46fc93aed53af8c83baf637f62193c4f11"),

	// todo: add carrot txs later
}

func TestMatchTransaction(t *testing.T) {
	rpc := client.GetDefaultClient()

	vw, err := NewViewWallet[curve25519.VarTimeOperations](testGeneralFundAddr, testGeneralFundViewKey.Scalar(), 0, 80)
	if err != nil {
		t.Fatal(err)
	}

	for _, txId := range matchTransactions {
		t.Run(fmt.Sprintf("%s...", txId.String()[:8]), func(t *testing.T) {

			result, _, err := rpc.GetPrunedTransactions(txId)
			if err != nil {
				t.Fatal(err)
			}
			data := result[0]

			tx, err := transaction.NewPrunedTransactionFromBytes(data)
			if err != nil {
				t.Fatal(err)
			}

			var hadMatch bool
			err = MatchTransaction[curve25519.VarTimeOperations](vw,
				func(index int, scan *LegacyScan, ix address.SubaddressIndex) {
					hadMatch = true
					t.Logf("LEGACY: output #%d at %d,%d, addr = %s: received %s XMR", index, ix.Account, ix.Offset, string(vw.Get(ix).ToBase58()), utils.XMRUnits(scan.Amount))
				},
				func(index int, scan *carrot.ScanV1, ix address.SubaddressIndex) {
					hadMatch = true
					t.Logf("CARROT: output #%d at %d,%d, addr = %s: received %s XMR", index, ix.Account, ix.Offset, string(vw.Get(ix).ToBase58()), utils.XMRUnits(scan.Amount))
				},
				tx,
			)
			if err != nil {
				t.Fatal(err)
			}
			if !hadMatch {
				t.Fatalf("no match")
			}
		})
	}
}
