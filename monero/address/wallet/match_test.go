package wallet

import (
	"fmt"
	"os"
	"testing"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address/carrot"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/client"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/proofs"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/transaction"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	"git.gammaspectra.live/P2Pool/consensus/v5/utils"
)

func init() {
	client.SetDefaultClientSettings(os.Getenv("MONEROD_RPC_URL"))
}

func TestMatchTransactionProof(t *testing.T) {
	rpc := client.GetDefaultClient()

	type txEntry struct {
		Id      types.Hash
		Address *address.Address
		Proof   string
	}

	for _, e := range []txEntry{
		{
			Id:      types.MustHashFromString("353b37c532e5d235afd9f2f21f7acf3d0798b3108a8d5e3c0232e9b403e33e47"),
			Address: address.FromBase58("466tvQKFwxRCp4Da75g6yw4RjugbNNEikSxkHVmkSAZ9eGFpdvNS2ACAQjqKkhXTXzHedM2NQ2Bv4QtiwTTuS4x32D6hU14"),
			Proof:   "OutProofV2KzQRvSdnoZBd2tb4NjcN2nLAoneCu8G2V9f9hy6icEXeJUdioQDsbGw53VpjD7j3FU5Ht1U4yPTB98865dU5uM9a8pYqYdRv1174uJhinmoAqua1zbeyMwTikN7caue2NiBF",
		},
		{
			Id:      types.MustHashFromString("9d8dc30d346712ea54c3f5ff4013f0fd95332c1886e74374128d55b4cf57e22a"),
			Address: address.FromBase58("888tNkZrPN6JsEgekjMnABU4TBzc2Dt29EPAvkRxbANsAnjyPbb3iQ1YBRk1UXcdRsiKc9dhwMVgN5S9cQUiyoogDavup3H"),
			Proof:   "InProofV2MLmU5CnGMagFdxAhXcqUunbgNwPNRLVxCJVwgp3cZSfvd6SG6qBSsxFT1o8qbB3eb8E3jcPXpxbfGKRrBMJ6gFXvThzGkco47csctU5gYuhi5y8EDsWpHhtNH9auLUm1m8o6",
		},

		// todo: add carrot txs later
	} {
		t.Run(fmt.Sprintf("%s...", e.Id.String()[:8]), func(t *testing.T) {

			result, _, err := rpc.GetPrunedTransactions(e.Id)
			if err != nil {
				t.Fatal(err)
			}
			data := result[0]

			tx, err := transaction.NewPrunedTransactionFromBytes(data)
			if err != nil {
				t.Fatal(err)
			}

			proof, err := proofs.NewTxProofFromString[curve25519.VarTimeOperations](e.Proof)
			if err != nil {
				t.Fatal(err)
			}

			var hadMatch bool
			err = MatchTransactionProof[curve25519.VarTimeOperations](e.Address, proof, "",
				func(index int, scan *LegacyScan, ix address.SubaddressIndex) {
					hadMatch = true
					t.Logf("LEGACY: output #%d at %d,%d, addr = %s: received %s XMR", index, ix.Account, ix.Offset, string(e.Address.ToBase58()), utils.XMRUnits(scan.Amount))
				},
				func(index int, scan *carrot.ScanV1, ix address.SubaddressIndex) {
					hadMatch = true
					t.Logf("CARROT: output #%d at %d,%d, addr = %s: received %s XMR", index, ix.Account, ix.Offset, string(e.Address.ToBase58()), utils.XMRUnits(scan.Amount))
				},
				e.Id,
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

func TestMatchTransaction(t *testing.T) {
	rpc := client.GetDefaultClient()

	vw, err := NewViewWallet[curve25519.VarTimeOperations](testGeneralFundAddr, testGeneralFundViewKey.Scalar(), 0, 80)
	if err != nil {
		t.Fatal(err)
	}

	for _, txId := range []types.Hash{
		// some v2 txs legacy
		types.MustHashFromString("0b0ff5efc5e1a277f256501a4df8e86eb3387828c1cf235a93702a9c16548965"),
		types.MustHashFromString("d6f518d8131472aac362f1f22a99da46fc93aed53af8c83baf637f62193c4f11"),

		// todo: add carrot txs later
	} {
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
