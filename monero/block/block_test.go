package block

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"path"
	"runtime"
	"testing"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/client"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/randomx"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	"git.gammaspectra.live/P2Pool/consensus/v5/utils"
)

func init() {
	_, filename, _, _ := runtime.Caller(0)
	// The ".." may change depending on you folder structure
	dir := path.Join(path.Dir(filename), "../..")
	err := os.Chdir(dir)
	if err != nil {
		panic(err)
	}

	client.SetDefaultClientSettings(os.Getenv("MONEROD_RPC_URL"))
}

var fuzzPoolBlocks = []string{
	"testdata/v4_block.dat",
	"testdata/v2_block.dat",
	"testdata/v1_mainnet_test2_block.dat",
}

func FuzzMainBlockRoundTrip(f *testing.F) {

	for _, path := range fuzzPoolBlocks {
		data, err := os.ReadFile(path)
		if err != nil {
			f.Fatal(err)
		}
		reader := bytes.NewReader(data)
		b := &PoolMainBlock{}
		err = b.FromReader(reader, false, nil)
		if err != nil {
			f.Skipf("leftover error: %s", err)
		}
		buf, err := b.MarshalBinary()
		if err != nil {
			f.Fatal(err)
		}
		f.Add(buf)
	}

	f.Fuzz(func(t *testing.T, buf []byte) {
		b := &PoolMainBlock{}
		reader := bytes.NewReader(buf)
		err := b.FromReader(reader, false, nil)
		if err != nil {
			t.Skipf("leftover error: %s", err)
		}
		if reader.Len() > 0 {
			//clamp comparison
			buf = buf[:len(buf)-reader.Len()]
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

var testBlocks = []types.Hash{

	// genesis
	types.MustHashFromString("418015bb9ae982a1975da7d79277c2705727a56894ba0fb246adaabb1f4632e3"),
	// genesis+1
	types.MustHashFromString("771fbcd656ec1464d3a02ead5e18644030007a0fc664c0a964d30922821a8148"),

	// block 202612 bug
	existingHashBlock202612,

	// version 2
	types.MustHashFromString("a344b5ef0100ab55ca529b8c1f67db30a1301ca529da0abbcca4631fe01bf789"),
	// version 3
	types.MustHashFromString("9aa5eb083e08bfa74ff9c833a3375a4e1a4f4674ec64d17c636286b019915095"),
	// version 4
	types.MustHashFromString("953f19942d03654bbb94e073473f0cd66164581e6fe264a33f645fc5bfc1d24b"),
	// version 5
	types.MustHashFromString("875ac1bc7aa6c5eedc5410abb9c694034f9e7f79dce4c60698baf37009cb6365"),
	// version 6
	types.MustHashFromString("fbf69d7e33aeaeec052e9c2c25b2b05f38fe2ec64bc53bf40c58495bbbfdc895"),
	// version 7
	types.MustHashFromString("b408bf4cfcd7de13e7e370c84b8314c85b24f0ba4093ca1d6eeb30b35e34e91a"),
	// version 8
	types.MustHashFromString("b634aa84df177ac0edc22e66eb5310c6d81d03486029f643e587baf2e2ebf6c1"),
	// version 9
	types.MustHashFromString("c7e45cedd9e9a7c4937c64a2f0cff7b09874ce6f0c12003c763bbe5d28037038"),
	// version 10
	types.MustHashFromString("feef31ad82513f3e2cd157f32b16c547311086ea189df169b663b23c92c13dda"),
	// version 11
	types.MustHashFromString("61765b9d7e88eed25a1168a04839fa99ed8c7e2b5362292e9e0d299b771cc4b7"),
	// version 12
	types.MustHashFromString("c528ed607e448481fdeb9cf18c5abc06b64e5523d6e7589d5dce6aebd48ada23"),
	// version 13
	types.MustHashFromString("f8f31ddd124c5833309b9b9b1e9353a43a510e44c5b1cc66bf86bcbff15b5081"),
	// version 14
	types.MustHashFromString("1526e4ae15040136f86e49d26aef2d2461c0b08e93d6edaadb1687e2d71e1469"),
	// version 15
	types.MustHashFromString("6bd4550a97aaba2eeab7be8cd70041ba0651e1a25300a4b963c83eb764a7149c"),
	// version 16
	types.MustHashFromString("84785e719b9bcbb763b103bb04b46565cea1c82a4995d984ae30817b8c6ac922"),

	// first p2pool block
	types.MustHashFromString("de765284307d562be5d68cd46d1c80f3e2c311680c14e07cd1cfd91e6bbf0575"),
	// newer p2pool block
	types.MustHashFromString("ee860c8d05640f0fe200904ca806140d2620f5cdd1a5e68f2418535e24d7742a"),

	// invalid extra data due to Tari merge mining bug
	types.MustHashFromString("35050900709dac5b4529101ead86631985f74e9e1f2142761b2854bd5b387aef"),
}

func TestHeight202612Blocks(t *testing.T) {
	for _, testPath := range [][2]string{
		{"testdata/monero_blocks_block_202612_mainnet.bin", "bbd604d2ba11ba27935e006ed39c9bfdd99b76bf4a50654bc1e1e61217962698"},
		{"testdata/monero_blocks_block_202612_stagenet.bin", "f3449e658b5f880c4b0e69007ed5d092c9c883ac3a518166fa652d5cc505e7b1"},
		{"testdata/monero_blocks_block_202612_testnet.bin", "248fde4b96b829c4ddbd00e3f76d35b03d01257898bc1b5578bc9e04b379a676"},
	} {
		t.Run(fmt.Sprintf("%s", path.Base(testPath[0])), func(t *testing.T) {
			buf, err := os.ReadFile(testPath[0])
			if err != nil {
				t.Fatal(err)
			}
			var b GenericBlock
			if err = b.UnmarshalBinary(buf, false, nil); err != nil {
				t.Fatal(err)
			}

			if id := b.Id(); id.String() != testPath[1] {
				t.Fatalf("id: got %s, want %s", id.String(), testPath[1])
			}

			if hash, err := b.PowHashWithError(nil, nil); err != nil {
				t.Fatal(err)
			} else if hash != powHashBlock202612 {
				t.Fatalf("pow: got %s, want %s", hash.String(), powHashBlock202612.String())
			}
		})
	}
}

func TestBlocks(t *testing.T) {
	rpc := client.GetDefaultClient()

	rx, err := randomx.NewRandomX(1)
	if err != nil {
		t.Fatal(err)
	}

	for _, id := range testBlocks {
		t.Run(fmt.Sprintf("%s...", id.String()[:8]), func(t *testing.T) {

			result, err := rpc.GetBlock(id, true, t.Context())
			if err != nil {
				t.Fatal(err)
			}

			hdr := result.BlockHeader

			var b GenericBlock
			if err = b.UnmarshalBinary(result.Blob, false, nil); err != nil {
				t.Fatal(err)
			}

			calculatedId := b.Id()
			calculatedMinerId := b.Coinbase.Hash()
			calculatedPow, err := b.PowHashWithError(rx, func(height uint64) (hash types.Hash) {
				result, err := rpc.GetBlockHeaderByHeight(randomx.SeedHeight(height), t.Context())
				if err != nil {
					t.Fatal(err)
				}
				if result.BlockHeader.Hash == types.ZeroHash {
					t.Fatal("expected block header hash")
				}
				return result.BlockHeader.Hash
			})
			if err != nil {
				t.Fatal(err)
			}

			bufLength := b.BufferLength()

			buf, err := b.AppendBinaryFlags(make([]byte, 0, bufLength), false, false, false)
			if err != nil {
				t.Fatal(err)
			}
			if bufLength != len(buf) {
				t.Fatalf("expected %d, got %d", bufLength, len(buf))
			}
			if bytes.Compare(result.Blob, buf) != 0 {
				t.Fatal("tx buffer data mismatch")
			}

			t.Logf("version = %d", b.MajorVersion)
			t.Logf("height  = %d", b.Coinbase.GenHeight())
			t.Logf("id      = %s", calculatedId)
			t.Logf("pow     = %s", calculatedPow)
			t.Logf("tx id   = %s", calculatedMinerId)
			t.Logf("reward  = %s XMR", utils.XMRUnits(b.Coinbase.TotalReward()))

			if calculatedId != id {
				t.Fatalf("expected id %s, got %s", id, calculatedId)
			}

			if calculatedPow != hdr.PowHash {
				t.Fatalf("expected pow %s, got %s", hdr.PowHash, calculatedPow)
			}

			if calculatedMinerId != hdr.MinerTxHash {
				t.Fatalf("expected tx id %s, got %s", hdr.MinerTxHash, calculatedMinerId)
			}

			if b.Coinbase.TotalReward() != hdr.Reward {
				t.Fatalf("expected reward %d, got %d", hdr.Reward, b.Coinbase.TotalReward())
			}
		})
	}
}
