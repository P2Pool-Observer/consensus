package stratum

import (
	"compress/gzip"
	"fmt"
	"git.gammaspectra.live/P2Pool/consensus/v3/monero/address"
	"git.gammaspectra.live/P2Pool/consensus/v3/monero/client"
	"git.gammaspectra.live/P2Pool/consensus/v3/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v3/p2pool/sidechain"
	p2pooltypes "git.gammaspectra.live/P2Pool/consensus/v3/p2pool/types"
	"git.gammaspectra.live/P2Pool/consensus/v3/types"
	"git.gammaspectra.live/P2Pool/consensus/v3/utils"
	unsafeRandom "math/rand/v2"
	"os"
	"path"
	"runtime"
	"testing"
	"time"
	_ "unsafe"
)

var preLoadedMiniSideChain *sidechain.SideChain

var preLoadedPoolBlock *sidechain.PoolBlock

func init() {
	utils.GlobalLogLevel = 0

	_, filename, _, _ := runtime.Caller(0)
	// The ".." may change depending on you folder structure
	dir := path.Join(path.Dir(filename), "../..")
	err := os.Chdir(dir)
	if err != nil {
		panic(err)
	}

	_ = sidechain.ConsensusDefault.InitHasher(2)
	_ = sidechain.ConsensusMini.InitHasher(2)
	client.SetDefaultClientSettings(os.Getenv("MONEROD_RPC_URL"))
}

func getMinerData() *p2pooltypes.MinerData {
	if d, err := client.GetDefaultClient().GetMinerData(); err != nil {
		return nil
	} else {
		return &p2pooltypes.MinerData{
			MajorVersion:          d.MajorVersion,
			Height:                d.Height,
			PrevId:                d.PrevId,
			SeedHash:              d.SeedHash,
			Difficulty:            d.Difficulty,
			MedianWeight:          d.MedianWeight,
			AlreadyGeneratedCoins: d.AlreadyGeneratedCoins,
			MedianTimestamp:       d.MedianTimestamp,
			TimeReceived:          time.Now(),
			TxBacklog:             nil,
		}
	}
}

func TestMain(m *testing.M) {
	if buf, err := os.ReadFile("testdata/block.dat"); err != nil {
		panic(err)
	} else {
		preLoadedPoolBlock = &sidechain.PoolBlock{}
		if err = preLoadedPoolBlock.UnmarshalBinary(sidechain.ConsensusDefault, &sidechain.NilDerivationCache{}, buf); err != nil {
			panic(err)
		}
	}

	_ = sidechain.ConsensusMini.InitHasher(2)
	client.SetDefaultClientSettings(os.Getenv("MONEROD_RPC_URL"))

	preLoadedMiniSideChain = sidechain.NewSideChain(sidechain.GetFakeTestServer(sidechain.ConsensusMini))

	f, err := os.Open("testdata/sidechain_dump_mini.dat.gz")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	r, err := gzip.NewReader(f)
	if err != nil {
		panic(err)
	}
	defer r.Close()

	if err = sidechain.LoadSideChainTestData(preLoadedMiniSideChain, r); err != nil {
		panic(err)
	}

	code := m.Run()

	os.Exit(code)
}

func TestStratumServer(t *testing.T) {
	stratumServer := NewServer(preLoadedMiniSideChain, func(block *sidechain.PoolBlock) error {
		return nil
	})
	minerData := getMinerData()
	tip := preLoadedMiniSideChain.GetChainTip()
	stratumServer.HandleMinerData(minerData)
	stratumServer.HandleTip(tip)

	func() {
		//Process all incoming changes first
		for {
			select {
			case f := <-stratumServer.incomingChanges:
				if f() {
					stratumServer.Update()
				}
			default:
				return
			}
		}
	}()

	tpl, _, _, seedHash, err := stratumServer.BuildTemplate(address.FromBase58(types.DonationAddress).ToPackedAddress(), false)
	if err != nil {
		t.Fatal(err)
	}

	if seedHash != minerData.SeedHash {
		t.Fatal()
	}

	if tpl.MainHeight != minerData.Height {
		t.Fatal()
	}

	if tpl.MainParent != minerData.PrevId {
		t.Fatal()
	}

	if tpl.SideHeight != (tip.Side.Height + 1) {
		t.Fatal()
	}

	if tpl.SideParent != tip.SideTemplateId(preLoadedMiniSideChain.Consensus()) {
		t.Fatal()
	}
}

func BenchmarkServer_FillTemplate(b *testing.B) {
	stratumServer := NewServer(preLoadedMiniSideChain, func(block *sidechain.PoolBlock) error {
		return nil
	})
	minerData := getMinerData()
	tip := preLoadedMiniSideChain.GetChainTip()
	stratumServer.minerData = minerData
	stratumServer.tip = tip

	b.ResetTimer()

	b.Run("New", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if err := stratumServer.fillNewTemplateData(minerData.Difficulty); err != nil {
				b.Fatal(err)
			}
		}
		b.ReportAllocs()
	})

	b.Run("Cached", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if err := stratumServer.fillNewTemplateData(types.ZeroDifficulty); err != nil {
				b.Fatal(err)
			}
		}
		b.ReportAllocs()
	})

}

func BenchmarkServer_BuildTemplate(b *testing.B) {
	stratumServer := NewServer(preLoadedMiniSideChain, func(block *sidechain.PoolBlock) error {
		return nil
	})
	minerData := getMinerData()
	tip := preLoadedMiniSideChain.GetChainTip()
	stratumServer.minerData = minerData
	stratumServer.tip = tip

	if err := stratumServer.fillNewTemplateData(minerData.Difficulty); err != nil {
		b.Fatal(err)
	}

	const randomPoolSize = 512
	var randomKeys [randomPoolSize]address.PackedAddress

	//generate random keys deterministically
	for i := range randomKeys {
		spendPriv, viewPriv := crypto.DeterministicScalar([]byte(fmt.Sprintf("BenchmarkBuildTemplate_%d_spend", i))), crypto.DeterministicScalar([]byte(fmt.Sprintf("BenchmarkBuildTemplate_%d_spend", i)))
		randomKeys[i][0] = (*crypto.PrivateKeyScalar)(spendPriv).PublicKey().AsBytes()
		randomKeys[i][1] = (*crypto.PrivateKeyScalar)(viewPriv).PublicKey().AsBytes()
	}

	b.ResetTimer()
	b.ReportAllocs()

	b.Run("Cached", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			counter := unsafeRandom.IntN(randomPoolSize)
			for pb.Next() {
				a := randomKeys[counter%randomPoolSize]
				if _, _, _, _, err := stratumServer.BuildTemplate(a, false); err != nil {
					b.Fatal(err)
				}
				counter++
			}
		})
		b.ReportAllocs()
	})

	b.Run("Forced", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			counter := unsafeRandom.IntN(randomPoolSize)
			for pb.Next() {
				a := randomKeys[counter%randomPoolSize]
				if _, _, _, _, err := stratumServer.BuildTemplate(a, true); err != nil {
					b.Fatal(err)
				}
				counter++
			}
		})
		b.ReportAllocs()
	})
}
