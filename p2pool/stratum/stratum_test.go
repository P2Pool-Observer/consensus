package stratum

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math"
	unsafeRandom "math/rand/v2"
	"os"
	"path"
	"runtime"
	"testing"
	"time"
	_ "unsafe"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/block"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/client"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/p2pool/mempool"
	"git.gammaspectra.live/P2Pool/consensus/v5/p2pool/sidechain"
	p2pooltypes "git.gammaspectra.live/P2Pool/consensus/v5/p2pool/types"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	"git.gammaspectra.live/P2Pool/consensus/v5/utils"
	"git.gammaspectra.live/P2Pool/edwards25519"
	"github.com/ulikunitz/xz"
)

var preLoadedMiniSideChain *sidechain.SideChain

var preLoadedPoolBlock *sidechain.PoolBlock

var submitBlockFunc = func(block *sidechain.PoolBlock) (err error) {
	if blob, err := block.MarshalBinary(); err == nil {
		_, err = client.GetDefaultClient().SubmitBlock(blob)
		return err
	}
	return err
}
var submitMainBlockFunc = func(b *block.Block) (err error) {
	if blob, err := b.MarshalBinary(); err == nil {
		_, err = client.GetDefaultClient().SubmitBlock(blob)
		return err
	}
	return err
}

var donationAddr = address.FromBase58(types.DonationAddress)
var donationAddrFunc = func(majorVersion uint8) address.PackedAddressWithSubaddress {
	pa := donationAddr.ToPackedAddress()
	return address.NewPackedAddressWithSubaddress(&pa, donationAddr.IsSubaddress())
}

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
	_ = sidechain.ConsensusNano.InitHasher(2)
	client.SetDefaultClientSettings(os.Getenv("MONEROD_RPC_URL"))
}

func getMinerData(rpcClient *client.Client) *p2pooltypes.MinerData {
	if rpcClient == nil {
		rpcClient = client.GetDefaultClient()
	}
	version, err := rpcClient.GetVersion()
	if err != nil {
		return nil
	}

	if d, err := rpcClient.GetMinerData(); err != nil {
		return nil
	} else {
		return &p2pooltypes.MinerData{
			MajorVersion:          d.MajorVersion,
			MinorVersion:          uint8(version.HardForks[len(version.HardForks)-1].Version),
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
	client.SetDefaultClientSettings(os.Getenv("MONEROD_RPC_URL"))

	if buf, err := os.ReadFile("testdata/v4_block.dat"); err != nil {
		panic(err)
	} else {
		preLoadedPoolBlock = &sidechain.PoolBlock{}
		if err = preLoadedPoolBlock.UnmarshalBinary(sidechain.ConsensusDefault, &sidechain.NilDerivationCache{}, buf); err != nil {
			panic(err)
		}
	}

	_ = sidechain.ConsensusMini.InitHasher(2)

	preLoadedMiniSideChain = sidechain.NewSideChain(sidechain.GetFakeTestServer(sidechain.ConsensusMini))

	f, err := os.Open("testdata/v4_2_sidechain_dump_mini.dat.xz")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	r, err := xz.NewReader(f)
	if err != nil {
		panic(err)
	}

	if blocks, err := sidechain.LoadSideChainTestData(preLoadedMiniSideChain.Consensus(), preLoadedMiniSideChain.DerivationCache(), r); err != nil {
		panic(err)
	} else {
		for _, b := range blocks {
			// verify externally first without PoW, then add directly
			if _, err, _ = preLoadedMiniSideChain.PoolBlockExternalVerify(b); err != nil {
				panic(err)
			}
			if err = preLoadedMiniSideChain.AddPoolBlock(b); err != nil {
				panic(err)
			}
		}
	}

	code := m.Run()

	os.Exit(code)
}

func TestStratumServer(t *testing.T) {
	stratumServer := NewServer(preLoadedMiniSideChain, submitBlockFunc, submitMainBlockFunc)
	minerData := getMinerData(nil)
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

	tpl, _, _, seedHash, err := stratumServer.BuildTemplate(0, donationAddrFunc, false)
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

func testFromGenesis(t *testing.T, consensus *sidechain.Consensus, rpcClient *client.Client, n int) {
	oldLogLevel := utils.GlobalLogLevel
	defer func() {
		utils.GlobalLogLevel = oldLogLevel
	}()
	utils.GlobalLogLevel = utils.LogLevelInfo | utils.LogLevelNotice | utils.LogLevelError

	var testAddresses []address.PackedAddressWithSubaddress

	minerData := getMinerData(rpcClient)
	if minerData == nil {
		t.Fatal("miner data is nil")
	}

	pa := address.FromBase58(types.DonationAddress).ToPackedAddress()
	testAddresses = append(testAddresses, address.NewPackedAddressWithSubaddress(&pa, false))
	if n > 2 {
		for range n / 2 {
			testAddresses = append(testAddresses, address.NewPackedAddressWithSubaddressFromBytes(
				new(curve25519.VarTimePublicKey).ScalarBaseMult(crypto.RandomScalar(new(edwards25519.Scalar), rand.Reader)).Bytes(),
				new(curve25519.VarTimePublicKey).ScalarBaseMult(crypto.RandomScalar(new(edwards25519.Scalar), rand.Reader)).Bytes(),
				sidechain.P2PoolShareVersion(consensus, 0) >= sidechain.ShareVersion_V3 && /* TODO: remove when supported? */ minerData.MajorVersion < monero.HardForkCarrotVersion,
			))
		}
	}

	if consensus.MinimumDifficulty == 1 {
		err := consensus.InitHasher(1)
		if err != nil {
			t.Fatal(err)
		}
		defer consensus.GetHasher().Close()
	} else {
		// test hasher
		err := consensus.InitTestHasher()
		if err != nil {
			t.Fatal(err)
		}
	}

	fakeServer := sidechain.GetFakeTestServerWithRPC(consensus, rpcClient)
	sideChain := sidechain.NewSideChain(fakeServer)

	stratumServer := NewServer(sideChain, func(block *sidechain.PoolBlock) error {
		return nil
	}, func(b *block.Block) error {
		return nil
	})
	stratumServer.HandleMinerData(minerData)

	var expected uint64

	for i := range n {
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

		minerId := uint64(i % len(testAddresses))

		addrFunc := func(majorVersion uint8) address.PackedAddressWithSubaddress {
			if testAddresses[minerId].IsSubaddress() && majorVersion < monero.HardForkCarrotVersion {
				// weird fake address for testing
				return address.NewPackedAddressWithSubaddressFromBytes(*testAddresses[minerId].SpendPublicKey(), *testAddresses[minerId].SpendPublicKey(), false)
			}
			return testAddresses[minerId]
		}

		tpl, _, _, seedHash, err := stratumServer.BuildTemplate(minerId, addrFunc, false)
		if err != nil {
			t.Fatal(err)
		}

		var mmExtra sidechain.MergeMiningExtra

		if testAddresses[minerId].IsSubaddress() && tpl.MajorVersion() < monero.HardForkCarrotVersion {
			// explicitly add old subaddress tagging information before hardfork
			var subaddressViewPubBuf [curve25519.PublicKeySize + 2]byte
			copy(subaddressViewPubBuf[:], testAddresses[minerId].ViewPublicKey()[:])
			mmExtra = mmExtra.Set(sidechain.ExtraChainKeySubaddressViewPub, subaddressViewPubBuf[:])
		}

		addr := addrFunc(uint8(tpl.MajorVersion()))

		if seedHash != minerData.SeedHash {
			t.Fatal()
		}

		if tpl.MainHeight != minerData.Height {
			t.Fatal()
		}

		if tpl.MainParent != minerData.PrevId {
			t.Fatal()
		}

		if tpl.SideHeight != expected {
			t.Fatalf("expected side height %d, got %d", expected, tpl.SideHeight)
		}

		if i == 0 {
			// verify genesis parameters
			if tpl.SideParent != types.ZeroHash {
				t.Fatal("wrong side parent")
			}
		}

		var templateId types.Hash
		tpl.TemplateId(nil, consensus, addr, 0, 0, nil, mmExtra, p2pooltypes.CurrentSoftwareId, p2pooltypes.CurrentSoftwareVersion, &templateId)

		nonce := uint32(0)

		// do proper PoW!
		if consensus.MinimumDifficulty == 1 {
			for n := uint32(0); n < math.MaxUint8; n++ {
				blob := tpl.HashingBlob(nil, n, 0, templateId)
				powHash, err := consensus.GetHasher().Hash(seedHash[:], blob)
				if err != nil {
					t.Fatal(err)
				}
				if tpl.SideDifficulty.CheckPoW(powHash) {
					nonce = n
					break
				}
			}
		}

		blockData := tpl.Blob(nil, consensus, addr, nonce, 0, 0, 0, templateId, nil, mmExtra, p2pooltypes.CurrentSoftwareId, p2pooltypes.CurrentSoftwareVersion)

		buffer := bytes.NewBuffer(make([]byte, 0, tpl.BufferLength(consensus, nil, mmExtra)))
		if err := tpl.Write(buffer, consensus, addr, nonce, 0, 0, 0, templateId, nil, mmExtra, p2pooltypes.CurrentSoftwareId, p2pooltypes.CurrentSoftwareVersion); err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(blockData, buffer.Bytes()) {
			t.Fatal("unequal block data")
		}

		var b sidechain.PoolBlock
		err = b.UnmarshalBinary(consensus, &sidechain.NilDerivationCache{}, blockData)
		if err != nil {
			t.Fatal(err)
		}

		if b.FastSideTemplateId(consensus) != templateId {
			t.Fatalf("mismatched fast template id, got %s expected %s", b.FastSideTemplateId(consensus), templateId)
		}

		if b.SideTemplateId(consensus) != templateId {
			t.Fatalf("mismatched template id, got %s expected %s", b.SideTemplateId(consensus), templateId)
		}

		if i == 0 {
			if b.Side.CoinbasePrivateKeySeed != consensus.Id {
				t.Fatal("invalid private key seed")
			}

			if b.Side.CumulativeDifficulty.Cmp64(consensus.MinimumDifficulty) != 0 {
				t.Fatal()
			}

			if b.Side.Difficulty.Cmp64(consensus.MinimumDifficulty) != 0 {
				t.Fatal()
			}
		}

		missing, err := sideChain.PreprocessBlock(&b)
		if len(missing) != 0 {
			t.Fatal("missing blocks!")
		}
		if err != nil {
			t.Fatal(err)
		}

		switch i % 3 {
		case 0:
			missing, err, _ = sideChain.AddPoolBlockExternal(&b)
		case 1:
			// pruned, not compact
			blob, err := b.MarshalBinaryFlags(true, false)
			if err != nil {
				t.Fatalf("failed to marshal block: %s", err)
			}
			var b2 sidechain.PoolBlock
			err = b2.UnmarshalBinary(consensus, sideChain.DerivationCache(), blob)
			if err != nil {
				t.Fatalf("failed to unmarshal block: %s", err)
			}
			missing, err = sideChain.PreprocessBlock(&b2)
			if len(missing) != 0 {
				t.Fatal("missing blocks!")
			}
			if err != nil {
				t.Fatal(err)
			}

			missing, err, _ = sideChain.AddPoolBlockExternal(&b2)
		case 2:
			// pruned, compact
			blob, err := b.MarshalBinaryFlags(true, true)
			if err != nil {
				t.Fatalf("failed to marshal block: %s", err)
			}
			var b2 sidechain.PoolBlock
			err = b2.FromCompactReader(consensus, sideChain.DerivationCache(), bytes.NewReader(blob))
			if err != nil {
				t.Fatalf("failed to unmarshal block: %s", err)
			}
			missing, err = sideChain.PreprocessBlock(&b2)
			if len(missing) != 0 {
				t.Fatal("missing blocks!")
			}
			if err != nil {
				t.Fatal(err)
			}

			missing, err, _ = sideChain.AddPoolBlockExternal(&b2)

		}

		if len(missing) != 0 {
			t.Fatal("missing blocks!")
		}
		if err != nil {
			t.Fatal(err)
		}

		if fakeServer.Tip == nil {
			// unexpected
			t.Fatal("expected tip")
		}

		// add a fake tx every iteration to increase weight past limit
		stratumServer.HandleMempoolData(mempool.Mempool{
			{
				Id:           b.SideTemplateId(consensus),
				BlobSize:     0,
				Weight:       unsafeRandom.Uint64N(512*1024) + 64*1024,
				Fee:          unsafeRandom.Uint64N(1000000000000-10000000000) + 10000000000,
				TimeReceived: time.Now().AddDate(0, 0, -1),
			},
		})

		if i > 0 && i%7 == 0 {
			// do uncle
			continue
		}

		stratumServer.HandleTip(fakeServer.Tip)
		expected = fakeServer.Tip.Side.Height + 1
	}
}

func TestStratumServer_Genesis(t *testing.T) {

	const n = 256

	for _, version := range []sidechain.ShareVersion{
		sidechain.ShareVersion_V2,
		sidechain.ShareVersion_V3,
	} {
		t.Run(fmt.Sprintf("V%d", uint8(version)), func(t *testing.T) {
			consensus := sidechain.NewConsensus(sidechain.NetworkMainnet, "test", "", "", 1, sidechain.SmallestMinimumDifficulty, 100, 20)
			consensus.HardForks = []monero.HardFork{
				{uint8(version), 0, 0, 0},
			}
			testFromGenesis(t, consensus, nil, n)
		})
	}

	t.Run("Testnet", func(t *testing.T) {
		rpcClient, _ := client.NewClient("http://127.0.0.1:28081")
		if minerData := getMinerData(rpcClient); minerData == nil {
			t.Skip("No Testnet RPC")
		}

		consensus := sidechain.NewConsensus(sidechain.NetworkTestnet, "test", "", "", 1, 1, 60, 20)
		consensus.HardForks = []monero.HardFork{
			{uint8(sidechain.ShareVersion_V3), 0, 0, 0},
		}

		// override!
		if versionInfo, err := rpcClient.GetVersion(); err == nil {
			consensus.MoneroHardForks = nil
			for _, e := range versionInfo.HardForks {
				consensus.MoneroHardForks = append(consensus.MoneroHardForks, monero.HardFork{
					Version:   uint8(e.Version),
					Height:    e.Height,
					Threshold: 0,
					Time:      0,
				})
			}
		}

		// less that default due to PoW
		testFromGenesis(t, consensus, rpcClient, 32)
	})
}

func BenchmarkServer_FillTemplate(b *testing.B) {
	stratumServer := NewServer(preLoadedMiniSideChain, submitBlockFunc, submitMainBlockFunc)
	minerData := getMinerData(nil)
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
	stratumServer := NewServer(preLoadedMiniSideChain, submitBlockFunc, submitMainBlockFunc)
	minerData := getMinerData(nil)
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
		spendPriv, viewPriv := crypto.DeterministicScalar(new(edwards25519.Scalar), []byte(fmt.Sprintf("BenchmarkBuildTemplate_%d_spend", i))), crypto.DeterministicScalar(new(edwards25519.Scalar), []byte(fmt.Sprintf("BenchmarkBuildTemplate_%d_spend", i)))
		randomKeys[i][0] = new(curve25519.VarTimePublicKey).ScalarBaseMult(spendPriv).Bytes()
		randomKeys[i][1] = new(curve25519.VarTimePublicKey).ScalarBaseMult(viewPriv).Bytes()
	}

	b.ResetTimer()
	b.ReportAllocs()

	b.Run("Cached", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			counter := unsafeRandom.IntN(randomPoolSize)
			for pb.Next() {
				a := randomKeys[counter%randomPoolSize]
				if _, _, _, _, err := stratumServer.BuildTemplate(uint64(counter%randomPoolSize), func(majorVersion uint8) address.PackedAddressWithSubaddress {
					return address.NewPackedAddressWithSubaddress(&a, false)
				}, false); err != nil {
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
				if _, _, _, _, err := stratumServer.BuildTemplate(uint64(counter%randomPoolSize), func(majorVersion uint8) address.PackedAddressWithSubaddress {
					return address.NewPackedAddressWithSubaddress(&a, false)
				}, true); err != nil {
					b.Fatal(err)
				}
				counter++
			}
		})
		b.ReportAllocs()
	})
}
