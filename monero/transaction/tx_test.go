package transaction

import (
	"bytes"
	"fmt"
	"os"
	"testing"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/client"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	"git.gammaspectra.live/P2Pool/consensus/v5/utils"
	"git.gammaspectra.live/P2Pool/go-hex"
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

	// v2 coinbase p2pool
	types.MustHashFromString("8a72317bee39b1b6d8bd941607485986c7e4a50ebc440b9c144334feffd6fbfd"),

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
	types.MustHashFromString("32e66dcf37b87703ebff69a0bd93a3cdc8fb919463085778d046bdda900efe52"),

	// mordinals
	types.MustHashFromString("04a69ae5e9fb51327997f1a809604b4992ab9561680bab47e2f967f5c6129d72"),

	// fcmp++ beta stressnet tx
	types.MustHashFromString("332691761f1ded0d74c80b223a7266f3568f472fe67f33f97d8390a48d9caa29"),
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
			t.Logf("inputs  = %d", len(tx.Inputs()))
			t.Logf("outputs = %d", len(tx.Outputs()))

			if calculatedId != txId {
				t.Fatalf("expected %s, got %s", txId, calculatedId)
			}

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

var testTransactionsData = map[types.Hash][]byte{
	types.MustHashFromString("332691761f1ded0d74c80b223a7266f3568f472fe67f33f97d8390a48d9caa29"): hex.MustDecodeString("020001020000b65762072a662ba06b824df7760058d402d3a426a8dbf11742c9d82137b6311902000018ba991d09a78989e88b02b2df90460cf700d6f39147c5233e68cb46c9a61fd1c6666f311724a9b5153451d88ae1276879f19f0000d28936e3c6a730611bdb572a72240f0b4dc2cbdfcb7561b83bb443d2d266445e7bb96a41819f77e51753738ac307f1b4e37a632c0199d114866dad14fb3c588dcc7af2faf4cfd724b14fa44cc1cd34711475c55b6f02090119153b63e850521e07e0eb95a304342d86ef67c633d1006d543fa35ef12a680b696eeadbbc43e4099776a017d92c7570837895c0ba7cb40290747dc56e4604e1a5b553da4b63e29308132e52408d1dd64e7b2c47378e685fc6d5fff6cc0e01fafac63a2408ca43b7df6bc1be990b43164b0adee2891ffd55cc5d98b976e13276d34d13872af6d9ad7999ec9e579200e908b50378561fde9047e632eed55fdae2c08ceb46875dfa5d9d2d60bfc9a978997dfdf8823c3523e1400b9daf470a50b702b22f59a00b147f94bc70b421def2725e0751cf119f3e63d0b91d0839d002ae28dd0fab88aed29d5b93d8d1799e6fbeab633d0e470e7488a8a36656ee17095ae2bae2e0eef38e77f76df8dc896a4fdaf48ff68d80e71c24c7d1307c870c03072ef727361c46a4f59353ba162b54bad16d51e84c7cfd0aa53b5b8069e56e1ba524afe4c4fbb547a701b6720f5ca519824e1e2abaca1d5b4014f44cba29638d8b9268275eb0e07c2489c05b6f9c755f5820713c9ec3766a11a97157e320518c6a922461bdabd863f03a60af69acf3ef91b50d13c6925056f400bedf3133b9b694782adad8379feb3373fd0a42dc3c7f5cee87a1e81659f26a140d8f9c40870a8bae1f42cc0a0d979a9e62e33f929f39d4cdd2fe042ce90b83d7cb6b6400223358e56cc8625cd67cb239a4b2b3270e9ae91a8cd6ada9ff1df7e9ca96a989f812a107eb02dbc37b72880dec24e396eb2710bf0837ee73049c4dc9e02b402cd293928e1562ede7366879bdd85649e9e8abb1a2dbcde75c7746574ddf24aff8d15fdb57d237c5851156839e8a9bde89426e483363c8daac52cb7bba6fed89f16e234ee4abf18faaeaa403acdec4f5e158fc0cab86e22166a5cfb9f8e3b96eaecf495dccf7f7474bae83dbe9222114ee954a77d066c571540a3df93c11c9e874aca947e3cf28813b6f7174db99acb942e7f0151bcfa2ca8828faba28e5eeee6a577a8c02096dcee3b08c6ba765234849458704aa9d71e422195e263f56a3a93ca24d3f7697e7b80106fb23a49c8e015f6ab7480b0ce5e180586d3734bae3002f209d5bc4ba683b81005b5bdddca3da7d01f69dc03808d6225c09e2fc6f1659e38c03dd258a8c63664008a294f531fb0527893e5e264947b2d9930a96e4c716a337a18d11fd3cbdad237c91a7c13342760127d3e53ae9e14e29c8c185c5d5b6e38799773998e45c870a31f0b7557f5a934543860e666b441a8cd4e21c0d1ae5f47847c62897b8570e40fbf84cc914ac863c329c0fcecf1c00537d709a3cccdfadd99f4e6b7a724d123a7ed60834b1251ba834d2a6494d724199ba4abded7640fe51312b34b0d5a363e08b77113f7ef30df77a80ef1c3ae422fd817afa83621538a6ac559baebc82eacd96e8725f44a15e072a33794a5238b89b8551e4dde6b9e173751d6484e248fa61cd405be45664524f5d9d4ba88c6c8c26014f9ba4c327aa1aeae1165e9a3f450ff6dd65dcdd82f0d0fe5b127254858e0b38912ead5028458fcdfd240934855000abf0d1358bcbe7b16371439509fc53aef9323c37b56a44a57681d6dc6207630619c4a89587e82a3598b167ae0bdf7525ce7c835fa648b2701a02c7bf24c81e06019d5553da1b217208214a5d6533b94b369772111111ca4de1e3c54f5fafb50103c08773a55a694115ee85c35846c6896ae99914b87182a590ed88e678e66f01b80fd563511470376a8d0c65f225befe2a297d3c5acebf8efd79ecb6fb866706154192a28229029bf059f639e05fd73a0f8e830e0c9ac00b2c79029d561aba0de8c08b7fbe4bb0f9ab718dc06b173588fe5f04d38f03c2b1b352793aba24cd78364cbf227e7109b2a1a19e7136ff2e2551fe28f9990451e5ec9ba8d7890e44fb0de2088c0b2d42ca8fb969ae3e6e1797d6d3defc03711311b2d95db406e44004b649d8149a9a7da590fe34f2ab1cfad6949ce4c6787bfaab8c93cbcfdb43b942bfd45cc77abf2c1283c2f5db6981c1c80d9ee76861cc118ba415ec9e30b6dc774a0ae353b127f953ad833a91931339a34a54375ee005d533920bb0a3e1f332be1cfdd1df83b1bd9e671ff6a742c56995ffee929b2c7a52c6e63a287d7f7b8f90a427e96ba144c123b1f317696d4444f989fa500a8cc097aef9b1887c414d5596e71123c874e24e879416af73cb5d4d77c482f05a99b84aedd7fb61ecfff8d3c74397784758f523552948803b41e2d2d56415d164daaf14b8b731bb87d7797277f6d93213098c319b907d00eadfab2f5a6020182321a20011f740b52f00ab70e0d9e7a0dc0f87d012760415bd7a674f09e6350b532670e54c4801cc0586ea5b0e4f96c9535751a942cda1d46b92b0c465b35ae3be725a52a41c55c4a084e3b7a3de35a834d0ee261b9d02509e6fa73d994c56da22cdc260e7271179ed901b8a8b2e9461948dd708a431ab4e6991642817a2cc8bdaaedeb81f7d4efdd8e45c4c5cbb4f404b019baa27cd66be071d20901cd66bde27774ebe5ac780f569d36dbfb59d2abfaa19f2a95e3b1ea688eec3dca869a3ac0e8ff89303e1a670933457f349a17e425c8b0628cdf012bbcbebe93691b9c143b1298ab834d4a727620d622708641c2b68b66710eb35a79253f984fcffa94927b6e30b2dadcbdab34d6af575b54fad8efdfb516edbddf47653fa0a4c2571e8f4d1267c0188a16059479fcae45048bea4c99fe51d807e73eab81da10a84e2f85d73e680e0bbe24793451db4172ff4ba8230134b7daf2b41ef90fd009d8e3a24be361cc41cfdbc10b642c87350385b2082bad5e66e14cf403c90d1b2765a1d2650cf5d47ae42b25bdeb2177ad3822d1153b73a5d47ed559281277de00b3e431707b8ebc3142f0f8a0e1e4210d46ee6877ac8db20528e3e070921e1286ebc04bcf2f488e6b8ed926714512c9241909949e4f72ebdfe9083560b2f8ce3252b7c598ccf405b7e70b354ffe7f9568b608212e244a88d6f8f6b57223f2cec77763cd0a04ee80a588a1881b6e8a9dd00f0f780895e26211f3571203de53614be0117471368834f2bc02685617ceed5a4dbc3eeef2393dd45997b019b9ad1e31ef064db8d6ff234c919d35ae3e884182857efdbbe341770e2ca9bbc735ec89bc41fc68c645df7ba3ef52c3db46853ff4829489b8e36b168fd4daab0c1f43cb94d6c12f8e7809a6cd3702e13d9a6205beecdf461c9edb11f79dab4b904e692bd0cb5bd86cbfa5fac80828b9a45c67fcec45afeebe3b5f942aedf05c65bd1f830e9ffc29988e099897ba3b9d469dfc3c2f6755add12bf28ac00b12134fec11b92cf41d3a7406ba316a0b2f7abba36a95f1f4f2a25ac35faaa2684f5478c000f044bea4bdd3d1dee67aab055c2a0ea110278f02a448df968718c703f86e09317a91316f302b1d29701190aa15c69cc4504b6263725dc382f68d735afbdc0e21ed49a7e3395aec793aa3ffd2ca50ccf9ea37e05ef164103e4ba2d165d34f00882c76c17aea9049bb6cb9a2d9b4b7359b1f0a324b24eab917b678a4870602622228fe2e7016c9033bb01ed816fb5221adf6937731eb598e7936bf610fcec9db7ede8f75c666db052d90fada865875f858dc4258f32e7abbad4be3c1efdf535fe6c0d37e0ef1f8cfc85531e4af69d120f1da14b6e0c8bcad99937a9af0d5801b9f3ce77ebd9941bcfdafc1871267beec6555a3a6079f5d29df7422a91af84507d0a2df86f00458b9aed5ebe54db566de43783d5613de08088e0e913734605caf48c8a2ea78b15c031017d75e12720aaddfef4b717146ca1983a6211dc8e035250248b735002c52dedf3a72b9885a4e72dc4596cc181fe7002fe4e6d0b828b8579133180cb339716c4dff8f18968fe20077924c2f1a86fefd039e0fa7da1aebc11e57e8f202e0f6e5207c5ff95ebb00e80a14c9acc016d9739c3041cecd1df36841433e63136a1663c4d289d1bac09660d09812233649ead3e8d1c7b387a0c7b785d78bc45dd4251ac8527574d9f7c5a2ec10f8defdb57d085dce9688ea24a75ad38449a291a89093fb922eca87b95aeed109956a0af22a8b025689c41298cca50d91ca34c11ea0ea4cbb24ec8e2b9422f75e92146cb5edb4787503f53731688a9dd30215edbef5bfe39a766705ef141ad334c0288b7e604455332398e80e7fd28acc059daab0735d9d03ece6b92b8c06fc8124678f5271b4313058e0a1f117d8cfc1a701c157cf38328997c478da1708302485a1a4eec87c789d6743daf63ec78e3e1673764c16bda594b59ab2f8f4ad776be34321d9b8d1f13f0aab0603d4b761d4fd6ebae12f5ca14d111924ab9b982b05773447547dabfb1d88baae2371133c70a4b02ff129b74eb76fcc5a8c66b45330829147f5a085546fcf9093764908cf892db3f6d3963c70be80d374f3f4e324d0eb5845bfb4fcaba0754abe92b3f6039841309246234645fa10f87a2726b009ee6d45af0fa407fe5d9e0b9a88e37aec550fd62c68f6239127018ba0bf1365990cf5d4a32d629059352fe82daa406e62102d7d925264e88fb5e896e8a17653a355106a10dc043121226e97d0c98595d4392bde82119a8f2647172717d3e5c2803913d09e144c5df030746fd167d6ee8cd4e7cc673e6ab4d6c6ee03c3a9af3b4ee38d8fca4d40b44a58e44660b9174d645e23fd81bc658ee2ed8c68d795beb363eca1a8ccd1d7aa9aea3aa05137e56abd2e4607a5d1992613cf40df7b85e2765d691fc6cb5b7acd4d9c613f36c5acb9bdccbcca0029e282ed0feef2f62646fa5cc27d1fcd0f672209625a2c601850e745061c3e64383c2a6730a832063fab1170d836ea269d13183e16370267eac56efcfcf95b175727e3fa51477ba857fcae9183ce495d0bcbb670bcaca53fdf8b08663d16abce28f631dc3e53473d8d88a52265a5399d2a19f0867f5bb6580c106791cd733fb188a5de53cf7fbd83c691576d697756b2d8c4a3000998e17b09837cdbb010f7b474e7e4bde51526667298e7a8edc2b34a7c9ed1ff2022466a0f3df42ae74cfe0377d221f4291479a6f01c7c91367f991db85a55fa167ea97f3122652c9648f0a4a1066488ac4bb2c4a9efbc81b5c0920ba2ba02d757435c80d44a0688d085c11798168a3abd533a001c9aafd42729c616e2d360ec0d11831c1ca8431f65286e657c6a5608eee5c28015a82065affe9d8029f50b3d3f405927f8e0a28f4c57822fb984fc2cd3444e98b744cba92b0fd3a90ecec1e04a4aea12547e19ed70f2f4c814ec54d8bf6e391c37920790066ce9db766fe93d257a2d4c03afe622d46e0f2da6aa9869abb94b81944cd1b5532c3c09cb73c4f565bdbdeb77739b80ef680b3c1dfb8baf030670178fda11403f450850d3108ffd177352abe677e2c3b093c4c9a2f5dfa0daccf78e669771ed2c87ae17096a656ba142be0f43c4e99fcb0b8955ce192d48c17eaa1f90970bd98b7985e5c3c9e3534bc67409155fcc4082ce6e127dd7a1be4d1fff62207c8a0ab0cbb0ca8ec4125f59fa555dc9fe19c97ed03ca069fc0b19514b21ccabc0ec84d712c2c65cd8c624d1fc6b829bb201367ef9216257e47443eaa9cdaaf68ecce590d2b39d4ec8595ebe02cbbfcaee4bd3c1aca44995ccdc1d230a070762be8c6eb6a47bb23dbec72b3ac097edd2344084a5768f24879eea804d7d3be40040df3759f75047a0f08cfe6c68e0056237dad9c693618b56f686af1476db1d7fe55fb4c3302363e43a28659d55df991b34d671e6d6211cdea112f1419689c5dd2cf156c45934d6307bbf005b63cb1829605c0ebbd055ee85c4632ec8dfd57ae4764841e25a181669d1f98a0e9c458f9f6177577bf0158a705ebdc9980249734164b88a90db3bd5bf2a875481cf04a33cfe85af8d2071575a77fbdcdbe184a4c34573f0b4425d46aa400643183fd8c0920b67a46fa3562c225cbdfe40486480a8e035fcc9bc030cbb73dff0aa8f4247ddfda944e7df0c63e1abd0053bc77834ef11c527bc05d8863ab0670cc2da585ae2d82f114edb73621dd657f87a6ea8f23cec16c13188bdd08a8d228431ef938592b1c155014642fe1ae97c74b5eb16777af4ff2df0ed7663d7ec4e07b944fde6fcdff72efae53ade2f2c989bc3473cd6c8ec18fa1553b204318f1584387de698477aeddf7644cbd244fa6cd3e0fdf81d8d99a00c6d73ec32eb91983f9bf8ab5813e995c132a80d5df71bba0a2918a3df57c031d3fa3123680451bc8f2a74e44a096eba6a03a50d4189ae603e6bc3f3914c76766c56144f7858a9e8f4d651cc8b828fa85f9ce0fa41946a726fade00b3df6e297aa8d2be22990fc75b0304656993c497817e7949fb45a88a840f29d7efece460162b986f138e2d5765536e3a9e9abce7e3d69232f5146e6c0172fe76b11b9a53f4c0172ec5e6cfba8cfe22dbd41924c06ac109fd3f2c253624a60a39101e19140a7cbe18fe35ad2b3c0ce3d0b913298410d172bb450e646bc3d64931df3a44cc4fb913c5f9fc22fe7954c280fd0080820b8fbc197418d6a1db88f4d837608602b1682487786471c89faafddbb97aba42e20a35d00bf57bd0cadc6cb081fe560444663ae10d16c6981acbd23ee90f6c77306b750a90d4a289f761b863dce0e0b4488fcdc5c6d2f3b447e48b1e20e7c3155e88d4667ee973142458d942b521a40b4ea45be62ba4f7a6e9b50404fad1ddca70fd77dd9306816c08a92ffa828772b6bd3d6772b917ab5d1ba7c7da4db9c4263faee8ed20922914bccce950da522c44cd30b25974ace1b33dd5aabdbd9c558c5ebc35042a1a706df5c5f285750f605e05815d025c573d357e03a58387d341c1519a0003467e4f173c5715191bc12dd7375ad54de3467fd1e4fb04eaa254860ac1d1af373bfc0c8b97d62e744d3e741748192c3d3814b0ad94af4aa26feb201007976c4a93e01c585c6a365a13a4b4ad54fd49aa435bd170d9f45ab9d6f9d5859b8e305dec4e42a029a56f04584936777bc2bd89b901861e2c7c3c7adaee75ab13b06f1b81266d56509fd46d97ff47b13c674f03c2f3830bab4f784ae2cce1fda1bb4f9773bc5ec7267f5961fa88994fa99d276c62e665c139714d8a0a188d5380db517765f6b1f7d9b691911dcb6a988263385eb32ad48fb27f94643e6798382fdf74a4317cab1d6de02b25b37d9dfe26c52b7fa2c918637e8c5b2f0da2362eb974d8d3ed72e80c0e9ffd8b1bd73fd589b4f9426951396d8c78daf5209e90250e88316393950441c1c26b487b6339f1a855b97b8a25618f2d93d421cd621bba0cb509a0e03347f0d4a7cc0282b56030c8ff340e5b8bf08c8218eb426e7b1287254ceaea78c414c55e0510f6d4f3c2095b6232182db041a21d63ce04fa1f527a1a6b66a25de273dbd1379c91f45508474587e5155c27825a5ae109b0dfe0aa3f04ded63945f1d3edfe6fce0bd420d1aaa69e1b11c2367170428a30c01c37f8d7fc2fa2555dfa63d56e914d04cbd8fe2f29ea4023b7b886863573f95263a5caaf7ec49bd8750f5fdd242a35e3a8109ee47d96bc59d75205086cf7fb50eb3c24b2e3a1db677ec2591eea0d9b17f3b2eac602e93fb957fdb4fc2edcb6ae116ac84b3dbee25e8b67392bb8cf6cf1d4200043c7283868719290601ad21fafa76da339c0fc938a4744cf9ca2d38970a1e0fe0a54379a25ff0e5daa0e6aad44b7e1d5e2d2b46956cb4cca2e89586e24a1011723fe4ed9821d74a38705deb7b4b589e301c3a676fd31765b145e6b09cba48c088a201f58f701dd667f7f18125bcfbee5dbb78112678af0fbd081d59ea26a8345b7eab740be9ea8a298bd664fa826e07958139b266b0480780e87ec0c515abc93f3174a5d960b36b1c3da6093470438c0715c3bdd791f7dd69a48b678632d4a71bbf55547496027ed48992474cd82f9679a2b3d6511a868dbe57dc4a19936acdff7e6ff366c9dae51dbf73e4a79fd4776d0434c8d80a2dbd6c3308d18adc2dcedb4fb19d3541f6d774a0faee5a196add2bc1dfcda874efe0078945cdff878fac7cb4a4a1e49c11a1012f3c8329d583fbd2daaf19dbcdfb2f0433aad5a7e3d80bb1c80c0869f1fc191f076ec4595a91374e3a88618876317cd278c7000c9e17a18e1da15b6a606eff314671391cdb0701f5b72a48bea74ab0d8b51cbd0c23eb24f4ebaf49b83d4bde19e87697c1351010162e5a815843ef9a1a9d816f4a15c36dfad6a96c1c21ba78042f7f9a27c0aac980cfb65787fbf3e9cf5417f2c9607e0aac25c298f4f546c51c37cef837cdd9134e5706a8ec5d622af4b94174de12f63360aaea11bb1423f80a5538c33eb9adec19ba448511d14019d7dbcd8aa77f9baa2cf30797e2c734dc43cf2f506b95104c6a27b575ae347391de18b7be8227f37361e3ef55d9463753d4d575b26be3b110e78335dc1a01c9957429454404ccb6f4ac6e26009dd01455accb3af7d05123cd07d08cad6a05bb5f3baebcce8553b16285d9996d74e7357cb3838f218ce57b0126f13a5ecc97fc9013414d6ed84a512c75a27e9859554afd67f60a49b8ef81faa122debe59188ee4a2c8b0b3e6d385edb6c856abcde89d11b70be6c82bca707ca923def8f4733e78d4b7827cfd159263e6e03ffe88202e615b4fed711243056e55cd93eefe3f6e4890cab46c50332ea7c4f9b913878e5d79eac79d8d83af2bb6d24aba3b9276e7eafb214bc2e12a42269900db030935a25d8167b96059bba526bde75833252e8dfe9a0d8845f2fb36324ebcf4e1c81d048a5d3be1ad80ea895cda6b4ee0c7f6abb763bec531956532a47387de10da880bd6784c88b2d8b71f2c1060fd451e368b0912d528a60d295813391ffadeda8c2f9ca7d66a352ad2cbb82b5b98b619f885c0f4c8fe43166130610a9815ebb736fc546e8285c268fae949c2205ded1536ddc52805ecea087603cb25c14a8b05382b136292d018b53cf38255f06cf3811076a85b83fb2691e3c30bde8a1e4771e7aeef0efdade15a537c1002e0e5cb6ca4949162a7f834bf13cdba2c72d201f0112025b866ba8a4b0d82ea210a6c462d88ebf1ab1629627735cb7d31784ad01f03c572fa03d5937fd6e8003fcbdd333241656bf984e9bda9a2c8797069ff6a3892f07a6be3b01393823a163ec06833372fc1512f4442e547c1e429513c0647bd2142294b9c546ba7728ef22661779231e81ba2f34a59ace0229fc543126b06a384259864eb89f08c064c44976724863cddf6981d2b12a1288ee03e4e4badb171ddd76617157e72a7608623568e638bed04df7759e3b48e2195b2bcc7795679ad05a0f8ba7b5f70625b5b197965bc4758cac580dc90eb672119f7dd4d1e8012113e2b6f291577a0a68a5a143e10a11c4c7c7a1b954ab98e0e69dc001aba86436dacb3689126da4c00620933104974ee8fd01ce75c437f06a6a1df6e6624e37110411747710556cdc4d1d9f9662f1943c902e2ee7c109d0bae3a94830fae58b9631b295535e81c01ba56d193e7ebae1fe7049ef6b5b4c9564d5bc8f45ff8ef96b109f79d5ffcd1439c42199d1ea01082cff22c9c14f9e49a9e875f1766d357289c5d61d12de7007ddb6f2c950519fe0a250769d50baa0b0ade35383b6f4d101da91aa46fc5bf69e73925b7d7d5f53a95cb8c1f5a3f61181317ffdf5f8fca0e1eafe925c7f4b209281af81326f20badc94765173b4f03df5c91f7daf192e8b5236b98524b2dbc69eb0a810587c2353718f1e129f664ef896dca8f931b3ee02a498556b949cde6e919dd9881916570b2895402f35aa56f6b14c8ee06509650078ea3d5e5abd96c506bf58dd47ebb9379272c16964e867904ca46865c07a7a8a7ede4a278c512befad803b4bc0701b853367ee7384b33e2b972af906d89e1ce62204a69d7950a0f6592990c4c2bbf272c3f1719cc6f9d62e53ee76b13bf595f9f07ec157ea63d933acdda46e691fcacaee6c273f91e4510e5ad99773b9f12bb56e1b0638"),
}

var testPrunedTransactionsData = map[types.Hash][]byte{
	types.MustHashFromString("332691761f1ded0d74c80b223a7266f3568f472fe67f33f97d8390a48d9caa29"): hex.MustDecodeString("020001020000b65762072a662ba06b824df7760058d402d3a426a8dbf11742c9d82137b6311902000018ba991d09a78989e88b02b2df90460cf700d6f39147c5233e68cb46c9a61fd1c6666f311724a9b5153451d88ae1276879f19f0000d28936e3c6a730611bdb572a72240f0b4dc2cbdfcb7561b83bb443d2d266445e7bb96a41819f77e51753738ac307f1b4e37a632c0199d114866dad14fb3c588dcc7af2faf4cfd724b14fa44cc1cd34711475c55b6f02090119153b63e850521e07e0eb95a304342d86ef67c633d1006d543fa35ef12a680b696eeadbbc43e4099776a017d92c7570837895c0ba7cb40290747dc56e4604e1a5b553da4b63e29308132e52408d1dd64e7b2c47378e685fc6d5fff6cc0e"),
}
