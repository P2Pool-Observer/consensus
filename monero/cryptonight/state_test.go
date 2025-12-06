package cryptonight

import (
	"fmt"
	"testing"

	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	"github.com/tmthrgd/go-hex"
)

type testVector struct {
	Variant int
	Input   []byte
	Output  types.Hash
}

var testVectors = []testVector{
	// Variant 0

	// From CNS008
	{Variant: 0, Input: []byte(""), Output: types.MustHashFromString("eb14e8a833fac6fe9a43b57b336789c46ffe93f2868452240720607b14387e11")},
	{Variant: 0, Input: []byte("This is a test"), Output: types.MustHashFromString("a084f01d1437a09c6985401b60d43554ae105802c5f5d8a9b3253649c0be6605")},

	// Monero tests-slow.txt
	{Variant: 0, Input: []byte("de omnibus dubitandum"), Output: types.MustHashFromString("2f8e3df40bd11f9ac90c743ca8e32bb391da4fb98612aa3b6cdc639ee00b31f5")},
	{Variant: 0, Input: []byte("abundans cautela non nocet"), Output: types.MustHashFromString("722fa8ccd594d40e4a41f3822734304c8d5eff7e1b528408e2229da38ba553c4")},
	{Variant: 0, Input: []byte("caveat emptor"), Output: types.MustHashFromString("bbec2cacf69866a8e740380fe7b818fc78f8571221742d729d9d02d7f8989b87")},
	{Variant: 0, Input: []byte("ex nihilo nihil fit"), Output: types.MustHashFromString("b1257de4efc5ce28c6b40ceb1c6c8f812a64634eb3e81c5220bee9b2b76a6f05")},

	// Variant 1

	// Monero tests-slow-1.txt
	{Variant: 1, Input: hex.MustDecodeString("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000"), Output: types.MustHashFromString("b5a7f63abb94d07d1a6445c36c07c7e8327fe61b1647e391b4c7edae5de57a3d")},
	{Variant: 1, Input: hex.MustDecodeString("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"), Output: types.MustHashFromString("80563c40ed46575a9e44820d93ee095e2851aa22483fd67837118c6cd951ba61")},
	{Variant: 1, Input: hex.MustDecodeString("8519e039172b0d70e5ca7b3383d6b3167315a422747b73f019cf9528f0fde341fd0f2a63030ba6450525cf6de31837669af6f1df8131faf50aaab8d3a7405589"), Output: types.MustHashFromString("5bb40c5880cef2f739bdb6aaaf16161eaae55530e7b10d7ea996b751a299e949")},
	{Variant: 1, Input: hex.MustDecodeString("37a636d7dafdf259b7287eddca2f58099e98619d2f99bdb8969d7b14498102cc065201c8be90bd777323f449848b215d2977c92c4c1c2da36ab46b2e389689ed97c18fec08cd3b03235c5e4c62a37ad88c7b67932495a71090e85dd4020a9300"), Output: types.MustHashFromString("613e638505ba1fd05f428d5c9f8e08f8165614342dac419adc6a47dce257eb3e")},
	{Variant: 1, Input: hex.MustDecodeString("38274c97c45a172cfc97679870422e3a1ab0784960c60514d816271415c306ee3a3ed1a77e31f6a885c3cb"), Output: types.MustHashFromString("ed082e49dbd5bbe34a3726a0d1dad981146062b39d36d62c71eb1ed8ab49459b")},

	// extra
	{Variant: 1, Input: hex.MustDecodeString("e5ad98e59ca8e8a8bce6988ee38292e38081e38193e381aee682b2e9b3b4e38292e38081e68896e38184e381afe6ad8ce38292"), Output: types.MustHashFromString("24aa73ab3b1e74bf119b31c62470e5cf29dde98c9a8af33ac243d3103ebca0e5")},

	// Variant 2

	// Monero tests-slow-2.txt
	{Variant: 2, Input: hex.MustDecodeString("5468697320697320612074657374205468697320697320612074657374205468697320697320612074657374"), Output: types.MustHashFromString("353fdc068fd47b03c04b9431e005e00b68c2168a3cc7335c8b9b308156591a4f")},
	{Variant: 2, Input: hex.MustDecodeString("4c6f72656d20697073756d20646f6c6f722073697420616d65742c20636f6e73656374657475722061646970697363696e67"), Output: types.MustHashFromString("72f134fc50880c330fe65a2cb7896d59b2e708a0221c6a9da3f69b3a702d8682")},
	{Variant: 2, Input: hex.MustDecodeString("656c69742c2073656420646f20656975736d6f642074656d706f7220696e6369646964756e74207574206c61626f7265"), Output: types.MustHashFromString("410919660ec540fc49d8695ff01f974226a2a28dbbac82949c12f541b9a62d2f")},
	{Variant: 2, Input: hex.MustDecodeString("657420646f6c6f7265206d61676e6120616c697175612e20557420656e696d206164206d696e696d2076656e69616d2c"), Output: types.MustHashFromString("4472fecfeb371e8b7942ce0378c0ba5e6d0c6361b669c587807365c787ae652d")},
	{Variant: 2, Input: hex.MustDecodeString("71756973206e6f737472756420657865726369746174696f6e20756c6c616d636f206c61626f726973206e697369"), Output: types.MustHashFromString("577568395203f1f1225f2982b637f7d5e61b47a0f546ba16d46020b471b74076")},
	{Variant: 2, Input: hex.MustDecodeString("757420616c697175697020657820656120636f6d6d6f646f20636f6e7365717561742e20447569732061757465"), Output: types.MustHashFromString("f6fd7efe95a5c6c4bb46d9b429e3faf65b1ce439e116742d42b928e61de52385")},
	{Variant: 2, Input: hex.MustDecodeString("697275726520646f6c6f7220696e20726570726568656e646572697420696e20766f6c7570746174652076656c6974"), Output: types.MustHashFromString("422f8cfe8060cf6c3d9fd66f68e3c9977adb683aea2788029308bbe9bc50d728")},
	{Variant: 2, Input: hex.MustDecodeString("657373652063696c6c756d20646f6c6f726520657520667567696174206e756c6c612070617269617475722e"), Output: types.MustHashFromString("512e62c8c8c833cfbd9d361442cb00d63c0a3fd8964cfd2fedc17c7c25ec2d4b")},
	{Variant: 2, Input: hex.MustDecodeString("4578636570746575722073696e74206f6363616563617420637570696461746174206e6f6e2070726f6964656e742c"), Output: types.MustHashFromString("12a794c1aa13d561c9c6111cee631ca9d0a321718d67d3416add9de1693ba41e")},
	{Variant: 2, Input: hex.MustDecodeString("73756e7420696e2063756c706120717569206f666669636961206465736572756e74206d6f6c6c697420616e696d20696420657374206c61626f72756d2e"), Output: types.MustHashFromString("2659ff95fc74b6215c1dc741e85b7a9710101b30620212f80eb59c3c55993f9d")},
}

func TestSum(t *testing.T) {

	for _, v := range testVectors {
		t.Run(fmt.Sprintf("V%d/%x..._%d", v.Variant, v.Input[:min(len(v.Input), 8)], len(v.Input)), func(t *testing.T) {
			var state State
			result := state.Sum(v.Input, v.Variant, false)
			if result != v.Output {
				t.Errorf("Sum(%s) = %x, want %x", string(v.Input), result.Slice(), v.Output.Slice())
			}
		})
	}
}
