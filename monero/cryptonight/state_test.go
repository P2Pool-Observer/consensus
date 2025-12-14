package cryptonight

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"testing"

	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	"git.gammaspectra.live/P2Pool/go-hex"
)

type testVector struct {
	Variant Variant
	Input   []byte
	Height  uint64
	Output  types.Hash
}

var testVectors = []testVector{
	// Variant 0

	// From CNS008
	{Variant: V0, Input: []byte(""), Output: types.MustHashFromString("eb14e8a833fac6fe9a43b57b336789c46ffe93f2868452240720607b14387e11")},
	{Variant: V0, Input: []byte("This is a test"), Output: types.MustHashFromString("a084f01d1437a09c6985401b60d43554ae105802c5f5d8a9b3253649c0be6605")},

	// Monero tests-slow.txt
	{Variant: V0, Input: []byte("de omnibus dubitandum"), Output: types.MustHashFromString("2f8e3df40bd11f9ac90c743ca8e32bb391da4fb98612aa3b6cdc639ee00b31f5")},
	{Variant: V0, Input: []byte("abundans cautela non nocet"), Output: types.MustHashFromString("722fa8ccd594d40e4a41f3822734304c8d5eff7e1b528408e2229da38ba553c4")},
	{Variant: V0, Input: []byte("caveat emptor"), Output: types.MustHashFromString("bbec2cacf69866a8e740380fe7b818fc78f8571221742d729d9d02d7f8989b87")},
	{Variant: V0, Input: []byte("ex nihilo nihil fit"), Output: types.MustHashFromString("b1257de4efc5ce28c6b40ceb1c6c8f812a64634eb3e81c5220bee9b2b76a6f05")},

	// Variant 1

	// Monero tests-slow-1.txt
	{Variant: V1, Input: hex.MustDecodeString("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000"), Output: types.MustHashFromString("b5a7f63abb94d07d1a6445c36c07c7e8327fe61b1647e391b4c7edae5de57a3d")},
	{Variant: V1, Input: hex.MustDecodeString("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"), Output: types.MustHashFromString("80563c40ed46575a9e44820d93ee095e2851aa22483fd67837118c6cd951ba61")},
	{Variant: V1, Input: hex.MustDecodeString("8519e039172b0d70e5ca7b3383d6b3167315a422747b73f019cf9528f0fde341fd0f2a63030ba6450525cf6de31837669af6f1df8131faf50aaab8d3a7405589"), Output: types.MustHashFromString("5bb40c5880cef2f739bdb6aaaf16161eaae55530e7b10d7ea996b751a299e949")},
	{Variant: V1, Input: hex.MustDecodeString("37a636d7dafdf259b7287eddca2f58099e98619d2f99bdb8969d7b14498102cc065201c8be90bd777323f449848b215d2977c92c4c1c2da36ab46b2e389689ed97c18fec08cd3b03235c5e4c62a37ad88c7b67932495a71090e85dd4020a9300"), Output: types.MustHashFromString("613e638505ba1fd05f428d5c9f8e08f8165614342dac419adc6a47dce257eb3e")},
	{Variant: V1, Input: hex.MustDecodeString("38274c97c45a172cfc97679870422e3a1ab0784960c60514d816271415c306ee3a3ed1a77e31f6a885c3cb"), Output: types.MustHashFromString("ed082e49dbd5bbe34a3726a0d1dad981146062b39d36d62c71eb1ed8ab49459b")},

	// extra
	{Variant: V1, Input: hex.MustDecodeString("e5ad98e59ca8e8a8bce6988ee38292e38081e38193e381aee682b2e9b3b4e38292e38081e68896e38184e381afe6ad8ce38292"), Output: types.MustHashFromString("24aa73ab3b1e74bf119b31c62470e5cf29dde98c9a8af33ac243d3103ebca0e5")},

	// Variant 2

	// Monero tests-slow-2.txt
	{Variant: V2, Input: hex.MustDecodeString("5468697320697320612074657374205468697320697320612074657374205468697320697320612074657374"), Output: types.MustHashFromString("353fdc068fd47b03c04b9431e005e00b68c2168a3cc7335c8b9b308156591a4f")},
	{Variant: V2, Input: hex.MustDecodeString("4c6f72656d20697073756d20646f6c6f722073697420616d65742c20636f6e73656374657475722061646970697363696e67"), Output: types.MustHashFromString("72f134fc50880c330fe65a2cb7896d59b2e708a0221c6a9da3f69b3a702d8682")},
	{Variant: V2, Input: hex.MustDecodeString("656c69742c2073656420646f20656975736d6f642074656d706f7220696e6369646964756e74207574206c61626f7265"), Output: types.MustHashFromString("410919660ec540fc49d8695ff01f974226a2a28dbbac82949c12f541b9a62d2f")},
	{Variant: V2, Input: hex.MustDecodeString("657420646f6c6f7265206d61676e6120616c697175612e20557420656e696d206164206d696e696d2076656e69616d2c"), Output: types.MustHashFromString("4472fecfeb371e8b7942ce0378c0ba5e6d0c6361b669c587807365c787ae652d")},
	{Variant: V2, Input: hex.MustDecodeString("71756973206e6f737472756420657865726369746174696f6e20756c6c616d636f206c61626f726973206e697369"), Output: types.MustHashFromString("577568395203f1f1225f2982b637f7d5e61b47a0f546ba16d46020b471b74076")},
	{Variant: V2, Input: hex.MustDecodeString("757420616c697175697020657820656120636f6d6d6f646f20636f6e7365717561742e20447569732061757465"), Output: types.MustHashFromString("f6fd7efe95a5c6c4bb46d9b429e3faf65b1ce439e116742d42b928e61de52385")},
	{Variant: V2, Input: hex.MustDecodeString("697275726520646f6c6f7220696e20726570726568656e646572697420696e20766f6c7570746174652076656c6974"), Output: types.MustHashFromString("422f8cfe8060cf6c3d9fd66f68e3c9977adb683aea2788029308bbe9bc50d728")},
	{Variant: V2, Input: hex.MustDecodeString("657373652063696c6c756d20646f6c6f726520657520667567696174206e756c6c612070617269617475722e"), Output: types.MustHashFromString("512e62c8c8c833cfbd9d361442cb00d63c0a3fd8964cfd2fedc17c7c25ec2d4b")},
	{Variant: V2, Input: hex.MustDecodeString("4578636570746575722073696e74206f6363616563617420637570696461746174206e6f6e2070726f6964656e742c"), Output: types.MustHashFromString("12a794c1aa13d561c9c6111cee631ca9d0a321718d67d3416add9de1693ba41e")},
	{Variant: V2, Input: hex.MustDecodeString("73756e7420696e2063756c706120717569206f666669636961206465736572756e74206d6f6c6c697420616e696d20696420657374206c61626f72756d2e"), Output: types.MustHashFromString("2659ff95fc74b6215c1dc741e85b7a9710101b30620212f80eb59c3c55993f9d")},

	// Variant R

	// Monero tests-slow-4.txt
	{Variant: R, Height: 1806260, Input: hex.MustDecodeString("5468697320697320612074657374205468697320697320612074657374205468697320697320612074657374"), Output: types.MustHashFromString("f759588ad57e758467295443a9bd71490abff8e9dad1b95b6bf2f5d0d78387bc")},
	{Variant: R, Height: 1806261, Input: hex.MustDecodeString("4c6f72656d20697073756d20646f6c6f722073697420616d65742c20636f6e73656374657475722061646970697363696e67"), Output: types.MustHashFromString("5bb833deca2bdd7252a9ccd7b4ce0b6a4854515794b56c207262f7a5b9bdb566")},
	{Variant: R, Height: 1806262, Input: hex.MustDecodeString("656c69742c2073656420646f20656975736d6f642074656d706f7220696e6369646964756e74207574206c61626f7265"), Output: types.MustHashFromString("1ee6728da60fbd8d7d55b2b1ade487a3cf52a2c3ac6f520db12c27d8921f6cab")},
	{Variant: R, Height: 1806263, Input: hex.MustDecodeString("657420646f6c6f7265206d61676e6120616c697175612e20557420656e696d206164206d696e696d2076656e69616d2c"), Output: types.MustHashFromString("6969fe2ddfb758438d48049f302fc2108a4fcc93e37669170e6db4b0b9b4c4cb")},
	{Variant: R, Height: 1806264, Input: hex.MustDecodeString("71756973206e6f737472756420657865726369746174696f6e20756c6c616d636f206c61626f726973206e697369"), Output: types.MustHashFromString("7f3048b4e90d0cbe7a57c0394f37338a01fae3adfdc0e5126d863a895eb04e02")},
	{Variant: R, Height: 1806265, Input: hex.MustDecodeString("757420616c697175697020657820656120636f6d6d6f646f20636f6e7365717561742e20447569732061757465"), Output: types.MustHashFromString("1d290443a4b542af04a82f6b2494a6ee7f20f2754c58e0849032483a56e8e2ef")},
	{Variant: R, Height: 1806266, Input: hex.MustDecodeString("697275726520646f6c6f7220696e20726570726568656e646572697420696e20766f6c7570746174652076656c6974"), Output: types.MustHashFromString("c43cc6567436a86afbd6aa9eaa7c276e9806830334b614b2bee23cc76634f6fd")},
	{Variant: R, Height: 1806267, Input: hex.MustDecodeString("657373652063696c6c756d20646f6c6f726520657520667567696174206e756c6c612070617269617475722e"), Output: types.MustHashFromString("87be2479c0c4e8edfdfaa5603e93f4265b3f8224c1c5946feb424819d18990a4")},
	{Variant: R, Height: 1806268, Input: hex.MustDecodeString("4578636570746575722073696e74206f6363616563617420637570696461746174206e6f6e2070726f6964656e742c"), Output: types.MustHashFromString("dd9d6a6d8e47465cceac0877ef889b93e7eba979557e3935d7f86dce11b070f3")},
	{Variant: R, Height: 1806269, Input: hex.MustDecodeString("73756e7420696e2063756c706120717569206f666669636961206465736572756e74206d6f6c6c697420616e696d20696420657374206c61626f72756d2e"), Output: types.MustHashFromString("75c6f2ae49a20521de97285b431e717125847fb8935ed84a61e7f8d36a2c3d8e")},
}

func TestSum(t *testing.T) {

	for _, v := range testVectors {
		t.Run(fmt.Sprintf("V%d/%x..._%d", v.Variant, v.Input[:min(len(v.Input), 8)], len(v.Input)), func(t *testing.T) {
			var state State
			if v.Height > 0 && v.Variant == R {
				result := state.SumR(v.Input, v.Height, false)
				if result != v.Output {
					t.Errorf("SumR(...) = %x, want %x", result.Slice(), v.Output.Slice())
				}
			} else {
				result := state.Sum(v.Input, v.Variant, false)
				if result != v.Output {
					t.Errorf("Sum(...) = %x, want %x", result.Slice(), v.Output.Slice())
				}
			}
		})
	}
}

func BenchmarkSum(b *testing.B) {
	for _, variant := range []Variant{V0, V1, V2, R} {
		b.Run(fmt.Sprintf("V%d", variant), func(b *testing.B) {
			b.ReportAllocs()

			var state State

			var input [64]byte
			_, _ = rand.Read(input[:])

			var iterations uint64
			if variant == R {
				for b.Loop() {
					binary.LittleEndian.PutUint64(input[35:], iterations)
					iterations++
					state.SumR(input[:], iterations, false)
				}
			} else {
				for b.Loop() {
					binary.LittleEndian.PutUint64(input[35:], iterations)
					iterations++
					state.Sum(input[:], variant, false)
				}
			}
		})
	}
}
