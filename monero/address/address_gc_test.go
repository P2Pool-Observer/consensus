//go:build gc && !tinygo

package address

import (
	"sync/atomic"
	"testing"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
)

func BenchmarkGetEphemeralPublicKey(b *testing.B) {
	b.ReportAllocs()
	txKey := privateKey
	var i atomic.Uint64

	spendPub, _ := new(curve25519.PublicKey[curve25519.VarTimeCounterOperations]).SetBytes(testAddress3.SpendPublicKey()[:])
	viewPub, _ := new(curve25519.PublicKey[curve25519.VarTimeCounterOperations]).SetBytes(testAddress3.ViewPublicKey()[:])

	curve25519.VarTimeCounterOperationsReset()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		var out curve25519.PublicKey[curve25519.VarTimeCounterOperations]
		for pb.Next() {
			GetEphemeralPublicKey(&out, spendPub, viewPub, txKey, i.Add(1))
		}
	})

	b.StopTimer()
	curve25519.VarTimeCounterOperationsReport(b.N, b.ReportMetric)
}

func BenchmarkGetEphemeralPublicKeyAndViewTag(b *testing.B) {
	b.ReportAllocs()
	txKey := privateKey
	var i atomic.Uint64

	spendPub, _ := new(curve25519.PublicKey[curve25519.VarTimeCounterOperations]).SetBytes(testAddress3.SpendPublicKey()[:])
	viewPub, _ := new(curve25519.PublicKey[curve25519.VarTimeCounterOperations]).SetBytes(testAddress3.ViewPublicKey()[:])

	curve25519.VarTimeCounterOperationsReset()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		var out curve25519.PublicKey[curve25519.VarTimeCounterOperations]
		for pb.Next() {
			GetEphemeralPublicKeyAndViewTag(&out, spendPub, viewPub, txKey, i.Add(1))
		}
	})

	b.StopTimer()
	curve25519.VarTimeCounterOperationsReport(b.N, b.ReportMetric)
}
