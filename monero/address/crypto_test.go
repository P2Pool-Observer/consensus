package address

import (
	"os"
	"path"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
)

func init() {
	_, filename, _, _ := runtime.Caller(0)
	// The ".." may change depending on you folder structure
	dir := path.Join(path.Dir(filename), "../..")
	err := os.Chdir(dir)
	if err != nil {
		panic(err)
	}

}

func GetTestEntries(name string, n int) chan []string {
	buf, err := os.ReadFile("testdata/monero_crypto_tests.txt")
	if err != nil {
		return nil
	}
	result := make(chan []string)
	go func() {
		defer close(result)
		for _, line := range strings.Split(string(buf), "\n") {
			entries := strings.Split(strings.TrimSpace(line), " ")
			if entries[0] == name && len(entries) >= (n+1) {
				result <- entries[1:]
			}
		}
	}()
	return result
}

func TestDerivePublicKey(t *testing.T) {
	results := GetTestEntries("derive_public_key", 4)
	if results == nil {
		t.Fatal()
	}

	for e := range results {
		var expectedDerivedKey types.Hash

		derivation := curve25519.PublicKeyBytes(types.MustHashFromString(e[0]))
		outputIndex, _ := strconv.ParseUint(e[1], 10, 0)

		base := curve25519.PublicKeyBytes(types.MustHashFromString(e[2]))

		result := e[3] == "true"
		if result {
			expectedDerivedKey = types.MustHashFromString(e[4])
		}

		point2 := curve25519.DecodeCompressedPoint(new(curve25519.VarTimePublicKey), base)

		if result == false && point2 == nil {
			//expected failure
			continue
		} else if point2 == nil {
			t.Errorf("invalid point %s / %s", derivation.String(), base.String())
			continue
		}

		sharedData := crypto.GetDerivationSharedDataForOutputIndex(new(curve25519.Scalar), derivation, outputIndex)

		var sharedData2 curve25519.Scalar
		_ = crypto.GetDerivationSharedDataAndViewTagForOutputIndexNoAllocate(&sharedData2, derivation, outputIndex)

		if curve25519.PrivateKeyBytes(sharedData.Bytes()) != curve25519.PrivateKeyBytes(sharedData2.Bytes()) {
			t.Errorf("derive_public_key differs from no_allocate: %x != %x", sharedData.Bytes(), sharedData2.Bytes())
		}

		derivedKey := GetPublicKeyForSharedData(point2, sharedData)

		derivedKey2, _ := GetEphemeralPublicKeyAndViewTagNoAllocate(point2.P(), derivation, outputIndex)

		if derivedKey.Bytes() != derivedKey2 {
			t.Errorf("derive_public_key differs from no_allocate: %s != %s", derivedKey, &derivedKey2)
		}

		if result {
			if expectedDerivedKey.String() != derivedKey.String() {
				t.Errorf("expected %s, got %s", expectedDerivedKey.String(), derivedKey.String())
			}
		}
	}
}

func TestDeriveSecretKey(t *testing.T) {
	results := GetTestEntries("derive_secret_key", 4)
	if results == nil {
		t.Fatal()
	}

	for e := range results {
		var expectedDerivedKey curve25519.PrivateKeyBytes

		derivation := curve25519.PublicKeyBytes(types.MustHashFromString(e[0]))
		outputIndex, _ := strconv.ParseUint(e[1], 10, 0)

		base := curve25519.PrivateKeyBytes(types.MustHashFromString(e[2]))

		result := e[3] == "true"
		if result {
			expectedDerivedKey = curve25519.PrivateKeyBytes(types.MustHashFromString(e[4]))
		}

		scalar := base.Scalar()

		if result == false && scalar == nil {
			//expected failure
			continue
		} else if scalar == nil {
			t.Errorf("invalid scalar %s / %s", derivation.String(), base.String())
			continue
		}

		sharedData := crypto.GetDerivationSharedDataForOutputIndex(new(curve25519.Scalar), derivation, outputIndex)

		var sharedData2 curve25519.Scalar
		_ = crypto.GetDerivationSharedDataAndViewTagForOutputIndexNoAllocate(&sharedData2, derivation, outputIndex)

		if curve25519.PrivateKeyBytes(sharedData.Bytes()) != curve25519.PrivateKeyBytes(sharedData2.Bytes()) {
			t.Errorf("derive_secret_key differs from no_allocate: %x != %x", sharedData.Bytes(), sharedData2.Bytes())
		}

		derivedKey := GetPrivateKeyForSharedData(scalar, sharedData)

		if result {
			if expectedDerivedKey != curve25519.PrivateKeyBytes(derivedKey.Bytes()) {
				t.Errorf("expected %s, got %x", expectedDerivedKey.String(), derivedKey.Bytes())
			}
		}
	}
}

func TestGenerateKeyDerivation(t *testing.T) {
	results := GetTestEntries("generate_key_derivation", 3)
	if results == nil {
		t.Fatal()
	}
	for e := range results {
		var expectedDerivation types.Hash

		key1 := curve25519.PublicKeyBytes(types.MustHashFromString(e[0]))
		key2 := curve25519.PrivateKeyBytes(types.MustHashFromString(e[1]))
		result := e[2] == "true"
		if result {
			expectedDerivation = types.MustHashFromString(e[3])
		}

		point := key1.Point()
		scalar := key2.Scalar()

		if result == false && (point == nil || scalar == nil) {
			//expected failure
			continue
		} else if point == nil || scalar == nil {
			t.Errorf("invalid point %s / scalar %s", key1.String(), key2.String())
			continue
		}

		derivation := GetDerivation(new(curve25519.ConstantTimePublicKey), point, scalar)
		if result {
			if expectedDerivation.String() != derivation.String() {
				t.Errorf("expected %s, got %s", expectedDerivation.String(), derivation.String())
			}
		}
	}
}

var testThrowawayAddress = FromBase58("42ecNLuoGtn1qC9SPSD9FPMNfsv35RE66Eu8WJJtyEHKfEsEiALVVp7GBCeAYFb7PHcSZmz9sDUtRMnKk2as1KfuLuTQJ3i")
var signatureMessage = []byte("test_message")
var signatureMessage2 = []byte("test_message2")

const (
	SignatureSpendSuccess      = "SigV2DnQYF11xZ1ahLJxddohCroiEJRnUe1tgwD5ksmFMzQ9NcRdbxLPrEdQW3e8w4sLpqhSup5tU9igQqeAR8j7r7Sty"
	SignatureSpendWrongMessage = "SigV26RKRd31efizGHrWHwtYG6EN2MmwvF1rjU4ygZQuDmSxvCJnky1GJTzaM49naQeKvXbaGcnpZ1b3k8gVQLaFMFiBJ"
	SignatureViewSuccess       = "SigV2b7LaAuXrFvPAXwU11SJwHbcXJoKfQ5aBJ9FwMJNxvMTu78AebqNUCWPH1BVfNRvy1f3GCTLjHfWvuRJMZtSHu5uj"
	SignatureViewWrongMessage  = "SigV2AxWUATswZvnHSR5mMRsn9GcJe2gSCv3SbFwHv6J8THkj5KvmR8gUnTidHovZVyxgNHcUuiunM2dfVhbZvBTS6sZZ"
)

func TestSignature(t *testing.T) {
	result := VerifyMessage(testThrowawayAddress, signatureMessage, SignatureSpendSuccess)
	if result != ResultSuccessSpend {
		t.Fatalf("unexpected %d", result)
	}
	result = VerifyMessage(testThrowawayAddress, signatureMessage, SignatureSpendWrongMessage)
	if result != ResultFail {
		t.Fatalf("unexpected %d", result)
	}
	result = VerifyMessage(testThrowawayAddress, signatureMessage2, SignatureSpendSuccess)
	if result != ResultFail {
		t.Fatalf("unexpected %d", result)
	}
	result = VerifyMessage(testThrowawayAddress, signatureMessage, SignatureViewSuccess)
	if result != ResultFailZeroSpend {
		t.Fatalf("unexpected %d", result)
	}
	result = VerifyMessage(testThrowawayAddress, signatureMessage, SignatureViewWrongMessage)
	if result != ResultFail {
		t.Fatalf("unexpected %d", result)
	}
	result = VerifyMessage(testThrowawayAddress, signatureMessage2, SignatureViewSuccess)
	if result != ResultFail {
		t.Fatalf("unexpected %d", result)
	}
	result = VerifyMessage(&ZeroPrivateKeyAddress, signatureMessage, SignatureViewSuccess)
	if result != ResultFail {
		t.Fatalf("unexpected %d", result)
	}
}
