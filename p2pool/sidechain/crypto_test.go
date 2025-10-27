package sidechain

import (
	"encoding/hex"
	"os"
	"path"
	"runtime"
	"strings"
	"testing"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	fasthex "github.com/tmthrgd/go-hex"
)

func TestDeterministicTransactionPrivateKey(t *testing.T) {
	expectedPrivateKey := "c93cbd34c66ba4d5b3ddcccd3f550a0169e02225c8d045bc6418dbca4819260b"

	previousId, _ := types.HashFromString("b64ec18bf2dfa4658693d7f35836d212e66dee47af6f7263ab2bf00e422bcd68")
	publicSpendKeyBytes, _ := fasthex.DecodeString("f2be6705a034f8f485ee9bc3c21b6309cd0d9dd2111441cc32753ba2bac41b6d")
	p, _ := (&curve25519.Point{}).SetBytes(publicSpendKeyBytes)
	spendPublicKey := curve25519.FromPoint[curve25519.VarTimeOperations](p)

	calculatedPrivateKey := GetDeterministicTransactionPrivateKey(new(curve25519.Scalar), types.Hash(spendPublicKey.Bytes()), previousId)
	if hex.EncodeToString(calculatedPrivateKey.Bytes()) != expectedPrivateKey {
		t.Fatalf("got %x, expected %s", calculatedPrivateKey.Bytes(), expectedPrivateKey)
	}
}

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
	buf, err := os.ReadFile("testdata/v2_crypto_tests.txt")
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

func TestGetTxKeys(t *testing.T) {
	results := GetTestEntries("get_tx_keys", 4)
	if results == nil {
		t.Fatal()
	}
	for e := range results {
		walletSpendKey := types.MustHashFromString(e[0])
		moneroBlockId := types.MustHashFromString(e[1])
		expectedPublicKey := types.MustHashFromString(e[2])
		expectedSecretKey := types.MustHashFromString(e[3])

		privateKey := GetDeterministicTransactionPrivateKey(new(curve25519.Scalar), walletSpendKey, moneroBlockId)
		publicKey := new(curve25519.VarTimePublicKey).ScalarBaseMult(privateKey)

		if expectedSecretKey.String() != hex.EncodeToString(privateKey.Bytes()) {
			t.Fatalf("expected %s, got %x", expectedSecretKey.String(), privateKey.Bytes())
		}
		if expectedPublicKey.String() != publicKey.String() {
			t.Fatalf("expected %s, got %s", expectedPublicKey.String(), publicKey.String())
		}
	}
}
