package types

import (
	"runtime"
	"testing"
)

var (
	powHash             = MustHashFromString("abcf2c2ee4a64a683f24bedb2099dd16ae08c03a1ecc1208bf93a90200000000")
	sidechainDifficulty = DifficultyFrom64(2062136440)
	powDifficulty       = DifficultyFrom64(412975968250)
	moneroDifficulty    = DifficultyFrom64(229654626174)
)

func TestDifficultyFromPoW(t *testing.T) {
	diff := DifficultyFromPoW(powHash)

	if !diff.Equals(powDifficulty) {
		t.Errorf("%s does not equal %s", diff, powDifficulty)
	}
}

func TestDifficulty_CheckPoW(t *testing.T) {

	if !moneroDifficulty.CheckPoW(powHash) {
		t.Errorf("%s does not pass PoW %s", powHash, moneroDifficulty)
	}

	if !sidechainDifficulty.CheckPoW(powHash) {
		t.Errorf("%s does not pass PoW %s", powHash, sidechainDifficulty)
	}

	if !powDifficulty.CheckPoW(powHash) {
		t.Errorf("%s does not pass PoW %s", powHash, powDifficulty)
	}

	powHash2 := powHash
	powHash2[len(powHash2)-1]++

	if moneroDifficulty.CheckPoW(powHash2) {
		t.Errorf("%s does pass PoW %s incorrectly", powHash2, moneroDifficulty)
	}

	if sidechainDifficulty.CheckPoW(powHash2) {
		t.Errorf("%s does pass PoW %s incorrectly", powHash2, sidechainDifficulty)
	}

	powHash3 := powHash
	powHash3[len(powHash2)-9]++

	if powDifficulty.CheckPoW(powHash3) {
		t.Errorf("%s does pass PoW %s incorrectly", powHash3, powDifficulty)
	}
}

func TestDifficulty_CheckPoW_Native(t *testing.T) {

	if !moneroDifficulty.CheckPoW_Native(powHash) {
		t.Errorf("%s does not pass PoW %s", powHash, moneroDifficulty)
	}

	if !sidechainDifficulty.CheckPoW_Native(powHash) {
		t.Errorf("%s does not pass PoW %s", powHash, sidechainDifficulty)
	}

	if !powDifficulty.CheckPoW_Native(powHash) {
		t.Errorf("%s does not pass PoW %s", powHash, powDifficulty)
	}

	powHash2 := powHash
	powHash2[len(powHash2)-1]++

	if moneroDifficulty.CheckPoW_Native(powHash2) {
		t.Errorf("%s does pass PoW %s incorrectly", powHash2, moneroDifficulty)
	}

	if sidechainDifficulty.CheckPoW_Native(powHash2) {
		t.Errorf("%s does pass PoW %s incorrectly", powHash2, sidechainDifficulty)
	}

	powHash3 := powHash
	powHash3[len(powHash2)-9]++

	if powDifficulty.CheckPoW_Native(powHash3) {
		t.Errorf("%s does pass PoW %s incorrectly", powHash3, powDifficulty)
	}
}

func BenchmarkDifficulty_CheckPoW(b *testing.B) {

	b.Run("Uint128", func(b *testing.B) {
		b.ReportAllocs()
		var result bool
		for b.Loop() {
			result = moneroDifficulty.CheckPoW(powHash)
		}
		runtime.KeepAlive(result)
	})

	b.Run("Native", func(b *testing.B) {
		b.ReportAllocs()
		var result bool
		for b.Loop() {
			result = moneroDifficulty.CheckPoW_Native(powHash)
		}
		runtime.KeepAlive(result)
	})
}

func FuzzDifficulty_CheckPoW(f *testing.F) {
	f.Add(powHash[:], sidechainDifficulty.Lo, sidechainDifficulty.Hi)
	f.Add(powHash[:], powDifficulty.Lo, powDifficulty.Hi)
	f.Add(powHash[:], moneroDifficulty.Lo, moneroDifficulty.Hi)
	f.Add(ZeroHash[:], uint64(0), uint64(0))

	f.Fuzz(func(t *testing.T, hash []byte, lo, hi uint64) {
		if len(hash) != HashSize {
			t.SkipNow()
		}

		d := NewDifficulty(lo, hi)

		h := Hash(hash)

		result := d.CheckPoW(h)
		result2 := d.CheckPoW_Native(h)

		if result != result2 {
			t.Fatalf("%s diff lo,hi = %d, %d result mismatch: %v vs native %v", h.String(), lo, hi, result, result2)
		}
	})
}
