package types

import (
	"math"
	"testing"
)

func TestDifficulty(t *testing.T) {
	hexDiff := "000000000000000000000000683a8b1c"
	diff, err := DifficultyFromString(hexDiff)
	if err != nil {
		t.Fatal(err)
	}

	if diff.String() != hexDiff {
		t.Fatalf("expected %s, got %s", hexDiff, diff)
	}
}

func TestDifficulty_UnmarshalJSON(t *testing.T) {
	hexDiff := "\"0x4970d\""
	var diff Difficulty
	err := diff.UnmarshalJSON([]byte(hexDiff))
	if err != nil {
		t.Fatal(err)
	}

	if diff.Lo != 0x4970d {
		t.Fatalf("expected %d, got %d", 0x4970d, diff.Lo)
	}
}

func TestDifficulty_Convergence(t *testing.T) {
	// convergence tests with p2pool

	t.Run("Division", func(t *testing.T) {
		check := func(a, b, expected Difficulty) {
			actual := a.Div(b)
			if !actual.Equals(expected) {
				t.Fatalf("expected %s, got %s", expected, actual)
			}
		}

		check(MaxDifficulty, MaxDifficulty, Difficulty{Lo: 1, Hi: 0})
		check(MaxDifficulty, Difficulty{Lo: 0, Hi: 1}, Difficulty{Lo: math.MaxUint64, Hi: 0})
		check(MaxDifficulty, Difficulty{Lo: 1, Hi: 1}, Difficulty{Lo: math.MaxUint64, Hi: 0})
		check(MaxDifficulty, Difficulty{Lo: 2, Hi: 1}, Difficulty{Lo: math.MaxUint64 - 1, Hi: 0})
		check(MaxDifficulty, Difficulty{Lo: 439125228929, Hi: 439125228929}, Difficulty{Lo: 42007935, Hi: 0})
		check(Difficulty{Lo: 0, Hi: math.MaxUint64}, Difficulty{Lo: math.MaxUint64, Hi: 0}, Difficulty{Lo: 0, Hi: 1})
	})
}
