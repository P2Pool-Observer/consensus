package fcmp_plus_plus

import "testing"

const TARGET_LAYERS = 8

func TestMembershipProofSize(t *testing.T) {
	for inputs := range 256 + 1 {
		t.Logf("Proof size for %d inputs: %d", inputs, MembershipProofSize(inputs, TARGET_LAYERS))
	}
}
