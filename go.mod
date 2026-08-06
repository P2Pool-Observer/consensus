module git.gammaspectra.live/P2Pool/consensus/v5

go 1.26.0

// Internal or imported dependencies
require (
	git.gammaspectra.live/P2Pool/blake2b v0.42.1
	git.gammaspectra.live/P2Pool/edwards25519 v0.0.0-20260803152649-1ba9a7642c04
	git.gammaspectra.live/P2Pool/go-hex v0.0.0-20251214231021-098f65fc1214
	git.gammaspectra.live/P2Pool/go-randomx/v5 v5.0.1
	git.gammaspectra.live/P2Pool/helioselene v0.0.0-20260806070208-d7917a2b3dfa
	git.gammaspectra.live/P2Pool/monero-base58 v1.0.0
	git.gammaspectra.live/P2Pool/randomx-go-bindings v1.0.0
	git.gammaspectra.live/P2Pool/zmq4 v0.99.0

	// External dependencies
	github.com/hashicorp/golang-lru/v2 v2.0.7
	github.com/klauspost/cpuid/v2 v2.4.0 // indirect
	github.com/tidwall/btree v1.8.1
	golang.org/x/crypto v0.54.0
	golang.org/x/net v0.57.0
	golang.org/x/sync v0.22.0
	golang.org/x/sys v0.47.0
	lukechampine.com/uint128 v1.3.0
)
