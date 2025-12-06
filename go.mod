module git.gammaspectra.live/P2Pool/consensus/v5

go 1.25.5

// Internal or imported dependencies
require (
	git.gammaspectra.live/P2Pool/blake2b v0.42.1
	git.gammaspectra.live/P2Pool/edwards25519 v0.0.0-20251206112811-c233ac191587
	git.gammaspectra.live/P2Pool/go-json v0.0.0-20250621110326-6e32b22271c3
	git.gammaspectra.live/P2Pool/go-randomx/v4 v4.6.1
	git.gammaspectra.live/P2Pool/helioselene v0.0.0-20251201070947-26d62186ee7f
	git.gammaspectra.live/P2Pool/monero-base58 v1.0.0
	git.gammaspectra.live/P2Pool/randomx-go-bindings v1.0.0
	git.gammaspectra.live/P2Pool/softfloat64 v1.0.2 // indirect
	git.gammaspectra.live/P2Pool/zmq4 v0.99.0
)

// Go x packages dependencies
require (
	golang.org/x/crypto v0.45.0
	golang.org/x/net v0.47.0
	golang.org/x/sync v0.18.0
	golang.org/x/sys v0.38.0
)

// External dependencies
require (
	github.com/hashicorp/golang-lru/v2 v2.0.7
	github.com/tmthrgd/go-hex v0.0.0-20190904060850-447a3041c3bc
	github.com/ulikunitz/xz v0.5.15
	lukechampine.com/uint128 v1.3.0
)
