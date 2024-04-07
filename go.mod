module git.gammaspectra.live/P2Pool/consensus/v3

go 1.22

require (
	git.gammaspectra.live/P2Pool/edwards25519 v0.0.0-20240405085108-e2f706cb5c00
	git.gammaspectra.live/P2Pool/go-randomx v0.0.0-20221027085532-f46adfce03a7
	git.gammaspectra.live/P2Pool/monero-base58 v1.0.0
	git.gammaspectra.live/P2Pool/randomx-go-bindings v0.0.0-20230514082649-9c5f18cd5a71
	git.gammaspectra.live/P2Pool/sha3 v0.17.0
	github.com/dolthub/swiss v0.2.2-0.20240312182618-f4b2babd2bc1
	github.com/floatdrop/lru v1.3.0
	github.com/go-zeromq/zmq4 v0.16.1-0.20240124085909-e75c615ba1b3
	github.com/goccy/go-json v0.10.2
	github.com/sclevine/spec v1.4.0
	github.com/stretchr/testify v1.8.1
	github.com/tmthrgd/go-hex v0.0.0-20190904060850-447a3041c3bc
	golang.org/x/sys v0.19.0
	lukechampine.com/uint128 v1.3.0
)

require (
	github.com/bahlo/generic-list-go v0.2.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dolthub/maphash v0.1.0 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/niemeyer/pretty v0.0.0-20200227124842-a10e7caefd8e // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/crypto v0.22.0 // indirect
	golang.org/x/sync v0.7.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	gopkg.in/check.v1 v1.0.0-20200227125254-8fa46927fb4f // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/goccy/go-json => github.com/WeebDataHoarder/go-json v0.0.0-20230730135821-d8f6463bb887

replace github.com/go-zeromq/zmq4 => git.gammaspectra.live/P2Pool/zmq4 v0.16.1-0.20240407153747-7f7d531f586e
