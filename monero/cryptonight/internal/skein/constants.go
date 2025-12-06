// Copyright (c) 2016 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package skein

import "git.gammaspectra.live/P2Pool/consensus/v5/monero/cryptonight/internal/skein/threefish"

const (
	// BlockSize The blocksize of Skein-512 in bytes.
	BlockSize = threefish.BlockSize512
)

// The different parameter types
const (
	// CfgKey is the config type for the Key.
	CfgKey uint64 = 0

	// CfgConfig is the config type for the configuration.
	CfgConfig uint64 = 4

	// CfgPersonal is the config type for the personalization.
	CfgPersonal uint64 = 8

	// CfgPublicKey is the config type for the public key.
	CfgPublicKey uint64 = 12

	// CfgKeyID is the config type for the key id.
	CfgKeyID uint64 = 16

	// CfgNonce is the config type for the nonce.
	CfgNonce uint64 = 20

	// CfgMessage is the config type for the message.
	CfgMessage uint64 = 48

	// CfgOutput is the config type for the output.
	CfgOutput uint64 = 63

	// FirstBlock is the first block flag
	FirstBlock uint64 = 1 << 62

	// FinalBlock is the final block flag
	FinalBlock uint64 = 1 << 63

	// SchemaID The skein schema ID = S H A 3 1 0 0 0
	SchemaID uint64 = 0x133414853
)

var iv256 = [9]uint64{
	0xCCD044A12FDB3E13, 0xE83590301A79A9EB, 0x55AEA0614F816E6F, 0x2A2767A4AE9B94DB,
	0xEC06025E74DD7683, 0xE7A436CDC4746251, 0xC36FBAF9393AD185, 0x3EEDBA1833EDFC13,
	0,
}

// Config contains the Skein configuration:
// - Key for computing MACs
// - Personal for personalized hashing
// - PublicKey for public-key-bound hashing
// - KeyID for key derivation
// - Nonce for randomized hashing
// All fields are optional and can be nil.
type Config struct {
	Key       []byte // Optional: The secret key for MAC
	Personal  []byte // Optional: The personalization for unique hashing
	PublicKey []byte // Optional: The public key for public-key bound hashing
	KeyID     []byte // Optional: The key id for key derivation
	Nonce     []byte // Optional: The nonce for randomized hashing
}
