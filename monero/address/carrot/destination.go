package carrot

import (
	"git.gammaspectra.live/P2Pool/consensus/v4/monero/address"
)

type DestinationV1 struct {
	Address address.PackedAddress `json:"address"`

	IsSubaddress bool `json:"is_subaddress,omitempty"`

	PaymentId [8]byte `json:"payment_id,omitempty"`
}
