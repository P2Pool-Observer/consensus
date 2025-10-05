package carrot

import (
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address"
)

type DestinationV1 struct {
	Address address.PackedAddressWithSubaddress `json:"address"`

	PaymentId [8]byte `json:"payment_id,omitempty"`
}
