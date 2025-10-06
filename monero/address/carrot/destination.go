package carrot

import (
	"git.gammaspectra.live/P2Pool/consensus/v5/monero"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address"
)

type DestinationV1 struct {
	Address address.PackedAddressWithSubaddress `json:"address"`

	PaymentId [monero.PaymentIdSize]byte `json:"payment_id,omitempty"`
}
