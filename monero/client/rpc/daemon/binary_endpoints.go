package daemon

import (
	"context"
	"errors"
	"io"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/client/levin"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
)

const (
	endpointGetOIndexes = "/get_o_indexes.bin"
)

func (c *Client) GetOIndexes(
	ctx context.Context, txid types.Hash,
) (indexes []uint64, finalError error) {

	storage := levin.PortableStorage{Entries: levin.Entries{
		levin.Entry{
			Name:         "txid",
			Serializable: levin.BoostString(txid[:]),
		},
	}}

	data, err := storage.Bytes()
	if err != nil {
		return nil, err
	}

	var buf []byte
	err = c.RawBinaryRequest(ctx, endpointGetOIndexes, data, func(resp io.ReadCloser) error {
		buf, err = io.ReadAll(resp)
		return err
	})
	if err != nil {
		return nil, err
	}

	defer func() {
		if r := recover(); r != nil {
			indexes = nil
			finalError = errors.New("error decoding")
		}
	}()
	responseStorage, err := levin.NewPortableStorageFromBytes(buf)
	if err != nil {
		return nil, err
	}
	for _, e := range responseStorage.Entries {
		if e.Name == "o_indexes" {
			if entries, ok := e.Value.(levin.Entries); ok {
				indexes = make([]uint64, 0, len(entries))
				for _, e2 := range entries {
					if v, ok := e2.Value.(uint64); ok {
						indexes = append(indexes, v)
					}
				}
				return indexes, nil
			}
		}
	}

	return nil, errors.New("could not get outputs")
}
