package daemon_test

import (
	"context"
	"fmt"

	"git.gammaspectra.live/P2Pool/consensus/v4/monero/client/rpc"
	"git.gammaspectra.live/P2Pool/consensus/v4/monero/client/rpc/daemon"
)

// nolint
func ExampleGetHeight() {
	ctx := context.Background()
	addr := "http://localhost:18081"

	// instantiate a generic RPC client
	//
	client, err := rpc.NewClient(addr)
	if err != nil {
		panic(fmt.Errorf("new client for '%s': %w", addr, err))
	}

	// instantiate a daemon-specific client and call the `get_height`
	// remote procedure.
	//
	height, err := daemon.NewClient(client).GetHeight(ctx)
	if err != nil {
		panic(fmt.Errorf("get height: %w", err))
	}

	fmt.Printf("height=%d hash=%s\n", height.Height, height.Hash)
}
