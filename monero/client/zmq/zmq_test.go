package zmq_test

import (
	"bytes"
	"context"
	"errors"
	"git.gammaspectra.live/P2Pool/consensus/v4/monero/client/zmq"
	"git.gammaspectra.live/P2Pool/consensus/v4/p2pool/mempool"
	"os"
	"strings"
	"testing"
	"time"
)

func TestJSONFromFrame(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name          string
		input         []byte
		expectedJSON  []byte
		expectedTopic zmq.Topic
		err           string
	}{
		{
			name:  "nil",
			input: nil,
			err:   "malformed",
		},

		{
			name:  "empty",
			input: []byte{},
			err:   "malformed",
		},

		{
			name:  "unknown-topic",
			input: []byte(`foobar:[{"foo":"bar"}]`),
			err:   "unknown topic",
		},

		{
			name:          "proper w/ known-topic",
			input:         []byte(`json-minimal-txpool_add:[{"foo":"bar"}]`),
			expectedTopic: zmq.TopicMinimalTxPoolAdd,
			expectedJSON:  []byte(`[{"foo":"bar"}]`),
		},
	} {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			aTopic, aJSON, err := zmq.JSONFromFrame(tc.input)
			if tc.err != "" {
				if err == nil {
					t.Fatal("expected error")
				}
				if !strings.Contains(err.Error(), tc.err) {
					t.Errorf("expected %s in, got %s", tc.err, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("expected no error, got %s", err)
			}

			if tc.expectedTopic != aTopic {
				t.Errorf("expected %s, got %s", tc.expectedTopic, aTopic)
			}

			if bytes.Compare(tc.expectedJSON, aJSON) != 0 {
				t.Errorf("expected %s, got %s", string(tc.expectedJSON), string(aJSON))
			}
		})
	}
}

func TestClient(t *testing.T) {
	client := zmq.NewClient(os.Getenv("MONEROD_ZMQ_URL"), zmq.TopicFullChainMain, zmq.TopicFullTxPoolAdd, zmq.TopicFullMinerData, zmq.TopicMinimalChainMain, zmq.TopicMinimalTxPoolAdd)
	ctx, ctxFunc := context.WithTimeout(context.Background(), time.Second*10)
	defer ctxFunc()
	err := client.Listen(ctx, func(chainMain *zmq.FullChainMain) {
		t.Log(chainMain)
	}, func(txs []zmq.FullTxPoolAdd) {
		t.Log(txs)
	}, func(main *zmq.FullMinerData) {
		t.Log(main)
	}, func(chainMain *zmq.MinimalChainMain) {
		t.Log(chainMain)
	}, func(txs mempool.Mempool) {

		t.Log(txs)
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
}
