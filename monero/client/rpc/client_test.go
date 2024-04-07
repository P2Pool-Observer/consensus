package rpc_test

import (
	"context"
	"fmt"
	"git.gammaspectra.live/P2Pool/consensus/v3/utils"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"git.gammaspectra.live/P2Pool/consensus/v3/monero/client/rpc"
	"github.com/sclevine/spec"
	"github.com/sclevine/spec/report"
)

func assertError(t *testing.T, err error, msgAndArgs ...any) {
	if err == nil {
		message := ""
		if len(msgAndArgs) > 0 {
			message = fmt.Sprint(msgAndArgs...) + ": "
		}
		t.Errorf("%sexpected err", message)
	}
}

func assertContains(t *testing.T, actual, expected string, msgAndArgs ...any) {
	if !strings.Contains(actual, expected) {
		message := ""
		if len(msgAndArgs) > 0 {
			message = fmt.Sprint(msgAndArgs...) + ": "
		}
		t.Errorf("%sactual: %v expected: %v", message, actual, expected)
	}
}

func assertEqual(t *testing.T, actual, expected any, msgAndArgs ...any) {
	if !reflect.DeepEqual(actual, expected) {
		message := ""
		if len(msgAndArgs) > 0 {
			message = fmt.Sprint(msgAndArgs...) + ": "
		}
		t.Errorf("%sactual: %v expected: %v", message, actual, expected)
	}
}

// nolint:funlen
func TestClient(t *testing.T) {
	spec.Run(t, "JSONRPC", func(t *testing.T, when spec.G, it spec.S) {
		var (
			ctx    = context.Background()
			client *rpc.Client
			err    error
		)

		it("errors when daemon down", func() {
			daemon := httptest.NewServer(http.HandlerFunc(nil))
			daemon.Close()

			client, err = rpc.NewClient(daemon.URL, rpc.WithHTTPClient(daemon.Client()))
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}

			err = client.JSONRPC(ctx, "method", nil, nil)
			assertError(t, err)
			assertContains(t, err.Error(), "do:")
		})

		it("errors w/ empty response", func() {
			handler := func(w http.ResponseWriter, r *http.Request) {}

			daemon := httptest.NewServer(http.HandlerFunc(handler))
			defer daemon.Close()

			client, err = rpc.NewClient(daemon.URL, rpc.WithHTTPClient(daemon.Client()))
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}

			err = client.JSONRPC(ctx, "method", nil, nil)
			assertError(t, err)
			assertContains(t, err.Error(), "decode")
		})

		it("errors w/ non-200 response", func() {
			handler := func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(500)
			}

			daemon := httptest.NewServer(http.HandlerFunc(handler))
			defer daemon.Close()

			client, err = rpc.NewClient(daemon.URL, rpc.WithHTTPClient(daemon.Client()))
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}

			err = client.JSONRPC(ctx, "method", nil, nil)
			assertError(t, err)
			assertContains(t, err.Error(), "non-2xx status")
		})

		it("makes GET request to the jsonrpc endpoint", func() {
			var (
				endpoint string
				method   string
			)

			handler := func(w http.ResponseWriter, r *http.Request) {
				endpoint = r.URL.Path
				method = r.Method
			}

			daemon := httptest.NewServer(http.HandlerFunc(handler))
			defer daemon.Close()

			client, err = rpc.NewClient(daemon.URL, rpc.WithHTTPClient(daemon.Client()))
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}

			err = client.JSONRPC(ctx, "method", nil, nil)
			assertEqual(t, rpc.EndpointJSONRPC, endpoint)
			assertEqual(t, method, "GET")
		})

		it("encodes rpc in request", func() {
			var (
				body = &rpc.RequestEnvelope{}

				params = map[string]interface{}{
					"foo": "bar",
					"caz": 123.123,
				}
			)

			handler := func(w http.ResponseWriter, r *http.Request) {
				err := utils.NewJSONDecoder(r.Body).Decode(body)
				if err != nil {
					t.Errorf("unexpected err: %v", err)
				}
			}

			daemon := httptest.NewServer(http.HandlerFunc(handler))
			defer daemon.Close()

			client, err = rpc.NewClient(daemon.URL, rpc.WithHTTPClient(daemon.Client()))
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}

			err = client.JSONRPC(ctx, "rpc-method", params, nil)
			assertEqual(t, body.ID, "0")
			assertEqual(t, body.JSONRPC, "2.0")
			assertEqual(t, body.Method, "rpc-method")
			assertEqual(t, body.Params, params)
		})

		it("captures result", func() {
			handler := func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintln(w, `{"id":"id", "jsonrpc":"jsonrpc", "result": {"foo": "bar"}}`)
			}

			daemon := httptest.NewServer(http.HandlerFunc(handler))
			defer daemon.Close()

			client, err = rpc.NewClient(daemon.URL, rpc.WithHTTPClient(daemon.Client()))
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}

			result := map[string]string{}

			err = client.JSONRPC(ctx, "rpc-method/home/shoghicp/radio/p2pool-observer", nil, &result)
			if err != nil {
				t.Errorf("unexpected err: %v", err)
			}

			assertEqual(t, result, map[string]string{"foo": "bar"})
		})

		it("fails if rpc errored", func() {
			handler := func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintln(w, `{"id":"id", "jsonrpc":"jsonrpc", "error": {"code": -1, "message":"foo"}}`)
			}

			daemon := httptest.NewServer(http.HandlerFunc(handler))
			defer daemon.Close()

			client, err = rpc.NewClient(daemon.URL, rpc.WithHTTPClient(daemon.Client()))
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}

			result := map[string]string{}

			err = client.JSONRPC(ctx, "rpc-method", nil, &result)
			assertError(t, err)

			assertContains(t, err.Error(), "foo")
			assertContains(t, err.Error(), "-1")
		})
	}, spec.Report(report.Terminal{}), spec.Parallel(), spec.Random())
}
