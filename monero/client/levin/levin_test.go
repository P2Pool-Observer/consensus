package levin_test

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"git.gammaspectra.live/P2Pool/consensus/v3/monero/client/levin"
	"github.com/sclevine/spec"
	"github.com/sclevine/spec/report"
)

func assertNoError(t *testing.T, err error, msgAndArgs ...any) {
	if err != nil {
		message := ""
		if len(msgAndArgs) > 0 {
			message = fmt.Sprint(msgAndArgs...) + ": "
		}
		t.Errorf("%sunexpected err: %s", message, err)
	}
}

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

func TestLevin(t *testing.T) {
	spec.Run(t, "NewHeaderFromBytes", func(t *testing.T, when spec.G, it spec.S) {
		it("fails w/ wrong size", func() {
			bytes := []byte{
				0xff,
			}

			_, err := levin.NewHeaderFromBytesBytes(bytes)
			assertError(t, err)
		})

		it("fails w/ wrong signature", func() {
			bytes := []byte{
				0xff, 0xff, 0xff, 0xff, // signature
				0xff, 0xff, 0xff, 0xff,
				0x00, 0x00, 0x00, 0x00, // length
				0x00, 0x00, 0x00, 0x00, //
				0x00,                   // expects response
				0x00, 0x00, 0x00, 0x00, // command
				0x00, 0x00, 0x00, 0x00, // return code
				0x00, 0x00, 0x00, 0x00, // flags
				0x00, 0x00, 0x00, 0x00, // version
			}

			_, err := levin.NewHeaderFromBytesBytes(bytes)
			assertError(t, err)
			assertContains(t, err.Error(), "signature mismatch")
		})

		it("fails w/ invalid command", func() {
			bytes := []byte{
				0x01, 0x21, 0x01, 0x01, // signature
				0x01, 0x01, 0x01, 0x01,
				0x01, 0x00, 0x00, 0x00, // length
				0x00, 0x00, 0x00, 0x00, //
				0x01,                   // expects response
				0xff, 0xff, 0xff, 0xff, // command
				0x00, 0x00, 0x00, 0x00, // return code
				0x00, 0x00, 0x00, 0x00, // flags
				0x00, 0x00, 0x00, 0x00, // version
			}

			_, err := levin.NewHeaderFromBytesBytes(bytes)
			assertError(t, err)
			assertContains(t, err.Error(), "invalid command")
		})

		it("fails w/ invalid return code", func() {
			bytes := []byte{
				0x01, 0x21, 0x01, 0x01, // signature
				0x01, 0x01, 0x01, 0x01,
				0x01, 0x00, 0x00, 0x00, // length
				0x00, 0x00, 0x00, 0x00, //
				0x01,                   // expects response
				0xe9, 0x03, 0x00, 0x00, // command
				0xaa, 0xaa, 0xaa, 0xaa, // return code
				0x00, 0x00, 0x00, 0x00, // flags
				0x00, 0x00, 0x00, 0x00, // version
			}

			_, err := levin.NewHeaderFromBytesBytes(bytes)
			assertError(t, err)
			assertContains(t, err.Error(), "invalid return code")
		})

		it("fails w/ invalid version", func() {
			bytes := []byte{
				0x01, 0x21, 0x01, 0x01, // signature
				0x01, 0x01, 0x01, 0x01,
				0x01, 0x00, 0x00, 0x00, // length
				0x00, 0x00, 0x00, 0x00, //
				0x01,                   // expects response
				0xe9, 0x03, 0x00, 0x00, // command
				0x00, 0x00, 0x00, 0x00, // return code
				0x02, 0x00, 0x00, 0x00, // flags
				0x00, 0x00, 0x00, 0x00, // version
			}

			_, err := levin.NewHeaderFromBytesBytes(bytes)
			assertError(t, err)
			assertContains(t, err.Error(), "invalid version")
		})

		it("assembles properly from pong", func() {
			bytes := []byte{
				0x01, 0x21, 0x01, 0x01, // signature
				0x01, 0x01, 0x01, 0x01,
				0x01, 0x00, 0x00, 0x00, // length
				0x00, 0x00, 0x00, 0x00, //
				0x01,                   // expects response
				0xeb, 0x03, 0x00, 0x00, // command
				0x00, 0x00, 0x00, 0x00, // return code
				0x02, 0x00, 0x00, 0x00, // flags
				0x01, 0x00, 0x00, 0x00, // version
			}

			header, err := levin.NewHeaderFromBytesBytes(bytes)
			assertNoError(t, err)
			assertEqual(t, header.Command, levin.CommandPing)
			assertEqual(t, header.ReturnCode, levin.LevinOk)
			assertEqual(t, header.Flags, levin.LevinPacketReponse)
			assertEqual(t, header.Version, levin.LevinProtocolVersion)
		})
	})

	spec.Run(t, "NewRequestHeader", func(t *testing.T, when spec.G, it spec.S) {
		it("assembles properly w/ ping", func() {
			bytes := levin.NewRequestHeader(levin.CommandPing, 1).Bytes()

			assertEqual(t, bytes, []byte{
				0x01, 0x21, 0x01, 0x01, // signature
				0x01, 0x01, 0x01, 0x01,
				0x01, 0x00, 0x00, 0x00, // length		-- 0 for a ping msg
				0x00, 0x00, 0x00, 0x00,
				0x01,                   // expects response	-- `true` bool
				0xeb, 0x03, 0x00, 0x00, // command		-- 1003 for ping
				0x00, 0x00, 0x00, 0x00, // return code		-- 0 for requests
				0x01, 0x00, 0x00, 0x00, // flags		-- Q(1st lsb) set for req
				0x01, 0x00, 0x00, 0x00, // version
			})
		})

		it("assembles properly w/ handshake", func() {
			bytes := levin.NewRequestHeader(levin.CommandHandshake, 4).Bytes()

			assertEqual(t, bytes, []byte{
				0x01, 0x21, 0x01, 0x01, // signature
				0x01, 0x01, 0x01, 0x01,
				0x04, 0x00, 0x00, 0x00, // length		-- 0 for a ping msg
				0x00, 0x00, 0x00, 0x00,
				0x01, // expects response	-- `true` bool
				0xe9, 0x03, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, // return code		-- 0 for requests
				0x01, 0x00, 0x00, 0x00, // flags		-- Q(1st lsb) set for req
				0x01, 0x00, 0x00, 0x00, // version
			})
		})
	}, spec.Report(report.Log{}), spec.Parallel(), spec.Random())
}
