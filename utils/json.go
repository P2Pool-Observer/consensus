//go:build !purego && !goexperiment.jsonv2

package utils

import (
	"io"

	gojson "git.gammaspectra.live/P2Pool/go-json" //nolint:depguard
)

type JSONEncoder = gojson.Encoder
type JSONDecoder = gojson.Decoder

var encodeOptions = []gojson.EncodeOptionFunc{gojson.DisableHTMLEscape(), gojson.DisableNormalizeUTF8()}

func MarshalJSON(val any) ([]byte, error) {
	return gojson.MarshalWithOption(val, encodeOptions...)
}

func MarshalJSONIndent(val any, indent string) ([]byte, error) {
	return gojson.MarshalIndentWithOption(val, "", indent, encodeOptions...)
}

func UnmarshalJSON(data []byte, val any) error {
	return gojson.UnmarshalWithOption(data, val)
}

func NewJSONEncoder(writer io.Writer) *JSONEncoder {
	return gojson.NewEncoder(writer)
}

func NewJSONDecoder(reader io.Reader) *JSONDecoder {
	return gojson.NewDecoder(reader)
}
