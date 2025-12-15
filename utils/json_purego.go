//go:build purego && !goexperiment.jsonv2

package utils

import (
	"encoding/json" //nolint:depguard
	"io"
)

type JSONEncoder = json.Encoder
type JSONDecoder = json.Decoder

func MarshalJSON(val any) ([]byte, error) {
	return json.Marshal(val)
}

func MarshalJSONIndent(val any, indent string) ([]byte, error) {
	return json.MarshalIndent(val, "", indent)
}

func UnmarshalJSON(data []byte, val any) error {
	return json.Unmarshal(data, val)
}

func NewJSONEncoder(writer io.Writer) *JSONEncoder {
	return json.NewEncoder(writer)
}

func NewJSONDecoder(reader io.Reader) *JSONDecoder {
	return json.NewDecoder(reader)
}
