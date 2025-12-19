//go:build goexperiment.jsonv2

package utils

import (
	jsonv1 "encoding/json"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"io"
)

type JSONEncoder struct {
	w      io.Writer
	indent string
}

func (e *JSONEncoder) SetIndent(_, indent string) {
	e.indent = indent
}

func (e *JSONEncoder) Encode(val interface{}) error {
	return json.MarshalWrite(e.w, val, json.OmitZeroStructFields(true), jsontext.WithIndent(e.indent))
}

type JSONDecoder = jsonv1.Decoder

func MarshalJSON(val any) ([]byte, error) {
	return json.Marshal(val, json.OmitZeroStructFields(true))
}

func MarshalJSONIndent(val any, indent string) ([]byte, error) {
	out, err := MarshalJSON(val)
	if err != nil {
		return nil, err
	}
	err = (*jsontext.Value)(&out).Indent(jsontext.WithIndent(indent))
	if err != nil {
		return nil, err
	}
	return out, nil
}

func UnmarshalJSON(data []byte, val any) error {
	return json.Unmarshal(data, val)
}

func NewJSONEncoder(writer io.Writer) *JSONEncoder {
	return &JSONEncoder{
		w: writer,
	}
}

func NewJSONDecoder(reader io.Reader) *JSONDecoder {
	return jsonv1.NewDecoder(reader)
}
