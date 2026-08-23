//go:build goexperiment.jsonv2

package utils

import (
	jsonv1 "encoding/json" //nolint:depguard
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

func (e *JSONEncoder) Encode(val any) (err error) {
	//TODO: use streaming encoder
	if e.indent != "" {
		if err = json.MarshalWrite(e.w, val, jsontext.WithIndent(e.indent)); err != nil {
			return err
		}
	} else {
		if err = json.MarshalWrite(e.w, val); err != nil {
			return err
		}
	}

	_, err = e.w.Write([]byte{'\n'})
	return err
}

type JSONDecoder = jsonv1.Decoder

func MarshalJSON(val any) ([]byte, error) {
	return json.Marshal(val)
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
