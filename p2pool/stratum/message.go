package stratum

import "git.gammaspectra.live/P2Pool/consensus/v5/types"

type JsonRpcMessage struct {
	// Id set by client
	Id any `json:"id,omitempty"`
	// JsonRpcVersion Always "2.0"
	JsonRpcVersion string `json:"jsonrpc"`
	Method         string `json:"method"`
	Params         any    `json:"params,omitempty"`
}
type JsonRpcResult struct {
	// Id set by client
	Id any `json:"id,omitempty"`
	// JsonRpcVersion Always "2.0"
	JsonRpcVersion string `json:"jsonrpc"`
	Result         any    `json:"result,omitempty"`
	Error          any    `json:"error"`
}

type JsonRpcJob struct {
	// JsonRpcVersion Always "2.0"
	JsonRpcVersion string `json:"jsonrpc"`
	// Method always "job"
	Method string           `json:"method"`
	Params jsonRpcJobParams `json:"params"`
}

type jsonRpcJobParams struct {
	// Blob HashingBlob, in hex
	Blob string `json:"blob"`

	// JobId anything?
	JobId string `json:"job_id"`

	// Target uint64 target in hex
	Target string `json:"target"`

	Algo string `json:"algo,omitempty"`

	// Height main height
	Height uint64 `json:"height"`

	// SeedHash
	SeedHash types.Hash `json:"seed_hash,omitzero"`
}

type JsonRpcResponseJob struct {
	// Id set by client
	Id any `json:"id,omitempty"`
	// JsonRpcVersion Always "2.0"
	JsonRpcVersion string                   `json:"jsonrpc"`
	Result         jsonRpcResponseJobResult `json:"result"`
}

type jsonRpcResponseJobResult struct {
	Id         string           `json:"id,omitzero"`
	Job        jsonRpcJobParams `json:"job"`
	Extensions []string         `json:"extensions,omitzero"`
	Status     string           `json:"status"`
}

var baseRpcJob = JsonRpcJob{
	JsonRpcVersion: "2.0",
	Method:         "job",
}

var baseRpcResponseJob = JsonRpcResponseJob{
	JsonRpcVersion: "2.0",
	Result: jsonRpcResponseJobResult{
		Extensions: []string{"algo", "keepalive"},
		Status:     "OK",
	},
}

func copyBaseJob() JsonRpcJob {
	return baseRpcJob
}

func copyBaseResponseJob() JsonRpcResponseJob {
	return baseRpcResponseJob
}
