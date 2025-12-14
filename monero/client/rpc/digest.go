package rpc

import (
	"crypto/md5" // #nosec G501
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"strings"

	"git.gammaspectra.live/P2Pool/go-hex"
)

const digestQOPAuth = "auth"

type digest struct {
	QOP       string
	Algorithm string
	Realm     string
	Nonce     string
	Opaque    string
	Stale     string
}

func (d *digest) Hash(data ...[]byte) []byte {
	var hasher hash.Hash
	if d.Algorithm == "" || strings.HasPrefix(d.Algorithm, "MD5") {
		// #nosec G401
		hasher = md5.New()
	} else {
		panic(errors.New("unsupported digest algorithm"))
	}

	for i, b := range data {
		if i > 0 {
			hasher.Write([]byte{':'})
		}
		hasher.Write(b)
	}
	size := hasher.Size()
	dst := make([]byte, size*2)
	cksum := hasher.Sum(dst[size:size])

	hex.Encode(dst, cksum)

	return dst
}

var ErrUnsupportedQOP = errors.New("unsupported QOP")

func (d *digest) Auth(method, uri, user, password string, requestCounter uint32, clientNonce string) (string, error) {
	ha1 := d.Hash([]byte(user), []byte(d.Realm), []byte(password))

	if strings.HasSuffix(d.Algorithm, "-sess") {
		ha1 = d.Hash(ha1, []byte(d.Nonce), []byte(clientNonce))
	}

	var ha2, response []byte
	if len(d.QOP) == 0 || d.QOP == digestQOPAuth {
		ha2 = d.Hash([]byte(method), []byte(uri))
	} else {
		return "", ErrUnsupportedQOP
	}

	var nc [8]byte
	binary.BigEndian.PutUint32(nc[4:], requestCounter)
	hex.Encode(nc[:], nc[4:])

	if len(d.QOP) == 0 {
		response = d.Hash(ha1, []byte(d.Nonce), ha2)
	} else if d.QOP == digestQOPAuth {
		response = d.Hash(ha1, []byte(d.Nonce), nc[:], []byte(clientNonce), []byte(d.QOP), ha2)
	} else {
		return "", ErrUnsupportedQOP
	}

	var elements []string
	elements = append(elements, fmt.Sprintf("Digest username=%q,realm=%q,nonce=%q,uri=%q", user, d.Realm, d.Nonce, uri))
	if d.QOP != "" {
		elements = append(elements, "qop="+d.QOP)
	}
	elements = append(elements, "nc="+string(nc[:]))
	if d.QOP == digestQOPAuth || strings.HasSuffix(d.Algorithm, "-sess") {
		elements = append(elements, fmt.Sprintf("cnonce=%q", clientNonce))
	}
	elements = append(elements, fmt.Sprintf("response=%q", response))
	if d.Algorithm != "" {
		elements = append(elements, "algorithm="+d.Algorithm)
	}
	if d.Opaque != "" {
		elements = append(elements, fmt.Sprintf("opaque=%q", d.Opaque))
	}

	return strings.Join(elements, ","), nil
}

func (d *digest) Set(k, v string) bool {
	switch k {
	case "qop":
		d.QOP = v
	case "algorithm":
		d.Algorithm = v
	case "realm":
		d.Realm = v
	case "nonce":
		d.Nonce = v
	case "opaque":
		d.Opaque = v
	case "stale":
		d.Stale = v
	default:
		return false
	}
	return true
}

func newDigest(str string) *digest {
	const prefix = "Digest "
	if !strings.HasPrefix(str, prefix) {
		return nil
	}

	d := new(digest)

	const (
		keyOrEqual = iota
		quoteOrValue
		valueOrCommaOrEnd
		valueOrQuote
		commaOrEnd
	)

	state := keyOrEqual
	j := len(prefix)

	var key string

	for i := len(prefix); i < len(str); i++ {
		b := str[i]
		switch state {
		case keyOrEqual:
			if b == '=' {
				key = str[j:i]
				state = quoteOrValue
				j = i + 1
			}
		case quoteOrValue:
			if b == '"' {
				state = valueOrQuote
				j = i + 1
			} else {
				state = valueOrCommaOrEnd
			}
		case valueOrCommaOrEnd:
			if b == ',' {
				if !d.Set(key, str[j:i]) {
					return nil
				}
				state = keyOrEqual
				j = i + 1
			}
		case valueOrQuote:
			if b == '"' {
				if !d.Set(key, str[j:i]) {
					return nil
				}
				state = commaOrEnd
				j = i + 1
			}
		case commaOrEnd:
			if b != ',' {
				return nil
			} else {
				state = keyOrEqual
				j = i + 1
			}
		}
	}

	if state == valueOrCommaOrEnd {
		if !d.Set(key, str[j:]) {
			return nil
		}
		return d
	} else if state == commaOrEnd {
		return d
	} else {
		return nil
	}
}
