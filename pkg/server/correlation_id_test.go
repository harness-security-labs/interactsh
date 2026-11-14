package server

import (
	"strings"

	"github.com/projectdiscovery/interactsh/pkg/settings"
	"github.com/rs/xid"
)

// xidAlphabet and zbase32Alphabet are the same sets isCorrelationID accepts.
// Samples drawn from them stay valid at whatever length the settings use.
const (
	xidSample     = "c6rj61aciaeutn2ae680"
	zbase32Sample = "ybndrfg8ejkmcpqxot1uwisza345h769"
)

func alphabetPrefix(alphabet string, n int) string {
	if n <= 0 {
		return ""
	}
	out := strings.Repeat(alphabet, n/len(alphabet)+1)
	return out[:n]
}

// sampleCorrelationID is a stable preamble of length n in the xid alphabet.
func sampleCorrelationID(n int) string {
	return alphabetPrefix(xidSample, n)
}

// sampleNonce is a stable nonce of length n in the zbase32 alphabet.
func sampleNonce(n int) string {
	return alphabetPrefix(zbase32Sample, n)
}

// freshCorrelationID is a unique preamble of length n. The xid counter sits at
// the end of the encoded id, so the suffix changes on every call even when n
// is shorter than a full xid.
func freshCorrelationID(n int) string {
	if n <= 0 {
		return ""
	}
	raw := xid.New().String()
	if n <= len(raw) {
		return raw[len(raw)-n:]
	}
	return raw + strings.Repeat("a", n-len(raw))
}

func defaultCorrelationID() string {
	return freshCorrelationID(settings.CorrelationIdLengthDefault)
}

func defaultUniqueID() string {
	return sampleCorrelationID(settings.CorrelationIdLengthDefault) + sampleNonce(settings.CorrelationIdNonceLengthDefault)
}
