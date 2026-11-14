package server

import (
	"strings"
	"testing"

	"github.com/projectdiscovery/interactsh/pkg/settings"
	"github.com/stretchr/testify/require"
)

func TestIsCorrelationID_DefaultLengths(t *testing.T) {
	opts := &Options{
		CorrelationIdLength:      settings.CorrelationIdLengthDefault,
		CorrelationIdNonceLength: settings.CorrelationIdNonceLengthDefault,
	}

	id := defaultUniqueID()
	require.True(t, opts.isCorrelationID(id))
	require.False(t, opts.isCorrelationID(id+"x"))
	if len(id) > 0 {
		require.False(t, opts.isCorrelationID(id[:len(id)-1]+"!"))
	}
}

func TestIsCorrelationID_ShortLengthsRejectDomainLabelFalsePositives(t *testing.T) {
	opts := &Options{CorrelationIdLength: 3, CorrelationIdNonceLength: 3}

	const exampleLabel = "example"
	candidates := []string{exampleLabel[:6], exampleLabel[1:7], "google"}
	for _, candidate := range candidates {
		require.False(t, opts.isCorrelationID(candidate), "%q must not be treated as a correlation id", candidate)
	}

	require.True(t, opts.isCorrelationID("d82yyy"), "valid xid+zbase32 preamble must still match")
}

func TestIsCorrelationID_AlphabetBoundaries(t *testing.T) {
	opts := &Options{CorrelationIdLength: 3, CorrelationIdNonceLength: 3}

	require.False(t, opts.isCorrelationID("xyzbnd"), "xid prefix must reject chars outside 0-9a-v")
	require.False(t, opts.isCorrelationID("abclmv"), "zbase32 suffix must reject chars outside its alphabet")
}

func TestIsValidCorrelationID(t *testing.T) {
	opts := &Options{
		CorrelationIdLength: settings.CorrelationIdLengthDefault,
	}

	valid := sampleCorrelationID(settings.CorrelationIdLengthDefault)
	require.True(t, opts.isValidCorrelationID(valid))

	if settings.CorrelationIdLengthDefault > 0 {
		// Reject uppercase characters
		require.False(t, opts.isValidCorrelationID(strings.ToUpper(valid)))
		require.False(t, opts.isValidCorrelationID(valid[:len(valid)-1]+"A"))

		// Reject characters outside xid alphabet (w, x, y, z)
		require.False(t, opts.isValidCorrelationID(valid[:len(valid)-1]+"w"))
		require.False(t, opts.isValidCorrelationID(valid[:len(valid)-1]+"x"))
		require.False(t, opts.isValidCorrelationID(valid[:len(valid)-1]+"y"))
		require.False(t, opts.isValidCorrelationID(valid[:len(valid)-1]+"z"))

		// Reject invalid lengths
		require.False(t, opts.isValidCorrelationID(valid[:len(valid)-1]))
		require.False(t, opts.isValidCorrelationID(valid+"0"))
		require.False(t, opts.isValidCorrelationID(""))

		// Reject non-alphanumeric characters
		require.False(t, opts.isValidCorrelationID(valid[:len(valid)-1]+"-"))
		require.False(t, opts.isValidCorrelationID(valid[:len(valid)-1]+"."))
	}

	// Custom CorrelationIdLength
	customOpts := &Options{
		CorrelationIdLength: 5,
	}
	require.True(t, customOpts.isValidCorrelationID("c6rj6"))
	require.False(t, customOpts.isValidCorrelationID("c6rj61"))
	require.False(t, customOpts.isValidCorrelationID("c6rjW"))
}
