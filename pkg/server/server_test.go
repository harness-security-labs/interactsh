package server

import (
	"testing"

	"github.com/projectdiscovery/interactsh/pkg/settings"
	"github.com/stretchr/testify/require"
)

func TestGetURLIDComponent(t *testing.T) {
	options := Options{CorrelationIdLength: settings.CorrelationIdLengthDefault, CorrelationIdNonceLength: settings.CorrelationIdNonceLengthDefault}
	id := defaultUniqueID()
	random := options.getURLIDComponent(id + ".interactsh.com")
	require.Equal(t, id, random, "could not get correct component")
}
