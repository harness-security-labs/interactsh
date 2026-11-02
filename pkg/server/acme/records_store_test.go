package acme

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libdns/libdns"
	"github.com/stretchr/testify/require"
)

func TestSharedProviderVisibleAcrossInstances(t *testing.T) {
	dir := t.TempDir()
	writer := NewProvider(dir)
	reader := NewProvider(dir)

	zone := "_acme-challenge.app.collab.tr4t.io."
	txt := libdns.RR{Name: "@", Type: "TXT", Data: "challenge-token", TTL: 120 * time.Second}

	_, err := writer.AppendRecords(context.Background(), zone, []libdns.Record{txt})
	require.NoError(t, err)

	got, err := reader.GetRecords(context.Background(), zone)
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, "challenge-token", got[0].RR().Data)

	replacement := libdns.RR{Name: "@", Type: "TXT", Data: "next-token", TTL: 120 * time.Second}
	_, err = writer.AppendRecords(context.Background(), zone, []libdns.Record{replacement})
	require.NoError(t, err)

	got, err = reader.GetRecords(context.Background(), strings.ToLower(zone))
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, "next-token", got[0].RR().Data)

	deleted, err := writer.DeleteRecords(context.Background(), zone, []libdns.Record{replacement})
	require.NoError(t, err)
	require.Len(t, deleted, 1)

	_, err = reader.GetRecords(context.Background(), zone)
	require.Error(t, err)

	_, err = os.Stat(writer.zonePath(zone) + ".lock")
	require.NoError(t, err)
}

func TestProviderMemoryIsNotShared(t *testing.T) {
	writer := NewProvider("")
	reader := NewProvider("")
	zone := "_acme-challenge.example.com."
	txt := libdns.RR{Name: "@", Type: "TXT", Data: "only-local", TTL: time.Minute}

	_, err := writer.AppendRecords(context.Background(), zone, []libdns.Record{txt})
	require.NoError(t, err)

	_, err = reader.GetRecords(context.Background(), zone)
	require.Error(t, err)

	got, err := writer.GetRecords(context.Background(), zone)
	require.NoError(t, err)
	require.Equal(t, "only-local", got[0].RR().Data)
}

func TestProviderMemoryChallengeReplacesAndOtherZonesAppend(t *testing.T) {
	provider := NewProvider("")
	ctx := context.Background()

	challenge := "_acme-challenge.example.com."
	first := libdns.RR{Name: "@", Type: "TXT", Data: "first", TTL: time.Second}
	second := libdns.RR{Name: "@", Type: "TXT", Data: "second", TTL: time.Second}
	_, err := provider.AppendRecords(ctx, challenge, []libdns.Record{first})
	require.NoError(t, err)
	_, err = provider.AppendRecords(ctx, challenge, []libdns.Record{second})
	require.NoError(t, err)
	got, err := provider.GetRecords(ctx, challenge)
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, "second", got[0].RR().Data)

	zone := "example.com."
	a := libdns.RR{Name: "www", Type: "TXT", Data: "a", TTL: time.Second}
	b := libdns.RR{Name: "mail", Type: "TXT", Data: "b", TTL: time.Second}
	_, err = provider.AppendRecords(ctx, zone, []libdns.Record{a})
	require.NoError(t, err)
	_, err = provider.AppendRecords(ctx, zone, []libdns.Record{b})
	require.NoError(t, err)
	got, err = provider.GetRecords(ctx, zone)
	require.NoError(t, err)
	require.Len(t, got, 2)

	deleted, err := provider.DeleteRecords(ctx, "missing.example.com.", []libdns.Record{a})
	require.NoError(t, err)
	require.Empty(t, deleted)

	_, err = provider.GetRecords(ctx, "missing.example.com.")
	require.Error(t, err)
}

func TestSharedProviderNormalizesZoneName(t *testing.T) {
	dir := t.TempDir()
	writer := NewProvider(dir)
	reader := NewProvider(dir)
	txt := libdns.RR{Name: "@", Type: "TXT", Data: "normalized", TTL: time.Minute}

	_, err := writer.AppendRecords(context.Background(), "_acme-challenge.App.Collab.TR4T.io.", []libdns.Record{txt})
	require.NoError(t, err)

	got, err := reader.GetRecords(context.Background(), "_acme-challenge.app.collab.tr4t.io")
	require.NoError(t, err)
	require.Equal(t, "normalized", got[0].RR().Data)
	require.Equal(t, writer.zonePath("_acme-challenge.App.Collab.TR4T.io."), reader.zonePath("_acme-challenge.app.collab.tr4t.io"))
}

func TestSharedProviderAppendsNonChallengeRecords(t *testing.T) {
	dir := t.TempDir()
	writer := NewProvider(dir)
	reader := NewProvider(dir)
	ctx := context.Background()
	zone := "example.com."

	_, err := writer.AppendRecords(ctx, zone, []libdns.Record{
		libdns.RR{Name: "www", Type: "TXT", Data: "one", TTL: time.Second},
	})
	require.NoError(t, err)
	_, err = writer.AppendRecords(ctx, zone, []libdns.Record{
		libdns.RR{Name: "mail", Type: "TXT", Data: "two", TTL: time.Second},
	})
	require.NoError(t, err)

	got, err := reader.GetRecords(ctx, "Example.com")
	require.NoError(t, err)
	require.Len(t, got, 2)
}

func TestSharedProviderConcurrentAppends(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	const n = 8
	errCh := make(chan error, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			provider := NewProvider(dir)
			rec := libdns.RR{Name: fmt.Sprintf("n%d", i), Type: "TXT", Data: fmt.Sprintf("v%d", i), TTL: time.Second}
			_, err := provider.AppendRecords(ctx, "example.com.", []libdns.Record{rec})
			errCh <- err
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		require.NoError(t, err)
	}

	got, err := NewProvider(dir).GetRecords(ctx, "example.com.")
	require.NoError(t, err)
	require.Len(t, got, n)
}

func TestSharedProviderMissingAndCorruptZone(t *testing.T) {
	dir := t.TempDir()
	provider := NewProvider(dir)
	ctx := context.Background()

	_, err := provider.GetRecords(ctx, "missing.example.com.")
	require.Error(t, err)
	deleted, err := provider.DeleteRecords(ctx, "missing.example.com.", nil)
	require.NoError(t, err)
	require.Empty(t, deleted)

	zone := "broken.example.com."
	require.NoError(t, os.WriteFile(provider.zonePath(zone), []byte("{not-json"), 0o600))
	_, err = provider.GetRecords(ctx, zone)
	require.Error(t, err)
}
