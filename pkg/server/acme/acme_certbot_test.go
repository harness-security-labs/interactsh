package acme

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/libdns"
	"github.com/stretchr/testify/require"
)

func TestUseSharedStorageDisabledKeepsMemoryProvider(t *testing.T) {
	provider, err := UseSharedStorage("  ")
	require.NoError(t, err)
	require.Empty(t, provider.dir)

	_, err = provider.AppendRecords(context.Background(), "_acme-challenge.example.com.", []libdns.Record{
		libdns.RR{Name: "@", Type: "TXT", Data: "local", TTL: time.Second},
	})
	require.NoError(t, err)
}

func TestUseSharedStorageVisibleToSecondPod(t *testing.T) {
	previous := certmagic.Default.Storage
	t.Cleanup(func() { certmagic.Default.Storage = previous })

	dir := t.TempDir()
	writer, err := UseSharedStorage(dir)
	require.NoError(t, err)
	require.DirExists(t, filepath.Join(dir, "records"))
	require.DirExists(t, filepath.Join(dir, "certificates"))

	storage, ok := certmagic.Default.Storage.(*certmagic.FileStorage)
	require.True(t, ok)
	require.Equal(t, filepath.Join(dir, "certificates"), storage.Path)

	reader, err := UseSharedStorage(dir)
	require.NoError(t, err)

	zone := "_acme-challenge.example.com."
	_, err = writer.AppendRecords(context.Background(), zone, []libdns.Record{
		libdns.RR{Name: "@", Type: "TXT", Data: "shared-token", TTL: 30 * time.Second},
	})
	require.NoError(t, err)

	got, err := reader.GetRecords(context.Background(), zone)
	require.NoError(t, err)
	require.Equal(t, "shared-token", got[0].RR().Data)
	require.Equal(t, filepath.Join(dir, "records"), writer.dir)
	require.Equal(t, writer.dir, reader.dir)
}

func TestCertificateDir(t *testing.T) {
	dir := t.TempDir()
	require.Equal(t, dir, certificateDir(&certmagic.Config{Storage: &certmagic.FileStorage{Path: dir}}))

	home, err := os.UserHomeDir()
	require.NoError(t, err)
	require.Equal(t, filepath.Join(home, ".local", "share", "certmagic"), certificateDir(&certmagic.Config{}))
}

func TestCertAlreadyExistsAndExtractPaths(t *testing.T) {
	previous := certmagic.Default.Storage
	t.Cleanup(func() { certmagic.Default.Storage = previous })

	dir := t.TempDir()
	_, err := UseSharedStorage(dir)
	require.NoError(t, err)

	cfg := certmagic.NewDefault()
	issuer := &certmagic.DefaultACME
	domain := "*.example.com"
	ctx := context.Background()

	require.False(t, certAlreadyExists(cfg, issuer, domain))

	issuerKey := issuer.IssuerKey()
	require.NoError(t, cfg.Storage.Store(ctx, certmagic.StorageKeys.SiteCert(issuerKey, domain), []byte("cert")))
	require.NoError(t, cfg.Storage.Store(ctx, certmagic.StorageKeys.SitePrivateKey(issuerKey, domain), []byte("key")))
	require.False(t, certAlreadyExists(cfg, issuer, domain))

	require.NoError(t, cfg.Storage.Store(ctx, certmagic.StorageKeys.SiteMeta(issuerKey, domain), []byte("{}")))
	require.True(t, certAlreadyExists(cfg, issuer, domain))

	certPath, keyPath, err := ExtractCaddyPaths(cfg, issuer, domain)
	require.NoError(t, err)
	require.FileExists(t, certPath)
	require.FileExists(t, keyPath)
	require.Contains(t, certPath, filepath.Join(dir, "certificates"))
	require.Contains(t, keyPath, filepath.Join(dir, "certificates"))
}
