// Taken from https://github.com/chinzhiweiblank/coredns-acme/blob/e0cdfbdd78adfcc6c2d098255902f64ec60daecb/provider.go
// Copyright @chinzhiweiblank under Apache License 2.0
package acme

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/libdns/libdns"
)

type RecordStore struct {
	entries []libdns.Record
}

type Provider struct {
	sync.Mutex
	recordMap map[string]*RecordStore
	// dir is a directory of per-zone JSON files. When set, records are read
	// and written there under an exclusive file lock so every pod mounted on
	// the same directory answers the DNS-01 TXT from the same data.
	dir string
}

// NewProvider returns an in-memory provider when dir is empty. A non-empty
// dir is the shared record directory (one JSON file per zone).
func NewProvider(dir string) *Provider {
	return &Provider{Mutex: sync.Mutex{}, recordMap: make(map[string]*RecordStore), dir: dir}
}

func (p *Provider) getZoneRecords(_ context.Context, zoneName string) *RecordStore {
	return p.recordMap[zoneName]
}

func compareRecords(a, b libdns.Record) bool {
	rrA := a.RR()
	rrB := b.RR()
	return rrA.Type == rrB.Type && rrA.Name == rrB.Name && rrA.Data == rrB.Data && rrA.TTL == rrB.TTL
}

func (r *RecordStore) deleteRecords(recs []libdns.Record) []libdns.Record {
	var deletedRecords []libdns.Record
	for i, entry := range r.entries {
		for _, record := range recs {
			if compareRecords(entry, record) {
				deletedRecords = append(deletedRecords, record)
				r.entries = append(r.entries[:i], r.entries[i+1:]...)
			}
		}
	}
	return deletedRecords
}

func (p *Provider) AppendRecords(ctx context.Context, zoneName string, recs []libdns.Record) ([]libdns.Record, error) {
	if p.dir != "" {
		return p.appendRecordsFile(zoneName, recs)
	}
	p.Lock()
	defer p.Unlock()
	zoneRecordStore := p.getZoneRecords(ctx, zoneName)
	if zoneRecordStore == nil {
		zoneRecordStore = new(RecordStore)
		p.recordMap[zoneName] = zoneRecordStore
	}

	// ACME DNS challenge need only one record, old record should be deleted
	if strings.HasPrefix(strings.ToLower(zoneName), DNSChallengeString) {
		zoneRecordStore.entries = recs
	} else {
		zoneRecordStore.entries = append(zoneRecordStore.entries, recs...)
	}

	return zoneRecordStore.entries, nil
}

func (p *Provider) DeleteRecords(ctx context.Context, zoneName string, recs []libdns.Record) ([]libdns.Record, error) {
	if p.dir != "" {
		return p.deleteRecordsFile(zoneName, recs)
	}
	p.Lock()
	defer p.Unlock()
	zoneRecordStore := p.getZoneRecords(ctx, zoneName)
	if zoneRecordStore == nil {
		return nil, nil
	}
	deletedRecords := zoneRecordStore.deleteRecords(recs)
	return deletedRecords, nil
}

func (p *Provider) GetRecords(ctx context.Context, zoneName string) ([]libdns.Record, error) {
	if p.dir != "" {
		return p.getRecordsFile(zoneName)
	}
	p.Lock()
	defer p.Unlock()
	records := p.getZoneRecords(ctx, zoneName)
	if records == nil {
		return nil, fmt.Errorf("no records were found for %v", zoneName)
	}
	return records.entries, nil
}

func (p *Provider) appendRecordsFile(zoneName string, recs []libdns.Record) ([]libdns.Record, error) {
	var stored []libdns.Record
	err := p.withZoneFile(zoneName, true, func(store *RecordStore) error {
		if store == nil {
			store = &RecordStore{}
		}
		if strings.HasPrefix(strings.ToLower(zoneName), DNSChallengeString) {
			store.entries = recs
		} else {
			store.entries = append(store.entries, recs...)
		}
		stored = copyRecords(store.entries)
		return p.saveZone(zoneName, store)
	})
	return stored, err
}

func (p *Provider) deleteRecordsFile(zoneName string, recs []libdns.Record) ([]libdns.Record, error) {
	var deleted []libdns.Record
	err := p.withZoneFile(zoneName, true, func(store *RecordStore) error {
		if store == nil {
			return nil
		}
		deleted = store.deleteRecords(recs)
		return p.saveZone(zoneName, store)
	})
	return deleted, err
}

func (p *Provider) getRecordsFile(zoneName string) ([]libdns.Record, error) {
	var entries []libdns.Record
	err := p.withZoneFile(zoneName, false, func(store *RecordStore) error {
		if store == nil || len(store.entries) == 0 {
			return fmt.Errorf("no records were found for %v", zoneName)
		}
		entries = copyRecords(store.entries)
		return nil
	})
	return entries, err
}

// withZoneFile holds an advisory lock for zone so pods sharing dir cannot
// interleave a read with a replace of the TXT record.
//
// Only writers create the lock file. ServeDNS forwards every in-domain
// _acme-challenge TXT query to a read, so creating a lock before the zone
// exists would let an unauthenticated sender leave a permanent file per
// unique name and exhaust inodes on the shared volume. Readers open the
// existing lock without O_CREATE and fail when it is absent.
func (p *Provider) withZoneFile(zoneName string, exclusive bool, fn func(*RecordStore) error) error {
	if err := os.MkdirAll(p.dir, 0o755); err != nil {
		return err
	}
	flags := os.O_RDWR
	if exclusive {
		flags |= os.O_CREATE
	}
	lockFile, err := os.OpenFile(p.zonePath(zoneName)+".lock", flags, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = lockFile.Close() }()

	how := syscall.LOCK_SH
	if exclusive {
		how = syscall.LOCK_EX
	}
	if err := syscall.Flock(int(lockFile.Fd()), how); err != nil {
		return err
	}
	defer func() { _ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN) }()

	store, err := p.loadZone(zoneName)
	if err != nil {
		return err
	}
	return fn(store)
}

func (p *Provider) zonePath(zoneName string) string {
	name := strings.ToLower(strings.Trim(strings.TrimSpace(zoneName), "."))
	name = strings.ReplaceAll(name, "/", "_")
	if name == "" {
		name = "root"
	}
	return filepath.Join(p.dir, name+".json")
}

func (p *Provider) loadZone(zoneName string) (*RecordStore, error) {
	data, err := os.ReadFile(p.zonePath(zoneName))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return &RecordStore{}, nil
	}
	var rrs []libdns.RR
	if err := json.Unmarshal(data, &rrs); err != nil {
		return nil, err
	}
	store := &RecordStore{entries: make([]libdns.Record, 0, len(rrs))}
	for _, rr := range rrs {
		store.entries = append(store.entries, rr)
	}
	return store, nil
}

func (p *Provider) saveZone(zoneName string, store *RecordStore) error {
	rrs := make([]libdns.RR, 0, len(store.entries))
	for _, rec := range store.entries {
		rrs = append(rrs, rec.RR())
	}
	data, err := json.Marshal(rrs)
	if err != nil {
		return err
	}
	path := p.zonePath(zoneName)
	tmp, err := os.CreateTemp(p.dir, "zone-*.json")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, path)
}

func copyRecords(entries []libdns.Record) []libdns.Record {
	out := make([]libdns.Record, len(entries))
	copy(out, entries)
	return out
}

var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)

const (
	DNSChallengeString   = "_acme-challenge."
	CertificateAuthority = "letsencrypt.org."
)
