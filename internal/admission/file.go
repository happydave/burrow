package admission

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// keepFor bounds the file: records older than this are dropped on write.
const keepFor = 24 * time.Hour

// File is a Store in one JSON file, shared by processes on one host. Every
// operation holds an exclusive flock on a sibling lock file, and writes go
// to a temporary file renamed into place. It needs flock, so it works on
// Unix systems only; elsewhere every operation fails with
// ErrFileStoreUnsupported.
type File struct {
	Path string
	// Now dates the 24-hour pruning; nil means the wall clock. A test that
	// reserves at a fixed time sets it to that time, or its records would
	// age out once that time is a day old.
	Now func() time.Time
}

func (f *File) locked(fn func(records []Record) ([]Record, error)) error {
	lock, err := os.OpenFile(f.Path+".lock", os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close()
	unlock, err := flock(lock)
	if err != nil {
		return err
	}
	defer unlock()
	var records []Record
	data, err := os.ReadFile(f.Path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return err
	default:
		if err := json.Unmarshal(data, &records); err != nil {
			return fmt.Errorf("admission: %s is not a valid history: %w", f.Path, err)
		}
	}
	out, err := fn(records)
	if err != nil || out == nil {
		return err
	}
	clock := f.Now
	if clock == nil {
		clock = time.Now
	}
	cutoff := clock().Add(-keepFor)
	kept := out[:0]
	for _, r := range out {
		if r.Time.After(cutoff) || r.Outcome == Pending {
			kept = append(kept, r)
		}
	}
	data, err = json.MarshalIndent(kept, "", " ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(f.Path), ".admission-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), f.Path)
}

func (f *File) Reserve(domain, remote string, p Policy, now time.Time) (string, error) {
	var id string
	err := f.locked(func(rs []Record) ([]Record, error) {
		if !Allowed(filter(rs, domain), p, now) {
			return nil, fmt.Errorf("%w: domain %s", ErrRefused, domain)
		}
		id = newID()
		return append(rs, Record{ID: id, Domain: domain, Time: now, Remote: remote, Outcome: Pending}), nil
	})
	return id, err
}

func (f *File) Complete(id string, o Outcome) error {
	return f.locked(func(rs []Record) ([]Record, error) {
		for i := range rs {
			if rs[i].ID == id {
				rs[i].Outcome = o
				return rs, nil
			}
		}
		return nil, fmt.Errorf("admission: no record %s", id)
	})
}

func (f *File) Records(domain string) ([]Record, error) {
	var out []Record
	err := f.locked(func(rs []Record) ([]Record, error) {
		out = filter(rs, domain)
		return nil, nil
	})
	return out, err
}
