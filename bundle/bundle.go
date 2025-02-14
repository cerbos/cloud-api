// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"time"

	"go.uber.org/multierr"
)

type Version uint

const (
	VersionUnspecified Version = 0
	Version1           Version = 1
	Version2           Version = 2
)

const (
	DefaultBackoff      = 5 * time.Minute
	MaxDownloadAttempts = 3

	bufPeekSize      = 256
	bufSize          = 10 * 1024   // 10 KiB
	MaxBootstrapSize = 1024 * 1024 // 1MiB

	BundleIDUnknown  = "__unknown__"
	BundleIDOrphaned = "__orphaned__"
)

var JSONStart = []byte("{")

var (
	ErrBootstrapBundleNotFound         = errors.New("bootstrap bundle not found")
	ErrBootstrapBundleResponseNotFound = errors.New("bootstrap bundle response not found")
	ErrBootstrappingNotSupported       = errors.New("bootstrapping is not supported for the bundle source")
	ErrBundleNotFound                  = errors.New("bundle not found")
	ErrDownloadFailed                  = errors.New("download failed")
	ErrNoSegmentDownloadURL            = errors.New("no download URLs")
	ErrInvalidResponse                 = errors.New("invalid response from server")
	ErrStreamEnded                     = errors.New("stream ended")
)

type Ring struct {
	elements []string
	idx      int
}

func NewRing(elements []string) *Ring {
	return &Ring{
		elements: elements,
		idx:      rand.Intn(len(elements)), //nolint:gosec
	}
}

func (r *Ring) Next() string {
	el := r.elements[r.idx]
	r.idx = (r.idx + 1) % len(r.elements)
	return el
}

func (r *Ring) Size() int {
	return len(r.elements)
}

type SegmentJoiner struct {
	readers []io.ReadCloser
}

func NewSegmentJoiner(numSegments int) *SegmentJoiner {
	return &SegmentJoiner{readers: make([]io.ReadCloser, 0, numSegments)}
}

func (sj *SegmentJoiner) Add(file string) error {
	f, err := os.Open(file)
	if err != nil {
		return fmt.Errorf("failed to open %q: %w", file, err)
	}

	sj.readers = append(sj.readers, f)
	return nil
}

func (sj *SegmentJoiner) Close() (outErr error) {
	for _, r := range sj.readers {
		if err := r.Close(); err != nil {
			outErr = multierr.Append(outErr, err)
		}
	}

	return outErr
}

func (sj *SegmentJoiner) Join() io.ReadCloser {
	readers := make([]io.Reader, len(sj.readers))
	for i, r := range sj.readers {
		readers[i] = r
	}

	mr := io.MultiReader(readers...)
	return struct {
		io.Reader
		*SegmentJoiner
	}{
		Reader:        mr,
		SegmentJoiner: sj,
	}
}

// ReconnectError is the error returned when the server requests a reconnect.
type ReconnectError struct {
	Backoff time.Duration
}

func (er ReconnectError) Error() string {
	return fmt.Sprintf("reconnect in %s", er.Backoff)
}
