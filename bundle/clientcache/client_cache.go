// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package clientcache

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/minio/sha256-simd"
	"github.com/rogpeppe/go-internal/cache"
)

var errChecksumMismatch = errors.New("checksum mismatch")

const HashSize = cache.HashSize

func New(dir, tempDir string) (*ClientCache, error) {
	c, err := mkCache(dir)
	if err != nil {
		return nil, err
	}

	return &ClientCache{
		cache:   c,
		tempDir: tempDir,
	}, nil
}

type ClientCache struct {
	cache   *cache.Cache
	tempDir string
}

func (c *ClientCache) AddSegment(_ context.Context, cacheKey cache.ActionID, checksum []byte, resp *http.Response) (string, error) {
	file, cs, err := c.Add(cacheKey, resp.Body)
	if err != nil {
		return "", err
	}

	if !bytes.Equal(checksum, cs) {
		return "", errChecksumMismatch
	}

	return file, nil
}

func (c *ClientCache) Add(cacheKey cache.ActionID, in io.Reader) (string, []byte, error) {
	outFile, err := os.CreateTemp(c.tempDir, "cerbos-*")
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temporary file: %w", err)
	}
	defer func() {
		_ = outFile.Close()
		_ = os.Remove(outFile.Name())
	}()

	sum := sha256.New()
	mw := io.MultiWriter(outFile, sum)
	if _, err := io.Copy(mw, in); err != nil {
		return "", nil, fmt.Errorf("failed to write data to disk: %w", err)
	}

	out, _, err := c.cache.Put(cacheKey, outFile)
	if err != nil {
		return "", nil, fmt.Errorf("failed to add data to cache: %w", err)
	}

	return c.cache.OutputFile(out), sum.Sum(nil), nil
}

func (c *ClientCache) Get(key cache.ActionID) (string, error) {
	entry, err := c.cache.Get(key)
	if err != nil {
		return "", fmt.Errorf("failed to get from cache: %w", err)
	}

	return c.cache.OutputFile(entry.OutputID), nil
}

func (c *ClientCache) GetBytes(key cache.ActionID) ([]byte, error) {
	entry, _, err := c.cache.GetBytes(key)
	if err != nil {
		return nil, fmt.Errorf("failed to get bytes from cache: %w", err)
	}

	if len(entry) != cache.HashSize {
		return nil, errors.New("invalid cache entry for label")
	}

	return entry, nil
}

func (c *ClientCache) UpdateSourceCache(source string, bundleCacheKey cache.ActionID) error {
	return c.cache.PutBytes(SourceCacheKey(source), bundleCacheKey[:])
}

func mkCache(path string) (*cache.Cache, error) {
	cacheDir := path
	if cacheDir == "" {
		userCacheDir, err := os.UserCacheDir()
		if err != nil {
			return nil, fmt.Errorf("failed to determine user cache directory: %w", err)
		}

		cacheDir = filepath.Join(userCacheDir, "cerbos", "cloud", "bundles")
		//nolint:gomnd
		if err := os.MkdirAll(cacheDir, 0o774); err != nil {
			return nil, fmt.Errorf("failed to create cache directory %q: %w", cacheDir, err)
		}
	}

	c, err := cache.Open(cacheDir)
	if err != nil {
		return nil, fmt.Errorf("failed to open cache at %q: %w", cacheDir, err)
	}

	return c, nil
}

func SegmentCacheKey(checksum []byte) cache.ActionID {
	s := sha256.New()
	_, _ = fmt.Fprint(s, "segment:")
	_, _ = s.Write(checksum)
	return *((*cache.ActionID)(s.Sum(nil)))
}

func SourceCacheKey(source string) cache.ActionID {
	s := sha256.New()
	_, _ = fmt.Fprintf(s, "cerbos:cloud:bundle:source=%s", source)
	return *((*cache.ActionID)(s.Sum(nil)))
}
