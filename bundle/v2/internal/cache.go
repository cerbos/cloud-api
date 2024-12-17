// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"context"
	"errors"
	"io"
	"net/http"

	"github.com/rogpeppe/go-internal/cache"

	"github.com/cerbos/cloud-api/bundle/clientcache"
)

var ErrEncryptionKeyNotFound = errors.New("encryption key not found")

type ClientCache struct {
	encryptionKeys map[cache.ActionID][]byte
	cache          *clientcache.ClientCache
}

func NewClientCache(dir, tempDir string) (*ClientCache, error) {
	clientCache, err := clientcache.New(dir, tempDir)
	if err != nil {
		return nil, err
	}

	return &ClientCache{
		cache:          clientCache,
		encryptionKeys: make(map[cache.ActionID][]byte),
	}, nil
}

func (c *ClientCache) Add(bundleCacheKey cache.ActionID, encryptionKey []byte, in io.Reader) (path string, checksum []byte, err error) {
	if path, checksum, err = c.cache.Add(bundleCacheKey, in); err != nil {
		return "", nil, err
	}

	c.encryptionKeys[bundleCacheKey] = encryptionKey
	return path, checksum, err
}

func (c *ClientCache) AddSegment(ctx context.Context, cacheKey cache.ActionID, checksum []byte, resp *http.Response) (path string, err error) {
	return c.cache.AddSegment(ctx, cacheKey, checksum, resp)
}

func (c *ClientCache) UpdateLabelCache(bundleLabel string, encryptionKey []byte, bundleCacheKey cache.ActionID) error {
	if err := c.cache.UpdateLabelCache(bundleLabel, bundleCacheKey); err != nil {
		return err
	}

	c.encryptionKeys[bundleCacheKey] = encryptionKey
	return nil
}

func (c *ClientCache) Get(bundleCacheKey cache.ActionID) (path string, encryptionKey []byte, err error) {
	if path, err = c.cache.Get(bundleCacheKey); err != nil {
		return "", nil, err
	}

	var ok bool
	if encryptionKey, ok = c.encryptionKeys[bundleCacheKey]; !ok {
		return "", nil, ErrEncryptionKeyNotFound
	}

	return path, encryptionKey, nil
}

func (c *ClientCache) GetSegment(segmentCacheKey cache.ActionID) (path string, err error) {
	return c.cache.Get(segmentCacheKey)
}

func (c *ClientCache) GetBytes(labelCacheKey cache.ActionID) (entryBytes []byte, err error) {
	return c.cache.GetBytes(labelCacheKey)
}
