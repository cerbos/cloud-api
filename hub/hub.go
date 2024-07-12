// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package hub

import (
	"fmt"
	"sync"

	"connectrpc.com/connect"

	"github.com/cerbos/cloud-api/base"
	"github.com/cerbos/cloud-api/bundle"
	"github.com/cerbos/cloud-api/logcap"
)

var (
	mu       sync.RWMutex
	instance *Hub
)

type Hub struct {
	opts   []connect.ClientOption
	client base.Client
}

func Get(conf base.ClientConf) (*Hub, error) {
	mu.RLock()
	i := instance
	mu.RUnlock()

	if i != nil {
		return i, nil
	}

	mu.Lock()
	defer mu.Unlock()

	if instance != nil {
		return instance, nil
	}

	i, err := New(conf)
	if err != nil {
		return nil, fmt.Errorf("failed to create base Hub client: %w", err)
	}

	instance = i
	return instance, nil
}

func New(conf base.ClientConf) (*Hub, error) {
	client, opts, err := base.NewClient(conf)
	if err != nil {
		return nil, fmt.Errorf("failed to create base Hub client: %w", err)
	}

	return &Hub{
		client: client,
		opts:   opts,
	}, nil
}

func (h *Hub) BundleClient(conf bundle.ClientConf) (*bundle.Client, error) {
	return bundle.NewClient(conf, h.client, h.opts)
}

func (h *Hub) LogCapClient() (*logcap.Client, error) {
	return logcap.NewClient(h.client, h.opts)
}
