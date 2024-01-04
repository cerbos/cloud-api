// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"errors"

	"github.com/sourcegraph/conc/pool"
)

var _ WatchHandle = (*watchHandleImpl)(nil)

var errFailedToNotifyBundleChange = errors.New("failed to notify server about bundle change")

type WatchHandle interface {
	ServerEvents() <-chan ServerEvent
	Errors() <-chan error
	ActiveBundleChanged(string) error
}

type watchHandleImpl struct {
	serverEvents chan ServerEvent
	clientEvents chan ClientEvent
	errors       chan error
	p            *pool.ContextPool
	bundleLabel  string
}

func (wh *watchHandleImpl) ServerEvents() <-chan ServerEvent {
	return wh.serverEvents
}

func (wh *watchHandleImpl) ActiveBundleChanged(id string) error {
	select {
	case wh.clientEvents <- ClientEvent{Kind: ClientEventBundleSwap, ActiveBundleID: id}:
		return nil
	default:
		return errFailedToNotifyBundleChange
	}
}

func (wh *watchHandleImpl) Errors() <-chan error {
	return wh.errors
}

func (wh *watchHandleImpl) trySendError(err error) {
	select {
	case wh.errors <- err:
	default:
	}
}

func (wh *watchHandleImpl) wait() error {
	err := wh.p.Wait()
	wh.trySendError(err)
	close(wh.errors)

	return err
}
