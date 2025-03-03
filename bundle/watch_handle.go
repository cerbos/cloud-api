// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"errors"
	"time"

	"github.com/sourcegraph/conc/pool"
)

var _ WatchHandle = (*WatchHandleImpl[string])(nil)

var errFailedToNotifyBundleChange = errors.New("failed to notify server about bundle change")

type WatchHandle interface {
	ServerEvents() <-chan ServerEvent
	Errors() <-chan error
	ActiveBundleChanged(string) error
}

type WatchHandleImpl[T any] struct {
	ServerEventsCh chan ServerEvent
	ClientEventsCh chan ClientEvent
	ErrorsCh       chan error
	Pool           *pool.ContextPool
	Source         T
}

func (wh *WatchHandleImpl[T]) ServerEvents() <-chan ServerEvent {
	return wh.ServerEventsCh
}

func (wh *WatchHandleImpl[T]) ActiveBundleChanged(id string) error {
	select {
	case wh.ClientEventsCh <- ClientEvent{Kind: ClientEventBundleSwap, ActiveBundleID: id}:
		return nil
	default:
		return errFailedToNotifyBundleChange
	}
}

func (wh *WatchHandleImpl[T]) Errors() <-chan error {
	return wh.ErrorsCh
}

func (wh *WatchHandleImpl[T]) trySendError(err error) {
	select {
	case wh.ErrorsCh <- err:
	default:
	}
}

func (wh *WatchHandleImpl[T]) Wait() error {
	err := wh.Pool.Wait()
	wh.trySendError(err)
	close(wh.ErrorsCh)

	return err
}

// ServerEventKind represents events sent by the server through the watch stream.
type ServerEventKind uint8

const (
	ServerEventUndefined ServerEventKind = iota
	ServerEventError
	ServerEventNewBundle
	ServerEventBundleRemoved
	ServerEventReconnect
)

type ServerEvent struct {
	Error            error
	NewBundlePath    string
	EncryptionKey    []byte
	ReconnectBackoff time.Duration
	Kind             ServerEventKind
}

// ClientEventKind represents events sent by the client through the watch stream.
type ClientEventKind uint8

const (
	ClientEventUndefined ClientEventKind = iota
	ClientEventBundleSwap
)

type ClientEvent struct {
	ActiveBundleID string
	Kind           ClientEventKind
}
