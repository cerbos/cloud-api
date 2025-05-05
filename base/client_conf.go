// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package base

import (
	"crypto/tls"
	"errors"
	"fmt"
	"time"

	"buf.build/go/protovalidate"
	"github.com/go-logr/logr"
	"go.uber.org/multierr"

	"github.com/cerbos/cloud-api/credentials"
	pdpv1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/pdp/v1"
)

var (
	errEmptyAPIEndpoint          = errors.New("api endpoint must be defined")
	errEmptyBootstrapEndpoint    = errors.New("bootstrap endpoint must be defined")
	errHeartbeatIntervalTooShort = errors.New("heartbeat interval is too short")
	errMissingCredentials        = errors.New("missing credentials")
	errMissingIdentifier         = errors.New("missing PDP identifier")
)

const (
	defaultHeartbeatInterval = 2 * time.Minute
	defaultRetryWaitMin      = 1 * time.Second
	defaultRetryWaitMax      = 5 * time.Minute
	defaultRetryMaxAttempts  = 10
	minHeartbeatInterval     = 30 * time.Second
)

type ClientConf struct {
	PDPIdentifier     *pdpv1.Identifier
	TLS               *tls.Config
	Logger            logr.Logger
	Credentials       *credentials.Credentials
	APIEndpoint       string
	BootstrapEndpoint string
	RetryWaitMin      time.Duration
	RetryWaitMax      time.Duration
	RetryMaxAttempts  int
	HeartbeatInterval time.Duration
}

func (cc ClientConf) Validate() (outErr error) {
	if cc.Credentials == nil {
		outErr = multierr.Append(outErr, errMissingCredentials)
	}

	if cc.APIEndpoint == "" {
		outErr = multierr.Append(outErr, errEmptyAPIEndpoint)
	}

	if cc.BootstrapEndpoint == "" {
		outErr = multierr.Append(outErr, errEmptyBootstrapEndpoint)
	}

	if cc.PDPIdentifier == nil {
		outErr = multierr.Append(outErr, errMissingIdentifier)
	} else if err := protovalidate.Validate(cc.PDPIdentifier); err != nil {
		outErr = multierr.Append(outErr, fmt.Errorf("invalid PDP identifier: %w", err))
	}

	if cc.HeartbeatInterval > 0 && cc.HeartbeatInterval < minHeartbeatInterval {
		outErr = multierr.Append(outErr, errHeartbeatIntervalTooShort)
	}

	return outErr
}

func (cc *ClientConf) SetDefaults() {
	if cc.RetryMaxAttempts == 0 {
		cc.RetryMaxAttempts = defaultRetryMaxAttempts
	}

	if cc.RetryWaitMin == 0 {
		cc.RetryWaitMin = defaultRetryWaitMin
	}

	if cc.RetryWaitMax == 0 {
		cc.RetryWaitMax = defaultRetryWaitMax
	}

	if cc.HeartbeatInterval == 0 {
		cc.HeartbeatInterval = defaultHeartbeatInterval
	}
}

type logWrapper struct {
	logr.Logger
}

func (lw logWrapper) Printf(msg string, args ...any) {
	if log := lw.V(1); log.Enabled() {
		log.Info(fmt.Sprintf(msg, args...))
	}
}
