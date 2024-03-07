// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"fmt"
	"os"

	"go.uber.org/multierr"

	"github.com/cerbos/cloud-api/base"
)

type ClientConf struct {
	CacheDir string
	TempDir  string
	base.ClientConf
}

func (cc ClientConf) Validate() (outErr error) {
	if err := cc.ClientConf.Validate(); err != nil {
		outErr = multierr.Append(outErr, err)
	}

	if cc.CacheDir != "" {
		if err := validateDir(cc.CacheDir); err != nil {
			outErr = multierr.Append(outErr, err)
		}
	}

	if cc.TempDir != "" {
		if err := validateDir(cc.TempDir); err != nil {
			outErr = multierr.Append(outErr, err)
		}
	}

	return outErr
}

func validateDir(path string) error {
	stat, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to stat %q: %w", path, err)
	}

	if !stat.IsDir() {
		return fmt.Errorf("not a directory: %q", path)
	}

	return nil
}
