// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"fmt"
	"sync"

	"github.com/bufbuild/protovalidate-go"
	"google.golang.org/protobuf/proto"

	bootstrapv1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/bootstrap/v1"
)

var (
	validateFn    func(proto.Message) error
	validatorOnce sync.Once
)

func Validate[T proto.Message](obj T) error {
	validatorOnce.Do(func() {
		validator, err := protovalidate.New(
			protovalidate.WithMessages(
				&bootstrapv1.PDPConfig{},
			),
		)
		if err != nil {
			validateFn = func(_ proto.Message) error {
				return fmt.Errorf("failed to initialize validator: %w", err)
			}
		} else {
			validateFn = func(m proto.Message) error {
				return validator.Validate(m)
			}
		}
	})

	return validateFn(obj)
}
