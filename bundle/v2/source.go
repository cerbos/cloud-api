// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package v2

import (
	"encoding/base64"
	"fmt"
	"path"

	"github.com/cerbos/cloud-api/bundle"
	"github.com/cerbos/cloud-api/credentials"
	bundlev2 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/bundle/v2"
)

type Source interface {
	String() string
	ToProto() *bundlev2.Source
	bootstrapBundleURLPath(*credentials.Credentials) (string, error)
}

func sourceFromProto(source *bundlev2.Source) (Source, error) {
	switch source := source.GetSource().(type) {
	case *bundlev2.Source_DeploymentId:
		return DeploymentID(source.DeploymentId), nil
	case *bundlev2.Source_PlaygroundId:
		return PlaygroundID(source.PlaygroundId), nil
	default:
		return nil, fmt.Errorf("unknown bundle source %T", source)
	}
}

type DeploymentID string

func (d DeploymentID) String() string {
	return "deployment:" + string(d)
}

func (d DeploymentID) ToProto() *bundlev2.Source {
	return &bundlev2.Source{Source: &bundlev2.Source_DeploymentId{DeploymentId: string(d)}}
}

func (d DeploymentID) bootstrapBundleURLPath(creds *credentials.Credentials) (string, error) {
	return path.Join("bootstrap/v2", string(d), creds.ClientID, base64.RawURLEncoding.EncodeToString(creds.BootstrapKey)), nil
}

type PlaygroundID string

func (p PlaygroundID) String() string {
	return "playground:" + string(p)
}

func (p PlaygroundID) ToProto() *bundlev2.Source {
	return &bundlev2.Source{Source: &bundlev2.Source_PlaygroundId{PlaygroundId: string(p)}}
}

func (p PlaygroundID) bootstrapBundleURLPath(*credentials.Credentials) (string, error) {
	return "", bundle.ErrBootstrappingNotSupported
}
