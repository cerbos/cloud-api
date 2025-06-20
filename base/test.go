// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build tests

package base

func ResetCircuitBreaker() {
	circuitBreaker = newCircuitBreaker()
}

func (c Client) BypassCircuitBreaker() {
	c.circuitBreaker.enabled = false
}
