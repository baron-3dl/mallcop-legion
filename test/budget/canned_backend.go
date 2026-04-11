//go:build e2e

// Package budget contains the chain budget enforcement integration test.
//
// canned_backend.go — re-exports the shared CannedBackend and CannedRequest
// types from internal/testutil/cannedbackend so that chain_budget_test.go can
// continue to reference them without a package-path change.
//
// The implementation has been promoted to internal/testutil/cannedbackend/ so
// that test/quality can also import it without cross-package build-tag issues.
// See internal/testutil/cannedbackend/cannedbackend.go for the full source.
package budget

import "github.com/thirdiv/mallcop-legion/internal/testutil/cannedbackend"

// CannedBackend re-exports the shared type for use in chain_budget_test.go.
type CannedBackend = cannedbackend.CannedBackend

// CannedRequest re-exports the shared type.
type CannedRequest = cannedbackend.CannedRequest
