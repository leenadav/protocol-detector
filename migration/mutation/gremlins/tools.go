//go:build tools

// Package tools records the mutation-testing tool as a module requirement, so go.mod and go.sum pin its version
// and hashes.
package tools

import _ "github.com/go-gremlins/gremlins/cmd/gremlins"
