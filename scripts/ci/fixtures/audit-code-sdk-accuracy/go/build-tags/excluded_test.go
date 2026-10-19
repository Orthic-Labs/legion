//go:build legion_never_enabled

package fixture

import "testing"

func TestExcluded(t *testing.T) {
	t.Fatal("excluded build-tag test must not run")
}
