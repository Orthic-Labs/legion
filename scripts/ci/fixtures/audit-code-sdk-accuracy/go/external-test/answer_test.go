package fixture_test

import (
	"testing"

	fixture "example.invalid/legion-code-fixture"
)

func TestExternal(t *testing.T) {
	if fixture.Add(2, 3) != 5 {
		t.Fatal("external test package must execute")
	}
}
