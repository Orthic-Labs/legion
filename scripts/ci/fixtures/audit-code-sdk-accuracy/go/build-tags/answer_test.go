package fixture

import "testing"

func TestSelected(t *testing.T) {
	if Selected() != 42 {
		t.Fatal("selected build-tag function must execute")
	}
}
