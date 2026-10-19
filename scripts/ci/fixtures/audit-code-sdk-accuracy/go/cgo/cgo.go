//go:build legion_never_enabled && cgo

package fixture

/*
int legion_unused(void) { return 1; }
*/
import "C"

func unusedCgo() int {
	return int(C.legion_unused())
}
