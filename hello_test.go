package mallcoplegion_test

import "testing"

func TestHello(t *testing.T) {
	got := "mallcop-legion"
	if got == "" {
		t.Fatal("expected non-empty module name")
	}
}
