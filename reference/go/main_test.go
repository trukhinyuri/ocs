package main

import "testing"

func TestRejectAmbiguousFrames(t *testing.T) {
	for _, s := range []string{
		"{\"x\":1,\"x\":2}", "{\"x\":{\"id\":1,\"id\":2}}", "{\"v\":\"\\uD800\"}",
		"{\"v\":\"\\uDE00\"}", "{\"v\":9007199254740992}", "{\"a\":1} {}", "{\"v\":1e500}",
	} {
		if _, e := decode([]byte(s)); e == nil {
			t.Errorf("accepted invalid frame %q", s)
		}
	}
	if _, e := decode([]byte("{\"v\":\"\\uD83D\\uDE00\"}")); e != nil {
		t.Fatal(e)
	}
}
