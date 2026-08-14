package outbound

import (
	"errors"
	"testing"
)

type blackstoneCloseFixture struct {
	calls int
	err   error
}

func (fixture *blackstoneCloseFixture) Close() error {
	fixture.calls++
	return fixture.err
}

func TestReplaceBlackstoneResourceClosesPreviousResource(t *testing.T) {
	previous := &blackstoneCloseFixture{}
	next := &blackstoneCloseFixture{}
	current, err := replaceBlackstoneResource(previous, next)
	if err != nil {
		t.Fatalf("replaceBlackstoneResource returned error: %v", err)
	}
	if previous.calls != 1 {
		t.Fatalf("previous resource close calls = %d", previous.calls)
	}
	if current != next {
		t.Fatal("replacement resource was not retained")
	}
}

func TestReplaceBlackstoneResourcePreservesPreviousOnCloseError(t *testing.T) {
	previous := &blackstoneCloseFixture{err: errors.New("close failed")}
	next := &blackstoneCloseFixture{}
	current, err := replaceBlackstoneResource(previous, next)
	if err == nil {
		t.Fatal("expected close error")
	}
	if current != previous {
		t.Fatal("failed replacement must preserve previous resource")
	}
}
