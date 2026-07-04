package netbackend

import (
	"context"
	"io"
	"net"
	"testing"
)

type fakeStreamBackend struct {
	name string
}

func (f fakeStreamBackend) Name() string { return f.name }

func (f fakeStreamBackend) OpenPairing(context.Context, Target) (io.ReadWriteCloser, error) {
	a, b := net.Pipe()
	_ = b.Close()
	return a, nil
}

func (f fakeStreamBackend) OpenTunnel(context.Context, Target) (io.ReadWriteCloser, error) {
	a, b := net.Pipe()
	_ = b.Close()
	return a, nil
}

func TestRegistryRegisterAliasAndUnregister(t *testing.T) {
	reg := NewRegistry()
	backend := fakeStreamBackend{name: "primary"}

	reg.Register(backend, "alias")
	if _, ok := reg.Get("primary"); !ok {
		t.Fatal("primary backend not registered")
	}
	if _, ok := reg.Get("alias"); !ok {
		t.Fatal("alias backend not registered")
	}

	reg.Unregister("alias")
	if _, ok := reg.Get("alias"); ok {
		t.Fatal("alias backend still registered after unregister")
	}
	if _, ok := reg.Get("primary"); !ok {
		t.Fatal("primary backend should remain registered")
	}
}

func TestRegistryMustGetMissingBackend(t *testing.T) {
	reg := NewRegistry()
	if _, err := reg.MustGet("missing"); err == nil {
		t.Fatal("missing backend should return an error")
	}
}

type fakeLifecycleBackend struct {
	fakeStreamBackend
	started string
	stopped bool
}

func (f *fakeLifecycleBackend) Start(_ context.Context, backend string) error {
	f.started = backend
	return nil
}

func (f *fakeLifecycleBackend) Stop(context.Context) error {
	f.stopped = true
	return nil
}

func (f *fakeLifecycleBackend) Running() bool { return f.started != "" && !f.stopped }

func TestRegistryLifecycleStartStop(t *testing.T) {
	reg := NewRegistry()
	backend := &fakeLifecycleBackend{fakeStreamBackend: fakeStreamBackend{name: "primary"}}
	reg.Register(backend, "alias")

	if err := reg.Start(context.Background(), "alias"); err != nil {
		t.Fatalf("start: %v", err)
	}
	if backend.started != "alias" {
		t.Fatalf("started backend = %q, want alias", backend.started)
	}
	if err := reg.Stop(context.Background(), "alias"); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if !backend.stopped {
		t.Fatal("backend was not stopped")
	}
}
