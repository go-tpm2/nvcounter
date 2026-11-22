package nvcounter

// End to end against a software TPM: swtpm's raw TPM 2.0 stream on a unix
// socket, reached through the real connect. Skipped when swtpm is not
// installed, unless NVCOUNTER_REQUIRE_SWTPM is set (CI sets it): a skipped
// test is not a pass.

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// startSwtpm launches a fresh swtpm and returns the "unix:" device naming it.
func startSwtpm(t *testing.T) string {
	t.Helper()
	bin, err := exec.LookPath("swtpm")
	if err != nil {
		if os.Getenv("NVCOUNTER_REQUIRE_SWTPM") != "" {
			t.Fatal("swtpm not installed and NVCOUNTER_REQUIRE_SWTPM is set")
		}
		t.Skip("swtpm not installed")
	}
	dir, err := os.MkdirTemp("", "sw") // short: unix socket paths are limited to ~100 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	state := filepath.Join(dir, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "d")
	cmd := exec.Command(bin, "socket", "--tpm2", "--tpmstate", "dir="+state,
		"--server", "type=unixio,path="+sock, "--ctrl", "type=unixio,path="+filepath.Join(dir, "c"),
		"--flags", "not-need-init,startup-clear", "--log", "level=1")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
		if _, err := os.Stat(sock); err == nil {
			return "unix:" + sock
		}
	}
	t.Fatal("swtpm did not create its socket")
	return ""
}

func TestSwtpmCounter(t *testing.T) {
	dev := startSwtpm(t)
	opts := Options{Device: dev, Auth: []byte("index secret")}
	ctr, err := Create(opts)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if ctr.Handle() != First {
		t.Fatalf("handle %#x, want the first free one", ctr.Handle())
	}
	// A second counter takes the next free handle.
	other, err := Create(Options{Device: dev, Auth: []byte("x")})
	if err != nil || other.Handle() != First+1 {
		t.Fatalf("second Create: %v, handle %#x", err, other.Handle())
	}
	// An index nobody incremented cannot be read yet (TPM_RC_NV_UNINITIALIZED).
	if _, err := ctr.Read(); err == nil {
		t.Fatal("read of a counter that was never incremented")
	}
	nameBefore := append([]byte(nil), ctr.Name()...)
	if err := ctr.Increment(); err != nil {
		t.Fatal(err)
	}
	before, err := ctr.Read()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := ctr.Increment(); err != nil {
			t.Fatalf("Increment %d: %v", i, err)
		}
	}
	after, err := ctr.Read()
	if err != nil || after != before+2 {
		t.Fatalf("counter %d -> %d (%v) after two increments", before, after, err)
	}
	// The Name covers TPMA_NV_WRITTEN: it changed once, at the first increment.
	if bytes.Equal(nameBefore, ctr.Name()) {
		t.Fatal("the Name did not change at the first increment")
	}
	// Open attaches to it from nothing but the handle, and sees the same value.
	o := opts
	o.Handle = ctr.Handle()
	re, err := Open(o)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if v, err := re.Read(); err != nil || v != after {
		t.Fatalf("reopened counter reads %d (%v), want %d", v, err, after)
	}
	if !bytes.Equal(re.Name(), ctr.Name()) {
		t.Fatalf("reopened Name %x, want %x", re.Name(), ctr.Name())
	}
	// A wrong authValue is refused by the TPM; reading the public area needs none.
	wrong, err := Open(Options{Device: dev, Handle: First, Auth: []byte("wrong")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrong.Read(); err == nil {
		t.Fatal("read with a wrong authValue")
	}
	if err := wrong.Increment(); err == nil {
		t.Fatal("increment with a wrong authValue")
	}
	if v, _ := ctr.Read(); v != after {
		t.Fatalf("a refused increment moved the counter: %d -> %d", after, v)
	}
	// A handle with no index is ErrNoCounter.
	if _, err := Open(Options{Device: dev, Handle: First + 0x800, Auth: opts.Auth}); !errors.Is(err, ErrNoCounter) {
		t.Fatalf("undefined handle: %v, want ErrNoCounter", err)
	}
	// Undo: delete the index (owner password empty on swtpm).
	if err := ctr.Destroy(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(o); !errors.Is(err, ErrNoCounter) {
		t.Fatalf("destroyed counter: %v, want ErrNoCounter", err)
	}
	// Recreating the handle gives a counter above every earlier count (Part 3,
	// p. 376): the reset an attacker would want is not available.
	again, err := Create(Options{Device: dev, Auth: opts.Auth, Handle: First})
	if err != nil {
		t.Fatal(err)
	}
	if err := again.Increment(); err != nil {
		t.Fatal(err)
	}
	if v, err := again.Read(); err != nil || v <= after {
		t.Fatalf("redefined counter reads %d (%v), want more than %d", v, err, after)
	}
}

// The attack that Identity exists for, on two real software TPMs: the same
// handle and Name on a second TPM, raised to the value of the first.
func TestSwtpmIdentity(t *testing.T) {
	devA, devB := startSwtpm(t), startSwtpm(t)
	auth := []byte("index secret")
	ctrA, err := Create(Options{Device: devA, Auth: auth})
	if err != nil {
		t.Fatal(err)
	}
	ctrB, err := Create(Options{Device: devB, Auth: auth})
	if err != nil {
		t.Fatal(err)
	}
	idA, err := ctrA.Identity()
	if err != nil || len(idA) != IDSize {
		t.Fatalf("identity of A: %x %v", idA, err)
	}
	idB, err := ctrB.Identity()
	if err != nil || bytes.Equal(idA, idB) {
		t.Fatalf("two TPMs, identities %x and %x (%v)", idA, idB, err)
	}
	if again, _ := ctrA.Identity(); !bytes.Equal(again, idA) {
		t.Fatal("the identity of one TPM changed between two calls")
	}
	if ctrA.Handle() != ctrB.Handle() {
		t.Fatalf("handles %#x and %#x", ctrA.Handle(), ctrB.Handle())
	}
	for _, c := range []*Counter{ctrA, ctrB} {
		if err := c.Increment(); err != nil {
			t.Fatal(err)
		}
	}
	// Same handle, same Name, same value on two TPMs: the counter alone cannot
	// tell them apart, the identity can.
	if !bytes.Equal(ctrA.Name(), ctrB.Name()) {
		t.Fatalf("the attack needs the same Name: %x vs %x", ctrA.Name(), ctrB.Name())
	}
	va, _ := ctrA.Read()
	vb, _ := ctrB.Read()
	if va != vb {
		t.Fatalf("values %d and %d", va, vb)
	}
}
