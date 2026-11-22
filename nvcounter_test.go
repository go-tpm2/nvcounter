package nvcounter

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/go-tpm2/tpm2"
)

// fakeTPM is an in-memory NV counter store.
type fakeTPM struct {
	pubs    map[uint32]tpm2.NVPublic
	vals    map[uint32]uint64
	written map[uint32]bool
	fail    map[string]error
	always  bool // NVReadPublic reports every handle as taken
	closeEr error
	device  string
	ekName  []byte // EKIdentity's answer; a fixed good Name when nil
	ekAuth  []byte // the endorsement password EKIdentityAuth last received
}

func newFake() *fakeTPM {
	return &fakeTPM{pubs: map[uint32]tpm2.NVPublic{}, vals: map[uint32]uint64{},
		written: map[uint32]bool{}, fail: map[string]error{}}
}

func (f *fakeTPM) NVDefineCounter(owner, idx []byte, h uint32) ([]byte, error) {
	if e := f.fail["define"]; e != nil {
		return nil, e
	}
	f.pubs[h] = tpm2.NVPublic{Index: h, NameAlg: 0x0B, Attributes: tpm2.CounterAttributes, DataSize: 8}
	return []byte{0, 0x0B, byte(h)}, nil
}

func (f *fakeTPM) NVReadPublic(h uint32) (tpm2.NVPublic, []byte, error) {
	if e := f.fail["readpublic"]; e != nil {
		return tpm2.NVPublic{}, nil, e
	}
	p, ok := f.pubs[h]
	if f.always {
		return p, nil, nil
	}
	if !ok {
		return tpm2.NVPublic{}, nil, &tpm2.TPMError{CC: 0x169, RC: 0x18B}
	}
	if f.written[h] {
		p.Attributes |= tpm2.NVWritten
	}
	// The Name covers the WRITTEN attribute: it changes at the first increment.
	return p, []byte{0, 0x0B, byte(h), byte(p.Attributes >> 29 & 1)}, nil
}

func (f *fakeTPM) NVIncrementAuth(hh uint32, auth []byte, h uint32) error {
	if e := f.fail["increment"]; e != nil {
		return e
	}
	f.vals[h]++
	f.written[h] = true
	return nil
}

func (f *fakeTPM) NVReadCounter(auth []byte, h uint32) (uint64, error) {
	if e := f.fail["read"]; e != nil {
		return 0, e
	}
	return f.vals[h], nil
}

func (f *fakeTPM) NVUndefineSpaceAuth(owner []byte, h uint32) error {
	if e := f.fail["undefine"]; e != nil {
		return e
	}
	delete(f.pubs, h)
	return nil
}

func (f *fakeTPM) EKIdentityAuth(auth []byte) ([]byte, error) {
	f.ekAuth = append([]byte(nil), auth...)
	if e := f.fail["ek"]; e != nil {
		return nil, e
	}
	if f.ekName != nil {
		return f.ekName, nil
	}
	return append([]byte{0, 0x0B}, bytes.Repeat([]byte{0x5a}, 32)...), nil
}

// A Name of the right length with the wrong algorithm prefix, and a Name of
// the right prefix and the wrong length, are each refused on their own: the
// two halves of the check are each asserted, none left to a crash.
func TestIdentityNameShape(t *testing.T) {
	f := newFake()
	use(t, f)
	c := &Counter{opts: Options{Device: "unix:x"}}
	for name, n := range map[string][]byte{
		"right length, wrong alg":  append([]byte{0, 0x04}, make([]byte, 32)...),
		"right prefix, one longer": append([]byte{0, 0x0B}, make([]byte, 33)...),
	} {
		f.ekName = n
		id, err := c.Identity()
		if !errors.Is(err, ErrIdentity) || id != nil {
			t.Errorf("%s: %x %v", name, id, err)
		}
	}
}

func TestIdentity(t *testing.T) {
	f := newFake()
	use(t, f)
	c := &Counter{opts: Options{Device: "unix:x"}}
	id, err := c.Identity()
	if err != nil || !bytes.Equal(id, bytes.Repeat([]byte{0x5a}, IDSize)) {
		t.Fatalf("identity %x (%v)", id, err)
	}
	// What the TPM answers is checked, not trusted: a short or oversized Name,
	// or one that is not SHA-256's, is no identity.
	for name, n := range map[string][]byte{
		"short":      {0, 0x0B, 1},
		"long":       bytes.Repeat([]byte{0}, 100),
		"empty":      {},
		"wrong alg":  append([]byte{0, 0x04}, make([]byte, 32)...),
		"wrong alg2": append([]byte{1, 0x0B}, make([]byte, 32)...),
	} {
		f.ekName = n
		if _, err := c.Identity(); !errors.Is(err, ErrIdentity) {
			t.Errorf("%s: %v", name, err)
		}
	}
	f.ekName = nil
	f.fail["ek"] = boom
	// The refusal carries the TPM's own error, not a complaint about a Name that
	// was never returned.
	if _, err := c.Identity(); !errors.Is(err, ErrIdentity) || !strings.Contains(err.Error(), "boom") ||
		strings.Contains(err.Error(), "bytes") {
		t.Fatalf("EK failure: %v", err)
	}
	f.ekName = []byte{0, 0x0B, 1}
	delete(f.fail, "ek")
	if _, err := c.Identity(); !errors.Is(err, ErrIdentity) || !strings.Contains(err.Error(), "3 bytes") {
		t.Fatalf("short Name: %v", err)
	}
	f.ekName = nil
	f.fail["ek"] = boom
	delete(f.fail, "ek")
	f.fail["connect"] = boom
	if _, err := c.Identity(); !errors.Is(err, boom) {
		t.Fatalf("connect failure: %v", err)
	}
}

// The endorsement password goes to the TPM, and a TPM refusing it is
// ErrEndorsementAuth (which also is ErrIdentity), whatever else fails stays
// ErrIdentity only.
func TestIdentityEndorsementAuth(t *testing.T) {
	f := newFake()
	use(t, f)
	c := &Counter{opts: Options{Device: "unix:x", EndorsementAuth: []byte("ek-pw")}}
	if _, err := c.Identity(); err != nil || string(f.ekAuth) != "ek-pw" {
		t.Fatalf("identity %v, the TPM got %q", err, f.ekAuth)
	}
	for name, rc := range map[string]uint32{"bad auth": 0x0A2 + 0x100, "auth fail": 0x08E + 0x100} {
		f.fail["ek"] = &tpm2.TPMError{CC: 0x131, RC: rc}
		_, err := c.Identity()
		if !errors.Is(err, ErrEndorsementAuth) || !errors.Is(err, ErrIdentity) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, e := range map[string]error{
		"another rc":     &tpm2.TPMError{CC: 0x131, RC: 0x9A5}, // format one, TPM_RC_LOCKOUT-like, not an auth refusal
		"format zero":    &tpm2.TPMError{CC: 0x131, RC: 0x22},  // TPM_RC_BAD_AUTH's number without the format-one bit
		"not a TPMError": boom,
	} {
		f.fail["ek"] = e
		if _, err := c.Identity(); errors.Is(err, ErrEndorsementAuth) || !errors.Is(err, ErrIdentity) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Only a format-one TPM_RC_BAD_AUTH or TPM_RC_AUTH_FAIL (whatever the session
// or parameter number) is an authorization refusal.
func TestIsAuthRefusal(t *testing.T) {
	for name, c := range map[string]struct {
		err  error
		want bool
	}{
		"nil":                           {nil, false},
		"not a TPM error":               {boom, false},
		"bad auth":                      {&tpm2.TPMError{RC: 0x0A2}, true},
		"bad auth, session 1":           {&tpm2.TPMError{RC: 0x1A2}, true},
		"auth fail":                     {&tpm2.TPMError{RC: 0x08E}, true},
		"auth fail, session 2":          {&tpm2.TPMError{RC: 0x28E}, true},
		"wrapped":                       {fmt.Errorf("x: %w", &tpm2.TPMError{RC: 0x0A2}), true},
		"bad auth number, format zero":  {&tpm2.TPMError{RC: 0x022}, false},
		"auth fail number, format zero": {&tpm2.TPMError{RC: 0x00E}, false},
		"format one, other":             {&tpm2.TPMError{RC: 0x0A5}, false},
		"lockout":                       {&tpm2.TPMError{RC: 0x921}, false},
	} {
		if got := isAuthRefusal(c.err); got != c.want {
			t.Errorf("%s: %v, want %v", name, got, c.want)
		}
	}
}

func TestCheckEndorsementAuthSize(t *testing.T) {
	use(t, newFake())
	if _, err := Create(Options{Device: "unix:x", EndorsementAuth: make([]byte, 65)}); !errors.Is(err, ErrAuthTooLong) {
		t.Fatalf("65 bytes: %v", err)
	}
	if _, err := Create(Options{Device: "unix:x", OwnerAuth: make([]byte, 65)}); !errors.Is(err, ErrAuthTooLong) {
		t.Fatalf("owner, 65 bytes: %v", err)
	}
	if _, err := Create(Options{Device: "unix:x", EndorsementAuth: make([]byte, 64), OwnerAuth: make([]byte, 64)}); err != nil {
		t.Fatalf("64 bytes: %v", err)
	}
}

// use installs f as the TPM behind connect, for the test's duration.
func use(t *testing.T, f *fakeTPM) {
	t.Helper()
	old, oldOS := connect, goos
	t.Cleanup(func() { connect, goos = old, oldOS })
	goos = "linux"
	connect = func(device string) (nvTPM, func() error, error) {
		f.device = device
		if e := f.fail["connect"]; e != nil {
			return nil, nil, e
		}
		return f, func() error { return f.closeEr }, nil
	}
}

var boom = errors.New("boom")

func TestCreateOpenIncrementRead(t *testing.T) {
	f := newFake()
	use(t, f)
	f.pubs[First] = tpm2.NVPublic{} // taken
	f.pubs[First+1] = tpm2.NVPublic{}
	c, err := Create(Options{Auth: []byte("a")})
	if err != nil {
		t.Fatal(err)
	}
	if c.Handle() != First+2 || len(c.Name()) == 0 || f.device != DefaultLinuxDevice {
		t.Fatalf("handle %#x name %x device %q", c.Handle(), c.Name(), f.device)
	}
	before := string(c.Name())
	if err := c.Increment(); err != nil {
		t.Fatal(err)
	}
	if string(c.Name()) == before {
		t.Fatal("the Name was not refreshed after the first increment")
	}
	if v, err := c.Read(); err != nil || v != 1 {
		t.Fatalf("read %d %v", v, err)
	}
	o, err := Open(Options{Handle: c.Handle(), Auth: []byte("a"), Device: "/dev/x"})
	if err != nil || string(o.Name()) != string(c.Name()) || f.device != "/dev/x" {
		t.Fatalf("open: %v %x", err, o)
	}
	if err := c.Destroy(); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.pubs[c.Handle()]; ok {
		t.Fatal("not destroyed")
	}
}

func TestCreateExplicitHandle(t *testing.T) {
	f := newFake()
	use(t, f)
	c, err := Create(Options{Handle: 0x01500777})
	if err != nil || c.Handle() != 0x01500777 {
		t.Fatalf("%v %v", c, err)
	}
}

func TestCreateErrors(t *testing.T) {
	f := newFake()
	use(t, f)
	if _, err := Create(Options{Auth: make([]byte, 33)}); !errors.Is(err, ErrAuthTooLong) {
		t.Fatalf("auth: %v", err)
	}
	if _, err := Create(Options{OwnerAuth: make([]byte, 65)}); !errors.Is(err, ErrAuthTooLong) {
		t.Fatalf("owner auth: %v", err)
	}
	f.fail["define"] = boom
	if _, err := Create(Options{}); !errors.Is(err, boom) {
		t.Fatalf("define: %v", err)
	}
	delete(f.fail, "define")
	f.fail["readpublic"] = boom
	if _, err := Create(Options{}); !errors.Is(err, boom) {
		t.Fatalf("probe: %v", err)
	}
	delete(f.fail, "readpublic")
	f.always = true
	if _, err := Create(Options{}); !errors.Is(err, ErrNoFreeHandle) {
		t.Fatalf("full: %v", err)
	}
	f.always = false
	f.fail["connect"] = boom
	if _, err := Create(Options{}); !errors.Is(err, boom) {
		t.Fatalf("connect: %v", err)
	}
	delete(f.fail, "connect")
	f.closeEr = boom
	if _, err := Create(Options{}); !errors.Is(err, boom) {
		t.Fatalf("close: %v", err)
	}
}

func TestOpenErrors(t *testing.T) {
	f := newFake()
	use(t, f)
	if _, err := Open(Options{Handle: 1, Auth: make([]byte, 40)}); !errors.Is(err, ErrAuthTooLong) {
		t.Fatalf("auth: %v", err)
	}
	if _, err := Open(Options{Handle: First}); !errors.Is(err, ErrNoCounter) {
		t.Fatalf("open of an undefined handle: %v", err)
	}
	f.fail["readpublic"] = boom
	if _, err := Open(Options{Handle: First}); !errors.Is(err, boom) || errors.Is(err, ErrNoCounter) {
		t.Fatalf("another ReadPublic failure: %v", err)
	}
	delete(f.fail, "readpublic")
	f.pubs[First] = tpm2.NVPublic{Attributes: 0x00060006, DataSize: 32} // an ordinary index
	if _, err := Open(Options{Handle: First}); !errors.Is(err, ErrNotCounter) {
		t.Fatalf("ordinary index: %v", err)
	}
	f.pubs[First] = tpm2.NVPublic{Attributes: tpm2.LegacyCounterAttributes, DataSize: 4}
	if _, err := Open(Options{Handle: First}); !errors.Is(err, ErrNotCounter) {
		t.Fatalf("wrong size: %v", err)
	}
}

func TestOperationErrors(t *testing.T) {
	f := newFake()
	use(t, f)
	c, err := Create(Options{})
	if err != nil {
		t.Fatal(err)
	}
	for name, call := range map[string]func() error{
		"read":       func() error { _, e := c.Read(); return e },
		"increment":  c.Increment,
		"readpublic": c.Increment, // the Name refresh after the increment
		"undefine":   c.Destroy,
	} {
		f.fail[name] = boom
		if err := call(); !errors.Is(err, boom) {
			t.Fatalf("%s: %v", name, err)
		}
		delete(f.fail, name)
	}
}

func TestUnsupportedPlatform(t *testing.T) {
	f := newFake()
	use(t, f)
	for _, os := range []string{"darwin", "freebsd"} {
		goos = os
		if _, err := Create(Options{}); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("%s: %v", os, err)
		}
		// An explicit device is honored anywhere.
		if _, err := Create(Options{Device: "unix:/x"}); err != nil {
			t.Fatalf("%s with a device: %v", os, err)
		}
	}
}

// Windows defaults to TBS, which Linux's default is not.
func TestWindowsDefaultsToTBS(t *testing.T) {
	f := newFake()
	use(t, f)
	goos = "windows"
	if _, err := Create(Options{}); err != nil {
		t.Fatal(err)
	}
	if f.device != TBSDevice {
		t.Fatalf("device %q, want %q", f.device, TBSDevice)
	}
}

// fakeTransport is a TPM channel that counts its closes.
type fakeTransport struct{ closed int }

func (f *fakeTransport) Send([]byte) ([]byte, error) { return nil, boom }
func (f *fakeTransport) Close() error                { f.closed++; return nil }

// The real connect with the TBS device: the TBS context is opened through
// openTBS, its error is returned, and its Close is the connection's.
func TestConnectTBS(t *testing.T) {
	old := openTBS
	t.Cleanup(func() { openTBS = old })

	// A transport comes back with the error: it must still be refused.
	ft := &fakeTransport{}
	openTBS = func() (transport, error) { return ft, boom }
	if tp, closeFn, err := connect(TBSDevice); !errors.Is(err, boom) || tp != nil || closeFn != nil {
		t.Fatalf("open error: %v %v", err, tp)
	}

	openTBS = func() (transport, error) { return ft, nil }
	tp, closeFn, err := connect(TBSDevice)
	if err != nil || tp == nil {
		t.Fatalf("connect: %v", err)
	}
	if err := closeFn(); err != nil || ft.closed != 1 {
		t.Fatalf("close: %v, closed %d", err, ft.closed)
	}
}

// The real openTBS: off Windows devtpm refuses, and the counter says so; on
// Windows it is a TBS error or a context (a machine without a TPM answers
// TBS_E_TPM_NOT_FOUND).
func TestRealOpenTBS(t *testing.T) {
	tr, err := openTBS()
	if err != nil {
		if runtime.GOOS != "windows" && !strings.Contains(err.Error(), "only on Windows") {
			t.Fatalf("off Windows: %v", err)
		}
		return
	}
	if runtime.GOOS != "windows" {
		t.Fatal("a TBS context off Windows")
	}
	if err := tr.Close(); err != nil {
		t.Fatal(err)
	}
}

// The real connect: a character device path, and a unix socket.
func TestConnect(t *testing.T) {
	if _, _, err := connect(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("a missing device opened")
	}
	file := filepath.Join(t.TempDir(), "tpm")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	tp, closeFn, err := connect(file)
	if err != nil || tp == nil || closeFn() != nil {
		t.Fatalf("file device: %v", err)
	}
	dir, err := os.MkdirTemp("", "tc")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "s")
	if _, _, err := connect("unix:" + sock); err == nil {
		t.Fatal("a missing socket connected")
	}
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	tp, closeFn, err = connect("unix:" + sock)
	if err != nil || tp == nil || closeFn() != nil {
		t.Fatalf("unix device: %v", err)
	}
}
