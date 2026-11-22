// Package nvcounter is a rollback counter on a TPM 2.0: a TPM_NT_COUNTER NV
// index (TCG TPM 2.0 Library Part 3, 31.8), created once, incremented by its
// own authValue and never reset, over go-tpm2/tpm2. It is the counter theca
// binds a container to; nothing in it is specific to theca.
//
// Counter.Identity names the TPM the counter lives on (the digest inside the
// Name of its ECC P-256 endorsement key), so a caller can pin a counter to one
// TPM and refuse the same handle and Name on another.
//
// Transports: the Linux kernel resource manager (/dev/tpmrm0), Windows TPM
// Base Services ("tbs:", the Windows default, go-tpm2/devtpm OpenTBS), and any
// raw TPM 2.0 stream the caller names as "unix:<socket>" (a software TPM
// started with swtpm --server type=unixio). macOS has no TPM and returns
// ErrUnsupported unless a device is named explicitly; "tbs:" off Windows is an
// error too.
//
// A Counter holds no open connection. Each operation opens the device and
// closes it, so no lifetime has to be managed and the kernel resource manager
// releases everything between operations.
package nvcounter

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"runtime"

	"github.com/go-tpm2/common"
	"github.com/go-tpm2/devtpm"
	"github.com/go-tpm2/tpm2"
)

// Errors.
var (
	// ErrUnsupported: this platform has no TPM interface and no device was named.
	ErrUnsupported = errors.New("nvcounter: no TPM interface on this platform (name a device)")
	// ErrNotCounter: the NV index exists but is not a counter this package made.
	ErrNotCounter = errors.New("nvcounter: the NV index is not a rollback counter created by this package")
	// ErrNoCounter: the NV index is not defined on this TPM (it was undefined,
	// the TPM was cleared, or this is another TPM).
	ErrNoCounter = errors.New("nvcounter: the TPM has no NV index at the counter's handle")
	// ErrAuthTooLong: an authValue longer than a SHA-256 digest (Part 3 31.3.1).
	ErrAuthTooLong = errors.New("nvcounter: an authValue is at most 32 bytes")
	// ErrIdentity: the TPM could not name itself (no EK, a set endorsement
	// authValue) or answered with something that is not an EK Name.
	ErrIdentity = errors.New("nvcounter: cannot read this TPM's identity")
	// ErrNoFreeHandle: every handle in the search range is taken.
	ErrNoFreeHandle = errors.New("nvcounter: no free NV index handle in the owner range searched")
)

// First and Span give the owner NV handles searched for a free one: the TCG
// registry assigns 0x01500000-0x01BFFFFF to the owner.
const (
	First uint32 = 0x01500000
	Span  uint32 = 0x1000
)

// DefaultLinuxDevice is the kernel resource manager.
const DefaultLinuxDevice = devtpm.DefaultDevice

// TBSDevice names Windows TPM Base Services, the Windows default: one TBS
// context per operation, as for the other devices.
const TBSDevice = "tbs:"

// IDSize is the size of an identity: a SHA-256 digest.
const IDSize = 32

// maxAuth is the digest size of the counter's nameAlg (SHA-256).
const maxAuth = 32

// maxHierarchyAuth bounds a hierarchy password before it is sent: an authValue
// is at most the digest size of the algorithm in play (TCG Part 1 rev 1.59,
// 19.6.4.2, p. 105), so 64 bytes (SHA-512) is the largest a TPM can ask for;
// the TPM itself refuses what it does not take.
const maxHierarchyAuth = 64

// ErrEndorsementAuth: the TPM refused the endorsement hierarchy password
// (TPM_RC_BAD_AUTH or TPM_RC_AUTH_FAIL). The authValue of a hierarchy is not
// DA protected, so the refusal does not count toward the lockout.
var ErrEndorsementAuth = errors.New("nvcounter: the TPM refused the endorsement hierarchy password")

// rcBadAuth and rcAuthFail are TPM_RC_BAD_AUTH (0x22) and TPM_RC_AUTH_FAIL
// (0x0E) in the format-one response codes.
const (
	rcBadAuth  = 0x22
	rcAuthFail = 0x0E
	rcFmt1     = 0x80
)

// isAuthRefusal reports whether err is the TPM refusing an authValue.
func isAuthRefusal(err error) bool {
	var te *tpm2.TPMError
	if !errors.As(err, &te) || te.RC&rcFmt1 == 0 {
		return false
	}
	n := te.RC & 0x3F
	return n == rcBadAuth || n == rcAuthFail
}

// rcHandle is TPM_RC_HANDLE's number in the format-one response codes
// (0x08B): a handle that does not exist.
const rcHandle = 0x0B

// Options select the TPM and the credentials.
type Options struct {
	// Device is a character device path, "unix:<socket>", or empty for the
	// platform default (/dev/tpmrm0 on Linux).
	Device string
	// Handle is the NV index. Create picks a free one when it is 0; Open
	// requires it.
	Handle uint32
	// OwnerAuth authorizes Create and Destroy (the owner hierarchy password;
	// empty on a TPM with no owner password). Read from a file by the caller,
	// never from argv or the environment.
	OwnerAuth []byte
	// Auth is the counter's own authValue, used to increment and read it.
	Auth []byte
	// EndorsementAuth authorizes the creation of the endorsement key that names
	// the TPM (Identity): the endorsement hierarchy password, empty on a TPM
	// with none. A wrong one is ErrEndorsementAuth.
	EndorsementAuth []byte
}

// nvTPM is the part of *tpm2.TPM the counter uses.
type nvTPM interface {
	NVDefineCounter(ownerAuth, indexAuth []byte, nvIndex uint32) ([]byte, error)
	NVReadPublic(nvIndex uint32) (tpm2.NVPublic, []byte, error)
	NVIncrementAuth(authHandle uint32, auth []byte, nvIndex uint32) error
	NVReadCounter(auth []byte, nvIndex uint32) (uint64, error)
	NVUndefineSpaceAuth(ownerAuth []byte, nvIndex uint32) error
	EKIdentityAuth(endorsementAuth []byte) ([]byte, error)
}

// goos is replaced by tests.
var goos = runtime.GOOS

// openTBS opens a TBS context; tests replace it. Off Windows devtpm answers
// ErrTBSUnsupported. The transport is only used when err is nil (a nil
// *devtpm.TBS is returned with an error).
var openTBS = func() (transport, error) { t, err := devtpm.OpenTBS(); return t, err }

// transport is a TPM 2.0 command channel that can be closed.
type transport interface {
	common.Transport
	Close() error
}

// connect opens the TPM; tests replace it. The function closes the connection.
var connect = func(device string) (nvTPM, func() error, error) {
	if device == TBSDevice {
		t, err := openTBS()
		if err != nil {
			return nil, nil, err
		}
		return tpm2.New(t), t.Close, nil
	}
	if len(device) > 5 && device[:5] == "unix:" {
		conn, err := net.Dial("unix", device[5:])
		if err != nil {
			return nil, nil, err
		}
		t := devtpm.New(conn)
		return tpm2.New(t), t.Close, nil
	}
	t, err := devtpm.Open(device)
	if err != nil {
		return nil, nil, err
	}
	return tpm2.New(t), t.Close, nil
}

func (o Options) device() (string, error) {
	if o.Device != "" {
		return o.Device, nil
	}
	switch goos {
	case "linux":
		return DefaultLinuxDevice, nil
	case "windows":
		return TBSDevice, nil
	}
	return "", ErrUnsupported
}

func (o Options) check() error {
	if len(o.Auth) > maxAuth || len(o.OwnerAuth) > maxHierarchyAuth || len(o.EndorsementAuth) > maxHierarchyAuth {
		return ErrAuthTooLong
	}
	return nil
}

// with runs f on a fresh connection.
func (o Options) with(f func(nvTPM) error) error {
	dev, err := o.device()
	if err != nil {
		return err
	}
	t, closeFn, err := connect(dev)
	if err != nil {
		return err
	}
	err = f(t)
	if cerr := closeFn(); err == nil {
		err = cerr
	}
	return err
}

// Counter is a TPM NV counter. It satisfies theca.Counter and
// theca.IdentifiedCounter.
type Counter struct {
	opts   Options
	handle uint32
	name   []byte
}

// Create defines a new counter index and returns it. The index is not yet
// written: the first Increment writes it. If a later step fails, call Destroy.
func Create(o Options) (*Counter, error) {
	if err := o.check(); err != nil {
		return nil, err
	}
	c := &Counter{opts: o}
	err := o.with(func(t nvTPM) error {
		h, err := pickHandle(t, o.Handle)
		if err != nil {
			return err
		}
		name, err := t.NVDefineCounter(o.OwnerAuth, o.Auth, h)
		if err != nil {
			return err
		}
		c.handle, c.name = h, name
		return nil
	})
	if err != nil {
		return nil, err
	}
	c.opts.Handle = c.handle
	return c, nil
}

// pickHandle returns want if it is not 0, otherwise the first free handle.
func pickHandle(t nvTPM, want uint32) (uint32, error) {
	if want != 0 {
		return want, nil
	}
	for h := First; h < First+Span; h++ {
		_, _, err := t.NVReadPublic(h)
		if err == nil {
			continue // taken
		}
		var te *tpm2.TPMError
		if errors.As(err, &te) && te.RC&0x3F == rcHandle {
			return h, nil
		}
		return 0, err
	}
	return 0, ErrNoFreeHandle
}

// Open attaches to the existing counter o.Handle and reads its Name from the
// TPM. It refuses an index that is not a counter with the attributes Create
// sets. (The container pins the Name too: a different index fails there.)
func Open(o Options) (*Counter, error) {
	if err := o.check(); err != nil {
		return nil, err
	}
	c := &Counter{opts: o, handle: o.Handle}
	err := o.with(func(t nvTPM) error {
		pub, name, err := t.NVReadPublic(o.Handle)
		var te *tpm2.TPMError
		if errors.As(err, &te) && te.RC&0x3F == rcHandle {
			return fmt.Errorf("%w (handle %#08x)", ErrNoCounter, o.Handle)
		}
		if err != nil {
			return err
		}
		if !tpm2.IsCounterAttributes(pub.Attributes) || pub.DataSize != tpm2.CounterSize {
			return fmt.Errorf("%w (handle %#08x)", ErrNotCounter, o.Handle)
		}
		c.name = name
		return nil
	})
	if err != nil {
		return nil, err
	}
	return c, nil
}

// Handle is the NV index.
func (c *Counter) Handle() uint32 { return c.handle }

// Name is the NV Name the TPM computed.
func (c *Counter) Name() []byte { return c.name }

// Read returns the counter's value.
func (c *Counter) Read() (uint64, error) {
	var v uint64
	err := c.opts.with(func(t nvTPM) (err error) {
		v, err = t.NVReadCounter(c.opts.Auth, c.handle)
		return err
	})
	return v, err
}

// Increment adds one to the counter. It then reads the Name again: the first
// increment sets TPMA_NV_WRITTEN, which is part of the public area the Name is
// the digest of, so the Name of a counter that was just created changes once.
// (Measured on swtpm: a Name read before the first increment does not match
// the one read after it.)
func (c *Counter) Increment() error {
	return c.opts.with(func(t nvTPM) error {
		if err := t.NVIncrementAuth(c.handle, c.opts.Auth, c.handle); err != nil {
			return err
		}
		_, name, err := t.NVReadPublic(c.handle)
		if err == nil {
			c.name = name
		}
		return err
	})
}

// Identity is the identity of THIS TPM, the
// SHA-256 digest inside the Name of its endorsement key (the EK Credential
// Profile ECC P-256 template, created transiently and flushed, never made
// persistent). The same TPM gives the same identity on every call, another TPM
// another one. Needs the endorsement hierarchy's authValue to be empty, the
// default, or EndorsementAuth to be the password; otherwise it fails (with
// ErrEndorsementAuth if the TPM refused the password).
//
// It names the TPM, it does not prove the TPM answering is that one: whoever
// controls a software TPM can present any EK.
func (c *Counter) Identity() ([]byte, error) {
	var id []byte
	err := c.opts.with(func(t nvTPM) error {
		name, err := t.EKIdentityAuth(c.opts.EndorsementAuth)
		if isAuthRefusal(err) {
			return fmt.Errorf("%w: %w (%v)", ErrIdentity, ErrEndorsementAuth, err)
		}
		if err != nil {
			return fmt.Errorf("%w: %v", ErrIdentity, err)
		}
		// 0x000B (SHA-256) || 32-byte digest: anything else is not the Name
		// of the template asked for, and is not hashed into an identity.
		if len(name) != 2+IDSize || !bytes.HasPrefix(name, []byte{0x00, 0x0B}) {
			return fmt.Errorf("%w: the EK Name is %d bytes, want 34 starting 000b", ErrIdentity, len(name))
		}
		id = append([]byte(nil), name[2:]...)
		return nil
	})
	return id, err
}

// Destroy deletes the index under the owner password in the Options it was
// created with. Use it only to undo a Create.
func (c *Counter) Destroy() error {
	return c.opts.with(func(t nvTPM) error {
		return t.NVUndefineSpaceAuth(c.opts.OwnerAuth, c.handle)
	})
}
