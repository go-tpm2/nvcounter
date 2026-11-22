# go-tpm2/nvcounter

[![CI](https://github.com/go-tpm2/nvcounter/actions/workflows/ci.yml/badge.svg)](https://github.com/go-tpm2/nvcounter/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/go-tpm2/nvcounter.svg)](https://pkg.go.dev/github.com/go-tpm2/nvcounter)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-blue)](LICENSE)

A **monotonic counter on a TPM 2.0**: a `TPM_NT_COUNTER` NV index (TCG TPM 2.0
Library Part 3, 31.8) that is created once, incremented under its own
authValue and never goes back. A rollback guard for anything that must refuse
an older copy of itself: [theca](https://github.com/go-theca/theca) binds a
container to one.

```go
import "github.com/go-tpm2/nvcounter"

c, err := nvcounter.Create(nvcounter.Options{Auth: secret}) // defines a free owner index
err = c.Increment()
v, err := c.Read()
id, err := c.Identity() // names THIS TPM: the digest of its ECC P-256 EK

c, err = nvcounter.Open(nvcounter.Options{Handle: c.Handle(), Auth: secret})
```

- A `Counter` holds no connection: each operation opens the device and closes it.
- Transports: `/dev/tpmrm0` (Linux, the default), Windows TBS (`tbs:`, the Windows
  default, through [devtpm](https://github.com/go-tpm2/devtpm)), and `unix:<socket>`
  for a software TPM (`swtpm socket --tpm2 --server type=unixio,path=SOCKET`).
  macOS has no TPM: `ErrUnsupported` unless a device is named.
- New counters carry `TPMA_NV_NO_DA`; a wrong authValue does not lock the TPM.
- The Name of a counter changes once, at its first increment (it covers
  `TPMA_NV_WRITTEN`): `Increment` reads it again. An index nobody incremented
  cannot be read.
- `Identity` names the TPM, it does not prove the TPM answering is that one:
  whoever controls a software TPM can present any EK. It needs the endorsement
  hierarchy password in `Options.EndorsementAuth` if one is set; a refusal is
  `ErrEndorsementAuth` and does not count toward the lockout.
- Every answer from the TPM that becomes a value is bounded (authValues at most
  32 bytes, the EK Name exactly 34 bytes starting `000b`).

Built on [tpm2](https://github.com/go-tpm2/tpm2) (`NVDefineCounter`,
`NVIncrementAuth`, `NVReadCounter`, `EKIdentityAuth`). This package is where the
transport lives, so `tpm2` itself stays free of `devtpm` and `x/sys`. Salted HMAC
sessions for NV authorization are tracked in
[tpm2#20](https://github.com/go-tpm2/tpm2/issues/20); today the authValue travels
in a password session, as for every other `tpm2` command.

Tested against a real software TPM in CI (`NVCOUNTER_REQUIRE_SWTPM=1` turns a
missing swtpm into a failure) and against a fake TPM for every error path, with
100% statement coverage. This code was moved here from theca's `tpmcounter`
package, unchanged apart from the name.

## Performance

No operation does work of its own: each opens the device, sends a fixed number of
TPM commands and closes it, so the time is the TPM's, and there is no C reference
tool to compare with. `Create`: `NV_DefineSpace` plus one `NV_ReadPublic` probe
per taken handle. `Open`: one `NV_ReadPublic`. `Read`: one `NV_Read`.
`Increment`: one `NV_Increment` (an NV write) and one `NV_ReadPublic`. `Destroy`:
one `NV_UndefineSpace`. `Identity`: one `TPM2_CreatePrimary` of the ECC P-256 EK
and one `TPM2_FlushContext`. `Handle` and `Name` return stored values. Measured on
swtpm under a 1-minute load of 13 (so the times are indicative, the command counts
are exact): `Identity` 0.26 ms, `Read` 0.04 ms, `Increment` 0.33 ms. A hardware TPM
was not measured.

## Install

```sh
go get github.com/go-tpm2/nvcounter
```

## License

BSD-3-Clause. See [LICENSE](LICENSE).
