# sintykey-tpm: the TPM 2.0 backend

A native Zig backend over libtss2 ESYS: no shell, no tpm2-tools subprocess, no
PATH lookup in a root-run seal path. It seals the encryption key under the PIN in
a sealed keyedhash object, and the TPM's dictionary-attack lockout throttles wrong
PINs. It works against swtpm in a VM and a discrete or Pluton TPM on hardware, so
the whole PIN path is testable without real hardware. sintykey execs it by
absolute path and passes the PIN in a 0600 file, never on argv.

## Contract

```
sintykey-tpm ensure-primary
sintykey-tpm seal   <keyfile> <pinfile> <pub_out> <priv_out>
sintykey-tpm unseal <pinfile> <pub> <priv> <out>
sintykey-tpm verify <pinfile> <pub> <priv>          # exit 0 ok, 1 wrong PIN
```

The sealed object lives under a persistent ECC storage primary at `0x81000001`.
The pub/priv blobs are marshalled with `Tss2_MU` and written 0600; the key never
leaves the TPM in the clear.

## TCTI

The transport is chosen by `SINTYKEY_TCTI` (tctildr syntax):
`swtpm:host=127.0.0.1,port=2321` in a VM, `device:/dev/tpmrm0` on hardware. Unset
uses the tctildr default. The build links `tss2-esys`, `tss2-mu`, `tss2-rc` and
`tss2-tctildr` (Debian: `libtss2-dev`).

## PCR binding

With the `seal-pcrs` build option the sealed key is also bound to the measured
boot state via PolicyPCR: unsealing then requires both the correct PIN and a
genuine measured boot, so extracting the disk and booting a tampered OS cannot
unseal it.
