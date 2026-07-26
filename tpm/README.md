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

## Bootloader lock bit (hardware-anchored, TPM NV)

The bootloader lock/unlock state lives in TPM NV, not an ESP file (an ESP file is
forgeable offline; an NV index is anchored in the TPM). Three owner-hierarchy
indices, all `NO_DA`:

```
0x01800001  ordinary, 16 bytes   lock record: magic "SKLK" + state byte + u64 unlock count (LE)
0x01800002  TPM2_NT_COUNTER      hardware-monotonic anchor, bumped on every state transition
0x01800003  ordinary, 1 byte     dm-verity toggle (0xA5 == off, anything else/absent == on)
```

State byte in `0x01800001`: `0xA5` == unlocked, anything else == locked. Every
read is FAIL CLOSED: an undefined index, a read error, a wrong magic, or any other
state byte reports LOCKED / verity ON. A missing or failing TPM never reads as
unlocked.

Backend contract:

```
sintykey-tpm lock-read        # stdout: state=<locked|unlocked> unlocks=<n> hwcounter=<m>
sintykey-tpm lock-unlock      # set unlocked, unlock count += 1, bump hw counter
sintykey-tpm lock-relock      # set locked (count kept, monotonic), bump hw counter
sintykey-tpm verity-read      # stdout: verity=<on|off>
sintykey-tpm verity-set-off   # request verity OFF (unlocked boot)
sintykey-tpm verity-set-on    # request verity ON (verified boot)
```

`lock-read`/`verity-read` exit 0 whenever the TPM is reachable (a legitimately
locked box is not an error); they exit nonzero only when the TPM itself cannot be
reached, which the `sintykey` wrapper maps to a fail-closed LOCKED answer.

### Loader consumption (verity toggle)

The loader turns dm-verity off for the unlocked state via its existing
no-`ATOM_ROOT_HASH` path. It reads the toggle from **TPM NV index `0x01800003`**
(value `0xA5` == boot with verity off, omit `ATOM_ROOT_HASH`); anything else or an
absent index == verified boot. Equivalently it may shell `sintykey verity-state`
(prints `verity=off` / `verity=on`, fail closed to `on`). The ESP consent flag
`<ESP>/state/unlock-armed` is owned by the recovery/boot-state side, not here.
