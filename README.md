# Sinty Crypto

Login and file encryption for Sinty OS. User files are encrypted with a key kept
in the TPM (the machine's security chip), unlocked by the user's PIN. A recovery
key covers a forgotten PIN or a reset TPM. `pam_sinty` authenticates the login with
this key in place of a Unix password.

Sinty OS has no `/etc/shadow`: a PIN is checked by unsealing the key from the TPM,
not by matching a stored hash. A disk read on another machine has nothing to forge
a login with, and the TPM throttles repeated wrong PINs.

## Components

- `libsintykey/`: creates a per-user encryption key, seals it in the TPM under the
  PIN, and keeps a recovery copy sealed under a recovery secret (Argon2id and
  XChaCha20-Poly1305) for the forgotten-PIN case.
- `pam_sinty/`: the PAM module. A correct PIN unseals the key and starts the
  session, in place of pam_unix in greetd, login, lock and polkit.

## Build

`libsintykey` is pure Zig (std.crypto, no libsodium); `pam_sinty` links libpam.
Requires Zig 0.16.

## License

GPL-3.0-only, see [LICENSE](LICENSE). Contributions under the [CLA](CLA.md).
