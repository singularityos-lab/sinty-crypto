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

## Use of Generative AI

Maintainers may use generative AI tools as assistants while working on sinty-crypto. Non-trivial assisted commits disclose the tool, model, and scope of the work.

AI tools may assist with code comments, documentation, repetitive code, and issue triage. Maintainers make project decisions and review every assisted change before it is merged.

Use these trailers for non-trivial assisted commits:

```plain
Assisted-by: <tool>:<model-version>
AI-Scope: <what the tool generated and the prompt or a short prompt summary>
```

Single-line completions, renames, and formatting changes do not need trailers.

Coding agents must also follow [AGENTS.md](AGENTS.md) before changing files,
creating commits, or opening pull requests.
