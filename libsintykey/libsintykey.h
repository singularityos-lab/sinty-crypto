/* libsintykey: the key-custody primitive behind pam_sinty and the installer.
 *
 * It seals a per-user CE key to the TPM under a PIN (protected by the TPM's
 * dictionary-attack lockout), and ALSO wraps the same key under a high-entropy
 * recovery secret, so a forgotten PIN or a cleared TPM does not lose data. The
 * recovery wrap is pure crypto (Argon2id + AEAD); the seal/unseal talk to the TPM.
 *
 * All functions return 0 on success, negative on error. SPDX: GPL-3.0-only.
 */
#ifndef LIBSINTYKEY_H
#define LIBSINTYKEY_H

#include <stddef.h>

#define SINTYKEY_KEYLEN 32                 /* 256-bit CE master key */
#define SINTYKEY_RECOVERY_BLOB_MAX 128     /* upper bound for the recovery blob */

typedef struct { unsigned char bytes[SINTYKEY_KEYLEN]; } sintykey_key;

/* Generate a fresh random CE master key. */
int sintykey_generate(sintykey_key *out);

/* ---- recovery wrap (pure crypto, no TPM; testable offline) ---- */

/* A human-savable recovery secret (grouped Base32, ~128-bit). out_len >= 40. */
int sintykey_recovery_generate(char *out, size_t out_len);

/* Wrap K under the recovery secret: AEAD keyed by Argon2id(secret). blob_out must
 * hold SINTYKEY_RECOVERY_BLOB_MAX; *blob_len gets the actual length. */
int sintykey_recovery_wrap(const sintykey_key *k, const char *recovery_secret,
                           unsigned char *blob_out, size_t *blob_len);

/* Recover K from the blob with the recovery secret. Fails on a wrong secret. */
int sintykey_recovery_unwrap(const unsigned char *blob, size_t blob_len,
                             const char *recovery_secret, sintykey_key *out);

/* ---- TPM seal/unseal (needs hardware; the boot-chain part) ---- */

/* Seal K to the TPM under (stable-root PCR policy) AND (PIN auth), persisting the
 * sealed blob at blob_path. */
int sintykey_tpm_seal(const sintykey_key *k, const char *pin, const char *blob_path);

/* Unseal K with the PIN (pam_sinty auth). A wrong PIN advances the TPM DA-lockout.
 * On success K is returned so the session can mount the user's fscrypt CE. */
int sintykey_tpm_unseal(const char *blob_path, const char *pin, sintykey_key *out);

/* Re-seal K to the current PCRs; atomd calls this after an OTA that moved them. */
int sintykey_tpm_reseal(const char *blob_path, const sintykey_key *k, const char *pin);


/* Gate check: verify the PIN without returning the key (polkit, confirm-owner).
 * 0 if correct, -EACCES if wrong (advances the TPM DA-lockout). */
int sintykey_verify_pin(const char *blob_path, const char *pin);

/* Change the PIN: unseal K with old_pin, re-seal under new_pin. */
int sintykey_change_pin(const char *blob_path, const char *old_pin, const char *new_pin);

#endif
