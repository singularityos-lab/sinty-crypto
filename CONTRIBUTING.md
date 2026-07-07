# Contributing to Sinty Crypto

Thanks for your interest! This is security-critical code; changes are reviewed
carefully.

## Rules
- The proof of a credential must stay CRYPTOGRAPHIC (unseal), never a comparison.
  Do not add a code path that authenticates by comparing a stored secret.
- The recovery key is mandatory: never ship a flow that can lose data on a
  forgotten PIN without the recovery escape.
- Keep the pure-crypto paths (recovery wrap) unit tested; the TPM paths are
  exercised on hardware.

GPL-3.0-only; by contributing you agree to the [CLA](CLA.md).
