# Contribution policy — publication draft

All changes require review before signing/release, including CMake, resources, CI and documentation. Keep the fixed query allowlist, strict nonce format and no-existing-key-write boundary. Do not add raw TPM command passthrough, automatic retries, certificate installers, key/ACL modification or external submission.

Run the portable tests. Windows-specific changes also require isolated compile checks; --help must not touch TPM. Hardware execution is separately scoped and authorized. Do not use public CI runners for real TPM diagnostics or enrollment.

Every proposed release needs an accountable human approver. AI-generated reviews are supporting evidence and do not replace that approver.
