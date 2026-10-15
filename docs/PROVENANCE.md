# Source and build provenance

This draft adapts three session-authored Windows diagnostic sources (unnamed ephemeral profile, profile header and fixed PCR capability query). No Microsoft TSS parser or certificate bundle is shipped in this project. Windows SDK/platform libraries are system dependencies.

Changes: remove the application-specific domain/challenge/statement binding from the helper; accept an external nonce; rename project and namespace; add explicit operation acknowledgment and no-TPM help; expose profile mismatch exit code; add build/resources/docs and portable input tests.

References consulted (not vendored code):
- NCryptCreateClaim / NCryptCreatePersistedKey API: https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreateclaim
- Microsoft TSS.MSR GetCapabilities command format: https://github.com/microsoft/TSS.MSR
- SignPath source and build-origin requirements: https://signpath.org/terms.html

No third-party software package was installed or embedded in this draft. Dependencies: MSVC C++ runtime (static /MT in the reviewed direct Windows build), Windows SDK headers, Windows ncrypt/bcrypt/tbs system libraries, CMake build tooling. Reviewed PE imports and binary hashes are now recorded in WINDOWS-BUILD-REVIEW.json. COMPONENTS.json is a limited component inventory; exact compiler/SDK package versions and an independent reproducible build remain unverified. This document is not proof of license ownership or a signed build attestation; ownership/provenance review is a publication gate.
