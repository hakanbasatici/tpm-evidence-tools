# TPM Evidence Tools — source preview

Two small Windows diagnostics built on TPM Base Services and the Microsoft Platform Crypto Provider. No remote service, certificate installation, enrollment, existing key mutation, or application trust decision is implemented. This is a source preview under the MIT license. No signed binary release is available.

- **PcrBanks:** sends one fixed TPM2_GetCapability/PCRS command. The complete request/response is preserved as hex. Exit 0 means the transport capture completed; the TPM response code still needs independent decoding.
- **EphemeralClaim:** creates one unnamed identity key (RSA2048, RSASSA/SHA256 settings before finalize), receives a 32-byte caller nonce, requests a platform claim and exports the public RSA blob. It has no persisted key name and opens no existing AIK. It cannot provide a certificate for its ephemeral key.

The caller owns challenge generation, canonical statement/domain binding and freshness. A syntactically valid nonce alone does not prove freshness. Byte-level claim verification, nonce equality and trusted enrollment must happen outside these diagnostics. No output authorizes an action.

## Build validation and CMake build plan

The isolated direct MSVC/Windows SDK build and resource compile passed. The portable test passed all 38 cases on Windows. Offline PE inspection passed; the helpers were not started and remain unsigned. CMake execution itself has not been verified. See validation.json and docs/WINDOWS-BUILD-REVIEW.json.

Windows x64, MSVC C++17 and a Windows SDK that includes the PCP scheme properties are required. Build through CMake (3.20+) in an isolated directory:

```text
cmake -S . -B build -A x64
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

Portable tests can also be built on Linux with g++ C++17. Their fake operations never invoke TPM APIs. There is no automatic dependency installer.

## CLI design — not an instruction to run on a user device

```text
PcrBanks --help
PcrBanks pcr-banks --acknowledge-readonly-query
EphemeralClaim --help
EphemeralClaim ephemeral-claim --nonce-hex <64-lowercase-hex-from-relying-party> --acknowledge-ephemeral-key
```

The acknowledgment arguments expose side effects; they are not authorization tokens or tamper-resistant execution gates. Use deployment-specific human approval and process bounds. Never run a new TPM operation merely because a binary is signed.

The claim tool makes two NCryptCreateClaim API calls (size then data). It does not promise an exact underlying TPM-command count. There are no automatic retries. Hardware-provider flags and metadata do not establish hardware origin. Exact NTE_NOT_SUPPORTED getter errors are reported unavailable; other errors/mismatches stop. Actual quote signatures must still be verified. PCR-bank selection is not configured by this utility.

Exit codes: 0 = captured expected metadata, independent crypto review still required; 1 = failed/stopped; 2 = captured mismatching bank/scheme/hash metadata, diagnostic rejected. Error output is JSON on stderr; successful capture JSON is on stdout.

## Privacy and safety

No network requests, registry/ACL/configuration writes, TPM clearing or persistent enrollment are implemented. Claim output may contain a public key, PCR values, signed quote, nonce and public device information: share only with the intended relying party. Logs may be linkable to a machine. Do not post device outputs in public issues.

The binaries will be unsigned until a supported signing path is approved. Smart App Control compatibility has not been established. Do not turn off security policy to run this draft.

## Review documents

Read LICENSE, REVIEW-TR.md, docs/SIGNING-POLICY-DRAFT.md, docs/RELEASE-GATES.md and docs/PROVENANCE.md. MIT applies only to the sources in this standalone project. No SignPath sponsorship is claimed. Source repository: https://github.com/hakanbasatici/tpm-evidence-tools. Maintainer: @hakanbasatici. A private security reporting channel is not yet configured; see SECURITY.md.
