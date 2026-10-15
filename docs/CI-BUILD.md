# Manual Windows build and portable tests

Workflow: `.github/workflows/windows-build-draft.yml`. Manually dispatched only; no push, pull-request or schedule trigger. Only repository owner `hakanbasatici` with input `BUILD_AND_PORTABLE_TEST_ONLY` can start the build job.

Scope: existing MSVC/Windows SDK on GitHub-hosted `windows-2022`, reviewed input hash checks, CMake configure/build, exactly the `profile-and-input` CTest test, then review-artifact upload with 14-day retention. CMake may compile/run toolchain probes. PcrBanks.exe and EphemeralClaim.exe are never launched by this workflow. There are no TPM operations, enrollment, signing, release publication or external service API calls in the project steps. Checkout and artifact upload use GitHub networking. The workflow token has contents:read only and checkout credentials are not persisted.

The owner approved one standard hosted Windows build/test run on 2026-10-15. No rerun is covered by that one-run approval. Manual input is a scope reminder, not a tamper-resistant authorization mechanism. The initial run is pending; workflow installation is not a passing build.

Pinned dependencies resolved from official action release/tag metadata on 2026-10-15:
- actions/checkout v7.0.1: `3d3c42e5aac5ba805825da76410c181273ba90b1` (node24)
- actions/upload-artifact v7.0.2: `cf430e030ddbb5b0abf93d22962f4752f3646cd9` (node24)

The runner image and installed compiler/SDK evolve; run/image information, CMakeCache, test log, source hashes and binary hashes are captured for review. These records link CI outputs to a source commit; they do not establish bit-reproducible builds, independent attestation, TPM behavior or signing-provider acceptance. No extra secrets or PAT are requested.

The previously published v0.1.0-preview.1 was built locally with direct MSVC compilation. CI outputs must be separately reviewed and are not automatically published or substituted into that release.
