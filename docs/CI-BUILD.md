# Manual Windows build and portable tests

Workflow: `.github/workflows/windows-build-draft.yml`. Manually dispatched only; no push, pull-request or schedule trigger. Only repository owner `hakanbasatici` with input `BUILD_AND_PORTABLE_TEST_ONLY` can start the build job.

Scope: existing MSVC/Windows SDK on GitHub-hosted `windows-2022`, reviewed input hash checks, CMake configure/build, exactly the `profile-and-input` CTest test, then review-artifact upload with 14-day retention. CMake may compile/run toolchain probes. PcrBanks.exe and EphemeralClaim.exe are never launched by this workflow. There are no TPM operations, enrollment, signing, release publication or external service API calls in the project steps. Checkout and artifact upload use GitHub networking. The workflow token has contents:read only and checkout credentials are not persisted.

The owner approved one standard hosted Windows build/test run on 2026-10-15. No rerun is covered by that one-run approval. Manual input is a scope reminder, not a tamper-resistant authorization mechanism. The first run (38744418635, attempt 1) failed during reviewed-input verification at CMakeLists.txt. Configure, build, test, packaging and artifact upload were skipped. The one-run authorization is consumed; another run needs a new owner decision.

Pinned dependencies resolved from official action release/tag metadata on 2026-10-15:
- actions/checkout v7.0.1: `3d3c42e5aac5ba805825da76410c181273ba90b1` (node24)
- actions/upload-artifact v7.0.2: `cf430e030ddbb5b0abf93d22962f4752f3646cd9` (node24)

The runner image and installed compiler/SDK evolve; run/image information, CMakeCache, test log, source hashes and binary hashes are captured for review. These records link CI outputs to a source commit; they do not establish bit-reproducible builds, independent attestation, TPM behavior or signing-provider acceptance. No extra secrets or PAT are requested.

The previously published v0.1.0-preview.1 was built locally with direct MSVC compilation. CI outputs must be separately reviewed and are not automatically published or substituted into that release.

## First-run checkout correction

Run: https://github.com/hakanbasatici/tpm-evidence-tools/actions/runs/38744418635 . The repository CMakeLists.txt blob still has the reviewed LF SHA-256. The original workflow did not pin checkout line endings. Windows CRLF checkout conversion is the leading explanation, not a directly observed byte hash from that run: the old error did not print the actual hash or EOL state. The correction adds `.gitattributes` to force LF for text, retains every reviewed hash, and prints EOL/actual-hash diagnostics on failure. Native sources and CMake bytes are unchanged. No cloud retry was performed as part of this correction.

## Verified successful run

Owner-authorized second dispatch: [38745252012](https://github.com/hakanbasatici/tpm-evidence-tools/actions/runs/38745252012), attempt 1, source `bd4c2c7d855a0ec17d1c6ac1d264e2f60aa94bfb`. Checkout/input checks, configure, all three builds, one portable test with 38 cases, packaging and artifact upload passed. Artifact 11977917582 SHA-256 `c96a45f6fadabfd7e923caa723ee1b588e12eae6485aeb098fff233c5a354d30` was downloaded and verified, including source commit, run/attempt, six native-source hashes, both EXE hashes and the 38-case test log. No diagnostic helper was started.

Toolchain from logs: CMake 3.31.6, MSVC 19.44.35229.0, SDK 10.0.26100.0, runner image 20261012.333.1. The D9025 test-only warning confirms `/UNDEBUG` overrides Release `/DNDEBUG`, keeping test assertions enabled.

CI EXE SHA-256:
- PcrBanks.exe: `deb1af815eca77eaf2dd272e812b2fdb171ae470046f8b0399e7b20d75cdb018`
- EphemeralClaim.exe: `6196324a1c0d028fd1fd3f2183a77017bc03b2d6055c23eae0d49bf314c016ec`

These outputs differ from the earlier locally built release binaries and have not been published as a release. Both authorized runs are consumed; no additional run or automatic rerun is authorized by this record.
