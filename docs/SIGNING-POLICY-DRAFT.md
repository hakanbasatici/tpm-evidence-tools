# Code signing policy — draft, not in force

Candidate signing path: SignPath Foundation for an independent open-source utility. No application has been submitted and no acceptance/certificate has been granted. No free-signing attribution is claimed at this stage.

Repository owner and maintainer: Hakan Basatici (@hakanbasatici). Sole maintainer and final signing approver: Hakan Basatici (@hakanbasatici), confirmed by the owner on 2026-10-15. No additional human code reviewer is assigned. This is a single-maintainer project; no independent human review is claimed. AI assistance supports technical coordination, implementation and review; it is not an accountable human reviewer, repository owner or signing approver. GitHub authenticator-based 2FA was enabled on 2026-10-15, confirmed by the owner's success screen. This is not an API audit of account security. No SignPath account or SignPath MFA configuration has been verified. Every participating repository/signing account must use MFA.

Private security reporting is enabled; see [SECURITY.md](../SECURITY.md). No test advisory has been sent. The project has a public MIT source preview but no published binary release. This does not yet establish the provider's already-released-artifact condition.

A proposed signing request must bind the exact reviewed source commit, build configuration, product name/version, independently inspected binary hash, license and allowed artifacts. Only artifacts built from reviewed project sources may be signed. No arbitrary uploaded EXE or DOK proprietary binary can be signed under this project.

Candidate artifact names: PcrBanks.exe and EphemeralClaim.exe. Windows resource ProductName is TPM Evidence Tools, version 0.1.0-draft. Static code-signing policy checks and signed output verification are separate from TPM evidence validation.

If accepted, the final release page must add the precise attribution required by SignPath, reflect the actual certificate publisher, publish privacy/uninstallation information and replace draft URLs/channels with real ones. SignPath Foundation may be the visible publisher; that is not a Hakan Basatici certificate. Its project/reputation and security-tool restrictions require provider assessment; eligibility is not guaranteed.

Source: https://signpath.org/terms.html
