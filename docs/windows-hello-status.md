# Windows Hello / TPM handoff

Updated: 2026-10-19.

## Delivery

Implementation is complete in [fork PR #1](https://github.com/uJZk/VaultType/pull/1). Integration is
into `uJZk/VaultType` only; no upstream PR or Microsoft Store submission has been made. The user
requested the `tie-up` workflow to finish integration after the beta was published. Windows device
acceptance remains pending; integration does not establish production readiness.

[Beta v1.2.4-beta.1](https://github.com/uJZk/VaultType/releases/tag/v1.2.4-beta.1) is a published
pre-release, built from `93ddf7df0b3ef98c1e8c82515aea062cbb9971ec`. Its assets include the portable
x64 ZIP, installer, signed MSIX, public test certificate and MSIX installation instructions. The
MSIX package version is `1.2.4.1`. Later commits add release automation and this handoff; the beta
tag and its existing binaries have not been moved or replaced.

## Agreed behavior

- Windows Hello accepts fingerprint, face and the Windows Hello PIN. The existing `bio` preference
  remains compatible with saved configuration.
- TPM persistence is an independent, per-account option, **off by default**. Without it the Hello
  envelope stays in RAM and restarting VaultType requires one master-password unlock and Hello
  enrollment again.
- Persistence requires a usable TPM, a hardware provider and a non-exportable wrapping key, with
  no software-provider fallback. A Hello signature derives the AES-GCM wrapping key; signatures
  and derived keys are not cached. The persisted envelope is bound to account/server/enrollment.
- Every Hello unlock still needs a connection to the vault server. It does not provide offline
  vault storage or automatic unlock at startup.
- Master-password fallback and entry reprompts remain available. SSH/passkey requests share the
  unlock flow. A lock arriving during a pending Hello operation invalidates its result.
- Beta release tags skip Store submission and default-branch changelog updates. The manual
  `msix_release_tag` input on the Release workflow attaches an MSIX built from an existing beta's
  exact tag commit; it does not rebuild from a moving branch.

## Verification

- Release cross-build: zero warnings/errors; Windows x64 self-contained publication completed.
- The envelope suite passed all 29 tests locally and on Windows CI. All 11 locale key sets and
  format placeholders match. These checks do not simulate Windows Hello or TPM hardware.
- [Windows CI](https://github.com/uJZk/VaultType/actions/runs/39202515744) passed for the final
  implementation/release-automation commit before this documentation update.
- [Beta release workflow](https://github.com/uJZk/VaultType/actions/runs/39201381365) built and
  uploaded portable/installer assets; Store and changelog steps were skipped.
- [MSIX workflow](https://github.com/uJZk/VaultType/actions/runs/39202538854) passed the envelope
  tests, built the package from the beta tag, verified its signature and manifest version, and
  uploaded all three MSIX-related assets. Signature verification trusted the test signer on the
  disposable runner; it does not mean the certificate is publicly trusted on users' computers.
- The downloaded release certificate was independently confirmed to match a certificate embedded
  in the published MSIX signature. Its SHA-1 thumbprint is
  `7D1549A6C61152BE3D8651DF26C3EBE8620BFC0C` (subject/issuer `CN=VaultType Dev`).

## Installation status and next steps

The user encountered certificate-chain error `0x800B010A` and confirmed the test certificate had
not been imported. The following instructions were supplied; successful installation has **not**
yet been reported.

Download the MSIX and its matching `VaultType-1.2.4-beta.1-dev.cer` from the same beta release.
In administrator PowerShell, in the download directory:

```powershell
Import-Certificate -FilePath ".\VaultType-1.2.4-beta.1-dev.cer" -CertStoreLocation Cert:\LocalMachine\TrustedPeople
```

Then install under the user's normal Windows account:

```powershell
Add-AppxPackage -Path ".\VaultType-1.2.4-beta.1-win-x64.msix"
```

This self-signed package uses the development identity, separate from the Microsoft Store edition.
Passkey Provider requires Windows 11 24H2 or later. Only the public certificate is distributed;
the signing private key stayed on the disposable build runner.

Next: confirm installation, then complete [the Windows acceptance checklist](windows-hello-testing.md),
especially native prompt/focus behavior, TPM private-key export rejection, app/OS restart persistence,
unavailable/reset TPM behavior, cancellation, password fallback and SSH/passkey reprompts. Keep the
release in beta until those device results are recorded. Consider an upstream PR afterward.

## Beta feedback follow-up

The user reported an always-on-top settings window and repeated Hello prompts after verification.
The settings window's hard-coded `Topmost=True` has been removed on the follow-up branch; the
Release cross-build passed with zero warnings/errors. The published beta still contains the old
window behavior until a follow-up build is released.

The repeated-prompt report still needs its trigger and count: first enrollment, ordinary vault
unlock, or a website passkey request. Enrollment currently calls both `RequestCreateAsync` and
`RequestSignAsync`, which can each prompt. An ordinary vault unlock calls `RequestSignAsync` once.
Passkey use can additionally invoke the original plugin user-verification prompt. Do not describe
an indefinite loop as fixed or remove a verification gate without identifying the reported path.

The upstream source was checked directly: its settings XAML also specifies `Topmost=True`, its
account `bio` method falls back to the master password, and its functional Hello verification is
in `Security/Passkey/Ceremony.cs` for website passkey operations. The observed Store edition's
window behavior has not been independently reproduced.
