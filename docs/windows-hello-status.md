# Windows Hello / TPM handoff

Updated: 2026-10-20.

## Delivery

Implementation is complete in [fork PR #1](https://github.com/uJZk/VaultType/pull/1). Integration is
into `uJZk/VaultType` only; no upstream PR or Microsoft Store submission has been made. The user
requested the `tie-up` workflow to finish integration after the beta was published. The user
subsequently installed the beta and reported that Beta 2 resolves the observed Hello prompt issue. The full hardware acceptance checklist has not yet been reported.

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
not been imported. The user subsequently installed the beta, reported the prompt loop, and
confirmed on 2026-10-20 that Beta 2 works. The following instructions remain applicable to each beta with its
matching certificate.

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

Next: complete [the Windows acceptance checklist](windows-hello-testing.md),
especially native prompt/focus behavior, TPM private-key export rejection, app/OS restart persistence,
unavailable/reset TPM behavior, cancellation, password fallback and SSH/passkey reprompts. Keep the
release in beta until those device results are recorded. Consider an upstream PR afterward.

## Beta feedback follow-up

The user reported an always-on-top settings window and repeated Hello prompts after verification.
The settings window's hard-coded `Topmost=True` has been removed on the follow-up branch; the
Release cross-build passed with zero warnings/errors. Beta 1 retains the old window behavior;
[Beta 2](https://github.com/uJZk/VaultType/releases/tag/v1.2.4-beta.2) distributes the follow-up
candidate from `66e26f3598987561b5654b62cccffe8ec976e62c` (MSIX version `1.2.4.2`).

The user clarified that the prompt repeats indefinitely after saving the account, and canceling
returns a Hello failure. This is not the finite two-prompt first enrollment sequence. The candidate
fix in [PR #2](https://github.com/uJZk/VaultType/pull/2) allows one interactive vault
Hello operation at a time without queuing, a two-minute cancellation deadline forwarded to WinRT,
best-effort foreground activation of the native credential dialog only while VaultType owns the
foreground, and temporarily lowering the unlock window out of the topmost band. Native failures
identify `HELLO_CREATE`, `HELLO_OPEN` or `HELLO_SIGN`; native cancellation HRESULTs are treated as
cancellation instead of generic failure. No verification gate has been bypassed.

The follow-up cross-build passed with zero warnings/errors. All 34 tests passed, including five
new coordinator tests for concurrency, exception recovery, pre-cancellation, user cancellation and
deadline cancellation. These tests do not reproduce the actual Windows UI loop. Its root cause
was not established in development. On 2026-10-20 the user reported that Beta 2 works; the
individual TPM/restart checks have not been reported separately.
Enrollment still calls both creation and signing, which may each prompt once. Ordinary vault
unlock signs once; website passkey use may additionally invoke the original plugin verification.

The upstream source was checked directly: its settings XAML also specifies `Topmost=True`, its
account `bio` method falls back to the master password, and its functional Hello verification is
in `Security/Passkey/Ceremony.cs` for website passkey operations. The observed Store edition's
window behavior has not been independently reproduced.

There is also a [documented desktop credential-dialog focus issue](https://github.com/microsoft/cppwinrt/issues/999)
with this WinRT API, which lacks an owner-HWND overload. That supports testing foreground handling,
but is not proof that this user's infinite verification loop has the same cause. Beta 2 has a new
ephemeral signing certificate; import its own `.cer` before installing its MSIX, even if Beta 1's
certificate was already trusted. PR #2 remains open in the fork.

## Beta 3 UI follow-up

After reporting that Beta 2 works, the user requested removal of the settings-window topmost fix
and the TPM explanatory text. Settings again uses the upstream `Topmost=True` behavior; only the
unlock window's temporary yielding during native Hello remains. The account form keeps the TPM
persistence toggle and the supported Hello methods, but removes the persistence explanation and
its unused localization key from all 11 locales. Persistence defaults, hardware requirements and
cryptography are unchanged.

[Beta 3](https://github.com/uJZk/VaultType/releases/tag/v1.2.4-beta.3) packages this UI revision
from `3bbbdb9ef5abca85c419d5c810113cc9bc9d4c36` without replacing either earlier beta. Its MSIX
package version is `1.2.4.3`. The Release cross-build passed with zero warnings/errors; locale key
sets/placeholders and whitespace checks passed. All 34 tests passed on Windows in both
[CI](https://github.com/uJZk/VaultType/actions/runs/39355118310) and the
[portable/installer release](https://github.com/uJZk/VaultType/actions/runs/39355117964). The
[MSIX workflow](https://github.com/uJZk/VaultType/actions/runs/39355286465) builds the same tag,
checks the signature and manifest version before uploading the package and its matching certificate.

Its restored Settings stacking has not yet been tested on the user's device. Continue the
remaining hardware acceptance checks in [the checklist](windows-hello-testing.md).
