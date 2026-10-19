# Windows Hello unlock validation

The envelope tests run without Windows or TPM hardware:

```sh
dotnet run --project tests/VaultType.Hello.Tests -c Release
```

They verify authentication of ciphertext and enrollment context, malformed data rejection,
account/server/email isolation, policy tampering, nonce renewal and serialization. A simulated
256-byte TPM ciphertext tests the outer format only; it does not verify hardware security.

## Windows acceptance checks

Use a test vault and Windows 10 build 19041 or later with Windows Hello configured. Record the
Windows build, TPM manufacturer/version, app edition (portable/installed/MSIX) and test outcome.
Use a machine without a usable TPM for the negative persistence check. Test both PBKDF2 and
Argon2id accounts where available. No Windows Hello or TPM hardware checks can run on Linux CI.

1. Add/edit an account, select **Windows Hello**, leave persistence off and sign in. Complete
   enrollment. Lock and unlock using Hello. Repeat with fingerprint/face and Hello PIN where
   available. Confirm a fresh Windows prompt on every unlock and check foreground/focus behavior.
2. Cancel the Hello prompt. The vault must remain locked, and the dialog must allow retry, close
   and **Use master password**. Cancel enrollment separately: the app must report cancellation
   and select master-password unlock.
3. With persistence off, confirm `session.json` has no `Hello` envelope. Exit/relaunch and reboot
   Windows separately: each must first require the master password, followed by Hello enrollment.
4. Edit the account and turn TPM persistence on. Sign in/enroll, lock, exit/relaunch and reboot
   Windows. Each time Hello must unlock without entering the master password. The vault must stay
   locked until Hello succeeds. Only ciphertext/challenge/nonce/tag/identifier belong in `Hello`;
   no raw user key, signature, derived key or master password may be persisted.
5. Check the named `VaultType.Hello.<account id>.<key id>` key using a separate CNG test tool:
   provider must be **Microsoft Platform Crypto Provider**, implementation flags must include
   `NCRYPT_IMPL_HARDWARE_FLAG`, export policy must be zero and private-key export must fail. Do
   not export or log live vault keys. Test encryption/decryption only with synthetic key material.
6. Without a usable TPM, persistence enrollment must report a TPM error and leave master-password
   unlock selected. There must be no persisted Hello envelope and no software-provider fallback.
   RAM-only Hello remains usable if Windows itself supports it.
7. With a test vault only, corrupt the envelope/tag, delete its Hello credential, and remove its
   TPM key separately. Each case must remain locked and offer the master password. Complete
   fallback and confirm enrollment repairs the method. Do not clear a production TPM to test this.
8. Configure two accounts, including accounts on different servers. Switch between them in the
   unlock dialog. Copy one test account's envelope to the other: it must fail. Editing identity or
   server and switching to password/PIN must remove the old Hello envelope and OS keys.
9. Test SSH/passkey requests while locked. Hello must unlock the owning account only. An entry
   with master-password reprompt must still request the master password after Hello. Canceling
   Hello must not authorize the request. Repeat using the password fallback.
10. Disconnect the server or reject the refresh token. The vault must remain locked: network
    failure must show the connectivity error before prompting Hello; a rejected token must
    require sign-in (the synchronous agent request fails and can be retried after sign-in).
11. While sync or Hello is pending, lock the vault from the tray or let idle lock fire. A late
    result must not unlock it. Remove the account and verify its session and OS keys are removed.
    Check that canceling account edits leaves the current method usable.
12. Repeat enrollment/unlock in portable and MSIX editions. Verify localization, keyboard focus,
    master-password fallback layout, small-screen scrolling and existing password/PIN unlock.

Native acceptance remains required before release. Passing the portable tests or cross-compiling
the application does not establish that Hello prompts or TPM operations work on a Windows device.
