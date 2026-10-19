using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.WindowsRuntime;
using Microsoft.Win32.SafeHandles;
using Windows.Security.Credentials;
using Windows.Security.Cryptography;
using Windows.Foundation;

namespace VaultType.Security;

// Native Windows Hello credentials work in installed, portable and MSIX builds. Every use signs
// a challenge: a boolean consent result alone would not cryptographically protect an envelope.
// No signature/derived key cache: every unlock, including SSH/passkey requests, needs fresh Hello.
internal static class WindowsHelloKey
{
    private static readonly CngProvider TpmProvider = new("Microsoft Platform Crypto Provider");
    private static readonly HelloPromptCoordinator Prompts = new(TimeSpan.FromMinutes(2));
    private static string Name(string accountId, string keyId) => $"VaultType.Hello.{accountId}.{keyId}";

    internal static Task<HelloEnvelope> EnrollAsync(string accountId, string server, string email,
        Func<byte[]> exportUserKey, bool persist)
        => Prompts.RunAsync(ct => EnrollCoreAsync(accountId, server, email, exportUserKey, persist, ct));

    private static async Task<HelloEnvelope> EnrollCoreAsync(string accountId, string server, string email,
        Func<byte[]> exportUserKey, bool persist, CancellationToken ct)
    {
        if (!await KeyCredentialManager.IsSupportedAsync().AsTask(ct))
            throw new InvalidOperationException(Loc.T("hello.unavailable"));

        var envelope = new HelloEnvelope
        {
            KeyId = Guid.NewGuid().ToString("N"),
            Challenge = RandomNumberGenerator.GetBytes(32),
            TpmProtected = persist,
        };
        byte[]? userKey = null, wrappingKey = null, tpmCipher = null;
        CngKey? tpm = null;
        try
        {
            // Fail before displaying Hello if there is no usable TPM. Never use a software KSP
            // as a fallback for the persistence option.
            if (persist)
            {
                try
                {
                    tpm = CngKey.Create(CngAlgorithm.Rsa, Name(accountId, envelope.KeyId),
                        new CngKeyCreationParameters
                        {
                            Provider = TpmProvider,
                            KeyUsage = CngKeyUsages.Decryption,
                            ExportPolicy = CngExportPolicies.None,
                            Parameters = { new CngProperty("Length", BitConverter.GetBytes(2048), CngPropertyOptions.None) },
                        });
                    RequireHardware(tpm);
                }
                catch (CryptographicException ex)
                {
                    throw new CryptographicException(Loc.T("hello.tpmUnavailable"), ex);
                }
            }

            var result = await PromptAsync(() => KeyCredentialManager.RequestCreateAsync(Name(accountId, envelope.KeyId),
                KeyCredentialCreationOption.FailIfExists), ct, "HELLO_CREATE");
            CheckStatus(result.Status, "HELLO_CREATE");
            wrappingKey = await DeriveKeyAsync(result.Credential, envelope.Challenge, ct);
            ct.ThrowIfCancellationRequested();
            // Export only after the interactive prompt: a plaintext vault key must not sit in a
            // managed array while Windows waits for the user. The callback also rechecks lock state.
            userKey = exportUserKey();
            if (tpm != null)
            {
                using var rsa = new RSACng(tpm);
                tpmCipher = rsa.Encrypt(userKey, RSAEncryptionPadding.OaepSHA256);
            }
            envelope.Seal(wrappingKey, tpmCipher ?? userKey, accountId, server, email);
            return envelope;
        }
        catch
        {
            if (userKey != null) CryptographicOperations.ZeroMemory(userKey);
            if (wrappingKey != null) CryptographicOperations.ZeroMemory(wrappingKey);
            tpm?.Dispose();
            tpm = null;
            await DeleteAsync(accountId, envelope);
            throw;
        }
        finally
        {
            tpm?.Dispose();
            if (userKey != null) CryptographicOperations.ZeroMemory(userKey);
            if (wrappingKey != null) CryptographicOperations.ZeroMemory(wrappingKey);
            if (tpmCipher != null) CryptographicOperations.ZeroMemory(tpmCipher);
        }
    }

    internal static Task<byte[]> UnwrapAsync(string accountId, string server, string email, HelloEnvelope envelope,
        CancellationToken cancellationToken = default)
        => Prompts.RunAsync(ct => UnwrapCoreAsync(accountId, server, email, envelope, ct), cancellationToken);

    private static async Task<byte[]> UnwrapCoreAsync(string accountId, string server, string email,
        HelloEnvelope envelope, CancellationToken ct)
    {
        if (!envelope.IsValid) throw new CryptographicException(Loc.T("hello.failed"));
        // Open only. Recreating a missing credential on unlock cannot recover its envelope.
        var result = await KeyCredentialManager.OpenAsync(Name(accountId, envelope.KeyId)).AsTask(ct);
        CheckStatus(result.Status, "HELLO_OPEN");
        byte[] key = await DeriveKeyAsync(result.Credential, envelope.Challenge, ct);
        byte[]? plaintext = null;
        try
        {
            plaintext = envelope.Unseal(key, accountId, server, email);
            if (!envelope.TpmProtected)
            {
                byte[] raw = plaintext;
                plaintext = null; // ownership passes to the caller
                return raw;
            }
            using var tpm = CngKey.Open(Name(accountId, envelope.KeyId), TpmProvider);
            RequireHardware(tpm);
            using var rsa = new RSACng(tpm);
            return rsa.Decrypt(plaintext, RSAEncryptionPadding.OaepSHA256);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            if (plaintext != null) CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private static async Task<byte[]> DeriveKeyAsync(KeyCredential credential, byte[] challenge, CancellationToken ct)
    {
        var result = await PromptAsync(() => credential.RequestSignAsync(CryptographicBuffer.CreateFromByteArray(challenge)),
            ct, "HELLO_SIGN");
        CheckStatus(result.Status, "HELLO_SIGN");
        CryptographicBuffer.CopyToByteArray(result.Result, out byte[] signature);
        try
        {
            // Clear the WinRT buffer as well as the managed copy of this secret signature.
            using var stream = result.Result.AsStream();
            stream.Write(new byte[checked((int)result.Result.Length)]);
            return SHA256.HashData(signature);
        }
        finally { CryptographicOperations.ZeroMemory(signature); }
    }

    // The desktop credential API has no owner-HWND overload. Give its visible security dialog
    // foreground once, only while our own app still owns the foreground. Never pull focus back
    // from an unrelated app the user has deliberately switched to. No polling after completion.
    private static async Task<T> PromptAsync<T>(Func<IAsyncOperation<T>> start, CancellationToken ct, string stage)
    {
        int focused = 0;
        await using var timer = new System.Threading.Timer(_ =>
        {
            if (ct.IsCancellationRequested || Volatile.Read(ref focused) != 0) return;
            try
            {
                IntPtr dialog = Native.FindWindow("Credential Dialog Xaml Host", null);
                if (dialog == IntPtr.Zero || !Native.IsWindowVisible(dialog)) return;
                IntPtr foreground = Native.GetForegroundWindow();
                if (foreground == dialog) { Interlocked.Exchange(ref focused, 1); return; }
                Native.GetWindowThreadProcessId(foreground, out uint owner);
                if (owner == (uint)Environment.ProcessId && Native.SetForegroundWindow(dialog))
                    Interlocked.Exchange(ref focused, 1);
            }
            catch { /* foreground assistance is best effort, never an authentication result */ }
        }, null, TimeSpan.FromMilliseconds(250), TimeSpan.FromMilliseconds(250));
        try { return await start().AsTask(ct).ConfigureAwait(false); }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) when (ex.HResult is unchecked((int)0x80090036) // NTE_USER_CANCELLED
            or unchecked((int)0x800704C7) or unchecked((int)0x80004004))
        {
            throw new OperationCanceledException("Windows Hello was canceled.", ex, ct);
        }
        catch (Exception ex)
        {
            throw new CryptographicException($"{Loc.T("hello.failed")} ({stage}: 0x{ex.HResult:X8})", ex);
        }
    }

    private static void CheckStatus(KeyCredentialStatus status, string stage)
    {
        if (status == KeyCredentialStatus.UserCanceled) throw new OperationCanceledException();
        if (status != KeyCredentialStatus.Success)
            throw new CryptographicException($"{Loc.T("hello.failed")} ({stage}: {status})");
    }

    private static void RequireHardware(CngKey key)
    {
        using var provider = key.ProviderHandle;
        if (NCryptGetProperty(provider, "Impl Type", out int flags, sizeof(int), out _, 0) != 0
            || (flags & 1) == 0
            || key.ExportPolicy != CngExportPolicies.None)
            throw new CryptographicException(Loc.T("hello.tpmUnavailable"));
    }

    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    private static extern int NCryptGetProperty(SafeNCryptProviderHandle handle, string property,
        out int value, int size, out int resultSize, int flags);

    // Ciphertext is removed by the backend first. A failed OS-key cleanup must not restore unlock.
    internal static async Task DeleteAsync(string accountId, HelloEnvelope envelope)
    {
        if (!Guid.TryParseExact(envelope.KeyId, "N", out _)) return;
        try
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await KeyCredentialManager.DeleteAsync(Name(accountId, envelope.KeyId)).AsTask(deadline.Token);
        }
        catch { }
        if (envelope.TpmProtected)
        {
            try
            {
                using var key = CngKey.Open(Name(accountId, envelope.KeyId), TpmProvider);
                key.Delete();
            }
            catch { }
        }
    }
}
