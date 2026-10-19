using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.WindowsRuntime;
using Microsoft.Win32.SafeHandles;
using Windows.Security.Credentials;
using Windows.Security.Cryptography;

namespace VaultType.Security;

// Native Windows Hello credentials work in installed, portable and MSIX builds. Every use signs
// a challenge: a boolean consent result alone would not cryptographically protect an envelope.
// No signature/derived key cache: every unlock, including SSH/passkey requests, needs fresh Hello.
internal static class WindowsHelloKey
{
    private static readonly CngProvider TpmProvider = new("Microsoft Platform Crypto Provider");
    private static string Name(string accountId, string keyId) => $"VaultType.Hello.{accountId}.{keyId}";

    internal static async Task<HelloEnvelope> EnrollAsync(string accountId, string server, string email,
        Func<byte[]> exportUserKey, bool persist)
    {
        if (!await KeyCredentialManager.IsSupportedAsync())
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

            var result = await KeyCredentialManager.RequestCreateAsync(Name(accountId, envelope.KeyId),
                KeyCredentialCreationOption.FailIfExists);
            CheckStatus(result.Status);
            wrappingKey = await DeriveKeyAsync(result.Credential, envelope.Challenge);
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

    internal static async Task<byte[]> UnwrapAsync(string accountId, string server, string email, HelloEnvelope envelope)
    {
        if (!envelope.IsValid) throw new CryptographicException(Loc.T("hello.failed"));
        // Open only. Recreating a missing credential on unlock cannot recover its envelope.
        var result = await KeyCredentialManager.OpenAsync(Name(accountId, envelope.KeyId));
        CheckStatus(result.Status);
        byte[] key = await DeriveKeyAsync(result.Credential, envelope.Challenge);
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

    private static async Task<byte[]> DeriveKeyAsync(KeyCredential credential, byte[] challenge)
    {
        var result = await credential.RequestSignAsync(CryptographicBuffer.CreateFromByteArray(challenge));
        CheckStatus(result.Status);
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

    private static void CheckStatus(KeyCredentialStatus status)
    {
        if (status == KeyCredentialStatus.UserCanceled) throw new OperationCanceledException();
        if (status != KeyCredentialStatus.Success) throw new CryptographicException(Loc.T("hello.failed"));
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
        try { await KeyCredentialManager.DeleteAsync(Name(accountId, envelope.KeyId)); } catch { }
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
