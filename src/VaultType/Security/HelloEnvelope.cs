using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;

namespace VaultType.Security;

// Ciphertext only. Windows Hello signs Challenge; SHA-256 of that deterministic RSA signature
// is the AES key. Neither the signature nor the derived key may be stored with this envelope.
// With persistence enabled the AES plaintext is itself RSA-OAEP wrapped by the account's TPM key.
public sealed class HelloEnvelope
{
    public int Version { get; set; } = 1;
    public string KeyId { get; set; } = "";
    public bool TpmProtected { get; set; }
    public byte[] Challenge { get; set; } = Array.Empty<byte>();
    public byte[] Nonce { get; set; } = Array.Empty<byte>();
    public byte[] Tag { get; set; } = Array.Empty<byte>();
    public byte[] Ciphertext { get; set; } = Array.Empty<byte>();

    [JsonIgnore]
    public bool IsValid => Version == 1 && Guid.TryParseExact(KeyId, "N", out _)
        && Challenge?.Length == 32 && Nonce?.Length == 12 && Tag?.Length == 16
        && (TpmProtected ? Ciphertext?.Length == 256 : Ciphertext?.Length is 32 or 64);

    // Bind both layers to this account, server and enrollment. A copied or modified envelope
    // must fail authentication before its plaintext is used by the vault backend.
    private byte[] Context(string accountId, string server, string email)
        => Encoding.UTF8.GetBytes(System.Text.Json.JsonSerializer.Serialize(new object[]
        {
            "VaultType.WindowsHello", Version, accountId, server.TrimEnd('/'),
            email.Trim().ToLowerInvariant(), KeyId, TpmProtected, Convert.ToBase64String(Challenge),
        }));

    public void Seal(byte[] key, byte[] plaintext, string accountId, string server, string email)
    {
        Nonce = RandomNumberGenerator.GetBytes(12);
        Tag = new byte[16];
        Ciphertext = new byte[plaintext.Length];
        using var aes = new AesGcm(key, 16);
        aes.Encrypt(Nonce, plaintext, Ciphertext, Tag, Context(accountId, server, email));
    }

    // The caller owns (and must wipe) the returned plaintext.
    public byte[] Unseal(byte[] key, string accountId, string server, string email)
    {
        if (!IsValid) throw new CryptographicException("Invalid Windows Hello envelope.");
        byte[] plaintext = new byte[Ciphertext.Length];
        try
        {
            using var aes = new AesGcm(key, 16);
            aes.Decrypt(Nonce, Ciphertext, Tag, plaintext, Context(accountId, server, email));
            return plaintext;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(plaintext);
            throw;
        }
    }
}
