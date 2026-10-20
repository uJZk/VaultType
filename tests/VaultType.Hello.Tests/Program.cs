using System.Security.Cryptography;
using System.Text.Json;
using VaultType.Security;

// No Windows/Hello device or test framework dependency: exercise the real persisted crypto format
// on every CI run. Native Hello/TPM and restart checks are in docs/windows-hello-testing.md.
const string Account = "a08c62edbba54b62b77ecb00becdd25a5";
const string Server = "https://vault.example.com/bitwarden";
const string Email = "alice@example.com";
int passed = 0, failed = 0;
byte[] key = RandomNumberGenerator.GetBytes(32);
byte[] raw = RandomNumberGenerator.GetBytes(64);

HelloEnvelope Make(bool tpm = false, byte[]? plaintext = null)
{
    var envelope = new HelloEnvelope
    {
        KeyId = Guid.NewGuid().ToString("N"),
        Challenge = RandomNumberGenerator.GetBytes(32),
        TpmProtected = tpm,
    };
    envelope.Seal(key, plaintext ?? raw, Account, Server, Email);
    return envelope;
}

void Check(string name, Action test)
{
    try { test(); passed++; Console.WriteLine($"PASS {name}"); }
    catch (Exception ex) { failed++; Console.WriteLine($"FAIL {name}: {ex.Message}"); }
}

async Task CheckAsync(string name, Func<Task> test)
{
    try { await test(); passed++; Console.WriteLine($"PASS {name}"); }
    catch (Exception ex) { failed++; Console.WriteLine($"FAIL {name}: {ex.Message}"); }
}

void Require(bool ok)
{
    if (!ok) throw new Exception("Assertion failed.");
}

void Reject(Action action)
{
    try { action(); }
    catch (CryptographicException) { return; }
    throw new Exception("Unauthenticated envelope was accepted.");
}

try
{
    foreach (int length in new[] { 32, 64 })
    {
        Check($"user key round trip ({length} bytes)", () =>
        {
            byte[] plaintext = raw[..length];
            var envelope = Make(plaintext: plaintext);
            Require(envelope.IsValid);
            byte[] recovered = envelope.Unseal(key, Account, Server, Email);
            try { Require(recovered.AsSpan().SequenceEqual(plaintext)); }
            finally { CryptographicOperations.ZeroMemory(recovered); }
        });
    }

    Check("TPM ciphertext survives persistence", () =>
    {
        // These bytes stand for RSA-2048 ciphertext. This test covers the outer envelope only;
        // hardware protection is verified on Windows, never simulated as a passing TPM check.
        byte[] tpmCipher = RandomNumberGenerator.GetBytes(256);
        var envelope = JsonSerializer.Deserialize<HelloEnvelope>(JsonSerializer.Serialize(Make(true, tpmCipher)))!;
        Require(envelope.IsValid && envelope.TpmProtected);
        byte[] recovered = envelope.Unseal(key, Account, Server, Email);
        try { Require(recovered.AsSpan().SequenceEqual(tpmCipher)); }
        finally { CryptographicOperations.ZeroMemory(recovered); }
    });

    Check("wrong signing-derived key rejected", () => Reject(() =>
        Make().Unseal(RandomNumberGenerator.GetBytes(32), Account, Server, Email)));
    Check("other account rejected", () => Reject(() => Make().Unseal(key, "other-account", Server, Email)));
    Check("other server rejected", () => Reject(() => Make().Unseal(key, Account, "https://other.example.com", Email)));
    Check("case-sensitive server path bound", () => Reject(() =>
        Make().Unseal(key, Account, "https://vault.example.com/Bitwarden", Email)));
    Check("other email rejected", () => Reject(() => Make().Unseal(key, Account, Server, "bob@example.com")));
    Check("normalized email and trailing slash", () =>
    {
        byte[] recovered = Make().Unseal(key, Account, Server + "/", " Alice@Example.com ");
        try { Require(recovered.AsSpan().SequenceEqual(raw)); }
        finally { CryptographicOperations.ZeroMemory(recovered); }
    });

    foreach (var (name, mutate) in new (string, Action<HelloEnvelope>)[]
    {
        ("ciphertext", e => e.Ciphertext[0] ^= 1),
        ("tag", e => e.Tag[0] ^= 1),
        ("nonce", e => e.Nonce[0] ^= 1),
        ("challenge", e => e.Challenge[0] ^= 1),
        ("enrollment id", e => e.KeyId = Guid.NewGuid().ToString("N")),
        ("unknown version", e => e.Version = 2),
        ("invalid enrollment id", e => e.KeyId = "../other"),
        ("missing challenge", e => e.Challenge = null!),
        ("short challenge", e => e.Challenge = new byte[31]),
        ("missing nonce", e => e.Nonce = null!),
        ("short nonce", e => e.Nonce = new byte[11]),
        ("missing tag", e => e.Tag = null!),
        ("short tag", e => e.Tag = new byte[15]),
        ("missing ciphertext", e => e.Ciphertext = null!),
        ("truncated ciphertext", e => e.Ciphertext = e.Ciphertext[..63]),
        ("TPM downgrade", e => e.TpmProtected = false),
    })
    {
        Check($"tampered {name} rejected", () =>
        {
            var envelope = name == "TPM downgrade" ? Make(true, new byte[256]) : Make();
            mutate(envelope);
            Reject(() => envelope.Unseal(key, Account, Server, Email));
        });
    }

    Check("missing fields rejected", () => Reject(() =>
        JsonSerializer.Deserialize<HelloEnvelope>("{}")!.Unseal(key, Account, Server, Email)));
    Check("TPM policy is authenticated", () =>
    {
        // Same length, different mode: bypassing shape validation still cannot bypass the tag.
        var envelope = Make();
        envelope.TpmProtected = true;
        envelope.Ciphertext = new byte[256];
        Require(envelope.IsValid);
        Reject(() => envelope.Unseal(key, Account, Server, Email));
    });
    Check("fresh nonce on reseal", () =>
    {
        var envelope = Make();
        byte[] nonce = (byte[])envelope.Nonce.Clone();
        envelope.Seal(key, raw, Account, Server, Email);
        Require(!nonce.AsSpan().SequenceEqual(envelope.Nonce));
    });
    Check("serialized envelope contains no plaintext or derived key", () =>
    {
        string json = JsonSerializer.Serialize(Make());
        Require(!json.Contains(Convert.ToBase64String(raw)) && !json.Contains(Convert.ToBase64String(key)));
        Require(!json.Contains("IsValid"));
    });

    await CheckAsync("concurrent Hello is rejected, never queued or started", async () =>
    {
        var gate = new HelloPromptCoordinator(TimeSpan.FromSeconds(5));
        var finish = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
        int calls = 0;
        var first = gate.RunAsync(_ => { calls++; return finish.Task; });
        try
        {
            try { await gate.RunAsync(_ => { calls++; return Task.FromResult(2); }); throw new Exception("Duplicate prompt accepted."); }
            catch (OperationCanceledException) { }
            Require(calls == 1);
        }
        finally { finish.TrySetResult(1); }
        Require(await first == 1);
        Require(await gate.RunAsync(_ => Task.FromResult(3)) == 3);
    });

    await CheckAsync("Hello exception releases the gate without retry", async () =>
    {
        var gate = new HelloPromptCoordinator(TimeSpan.FromSeconds(5));
        int calls = 0;
        try
        {
            await gate.RunAsync<int>(_ => { calls++; throw new CryptographicException(); });
            throw new Exception("Failure was swallowed.");
        }
        catch (CryptographicException) { }
        Require(calls == 1 && await gate.RunAsync(_ => Task.FromResult(true)));
    });

    await CheckAsync("pre-canceled Hello never starts authentication", async () =>
    {
        var gate = new HelloPromptCoordinator(TimeSpan.FromSeconds(5));
        using var canceled = new CancellationTokenSource();
        canceled.Cancel();
        bool started = false;
        try
        {
            await gate.RunAsync(_ => { started = true; return Task.FromResult(true); }, canceled.Token);
            throw new Exception("Cancellation was ignored.");
        }
        catch (OperationCanceledException) { }
        Require(!started && await gate.RunAsync(_ => Task.FromResult(true)));
    });

    await CheckAsync("user cancellation is propagated once without retry", async () =>
    {
        var gate = new HelloPromptCoordinator(TimeSpan.FromSeconds(5));
        using var canceled = new CancellationTokenSource();
        int calls = 0;
        var pending = gate.RunAsync(async ct => { calls++; await Task.Delay(Timeout.Infinite, ct); return true; }, canceled.Token);
        canceled.Cancel();
        try { await pending.WaitAsync(TimeSpan.FromSeconds(5)); throw new Exception("Cancellation was ignored."); }
        catch (OperationCanceledException) { }
        Require(calls == 1 && await gate.RunAsync(_ => Task.FromResult(true)));
    });

    await CheckAsync("deadline cancels the operation and allows a later explicit attempt", async () =>
    {
        var gate = new HelloPromptCoordinator(TimeSpan.FromMilliseconds(40));
        bool operationCanceled = false;
        int calls = 0;
        try
        {
            await gate.RunAsync(async ct =>
            {
                calls++;
                try { await Task.Delay(Timeout.Infinite, ct); return true; }
                finally { operationCanceled = ct.IsCancellationRequested; }
            }).WaitAsync(TimeSpan.FromSeconds(5));
            throw new Exception("Deadline was ignored.");
        }
        catch (TimeoutException) { }
        Require(operationCanceled && calls == 1 && await gate.RunAsync(_ => Task.FromResult(true)));
    });
}
finally
{
    CryptographicOperations.ZeroMemory(key);
    CryptographicOperations.ZeroMemory(raw);
}
Console.WriteLine($"{passed} passed; {failed} failed.");
return failed == 0 ? 0 : 1;
