namespace VaultType.Security;

// Interactive requests must not queue behind one another: a second trigger while Hello is open
// should not produce another prompt after the user has already verified. The native operation
// must observe the supplied token (WinRT AsTask forwards cancellation to IAsyncInfo.Cancel).
internal sealed class HelloPromptCoordinator(TimeSpan timeout)
{
    private int _active;

    internal async Task<T> RunAsync<T>(Func<CancellationToken, Task<T>> action,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (Interlocked.CompareExchange(ref _active, 1, 0) != 0)
            throw new OperationCanceledException("A Windows Hello operation is already in progress.");
        try
        {
            using var deadline = new CancellationTokenSource(timeout);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
            try
            {
                linked.Token.ThrowIfCancellationRequested();
                return await action(linked.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (deadline.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
            {
                throw new TimeoutException("Windows Hello did not complete before the deadline.");
            }
        }
        finally { Volatile.Write(ref _active, 0); }
    }
}
