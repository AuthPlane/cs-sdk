namespace Authplane;

/// <summary>
/// In-process <see cref="IDPoPNonceStore"/> with true LRU eviction at the
/// configured capacity (128 by default). Both reads and writes move the entry to
/// the most-recently-used position, so the eviction victim is genuinely the
/// least-recently-touched origin instead of a hash-table-arbitrary one.
/// </summary>
public sealed class InMemoryDPoPNonceStore : IDPoPNonceStore
{
    /// <summary>Default capacity (entries).</summary>
    public const int DefaultMaxEntries = 128;

    private readonly int _maxEntries;

    /// <summary>
    /// Configure the LRU capacity. Must be positive.
    /// </summary>
    public InMemoryDPoPNonceStore(int maxEntries = DefaultMaxEntries)
    {
        if (maxEntries <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxEntries),
                "maxEntries must be positive.");
        }
        _maxEntries = maxEntries;
    }

    // LinkedList tracks insertion / access order; the head is the LRU end.
    private readonly LinkedList<KeyValuePair<string, string>> _order = new();
    private readonly Dictionary<string, LinkedListNode<KeyValuePair<string, string>>> _index = new();
    private readonly object _gate = new();

    public Task<string?> GetAsync(string origin, CancellationToken cancellationToken = default)
    {
        string? nonce;
        lock (_gate)
        {
            if (_index.TryGetValue(origin, out var node))
            {
                _order.Remove(node);
                _order.AddLast(node);
                nonce = node.Value.Value;
            }
            else
            {
                nonce = null;
            }
        }
        return Task.FromResult(nonce);
    }

    public Task SetAsync(string origin, string nonce, CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            if (_index.TryGetValue(origin, out var existing))
            {
                _order.Remove(existing);
                _index.Remove(origin);
            }

            var node = new LinkedListNode<KeyValuePair<string, string>>(new(origin, nonce));
            _order.AddLast(node);
            _index[origin] = node;

            while (_index.Count > _maxEntries)
            {
                var lru = _order.First;
                if (lru is null)
                {
                    break;
                }
                _order.RemoveFirst();
                _index.Remove(lru.Value.Key);
            }
        }
        return Task.CompletedTask;
    }
}
