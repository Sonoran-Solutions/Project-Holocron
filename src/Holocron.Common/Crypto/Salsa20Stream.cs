namespace Holocron.Common.Crypto;

/// <summary>Directional streaming cipher adapter. Does not define compression
/// or application framing. A failed/cancelled write requires closing the session.</summary>
public sealed class Salsa20Stream(Stream inner, Salsa20 receive, Salsa20 send) : Stream
{
    private readonly SemaphoreSlim readGate = new(1);
    private readonly SemaphoreSlim writeGate = new(1);
    public override bool CanRead => inner.CanRead;
    public override bool CanWrite => inner.CanWrite;
    public override bool CanSeek => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
    {
        await readGate.WaitAsync(ct);
        try
        {
            int count = await inner.ReadAsync(buffer, ct);
            receive.Process(buffer.Span[..count], buffer.Span[..count]);
            return count;
        }
        finally { readGate.Release(); }
    }

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default)
    {
        await writeGate.WaitAsync(ct);
        byte[] encrypted = new byte[buffer.Length];
        try
        {
            send.Process(buffer.Span, encrypted);
            await inner.WriteAsync(encrypted, ct);
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(encrypted);
            writeGate.Release();
        }
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct)
        => ReadAsync(buffer.AsMemory(offset, count), ct).AsTask();
    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken ct)
        => WriteAsync(buffer.AsMemory(offset, count), ct).AsTask();
    public override void Flush() => inner.Flush();
    public override Task FlushAsync(CancellationToken ct) => inner.FlushAsync(ct);
    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException("Use asynchronous I/O.");
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException("Use asynchronous I/O.");
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
}
