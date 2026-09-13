using Holocron.Common.Crypto;

namespace Holocron.Common.Protocol;

/// <summary>One decoded transport frame: the transport type from the low nibble
/// and the logical (decompressed) application payload.</summary>
public readonly record struct TransportMessage(byte Type, byte[] Payload)
{
    public bool IsControl => Type != 0;
}

/// <summary>
/// Stateful SWTOR transport codec for one connection.
///
/// Receive: socket bytes -> Salsa20 -> validate the six-byte transport header ->
/// inspect the type byte -> decompress when bit <c>0x10</c> is set -> logical
/// payload.
///
/// Send: logical payload -> compress when it is large enough -> transport frame
/// with bit <c>0x10</c> -> Salsa20 -> socket.
///
/// Encryption is session state rather than a per-frame property, and bit
/// <c>0x10</c> is a compression flag on the transport type byte rather than a
/// distinct transport class: the retail sender sets it only after compressing
/// (<c>0x14045C4F1</c>) and the retail receiver tests it before decompressing
/// (<c>0x14043BD24</c>). The low nibble carries the actual transport type
/// (<c>0</c> = routed application dispatch, <c>1</c>/<c>2</c> = time sync,
/// <c>4</c> = key exchange).
/// </summary>
public sealed class TransportCodec : IDisposable
{
    private readonly Salsa20Stream _stream;
    private readonly TransportCompressor _compressor = new();
    private readonly TransportDecompressor _decompressor = new();

    public TransportCodec(Stream inner, Salsa20 receive, Salsa20 send)
    {
        _stream = new Salsa20Stream(inner, receive, send);
    }

    /// <summary>Reads and decodes the next transport frame, or null at clean end of stream.</summary>
    public async Task<TransportMessage?> ReadAsync(CancellationToken ct = default)
    {
        byte[]? frame = await TransportFrame.ReadAsync(_stream, ct);
        return frame is null ? null : Decode(frame);
    }

    private TransportMessage Decode(byte[] frame)
    {
        byte type = frame[0];
        ReadOnlySpan<byte> payload = frame.AsSpan(TransportFrame.HeaderSize);
        bool compressed = (type & TransportFrame.CompressionFlag) != 0;
        byte[] logical = compressed ? _decompressor.Decompress(payload) : payload.ToArray();
        return new TransportMessage((byte)(type & TransportFrame.TypeMask), logical);
    }

    /// <summary>Encodes and writes one logical payload as a transport frame.</summary>
    public Task WriteAsync(byte type, byte[] payload, CancellationToken ct = default)
    {
        bool compress = payload.Length >= TransportCompression.MinimumCompressiblePayload;
        byte[] encoded = compress ? _compressor.Compress(payload) : payload;
        byte[] frame = TransportFrame.Encode(
            (byte)((type & TransportFrame.TypeMask) | (compress ? TransportFrame.CompressionFlag : 0)), encoded);
        return WriteFrameAsync(frame, ct);
    }

    private async Task WriteFrameAsync(byte[] frame, CancellationToken ct)
    {
        await _stream.WriteAsync(frame, ct);
        await _stream.FlushAsync(ct);
    }

    public void Dispose()
    {
        _compressor.Dispose();
        _decompressor.Dispose();
        _stream.Dispose();
    }
}
