using System.Buffers;
using ZstdSharp;
using ZstdSharp.Unsafe;

namespace Holocron.Common.Protocol;

/// <summary>
/// SWTOR transport payload compression.
///
/// Retail keeps one Zstandard context per transport connection and one
/// continuous compressed stream for that connection's lifetime:
///
/// <list type="bullet">
/// <item>The contexts are created during application connection setup at
/// <c>0x14043E749</c> (compressor) and <c>0x14043E7AB</c> (decompressor) with a
/// zero level-selector argument, which resolves to Zstandard level 3 in the
/// shared <c>0x140439E90</c> initializer.</item>
/// <item>Both contexts are put into <c>ZSTD_f_zstd1_magicless</c> mode
/// (<c>ZSTD_c_format</c>/<c>ZSTD_d_format</c> = 1), so a compressed transport
/// payload begins directly with the frame header and never with the
/// <c>28 B5 2F FD</c> magic number.</item>
/// <item>Messages are emitted with <c>ZSTD_e_flush</c>, which terminates the
/// block but not the frame. Only the first message on a connection therefore
/// carries a frame header; every later message continues the same frame and
/// the receiver must keep one decompressor alive for the whole connection.</item>
/// <item>The transport sender only compresses payloads of at least
/// <c>0x20</c> bytes (<c>0x14043B887</c>), and the transport receiver only
/// decompresses frames whose type byte has bit <c>0x10</c> set.</item>
/// </list>
///
/// These settings were recovered from the installed client and were then
/// validated against a real client frame: the 40-byte payload of a captured
/// <c>0x10</c> request re-encodes byte-for-byte with this configuration.
/// </summary>
public static class TransportCompression
{
    /// <summary>Zstandard level used by the retail transport contexts.</summary>
    public const int Level = 3;

    /// <summary>Retail does not compress payloads shorter than this many bytes.</summary>
    public const int MinimumCompressiblePayload = 0x20;

    /// <summary>Upper bound applied to a single decompressed payload.</summary>
    public const int MaximumPayloadSize = TransportFrame.MaximumSize;

    /// <summary>ZSTD_c_format (parameter 10) set to ZSTD_f_zstd1_magicless (1).</summary>
    public static readonly ZSTD_cParameter CompressorFormat = ZSTD_cParameter.ZSTD_c_experimentalParam2;

    /// <summary>ZSTD_d_format (parameter 1000) set to ZSTD_f_zstd1_magicless (1).</summary>
    public static readonly ZSTD_dParameter DecompressorFormat = ZSTD_dParameter.ZSTD_d_experimentalParam1;
}

/// <summary>
/// One connection's outbound compression context. The Zstandard stream it owns
/// is continuous: every <see cref="Compress"/> call flushes the pending input
/// into the same frame, exactly like the retail sender.
/// </summary>
public sealed class TransportCompressor : IDisposable
{
    private readonly Compressor _compressor = new(TransportCompression.Level);
    private byte[] _buffer = new byte[TransportFrame.MaximumSize];

    public TransportCompressor()
    {
        _compressor.SetParameter(TransportCompression.CompressorFormat, (int)ZSTD_format_e.ZSTD_f_zstd1_magicless);
    }

    /// <summary>Compresses one application payload and flushes it into the stream.</summary>
    public byte[] Compress(ReadOnlySpan<byte> payload)
    {
        int consumed = 0;
        int written = 0;
        while (consumed < payload.Length)
        {
            EnsureCapacity(written + payload.Length + 64);
            var status = _compressor.WrapStream(
                payload[consumed..], _buffer.AsSpan(written), out int stepConsumed, out int stepWritten, isFinalBlock: false);
            consumed += stepConsumed;
            written += stepWritten;
            if (stepWritten == 0 && stepConsumed == 0)
            {
                if (status == System.Buffers.OperationStatus.InvalidData)
                    throw new InvalidDataException("Transport payload compression failed.");
                break;
            }
        }

        while (true)
        {
            EnsureCapacity(written + 64);
            _compressor.FlushStream(_buffer.AsSpan(written), out int flushed, isFinalBlock: false);
            written += flushed;
            if (flushed == 0) break;
        }

        return _buffer.AsSpan(0, written).ToArray();
    }

    private void EnsureCapacity(int required)
    {
        if (required <= _buffer.Length) return;
        int size = _buffer.Length;
        while (size < required) size *= 2;
        Array.Resize(ref _buffer, size);
    }

    public void Dispose() => _compressor.Dispose();
}

/// <summary>
/// One connection's inbound decompression context. Retail frames are flushed
/// but never terminated inside a transport frame, so the context must survive
/// across consecutive frames on the same connection.
/// </summary>
public sealed class TransportDecompressor : IDisposable
{
    private readonly Decompressor _decompressor = new();
    private byte[] _buffer = new byte[64 * 1024];

    public TransportDecompressor()
    {
        _decompressor.SetParameter(TransportCompression.DecompressorFormat, (int)ZSTD_format_e.ZSTD_f_zstd1_magicless);
    }

    /// <summary>Feeds one compressed transport payload and returns everything it produced.</summary>
    public byte[] Decompress(ReadOnlySpan<byte> payload)
    {
        int consumed = 0;
        int written = 0;
        while (true)
        {
            if (written == _buffer.Length)
            {
                if (_buffer.Length >= TransportCompression.MaximumPayloadSize)
                    throw new InvalidDataException("Decompressed transport payload exceeds the size limit.");
                Array.Resize(ref _buffer, Math.Min(_buffer.Length * 2, TransportCompression.MaximumPayloadSize));
            }

            var status = _decompressor.UnwrapStream(
                payload[consumed..], _buffer.AsSpan(written), out int stepConsumed, out int stepWritten);

            consumed += stepConsumed;
            written += stepWritten;

            switch (status)
            {
                // A flushed-but-unterminated retail frame legitimately reports
                // NeedMoreData; only a real decode error is a protocol failure.
                case OperationStatus.Done:
                case OperationStatus.NeedMoreData:
                    return _buffer.AsSpan(0, written).ToArray();
                case OperationStatus.DestinationTooSmall:
                    if (stepWritten == 0 && stepConsumed == 0)
                        throw new InvalidDataException("Decompressed transport payload made no progress.");
                    continue;
                default:
                    throw new InvalidDataException("Transport payload is not a valid compressed frame.");
            }
        }
    }

    public void Dispose() => _decompressor.Dispose();
}
