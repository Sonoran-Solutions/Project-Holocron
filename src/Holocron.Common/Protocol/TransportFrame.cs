using System.Buffers.Binary;

namespace Holocron.Common.Protocol;

/// <summary>Uncompressed, unencrypted transport framing. Encryption/compression
/// must be handled separately; application packets are not transport headers.</summary>
public static class TransportFrame
{
    public const int HeaderSize = 6;
    public const int MaximumSize = 1024 * 1024;

    public static byte[] Encode(byte type, ReadOnlySpan<byte> payload)
    {
        if (payload.Length > MaximumSize - HeaderSize)
            throw new InvalidDataException("Transport frame exceeds size limit.");
        byte[] frame = new byte[HeaderSize + payload.Length];
        frame[0] = type;
        BinaryPrimitives.WriteInt32LittleEndian(frame.AsSpan(1, 4), frame.Length);
        frame[5] = ComputeChecksum(frame);
        payload.CopyTo(frame.AsSpan(HeaderSize));
        return frame;
    }

    public static async Task<byte[]?> ReadAsync(Stream stream, CancellationToken ct = default)
    {
        byte[] header = new byte[HeaderSize];
        if (await stream.ReadAsync(header.AsMemory(0, 1), ct) == 0) return null;
        await stream.ReadExactlyAsync(header.AsMemory(1), ct);
        byte checksum = ComputeChecksum(header);
        if (checksum != header[5]) throw new InvalidDataException("Invalid transport header checksum.");
        int length = BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(1, 4));
        if (length < HeaderSize || length > MaximumSize)
            throw new InvalidDataException("Invalid transport frame length.");
        byte[] frame = new byte[length];
        header.CopyTo(frame, 0);
        await stream.ReadExactlyAsync(frame.AsMemory(HeaderSize), ct);
        return frame;
    }

    private static byte ComputeChecksum(ReadOnlySpan<byte> header)
    {
        byte checksum = 0;
        for (int i = 0; i < 5; i++) checksum ^= header[i];
        // Retail's transport parser complements the XOR checksum when the
        // transport type has any high-nibble flag (e.g. encrypted 0x10).
        return (header[0] & 0xF0) != 0 ? (byte)~checksum : checksum;
    }
}
