using System.Buffers.Binary;

namespace Holocron.Common.Protocol;

/// <summary>
/// Framing for the transport-level time-synchronization exchange. These frames
/// are carried inside the established encrypted byte stream, but are not routed
/// application messages.
/// </summary>
public static class TransportTimeSync
{
    public const byte RequestType = 0x01;
    public const byte ResponseType = 0x02;
    public const int RequestPayloadSize = sizeof(ulong);
    public const int BaseResponsePayloadSize = sizeof(ulong) + sizeof(byte) + sizeof(uint);

    /// <summary>Reads the sole little-endian sequence field from a validated frame.</summary>
    public static ulong ReadRequestSequence(ReadOnlySpan<byte> frame)
    {
        if (frame.Length != TransportFrame.HeaderSize + RequestPayloadSize ||
            frame[0] != RequestType ||
            BinaryPrimitives.ReadInt32LittleEndian(frame[1..]) != frame.Length)
        {
            throw new InvalidDataException("Expected a 14-byte type-0x01 transport time request.");
        }

        return BinaryPrimitives.ReadUInt64LittleEndian(frame[TransportFrame.HeaderSize..]);
    }

    /// <summary>
    /// Encodes the canonical base-only response. Count one denotes the local
    /// clock record; optional relayed clock records follow as pairs of u32.
    /// </summary>
    public static byte[] EncodeBaseResponse(ulong sequence, uint localTimeMilliseconds)
    {
        Span<byte> payload = stackalloc byte[BaseResponsePayloadSize];
        BinaryPrimitives.WriteUInt64LittleEndian(payload, sequence);
        payload[sizeof(ulong)] = 1;
        BinaryPrimitives.WriteUInt32LittleEndian(payload[(sizeof(ulong) + sizeof(byte))..], localTimeMilliseconds);
        return TransportFrame.Encode(ResponseType, payload);
    }
}
