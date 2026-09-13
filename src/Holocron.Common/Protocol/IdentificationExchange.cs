using System.Buffers.Binary;
using System.Text;

namespace Holocron.Common.Protocol;

/// <summary>
/// The global identification exchange that a retail client performs immediately
/// after the key exchange, before any routed application traffic is valid.
///
/// The three message ids are global: the receiver consumes them out of the
/// global dispatcher at <c>0x14042B990</c> instead of resolving a routed
/// endpoint, and the client sends them on the <c>0xFFFF</c>/<c>0xFFFF</c>
/// wildcard route. Their semantic names are registered in the client binary:
///
/// <code>
/// 0xA609E6A7  RequestIDIFace::RequestIDSignature           (client -> server)
/// 0x6731C5AF  ReplyIDIFace::ReplyIDSignature               (server -> client)
/// 0x8B0D492F  RequestIDIFace::IntroduceConnectionSignature (client -> server)
/// </code>
///
/// Pairing evidence, not inference: the only producer of
/// <c>ReplyIDSignature</c> in the binary is the handler for an incoming
/// <c>RequestIDSignature</c> (<c>0x14042BCA0</c> calls <c>0x14045BCD0</c> at
/// five sites), and the only producer of <c>IntroduceConnectionSignature</c>
/// is the handler for an incoming <c>ReplyIDSignature</c> (<c>0x14042C300</c>
/// calls <c>0x14045B620</c> at <c>0x14042C6B7</c>).
/// </summary>
public static class IdentificationExchange
{
    /// <summary><c>RequestIDIFace::RequestIDSignature</c>, sent by the client.</summary>
    public const uint RequestIdSignature = 0xA609E6A7;

    /// <summary><c>ReplyIDIFace::ReplyIDSignature</c>, sent by the server.</summary>
    public const uint ReplyIdSignature = 0x6731C5AF;

    /// <summary><c>RequestIDIFace::IntroduceConnectionSignature</c>, sent by the client.</summary>
    public const uint IntroduceConnectionSignature = 0x8B0D492F;

    /// <summary>The route word pair the client uses for its global requests.</summary>
    public const ushort WildcardRouteWord = 0xFFFF;

    /// <summary>Encodes a length-prefixed string: u32 byte count including the
    /// terminal NUL, the bytes, then the NUL. Minimum encoding is <c>01 00 00 00 00</c>.</summary>
    public static byte[] EncodeString(string value)
    {
        byte[] utf8 = Encoding.UTF8.GetBytes(value);
        byte[] encoded = new byte[sizeof(uint) + utf8.Length + 1];
        BinaryPrimitives.WriteUInt32LittleEndian(encoded, (uint)(utf8.Length + 1));
        utf8.CopyTo(encoded.AsSpan(sizeof(uint)));
        return encoded;
    }

    /// <summary>Parses one length-prefixed string, advancing <paramref name="offset"/>.</summary>
    public static string ReadString(ReadOnlySpan<byte> body, ref int offset)
    {
        if (body.Length - offset < sizeof(uint))
            throw new InvalidDataException("Truncated encoded string length.");
        int length = BinaryPrimitives.ReadInt32LittleEndian(body[offset..]);
        offset += sizeof(uint);
        if (length <= 0 || body.Length - offset < length)
            throw new InvalidDataException("Invalid encoded string length.");
        if (body[offset + length - 1] != 0)
            throw new InvalidDataException("Encoded string is not NUL terminated.");
        string value = Encoding.UTF8.GetString(body.Slice(offset, length - 1));
        offset += length;
        return value;
    }

    /// <summary>
    /// The client's request body, recovered from a real frame: a
    /// length-prefixed shard name followed by an eight-byte correlation value.
    /// The client's own serializer echoes that value into the reply.
    /// </summary>
    public static (string Name, ulong Correlation) ReadRequestIdSignature(ReadOnlySpan<byte> body)
    {
        int offset = 0;
        string name = ReadString(body, ref offset);
        if (body.Length - offset < sizeof(ulong))
            throw new InvalidDataException("Truncated request-id signature payload.");
        ulong correlation = BinaryPrimitives.ReadUInt64LittleEndian(body[offset..]);
        return (name, correlation);
    }

    /// <summary>
    /// Builds the reply body in the exact order the client's parser consumes:
    /// u16 route word, three length-prefixed strings, then eight bytes. The
    /// client reads the u16 first (<c>0x14042C376</c>), then three strings
    /// (<c>0x14042C3AC</c>, <c>0x14042C3C2</c>, <c>0x14042C3D8</c>), requires
    /// eight more bytes (<c>0x14042C3E5</c>) and requires complete consumption
    /// (<c>0x14042C423</c>).
    /// </summary>
    public static byte[] EncodeReplyIdSignature(
        ushort routeWord, string name, string className, string interfaces, ulong correlation)
    {
        using var buffer = new MemoryStream();
        Span<byte> word = stackalloc byte[sizeof(ushort)];
        BinaryPrimitives.WriteUInt16LittleEndian(word, routeWord);
        buffer.Write(word);
        buffer.Write(EncodeString(name));
        buffer.Write(EncodeString(className));
        buffer.Write(EncodeString(interfaces));
        Span<byte> id = stackalloc byte[sizeof(ulong)];
        BinaryPrimitives.WriteUInt64LittleEndian(id, correlation);
        buffer.Write(id);
        return buffer.ToArray();
    }

    /// <summary>
    /// The client's IntroduceConnection body. The producer supplies two 16-bit
    /// route words (client <c>0x14042C6A5</c>/<c>0x14042C6AB</c>); this reads a
    /// conservative leading pair and leaves additional fields to the caller.
    /// </summary>
    public static (ushort First, ushort Second) ReadIntroduceConnection(ReadOnlySpan<byte> body)
    {
        if (body.Length < 2 * sizeof(ushort))
            throw new InvalidDataException("Truncated introduce-connection payload.");
        return (BinaryPrimitives.ReadUInt16LittleEndian(body),
                BinaryPrimitives.ReadUInt16LittleEndian(body[sizeof(ushort)..]));
    }
}
