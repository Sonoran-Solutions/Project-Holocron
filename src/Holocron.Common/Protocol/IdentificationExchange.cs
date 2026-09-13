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
    /// <summary>Decoded <c>IntroduceConnectionSignature</c> body.</summary>
    public readonly record struct IntroduceConnection(
        ushort ClientObjectId, ushort ReplyRouteWord, string Name, string ClassName, string Interfaces, ulong Value)
    {
        /// <summary>
        /// The route pair a server-to-client routed message must carry once this
        /// handshake completes. Both directions derive their key from the same
        /// two words with the roles swapped: the receiver registers
        /// <c>(localWord, resolvedPeerWord)</c> while the sender addresses
        /// <c>(peerWord, localWord)</c>.
        /// </summary>
        public (ushort First, ushort Second) PeerEnvelopeRoute => (ReplyRouteWord, ClientObjectId);
    }

    /// <summary><c>RequestIDIFace::RequestIDSignature</c>, sent by the client.</summary>
    public const uint RequestIdSignature = 0xA609E6A7;

    /// <summary><c>ReplyIDIFace::ReplyIDSignature</c>, sent by the server.</summary>
    public const uint ReplyIdSignature = 0x6731C5AF;

    /// <summary><c>RequestIDIFace::IntroduceConnectionSignature</c>, sent by the client.</summary>
    public const uint IntroduceConnectionSignature = 0x8B0D492F;

    /// <summary>
    /// <c>Close</c>. Registered in the same global block as the identification
    /// messages (name string at <c>0x14157E740</c>) and dispatched at
    /// <c>0x14042BABC</c> to <c>0x1404123D0(connection, 1, 0)</c>. The retail
    /// client sends this immediately after
    /// <see cref="IntroduceConnectionSignature"/>, tearing down the bootstrap
    /// connection, so it is the boundary in front of any routed delivery.
    /// </summary>
    public const uint Close = 0x43DB3479;

    /// <summary>
    /// <c>RequestClose</c>, dispatched at <c>0x14042BACC</c> to
    /// <c>0x1404123D0(connection, 0, 0)</c>. It has no serializer in the
    /// executable, so the client never sends it: it is a server-to-client
    /// message only.
    /// </summary>
    public const uint RequestClose = 0x0598D9A7;

    /// <summary>
    /// Reads the two route words a <see cref="Close"/> frame carries. The
    /// producer <c>0x1404123D0</c> writes the sending connection's own object
    /// id (<c>Connection + 0x28</c>) first and its peer word
    /// (<c>Connection + 0x60</c>) second, at <c>0x140412594</c> and
    /// <c>0x1404125A2</c> - the sender's order, which is the reverse of the
    /// receive-tree key order.
    /// </summary>
    public static (ushort OwnObjectId, ushort PeerWord) ReadClose(ReadOnlySpan<byte> body)
    {
        if (body.Length < 2 * sizeof(ushort))
            throw new InvalidDataException("Truncated close payload.");
        return (BinaryPrimitives.ReadUInt16LittleEndian(body),
                BinaryPrimitives.ReadUInt16LittleEndian(body[sizeof(ushort)..]));
    }

    /// <summary>The route word pair the client uses for its global requests, and
    /// the value the reply's body word must NOT carry.</summary>
    public const ushort WildcardRouteWord = 0xFFFF;

    /// <summary>
    /// Sentinel meaning "no object assigned" in the reply's body word. The
    /// client compares the reply word against this value at <c>0x14042C50A</c>;
    /// on equality it performs a connection state transition
    /// (<c>0x1404123D0(connection, 2, 3)</c>) and returns without introducing
    /// the connection. Only a reply word that is <b>not</b> this sentinel
    /// reaches the sole producer of <c>IntroduceConnectionSignature</c>.
    /// </summary>
    public const ushort UnassignedObjectSentinel = 0xFFFF;

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
    /// The client's IntroduceConnection body, in the order its serializer
    /// <c>0x14045B620</c> writes it: u16, u16, three length-prefixed strings,
    /// then eight bytes. The first word is the client's own object id (the
    /// pending record's <c>+0x28</c>); the second is the reply's body word
    /// (<c>0x14042C6A5</c> reads it straight back out of <c>[rsp+0x40]</c>).
    /// </summary>
    public static IntroduceConnection ReadIntroduceConnection(ReadOnlySpan<byte> body)
    {
        if (body.Length < 2 * sizeof(ushort))
            throw new InvalidDataException("Truncated introduce-connection payload.");
        ushort first = BinaryPrimitives.ReadUInt16LittleEndian(body);
        ushort second = BinaryPrimitives.ReadUInt16LittleEndian(body[sizeof(ushort)..]);
        int offset = 2 * sizeof(ushort);
        string name = ReadString(body, ref offset);
        string className = ReadString(body, ref offset);
        string interfaces = ReadString(body, ref offset);
        if (body.Length - offset < sizeof(ulong))
            throw new InvalidDataException("Truncated introduce-connection payload.");
        ulong value = BinaryPrimitives.ReadUInt64LittleEndian(body[offset..]);
        return new IntroduceConnection(first, second, name, className, interfaces, value);
    }

    /// <summary>Builds an IntroduceConnection body with the recovered field order.</summary>
    public static byte[] EncodeIntroduceConnection(
        ushort first, ushort second, string name, string className, string interfaces, ulong value)
    {
        using var buffer = new MemoryStream();
        Span<byte> words = stackalloc byte[2 * sizeof(ushort)];
        BinaryPrimitives.WriteUInt16LittleEndian(words, first);
        BinaryPrimitives.WriteUInt16LittleEndian(words[sizeof(ushort)..], second);
        buffer.Write(words);
        buffer.Write(EncodeString(name));
        buffer.Write(EncodeString(className));
        buffer.Write(EncodeString(interfaces));
        Span<byte> tail = stackalloc byte[sizeof(ulong)];
        BinaryPrimitives.WriteUInt64LittleEndian(tail, value);
        buffer.Write(tail);
        return buffer.ToArray();
    }
}
