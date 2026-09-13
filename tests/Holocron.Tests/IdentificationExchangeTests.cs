using System.Buffers.Binary;
using Holocron.Common.Protocol;

namespace Holocron.Tests;

/// <summary>
/// Locks the global identification-exchange encodings to the field order the
/// retail client's own parser consumes.
/// </summary>
public class IdentificationExchangeTests
{
    // Recovered from a real client frame: RequestIDSignature carrying the shard
    // name and an eight-byte correlation value.
    private const string RealRequestBody =
        "0F000000636173746C6568696C6C74657374000E00000000000000";

    [Fact]
    public void RealClientRequestBodyParsesAsNameAndCorrelation()
    {
        (string name, ulong correlation) =
            IdentificationExchange.ReadRequestIdSignature(Convert.FromHexString(RealRequestBody));

        Assert.Equal("castlehilltest", name);
        Assert.Equal(14UL, correlation);
    }

    [Fact]
    public void RealLogicalPayloadParsesAfterTheEightByteDispatchEnvelope()
    {
        // The full 39-byte logical payload of the captured client frame:
        // u32 message, u16 route word, u16 route word, then the body. The body
        // starts at offset 8 - not at offset 4.
        byte[] logical = Convert.FromHexString(
            "A7E609A6FFFFFFFF0F000000636173746C6568696C6C74657374000E0000000000000000000000");
        Assert.Equal(0xA609E6A7u, System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(logical));
        Assert.Equal(0xFFFF, System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(logical.AsSpan(4)));
        Assert.Equal(0xFFFF, System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(logical.AsSpan(6)));

        (string name, ulong correlation) =
            IdentificationExchange.ReadRequestIdSignature(logical.AsSpan(8));
        Assert.Equal("castlehilltest", name);
        Assert.Equal(14UL, correlation);
    }

    [Fact]
    public void ReplyBodyMatchesTheClientParsersFieldOrder()
    {
        byte[] body = IdentificationExchange.EncodeReplyIdSignature(
            IdentificationExchange.WildcardRouteWord, "castlehilltest", "castlehilltest", "castlehilltest", 14);

        // Independent walk of the client's parse order:
        // u16, string, string, string, u64, then end of body.
        int offset = 0;
        Assert.Equal(0xFFFF, BinaryPrimitives.ReadUInt16LittleEndian(body));
        offset += sizeof(ushort);
        Assert.Equal("castlehilltest", ReadEncodedString(body, ref offset));
        Assert.Equal("castlehilltest", ReadEncodedString(body, ref offset));
        Assert.Equal("castlehilltest", ReadEncodedString(body, ref offset));
        Assert.Equal(14UL, BinaryPrimitives.ReadUInt64LittleEndian(body[offset..]));
        offset += sizeof(ulong);
        Assert.Equal(body.Length, offset);
    }

    [Fact]
    public void EncodedStringsAreLengthPrefixedIncludingTheTerminalNul()
    {
        Assert.Equal("0100000000", Convert.ToHexString(IdentificationExchange.EncodeString(string.Empty)));
        Assert.Equal("03000000686900", Convert.ToHexString(IdentificationExchange.EncodeString("hi")));

        int offset = 0;
        byte[] body = IdentificationExchange.EncodeString("hi");
        Assert.Equal("hi", ReadEncodedString(body, ref offset));
        Assert.Equal(body.Length, offset);
    }

    [Fact]
    public void MalformedEncodedStringsAreRejected()
    {
        // Declared length runs past the body.
        Assert.Throws<InvalidDataException>(() => Parse("08000000686900"));
        // Declared length present but the last byte is not a NUL.
        Assert.Throws<InvalidDataException>(() => Parse("03000000686921"));
        // Zero declared length.
        Assert.Throws<InvalidDataException>(() => Parse("00000000"));
    }

    private static string Parse(string hex)
    {
        int offset = 0;
        return IdentificationExchange.ReadString(Convert.FromHexString(hex), ref offset);
    }

    private static string ReadEncodedString(ReadOnlySpan<byte> body, ref int offset)
        => IdentificationExchange.ReadString(body, ref offset);
}
