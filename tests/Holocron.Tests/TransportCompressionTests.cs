using System.Buffers.Binary;
using Holocron.Common.Crypto;
using Holocron.Common.Protocol;

namespace Holocron.Tests;

/// <summary>
/// Regression coverage for the transport payload codec. The first vector is a
/// real client payload captured from an isolated retail run, kept exactly as
/// captured so these tests cannot drift with the implementation.
/// </summary>
public class TransportCompressionTests
{
    // The 40-byte payload of a real client type-0x10 login request frame,
    // captured after Salsa20 decryption. Its transport header was
    // 10 2E 00 00 00 C1 (type byte 0x10, total length 46).
    private const string RetailRequestPayload =
        "00581C0100E8A7E609A6FFFFFFFF0F000000636173746C6568696C6C74657374000E0001006DC009";

    // What that payload decompresses to: a routed dispatch envelope carrying
    // message 0xA609E6A7 on the wildcard route pair, then a length-prefixed
    // 15-byte string ("castlehilltest" plus NUL) and two trailing fields.
    private const string RetailRequestLogical =
        "A7E609A6FFFFFFFF0F000000636173746C6568696C6C74657374000E0000000000000000000000";

    private static byte[] RetailPayload => Convert.FromHexString(RetailRequestPayload);
    private static byte[] RetailLogical => Convert.FromHexString(RetailRequestLogical);

    [Fact]
    public void RealClientRequestPayloadDecompressesToItsDispatchEnvelope()
    {
        using var decompressor = new TransportDecompressor();
        byte[] logical = decompressor.Decompress(RetailPayload);

        Assert.Equal(RetailLogical, logical);
        Assert.Equal(0xA609E6A7u, BinaryPrimitives.ReadUInt32LittleEndian(logical));
        Assert.Equal(0xFFFF, BinaryPrimitives.ReadUInt16LittleEndian(logical.AsSpan(4)));
        Assert.Equal(0xFFFF, BinaryPrimitives.ReadUInt16LittleEndian(logical.AsSpan(6)));
        Assert.Equal(15u, BinaryPrimitives.ReadUInt32LittleEndian(logical.AsSpan(8)));
        Assert.Equal("castlehilltest", System.Text.Encoding.UTF8.GetString(logical, 12, 14));
        Assert.Equal(0, logical[26]);
    }

    [Fact]
    public void RealClientRequestPayloadIsReproducedByteForByte()
    {
        using var compressor = new TransportCompressor();
        Assert.Equal(RetailPayload, compressor.Compress(RetailLogical));
    }

    [Fact]
    public void CompressedPayloadIsMagiclessAndFlushedButNotTerminated()
    {
        using var compressor = new TransportCompressor();
        byte[] payload = compressor.Compress(RetailLogical);

        Assert.Equal(0x00, payload[0]);  // frame header descriptor: streaming, no content size, no dictionary
        Assert.Equal(0x58, payload[1]);  // window descriptor: windowLog 21, the level-3 default
        int blockHeader = payload[2] | (payload[3] << 8) | (payload[4] << 16);
        Assert.Equal(0, blockHeader & 1);         // Last_Block = 0: the frame continues
        Assert.Equal(2, (blockHeader >> 1) & 3);  // compressed block
        Assert.Equal(payload.Length, 2 + 3 + (blockHeader >> 3));
        Assert.DoesNotContain("28B52FFD", Convert.ToHexString(payload));
    }

    [Fact]
    public void ConsecutiveMessagesFormOneContinuousCompressedStream()
    {
        byte[] first = RetailLogical;
        byte[] second = Convert.FromHexString("CD5CBAD4FFFFFFFF" + new string('5', 64));

        using var compressor = new TransportCompressor();
        byte[] firstPayload = compressor.Compress(first);
        byte[] secondPayload = compressor.Compress(second);
        Assert.Equal(0x00, firstPayload[0]);
        Assert.NotEqual(0x00, secondPayload[0]);

        using var decompressor = new TransportDecompressor();
        Assert.Equal(first, decompressor.Decompress(firstPayload));
        Assert.Equal(second, decompressor.Decompress(secondPayload));

        using var combined = new TransportDecompressor();
        Assert.Equal([.. first, .. second], combined.Decompress([.. firstPayload, .. secondPayload]));
    }

    [Fact]
    public void CorruptCompressedPayloadIsRejected()
    {
        // Magicless frame header with the reserved bit set.
        using var reserved = new TransportDecompressor();
        Assert.Throws<InvalidDataException>(
            () => reserved.Decompress(Convert.FromHexString("08587001000568656C6C6F")));

        // No plausible frame header at all.
        using var garbage = new TransportDecompressor();
        Assert.Throws<InvalidDataException>(
            () => garbage.Decompress(Convert.FromHexString("DEADBEEFCAFEBABE1234567890ABCDEF0011223344556677")));
    }

    [Fact]
    public async Task CodecCompressesApplicationFramesAndFlagsThem()
    {
        byte[] envelope = RetailLogical;

        using var wire = new MemoryStream();
        using (var codec = NewCodec(wire))
            await codec.WriteAsync(0, envelope);

        byte[] frame = Decode(wire.ToArray());

        // The exact wire form, including the complemented transport checksum.
        using var reference = new TransportCompressor();
        byte[] expected = TransportFrame.Encode(
            TransportFrame.CompressionFlag, reference.Compress(envelope));
        Assert.Equal(expected, frame);
        Assert.Equal("102E000000C1", Convert.ToHexString(frame.AsSpan(0, TransportFrame.HeaderSize)));
    }

    [Fact]
    public async Task ControlFramesAreNotCompressed()
    {
        byte[] requestPayload = [8, 7, 6, 5, 4, 3, 2, 1];
        byte[] responsePayload = TransportTimeSync.EncodeBaseResponsePayload(0x0102030405060708UL, 0x11223344u);

        using var wire = new MemoryStream();
        using (var codec = NewCodec(wire))
        {
            await codec.WriteAsync(TransportTimeSync.RequestType, requestPayload);
            await codec.WriteAsync(TransportTimeSync.ResponseType, responsePayload);
        }

        byte[] bytes = Decode(wire.ToArray());
        int secondOffset = TransportFrame.HeaderSize + requestPayload.Length;
        Assert.Equal(TransportTimeSync.RequestType, bytes[0]);
        Assert.Equal(TransportTimeSync.ResponseType, bytes[secondOffset]);
        Assert.Equal(0, bytes[0] & TransportFrame.CompressionFlag);
        Assert.Equal(0, bytes[secondOffset] & TransportFrame.CompressionFlag);
        Assert.Equal(TransportFrame.Encode(TransportTimeSync.RequestType, requestPayload), bytes[..(secondOffset)]);
        Assert.Equal(TransportFrame.Encode(TransportTimeSync.ResponseType, responsePayload), bytes[secondOffset..]);

        wire.Position = 0;
        using var reader = NewCodec(wire);
        TransportMessage? first = await reader.ReadAsync();
        TransportMessage? second = await reader.ReadAsync();
        Assert.NotNull(first);
        Assert.NotNull(second);
        Assert.Equal(TransportTimeSync.RequestType, first!.Value.Type);
        Assert.Equal(requestPayload, first.Value.Payload);
        Assert.Equal(TransportTimeSync.ResponseType, second!.Value.Type);
        Assert.Equal(responsePayload, second.Value.Payload);
        Assert.Null(await reader.ReadAsync());
    }

    [Fact]
    public async Task CipherAndCompressionStateSurviveConsecutiveFramesInBothDirections()
    {
        byte[] first = RetailLogical;
        byte[] second = Convert.FromHexString("CD5CBAD4FFFFFFFF000000000100000000");
        byte[] control = [1, 2, 3, 4, 5, 6, 7, 8];

        byte[] key = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
        byte[] iv = Enumerable.Range(0, 8).Select(i => (byte)i).ToArray();

        using var wire = new MemoryStream();
        using (var sender = new TransportCodec(wire, new Salsa20(key, iv), new Salsa20(key, iv)))
        {
            await sender.WriteAsync(0, first);
            await sender.WriteAsync(0, second);
            await sender.WriteAsync(TransportTimeSync.RequestType, control);
        }

        wire.Position = 0;
        using var receiver = new TransportCodec(wire, new Salsa20(key, iv), new Salsa20(key, iv));
        Assert.Equal(first, (await receiver.ReadAsync())!.Value.Payload);
        Assert.Equal(second, (await receiver.ReadAsync())!.Value.Payload);
        Assert.Equal(control, (await receiver.ReadAsync())!.Value.Payload);
        Assert.Null(await receiver.ReadAsync());
    }

    private static readonly byte[] Key = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
    private static readonly byte[] Iv = Enumerable.Range(0, 8).Select(i => (byte)i).ToArray();

    private static TransportCodec NewCodec(Stream stream)
        => new(stream, new Salsa20(Key, Iv), new Salsa20(Key, Iv));

    /// <summary>Recovers the plaintext transport bytes the codec wrote.</summary>
    private static byte[] Decode(byte[] cipherText)
    {
        byte[] plain = new byte[cipherText.Length];
        new Salsa20(Key, Iv).Process(cipherText, plain);
        return plain;
    }
}
