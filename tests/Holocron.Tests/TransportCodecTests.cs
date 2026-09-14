using Holocron.Common.Crypto;
using Holocron.Common.Protocol;

namespace Holocron.Tests;

/// <summary>
/// Transport codec provenance: the payload vectors are REAL captured client
/// bytes (a fixed retail vector), and the 0x10 bit they exercise is the
/// Zstandard COMPRESSION flag -- not an encryption class. Salsa20 is session
/// state established by the RSA exchange, not a per-frame property.
/// </summary>
public class TransportCodecTests
{
    [Fact]
    public async Task CompressedRoutedEnvelopeRoundTripsAndDecompressesToItsDispatchFields()
    {
        byte[] key = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
        byte[] iv = new byte[8];
        // A real captured client logical envelope: message 0xA609E6A7,
        // wildcard route pair, a length-prefixed string and two trailing fields.
        // It exceeds the retail 0x20-byte threshold, so the transport compresses
        // it and sets bit 0x10 -- the Zstandard flag, NOT an encryption class.
        byte[] envelope = Convert.FromHexString(
            "A7E609A6FFFFFFFF0F000000636173746C6568696C6C74657374000E0000000000000000000000");

        using var wire = new MemoryStream();
        using (var output = new TransportCodec(wire, new Salsa20(key, iv), new Salsa20(key, iv)))
            await output.WriteAsync(0, envelope);

        byte[] rawFrame = new byte[wire.Length];
        new Salsa20(key, iv).Process(wire.ToArray(), rawFrame);
        Assert.Equal(TransportFrame.CompressionFlag, rawFrame[0] & TransportFrame.CompressionFlag);
        Assert.NotEqual(envelope, rawFrame[TransportFrame.HeaderSize..]);

        wire.Position = 0;
        using var input = new TransportCodec(wire, new Salsa20(key, iv), new Salsa20(key, iv));
        TransportMessage? decoded = await input.ReadAsync();
        Assert.NotNull(decoded);
        Assert.Equal(0, decoded!.Value.Type);
        Assert.Equal(envelope, decoded.Value.Payload);
        Assert.Null(await input.ReadAsync());
    }

    [Fact]
    public async Task SmallRoutedEnvelopeIsSentUncompressed()
    {
        byte[] key = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
        byte[] iv = new byte[8];
        // Below the retail compression threshold the transport keeps a routed
        // application payload raw and leaves bit 0x10 clear.
        byte[] envelope = [0x00, 0x58, 0x1C, 0x01, 0x34, 0x12, 0x78, 0x56];

        using var wire = new MemoryStream();
        using (var output = new TransportCodec(wire, new Salsa20(key, iv), new Salsa20(key, iv)))
            await output.WriteAsync(0, envelope);

        byte[] rawFrame = new byte[wire.Length];
        new Salsa20(key, iv).Process(wire.ToArray(), rawFrame);
        Assert.Equal(0, rawFrame[0]);

        wire.Position = 0;
        using var input = new TransportCodec(wire, new Salsa20(key, iv), new Salsa20(key, iv));
        TransportMessage? decoded = await input.ReadAsync();
        Assert.NotNull(decoded);
        Assert.Equal(0, decoded!.Value.Type);
        Assert.Equal(envelope, decoded.Value.Payload);
    }

    [Fact]
    public async Task CipherStateSurvivesDifferentWriteAndReadBoundaries()
    {
        byte[] key = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
        byte[] iv = new byte[8];
        byte[] first = TransportFrame.Encode(0, new byte[131]);
        byte[] second = TransportFrame.Encode(1, new byte[8]);
        byte[] plain = [.. first, .. second];
        using var wire = new MemoryStream();
        using var output = new Salsa20Stream(wire, new Salsa20(key, iv), new Salsa20(key, iv));
        await output.WriteAsync(plain.AsMemory(0, 3));
        await output.WriteAsync(plain.AsMemory(3));
        Assert.False(plain.SequenceEqual(wire.ToArray()));
        wire.Position = 0;
        using var input = new Salsa20Stream(wire, new Salsa20(key, iv), new Salsa20(key, iv));
        Assert.Equal(first, await TransportFrame.ReadAsync(input));
        Assert.Equal(second, await TransportFrame.ReadAsync(input));
        Assert.Null(await TransportFrame.ReadAsync(input));
    }
}
