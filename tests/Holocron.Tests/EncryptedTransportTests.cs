using Holocron.Common.Crypto;
using Holocron.Common.Protocol;

namespace Holocron.Tests;

public class EncryptedTransportTests
{
    [Fact]
    public async Task EncryptedType10EnvelopeRoundTripsWithOnlyItsDispatchFields()
    {
        byte[] key = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
        byte[] iv = new byte[8];
        byte[] envelope = [0x00, 0x58, 0x1C, 0x01, 0x34, 0x12, 0x78, 0x56];
        byte[] frame = TransportFrame.Encode(0x10, envelope);

        using var wire = new MemoryStream();
        using (var output = new Salsa20Stream(wire, new Salsa20(key, iv), new Salsa20(key, iv)))
            await output.WriteAsync(frame);

        wire.Position = 0;
        using var input = new Salsa20Stream(wire, new Salsa20(key, iv), new Salsa20(key, iv));
        Assert.Equal(frame, await TransportFrame.ReadAsync(input));
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
