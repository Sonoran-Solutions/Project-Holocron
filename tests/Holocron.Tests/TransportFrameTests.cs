using Holocron.Common.Protocol;

namespace Holocron.Tests;

public class TransportFrameTests
{
    [Fact]
    public void EncryptedTransportTypeUsesComplementedChecksum()
    {
        byte[] frame = TransportFrame.Encode(0x10, new byte[40]);
        Assert.Equal("102E000000C1", Convert.ToHexString(frame.AsSpan(0, TransportFrame.HeaderSize)));
    }

    [Fact]
    public async Task FragmentedAndCoalescedFramesRemainSeparate()
    {
        byte[] greeting = Convert.FromHexString("030E0000000D1200000000000000");
        using var stream = new FragmentedStream([.. greeting, .. greeting]);
        Assert.Equal(greeting, await TransportFrame.ReadAsync(stream));
        Assert.Equal(greeting, await TransportFrame.ReadAsync(stream));
        Assert.Null(await TransportFrame.ReadAsync(stream));
    }

    [Theory]
    [InlineData("030E00000000")]
    [InlineData("030500000006")]
    [InlineData("03FFFFFF7F83")]
    public async Task InvalidHeadersAreRejected(string hex)
    {
        using var stream = new MemoryStream(Convert.FromHexString(hex));
        await Assert.ThrowsAsync<InvalidDataException>(() => TransportFrame.ReadAsync(stream));
    }

    [Fact]
    public async Task PartialFrameIsNotCleanEof()
    {
        using var stream = new MemoryStream(Convert.FromHexString("030E0000000D12"));
        await Assert.ThrowsAsync<EndOfStreamException>(() => TransportFrame.ReadAsync(stream));
    }

    [Fact]
    public void TimeRequestContainsOnlyLittleEndianSequence()
    {
        byte[] request = TransportFrame.Encode(TransportTimeSync.RequestType,
            Convert.FromHexString("0807060504030201"));

        Assert.Equal("010E0000000F0807060504030201", Convert.ToHexString(request));
        Assert.Equal(0x0102030405060708UL, TransportTimeSync.ReadRequestSequence(request));
        Assert.Throws<InvalidDataException>(() => TransportTimeSync.ReadRequestSequence([.. request, 0]));
    }

    [Fact]
    public void BaseTimeResponseEchoesSequenceAndOneLocalClockRecord()
    {
        byte[] response = TransportTimeSync.EncodeBaseResponse(1, 0x11223344);

        Assert.Equal("02130000001101000000000000000144332211", Convert.ToHexString(response));
    }

    private sealed class FragmentedStream(byte[] bytes) : MemoryStream(bytes)
    {
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
            => base.ReadAsync(buffer[..Math.Min(1, buffer.Length)], ct);
    }
}
