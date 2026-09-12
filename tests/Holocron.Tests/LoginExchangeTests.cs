using System.Security.Cryptography;
using System.Text;
using System.Buffers.Binary;
using Holocron.Common.Crypto;
using Holocron.Common.Protocol;
using Holocron.Auth;
using System.Net;
using System.Net.Sockets;
using System.Xml.Linq;

namespace Holocron.Tests;

public class LoginExchangeTests
{
    [Fact]
    public async Task ProbePreservesD4ConfigurationAndEncryptedTimeSyncContract()
    {
        // Synthetic peer only: this verifies the actual server wire output, not
        // acceptance of the XML or launch reply by the retail client.
        using RSA rsa = RSA.Create(2048);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var server = new AuthServer(0, testKey: rsa, handshakeOnly: true,
            probeLoginReplyEnvelope: true);
        Task serverTask = server.StartAsync(cancellation.Token);
        try
        {
            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, server.Port, cancellation.Token);
            var network = client.GetStream();
            Assert.NotNull(await TransportFrame.ReadAsync(network, cancellation.Token));

            byte[] clear = new byte[88];
            for (int i = 8; i < clear.Length; i++) clear[i] = (byte)i;
            await network.WriteAsync(Encode(clear, rsa), cancellation.Token);
            using var encrypted = new Salsa20Stream(network,
                new Salsa20(clear[8..40], clear[72..80]),
                new Salsa20(clear[40..72], clear[80..88]));
            byte[] request = TransportFrame.Encode(0x10,
                Convert.FromHexString("00581C0100E8A7E6"));
            await encrypted.WriteAsync(request, cancellation.Token);
            byte[] reply = (await TransportFrame.ReadAsync(encrypted, cancellation.Token))!;
            Assert.Equal(0x10, reply[0]);
            Assert.Equal("CD5CBAD4A7E600E8", Convert.ToHexString(reply.AsSpan(6, 8)));
            Assert.Equal(0u, BinaryPrimitives.ReadUInt32LittleEndian(reply.AsSpan(14)));
            int stringBytes = BinaryPrimitives.ReadInt32LittleEndian(reply.AsSpan(18));
            Assert.Equal(reply.Length - 22, stringBytes);
            Assert.Equal(0, reply[^1]);
            Assert.DoesNotContain((byte)0, reply[22..^1]);
            string xml = new UTF8Encoding(false, true).GetString(reply[22..^1]);
            var root = XElement.Parse(xml);
            Assert.Equal("client", root.Name.LocalName);
            Assert.Equal("Test Client", (string?)root.Attribute("title"));
            Assert.Equal("true", (string?)root.Attribute("useSyncClock"));
            Assert.Equal("debug", (string?)root.Attribute("loglevel"));
            Assert.Equal("username=local-test;WorldName=he1012;SHARD_PUBLIC_NAME=he1012;", (string?)root.Attribute("additionalClientConfigs"));
            var rule = Assert.Single(root.Element("access-rights")!.Elements("client"));
            Assert.Equal("Automaton.exe", (string?)rule.Attribute("name"));
            var subnet = Assert.Single(rule.Elements("network"));
            Assert.Equal("BWA", (string?)subnet.Attribute("name"));
            Assert.Equal("10.2.0.0/15", (string?)subnet.Attribute("address"));

            byte[] launch = (await TransportFrame.ReadAsync(encrypted, cancellation.Token))!;
            Assert.Equal(0x10, launch[0]);
            Assert.Equal("4DD0F290A7E600E8", Convert.ToHexString(launch.AsSpan(6, 8)));

            uint before = unchecked((uint)(DateTime.UtcNow.ToFileTimeUtc() / 10000));
            byte[] sequence = Convert.FromHexString("0807060504030201");
            await encrypted.WriteAsync(TransportFrame.Encode(1, sequence), cancellation.Token);
            byte[] sync = (await TransportFrame.ReadAsync(encrypted, cancellation.Token))!;
            Assert.Equal("021300000011", Convert.ToHexString(sync.AsSpan(0, 6)));
            Assert.Equal(sequence, sync[6..14]);
            Assert.Equal(1, sync[14]);
            uint clock = BinaryPrimitives.ReadUInt32LittleEndian(sync.AsSpan(15));
            // Modular subtraction handles the low-32-bit clock wrapping. Allow
            // scheduling and millisecond quantization without accepting epoch zero.
            Assert.InRange(unchecked((int)(clock - before)), -1000, 10000);
        }
        finally
        {
            cancellation.Cancel();
            await serverTask;
        }
    }

    [Fact]
    public void LocalKeyPairExtractsKeysAndRejectsDifferentKey()
    {
        using RSA rsa = RSA.Create(2048);
        byte[] clear = new byte[88]; // two empty length-prefixed strings + 80 key bytes
        for (int i = 8; i < clear.Length; i++) clear[i] = (byte)i;
        byte[] frame = Encode(clear, rsa);
        var keys = SwtorLoginKeyExchange.Decode(frame, rsa);
        Assert.Equal(clear[8..40], keys.ServerToClientKey);
        Assert.Equal(clear[40..72], keys.ClientToServerKey);
        Assert.Equal(clear[72..80], keys.ServerToClientIv);
        Assert.Equal(clear[80..88], keys.ClientToServerIv);
        using RSA other = RSA.Create(2048);
        Assert.ThrowsAny<CryptographicException>(() => SwtorLoginKeyExchange.Decode(frame, other));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(200)]
    [InlineData(500)]
    public void ParsesAcrossZeroPaddedRsaBlocks(int identifierLength)
    {
        using RSA rsa = RSA.Create(2048);
        byte[] clear = new byte[88 + identifierLength];
        BinaryPrimitives.WriteInt32LittleEndian(clear, identifierLength);
        clear.AsSpan(8 + identifierLength, 80).Fill(42);
        var keys = SwtorLoginKeyExchange.Decode(Encode(clear, rsa), rsa);
        Assert.All(keys.ServerToClientKey, b => Assert.Equal((byte)42, b));
        Assert.All(keys.ClientToServerIv, b => Assert.Equal((byte)42, b));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(7)]
    [InlineData(87)]
    [InlineData(246)]
    [InlineData(-1)]
    public void RejectsInvalidDeclaredPlaintextLength(int length)
    {
        using RSA rsa = RSA.Create(2048);
        byte[] frame = Encode(new byte[88], rsa);
        BinaryPrimitives.WriteInt32LittleEndian(frame.AsSpan(6, 4), length);
        Assert.Throws<InvalidDataException>(() => SwtorLoginKeyExchange.Decode(frame, rsa));
    }

    private static byte[] Encode(byte[] clear, RSA rsa)
    {
        using var encrypted = new MemoryStream();
        for (int offset = 0; offset < clear.Length; offset += 245)
        {
            byte[] block = new byte[245];
            clear.AsSpan(offset, Math.Min(245, clear.Length - offset)).CopyTo(block);
            encrypted.Write(rsa.Encrypt(block, RSAEncryptionPadding.Pkcs1));
        }
        byte[] payload = new byte[4 + encrypted.Length * 2];
        BinaryPrimitives.WriteInt32LittleEndian(payload, clear.Length);
        Encoding.ASCII.GetBytes(Convert.ToHexString(encrypted.ToArray())).CopyTo(payload, 4);
        return TransportFrame.Encode(4, payload);
    }
}
