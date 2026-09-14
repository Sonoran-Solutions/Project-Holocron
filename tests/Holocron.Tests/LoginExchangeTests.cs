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
    /// <summary>
    /// HISTORICAL EXPERIMENT — NOT RETAIL SEQUENCING.
    ///
    /// This test exercises the <c>--historical-invalid-direct-login-probe</c>
    /// mode, which answers the client's first global message
    /// (<c>0xA609E6A7 RequestIDSignature</c>) directly with D4
    /// (<c>0xD4BA5CCD</c>). That is <b>not</b> valid retail sequencing: the
    /// proven reply to <c>0xA609E6A7</c> is <c>0x6731C5AF ReplyIDSignature</c>,
    /// after which the client sends <c>0x8B0D492F
    /// IntroduceConnectionSignature</c>.
    ///
    /// What it <i>does</i> prove, against a synthetic peer: the exact byte shape
    /// of the D4 initialization document, the immediate game-launch reply, and
    /// the transport time-sync contract. It proves nothing about whether a
    /// retail client accepts them, and nothing about message ordering.
    /// </summary>
    [Fact]
    public async Task HistoricalInvalidDirectLoginProbe_EmitsD4EnvelopeShapeAndTimeSyncContract()
    {
        using RSA rsa = RSA.Create(2048);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var server = new AuthServer(0, testKey: rsa, handshakeOnly: true,
            historicalInvalidDirectLoginProbe: true);
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
            using var codec = new TransportCodec(network,
                new Salsa20(clear[8..40], clear[72..80]),
                new Salsa20(clear[40..72], clear[80..88]));
            // A real captured client envelope: 0xA609E6A7 on the wildcard
            // route pair. In retail this is RequestIDSignature and is answered
            // by ReplyIDSignature -- this probe answers it with D4 instead,
            // which is the historical (invalid) behaviour under test here.
            await codec.WriteAsync(0, Convert.FromHexString("A7E609A6FFFFFFFF0F000000636173746C6568696C6C74657374000E0000000000000000000000"), cancellation.Token);
            TransportMessage? replyOrNull = await codec.ReadAsync(cancellation.Token);
            Assert.NotNull(replyOrNull);
            TransportMessage reply = replyOrNull!.Value;
            Assert.Equal(0, reply.Type);
            Assert.Equal(0xD4BA5CCDu, BinaryPrimitives.ReadUInt32LittleEndian(reply.Payload));
            Assert.Equal(0xFFFF, BinaryPrimitives.ReadUInt16LittleEndian(reply.Payload.AsSpan(4)));
            Assert.Equal(0xFFFF, BinaryPrimitives.ReadUInt16LittleEndian(reply.Payload.AsSpan(6)));
            Assert.Equal(0u, BinaryPrimitives.ReadUInt32LittleEndian(reply.Payload.AsSpan(8)));
            int stringBytes = BinaryPrimitives.ReadInt32LittleEndian(reply.Payload.AsSpan(12));
            Assert.Equal(reply.Payload.Length - 16, stringBytes);
            Assert.Equal(0, reply.Payload[^1]);
            Assert.DoesNotContain((byte)0, reply.Payload[16..^1]);
            string xml = new UTF8Encoding(false, true).GetString(reply.Payload[16..^1]);
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

            TransportMessage? launchOrNull = await codec.ReadAsync(cancellation.Token);
            Assert.NotNull(launchOrNull);
            TransportMessage launch = launchOrNull!.Value;
            Assert.Equal(0, launch.Type);
            Assert.Equal(0x90F2D04Du, BinaryPrimitives.ReadUInt32LittleEndian(launch.Payload));
            Assert.Equal(0xFFFF, BinaryPrimitives.ReadUInt16LittleEndian(launch.Payload.AsSpan(4)));
            Assert.Equal(0xFFFF, BinaryPrimitives.ReadUInt16LittleEndian(launch.Payload.AsSpan(6)));
            int addressBytes = BinaryPrimitives.ReadInt32LittleEndian(launch.Payload.AsSpan(8));
            Assert.Equal("127.0.0.1:20061", Encoding.UTF8.GetString(launch.Payload, 12, addressBytes - 1));
            Assert.Equal(0, launch.Payload[12 + addressBytes - 1]);

            uint before = unchecked((uint)(DateTime.UtcNow.ToFileTimeUtc() / 10000));
            byte[] sequence = Convert.FromHexString("0807060504030201");
            await codec.WriteAsync(TransportTimeSync.RequestType, sequence, cancellation.Token);
            TransportMessage? syncOrNull = await codec.ReadAsync(cancellation.Token);
            Assert.NotNull(syncOrNull);
            TransportMessage sync = syncOrNull!.Value;
            Assert.Equal(TransportTimeSync.ResponseType, sync.Type);
            Assert.Equal("021300000011", Convert.ToHexString(TransportFrame.Encode(sync.Type, sync.Payload).AsSpan(0, 6)));
            Assert.Equal(sequence, sync.Payload[..8]);
            Assert.Equal(1, sync.Payload[8]);
            uint clock = BinaryPrimitives.ReadUInt32LittleEndian(sync.Payload.AsSpan(9));
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
