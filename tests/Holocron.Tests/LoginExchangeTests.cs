using System.Security.Cryptography;
using System.Text;
using System.Buffers.Binary;
using Holocron.Common.Crypto;
using Holocron.Common.Protocol;

namespace Holocron.Tests;

public class LoginExchangeTests
{
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
