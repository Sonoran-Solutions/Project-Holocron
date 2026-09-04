using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Holocron.Common.Crypto;

public sealed record SwtorLoginSessionKeys(
    byte[] ServerToClientKey,
    byte[] ClientToServerKey,
    byte[] ServerToClientIv,
    byte[] ClientToServerIv);

/// <summary>
/// Decodes SWTOR's initial RSA-wrapped Salsa20 key exchange. Account and
/// session identifiers are skipped and never returned to callers.
/// </summary>
public static class SwtorLoginKeyExchange
{
    private const int EncodedCiphertextLength = 1024;
    private const int RsaBlockLength = 256;

    // Protocol key used by the retail client for the login transport.
    private const string PrivateKeyPkcs8Base64 =
        "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCyOxTQYMMN25BTKZT9Y/NXDQJVQc0Iam//DUTlGagE5jwxKBxxdECte6uP4z4G970Q9T2OD6kAuLagj+TL5BM9hLzpGZFuzliEUNx5FdMW7ms27N+BHo8DmyCxjlZOUWbtx/x+A8TM0s0xHKwcFz6z9l+4qgVarrWxUD7okGkfuoQO22JYZEpLZOe2Wi2jbI5sJgL2CPZ6AyDAaGOxGe8YmmCz3Ykh9poBHj1RjwMOXdiWIgZ8RyFm8Sm8KD6Nvu5La31X4TUYaoe1H8wXrsdGc3lu+KbZ5ZhS6eYdim0O7rxrk/X4f30wabYhUD2hJ3KZyCIAUbWVuUEgfvqTVToxAgERAoIBAAksc+UUCgogAcgLjVDOjmg+yYgnJsnYTUs+zPU0JOIicEZLee9AVicMAy7vdgQfkySjNf3mc/4nn/z4WPPn+XX9a5sOfhLhNX9H7TrwLqEuJ2aXfHHwobbGGidBrdqeivHiw5WLfPP0QwgsxRgIudDKzHTMhApQhZZNisRw2Dv8VkzmUv98RCyvzQGiwfubOq8D4CS36+JVwKfWmqSzLFaOWxl/Ty530SYvAodW3PMpE42M+vBUJnyJC7O8Ss73MwJW64iQlERhU+B1B2pw9RppaXGaqhW9STih5QpwahuczgQ5fGjP+Bfuo5xASuFa7nFkXmQjzqxw/DkZnCi8P6kCgYEA8IU3G8BkqQLcSCFu/AQPgMQ8fV1Ye5g1vzw/xakROMWQdbd/KjBTnatlPiFFBAavy1cuNLZb48uvWGWbfIb8F4dQgl1RRKEEA5Nhgf8jkaFkBmPQXUUenQ5MK6EU4eIJYtctJ3Muw/CGnubHY3BwqUFgzQP1oZX0tkYQqkgHa/kCgYEAvbOXHqH/Bwjn7AdseNAndPHnXj0EStkCMDUDvPXdWOXzAQz+E2rUQW/ehOrW8SW0kVxAxmQamwMkW7KLpuQAHE2CP3i7i0bfAfRKTE2vdxGhu5CP81wgSBzmobGkWRRskmblXWxjnAE0Y17MT/HQHnQ3BodbQA4M1DvqdlhyHfkCgYEAqcdyMbT7wpibfjW3wPPOtT85weeJwKetd+5LIhz9GQPtgEVKtF5ZJACDs2LHTiLWcWq3NER9GUR7xe1eskEqavYatl/9IWKZa++QH4br7lPOIqDPUOV/BXOBD7z/roFwCYjUlFFOL/UTu3W569bmHR8XJ04WzGnZ6hNXDsluppECgYAsorolU0sQts0oejej9L39ZhhSaLW3Qh6h7ls7hSUF28C08/+MGSLiOHCXvskproTW6Ie2NavoPPl+/NWQrh4kxvF4WKSZPdoek9U/IVZ2XoBoXj/9Bp4vFdvpz3H216ETY4FDKI/oeMEIUoptKdadwP3jaySHitXXlaCUUQvK0QKBgQDVRN6rOp+dXH60b3xioVqHtjAn5+5Yhh1GHIwNAo8cM0wYt8HgCtRhigwAzsx1AZHOVrPU2jNQsX0bNT7CnmOA/ehJZe/UAdrQjwInxSSizQ3V2MXg0P0/asuGNV1WxZCp9k3V7ZOGhdkpL8g8mdfY4O9YiZhCZaY0nZ4MpXjngA==";

    public static SwtorLoginSessionKeys Decode(ReadOnlySpan<byte> packet)
    {
        if (packet.Length < EncodedCiphertextLength)
            throw new InvalidDataException($"Key exchange is too short ({packet.Length} bytes)." );

        int encodedOffset = FindEncodedCiphertext(packet);
        Span<byte> ciphertext = stackalloc byte[EncodedCiphertextLength / 2];
        DecodeHexAscii(packet.Slice(encodedOffset, EncodedCiphertextLength), ciphertext);

        byte[] keyBytes = Convert.FromBase64String(PrivateKeyPkcs8Base64);
        byte[] cleartext;
        using (RSA rsa = RSA.Create())
        {
            rsa.ImportPkcs8PrivateKey(keyBytes, out _);
            byte[] first = rsa.Decrypt(ciphertext[..RsaBlockLength], RSAEncryptionPadding.Pkcs1);
            byte[] second = rsa.Decrypt(ciphertext[RsaBlockLength..], RSAEncryptionPadding.Pkcs1);
            cleartext = new byte[first.Length + second.Length];
            first.CopyTo(cleartext, 0);
            second.CopyTo(cleartext, first.Length);
            CryptographicOperations.ZeroMemory(first);
            CryptographicOperations.ZeroMemory(second);
        }
        CryptographicOperations.ZeroMemory(keyBytes);
        CryptographicOperations.ZeroMemory(ciphertext);

        try
        {
            int offset = SkipLengthPrefixedString(cleartext, 0);
            offset = SkipLengthPrefixedString(cleartext, offset);
            if (cleartext.Length - offset < 80)
                throw new InvalidDataException("Decrypted key exchange does not contain four Salsa20 parameters.");

            return new SwtorLoginSessionKeys(
                cleartext.AsSpan(offset, 32).ToArray(),
                cleartext.AsSpan(offset + 32, 32).ToArray(),
                cleartext.AsSpan(offset + 64, 8).ToArray(),
                cleartext.AsSpan(offset + 72, 8).ToArray());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(cleartext);
        }
    }

    private static int SkipLengthPrefixedString(ReadOnlySpan<byte> data, int offset)
    {
        if (data.Length - offset < 4)
            throw new InvalidDataException("Truncated string length in key exchange.");

        int length = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(offset, 4));
        if (length < 0 || length > data.Length - offset - 4)
            throw new InvalidDataException("Invalid string length in key exchange.");

        return offset + 4 + length;
    }

    private static void DecodeHexAscii(ReadOnlySpan<byte> source, Span<byte> destination)
    {
        if (source.Length != destination.Length * 2)
            throw new InvalidDataException("Key exchange RSA payload has an invalid length.");

        for (int i = 0; i < destination.Length; i++)
        {
            int high = HexNibble(source[i * 2]);
            int low = HexNibble(source[i * 2 + 1]);
            if (high < 0 || low < 0)
                throw new InvalidDataException("Key exchange RSA payload is not valid hexadecimal.");
            destination[i] = (byte)((high << 4) | low);
        }
    }

    private static int FindEncodedCiphertext(ReadOnlySpan<byte> packet)
    {
        int runStart = 0;
        int runLength = 0;
        for (int i = 0; i < packet.Length; i++)
        {
            if (HexNibble(packet[i]) >= 0)
            {
                if (runLength == 0) runStart = i;
                runLength++;
                if (runLength >= EncodedCiphertextLength) return runStart;
            }
            else
            {
                runLength = 0;
            }
        }

        throw new InvalidDataException("Key exchange does not contain a complete RSA ciphertext.");
    }

    private static int HexNibble(byte value) => value switch
    {
        >= (byte)'0' and <= (byte)'9' => value - '0',
        >= (byte)'A' and <= (byte)'F' => value - 'A' + 10,
        >= (byte)'a' and <= (byte)'f' => value - 'a' + 10,
        _ => -1
    };
}
