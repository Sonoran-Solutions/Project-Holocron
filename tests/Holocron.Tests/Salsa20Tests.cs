using System.Text;
using Holocron.Common.Crypto;
using Xunit;

namespace Holocron.Tests;

public class Salsa20Tests
{
    [Fact]
    public void Salsa20_EncryptDecrypt_RoundTrip_MatchesOriginal()
    {
        byte[] key = new byte[32];
        byte[] iv = new byte[8];
        for (int i = 0; i < 32; i++) key[i] = (byte)(i + 1);
        for (int i = 0; i < 8; i++) iv[i] = (byte)(i + 10);

        byte[] plainText = Encoding.UTF8.GetBytes("May the Force be with you, always. Project Holocron!");
        byte[] cipherText = new byte[plainText.Length];
        byte[] decrypted = new byte[plainText.Length];

        var enc = new Salsa20(key, iv);
        enc.Process(plainText, cipherText);

        var dec = new Salsa20(key, iv);
        dec.Process(cipherText, decrypted);

        Assert.Equal(plainText, decrypted);
        Assert.NotEqual(plainText, cipherText);
    }
}
