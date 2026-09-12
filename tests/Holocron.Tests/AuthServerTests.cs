using System.Net;
using System.Net.Sockets;
using Holocron.Auth;

namespace Holocron.Tests;

public sealed class AuthServerTests
{
    [Fact]
    public async Task NewConnectionReceivesFramedLoginTransportGreeting()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var server = new AuthServer(0);
        Task serverTask = server.StartAsync(cancellation.Token);

        TcpClient? client = null;
        for (int i = 0; i < 50; i++)
        {
            if (serverTask.IsFaulted)
                await serverTask;

            try
            {
                client = new TcpClient();
                await client.ConnectAsync(IPAddress.Loopback, server.Port, cancellation.Token);
                break;
            }
            catch (SocketException) when (i < 49)
            {
                client?.Dispose();
                client = null;
                await Task.Delay(50, cancellation.Token);
            }
        }

        Assert.NotNull(client);
        using (client)
        {

        byte[] actual = new byte[22];
        await client.GetStream().ReadExactlyAsync(actual, cancellation.Token);

        byte[] expectedPrefix =
        [
            0x03, 0x16, 0x00, 0x00, 0x00, 0x15,
            0x12, 0x00, 0x00, 0x00,
            0x08, 0x00, 0x00, 0x00
        ];

        Assert.Equal(expectedPrefix, actual[..14]);
        Assert.Contains(actual[14..], value => value != 0);

        cancellation.Cancel();
        await serverTask;
    }
}
}
