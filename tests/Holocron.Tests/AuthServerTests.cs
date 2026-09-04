using System.Net;
using System.Net.Sockets;
using Holocron.Auth;

namespace Holocron.Tests;

public sealed class AuthServerTests
{
    [Fact]
    public async Task NewConnectionReceivesFramedLoginTransportGreeting()
    {
        int port = GetUnusedTcpPort();
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var server = new AuthServer(port);
        Task serverTask = server.StartAsync(cancellation.Token);

        using var client = new TcpClient();
        for (int i = 0; i < 50; i++)
        {
            try
            {
                await client.ConnectAsync(IPAddress.Loopback, port, cancellation.Token);
                break;
            }
            catch (SocketException) when (i < 49)
            {
                await Task.Delay(50, cancellation.Token);
            }
        }

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

    private static int GetUnusedTcpPort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }
}
