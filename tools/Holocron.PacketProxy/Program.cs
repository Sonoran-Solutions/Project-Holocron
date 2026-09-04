using System.Net;
using System.Net.Sockets;

Console.WriteLine("=================================================");
Console.WriteLine("   Project Holocron - SWTOR Network Packet Proxy");
Console.WriteLine("=================================================");

int listenPort = 7979;
string targetHost = "127.0.0.1";
int targetPort = 7980;

if (args.Length >= 1 && int.TryParse(args[0], out int p)) listenPort = p;
if (args.Length >= 2) targetHost = args[1];
if (args.Length >= 3 && int.TryParse(args[2], out int tp)) targetPort = tp;

Console.WriteLine($"[CONFIG] Listening on port 0.0.0.0:{listenPort}");
Console.WriteLine($"[CONFIG] Forwarding to {targetHost}:{targetPort}");
Console.WriteLine($"[STATUS] Waiting for SWTOR client connections...\n");

var listener = new TcpListener(IPAddress.Any, listenPort);
listener.Start();

int sessionCounter = 0;

while (true)
{
    var clientSocket = await listener.AcceptSocketAsync();
    int sessionId = Interlocked.Increment(ref sessionCounter);
    Console.WriteLine($"[PROXY] Session #{sessionId} accepted from {clientSocket.RemoteEndPoint}");

    _ = Task.Run(async () =>
    {
        using var client = new TcpClient { Client = clientSocket };
        using var server = new TcpClient();
        try
        {
            await server.ConnectAsync(targetHost, targetPort);
            Console.WriteLine($"[PROXY] Session #{sessionId} connected to target {targetHost}:{targetPort}");

            using var clientStream = client.GetStream();
            using var serverStream = server.GetStream();

            var clientToServer = ForwardAndLogAsync(sessionId, "CLIENT -> SERVER", clientStream, serverStream);
            var serverToClient = ForwardAndLogAsync(sessionId, "SERVER -> CLIENT", serverStream, clientStream);

            await Task.WhenAny(clientToServer, serverToClient);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[PROXY] Session #{sessionId} error: {ex.Message}");
        }
        finally
        {
            Console.WriteLine($"[PROXY] Session #{sessionId} closed.");
        }
    });
}

static async Task ForwardAndLogAsync(int sessionId, string direction, NetworkStream input, NetworkStream output)
{
    byte[] buffer = new byte[8192];
    while (true)
    {
        int bytesRead = await input.ReadAsync(buffer, 0, buffer.Length);
        if (bytesRead == 0) break;

        // Deliberately log metadata only. Login frames can contain encrypted
        // account/session material and must never be dumped to the console.
        string timestamp = DateTime.Now.ToString("HH:mm:ss.fff");
        Console.WriteLine($"[{timestamp}] [S#{sessionId}] [{direction}] {bytesRead} bytes");

        await output.WriteAsync(buffer, 0, bytesRead);
        await output.FlushAsync();
    }
}
