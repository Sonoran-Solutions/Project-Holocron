using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using Holocron.Common.Protocol;
using Holocron.World.Network;

namespace Holocron.World;

public sealed class WorldServer
{
    private readonly int _port;
    private readonly WorldPacketDispatcher _dispatcher = new();
    private TcpListener? _listener;
    private bool _running;

    public WorldServer(int port = 20061)
    {
        _port = port;
    }

    public async Task StartAsync(CancellationToken cancellationToken = default)
    {
        _listener = new TcpListener(IPAddress.Any, _port);
        _listener.Start();
        _running = true;

        Console.WriteLine($"[WORLD] ========================================================");
        Console.WriteLine($"[WORLD] Project Holocron: World Shard Server Online on port {_port}");
        Console.WriteLine($"[WORLD] Pre-loaded {_dispatcher.SaveManager.Characters.Count} Level 80 characters ready for instant testing");
        Console.WriteLine($"[WORLD] ========================================================");

        while (_running && !cancellationToken.IsCancellationRequested)
        {
            try
            {
                var socket = await _listener.AcceptSocketAsync(cancellationToken);
                _ = HandleSessionAsync(socket, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[WORLD] Accept error: {ex.Message}");
            }
        }
    }

    private async Task HandleSessionAsync(Socket socket, CancellationToken ct)
    {
        string endpoint = socket.RemoteEndPoint?.ToString() ?? "Unknown";
        Console.WriteLine($"[WORLD] Client connected from {endpoint}");

        using var stream = new NetworkStream(socket, ownsSocket: true);
        var session = new WorldSession(stream);

        try
        {
            // Step 1: Send initial HeroEngine SMSG_HANDSHAKE
            await session.SendHandshakeAsync(ct);

            byte[] buffer = new byte[8192];
            int read = await stream.ReadAsync(buffer, ct);
            if (read <= 0) return;

            Console.WriteLine($"[WORLD] Received {read} bytes initial handshake response from {endpoint}");

            // Step 2: Configure Client
            await session.SendClientConfigurationAsync(ct);

            // Step 3: Event Loop
            while (!ct.IsCancellationRequested)
            {
                read = await stream.ReadAsync(buffer, ct);
                if (read <= 0) break;

                byte[] packetData = new byte[read];
                Array.Copy(buffer, packetData, read);

                await _dispatcher.DispatchAsync(session, packetData, ct);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[WORLD] Session error with {endpoint}: {ex.Message}");
        }
        finally
        {
            Console.WriteLine($"[WORLD] Session closed for {endpoint}");
        }
    }
}
