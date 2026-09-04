using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using Holocron.Common.Protocol;
using Holocron.World.Network;

namespace Holocron.World;

public sealed class WorldServer
{
    private static readonly byte[] InitialWorldGreeting =
    [
        0x03, 0x0E, 0x00, 0x00, 0x00, 0x0D,
        0x12, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    ];

    private readonly int[] _ports;
    private readonly WorldPacketDispatcher _dispatcher = new();
    private readonly List<TcpListener> _listeners = new();
    private bool _running;

    public WorldServer(params int[] ports)
    {
        _ports = (ports != null && ports.Length > 0) ? ports : new[] { 20061, 9007 };
    }

    public async Task StartAsync(CancellationToken cancellationToken = default)
    {
        _running = true;
        var acceptTasks = new List<Task>();

        foreach (var port in _ports)
        {
            try
            {
                var listener = new TcpListener(IPAddress.Any, port);
                listener.Start();
                _listeners.Add(listener);
                Console.WriteLine($"[WORLD] Listening on 0.0.0.0:{port}");
                acceptTasks.Add(AcceptLoopAsync(listener, port, cancellationToken));
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[WORLD] Warning: Could not bind to port {port}: {ex.Message}");
            }
        }

        Console.WriteLine($"[WORLD] ========================================================");
        Console.WriteLine($"[WORLD] Project Holocron: Server Online on ports: {string.Join(", ", _ports)}");
        Console.WriteLine($"[WORLD] Pre-loaded {_dispatcher.SaveManager.Characters.Count} Level 80 characters ready for instant testing");
        Console.WriteLine($"[WORLD] ========================================================");

        await Task.WhenAll(acceptTasks);
    }

    private async Task AcceptLoopAsync(TcpListener listener, int port, CancellationToken ct)
    {
        while (_running && !ct.IsCancellationRequested)
        {
            try
            {
                var socket = await listener.AcceptSocketAsync(ct);
                _ = HandleSessionAsync(socket, port, ct);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[WORLD] Accept error on port {port}: {ex.Message}");
            }
        }

        Console.WriteLine($"[WORLD] AcceptLoopAsync terminated on port {port}. Running={_running}, Cancelled={ct.IsCancellationRequested}");
    }

    private async Task HandleSessionAsync(Socket socket, int listenPort, CancellationToken ct)
    {
        string endpoint = socket.RemoteEndPoint?.ToString() ?? "Unknown";
        Console.WriteLine($"[WORLD] Client connected from {endpoint} on port {listenPort}");

        using var stream = new NetworkStream(socket, ownsSocket: true);
        var session = new WorldSession(stream);

        try
        {
            byte[] buffer = new byte[8192];

            await stream.WriteAsync(InitialWorldGreeting, ct);
            await stream.FlushAsync(ct);
            Console.WriteLine($"[WORLD] Sent world transport greeting ({InitialWorldGreeting.Length} bytes) to {endpoint} on port {listenPort}");

            // Event Loop
            while (!ct.IsCancellationRequested)
            {
                int read = await stream.ReadAsync(buffer, ct);
                if (read <= 0) break;

                Console.WriteLine($"[WORLD] [{endpoint}] Received {read} bytes on port {listenPort}");

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
