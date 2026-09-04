using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Holocron.Common.Crypto;
using Holocron.Common.Protocol;

namespace Holocron.Auth;

public sealed class AuthServer
{
    // Layout: 1-byte opcode, 4-byte LE packet length, 1-byte XOR checksum,
    // followed by transport type, content version, and a per-connection nonce.
    private static byte[] CreateInitialGreeting()
    {
        byte[] greeting =
        [
            0x03, 0x16, 0x00, 0x00, 0x00, 0x15,
            0x12, 0x00, 0x00, 0x00,
            0x08, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        ];

        RandomNumberGenerator.Fill(greeting.AsSpan(14, 8));
        return greeting;
    }

    private readonly int _port;
    private readonly string _worldHost;
    private readonly int _worldPort;
    private TcpListener? _listener;
    private bool _running;

    public AuthServer(int port = 7979, string worldHost = "127.0.0.1", int worldPort = 20061)
    {
        _port = port;
        _worldHost = worldHost;
        _worldPort = worldPort;
    }

    public async Task StartAsync(CancellationToken cancellationToken = default)
    {
        _listener = new TcpListener(IPAddress.Any, _port);
        _listener.Start();
        _running = true;

        Console.WriteLine($"[AUTH] Auth Server listening on 0.0.0.0:{_port}");
        Console.WriteLine($"[AUTH] Configured World Server target: {_worldHost}:{_worldPort}");

        while (_running && !cancellationToken.IsCancellationRequested)
        {
            try
            {
                var socket = await _listener.AcceptSocketAsync(cancellationToken);
                _ = HandleClientAsync(socket, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[AUTH] Accept error: {ex.Message}");
            }
        }
    }

    private async Task HandleClientAsync(Socket socket, CancellationToken ct)
    {
        string endpoint = socket.RemoteEndPoint?.ToString() ?? "Unknown";
        Console.WriteLine($"[AUTH] Client connected from {endpoint}");

        using var stream = new NetworkStream(socket, ownsSocket: true);

        try
        {
            // Step 1: Send the framed login transport greeting. This is not a
            // normal application packet and must not use PacketWriter's header.
            byte[] greeting = CreateInitialGreeting();
            await stream.WriteAsync(greeting, ct);
            await stream.FlushAsync(ct);
            Console.WriteLine($"[AUTH] Sent login transport greeting ({greeting.Length} bytes) to {endpoint}");

            // Step 2: Read CMSG_HANDSHAKE
            byte[] buffer = new byte[4096];
            int read = await stream.ReadAsync(buffer, ct);
            if (read <= 0) return;

            Console.WriteLine($"[AUTH] Received CMSG_HANDSHAKE ({read} bytes) from {endpoint}");

            SwtorLoginSessionKeys sessionKeys = SwtorLoginKeyExchange.Decode(buffer.AsSpan(0, read));
            var sendCipher = new Salsa20(sessionKeys.ServerToClientKey, sessionKeys.ServerToClientIv);
            var recvCipher = new Salsa20(sessionKeys.ClientToServerKey, sessionKeys.ClientToServerIv);
            CryptographicOperations.ZeroMemory(sessionKeys.ServerToClientKey);
            CryptographicOperations.ZeroMemory(sessionKeys.ClientToServerKey);
            CryptographicOperations.ZeroMemory(sessionKeys.ServerToClientIv);
            CryptographicOperations.ZeroMemory(sessionKeys.ClientToServerIv);
            Console.WriteLine($"[AUTH] RSA key exchange validated; Salsa20 session established for {endpoint}");

            // Generate ephemeral session ServerId token
            string serverIdToken = Guid.NewGuid().ToString("N")[..16];

            // Serve session loop
            while (!ct.IsCancellationRequested)
            {
                read = await stream.ReadAsync(buffer, ct);
                if (read <= 0) break;

                // For raw or encrypted packets, parse opcode
                uint opcode = BinaryPrimitives.ReadUInt32LittleEndian(buffer.AsSpan(0, 4));

                switch ((Opcode)opcode)
                {
                    case Opcode.CMSG_PING:
                    {
                        var pingReply = new PacketWriter(Opcode.SMSG_PING);
                        byte[] raw = pingReply.ToByteArray();
                        await stream.WriteAsync(raw, ct);
                        break;
                    }

                    case Opcode.MSG_REQUEST_SIGNATURE:
                    {
                        Console.WriteLine($"[AUTH] Received MSG_REQUEST_SIGNATURE");
                        var sigReply = new PacketWriter(Opcode.MSG_SIGNATURE)
                            .WriteUInt16(0x04)
                            .WriteString("holocron_shard")
                            .WriteString("afc1bb5a")
                            .WriteString("loginserver")
                            .WriteUInt64(1);
                        await stream.WriteAsync(sigReply.ToByteArray(), ct);
                        break;
                    }

                    case Opcode.CMSG_REQUEST_INTRODUCE_CONNECTION:
                    {
                        Console.WriteLine($"[AUTH] Handing off client to World Server: {_worldHost}:{_worldPort} (Token: {serverIdToken})");
                        var introReply = new PacketWriter(Opcode.SMSG_REQUEST_INTRODUCE_CONNECTION)
                            .WriteString($"{_worldHost}:{_worldPort}")
                            .WriteString(serverIdToken);
                        await stream.WriteAsync(introReply.ToByteArray(), ct);
                        break;
                    }

                    case Opcode.CMSG_REQUEST_CLOSE:
                        Console.WriteLine($"[AUTH] Client requested graceful disconnect.");
                        return;

                    default:
                        Console.WriteLine($"[AUTH] Unhandled opcode: 0x{opcode:X8} ({read} bytes)");
                        break;
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[AUTH] Client session error: {ex.Message}");
        }
        finally
        {
            Console.WriteLine($"[AUTH] Client disconnected: {endpoint}");
        }
    }
}
