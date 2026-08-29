using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Holocron.Common.Crypto;
using Holocron.Common.Protocol;

namespace Holocron.World;

public sealed class WorldServer
{
    private readonly int _port;
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

        Console.WriteLine($"[WORLD] World Shard Server listening on 0.0.0.0:{_port}");

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
        Console.WriteLine($"[WORLD] Player connection accepted from {endpoint}");

        using var stream = new NetworkStream(socket, ownsSocket: true);

        try
        {
            // Step 1: Send SMSG_HANDSHAKE
            byte[] handshake = new byte[28];
            BinaryPrimitives.WriteUInt32LittleEndian(handshake.AsSpan(0, 4), (uint)Opcode.SMSG_HANDSHAKE);
            BinaryPrimitives.WriteUInt32LittleEndian(handshake.AsSpan(4, 4), 0);
            BinaryPrimitives.WriteUInt16LittleEndian(handshake.AsSpan(8, 2), 0x08);
            BinaryPrimitives.WriteUInt16LittleEndian(handshake.AsSpan(10, 2), 0x00);
            BinaryPrimitives.WriteUInt64LittleEndian(handshake.AsSpan(12, 8), 0x14AA63E353DBF459UL);

            await stream.WriteAsync(handshake, ct);
            await stream.FlushAsync(ct);

            byte[] buffer = new byte[8192];
            int read = await stream.ReadAsync(buffer, ct);
            if (read <= 0) return;

            Console.WriteLine($"[WORLD] Handshake completed with {endpoint}. Initializing HeroEngine subsystems...");

            // Send initial HeroEngine XML client configuration
            string clientInfoXml = "<ClientInformation universeID=\"holocron\" networkNapTimeMS=\"20\" CacheFilePath=\"HeroEngineCache\\Local\"/>";
            var clientInfoPacket = new PacketWriter(Opcode.SMSG_CLIENT_INFORMATION)
                .WriteString(clientInfoXml);
            await stream.WriteAsync(clientInfoPacket.ToByteArray(), ct);

            // Send Gauntlet protocol version
            var gauntletPacket = new PacketWriter(Opcode.SMSG_NOTIFY_GAUNTLET_VERSION).WriteUInt32(0x11);
            await stream.WriteAsync(gauntletPacket.ToByteArray(), ct);

            // Send Awareness Ranges (9.0m enter, 13.5m escape)
            var awarenessPacket = new PacketWriter(Opcode.SMSG_AWARENESS_RANGE)
                .WriteFloat(9.0f)
                .WriteFloat(13.5f);
            await stream.WriteAsync(awarenessPacket.ToByteArray(), ct);

            while (!ct.IsCancellationRequested)
            {
                read = await stream.ReadAsync(buffer, ct);
                if (read <= 0) break;

                uint opcode = BinaryPrimitives.ReadUInt32LittleEndian(buffer.AsSpan(0, 4));

                switch ((Opcode)opcode)
                {
                    case Opcode.CMSG_PING:
                    {
                        var pingReply = new PacketWriter(Opcode.SMSG_PING);
                        await stream.WriteAsync(pingReply.ToByteArray(), ct);
                        break;
                    }

                    case Opcode.CMSG_CHARACTER_LIST:
                    {
                        Console.WriteLine($"[WORLD] Serving character list to {endpoint}");
                        var charListPacket = new PacketWriter(Opcode.SMSG_CHARACTER_LIST);
                        charListPacket.WriteUInt32(0); // 0 characters for fresh account
                        string entitlementsXml = "<Entitlements><Entitlement id=\"7\"/><Entitlement id=\"30\"/><Entitlement id=\"39\"/><Entitlement id=\"2013\"/><Entitlement id=\"40\"/><Entitlement id=\"71\"/></Entitlements>";
                        charListPacket.WriteString(entitlementsXml);
                        await stream.WriteAsync(charListPacket.ToByteArray(), ct);
                        break;
                    }

                    case Opcode.CMSG_CHARACTER_SELECT:
                    {
                        Console.WriteLine($"[WORLD] Character selected by {endpoint}. Loading zone...");
                        
                        // Acknowledge character selection
                        var selectAck = new PacketWriter(Opcode.SMSG_CHARACTER_SELECTED);
                        await stream.WriteAsync(selectAck.ToByteArray(), ct);

                        // Direct client to Tython starting zone
                        var mapPacket = new PacketWriter(Opcode.SMSG_TRAVEL_PENDING)
                            .WriteString("tython_main")
                            .WriteString("4611686019802843831")
                            .WriteString(@"\world\areas\tython_main\area.dat");
                        await stream.WriteAsync(mapPacket.ToByteArray(), ct);

                        var travelStatus = new PacketWriter(Opcode.SMSG_TRAVEL_STATUS).WriteUInt32(1);
                        await stream.WriteAsync(travelStatus.ToByteArray(), ct);
                        break;
                    }

                    case Opcode.CMSG_CHAT_MESSAGE:
                    {
                        Console.WriteLine($"[WORLD] Chat message received from {endpoint}");
                        break;
                    }

                    default:
                        Console.WriteLine($"[WORLD] Received Opcode: {(Enum.IsDefined(typeof(Opcode), opcode) ? ((Opcode)opcode).ToString() : $"0x{opcode:X8}")} ({read} bytes)");
                        break;
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[WORLD] Session error: {ex.Message}");
        }
        finally
        {
            Console.WriteLine($"[WORLD] Session closed for {endpoint}");
        }
    }
}
