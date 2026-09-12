using System.Buffers.Binary;
using System.Diagnostics;
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
    private readonly RSA? _testKey;
    private readonly bool _handshakeOnly;
    private readonly bool _capturePostHandshake;
    private readonly bool _probeLoginReplyEnvelope;
    private readonly long _timeBaseFileTimeMilliseconds;
    private readonly long _timeBaseStopwatchTimestamp;

    public AuthServer(int port = 7979, string worldHost = "127.0.0.1", int worldPort = 20061,
        RSA? testKey = null, bool handshakeOnly = false, bool capturePostHandshake = false,
        bool probeLoginReplyEnvelope = false)
    {
        _port = port;
        _worldHost = worldHost;
        _worldPort = worldPort;
        _testKey = testKey;
        _handshakeOnly = handshakeOnly;
        _capturePostHandshake = capturePostHandshake;
        _probeLoginReplyEnvelope = probeLoginReplyEnvelope;
        _timeBaseFileTimeMilliseconds = DateTime.UtcNow.ToFileTimeUtc() / TimeSpan.TicksPerMillisecond;
        _timeBaseStopwatchTimestamp = Stopwatch.GetTimestamp();
    }

    public int Port => _listener?.LocalEndpoint is IPEndPoint ep ? ep.Port : _port;

    public async Task StartAsync(CancellationToken cancellationToken = default)
    {
        _listener = new TcpListener(IPAddress.Loopback, _port);
        _listener.Server.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        _listener.Start();
        _running = true;

        Console.WriteLine($"[AUTH] Auth Server listening on 127.0.0.1:{Port}");
        Console.WriteLine($"[AUTH] Configured World Server target: {_worldHost}:{_worldPort}");

        try
        {
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
        finally
        {
            _listener.Stop();
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
            byte[]? handshake = await TransportFrame.ReadAsync(stream, ct);
            if (handshake is null) return;
            if (handshake[0] != 4)
                throw new InvalidDataException("Expected key-exchange transport type 4.");
            int read = handshake.Length;

            Console.WriteLine($"[AUTH] Received CMSG_HANDSHAKE ({read} bytes) from {endpoint}");

            SwtorLoginSessionKeys sessionKeys;
            try
            {
                if (_testKey is null)
                    sessionKeys = SwtorLoginKeyExchange.Decode(handshake);
                else
                    lock (_testKey) sessionKeys = SwtorLoginKeyExchange.Decode(handshake, _testKey);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(handshake);
            }
            var sendCipher = new Salsa20(sessionKeys.ServerToClientKey, sessionKeys.ServerToClientIv);
            var recvCipher = new Salsa20(sessionKeys.ClientToServerKey, sessionKeys.ClientToServerIv);
            CryptographicOperations.ZeroMemory(sessionKeys.ServerToClientKey);
            CryptographicOperations.ZeroMemory(sessionKeys.ClientToServerKey);
            CryptographicOperations.ZeroMemory(sessionKeys.ServerToClientIv);
            CryptographicOperations.ZeroMemory(sessionKeys.ClientToServerIv);
            Console.WriteLine($"[AUTH] RSA envelope and historical key-field layout validated for {endpoint}; encrypted application protocol not yet verified.");
            if (_handshakeOnly)
            {
                if (_probeLoginReplyEnvelope)
                {
                    await ProbeLoginReplyEnvelopeAsync(stream, recvCipher, sendCipher, endpoint, ct);
                    return;
                }
                if (_capturePostHandshake)
                {
                    using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    timeout.CancelAfter(TimeSpan.FromSeconds(3));
                    try
                    {
                        byte[] probe = new byte[4096];
                        int received = await stream.ReadAsync(probe, timeout.Token);
                        if (received > 0)
                        {
                            byte[] plain = new byte[received];
                            recvCipher.Process(probe.AsSpan(0, received), plain);
                            int headerLength = Math.Min(6, plain.Length);
                            int payloadPrefixLength = Math.Min(8, Math.Max(0, plain.Length - headerLength));
                            Console.WriteLine($"[AUTH] Post-handshake client bytes: encrypted={received}, decrypted-header={Convert.ToHexString(plain.AsSpan(0, headerLength))}, decrypted-payload-prefix={Convert.ToHexString(plain.AsSpan(headerLength, payloadPrefixLength))}, decrypted-sha256={Convert.ToHexString(SHA256.HashData(plain))}");
                            CryptographicOperations.ZeroMemory(plain);
                        }
                        else Console.WriteLine("[AUTH] Client closed without a post-handshake message.");
                    }
                    catch (OperationCanceledException) { Console.WriteLine("[AUTH] No post-handshake client bytes before timeout; client is waiting for a server message."); }
                }
                Console.WriteLine("[AUTH] Handshake-only probe complete; closing without speculative application replies.");
                return;
            }

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
                        Console.WriteLine($"[AUTH] Handing off client to World Server: {_worldHost}:{_worldPort}");
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

    private async Task ProbeLoginReplyEnvelopeAsync(
        Stream stream, Salsa20 recvCipher, Salsa20 sendCipher, string endpoint, CancellationToken ct)
    {
        byte[]? request = await ReadEncryptedTransportFrameAsync(stream, recvCipher, ct);
        if (request is null)
        {
            Console.WriteLine("[AUTH] Client closed without a post-handshake message.");
            return;
        }

        if (request[0] != 0x10 || request.Length < TransportFrame.HeaderSize + 8)
            throw new InvalidDataException("Expected a type-0x10 frame with an 8-byte dispatch envelope.");

        // The retail receive path reads exactly uint32 + uint16 + uint16 before
        // dispatch. Outbound calls serialize Connection+0x28 followed by +0x60,
        // while the peer's receive registry is keyed by +0x60 followed by +0x28.
        // The same proven ServerProxy callback accepts LoginRequestIFace reply
        // D4BA5CCD and ReplyGameLaunch 90F2D04D. The login reply initializes the
        // application first. ReplyGameLaunch then passes its first encoded string
        // to the connection controller and finishes the retained Auth connection.
        // Its second string is left at the parser-valid empty minimum so this probe
        // does not invent a session token or other authentication data.
        uint messageId = BinaryPrimitives.ReadUInt32LittleEndian(request.AsSpan(TransportFrame.HeaderSize));
        ushort routeA = BinaryPrimitives.ReadUInt16LittleEndian(request.AsSpan(TransportFrame.HeaderSize + 4));
        ushort routeB = BinaryPrimitives.ReadUInt16LittleEndian(request.AsSpan(TransportFrame.HeaderSize + 6));
        Console.WriteLine($"[AUTH] Received type-0x10 login envelope: length={request.Length}, message=0x{messageId:X8}, route=0x{routeA:X4}/0x{routeB:X4}");
        CryptographicOperations.ZeroMemory(request);

        if (messageId != 0x011C5800)
            throw new InvalidDataException($"Expected login request message 0x011C5800, received 0x{messageId:X8}.");

        // The retail binary requires root <client> with attributes (e.g. useSyncClock, loglevel)
        // for post-config handler 0x140447470, plus child <access-rights> containing
        // <client name="..."> and <network name="..." address="..."/> for HandleInitialized.
        byte[] initializationDocument = "<client title=\"Test Client\" useSyncClock=\"true\" loglevel=\"debug\"><access-rights><client name=\"Automaton.exe\"><network name=\"BWA\" address=\"10.2.0.0/15\"/></client></access-rights></client>"u8.ToArray();
        int encodedStringLength = initializationDocument.Length + 1;
        byte[] envelope = new byte[16 + encodedStringLength];
        BinaryPrimitives.WriteUInt32LittleEndian(envelope, 0xD4BA5CCD);
        BinaryPrimitives.WriteUInt16LittleEndian(envelope.AsSpan(4), routeB);
        BinaryPrimitives.WriteUInt16LittleEndian(envelope.AsSpan(6), routeA);
        // Body: u32 status = 0; u32 byte length including the terminal NUL;
        // UTF-8 XML bytes; terminal NUL (provided by the zero-initialized array).
        BinaryPrimitives.WriteUInt32LittleEndian(envelope.AsSpan(12), (uint)encodedStringLength);
        initializationDocument.CopyTo(envelope.AsSpan(16));

        byte[] response = TransportFrame.Encode(0x10, envelope);
        byte[] encryptedResponse = new byte[response.Length];
        sendCipher.Process(response, encryptedResponse);
        await stream.WriteAsync(encryptedResponse, ct);
        await stream.FlushAsync(ct);
        Console.WriteLine($"[AUTH] Sent encrypted login-reply envelope with minimal client initializer ({response.Length} bytes, message=0xD4BA5CCD, route=0x{routeB:X4}/0x{routeA:X4}, body={envelope.Length - 8} bytes) to {endpoint}.");
        CryptographicOperations.ZeroMemory(encryptedResponse);
        CryptographicOperations.ZeroMemory(response);
        CryptographicOperations.ZeroMemory(envelope);

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(5));
        try
        {
            byte[]? next = await ReadEncryptedTransportFrameAsync(stream, recvCipher, timeout.Token);
            if (next is null) Console.WriteLine("[AUTH] Client closed after the correlated envelope.");
            else
            {
                if (next[0] == 0x01 && next.Length == TransportFrame.HeaderSize + sizeof(ulong))
                {
                    ulong sequence = TransportTimeSync.ReadRequestSequence(next);
                    Console.WriteLine($"[AUTH] Client advanced with transport time request: type=0x01, length={next.Length}, sequence=0x{sequence:X16}.");
                    CryptographicOperations.ZeroMemory(next);

                    uint localTimeMilliseconds = GetTimeSyncMilliseconds();
                    byte[] controlResponse = TransportTimeSync.EncodeBaseResponse(sequence, localTimeMilliseconds);
                    byte[] encryptedControlResponse = new byte[controlResponse.Length];
                    sendCipher.Process(controlResponse, encryptedControlResponse);
                    await stream.WriteAsync(encryptedControlResponse, timeout.Token);
                    await stream.FlushAsync(timeout.Token);
                    Console.WriteLine($"[AUTH] Sent encrypted base-only transport time response: type=0x02, length={controlResponse.Length}, sequence=0x{sequence:X16}, count=1, local-ms=0x{localTimeMilliseconds:X8}.");
                    CryptographicOperations.ZeroMemory(encryptedControlResponse);
                    CryptographicOperations.ZeroMemory(controlResponse);

                    byte[] gameAddress = Encoding.UTF8.GetBytes($"{_worldHost}:{_worldPort}");
                    int encodedAddressLength = gameAddress.Length + 1;
                    int secondStringLengthOffset = 12 + encodedAddressLength;
                    byte[] launchEnvelope = new byte[secondStringLengthOffset + sizeof(uint) + 1];
                    BinaryPrimitives.WriteUInt32LittleEndian(launchEnvelope, 0x90F2D04D);
                    BinaryPrimitives.WriteUInt16LittleEndian(launchEnvelope.AsSpan(4), routeB);
                    BinaryPrimitives.WriteUInt16LittleEndian(launchEnvelope.AsSpan(6), routeA);
                    BinaryPrimitives.WriteUInt32LittleEndian(launchEnvelope.AsSpan(8), (uint)encodedAddressLength);
                    gameAddress.CopyTo(launchEnvelope.AsSpan(12));
                    BinaryPrimitives.WriteUInt32LittleEndian(launchEnvelope.AsSpan(secondStringLengthOffset), 1);

                    byte[] launchResponse = TransportFrame.Encode(0x10, launchEnvelope);
                    byte[] encryptedLaunchResponse = new byte[launchResponse.Length];
                    sendCipher.Process(launchResponse, encryptedLaunchResponse);
                    await stream.WriteAsync(encryptedLaunchResponse, timeout.Token);
                    await stream.FlushAsync(timeout.Token);
                    Console.WriteLine($"[AUTH] Sent encrypted post-sync game-launch reply ({launchResponse.Length} bytes, message=0x90F2D04D, route=0x{routeB:X4}/0x{routeA:X4}, address={_worldHost}:{_worldPort}, second-string=empty) to {endpoint}.");
                    CryptographicOperations.ZeroMemory(encryptedLaunchResponse);
                    CryptographicOperations.ZeroMemory(launchResponse);
                    CryptographicOperations.ZeroMemory(launchEnvelope);
                    CryptographicOperations.ZeroMemory(gameAddress);

                    using var followUpTimeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    followUpTimeout.CancelAfter(TimeSpan.FromSeconds(5));
                    try
                    {
                        byte[]? followUp = await ReadEncryptedTransportFrameAsync(stream, recvCipher, followUpTimeout.Token);
                        if (followUp is null)
                        {
                            Console.WriteLine("[AUTH] Client closed after the transport time response.");
                        }
                        else
                        {
                            Console.WriteLine($"[AUTH] Client advanced after the transport time response: type=0x{followUp[0]:X2}, length={followUp.Length}.");
                            CryptographicOperations.ZeroMemory(followUp);
                        }
                    }
                    catch (OperationCanceledException)
                    {
                        Console.WriteLine("[AUTH] Client did not send another frame within the bounded post-time-response window.");
                    }
                    return;
                }
                else
                {
                    Console.WriteLine($"[AUTH] Client advanced with next encrypted transport frame: type=0x{next[0]:X2}, length={next.Length}.");
                }
                CryptographicOperations.ZeroMemory(next);
            }
        }
        catch (OperationCanceledException)
        {
            Console.WriteLine("[AUTH] Client did not send a next frame within the bounded probe window.");
        }
    }

    private uint GetTimeSyncMilliseconds()
    {
        long elapsedMilliseconds = Stopwatch.GetElapsedTime(_timeBaseStopwatchTimestamp).Ticks /
                                   TimeSpan.TicksPerMillisecond;
        return unchecked((uint)(_timeBaseFileTimeMilliseconds + elapsedMilliseconds));
    }

    private static async Task<byte[]?> ReadEncryptedTransportFrameAsync(Stream stream, Salsa20 cipher, CancellationToken ct)
    {
        byte[] encryptedHeader = new byte[TransportFrame.HeaderSize];
        int first = await stream.ReadAsync(encryptedHeader.AsMemory(0, 1), ct);
        if (first == 0) return null;
        await stream.ReadExactlyAsync(encryptedHeader.AsMemory(1), ct);

        byte[] header = new byte[TransportFrame.HeaderSize];
        cipher.Process(encryptedHeader, header);
        int length = BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(1, 4));
        if (length < TransportFrame.HeaderSize || length > TransportFrame.MaximumSize)
            throw new InvalidDataException("Invalid encrypted transport frame length.");

        byte[] frame = new byte[length];
        header.CopyTo(frame, 0);
        if (length > TransportFrame.HeaderSize)
        {
            byte[] encryptedPayload = new byte[length - TransportFrame.HeaderSize];
            await stream.ReadExactlyAsync(encryptedPayload, ct);
            cipher.Process(encryptedPayload, frame.AsSpan(TransportFrame.HeaderSize));
            CryptographicOperations.ZeroMemory(encryptedPayload);
        }
        CryptographicOperations.ZeroMemory(encryptedHeader);
        CryptographicOperations.ZeroMemory(header);

        // Reuse the established checksum validation without exposing any body.
        using var parser = new MemoryStream(frame, writable: false);
        byte[]? validated;
        try { validated = await TransportFrame.ReadAsync(parser, ct); }
        catch (InvalidDataException ex)
        {
            throw new InvalidDataException($"{ex.Message} Decrypted header={Convert.ToHexString(frame.AsSpan(0, TransportFrame.HeaderSize))}.", ex);
        }
        if (validated is null) throw new InvalidDataException("Missing decrypted transport frame.");
        CryptographicOperations.ZeroMemory(frame);
        return validated;
    }
}
