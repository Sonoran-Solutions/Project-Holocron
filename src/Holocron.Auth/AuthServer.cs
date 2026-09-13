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
    // Client -> server login request message id. Recovered after transport
    // decompression; the client's own serializer writes this exact constant
    // (0x14045BAC4) together with the wildcard route pair 0xFFFF/0xFFFF.
    private const uint ClientLoginRequestMessage = 0xA609E6A7;

    // Server -> client login reply and game launch reply. These come from the
    // omega::ServerProxy receive callback 0x14045A1C0, which dispatches them to
    // LoginRequestIFace and AuthorizationReplyIFace respectively.
    private const uint LoginReplyMessage = 0xD4BA5CCD;
    private const uint GameLaunchReplyMessage = 0x90F2D04D;

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
    private readonly bool _probeIdBootstrap;
    private readonly long _timeBaseFileTimeMilliseconds;
    private readonly long _timeBaseStopwatchTimestamp;

    public AuthServer(int port = 7979, string worldHost = "127.0.0.1", int worldPort = 20061,
        RSA? testKey = null, bool handshakeOnly = false, bool capturePostHandshake = false,
        bool probeLoginReplyEnvelope = false, bool probeIdBootstrap = false)
    {
        _port = port;
        _worldHost = worldHost;
        _worldPort = worldPort;
        _testKey = testKey;
        _handshakeOnly = handshakeOnly;
        _capturePostHandshake = capturePostHandshake;
        _probeLoginReplyEnvelope = probeLoginReplyEnvelope;
        _probeIdBootstrap = probeIdBootstrap;
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

            // Step 2: Read CMSG_HANDSHAKE. The key exchange is not encrypted.
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

            // One transport implementation for every higher-level behavior: the
            // session codec owns the Salsa20 stream state and the per-connection
            // Zstandard contexts that retail keeps for the connection lifetime.
            using var codec = new TransportCodec(
                stream,
                new Salsa20(sessionKeys.ClientToServerKey, sessionKeys.ClientToServerIv),
                new Salsa20(sessionKeys.ServerToClientKey, sessionKeys.ServerToClientIv));
            CryptographicOperations.ZeroMemory(sessionKeys.ServerToClientKey);
            CryptographicOperations.ZeroMemory(sessionKeys.ClientToServerKey);
            CryptographicOperations.ZeroMemory(sessionKeys.ServerToClientIv);
            CryptographicOperations.ZeroMemory(sessionKeys.ClientToServerIv);
            Console.WriteLine($"[AUTH] RSA envelope and historical key-field layout validated for {endpoint}.");

            if (_handshakeOnly)
            {
                if (_probeIdBootstrap)
                {
                    await ProbeIdBootstrapAsync(codec, endpoint, ct);
                    return;
                }
                if (_probeLoginReplyEnvelope)
                {
                    await ProbeLoginReplyEnvelopeAsync(codec, endpoint, ct);
                    return;
                }
                if (_capturePostHandshake)
                {
                    await CapturePostHandshakeAsync(codec, endpoint, ct);
                    return;
                }
                Console.WriteLine("[AUTH] Handshake-only probe complete; closing without speculative application replies.");
                return;
            }

            // Generate ephemeral session ServerId token
            string serverIdToken = Guid.NewGuid().ToString("N")[..16];

            // Serve session loop
            while (!ct.IsCancellationRequested)
            {
                TransportMessage? message = await codec.ReadAsync(ct);
                if (message is null) break;

                byte[] payload = message.Value.Payload;
                if (payload.Length < 4)
                {
                    Console.WriteLine($"[AUTH] Ignoring short transport payload ({payload.Length} bytes, type 0x{message.Value.Type:X2}).");
                    continue;
                }

                uint opcode = BinaryPrimitives.ReadUInt32LittleEndian(payload);

                switch ((Opcode)opcode)
                {
                    case Opcode.CMSG_PING:
                    {
                        var pingReply = new PacketWriter(Opcode.SMSG_PING);
                        await codec.WriteAsync(0, pingReply.ToByteArray(), ct);
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
                        await codec.WriteAsync(0, sigReply.ToByteArray(), ct);
                        break;
                    }

                    case Opcode.CMSG_REQUEST_INTRODUCE_CONNECTION:
                    {
                        Console.WriteLine($"[AUTH] Handing off client to World Server: {_worldHost}:{_worldPort}");
                        var introReply = new PacketWriter(Opcode.SMSG_REQUEST_INTRODUCE_CONNECTION)
                            .WriteString($"{_worldHost}:{_worldPort}")
                            .WriteString(serverIdToken);
                        await codec.WriteAsync(0, introReply.ToByteArray(), ct);
                        break;
                    }

                    case Opcode.CMSG_REQUEST_CLOSE:
                        Console.WriteLine($"[AUTH] Client requested graceful disconnect.");
                        return;

                    default:
                        Console.WriteLine($"[AUTH] Unhandled opcode: 0x{opcode:X8} ({payload.Length} bytes, transport type 0x{message.Value.Type:X2})");
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

    /// <summary>
    /// Bounded login-reply probe. Reads one routed application frame through the
    /// shared codec, so the dispatch envelope is taken from the decompressed
    /// logical payload exactly as the retail receiver does.
    /// </summary>
    private async Task ProbeLoginReplyEnvelopeAsync(TransportCodec codec, string endpoint, CancellationToken ct)
    {
        TransportMessage? request = await codec.ReadAsync(ct);
        if (request is null)
        {
            Console.WriteLine("[AUTH] Client closed without a post-handshake message.");
            return;
        }

        if (request.Value.Type != 0 || request.Value.Payload.Length < 8)
            throw new InvalidDataException("Expected a routed application frame with an 8-byte dispatch envelope.");

        byte[] envelope = request.Value.Payload;
        uint messageId = BinaryPrimitives.ReadUInt32LittleEndian(envelope);
        ushort routeA = BinaryPrimitives.ReadUInt16LittleEndian(envelope.AsSpan(4));
        ushort routeB = BinaryPrimitives.ReadUInt16LittleEndian(envelope.AsSpan(6));
        Console.WriteLine($"[AUTH] Received routed client request: logical={envelope.Length} bytes, message=0x{messageId:X8}, route=0x{routeA:X4}/0x{routeB:X4}.");

        if (messageId != ClientLoginRequestMessage)
            Console.WriteLine($"[AUTH] WARNING: expected client login request 0x{ClientLoginRequestMessage:X8}, received 0x{messageId:X8}; replying on the observed route pair.");

        // Full canonical configuration grounded in static disassembly and historical evidence:
        // - useSyncClock="true" enables the synchronized clock service.
        // - loglevel="debug" sets client logging severity.
        // - additionalClientConfigs contains the currently tested client identifiers. Static analysis found a
        //   null-unsafe username lookup in HandleInitialized, but process-lifetime evidence disproves that
        //   dereference as the active cause of the observed Auth-socket close.
        // - access-rights provides client and network subnet declarations parsed by HandleInitialized.
        byte[] initializationDocument = "<client title=\"Test Client\" useSyncClock=\"true\" loglevel=\"debug\" additionalClientConfigs=\"username=local-test;WorldName=he1012;SHARD_PUBLIC_NAME=he1012;\"><access-rights><client name=\"Automaton.exe\"><network name=\"BWA\" address=\"10.2.0.0/15\"/></client></access-rights></client>"u8.ToArray();
        int encodedStringLength = initializationDocument.Length + 1;
        byte[] replyEnvelope = new byte[16 + encodedStringLength];
        BinaryPrimitives.WriteUInt32LittleEndian(replyEnvelope, LoginReplyMessage);
        // The observed client request uses the wildcard route pair 0xFFFF/0xFFFF,
        // where word order is not observable. Echo the observed pair.
        BinaryPrimitives.WriteUInt16LittleEndian(replyEnvelope.AsSpan(4), routeA);
        BinaryPrimitives.WriteUInt16LittleEndian(replyEnvelope.AsSpan(6), routeB);
        // Body: u32 status = 0; u32 byte length including the terminal NUL;
        // UTF-8 XML bytes; terminal NUL (provided by the zero-initialized array).
        BinaryPrimitives.WriteUInt32LittleEndian(replyEnvelope.AsSpan(12), (uint)encodedStringLength);
        initializationDocument.CopyTo(replyEnvelope.AsSpan(16));

        await codec.WriteAsync(0, replyEnvelope, ct);
        Console.WriteLine($"[AUTH] Sent login-reply envelope (message=0x{LoginReplyMessage:X8}, route=0x{routeA:X4}/0x{routeB:X4}, body={replyEnvelope.Length - 8} bytes) to {endpoint}.");
        CryptographicOperations.ZeroMemory(replyEnvelope);

        // Immediate game launch reply (0x90F2D04D).
        // Retail client evidence confirms that ServerProxy::ReplyGameLaunch (0x90F2D04D)
        // arrives alongside or immediately following D4. It supplies the World shard address and clears
        // [ServerProxy + 0x78]. If the connection closes before 0x90F2D04D arrives, ServerProxy::OnDisconnect (0x140427170)
        // triggers HandleLaunchFailure(1003). Type 0x01 is on an independent 10-second background timer and must NOT gate 0x90F2D04D.
        byte[] gameAddress = Encoding.UTF8.GetBytes($"{_worldHost}:{_worldPort}");
        int encodedAddressLength = gameAddress.Length + 1;
        int secondStringLengthOffset = 12 + encodedAddressLength;
        byte[] launchEnvelope = new byte[secondStringLengthOffset + sizeof(uint) + 1];
        BinaryPrimitives.WriteUInt32LittleEndian(launchEnvelope, GameLaunchReplyMessage);
        BinaryPrimitives.WriteUInt16LittleEndian(launchEnvelope.AsSpan(4), routeA);
        BinaryPrimitives.WriteUInt16LittleEndian(launchEnvelope.AsSpan(6), routeB);
        BinaryPrimitives.WriteUInt32LittleEndian(launchEnvelope.AsSpan(8), (uint)encodedAddressLength);
        gameAddress.CopyTo(launchEnvelope.AsSpan(12));
        BinaryPrimitives.WriteUInt32LittleEndian(launchEnvelope.AsSpan(secondStringLengthOffset), 1);

        await codec.WriteAsync(0, launchEnvelope, ct);
        Console.WriteLine($"[AUTH] Sent game-launch reply (message=0x{GameLaunchReplyMessage:X8}, route=0x{routeA:X4}/0x{routeB:X4}, address={_worldHost}:{_worldPort}, second-string=empty) to {endpoint}.");
        CryptographicOperations.ZeroMemory(launchEnvelope);
        CryptographicOperations.ZeroMemory(gameAddress);

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(5));
        try
        {
            while (!timeout.Token.IsCancellationRequested)
            {
                TransportMessage? next = await codec.ReadAsync(timeout.Token);
                if (next is null)
                {
                    Console.WriteLine("[AUTH] Client closed connection after launch reply.");
                    break;
                }

                if (next.Value.Type == TransportTimeSync.RequestType &&
                    next.Value.Payload.Length == TransportTimeSync.RequestPayloadSize)
                {
                    ulong sequence = TransportTimeSync.ReadRequestSequencePayload(next.Value.Payload);
                    Console.WriteLine($"[AUTH] Client advanced with transport time request: type=0x01, length={next.Value.Payload.Length}, sequence=0x{sequence:X16}.");

                    uint localTimeMilliseconds = GetTimeSyncMilliseconds();
                    byte[] controlPayload = TransportTimeSync.EncodeBaseResponsePayload(sequence, localTimeMilliseconds);
                    await codec.WriteAsync(TransportTimeSync.ResponseType, controlPayload, timeout.Token);
                    Console.WriteLine($"[AUTH] Sent base-only transport time response: type=0x02, payload={controlPayload.Length}, sequence=0x{sequence:X16}, count=1, local-ms=0x{localTimeMilliseconds:X8}.");
                    CryptographicOperations.ZeroMemory(controlPayload);
                }
                else
                {
                    Console.WriteLine($"[AUTH] Client sent post-launch frame: type=0x{next.Value.Type:X2}, logical-length={next.Value.Payload.Length}.");
                }
            }
        }
        catch (OperationCanceledException)
        {
            Console.WriteLine("[AUTH] Post-launch listen window completed.");
        }
    }

    /// <summary>
    /// Minimal falsifiable bootstrap experiment. The client's first global
    /// request is answered with exactly one message - the reply its own binary
    /// pairs with that request - and the server then only listens, so whatever
    /// the client sends next is new behavioural evidence and not a reaction to
    /// anything else we invented.
    /// </summary>
    private async Task ProbeIdBootstrapAsync(TransportCodec codec, string endpoint, CancellationToken ct)
    {
        TransportMessage? request = await codec.ReadAsync(ct);
        if (request is null)
        {
            Console.WriteLine("[AUTH] Client closed without a post-handshake message.");
            return;
        }

        byte[] body = request.Value.Payload;
        uint messageId = body.Length >= 8 ? BinaryPrimitives.ReadUInt32LittleEndian(body) : 0u;
        Console.WriteLine($"[AUTH] Bootstrap request: transport-type=0x{request.Value.Type:X2}, logical={body.Length} bytes, message=0x{messageId:X8}.");

        if (messageId != IdentificationExchange.RequestIdSignature || body.Length <= 8)
        {
            Console.WriteLine($"[AUTH] Not the expected global request; stopping without replying.");
            return;
        }

        (string shardName, ulong correlation) = IdentificationExchange.ReadRequestIdSignature(body.AsSpan(8));
        Console.WriteLine($"[AUTH] RequestIDSignature: name=\"{shardName}\", correlation=0x{correlation:X16}.");

        // The reply's body word is the server-assigned object id. 0xFFFF is
        // the "no object assigned" sentinel: the client takes it, performs a
        // connection state transition at 0x1404123D0(connection, 2, 3) and
        // returns without introducing the connection. The three strings are
        // parsed and released by this handler and are not passed to the builder
        // at 0x14042D320, so they are sent as the parser-valid empty encoding
        // rather than inventing values. The u64 must echo the request
        // correlation: the client looks its pending request up by that key.
        const ushort assignedObjectId = 1;
        byte[] reply = IdentificationExchange.EncodeReplyIdSignature(
            assignedObjectId, string.Empty, string.Empty, string.Empty, correlation);
        byte[] replyEnvelope = new byte[8 + reply.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(replyEnvelope, IdentificationExchange.ReplyIdSignature);
        BinaryPrimitives.WriteUInt16LittleEndian(replyEnvelope.AsSpan(4), IdentificationExchange.WildcardRouteWord);
        BinaryPrimitives.WriteUInt16LittleEndian(replyEnvelope.AsSpan(6), IdentificationExchange.WildcardRouteWord);
        reply.CopyTo(replyEnvelope.AsSpan(8));
        await codec.WriteAsync(0, replyEnvelope, ct);
        Console.WriteLine($"[AUTH] Sent ReplyIDSignature: message=0x{IdentificationExchange.ReplyIdSignature:X8}, route=0xFFFF/0xFFFF, assigned-object-id=0x{assignedObjectId:X4}, correlation=0x{correlation:X16}, logical={replyEnvelope.Length} bytes.");

        // Listen only until the client introduces its connection.
        using var window = CancellationTokenSource.CreateLinkedTokenSource(ct);
        window.CancelAfter(TimeSpan.FromSeconds(20));
        IdentificationExchange.IntroduceConnection? introduced = null;
        try
        {
            while (!window.Token.IsCancellationRequested && introduced is null)
            {
                TransportMessage? next = await codec.ReadAsync(window.Token);
                if (next is null)
                {
                    Console.WriteLine("[AUTH] Client closed the connection.");
                    return;
                }

                byte[] payload = next.Value.Payload;
                uint nextId = payload.Length >= 4 ? BinaryPrimitives.ReadUInt32LittleEndian(payload) : 0u;
                if (nextId == IdentificationExchange.IntroduceConnectionSignature && payload.Length > 8)
                {
                    IdentificationExchange.IntroduceConnection parsed =
                        IdentificationExchange.ReadIntroduceConnection(payload.AsSpan(8));
                    introduced = parsed;
                    Console.WriteLine($"[AUTH] IntroduceConnectionSignature received: client-object-id=0x{parsed.ClientObjectId:X4}, reply-word=0x{parsed.ReplyRouteWord:X4}, name=\"{parsed.Name}\", class=\"{parsed.ClassName}\", interfaces=\"{parsed.Interfaces}\", value=0x{parsed.Value:X16}, logical={payload.Length} bytes.");
                    break;
                }

                Console.WriteLine($"[AUTH] Client follow-up: transport-type=0x{next.Value.Type:X2}, logical={payload.Length} bytes, message=0x{nextId:X8}, body={Convert.ToHexString(payload.AsSpan(0, Math.Min(payload.Length, 48)))}.");
            }
        }
        catch (OperationCanceledException)
        {
            Console.WriteLine("[AUTH] Bootstrap observation window completed with no IntroduceConnectionSignature.");
        }

        if (introduced is null)
        {
            Console.WriteLine("[AUTH] No routed endpoint was registered; not sending any routed application message.");
            return;
        }

        // Control mode: the client registers its OWN receive entry when it
        // sends this message (0x14042C782 sets Connection+0x60 from the reply
        // word), so an incoming IntroduceConnection is not required for the
        // client to be reachable. Unless explicitly enabled, send nothing
        // further and only observe, so the next packet cannot be confounded.
        if (Environment.GetEnvironmentVariable("HOLOCRON_BOOTSTRAP_SEND_D4") is null)
        {
            Console.WriteLine("[AUTH] Control mode: no mirror and no D4 sent; observing only.");
            using var control = CancellationTokenSource.CreateLinkedTokenSource(ct);
            control.CancelAfter(TimeSpan.FromSeconds(20));
            try
            {
                while (!control.Token.IsCancellationRequested)
                {
                    TransportMessage? next = await codec.ReadAsync(control.Token);
                    if (next is null)
                    {
                        Console.WriteLine("[AUTH] Client closed the connection during the control window.");
                        return;
                    }
                    byte[] payload = next.Value.Payload;
                    uint id = payload.Length >= 4 ? BinaryPrimitives.ReadUInt32LittleEndian(payload) : 0u;
                    Console.WriteLine($"[AUTH] Control-window frame: transport-type=0x{next.Value.Type:X2}, logical={payload.Length} bytes, message=0x{id:X8}.");
                }
                Console.WriteLine("[AUTH] Control window completed with the connection still open.");
            }
            catch (OperationCanceledException)
            {
                Console.WriteLine("[AUTH] Control window completed with the connection still open.");
            }
            return;
        }

        // The client registered nothing on our side yet, so mirror the
        // handshake back on the wildcard route and only then address the client
        // on the swapped pair it will have registered.
        (ushort peerFirst, ushort peerSecond) = introduced.Value.PeerEnvelopeRoute;
        Console.WriteLine($"[AUTH] Derived routed envelope pair for server->client traffic: 0x{peerFirst:X4}/0x{peerSecond:X4}.");

        byte[] mirror = IdentificationExchange.EncodeIntroduceConnection(
            introduced.Value.ReplyRouteWord, introduced.Value.ClientObjectId,
            string.Empty, string.Empty, string.Empty, introduced.Value.Value);
        byte[] mirrorEnvelope = new byte[8 + mirror.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(mirrorEnvelope, IdentificationExchange.IntroduceConnectionSignature);
        BinaryPrimitives.WriteUInt16LittleEndian(mirrorEnvelope.AsSpan(4), IdentificationExchange.WildcardRouteWord);
        BinaryPrimitives.WriteUInt16LittleEndian(mirrorEnvelope.AsSpan(6), IdentificationExchange.WildcardRouteWord);
        mirror.CopyTo(mirrorEnvelope.AsSpan(8));
        await codec.WriteAsync(0, mirrorEnvelope, ct);
        Console.WriteLine($"[AUTH] Sent mirror IntroduceConnectionSignature on 0xFFFF/0xFFFF to register the client-side entry.");

        // Exactly one routed D4 on the derived pair, with the frozen D4 body.
        byte[] initializationDocument = "<client title=\"Test Client\" useSyncClock=\"true\" loglevel=\"debug\" additionalClientConfigs=\"username=local-test;WorldName=he1012;SHARD_PUBLIC_NAME=he1012;\"><access-rights><client name=\"Automaton.exe\"><network name=\"BWA\" address=\"10.2.0.0/15\"/></client></access-rights></client>"u8.ToArray();
        byte[] d4 = new byte[16 + initializationDocument.Length + 1];
        BinaryPrimitives.WriteUInt32LittleEndian(d4, LoginReplyMessage);
        BinaryPrimitives.WriteUInt16LittleEndian(d4.AsSpan(4), peerFirst);
        BinaryPrimitives.WriteUInt16LittleEndian(d4.AsSpan(6), peerSecond);
        BinaryPrimitives.WriteUInt32LittleEndian(d4.AsSpan(12), (uint)(initializationDocument.Length + 1));
        initializationDocument.CopyTo(d4.AsSpan(16));
        await codec.WriteAsync(0, d4, ct);
        Console.WriteLine($"[AUTH] Sent one routed D4 on 0x{peerFirst:X4}/0x{peerSecond:X4}, message=0x{LoginReplyMessage:X8}, logical={d4.Length} bytes.");
        CryptographicOperations.ZeroMemory(d4);

        using var tail = CancellationTokenSource.CreateLinkedTokenSource(ct);
        tail.CancelAfter(TimeSpan.FromSeconds(10));
        try
        {
            while (!tail.Token.IsCancellationRequested)
            {
                TransportMessage? next = await codec.ReadAsync(tail.Token);
                if (next is null)
                {
                    Console.WriteLine("[AUTH] Client closed the connection after the routed D4.");
                    break;
                }
                byte[] payload = next.Value.Payload;
                uint nextId = payload.Length >= 4 ? BinaryPrimitives.ReadUInt32LittleEndian(payload) : 0u;
                Console.WriteLine($"[AUTH] Post-D4 client frame: transport-type=0x{next.Value.Type:X2}, logical={payload.Length} bytes, message=0x{nextId:X8}.");
            }
        }
        catch (OperationCanceledException)
        {
            Console.WriteLine("[AUTH] Post-D4 observation window completed.");
        }
    }

    /// <summary>Bounded diagnostic: decodes one post-handshake frame through the
    /// shared codec and reports only structural facts, never payload contents.</summary>
    private async Task CapturePostHandshakeAsync(TransportCodec codec, string endpoint, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(3));
        try
        {
            TransportMessage? message = await codec.ReadAsync(timeout.Token);
            if (message is null)
            {
                Console.WriteLine("[AUTH] Client closed without a post-handshake message.");
                return;
            }

            byte[] payload = message.Value.Payload;
            string digest = Convert.ToHexString(SHA256.HashData(payload));
            Console.WriteLine($"[AUTH] Post-handshake frame from {endpoint}: transport-type=0x{message.Value.Type:X2}, logical-length={payload.Length}, logical-sha256={digest}{(payload.Length >= 8 ? $", message=0x{BinaryPrimitives.ReadUInt32LittleEndian(payload):X8}, route=0x{BinaryPrimitives.ReadUInt16LittleEndian(payload.AsSpan(4)):X4}/0x{BinaryPrimitives.ReadUInt16LittleEndian(payload.AsSpan(6)):X4}" : string.Empty)}.");
        }
        catch (OperationCanceledException)
        {
            Console.WriteLine("[AUTH] No post-handshake client bytes before timeout; client is waiting for a server message.");
        }
    }

    private uint GetTimeSyncMilliseconds()
    {
        long elapsedMilliseconds = Stopwatch.GetElapsedTime(_timeBaseStopwatchTimestamp).Ticks /
                                   TimeSpan.TicksPerMillisecond;
        return unchecked((uint)(_timeBaseFileTimeMilliseconds + elapsedMilliseconds));
    }
}
