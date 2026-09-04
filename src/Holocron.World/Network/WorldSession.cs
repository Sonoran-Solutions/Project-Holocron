using System.Buffers.Binary;
using System.Net.Sockets;
using DotRecast.Core.Numerics;
using Holocron.Common.Crypto;
using Holocron.Common.Protocol;
using Holocron.World.AI;
using Holocron.World.Area;
using Holocron.World.Combat;
using Holocron.World.Navigation;

namespace Holocron.World.Network;

public enum SessionState
{
    Handshaking,
    Authenticated,
    InCharacterSelect,
    LoadingWorld,
    InWorld,
    Disconnected
}

public sealed class CharacterSummary
{
    public ulong Id { get; init; }
    public string Name { get; init; } = string.Empty;
    public uint ClassId { get; init; }
    public uint Level { get; init; } = 1;
    public string AreaFqid { get; init; } = "tython_main";
    public RcVec3f Position { get; init; } = new(0, 0, 0);
}

/// <summary>
/// Manages an individual player connection session to the World Shard.
/// Handles encryption, character lifecycle, area zoning, and real-time entity visibility streaming.
/// </summary>
public sealed class WorldSession
{
    private readonly Stream _stream;
    private readonly Salsa20? _cipher;
    private readonly object _sendLock = new();

    public ulong AccountId { get; set; }
    public SessionState State { get; set; } = SessionState.Handshaking;
    public CharacterSummary? ActiveCharacter { get; private set; }
    public string CurrentAreaFqid { get; private set; } = string.Empty;

    // Track visible entity GUIDs sent to the client
    public HashSet<ulong> KnownEntities { get; } = new();

    // In-memory packet log for testing and verification
    public List<Opcode> SentPacketOpcodes { get; } = new();

    public WorldSession(Stream stream, Salsa20? cipher = null)
    {
        _stream = stream ?? throw new ArgumentNullException(nameof(stream));
        _cipher = cipher;
    }

    public async Task SendPacketAsync(PacketWriter writer, CancellationToken ct = default)
    {
        byte[] payload = writer.ToByteArray();
        lock (_sendLock)
        {
            SentPacketOpcodes.Add(writer.Opcode);
        }

        if (_cipher != null)
        {
            // Encrypt packet payload with Salsa20 if session cipher is active
            _cipher.Process(payload, payload);
        }

        await _stream.WriteAsync(payload, ct);
        await _stream.FlushAsync(ct);
    }

    public async Task SendHandshakeAsync(CancellationToken ct = default)
    {
        var handshake = new PacketWriter(Opcode.SMSG_HANDSHAKE)
            .WriteUInt64(0x14AA63E353DBF459UL);

        await SendPacketAsync(handshake, ct);
    }

    public async Task SendClientConfigurationAsync(CancellationToken ct = default)
    {
        string clientInfoXml = "<ClientInformation universeID=\"holocron\" networkNapTimeMS=\"20\" CacheFilePath=\"HeroEngineCache\\Local\"/>";
        var clientInfo = new PacketWriter(Opcode.SMSG_CLIENT_INFORMATION).WriteString(clientInfoXml);
        await SendPacketAsync(clientInfo, ct);

        var gauntlet = new PacketWriter(Opcode.SMSG_NOTIFY_GAUNTLET_VERSION).WriteUInt32(0x11);
        await SendPacketAsync(gauntlet, ct);

        var awareness = new PacketWriter(Opcode.SMSG_AWARENESS_RANGE).WriteFloat(15.0f).WriteFloat(25.0f);
        await SendPacketAsync(awareness, ct);
    }

    public async Task SendCharacterListAsync(IReadOnlyList<CharacterSummary> characters, CancellationToken ct = default)
    {
        var packet = new PacketWriter(Opcode.SMSG_CHARACTER_LIST);
        packet.WriteUInt32((uint)characters.Count);

        foreach (var c in characters)
        {
            packet.WriteUInt64(c.Id);
            packet.WriteString(c.Name);
            packet.WriteUInt32(c.ClassId);
            packet.WriteUInt32(c.Level);
            packet.WriteString(c.AreaFqid);
        }

        string entitlementsXml = "<Entitlements><Entitlement id=\"7\"/><Entitlement id=\"30\"/><Entitlement id=\"39\"/><Entitlement id=\"2013\"/><Entitlement id=\"40\"/><Entitlement id=\"71\"/></Entitlements>";
        packet.WriteString(entitlementsXml);

        State = SessionState.InCharacterSelect;
        await SendPacketAsync(packet, ct);
    }

    public async Task SelectCharacterAsync(CharacterSummary character, CancellationToken ct = default)
    {
        ActiveCharacter = character;
        CurrentAreaFqid = character.AreaFqid;
        State = SessionState.LoadingWorld;

        // Acknowledge selection
        var ack = new PacketWriter(Opcode.SMSG_CHARACTER_SELECTED);
        await SendPacketAsync(ack, ct);

        // Send travel pending to area
        var travel = new PacketWriter(Opcode.SMSG_TRAVEL_PENDING)
            .WriteString(character.AreaFqid)
            .WriteString("4611686019802843831")
            .WriteString($@"\world\areas\{character.AreaFqid}\area.dat");
        await SendPacketAsync(travel, ct);

        var status = new PacketWriter(Opcode.SMSG_TRAVEL_STATUS).WriteUInt32(1);
        await SendPacketAsync(status, ct);

        State = SessionState.InWorld;
    }

    /// <summary>
    /// Streams surrounding world creature instances into the client's visibility scope.
    /// </summary>
    public async Task StreamCreaturesAsync(IEnumerable<CreatureInstance> creatures, CancellationToken ct = default)
    {
        foreach (var c in creatures)
        {
            if (KnownEntities.Contains(c.Guid)) continue;

            var spawnPacket = new PacketWriter(Opcode.SMSG_SPAWN_OBJECT)
                .WriteUInt64(c.Guid)
                .WriteString(c.Template.Name)
                .WriteUInt32((uint)c.Template.MinLevel)
                .WriteFloat(c.CurrentHealth)
                .WriteFloat(c.Template.MaxHealth)
                .WriteFloat(c.PosX)
                .WriteFloat(c.PosY)
                .WriteFloat(c.PosZ)
                .WriteUInt32(c.Template.Faction);

            KnownEntities.Add(c.Guid);
            await SendPacketAsync(spawnPacket, ct);
        }
    }

    /// <summary>
    /// Streams companion bots accompanying the player into the client's visibility scope.
    /// </summary>
    public async Task StreamCompanionBotsAsync(IEnumerable<BotAgent> bots, CancellationToken ct = default)
    {
        foreach (var bot in bots)
        {
            if (KnownEntities.Contains(bot.Entity.Guid)) continue;

            var botPacket = new PacketWriter(Opcode.SMSG_SPAWN_OBJECT)
                .WriteUInt64(bot.Entity.Guid)
                .WriteString(bot.Entity.Name)
                .WriteUInt32(10) // Level 10 Companion
                .WriteFloat(bot.Entity.CurrentHealth)
                .WriteFloat(bot.Entity.MaxHealth)
                .WriteFloat(bot.Entity.Position.X)
                .WriteFloat(bot.Entity.Position.Y)
                .WriteFloat(bot.Entity.Position.Z)
                .WriteUInt32(bot.Entity.Faction);

            KnownEntities.Add(bot.Entity.Guid);
            await SendPacketAsync(botPacket, ct);
        }
    }

    /// <summary>
    /// Broadcasts an entity position/movement update to the client.
    /// </summary>
    public async Task SendMovementUpdateAsync(ulong entityGuid, RcVec3f position, MovementType movementType, CancellationToken ct = default)
    {
        var movePacket = new PacketWriter(Opcode.SMSG_MOVEMENT_UPDATE)
            .WriteUInt64(entityGuid)
            .WriteFloat(position.X)
            .WriteFloat(position.Y)
            .WriteFloat(position.Z)
            .WriteUInt32((uint)movementType);

        await SendPacketAsync(movePacket, ct);
    }
}
