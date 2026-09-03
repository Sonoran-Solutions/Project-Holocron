using System.IO;
using DotRecast.Core.Numerics;
using Holocron.Common.Area;
using Holocron.Common.Navigation;
using Holocron.Common.Protocol;
using Holocron.World.AI;
using Holocron.World.Area;
using Holocron.World.Combat;
using Holocron.World.Navigation;
using Holocron.World.Network;
using Xunit;

namespace Holocron.Tests;

public class WorldSessionTests
{
    [Fact]
    public async Task WorldSession_FullLoginAndStreamingLifecycle()
    {
        using var memoryStream = new MemoryStream();
        var session = new WorldSession(memoryStream);
        var dispatcher = new WorldPacketDispatcher();

        // 1. Initial Handshake & Configuration
        await session.SendHandshakeAsync();
        await session.SendClientConfigurationAsync();

        Assert.Contains(Opcode.SMSG_HANDSHAKE, session.SentPacketOpcodes);
        Assert.Contains(Opcode.SMSG_CLIENT_INFORMATION, session.SentPacketOpcodes);
        Assert.Contains(Opcode.SMSG_NOTIFY_GAUNTLET_VERSION, session.SentPacketOpcodes);
        Assert.Contains(Opcode.SMSG_AWARENESS_RANGE, session.SentPacketOpcodes);

        // 2. Client Requests Character List (CMSG_CHARACTER_LIST)
        var charListReq = new PacketWriter(Opcode.CMSG_CHARACTER_LIST).ToByteArray();
        await dispatcher.DispatchAsync(session, charListReq);

        Assert.Equal(SessionState.InCharacterSelect, session.State);
        Assert.Contains(Opcode.SMSG_CHARACTER_LIST, session.SentPacketOpcodes);

        // 3. Client Selects Character (CMSG_CHARACTER_SELECT)
        var charSelectReq = new PacketWriter(Opcode.CMSG_CHARACTER_SELECT).WriteUInt64(10001).ToByteArray();
        await dispatcher.DispatchAsync(session, charSelectReq);

        Assert.Equal(SessionState.InWorld, session.State);
        Assert.NotNull(session.ActiveCharacter);
        Assert.Equal("HeroOfTython", session.ActiveCharacter.Name);
        Assert.Equal("tython_main", session.CurrentAreaFqid);
        Assert.Contains(Opcode.SMSG_CHARACTER_SELECTED, session.SentPacketOpcodes);
        Assert.Contains(Opcode.SMSG_TRAVEL_PENDING, session.SentPacketOpcodes);
        Assert.Contains(Opcode.SMSG_TRAVEL_STATUS, session.SentPacketOpcodes);

        // 4. Stream World Creature Spawns
        var tpl = new CreatureTemplate { Entry = 1, Name = "Flesh Raider Scout", MinLevel = 2, MaxLevel = 2, MaxHealth = 120, Faction = 3 };
        var spawn = new SpawnDefinition { Id = 9901, PosX = 10, PosY = 0, PosZ = 10, Template = tpl };
        var creature = new CreatureInstance(9901, spawn);

        await session.StreamCreaturesAsync(new[] { creature });
        Assert.Contains(9901UL, session.KnownEntities);
        Assert.Contains(Opcode.SMSG_SPAWN_OBJECT, session.SentPacketOpcodes);

        // Streaming again should deduplicate
        int countBefore = session.SentPacketOpcodes.Count(op => op == Opcode.SMSG_SPAWN_OBJECT);
        await session.StreamCreaturesAsync(new[] { creature });
        int countAfter = session.SentPacketOpcodes.Count(op => op == Opcode.SMSG_SPAWN_OBJECT);
        Assert.Equal(countBefore, countAfter);

        // 5. Stream Companion Bot
        var navMesh = NavMeshService.CreatePlane(-20, -20, 20, 20, 0);
        var botEntity = new CombatEntity { Guid = 7701, Name = "T7-01", CurrentHealth = 400, MaxHealth = 400 };
        var companionBot = new BotAgent(botEntity, navMesh, BotRole.Tank);

        await session.StreamCompanionBotsAsync(new[] { companionBot });
        Assert.Contains(7701UL, session.KnownEntities);

        // 6. Broadcast Movement Update
        await session.SendMovementUpdateAsync(7701, new RcVec3f(5, 0, 5), MovementType.Follow);
        Assert.Contains(Opcode.SMSG_MOVEMENT_UPDATE, session.SentPacketOpcodes);
    }
}
