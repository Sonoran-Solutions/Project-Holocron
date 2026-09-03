using System.IO;
using Holocron.Common.Protocol;
using Holocron.World.Characters;
using Holocron.World.Network;
using Xunit;

namespace Holocron.Tests;

public class CharacterSaveTests
{
    [Fact]
    public void CharacterSaveManager_HasPreMadeLevel80Characters()
    {
        var manager = new CharacterSaveManager();

        Assert.True(manager.Characters.Count >= 6);

        foreach (var c in manager.Characters)
        {
            Assert.Equal(80u, c.Level);
            Assert.True(c.MaxHealth >= 30000.0f, $"Character {c.Name} should have endgame health pool");
            Assert.NotEmpty(c.Gear);
            Assert.True(c.TotalArmorRating > 500.0f, $"Character {c.Name} should be wearing high-tier armor");
        }

        // Verify flashpoint shortcut character
        var btWarrior = manager.GetCharacterByGuid(80005);
        Assert.NotNull(btWarrior);
        Assert.Equal("Darth Vindicator", btWarrior.Name);
        Assert.Equal("black_talon", btWarrior.AreaFqid);
    }

    [Fact]
    public async Task WorldPacketDispatcher_DeliversLevel80Characters_AndSelectsInstantSave()
    {
        using var memoryStream = new MemoryStream();
        var session = new WorldSession(memoryStream);
        var dispatcher = new WorldPacketDispatcher();

        // 1. Request Character List
        var listReq = new PacketWriter(Opcode.CMSG_CHARACTER_LIST).ToByteArray();
        await dispatcher.DispatchAsync(session, listReq);

        Assert.Equal(SessionState.InCharacterSelect, session.State);
        Assert.Contains(Opcode.SMSG_CHARACTER_LIST, session.SentPacketOpcodes);

        // 2. Select Level 80 Flashpoint Character (Darth Vindicator - Guid 80005)
        var selectReq = new PacketWriter(Opcode.CMSG_CHARACTER_SELECT).WriteUInt64(80005).ToByteArray();
        await dispatcher.DispatchAsync(session, selectReq);

        Assert.Equal(SessionState.InWorld, session.State);
        Assert.NotNull(session.ActiveCharacter);
        Assert.Equal(80005UL, session.ActiveCharacter.Id);
        Assert.Equal("Darth Vindicator", session.ActiveCharacter.Name);
        Assert.Equal(80u, session.ActiveCharacter.Level);
        Assert.Equal("black_talon", session.CurrentAreaFqid);
        Assert.Contains(Opcode.SMSG_CHARACTER_SELECTED, session.SentPacketOpcodes);
        Assert.Contains(Opcode.SMSG_TRAVEL_PENDING, session.SentPacketOpcodes);
    }
}
