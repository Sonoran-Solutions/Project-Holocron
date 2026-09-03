using Holocron.Common.Protocol;
using Holocron.World.Characters;

namespace Holocron.World.Network;

/// <summary>
/// Dispatches incoming client packets to registered handler logic based on HeroEngine opcodes.
/// </summary>
public sealed class WorldPacketDispatcher
{
    private readonly Dictionary<Opcode, Func<WorldSession, PacketReader, Task>> _handlers = new();
    private readonly CharacterSaveManager _saveManager = new();

    public CharacterSaveManager SaveManager => _saveManager;

    public WorldPacketDispatcher()
    {
        RegisterDefaultHandlers();
    }

    public void Register(Opcode opcode, Func<WorldSession, PacketReader, Task> handler)
    {
        _handlers[opcode] = handler;
    }

    public async Task DispatchAsync(WorldSession session, byte[] packetData, CancellationToken ct = default)
    {
        var reader = new PacketReader(packetData);
        var opcode = reader.Opcode;

        if (_handlers.TryGetValue(opcode, out var handler))
        {
            await handler(session, reader);
        }
        else
        {
            Console.WriteLine($"[WORLD] Unhandled Opcode: {opcode} (0x{(uint)opcode:X})");
        }
    }

    private void RegisterDefaultHandlers()
    {
        Register(Opcode.CMSG_PING, async (session, reader) =>
        {
            var pingReply = new PacketWriter(Opcode.SMSG_PING);
            await session.SendPacketAsync(pingReply);
        });

        Register(Opcode.CMSG_HANDSHAKE, async (session, reader) =>
        {
            session.State = SessionState.Authenticated;
            await session.SendClientConfigurationAsync();
        });

        Register(Opcode.CMSG_CHARACTER_LIST, async (session, reader) =>
        {
            // Present full roster of pre-made high-level test saves
            var summaries = _saveManager.Characters.Select(c => new CharacterSummary
            {
                Id = c.Guid,
                Name = c.Name,
                ClassId = c.ClassId,
                Level = c.Level,
                AreaFqid = c.AreaFqid,
                Position = c.SpawnPosition
            }).ToList();

            Console.WriteLine($"[WORLD] Serving {summaries.Count} pre-made Level 80 characters to client");
            await session.SendCharacterListAsync(summaries);
        });

        Register(Opcode.CMSG_CHARACTER_SELECT, async (session, reader) =>
        {
            ulong charId = reader.RemainingBytes >= 8 ? reader.ReadUInt64() : 80001;
            var character = _saveManager.GetCharacterByGuid(charId) ?? _saveManager.Characters.First();

            var selectedSummary = new CharacterSummary
            {
                Id = character.Guid,
                Name = character.Name,
                ClassId = character.ClassId,
                Level = character.Level,
                AreaFqid = character.AreaFqid,
                Position = character.SpawnPosition
            };

            Console.WriteLine($"[WORLD] Selected character: {character.Name} (Lvl {character.Level} {character.AdvancedClassName}) -> Zoning to {character.AreaName} [{character.AreaFqid}]");
            await session.SelectCharacterAsync(selectedSummary);
        });
    }
}
