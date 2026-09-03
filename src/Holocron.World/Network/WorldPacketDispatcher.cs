using Holocron.Common.Protocol;

namespace Holocron.World.Network;

/// <summary>
/// Dispatches incoming client packets to registered handler logic based on HeroEngine opcodes.
/// </summary>
public sealed class WorldPacketDispatcher
{
    private readonly Dictionary<Opcode, Func<WorldSession, PacketReader, Task>> _handlers = new();

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
            // Default sample starting character for Project Holocron
            var defaultChar = new CharacterSummary
            {
                Id = 10001,
                Name = "HeroOfTython",
                ClassId = 1, // Jedi Knight
                Level = 1,
                AreaFqid = "tython_main"
            };

            await session.SendCharacterListAsync(new[] { defaultChar });
        });

        Register(Opcode.CMSG_CHARACTER_SELECT, async (session, reader) =>
        {
            ulong charId = reader.RemainingBytes >= 8 ? reader.ReadUInt64() : 10001;
            var selectedChar = new CharacterSummary
            {
                Id = charId,
                Name = "HeroOfTython",
                ClassId = 1,
                Level = 1,
                AreaFqid = "tython_main"
            };

            await session.SelectCharacterAsync(selectedChar);
        });
    }
}
