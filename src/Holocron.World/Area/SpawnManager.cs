using Holocron.Common.Area;

namespace Holocron.World.Area;

/// <summary>
/// Manages runtime creature instances, aggro checks, combat updates, and respawn timers within a zone.
/// </summary>
public sealed class SpawnManager
{
    private readonly List<CreatureInstance> _creatures = new();
    private ulong _guidCounter = 100000;

    public IReadOnlyList<CreatureInstance> Creatures => _creatures;

    public void LoadSpawns(IEnumerable<SpawnDefinition> spawns)
    {
        foreach (var spawn in spawns)
        {
            var instance = new CreatureInstance(++_guidCounter, spawn);
            _creatures.Add(instance);
        }
    }

    public void Tick(float deltaSeconds, IReadOnlyList<(ulong Guid, float X, float Y, float Z)> playerPositions)
    {
        foreach (var creature in _creatures)
        {
            // 1. Handle Respawn
            if (creature.State == CreatureState.Dead)
            {
                creature.RespawnTimerRemaining -= deltaSeconds;
                if (creature.RespawnTimerRemaining <= 0)
                {
                    creature.Respawn();
                }
                continue;
            }

            // 2. Handle Aggro Detection for Idle / Hostile creatures
            if (creature.State == CreatureState.Idle && creature.Template.Faction >= 3)
            {
                foreach (var (playerGuid, px, py, pz) in playerPositions)
                {
                    float dx = creature.PosX - px;
                    float dy = creature.PosY - py;
                    float dz = creature.PosZ - pz;
                    float distSq = dx * dx + dy * dy + dz * dz;

                    float aggroSq = creature.Template.AggroRadius * creature.Template.AggroRadius;
                    if (distSq <= aggroSq)
                    {
                        creature.State = CreatureState.InCombat;
                        creature.TargetGuid = playerGuid;
                        break;
                    }
                }
            }
        }
    }
}
