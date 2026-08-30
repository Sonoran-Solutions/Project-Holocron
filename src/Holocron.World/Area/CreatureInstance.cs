using Holocron.Common.Area;

namespace Holocron.World.Area;

/// <summary>
/// Represents an active runtime creature spawned in an open world zone or instance.
/// </summary>
public sealed class CreatureInstance
{
    public ulong Guid { get; init; }
    public SpawnDefinition Spawn { get; init; }
    public CreatureTemplate Template => Spawn.Template ?? DefaultTemplate;

    public CreatureState State { get; set; } = CreatureState.Idle;
    public float CurrentHealth { get; set; }
    public float CurrentForce { get; set; }
    public float PosX { get; set; }
    public float PosY { get; set; }
    public float PosZ { get; set; }
    public float Orientation { get; set; }

    public ulong? TargetGuid { get; set; }
    public float RespawnTimerRemaining { get; set; }

    private static readonly CreatureTemplate DefaultTemplate = new()
    {
        Name = "Unknown Creature",
        MaxHealth = 100,
        MaxForce = 100,
        AggroRadius = 12.0f
    };

    public CreatureInstance(ulong guid, SpawnDefinition spawn)
    {
        Guid = guid;
        Spawn = spawn ?? throw new ArgumentNullException(nameof(spawn));
        PosX = spawn.PosX;
        PosY = spawn.PosY;
        PosZ = spawn.PosZ;
        Orientation = spawn.Orientation;
        CurrentHealth = Template.MaxHealth;
        CurrentForce = Template.MaxForce;
    }

    public void TakeDamage(float damage, ulong attackerGuid)
    {
        if (State == CreatureState.Dead) return;

        CurrentHealth -= damage;
        if (CurrentHealth <= 0)
        {
            CurrentHealth = 0;
            State = CreatureState.Dead;
            RespawnTimerRemaining = Spawn.RespawnTimeSeconds;
            TargetGuid = null;
        }
        else
        {
            State = CreatureState.InCombat;
            TargetGuid = attackerGuid;
        }
    }

    public void Respawn()
    {
        CurrentHealth = Template.MaxHealth;
        CurrentForce = Template.MaxForce;
        PosX = Spawn.PosX;
        PosY = Spawn.PosY;
        PosZ = Spawn.PosZ;
        Orientation = Spawn.Orientation;
        State = CreatureState.Idle;
        TargetGuid = null;
        RespawnTimerRemaining = 0;
    }
}
