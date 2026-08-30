namespace Holocron.World.AI.Core;

/// <summary>
/// Sensory blackboard representing the bot's current game state and surrounding environment.
/// </summary>
public sealed class BotContext
{
    public ulong BotGuid { get; init; }
    public string Name { get; set; } = "Bot";
    public string ClassName { get; set; } = "Jedi Guardian";
    public string Role { get; set; } = "Tank"; // Tank, Healer, DPS

    // Stats & Resources
    public float HealthPercent { get; set; } = 1.0f;
    public float ResourcePercent { get; set; } = 1.0f; // Force, Energy, Rage, Heat
    public bool InCombat { get; set; }
    public bool IsCasting { get; set; }
    public float GlobalCooldownRemaining { get; set; }

    // Spatial State
    public float PositionX { get; set; }
    public float PositionY { get; set; }
    public float PositionZ { get; set; }

    // Target & Threat Info
    public ulong? TargetGuid { get; set; }
    public float TargetDistance { get; set; } = float.MaxValue;
    public float TargetHealthPercent { get; set; } = 1.0f;
    public bool TargetIsCastingInterruptible { get; set; }

    // Group / Party Info
    public List<PartyMemberContext> PartyMembers { get; } = new();

    public readonly Dictionary<string, (object Value, DateTime ExpiresAt)> CachedValues = new();
}

public sealed class PartyMemberContext
{
    public ulong Guid { get; init; }
    public string Name { get; init; } = string.Empty;
    public string Role { get; init; } = "DPS";
    public float HealthPercent { get; set; } = 1.0f;
    public float Distance { get; set; }
    public bool HasAggro { get; set; }
}
