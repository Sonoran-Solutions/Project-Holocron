namespace Holocron.Common.Combat;

/// <summary>
/// Represents an active buff, debuff, DoT, HoT, or CC applied to an entity.
/// </summary>
public sealed class Aura
{
    public uint AbilityId { get; init; }
    public string Name { get; init; } = string.Empty;
    public ulong SourceGuid { get; init; }
    public AbilityEffectType EffectType { get; init; }
    public DamageType DamageType { get; init; }

    public float DurationRemaining { get; set; }
    public float TickInterval { get; init; } = 1.0f;
    public float TickTimer { get; set; }
    public float ValuePerTick { get; set; }

    public bool IsExpired => DurationRemaining <= 0;
}
