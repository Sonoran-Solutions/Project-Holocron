namespace Holocron.Common.Combat;

/// <summary>
/// Defines an ability/spell in the SWTOR combat system.
/// </summary>
public sealed class AbilityDefinition
{
    public uint Id { get; init; }
    public string Fqid { get; init; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;

    public float CastTime { get; set; } = 0.0f; // 0 = instant cast
    public float ChannelTime { get; set; } = 0.0f;
    public float Cooldown { get; set; } = 0.0f;
    public float GlobalCooldown { get; set; } = 1.5f;

    public float RangeMin { get; set; } = 0.0f;
    public float RangeMax { get; set; } = 4.0f; // 4m for melee, 30m for ranged/force

    public ResourceType Resource { get; set; } = ResourceType.Force;
    public int ResourceCost { get; set; } = 0; // Positive = spends, Negative = generates (e.g. Strike generates Focus)

    public AbilityEffectType EffectType { get; set; } = AbilityEffectType.DirectDamage;
    public DamageType DamageType { get; set; } = DamageType.Kinetic;

    public float BaseMin { get; set; } = 10.0f;
    public float BaseMax { get; set; } = 20.0f;
    public float StatMultiplier { get; set; } = 1.0f;

    // Periodic / Aura attributes
    public float Duration { get; set; } = 0.0f;
    public float TickInterval { get; set; } = 1.0f;

    public override string ToString() => $"Ability #{Id}: {Name} [{EffectType}, Range: {RangeMin}-{RangeMax}m, Cost: {ResourceCost} {Resource}]";
}
