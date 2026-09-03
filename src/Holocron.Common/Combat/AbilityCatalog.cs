namespace Holocron.Common.Combat;

/// <summary>
/// Pre-configured standard SWTOR combat abilities for Jedi, Sith, and tech classes.
/// </summary>
public static class AbilityCatalog
{
    // Jedi Guardian / Sith Juggernaut
    public static readonly AbilityDefinition SaberStrike = new()
    {
        Id = 1,
        Fqid = "abl.jedi_guardian.saber_strike",
        Name = "Saber Strike",
        RangeMin = 0.0f,
        RangeMax = 4.0f,
        Resource = ResourceType.Force,
        ResourceCost = 0,
        Cooldown = 0.0f,
        GlobalCooldown = 1.5f,
        EffectType = AbilityEffectType.DirectDamage,
        DamageType = DamageType.Kinetic,
        BaseMin = 25.0f,
        BaseMax = 35.0f
    };

    public static readonly AbilityDefinition BladeStorm = new()
    {
        Id = 2,
        Fqid = "abl.jedi_guardian.blade_storm",
        Name = "Blade Storm",
        RangeMin = 0.0f,
        RangeMax = 10.0f,
        Resource = ResourceType.Force,
        ResourceCost = 20,
        Cooldown = 9.0f,
        GlobalCooldown = 1.5f,
        EffectType = AbilityEffectType.DirectDamage,
        DamageType = DamageType.Energy,
        BaseMin = 85.0f,
        BaseMax = 115.0f
    };

    public static readonly AbilityDefinition ForceKick = new()
    {
        Id = 3,
        Fqid = "abl.jedi_guardian.force_kick",
        Name = "Force Kick",
        RangeMin = 0.0f,
        RangeMax = 4.0f,
        Resource = ResourceType.Force,
        ResourceCost = 0,
        Cooldown = 12.0f,
        GlobalCooldown = 0.0f, // Off-GCD
        EffectType = AbilityEffectType.Interrupt
    };

    public static readonly AbilityDefinition ForceTaunt = new()
    {
        Id = 4,
        Fqid = "abl.jedi_guardian.force_taunt",
        Name = "Force Taunt",
        RangeMin = 0.0f,
        RangeMax = 30.0f,
        Resource = ResourceType.Force,
        ResourceCost = 0,
        Cooldown = 15.0f,
        GlobalCooldown = 0.0f, // Off-GCD
        EffectType = AbilityEffectType.Taunt
    };

    // Sith Sorcerer / Jedi Sage
    public static readonly AbilityDefinition LightningStrike = new()
    {
        Id = 10,
        Fqid = "abl.sith_sorcerer.lightning_strike",
        Name = "Lightning Strike",
        RangeMin = 0.0f,
        RangeMax = 30.0f,
        Resource = ResourceType.Force,
        ResourceCost = 30,
        CastTime = 1.5f,
        Cooldown = 0.0f,
        GlobalCooldown = 1.5f,
        EffectType = AbilityEffectType.DirectDamage,
        DamageType = DamageType.Energy,
        BaseMin = 90.0f,
        BaseMax = 120.0f
    };

    public static readonly AbilityDefinition Affliction = new()
    {
        Id = 11,
        Fqid = "abl.sith_sorcerer.affliction",
        Name = "Affliction",
        RangeMin = 0.0f,
        RangeMax = 30.0f,
        Resource = ResourceType.Force,
        ResourceCost = 20,
        Cooldown = 0.0f,
        GlobalCooldown = 1.5f,
        EffectType = AbilityEffectType.PeriodicDamage,
        DamageType = DamageType.Internal,
        BaseMin = 25.0f, // 25 damage per tick
        Duration = 18.0f,
        TickInterval = 3.0f // 6 ticks
    };

    public static readonly AbilityDefinition DarkInfusion = new()
    {
        Id = 12,
        Fqid = "abl.sith_sorcerer.dark_infusion",
        Name = "Dark Infusion",
        RangeMin = 0.0f,
        RangeMax = 30.0f,
        Resource = ResourceType.Force,
        ResourceCost = 35,
        CastTime = 2.0f,
        Cooldown = 0.0f,
        GlobalCooldown = 1.5f,
        EffectType = AbilityEffectType.DirectHeal,
        BaseMin = 140.0f,
        BaseMax = 180.0f
    };
}
