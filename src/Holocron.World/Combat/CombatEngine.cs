using DotRecast.Core.Numerics;
using Holocron.Common.Combat;
using Holocron.Common.Navigation;

namespace Holocron.World.Combat;

public sealed class CombatEngine
{
    private static readonly Random Rng = new();

    public static bool CanCast(CombatEntity source, CombatEntity target, AbilityDefinition ability, NavMeshService? navMesh, out string failReason)
    {
        failReason = string.Empty;

        if (source.IsDead)
        {
            failReason = "Caster is dead";
            return false;
        }

        if (source.GlobalCooldownRemaining > 0 && ability.GlobalCooldown > 0)
        {
            failReason = "Global cooldown active";
            return false;
        }

        if (source.Cooldowns.TryGetValue(ability.Id, out float cd) && cd > 0)
        {
            failReason = $"Ability on cooldown ({cd:F1}s remaining)";
            return false;
        }

        // Resource Cost Check
        if (ability.ResourceCost > 0)
        {
            if (ability.Resource == ResourceType.Heat)
            {
                if (source.CurrentResource + ability.ResourceCost > source.MaxResource)
                {
                    failReason = "Heat overload";
                    return false;
                }
            }
            else
            {
                if (source.CurrentResource < ability.ResourceCost)
                {
                    failReason = $"Insufficient {ability.Resource}";
                    return false;
                }
            }
        }

        // Range Check
        float dx = source.Position.X - target.Position.X;
        float dy = source.Position.Y - target.Position.Y;
        float dz = source.Position.Z - target.Position.Z;
        float dist = (float)Math.Sqrt(dx * dx + dy * dy + dz * dz);

        if (dist < ability.RangeMin || dist > ability.RangeMax)
        {
            failReason = $"Target out of range (dist: {dist:F1}m, range: {ability.RangeMin}-{ability.RangeMax}m)";
            return false;
        }

        // Line of Sight Check via NavMesh Raycast
        if (navMesh != null && !navMesh.HasLineOfSight(source.Position, target.Position, out _))
        {
            failReason = "Target not in line of sight";
            return false;
        }

        return true;
    }

    public static float ExecuteAbility(CombatEntity source, CombatEntity target, AbilityDefinition ability)
    {
        // Deduct/Generate Resources
        if (ability.Resource == ResourceType.Heat)
        {
            source.CurrentResource = Math.Min(source.MaxResource, source.CurrentResource + ability.ResourceCost);
        }
        else
        {
            source.CurrentResource = Math.Clamp(source.CurrentResource - ability.ResourceCost, 0, source.MaxResource);
        }

        // Apply Cooldowns
        if (ability.Cooldown > 0)
        {
            source.Cooldowns[ability.Id] = ability.Cooldown;
        }

        if (ability.GlobalCooldown > 0)
        {
            source.GlobalCooldownRemaining = ability.GlobalCooldown;
        }

        source.InCombat = true;
        target.InCombat = true;

        float outcomeValue = 0.0f;

        switch (ability.EffectType)
        {
            case AbilityEffectType.DirectDamage:
            {
                float baseDamage = ability.BaseMin + (float)Rng.NextDouble() * (ability.BaseMax - ability.BaseMin);
                bool isCrit = Rng.NextDouble() <= source.CriticalChance;
                if (isCrit)
                {
                    baseDamage *= source.CriticalMultiplier;
                }

                // Apply Armor mitigation for Kinetic and Energy
                float mitigatedDamage = baseDamage;
                if (ability.DamageType == DamageType.Kinetic || ability.DamageType == DamageType.Energy)
                {
                    float mitigation = target.ArmorRating / (target.ArmorRating + 1500.0f);
                    mitigatedDamage *= (1.0f - Math.Clamp(mitigation, 0.0f, 0.75f));
                }

                target.CurrentHealth = Math.Max(0, target.CurrentHealth - mitigatedDamage);
                target.AddThreat(source.Guid, mitigatedDamage);
                outcomeValue = mitigatedDamage;
                break;
            }

            case AbilityEffectType.DirectHeal:
            {
                float baseHeal = ability.BaseMin + (float)Rng.NextDouble() * (ability.BaseMax - ability.BaseMin);
                if (Rng.NextDouble() <= source.CriticalChance)
                {
                    baseHeal *= source.CriticalMultiplier;
                }

                target.CurrentHealth = Math.Min(target.MaxHealth, target.CurrentHealth + baseHeal);
                outcomeValue = baseHeal;
                break;
            }

            case AbilityEffectType.PeriodicDamage:
            {
                var dot = new Aura
                {
                    AbilityId = ability.Id,
                    Name = ability.Name,
                    SourceGuid = source.Guid,
                    EffectType = AbilityEffectType.PeriodicDamage,
                    DamageType = ability.DamageType,
                    DurationRemaining = ability.Duration,
                    TickInterval = ability.TickInterval,
                    TickTimer = ability.TickInterval,
                    ValuePerTick = ability.BaseMin
                };
                target.ActiveAuras.Add(dot);
                break;
            }

            case AbilityEffectType.Taunt:
            {
                // Force Taunt: Snap target's threat towards source to match current highest threat + 15%
                float highestThreat = target.ThreatTable.Values.DefaultIfEmpty(100.0f).Max();
                target.ThreatTable[source.Guid] = highestThreat * 1.15f;
                target.CurrentTargetGuid = source.Guid;
                break;
            }

            case AbilityEffectType.Interrupt:
            {
                target.GlobalCooldownRemaining = 1.0f; // lock out briefly
                break;
            }
        }

        return outcomeValue;
    }

    public static void Tick(CombatEntity entity, float deltaSeconds)
    {
        // 1. Decrement GCD
        if (entity.GlobalCooldownRemaining > 0)
        {
            entity.GlobalCooldownRemaining = Math.Max(0, entity.GlobalCooldownRemaining - deltaSeconds);
        }

        // 2. Decrement Cooldowns
        var expiredCds = new List<uint>();
        foreach (var (id, cd) in entity.Cooldowns)
        {
            float next = cd - deltaSeconds;
            if (next <= 0) expiredCds.Add(id);
            else entity.Cooldowns[id] = next;
        }
        foreach (var id in expiredCds) entity.Cooldowns.Remove(id);

        // 3. Resource Regeneration / Heat Venting
        if (entity.Resource == ResourceType.Force)
        {
            entity.CurrentResource = Math.Min(entity.MaxResource, entity.CurrentResource + 8.0f * deltaSeconds); // 8 Force/sec
        }
        else if (entity.Resource == ResourceType.Energy)
        {
            entity.CurrentResource = Math.Min(entity.MaxResource, entity.CurrentResource + 5.0f * deltaSeconds); // 5 Energy/sec
        }
        else if (entity.Resource == ResourceType.Heat)
        {
            entity.CurrentResource = Math.Max(0, entity.CurrentResource - 5.0f * deltaSeconds); // Vent 5 Heat/sec
        }

        // 4. Tick Active Auras
        for (int i = entity.ActiveAuras.Count - 1; i >= 0; i--)
        {
            var aura = entity.ActiveAuras[i];
            aura.DurationRemaining -= deltaSeconds;
            aura.TickTimer -= deltaSeconds;

            if (aura.TickTimer <= 0 && aura.DurationRemaining > 0)
            {
                if (aura.EffectType == AbilityEffectType.PeriodicDamage)
                {
                    entity.CurrentHealth = Math.Max(0, entity.CurrentHealth - aura.ValuePerTick);
                    entity.AddThreat(aura.SourceGuid, aura.ValuePerTick);
                }
                else if (aura.EffectType == AbilityEffectType.PeriodicHeal)
                {
                    entity.CurrentHealth = Math.Min(entity.MaxHealth, entity.CurrentHealth + aura.ValuePerTick);
                }

                aura.TickTimer = aura.TickInterval;
            }

            if (aura.IsExpired)
            {
                entity.ActiveAuras.RemoveAt(i);
            }
        }
    }
}
