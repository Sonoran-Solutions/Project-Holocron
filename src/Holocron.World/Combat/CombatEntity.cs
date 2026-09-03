using DotRecast.Core.Numerics;
using Holocron.Common.Combat;

namespace Holocron.World.Combat;

/// <summary>
/// Unified entity participating in real-time combat (Player, Bot, or Creature).
/// </summary>
public sealed class CombatEntity
{
    public ulong Guid { get; init; }
    public string Name { get; set; } = "Entity";
    public uint Faction { get; set; } = 0; // 0 = Neutral, 1 = Republic, 2 = Imperial, 3 = Hostile

    // Health & Vitals
    public float CurrentHealth { get; set; } = 100.0f;
    public float MaxHealth { get; set; } = 100.0f;
    public bool IsDead => CurrentHealth <= 0;
    public float HealthPercent => MaxHealth > 0 ? Math.Clamp(CurrentHealth / MaxHealth, 0.0f, 1.0f) : 0.0f;

    // Resource Pool
    public ResourceType Resource { get; set; } = ResourceType.Force;
    public float CurrentResource { get; set; } = 100.0f;
    public float MaxResource { get; set; } = 100.0f;

    // Position in 3D Space
    public RcVec3f Position { get; set; } = RcVec3f.Zero;

    // Combat State
    public bool InCombat { get; set; }
    public float GlobalCooldownRemaining { get; set; }
    public ulong? CurrentTargetGuid { get; set; }

    // Active Cooldowns (AbilityId -> Remaining Seconds)
    public Dictionary<uint, float> Cooldowns { get; } = new();

    // Active Auras (Buffs, Debuffs, DoTs, HoTs)
    public List<Aura> ActiveAuras { get; } = new();

    // Threat Table: HostileGuid -> ThreatValue
    public Dictionary<ulong, float> ThreatTable { get; } = new();

    // Combat Stats
    public float ArmorRating { get; set; } = 500.0f; // ~25% damage mitigation
    public float CriticalChance { get; set; } = 0.20f; // 20%
    public float CriticalMultiplier { get; set; } = 1.75f; // 175% damage

    public void AddThreat(ulong hostileGuid, float amount)
    {
        if (ThreatTable.TryGetValue(hostileGuid, out float current))
        {
            ThreatTable[hostileGuid] = current + amount;
        }
        else
        {
            ThreatTable[hostileGuid] = amount;
        }
    }

    public ulong? GetTopThreatTarget()
    {
        if (ThreatTable.Count == 0) return null;
        return ThreatTable.OrderByDescending(kv => kv.Value).First().Key;
    }
}
