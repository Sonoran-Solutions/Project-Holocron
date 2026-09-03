using DotRecast.Core.Numerics;
using Holocron.Common.Combat;

namespace Holocron.World.Characters;

public sealed class EquippedItem
{
    public uint SlotId { get; init; }
    public string SlotName { get; init; } = string.Empty;
    public string ItemName { get; init; } = string.Empty;
    public string ItemFqid { get; init; } = string.Empty;
    public uint ItemLevel { get; init; } = 340; // Endgame item rating
    public float ArmorValue { get; init; } = 150.0f;
}

/// <summary>
/// Detailed character profile containing progression, high-tier gear, and spawn coordinates.
/// </summary>
public sealed class CharacterProfile
{
    public ulong Guid { get; init; }
    public ulong AccountId { get; init; } = 1;
    public string Name { get; init; } = string.Empty;
    public string Title { get; init; } = string.Empty;
    public uint Level { get; set; } = 80;
    public uint ClassId { get; init; }
    public string ClassName { get; init; } = string.Empty;
    public string AdvancedClassName { get; init; } = string.Empty;
    public uint Faction { get; init; } // 1 = Republic, 2 = Imperial

    // Vitals & Resources
    public float MaxHealth { get; set; } = 35000.0f;
    public float CurrentHealth { get; set; } = 35000.0f;
    public ResourceType Resource { get; set; } = ResourceType.Force;
    public float MaxResource { get; set; } = 100.0f;
    public float CurrentResource { get; set; } = 100.0f;

    // Location & Zoning
    public string AreaFqid { get; set; } = "tython_main";
    public string AreaName { get; set; } = "Tython";
    public RcVec3f SpawnPosition { get; set; } = new(0, 0, 0);
    public float Orientation { get; set; } = 0.0f;

    // Equipped Gear
    public List<EquippedItem> Gear { get; } = new();

    // Known Abilities
    public List<uint> UnlockedAbilityIds { get; } = new();

    public float TotalArmorRating => Gear.Sum(g => g.ArmorValue);
}
