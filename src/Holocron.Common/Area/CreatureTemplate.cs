namespace Holocron.Common.Area;

/// <summary>
/// Defines the base stats, level, faction, and combat attributes for a creature entity in SWTOR.
/// </summary>
public sealed class CreatureTemplate
{
    public uint Entry { get; init; }
    public string Fqid { get; init; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Subname { get; set; } = string.Empty;
    public int MinLevel { get; set; } = 1;
    public int MaxLevel { get; set; } = 1;
    public uint Faction { get; set; } = 0; // 0 = Neutral, 1 = Republic, 2 = Imperial, 3 = Hostile
    public int MaxHealth { get; set; } = 100;
    public int MaxForce { get; set; } = 100;
    public float DamageMin { get; set; } = 5.0f;
    public float DamageMax { get; set; } = 10.0f;
    public float AggroRadius { get; set; } = 12.0f;
    public List<string> Abilities { get; } = new();

    public override string ToString() => $"[#{Entry}] {Name} (Lvl {MinLevel}-{MaxLevel}) [{Fqid}]";
}
