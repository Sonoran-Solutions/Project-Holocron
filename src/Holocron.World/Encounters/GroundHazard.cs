using DotRecast.Core.Numerics;

namespace Holocron.World.Encounters;

/// <summary>
/// Represents a telegraphed ground AoE danger zone (e.g. fire circle, orbital strike, missile barrage).
/// Entities standing inside the hazard take periodic damage until they evacuate.
/// </summary>
public sealed class GroundHazard
{
    public uint Id { get; init; }
    public string Name { get; init; } = "Hazard Area";
    public RcVec3f Center { get; init; }
    public float Radius { get; init; } = 8.0f;
    public float DamagePerTick { get; init; } = 45.0f;
    public float TickInterval { get; init; } = 1.0f;
    public float TickTimer { get; set; }
    public float DurationRemaining { get; set; } = 12.0f;

    public bool IsExpired => DurationRemaining <= 0;

    public bool IsInside(RcVec3f point)
    {
        float dx = point.X - Center.X;
        float dz = point.Z - Center.Z;
        return (dx * dx + dz * dz) <= (Radius * Radius);
    }
}
