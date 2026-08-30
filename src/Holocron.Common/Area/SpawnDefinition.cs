namespace Holocron.Common.Area;

/// <summary>
/// Represents a static or dynamic spawn placement in a planet zone or flashpoint.
/// </summary>
public sealed class SpawnDefinition
{
    public uint Id { get; init; }
    public string Fqid { get; init; } = string.Empty;
    public string ZoneName { get; init; } = string.Empty;
    public ulong MapId { get; init; }
    public float PosX { get; set; }
    public float PosY { get; set; }
    public float PosZ { get; set; }
    public float Orientation { get; set; }
    public int RespawnTimeSeconds { get; set; } = 60;
    public CreatureTemplate? Template { get; set; }

    public override string ToString() => $"Spawn #{Id} in {ZoneName} @ ({PosX:F1}, {PosY:F1}, {PosZ:F1}) [{Fqid}]";
}
