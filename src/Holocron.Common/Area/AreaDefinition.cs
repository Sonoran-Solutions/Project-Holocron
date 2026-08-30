namespace Holocron.Common.Area;

/// <summary>
/// Represents a planet or flashpoint area/zone in SWTOR.
/// </summary>
public sealed class AreaDefinition
{
    public ulong AreaId { get; init; }
    public string ZoneName { get; init; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string DatFilePath { get; set; } = string.Empty;
    public List<SpawnDefinition> Spawns { get; } = new();

    public override string ToString() => $"Area {DisplayName} ({ZoneName}, ID: 0x{AreaId:X16}, Spawns: {Spawns.Count})";
}
