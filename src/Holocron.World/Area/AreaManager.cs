using Holocron.Common.Area;

namespace Holocron.World.Area;

/// <summary>
/// Central registry managing all planet areas, zones, and flashpoint instances.
/// </summary>
public sealed class AreaManager
{
    private readonly Dictionary<string, (AreaDefinition Definition, SpawnManager Spawns)> _areas = new();

    public IReadOnlyDictionary<string, (AreaDefinition Definition, SpawnManager Spawns)> Areas => _areas;

    public void RegisterArea(AreaDefinition definition)
    {
        var spawnManager = new SpawnManager();
        spawnManager.LoadSpawns(definition.Spawns);
        _areas[definition.ZoneName] = (definition, spawnManager);
    }

    public bool TryGetArea(string zoneName, out (AreaDefinition Definition, SpawnManager Spawns) area)
    {
        return _areas.TryGetValue(zoneName, out area);
    }

    public void Tick(float deltaSeconds, IReadOnlyList<(ulong Guid, string ZoneName, float X, float Y, float Z)> players)
    {
        foreach (var (zoneName, (def, spawnMgr)) in _areas)
        {
            var zonePlayers = players
                .Where(p => p.ZoneName == zoneName)
                .Select(p => (p.Guid, p.X, p.Y, p.Z))
                .ToList();

            spawnMgr.Tick(deltaSeconds, zonePlayers);
        }
    }
}
