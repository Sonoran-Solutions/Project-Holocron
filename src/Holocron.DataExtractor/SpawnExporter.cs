using System.Text;
using System.Text.Json;
using Holocron.Common.Area;
using Holocron.Common.Data;

namespace Holocron.DataExtractor;

public static class SpawnExporter
{
    public static void ExportStartingPlanetSpawns(string defaultAssetsDir, string outputJsonPath, string outputSqlPath)
    {
        string globalArchive = Path.Combine(defaultAssetsDir, "swtor_main_global_1.tor");
        if (!File.Exists(globalArchive))
        {
            Console.WriteLine($"[ERROR] File not found: {globalArchive}");
            return;
        }

        Console.WriteLine($"[1/3] Extracting spawns from {Path.GetFileName(globalArchive)}...");
        using var archive = new MypArchive(globalArchive);

        string[] targetPlanets = { "tython", "ord_mantell", "korriban", "hutta", "coruscant", "dromund_kaas", "black_talon", "esseles" };
        var planetAreas = new Dictionary<string, AreaDefinition>();

        foreach (var p in targetPlanets)
        {
            planetAreas[p] = new AreaDefinition
            {
                ZoneName = p,
                DisplayName = FormatDisplayName(p),
                DatFilePath = $@"\world\areas\{p}\area.dat"
            };
        }

        uint spawnIdCounter = 1;
        uint creatureEntryCounter = 1;
        var knownCreatures = new Dictionary<string, CreatureTemplate>();

        foreach (var entry in archive.Entries)
        {
            if (entry.UncompressedSize < 10000) continue;
            byte[] data = archive.Extract(entry);

            int idx = 0;
            while (idx < data.Length - 10)
            {
                if (idx + 4 < data.Length && 
                    (data[idx] == 's' && data[idx+1] == 'p' && data[idx+2] == 'n' && data[idx+3] == '.' ||
                     data[idx] == 'n' && data[idx+1] == 'p' && data[idx+2] == 'c' && data[idx+3] == '.'))
                {
                    int end = idx;
                    while (end < data.Length && data[end] >= 32 && data[end] <= 126) end++;

                    string fqid = Encoding.ASCII.GetString(data.AsSpan(idx, end - idx));
                    if (fqid.Length >= 8 && fqid.Contains('.'))
                    {
                        string lower = fqid.ToLowerInvariant();
                        foreach (var p in targetPlanets)
                        {
                            if (lower.Contains(p) && !planetAreas[p].Spawns.Any(s => s.Fqid == fqid))
                            {
                                if (!knownCreatures.TryGetValue(fqid, out var template))
                                {
                                    template = new CreatureTemplate
                                    {
                                        Entry = creatureEntryCounter++,
                                        Fqid = fqid,
                                        Name = GenerateCreatureName(fqid),
                                        MinLevel = DetermineLevel(p),
                                        MaxLevel = DetermineLevel(p) + 2,
                                        Faction = (uint)(fqid.Contains("vendor") || fqid.Contains("medcenter") ? 0 : 3), // 0=neutral, 3=hostile
                                        MaxHealth = 100 + DetermineLevel(p) * 45,
                                        MaxForce = 100,
                                        DamageMin = 5 + DetermineLevel(p) * 2,
                                        DamageMax = 10 + DetermineLevel(p) * 4,
                                        AggroRadius = 12.0f
                                    };
                                    knownCreatures[fqid] = template;
                                }

                                var spawn = new SpawnDefinition
                                {
                                    Id = spawnIdCounter++,
                                    Fqid = fqid,
                                    ZoneName = p,
                                    PosX = (spawnIdCounter % 50) * 15.0f - 375.0f,
                                    PosY = (spawnIdCounter % 30) * 15.0f - 225.0f,
                                    PosZ = 10.0f,
                                    Orientation = (spawnIdCounter * 45.0f) % 360.0f,
                                    RespawnTimeSeconds = 60,
                                    Template = template
                                };
                                planetAreas[p].Spawns.Add(spawn);
                            }
                        }
                    }
                    idx = end;
                }
                else
                {
                    idx++;
                }
            }
        }

        Console.WriteLine($"[2/3] Writing JSON catalog to {outputJsonPath}...");
        var options = new JsonSerializerOptions { WriteIndented = true };
        string json = JsonSerializer.Serialize(planetAreas.Values, options);
        File.WriteAllText(outputJsonPath, json);

        Console.WriteLine($"[3/3] Generating SQL seed database at {outputSqlPath}...");
        var sb = new StringBuilder();
        sb.AppendLine("-- Project Holocron: Auto-Generated World Spawn Database");
        sb.AppendLine("USE `holocron_world`;\n");

        sb.AppendLine("INSERT IGNORE INTO `creature_templates` (`entry`, `name`, `subname`, `min_level`, `max_level`, `faction`, `health`, `mana`, `damage_min`, `damage_max`) VALUES");
        int templateCount = 0;
        foreach (var t in knownCreatures.Values)
        {
            templateCount++;
            string comma = (templateCount == knownCreatures.Count) ? ";" : ",";
            string escapedName = t.Name.Replace("'", "''");
            string escapedSub = t.Fqid.Replace("'", "''");
            sb.AppendLine($"  ({t.Entry}, '{escapedName}', '{escapedSub}', {t.MinLevel}, {t.MaxLevel}, {t.Faction}, {t.MaxHealth}, {t.MaxForce}, {t.DamageMin}, {t.DamageMax}){comma}");
        }

        sb.AppendLine("\nINSERT IGNORE INTO `creature_spawns` (`id`, `creature_entry`, `map_id`, `pos_x`, `pos_y`, `pos_z`, `orientation`, `spawntimesecs`) VALUES");
        int totalSpawns = planetAreas.Values.Sum(a => a.Spawns.Count);
        int currentSpawn = 0;
        foreach (var area in planetAreas.Values)
        {
            foreach (var s in area.Spawns)
            {
                currentSpawn++;
                string comma = (currentSpawn == totalSpawns) ? ";" : ",";
                sb.AppendLine($"  ({s.Id}, {s.Template!.Entry}, {area.AreaId}, {s.PosX:F1}, {s.PosY:F1}, {s.PosZ:F1}, {s.Orientation:F1}, {s.RespawnTimeSeconds}){comma}");
            }
        }

        File.WriteAllText(outputSqlPath, sb.ToString());
        Console.WriteLine($"[OK] Successfully exported {knownCreatures.Count:N0} creature templates and {totalSpawns:N0} world spawns across {planetAreas.Count} starting zones!");
    }

    private static string FormatDisplayName(string planet) => planet switch
    {
        "tython" => "Tython (Jedi Starting World)",
        "ord_mantell" => "Ord Mantell (Trooper/Smuggler World)",
        "korriban" => "Korriban (Sith Academy World)",
        "hutta" => "Hutta (Bounty Hunter/Agent World)",
        "coruscant" => "Coruscant (Republic Capital)",
        "dromund_kaas" => "Dromund Kaas (Imperial Capital)",
        "black_talon" => "The Black Talon (Imperial Flashpoint)",
        "esseles" => "The Esseles (Republic Flashpoint)",
        _ => planet
    };

    private static int DetermineLevel(string planet) => planet switch
    {
        "tython" or "korriban" or "ord_mantell" or "hutta" => 1,
        "coruscant" or "dromund_kaas" => 10,
        "black_talon" or "esseles" => 10,
        _ => 1
    };

    private static string GenerateCreatureName(string fqid)
    {
        string last = fqid.Split('.').LastOrDefault(s => !string.IsNullOrWhiteSpace(s)) ?? "Creature";
        var parts = last.Split('_').Where(w => !string.IsNullOrWhiteSpace(w)).Select(w => char.ToUpperInvariant(w[0]) + w[1..]);
        string name = string.Join(" ", parts);
        return string.IsNullOrWhiteSpace(name) ? "Creature" : name;
    }
}
