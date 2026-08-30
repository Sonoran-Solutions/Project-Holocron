using System.Diagnostics;
using Holocron.DataExtractor;

Console.WriteLine("=================================================");
Console.WriteLine("  Project Holocron - World & Area Spawn Exporter ");
Console.WriteLine("=================================================");

string defaultAssetsDir = "/home/dq/snap/steam/common/.local/share/Steam/steamapps/common/Star Wars - The Old Republic/Assets";
string outputJson = "/home/dq/project-holocron/data/definitions/spawns.json";
string outputSql = "/home/dq/project-holocron/sql/03_world.sql";

var sw = Stopwatch.StartNew();
SpawnExporter.ExportStartingPlanetSpawns(defaultAssetsDir, outputJson, outputSql);
sw.Stop();

Console.WriteLine($"\n[COMPLETE] Extractor finished in {sw.ElapsedMilliseconds} ms!");
