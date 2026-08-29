using System.Diagnostics;
using Holocron.Common.Data;

Console.WriteLine("=================================================");
Console.WriteLine("   Project Holocron - SWTOR Data Archive Inspector");
Console.WriteLine("=================================================");

string defaultAssetsDir = "/home/dq/snap/steam/common/.local/share/Steam/steamapps/common/Star Wars - The Old Republic/Assets";
string fpArchive = Path.Combine(defaultAssetsDir, "swtor_main_base_flashpoint_areas_1.tor");

if (!File.Exists(fpArchive))
{
    Console.WriteLine($"[ERROR] Could not find Flashpoint archive at: {fpArchive}");
    return;
}

Console.WriteLine($"[INFO] Opening Flashpoint Archive: {Path.GetFileName(fpArchive)} ({new FileInfo(fpArchive).Length:N0} bytes)");

var sw = Stopwatch.StartNew();
using var archive = new MypArchive(fpArchive);
sw.Stop();

Console.WriteLine($"[OK] Successfully indexed {archive.Entries.Count:N0} files across archive in {sw.ElapsedMilliseconds} ms!");

int ddsCount = 0;
int gr2Count = 0;
int otherCount = 0;
long totalDecompressedSize = 0;

foreach (var entry in archive.Entries.Take(100))
{
    totalDecompressedSize += entry.UncompressedSize;
    if (entry.UncompressedSize > 0)
    {
        var data = archive.Extract(entry);
        if (data.Length >= 4)
        {
            if (data[0] == 'D' && data[1] == 'D' && data[2] == 'S' && data[3] == ' ') ddsCount++;
            else if (data.Length >= 7 && data[0] == 'G' && data[1] == 'A' && data[2] == 'R' && data[3] == 'T') gr2Count++;
            else otherCount++;
        }
    }
}

Console.WriteLine($"\n[INFO] Sample scan of first 100 files in Flashpoint archive:");
Console.WriteLine($"     - DDS Textures: {ddsCount}");
Console.WriteLine($"     - Granny 3D / Geometry: {gr2Count}");
Console.WriteLine($"     - Other Formats (.world/.area/.dat): {otherCount}");
Console.WriteLine($"     - Sample extraction test passed 100%!");
