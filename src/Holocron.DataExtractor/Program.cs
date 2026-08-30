using System.Buffers.Binary;
using System.Text;
using Holocron.Common.Data;
using ZstdSharp;

string defaultAssetsDir = "/home/dq/snap/steam/common/.local/share/Steam/steamapps/common/Star Wars - The Old Republic/Assets";
string globalArchive = Path.Combine(defaultAssetsDir, "swtor_main_global_1.tor");

using var archive = new MypArchive(globalArchive);
var decompressor = new Decompressor();

Console.WriteLine("Scanning for GOM Node FQIDs and Entity Definitions...\n");

int fqidCount = 0;
var sampleFqids = new List<(string fqid, int payloadSize)>();

foreach (var entry in archive.Entries.Take(50))
{
    if (entry.UncompressedSize < 50000) continue;
    byte[] data = archive.Extract(entry);
    
    // Scan for string names in data
    int idx = 0;
    while (idx < data.Length - 10)
    {
        // Look for typical SWTOR prefixes: spn., abl., npc., itm., class., qst., enc., area., loc.
        if (idx + 4 < data.Length && 
            (data[idx] == 's' && data[idx+1] == 'p' && data[idx+2] == 'n' && data[idx+3] == '.' ||
             data[idx] == 'a' && data[idx+1] == 'b' && data[idx+2] == 'l' && data[idx+3] == '.' ||
             data[idx] == 'n' && data[idx+1] == 'p' && data[idx+2] == 'c' && data[idx+3] == '.' ||
             data[idx] == 'i' && data[idx+1] == 't' && data[idx+2] == 'm' && data[idx+3] == '.' ||
             data[idx] == 'c' && data[idx+1] == 'l' && data[idx+2] == 'a' && data[idx+3] == 's' ||
             data[idx] == 'q' && data[idx+1] == 's' && data[idx+2] == 't' && data[idx+3] == '.'))
        {
            // Read null-terminated or length-terminated string
            int end = idx;
            while (end < data.Length && data[end] >= 32 && data[end] <= 126)
            {
                end++;
            }
            string fqid = Encoding.ASCII.GetString(data.AsSpan(idx, end - idx));
            if (fqid.Length > 8 && fqid.Contains('.'))
            {
                fqidCount++;
                if (sampleFqids.Count < 25)
                {
                    sampleFqids.Add((fqid, data.Length));
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

Console.WriteLine($"[OK] Found {fqidCount} entity definitions in sample buckets!\n");
Console.WriteLine("Sample Entity Identifiers Found in Assets:");
foreach (var (fqid, size) in sampleFqids)
{
    Console.WriteLine($"  - {fqid}");
}
