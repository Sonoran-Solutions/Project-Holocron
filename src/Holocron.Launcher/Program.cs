using System.Diagnostics;

Console.WriteLine("=================================================");
Console.WriteLine("     Project Holocron - SWTOR Offline Launcher");
Console.WriteLine("=================================================");

string steamCommon = "/home/dq/snap/steam/common/.local/share/Steam/steamapps/common";
string swtorDir = Path.Combine(steamCommon, "Star Wars - The Old Republic/swtor/retailclient");
string swtorExe = Path.Combine(swtorDir, "swtor.exe");

string protonDir = Path.Combine(steamCommon, "Proton - Experimental/files/bin");
string protonExe = Path.Combine(protonDir, "wine");
string compatPrefix = "/home/dq/snap/steam/common/.local/share/Steam/steamapps/compatdata/1286830/pfx";

string authHost = "127.0.0.1";
int authPort = 7979;

if (args.Length >= 1) authHost = args[0];
if (args.Length >= 2 && int.TryParse(args[1], out int p)) authPort = p;

Console.WriteLine($"[CONFIG] Target Executable: {swtorExe}");
Console.WriteLine($"[CONFIG] Shard Address: @{authHost}:{authPort}:1");

if (!File.Exists(swtorExe))
{
    Console.WriteLine($"[ERROR] swtor.exe not found at: {swtorExe}");
    return;
}

Console.WriteLine("\n[INFO] Launch Configuration Prepared:");
Console.WriteLine($"     - Auth Server: {authHost}:{authPort}");
Console.WriteLine($"     - Shard Target: @{authHost}:{authPort}:1");
Console.WriteLine($"     - Wine Prefix: {compatPrefix}");

Console.WriteLine("\n[INFO] Launch command ready to execute when server stack is online!");
