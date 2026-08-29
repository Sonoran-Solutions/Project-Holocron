using Holocron.World;

Console.WriteLine("=================================================");
Console.WriteLine("       Project Holocron - SWTOR World Server");
Console.WriteLine("=================================================");

var worldServer = new WorldServer(port: 20061);
using var cts = new CancellationTokenSource();

Console.CancelKeyPress += (s, e) =>
{
    e.Cancel = true;
    cts.Cancel();
    Console.WriteLine("\n[WORLD] Shutting down...");
};

await worldServer.StartAsync(cts.Token);
