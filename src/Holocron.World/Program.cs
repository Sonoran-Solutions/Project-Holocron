using Holocron.World;

if (Console.Out is StreamWriter sw) sw.AutoFlush = true;
Console.WriteLine("=================================================");
Console.WriteLine("       Project Holocron - SWTOR World Server");
Console.WriteLine("=================================================");

int[] handoffPorts = [20061, 9007, .. Enumerable.Range(20350, 71)];
var worldServer = new WorldServer(handoffPorts);
using var cts = new CancellationTokenSource();

Console.CancelKeyPress += (s, e) =>
{
    e.Cancel = true;
    cts.Cancel();
    Console.WriteLine("\n[WORLD] Shutting down...");
};

await worldServer.StartAsync(cts.Token);
try
{
    await Task.Delay(-1, cts.Token);
}
catch (OperationCanceledException)
{
    // Normal shutdown
}
