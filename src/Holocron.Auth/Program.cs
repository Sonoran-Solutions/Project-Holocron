using Holocron.Auth;

Console.WriteLine("=================================================");
Console.WriteLine("     Project Holocron - SWTOR Authentication Server");
Console.WriteLine("=================================================");

var authServer = new AuthServer(port: 7979, worldHost: "127.0.0.1", worldPort: 20061);
using var cts = new CancellationTokenSource();

Console.CancelKeyPress += (s, e) =>
{
    e.Cancel = true;
    cts.Cancel();
    Console.WriteLine("\n[AUTH] Shutting down...");
};

await authServer.StartAsync(cts.Token);
