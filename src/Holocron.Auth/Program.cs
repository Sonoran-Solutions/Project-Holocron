using Holocron.Auth;
using System.Security.Cryptography;

Console.WriteLine("=================================================");
Console.WriteLine("     Project Holocron - SWTOR Authentication Server");
Console.WriteLine("=================================================");

bool capturePostHandshake = args.Length == 3 && args[2] == "--capture-post-handshake";
bool probeLoginReplyEnvelope = args.Length == 3 && args[2] == "--probe-login-reply-envelope";
if ((args.Length != 0 && args.Length != 2 && !capturePostHandshake && !probeLoginReplyEnvelope) ||
    (args.Length >= 1 && args[0] != "--test-key"))
{
    Console.Error.WriteLine("Usage: Holocron.Auth [--test-key /path/to/local-auth-key.pem [--capture-post-handshake|--probe-login-reply-envelope]]");
    return;
}
using RSA? testKey = args.Length >= 2 ? RSA.Create() : null;
if (testKey is not null)
{
    testKey.ImportFromPem(File.ReadAllText(args[1]));
    Console.WriteLine("[AUTH] LOCAL TEST KEY: loopback-only, handshake-only; do not use real credentials.");
}
var authServer = new AuthServer(port: 7979, worldHost: "127.0.0.1", worldPort: 20061,
    testKey: testKey, handshakeOnly: testKey is not null, capturePostHandshake: capturePostHandshake,
    probeLoginReplyEnvelope: probeLoginReplyEnvelope);
using var cts = new CancellationTokenSource();

Console.CancelKeyPress += (s, e) =>
{
    e.Cancel = true;
    cts.Cancel();
    Console.WriteLine("\n[AUTH] Shutting down...");
};

await authServer.StartAsync(cts.Token);
