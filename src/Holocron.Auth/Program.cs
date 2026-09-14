using Holocron.Auth;
using System.Security.Cryptography;

Console.WriteLine("=================================================");
Console.WriteLine("     Project Holocron - SWTOR Authentication Server");
Console.WriteLine("=================================================");

bool capturePostHandshake = args.Length == 3 && args[2] == "--capture-post-handshake";
// Deliberately, unmistakably named: this mode answers RequestIDSignature
// (0xA609E6A7) directly with D4 and bypasses the proven identification
// exchange. It is NOT valid retail sequencing. See the method's docs and
// docs/CURRENT-RETAIL-STATE.md.
bool historicalInvalidDirectLoginProbe = args.Length == 3 && args[2] == "--historical-invalid-direct-login-probe";
bool probeIdBootstrap = args.Length == 3 && args[2] == "--probe-id-bootstrap";
if ((args.Length != 0 && args.Length != 2 && !capturePostHandshake && !historicalInvalidDirectLoginProbe && !probeIdBootstrap) ||
    (args.Length >= 1 && args[0] != "--test-key"))
{
    Console.Error.WriteLine("Usage: Holocron.Auth [--test-key /path/to/local-auth-key.pem [--probe-id-bootstrap|--capture-post-handshake|--historical-invalid-direct-login-probe]]");
    Console.Error.WriteLine();
    Console.Error.WriteLine("  --probe-id-bootstrap                 canonical bootstrap probe (RequestID -> ReplyID -> Introduce)");
    Console.Error.WriteLine("  --capture-post-handshake             observe only, no application replies");
    Console.Error.WriteLine("  --historical-invalid-direct-login-probe");
    Console.Error.WriteLine("                                       HISTORICAL/INVALID: answers RequestIDSignature directly with");
    Console.Error.WriteLine("                                       D4, bypassing the proven identification exchange. Retained");
    Console.Error.WriteLine("                                       only as an envelope-shape contract. Do not treat as retail.");
    Environment.ExitCode = 1;
    return;
}
using RSA? testKey = args.Length >= 2 ? RSA.Create() : null;
if (testKey is not null)
{
    testKey.ImportFromPem(File.ReadAllText(args[1]));
    Console.WriteLine("[AUTH] LOCAL TEST KEY: loopback-only; do not use real credentials.");
}
var authServer = new AuthServer(port: 7979, worldHost: "127.0.0.1", worldPort: 20061,
    testKey: testKey, handshakeOnly: testKey is not null, capturePostHandshake: capturePostHandshake,
    historicalInvalidDirectLoginProbe: historicalInvalidDirectLoginProbe, probeIdBootstrap: probeIdBootstrap);using var cts = new CancellationTokenSource();

Console.CancelKeyPress += (s, e) =>
{
    e.Cancel = true;
    cts.Cancel();
    Console.WriteLine("\n[AUTH] Shutting down...");
};

await authServer.StartAsync(cts.Token);
