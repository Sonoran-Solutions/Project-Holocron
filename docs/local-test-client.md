# Isolated client preparation

> **For the current model see [`docs/CURRENT-RETAIL-STATE.md`](CURRENT-RETAIL-STATE.md).**
> This document has two parts: the current preparation/runtime facts at the top,
> and a clearly-labelled historical findings log at the bottom that preserves
> superseded conclusions (for example the earlier handshake-only description).

## Current facts

The local test copy lives in `.local-test/client-v1/game/swtor/retailclient`.
The original Steam executable is untouched. Only the copied executable's
292-byte inverted public-key region is replaced. The inspected PE has no
Authenticode certificate. Other possible integrity checks have not been established.

The matching freshly generated private key is in `.local-test/client-v1` with
owner-only permissions. The directory is Git-ignored. Never distribute that
private key or use this test client with real account credentials.

Preparation selects `shardaddress @::` for repository-stub mode. The current
experimental `swtor.icb` also selects repository-stub mode, after an explicit
local repository address produced login error 1003.

### Canonical shard address

The platform fixture (`tools/fixtures/platform-responses.json`) serves one shard
whose `host` field is the canonical launch target:

```text
localhost:7979:castlehilltest
```

Note **`localhost`**, not `127.0.0.1`. The outer address parser strips the final
colon component (the service/shard suffix) before the transport parses
`host:port`; omitting the suffix therefore loses the port. The client's own log
confirms the value it consumed:

```text
[OMEGACONNECT] Starting login: local-test : @localhost:7979:castlehilltest
```

### Canonical reproduction entrypoint

```bash
python3 tools/run-retail-bootstrap-probe.py
```

The isolated namespace contains only `lo`, and the retail TCP hint builder sets
`AI_ADDRCONFIG` (`0x400`) at RVA `0x4507C9`. In that namespace the flag makes
`getaddrinfo` reject every IPv4 result including `127.0.0.1`, so the client never
opens an Auth socket and fails at `0x140427F10` on a missing
`[ServerProxy+0x80]` -- an **environment artifact**, not the protocol boundary.

`tools/run-retail-bootstrap-probe.py` clears exactly that one immediate on the
**private** client, verifies the build hash first, and restores the original
bytes byte-for-byte in a `finally` path. Do not hand-patch; do not run the
launcher directly on stock bytes and expect the historical path.

### What the auth probe currently does

`Holocron.Auth --test-key PATH --probe-id-bootstrap` runs the **canonical
bootstrap probe**: it answers `RequestIDSignature` (`0xA609E6A7`) with
`ReplyIDSignature` (`0x6731C5AF`), observes the client's
`IntroduceConnectionSignature` (`0x8B0D492F`), and then **only observes**. It does
not send D4.

`--capture-post-handshake` observes without replying.
`--historical-invalid-direct-login-probe` is **historical and invalid**: it
answers `RequestIDSignature` directly with D4, bypassing the proven identification
exchange. It is retained only as an envelope-shape contract and prints a loud
warning; it does not establish retail sequencing.
A private Proton runtime and a separately initialized `compatdata` prefix are used.
Some historical logs were copied with the runtime: their existence is not evidence
of a new launch. Check timestamps and the runner's current trace instead.

The 55 GB asset directory has deliberately not been duplicated or symlinked.
Before a real client launch, mount original assets **read-only** into the test
game directory, and place client and local services inside the same isolated
network namespace. Host namespace support has been checked with a harmless
`bwrap --unshare-user --unshare-net ... /bin/true` invocation. It requires running
outside the agent sandbox on this host. Do not fall back to an unrestricted
network launch if isolation fails.

Do not use the existing `launch-swtor.sh`: it targets the original Steam
installation and prefix. No Steam launch options or hosts entries were changed.

## Checks

`tools/prepare-local-client.py SOURCE_RETAILCLIENT NEW_DESTINATION` fingerprints
the known executable, generates the test key, prepares the copy, verifies the
matching public numbers and confirms the original executable is unchanged.
It refuses an existing destination or unknown executable build.

After building Debug, `tools/probe-local-key.py TEST_DIRECTORY --dotnet DOTNET`
starts its own loopback-only auth probe, reads the public key from the actual
prepared executable, encrypts dummy handshake fields, verifies server acceptance,
and stops its own server. Run it inside a network namespace for isolation.

`Holocron.Auth --test-key PATH` selects the supplied private key. With no mode
flag it validates the historical key-field schema and closes without emitting
application responses; with `--probe-id-bootstrap` it runs the canonical
identification exchange described above.

This is preparation and a synthetic RSA interoperability check, **not** evidence
that the real client reaches character selection or that C2/C3 is resolved.

## Historical findings log

> ⚠ **Everything below is a chronological record.** It contains superseded
> conclusions -- notably "the auth service is deliberately handshake-only" (the
> canonical probe now performs the identification exchange) and the earlier
> `127.0.0.1:7979:castlehilltest` fixture value (the canonical value is
> `localhost:7979:castlehilltest`). Do not treat it as current state.

## Isolated launch findings (updated 2026-09-05)

`tools/launch-isolated-client.sh` uses the copied executable, private Proton,
read-only asset mount, and local servers in one private network namespace.
The X11 socket must also be mounted for visible dialogs. Correcting command
syntax to `-set NAME VALUE ... @swtor.icb` changed silent exits into a captured
C2 startup dialog. No connection to local auth was observed in those tests.
This does not establish an integrity-check failure or a Steam relaunch failure.

Static analysis found that `platform` is a host:port address, not a product name:
property lookup at `0x14010c6b1`, colon search at `0x14010c718`, and host/port
split at `0x14010c760`. The first corrected test used `127.0.0.1:7979`.
That corrects the argument format, but does not establish successful login.
All token/password values in this test are dummy data, not account credentials.

With the corrected platform format, a fresh client log
`Client_20260905T130846_308.log` reached `PlayerClient::Login`, selected the remote
repository, and reported `LOGIN_ERROR_FAILED_CONNECT_TO_LOGIN_SERVER` (1003).
The auth service saw no connection in that remote-repository test.

The next run, `Client_20260905T131039_308.log`, used repository stub `@::` and
`platform=127.0.0.1:7979`. It successfully created a renderer device, completed
OSStartup and displayed the server-selection screen. Two localhost connections
were rejected by auth with `Invalid transport header checksum`; the client logged
an invalid `getShardList` response (status 0) and `PLATFORM_ERROR_EMPTY_SHARD_LIST`
(4001). The server list was empty. This is not an end-to-end success.

The runner separates HTTPS platform service on **7978** from binary
auth on **7979**. The initial `probe-local-platform.py` identified request method/path or TLS,
omits query/headers/body from its log, and returns HTTP 501 rather than claiming
to implement a shard list. The bootstrap now uses `platform=127.0.0.1:7978`.

The 13:15:54 run identified two TLS records. The 13:20:51 run used a short-lived
self-signed localhost certificate with the TLS diagnostic: the client closed
both negotiations (`SSLEOFError`) before an HTTP request was received, and again
displayed an empty server-selection screen. This does not prove certificate
pinning: trust handling and TLS compatibility must be distinguished next.
No system certificate store was changed and no verification check was bypassed.
The certificate/key are private test files (`platform-cert.pem` and
`platform-key.pem`, key mode 600); the certificate expires after two days.

Asset initialization can exceed the earlier short capture windows. The capture
helper now permits a bounded five-minute run and tolerates disappearing X11
windows. The runner locks the private prefix against simultaneous launches and
directs shader caches to the private writable directory.

The auth service is deliberately handshake-only with the private test key.
Even a successful client RSA exchange will not provide character selection:
application framing, RPCs, login/handoff and world support remain unverified.

### Trusted HTTPS and populated server list (22:21 run)

Installing a private test CA in the isolated Wine prefix resolved the TLS
negotiation failure without bypassing certificate verification. This does not
authenticate a real account. `install-private-platform-ca.py` refuses any prefix
except the runner's `/opt/holocron-test/compatdata/pfx`; system/Steam trust stores
are not modified. The runner uses `platform-server-cert.pem`/`platform-server-key.pem`
signed by this CA, not the earlier self-signed leaf.

`local-platform.py` now implements the two observed GET paths using
`tools/fixtures/platform-responses.json`. Fields are traced in
`docs/retail-protocol-evidence.md`; unknown routes remain HTTP 501. Query strings
and headers are not logged. The real client accepted the responses and logged
one shard, displaying **Holocron Local Test**. Selecting it initially failed
with login error 1003 before any binary auth connection.

The fixture's host now includes the service suffix -- superseded wording below
said `127.0.0.1:7979:castlehilltest`; the canonical value is
`localhost:7979:castlehilltest`. The outer address parser removes the final colon
component before the transport parses host/port; omitting the service therefore
loses the port. A fresh client run is required to validate this correction
because the displayed shard list is cached.

Run the platform regressions with
`python3 -m unittest discover -s tools -p test_local_platform.py -v`.
These check the observed schema/address shape, route handling and query redaction;
they are not an end-to-end login test.
