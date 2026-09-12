# Retail protocol evidence (2026-09-04)

This is a partial static analysis, not a claim that the emulator supports retail.
Addresses below are preferred virtual addresses in the installed x64 `swtor.exe`.
SHA-256: `ad541a742a62500c2095f87c3cff116def462ebd26d1de95de32bc7293eb596b`.
No account credentials or captured session keys are recorded here.

## Repository mode

At `0x1400bdc25`–`0x1400bdc4f`, the client compares the first two UTF-16
characters of `shardaddress` to `@:` using imported `_wcsnicmp` at
`0x14136aa48`. The result controls the branch at `0x1400bdfcb`.
Strings referenced by the two paths include `Client connect to repository`
(`0x14156cc00`) and `Client using repository stub instance` (`0x14156ccc0`).

Existing client logs corroborate that `shardaddress @::` uses the stub and can
reach official character summaries. An explicit `@127.0.0.1:7979:castlehilltest`
instead enters repository connection setup. This does NOT prove local login
or world support. Restore stub mode only as part of an isolated, backed-up test;
do not treat the shardaddress field as an authentication endpoint override.

## RSA envelope

Serializer around `0x140439c1e` calls encryption at `0x140415210`, then writes
six transport-header bytes, a little-endian uint32 original plaintext length,
and hex-encoded ciphertext. Receiver `0x140439d50` compares that declared length
with decoded size and copies only the declared number of bytes.

Encryption loop `0x1404155c5`–`0x140415744` uses 245-byte plaintext chunks,
zero-filling the last chunk before encryption. The encryptor vtable at
`0x141485c40` has MSVC RTTI identifying CryptoPP RSA/PKCS1v15 with
PKCS_EncryptionPaddingScheme. This supports RSA-2048 PKCS#1 v1.5, not OAEP.
Each 256-byte ciphertext block becomes 512 hex characters. A 1034-byte frame
therefore has two blocks, but frame size must not be hardcoded to 1034.

The decoder now honors declared length and variable block count. Its extraction
of two strings followed by four Salsa20 parameters is still a historical-schema
assumption, not yet independently verified against this executable.

## Confirmed key mismatch

At `0x14043e339`, the handshake stores the pointer `0x141ab66b0` in its key
field at object offset `0x188`, with length `0x124`. Function `0x1404399b0`
complements each byte while decoding ASN.1 length. Its output is passed to
the RSA serializer at `0x14043e6a5`.

The source data is at file offset `0x1ab50b0`. Complementing its 292 bytes
produces a valid RSA-2048 public key with exponent 17. Its DER SHA-256 is
`097379cbe069efe8704466fcfb01e760185997ca5a1a7caef56a410b94a5a630`.
Comparing its public numbers with the emulator's historical private key proves
they do not match. Reproduce with `tools/inspect-retail-key.py`; it is read-only
and prints fingerprints and the comparison, not key material.

Without the matching private key, an unchanged client cannot establish this
encrypted session with the emulator. A separately isolated test-client key
configuration or modification is required; the official private key cannot
be derived from this public key. No executable was patched during this analysis.

## Still blocking a retail-compatible local test

- Establish an isolated client using a matching local test key, without routing
  real account credentials through the experimental server.
- Verify plaintext key ordering and cipher activation/framing boundaries.
- Decode real application envelopes and RPC identifiers. Current internal
  PacketReader/PacketWriter and small sequential opcodes are not proven retail.
- Implement and independently validate login, handoff, and character-list
  state transitions before requesting another full game login.

Unit tests use generated keys and synthetic fixtures. Passing them only proves
the implemented parsing mechanics, not retail interoperability or absence of C3.

## Isolated startup evidence (2026-09-05)

The `platform` property is an address: code at `0x14010c6b1` looks up ASCII
`platform` (`0x14156ebc8`), searches its value for `:` at `0x14010c718`, then
splits host/port at `0x14010c760`. Missing/invalid values return explicit
platform-address error strings. Passing a product name here was incorrect.

With `platform=127.0.0.1:7979`, a fresh private-client log at 13:08:46 reached
`PlayerClient::Login` and attempted repository login to the explicit shard
address, returning `LOGIN_ERROR_FAILED_CONNECT_TO_LOGIN_SERVER` (1003).
The auth listener saw no connection. A subsequent run at 13:10:39 using
`shardaddress @::` explicitly logged `Client using repository stub instance`.
These are actual-client observations, not synthetic fixtures. They do not yet
establish an auth exchange, character selection, or a playable world.

The 13:10:39 run subsequently created its graphics device, completed OSStartup,
and displayed an empty server-selection screen. It attempted two connections to
7979, both rejected by the binary listener's header checksum check; the client
reported an invalid `getShardList` response and `PLATFORM_ERROR_EMPTY_SHARD_LIST`.
A separate diagnostic on 7978 in the 13:15:54 run identified **TLS records** on
both connections. Thus the platform endpoint is not the binary auth endpoint.
The client contains `Content-Type: application/json` (file `0x157af40`) and
`/platform/shard/` (file `0x157baa8`); these strings alone do not prove response
schema. The TLS diagnostic logs no query, request headers, body, or credentials.

The unit tests and prepared-public-key/local-private-key synthetic probe were
rerun successfully on this date. The test project suppresses only `NU1900`:
the isolated local runner cannot reach NuGet's vulnerability service index, so
that unavailable external audit feed must not fail protocol tests.

## Platform TLS and response parsing

ClientHello advertises TLS 1.3, 1.2, 1.1 and 1.0 without SNI for the localhost
endpoint. Installing the local CA into the isolated Wine prefix made TLS work:
the 13:32:26 run issued HTTPS GET `/gamepad/lastshard` and `/gamepad/shardlist`,
and its log reported the diagnostic's actual HTTP 501 status. This establishes
the trust fix; it does not establish account authentication.

`receivedShardList` parses the response body into a JSON object at `0x1403dbcd8`,
then reads `shards` into an array at `0x1403dbdae`, optional integer
`accountRegion` at `0x1403dbe7c` and optional bool `environmentDisabled` at
`0x1403dbf50`. Array iteration starts at `0x1403dc200`.

Per-shard fields traced from that loop:

| Fields | JSON type | Reader |
| --- | --- | --- |
| name, host | required string | 0x1403cd200 |
| isup | required boolean | 0x1403cd000 |
| islocked, isguilded | optional boolean | 0x1403cd140 |
| queuewait, loadlevel, timezone, focusid | required integer | 0x1403cd480 |
| region, weight, characters | optional integer | 0x1403cd530 |
| language | optional string | 0x1403cd350 |

The last-shard reader at `0x1403dac94` accepts HTTP 200, then reads required
`name`, `isup`, `host` and optional `environmentDisabled` from the root object.
The first implementation returns an empty/down last shard to open selection,
and one local shard with zero-valued load/queue counters. Enum semantics and
the connection address format need actual-client validation.

## Synchronous login failure (September 5–6)

The populated list is accepted, but selecting the numeric loopback address
fails before auth receives a socket. Temporary failure labels distinguished
`0x14042804a` (address parsing), `0x1404280d5` (connection construction) and
`0x1404280f8` (transport setup). The actual client reported **6102**, identifying
connection construction. The diagnostic restored all three original instructions.

`AsioTcpSocket` has vtable `0x1414b7978`; its endpoint setup at
`0x140461700` invokes resolver `0x14044dbf0`. Query construction at
`0x1404507c9` sets `AI_ADDRCONFIG` (`0x400` in Winsock), AF_INET, SOCK_STREAM,
IPPROTO_TCP. The September 6 Winsock trace shows `getaddrinfo` for `127.0.0.1`
with null service and no resulting address. No connection to port 7979 follows.
A separate loopback-only namespace reproduces native AI_ADDRCONFIG lookup
failure. Hostname resolution in Wine also has special handling: the trace
successfully resolves the machine's own name to loopback. A localhost fixture
trial was then completed: it produces the same 1003 and no auth socket, so it
does not solve the boundary. The namespace contains only `lo`, and a disposable
attempt to add a non-loopback address was denied by its namespace policy.

The address-hint object is built at `0x140450770`: `0x1404507c9` writes
`AI_ADDRCONFIG` (`0x400`), then writes AF_INET, SOCK_STREAM and IPPROTO_TCP.
The next bounded experiment will clear only that resolver-hint bit in the
private test executable and restore the exact original bytes afterward. It does
not alter the Steam executable or make a server-side validation pass.

### Confirmed TCP and RSA boundary (September 6, 12:09)

The bounded private-client probe cleared only the `AI_ADDRCONFIG` immediate and
used the existing `localhost:7979:castlehilltest` shard address. Selecting the
visible local shard then produced a real `connect()` to `127.0.0.1:7979`.
`Holocron.Auth` accepted the connection, sent its 22-byte greeting, received a
522-byte type-4 key exchange, and decrypted/validated the RSA envelope and
historical key-field layout using the test-only key. The client advanced to
`CS_LOGGING_IN` before returning 1003 because auth intentionally closes at that
point rather than invent encrypted application responses.

This confirms the former blocker was resolver configuration, not the shard
schema, port, TLS platform service, RSA key, or binary listener. The copied
client is restored by the probe on exit. The next unresolved boundary is the
encrypted application protocol following the key exchange.

## First encrypted post-handshake message (September 6, 12:52)

A capture-only probe kept the validated connection open without sending any
application reply. The client sent **46 encrypted bytes** before the server
closed; their decrypted stream SHA-256 was
`1AA76070FDE4B7EF4B4E4AB4763BF54B61007541240A91B903346DCB2175E6D7`.
Therefore the next boundary is client-first, not a missing server-first login
message. The next repeat will retain only the decrypted six-byte transport
header (and a digest), never application payload or credentials.

The repeat established a stable decrypted header: `10 2E 00 00 00 C1`.
It is a type-`0x10` encrypted transport frame with a total length of 46 bytes
(40-byte payload). The next minimal capture retains only its first eight payload
bytes, sufficient to classify the inner message without recording a string or
credential field.

That bounded prefix capture produced `00 58 1C 01 00 E8 A7 E6` after the
transport header. The first byte and following three-byte/word-looking region
must be treated as an unclassified inner envelope: the remaining bytes vary
per session, and the project's legacy `Opcode` enum is not evidence of its
retail meaning. The next step is static tracing of the installed client's
type-`0x10` receive/send handler before attempting a response.

## Encrypted type-`0x10` dispatch envelope (September 6, 13:13)

The client receive path at `0x14043bbe0` validates the six-byte transport
header, treats bit `0x10` as the encrypted-frame flag, and routes low-nibble
zero to `0x14043cf20`. Thus `0x10` is an encrypted transport class, not a
legacy application opcode.

`0x14043cf20` skips the transport header and calls `0x140454070`, which reads
the first eight decrypted payload bytes as one little-endian `uint32` followed
by two little-endian `uint16` values. The two `uint16` values are used for a
registered receive-handler lookup; the `uint32` is forwarded to that selected
handler. This establishes the inner envelope layout without retaining a login
body. The observed client-first prefix is consequently consistent with
`uint32 0x011c5800` followed by a session-varying 16-bit routing pair.

A test-only server mode now sends a **bounded structural probe**: after reading
the client's fully framed encrypted request, it returns type `0x10` containing
only the observed eight-byte dispatch envelope, encrypted with the validated
server-to-client Salsa20 stream. It does not retain or interpret the remainder
of the login request. This is not yet a claim that an empty correlated envelope
is a valid login response: the first run closed at server selection before a
connection was made, so that runtime hypothesis remains untested.

### Confirmed encrypted checksum rule (September 6, 13:31)

The corrected raw receive probe decrypted the client header again as
`10 2E 00 00 00 C1`. This disproved the repository helper's prior checksum
rule, not the cipher direction: for a transport type with a nonzero high
nibble, the client complements the XOR of the first five bytes. For this
frame, `0x10 ^ 0x2e = 0x3e`, and its one-byte complement is `0xc1`.

`TransportFrame` now implements and regression-tests that rule. Consequently
the next server response must be an encrypted type-`0x10` frame with the same
complemented checksum convention. The prior empty-envelope response was never
transmitted because the server correctly rejected the request under the old
local checksum implementation; its semantic acceptance remains untested.

### First correlated response rejected (September 6, 13:37)

With the checksum correction deployed, the isolated client completed the RSA
exchange and sent the same 46-byte encrypted request twice. The server parsed
the dispatch envelope as `message=0x011C5800`, `route=0xE800/0xE6A7`, then
sent a 14-byte encrypted type-`0x10` response containing exactly those eight
routing bytes and no application body. The client closed the connection on
each attempt without sending another transport frame, then reported its normal
1003 login failure.

This is a **disproven hypothesis**: matching transport framing, cipher stream,
message value, and routing pair alone is insufficient. The first valid server
response needs a non-empty, message-specific payload (and possibly a different
response message/routing combination). The next unresolved boundary is the
handler selected for the `0x011C5800` request and the exact response body it
requires. No credential or full decrypted login payload was retained.

### Receive-side reconnaissance for the first encrypted login response (September 6)

**CONFIRMED — raw transport through envelope dispatch.** `0x14043bbe0` validates
the six-byte transport frame, including the complemented checksum for a
nonzero high nibble, and directs encrypted low-nibble-zero frames to
`0x14043cf20`. That function skips the six-byte header and calls
`0x140454070`. The latter performs the three bounded reads: `uint32` at payload
offset 0, `uint16` at offset 4, and `uint16` at offset 6. It rejects a payload
shorter than eight bytes before any message-specific code can run.

**CONFIRMED — routing is a pair-key lookup, not a direct message-ID switch.**
After the envelope read, `0x14043cf20` looks up `(routeA, routeB)` in the
ordered runtime map rooted at receiver-context offset `+0x58`; the map node
keys are at `+0x20` and `+0x24`, respectively. For the observed request that
means the lookup key is `(0xE800, 0xE6A7)`. The `uint32 message` is preserved
separately. This is why a static search has no direct literal xref for
`0x011C5800` (nor for the packed observed route bytes).

**CONFIRMED — asynchronous dispatch boundary.** The selected route endpoint is
resolved through `0x140414250` from endpoint offset `+0x70`, then
`0x1404360a0` creates and queues a 0x58-byte event. Its confirmed fields are
the `uint32 message` at event offset `+0x28`, `uint16 routeA` at `+0x2c`, and
the remaining packet reader/body at `+0x30`. The queue insertion is
`0x1403fc0b0`; therefore no response parser is synchronously invoked by
`0x14043cf20` itself.

**CONFIRMED — alternate global message path is not the response parser.**
Before the route event is queued, `0x14043cf20` calls `0x14042b990` with the
message in `r9d`. That function only compares `r9d` to several unrelated
generated constants and returns whether one of those global cases consumed the
event. `0x011C5800` is not present as a direct comparison in that function, so
the observed login message falls through to the route-selected endpoint.

**HYPOTHESIS.** The missing parser belongs to the executor/endpoint resolved
from the live `(0xE800,0xE6A7)` map entry, and will consume the queued event
body beginning at offset 8. This is consistent with the empty-body response
disconnect, but it does *not* establish that the response repeats
`0x011C5800`, repeats the route pair, or starts with a status field.

**UNRESOLVED.** The response message-ID relationship, endpoint's concrete
parser address, minimum body length, status-success value, required session or
challenge fields, and next state transition remain unknown. No protocol-grounded
response body can yet be constructed.

**Next-session starting point.** Instrument the isolated client at the queue
consumer for events inserted by `0x1403fc0b0`, filtered solely to
`message=0x011C5800` and routes `0xE800/0xE6A7`. Record only the eventual
virtual/parser target and body read offsets/length checks (not body contents).
This will resolve the runtime endpoint without revisiting RSA, transport, or
envelope framing.

### Filtered queue-callback runtime result (September 6)

**CONFIRMED.** The event virtual method at `0x140434770` is the narrow callback
boundary: it loads an endpoint object from event offset `+0x18`/`+0x100`, loads
the endpoint vtable slot at `+0x30`, then invokes it at `0x1404347eb` with the
event's message (`r8d`) and routeA (`r9d`). A managed GDB breakpoint at that
instruction was filtered to `message=0x011C5800` and `routeA=0xE800`.

**CONFIRMED — the earlier route-rejection inference is disproven.** In a
resolver-enabled isolated run, a breakpoint at `0x14043cf20` fired after the
bounded 14-byte echoed probe arrived. In that same probe, the route-miss branch
at `0x14043d029` did not fire. Therefore the response reaches the encrypted
receive handler and does not take that particular ordered-map miss branch. The
request route pair is not thereby proven to be a valid response route, but it
is no longer evidence-based to describe it as rejected before route resolution.

**CONFIRMED — envelope reader contract.** `0x14043cf20` calls
`0x140454070` before its map lookup. The helper reads exactly, in order,
`uint32 message`, `uint16 routeA`, and `uint16 routeB`, advancing its reader
after each field. It invokes the client's bounded-reader failure path if fewer
than 4, then 2, then 2 bytes respectively remain. Thus the envelope itself has
a minimum of eight bytes; the empty echoed probe meets that structural minimum,
but has no message body.

**UNRESOLVED — reliable post-reader trace.** Host-side GDB attaches are across
the bubblewrap PID namespace. GDB reports unreliable thread events there and
Wine `SIGUSR1` initially stopped the game thread, so post-reader/callback
breakpoint non-hits from those sessions are not protocol evidence. A trace-only
`HOLOCRON_GDB_INNER=1` launcher mode starts GDB *inside* the isolated namespace
after the copied client starts. It preserves the private copy and avoids
`strace`, but the current kernel ptrace policy rejects that sibling attach
(`Operation not permitted`). No installed `gdbserver` was available. This is a
tooling limitation, not a client protocol result.

**Exact next breakpoint/action.** Use a debugger server started as the target's
parent (or an explicitly provisioned in-namespace `gdbserver`) rather than a
sibling attach. With the same bounded echoed probe, set `handle SIGUSR1 nostop
noprint pass`, then break at `0x14043cf98` (immediately after `0x140454070`).
Record only the three decoded structural fields from the local outputs. If they
are not sentinels, continue to `0x14043d29d` to record the global-consumed
Boolean and endpoint entry pointer. This cleanly distinguishes envelope
decoding, global consumption, and route endpoint dispatch before investigating
any body parser.

### Late WineDbg attachment inside the existing Proton session (September 7)

**CONFIRMED — direct private-Wine invocation joins the existing session.** The
dormant in-namespace helper now waits for SWTOR, reads only the allowlisted
Wine/Proton context from that running `swtor.exe` process (`WINEPREFIX`, Wine
loader/server settings when present, DLL/library paths, `PATH`, relevant
`STEAM_COMPAT_*` paths, and Steam app IDs), then runs Proton's private
`files/bin/wine winedbg.exe` directly. It does **not** call `proton run`, so it
does not invoke the Proton Steam bootstrap path a second time. `info proc`
returned the existing `swtor.exe` as Windows PID `0x134` (decimal 308), alongside
the already-running wineserver clients.

**CONFIRMED — late WineDbg GDB proxy.** WineDbg accepts the Windows PID as a
decimal argument: using the hex text from `info proc` directly was **DISPROVEN**
because WineDbg interpreted bare `00000134` as octal (`0x5c`). With decimal 308,
`winedbg.exe --gdb --no-start --port 27979 308` attached to `swtor.exe`, opened
the local GDB proxy, and GDB inside the same namespace connected successfully.
The live client disassembled the expected instructions at `0x14043cf98`
(`mov [rsp+0x60],rbx`) and `0x140434770` (callback prologue), then remained
running after the detached address-inspection probe. This establishes a stable
late-attach path without debugger ownership during initialization.

**CONFIRMED — precise post-reader locals for the filtered trace.** In
`0x14043cf20`, the call to `0x140454070` receives output locations
`[rsp+0x58]` (message `uint32`), `[rsp+0x30]` (routeA `uint16`), and
`[rsp+0xf8]` (routeB `uint16`). The reusable GDB trace filters to
`message=0x011c5800` before printing those structural fields. At
`0x1404347eb`, it filters `r8d=0x011c5800` and `r9w=0xE800`, and prints only
the resolved endpoint virtual target in `r14`; it does not inspect the body.

### Late-attach selection result (September 7)

**CONFIRMED — the stable late attachment survives a real isolated selection.**
With the bounded test-only resolver adjustment active, a selected Holocron
Local Test row connected to `Holocron.Auth`, completed the RSA exchange, sent
the 46-byte type-`0x10` request, received the bounded 14-byte encrypted echoed
envelope, and closed immediately afterward. This repeats the prior observed
rejection with the client attached late rather than launched under a debugger.

**DISPROVEN — the current WineDbg GDB proxy can instrument this live client
reliably.** The proxy attached and served GDB, but emitted
`dbg_thread_set_single_step set_context failed` for the SWTOR threads during
the live response. Consequently neither the filtered post-reader breakpoint
at `0x14043cf98` nor the callback breakpoint at `0x1404347eb` fired, even
though the auth log confirms the echoed envelope was sent and the client
closed. This is a debugger backend limitation in this run, not evidence that
the envelope failed to reach either breakpoint or that a particular parser
rejected it.

**UNRESOLVED.** No authoritative dynamic parser target, body length check, or
status field was recovered from this session. Therefore no minimum
evidence-backed correction to `Holocron.Auth` is justified yet; the empty
correlated response remains an observed rejection, not a body schema.

### Native WineDbg breakpoint discriminator (September 7)

**CONFIRMED — native WineDbg can attach and install an address breakpoint.**
Using the same dormant-helper late attachment (not the GDB proxy), native
WineDbg attached to the normally initialized `swtor.exe`, installed breakpoint
1 at `0x14043cf98` (`swtor+0x43cf98`), and `info break` reported it enabled.
The client remained visible and completed the bounded local selection.

**DISPROVEN — native WineDbg resolves the live-context/breakpoint limitation.**
In a bounded echoed-envelope run, `Holocron.Auth` confirmed receipt of the
46-byte type-`0x10` request, sent the 14-byte encrypted correlated envelope,
and observed the client close twice. Native WineDbg never reported a trap at
the enabled `0x14043cf98` breakpoint and emitted `Cannot set ctx on <TID>` for
a SWTOR thread. This distinguishes successful breakpoint installation from
runtime trapping: it appears installed but cannot establish usable context for
the relevant live thread. No wider WineDbg breakpoint plan is warranted in
this environment.

**HYPOTHESIS — static and non-invasive boundary evidence are now the only
reliable parser-recovery path in this setup.** Both the GDB proxy and native
WineDbg frontend exhibit the live-thread context limitation after successful
late attach. This does not identify the parser or validate an empty body; it
only closes the dynamic WineDbg-breakpoint branch under the current isolation.

### Static callback reconstruction (September 7; superseded)

**SUPERSEDED IN FULL.** This subsection records an intermediate reconstruction.
Its four-argument callback ABI and route-map ownership description are corrected
by the audited section below and must not be used as current evidence.

**CONFIRMED — callback object contract at `0x140434770`.** The complete
callback-boundary function establishes the following neutral layout:

```text
event +0x18             route-map value / owner object
event +0x28             message (uint32)
event +0x2c             routeA (uint16)
event +0x30             inline body-reader object
&event +0x30            callback reader argument
route-map-value +0x100  endpoint/consumer object
endpoint vtable +0x30   indirect callback target
```

At `0x140434770`, the code loads `endpoint = [event+0x18] + 0x100`, reads
`callback = [endpoint vtable + 0x30]`, and invokes the callback using the
Windows x64 assignments:

```text
rcx = endpoint
rdx = &event + 0x30
r8d = event->message
r9d = zero-extended event->routeA
call callback
```

The callback boundary therefore has the structural form
`callback(endpoint, bodyReader, message, routeA)`. There is no fifth argument
for `routeB`. The event constructor at `0x1404360a0` initializes the inline
reader and copies the unread source-reader bytes into it before inserting the
event with `0x1403fc0b0`. The reader methods maintain the body buffer and
cursor/end state; no body bytes were retained or printed.

**CONFIRMED — `routeB` is lookup-only at this boundary.** `0x14043cf20`
decodes `routeB` into its local at `[rsp+0xf8]`, compares `(routeA, routeB)`
against the ordered map rooted at receiver-context `+0x58`, and obtains the
route-map value from node `+0x28`. `0x1404360a0` then receives that value as
its `rcx` object and the event owns it through `event +0x18`. The callback
does not receive a copied `routeB` field. Consequently, a proposed response
contract that relies on passing `routeB` through the queued event is ruled
out, while the response’s route pair itself remains unproven.

**STATIC LIMIT — endpoint origin is narrowed but not yet concrete.** The
consumer object is not installed by `0x140434770`; it is the `+0x100` field of
the route-map value selected by the pair-key tree. The current executable
disassembly has not yet established the registration call that populates that
field or the concrete endpoint vtable instance for `(0xE800, 0xE6A7)`. The
nearby code that initializes the queue and generic reader/container vtables
is not evidence of the login parser and is intentionally not being promoted
to a handler candidate.

**NO RESPONSE CHANGE JUSTIFIED.** The static boundary proves that the empty
body reaches an asynchronous endpoint callback only if the map value and its
`+0x100` consumer are valid; it does not prove a minimum body size, status
field, response message, or success transition. `Holocron.Auth` therefore
remains unchanged pending the concrete endpoint registration/vtable path.

**Dynamic tracing status is closed.** WineDbg GDB-proxy and native WineDbg
both attached and read retail code/memory, but neither could establish usable
live thread context for breakpoint execution. Their non-hits are not parser
evidence. Do not retry debugger modes, breakpoint variants, PID attachment
variants, parent GDB, fork tracing, namespace entry, or debugger-at-startup
approaches for this phase.

### Nested endpoint resolution recovered statically (September 7; superseded)

**SUPERSEDED IN FULL.** The claimed second lookup through `holder +0x70` was a
misclassification of a synchronized retained-pointer load. See the audited
section below for the direct composite-key map value and ownership chain.

**CONFIRMED — the endpoint holder is reached through two lookups.** The
control flow in `0x14043cf20` is more specific than a single direct
route-to-endpoint map:

```text
decoded routeA/routeB
  → ordered tree rooted at receiver-context +0x58
  → matching node +0x28 = first holder object
  → holder +0x70 = nested lookup structure
  → nested lookup result written to a local temporary
  → result passed as rcx to 0x1404360a0
  → event +0x18 = nested lookup result
  → event +0x18 + 0x100 = endpoint object
```

The first tree compares the two 32-bit zero-extended route components at node
offsets `+0x20` and `+0x24`. The selected node value at `+0x28` is retained as
the holder. After the call to `0x14042b990` returns the observed message as
not globally consumed, the receive function checks the holder and performs a
second lookup through `holder +0x70`; the result is the object used by the
`0x1404360a0` event constructor. This means the earlier shorthand
“route-map value +0x100” was structurally correct for the event owner but
omitted the intermediate holder and nested lookup.

**CONFIRMED — no direct routeB-to-callback argument exists.** `routeB` is
consumed by the first tree only. The nested result, rather than either route
component, supplies the event owner. The callback still receives only
`(endpoint, &event+0x30, message, routeA)`.

**UNRESOLVED — concrete nested entry type and callback target.** Static
disassembly has now narrowed the required backward trace to the code that
populates the holder’s `+0x70` nested structure and the nested-entry
`+0x100` field. No response body field is justified until that registration
path resolves the nested entry’s vtable and slot `+0x30`. The current empty
response therefore remains unsuitable for a server-side correction.

### Nested value, endpoint registration, and callback recovery (September 7; superseded)

**SUPERSEDED IN FULL.** This subsection conflates `omega::Connection` with the
`omega::ObjectSurrogate`, attributes the event owner to the wrong constructor,
and treats a transient base vtable as the route-specific final vtable. The
addresses remain useful archaeology only; the audited section below is
authoritative.

The preceding “UNRESOLVED” statement is superseded by the concrete static
chain below. The `+0x70` operation is not a second key comparison in the
receive function: `0x140414250` performs a synchronized load of the pointer
stored at its argument, temporarily using the value `1` as its lock marker,
and returns the loaded pointer through the caller’s output slot. The loaded
pointer is reference-counted; callers increment/release the object through its
virtual methods.

**CONFIRMED — nested lookup value layout and event ownership.**

```text
outer tree node +0x28       = holder object
holder +0x70                = synchronized pointer slot
0x140414250(holder +0x70)   = loaded nested value pointer
0x1404360a0(rcx=nested)     = event construction
event +0x18                  = nested value pointer
nested value +0x100         = endpoint pointer
```

The nested value object is initialized by `0x140434da0`, which installs
vtable `0x1414b6850`, initializes `+0x70` to null, and initializes `+0x100`
to null. Registration helper `0x140435130` receives that value as `rcx` and
the endpoint as `rdx`; after its state checks it performs the direct store
`[value + 0x100] = rdx`. Its caller `0x14040a9a0` obtains the nested value
from the registration/tree helper and passes the endpoint object as the
original `rcx` supplied to that helper. Thus `event +0x18` is the nested
value object itself, not an additional wrapper introduced by the event
queue.

**CONFIRMED — endpoint vtable and concrete callback for this registration
family.** One concrete registration site at `0x140426d56` invokes
`0x14040a9a0`; the endpoint object is subsequently initialized with vtable
`0x1414b7550`. Its relevant vtable entries are:

```text
endpoint vtable              = 0x1414b7550
vtable +0x30                 = 0x14045a1c0
```

Adjacent entries are also populated with concrete methods, including the
destructor/state methods at slots `+0x00`, `+0x08`, `+0x10`, `+0x18`, `+0x20`,
`+0x28`, and later slots. The repeated `0x140ff9700` entries in the separate
holder vtable are import thunks and are not the endpoint callback used here.

**CONFIRMED — callback dispatch and first body-dependent validations.**
`0x14045a1c0` consumes arguments as `rcx=endpoint`, `rdx=inline body
reader`, `r8d=message`, and `r9d=routeA`. It dispatches on `message`. For
the concrete case `message == 0x2CFF577B`, it reads the inline reader fields
`[reader+0x0c]` (cursor), `[reader+0x10]` (end), and `[reader+0x18]` (data
pointer), requiring `end - cursor >= 4`; otherwise it branches to
`0x14045AAAC`, whose repeated calls to `0x1403FA710` are the reader bounds
failure path. On success it reads `field_00_u32` at the current cursor,
advances the cursor by four bytes, and applies the observed threshold
normalization against constants `0x2329` and `0x232A` before continuing.

The same callback has additional body-reading cases. For example, the
`message == 0xEE36C3E4` case first requires four bytes, reads a `u32`, then
requires and reads another `u32`, then requires two bytes and reads a `u16`
that is bounded to `0x08`. These are structural parser facts; no semantic
field names are assigned.

The callback’s default branch for an unlisted message calls generic handler
`0x14040AE50`; that path performs context/state cleanup and does not show a
message-specific body read before returning. The callback therefore provides
a concrete parser contract for its registered message cases, but not a
proven body contract for every message value.

**CURRENT RESPONSE FATE — static evidence.**

```text
transport accepted                 CONFIRMED by existing receive behavior
envelope reader                    CONFIRMED; reads message, routeA, routeB
outer (routeA, routeB) lookup      CONFIRMED in receiver-context +0x58 tree
nested +0x70 load                  CONFIRMED; synchronized pointer load
endpoint selected                  CONFIRMED for a non-null nested value
callback selected                  CONFIRMED for endpoint vtable 0x1414b7550
message-specific dispatch          CONFIRMED in 0x14045a1c0
message-specific body validation   only for the listed callback cases
observed message 0x011C5800        not equal to the recovered case constants
first failing condition             unresolved for this observed message
```

The observed `0x011C5800` response message does not match the concrete
message cases recovered in `0x14045A1C0`, so static evidence currently points
to its default path rather than to the four-byte parser case. This does not
prove that the observed message is invalid: the route-specific endpoint
registration that selects the exact login consumer among the several
`0x14040a9a0` registration families is not yet discriminated by a static
reference to `(0xE800, 0xE6A7)`.

**HYPOTHESIS.** The concrete registration family above may be a neighboring
protocol endpoint rather than the login endpoint. The meanings of the
message constants, `field_00_u32`, and the threshold values remain
unproven.

**DISPROVEN / SUPERSEDED.** The direct route-map-to-endpoint shorthand is
incomplete; the authoritative path includes the holder’s `+0x70`
synchronized nested value load. `routeB` remains lookup-only and is still
not a callback argument.

**NO `Holocron.Auth` CHANGE.** No single evidence-backed response correction
is justified yet. Changing the body or message now would conflate the
unresolved route-specific endpoint selection with a neighboring parser
contract.

### Audited route orientation, ownership, and endpoint attribution (September 7)

This section supersedes all three intermediate static-reconstruction sections
above. It records a senior verification pass against the retail disassembly and
the exact outbound and inbound serialization sites.

**CONFIRMED — the receive registry is one composite-key tree, not two
lookups.** At `0x14043CFBD`–`0x14043D02E`, the receiver searches the ordered
tree rooted at receiver-context `+0x58`. The lexicographic key is the pair of
decoded incoming route words:

```text
tree node +0x20 = incoming route word 1 (zero-extended dword)
tree node +0x24 = incoming route word 2 (zero-extended dword)
tree node +0x28 = omega::Connection pointer
```

A miss branches at `0x14043D029` to the receive function's return at
`0x14043D367`; no queued event, endpoint, callback, or body parser is reached.
`0x140414250`, previously described as a nested lookup, is a synchronized
retained-pointer load that temporarily uses pointer value `1` as a lock marker.

**CONFIRMED — registration and wire route order are opposite directions.**
`0x140412180` stores its route argument at `Connection +0x60` and calls
`0x14043D380`. That insertion helper constructs the receive key as:

```text
key word 1 = Connection +0x60
key word 2 = Connection +0x28
value      = Connection
```

The control-setup parser at `0x14042C910` supplies its first parsed `u16` to
`0x140412180`, making it `Connection +0x60`. Its second parsed `u16` is used by
`0x14042A950` to retrieve an `omega::ObjectSurrogate`; `0x140411D30` copies
that surrogate's local ID from `ObjectSurrogate +0x28` to `Connection +0x28`.

Normal outbound envelope construction uses the reverse order. At the concrete
serialization site in `0x14045AAF0`, `0x14045AC6A` appends
`Connection +0x28` first and `0x14045AC77` appends `Connection +0x60` second.
Thus the observed client request routes mean:

```text
outgoing request routeA = 0xE800 = Connection +0x28 (client-local ID)
outgoing request routeB = 0xE6A7 = Connection +0x60 (peer/server ID)

client receive-tree key = (Connection +0x60, Connection +0x28)
                        = (0xE6A7, 0xE800)
```

The existing echoed response `(0xE800,0xE6A7)` therefore cannot select the
`Connection` that originated the request: that object's registered receive key
is `(0xE6A7,0xE800)`. Static code alone does not inventory the live tree, so it
cannot exclude an unrelated entry with the unswapped pair. If no such unrelated
entry exists, the packet takes the map-miss return at `0x14043D029`. A
structurally correlated response must reverse the words to
`(0xE6A7,0xE800)`.

**CONFIRMED — object ownership and endpoint installation.** On a successful
receive lookup, the map value is an `omega::Connection`. The receive path
checks its state, loads `Connection +0x70` with `0x140414250`, and passes the
loaded `omega::ObjectSurrogate` to `0x1404360A0`. The actual chain is:

```text
receive tree node +0x28 = omega::Connection
Connection +0x70        = retained omega::ObjectSurrogate
event +0x18             = retained omega::ObjectSurrogate
event +0x20             = retained omega::Connection
event +0x28             = message (u32)
event +0x2c             = incoming route word 1
event +0x30             = inline body reader
ObjectSurrogate +0x100  = endpoint
```

`0x140435130` performs the direct `ObjectSurrogate +0x100 = endpoint` store at
`0x1404351A2`, then calls `0x14042AA30` to allocate/store the surrogate's
16-bit local ID at `+0x28`. `0x14042A950` is the corresponding ID lookup.
`0x140434DA0` constructs a separate `0x1C0`-byte object and is not the queued
event's owner.

**CONFIRMED — corrected callback ABI.** `0x140434770` invokes virtual slot
`endpoint vtable +0x30` with five arguments under the Windows x64 ABI:

```text
rcx             = endpoint = [event +0x18] +0x100
rdx             = temporary retained reference to event +0x20 Connection
r8d             = event +0x28 message
r9d             = zero-extended event +0x2c incoming route word 1
stack argument 5 = &event +0x30 body reader
```

Incoming route word 2 participates in the composite lookup but is not passed
independently to the callback.

**CONFIRMED — `ServerProxy` is a real endpoint family, but not attributed to
the echoed route pair.** Constructor `0x140426CB0` registers the object through
`0x14040A9A0` at `0x140426D56`, using the name
`OmegaServerProxyObjectName`. RTTI identifies:

```text
0x1414B7550 = ServerProxyBase vtable (installed transiently)
0x1414B65E0 = omega::ServerProxy final vtable
```

Both vtables have slot `+0x30 = 0x14045A1C0`. The constructor installs the
base vtable at `0x140426DB2` and replaces it with the final derived vtable at
`0x140426DDD`. Therefore `0x1414B7550` is legitimate but is not the final
concrete vtable of the initialized object.

The runtime local ID `0xE800` is allocated by `0x14042AA30`. Static evidence
examined so far does not reconstruct enough startup allocation order to prove
that the surrogate whose local ID becomes `0xE800` owns this `ServerProxy`.
More importantly, the wire pair `(0xE800,0xE6A7)` cannot select the originating
connection's endpoint; it cannot be evidence for `ServerProxy` attribution.

**CONFIRMED — conditional behavior of candidate callback `0x14045A1C0`.** If
the corrected route pair selects the `ServerProxy` family, message
`0x011C5800` takes the default branch at `0x14045A733`. That branch does not
read stack argument 5 or consume body bytes. It retains the supplied
`Connection`, calls `0x14040AE50`/`0x14040B010`, and transitions through
`0x1404123D0(Connection, 2, 11)` or
`0x14043ADF0(context, 0, 1, 11)` according to connection state. The callback
returns `void`; the caller does not inspect a result. Structurally this is a
failure/connection-state transition with code `11`, not a silent ignore.

This behavior remains conditional because exact runtime ID-to-endpoint
attribution for the corrected pair has not yet been proven. The unrelated
explicit case `0x2CFF577B` has a four-byte `u32` body read, but that parser is
not evidence for the observed message.

**CURRENT ECHOED RESPONSE FATE — confirmed static control flow and explicit
runtime-content limit.**

```text
Stage                              Current response (011C5800/E800/E6A7)
---------------------------------------------------------------------------
encrypted transport/frame          accepted by the observed receive attempt
application envelope               message and two route words are readable
routeA/routeB composite lookup      cannot match the originating Connection
exact live-tree result              unresolved: miss or unrelated registration
originating Connection selected     no
originating ObjectSurrogate         no
originating endpoint/callback       no
message/body handling               not attributable from static code alone
first proven protocol defect        route fields have the wrong direction
```

**HYPOTHESIS / unresolved after this pass.** Once the response routes are
reversed, the surrogate identified by local ID `0xE800` may belong to the
login-related `omega::ServerProxy` family, but the static allocator order does
not yet prove it. Consequently `0x011C5800` is neither confirmed nor disproven
as a valid response message, no alternate response message is evidence-backed,
and no relevant minimum body contract has been recovered. Discriminating the
unswapped pair's exact live-tree result would require either a trustworthy
runtime tree inventory or a complete reconstruction of startup registrations;
neither is necessary to establish the route reversal required for the
originating connection.

**DISPROVEN / superseded.** The following are not current evidence:

- an outer tree followed by a nested route lookup at `holder +0x70`;
- `0x140434DA0` as the constructor for the event owner;
- a four-argument callback with the reader in `rdx`;
- `0x1414B7550` as the final route-specific endpoint vtable;
- `(0xE800,0xE6A7) → 0x1414B7550/0x14045A1C0`;
- the `0x14045A1C0` default branch as the fate of the currently echoed packet.

**MINIMUM EVIDENCE-BACKED SERVER CORRECTION.** Reverse only the two route
words in the bounded empty-envelope response. Preserve message `0x011C5800`
and preserve the empty body so the next isolated observation discriminates
route selection from message/body validity. No credentials, account data,
tokens, or authentication checks are changed.

### Route-reversal build and isolated-run validation (September 7)

**CONFIRMED — the route-reversal probe was built from the current source.**
The Debug `Holocron.Auth` artifact used by
`tools/launch-isolated-client.sh` was rebuilt with .NET SDK `8.0.424`. Its
UTF-16 metadata contains the log marker `Sent encrypted empty route-reversed
envelope`, and its timestamp postdates the route-reversal source edit. The
complete Debug solution test suite then passed: **44/44**.

**CONFIRMED — the isolated client executable remained the prepared private
copy.** After the run, its SHA-256 matched
`.local-test/client-v1/manifest.json`. No resolver/failure-label/debugger patch
was enabled by this validation; only the normal private launcher and the
`HOLOCRON_AUTH_ECHO_EMPTY` probe flag were used.

**INCONCLUSIVE — no application-protocol observation was produced.** One
60-second run and one documented 300-second bounded run started the loopback
Auth, World, and HTTPS platform services and launched the private client.
During the 300-second run the Auth log recorded no TCP connection, therefore
no RSA exchange, encrypted type-`0x10` request, or reversed response occurred.
The route-reversed envelope was never sent. The client consumed mounted assets
and emitted only non-protocol Proton/private-prefix diagnostics in the captured
structural logs.

This is **not** classification C (identical post-response behavior): the
experiment did not reach the response boundary. It provides no behavioral
confirmation or refutation of route reversal, message `0x011C5800`, the empty
body, `ServerProxy` attribution, or the conditional failure-code-11 path.

**NEXT VALID DISCRIMINATOR.** Restore a normal isolated client path that reaches
the existing binary Auth request boundary, then repeat this exact one-variable
probe with `(message, routeA, routeB, body) =
(0x011C5800, 0xE6A7, 0xE800, empty)`. Do not change the message or body until
that boundary is observed.

### Empty server-list correction (September 7)

**CONFIRMED — the visible server list is not populated from the persisted
`LastPlayedShard` settings.** The private account settings continued to contain
`Holocron Local Test` and `localhost:7979:castlehilltest`, but the retail client
obtains the selectable catalog from the HTTPS platform requests
`/gamepad/lastshard` and `/gamepad/shardlist`. The local fixture is the source
of the one selectable entry; it supplies the same name, target, and `isup: true`
state.

**CONFIRMED — the immediate empty-list cause was expired private TLS
credentials.** Both the private platform CA and its `127.0.0.1` leaf expired at
2026-09-07 20:31:53 UTC. In the subsequent isolated runs the platform listener
started but logged no HTTP request, while the client logged status `0` for
`getShardList` and `PLATFORM_ERROR_EMPTY_SHARD_LIST`. This explains why the
persisted last-shard values did not create a selectable entry.

**CONFIRMED — test-only correction and validation.** The expired, ignored
private CA and leaf were rotated with a fresh 365-day CA, a `127.0.0.1` leaf
with an IP subject-alt-name, and the CA was installed only into the existing
private Wine prefix. No Steam file, host trust store, bootstrap, response
fixture, or protocol field changed. A normal isolated client then completed
both local HTTPS GETs, parsed one shard, and logged the expected
`@localhost:7979:castlehilltest` target after selection.

**INCONCLUSIVE — all recent no-TCP route-reversal runs.** Their server list was
empty, so no selection could reach resolver invocation, TCP, RSA, or the
reversed application envelope. They neither confirm nor refute route reversal,
message `0x011C5800`, or the empty response body. A normal list-restoration
validation selected the entry without the resolver patch and consequently
failed at the already-known loopback resolver boundary; it is likewise not a
route-reversal result.

### Manual reversed-route result (September 7)

**CONFIRMED — the single-variable route-reversal response was physically
observed.** After the repaired catalog returned one selectable shard, the
private resolver patch was live and the client selected
`@localhost:7979:castlehilltest`. `Holocron.Auth` accepted TCP, completed the
validated RSA handshake, received the 46-byte type-`0x10` request
`message=0x011C5800, route=0xE800/0xE6A7`, and sent exactly one 14-byte
encrypted type-`0x10` response with `message=0x011C5800`, route
`0xE6A7/0xE800`, and an empty body. No other protocol field changed.

**CONFIRMED — classification C.** The client sent no subsequent encrypted
frame, closed the correlated connection, and logged the normal 1003
`LOGIN_ERROR_FAILED_CONNECT_TO_LOGIN_SERVER`. This is behaviorally identical
to the earlier same-message/empty-body echoed-envelope runs, but unlike the
previous no-connect probes it is a valid post-response observation. Route
reversal is retained because the static receive-key correction is still
required even though it is insufficient.

**NEXT STATIC QUESTION.** The next evidence task is whether the reversed key
`(0xE6A7, 0xE800)` selects `omega::ServerProxy` and callback `0x14045A1C0`,
and whether echoed message `0x011C5800` is itself invalid for that endpoint.
Message ID, body, transport framing, encryption behavior, and the corrected
route direction must remain unchanged until that attribution supplies new
evidence.

### Corrected-key endpoint attribution and reply dispatch (September 8)

**CONFIRMED — the corrected receive key selects the registered
`omega::ServerProxy` endpoint.** The earlier allocator-order limitation is
superseded by a concrete connection-setup chain:

```text
0x140405780 constructs omega::ServerProxy
  -> wrapper +0x08 = ServerProxy
  -> controller +0x10 = wrapper

ConnectionObject::beginConnection (0x140135490)
  -> controller +0x10 -> wrapper +0x08
  -> 0x140427F10(ServerProxy, login inputs)
  -> creates the Auth transport connection and stores it at ServerProxy +0x80
  -> 0x14043E2D0(transport connection, ServerProxy)
  -> transport connection +0x1b8 = ServerProxy +0x10 ObjectSurrogate

omega connection setup (0x14042C910)
  -> 0x14042A950 resolves the local route ID to that ObjectSurrogate
  -> 0x140411D30 constructs the omega::Connection
  -> Connection +0x70 = retained ObjectSurrogate
  -> Connection +0x28 = ObjectSurrogate +0x28 local ID
  -> 0x140412180 installs the peer ID and composite receive-tree entry
```

The live request supplies the final route values for that statically identified
connection: outgoing `(Connection +0x28, Connection +0x60) =
(0xE800,0xE6A7)`. The one-tree receive key is reversed, so incoming
`(0xE6A7,0xE800)` retrieves that same `omega::Connection`. The already-proven
receive event then follows `Connection +0x70 -> ObjectSurrogate +0x100 ->
endpoint`.

`0x140426CB0` registered this endpoint under
`OmegaServerProxyObjectName`. Its initialized concrete vtable is
`0x1414B65E0`; vtable slot `+0x30` is `0x14045A1C0`. The promoted chain is:

```text
(E6A7,E800) receive key
  -> omega::Connection
  -> retained ServerProxy ObjectSurrogate
  -> omega::ServerProxy
  -> vtable 0x1414B65E0
  -> callback 0x14045A1C0
```

This proof combines static object provenance with the observed route words; it
does not depend on reconstructing global surrogate-allocation order.

**CONFIRMED — echoed message `0x011C5800` is rejected before body parsing.**
`0x14045A1C0` compares the message argument against six explicit constants.
`0x011C5800` matches none and reaches the default block at `0x14045A733`.
That block never loads or advances the body-reader argument. It retains the
supplied `Connection`, calls `0x14040AE50` and `0x14040B010`, and returns
`void` after cleanup. Depending on the guarded connection state,
`0x14040B010` invokes either:

```text
0x1404123D0(Connection, 2, 11)
0x14043ADF0(context, 0, 1, 11)
```

Code `11` is therefore a confirmed failure/state-transition parameter for this
dispatch failure. A direct static edge from this call to the later socket close
has not been established; the observed close is consistent with the failure
transition but is not used to prove it. Adding bytes to an
`0x011C5800` response cannot repair this immediate error because its reader is
never consulted.

**CONFIRMED — explicit messages accepted by this exact callback.** Minimum
sizes below are parser-valid minima, including encoded-string terminators.

| Message | Minimum body | First parser/callee | Major structural behavior |
|---|---:|---|---|
| `0x90F2D04D` | 10 bytes | two encoded strings via `0x1403FB300`; `AuthorizationReplyIFace+0` / `0x140427290` | `ReplyGameLaunch` path; consumes an address-like string and consults the later connect controller |
| `0x4C3737B3` | 0 bytes | end check `0x1403FB230`; `AuthorizationReplyIFace+0x10` / `0x140427540` | clears connection state and reports code `1004` through the owner callback |
| `0x2CFF577B` | 4 bytes | one `u32`; `AuthorizationReplyIFace+0x08` / `0x140427220` | clamps values above `0x2329` to `0x232A`, clears connection state, and reports the resulting value |
| `0xA93588EB` | 10 bytes | two encoded strings; `ReplyConnectionIFace+0` / `0x140427BB0` | looks up an object using the first string and invokes a connection-related callee with the second |
| `0xEE36C3E4` | 10 bytes | `u32`, `u32`, `u16`; `AuthorizationReplyIFace+0x18` / `0x1404275B0` | clamps the `u16` to at most 8 and forwards all three fields to an owner callback |
| `0xD4BA5CCD` | 9 bytes | `u32` plus one encoded string; `LoginRequestIFace+0` / `0x1404279D0` | nonzero status returns immediately; zero enters the success-side path, optionally processes a nonempty string, then releases the Auth connection |

Every case calls `0x1403FB230` to require complete body consumption before its
interface callback. The encoded-string reader `0x1403FB300` first reads a
little-endian `u32` byte count, requires that many bytes, requires the last byte
to be NUL, and verifies that the preceding bytes have the declared string
length. Its minimum valid encoding is therefore `01 00 00 00 00` (one-byte
payload consisting only of the terminator), not a zero length.

**CONFIRMED — `0xD4BA5CCD` is the login-reply dispatch case; HYPOTHESIS — the
minimum empty-string success body is semantically sufficient.** The retail
`beginConnection` path enters `omega::ServerProxy` through `0x140427F10`, and
the only receive case dispatched through that object's `LoginRequestIFace` is
`0xD4BA5CCD -> 0x1404279D0`. The other five cases enter authorization,
game-launch, or reply-connection interfaces. This endpoint/interface pairing
establishes the immediate request/reply relationship:

```text
client login request  0x011C5800
server login reply    0xD4BA5CCD
```

It also demonstrates that this protocol does not generally echo a request ID.
Generated outbound stubs serialize their own operation constants, while the
endpoint callback dispatches a separate set of inbound constants. No literal
`0x011C5800` case exists in this receive callback.

The `0xD4BA5CCD` parser contract is:

```text
body +0x00  u32 status
body +0x04  u32 encoded-string byte count
body +0x08  encoded-string bytes (minimum: one NUL)

first size check       remaining >= 4
first semantic branch  status != 0 -> immediate return
success-side branch    status == 0
optional deeper call   nonempty string -> 0x140446C90
final action           release/close the Auth-side connection through owner
```

The role of the optional string is not yet proven and is intentionally left
unnamed. A status-zero body containing the parser-valid empty string reaches
the success-side branch but skips `0x140446C90`; whether that is sufficient for
client progression is a runtime discriminator, not a confirmed semantic fact.

**DISPROVEN / superseded.** The prior conditional statement that exact route
attribution was unknown is no longer current. The following is now proven:

```text
(E6A7,E800)
  -> omega::ServerProxy
  -> vtable 0x1414B65E0
  -> callback 0x14045A1C0
  -> 0x011C5800 default failure with code 11 before any body read
```

**MINIMUM NEXT EXPERIMENT.** The bounded Auth probe now preserves transport
type `0x10`, framing, encryption, and route `E6A7/E800`, while replacing the
invalid echoed ID and supplying only the proven parser minimum:

```text
message  D4BA5CCD
route    E6A7/E800
body     00000000 01000000 00
         ^status  ^length  ^NUL
```

A message-only/empty-body `D4BA5CCD` packet would prove only that the callback
then fails its first length check; without invasive instrumentation that is not
a useful behavioral discriminator. The nine-byte body is the smallest input
that separates reply-ID dispatch from mandatory parser framing without
inventing authentication material. The Debug artifact builds successfully and
the complete C# suite remains **44/44 passing** after this change.

### Minimum login-reply runtime result (September 8)

**CONFIRMED — classification ADVANCES.** In the normal private client, with no
debugger mode enabled and the bounded loopback resolver correction active,
`Holocron.Auth` observed this exact sequence on a clean manual selection:

```text
TCP accepted
RSA handshake: 522-byte type-0x04 frame
client: type 0x10, length 46
        message 011C5800, route E800/E6A7
server: type 0x10, length 23
        message D4BA5CCD, route E6A7/E800
        body 00000000 01000000 00
client: type 0x01, length 14
        u64 correlation 0000000000000001
```

The client-to-server type-`0x01` frame was reproduced and structurally logged
without retaining any login-request body. The prior echoed-message baseline
sent no subsequent frame and closed immediately. Correcting the response
message and supplying its minimum parser-valid body therefore moves the deepest
observed boundary beyond `omega::ServerProxy` login-reply dispatch.

An earlier attempt in the same first run produced a close immediately after the
same reply, followed by a second connection that did send type `0x01`. The clean
manual reproduction above removes that race/attempt ambiguity. Route reversal
and message `0xD4BA5CCD` remain preserved.

**CONFIRMED — the next frame is transport control, not another routed
application message.** Retail transport receive at `0x14043BBE0` masks the low
nibble of the type. Low-nibble zero enters the routed type-`0x10` path, while
type `0x01` enters `0x14043C6D2`. That handler:

```text
requires connection state == 1
requires exactly one u64 body value
requires complete body consumption
calls 0x14043C900(connection, u64 value)
```

`0x14043C780` is the corresponding type-`0x01` sender: it increments the
connection's `u64` counter, serializes that value, and changes the outstanding
control state from `1` to `2`. The observed value `1` is the first such request
on this connection.

**CONFIRMED — type-`0x01` is a transport time-synchronization request.** Its
decoded header and body are exactly:

```text
offset  width  value
+0x00   u8     type = 0x01
+0x01   i32    total length = 14, little-endian
+0x05   u8     XOR(type and four length bytes) = 0x0F
+0x06   u64    little-endian per-connection sequence
```

`0x14043C780` increments `Connection +0xA0` and serializes the result, so this
field is a sequence/correlation counter, not a timestamp or nonce. Before
sending it, the function stores the local send clock at `Connection +0xC0` and
changes the outstanding-control state at `+0x98` from `1` to `2`. The receiver
at `0x14043C6D2` requires exactly eight payload bytes, reads the `u64`, requires
end-of-body, and passes the unchanged value to `0x14043C900`.

The post-handshake cipher wraps the entire frame on the wire. The header above
is the decoded header; because its type has no high-nibble flag, its checksum is
the ordinary XOR rather than the complemented type-`0x10` rule.

**CONFIRMED — exact type-`0x02` response contract and count semantics.**
`0x14043C900` is the peer-role serializer used by the same binary when it
receives type `0x01`. It echoes the request sequence unchanged and always emits
one base clock record. It may append up to two clock records retained from an
associated connection. With `N` appended records:

```text
offset  width  value
+0x00   u8     type = 0x02
+0x01   i32    total length = 19 + 8*N, little-endian
+0x05   u8     ordinary XOR checksum
+0x06   u64    request sequence, echoed unchanged
+0x0E   u8     record count = 1 + N
+0x0F   u32    local clock, low 32 bits, little-endian
+0x13   u32    appended record 1 field A, if N >= 1
+0x17   u32    appended record 1 field B, if N >= 1
+0x1B   u32    appended record 2 field A, if N >= 2
+0x1F   u32    appended record 2 field B, if N >= 2
```

Thus the canonical base-only payload is 13 bytes and the complete frame is 19
bytes. For that frame the decoded header is `02 13 00 00 00 11`. Count zero is
accepted by the parser but is never produced by the canonical serializer;
count one is the minimum evidence-backed response. Additional record pairs are
not required for a connection that has no retained downstream clock records.

The type-`0x02` parser at `0x14043C455` requires the echoed `u64` field but does
not compare it locally. It then reads the count. Record zero contains only the
remote clock value; every later record contains the A/B pair. It consumes all
declared records, retains at most two, requires end-of-body, and clears
`Connection +0x98` from the outstanding state. The echo relationship is proven
by the peer-role serializer even though this parser does not enforce equality.

**CONFIRMED — clock source and round-trip calculation.** Global initialization
at `0x140063410` snapshots two values:

```text
raw base  = KUSER_SHARED_DATA.InterruptTime
wall base = current Windows FILETIME converted to milliseconds
```

The imported call at IAT slot `0x141369728` is
`GetSystemTimeAsFileTime`. The conversion subtracts
`116444736000000000` 100-nanosecond units while constructing the calendar time;
the time system is then based at `1601-01-01`. The final division by 1,000
converts its microsecond duration to FILETIME-epoch milliseconds.

Every later clock read, including `0x14043C780`, `0x14043C900`, and the
type-`0x02` parser, uses:

```text
current_ms = wall_base_ms
           + trunc((InterruptTime - raw_base) / 10,000)
```

The signed multiply by `0x346DC5D63886594B`, high-half extraction, and shift
by 11 implement division by 10,000 exactly. The serializer writes the low 32
bits of `current_ms`. This is a wall-clock-seeded, monotonically advanced
FILETIME-millisecond clock; it is not an arbitrary status value.

On type-`0x02` receive, the client independently obtains `receive_ms`, stores it
at `Connection +0xC8`, and computes:

```text
round_trip_ms = low32(receive_ms) - low32(Connection +0xC0 send_ms)
```

For base record zero, the receiver supplies implicit field A = 0, stores
`round_trip_ms` in the first estimator, and stores the received remote clock in
the second. For appended records it stores `field_A + round_trip_ms` and
`field_B`. `0x14043E0A0` updates the paired estimators and propagates their
clock/latency mapping to registered omega connections. This establishes a
transport clock-synchronization exchange with round-trip measurement, rather
than a generic ping or application message.

**CONFIRMED — minimum implementation and focused tests.**
`TransportTimeSync` now parses the exact 14-byte request and serializes the
base-only 19-byte response. `Holocron.Auth` seeds its clock once from
`DateTime.UtcNow.ToFileTimeUtc()` and advances it with `Stopwatch`, mirroring
the retail wall-clock-plus-monotonic-delta construction. It echoes the observed
sequence, emits count one, and adds no optional records. The confirmed
`D4BA5CCD/E6A7/E800` application reply is unchanged. Two byte-exact framing
tests increase the complete passing suite from 44 to **46/46**.

### Type-`0x02` private-client result (September 8)

**CONFIRMED — the evidence-backed response was physically transmitted.** One
synchronized normal-client selection, with the private resolver patch active
and no debugger mode, produced:

```text
client  type 0x10: 011C5800 / E800/E6A7
server  type 0x10: D4BA5CCD / E6A7/E800 / 9-byte body
client  type 0x01: length 14, sequence 1
server  type 0x02: length 19, sequence 1, count 1,
                   local-ms 0xB08EBD69
client  clean EOF: no later transport frame
```

The server's clock value agrees with the low 32 bits of FILETIME milliseconds
at the experiment time. The client sent no subsequent frame and closed only
after the type-`0x02` response arrived. This is the deepest confirmed transport
boundary. Whether that EOF is the expected completion of the Auth connection
or accompanies a remaining application/UI failure depends on the visible
client state and is not inferred from EOF alone.

**DISPROVEN / superseded.** The type-`0x01` value is not an unknown opaque
timing field: it is a per-connection sequence counter. The type-`0x02` base
field is not merely “timing-like,” and an empty/count-zero reply is not the
canonical minimum. The evidence-backed minimum is sequence echo, count one,
and the sender's monotonicized FILETIME-millisecond clock.

### Application-initializer and launch-reply discriminator (September 8)

**CONFIRMED — the base-only time reply did not complete login.** The synchronized
type-`0x02` run above ended in the ordinary visible client error `1003`
(`LOGIN_ERROR_FAILED_CONNECT_TO_LOGIN_SERVER`). Its clean EOF is therefore not
treated as successful Auth completion. The deepest accepted wire stage remains
the type-`0x02` response; there was no game-launch reply log, no
`HandleInitialize completed.` log, and no later encrypted frame.

**CONFIRMED — a nonempty D4 string is an omega XML/Frame document.** On the
`D4BA5CCD` zero-status path, `0x1404279D0` calls `0x14040D4D0` for a nonempty
string. `0x140446C90` serializes the resulting Frame through `0x140410B10` and
the XML serializer at `0x14040E810`, reparses it into the application Buffer,
and calls `0x140447470`. `OmegaClientApp::HandleInitialized` at `0x140121360`
obtains the `access-rights` setting, rejects an empty value with the literal
`access-rights not configured on server`, reparses a nonempty value as XML,
looks up `client`, and iterates `network` children with `name` and `address`
fields. These are structural names only; no credential or token semantics are
inferred.

**CONFIRMED — `<client/>` alone changes behavior but does not advance login.** A
normal synchronized run transmitted:

```text
client  type 0x10: 011C5800 / E800/E6A7
server  type 0x10: D4BA5CCD / E6A7/E800
        status 0, encoded string `<client/>`
client  clean EOF: no type 0x01 and no later frame
UI      error 1003
```

The prior parser-minimum empty string reached type `0x01`, whereas this
nonempty document closed immediately after D4. This proves that the optional
string is semantically active. It does not by itself prove whether `<client/>`
was rejected as an incomplete initializer or whether initialization proceeded
but the still-missing game-launch reply caused the close. `<client/>` as the
only post-request application reply is **DISPROVEN** as sufficient; its exact
internal acceptance remains **INCONCLUSIVE** without the launch reply.

**CONFIRMED — `0x90F2D04D` supplies the missing launch address on the same
endpoint.** The proven `omega::ServerProxy` receive callback dispatches
`0x90F2D04D` to `0x140427290`. That handler parses two encoded strings. It logs
the first with `Game launch reply address = %s`, then `0x140427C90` stores and
passes that first string to the downstream connection controller. The second
string is stored separately. Historical successful client logging orders the
events as:

```text
Starting login
Game launch reply address = <host>:<port>
HandleInitialize completed.
CS_APP_INITIALIZED ...
```

This proves callback/state ordering, but not wire ordering: initialization
started by D4 may complete asynchronously after the launch callback logs.
`0x140427290` calls `0x140427C90` and then transitions the retained Auth
`Connection` through `0x1404123D0`, so ReplyGameLaunch is structurally the
terminal operation of the two.

**DISPROVEN — launch reply before D4.** A synchronized normal-client run sent
the encrypted `90F2D04D` frame first, followed immediately by the unchanged D4
`<client/>` frame. Both writes completed, but the client produced no type-`0x01`
frame, no `Game launch reply address` log, no World TCP connection, and the same
visible error `1003`. This ordering is not an advance and is inconsistent with
the launch handler's terminal connection transition.

**CONFIRMED — reversing those two writes does not cure the earlier D4
failure.** A second synchronized run sent the same frames D4-first. The client
again closed after both writes, emitted no type-`0x01`, logged no launch reply,
made no World connection, and reported error `1003`. Since the first frame in
that run was the still-incomplete `<client/>` initializer, this result does not
disprove D4-first ordering; it isolates the failure before ReplyGameLaunch can
be observed.

**CONFIRMED — the missing D4 element is exactly `access-rights`.** The hidden
return-buffer ABI gives `0x1404068C0` arguments in `RDX` and `R8`. At its call to
`0x14044A030`, the compiler leaves the incoming `R8` unchanged; `0x14044A030`
then calls `0x1404107F0` without reloading it. `0x1404107F0` reads the requested
name from `R8` and compares it with Frame node names. The apparent absence of a
key use in `0x14044A030` was therefore a register-forwarding artifact. A root
`<client/>` document contains no node named `access-rights`, so the confirmed
empty-setting guard explains the immediate close. No speculative runtime
attribution is needed for this conclusion.

After serializing the matching `access-rights` element,
`OmegaClientApp::HandleInitialized` reparses it and searches for its `client`
child. The smallest document satisfying both proven lookups is therefore:

```xml
<access-rights><client/></access-rights>
```

No `network` children are mandatory on the recovered path: an absent first
`network` child skips the iteration and continues toward
`HandleInitialize completed.`

**INCONCLUSIVE — corrected XML followed immediately by another application
frame.** A synchronized run transmitted the minimum two-level access-rights
document and then immediately transmitted ReplyGameLaunch. The client again
closed without type-`0x01`, a launch log, or a World connection. This does not
isolate XML acceptance: the established empty-D4 baseline sends type-`0x01`
before any second application exchange, so the immediate launch frame crossed
an unresolved transport-synchronization boundary.

**DISPROVEN — the two-level tag document does not pass initialization.** A
clean synchronized run isolated the stages exactly as described below. The
server sent only the corrected D4 frame first:

```text
message  D4BA5CCD
route    E6A7/E800
body     status 0, encoded string
         `<access-rights><client/></access-rights>`
```

The client closed the connection immediately after that encrypted frame. It
sent no type-`0x01`, logged the same launch failure `1003`, and therefore never
received either the type-`0x02` response or ReplyGameLaunch. This removes the
immediate second application frame as a confounder. Although the lookup key is
confirmed to be `access-rights`, representing it as a conventional XML element
containing a conventional `client` child is not sufficient for the retail
Frame parser/lookup contract.

`Holocron.Auth` remains staged at this boundary: it waits for the client
type-`0x01` request and only if that request arrives sends the proven
type-`0x02` response, followed by:

```text
message  90F2D04D
route    E6A7/E800
body     encoded string `127.0.0.1:20061`
         encoded empty string
```

Type-`0x01` remains the discriminator for any subsequent evidence-backed
initializer experiment without allowing ReplyGameLaunch to interfere. The
first launch string uses
the server's existing private World target. The second string remains at the
parser-valid empty minimum; no session token or
authentication material is invented. Transport framing, encryption, route
reversal, message IDs, D4 status, and all other body fields are unchanged. The
complete C# suite passes **46/46** for the currently staged implementation.

**CONFIRMED — Expat XML parsing and Frame Node Representation (`0x14040B940`):**
- XML element start callback creates a Frame node (`NodeData` at `+0x10`).
- Element tag name is stored at `NodeData + 0x40`.
- Child nodes are stored as a linked list (`NodeData + 0x10` = first child, `NodeData + 0x20` = next sibling).
- Attribute pairs are stored as child nodes marked with byte flag `NodeData + 0xC8 = 1`.
- Standard element nodes have byte flag `NodeData + 0xC8 = 0`.

**CONFIRMED — Frame Search Semantics and Helper Classification:**
- `0x1404107F0` (`Frame::FindElementByNameRecursive`):
  Recursive descendant search. Compares node name at `+0x40` case-sensitively (`sub ecx, eax` loop). Crucially, checks `cmp byte ptr [r9 + 0xC8], cl` (where `cl == 0`), skipping any node marked with flag `+0xC8 != 0`. It **strictly ignores attribute nodes** and only returns element nodes.
- `0x140410340` (`Frame::FindAttributeValue`):
  Searches child nodes for attribute name match where `[node + 0xC8] != 0` (strictly requires attribute flag). Extracts the attribute string value from `[node + 0x50]`.
- `0x140410490` (`Frame::FindChildElement`):
  Searches children for named elements.
- `0x14044A030` (`GetSetting`):
  Takes the installed Frame from `[app + 0xF0]`, performs recursive lookup via `0x1404107F0`. If found, allocates a buffer and serializes the matching Frame subtree back to XML string via `0x140410B10` / `0x14040E810`.

**CONFIRMED — `HandleInitialized` (`0x140121360`) Requirement Chain:**
1. `GetSetting("access-rights")` via `0x1404068C0` -> `0x14044A030` -> `0x1404107F0`.
2. First-byte check at `0x1401213E3` / `0x1401213F3`: `cmp cl, 0` against null terminator.
   - If empty/missing: logs literal `"access-rights not configured on server"` (`0x14012146C`), but execution continues past error logging.
3. If non-empty: reparses the serialized `access-rights` XML string via `0x14040D4D0`.
4. In the reparsed Frame, searches for child element `"client"` via `0x140410490`.
5. Under `client`, iterates child elements `"network"` via `0x140410490`.
6. For each `network` element, queries attribute `"name"` via `0x140410340` and attribute `"address"` via `0x140410340`.
7. Queries root attribute `"additionalClientConfigs"` via `0x140406900` -> `0x140410340` at `0x140121B10`.

**CONFIRMED — Post-Configuration Handler (`0x140447470`):**
- Invoked by `0x140446C90` after parsing and installing the D4 config string at `[app + 0xF0]`.
- If `[app + 0xF0]` is null (the 9-byte empty string D4 payload), it jumps to `0x14044A015` and skips all attribute inspections, allowing the connection to stay alive and reach transport sync (type `0x01`).
- If `[app + 0xF0]` is non-null (any XML payload installed):
  Inspects the root element's attributes using `0x140410340`:
  - `"loglevel"` (`0x1404474c2`)
  - `"logconfig"` (`0x140447545`)
  - `"useSyncClock"` (`0x140447bad`)
  - `"addresses"` (`0x140447e0d`), `"ports"` (`0x14044827e`), etc.

**CONFIRMED — Root Document Shape and Historical Ground Truth:**
- Historical emulator source (`research/SwTor-1.3/server/WorldServer/Src/Logic/Senders/Client.cpp`, lines 27-33) confirms the canonical initialization XML has root `<client ...>`:
  ```xml
  <client title="Test Client" useSyncClock="true" loglevel="debug">
    <gamesystemsservers first="GameSystemsServer:gamesystemsserver"/>
    <biomon metricspublisherserver="biomonserver:biomon">
      <biomon-sampler service_family="he1012" service_type="gameclient"></biomon-sampler>
    </biomon>
    <access-rights>
      <client name="Automaton.exe">
        <network name="BWA" address="10.2.0.0/15"/>
        <network name="AUS" address="10.64.10.0/24"/>
        <network name="BWE" address="10.0.0.0/15"/>
        <network name="Mythic" address="10.18.11.0/24"/>
      </client>
      <client name="HeroBlade.exe">
        <network name="Ultizen" address="172.16.0.0/24"/>
      </client>
    </access-rights>
  </client>
  ```
- Corroborated by actual client log `.local-test/client-v1/game/swtor/retailclient/swtor/logs/Client_20260904T092441_708.log`:
  `HandleInitialize completed. [Firestorm.firestorm.client.OmegaClientApp](omegaclientapp.cpp:OmegaClientApp::HandleInitialized:411)` -> `setState changing state to [CS_APP_INITIALIZED]`.

**DISPROVEN:**
- `<access-rights>` as root document is disproven: `<access-rights>` is a child element of `<client>`, not the root configuration document. Having `<access-rights>` as root causes `0x140447470` to fail attribute extraction on the root node.
- The hypothesis that `<access-rights><client/></access-rights>` failed because of element vs attribute XML dialect is disproven: `<client>` inside `<access-rights>` is an element, but it requires child `<network name="..." address="..."/>` elements and the root document requires the `<client ...>` shape with attributes.

