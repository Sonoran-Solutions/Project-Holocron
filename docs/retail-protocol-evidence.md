# Retail protocol evidence (2026-09-04)

> # ⚠ THIS IS A CHRONOLOGICAL LAB NOTEBOOK
>
> Earlier sections intentionally preserve hypotheses, wrong turns and
> conclusions that were **later disproven or superseded**. They are kept because
> the raw observations and the reasoning trail are still useful, and because
> silently rewriting them would hide how a conclusion was reached.
>
> **Do not treat an isolated `CONFIRMED` statement in this file as current
> truth.** A `CONFIRMED` label is only as good as its own evidence, and later
> sections routinely retract earlier ones. Before relying on anything here,
> check:
>
> 1. `docs/CURRENT-RETAIL-STATE.md` — **authoritative for the current model**;
> 2. the latest correction/retraction section near the end of this file;
> 3. whether the section you are reading is marked `SUPERSEDED`,
>    `SUPERSEDED IN PART` or `DISPROVEN`.
>
> When this file and `docs/CURRENT-RETAIL-STATE.md` conflict, the current-state
> document wins.
>
> Known material corrections to look for (non-exhaustive): the `0x10` bit is a
> Zstandard flag, not encryption; `0x011C5800` and routes `E800`/`E6A7` are
> `DISPROVEN`; the reproduced `Close` was **not** produced by
> `omega::TimeRequester`; the `App+0x2A` reset path did not execute;
> `0x14040AEEB` does **not** clear `conn+0x88`.

This is a partial static analysis, not a claim that the emulator supports retail.
Addresses below are preferred virtual addresses in the installed x64 `swtor.exe`.
SHA-256: `ad541a742a62500c2095f87c3cff116def462ebd26d1de95de32bc7293eb596b`.
No account credentials or captured session keys are recorded here.

> September 11 audit: the current candidate was tested and still closes after D4.
> See the final audit section before relying on earlier XML-rejection claims.
> In particular, absence of type `0x01` does not identify a failing Frame lookup.
>
> **September 13 correction, read this first.** Transport type bit `0x10` is a
> **Zstandard compression flag**, not an encryption class, and a `0x10` payload
> is compressed rather than a raw application envelope. Every earlier section
> that reads a dispatch envelope directly out of a `0x10` payload — including
> the recovered message `0x011C5800` and routes `0xE800`/`0xE6A7` — is
> **DISPROVEN**. See "Transport bit `0x10` is Zstandard compression" at the end
> of this document for the byte-exact evidence, the corrected pipeline, and the
> corrected `omega::ServerProxy` field offsets.

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
transport header. **DISPROVEN as an envelope (September 13):** those bytes are
a magicless Zstandard frame header, a block header, and the first literal
bytes, not a message id and two route words. The first byte and following three-byte/word-looking region
must be treated as an unclassified inner envelope: the remaining bytes vary
per session, and the project's legacy `Opcode` enum is not evidence of its
retail meaning. The next step is static tracing of the installed client's
type-`0x10` receive/send handler before attempting a response.


> **DISPROVEN (September 13).** Those bytes are a magicless Zstandard frame
> header (`00 58`), a block header (`1C 01 00`), and the first literal bytes of
> the compressed block. They are not a message id and two route words.
## Encrypted type-`0x10` dispatch envelope (September 6, 13:13)

> **SUPERSEDED (September 13).** Bit `0x10` is the Zstandard compression flag,
> not an encrypted-frame flag, and `0x10` is not a transport class. The
> low-nibble routing described below is still correct, but it applies to the
> *decompressed* payload. See the September 13 section.

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
**DISPROVEN (September 13):** the same reasoning applied to a compressed
payload, and the recovered message is `0xA609E6A7` on the wildcard route pair
`0xFFFF`/`0xFFFF`.

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

**CONFIRMED lookup key; DISPROVEN failure attribution — `access-rights`.** The hidden
return-buffer ABI gives `0x1404068C0` arguments in `RDX` and `R8`. At its call to
`0x14044A030`, the compiler leaves the incoming `R8` unchanged; `0x14044A030`
then calls `0x1404107F0` without reloading it. `0x1404107F0` reads the requested
name from `R8` and compares it with Frame node names. The apparent absence of a
key use in `0x14044A030` was therefore a register-forwarding artifact. A root
`<client/>` document contains no node named `access-rights`, but the empty-setting branch logs and continues at `0x140121AEE`.
It does not establish the cause of the immediate close; the former attribution
is withdrawn by the September 11 audit.

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

**CONFIRMED failed experiment; HYPOTHESIS internal rejection — two-level XML.** A
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
confirmed to be `access-rights`, this observation does not demonstrate a Frame
parser/lookup violation. It establishes only that this staged exchange failed
to complete login. The September 11 audit withdraws the stronger attribution.

`Holocron.Auth` remains staged at this boundary: it waits for the client
type-`0x01` request and only if that request arrives sends the proven
type-`0x02` response, followed by:

```text
message  90F2D04D
route    E6A7/E800
body     encoded string `127.0.0.1:20061`
         encoded empty string
```

Type-`0x01` was used as the transport discriminator for these experiments.
It is not an XML-acceptance oracle; see the September 11 audit. The
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
  Child element lookups, not attribute lookups, then inspect `"addresses"`
  (`0x140447E25`) and `"ports"` (`0x140448298`) via `0x140410490`.

**CONFIRMED historical shape; CONDITIONAL current-retail relevance:**
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
- Successful initialization (but not the historical XML contents) is corroborated by client log `.local-test/client-v1/game/swtor/retailclient/swtor/logs/Client_20260904T092441_708.log`:
  `HandleInitialize completed. [Firestorm.firestorm.client.OmegaClientApp](omegaclientapp.cpp:OmegaClientApp::HandleInitialized:411)` -> `setState changing state to [CS_APP_INITIALIZED]`.

**DISPROVEN — prior mandatory-shape claims.** The earlier assertion that an
`access-rights` root necessarily fails root-attribute extraction was unsupported.
Missing `loglevel` and `useSyncClock` have explicit non-error paths. Likewise,
`HandleInitialized` skips absent `client` and `network` elements; network children
are not mandatory. Element/attribute distinctions remain confirmed, but they do
not identify the cause of the failed runs. Historical emission of a `<client>`
root with these attributes is not proof that retail requires all of them.

## Senior audit and clean candidate experiment (September 11)

**CONFIRMED — starting state.** Clean `main` at
`f032f344b4c2d3e53e22432eac821d0d80f607d5`, not the reported `d7f12a5`.
The initial C# suite passed 46/46 with `/home/dq/.dotnet/dotnet test
--no-restore -m:1 -nr:false`. The sandbox denied MSBuild's local socket bind;
the approved outside-sandbox run passed. NU1900 warnings concern the unavailable
NuGet audit feed, not ignored test failures. Static addresses refer to the same
private retail copy; only the already-established test key and bounded resolver
patch differ from the retail executable identified at the start of this document.

### Exact useSyncClock behavior

**CONFIRMED.** The app constructor writes byte `App +0x1A0 = 0` at
`0x14044574F`. At `0x140447BD3`, `FindAttributeValue` looks up `useSyncClock`.
An absent attribute produces null at `0x140447BF1`; the test at
`0x140447C15` skips the comparison. A present value is compared to ASCII
`true` at `0x141571030` by imported `_stricmp` (IAT `0x14136AA00`). Only equality
writes one at `0x140447C2E`. There is no false/absent reset in this handler.

```text
fresh app, absent       -> +0x1A0 stays 0
fresh app, "false"      -> _stricmp != 0 -> +0x1A0 stays 0
fresh app, "true"       -> _stricmp == 0 -> +0x1A0 = 1
fresh app, "TRUE"       -> same as "true"
previously enabled app -> absent/"false" leaves +0x1A0 = 1
```

**CONFIRMED — two consumers, neither the transport send gate.** After the
configuration installer returns, `0x140427B6B` tests this byte. If set, it calls
`0x140467BD0(App +0x1A8)`. That service first checks for a `*:timesource`
connection via `0x140468B50`; if found, it schedules callback `0x140467DD0`
and sets its own `+0x40` active byte. The second consumer, `0x14044A1D0`, returns
the ordinary local clock when the flag is zero or the service pointer is null.
With a service it adds the service's `+0xA0` correction and clamps against its
`+0xB8` previous value to prevent backward time. Thus the attribute enables use
of the application synchronized clock; it does not directly enable type `0x01`.
The optional service's successful lookup is not proven in this local experiment.

**CONFIRMED — transport request producer.** Login setup independently writes
`Connection +0xB8 = 0x2710` (10,000 ms) at `0x140428183`. The transport timer
`0x14043DE10` requires connection lifecycle state 4, a positive interval, and
`now - Connection +0xD0 >= interval`. When control state `+0x98` is zero it
writes one at `0x14043E023` and queues a send. The send path requires
`Connection +0x180 == 1` at `0x14043B638` and `+0x98 == 1` at `0x14043B680`,
then calls `0x14043C780`. That writes the type-1 sequence, snapshots local time
at `+0xC0`, and sets outstanding state two. The timer's caller `0x1404301D3`
and the serializer use the local interrupt-time-based clock, not
`0x14044A1D0`. No dependency on the application flag occurs in this producer
chain. Connection lifetime and scheduling still affect whether a request is
observed before a close.

**DISPROVEN — “nonempty config without type 0x01 means the Frame was rejected.”**
That inference is too strong: transport liveness does not identify XML parser
acceptance or an application failure site. The alternative claim that an absent
`useSyncClock` directly disables this transport producer is also disproven by
the separate state/clock paths. Broader application effects remain conditional
on service discovery. The empty-string baseline already emitted type `0x01`
without installing a true attribute. The new true-bearing candidate below also
failed to restore type `0x01`; absence of that attribute cannot alone explain
the observed difference.

### Candidate fields: required versus optional

These classifications concern the audited retail paths, not an assertion of
end-to-end sufficiency. No successful nonempty D4 minimum has been established.

| Field | Classification | Current retail evidence |
| --- | --- | --- |
| root `title` | HISTORICAL-ONLY | No requirement established in the audited installer/initializer; retained in candidate, not claimed mandatory. Other consumers remain unresolved. |
| `useSyncClock` | REQUIRED FOR SPECIFIC BEHAVIOR | Case-insensitive true enables the application sync-clock service/use; absent and false are accepted by the lookup path. Not required by the transport type-1 producer. |
| `loglevel` | OPTIONAL | Null at `0x14044750D`; branch `0x140447659` skips severity selection. A present recognized value changes logging. |
| `access-rights` | OPTIONAL on this initializer path | Missing setting logs the diagnostic, then jumps from `0x1401214F8` to `0x140121AEE`, continuing initialization. It is needed to populate access-rights records, not proven a login gate. |
| nested `client name` | REQUIRED FOR PARSING/INITIALIZATION, CONDITIONAL on a present network record | Absent client skips at `0x140121581`; no network skips at `0x140121643`. With a network, the client name string is dereferenced at `0x14012186A`; omission yields null. The literal `Automaton.exe` is historical, not a required match. |
| `network name` | REQUIRED FOR PARSING/INITIALIZATION, CONDITIONAL on a present network record | Lookup at `0x140121671`; missing value becomes null, dereferenced at `0x1401217C9`. The literal `BWA` is historical. |
| `network address` | REQUIRED FOR PARSING/INITIALIZATION, CONDITIONAL on a present network record | Lookup at `0x1401216D5`; missing value becomes null, dereferenced at `0x140121724`. Its string is passed with names to `0x140123E30`. Accepted address grammar beyond this historical candidate remains unresolved. |

**CONFIRMED.** Missing client/network elements take explicit skip paths, so the
previous requirement for at least one network was wrong. No access-control
check is changed or bypassed by this audit. The candidate's actual rules remain
unchanged. Static tolerance of a missing element does not justify describing
`<client/>` or the two-level document as a successful runtime minimum.

### Wire audit and new retail result

**CONFIRMED — current implementation.** D4 remains `0xD4BA5CCD`, with the
request routes reversed to `E6A7/E800`. Status is zero; the next LE u32 is 187,
covering 186 UTF-8 XML bytes plus the terminal NUL. The XML is well formed and
matches the exact historical candidate in `AuthServer.cs`. Body length is 195,
total frame length 209, type `0x10` with complemented header checksum. The
encoded-string parser `0x1403FB300`, called at `0x14045A921`, checks the NUL and
length; the candidate satisfies those structural checks. No message, route,
cipher ordering, status, XML bytes, or subsequent protocol behavior was changed
in this audit.

**CONFIRMED — clean normal-client experiment.** Fresh log
`Client_20260911T210632_308.log`, one screenshot-verified selection at 21:07:44
America/Phoenix. Auth and HTTPS platform ran in the isolated namespace, the
private resolver's AI_ADDRCONFIG immediate was zero, and no WineDbg/GDB/strace
mode was enabled. The user delegated selection; the agent clicked Select once.

```text
client  RSA type 4, 522 bytes, test-key envelope validated
client  type 0x10, 46 bytes, 011C5800 / E800/E6A7
server  type 0x10, 209 bytes, D4BA5CCD / E6A7/E800
        status 0, current <client ... useSyncClock="true" ...> document
client  EOF; no type 0x01 or later frame
UI      connection-error dialog; fresh client log reports error 1003
        no HandleInitialize completed / CS_APP_INITIALIZED / launch-reply log
```

**DISPROVEN — the current candidate restores transport sync.** It did not.
The staged server therefore sent neither type `0x02` nor ReplyGameLaunch in
this run. The client was quit normally and the runner reported restoration of
the private resolver bytes. No login body or sensitive account data was retained.

**HYPOTHESIS / unresolved boundary.** Failure remains between receipt of D4
and a demonstrated initializer completion. The first failing internal lookup
or validation has not been localized by this normal run. In particular, no
evidence justifies adding title/loglevel/network fields as a correction: they
are already present, and the audited missing-element branches do not prove
rejection. Do not mutate multiple fields or claim a parser failure from EOF.
Further work must distinguish XML parse/install completion from the owner
callback at `0x140427B84` and its connection lifetime effects, using structural
observations without recording login contents.

### Existing type-2 implementation and regression coverage

**CONFIRMED.** Type `0x02` was already implemented before this audit. Rechecking
`0x14043C900` confirms the sequence store at `0x14043CB07`, count byte at
`0x14043CB3B`, and low-32-bit local clock at `0x14043CB7D`. Its base response is
19 bytes: ordinary XOR header `02 13 00 00 00 11`, LE u64 echo, u8 count one,
LE u32 clock. Each optional downstream record adds two u32s, not another
base-sized record. The clock producer reads shared InterruptTime, subtracts
the saved base, divides by 10,000, and adds the saved FILETIME-millisecond base.
`AuthServer`'s FILETIME seed plus Stopwatch elapsed milliseconds matches this
construction; no timing value was fabricated or changed.

The socket-test change to bind port zero removes the bind-release-rebind race.
Retries still fail on exhaustion and faulted server tasks are awaited; they do
not turn failures into passes. ReuseAddress affects local listener binding,
not protocol validation. The added synthetic socket regression exercises the
actual private-key probe path, independently checks D4 XML/framing/routes,
sends a nontrivial sequence and verifies the type-2 echo/count/clock plus
continued cipher state through the launch reply. This is server-contract
coverage, not a claim of retail XML or launch acceptance.

**CONFIRMED — final validation.** The same full-suite command passes **47/47**,
zero skipped, after the audit changes. `git diff --check` passes. The restored
resolver instruction is `C7 06 00 04 00 00`. Type-2 retail retesting is still
conditional on reaching a type-1 request; the candidate run did not reach it.

## Comprehensive static disassembly audit: ConnectionObject, ServerProxy, and ReplyGameLaunch (September 12)

### Corrected attribution of the early close and error 1003

**DISPROVEN — process crash and active `username` null dereference.** A clean
September 12 run left `swtor.exe` alive for more than two minutes after the
Auth EOF. Wine/Proton emitted no `0xC0000005`, page fault, fatal signal, or
client exit. The approximately 250--268 ms event is an Auth socket/ServerProxy
close, not process termination. The unchecked `username` dereference at
`0x140121C39` is real static code for a document that reaches
`HandleInitialized` without that key, but the current document supplies
`username=local-test;` and the surviving process disproves it as the active
cause of this observed close.

**CONFIRMED — error 1003 is disconnect aftermath.** At `0x14042718E`,
`ServerProxy::OnDisconnect` inspects the retained launch context at
`ServerProxy +0x90`. If it is still present, `0x1404271D6` supplies decimal
1003 and invokes the application's launch-failure callback through the
application pointer at `ServerProxy +0x78`. **CONFIRMED (September 13) from
`0x14042718E`/`0x1404271CF`.** Thus the visible 1003
identifies an Auth disconnect before completed launch dispatch; it does not
identify the original D4 rejection and is not evidence of a process crash.

### ConnectionObject Lifecycle State Machine

Static analysis of `0x140134d70` (`ConnectionObject::setState`), `0x140135d20` (`slot 0`), `0x140135df0` (`slot 1`), `0x140135eb0` (`slot 2`), and `0x140136400` (`slot 4 / setError`) maps the complete lifecycle:

| State ID | State Constant | Entry Trigger / Condition |
| --- | --- | --- |
| 1 | `CS_WAITING_FOR_INIT` | `ConnectionObject` construction |
| 2 | `CS_LOGGING_IN` | `ConnectionObject::beginConnection` (`0x140134d70` call at `0x1401350a8`) |
| 3 | `CS_APP_INITIALIZED` | `ConnectionObject::slot0` (`0x140135d20`) when global initialized flag `0x141bab4fa == 1` |
| 4 | `CS_CONNECTING_REPOSITORY` | Advanced by `slot0` immediately after state 3 if desired state >= 5; calls `ConnectRepository` (`0x140124380`) |
| 5 | `CS_REPOSITORY_CONNECTED` | `ConnectionObject::slot1` (`0x140135df0`); in client mode (`[App+0x118] & 2 == 0`), `0x1401243aa` skips repository connect and directly calls `slot1` |
| 6 | `CS_CONNECTING_COMPILERS` | Advanced by `slot1` if desired state > 5; calls `ConnectCompilers` (`0x140124aa0`) |
| 7 | `CS_COMPILERS_CONNECTED` | `ConnectionObject::slot2` (`0x140135eb0`); in client mode (`[App+0x118] & 4 == 0`), `0x140124acf` skips compiler connect and directly calls `slot2` |
| 8 | `CS_CONNECTING_SHARD` | Advanced by `slot2` if desired state > 7; initiates connection to shard address supplied by `0x90F2D04D` |
| 9 | `CS_SHARD_CONNECTED` | Shard connection handshake completed |
| 10 | `CS_SHARD_DISCONNECTING` | Shard disconnection initiated |
| 11 | `CS_FAILED` | Error condition reached via `ConnectionObject::slot4` (`setError`) |

### omega::ServerProxy Class Hierarchy and Vtable Layout

Extracted directly from RTTI Complete Object Locators in `.rdata`:

- **Base 0: `omega::ServerProxy`** (mdisp = `0x0`, COL `0x141702188`, vtable `0x1414b65e0`):
  - Slot 0 (`+0x00`): `0x140426e80` — Virtual destructor
  - Slot 6 (`+0x30`): `0x14045a1c0` — `HandleMessage` dispatcher:
    - `0x14045a71d`: checks message ID `0xD4BA5CCD` -> calls `LoginRequestIFace::slot0` (`0x1404279d0`)
    - `0x14045a216`: checks message ID `0x90F2D04D` -> calls `AuthorizationReplyIFace::slot0` (`0x140427220`)
  - Slot 7 (`+0x38`): `0x140459bb0` — Route dispatcher (checks `*` route `0x14156e2d0`)
  - Slot 8 (`+0x40`): `0x140427170` — `OnDisconnect` (**SUPERSEDED: the state check is at `[ServerProxy + 0x90]`, and `+0x78` is the application pointer used to report 1003**; see the September 13 section)

- **Base 4: `LoginRequestIFace`** (mdisp = `0x18`, COL `0x141702138`, vtable `0x1414b65d0`):
  - Slot 0 (`+0x00`): `0x1404279d0` — Handles D4 (`0xD4BA5CCD`):
    - Decodes status code (u32) and XML configuration string.
    - Parses XML via `0x14040d4d0`.
    - Installs Frame and inspects `loglevel`, `logconfig`, `useSyncClock`, `addresses`, `ports` via `0x140446c90`.
    - If `useSyncClock` is true, initializes clock service (`0x140467bd0`).
    - Calls the connection object's slot 0 (`0x140135D20`) at `0x140427B84` after settings processing.
    - `0x140447470` reaches `OmegaClientApp::HandleInitialized` (`0x140121360`)
      only through the configured `<objects>` / `<globalobject>` loop; it is
      not an unconditional direct call from the D4 handler.

- **Base 5: `AuthorizationReplyIFace`** (mdisp = `0x20`, COL `0x141702110`, vtable `0x1414b66a8`):
  - Slot 0 (`+0x00`): `0x140427220` — Handles ReplyGameLaunch (`0x90F2D04D`):
    - Dispatches to `0x140427290`.
    - String 1: Game server shard address (`{host}:{port}`).
    - String 2: Session token / account string.
    - Logs `Game launch reply address = %s` (`0x14157f0d8`).
    - Passes shard target to downstream connection controller (`0x140427c90`).
    - Clears a `+0x78` field. **SUPERSEDED:** on the `OnDisconnect` path `+0x78` is the application pointer and the retained launch context is `+0x90`; see the September 13 section.

- **Base 6: `ReplyConnectionIFace`** (mdisp = `0x28`, COL `0x141702160`, vtable `0x1414b6690`):
  - Slot 0 (`+0x00`): `0x140427bb0`.

### Wire Ordering and Time-Sync Timing Contract

1. **Type `0x01` is not a D4 handshake response:**
   - In `ServerProxy::Login` (`0x140428183`), the client initializes its background time-sync timer interval to `0x2710` (10,000 ms = 10 seconds).
   - The transport timer `0x14043de10` checks `now - Connection+0xD0 >= interval`.
   - The client does not emit type `0x01` synchronously in response to D4.
   - Gating `0x90F2D04D` behind type `0x01` in the server caused a deadlock and timeout.

2. **Canonical Post-D4 Sequence:**
   - The server transmits D4 (`0xD4BA5CCD`) containing canonical XML with:
     - `title="Test Client"`
     - `useSyncClock="true"`
     - `loglevel="debug"`
     - `additionalClientConfigs="username=...;WorldName=he1012;SHARD_PUBLIC_NAME=he1012;"`
     - `<access-rights><client name="Automaton.exe"><network name="BWA" address="10.2.0.0/15"/></client></access-rights>`
   - The server immediately transmits ReplyGameLaunch (`0x90F2D04D`) on routes `0xE6A7/0xE800` containing `{worldHost}:{worldPort}`.
   - The server maintains an asynchronous receive loop for transport control frames; when type `0x01` arrives from the background timer, the server replies with type `0x02` (TransportTimeSync base response echoing the sequence and millisecond clock).

### Runtime validation of canonical `additionalClientConfigs` and immediate ReplyGameLaunch (September 12)

**CONFIRMED — resolver and encrypted-envelope boundary.** A clean isolated
private-client run, with only the documented copied-client `AI_ADDRCONFIG`
adjustment active, selected `Holocron Local Test`, connected to Auth, received
the 22-byte greeting, completed the 522-byte RSA handshake, and sent:

```text
client  type 0x10, message 011C5800, route E800/E6A7
```

This removes the previously observed no-socket failure from consideration for
this run. The test-only resolver bytes were restored after validation.

**CONFIRMED — server transmission order.** Auth then sent, in order, one
encrypted D4 response followed immediately by one encrypted ReplyGameLaunch:

```text
server  type 0x10, message D4BA5CCD, route E6A7/E800, 298 bytes
server  type 0x10, message 90F2D04D, route E6A7/E800, 39 bytes
```

The D4 document used the current canonical
`additionalClientConfigs="username=local-test;WorldName=he1012;SHARD_PUBLIC_NAME=he1012;"`
value. ReplyGameLaunch used `127.0.0.1:20061` plus its parser-valid empty
second string. No type-`0x01` gate was used.

**DISPROVEN as a complete behavioral explanation — missing `username` alone.**
The client closed the Auth socket approximately 268 ms after entering
`CS_LOGGING_IN`, before a type-`0x01` frame, the `Game launch reply address`
log, `HandleInitialize completed`, `CS_APP_INITIALIZED`, or any World socket
connection. The visible result remained error 1003. This is materially the
same early boundary as the prior roughly 283 ms failure, despite transmission
of a D4 document containing `username`.

The static null-dereference remains a **HYPOTHESIS** for documents whose
parsed configuration map lacks `username`; this run does not directly expose
the client map and therefore cannot prove whether that field was installed
before another D4 initialization failure. It does, however, show that adding
the field does not by itself advance this retail run.

**HYPOTHESIS — next deepest boundary.** Failure occurs during D4 handling,
before `AuthorizationReplyIFace::ReplyGameLaunch` dispatch and before shard
connection. Preserve the D4 field set, immediate launch ordering, and
asynchronous type-`0x01` handler. The next investigation must distinguish the
D4 XML parse/install path from `OmegaClientApp::HandleInitialized` without
randomly changing XML fields or treating error 1003 as the original rejection.

## Exact current-config D4 path and correction decision (September 12)

### Process lifetime discriminator

**BEHAVIORALLY CONFIRMED — socket close, not process crash.** In the clean
current-config run beginning at 07:53, Auth sent the 298-byte D4 frame and the
39-byte ReplyGameLaunch frame. The client entered `CS_LOGGING_IN`, reported
1003 about 250 ms later, and closed only the Auth connection. `swtor.exe`
remained alive for more than two minutes. Its log continued to receive platform
events, and Wine/Proton reported no `0xC0000005`, page fault, fatal signal, or
process exit. This directly resolves the earlier 268 ms ambiguity and makes
the crash explanation **DISPROVEN** for the observed event.

### First concrete failure on the current XML path

**CONFIRMED — static current-config branch.** The D4 success handler at
`0x1404279D0` parses the nonempty string, obtains the Frame, and calls
`0x140446C90` at `0x140427B3D`. `0x140446C90` installs the Frame at
`ApplicationImpl +0xF0` (`0x140446D8F`) and calls
`ApplicationImpl::HandleSettings` at `0x140447470` (`0x140446E7A`).

`HandleSettings` looks for the root child element `objects` at `0x140448E36`.
The current D4 XML has no such child. The null result is tested at
`0x140448EA4`, and `0x140448EA7` branches to cleanup/return at `0x140449FF4`.
That branch skips the global-object loop and therefore never dispatches the
application object's virtual slot `+0x08`, whose `OmegaClientApp` target is
`HandleInitialized` at `0x140121360`. The global initialized byte
`0x141BAB4FA`, which `HandleInitialized` would set at `0x140121C7B`, remains
zero.

After settings processing, the D4 handler calls the connection object's slot 0
at `0x140427B84`. `ConnectionObject::slot0` (`0x140135D20`) checks the
application error byte and then reads the initialized byte at
`0x140135D43`. The zero result makes the conditional branch at
`0x140135D4A` go to `0x140135DB0`; with error value 3 it loads virtual slot
`+0x20` at `0x140135DB8` and tail-calls the connection failure/close path.

The first failing function is therefore **`ConnectionObject::slot0` at
`0x140135D20`**. The first concrete failing check is the initialized-byte read
at **`0x140135D43`**, with its zero branch at **`0x140135D4A`**. The explicit
failure dispatch is **`0x140135DB8`**. Error 1003 is subsequently synthesized
by `ServerProxy::OnDisconnect`; it is not this internal error value and is not
the root cause.

### Null-unsafe and mandatory accesses in `OmegaClientApp::HandleInitialized`

The table is limited to settings actually touched by `0x140121360`. It does
not imply that this function is reached by the current XML; the missing
`objects` branch above prevents that callback.

| Setting/key | Lookup address | Missing-value behavior |
| --- | --- | --- |
| `access-rights` | `0x1401213B4` | Safe on this path: logs that it is not configured, then continues at `0x140121AEE`. |
| child `client` | `0x14012154E` | Safe: absent child skips the access-rights iteration. |
| child `network` | `0x1401215B2` | Safe: absent child skips the network loop. |
| `client/@name` | `0x1401215FD` | Conditionally unsafe when a network record exists; null is later dereferenced at `0x14012186A`. |
| `network/@name` | `0x140121671` | Conditionally unsafe when a network record exists; null is dereferenced at `0x1401217C9`. |
| `network/@address` | `0x1401216D5` | Conditionally unsafe when a network record exists; null is dereferenced at `0x140121724`. |
| `additionalClientConfigs` | `0x140121B10` | Missing/empty input produces no parsed entries; the later mandatory `username` lookup then returns null. |
| `username` | `0x140121BF0` | Unsafe if the callback is reached without the key: null from `0x14011E65B` is dereferenced at `0x140121C39`. Current XML supplies it. |
| `WorldName` | not touched | Not read by this function; no requirement established here. |
| `SHARD_PUBLIC_NAME` | not touched | Not read by this function; no requirement established here. |
| `repositoryserver` | not touched | Not read by this function; no requirement established here. |
| `worldserver` | not touched | Not read by this function; no requirement established here. |

The object dereference through `[r12+0x80]` at `0x140121E55` is not a config
lookup and occurs after the initialized byte is set and the completion log is
dispatched. It cannot explain the current absence of `HandleInitialize
completed`.

### Historical comparison and ReplyGameLaunch boundary

**CONFIRMED — historical source cannot supply the missing representation.**
`research/SwTor-1.3/server/WorldServer/Src/Logic/Senders/Client.cpp` supplies
the access-rights hierarchy and many root attributes, but it contains neither
an `objects` subtree nor `username`. It is an older-client reference and does
not establish the current retail global-object `code` value. Copying its full
initializer would therefore be speculation rather than a focused correction.

**CONFIRMED — ReplyGameLaunch is downstream and independent of the D4 failure.**
`0x140427220` is a separate message dispatch. No instruction in the missing-
`objects` branch or the initialized-byte failure check consumes its strings or
depends on its timing. `ServerProxy +0x78` remains retained until the reply is
successfully dispatched; the later disconnect merely converts that retained
context into visible error 1003. D4 opcode/routes, immediate ReplyGameLaunch,
type `0x01`/`0x02`, and launch ordering remain frozen.

### Focused correction experiments

**DISPROVEN — `<globalobject name="$appname"/>` is sufficient.** A clean run
with only `<objects><globalobject name="$appname"/></objects>` added sent a
348-byte D4 envelope. The client closed Auth at the same boundary and emitted
neither `HandleInitialize completed` nor `CS_APP_INITIALIZED`. Static control
flow also shows that an absent `code` supplies an empty module key to
`0x1404416D0`; a null return branches at `0x14044910D` to the application
failure callback at `0x1404495EF`.

**DISPROVEN — `code="HeroEngine"` is sufficient.** The local `swtor.icb`
installs and starts `HeroEngine`, making it a focused candidate rather than a
random historical attribute. A second clean run used exactly
`<objects><globalobject name="$appname" code="HeroEngine"/></objects>` and
sent a 366-byte D4 envelope. It produced the same Auth close and error 1003,
with no completion marker and no World connection. The experiment was reverted;
the production D4 XML and its focused test remain unchanged.

**CONFIRMED — correction decision.** The required configuration concept is a
root `objects` entry whose `globalobject` resolves the already-running
application object and invokes virtual slot `+0x08`. The exact accepted
current-retail `code`/representation is not recovered by the historical source,
and both evidence-derived minimal candidates failed runtime validation.
Consequently **no one-field correction is justified or retained**. The next
one-field correction is `none` until an accepted object descriptor is recovered;
adding another guessed field would violate the focused-change criterion.

The final full-suite baseline remains **47/47**. The copied executable's
temporary resolver instruction was restored to `C7 06 00 04 00 00` after
each run.

## Transport bit `0x10` is Zstandard compression — CONFIRMED (September 13)

This section is the current authority on the transport type byte. It supersedes
every earlier statement that `0x10` is an encryption class, that a type-`0x10`
payload is a raw application envelope, or that the client's login request
carries message `0x011C5800` on routes `0xE800`/`0xE6A7`.

### Method

One bounded private-client run used the existing isolated launcher with the
documented local test key and the temporary copied-client resolver adjustment.
The auth probe was temporarily extended to write the fully decrypted
post-handshake transport frame to a local, git-ignored analysis path; that
capture switch has been removed again. The private test client presents
synthetic credentials only, and no credential, token, or account field is
recorded here.

### The captured request

The client sent one encrypted frame whose decrypted transport header is
`10 2E 00 00 00 C1` (type byte `0x10`, declared length 46, complemented XOR
checksum), i.e. a 40-byte payload:

```text
00581C0100E8A7E609A6FFFFFFFF0F000000636173746C6568696C6C74657374000E0001006DC009
```

### That payload is a magicless Zstandard frame — CONFIRMED

Parsing it as a magicless Zstandard frame is self-consistent to the byte:

| Offset | Bytes | Meaning |
| --- | --- | --- |
| 0 | `00` | Frame_Header_Descriptor: no content size, no dictionary, no checksum, not single-segment |
| 1 | `58` | Window_Descriptor: windowLog 21, i.e. a 2 MiB window |
| 2 | `1C 01 00` | Block_Header 0x00011C: Last_Block 0, Block_Type 2 (compressed), Block_Size 35 |
| 5–39 | 35 bytes | the compressed block |

`2 + 3 + 35 = 40`, exactly the payload length. Independently, a reference
Zstandard library reports `headerSize = 2`, `frameContentSize = unknown`,
`windowSize = 2097152` for this payload under the magicless format, and rejects
it under the standard format because the frame begins without the
`28 B5 2F FD` magic number.

`Last_Block = 0` is expected rather than anomalous: the retail sender flushes
but does not terminate its frame (see below), so the stream continues into the
next transport frame.

### Exact Zstandard mode and configuration — CONFIRMED

Recovered from the installed client and then validated on the wire:

```text
context creation   client-role connection setup
                   0x14043E749 compressor, 0x14043E7AB decompressor
                   shared initializer 0x140439E90; the level argument is 0,
                   which selects Zstandard level 3
format             ZSTD_c_format (parameter 10) = 1
                   (ZSTD_f_zstd1_magicless), set at 0x140439F80
decompressor       ZSTD_d_format (parameter 1000) = 1
                   (ZSTD_f_zstd1_magicless), set at 0x140439F22
flush mode         ZSTD_e_flush: output flushes the pending input but leaves
                   Last_Block = 0, so one connection is one continuous frame
threshold          the sender compresses only payloads of at least 0x20 bytes
                   (0x14043B887) and then sets bit 0x10 (0x14045C4F1)
dictionary         none; no dictionary is loaded on either context
checksum flag      off (frame descriptor bit 2 clear)
```

There is no dictionary, no special format parameter beyond magicless framing,
and no preprocessing step.

### Byte-exact confirmation — CONFIRMED

Decompressing the captured payload yields 39 logical bytes:

```text
A7E609A6FFFFFFFF0F000000636173746C6568696C6C74657374000E0000000000000000000000
```

Re-encoding exactly those 39 bytes with Zstandard level 3, magicless framing and
`ZSTD_e_flush` reproduces the captured 40-byte payload **byte for byte**. Two
independent implementations agree on the decode, and the encode is
deterministic, so this pair is the client's actual request and not a
plausible-looking coincidence.

### DISPROVEN — the former `0x011C5800` / `0xE800` / `0xE6A7` envelope

Those values were read from the *compressed* payload as if it were an
application envelope. Their source bytes are the frame header (`00 58`), the
block header (`1C 01 00`), and the first literal bytes of the compressed block.
They are therefore not a message id, not routes, and carry no protocol meaning:

```text
old reading   message 0x011C5800, route 0xE800/0xE6A7   DISPROVEN
              "0x10 is an encrypted transport class"     DISPROVEN
              "the payload after the header is the       DISPROVEN
               application dispatch envelope"
```

The route-reversal conclusion and every response that used
`0xE6A7`/`0xE800` inherited the same error.

### Corrected request envelope — CONFIRMED

After decompression the dispatch envelope is:

```text
offset  width  value
+0x00   u32    0xA609E6A7   message
+0x04   u16    0xFFFF       route word 1 (wildcard)
+0x06   u16    0xFFFF       route word 2 (wildcard)
+0x08   u32    15           length-prefixed string, including its NUL
+0x0C   15      "castlehilltest" + NUL
+0x1B   ...     two trailing fields
```

The client's own serializer corroborates this independently: `0x14045BAC4`
writes `0xA609E6A7` as the message and `0x14045BB02`/`0x14045BB46` write the
constant `0xFFFF` for both route words immediately after it. The same constant
is compared at `0x140412B61` and `0x14042B9B9` and passed as the message at
`0x14045BC5E`.

Because both route words are the wildcard value, the previously reported
"route direction" question does not apply to the observed login request:
there is nothing to swap.

### Corrected transport pipeline

```text
before (incorrect)
  receive: socket -> Salsa20 -> header -> payload used directly as envelope
  send:    envelope -> TransportFrame(0x10) -> Salsa20 -> socket

after (confirmed)
  receive: socket -> Salsa20 -> header -> if bit 0x10: Zstd decompress
           -> logical payload -> envelope
  send:    logical payload -> if >= 0x20 bytes: Zstd compress and set bit 0x10
           -> transport frame -> Salsa20 -> socket
```

Encryption is session state, not a per-frame property, and `0x10` is a flag on
the transport type byte rather than a discrete transport class; the low nibble
carries the actual transport type (`0` routed application, `1`/`2` time sync,
`4` key exchange). Transport control frames we send are 8 and 13 bytes, below
the compression threshold, so they stay uncompressed and unchanged.

### Corrected `omega::ServerProxy` layout — CONFIRMED

`ServerProxy::OnDisconnect` at `0x140427170` gates the whole failure path on
`[this + 0x90]`:

```text
0x14042718E  cmp QWORD PTR [rcx+0x90],0      state/launch context test
0x140427196  je  ...                         no context -> no failure report
0x1404271A9  mov rcx,[rcx+0x90]              take it
0x1404271B5  mov [rbx+0x90],rax(0)           clear it, releasing via vtable +0x30
0x1404271CF  mov rcx,[rbx+0x78]              application pointer
0x1404271D6  mov DWORD PTR [rsp+0x40],0x3EB  error 1003
0x1404271E3  call [rax+0x98]                 report through the application
```

Therefore `ServerProxy + 0x78` is the application pointer used to report the
failure, and the retained launch/state context that gates `OnDisconnect` is at
`ServerProxy + 0x90`. The earlier statement that `+0x78` is the retained
launch-request context is **SUPERSEDED**. Reply handlers also read and clear a
`+0x78` field (`0x140427264`, `0x140427516`, `0x14042757F`); whether that is
the same field or a field of an adjusted base subobject is not resolved by this
pass and is not used as evidence here.

### Implementation and regression coverage — CONFIRMED

`TransportCompressor` / `TransportDecompressor` own the payload layer and
`TransportCodec` owns the session layer (Salsa20 state plus the per-connection
compression contexts). Both the bounded probe and the normal AuthServer session
loop now use that single implementation; there is no separate probe protocol.

The captured payload is committed as a fixed test vector. Tests assert that it
decompresses to the exact logical bytes, that re-encoding reproduces it byte for
byte, that its frame header and unfinished block match the layout above, that
consecutive messages share one continuous compressed stream, that a corrupt or
non-compressed payload is rejected, that control frames stay uncompressed, and
that cipher and compression state survive consecutive frames in both
directions. The complete suite passes **56/56**.

### One bounded retail validation run — CONFIRMED and HYPOTHESIS separated

A single bounded private-client run (both automatic selections in that one run
produced the same result) changed only the transport payload codec: Salsa20
framing, D4 XML, ReplyGameLaunch strings, message ids, request timing and
ordering were untouched. The captured executable's temporary resolver
adjustment was restored by the runner afterwards, and no payload or credential
was retained.

```text
CONFIRMED  client  RSA type 4, 522 bytes, test-key envelope validated
CONFIRMED  client  routed application frame decoded through the codec
                   logical 39 bytes, message 0xA609E6A7, route 0xFFFF/0xFFFF
CONFIRMED  server  login reply D4BA5CCD, route 0xFFFF/0xFFFF, 284-byte body
CONFIRMED  server  game launch reply 90F2D04D, route 0xFFFF/0xFFFF
CONFIRMED  client  EOF after the launch reply, twice, on two connections
CONFIRMED  client  error 1003 about 341 ms after CS_LOGGING_IN
CONFIRMED  snapshot after both attempts: initialized byte 0, settings Frame 0
```

The server-side decode is a real advance: before this change the server read a
compressed payload as if it were an envelope, and its replies set bit `0x10` on
an *uncompressed* payload, so the client could never decode any server
application frame at all.

**CONFIRMED — the server's outbound frames are decodable.** The exact 292-byte
D4 reply envelope, compressed through the same code path, round-trips through a
reference Zstandard library (magic restored) with no residue. The client's
decoder is configured for the same magicless format, so the reply is not
rejected at the payload layer.

**HYPOTHESIS — the reply does not reach the D4 handler.** The post-run snapshot
still reports no installed settings Frame, which the D4 success path would
install at `ApplicationImpl + 0xF0` before calling `HandleSettings`. Since the
payload layer is now known-good, the remaining candidates are the reply's
dispatch key and the connection-setup stage that precedes routed delivery.

**CONFIRMED — `(0xFFFF, 0xFFFF)` is a dedicated wildcard route, not a map key.**
At `0x14043CF9D` the receiver loads `0xFFFF` and compares both decoded route
words against it; when *both* match it branches at `0x14043CFB7` to a separate
path at `0x14043D060` instead of searching the composite-key tree at
`0x14043CFBD`. Both paths rejoin the global-message check at `0x14043D266`.
The client's login request and the server's replies therefore use the dedicated
wildcard route rather than a per-connection route entry.

**CONFIRMED — the receiver's global message cases.** `0x14042B990` compares the
incoming message against exactly three constants and consumes the event for
them:

```text
0xA609E6A7  -> 0x14042BCA0   the client's own login request message
0x6731C5AF  -> 0x14042C300
0x8B0D492F  -> 0x14042C910   the control-setup parser that installs the
                             composite receive-tree entry for a connection
```

The reply message `0xD4BA5CCD` matches none of them, so a wildcard-routed reply
falls through to wildcard endpoint resolution. Whether that resolves to
`omega::ServerProxy` is unresolved, and the earlier attribution of the reply
message ids was obtained under the disproven envelope reading.

**NEW FAILURE BOUNDARY.** The failure is no longer "the server cannot speak the
retail transport". It is now: *the client accepts nothing on the wildcard route
beyond the three global messages, so a `D4BA5CCD` reply never reaches the D4
handler.* The next stage to investigate is the client-initiated connection
setup that the three global messages represent, in particular the payload
contract of `0x8B0D492F` at `0x14042C910` and of `0x6731C5AF` at `0x14042C300`,
and which endpoint the wildcard path resolves to. No speculative change was
made to that stage.

The complete suite passes **56/56** with these findings, and the working tree
passes `git diff --check`.

## Global connection bootstrap: the identification exchange (September 13)

This section answers what the client's first global request is, what answers it,
and how a routed endpoint is meant to be established. It supersedes the
September 13 note in the transport section that listed the three global message
ids only as dispatch cases.

### Semantic names — CONFIRMED

The client binary registers each global message id together with an interface
signature string (`0x1404060AA`/`0x1404060FB`/`0x14040614E` store the id and the
adjacent `lea` loads the name):

```text
0xA609E6A7  RequestIDIFace::RequestIDSignature
0x6731C5AF  ReplyIDIFace::ReplyIDSignature
0x8B0D492F  RequestIDIFace::IntroduceConnectionSignature
```

They live in the omega object system's name table next to
`OmegaServerProxyObjectName`, `Close`, and `RequestClose`.

### Proven directionality — CONFIRMED, by producer/consumer pairing

Direction is not inferred from the mere existence of a handler. Each id has a
serializer (producer) and a comparison in the receive dispatcher (consumer), and
the producers form a closed exchange:

| Id | Producer (serializer) | Only caller | Consumer (receive) |
| --- | --- | --- | --- |
| `0xA609E6A7` | `0x14045BA00` | `0x14042BC19` | `0x14042BCA0` |
| `0x6731C5AF` | `0x14045BCD0` | `0x14042BECD`, `0x14042BFA4`, `0x14042C06D`, `0x14042C151`, `0x14042C208` | `0x14042C300` |
| `0x8B0D492F` | `0x14045B620` | `0x14042C6B7` | `0x14042C910` |

The decisive fact is where each producer is called **from**:

```text
0x14042BCA0  handler for an incoming 0xA609E6A7  ->  sends 0x6731C5AF
0x14042C300  handler for an incoming 0x6731C5AF  ->  sends 0x8B0D492F
```

So the exchange is `RequestIDSignature` (client) → `ReplyIDSignature` (server) →
`IntroduceConnectionSignature` (client). The pairing is defined by the binary
itself, not by convention.

### `0xD4BA5CCD` and `0x90F2D04D` re-verified — CONFIRMED as server → client

Both ids occur **only** as comparisons in the `omega::ServerProxy` message
dispatcher (`0x14045A71D` and `0x14045A216`). Neither has a serializer anywhere
in the executable, so the client never produces them. Their direction is
independently confirmed even though the route interpretation that originally
introduced them was wrong.

### Payload layouts — CONFIRMED

`RequestIDSignature`, server-side parser `0x14042BCA0` (string at `0x14042BD56`
through the length-prefixed string reader `0x1403FB300`, then eight bytes):

```text
+0x00  encoded string   shard name ("castlehilltest" in every observed run)
+0x..  u64              session correlation, echoed by the reply
```

The captured real body is `0F 00 00 00 "castlehilltest" 00 | 0E 00 00 00 00 00 00 00`.
The correlation is **not** the string length: two later runs carried `6` and
`10` with the same 14-character name.

`ReplyIDSignature`, client-side parser `0x14042C300`, which requires remaining
length `2`, then a `u16`, then three strings, then eight bytes, then complete
consumption:

```text
+0x00  u16              route word; every producer site passes 0xFFFF
+0x02  encoded string
+0x..  encoded string
+0x..  encoded string
+0x..  u64              echoes the request correlation
```

`IntroduceConnectionSignature`, serializer `0x14045B620`, arguments
`(out, u16 a, u16 b, struct*)`:

```text
envelope  u32 0x8B0D492F, u16 0xFFFF, u16 0xFFFF
+0x00  u16 a            client 0x14042C6AB: ObjectSurrogate + 0x28 local id
+0x02  u16 b            client 0x14042C6A5: the route word from the reply
+0x04  encoded string
+0x..  encoded string
+0x..  encoded string
+0x..  u64
```

### Route-registration mechanism — CONFIRMED

`0x14042C910` is the receiver of `IntroduceConnectionSignature`. It parses two
`u16` words and, through `0x140412180` / `0x140411D30`, stores the first as the
connection's local route word and resolves the second to an object surrogate
whose local id becomes the peer word, then inserts the composite receive key
`(word 1, word 2)` for that connection. **These words originate on the client**,
from its own object surrogate and from the route word carried in the server's
`ReplyIDSignature`.

The client's first request does not use that mechanism: `0x14045BA00`
hardcodes the wildcard pair `0xFFFF`/`0xFFFF`, and the receiver recognises it at
`0x14043CF9D` and branches to a dedicated wildcard path instead of the
composite-key tree.

### Runtime experiment — one reply, listen only

`Holocron.Auth --probe-id-bootstrap` answers the client's global request with
exactly one `ReplyIDSignature` (u16 `0xFFFF`, the shard name in all three string
fields, request correlation echoed) and then only listens. Nothing else was
changed: no D4, no ReplyGameLaunch, frozen transport codec, frozen compression.

Two selections in one bounded run produced identical results:

```text
client  type 0x00  logical 39 bytes  RequestIDSignature name="castlehilltest" correlation=0x06 / 0x0A
server  type 0x10  ReplyIDSignature 0x6731C5AF on route 0xFFFF/0xFFFF
client  type 0x01  logical 8 bytes   transport time request, sequence 1
client  no IntroduceConnection within the 20 s window
client  HandleLaunchFailure 1003 about 104 ms after CS_LOGGING_IN
state   initialized byte 0, settings Frame 0
```

**CONFIRMED — the reply is the paired response and moves the state machine.**
The client's reply handler reaches `0x14042C50A`, compares the reply's `u16`
against `0xFFFF`, takes the *equal* branch, and calls
`0x1404123D0(connection, 2, 3)` — a connection state transition. That call is
reached only because our reply carried `0xFFFF`.

**CONFIRMED — the client sends its transport time request on this path.** No
earlier run of ours ever observed a client `0x01` frame; it appears in both
attempts here.

**HYPOTHESIS — the bootstrap is still incomplete.** The client did not send
`IntroduceConnectionSignature`, so no routed endpoint exists yet. The three
string fields and the object produced by `0x14042D320` (called at `0x14042C437`,
whose result is dereferenced at `0x14042C4EA` where a null bails to
`0x14042C8D0`) are the next unknowns; the placeholder value used in this
experiment was the shard name, and the binary's own server-side handler passes
the literal `"???"` there.

### NEW FAILURE BOUNDARY

The failure is no longer "the client never answers the bootstrap". It is now:
*the client accepts `ReplyIDSignature` and runs the connection transition, but
does not emit `IntroduceConnectionSignature`, so no route is registered and no
routed endpoint exists to deliver D4 to.* The next task is to recover the
`ReplyIDSignature` string semantics and the `0x14042D320` object contract, then
re-run this same one-reply experiment until the client emits
`0x8B0D492F`; its two `u16` words are then the proven route pair for D4.

Baseline after this task: **61/61** tests pass and the copied executable's
resolver instruction was restored to `C7 06 00 04 00 00`.

## ReplyIDSignature handler contract and the IntroduceConnection transition (September 13)

This section supersedes the HYPOTHESIS paragraph at the end of the previous
section. The bootstrap transition is now proven, and the exact condition that
blocked it is known.

### The handler control flow — CONFIRMED

`0x14042C300` is the receiver of `0x6731C5AF`. Its arguments are
`rcx = context`, `rdx = body reader`, `r8 = reader end`. Parse order, all
required:

```text
0x14042C35E  remaining >= 2                      else exit 0x14042C8ED
0x14042C376  u16 read into r12w and [rsp+0x40]   <- the reply's body word
0x14042C3AC  length-prefixed string -> [rsp+0x68]
0x14042C3C2  length-prefixed string -> [rsp+0x58]
0x14042C3D8  length-prefixed string -> [rsp+0x48]
0x14042C3E5  remaining >= 8                      else exit 0x14042C8F9
0x14042C3FD  u64 read into r14 (the correlation)
0x14042C423  0x1403FB230 requires complete body consumption
0x14042C437  call 0x14042D320(rcx=context, rdx=&[rsp+0x128], r8=r14)
0x14042C43D  rcx = [rsp+0x128]
0x14042C445  test rcx,rcx
0x14042C448  jne 0x14042C505                     <- builder result decides
```

```text
builder returned NULL
  0x14042C44E..0x14042C4E2  release the three strings and the object
  0x14042C4E7  rcx = [rsi]
  0x14042C4ED  je 0x14042C8D0                    -> function exit
  0x14042C4FA  virtual release
  0x14042C500  jmp 0x14042C8D0                   -> function exit
  (IntroduceConnection is never reached)

builder returned non-NULL
  0x14042C505  eax = 0xFFFF
  0x14042C50A  cmp r12w,ax                       <- reply word vs sentinel
  0x14042C50E  jne 0x14042C5DA

  reply word == 0xFFFF
    0x14042C514/0x14042C519  edx = 2, r8d = 3
    0x14042C51D  call 0x1404123D0(connection, 2, 3)   <- state transition
    0x14042C523..0x14042C5BC  release everything
    0x14042C5C2  je 0x14042C8D0
    0x14042C5D5  jmp 0x14042C8D0                 -> function exit
    (IntroduceConnection is never reached)

  reply word != 0xFFFF
    0x14042C5DA..0x14042C639  release the strings, take the object
    0x14042C641  lock cmpxchg [object+0x88]
    0x14042C6A5  r8d = [rsp+0x40]                <- the reply word
    0x14042C6AB  edx = [object+0x28]             <- the pending record's id
    0x14042C6B7  call 0x14045B620                <- IntroduceConnection
```

Answers, explicitly:

1. **Does the `u16 == 0xFFFF` path reach `0x14042C6B7`?** No. It calls
   `0x1404123D0(connection, 2, 3)` and then jumps to the exit at `0x14042C8D0`.
2. **Does the `u16 != 0xFFFF` path reach it?** Yes, and it is the only path.
3. **Is a non-null builder result required?** Yes. A null result releases
   everything and exits at `0x14042C8D0`.
4. **Additional checks?** Only the two above plus the strict parse. There is no
   further state or object test between `0x14042C448` and `0x14042C6B7`.
5. **What failed in the previous run?** The reply word was `0xFFFF`, so the
   client took the equal branch. The builder condition held — the client only
   reaches `0x14042C505` when the builder is non-null.

### What the reply's body word means — CONFIRMED

It is the **server-assigned object id** for this connection, and `0xFFFF` is the
**"no object assigned" sentinel**. Evidence:

* the client tests it against `0xFFFF` and treats that value as a distinct,
  connection-transition-only outcome (`0x14042C50A`);
* the client copies the received value straight back into the first field of
  `IntroduceConnectionSignature` (`0x14042C6A5`), which the peer resolves to an
  object surrogate;
* the serializer `0x14045BCD0` writes it as a body field (`0x14045BE5D`), while
  the envelope route words are hardcoded `0xFFFF` (`0x14045BDD5`,
  `0x14045BE19`). The two are different values with different roles.

The five in-binary producer sites in `0x14042BCA0` all pass the literal
`0xFFFF`. Since that value cannot reach the introduce path, those sites are
peer-role refusals, not the successful authentication reply. The success value
must come from the server's own object allocation; this is why no in-binary
producer demonstrates it.

### The three strings — CONFIRMED provenance

Serializer `0x14045BCD0` writes them in order, and each is taken from a
different argument:

```text
string 1  0x14045BE80..0x14045BE99   *(arg3)   or 0x14156BD60 when null
string 2  0x14045BE9E..0x14045BEB0   *(arg4)   or 0x14156BD60 when null
string 3  0x14045BEBC..0x14045BECE   *(arg5)   or 0x14156BD60 when null
```

At every in-binary call site `arg3` is `0x14157F2D4`, the literal `"???"`, and
`arg4` is `0x14156BD60`, the shared empty-string constant; `arg5` is
`[context+0x10]`, a dynamic value. So `"???"` is a placeholder object name, not
a meaningful token.

The handler that consumes the reply parses all three, then **only frees them**:
`0x14042D320` is called with `(context, &out, correlation)` and receives none of
them. Their values therefore do not gate the introduce transition.

The semantics come from the opposite direction. The client's own
`IntroduceConnectionSignature` carries the object-surrogate descriptor, and the
live capture names it outright:

```text
name        "OmegaServerProxyObjectName"
class       "Client"
interfaces  "b7a6bba3:8ab55405:5bc541f9"
```

`OmegaServerProxyObjectName` and `Client` are both entries in the object-name
table beside the interface signatures, so the three fields are the **object
name, its class, and its interface list**. An authentication reply that wants to
name the object it is introducing would carry the same shape.

### `0x14042D320` — CONFIRMED contract

A mutex-guarded linear search, not an object allocator:

```text
signature  0x14042D320(rcx = context, rdx = out slot, r8 = u64 key)
0x14042D342  rbp = r8                     the key
0x14042D352  rsi = context + 0x28         the guard
0x14042D35D  EnterCriticalSection
0x14042D364  r15 = context + 0x130        the list sentinel
0x14042D36B  rdi = [r15]
0x14042D371  rdi == r15 -> empty -> 0x14042D3C0
0x14042D380  rbx = [rdi+0x10]             the node payload
0x14042D3A2  cmp [rbx+0x10], rbp          payload key == u64
0x14042D3A6  equal -> 0x14042D3FC         found
0x14042D3BE  jne 0x14042D380              advance and retry
0x14042D3C0  [out] = 0                    not found
0x14042D3CB  leave critical section, return the out slot
```

Working name: **`FindPendingRequestByCorrelationId`**. Its key is the 64-bit
value the client sent in `RequestIDSignature` and expects echoed in the reply;
its result is the pending-request record whose `+0x28` becomes the first word of
`IntroduceConnectionSignature`. A reply that does not echo the correlation makes
the lookup fail and the handler exits before any branch.

### Runtime result — the transition is proven

One reply, `u16 = 0x0001` (a real assignment rather than the sentinel), three
empty strings (the parser-valid encoding, since this path does not consume
them), correlation echoed. Two selections in one bounded run, identical:

```text
client  RequestIDSignature        correlation 0x06 / 0x0A
server  ReplyIDSignature          u16 0x0001 on 0xFFFF/0xFFFF
client  IntroduceConnectionSignature  *** EMITTED ***
          client-object-id  0x0000
          reply-word        0x0001   (the value we assigned, echoed)
          name              "OmegaServerProxyObjectName"
          class             "Client"
          interfaces        "b7a6bba3:8ab55405:5bc541f9"
          u64               0x0000000000000000
          logical           111 bytes
```

**CONFIRMED.** The bootstrap transition the previous task could not obtain now
occurs, reproducibly, and the only changed input is the reply's body word.

### Route registration and D4 — NOT PROVEN

The client-object-id came back as `0x0000`, which is itself a sentinel-shaped
value, and the mirror `IntroduceConnectionSignature` the server sent to establish
the client-side entry used it as a lookup key. Naming and pairing for the
server-to-client direction are therefore still unproven. One routed D4 was sent
on the mirror-derived pair `0x0001/0x0000`; the client closed the socket, the
settings Frame stayed null, no `HandleInitialize completed` appeared, and error
1003 followed 45 ms after `CS_LOGGING_IN`. D4 did **not** demonstrably reach its
handler, and this pair must not be treated as the route.

### NEW FAILURE BOUNDARY

The failure has moved past identification and past connection introduction. It
is now: *the client introduces `OmegaServerProxyObjectName`/`Client` and expects
the peer to complete the pairing, but the server-to-client route key is still
unknown because the introduced client object id is `0x0000` and the mirror rule
used to derive the pair is a hypothesis.* The next task is to recover the
client's inbound receive key directly — from the client's receive-tree
registration path (`0x140412180` / `0x14043D380`) and from what the client does
with an incoming `IntroduceConnectionSignature` — before any further D4 is sent.

Baseline after this task: **63/63** tests pass and the copied executable's
resolver instruction was restored to `C7 06 00 04 00 00`.

## Routed receive-key derivation and the post-introduce `Close` (September 13)

This section supersedes the "Route registration and D4 — NOT PROVEN" paragraph
and the NEW FAILURE BOUNDARY that followed it. The receive key is now derived
from code, the two route words have proven roles, and the early socket death has
been shown to be intrinsic to the client rather than caused by our packets.

### Incoming `IntroduceConnectionSignature` handler — CONFIRMED CFG

`0x14042C910`, arguments `rcx = context`, `rdx = body reader`, `r8 = reader end`:

```text
0x14042C99C  require remaining >= 2            else exit 0x14042D2FE
0x14042C9BB  r14w = u16 #1 -> [rsp+0x88] and [rsp+0x428]
0x14042C9F3  require remaining >= 2            else exit 0x14042D30A
0x14042CA0D  r13w = u16 #2 -> [rsp+0x8c]
0x14042CA40  string #1 -> [rsp+0x78]
0x14042CA56  string #2 -> [rsp+0x60]
0x14042CA6C  string #3 -> [rsp+0x50]
0x14042CA7C  call 0x140411660
0x14042CA84  call 0x1403FB230                  require complete consumption
             failure -> 0x14042CB73            (cleanup)
0x14042CC9C  r8d = r13w                        <- u16 #2
0x14042CCAB  call 0x14042A950                  ObjectSurrogate lookup by id
0x14042CCBC  jne 0x14042CE4D                   found -> continue
             not found -> cleanup, exit 0x14042D2E1   (no registration)
0x14042CE4D  rcx = [rax+0x30]; call 0x14042D470
0x14042CE79  jne 0x14042D07B
0x14042CE88  call 0x140431800 ; je 0x14042CF9C
0x14042CECC  call 0x140430E20
0x14042CF88  call 0x140411D30                  Connection+0x28 = surrogate+0x28
0x14042D07B  call 0x140429100 ; 0x1404115B0 ; 0x140412C90 ; 0x1404117E0
0x14042D14F  edx = [rsp+0x428]                 <- u16 #1
0x14042D15A  call 0x140412180                  Connection+0x60 = u16 #1, then insert
```

Field flow, exactly:

```text
u16 #1  -> Connection + 0x60            via 0x1404121E4 "mov WORD PTR [rdi+0x60],bx"
u16 #2  -> ObjectSurrogate lookup       via 0x14042A950
        -> surrogate + 0x28             via 0x140411DE2/0x140411DE7
        -> Connection + 0x28
strings -> parsed and released; the registration path does not consume them
```

### Word roles — CONFIRMED

| | Meaning | Evidence |
| --- | --- | --- |
| u16 #1 | the **peer's** object id for this connection; becomes the receiver's `Connection + 0x60` | `0x14042D14F` loads it into `edx` for `0x140412180`, which stores it at `[rdi+0x60]` (`0x1404121E4`) |
| u16 #2 | the **receiver's own** object id; resolved to an `ObjectSurrogate` on the receiving side, whose `+0x28` becomes `Connection + 0x28` | `0x14042CC9C`/`0x14042CCAB` lookup, then `0x140411D30` |

This is a mirror, not a symmetry assumption: the client sends the id it received
in the reply as `#2` precisely so the peer can resolve it to the object the peer
itself assigned.

### `ObjectSurrogate + 0x28` — CONFIRMED

It is the surrogate's **16-bit local object id**, copied verbatim into the
connection:

```text
0x140411DE2  movzx eax, WORD PTR [r13+0x28]
0x140411DE7  mov   WORD PTR [rdi+0x28], ax
```

The client's `Connection + 0x28` is set from its own surrogate by the
`RequestIDSignature` send path (`0x14042B721`) and again by the incoming
introduce handler (`0x14042CF88`).

### Is object id `0x0000` valid? — CONFIRMED usable, sentinel is `0xFFFF`

* `0x14042AA30` reserves `0xFFFF` explicitly: `mov r14d,0xffff` compared against
  the candidate id, with collision checks against the existing id tree. No
  comparable special case exists for zero anywhere on this path.
* The receive path's wildcard test at `0x14043CF9D`-`0x14043CFB7` requires
  **both** route words to be `0xFFFF`. A `(x, 0)` pair is therefore an ordinary
  tree key, never a wildcard.
* Operationally, the retail client itself produced `0x0000` as its connection's
  local id and then used it as the second word of its own receive key.

So zero is a normal key component. Whether it is specifically the *first*
allocated id is not proven and is not needed.

### Receive-tree key construction — CONFIRMED

```text
0x14043D416  movzx ecx, WORD PTR [rax+0x60]   Connection + 0x60  -> key field A
0x14043D421  movzx ecx, WORD PTR [rax+0x28]   Connection + 0x28  -> key field B
```

stored adjacently at `[rbp+0x50]`/`[rbp+0x54]`, i.e. a packed
`u32 = (B << 16) | A`, then inserted through `0x14043FEC0` into the ordered tree
whose nodes compare at `+0x20` (field A) and `+0x24` (field B).

### Envelope route words to tree-key words — CONFIRMED

`0x140454070` (the dispatch envelope reader) writes its outputs in this order:

```text
0x140454098/0x14045409B  u32 at offset 0 -> rdx argument
0x1404540C9/0x1404540CD  u16 at offset 4 -> r8  argument
0x1404540FC/0x140454100  u16 at offset 6 -> r9  argument
```

and the receive call site `0x14043CF7D`-`0x14043CF92` passes
`r9 = &[rsp+0xF8]`, `r8 = &[rsp+0x30]`. The tree search then uses
`[rsp+0x30]` (offset-4 word) against node `+0x20` and `[rsp+0xF8]`
(offset-6 word) against node `+0x24`.

Therefore, for a message addressed to a connection `C`:

```text
envelope routeA (offset 4) == key field A == C + 0x60
envelope routeB (offset 6) == key field B == C + 0x28
```

### Does the peer have to send an introduce back? — CONFIRMED NO

The client sets its **own** `Connection + 0x60` and inserts its own receive entry
when it *sends* `IntroduceConnectionSignature`, not when it receives one:

```text
0x14042C77A  movzx edx, WORD PTR [rsp+0x40]   <- the reply's body word
0x14042C782  call 0x140412180                  -> Connection+0x60, then 0x14043D380 insert
```

`0x140412180` is reached from exactly two places, and the other one
(`0x14042D15A`) is the incoming handler. So an incoming introduce registers the
*receiver's* key; it is not required for the client to become reachable.

### Derived route pair

```text
client object id:   0x0000   (its Connection + 0x28)
server object id:   0x0001   (the reply's body word = its Connection + 0x60)

client receive-tree key:
    word A (Connection+0x60) = 0x0001
    word B (Connection+0x28) = 0x0000

server -> client routed envelope:
    routeA = 0x0001
    routeB = 0x0000

confidence: high for the construction; the two numerals are the values the
            retail client reported at runtime in this experiment
evidence:   any one branch of the chain above, and the live IntroduceConnection
            payload itself for the two numerals
```

### Runtime control result — the early close is intrinsic

With the server sending **nothing** after `ReplyIDSignature` (no mirror, no D4),
the client still emitted its introduce and then, one frame later:

```text
[AUTH] Control-window frame: transport-type=0x00, logical=8 bytes, message=0x43DB3479
[AUTH] Client closed the connection during the control window.
client error 1003 about 45 ms after CS_LOGGING_IN
```

**CONFIRMED — `0x43DB3479` is `Close`.** It is registered in the same global
registration block as the other identification messages, and the name string
loaded immediately after its constant is the one at `0x14157E740`, `"Close"`.
Its dispatcher case at `0x14042BABC` performs a connection state transition:

```text
0x14042BABC  cmp r9d,0x43DB3479     ; Close
0x14042BAC5  mov edx,1              ; -> 0x1404123D0(connection, 1, 0)
0x14042BACC  cmp r9d,0x0598D9A7     ; RequestClose
0x14042BAD5  xor edx,edx            ; -> 0x1404123D0(connection, 0, 0)
```

So `Close` and `RequestClose` are additional global messages in the same family,
and the client closes the bootstrap connection itself. This also **DISPROVES**
the earlier implication that our mirror packet or the routed D4 caused the
~45 ms socket death: the same death occurs with nothing sent.

### NEW FAILURE BOUNDARY

The failure is now: *the client completes `IntroduceConnectionSignature` and then
immediately sends `Close`, tearing down the bootstrap connection before any
routed application message can be delivered.* The next task is to determine what
the client requires between those two events — the strongest candidate is that
`ReplyIDSignature` must carry the peer object's real descriptor in its three
string fields (this experiment sent them empty, and the binary's own producer
sends `"???"`/empty/dynamic), or that an additional global message is expected in
that window. Only after that is resolved is a routed D4 meaningful.

The derived pair `0x0001`/`0x0000` is recorded above and must not be re-tested
until the `Close` boundary is resolved, because a socket that is already being
torn down cannot demonstrate route delivery.

## Close/RequestClose lifecycle, the `0x1404123D0` contract, and route survival (September 13)

This section supersedes the "NEW FAILURE BOUNDARY" of the previous section and
records what the post-introduce `Close` actually is.

### `0x1404123D0` is the close verb, not a generic state setter — CONFIRMED

Signature `0x1404123D0(rcx = connection, edx = X, r8d = Y)`. It contains the
`Close` serializer and sender:

```text
0x140412419  call 0x140414CB0(connection, 7, 0x7F, 0x180)   state query
0x140412481  rbx = [rbp+0xF8]
0x1404124D3  rdi = [rsp+0x28]        the connection resolved from the correlation lookup at 0x140412465
0x1404124DB  je 0x1404126FE          null -> cleanup, nothing sent
0x1404124E1  cmp r14d, 0x4           r14d = the state-query result
0x1404124E5  jne 0x1404126C5         not 4 -> skip the send
0x1404124EB  test r15d, r15d         r15d = X
0x1404124EE  jne 0x1404126C5         X != 0 -> skip the send
0x140412572  mov DWORD PTR [rax], 0x43DB3479        write "Close"
0x140412594  movzx edx, WORD PTR [rsi+0x28]         body word 1 = Connection+0x28
0x1404125A2  movzx edx, WORD PTR [rsi+0x60]         body word 2 = Connection+0x60
0x140412604/0x14041260C  requires state 4 or 7
0x140412654  mov r9d, 0x43DB3479
0x140412667  call 0x14043B460                       transport send
0x1404126F2  call 0x14043D550                       receive-tree operation
```

**The exact condition that emits a `Close` frame is therefore: the connection is
non-null, the state query returns `4`, and `X == 0`.** Every other `X` value
simply performs the state bookkeeping without sending.

Caller `X`/`Y` values recovered:

| Caller | X | Y | Sends Close? |
| --- | --- | --- | --- |
| `0x140412317` registration insert failed (`0x140412180`) | 2 | 1 | no |
| `0x14043D4E7` registration insert succeeded (insert helper `0x14043D380`) | 2 | 12 | no |
| `0x14042C51D` `ReplyIDSignature` with reply word `0xFFFF` | 2 | 3 | no |
| `0x14042BADD` incoming `RequestClose` dispatch | 0 | 0 | **yes** |
| `0x1404371E6` list teardown over connections | 0 | 0 | **yes** |
| `0x140468D66` single-connection teardown (`rcx = [rdx+8]`) | 0 | 0 | **yes** |
| `0x14043B190`, `0x14043B210`, `0x14042B94F`, `0x140438268`, `0x140430270`, `0x140430460` | 2 | varies | no |

So `X` behaves as a **verb**: `2` = state bookkeeping only, `0` = close this
connection. The dispatcher confirms it: an incoming `RequestClose` is turned into
`(connection, 0, 0)`.

### Directionality — CONFIRMED

`RequestClose` (`0x0598D9A7`) has **no serializer anywhere** in the executable
(only the registration at `0x140406059`, the receive comparison at `0x140412B7E`
and the dispatcher case at `0x14042BACC`). The client never sends it: it is a
server-to-client message. `Close` (`0x43DB3479`) has both a serializer
(`0x140412572`) and a dispatcher case (`0x14042BABC`), so it travels both ways.

The `Close` body is the sender's own two route words in sender order —
`Connection + 0x28` then `Connection + 0x60` — which is the reverse of the
receive-tree key order. For our observation that is `0x0000` then `0x0001`.

### DISPROVEN — the introduce/registration path does not send Close

Both branches of the client's post-introduce registration call
`0x1404123D0` with `X = 2`:

```text
insert failed  -> 0x140412317  (connection, 2, 1)
insert success -> 0x14043D4E7  (connection, 2, 12)
```

Since `X = 2` never sends, **neither the success nor the failure of the client's
own receive-tree insertion produces the observed `Close`**. The trigger is a
separate lifecycle path that passes `X = 0`. Two concrete call sites do, and both
are teardown shaped:

* `0x1404371E6` walks a list of connections and closes each;
* `0x140468D66` closes the single connection held at `[rdx+8]` of its argument.

Which of the two fired in the retail run is **UNRESOLVED**; localizing it needs
either a breakpoint (not viable in this environment, see the September 7
debugger findings) or a distinguishing runtime observable.

### Post-introduce state and route survival — CONFIRMED structure, UNRESOLVED runtime

`0x1404123D0` ends by calling `0x14043D550` (`0x1404126F2`) on the connection,
which is a receive-tree operation and is the only tree mutation this function
performs. The tree entry inserted by the client at `0x14042C782` is therefore
subject to it. The connection's `+0x28`/`+0x60` and the resolved
`ObjectSurrogate` are released on the same teardown path.

Because the bootstrap socket closes immediately afterwards and the client makes
no further connection, the practical answer is:

```text
route 0001/0000 after Close:  REMOVED with the bootstrap connection (HYPOTHESIS)
```

It is not MIGRATED: no subsequent TCP connection of any kind was observed, and
no code path was found that transfers a receive key between connections.

### Subsequent network activity — CONFIRMED none

From the two selections of the control run:

```text
auth   two connections, one per manual selection, each ending in Close
world  no connection at all (world.log shows only startup)
platform  /gamepad/shardlist requested again after each failure
client  returns to the server list and reports error 1003
```

There is no automatic retry, no second auth connection, no World connection, and
no connection to any other destination.

### Reply strings — CONFIRMED not causal to this boundary

`0x14042D320` receives only `(context, &out, correlation)`; the three strings are
stored in locals, freed, and never passed on. Nothing in the recovered path
copies them elsewhere. They are **not causal to the current Close boundary**.

### Classification of the observed post-introduce Close

```text
Observed post-introduce Close:

classification:
    FAILURE TEARDOWN  (leaning; producer site not definitively resolved)

producer:
    one of 0x1404371E6 / 0x140468D66, both calling
    0x1404123D0(connection, 0, 0); NOT the registration branches, which pass X=2

triggering condition:
    X == 0 AND the connection state query returns 4; the upstream condition that
    chooses the teardown path is unresolved

connection state before:  CS_LOGGING_IN, launch context still outstanding
connection state after:   disconnected; ServerProxy::OnDisconnect reports 1003

route 0001/0000 after Close:
    REMOVED with the bootstrap connection (HYPOTHESIS)

next client network action:
    none; it returns to the server list and re-requests /gamepad/shardlist

evidence:
    0x1404124E1/0x1404124EB gate; X values of every caller; absence of any
    serializer for RequestClose; world.log and platform.log of the control run;
    the 45 ms 1003 while the launch context was still set
```

### D4 RULE — still not satisfiable

D4 must not be sent on the bootstrap socket: the client resolves that socket
through `Close` within tens of milliseconds and makes no further connection, so
there is no proven point at which a routed delivery would be valid. The derived
pair `0x0001`/`0x0000` stands, and the next task is to localize the `X == 0`
trigger — which decides whether the bootstrap connection is meant to end
normally and the login continue elsewhere, or whether the client is aborting
because a required peer message never arrived in the introduce/close window.

## Close producer identified: `omega::TimeRequester` teardown (September 13)

This section supersedes the "producer site not definitively resolved" line of the
previous section. One of the two candidates is eliminated by reachability and the
other is identified by RTTI.

### Candidate A eliminated — the list-teardown is a type-3 transport path

`0x1404371E6` lives in `0x140436C80`, whose **only** caller in the executable is
`0x14043C409`, inside the transport **type-3** receive handler
(`0x14043C321`). That handler's first instruction is:

```text
0x14043C321  cmp DWORD PTR [r12+0x180],0x3
0x14043C32A  jne 0x14043C460              ; not 3 -> not this handler
```

`Connection + 0x180` is the role/state field: the client-role connection sets it
to `1` (`0x14043E7E2`), and the send path requires `1` (`0x14043B638`); the RSA
receive handler requires `2`. Nothing in the observed run sets `3`, and no type-3
frame was ever sent by Holocron. **DISPROVEN as the producer for this run.**

### Candidate B identified — `omega::TimeRequester`

`0x140468D40` has **no direct callers**. It is referenced exactly once in the
image, as a vtable slot at `0x1414B7CC8`. Its RTTI Complete Object Locator
(`0x1417047C8`, `mdisp = 0x18`) resolves to:

```text
.?AVTimeRequester@omega@@          i.e. omega::TimeRequester
vtable 0x1414B7CC8  slot +0x00 -> 0x140468D40
                    slot +0x20 -> 0x140468530
                    slot +0x30 -> 0x1404689A0
                    slot +0x38 -> 0x140468B00
```

The object's identity is corroborated in the string data: the RTTI name is
immediately followed by the literal `"*:timesource"` (file offsets `0x157EDD0`
onward), and the sibling method `0x140468B50` uses the string at `0x1415803D0`.
This is the same `*:timesource` lookup the September 11 audit found behind
`0x140467BD0(App + 0x1A8)`.

The teardown method itself:

```text
0x140468D40  rcx = this, rdx = arg2, r8 = arg3, r9d = arg4
0x140468D55  rcx = [rdx+8]        the connection comes from an ARGUMENT struct,
                                  not from the object
0x140468D5F  je 0x140468D6B        null -> skip
0x140468D61  xor r8d,r8d
0x140468D64  xor edx,edx
0x140468D66  call 0x1404123D0     (connection, 0, 0)  -> X = 0 -> Close is sent
```

**CONFIRMED — the observed `Close` was emitted by a teardown path belonging to
`omega::TimeRequester`, an object whose purpose is to find and use a
`*:timesource` connection.**

### The causal chain, and where it is still open

```text
client completes introduce and self-registers route 0001/0000
  -> an omega::TimeRequester that holds this connection is destroyed
  -> 0x140468D66  0x1404123D0(connection, 0, 0)      [X = 0]
  -> 0x1404124E1 state query == 4 and 0x1404124EB X == 0
  -> 0x140412654 Close 0x43DB3479 sent
  -> socket EOF
  -> ServerProxy::OnDisconnect (0x140427170) sees the launch context at +0x90
     still set and reports 1003
```

**What is still open:** both `omega::TimeRequester` constructor paths
(`0x140467613`, `0x14046780F`, each installing the vtable at `0x14046771B` /
`0x140467830`) also have **no direct callers**, so construction and destruction
happen through virtual dispatch from a manager that has not been localized. The
run has not yet been shown to reach `0x140467BD0`, whose activation the
September 11 audit tied to the `useSyncClock` application flag — and that flag is
set from D4, which in this run never reached its handler.

### Causal ordering: is Close the cause or the cleanup?

**CONFIRMED — Close is cleanup, not the cause.** `Close` is sent by `0x1404123D0`
only after an owner has already decided to tear the connection down; the function
performs state bookkeeping and the graceful frame, and its `X = 2` callers (the
registration success and failure paths, and the reply's `0xFFFF` path) do not
send at all. Error 1003 is produced afterwards by `ServerProxy::OnDisconnect`
because the launch context at `+0x90` is still outstanding, i.e. because the login
had not completed for an independent reason.

### D4 on this connection — UNKNOWN, leaning NO for the current sequence

```text
Does D4 belong on this same connection?

classification: UNKNOWN

If YES (HYPOTHESIS, not proven):
    the same auth socket, in the window between the client's
    IntroduceConnectionSignature and its teardown
    route 0x0001 / 0x0000 (proven key)
    because D4 is what sets useSyncClock, which is what reaches
    0x140467BD0 and the omega::TimeRequester activation path

If NO:
    the outstanding requirement is a *:timesource peer object; the
    omega::TimeRequester teardown shows the client looking for one and
    tearing the connection down when it is not there

evidence: the RTTI identification, the adjacent "*:timesource" literal, the
          X == 0 gate, and the absence of direct callers for construction
```

Sending D4 now would still be a guess: the previous task proved only that D4 sent
after the teardown is committed is uninformative, and this task has not yet shown
that any server message cancels the teardown. **No server behaviour was changed.**

### NEW FAILURE BOUNDARY

*The client's bootstrap connection is torn down by an `omega::TimeRequester`
teardown, and that object exists to acquire a `*:timesource` connection.* The next
task is to localize which manager constructs and destroys the `TimeRequester` on
this connection, and what peer-visible condition makes its `*:timesource` lookup
fail — that is the decision point in front of the teardown. Only then is a server
action justified.

## `omega::TimeRequester` owner, teardown dispatch and the `*:timesource` question (September 13)

This section continues "Close producer identified: `omega::TimeRequester`
teardown". It **resolves the owning manager** and the virtual dispatch that
reaches `0x140468D40`, **corrects** two claims of the previous section, and
**answers** the `*:timesource` causality question in the negative.

Binary identity: `.text`, `.rdata`, `.data`, `.pdata`, `.reloc` and `.rsrc` of
the prepared private client are **bit-identical** to the retail copy whose
SHA-256 is recorded at the top of this document; the only difference in the whole
file is 256 bytes at file offset `0x1AB50D1`–`0x1AB51D0`, which is the installed
RSA test key. Every address below is consequently valid for the retail
executable.

### CORRECTION 1 — `0x1414B7CC8` is the `omega::TimeRequester` vtable at mdisp 0x18

The class hierarchy was re-derived with a validated RTTI reader. The x64 layout
this image uses is:

```text
vtable[-1]    : 8-byte VA of the Complete Object Locator (COL)
COL : +00 signature = 1   +04 moffset   +08 cd_offset
      +0C pTD (rva)       +10 pCD (rva) +14 pSelf (rva)
TD  : inline decorated name at TD + 0x10
CHD : +00 sig = 0  +04 attributes  +08 numBaseClasses  +0C pBaseClassArray (rva)
BCD (0x1C bytes): +00 pTD +04 numContainedBases +08 mdisp +0C pdisp
                  +10 vdisp +14 attributes +18 pCD
```

Note the two traps: the COL **signature is 1**, not 0 (requiring 0 finds no COL
in this image at all), and a `BaseClassDescriptor` is **0x1C** bytes, not 0x18.

```text
COL 0x1417047C8  signature=1  moffset=0x18  pTD=0x141B67700  pCD=0x141704A00
TD  0x141B67700  name at +0x10 = ".?AVTimeRequester@omega@@"
CHD 0x141704A00  attributes=1  numBaseClasses=7  pBaseClassArray=0x141704878
```

The seven base-class descriptors, in `pBaseClassArray` order:

```text
mdisp 0x00  omega::TimeRequester            vtable 0x1414B7C28  (moffset 0x00)
mdisp 0x00  omega::TimeRequesterBase
mdisp 0x00  omega::Object
mdisp 0x08  omega::ComponentConsumer
mdisp 0x18  TimeSourceReplyIFace            vtable 0x1414B7CC8  (moffset 0x18)
mdisp 0x20  omega::SocketObserver           vtable 0x1414B7CD8  (moffset 0x20)
mdisp 0x20  omega::Interface
```

`omega::TimeRequesterBase` is a separate four-entry hierarchy by the same
readers. So `0x1414B7CC8` is one of `omega::TimeRequester`'s own vtables — the
one its `TimeSourceReplyIFace` base subobject occupies at object offset `0x18`.

This **supersedes** the previous section's reading that the object was
`omega::TimeRequesterBase`. The class name was right; the *subobject* was wrong.

### CORRECTION 2 — object layout; the teardown's `this` is not the object base

The constructor `0x140467600` installs **exactly three** vtable pointers
(`0x1404676fc`–`0x14046772d`):

```text
1404676fc  lea rax,[rip+0x1050795]  ; 0x1414B7E98  TimeRequesterBase vtable
140467703  mov [rsi],rax
140467706  lea rax,[rip+0x105077b]  ; 0x1414B7E88
14046770d  mov [rsi+0x18],rax
140467711  lea rax,[rip+0x1050510]  ; 0x1414B7C28  TimeRequester PRIMARY
140467718  mov [rsi],rax
14046771b  lea rax,[rip+0x10505a6]  ; 0x1414B7CC8  TimeSourceReplyIFace @0x18
140467722  mov [rsi+0x18],rax
140467726  lea rax,[rip+0x10505ab]  ; 0x1414B7CD8  SocketObserver @0x20
14046772d  mov [rsi+0x20],rax
```

```text
omega::TimeRequester, size 0x158 (the deleting destructor frees 0x158 at
0x1404677d9), constructor 0x140467600

  +0x000  vptr  omega::TimeRequester primary   0x1414B7C28
  +0x008  ptr   context/session object         (base ctor 0x14040a9a0)
  +0x010  ptr   this object's ObjectSurrogate  (0x14040aae5)
  +0x018  vptr  TimeSourceReplyIFace           0x1414B7CC8  <-- teardown slot +0x00
  +0x020  vptr  SocketObserver / Interface     0x1414B7CD8
  +0x028  0        +0x030 dword 0   +0x038 0   +0x040 byte 0   (active flag)
  +0x048  {ptr,len}  "Client" identity string
  +0x058  {ptr,len}  stream buffer (cleared by teardown)
  +0x068  0
  +0x070  subobject built by 0x140469670
  +0x098  qword last synced timestamp     (callback 0x140467DD0)
  +0x0A0  qword clock correction, atomic  (callback 0x140467DD0)
  +0x0A8  dword 0
  +0x140 / +0x148 / +0x150  cleared by the 0x140467BD0 activation path
```

Because `vtable 0x1414B7CC8` belongs at object offset `0x18`, `0x140468D40` is
entered with `this = TimeRequester + 0x18`. That is why it reads `[rbx-0x10]` and
`[rbx-0x18]` (real TimeRequester fields `+0x08` and `+0x00`) and why its
`lea rcx,[rbx-0x18]` calls `0x140468B50` on the object base.

### The owning manager — `omega::ApplicationImpl`, not a TimeRequester-internal manager

The creators are found by relative-call scanning (an earlier helper omitted the
section `VirtualAddress` and therefore reported no callers for anything; that bug
is fixed):

```text
0x140467600  omega::TimeRequester::TimeRequester(size 0x158)
             sole caller 0x14044672c, inside 0x140446490
0x140446490  sole caller 0x140405a4c, inside 0x1404058f0
0x1404058f0  sole caller 0x140120e4b, inside 0x140120df0
0x140120df0  sole caller 0x14010c0ab, inside 0x14010c070
0x14010c070  sole caller 0x1400bc065, inside 0x1400bbe40  ("Client startup detected existing instance")
```

`0x1400bbe40` is the client-startup singleton initializer. Its
`0x140120df0` step allocates a `0x178` object, assigns it to a global at
`0x141bab520`, and calls it. Walking into `0x140446490`, `rdi+8`/`rdi+0x10` are
the freshly built `App`:

```text
1404464e4  mov rax,[rbx+0x1d8]        ; App -> ServerProxy
140446520  lea rdi,[rbx+0x18]         ; rdi = the TimeSourceReplyIFace slot
14044658b  mov [rax+0xe0],rdi         ; register the interface with ServerProxy
14044659  mov rax,[App+0x1D8]         ; App -> ServerProxy
            mov rcx,[rax+0xd8]        ;   -> connection slot
1404465a7  call 0x14042f960           ; bind the requester to that slot
1404466f9  mov rax,[0x141369df8]      ; operator new
140446700  mov ecx,0x158
140446708  call [0x14136acc0]         ; allocate 0x158
14044672c  call 0x140467600           ; construct the TimeRequester
140446745  call 0x14044c220           ; build refcount control block
1404467b5  mov rax,[rbx+0x1a8]        ; old App+0x1A8
1404467c1  mov [rbx+0x1a8],rcx        ; install the new one
1404467e5  call 0x1400b79f0           ; release the old one
```

`0x140446490` is a method of `omega::ApplicationImpl` (its vtable is
`0x1414B7170`), and it also stores the result at `App+0x1A8`. **So the object
that constructs, activates and destroys the `TimeRequester` is
`omega::ApplicationImpl`**, and `App+0x1A8`/`App+0x1B0` is a refcounted pair
holding the **TimeSourceReplyIFace subobject** (`TimeRequester + 0x18`) and its
control block.

### The virtual destruction dispatch — proven end to end

`0x140468D40` has no direct caller and exactly one materialization in the image:
slot `+0x00` of `0x1414B7CC8`. The control block created for it at `0x14044c220`
installs `0x1414b7040` (whose first entry is `0x14011d7c0`):

```text
14044c25  lea rcx,[rip+0xf5a280]   ; 0x1413a64e0  base control-block vtable
14044c260 mov [rax],rcx
14044c263 mov dword [rax+8],1      ; strong count
14044c26a mov dword [rax+0xc],1    ; weak count
14044c271 lea rcx,[rip+0x106adc8]  ; 0x1414b7040  specialised control-block vtable
14044c278 mov [rax],rcx
14044c27b mov [rax+0x10],rdi       ; the TimeSourceReplyIFace pointer
```

The shared-pointer release primitive `0x1400b79f0` drops the strong count and,
at zero, dispatches virtually:

```text
1400b79f0  mov rbx,[rcx]
1400b7a13  lock xadd [rbx+8],eax        ; strong count - 1
1400b7a18  cmp eax,1 / jne 0x1400b7a49
1400b7a1d  mov rax,[rbx]
1400b7a23  mov rax,[rax+8]              ; >> specialised control-block slot +0x08
1400b7a27  call qword [0x14136acc0]     ; == 0x14011d7c0
```

and `0x14011d7c0` is the control block's `Destroy`, which immediately invokes the
**object's own** vtable slot `+0x00`:

```text
14011d7c0  mov [rsp+8],rcx
14011d7d3  mov rbx,rcx
14011d7d6  lea rax,[rip+0x1288d03]      ; 0x1413a64e0  reset to the BASE vtable
14011d7dd  mov [rcx],rax
14011d7e0  test dl,1 / je 0x14011d7f0
14011d7e5  mov edx,0x18
14011d7ea  call 0x140fd7090             ; operator delete(block, 0x18)
```

so the object's vtable slot `+0x00` is `0x140468D40` — the deleting destructor of
the `TimeSourceReplyIFace` subobject. **The dispatch site is `0x14011d7c0`'s
`mov rax,[rbx]; mov rax,[rax]` sequence, reached from `0x1400b79f0`, reached from
whichever owner dropped the last reference.**

### The argument structure passed to the teardown

`0x140468D40(this /*TimeSourceReplyIFace*/, arg2, arg3, arg4)`:

```text
140468d40  mov [rsp+8],rbx / mov [rsp+0x10],rsi / push rdi / sub rsp,0x20
140468d4f  mov rbx,rcx                  ; this = TR+0x18
140468d52  mov esi,r9d                  ; arg4
140468d55  mov rcx,[rdx+8]              ; >>> the connection comes from arg2+8
140468d59  mov rdi,r8                   ; arg3 = pointer to the timesource name
140468d5c  test rcx,rcx / je 0x140468d6b
140468d61  xor r8d,r8d
140468d64  xor edx,edx
140468d66  call 0x1404123d0             ; (connection, 0, 0)  -> Close 0x43DB3479
```

`arg2` is therefore a struct whose `+0x08` is the connection; `arg3` points at the
name used for the unbind comparison. Both are supplied by the caller of the
virtual slot, not stored on the object.

### The `*:timesource` lookup — and the answer to the causal question

`0x140468B50` is the only code in the image that references the literal
`"*:timesource"` (`0x1415803D0`; exactly one RIP-relative reference, at
`0x140468b99`). It resolves through `0x14040ac70`, whose effective scope object is
`owner->[0x10]` — for the TimeRequester, its own `omega::ObjectSurrogate`, and
thence the omega **object directory** (intrusive list at `directory+0x130`,
critical section at `+0x28`, entries matched by type at `+0x10` and name at
`+0x30`). Full CFG in `scratch/tr/TIMESOURCE_CFG.md`.

```text
success: *out = the AddRef'd directory entry; 0x140468B50 then Releases it
         (slot +0x30) and returns true.  No TimeRequester field is written.
failure: 0x140435b59  mov qword [rbx],r15   (r15 = 0)  ->  *out = 0
         the guarded release at 0x140468c1a is SKIPPED; return false.
```

**Does a failed `*:timesource` lookup cause `0x140468D40` to be invoked? NO.**
The causal direction in the previous section was inverted:

```text
0x140468D40 is the handler that CALLS the lookup, at 0x140468de6, LAST.
It emits the Close FIRST, at 0x140468d66, before any lookup happens.
It can also return without any lookup: empty name (0x140468d8b / 0x140468d71),
name already equal to the current source (0x140468dc8), or 0x140467ec0
succeeded (0x140468de0).
And within 0x140468B50 the only indirect call is guarded by `handle != 0`,
i.e. success only (0x140468c0b / 0x140468c1a).
```

The lookup is part of the teardown's *unbind* work, not its cause.

### The `D4` / `useSyncClock` contradiction — resolved

There is **one** creator and **one** owner, so there is no second instance and no
provisional bootstrap object. The resolution is:

```text
0x140446490 (omega::ApplicationImpl method) creates the TimeRequester during
client startup, at the 0x140120df0 step, and installs it at App+0x1A8.
0x140467BD0(App+0x1A8) does NOT create it -- it ACTIVATES the already-existing
object: it calls 0x140468B50, and only on success sets [TR+0x40] = 1 and clears
TR+0x98 / TR+0xA0 / TR+0x140 / TR+0x148 / TR+0x150.
```

`App+0x1A8` is written at exactly two places — `0x1404467c1` (owner installation)
and `0x140446860` (explicit clear) — and read by `0x140405b0d`, `0x140406cf1`,
`0x140427b74` (`0x140427b7b` calls `0x140467BD0`), `0x14043a591`, `0x14044a1f4`
(the clock read guarded by the `useSyncClock` byte at `App+0x1A0`) and
`0x140446852` (the clear). It is **non-null before D4**: the object exists, is
owned, and merely awaits activation. Option A of the open question holds
("created before D4, activated/configured by `useSyncClock`"); the previous
section's implication that the object is created by that path is **DISPROVEN**.

### Three proven ways `App+0x1A8` is released

```text
1. 0x1404467c1 (owner, replacement)      releases the OLD value at 0x1404467e5
2. 0x140446830 (explicit clear)          zeroes App+0x1A8 / App+0x1B0, then
                                         calls 0x1400b79f0
3. 0x140445b2e (ApplicationImpl dtor)    releases App+0xF0, App+0x100, App+0x1A8
```

Entry point 2 is reached by a tail `jmp` from `0x140406f54` inside the
application-level shutdown `0x140406c90`, which first observes and then sets the
`App+0x2A` shutdown byte (`0x140406ccf` / `0x140406cd9`), walks the connection map,
and performs the remaining game-level teardown before clearing the requester.

### NEW FAILURE BOUNDARY

The `Close` this run observes is emitted by the **`omega::ApplicationImpl`-owned
`omega::TimeRequester`'s `TimeSourceReplyIFace` deleting destructor
(`0x140468D40`)** when the last reference on `App+0x1A8` is dropped. That happens
by construction in exactly three places: replacement by the owner, the explicit
application-level clear at `0x140446830`, or `~ApplicationImpl`. The
`*:timesource` lookup is **not** an input to that decision — it runs after the
Close, inside the same teardown.

What remains **UNRESOLVED** is which of the three release sites fires in the
retail run, because that depends on runtime state (whether the application enters
its shutdown path) rather than on any single static branch. Discriminating them
needs a runtime observable; a witness was attempted but the isolated runtime used
by previous sessions (`/opt/holocron-test`, a `bwrap` namespace built by
`tools/launch-isolated-client.sh`) requires the private Proton tree to start a
WineDbg proxy, and it did not come up in this environment, so no witness value
was obtained. **No server behaviour was changed.**

## Which ApplicationImpl release site drops the TimeRequester (September 13)

This section answers the question left open by the previous one: which of the
three `App+0x1A8` release sites drops the final `omega::TimeRequester`
reference, and what decides it. The result is that the teardown is cleanup
driven by the application object's **one-shot teardown latch `App+0x2A`**
(`0x140406C90` → `0x140446830`), and that the real failure boundary is *above*
it, in the client's own login-transport initialisation `0x140427F10`. The three
release sites are classified below against a real captured run.

### Phase 1 — the three release sites

```text
A  0x1404467C1  inside 0x140446490..0x14044682D  (the ApplicationImpl owner method)
B  0x140446830  inside 0x140446830..0x14044689F  (dedicated clear, 0x6F bytes)
C  0x140445B2E  inside 0x140445A60..0x1404463AA  (~ApplicationImpl)
```

All three zero the `{ptr, control block}` pair at `App+0x1A8`/`App+0x1B0` and
then call the shared-pointer release primitive `0x1400B79F0`:

```text
A  1404467b5  mov rax,[rbx+0x1a8]     ; old value
   1404467c1  mov [rbx+0x1a8],rcx     ; install the new TimeRequester
   1404467e5  call 0x1400b79f0        ; release the old pair
B  140446852  mov rax,[rcx+0x1a8]
   140446860  mov qword ptr [rbx+0x1a8],0
   14044686e  mov qword ptr [rbx+0x1b0],0
   14044687f  call 0x1400b79f0
C  140445b14  mov rax,[r15]           ; r15 = &App+0x1A8
   140445b1b  mov qword ptr [r15],0
   140445b22  mov qword ptr [r15+8],0
   140445b2e  call 0x1400b79f0
```

**Site B is the only one reachable while the application stays alive.** Its
containing function is reachable by exactly one edge in the whole image — a tail
`jmp` from `0x140406F54` inside `0x140406C90` — and `0x140406C90` stores the
one-shot shutdown byte `App+0x2A`:

```text
140406ccf  cmp byte ptr [rax+0x2a],0     ; App = [this+8]
140406cd3  jne 0x140406ef5               ; already shut down -> skip everything
140406cd9  mov byte ptr [rax+0x2a],1     ; latch
140406ce7  call qword ptr [rax+0x20]     ; one virtual "stop" step
140406cf1  mov rcx,[r14+0x1a8]           ; the TimeRequester
140406cfd  call 0x140467a40              ; deactivate it (clears TR+0x40)
...
140406f54  jmp 0x140446830               ; -> the clear (site B)
```

`App+0x2A` is read or written in only three places, all inside the
`0x140406B20..0x140406F49` vtable cluster, so it is a private one-shot latch for
this teardown pair and nothing else consumes it.

### Runtime witness — CONFIRMED, read-only, no client bytes patched

The isolated private client was run under the existing WineDbg GDB proxy with
hardware breakpoints only. The client executable was never modified:

```text
before 47d8c8f03242606819fe7afe711bfd8186e83811a178613a89f944ccb1ac4f14
after  47d8c8f03242606819fe7afe711bfd8186e83811a178613a89f944ccb1ac4f14
```

Captured at the owner's constructor call:

```text
### REPLACE-CREATE 0x14044672c  App=0x14b3e00  old App+1A8=(nil)
```

**Site A fired exactly once and with `App+0x1A8 == NULL`.** The replacement path
is a *first-time creation*, not a replacement: there was no previous
`TimeRequester` reference to drop, so site A cannot be the release that produced
the observed teardown.

Captured on a later, independent login attempt in the same instrumented run:

```text
[A] launch name=local-test
    sp+0x38=(nil) +0x48=(nil) +0x78=0x14afd80 +0x80=(nil) +0x88=(nil) +0x90=(nil)
[B] after first check al=1
[C] after get-or-create rax=0x69cb9f8  +0x80=(nil)
[D] check +0x80 rcx=(nil)  +0x80=(nil) +0x90=(nil)
[H] *** 1003 REPORT SITE REACHED ***
```

`ServerProxy+0x80` — the auth transport — is **null**, so the report came from
the `0x1404280E0` arm of `0x140427F10`, not from `OnDisconnect`. The teardown
breakpoint at `0x140468D40` never fired in that run, i.e. `TimeRequester`
remained owned.

### Phase 2 — replacement is startup-only, formally

Site A is reached only from `0x1404058F0`, which is reached only from
`0x140120DF0`, which is the client-startup singleton step reached only from
`0x14010C070` ← `0x1400BBE40`, gated at `0x1400BBE75` by an already-initialized
test. It installs a *new* `TimeRequester` and **requires `App+0x1A8` to be
NULL**: the witness shows exactly that, and the containing call cannot succeed a
second time because nothing between the two states clears `App+0x1A8`. It is
**IMPOSSIBLE FOR OBSERVED RUN** as the release.

### Phase 3/4 — the explicit clear and its upstream event

Site B is **POSSIBLE FOR OBSERVED RUN** and is the only candidate that survives.
Its upstream is the one-shot application-level teardown `0x140406C90`, which
latches `App+0x2A`, deactivates the `TimeRequester` (`0x140467A40`), performs the
remaining game-level teardown (`0x140408190`, `0x1404084A0`, `0x14042B1F0`,
`0x140424550`), and then tail-calls the clear. The clear additionally hands the
`ServerProxy` to the bounded spin/settle helper `0x1404411F0`:

```text
140446889  mov rcx,[rbx+0x1d8]    ; ServerProxy
14044689a  jmp 0x1404411f0        ; (ServerProxy, edx = arg2, r8b = 1)
```

`0x1404411F0` is called from exactly two places in the whole image: inside
`~ApplicationImpl` at `0x140445D8E`, and from this clear at `0x14044689A`. That
shared tail is the decisive discriminator — **the clear is a bounded
deactivation of the running application, not a destruction of it.**

### Phase 5/6 — causal order, and the 45 ms

```text
TimeRequester teardown is NOT the root failure.  It is cleanup.

root decision  : the application object enters its one-shot teardown
                 (App+0x2A 0 -> 1) during the login attempt
                 -> 0x140406C90 deactivates the TimeRequester (0x140467A40)
                 -> clears App+0x1A8/App+0x1B0 (0x140446830)
                 -> 0x1400B79F0 drops the last reference
                 -> 0x14011D7C0 control-block Destroy
                 -> 0x140468D40 TimeRequester vtable slot +0x00
                 -> 0x1404123D0(connection, 0, 0)  ->  Close 0x43DB3479
                 -> ServerProxy::OnDisconnect (0x14042718E) still sees the
                    launch context at +0x90 and reports 1003
```

The 45 ms is **not a network timeout**. There is no timer, queued task or
failed future in this chain: `0x140406C90` is a straight-line synchronous
teardown and every step is an ordinary call. The latency is simply the cost of
the steps above, which is exactly the order of magnitude observed. The chain is
entered from an immediate application-level decision, so it is a correct
inference that a local condition present at the start of the attempt caused it.
`Close` and `1003` are both *after* that decision.

### Phase 7 — what the runtime witness resolved, and what it could not

Resolved: site A is a first-time creation with a null old value; site D
(there is no site D) — the teardown is a released reference and not a direct
call; the `TimeRequester` is still owned in a modern failing attempt.

Not resolved: the exact dispatch of `0x140406C90`. Its vtable cluster
(`0x1414B5A00`, `0x1414B5B50`, `0x141483378`) is referenced by **zero**
rip-relative loads in `.text` and by zero 8-byte data pointers, so the
`this` object is not built by a direct vtable store anywhere in the image; it is
installed through the interface machinery. The upstream event is therefore
**documented as a remaining ambiguity** rather than guessed.

### Phase 8/9 — the true root condition, and D4

The earliest non-cleanup failing condition found in this pass is in the client's
own login-transport initialisation, `0x140427F10` (reached from
`ConnectionObject::beginConnection` at `0x140135AE2`, immediately after
`setState CS_LOGGING_IN`). It hard-gates the attempt on prerequisites that are
all **local**, before any socket exists:

```text
0x14042803A  call 0x140407000   ; name/pattern pre-check
0x140428041  jne  ok
0x140428043  ... mov dword [..],0x3EB ; jmp 0x140428327   -> 1003
0x140428077  call 0x1404061E0   ; build/find the auth transport
0x1404280C2  test rcx,rcx
0x1404280CC  jne  ok
0x1404280CE  ... mov dword [..],0x3EB ; jmp 0x140428327   -> 1003
0x1404280E8  call 0x14043E2D0   ; transport handshake setup + open
0x1404280ED  test al,al
0x1404280EF  jne  ok
0x1404280F1  ... mov dword [..],0x3EB ; jmp 0x140428327   -> 1003
```

All three report through `[App_vtable+0x98]` = `HandleLaunchFailure`
(`0x140122480`, reached in the trace from `0x140428334`). The capture shows the
`+0x80` precondition absent, so the client reports 1003 to itself without ever
opening a socket.

**Would receiving D4 before this condition fires prevent the clear?
UNKNOWN, leaning NO.** D4 (`LoginRequestIFace::slot0`) can only be delivered
over an already-established routed connection; all three gates above run before
the transport exists, and the capture shows them failing with
`ServerProxy+0x80 == NULL`. D4 does *replace* the launch context at
`ServerProxy+0x90` (`0x14042827C`), which is why a pending D4 exchange is
plausibly what the *historical* run was waiting for — but nothing in this pass
proves that a peer message is what was missing in the observed historical run,
and the historical run's exact failing arm could not be reproduced because it
depended on an auth exchange that this environment no longer completes.

### NEW FAILURE BOUNDARY

The `Close` this run observes is emitted by the `TimeRequester` teardown, which
is cleanup triggered by the application object's one-shot teardown
(`App+0x2A 0 -> 1`, `0x140406C90` → `0x140446830`). The real boundary is *above*
that: the client's login-transport initialisation `0x140427F10` refunds the
attempt with a locally synthesised 1003 when one of its prerequisites is absent,
and it does so before any network I/O.

**No server behaviour was changed.** No peer-visible missing action was proven,
so no falsifiable experiment was justified: the three gates are local
prerequisites, and their inputs are not something Holocron currently sends.

## Historical bootstrap reproduced, and the Close producer corrected (September 13)

This section **restores the known-good runtime**, reproduces the historical
bootstrap exactly, and **retracts** the interim conclusion that the observed
`Close` came from the `omega::TimeRequester` teardown. The witness below was
taken on a run that reaches `IntroduceConnectionSignature`, and on that run the
`TimeRequester` teardown **never executed**.

### Root cause of the recent non-reproduction — a resolver hint, not a client change

The known-good runs cleared the Winsock `AI_ADDRCONFIG` bit; the newer witness
launcher did not, so the client never opened an Auth socket.

```text
0x140450770   hint builder
0x1404507C9   mov dword ptr [rsi], 0x400    ; AI_ADDRCONFIG
0x1404507CF   mov eax,[rdi]                 ; verify() -> exit if hints != 0
```

In a namespace containing only `lo`, `AI_ADDRCONFIG` rejects every IPv4 result,
so `getaddrinfo("127.0.0.1")` yields no address and the client stops before the
socket exists. The next pre-socket gate is then tripped:

```text
0x140427F10  login-transport initialisation (from beginConnection, 0x140135AE2)
0x1404280C2  test rcx,rcx                 ; ServerProxy+0x80 (the auth socket)
0x1404280CC  jne  ok
0x1404280CE  ... mov dword [..],0x3EB     ; locally synthesised 1003
```

`0x140427F10` writes `ServerProxy+0x80` itself at `0x140428092`, so the field is
created by this very call and is legitimately null on entry (the `ServerProxy`
constructor zeroes it at `0x140426E30`). The gate is not a missing server
action; it is proof that the local transport was never built.

Bounded, restored run condition — the project's documented loopback-resolver
step (`tools/probe-loopback-resolver.py`), applied to the copied private client
only, byte-exact and restored in a `finally` block:

```text
before sha256 47d8c8f03242606819fe7afe711bfd8186e83811a178613a89f944ccb1ac4f14
resolver immediate 0x400 -> 0
after  sha256 47d8c8f03242606819fe7afe711bfd8186e83811a178613a89f944ccb1ac4f14
restored exactly: True
```

No client logic was patched, no check bypassed, no field forced non-null.

### Reproduction — CONFIRMED, same sequence as the historical runs

```text
[AUTH] Client connected from 127.0.0.1:47536
[AUTH] Sent login transport greeting (22 bytes)
[AUTH] Received CMSG_HANDSHAKE (522 bytes)
[AUTH] RSA envelope and historical key-field layout validated
[AUTH] Bootstrap request: transport-type=0x00, logical=39 bytes, message=0xA609E6A7
[AUTH] RequestIDSignature: name="castlehilltest", correlation=0x0000000000000006
[AUTH] Sent ReplyIDSignature: message=0x6731C5AF, route=0xFFFF/0xFFFF,
       assigned-object-id=0x0001, logical=33 bytes
[AUTH] IntroduceConnectionSignature received: client-object-id=0x0000,
       reply-word=0x0001, name="OmegaServerProxyObjectName", class="Client",
       interfaces="b7a6bba3:8ab55405:5bc541f9", logical=111 bytes
[AUTH] Control mode: no mirror and no D4 sent; observing only
[AUTH] Control-window frame: transport-type=0x00, logical=8 bytes,
       message=0x43DB3479
[AUTH] Client closed the connection during the control window
```

Client-side timing from the same run:

```text
17:31:26.736341  Constructed with desired state [CS_SHARD_CONNECTED]
17:31:26.736341  Starting login: local-test : @localhost:7979:castlehilltest
17:31:26.747340  setState changing state to [CS_LOGGING_IN]
17:31:26.830338  HandleLaunchFailure with error type 1003   (+83 ms)
```

`Close` reproduced as `0x43DB3479`, exactly as historically observed.

### RETRACTION — `0x140468D40` is not the producer of this `Close`

The same-run witness proves the `TimeRequester` teardown did **not** run:

```text
[OK] login-init succeeded +0x80=0x4ff70a00     ; the +0x80 gate passed
    ; NO [Z] at 0x140468D40      -- TimeRequester teardown never executed
    ; NO [R0] at 0x140406cd9     -- App+0x2A never latched 0 -> 1
    ; NO [R1] at 0x140406c90     -- reset routine never entered
    ; NO [R2] at 0x140446830     -- App clear never executed
    ; NO [R3] at 0x140445a60     -- ~ApplicationImpl never entered
```

Therefore the earlier statement that the observed `Close` was emitted by the
`omega::TimeRequester` teardown is **DISPROVEN for this execution path**. That
static chain is real but is not what fired here.

### The actual producer — CONFIRMED

Breakpoint on the single Close sender `0x1404123D0` (**not** on a caller)
captured both call sites on the same run:

```text
[CALL 0x1404123d0] conn=0x41675860 x=0/0  ret=0x14040af2c
[CALL 0x1404123d0] conn=0x41675860 x=0/0  ret=0x140444ab7
```

The first is the producer; the second is the reference-counted release that
follows. `OnDisconnect` fired **between** them, i.e. downstack of the producer:

```text
[O] OnDisconnect launchctx+90=0x41675860
    #7  0x14dfd30   <- the ServerProxy
    #8  0x14040af69 <- inside the producer, past its Close call
```

Producer: `0x14040AEC0..0x14040AF87`.

```text
14040aedb  mov rdx,[rdx]                  ; rdx = arg2, rdx[0] = the connection
14040aeeb  lock cmpxchg qword ptr [rdx+0x88], rcx(0)   ; latch: Close only once
14040aef4  lea rcx,[rip+0x1160e65]        ; "" empty route name
14040aefd  mov rax,[rax+0x40]             ; else the object's route/name string
14040af08  movzx eax,byte ptr [rcx]
14040af0b  cmp al, byte ptr [0x14156e2d0] ; "*"
14040af11  jne 0x14040af1f
14040af13  movzx eax,byte ptr [rcx+1]
14040af17  cmp al, byte ptr [0x14156e2d1] ; NUL  -> name is exactly "*"
14040af1d  je  0x14040af6a               ; wildcard route: SKIP the Close
14040af1f  xor r8d,r8d
14040af22  xor edx,edx
14040af24  mov rcx,[rbx]
14040af27  call 0x1404123d0              ; (connection, 0, 0)  -> Close 0x43DB3479
...
14040af6a  ... release the argument's reference (vtable +0x30)
```

Semantics: **turning off the routed peer on this connection**. If the retained
route name is the wildcard `"*"` the Close is skipped; otherwise a Close is sent
once (guarded by the `+0x88` latch) and the reference released. This is
route/peer teardown, not clock or application teardown.

`0x140444A80` is a reference-counted release: it drops `[+0xE0]`, and only when
that reaches zero and `[+0xE4]` is clear does it mark `[+0xE4] = 1`, call
`vtable+0x48`, call `0x140441D10`, and latch `[+0x1C] = 1`.

### NEW FAILURE BOUNDARY

The historical failing login is reproducible, and on that run:

* the Auth socket, RSA, Salsa20, `RequestIDSignature`, `ReplyIDSignature`,
  `IntroduceConnectionSignature` and route `0x0001/0x0000` registration all
  complete;
* `ServerProxy+0x80` is populated (`0x4ff70a00`), so `0x140427F10` succeeds;
* **no** application reset occurs (`App+0x2A` untouched, `0x140406C90`,
  `0x140446830` and `~ApplicationImpl` all unentered);
* **no** `TimeRequester` teardown occurs;
* the `Close` is produced by `0x14040AEC0`, a routed-object/peer teardown that
  fires 83 ms after `CS_LOGGING_IN`, and `OnDisconnect` is its consequence.

So the protocol boundary to pursue is whatever drops the reference that leads to
`0x14040AEC0` — *not* the `TimeRequester`/`App` cleanup chain, which is a
different (and here unexercised) path.

**No server behaviour was changed and D4 was not sent.** The resolver step is
the project's pre-existing documented loopback aid, applied only to the copied
private client and restored byte-exactly; the Steam installation was never
touched.

## The duplicate routed-peer attach that produces the historical Close (September 13)

The historical bootstrap is reproducible, and a same-run read-only witness now
identifies the exact ownership event behind the `Close`. The client attaches the
same routed peer **twice**; the second attach replaces the first, and releasing
the replaced peer is what runs `0x14040AEC0` → `0x1404123D0` → `Close`.

### Phase 1 — identity of `0x14040AEC0`

`0x14040AEC0..0x14040AF87` receives `rdx` = a stack smart-pointer whose first
field is the connection, and `rcx` = the `omega::ServerProxy`. It is reached
through the `omega::ServerProxy` route dispatcher vtable slot `+0x38`
(`0x140459BB0`, RTTI `.?AVServerProxy@omega@@`, moffset `0x18`).

```text
0x14040AEDB  rdx = [arg2]                  ; the connection
0x14040AEEB  lock cmpxchg [conn+0x88], 0   ; one-shot TAKE of the routed peer
0x14040AEF4  rcx = "" (empty)              ; old value was 0 -> no name
0x14040AEFD  rax = [old_peer+0x40]         ; else the peer's route name
0x14040AEFD  cmovne rcx, rax
0x14040AF08  compare name[0] with '*' and name[1] with NUL
0x14040AF1D  je 0x14040AF6A                 ; name == "*"  -> SKIP the Close
0x14040AF1F  r8d = 0 ; edx = 0
0x14040AF27  call 0x1404123D0              ; (connection, 0, 0) -> Close 0x43DB3479
0x14040AF2C  rsi = [ [rdi]+0x40 ]          ; ServerProxy+0x40 = this proxy's ObjectSurrogate
0x14040AF63  call [rsi_vtable]             ; detach notification on the surrogate
0x14040AF6A  release [arg2]                ; the argument's reference
```

Method role: **detach/teardown of the routed peer retained on a connection.**
The `+0x88` slot is *taken* (atomically zeroed) rather than merely read, so the
function is idempotent and owns the peer reference it consumes.

### Phase 4 — the retained name is a shard-address triple, never `"*"`

The peer object is 0x88 bytes, allocated and initialised by `0x140412820`
(`mov ecx,0x88`), which stores it into `[connection+0x88]` at `0x140412A4F`
behind a lock-free exchange loop (`0x140412A45`/`0x140412A4F`/`0x140412A58`).
Its constructor writes five `{ptr,len}` string pairs at `+0x00`, `+0x10`,
`+0x20`, `+0x30`, `+0x40` (each with `0x14156BD60` = the empty-string singleton)
plus a larger record at `+0x50`.

The same-run witness captured the two peers' names verbatim:

```text
first  peer 0x40BC3570   +0x20 = "localhost:7979:castlehilltest"
                         +0x30 = "localhost:7979"
                         +0x40 = ""
second peer 0x13E25B0    +0x20 = ":castlehilltest"
                         +0x30 = "localhost:7979"
                         +0x40 = ""
```

So the `"*"` test is a **wildcard-route** test: a peer registered on the
catch-all route is not connection-owned and must not close the connection when
it goes away, whereas a peer bound to a concrete `host:port` route is, and its
removal must tear the connection down. Both peers here are concrete, so neither
can take the skip path — the `Close` is the designed consequence of removing a
concrete routed peer, not an error branch.

`0x14040B170` is the read-only twin of `0x14040AEC0` (same `cmpxchg [conn+0x88]`
take at `0x14040B190`, then returns the name instead of sending a Close), and
`0x14040B010` is the retain/attach arm.

### Phase 6 — `0x140444A80` is downstream cleanup, not the trigger

`0x140444A80` drops `[this+0xE0]`; only when that reaches zero **and**
`[this+0xE4] == 0` does it set `[+0xE4] = 1`, call `vtable+0x48`, call
`0x140441D10` and latch `[+0x1C] = 1`. In the captured run `this = 0x3F501950`
(the `ServerProxy`) and `[+0xE0]` was 5–8, so this is a reference-counted owner
release that runs **after** the peer teardown and sends the second (already
peer-less) `Close`. It is cleanup, not the cause.

### Phase 7 — the runtime chain, CONFIRMED on the historical run

Read-only hardware breakpoints, one bounded run with the documented loopback
resolver step (restored byte-exactly; the client executable hash was identical
before and after).

```text
[OK] login-init succeeded                     ; 0x14042810e, +0x80 populated

[STORE] conn=0x3F8A1A40 newpeer=0x40BC3570 old=(nil)   thread=2
        first peer attached; old value is NULL
[STORE] conn=0x3F8A1A40 newpeer=0x13E25B0 old=0x40BC3570 thread=58
        SECOND peer attached, REPLACING the first

[PEER-TEARDOWN] serverproxy=0x3F8A1A40 connfield=0x13E25B0
[CLOSE] conn=0x3F8A1A40 ret=0x14040AF2C        ; the replaced peer's Close
[CLOSE] conn=0x3F8A1A40 ret=0x140444AB7        ; later refcount release
```

Attach path of the **first** peer (frame `#0 = 0x14042B721`, shallow stack):

```text
0x14042B721  (func 0x140411D30, the "attach peer to connection" routine)
             callers of 0x140411D30: 0x14042B721 and 0x14042CF88
```

Attach path of the **replacing** peer (frame `#0 = 0x14042C782`, deeper stack,
thread 58):

```text
0x14042C782  (func 0x14042C300)  <- 0x14042BA70 (func 0x14042B990)
             <- 0x14040647F (func 0x140406420) <- 0x140435C92
```

`0x14042B990` is the identification-message dispatcher and selects the attach by
message id:

```text
14042B9B9  cmp r9d, 0xA609E6A7   ; RequestIDSignature
14042BA35  cmp r9d, 0x6731C5AF   ; ReplyIDSignature
14042BA77  cmp r9d, 0x8B0D492F
```

`0x14042C300` — the path that performs the **replacing** attach — is taken on the
`0x6731C5AF` (`ReplyIDSignature`) arm, and that is the reply Holocron sends for
the bootstrap `RequestIDSignature`.

The detach that consumes the replaced peer:

```text
0x140434430  this=0x50F1A9E0  +0x18=0x152BD40  +0x20=0x405F1860
             target[+0x100]=0x14DFD30   (the ServerProxy)
             call [target_vtable+0x28]  then  call [target_vtable+0x70]
             <- 0x14042472E
```

### Phase 8/9 — the earliest non-cleanup condition

```text
first failing condition:
    a SECOND routed peer is attached to the same connection while the
    bootstrap-attached peer is still held in [connection+0x88]
function:
    0x140412820 (peer alloc/attach), reached from the 0x6731C5AF
    (ReplyIDSignature) arm via 0x14042C300 -> 0x14042C782 -> 0x140411D30
field/value:
    [connection+0x88] already holds peer 0x40BC3570 (name
    "localhost:7979:castlehilltest") when the replacement runs
expected:
    one routed peer per connection, i.e. [connection+0x88] == NULL at attach
actual:
    non-NULL; the exchange at 0x140412A4F overwrites it
event that normally satisfies it:
    none in Holocron's bootstrap — the replacement is caused by OUR OWN
    ReplyIDSignature, so the peer is attached twice from two different
    code paths for one reply
peer-visible or local:
    LOCAL, but triggered by the shape/content of the ReplyIDSignature the
    server sends. The two attach paths differ in the address fragment they
    build: the first records "localhost:7979:castlehilltest", the
    replacement records ":castlehilltest" with host/port re-parsed.
```

### Classification

```text
0x14040AEC0 Close producer                    CONFIRMED
Close is caused by losing a concrete routed peer  CONFIRMED
peer is attached twice in this run            CONFIRMED
second attach replaces the first              CONFIRMED
release of the replaced peer sends Close      CONFIRMED
0x140444A80 is downstream cleanup             CONFIRMED
D4 is the expected missing action             DISPROVEN (D4 arrives only over
                                              an established routed connection
                                              and is not on this path)
```

**No server behaviour was changed and D4 was not sent.** No peer-visible missing
action was proven: the two attach paths both run inside the client while handling
the single `ReplyIDSignature` Holocron already sends, so the next step is to
determine which of the two arms is spurious — a client-side double-attach driven
by the reply's shape — before any server change is justified.

## Wildcard-handoff hypothesis tested and DISPROVEN (September 13)

The previous section proposed that the first peer is normally a wildcard peer
whose release is exempted from sending `Close`, and that our fixture supplies a
concrete name instead. A single-field fixture experiment **disproves** that
hypothesis, and the same-run witness shows the wildcard test does not read the
peer name at all.

### Correction to the previous section's reading of `0x14040AEC0`

The previous section stated that the function reads the displaced peer's route
name from `[peer+0x40]`. Exact instruction bytes show the load uses **`rax`**,
which after `lock cmpxchg` holds the *replaced* value:

```text
14040aeeb  f0 48 0f b1 8a 88 00 00 00   lock cmpxchg qword ptr [rdx+0x88], rcx
14040aef4  48 8d 0d 65 0e 16 01         lea  rcx, [rip+0x1160e65]   ; 0x14156BD60 = ""
14040aefb  74 0b                        je   0x14040af08           ; old == 0 -> keep ""
14040aefd  48 8b 40 40                  mov  rax, [rax+0x40]        ; rax = OLD peer
14040af01  48 85 c0                     test rax, rax
14040af04  48 0f 45 c8                  cmovne rcx, rax
14040af08  0f b6 01                     movzx eax, byte ptr [rcx]
14040af0b  3a 05 bf 33 16 01            cmp  al, byte ptr [0x14156E2D0]  ; "*"
14040af11  75 0c                        jne  0x14040af1f
14040af13  0f b6 41 01                  movzx eax, byte ptr [rcx+1]
14040af17  3a 05 b4 33 16 01            cmp  al, byte ptr [0x14156E2D1]  ; NUL
14040af1d  74 4b                        je   0x14040af6a              ; skip Close
```

So the compared string is the **displaced peer's `[peer+0x40]`**, and an empty
string (or a NULL old peer) does **not** satisfy the wildcard test — the branch
is taken only for exactly `"*"`. This supersedes the earlier wording.

### The experiment — one field, falsifiable, and NEGATIVE

Changed exactly one value: the `host` field of the single shard in
`tools/fixtures/platform-responses.json`, from `localhost:7979:castlehilltest`
to `localhost:7979:*`. Nothing else was touched; no client logic, no attach
suppression, no forced NULL. Client bytes were restored byte-exactly and the
fixture was restored from a pre-change copy.

Result — the fixture value propagates faithfully into the peers, but the `Close`
is **not** suppressed:

```text
[STORE] conn newpeer=0x41A36AC0 old=(nil)          thread=2
   NEW +0x20=localhost:7979:*   +0x30=localhost:7979   +0x40=
[STORE] conn newpeer=0x13E25B0 old=0x41A36AC0      thread=58
   NEW +0x20=:*                 +0x30=localhost:7979   +0x40=
   OLD +0x20=localhost:7979:*   +0x30=localhost:7979   +0x40=
[PEER-TEARDOWN]
[CLOSE-CALL] 0x14040af27 -> Close SENT
[CLOSE] ret=0x14040af2c ; [CLOSE] ret=0x140444ab7
```

The wildcard breakpoint at `0x14040af1d` never fired and the Close-call
breakpoint did, in every variant tested.

### Why the test came out negative — the compared field was not what we changed

A value-capture run on the **stock** fixture shows the compared string directly:

```text
[WILD-TEST] compared string = ""   (rcx=0x14156BD60, the empty-string singleton)
   rdi = 0x14DFD30                ; the ServerProxy (same object as [arg2])
```

`rcx` still held the empty-string singleton at `0x14040af08`, which means the
`je` at `0x14040aefb` was taken — **the replaced value was zero for this call**,
so `[rax+0x40]` was never loaded. The wildcard test therefore had nothing to
compare, and the fall-through to `0x14040af1f` sent the Close.

That in turn means the `Close` observed in this run is produced by a teardown
whose `[conn+0x88]` was **already empty at entry**, not by comparing a concrete
name against `"*"`. The `"*"` exemption is real and reachable in the code, but it
is **not** the guard that fired here.

### Classification

```text
first peer's +0x20 echoes the fixture host verbatim        CONFIRMED
second peer's +0x20 is the fixture host minus its first
  colon-separated component (":castlehilltest", ":*")      CONFIRMED
fixture's third component reaches the peer name            CONFIRMED
setting the third component to "*" suppresses Close        DISPROVEN
the "*" test compares the displaced peer's +0x40           CONFIRMED
the "*" test was satisfiable in the captured failing call  DISPROVEN (the
                                                           replaced value was 0)
wildcard-to-routed handoff is this run's mechanism         DISPROVEN
```

### Remaining open question

`[rdi]+0x40` on the third successful `cmpxchg` chain (`0x14042c641`/`0x14042c731`/
`0x14042c754`) selects the string that is compared, and the first two of those
three exchanges are unreachable fallbacks. Nothing recovered so far establishes
which component of a real retail shard address is intended to equal `"*"`, or
whether `"*"` is generated internally from a connection role rather than from
the shard address at all. Per the working rule, no further fixture or server
change is made until that provenance is proven.

**No server behaviour was changed and D4 was not sent.** The copied client and
the fixture were both restored byte-exactly after every run
(`47d8c8f0…` for the client, `localhost:7979:castlehilltest` for the fixture).

## The `conn+0x88` mutation history, and why no "hidden clear" exists (September 13)

> **SUPERSEDED IN PART — read the next section first.** The runtime chronology,
> the call chain and the timed-loop findings below are retained and correct, but
> the claim that `0x14040AEEB` **clears** `conn+0x88` is **RETRACTED**. As the
> register-level revalidation in the following section proves, that
> `lock cmpxchg` fails, leaves the destination **unchanged**, and returns the old
> value in `RAX`. The field still holds peer B after the instruction, and the
> teardown never removes it. Statements below that describe a `peer B -> NULL`
> transition, or call `0x14040AEC0` a "take", are wrong and superseded.

The previous section left an apparent gap: `conn+0x88` was thought to be `NULL` by
the time `0x14040AEC0` ran, implying an unseen mutation between the second attach
and the Close. A complete same-run mutation witness closes that gap and
**corrects the premise**.

### Phase 1 — complete mutation history, one run, chronological

Every writer of `conn+0x88` known in the image was hooked, plus the teardown take.
All five mutations of the *same* connection object were captured:

```text
conn = 0x3F4B1C20   (identical in every record)

[STORE]  0x140412A4F  cmpxchg [rbx+0x88], r15   thread=2
         r15 = 0x4096FBA0   old = NULL            NULL   -> peer A

[M1]     0x14042C641  cmpxchg [rcx+0x88], rdi   thread=58
         rdi = NULL         old = 0x4096FBA0      peer A -> (no change; rdi is NULL)

[M2]     0x14042C731  cmpxchg [rcx+0x88], rdi   thread=58
         rdi = NULL         old = 0x4096FBA0      peer A -> (no change; rdi is NULL)

[M3]     0x14042C754  cmpxchg [rdx+0x88], rdi   thread=58
         rdi = NULL         old = 0x4096FBA0      peer A -> (no change; rdi is NULL)

[STORE]  0x140412A4F  cmpxchg [rbx+0x88], r15   thread=58
         r15 = 0x13E25B0    old = 0x4096FBA0      peer A -> peer B

[M5]     0x14040AEEB  cmpxchg [rdx+0x88], rcx   thread=2
         rcx = 0            old = 0x13E25B0       (RETRACTED: no change)
[CLOSE-CALL] 0x14040AF27
[CLOSE] 0x1404123D0 ret=0x14040AF2C
[CLOSE] 0x1404123D0 ret=0x140444AB7
```

Correction to the premise (**itself now retracted — see the next section**): this
pass concluded that the teardown's own atomic take was the operation setting
`conn+0x88` to NULL. Register-level revalidation disproves that. `0x14040AEEB`
fails its comparison and leaves the destination holding peer B; `conn+0x88` is
**never cleared** anywhere in the observed run. What actually produced the empty
string at the wildcard test is peer B's own `+0x40` field, which contains the
empty-string singleton, so `cmovne` does not replace `rcx`. `0x14040AF1D` still
did not fire, so that empty value was compared and was not `"*"`.

### Phase 3 — the three ReplyID `cmpxchg` operations

All three share an identical shape and, at runtime, all three write **`rdi`, which
is NULL**:

```text
address    target field        eax(expected)  source        semantics
0x14042C641  [rcx+0x88]        0 (xor eax,eax)  rdi = NULL   guarded store of NULL
0x14042C731  [rcx+0x88]        0 (xor eax,eax)  rdi = NULL   guarded store of NULL
0x14042C754  [rdx+0x88]        0 (xor eax,eax)  rdi = NULL   guarded store of NULL
```

Runtime branch behaviour (captured, not inferred): each compares the field with
`EAX = 0` against a non-null old value, so **the comparison fails, ZF is clear,
and the store does not commit**; `RAX` returns the old value. The `jne`/`je`
guards then select the non-null path, which loads the old peer's `+0x50`/`+0x30`
as the route/name selector instead of the empty-string fallback at
`0x141B31AE8`.

So none of the three clears `conn+0x88`, and none of them is a peer removal. They
are **reads dressed as conditional stores** — the compiled form of an atomic
"read this one-shot field" where the compiler reused `cmpxchg ... 0` to test
against a sentinel. The same idiom appears at `0x14040AEEB`, `0x14040B190` and
`0x14040B03B`, which is why the earlier pass mistook them for fallbacks.

### Phase 5 — the caller chain into `0x14040AEC0`

Entry captured on the reproduced run:

```text
[PEER-TEARDOWN] rcx=0x14DFD30 (ServerProxy)  arg=0x69CF6D0  conn=0x3F4B1C20
                conn+0x88=0x13E25B0 (peer B still present)  thread=2

#0 0x14040AEC0   <- the teardown itself
#1 0x1404344E0   <- inside 0x140434430, the detach, just past its vtable calls
#2 0x14DFD30     (ServerProxy)
#9 0x14042472E   <- inside the collection destructor 0x1404245F0
```

Caller of the detach, from the same run:

```text
[DETACH] 0x140434430  this=0x509BA9E0  +0x18=0x152BD40  +0x20=0x3F8A1D10  thread=2
#0 0x140434430
#1 0x14042472E     <- collection destructor 0x1404245F0
```

`0x1404245F0` is a **collection destructor**: it takes a mutex at `this+0xC0`,
zeroes the shared_ptr at `this+0x100`, walks the sentinel-terminated intrusive
list at `this+0xF0`, and for each element calls `vtable+0x08` then `vtable+0x00`
(`0x140424725`, `0x14042473C`, loop counter in `EDI`).

That destructor's own caller, captured three times on thread 2:

```text
[DTOR] 0x1404245F0  this=0x14B3EB0  thread=2
#0 0x1404245F0
#1 0x140423EA1     <- inside 0x140423DD0
```

`0x140423DD0..0x140423FE1` is a **timed wait / task loop**: it reads a tick pair
at `0x140423E41`/`0x140423EAB`, and gates on two fields of one object —
`[r8]` at `0x140423DFD` and `[r8+0x2D]` at `0x140423E12`/`0x140423F6B`, with a
further `[rax+0x2C]` test at `0x140423EE6`.

### Phase 6 — ordered timeline (same run)

```text
T0  thread 2   NULL -> peer A  (0x140412A4F)
T1  thread 58  M1/M2/M3 read the field with rdi=NULL, no commit
T2  thread 58  peer A -> peer B (0x140412A4F)
T3  thread 2   0x140423DD0 timed loop -> 0x1404245F0 collection dtor
               -> 0x140434430 detach -> 0x14040AEC0 peer teardown
T4  0x14040AEEB  peer B -> NULL   (the only clear)
T5  0x14040AF27  Close 0x43DB3479 sent
T6  ServerProxy::OnDisconnect (launch context still set)
T7  HandleLaunchFailure 1003
```

The teardown runs on **thread 2**, the same thread as the timed loop — not on the
ReplyID thread 58 that installed peer B. **Peer A's replacement and the Close are
separate lifecycle events**, confirming the task's warning against conflating them.

### Phase 10 — `peer+0x40` / `"*"`

```text
peer+0x40 wildcard behavior: REAL BUT NOT CAUSAL TO CURRENT FAILURE
```

Confirmed again on this run: peer B was present at the teardown, was taken by
`0x14040AEEB`, and `0x14040AF1D` did not fire. No further hunt for a `"*"` source
is justified without new evidence.

### Classification

```text
conn+0x88 mutation history captured end-to-end         CONFIRMED
teardown's own take is the only clear of conn+0x88     CONFIRMED
M1/M2/M3 write NULL and do not commit                  CONFIRMED
teardown runs on thread 2 from a timed loop            CONFIRMED
teardown reached via 0x140423DD0 -> 0x1404245F0
  (collection dtor) -> 0x140434430 (detach)            CONFIRMED
peer A's release and the Close are separate events     CONFIRMED
peer+0x40 / "*" is causal to this failure              DISPROVEN
ReplyID handling clears conn+0x88                      DISPROVEN
```

### Remaining open question

What makes the timed loop `0x140423DD0` proceed into the collection-destructor
path. It has no direct callers and no data references, so it is entered
indirectly; the gating fields `[r8]`, `[r8+0x2D]` and `[rax+0x2C]` and the
identity of the object at `0x14B3EB0` are the next targets. Until that is
established the teardown is **not** yet proven to be failure cleanup rather than
an intentional transition, so `conn+0x88` becoming NULL through the teardown is
classified **UNKNOWN** for normal-vs-failure.

**No server behaviour was changed and D4 was not sent.** Client restored
byte-exactly (`47d8c8F0…`) and fixture restored (`localhost:7979:castlehilltest`)
after every run.

## RETRACTION: x86 CMPXCHG failure does not clear `conn+0x88` (September 13)

### What is retracted

The preceding section classified `0x14040AEEB` as the instruction that clears
`conn+0x88`, printing a `peer B -> NULL` transition. That is **wrong**.

`LOCK CMPXCHG r/m64, r64` compares `RAX` with the destination and:

```text
if RAX == DEST:  DEST = SRC ; ZF = 1
else:            RAX  = DEST ; DEST unchanged ; ZF = 0
```

The comparison-failure path **never writes the destination**. The hardware
watchpoint fired because `lock cmpxchg` is a locked read-modify-write bus
operation regardless of the architectural outcome. A watchpoint hit is
therefore **not** evidence of a value change. The `peer B -> NULL` transition
reported in the previous section was an artefact of that inference.

### Register-level revalidation — CONFIRMED on the historical run

One bounded run with the documented loopback resolver step, client and fixture
restored byte-exactly. Instruction bytes at the site:

```text
0x14040AEEB:  f0 48 0f b1 8a 88 00 00 00   lock cmpxchg qword ptr [rdx+0x88], rcx
0x14040AEF4:  48 8d 0d 65 0e 16 01         lea  rcx, [rip+0x1160e65]
```

Captured immediately before and after, on the failing path:

```text
[BEFORE] rax=0x14040AEC0 rcx=0x14DFD30 rdx=0x3F8A1A40
[BEFORE] conn+0x88 = 0x13E25B0            (peer B present)

[AFTER ] rax=0x13E25B0 rcx=0
[AFTER ] conn+0x88 = 0x13E25B0            (UNCHANGED)
[AFTER ] eflags=0x287  ZF=0
```

```text
Does 0x14040AEEB mutate conn+0x88 when it is non-null?   NO
```

`RAX` returns peer B exactly as the architecture specifies, `ZF` is clear, and
the destination is byte-identical before and after. So:

```text
conn+0x88 is never cleared anywhere in the observed run.
peer B remains attached right through the Close.
```

### Phase 1 — corrected mutation history (same run)

```text
initial:                  NULL
first attach  (0x140412a4f, thread 2):   NULL    -> peer A   (real store, succeeds)
0x14042c641   (thread 58):  before 0x4096FBA0  after 0x4096FBA0   (no change)
0x14042c731   (thread 58):  before 0x4096FBA0  after 0x4096FBA0   (no change)
0x14042c754   (thread 58):  before 0x4096FBA0  after 0x4096FBA0   (no change)
ReplyID replacement (0x140412a4f, thread 58): peer A -> peer B     (real store)
0x14040aeeb   (thread 2):   before 0x013E25B0  after 0x013E25B0   (no change)

Only TWO real mutations exist: NULL -> peer A, then peer A -> peer B.
The only writer of conn+0x88 is 0x140412A4F.
```

The `cmpxchg ... , rdi` operations at `0x14042c641`/`0x14042c731`/`0x14042c754`
have `rdi = NULL` at runtime, so even had they succeeded they would have *erased*
the field; because the field is non-null and `EAX = 0`, they fail and change
nothing. They are conditional stores used as atomic probes.

### Phase 2 — why `rcx` held the empty string, resolved

Two candidate causes existed. Runtime settles it as **B**, not **A**:

```text
A. conn+0x88 was NULL and the cmpxchg succeeded, so JE was taken
   -> DISPROVEN: ZF=0, the cmpxchg failed
B. conn+0x88 held a peer, cmpxchg failed, peer+0x40 was NULL so CMOVNE did not
   replace rcx
   -> CONFIRMED
```

Captured values:

```text
peerB(rax)          = 0x13E25B0
peerB+0x40 raw      = 0x14156BD60        <- the empty-string singleton
peerB+0x40 str      = ""
peerB+0x20 str      = ":castlehilltest"
peerB+0x30 str      = "localhost:7979"

[TEST] rcx = 0x14156BD60   empty_singleton = 0x14156BD60   equal = 1
[BRANCH] fallthrough -> Close sent
```

`lea rcx,[0x14156BD60]` loads the empty-string singleton; `mov rax,[rax+0x40]`
loads peer B's `+0x40`, which is *that same* singleton; `test rax,rax` sees a
non-null pointer so `cmovne rcx,rax` copies it, a no-op in value. `rcx` is
therefore non-null and empty, and `""` does not equal `"*"`, so the Close is
sent on the fall-through. **The empty-string result comes from peer B's own
`+0x40` field, not from the connection field being empty.**

Note this also means `peer+0x40` is a real string field that held `""` here;
whether it is ever populated is now the only open part of the wildcard question.

### Phase 3 — corrected semantic role of `0x14040AEC0`

```text
Does 0x14040AEC0 itself remove the peer from connection+0x88?   NO
Does it merely atomically read/classify the current peer before
  deciding whether to Close?                                    YES
```

Role: **atomic routed-peer probe + routed-connection termination.** It loads the
connection from its argument, probes `[conn+0x88]` with a sentinel compare (which
fails, returning the peer in `RAX`), classifies the peer by its `+0x40` string
against `"*"`, and closes the connection when the name is not the wildcard.

`0x14040AF6A` releases `[arg2]` — the connection smart-pointer held by the
argument struct, **not** the peer in `conn+0x88`. That connection object is
distinct from the peer, and its release is the reference that the teardown is
finishing with, not a peer deletion.

### Phase 4 — the call chain, retained and verified

The chain recovered by the previous run is unaffected by the cmpxchg correction
and is retained:

```text
0x140423DD0   timed wait / periodic task
   -> 0x1404245F0  collection teardown (mutex +0xC0, intrusive list +0xF0,
                   shared_ptr +0x100; per element calls vtable+0x08 then +0x00)
   -> 0x140434430  surrogate/target detach (calls vtable+0x28 then +0x70)
   -> 0x14040AEC0  routed-peer probe + Close
   -> 0x1404123D0  Close 0x43DB3479
   -> ServerProxy::OnDisconnect -> 1003
```

Re-verified edges on the failing run: the detach enters `0x14040AEC0` on
**thread 2**, the same thread as the timed routine, not the ReplyID thread 58.

### Phase 6/10 — partial gate semantics of `0x140423DD0`

Recovered from the full disassembly (not inferred from shape):

```text
rcx = rdi = destination object (released at 0x140423FA9 -> 0x1400B79F0)
rdx = rbx = argument; [rbx] = target object; [rbx+8] = its refcounted control block
r8        = gate input

140423dfd  cmp dword ptr [r8],0      ; gate: non-zero -> 0x140423F65
140423e07  rax = [rdx] ; r8 = [rax]
140423e0d  cmp byte ptr [r8+0x2d],0  ; non-zero -> 0x140423FA9 (exit, no teardown)
```

Timing source is `KUSER_SHARED_DATA`: `0x7FFE0008` (low), `0x7FFE000C` (high),
`0x7FFE0010` (sequence), converted with the `0x346DC5D63886594B` / `>>0xB`
millisecond scaling, with deadlines at `[[rbx]]+0x28` and elapsed compared at
`0x140423eec`.

```text
condition that selects teardown =
    at entry [r8] == 0, [target+0x2D] == 0; then [target+0x2C] and the
    elapsed>=deadline comparison at 0x140423eec choose between the periodic
    callback 0x140423FF0 and the completion callback 0x140423A70
```

Runtime values of `[r8]`, `[target+0x2C]`, `[target+0x2D]` and the deadline were
**not** captured, so:

```text
83 ms teardown trigger:  UNKNOWN
  (a real timeout is NOT proven: the ~83 ms spans the whole
   CS_LOGGING_IN -> HandleLaunchFailure interval in the client log and was
   never isolated to this loop)
conn+0x88 becoming NULL: does not happen; classification void
double attach:           NOT CAUSAL (0x14040AEC0 does not depend on the peer
                         having been replaced; only on the peer's +0x40 name)
D4 causal relevance:     UNKNOWN (not sent)
peer+0x40 / "*":         REAL; whether the field can ever hold "*" is OPEN
```

### Remaining open question

**Why the owner begins the collection-teardown path.** `0x140423DD0` has no
direct callers, no data references and no 8-byte pointer anywhere in the image
that lands inside its range, so it is entered by a dispatch not yet localized.
Its gate fields (`[r8]`, `[target+0x2C]`, `[target+0x2D]`), the identity of the
object at `0x14B3EB0`, and the identity of the `0x1404245F0` collection are the
next targets.

**No server behaviour was changed; D4 was not sent.** The copied client and the
fixture were restored byte-exactly after every run.

---

## Canonical-runner hardening, and scoping the `"*"` Close test (September 13)

No protocol behaviour changed in this section. It records one repository
correctness fix and one documentation scoping correction, made together before
the next reverse-engineering checkpoint.

### The canonical runner inherited mode variables

`tools/run-retail-bootstrap-probe.py` is the single supported entrypoint, but it
only popped three variables (`HOLOCRON_AUTH_CAPTURE`, `HOLOCRON_AUTH_LOGIN_REPLY`
and, in an earlier revision, `HOLOCRON_RUN_SECONDS`) before setting the modes the
command line requested. Every other mode switch was therefore inherited from the
calling shell:

```text
HOLOCRON_AUTH_CAPTURE
HOLOCRON_AUTH_LOGIN_REPLY
HOLOCRON_AUTH_ID_BOOTSTRAP
HOLOCRON_WINEDBG_GDB
HOLOCRON_WINEDBG_TRACE
HOLOCRON_GDB_PARENT
HOLOCRON_GDB_INNER
HOLOCRON_GDB_TRACE
HOLOCRON_DORMANT_DEBUG
```

Concretely, a shell that already had `HOLOCRON_AUTH_ID_BOOTSTRAP=1` exported made
`--no-bootstrap-probe` a no-op, and any exported `HOLOCRON_GDB_*` value replaced
the whole normal client launch with a debugger branch inside
`tools/launch-isolated-client.sh`, because those branches are checked in
`elif` order. A run could silently not be the run that was asked for.

Fix: `sanitize_mode_environment()` clears the entire list first, and `main()`
then sets **only** the flags selected by this invocation. Two further accuracy
fixes went in at the same time:

* `--keep-patched` removed. Canonical runs always restore the private executable;
  the unrestricted `finally` restore has no override.
* `HOLOCRON_RUN_SECONDS` removed. Nothing in `tools/launch-isolated-client.sh`
  ever read it — only `scratch/retail-capture.py` did, for its own unrelated
  deadline — so the variable claimed a launcher time limit that did not exist.
  `--seconds` is now documented as what it actually is: the **wrapper's** bound on
  how long the launcher may run, plus a fixed 120 s shutdown grace. The launcher
  has no time limit of its own and receives no time-limit value.

`tools/test_run_retail_bootstrap_probe.py` covers this: mode sanitization, the
inherited-export case, default probe opt-in, deadline arithmetic, byte-exact
restoration on both the success and launcher-failure paths, refusal of an
unrecognized build, and a guard that these tests never invoke the isolated
launcher. All of it operates on throwaway synthetic clients; the real private
client is only ever read.

### Scoping the `"*"` Close test

The earlier section "Wildcard-handoff hypothesis tested and DISPROVEN" stated,
globally:

```text
if the retained route name is the wildcard "*" the Close is skipped;
otherwise a Close is sent
```

That was written too broadly. The `"*"` comparison at `0x14040AF0B`/`0x14040AF1D`
is a local decision **inside `0x14040AEC0`** and says nothing about Close
production anywhere else in the image. `docs/CURRENT-RETAIL-STATE.md` now states
only the local contract:

```text
Within 0x14040AEC0, its Close call is skipped when the classified peer string is
exactly "*"; otherwise that path calls Close.
```

Other Close producers exist structurally and are not erased by this test. The
superseded global phrasing is retained here as `SUPERSEDED` per the notebook's
provenance rule.

---

## The hidden dispatch into `0x140423DD0` is found: a runtime-materialised closure (September 13)

### What was blocking

The previous section left `0x140423DD0` as a function with **no direct callers,
no conditional branches, no tail jumps and no image-resident 8-byte pointer
landing inside its range**. That combination is impossible for a normal function
and pointed at a dispatch that does not exist in the image.

It was true, and the reason is now measured: `0x140423DD0` is a **closure body**.
Its address is written into a function pointer at runtime, so no static
reference to it exists.

### The dispatch, measured

One bounded run through the canonical runner
(`tools/run-retail-bootstrap-probe.py --launcher scratch/re2/witness-launcher.sh`),
client and fixture restored byte-exactly. Breakpoint at `0x140423DD0` entry:

```text
thread 2
RAX = 0x140423DD0
R11 = 0x140423DD0
RETADDR [rsp] = 0x140425806

machine code immediately preceding the return address:
  0x1404257FA  mov  rcx, r10
  0x1404257FD  mov  rax, r11
  0x140425800  call qword ptr [rip+0xf454ba]     ; -> slot 0x14136ACC0
slot 0x14136ACC0  ->  0x141283300
  0x141283300:  ff e0    jmp rax
```

Classification:

```text
mechanism = indirect CALL through a data slot in .rdata
slot      = 0x14136ACC0   (immediately after the IAT, which ends at 0x14136ACB8)
thunk     = 0x141283300   = `jmp rax`, one instruction
target    = RAX, which the call site sets to the closure's bound function
```

So the chain is:

```text
0x140425770   closure invoker (thread_data-style run() trampoline)
  -> call [0x14136ACC0] -> 0x141283300 (jmp rax) -> RAX = 0x140423DD0
```

`0x140423DD0` is **not** reached through a task trampoline or a thread start
routine. It is reached through a bound function pointer that a
`std::function`-style trampoline loads out of the closure object. Verified by
single-stepping the thunk with GDB:

```text
before the call:  rcx=0x14B3DA0 rdx=0x6CCFC50 rax=0x140423DD0
thunk resolves to 0x141283300  (bytes ff e0 == jmp rax)
```

### The closure object, measured

```text
closure (stack, thread 2, first field is the bound function):
  +0x00  0x140423DD0        bound function pointer
  +0x08  0x14B7DA0          first captured object
  +0x10  0x14E7FC8          second captured object
  +0x18  0x14C3B88          its boost control block
```

At `0x140423DD0` entry:

```text
arg1 rcx = 0x14B7DA0
arg2 rdx = &shared_ptr   [rdx] = 0x14E7FC8   [rdx+8] = 0x14C3B88
arg3 r8  = stack slot; measured [r8] = 0
arg4 r9d = 4
```

### Correction: which object the gates live in

`0x14E7FC8` is **not** the gate object. The function begins

```asm
140423e07  mov rax, qword ptr [rdx]      ; rax = *rdx = 0x14E7FC8
140423e0a  mov r8,  qword ptr [rax]      ; r8  = [0x14E7FC8] = 0x1523E58
140423e0d  cmp byte ptr [r8 + 0x2d], 0
```

so the gates live in **`[0x14E7FC8] = 0x1523E58`**. An earlier reading that
treated `0x14E7FC8` itself as the object missed that first dereference.

The control block at `0x14C3B88` has vtable `0x1414B6588`, and
`vtable[-1]` = `0x141701D88` is a well-formed COL with `moffset = 0` whose pTD
name is:

```text
.?AV?$sp_counted_impl_p@VApartmentTimer@omega@@@detail@boost@@
```

so the shared_ptr is a `boost::shared_ptr<omega::ApartmentTimer>` control block.
`CONFIRMED`.

### Measured gate values

```text
[r8]                 = 0x00000000
0x1523E58 + 0x00     = 0x1414B6761        (function table pointer; low bit set)
0x1523E58 + 0x08     = 0x140430800
0x1523E58 + 0x28     = 0x00000005        (dword, read as the wait argument)
0x1523E58 + 0x2C     = 0x01              (byte)
0x1523E58 + 0x2D     = 0x00              (byte)
0x1523E58 + 0x28 (q) = 0x0000000100000005
```

Because `[target+0x2C] != 0`, the function takes the timed-wait arm and calls
`0x140423FF0` with `r8d = 5`. Verified:

```text
[CHOSEN] callback A 0x140423FF0, wait_ms(r8d)=5 thread=2
```

### What the 5 ms actually is

`0x1523E58+0x28 == 5` is the millisecond argument handed to the wait. The
KUSER_SHARED_DATA block at `0x140423E30`–`0x140423E79` computes elapsed
milliseconds, `0x140423EE0`–`0x140423EFD` computes the remaining time and clamps
it with `cmp rcx,1 / cmovl ecx,eax` to a minimum of 1 ms. So this is a **timed
wait with a 1 ms floor**, not a deadline comparison that can itself expire into a
teardown. The measured quantum is 5 ms.

### Which task owns the loop

The closure is created and registered by `0x1404305D0`, the `boost::bind`
target of a `boost::detail::thread_data` object. RTTI confirms the thread type:

```text
.?AV?$thread_data@V?$bind_t@XV?$mf1@XVApartmentImpl@omega@@_N@_mfi@boost@@V?$list2@...
```

and the task body is recognisably the connection-state poller:

```asm
1404305D0  call 0x140431030
1404305DE  mov  rcx, [rbx+8]
1404305E2  lea  rdx, [rip+0x114e2e7]      ; "connection"
1404305E9  mov  rcx, [rcx+0xe8]
1404305F0  call 0x1403FC4C0               ; setting lookup
1404305F9  lea  rdx, [rip+0x114e330]      ; "signature"
140430607  jmp  0x1403FC4C0               ; setting lookup
```

`0x14042F960` arms this task with **5 ms** (`r9d=5`) and also with **500 ms**
(`r9d=0x1F4`) on the same object.

### Every timer registration site, and the historical `0x14B3EB0`

Every registration goes through `0x140423B50`. Runtime witness of the startup
registrations:

```text
site 0x1404264B8  callback(r8)=stack  timeout 60000  arg1 0x14B3C90
site 0x14042FA39  callback(r8)=stack  timeout   500  arg1 0x14B3DA0
site 0x14042FB10  callback(r8)=stack  timeout     5  arg1 0x14B3DA0
site 0x140446693  callback(r8)=stack  timeout 60000  arg1 0x14B3EB0
```

Two of these matter for provenance:

* the historical absolute heap address **`0x14B3EB0`** is one runtime instance of
  the object registered at site `0x140446693` with a **60 s** timeout. It is not
  the 5 ms poller.
* the 5 ms closure that reaches `0x140423DD0` belongs to `0x14B3DA0`.

Neither address is an identity. The identity is the type, and the type is reached
through RTTI, not through a heap address.

### What this pass did NOT establish

Retracted as this section's limit rather than as a claim: the historical
teardown chain was **not** re-observed under instrumentation. `0x1404245F0`,
`0x140434430` and `0x14040AEC0` were not hit in any instrumented run of this
pass. With the 5 ms loop instrumented, WineDbg's GDB stub terminates the client
with a Windows exception (`exit code 0x30000000005`) about 12 s after the first
breakpoint in that loop, and without instrumentation the shard click does not
complete. So:

```text
dispatch mechanism into 0x140423DD0            CONFIRMED
closure layout and gate object identity        CONFIRMED
runtime gate values ([r8]=0, +0x2C=1, +0x2D=0) CONFIRMED
timer quantum 5 ms                             CONFIRMED
writer of +0x2C / +0x2D                        UNKNOWN
what event sets +0x2D so the predicate succeeds UNKNOWN
owner decision that selects teardown            UNKNOWN
0x1404245F0 collection identity                 UNKNOWN
D4 causality                                    UNKNOWN (not sent)
```

**No server behaviour was changed and D4 was not sent.** The private client and
the platform fixture were restored byte-exactly after every run.

---

## The 5 ms poll is an operation-completion wait, and `0x140423A70` is its completion routine (September 13)

This section is **static reconstruction** plus the runtime facts already recorded
in the previous checkpoint. No new debugger instrumentation of the 5 ms loop was
used, per the standing constraint that WineDbg's GDB stub perturbs the client.

### `0x140423B50` is the single operation/timer factory

Every timer-like registration in the image goes through `0x140423B50`. Argument
roles, recovered from the body and confirmed against the runtime witnesses of
the previous checkpoint:

```text
rcx          = operation owner object      (0x14B3DA0, 0x14B3C90, 0x14B3EB0, ...)
rdx          = out shared_ptr slot (two qwords cleared then filled)
r8           = pointer to a materialised callable (function-object table)
r9d          = timeout in milliseconds
[stack+0x20] = byte flag forwarded to 0x1404595E0
```

It takes the owner's spinlock, builds the callable, links it into the owner's
structure at `owner+0x90`, and finishes by starting the timer:

```asm
140423ba2  lock cmpxchg dword ptr [rcx+0xa8], r13d    ; owner spinlock
140423bf6  call 0x1404595e0                            ; build callable
140423c0d  call 0x140425600                            ; shared_ptr control block
140423ccf  ...               mov  rax, [rbx]           ; operation object
140423d06                    mov  rax, [rcx]           ; its function table
140423d09                    mov  r8d, dword ptr [rax+0x28]   ; timeout
140423d33                    call 0x140423FF0          ; start the timer
```

That tail call is the key: **`0x140423FF0` is the timer/operation start entry**
and `0x140423DD0` is the wait it runs. The previous checkpoint's `CONFIRMED`
values now have roles:

```text
0x1523E58 + 0x28 = 5     wait quantum, read at 0x140423EEC, clamped to >= 1 ms
0x1523E58 + 0x2C = 1     wait-mode selector (cmp byte ptr [rax+0x2c],0)
0x1523E58 + 0x2D = 0     FINISHED flag
```

### Correction: `+0x2D` is the finish flag, and it has exactly one writer

The previous checkpoint recorded `+0x2C`/`+0x2D` as `UNKNOWN` semantics with no
observed writer. The writer exists and was found statically. `0x140423A70` is
the **completion routine**, and its body is:

```asm
140423a70  mov  [rsp+0x10], rdx
140423a93  cmp  qword ptr [rdx], 0        ; target present?
140423a99  lea  rcx, [rdx+8]              ; else just release the refcount
140423af2  mov  rax, [rdi]
140423af5  mov  rsi, [rax]                ; rsi = the target
140423af8  cmp  byte ptr [rsi+0x2d], 0
140423afc  jne  0x140423b19               ; already finished -> skip
140423afe  call 0x140fdb1c0               ; clock read
140423b03  lea  rdx, [rsi+0x38]           ; result slot
140423b07  lea  r8,  [rsp+0x28]
140423b0c  mov  rcx, [rsi+0x30]           ; owner-visible context
140423b10  call 0x140424860               ; publish the result / signal
140423b15  mov  byte ptr [rsi+0x2d], 1    ; <-- the only writer
```

So `target+0x2D` means **"this operation is finished"**, and its readers are:

```text
0x140423e0d  cmp byte ptr [r8+0x2d], 0   ; non-zero -> exit, no wait, no teardown
0x140423af8  cmp byte ptr [rsi+0x2d], 0  ; non-zero -> nothing left to do
```

The previous statement "semantics UNKNOWN, no runtime writer was observed" is
now `SUPERSEDED` for `+0x2D`: the writer is static, in the completion routine,
and was simply never executed in the instrumented windows.

`target+0x2C` selects the wait mode. `0x140423DD0` tests it directly
(`cmp byte ptr [rax+0x2c],0`), and with the measured value `1` the timed-wait arm
runs (`0x140423FF0` with `r8d = [target+0x28] = 5`). What the two modes *mean* is
still `HYPOTHESIS`; which arm each value selects is `CONFIRMED`.

### `0x1403FC050` is why both the timeout and the owner-cancel reach the same place

`0x1403FC050` is the shared cancel helper, and its body ends in a direct call to
the completion routine:

```asm
1403fc050  ...
1403fc063  mov  rcx, [rcx]
1403fc070  mov  rax, [rdx]
1403fc078  lea  rbx, [rdx+8]
1403fc08e  lock xadd dword ptr [rdx+8], eax      ; intrusive refcount
1403fc098  call 0x140423a70                      ; <-- completion routine
```

Ten call sites. Three are inside `0x14042FBA0` — the operation teardown that runs
when an operation is **replaced**:

```asm
14042fba0  ...
14042fbd7  mov  rcx, [rdi+0x220]        ; the registered operation
14042fc25  call 0x1403fc050             ; cancel it
14042fc32  mov  rax, [rdi+0x248]        ; second slot
14042fcaa  ...
14042fc9d  call 0x1403fc050             ; cancel it
14042fcd7  mov  rax, [rdi+0x238]        ; third slot
14042fd13  call 0x1403fc050             ; cancel it
```

and one is inside the polling body `0x140430620` (`0x140430798`).

This is the substantive result of this pass: **the timed-wait arm and the
owner-cancel path converge on the same completion routine.** "The wait did not
finish in time" and "the owner stopped the operation" are therefore not
distinguishable downstream from the call graph alone. Which one runs in the
failing run is `UNKNOWN`.

### Correction: every closure body here has zero xrefs

`0x140423DD0`, `0x14042FD80` and `0x1404305D0` all have zero direct branches and
zero 8-byte image references. They are function objects whose addresses are
materialised at runtime. The earlier "no callers, therefore dispatched by
something not yet localized" reading was correct but under-stated: *any* function
in this binary with no xrefs must first be suspected of being a closure body.

### The poller thread and its callback

`0x140430620` opens with `cmp byte ptr [rdi+0x258],0 / je 0x140430757` and then
`cmp qword ptr [rdi+0x248],0`. If the second check passes it takes
`[rdi+0x220]`, builds a refcounted callable, calls the shared cancel helper
`0x1403FC050`, clears `[rdi+0x248]`/`[rdi+0x250]`, and **registers a 1000 ms
timer** (`r9d = 0x3E8` at `0x1404306F4`) into `[rdi+0x238]`.

The callback slot `app+0x228` — armed with **500 ms** by `0x14042F960`
(`r9d = 0x1F4` at `0x14042FA39`) — holds a closure whose body is `0x1404305D0`:

```asm
1404305d0  mov  rbx, rcx                  ; ClientApplicationImpl*
1404305d9  call 0x140431030               ; per-tick connection walk
1404305de  mov  rcx, [rbx+8]
1404305e2  lea  rdx, [rip+0x114e2e7] "connection"
1404305e9  mov  rcx, [rcx+0xe8]
1404305f0  call 0x1403FC4C0
1404305f5  mov  rcx, [rbx+8]
1404305f9  lea  rdx, [rip+0x114e330] "signature"
140430600  mov  rcx, [rcx+0xe8]
140430607  jmp  0x1403FC4C0               ; tail call: its result is the return
```

`"signature"` at `0x14157E930` is referenced from **exactly one** code site in
the whole image: `0x1404305FA`. `"connection"` at `0x14157E8D0` is referenced
from `0x1400279EB`, `0x140409241`, `0x140409369`, `0x14040948E`, `0x1404095AE`,
`0x1404096CF`, `0x1404097F3` and `0x1404305E3`.

### The per-tick work is a connection-list walk

`0x140431030` takes a critical section on `owner+0x268` and walks two ordered
collections of intrusive-pointer elements:

```asm
14043105a  cmp qword ptr [rsi+0x2a8], 0
140431064  mov rax, [rsi+0x2a0]            ; index
14043106b  mov rbx, [rsi+0x2c0]            ; pointer array
140431072  mov rbx, [rbx+rax*8]            ; element
140431098  call 0x140409a60                ; virtual dispatch on the element
1404310d9  cmp qword ptr [rsi+0x2e0], 0
140431122  call 0x140409c50                ; second collection
```

and `0x140431180` shows the same owner gaining a new **0x88-byte** element that
is inserted into a `std::map` at `owner+0x298`:

```asm
1404311b3  mov ecx, 0x88
1404311bb  call mm_alloc
1404311dd  call 0x140408f00               ; build the element name/state
1404311e9  mov [rdi], rax                 ; return an intrusive pointer
14043121d  lea rcx, [rsi+0x298]           ; std::map
140431228  call 0x140432670               ; map::operator[]
```

The 0x88 size matches the routed-peer record recorded earlier in this notebook,
but establishing that these are the same object is `UNKNOWN` and is not claimed
here.

### What was established, and what was not

```text
0x140423B50 is the operation/timer factory                       CONFIRMED
its r9d is the timeout in ms; tail-calls 0x140423FF0             CONFIRMED
target+0x28 is the wait quantum (5), clamped to >= 1 ms          CONFIRMED
target+0x2C selects the wait mode                                CONFIRMED
target+0x2D is the FINISHED flag, written only in 0x140423A70    CONFIRMED
0x140423A70 is the completion routine                            CONFIRMED
0x1403FC050 (cancel) calls 0x140423A70, so timeout and owner
  cancel converge on the same routine                            CONFIRMED
0x140430620 walks connection collections and arms 1000 ms        CONFIRMED
app+0x228 closure body is 0x1404305D0, armed at 500 ms           CONFIRMED
0x1404305D0 looks up "connection" then "signature"               CONFIRMED
what the two lookups return and which branch consumes them       UNKNOWN
whether "connection"/"signature" are settings, interfaces or
  named content                                                  UNKNOWN
which of timeout vs owner-cancel fires in the failing run        UNKNOWN
concrete identity of the 0x1404245F0 collection                  UNKNOWN
whether the failed operation is local or peer-visible            UNKNOWN
D4 causality                                                     UNKNOWN (not sent)
```

The historical teardown chain
`0x140423DD0 -> 0x1404245F0 -> 0x140434430 -> 0x14040AEC0` is **retained as
previously captured evidence**. It was not re-observed in this pass, and no new
instrumentation was introduced to try, per the constraint that WineDbg's stub
perturbs the 5 ms loop and prevents the normal login path.

**No server behaviour was changed and D4 was not sent.**

---

## CORRECTION: `0x1403FC050` calls `0x140423A70`, not `0x1404245F0` (September 13)

### What was wrong

The previous section stated:

```text
0x1404245F0 is reached from 0x1403FC050, the shared cancel helper
```

and immediately quoted, in support of that sentence:

```asm
1403fc098  call 0x140423a70       ; <-- completion routine
```

The quoted instruction and the quoted sentence contradict each other. The
sentence is wrong and is retracted.

### What the evidence actually proves

```text
0x1403FC050 -> 0x140423A70            CONFIRMED (direct call at 0x1403FC098)
0x1403FC050 -> 0x1404245F0            DISPROVEN (no such edge exists)
```

`0x1404245F0` has no static predecessor at all: no direct branch, no conditional
branch, no tail jump, and no 8-byte image pointer lands on it. It is reachable
only through a runtime-materialised closure, exactly like `0x140423DD0`,
`0x14042FD80` and `0x1404305D0`.

### What must be preserved

The historical teardown chain remains valid **as previously captured runtime
evidence** and is not retracted by this correction:

```text
0x140423DD0
→ 0x1404245F0
→ 0x140434430
→ 0x14040AEC0
→ Close
```

What is retracted is only the claim that a *static call edge* connects
`0x1403FC050` to `0x1404245F0`. The runtime observation that `0x140423DD0`
precedes `0x1404245F0` on thread 2 stands; the mechanism by which
`0x140423DD0` reaches `0x1404245F0` is `UNKNOWN`.

### Why this matters for later work

Every function in this area with zero xrefs is a closure body. Treating the
absence of a static edge as evidence of a *different* static edge is exactly the
error this correction removes. A future pass must find each closure's
registration site (the machine code that materialises its address) rather than
guessing a callee.

---

## The application tick `0x140430620` and the slot it cancels (September 13)

### Why this function matters

The previous section established that owner cancellation
(`0x1403FC050 -> 0x140423A70`) and timed completion converge on the same
routine, so downstream evidence cannot separate them. That makes the *upstream*
decision the only useful target, and `0x140430620` is the one place in the
poller's own tile that calls `0x1403FC050`.

### Complete pseudocode

```text
0x140430620(this /*app*/):
  EnterCriticalSection(app + 0x28)
  if app->[0x258] == 0:                    # 0x140430660, je 0x140430757
      goto SHUTDOWN
  if app->[0x248] != 0:                    # 0x14043066D
      goto DONE
  op      = app->[0x220]                   # 0x14043067A
  closure = { fn = 0x1404305D0, arg = app } # 0x140430681/0x1404306C9
  new_op  = schedule(op, closure, 1000 ms)  # 0x1404306F4 -> 0x140423B50
  app->[0x248] = new_op                     # 0x140430704 -> 0x1400C67E0
  goto DONE

SHUTDOWN:                                   # 0x140430757
  if app->[0x248] == 0: goto DONE
  tmp = app->[0x248]                        # 0x140430772, retain at 0x14043078B
  cancel(tmp)                               # 0x140430798 -> 0x1403FC050
  app->[0x248] = 0                          # 0x1404307B0
  app->[0x250] = 0                          # 0x1404307B7
  goto DONE

DONE:                                       # 0x1404307D3
  LeaveCriticalSection(app + 0x28)
```

The two halves are mutually exclusive: non-zero `+0x258` may **arm**, zero
`+0x258` may **cancel**. `0x140430620` never touches `+0x228` or `+0x238`.

### The cancel branch, by pointer provenance

```asm
140430757  mov  rax, qword ptr [rdi + 0x248]
14043075e  test rax, rax
140430761  je   0x1404307d3
140430763  mov  rcx, qword ptr [rdi + 0x220]     ; overwritten before the call
140430772  mov  qword ptr [rbp - 0x19], rax      ; shared_ptr ptr = app->[0x248]
140430776  mov  rax, qword ptr [rdi + 0x250]     ; control block
14043078b  lock xadd dword ptr [rax + 8], esi
140430798  call 0x1403fc050                      ; rdx = &that shared_ptr
```

So the argument to `0x1403FC050` is built from `app+0x248`/`app+0x250`. The
`rcx` load from `+0x220` is dead for this call. Concluding "it cancels the
operation at +0x220" from the nearby load would have been wrong; the retain at
`0x14043078B` is what proves which slot is passed.

```text
0x140430798 cancels: app+0x248 / app+0x250
branch:              0x140430667 `je 0x140430757`
tested field:        byte ptr [app+0x258]
expected value:      0
```

`0x140258` is initialised to **1** by the `ClientApplicationImpl` constructor
`0x1404292E0` at `0x140429614`, alongside zeroing `+0x220`, `+0x228`, `+0x238`
and `+0x248`. That initialisation sequence is what identifies the object family:
the constructor also builds the two connection collections whose critical
sections are at `+0x1F0` and `+0x268` with spin counts `0xFA0`, and the walk at
`0x140431030` reads exactly those.

### Correction to the slot model

The previous documentation said `0x14042F960` establishes `+0x220`, `+0x228`,
`+0x238` and `+0x248`. That is true of the *stores*, but it does not follow that
all four are live in the poller's program. Only three functions in the whole
image write `+0x248`:

```text
0x140429614  ctor          -> 0
0x14042F960                -> (registration result)
0x14042FBA0  replace-teardown -> 0
0x140430620  this tick     -> new_op or 0
```

and the tick arms it only on the `+0x258 != 0` path. The 5 ms operation observed
reaching `0x140423DD0` lives in `+0x238` and is **not** what this tick cancels.
Treating `+0x238` and `+0x248` as the same operation was an unstated assumption
and is retracted here.

### `0x1403FC050` publishes no status

```text
0x1403FC050(rcx = context, rdx = &shared_ptr<callable>):
  rcx  = *rcx
  tmp  = *rdx
  ctl  = *(rdx+8)
  if ctl: lock xadd [ctl+8], 1
  call 0x140423A70(rcx, &tmp)
  release ctl
```

`r8` is unused, and `0x140423A70` reads no status operand before publishing. A
cancellation therefore reaches the completion routine **indistinguishable** from
a timeout. That is now proven from the callee's operand use rather than inferred
from the shared callee identity.

### What remains

```text
0x140430620 complete pseudocode                    CONFIRMED
0x140430798 cancels app+0x248/+0x250               CONFIRMED
cancellation branch tests [app+0x258] == 0         CONFIRMED
[app+0x258] initialised to 1 by the ctor           CONFIRMED
0x1403FC050 supplies no cancel/timeout status      CONFIRMED
which operation 0x140423DD0 belongs to             UNKNOWN (1 dword of state)
what sets [app+0x258] to 0 in the failing run      UNKNOWN
whether the failing Close uses cancel or timeout   UNKNOWN
0x1404245F0 closure registration site              UNKNOWN
"connection" / "signature" effects                 UNKNOWN
```

**No server behaviour was changed and D4 was not sent.**

---

## The `app+0x238` callable is `0x140430800`, proven from the registration bytes (September 13)

### The question this answers

The previous passes left "what is bound into `app+0x238`" open, and the
`0x1404305D0` body was attributed to the 500 ms slot only by association. This
section settles it from the instructions that build the callable, not from
address proximity.

### The registration, byte-for-byte

`0x14042F960` performs two registrations. The second one targets `app+0x238`:

```asm
14042FA96  mov  r10, qword ptr [rdi + 0x220]   ; the registered operation
14042FA9D  lea  rax, [rip + 0xd5c]             ; -> 0x140430800
14042FAA4  mov  qword ptr [rbp - 0x29], rax    ; callable.fn
14042FAA8  mov  dword ptr [rbp - 0x21], r14d
14042FAB0  mov  qword ptr [rbp + 0x2f], rdi
14042FAC1  movsd qword ptr [rbp - 0x19], xmm0
14042FAE5  lea  rax, [rip + 0x1086c74]         ; -> 0x1414B6760
14042FAEC  or   rax, 1
14042FAF0  mov  qword ptr [rbp - 9], rax       ; callable.fntable
14042FAFF  mov  r9d, 5                         ; timeout
14042FB05  lea  r8,  [rbp - 9]
14042FB09  lea  rdx, [rbp - 0x29]
14042FB0D  mov  rcx, qword ptr [r10]
14042FB10  call 0x140423B50
```

```text
app+0x238  fn      = 0x140430800
           timeout = 5 ms
           flag    = 1
app+0x228  fn      = (body 0x1404305D0)
           timeout = 500 ms
```

`0x14042FD80` is **not** the `app+0x238` callable. That hypothesis is disproven
by the `lea` at `0x14042FA9D`. `0x14042FD80` remains an unplaced closure body.

### What the factory stores, and what that means for the gate fields

`0x1404595E0` allocates `0x78` bytes and writes the operation's fields:

```asm
14045967A  mov dword ptr [rdi + 0x28], ebp   ; timeout
140459685  mov byte ptr  [rdi + 0x2c], al    ; the [rsp+0x20] flag
140459688  mov byte ptr  [rdi + 0x2d], 0     ; FINISHED := 0
14045968C  lea rbx, [rdi + 0x30]
1404596C5  mov qword ptr [rbx], rax          ; the callable
```

That explains every previously measured value without further assumptions:

```text
+0x28 = 5     the timeout given to the factory
+0x2C = 1     the flag argument both registrations pass as [rsp+0x20] = 1
+0x2D = 0     the constructor's own initialisation
```

The branch in `0x140423DD0` that tests `+0x2C` is therefore testing a
**registration-time flag**, not a runtime mode switch that some other subsystem
flips. The earlier phrase "wait-mode selector" was a description of the branch,
not of the value's origin; the origin is now known and the value is constant
because nothing re-registers the operation with a different flag.

### Method correction: closure bodies are heap-materialised

Runtime evidence recorded `[operation+0x00] = 0x1414B6761`. That value is not in
the image. Scans for the 8-byte values of `0x140430800`, `0x1404305D0`,
`0x14042FD80`, `0x1404245F0` and `0x140423DD0` return zero hits each, and the
file contents at `0x1414B6760` are four ordinary image functions
(`0x140433C90`, `0x1403C1B20`, `0x140433D20`, `0x140433DB0`), not the runtime
table's contents.

So the dispatch table is copied into heap storage at runtime, and **no raw
8-byte pointer scan can ever find a closure's registration site here.** The only
method that works is to find the `lea rax, [rip+...]` that materialises the
address into a stack slot immediately before a call to the factory `0x140423B50`
— which is how both registrations above were resolved. Earlier passes that
searched for image pointers were searching for something that cannot exist.

### What is still unknown

```text
app+0x238 fn = 0x140430800                      CONFIRMED
app+0x238 timeout = 5 ms, flag = 1              CONFIRMED
app+0x228 fn body = 0x1404305D0, timeout 500 ms CONFIRMED
+0x28/+0x2C/+0x2D origins                       CONFIRMED
0x14042FD80 is the app+0x238 callable           DISPROVEN
what 0x140430800 does                            UNKNOWN (not yet resolved)
what cancels or clears app+0x238                 UNKNOWN
0x1404245F0 registration site                    UNKNOWN
whether 0x1404245F0 is the app+0x238 callable    UNKNOWN
```

The last line is the key open item, and it is now testable: `0x1404245F0` is
**not** `0x140430800`, so if the historical teardown really is invoked by the
operation machinery, `0x1404245F0` must be reached from inside `0x140430800` or
bound into a different operation. Resolving `0x140430800` is the shortest path
to that answer.

**No server behaviour was changed and D4 was not sent.**

---

## Evidence corrections from the callable-layout reconstruction (September 13)

Three canonical descriptions predate the byte-for-byte registration
reconstruction and are now wrong. They are corrected here so the notebook keeps
the provenance of each mistake.

### Correction A — `0x1404305D0` is the 500 ms callable, not the 5 ms one

`CURRENT-RETAIL-STATE.md` said `0x14042F960` "arms that task with a 5 ms timeout
and a second, 500 ms timeout on the same object", which reads as one task with
two periods. The registrations are in fact two different operations with two
different callable bodies:

```text
app+0x228 -> fn 0x1404305D0, timeout 500 ms   (site 0x14042FA39, r9d=0x1F4)
app+0x238 -> fn 0x140430800, timeout   5 ms   (site 0x14042FB10, r9d=5)
```

The `app+0x238` identity is pinned by `0x14042FA9D lea rax,[rip+0xd5c]`, which
materialises `0x140430800`. Describing `0x1404305D0` as "the 5 ms closure" is
`SUPERSEDED`.

### Correction B — `operation+0x2C` is a registration-time flag

Earlier text called `+0x2C` a "wait-mode selector". That named the field after
one of its readers. The origin is now proven:

```asm
14042FA23  mov  byte ptr [rsp + 0x20], 1      ; registration A
14042FAFA  mov  byte ptr [rsp + 0x20], 1      ; registration B
140459685  mov  byte ptr [rdi + 0x2c], al     ; factory stores it
```

So the field carries the flag argument supplied at registration. Both known
registrations pass `1`, which is why the value measured at runtime was a
constant `1` and why no writer was ever observed changing it during the loop —
there is nothing to observe. Whether the flag's *meaning* is "this operation
waits" is `HYPOTHESIS`; the dataflow is `CONFIRMED`.

### Correction C — `operation+0x30` / `+0x38` are the callable and its context

Earlier text annotated:

```text
lea rdx, [rsi+0x38]      ; result slot
mov rcx, [rsi+0x30]      ; owner-visible context
```

The factory reconstruction shows `0x14045968C lea rbx,[rdi+0x30]` followed by
`0x1404596C5 mov qword ptr [rbx], rax` storing the object returned by the
callable builder `0x1402CB8D0`. `+0x30` is therefore the **stored callable**, and
`+0x38` is its **context/subfield**, not a result slot and not an owner-visible
context. Both old labels are `SUPERSEDED`.

Consequently the label `0x140424860 = "publish/signal helper"` loses its
support: it was inferred from those same two argument positions. It is demoted
to `HYPOTHESIS` until `0x140424860` is reversed on its own terms.

### What is unaffected

`target+0x2D` as the FINISHED byte, written only at `0x140423B15`, is unaffected
— that conclusion never depended on the `+0x30`/`+0x38` labels. The claim that
`+0x2C` selects between the two arms of `0x140423DD0` also stands as a statement
about the branch; only the field's *name* is withdrawn.

---

## `0x140430800`, the 5 ms callable, is a list-steal-and-destroy leaf (September 13)

### The body

`0x140430800` is a 51-byte self-contained function: `.pdata` extends
`0x140430800`–`0x140430833`, and a full-image scan of every `call`/`jmp` operand
finds **no branch anywhere targeting the function or its interior**. It is
reached only as a callback. Full body:

```asm
140430800  mov  qword ptr [rsp+0x18], rsi
140430805  push rdi
140430806  sub  rsp, 0x20
14043080A  prefetchw byte ptr [rcx+0x260]
140430811  xor  esi, esi
140430813  mov  rdi, qword ptr [rcx+0x260]          ; retry label
14043081A  mov  rax, rdi
14043081D  lock cmpxchg qword ptr [rcx+0x260], rsi   ; atomically take the list
140430826  jne  0x140430813
140430828  test rdi, rdi
14043082B  je   0x140430874
14043082D  add  rdi, -0x30
140430831  je   0x140430874
140430833  mov  qword ptr [rsp+0x38], rbx
140430840  mov  rbx, qword ptr [rdi+0x30]            ; next link
140430844  xor  r8d, r8d
140430847  mov  rcx, rdi
14043084A  call 0x14043B5D0                          ; per-element teardown
14043084F  mov  rax, qword ptr [rdi]
140430852  mov  rcx, rdi
140430855  mov  rax, qword ptr [rax+0x30]            ; element vtable+0x30
140430859  call qword ptr [rip+0xf3a461]             ; via thunk 0x14136ACC0
14043085F  test rbx, rbx
140430862  lea  rdi, [rbx-0x30]
140430866  cmove rdi, rsi
14043086A  test rdi, rdi
14043086D  jne  0x140430840
14043086F  mov  rbx, qword ptr [rsp+0x38]
140430874  mov  rsi, qword ptr [rsp+0x40]
140430879  add  rsp, 0x20
14043087D  pop  rdi
14043087E  ret                                       ; epilogue shared with 0x140430833
```

Semantics:

```text
atomically detach the intrusive singly-linked list at boundobj+0x260 (→ NULL),
then for each element:
    teardown_element(element, 0)          # 0x14043B5D0
    (*element->vtable[0x30])(element)     # virtual destructor
```

The `-0x30` / `+0x30` pair is the standard MSVC intrusive-list idiom: the link is
embedded at offset `0x30` of the element, so the stored node pointer is
`&element->link` and the element base is `link - 0x30`.

### It is a leaf, and it does not reach the historical teardown

```text
direct callees    = 0x14043B5D0 only
indirect callees  = element vtable+0x30 only
0x140430800 -> 0x1404245F0 = NO
```

There is no path from `0x140430800` to `0x1404245F0`, `0x140434430`,
`0x14040AEC0` or the Close producer. The historical runtime chain therefore does
**not** pass through this callable, and the earlier hypothesis that
`0x1404245F0` might be reached from inside the 5 ms callable is refuted for this
callable.

### It does not rearm itself

Nothing in the body reschedules, re-registers or re-arms anything. It steals a
list, destroys it, and returns. Whether the surrounding framework re-arms the
operation is a separate question and is `UNKNOWN`; the callable itself is
one-shot.

### Naming note

`0x140430800` is "the 5 ms callable" in the sense that it is what the 5 ms
registration binds — not in the sense that it runs every 5 ms. The previous
pass's phrase "the 5 ms closure that reaches 0x140423DD0" conflated the two and
is `SUPERSEDED`: this function is a teardown of an intrusive list, not a polling
loop, and it does not reach `0x140423DD0` either.

### Updated open list

```text
0x140430800 complete body                      CONFIRMED
0x140430800 -> 0x1404245F0                      DISPROVEN (leaf)
0x140430800 rearms itself                       DISPROVEN
which operation reaches 0x140423DD0             UNKNOWN
what wires 0x140430800's list (boundobj+0x260)  UNKNOWN
0x1404245F0 registration site                   UNKNOWN
0x140424860 semantics                           UNKNOWN (label withdrawn)
"connection"/"signature" effects                UNKNOWN
```

**No server behaviour was changed and D4 was not sent.**

---

## CORRECTION: two overclaims about `0x140430800` (September 13)

### Correction A — the function extent, and why "51-byte leaf" was wrong

The previous section stated both of these at once:

```text
0x140430800 is a 51-byte self-contained leaf
.pdata extent 0x140430800-0x140430833
```

and then printed a body that continues past `0x140430833` and ends at
`0x14043087E ret`. Those two statements cannot both hold. The second is right.

Reading the exception directory directly gives three consecutive records:

```text
Begin 0x140430800  End 0x140430833  UnwindInfo 0x14178AB18  flags=0x0A
Begin 0x140430833  End 0x140430874  UnwindInfo 0x14184B350  flags=0x05
Begin 0x140430874  End 0x14043087F  UnwindInfo 0x14184B364  flags=0x00
```

`flags=0x05` on the middle record is `UNW_FLAG_EHANDLER|UNW_FLAG_CHAININFO` with
`UNW_FLAG_CHAININFO` set — the bit value 4. The middle record is a **chained
unwind fragment of the same function**, not a separate function. The logical
function is `0x140430800`–`0x14043087F` (127 bytes) with a shared epilogue at
`0x140430874`.

The error came from treating every `.pdata` record as a function boundary. In
this image chained records are common, so any tool that enumerates
`RUNTIME_FUNCTION` entries as functions (including `funcs.py` in this
repository's scratch helpers) will report a single function as two or three.
Function extents derived that way must have the chain flag checked first. That
is a tool-usage correction, not a new fact about the binary.

Terminology corrected: `0x140430800` is **not** a leaf. It issues a direct call
and an indirect call per element. A precise description is *a short non-leaf
routine that drains an intrusive list*.

### Correction B — "no path to `0x1404245F0`" was not established

The previous section concluded:

```text
0x140430800 -> 0x1404245F0 = NO
```

and described the two functions as unrelated. What the disassembly actually
supports is narrower:

```text
DIRECT edge 0x140430800 -> 0x1404245F0      DISPROVEN
TRANSITIVE relationship                     UNKNOWN
```

`0x140430800` calls `0x14043B5D0` and one indirect target, `element vtable+0x30`.
Neither callee was resolved. A transitive path could in principle run through
either, and the historical chain was observed with wrapper frames that a static
call graph does not show. Equating "no direct call" with "no path" is the same
class of error as the retracted `0x1403FC050 -> 0x1404245F0` edge in reverse:
this time inferring absence rather than presence from insufficient resolution.

The same correction applies to `0x140434430`:

```text
DIRECT edge 0x140430800 -> 0x140434430      not present in the body
TRANSITIVE relationship                     UNKNOWN
```

### Terminology also corrected

Two labels were assigned from call position and are withdrawn to `HYPOTHESIS`:

```text
0x14043B5D0          "per-element teardown"      HYPOTHESIS
element vtable+0x30  "virtual destructor"        HYPOTHESIS
```

Neither callee body had been read when the labels were written. They must be
resolved before either name is used again.

### What still stands from the previous section

```text
0x140430800 body (127 bytes, three chained unwind records)   CONFIRMED
it atomically steals the list at boundobj+0x260 with CAS      CONFIRMED
link embedded at element+0x30, base = link-0x30               CONFIRMED
exactly two calls per element                                 CONFIRMED
it does not rearm itself                                      CONFIRMED
callee semantics                                              UNKNOWN
transitive reachability to the historical chain               UNKNOWN
```

---

## `boundobj+0x260` is a deferred-destruction stack, and the 5 ms callable drains it (September 13)

### The bound object, proven by RTTI

The 5 ms registration binds `rdi` from `0x14042F960`. The constructor at
`0x1404292E0` installs `0x1414B6798` at `[rcx]`, and `0x1414B6798 - 8` is a COL
(signature 1, moffset 0) whose type descriptor reads:

```text
.?AVObjectManagerImpl@omega@@
```

```text
bound object = omega::ObjectManagerImpl      COL 0x141702418
allocated by 0x140405F20 (0x360 bytes), built by ctor 0x1404292E0
```

The same constructor zeroes `+0x220`, `+0x228`, `+0x238`, `+0x248` and `+0x260`,
and sets `+0x258 = 1`. That is why the poller-tile fields and the object-manager
fields had been conflated: they belong to this one class, not to the application
object.

### The producer, and what its return value means

`0x140406530` is the push:

```asm
140406540  mov  rdi, qword ptr [rcx + 8]      ; rdi = ObjectManagerImpl
140406547  mov  rax, qword ptr [rax + 0x28]   ; virtual call on the retired obj
14040654B  call qword ptr [rip + 0xf6476f]
140406551  add  rbx, 0x30                     ; node = obj + 0x30
140406555  prefetchw byte ptr [rdi + 0x260]
140406560  mov  rcx, qword ptr [rdi + 0x260]  ; CAS retry
140406567  mov  qword ptr [rbx], rcx          ; node->next = head
14040656D  lock cmpxchg qword ptr [rdi + 0x260], rbx
140406576  jne  0x140406560
14040657D  test rcx, rcx
140406580  sete al                           ; returns (old_head == NULL)
```

The `sete al` is the interesting part. The push reports **whether the stack was
empty before this element**, which is exactly the condition a caller needs to
decide "I am the first retirement, so a drain must be scheduled". The consumer
`0x140430800` is the mirror image: one `lock cmpxchg` of the head to `NULL`, then
a walk of the stolen list via `element+0x30`.

```text
boundobj+0x260 = lock-free LIFO stack of objects awaiting destruction
intrusive link embedded at element+0x30, element base = node-0x30
```

### At least two manager instances share the idiom

`0x14043A390` performs the same `lock cmpxchg` on `+0x260` but pairs it with a
*different* queue at `+0x168`/`+0x164` on another instance, and re-installs a
vtable of its own at `0x1414B69A8`. So the deferred-destroy stack is a reusable
idiom in this object manager family, not a one-off. How many instances exist is
`UNKNOWN`.

### Terminology retracted

```text
0x14043B5D0                       "per-element teardown"   HYPOTHESIS
element vtable+0x30               "virtual destructor"     HYPOTHESIS
```

`0x14043B5D0` has a full prologue and takes a critical section at
`[rcx+0x80]+0x10`; it is an ordinary image function whose body has only been
read at its head. The `vtable+0x30` slot is called by both
`0x140430800` and `0x14043A390` on retiring objects, and `0x14043A390` also
calls `vtable+0x28` and `vtable+0x00`; which of these is a destructor, a release,
or a detach is not established.

### The 5 ms period is a drain deadline, not a poll interval

`0x140430800` contains no polling whatsoever — no state test, no comparison, no
periodic re-evaluation. It steals a batch and destroys it. Combined with the
producer's "was the stack empty" return, the natural reading is a **coalescing
window**: the first retirement arms the timer, later retirements accumulate, and
one drain pass collects the batch. The callable does not rearm itself
(`CONFIRMED`), so the periodicity must come from the framework or from each new
first-push.

This replaces the earlier framing of the 5 ms operation as a connection-state
poller. It was never polling anything.

### What this does and does not establish about the historical chain

```text
boundobj = omega::ObjectManagerImpl                    CONFIRMED
boundobj+0x260 is a deferred-destruction LIFO stack    CONFIRMED
producer 0x140406530, push with link at element+0x30   CONFIRMED
consumer 0x140430800 drains it                         CONFIRMED
5 ms is a coalescing drain deadline                    HYPOTHESIS
element concrete class(es)                             UNKNOWN
0x14043B5D0 semantics                                  UNKNOWN
element vtable+0x00/+0x28/+0x30 semantics              UNKNOWN
transitive path to 0x1404245F0 or 0x140434430          UNKNOWN
```

The last line is unchanged from the previous correction and was not resolved
here. What *has* changed is that the elements are now known to be objects being
**retired for destruction** by an object manager, which makes a connection to
connection/route teardown plausible but still unproven.

**No server behaviour was changed and D4 was not sent.**

## The `+0x260` elements are `omega::PacketSocket` (September 13)

This pass was asked to identify what object is retired onto
`ObjectManagerImpl+0x260` and why. It resolved the element class and both virtual
slots the producer and the drain invoke, and in doing so corrected two labels
carried by the previous checkpoint.

### Terminology retraction from the previous checkpoint

```text
"+0x260 is a deferred-destruction stack of objects awaiting destruction"
    -> was stronger than the evidence at the time: 0x14043B5D0 and both
       virtual slots were UNKNOWN
    -> replaced by "deferred-retirement stack" until destruction semantics
       were proved (they now have been, see below)

"5 ms coalescing window" -> remains HYPOTHESIS
```

The specific claim that the producer's `sete al` arms the drain is retracted
outright; see "the producer's AL is discarded".

### Method and tooling

A read-only static toolkit was written for this image (`tools/retail-re-toolkit.py`,
`tools/resolve-indirect.py`, `tools/callgraph.py`). Three findings about the
image itself were needed before any of the analysis below was trustworthy, and
each of them had produced plausible-looking nonsense beforehand:

1. **VA -> file offset must include the section `VirtualAddress`.**
   `file_off = PointerToRawData + (va - (ImageBase + VirtualAddress))`. `.text`
   here is VA `0x1000` / raw `0x400`, `.rdata` `0x1369000` / `0x1367a00`,
   `.data` `0x1a8c000` / `0x1a8aa00`. Using `va - ImageBase` silently reads the
   wrong bytes.

2. **`.pdata` holds several `RUNTIME_FUNCTION` entries per `BeginAddress`**
   (chained unwind info). The function extent is the **maximum** `EndAddress`
   over those entries, not the first. Taking the first truncates functions and
   splits them into apparently separate regions. `.pdata` boundaries are
   required for correct disassembly: a flat sweep of `.text` desynchronises and
   loses real call sites.

3. **The IAT is loader-filled; the on-disk dword is a stale RVA, not a
   pointer.** For example the `MemoryMan.dll!mm_alloc` slot `0x141369DF8` holds
   `0x1A86414` on disk, which is an RVA into the allocator name table, not an
   address. Reading it as a 64-bit pointer yields a nonexistent address. Import
   identity must come from the import descriptors.

With those fixed, xref completeness was established by disassembling every
`.pdata` function from its own entry point:

```text
callers of 0x140406530 (the producer) = exactly 2
    0x14043B53D  in 0x14043B460 - 0x14043B5C6
    0x14043E045  in 0x14043DE10 - 0x14043E091
```

This confirms the previous report's list is complete across the image — there
are no additional direct callers, and no third caller was found.

### The producer and consumer, byte-for-byte

Producer `0x140406530`, fn `0x140406530 - 0x140406589` (59 bytes). The full body:

```asm
140406530  mov  qword ptr [rsp + 0x10], rbx
140406535  push rdi
140406536  sub  rsp, 0x20
14040653a  mov  rax, qword ptr [rdx]            ; rax = element->vtable
14040653d  mov  rbx, rdx                        ; rbx = element
140406540  mov  rdi, qword ptr [rcx + 8]        ; rdi = manager
140406544  mov  rcx, rdx                        ; rcx = element (this for the virt)
140406547  mov  rax, qword ptr [rax + 0x28]     ; element->vtable[0x28]
14040654b  call qword ptr [rip + 0xf6476f]      ; -> 0x14043DB20
140406551  add  rbx, 0x30                       ; node = element + 0x30
140406555  prefetchw byte ptr [rdi + 0x260]
140406560  mov  rcx, qword ptr [rdi + 0x260]    ; <-- CAS retry label
140406567  mov  qword ptr [rbx], rcx            ; node->next = head
14040656a  mov  rax, rcx
14040656d  lock cmpxchg qword ptr [rdi + 0x260], rbx
140406576  jne  0x140406560
140406578  mov  rbx, qword ptr [rsp + 0x38]
14040657d  test rcx, rcx
140406580  sete al                             ; al = (old_head == NULL)
140406583  add  rsp, 0x20
140406587  pop  rdi
140406588  ret
```

```c
// rcx = manager, rdx = element
bool retire(void* manager, void* element) {
    void* mgr = *(void**)(manager + 8);
    element->vtable[0x28](element);            // 0x14043DB20
    Node* node = (Node*)((char*)element + 0x30);
    Node* old;
    do {
        old = *(Node**)((char*)mgr + 0x260);
        node->next = old;
    } while (!CAS((Node**)((char*)mgr + 0x260), old, node));
    return old == NULL;
}
```

Consumer `0x140430800`, fn `0x140430800 - 0x140430833` (33 bytes), extended to
`0x14043087F` to include the walk:

```asm
140430800  mov  qword ptr [rsp + 0x18], rsi
140430805  push rdi
140430806  sub  rsp, 0x20
14043080a  prefetchw byte ptr [rcx + 0x260]
140430811  xor  esi, esi
140430813  mov  rdi, qword ptr [rcx + 0x260]    ; <-- CAS retry label
14043081a  mov  rax, rdi
14043081d  lock cmpxchg qword ptr [rcx + 0x260], rsi   ; head := NULL
140430826  jne  0x140430813
140430828  test rdi, rdi
14043082b  je   0x140430874
14043082d  add  rdi, -0x30                      ; element = node - 0x30
140430831  je   0x140430874
140430833  mov  qword ptr [rsp + 0x38], rbx
140430840  mov  rbx, qword ptr [rdi + 0x30]     ; next = element->[0x30]
140430844  xor  r8d, r8d                        ; r8d = 0
140430847  mov  rcx, rdi                        ; rcx = element
14043084a  call 0x14043b5d0                     ; per-pass flush
14043084f  mov  rax, qword ptr [rdi]            ; element->vtable
140430852  mov  rcx, rdi
140430855  mov  rax, qword ptr [rax + 0x30]     ; element->vtable[0x30]
140430859  call qword ptr [rip + 0xf3a461]      ; -> 0x14043DBF0
14043085f  test rbx, rbx
140430862  lea  rdi, [rbx - 0x30]
140430866  cmove rdi, rsi
14043086a  test rdi, rdi
14043086d  jne  0x140430840
14043086f  mov  rbx, qword ptr [rsp + 0x38]
140430874  mov  rsi, qword ptr [rsp + 0x40]
140430879  add  rsp, 0x20
14043087d  pop  rdi
14043087e  ret
```

```c
// rcx = manager
void drain(void* manager) {
    Node* head;
    do { head = *(Node**)((char*)manager + 0x260); }
    while (!CAS((Node**)((char*)manager + 0x260), head, NULL));
    if (!head) return;
    void* element = (char*)head - 0x30;
    while (element) {
        Node* next = *(Node**)((char*)element + 0x30);
        flush(element, /*reset=*/0);            // 0x14043B5D0, r8d = 0
        element->vtable[0x30](element);         // 0x14043DBF0
        element = next ? (char*)next - 0x30 : NULL;
    }
}
```

### Caller A, `0x14043B460` (166 bytes)

Containing function boundaries: `0x14043B460 - 0x14043B5C6`. It is a method of
`omega::PacketSocket` (`rbx` is `this`; it drives `[rbx+0x168]`, `[rbx+0x164]`,
`[rbx+0x170]`, `[rbx+0x180]`). Reconstructed control flow:

```c
// this = rcx (PacketSocket), arg2 = rdx (a PacketSocket), arg3 = r8,
// arg4 = r9d
if (0x140414BD0(this) != 4) goto epilogue;      // state gate

rec = mm_alloc(0x20);                            // 0x14043B499/0x14043B4A8
if (!rec) { throw std::bad_alloc(); }            // 0x14043B593 path

// pull a reference out of arg2: *arg2 is an intrusive_ptr
// (*arg2)->vtable[0x28] is invoked (a virtual on the referenced object)
// and the result is moved into a 0x20-byte local record
ctx = { *arg2 };
if (ctx) ctx->vtable[0x28](ctx);

rec = 0x14043F9F0(rec, &ctx, arg3, arg4);        // build the 0x20-byte record

// push rec onto *this*'s own lock-free stack at +0x168 (CAS loop)
do { old = this->[0x168]; rec->[0] = old; }
while (!CAS(&this->[0x168], old, rec));

if (old != NULL) goto charge;                    // stack was NOT empty

// stack WAS empty: retire-once gate on this, then enqueue for retirement
if (CAS(&this->[0x164], 0, 1) != 0) goto charge; // only one thread wins
{
    PacketSocket* pkt = *(PacketSocket**)(this + 0x8);   // 0x14043B52F
    void* mgr         = *(void**)(pkt + 0xD8);           // 0x14043B536
    producer(mgr, this);                                 // 0x14043B53D
}

charge:
total = atomic_add(&this->[0x170], arg3->[0x10]);
if (total >= 0x100000 && this->[0x180] == 1)
    0x14043B5D0(this, /*r8b=*/1);               // flush
```

Argument provenance at the call, traced explicitly rather than from register
names:

```text
RCX at 0x14043B53D = *(void**)(*(PacketSocket**)(this + 0x8) + 0xD8)
RDX at 0x14043B53D = this                      (the PacketSocket itself)
RBX / object ultimately queued = this
manager = the producer re-reads [rcx+8] internally, so the object reaching
          the CAS at +0x260 is *this*
```

### Caller B, `0x14043DE10` (281 bytes)

Containing function boundaries: `0x14043DE10 - 0x14043E091`. It is the twin of
caller A with the same three-instruction call sequence and the same gate, but a
different trigger condition:

```asm
; caller A  0x14043B52F .. 0x14043B53D
14043B52F  mov  rcx, qword ptr [rax + 0xD8]
14043B533  mov  rdx, rbx
14043B53D  call 0x140406530

; caller B  0x14043E037 .. 0x14043E045
14043E037  mov  rax, qword ptr [rdi + 8]
14043E03E  mov  rcx, qword ptr [rax + 0xD8]
14043E045  call 0x140406530
```

In caller B (`rdi` = the socket object) the surrounding logic is:

```c
if (0x140414BD0(rdi) != 4) goto out;
if (rdi->[0x98] != 0) goto other;               // already in this state?
rdi->[0x98] = 1;
if (CAS(&rdi->[0x164], 0, 1) != 0) goto out;    // retire-once gate
{
    void* pkt = *(void**)(rdi + 8);
    void* mgr = *(void**)(pkt + 0xD8);
    producer(mgr, rdi);                          // 0x14043E045
}
out:
(*rdi->[0x40])->vtable[0x118](rdi->[0x40], arg2);   // 0x14043E04A
```

Both callers therefore retire the *same* thing: the object that reached state
`4`, whose `[+0x98]` discriminator selects a one-shot transition, gated by the
same `cmpxchg dword ptr [obj+0x164], 1`. **Same concrete class, not different
subclasses.**

```text
caller A 0x14043B53D  queued object = this (PacketSocket), gated on the
                      [+0x168] stack transitioning empty -> non-empty
caller B 0x14043E045  queued object = rdi (the same class), gated on
                      [+0x98]==0 -> 1 and the same [+0x164] CAS
```

### All callers of `0x140406530` (completeness check)

```text
| call site  | containing function      | queued-object provenance        | AL=1 path |
| ---------- | ------------------------ | ------------------------------- | --------- |
| 0x14043B53D | 0x14043B460-0x14043B5C6 | this (PacketSocket), reached    | none —    |
|            |                          | via *(void**)(*(void**)(this+8) | al is     |
|            |                          | +0xD8) as the manager argument  | discarded |
| 0x14043E045 | 0x14043DE10-0x14043E091 | rdi (same class), reached via   | none —    |
|            |                          | *(void**)(*(void**)(rdi+8)      | al is     |
|            |                          | +0xD8) as the manager argument  | discarded |
```

Exactly two call sites exist in the image. The search was an exhaustive scan of
every `.pdata` function entry followed by direct-call target matching, so a third
caller would have been found; none exists. No inline or sibling CAS push onto
`ObjectManagerImpl+0x260` was found elsewhere either. A full census of
`cmpxchg [reg+0x260]` across every `.pdata` function returns exactly four sites,
in three functions:

```text
14040656D  fn 140406530   the push (this queue)
14043081D  fn 140430800   the steal-all drain of this queue
14043A3FA  fn 14043A390   PacketSocket's own +0x260 queue (steal-all)
14043A44A  fn 14043A390   PacketSocket's own +0x260 queue (push)
```

### The producer's `AL` is discarded — the "arming signal" reading is retracted

`0x140406530` ends:

```asm
14040657D  test rcx, rcx
140406580  sete al                    ; al = (old_head == NULL)
140406588  ret
```

So the *value* `(old_head == NULL)` is `CONFIRMED`. What is **not** true is that
any caller uses it:

```text
caller A  0x14043B542  mov eax, dword ptr [rbp+0x10]   ; eax clobbered at once
caller B  0x14043E04A  mov rcx, qword ptr [rdi+0x40]   ; no test/jcc on al
```

```text
producer returns (old_head == NULL)      CONFIRMED (as a value)
any caller branches on AL                DISPROVEN
AL=1 path / AL=0 path                    DO NOT EXIST
"sete al is the arming signal"           RETRACTED
```

The behaviour the "arming" theory was trying to explain is real, but it lives in
the callers' own gate: a per-object retire-once flag at `[obj+0x164]` written by
`lock cmpxchg` `0 -> 1`, entered only when the push onto the object's own
`+0x168` stack found that stack empty. The relevant instruction census:

```text
14043A1F8  mov  dword ptr [rdi+0x164], ebp        fn 140439FE0  PacketSocket ctor
14043A3C7  lock cmpxchg dword ptr [rcx+0x164]     fn 14043A390  PacketSocket cleanup
14043B525  lock cmpxchg dword ptr [rbx+0x164]     fn 14043B460  caller A
14043B62A  lock cmpxchg dword ptr [rsi+0x164]     fn 14043B5D0  reset (r8b=0 path)
14043E02C  lock cmpxchg dword ptr [rdi+0x164]     fn 14043DE10  caller B
```

### The queue element is `omega::PacketSocket`

Two independent lines of evidence, both from RTTI and vtable bytes.

**(a) The only `LocklessListNode` instantiation in the image is
`LocklessListNode<PacketSocket>`.** Its link sits at class offset `0x30`, which
is precisely the intrusive link offset the producer writes (`add rbx, 0x30`) and
the drain walks (`add rdi, -0x30` to recover the element base). The class
hierarchy for `omega::PacketSocket` (COL `0x141702F08`, TD `0x141B65D70`) is:

```text
.?AVPacketSocket@omega@@
.?AVComponent@omega@@
.?AVComponentConsumer@omega@@
.?AVBufferedSocketObserver@omega@@
.?AVInterface@omega@@
.?AV?$LocklessListNode@VPacketSocket@omega@@@omega@@
.?AVLocklessListNodeImpl@detail@omega@@
```

**(b) The primary `PacketSocket` vtable has concrete functions at exactly the two
slots the lifecycle invokes.** The previous checkpoint had looked at vtable
`0x1414B69A8` and found those slots unresolved. That vtable is a *secondary*
vtable — the `Component` sub-object vtable embedded inside a `PacketSocket` —
whose unresolved slots are `_purecall`. The primary vtable is `0x1414B6968`:

```text
omega::PacketSocket primary vtable 0x1414B6968
  [+00] 140ff9700  _purecall
  [+08] 140ff9700  _purecall
  [+10] 14043d870
  [+18] 14043d9e0
  [+20] 14043da80
  [+28] 14043DB20   <-- invoked by the producer before enqueueing
  [+30] 14043DBF0   <-- invoked by the drain on every drained element
  [+38] 141702f30   COL pointer of the secondary vtable
  [+40] 14043fa70   scalar deleting destructor
```

```text
element class        = omega::PacketSocket                 CONFIRMED
primary vtable       = 0x1414B6968                         CONFIRMED
COL                  = 0x141702F08  (self-pointer verified) CONFIRMED
type descriptor      = 0x141B65D70                         CONFIRMED
allocation           = 0x1F8 bytes; freed via MemoryMan mm_free with
                       edx=0x1F8 in the scalar deleting dtor CONFIRMED
constructor          = 0x140439FE0                         CONFIRMED
```

Element size is `0x1F8`, seen directly in the scalar deleting destructor
`0x14043FA70` (reached through `vtable+0x00`):

```asm
14043fa89  mov  edx, 0x1f8
14043fa91  call 0x140fd7090     ; this-bound delete thunk
                                 ; -> jmp 0x14008CE90
14008cea2  mov  rax, qword ptr [rip + 0x12dcf57]   ; MemoryMan
14008ceac  call qword ptr [rip + 0x12dde0e]        ; mm_free(ptr, 0x1F8)
```

### `vtable+0x28` at producer time — `0x14043DB20`

`0x140406530` invokes the retired object's `vtable+0x28` *before* the CAS push:

```asm
14040653a  mov  rax, qword ptr [rdx]        ; rax = element->vtable
140406547  mov  rax, qword ptr [rax + 0x28] ; slot 5 of the primary vtable
14040654b  call qword ptr [rip + 0xf6476f]  ; -> 0x14043DB20
```

Target and semantics:

```text
vtable+0x28 target = 0x14043DB20 (fn 0x14043DB20 - 0x14043DBE3)
inputs             = rcx = element, rdx = a second object (the argument's
                     [+0x28] is invoked on)
locks              = EnterCriticalSection([rcx+0x58]+0x10) / LeaveCriticalSection
state reads        = [rcx+0x50], [rcx+0x14C], [rcx+0x198], [rcx+0x1B0]
branch             = 0x140414BD0(rcx-0x28) must equal 4, else return early
effects            = cmpxchg dword ptr [rcx+0x14C], 0  (a one-shot release
                     gate); on success and when [+0x198]==0 and [+0x1B0]==NULL
                     calls 0x14043ADF0(rcx-0x28, 0, 0, 0)
return             = void
semantic role      = a release/detach gate on the retired object, not a
                     deallocation and not a destructor
```

It is **not** a "prepare-destroy". It does not free, does not null the vtable, and
does not decrement a count that could reach zero here; it takes the object's own
lock, tests a one-shot flag at `+0x14C`, and conditionally runs a detach routine.
Classified as `release`/`detach`.

### `vtable+0x30` at drain time — `0x14043DBF0`

`0x140430800` calls this on every drained element:

```asm
140430840  mov  rbx, qword ptr [rdi + 0x30]   ; next node
140430844  xor  r8d, r8d
140430847  mov  rcx, rdi                      ; rcx = element base
14043084a  call 0x14043b5d0                   ; per-pass flush (see below)
14043084f  mov  rax, qword ptr [rdi]          ; element->vtable
140430855  mov  rax, qword ptr [rax + 0x30]   ; slot 6 of the primary vtable
140430859  call qword ptr [rip + 0xf3a461]    ; -> 0x14043DBF0
```

Target and semantics:

```text
vtable+0x30 target = 0x14043DBF0 (fn 0x14043DBF0 - 0x14043DD6C)
inputs             = rcx = element (PacketSocket), r8d/r9d and two stack
                     bytes forwarded to 0x140436890
locks              = EnterCriticalSection([rcx+0x58]+0x10)
state reads        = 0x140414BD0(rcx-0x28) must equal 4, else return early
containers         = walks a circular doubly-linked list at [rcx+0x30]:
                     nodes have next at +0x00 and prev at +0x08, sentinel at
                     rcx+0x30, payload at node+0x28
per element        = 0x140414250(node+0x70, &local) then 0x140436890(...)
                     with the node's own vtable[0x28] invoked first
return             = void
semantic role      = a list-draining detach/clear of the element's embedded
                     node list; it does NOT free the element and does NOT call
                     the destructor
```

So the drain does **not** delete the `PacketSocket`. It hands the element to
`0x14043DBF0`, which detaches the element's own `LocklessListNode` chain. The
element's memory is released elsewhere (the scalar deleting destructor
`0x14043FA70`, reached through `vtable+0x00`, via `mm_free` with `0x1F8`).

This is why the queue reads as a **deferred-retirement** stack rather than a
"deferred-destruction" stack: the drain performs deferred *reclamation work on*
the retired socket, and destruction of the socket is a separate path.

### `0x14043B5D0` fully resolved — it is a per-pass `PacketSocket` flush

`0x14043B5D0` (fn `0x14043B5D0 - 0x14043BB68`, 598 bytes, stack frame `0x808`)
is a method of `omega::PacketSocket`, not a per-element teardown:

```text
this                = omega::PacketSocket
[rcx+0x80]          = pointer; [rcx+0x80]+0x10 = its critical section
[rcx+0x164]         = retire-once/state flag; on the r8b==0 path it does
                      lock cmpxchg dword ptr [rcx+0x164], 0   (reset)
[rcx+0x98], [rcx+0x180]
                    = state fields gating the enumeration
[rcx+0x168]         = this socket's OWN lock-free stack of 0x20-byte recording
                      nodes, stolen whole with the same CAS idiom as +0x260
r8b                 = 0 -> reset the +0x164 flag first; != 0 -> do not
r9d / stack args    = forwarded to 0x140436890
```

`r8d = 0` from `0x140430800` therefore means: *"reset the retire-once flag, then
flush"*. It is a per-*pass* flush, called once per drain pass with the manager as
`this` — not once per element.

`0x14043B5D0` is called from 5 sites image-wide:

```text
14043084a  fn 140430833-140430874   the 5 ms drain (once per pass)
14043b563  fn 14043b460-14043b5c6   caller A, on the >= 0x100000 byte path
14043c258  fn 14043bea0-14043c77d
14043d6e8  fn 14043d550-14043d78b
14043e7f2  fn 14043e3a0-14043e8cb
```

### Relationship between `0x14043B53D` and `0x14043B5D0`

The two addresses are 147 bytes apart, which invited a "paired lifecycle
functions" reading. That reading is **DISPROVEN**:

```text
0x14043B460-0x14043B5C6  caller A: a PacketSocket method that enqueues a
                          retirement onto [+0x260] and flushes on a byte
                          threshold
0x14043B5D0-0x14043BB68  0x14043B5D0: a PacketSocket method that flushes the
                          socket's own [+0x168] recording stack

caller A does call 0x14043B5D0 (at 0x14043B563), but that is caller -> flush,
not release/finalize. They are neighbours in one contiguous PacketSocket method
block, not a producer/consumer pair.
```

### The manager, re-verified

The `+0x260` root object is still `omega::ObjectManagerImpl`, verified
independently here:

```text
vtable 0x1414B6798
COL    0x141702418   signature 1, offset 0
TD     0x141B65B48   ".?AVObjectManagerImpl@omega@@"
CHD    0x141702368
bases  ObjectManagerImpl, ComponentConsumer, ListenSocketObserver, Interface
ctor   0x1404292E0   writes vtable at [rcx], [rcx+8] = owner
                      zeroes +0x220/+0x228/+0x238/+0x248/+0x260, +0x258 = 1
```

`+0x260` is written zero by that constructor at `0x14042961B`, alongside the
timer slots `+0x228`, `+0x238`, `+0x248`. The 5 ms drain registration is
`0x14042F960`, called exactly once image-wide, from `0x1404465A7` inside the
object-manager initialisation path `0x140446490 - 0x14044682D`, which is the
same function that also registers the 500 ms operation at `0x14042FA28` and the
60 s operation at `0x140446693`. Registration bytes:

```text
14042fa28  mov  r9d, 0x1f4        ; 500 ms
14042fa39  call 0x140423b50
14042fa46  lea  rcx, [rdi + 0x228]

14042fa9d  lea  rax, [rip + 0xd5c]   ; -> 0x140430800
14042faff  mov  r9d, 5               ; 5 ms
14042fb10  call 0x140423b50
14042fb1b  lea  rcx, [rdi + 0x238]
```

Because this registration happens once at manager initialisation — not on the
first retirement — the coalescing window cannot be armed by the producer's
return value. `5 ms coalescing window` therefore remains `HYPOTHESIS`, supported
only by the drain's poll-free, rearm-free body.

### Second family: `0x1414B69A8` is a `PacketSocket`, not a second manager

The previous checkpoint recorded `0x1414B69A8` as a structurally similar manager
instance. That is **WRONG**. Resolving its COL gives:

```text
vtable 0x1414B69A8
COL    0x141702F30 (self-pointer verified)
TD     0x141B65D70   ".?AVPacketSocket@omega@@"
CHD    0x141702E90
bases  PacketSocket, Component, ComponentConsumer, BufferedSocketObserver,
       Interface, LocklessListNode<PacketSocket>, LocklessListNodeImpl
```

`0x1414B69A8` is the secondary (`Component` base sub-object) vtable of a
`PacketSocket`; the vtable that follows it at `+0x30` in the object is the
primary vtable holding the same COL. `0x14043A390` — the "second idiom producer"
— is the `PacketSocket` cleanup routine reached from the deleting destructor
`0x14043FA70`, and the `+0x260` CAS loop inside it is a *different* queue: the
`PacketSocket`'s own deferral list, not `ObjectManagerImpl+0x260`.

The previous note that `0x14043A390` "pairs its `cmpxchg` on `+0x260` with a
different queue at `+0x168`/`+0x164` on another instance" is consistent with
this: `+0x260` there belongs to a `PacketSocket`, and `+0x164`/`+0x168` are that
same `PacketSocket`'s own fields.

### Relation to known object types

```text
omega::PacketSocket          the element itself                        SAME
omega::Component             base class of the element                 BASE
omega::ComponentConsumer     base class of both element and manager    BASE
omega::LocklessListNode
      <omega::PacketSocket>  base providing the +0x30 link             BASE
omega::ObjectManagerImpl     owner of the +0x260 stack                 DISTINCT
omega::SocketManager         vtable 0x1414B5CD8, COL 0x141700AB8,
                             unrelated class                            UNRELATED
CConnection / ServerProxy /
ObjectSurrogate / routed peer
                             no RTTI evidence links these to the
                             +0x260 element                                UNKNOWN
```

No evidence was found tying the retired `PacketSocket` to the historical routed
teardown, and the transitive question is unchanged:

```text
0x140430800 -> 0x1404245F0     UNKNOWN
0x140430800 -> 0x140434430     UNKNOWN
```

The drain's direct callees are fully enumerated (see the drain body above). In
its 33-byte body it calls exactly two things per element: `0x14043B5D0` and the
element's `vtable+0x30` (`0x14043DBF0`). It does **not** call the element's
`vtable+0x00` (the scalar deleting destructor) and does **not** call `mm_free`
itself, so the drain is not the element's destruction path. It does not reach
`0x1404245F0` or `0x140434430` directly, and neither was reached transitively
from `0x14043B5D0` or `0x14043DBF0` within the depth explored here.

### The retirement trigger

Both call sites are state-gated. `0x140414BD0(x)` returns a small integer state;
`4` admits retirement. In caller B the surrounding condition is explicit:

```c
if (obj->[0x98] == 0) {
    obj->[0x98] = 1;                 // 0 -> 1 transition
    if (CAS(&obj->[0x164], 0, 1))    // retire-once
        producer(*(void**)(*(void**)(obj+8) + 0xD8), obj);
}
```

```text
retirement trigger = the socket object entering state 4, with its
                     [+0x98] discriminator at 0 and its [+0x164]
                     retire-once flag still 0
condition          = 0x140414BD0(obj) == 4 && [obj+0x98] == 0 &&
                     CAS([obj+0x164], 0, 1)
caller             = 0x14043B460 (caller A) and 0x14043DE10 (caller B)
object             = the omega::PacketSocket that reached state 4
local vs peer-visible = LOCAL. Nothing in the retired object's path emits a
                     packet, mutates a route, or reaches the serializer; the
                     retirement is local bookkeeping and reclamation
```

### What this changes

```text
queue element class                          CONFIRMED  omega::PacketSocket
producer AL=1 scheduling path                DISPROVEN  (al discarded twice)
element vtable+0x28 semantics                CONFIRMED  release/detach gate
element vtable+0x30 semantics                CONFIRMED  node-list detach/clear
0x1414B69A8 is a second manager              RETRACTED  it is a PacketSocket
"+0x260 destruction stack" label             NARROWED   deferred-retirement stack
5 ms coalescing window                       HYPOTHESIS (unchanged)
transitive path to 0x1404245F0/0x140434430   UNKNOWN    (unchanged)
```

This is stop condition 1 (concrete queue element class proven) together with
stop conditions 4 and 5 (`vtable+0x28` and `vtable+0x30` semantics proven), so
the pass stopped here rather than continuing into the next boundary.

**No breakpoint was placed, no witness was taken, no server behaviour was
changed, and D4 was not sent.**

## Correction: `+0x260` is a deferred PacketSocket service queue, not a retirement queue (September 13)

This notebook previously recorded, as current fact, that `ObjectManagerImpl+0x260`
is a "deferred-destruction stack" and then, once the element class was resolved, a
"deferred-retirement / deferred-reclamation stack" of objects being retired for
destruction.

**That interpretation is now `SUPERSEDED`.** It is preserved rather than deleted,
because it was a reasonable reading of the evidence available at the time. It is
no longer current fact.

```text
SUPERSEDED  +0x260 = objects being retired / reclaimed / destroyed
CURRENT     +0x260 = a work list of omega::PacketSocket objects with outstanding
                     deferred service work; the 5 ms drain hands them to the
                     transmit path and does not free them
```

Three facts overturn the retirement reading:

1. **Both per-element calls in the drain take the element as their receiver.**
   The drain does `add rdi, -0x30` to recover the element base and then
   `mov rcx, rdi` before *each* of the two calls. An earlier report in this
   notebook said `0x14043B5D0` is called "with the manager as `this`"; that was
   **wrong** and is retracted.

2. **`0x14043B5D0` is a transmit/flush, not a teardown.** Fully reversed, it
   steals `PacketSocket+0x168`, subtracts the record byte counts from
   `PacketSocket+0x170`, and hands the batch to `0x140452360`, which runs a
   quota/backpressure check and pushes the records into a deque-like container
   for an upward virtual hand-off.

3. **No free occurs on the path.** The drain's whole 33-byte body calls exactly
   two things per element: `0x14043B5D0` and `element->vtable+0x30`. Neither
   reaches the scalar deleting destructor `0x14043FA70` or `mm_free`. The
   socket's real deletion is a separate path.

The service machinery is also **message-type agnostic**: the function that queues
a socket onto `+0x260` (`0x14043B460`) has six call sites with one shape and
different 32-bit message ids, and one of them is the confirmed Close verb
`0x1404123D0`.

```text
+0x260 queue semantics            = deferred PacketSocket service
0x14043B5D0 classification        = SEND/FLUSH
"retirement" / "reclamation"      = SUPERSEDED
"0x14043B5D0 this = manager"      = RETRACTED (this = the PacketSocket element)
PacketSocket state enum names     = UNKNOWN (4 and 7 are both "sendable")
```

**No server behaviour was changed and D4 was not sent.**

## The 5 ms drain is a deferred PacketSocket service pass, and Close rides it (September 13)

`0x14043B5D0` was fully reversed this pass. It is a **transmit/flush** on the
`PacketSocket`, which closes the question of what the `+0x260` machinery is for.

### `0x14043B5D0` — complete semantic pseudocode

```c
// rcx = this = omega::PacketSocket, dl/r8b = mode (0 = service pass, 1 = threshold)
void PacketSocket::service(bool mode) {
    EnterCriticalSection(&this->[0x80]->cs_at_0x10);

    if (mode == 0)
        lock cmpxchg(&this->[0x164], 1, 0);      // clear outstanding-work gate

    if (this->[0x180] != 1) goto epilogue;        // service only if enabled

    // scratch: 0x100-byte inline buffer + vector header (0x1400b77c0 / 0x1400c0040)
    init_scratch(&scratch);

    if (this->[0x98] == 1)
        0x14043C780(this, &scratch);              // append one extra record

    // steal the socket's whole record stack
    Node* rec;
    do { rec = this->[0x168]; } while (!CAS(&this->[0x168], rec, NULL));

    if (rec == NULL && extra == NULL) goto epilogue;

    if (0x140414BD0(this) != 4) goto epilogue;    // socket state gate
    if (this->[0x38] == NULL)   goto epilogue;

    // count records and drain the queued byte total
    int n = 0;
    for (Node* p = rec; p; p = p->next) {
        n++;
        lock xadd(&this->[0x170], -(int)p->record->len);   // ecx = -len
    }
    int total = (extra ? n + 1 : n);

    // pointer + length arrays; heap when total > 0x64, else inline stack arrays
    Record** ptrs = (total > 0x64) ? mm_alloc(8*total) : stack_ptrs;
    int*     lens = (total > 0x64) ? mm_alloc(8*total) : stack_lens;

    if (extra) { ...store extra as ptrs[total-1], len at lens[total-1]... }
    for (Node* p = rec; p; p = p->next) { ptrs[--i] = p->record; lens[i] = p->record->len; }

    // statistic accumulation at this->[0x178] and [[this+8][0xd8]+0x2c8]
    int bytes = 0;
    for (int i = 0; i < total; i++) {
        Record* r = ptrs[i];
        int len = r->len;
        if (stats && len > 6 && (unsigned)(len - 6) >= 0x20)
            0x14045C330(r);                       // padding/CRC adjust?
        bytes += len;
        bump_counters(bytes, len, 1);             // lock xadd at +0x4c/+0x50/+0x54
    }

    // BULK TRANSMIT — the actual hand-off
    0x140452360(this->[0x38], ptrs, total, bytes);

    free heap arrays;
epilogue:
    LeaveCriticalSection(...);
}
```

Classification, from the instructions above:

```text
0x14043B5D0 = SEND/FLUSH        (not CLEANUP, not MIXED)
```

### `0x140452360` — the transmit hand-off

```text
- EnterCriticalSection([rcx+0xc8]+0x10)
- 0x140414BD0(rcx) must == 4
- 0x140452A80(rcx, total_bytes)
      reads a limit at [[rcx+0x38]+0x34], keeps a running total at [rcx+0xd0],
      returns whether the limit was just exceeded -> byte-quota / backpressure
- per record: 0x140453370(&rcx[0x70], &ptrs[i])   ; push into a deque-like
                                                    ; container (grow path inside)
- success: (*[[rcx+0x68]]->vtable[0x90])([rcx+0x68], &records)
- failure: per record, (*record)->vtable[0](record, 1)   ; release
```

### No free on the drain path

The drain body `0x140430800` calls exactly two things per element — `0x14043B5D0`
and `element->vtable+0x30` — and both take the element as receiver:

```asm
14043082d  add   rdi, -0x30
140430847  mov   rcx, rdi
14043084a  call  0x14043b5d0          ; 0x14043B5D0(element, r8b = 0)
140430852  mov   rcx, rdi
140430859  call  [rax + 0x30]         ; element->vtable+0x30(element)
```

Neither reaches `0x14043FA70` (the scalar deleting destructor) or `mm_free`. The
socket's real deletion is the separate `vtable+0x00` path. So a prior statement
that `0x14043B5D0` is called "with the manager as `this`" is **retracted**.

### The service path is generic outbound transport

`0x14043B460` (which builds the record, pushes it on `+0x168`, and enqueues the
socket on `ObjectManagerImpl+0x260`) has six call sites, all shaped
`rcx = socket, rdx/r8 = contexts, r9d = message id`:

```text
0x140412667  fn 0x1404123D0   r9d = 0x43DB3479  Close
0x140412BDF  fn 0x140412B20   r9d = edi         sibling Close-family verb
0x14043CE37  fn 0x14043C900   r9d = 0           socket-cluster internal
0x14045B992  fn 0x14045B620   r9d = 0x8B0D492F  IntroduceConnection
0x14045BC70  fn 0x14045BA00   r9d = 0xA609E6A7  RequestIDSignature
0x14045BF91  fn 0x14045BCD0   r9d = 0x6731C5AF  ReplyIDSignature
```

Message names confirmed against `src/Holocron.Common/Protocol/`. One function
serializes Close, IntroduceConnection and both signature messages identically, so
the mechanism is the **general outgoing-message path**, not close-time cleanup.

Close reaches it only when `arg2 == 0`: `0x1404123D0` writes the `0x43DB3479`
envelope inside the `arg2 == 0` block (entered by fallthrough at `0x1404124F4`;
nothing branches to `0x140412667`), and the observed wire producers pass 0:

```text
0x14040AEC0  routed-peer Close       arg2 = 0   TAKES the path
0x140468D40  TimeRequester teardown  arg2 = 0   TAKES the path
```

Counter-case: the inbound dispatcher `0x14042B990` routes an inbound Close
(`0x43DB3479`) with `arg2 = 1` and **skips** `0x14043B460`, while inbound
RequestClose (`0x598D9A7`) is routed with `arg2 = 0` and **takes** it.

### The state helpers, resolved and emulated

```text
0x140414BD0(x)                                    state GETTER
    returns [x+0x18] unchanged. 9 is a transient spin-lock marker: the accessor
    xchg's 9 in, reads the old value, restores it; if it sees 9 it waits on a
    QueryPerformanceCounter-timed loop.

0x140414CB0(x, newState, allowedMask, warnMask)   state COMPARE-AND-SWAP
    if (1 << oldState) & allowedMask: store newState; return oldState
    else:                            restore oldState; return 0xA (denied)
```

The Close verb uses both:

```asm
14041240a  mov   edx, 7              ; newState
14041240f  mov   r9d, 0x180          ; warnMask
140412415  lea   r8d, [rdx + 0x78]   ; allowedMask = 0x7F
140412419  call  0x140414cb0         ; CAS -> eax = OLD state
14041241e  mov   r14d, eax
140412421  cmp   eax, 0xa / jne ...  ; 0xA -> denied
1404124e1  cmp   r14d, 4 / jne ...   ; the PRE-transition state had to be 4
140412604  call  0x140414bd0         ; current state 4 or 7 -> allowed to send
140412609  cmp   eax, 4 / je  ...
140412611  call  0x140414bd0
140412616  cmp   eax, 7 / jne ...
140412667  call  0x14043b460         ; serialize + queue Close
```

### The PacketSocket service fields, from the constructor

`0x140439FE0` zeroes them all, which fixes the working set:

```asm
14043a1f8  mov  dword ptr [rdi + 0x164], ebp   ; outstanding-work gate
14043a1fe  mov  qword ptr [rdi + 0x168], rbp   ; record stack head
14043a205  mov  dword ptr [rdi + 0x170], ebp   ; queued byte total
14043a218  mov  dword ptr [rdi + 0x180], ebp   ; service-enabled flag
```

```text
+0x164  outstanding-work gate        0 -> 1 only after the +0x168 push found the
                                     stack empty; 1 -> 0 cleared by 0x14043B5D0
                                     mode 0. LIFECYCLE CONFIRMED. (0x14043B525,
                                     0x14043E02C set; 0x14043B62A clears.)
+0x168  0x20-byte record stack head   push in 0x14043B460 / 0x14043DE10,
                                     steal in 0x14043B5D0
+0x170  queued byte total             added +len at 0x14043B545, drained -len at
                                     0x14043B6FC -> counts queued bytes, not
                                     lifetime bytes. 0x100000 is a 1 MiB backlog
                                     threshold.
+0x180  service-enabled flag          both 0x14043B460 (0x14043B554) and
                                     0x14043B5D0 (0x14043B638) require == 1;
                                     set by 0x14043AD60, 0x14043BEA0, 0x14043E3A0
```

### Tooling correction recorded for reuse

The emulator built for this pass initially produced a wrong answer that pointed
away from the truth, because of two bugs worth recording:

```text
1. capstone register ids are not sequential from RAX (X86_REG_RCX == 38 while
   X86_REG_RAX == 35), so an index-arithmetic register map silently aliased rcx
   onto rbx and the function dereferenced NULL.
2. `mov eax, 1` writes the EAX register id, not RAX; storing it under its own
   key made every 32-bit return read back as 0, so a getter appeared to return 0
   for every input.
```

After fixing both, `0x140414BD0` returns its input field exactly for every value
0..8, which is what identified it as a state getter. `tools/mini-x64-run.py`
carries the fixes and a comment explaining them.

**No server behaviour was changed, no breakpoint was placed, and D4 was not sent.**

### CORRECTION to this section: the two layouts are different objects

This notebook previously recorded, in the same section, both of:

```text
record+0x10 = omega::Frame*
record+0x18 = uint32 size
```

and

```text
0x140452360 reads [record+0x10] as a size and [record+0x18] as a pointer
```

Those are not contradictory descriptions of one object; they describe two
different objects, and the second line was mislabelled. Re-read from the bytes:

```text
THE 0x20-BYTE QUEUE RECORD            THE omega::Frame IT POINTS AT
  +0x00  next                           +0x00  vtable (0x141480E08)
  +0x08  ctx intrusive ref              +0x08  uint32 length
  +0x10  omega::Frame*                  +0x10  uint32 size        <-- what
  +0x18  uint32 size/payload            +0x18  void*  buffer      <-- 0x140452360
                                                                      reads
```

`0x140452360` never sees a queue record. `0x14043B5D0` **moves** the
`omega::Frame*` out of each record into a flat pointer array and passes that:

```asm
; 0x14043B7EB..0x14043B7F3   the extra record (this[0x98] == 1)
14043b7eb  mov  rcx, qword ptr [rax + 0x10]    ; rcx = the Frame
14043b7ef  mov  qword ptr [rax + 0x10], 0      ; record+0x10 := NULL  (a MOVE)
14043b7f3  mov  qword ptr [rdx + r15], rcx     ; frames[idx] = Frame

; 0x14043B81B..0x14043B823   the stolen queue records
14043b81b  mov  rax, qword ptr [rdi + 0x10]    ; rax = the Frame
14043b81f  mov  qword ptr [rdi + 0x10], 0      ; record+0x10 := NULL  (a MOVE)
14043b823  mov  qword ptr [rdx], rax           ; frames[i] = Frame

; 0x14043BA05..0x14043BA1B   the hand-off
14043ba0f  mov  rbx, qword ptr [rsp + 0x20]    ; arg2 = the FRAME-pointer array
14043ba17  mov  rcx, qword ptr [rsi + 0x38]
14043ba1b  call 0x140452360
```

There are **two** arrays, and only one of them is passed:

```text
frames[]  omega::Frame*          (r15)      -> arg2 of 0x140452360
lens[]    the 0x20-byte record*  (rbp+0x768) -> NOT passed; cleanup only, so the
                                                epilogue can release and
                                                mm_free(rec, 0x20) each record
```

Confirmed at `0x140452360`:

```asm
1404523de  mov  rdi, rsi            ; rsi = frames[] (element size 8)
1404523ff  mov  rdx, qword ptr [rsi]        ; rdx = frames[i]  (a Frame*)
140452402  mov  r8d, dword ptr [rdx + 0x10]; r8d = Frame.size
140452406  mov  rdx, qword ptr [rdx + 0x18]; rdx = Frame.buffer
14045240e  call [rax + 8]                   ; write(buffer, size)
```

So the answer to "conversion or reversed labels?" is: **both** a conversion
(the flush separates frames from records, and keeps the record array only for
cleanup) **and** partly-reversed labels in the earlier prose. The `omega::Frame`
copy constructor independently confirms the Frame layout, because it reads its
source with the same `+0x10` / `+0x18` pair at `0x1403FAA0E` / `0x1403FAA12`.

One further earlier claim to retract: the arm at `0x14043BB35` is **not** a
"flush sink". It is the `mm_alloc` failure path — reached only from the
`test rax, rax / je` at `0x14043B7A7`, it frees nothing and instead calls
`0x14008CC20` and then `_CxxThrowException` (`0x140FF97D0`) with `ecx = 0x20`,
i.e. `std::bad_alloc`.

### The 0x20-byte record is an `omega::Frame` reference, and the chain reaches a write dispatch

`0x14043F9F0` builds the record and `0x1403FA990` builds what it points at. The
vtable installed by `0x1403FA990` is `0x141480E08`, which resolves by RTTI:

```text
omega::Frame       vtable 0x141480E08      CONFIRMED
```

```c
// 0x14043F9F0(rec, ctx, arg3, arg4)
rec->[0x00] = NULL;                              // intrusive-list next
rec->[0x08] = ctx->[0x00];                       // move an intrusive ref
if (rec->[0x08]) rec->[0x08]->vtable[0x28]();    // addref
rec->[0x10] = omega_Frame_copy(arg3);            // 0x1403FA990 -> new Frame
rec->[0x18] = arg4;                              // uint32 size
if (ctx->[0x00]) ctx->[0x00]->vtable[0x30]();    // release the moved-from ref

// 0x1403FA990(src)  -- src is the PacketSocket's frame at [socket+0x38]
Frame* f = mm_alloc(0x28);
f->[0x00] = &omega::Frame_vtable;
f->[0x08] = src->[0x10];                         // length
f->[0x18] = mm_alloc(f->[0x08]);                 // data buffer sized from src
f->[0x20] = 5; f->[0x24] = 0x101;
```

So the record is a **reference-counted `omega::Frame` plus a 32-bit size** -- not
a raw scatter/gather segment and not a bare serialized frame.

Full chain, as far as it is proven:

```text
logical queued object  omega::PacketSocket
record                 0x20 bytes: next, omega::Frame ref, size, 32-bit payload
queue                  PacketSocket+0x168 (lock-free LIFO)
accounting             PacketSocket+0x170 (added on queue, subtracted on service)
trigger                PacketSocket+0x164 gate -> ObjectManagerImpl+0x260 ->
                       the 5 ms callable 0x140430800
flush                  0x14043B5D0 (mode 0; mode 1 on the >= 1 MiB threshold)
hand-off               0x140452360(socket+0x38, records, count, total_bytes)
dispatch               [[socket+0xd8]]->vtable[8](buffer, size)   <-- write entry
```

The last hop is a virtual write on the object at `PacketSocket+0xd8`. The real
Winsock boundary in this image is `0x140A82CB0` (two `WSASend` calls in a
partial-write loop, returning -1 on failure). The hop from
`[[socket+0xd8]]->vtable[8]` to `0x140A82CB0` was **not** resolved this pass, so:

```text
record -> PacketSocket queue -> service -> flush -> hand-off -> write dispatch
                                                                      CONFIRMED
write dispatch -> WSASend 0x140A82CB0                                 UNKNOWN
```

That single unresolvable hop does not change the classification: every layer that
*was* resolved is a transmit path, and the Close envelope is produced upstream of
all of it.
