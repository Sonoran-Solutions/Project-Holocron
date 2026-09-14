# Current Retail State

**This file is authoritative for the current reverse-engineering model.**
`docs/retail-protocol-evidence.md` is a chronological lab notebook that
deliberately preserves superseded hypotheses; when the two conflict, **this file
wins**. Every claim below was re-checked against static evidence or a captured
runtime witness at the checkpoint recorded at the bottom.

---

## Authority / how to use this file

Status vocabulary — use these five words and nothing else:

| Status | Meaning |
| --- | --- |
| `CONFIRMED` | directly supported by static or runtime evidence recorded here |
| `HYPOTHESIS` | plausible interpretation that still needs a discriminating experiment |
| `UNKNOWN` | not enough evidence either way |
| `DISPROVEN` | contradicted by recorded evidence |
| `SUPERSEDED` | an earlier interpretation replaced by a better model; may still contain useful raw data |

A statement does **not** become `CONFIRMED` by appearing repeatedly in the older
notebook. Only the evidence moves it. When you learn something new, update this
file and add a dated correction section to the notebook — never silently rewrite
history there.

---

## Current reproducible environment

* Private client copy: `.local-test/client-v1` (Git-ignored).
  * Client executable SHA-256 `47d8c8f03242606819fe7afe711bfd8186e83811a178613a89f944ccb1ac4f14`.
  * Differs from the Steam executable
    (`ad541a742a62500c2095f87c3cff116def462ebd26d1de95de32bc7293eb596b`) in
    exactly **256 bytes** at file offsets `0x1AB50D1`–`0x1AB51D0` — the
    substituted RSA **test** public key. `.text`, `.rdata`, `.data`, `.pdata`,
    `.reloc` are bit-identical, so all disassembly addresses in the notebook are
    valid for the retail executable. `CONFIRMED`
  * The Steam installation is never modified. `CONFIRMED`
* Canonical shard address (platform fixture): `localhost:7979:castlehilltest`.
  `CONFIRMED`
* Auth listening on `127.0.0.1:7979`, HTTPS platform fixture on `127.0.0.1:7978`.
  `CONFIRMED`
* Isolated runtime: `bwrap` network namespace, private Proton copy, read-only
  asset mount. `CONFIRMED`

### Environment footgun — the resolver workaround

The isolated namespace contains only `lo`. The retail TCP hint builder sets
`AI_ADDRCONFIG` (`0x400`) at `0x1404507C9`, which in that namespace makes
`getaddrinfo` reject every IPv4 result including `127.0.0.1`, so the client never
opens an Auth socket. `CONFIRMED`

**Use `tools/run-retail-bootstrap-probe.py`.** It applies only that one
immediate (`0x400` → `0`), refuses unknown executable builds, and restores the
original bytes in a `finally` path with a byte-for-byte verification. Do not
hand-patch the executable. Running `tools/launch-isolated-client.sh` directly on
stock bytes reproduces an **environment artifact**, not the historical Auth path.

---

## CONFIRMED transport facts

* Transport bit `0x10` is a **Zstandard compression flag**, not an encryption
  class. Decompress before reading any dispatch envelope. `CONFIRMED`
* Encryption is **session state**: Salsa20 keyed from the RSA exchange. It is not
  a per-frame property. `CONFIRMED`
* The low nibble of the transport type byte carries the transport type
  (`0` = routed application, `1`/`2` = time sync, `4` = key exchange). `CONFIRMED`
* Auth greeting, login transport, RSA/PKCS#1 v1.5 with 245-byte plaintext
  chunks, and the declared-length handling are as recorded in the notebook.
  `CONFIRMED`
* First global client message is `0xA609E6A7` on route `0xFFFF`/`0xFFFF`, read
  after decompression. `CONFIRMED`

---

## CONFIRMED identification bootstrap

Reproduced end-to-end on a bounded private-client run:

```text
TCP -> RSA -> Salsa20
client  0xA609E6A7  RequestIDIFace::RequestIDSignature            (FFFF/FFFF)
server  0x6731C5AF  ReplyIDIFace::ReplyIDSignature                (FFFF/FFFF)
client  0x8B0D492F  RequestIDIFace::IntroduceConnectionSignature  (FFFF/FFFF)
client  registers its receive route 0x0001/0x0000
```

All three ids are **global** messages consumed by the global dispatcher at
`0x14042B990`, not routed endpoints. Producer pairing is proven by call sites,
not inferred. `CONFIRMED`

---

## CONFIRMED routed-peer / Close behavior

After the routed peer is installed, the client emits `Close 0x43DB3479`; the
Auth side observes it, `ServerProxy::OnDisconnect` (`0x14042718E`) finds the
launch context at `+0x90` still outstanding and reports error **1003**.

* `conn+0x88` holds a **routed peer** object (0x88 bytes, allocated by
  `0x140412820`, installed by the only writer `0x140412A4F`). `CONFIRMED`
* Exactly **two** mutations occur: `NULL -> peer A` (thread 2), then
  `peer A -> peer B` (thread 58). `CONFIRMED`
* **Peer B is still attached when `0x14040AEC0` runs and stays attached through
  the Close.** `CONFIRMED`
* `0x14040AEC0` is **not** a peer-removal primitive. It atomically *probes and
  classifies* the attached routed peer (a locked compare against a zero sentinel,
  which fails on a non-null field and returns the peer in `RAX`) and then
  terminates the routed connection. `CONFIRMED`
* At `0x14040AF6A` it releases `[arg2]` — the **connection smart pointer in the
  argument struct**, which is a different lifetime from the peer. `CONFIRMED`
* The Close is generated only when the classified name is not the wildcard
  `"*"`. In the observed run the compared string was `""`, taken from
  **`peerB+0x40`** (which held the empty-string singleton `0x14156BD60`), so the
  Close was sent. `CONFIRMED`

### Owner teardown chain (all on thread 2)

```text
0x140423DD0  timed / conditional wait logic
  -> 0x1404245F0  collection teardown
  -> 0x140434430  detach
  -> 0x14040AEC0  routed-peer probe + routed-connection termination
  -> 0x1404123D0
  -> Close 0x43DB3479
  -> ServerProxy::OnDisconnect
  -> error 1003
```

ReplyID / peer-B installation happens on **thread 58**. The teardown chain
happens on **thread 2**. That distinction matters. `CONFIRMED`

---

## Current failure boundary

> **The decision that causes the owner to enter the `0x140423DD0` →
> `0x1404245F0` collection-teardown path is UNKNOWN.**

Known gate inputs of `0x140423DD0` (recovered from full disassembly; semantics
**not** established):

```text
entry:      cmp dword ptr [r8], 0        ; non-zero -> 0x140423F65
then:       cmp byte ptr [target+0x2D],0 ; non-zero -> exit, no teardown
then:       [target+0x2C] and an elapsed-vs-deadline comparison at 0x140423EEC
            (deadline = [[rbx]]+0x28) select callbacks 0x140423FF0 / 0x140423A70
timing:     KUSER_SHARED_DATA 0x7FFE0008 / 0x7FFE000C / 0x7FFE0010,
            millisecond scaling
```

Open inputs, all `UNKNOWN`:

* meaning of `[r8]`, `[target+0x2C]`, `[target+0x2D]`;
* identity of runtime object `0x14B3EB0`;
* identity and contents of the `0x1404245F0` collection;
* the **hidden dispatch** into `0x140423DD0` (no direct callers, no data
  references, and no 8-byte pointer anywhere in the image lands inside its
  range);
* whether the observed **~83 ms** is itself a timeout. It is only the broad
  `CS_LOGGING_IN` → `HandleLaunchFailure` interval and was never isolated to
  this wait.

---

## UNKNOWN / open questions

* Why the owner begins the teardown (the boundary above).
* Semantic meaning of `peer+0x40`. It is a real string-valued field; it held
  `""` in the observed run. **Do not name it yet.**
* Whether `peer+0x40` can ever hold `"*"`, and where a wildcard peer would be
  created.
* **D4 causality: `UNKNOWN`.** It was deliberately not sent in the corrected
  validation. Static directionality facts about D4 may remain `CONFIRMED`
  independently, but no causal claim in either direction is established. D4 is
  **not** `DISPROVEN`.
* Whether the double attach has any behavioural consequence.
* Status of `0x14042C641`, `0x14042C731`, `0x14042C754`: they are conditional
  stores used as atomic probes; at runtime `rdi = NULL`, the compare fails and
  nothing is written. Their semantic role is `UNKNOWN`.
* Retail World transport, character list/select, and world-object streaming:
  entirely unvalidated (see "Legacy code" below).

---

## DISPROVEN / do not reuse

| Claim | Status | Correction |
| --- | --- | --- |
| `0x011C5800` is the first retail login message | `DISPROVEN` | Reading a `0x10` payload as a raw dispatch envelope is invalid; `0x10` is the Zstandard flag. Decompress first. The actual first global message is `0xA609E6A7`. |
| Route `E800`/`E6A7` is the current proven route | `DISPROVEN` | Derived from the same invalid `0x10` reading. The identification exchange runs on `0xFFFF`/`0xFFFF`. |
| `0x10` is an encryption class | `DISPROVEN` | `0x10` is the Zstandard compression flag; encryption is Salsa20 session state. |
| `A609E6A7` is a login request answered directly by D4 | `DISPROVEN` | `0xA609E6A7` is `RequestIDSignature`; it is answered by `0x6731C5AF ReplyIDSignature`. Sending D4 here bypasses the proven identification flow. |
| `omega::TimeRequester` / `0x140468D40` / `*:timesource` failure caused the reproduced Close | `DISPROVEN` | On the reproduced failing run the TimeRequester teardown never executed. The class/RTTI/object-layout research remains valid structure; only the causal attribution is retracted. |
| `App+0x2A` / `0x140406C90` / `0x140446830` / `~ApplicationImpl` caused the reproduced Close | `DISPROVEN` | None of them executed on the reproduced failing run. Structural findings retained. |
| Peer A replacement/release caused the Close | `DISPROVEN` | Replacement was observed; it is not the cause of this Close. |
| `0x14040AEEB` clears `conn+0x88` | `DISPROVEN` | `LOCK CMPXCHG` leaves the destination unchanged when the compare fails. Measured `ZF=0`, `RAX` ← peer B, `conn+0x88` byte-identical before and after. |
| Peer B is removed before the Close | `DISPROVEN` | Peer B remains attached through the Close. |
| The empty comparison string came from a NULL connection field | `DISPROVEN` | It came from `peerB+0x40`, which held the empty-string singleton. |
| ~83 ms is a proven timeout | `UNKNOWN`, not proven | See the failure boundary above. |
| D4 has been causally disproven | `DISPROVEN` as a claim | D4 is `UNKNOWN`. It was not sent. |
| A locked RMW watchpoint hit implies a value change | `DISPROVEN` | A watchpoint on `lock cmpxchg` fires on the locked bus access regardless of architectural outcome. Compare before/after values explicitly. |

---

## Legacy code that is NOT retail evidence

These are useful simulation scaffolding and **must not** be used as
reverse-engineering evidence:

* `Holocron.Common.Protocol.Opcode` — legacy/simulation opcode numbering. Its
  values are **not** current retail SWTOR message ids.
* `Holocron.Common.Protocol.PacketReader` / `PacketWriter` — legacy 12-byte
  header model, **not** the proven retail transport framing.
* `Holocron.World.Network.WorldSession` / `WorldPacketDispatcher` — simulation
  session and dispatcher built on the legacy packet model.
* Any README architecture diagram describing a two-stage auth → dynamic world
  handoff: that is a **legacy simulation target**, not current retail fact.

---

## Canonical reproduction procedure

```bash
# one bounded reproduction; patches only the AI_ADDRCONFIG immediate and
# restores the client byte-exactly
python3 tools/run-retail-bootstrap-probe.py

# or, to attach a debugger to the WineDbg proxy
python3 tools/run-retail-bootstrap-probe.py --winedbg-gdb
```

Expected success shape — the Auth log must show, in order:

```text
[AUTH] Client connected from 127.0.0.1:...
[AUTH] Sent login transport greeting (22 bytes) ...
[AUTH] Received CMSG_HANDSHAKE (...) ...
[AUTH] RSA envelope and historical key-field layout validated ...
[AUTH] Bootstrap request: ... message=0xA609E6A7.
[AUTH] RequestIDSignature: name="castlehilltest", correlation=0x...
[AUTH] Sent ReplyIDSignature: message=0x6731C5AF, route=0xFFFF/0xFFFF, ...
[AUTH] IntroduceConnectionSignature received: ... name="OmegaServerProxyObjectName" ...
[AUTH] Control-window frame: ... message=0x43DB3479.
[AUTH] Client closed the connection during the control window.
```

If `RequestIDSignature` does not appear, the resolver workaround did not take
effect — check that the wrapper restored/patch state is as expected rather than
debugging the protocol.

---

## Current tests / checkpoint

* `dotnet test` → **65/65** passing. Test names state what each one proves; see
  the provenance notes in `tests/Holocron.Tests/`.
* `python3 -m unittest discover -s tools -p 'test_*.py' -v` → **2/2** passing.
* Latest corrected reverse-engineering checkpoint: `e9dc46a` (it supersedes the
  unpushed `7f93d8a`, whose `CMPXCHG` interpretation was wrong).
* Evidence notebook: `docs/retail-protocol-evidence.md` (chronological; may
  contain superseded conclusions — always cross-check here).
