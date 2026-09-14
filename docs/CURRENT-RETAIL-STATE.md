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
immediate (`0x400` → `0`), refuses unknown executable builds, restores the
original bytes unconditionally in a `finally` path with a byte-for-byte
verification, and clears every inherited `HOLOCRON_*` mode variable before
setting the modes requested on its command line — so `--no-bootstrap-probe`
works even if the calling shell already exported `HOLOCRON_AUTH_ID_BOOTSTRAP`.
There is no supported "leave the patch applied" mode. Do not hand-patch the
executable. Running `tools/launch-isolated-client.sh` directly on
stock bytes reproduces an **environment artifact**, not the historical Auth path.

The launcher itself imposes **no** time limit. `--seconds` is the wrapper's own
bound on how long the launcher may run before the wrapper terminates it (plus a
fixed 120 s shutdown grace); no time-limit value is passed into the launcher.

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
* **Local contract inside `0x14040AEC0`:** its Close call is skipped when the
  classified peer string is exactly the wildcard `"*"`; otherwise that path calls
  Close. In the observed run the compared string was `""`, taken from
  **`peerB+0x40`** (which held the empty-string singleton `0x14156BD60`), so the
  Close was sent. `CONFIRMED`
  * This is a statement about **this function only**, not a global rule. Other
    Close producers exist structurally elsewhere in the image and must not be
    erased or explained away by this test.

### `0x140423DD0` is a closure, and its dispatch is runtime-materialised

The function has **no** direct, conditional, tail or indirect branch anywhere in the
image, and no image-resident 8-byte pointer lands anywhere inside its range. The
reason is now known: it is a **lambda/closure body**, reached only through a
function pointer written at runtime.

Runtime witness at entry (`CONFIRMED`):

```text
0x140423DD0 entry, thread 2
  RAX = 0x140423DD0        <- the target of the thunk
  R11 = 0x140423DD0
  caller return address = 0x140425806
  machine code immediately before the return address:
        0x1404257FA  mov rcx, r10
        0x1404257FD  mov rax, r11
        0x140425800  call qword ptr [rip+0xf454ba]   ; slot 0x14136ACC0
  slot 0x14136ACC0 -> 0x141283300
  0x141283300:  ff e0   jmp rax
```

Classification: **indirect call through a data slot** (`0x14136ACC0`, an
8-byte pointer table in `.rdata`, immediately after the IAT at
`0x141369000`–`0x14136ACB8`) into a one-instruction `jmp rax` thunk. `RAX` is the
closure's bound function pointer. The chain is therefore:

```text
0x140425770  closure invoker (thread_data-style run trampoline)
  -> call [0x14136ACC0] -> 0x141283300 (jmp rax) -> RAX
  -> 0x140423DD0
```

`0x140423DD0` is **not** a task/timer entry point reached through a thread
trampoline. `CONFIRMED`

### The closure that reaches `0x140423DD0`

Captured runtime layout of the invocation (`CONFIRMED`):

```text
closure object (stack, thread 2):
  +0x00  0x140423DD0        bound function pointer
  +0x08  0x14B7DA0          first captured object
  +0x10  0x14E7FC8          second captured object
  +0x18  0x14C3B88          its boost control block
```

and at `0x140423DD0` entry:

```text
arg1 rcx = 0x14B7DA0          (the +0x08 capture)
arg2 rdx = &shared_ptr        [rdx] = 0x14E7FC8, [rdx+8] = 0x14C3B88
arg3 r8  = stack slot holding a dword; measured [r8] = 0
arg4 r9d = 4
```

Gate-object identity (`CONFIRMED`):

* The function immediately executes `mov rax,[rdx]` then `mov r8,[rax]`, so the
  object whose fields the gate reads is **`[0x14E7FC8]` = `0x1523E58`**, not
  `0x14E7FC8`.
* `0x14E7FC8` is the shared_ptr's stored object; `0x14C3B88` is its control block,
  whose vtable `0x1414B6588` resolves by RTTI (`COL moffset 0`) to
  `boost::detail::sp_counted_impl_p<omega::ApartmentTimer>`. `CONFIRMED`
* The earlier reading of "the object at `0x14E7FC8`" was an artefact of not
  applying the `[rdx]` indirection first.

Runtime gate values at the first entry of the failing-direction run
(`CONFIRMED`, measured):

```text
[r8]            = 0x00000000        (the dword the entry compare reads)
0x1523E58+0x28  = 0x00000005        (dword: wait quantum in ms)
0x1523E58+0x2C  = 0x01              (byte: wait-mode selector)
0x1523E58+0x2D  = 0x00              (byte: FINISHED flag, 0 = not finished)
0x1523E58+0x00  = 0x1414B6761       (function table pointer, low bit set)
0x1523E58+0x08  = 0x140430800
0x1523E58+0x28  = 0x0000000100000005 (refcount pair: strong 5, weak 1)
```

Consequence for the branch logic: with `[target+0x2C] != 0` the timed-wait arm is
taken and the completion arm is not. `[r8] == 0` means the entry guard does **not**
short-circuit. `CONFIRMED`

### The polled object is a timer wait, and the 5 ms figure is a real timer quantum

`0x1523E58+0x28 == 5` is the value passed into the wait as the millisecond
argument at `0x140423F2D` (measured `wait_ms(r8d)=5`). The KUSER_SHARED_DATA
arithmetic around `0x140423E45`/`0x140423EB6` and the clamp
`cmp rcx,1 / cmovl ecx,eax` at `0x140423EF7` compute the remaining time and force
it to a minimum of 1 ms. This is a **timed wait with a floor**, not a deadline
comparison that can expire into teardown. Whether the wait's expiry selects the
teardown path is still `UNKNOWN` (see below). `CONFIRMED` for the arithmetic,
`UNKNOWN` for the causal link.

### The task that polls the connection setting

The closure is created and registered by the polling task body `0x1404305D0`,
which is the `boost::bind` target stored in a `boost::detail::thread_data` object
(`CONFIRMED` by RTTI: `.?AV?$thread_data@V?$bind_t@XV?$mf1@XVApartmentImpl@omega@@_N@_mfi@boost@@...`):

```text
0x1404305D0:
    call 0x140431030                       ; per-iteration work
    mov  rcx, [rbx+8]                      ; bound object
    lea  rdx, [rip+0x114e2e7]  "connection"
    mov  rcx, [rcx+0xe8]
    call 0x1403FC4C0                       ; setting lookup, name "connection"
    ...
    lea  rdx, [rip+0x114e330]  "signature"
    ... jmp 0x1403FC4C0                    ; setting lookup, name "signature"
```

`0x14042F960` arms that task with a **5 ms** timeout (`r9d=5` at its second
registration call) and a second, **500 ms** timeout (`r9d=0x1F4`) on the same
object. `CONFIRMED`

Every timer registration site in the image is `0x140423B50`. Runtime witness of
the startup registrations (`CONFIRMED`):

```text
site 0x1404264B8  timeout 60000 ms   arg1 0x14B3C90
site 0x14042FA39  timeout   500 ms   arg1 0x14B3DA0
site 0x14042FB10  timeout     5 ms   arg1 0x14B3DA0
site 0x140446693  timeout 60000 ms   arg1 0x14B3EB0   <- the historical instance
```

The historical absolute address **`0x14B3EB0`** is one runtime instance of the
object registered at site `0x140446693` (a 60 s registration); the 5 ms closure
that reaches `0x140423DD0` belongs to `0x14B3DA0`. **Do not treat either address
as identity**; the type is the identity. `CONFIRMED`

### `0x140423B50` is the operation/timer factory, and `0x140423A70` is its completion routine

`0x140423B50` is the single registration entrypoint used by every timer-like
site in the image. Its arguments (`CONFIRMED` from disassembly plus the runtime
witnesses in the previous checkpoint):

```text
rcx       = operation/timer owner object   (e.g. 0x14B3DA0, 0x14B3EB0)
rdx       = out shared_ptr slot (two qwords written at 0x140423B8F/0x140423B92)
r8        = pointer to a materialised callable (function-object pointer table)
r9d       = timeout in milliseconds        (500, 5, 60000, 1000, ...)
[stack+0x20] = a byte flag passed through to 0x1404595E0
```

It acquires the owner's spinlock at `owner+0xA8` (`lock cmpxchg dword ptr
[rcx+0xA8]`), allocates the callable, inserts it into the owner's structure at
`owner+0x90`, and at its tail calls the **timer-start** entry:

```text
140423d03  mov  rcx, [rbx]                  ; operation object
140423d06  mov  rax, [rcx]                  ; its function table
140423d09  mov  r8d, [rax+0x28]             ; timeout carried in the callable
140423d33  call 0x140423FF0
```

`CONFIRMED`

`0x140423FF0` is therefore **the timer/operation start entry**, and
`0x140423DD0` is the wait it runs. The two callbacks are not symmetric peers:

* `0x140423FF0` — runs the wait (`0x140423DD0` inline, or the
  `condition_variable`-style helper `0x140424860`).
* `0x140423A70` — the **completion routine**. `CONFIRMED` from its body:

```asm
140423af2  mov  rax, [rdi]           ; [rdi] = operation target
140423af5  mov  rsi, [rax]           ; rsi  = the target
140423af8  cmp  byte ptr [rsi+0x2d], 0
140423afc  jne  0x140423b19          ; already finished -> skip
140423afe  call 0x140fdb1c0          ; clock read
140423b03  lea  rdx, [rsi+0x38]      ; result slot
140423b07  lea  r8,  [rsp+0x28]
140423b0c  mov  rcx, [rsi+0x30]      ; owner-visible context
140423b10  call 0x140424860          ; publish the result
140423b15  mov  byte ptr [rsi+0x2d], 1   ; <-- the finish flag
```

So:

* **`target+0x2D` is the operation's "finished" byte.** It is written only here.
  Its read site is the entry guard of `0x140423DD0`
  (`cmp byte ptr [r8+0x2d],0 / jne 0x140423FA9`) and its own guard at
  `0x140423af8`. When it is 0 the operation has not finished. `CONFIRMED`
  (writer + reader + effect); the earlier "semantics UNKNOWN" is superseded.
* **`target+0x2C` selects the wait mode.** `0x140423DD0` tests it with
  `cmp byte ptr [rax+0x2c],0`; non-zero takes the timed-wait arm that calls
  `0x140423FF0` with `r8d = [target+0x28]`, zero takes the arm that calls
  `0x140423A70` directly. What the two modes *mean* is `HYPOTHESIS`; that it
  selects between those two arms is `CONFIRMED`.
* **`target+0x28` is the wait quantum in milliseconds** (measured 5), read at
  `0x140423EEC` and clamped to a 1 ms floor. `CONFIRMED`

**`0x1403FC050` is the shared cancel helper. Its proven static callee is
`0x140423A70`, not `0x1404245F0`:**

```asm
1403fc063  mov  rcx, [rcx]        ; operation context
1403fc070  mov  rax, [rdx]        ; the callable
1403fc078  lea  rbx, [rdx+8]
1403fc08e  lock xadd dword ptr [rdx+8], eax   ; intrusive refcount
1403fc098  call 0x140423a70       ; <-- completion routine
```

```text
static edge proven:   0x1403FC050 -> 0x140423A70     CONFIRMED
static edge claimed:  0x1403FC050 -> 0x1404245F0     DISPROVEN (no such edge)
```

`0x1404245F0` has **no** static predecessor of any kind in this image — no direct
branch, no data pointer. The only reason it is known to run at all is the
previously captured runtime chain below. No static edge between `0x1403FC050`
and `0x1404245F0` has been established and none should be inferred.

`0x1403FC050` is called from exactly ten sites; three are inside
`0x14042FBA0` (the operation teardown used when an operation is replaced) and
one is inside the polling body `0x140430620`. `CONFIRMED`

**Consequence:** the timed-wait arm (`0x140423DD0` → `0x140423FF0`/
`0x140423A70`) and the owner-cancel path (`0x1403FC050` → `0x140423A70`) converge
on the same completion routine. This is why "the wait did not finish in time" and
"the owner decided to stop the operation" cannot be told apart from downstream
completion evidence alone. `CONFIRMED` for the call graph; `UNKNOWN` for which
one runs in the failing run, and `UNKNOWN` for how the historical
`0x140423DD0 → 0x1404245F0` step is actually produced.

### Historical runtime chain — retained as captured evidence only

The following was observed at runtime in an earlier pass. It is **not**
re-derived from static call edges and must not be presented as such:

```text
0x140423DD0
→ 0x1404245F0
→ 0x140434430
→ 0x14040AEC0
→ Close
```

`0x1404245F0`, `0x140434430` and `0x14040AEC0` all have zero direct callers and
zero image pointers, so all three are runtime-materialised closures or indirect
targets whose registration sites are still `UNKNOWN`.

### All closure bodies reached this way have no static xrefs

`0x140423DD0`, `0x14042FD80` and `0x1404305D0` share the same property: zero
direct branches, zero 8-byte image pointers. They are all function objects whose
addresses are materialised at runtime. Any future "this function has no callers"
observation must be treated as "this is a closure", not as "unreachable".
`CONFIRMED`


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
**partially** established — see the sections above for the measured values):

```text
entry:      cmp dword ptr [r8], 0        ; non-zero -> 0x140423F65
            measured [r8] = 0 every observed iteration
then:       cmp byte ptr [target+0x2D],0 ; non-zero -> exit, no teardown
            measured 0
then:       [target+0x2C] != 0           ; -> timed-wait arm (0x140423FF0)
            measured 1, so the timed-wait arm is taken
            timed wait uses [target+0x28] = 5 ms, clamped to >= 1 ms
then:       [target+0x2C] == 0           ; -> completion arm (0x140423A70)
```

Open inputs, still `UNKNOWN`:

* meaning of `[r8]` (a stack slot holding 0 in every observed iteration);
* the writer of `[target+0x2C]`; it was **`0x01` at every observed entry and
  never changed** across thousands of iterations of the 5 ms loop;
* which code path sets `[target+0x2D]` to 1 in the *failing* run, and whether the
  timeout arm or the owner-cancel arm got there first;
* identity and contents of the `0x1404245F0` collection;
* whether the observed **~83 ms** is itself a timeout. It is only the broad
  `CS_LOGGING_IN` → `HandleLaunchFailure` interval and was never isolated to
  this wait. The measured timer quantum is **5 ms**, which is not 83 ms.

### Environment limitation hit during this pass

The historical failing chain (`0x140423DD0` → `0x1404245F0` → `0x140434430` →
`0x14040AC0`) could **not** be re-observed under instrumentation in this pass.
The client reaches the login path normally, but attaching WineDbg's GDB stub
terminates it with a Windows exception (`exit code 0x30000000005`) roughly 12 s
after the first breakpoint in the 5 ms loop, and with the loop instrumented the
client never reaches a state where the shard click completes. `0x1404245F0`,
`0x140434430` and `0x14040AEC0` were therefore **not** hit in any instrumented
run of this pass, and no backtrace through them was obtained. Everything stated
above about those three functions is static plus previously-recorded evidence,
not a new runtime witness. `UNKNOWN` for their new-run behaviour.

One further harness defect was found and fixed: run scripts that wrap the
canonical runner must ensure the launcher's `flock` is released, otherwise a
stale `flock`/`bwrap`/`gdb` set makes every later run exit immediately with
`flock` status 75 and patch nothing. `CONFIRMED`

---

## UNKNOWN / open questions

* Why the owner begins the teardown (the boundary above).
* The writer and semantics of `[target+0x2C]` / `[target+0x2D]` on the
  `omega::ApartmentTimer`-owned object `0x1523E58`. Both were constant
  (`0x01` / `0x00`) for the whole observed lifetime of the 5 ms loop.
* Whether the `~83 ms` interval relates to the 5 ms timer quantum at all.
  Measured quantum is 5 ms; 83 ms is not a multiple of it that has been proven
  to matter.
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
* `python3 -m unittest discover -s tools -p 'test_*.py' -v` → **15/15** passing
  (2 platform-fixture tests, 13 canonical-runner control tests in
  `tools/test_run_retail_bootstrap_probe.py`).
* Instrumented evidence for this pass lives in `scratch/re2/` (`run1`–`run13`,
  `phase*.gdb`, `witness-launcher.sh`, `run-witness.py`). It is scratch, not a
  deliverable, and must be driven through
  `tools/run-retail-bootstrap-probe.py --launcher` so that the client hash
  check, the single `AI_ADDRCONFIG` patch and the byte-exact restore all still
  apply.
* Canonical-runner hardening: `4fac42b`.
* Latest corrected reverse-engineering checkpoint: `e9dc46a` (it supersedes the
  unpushed `7f93d8a`, whose `CMPXCHG` interpretation was wrong).
* Evidence notebook: `docs/retail-protocol-evidence.md` (chronological; may
  contain superseded conclusions — always cross-check here).
