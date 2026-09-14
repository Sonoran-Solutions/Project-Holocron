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
0x1523E58+0x2C  = 0x01              (byte: registration-time flag; see below)
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

`0x14042F960` arms that task in **`app+0x228` with a 500 ms timeout**
(`r9d=0x1F4` at `0x14042FA39`) and arms a *different* callable in **`app+0x238`
with a 5 ms timeout** (`r9d=5` at `0x14042FAFF`/`0x14042FB10`). These are two
distinct operations with two distinct callable bodies — see the byte-for-byte
table below. `CONFIRMED`

```text
app+0x228 -> fn 0x1404305D0 (body shown above), 500 ms
app+0x238 -> fn 0x140430800,                    5 ms
```

Do **not** describe `0x1404305D0` as "the 5 ms callable". It is the 500 ms
callable. The 5 ms callable is `0x140430800`. `CONFIRMED`

Every timer registration site in the image is `0x140423B50`. Runtime witness of
the startup registrations (`CONFIRMED`):

```text
site 0x1404264B8  timeout 60000 ms   arg1 0x14B3C90
site 0x14042FA39  timeout   500 ms   arg1 0x14B3DA0   -> app+0x228, fn 0x1404305D0
site 0x14042FB10  timeout     5 ms   arg1 0x14B3DA0   -> app+0x238, fn 0x140430800
site 0x140446693  timeout 60000 ms   arg1 0x14B3EB0   <- the historical instance
```

The historical absolute address **`0x14B3EB0`** is one runtime instance of the
object registered at site `0x140446693` (a 60 s registration); the 5 ms
operation reaching `0x140423DD0` belongs to `0x14B3DA0`. **Do not treat either
address as identity**; the type is the identity. `CONFIRMED`

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
140423af5  mov  rsi, [rax]           ; rsi  = the operation object
140423af8  cmp  byte ptr [rsi+0x2d], 0
140423afc  jne  0x140423b19          ; already finished -> skip
140423afe  call 0x140fdb1c0          ; clock read
140423b03  lea  rdx, [rsi+0x38]      ; callable context/subfield (NOT a result slot)
140423b07  lea  r8,  [rsp+0x28]
140423b0c  mov  rcx, [rsi+0x30]      ; the stored callable (NOT an owner context)
140423b10  call 0x140424860          ; see the corrected note below
140423b15  mov  byte ptr [rsi+0x2d], 1   ; <-- the finish flag
```

Field-role correction (`CONFIRMED`, from the factory reconstruction in the next
subsection): `operation+0x30` is the **stored callable**, and
`operation+0x38` is **that callable's context/subfield**. The earlier labels
"owner-visible context" for `+0x30` and "result slot" for `+0x38` are
`SUPERSEDED` — they predate the callable-layout evidence and are not merely
imprecise, they are wrong.

`0x140424860` was previously labelled a "publish/signal helper". That label is
now `HYPOTHESIS` only: it was inferred from argument positions before the
callable layout was known, and the helper itself has not been reversed. Do not
rely on it.

So:

* **`target+0x2D` is the operation's "finished" byte.** It is written only here.
  Its read site is the entry guard of `0x140423DD0`
  (`cmp byte ptr [r8+0x2d],0 / jne 0x140423FA9`) and its own guard at
  `0x140423af8`. When it is 0 the operation has not finished. `CONFIRMED`
  (writer + reader + effect); the earlier "semantics UNKNOWN" is superseded.
* **`target+0x2C` is the registration-time flag.** Its origin is `CONFIRMED`:
  both `0x14042F960` registrations pass `[rsp+0x20] = 1` (`0x14042FA23`,
  `0x14042FAFA`) and the factory stores it verbatim at `0x140459685`
  (`mov byte ptr [rdi+0x2c], al`). `0x140423DD0` tests it with
  `cmp byte ptr [rax+0x2c],0` and the non-zero arm calls `0x140423FF0` with
  `r8d = [target+0x28]`. Calling this field a "wait-mode selector" named it
  after one of its consumers; that label is `SUPERSEDED`. The field is a flag
  supplied at registration whose semantic meaning is `UNKNOWN`/`HYPOTHESIS`.
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

### The `app+0x228` / `app+0x238` operations, byte-for-byte

Reconstruction of the second registration in `0x14042F960` — the one that writes
`app+0x238` — from the exact instructions (`CONFIRMED`):

```asm
14042FA96  mov  r10, qword ptr [rdi + 0x220]   ; the registered operation
14042FA9D  lea  rax, [rip + 0xd5c]             ; -> 0x140430800
14042FAA4  mov  qword ptr [rbp - 0x29], rax    ; callable.fn  = 0x140430800
14042FAA8  mov  dword ptr [rbp - 0x21], r14d   ; callable.aux = 0
14042FAB0  mov  qword ptr [rbp + 0x2f], rdi    ; callable.obj = rdi
14042FAC1  movsd qword ptr [rbp - 0x19], xmm0  ; callable.obj copied in
14042FAE5  lea  rax, [rip + 0x1086c74]         ; -> 0x1414B6760
14042FAEC  or   rax, 1
14042FAF0  mov  qword ptr [rbp - 9], rax       ; callable.fntable = 0x1414B6761
14042FAFF  mov  r9d, 5                         ; timeout = 5 ms
14042FB05  lea  r8,  [rbp - 9]                 ; &callable
14042FB09  lea  rdx, [rbp - 0x29]              ; &destination smart pointer
14042FB0D  mov  rcx, qword ptr [r10]           ; rcx = [operation + 0x00]
14042FB10  call 0x140423B50                    ; register
```

```text
app+0x238 fn      = 0x140430800      CONFIRMED by the lea at 0x14042FA9D
app+0x238 timeout = 5 ms             CONFIRMED by the mov at 0x14042FAFF
app+0x238 flag    = 1                CONFIRMED by [rsp+0x20] at 0x14042FA23
```

The first registration (`0x14042FA39`) has the same shape with `fn` = the
callable whose body is **`0x1404305D0`**, `fntable = 0x1414B6771`, timeout
**500 ms**, and it writes `app+0x228`.

`0x14042FD80` is **NOT** the `app+0x238` callable — that hypothesis is
`DISPROVEN` by the `lea` above. It is a closure body (zero xrefs, allocates two
`0x320`-byte buffers) bound somewhere else; where is `UNKNOWN`.

### `0x140430800` — the 5 ms callable — complete body

**Function extent (`CONFIRMED`, corrected).** The tail of this function is
covered by **three chained `RUNTIME_FUNCTION` records**, not three functions:

```text
Begin 0x140430800  End 0x140430833  UnwindInfo 0x14178AB18  flags=0x0A (EHANDLER)
Begin 0x140430833  End 0x140430874  UnwindInfo 0x14184B350  flags=0x05 (CHAININFO)
Begin 0x140430874  End 0x14043087F  UnwindInfo 0x14184B364  flags=0x00 (leaf epilogue)
```

`0x14184B350` has `UNW_FLAG_CHAININFO` set, so the middle record is a **chained
unwind fragment of the same function**, not a separate one. The logical function
is therefore **`0x140430800`–`0x14043087F` (127 bytes)** with shared epilogues.

An earlier statement in this document said "51-byte self-contained leaf; `.pdata`
extent `0x140430800`–`0x140430833`" and then printed a body running to
`0x14043087E ret`. That was self-contradictory and is `SUPERSEDED`. The cause was
treating each `.pdata` record as a function boundary; chained records must be
followed. `tools/…/funcs.py` reports each record separately, so its
`containing()` output cannot be used as a function extent without checking the
chain flag.

**Correct terminology:** `0x140430800` is **not** a leaf function. It makes two
kinds of call. It is best described as *a short non-leaf routine that drains an
intrusive list*.

Full body (`CONFIRMED`):

```asm
140430800  mov  qword ptr [rsp+0x18], rsi
140430805  push rdi
140430806  sub  rsp, 0x20
14043080A  prefetchw byte ptr [rcx+0x260]
140430811  xor  esi, esi
140430813  mov  rdi, qword ptr [rcx+0x260]         ; <-- retry label
14043081A  mov  rax, rdi
14043081D  lock cmpxchg qword ptr [rcx+0x260], rsi ; atomically take the list
140430826  jne  0x140430813                        ; CAS retry
140430828  test rdi, rdi
14043082B  je   0x140430874                        ; nothing to do -> epilogue
14043082D  add  rdi, -0x30                         ; node -> element base
140430831  je   0x140430874
140430833  mov  qword ptr [rsp+0x38], rbx          ; loop: save rbx
140430840  mov  rbx, qword ptr [rdi+0x30]          ; next link
140430844  xor  r8d, r8d
140430847  mov  rcx, rdi
14043084A  call 0x14043B5D0                        ; per-element call #1
14043084F  mov  rax, qword ptr [rdi]
140430852  mov  rcx, rdi
140430855  mov  rax, qword ptr [rax+0x30]          ; vtable slot +0x30
140430859  call qword ptr [rip+0xf3a461]           ; per-element call #2 (indirect)
14043085F  test rbx, rbx
140430862  lea  rdi, [rbx-0x30]
140430866  cmove rdi, rsi
14043086A  test rdi, rdi
14043086D  jne  0x140430840                        ; next element
14043086F  mov  rbx, qword ptr [rsp+0x38]
140430874  mov  rsi, qword ptr [rsp+0x40]          ; epilogue (shared tail)
140430879  add  rsp, 0x20
14043087D  pop  rdi
14043087E  ret
```

Pseudocode:

```text
0x140430800(this /* the bound obj, rcx */):
    esi = 0
retry:
    rdi = this->[0x260]
    if !CAS(&this->[0x260], rdi, 0):  goto retry     # steal the whole list
    if rdi == 0:                      goto done
    rdi -= 0x30
    if rdi == 0:                      goto done
    loop:
        rbx = rdi->[0x30]                            # next link
        per_element_call_1(rdi, 0)                   # 0x14043B5D0
        per_element_call_2(rdi)                      # element vtable+0x30
        rdi = rbx ? rbx - 0x30 : NULL
        if rdi: goto loop
done:
    return
```

Reading (`CONFIRMED` from the code shape):

* **atomically detaches** an intrusive singly-linked list from `boundobj+0x260`
  with a `lock cmpxchg` retry loop, storing `NULL`;
* walks the stolen list and issues exactly **two calls per element**;
* the `-0x30` / `+0x30` pair is the standard MSVC intrusive-list idiom: the link
  is embedded at offset `0x30`, so the stored node pointer is `&element->link`
  and the element base is `link - 0x30`.

```text
return value      = void; epilogue at 0x140430874 is shared
callees           = 0x14043B5D0 (direct) and element vtable+0x30 (indirect)
mutation          = boundobj+0x260 := NULL
locks             = one lock-prefixed CAS; no lock held across the two calls
fields read       = boundobj+0x260; per element +0x30 and its vtable
fields written    = boundobj+0x260 := 0
```

The semantics of the two per-element calls, and therefore the identity of the
elements, are **UNKNOWN** and are the live question. `0x14043B5D0` was earlier
labelled "per-element teardown" and the indirect call "virtual destructor"; both
labels are `HYPOTHESIS` only, derived from call position, and are withdrawn
pending the callee bodies.

### Relation of `0x140430800` to the historical teardown chain

The previous statement `0x140430800 -> 0x1404245F0 = NO` and the label
"unrelated" were **stronger than the evidence**. Corrected classification:

```text
0x140430800 -> 0x1404245F0   DIRECT edge:              DISPROVEN (no direct call)
0x140430800 -> 0x1404245F0   TRANSITIVE relationship:  UNKNOWN
0x140430800 -> 0x140434430   DIRECT edge:              not present in this body
0x140430800 -> 0x140434430   TRANSITIVE relationship:  UNKNOWN
```

Only the direct-edge statements follow from the disassembly. Transitive
reachability requires resolving `0x14043B5D0` and the element `vtable+0x30`
targets, which has not been done. `CONFIRMED` for the direct edges; `UNKNOWN`
for transitivity.

### `0x140430800` does not rearm itself

Nothing in the body reschedules, re-registers or re-arms anything: it steals a
list, issues the two calls per element, and returns. Whether the surrounding
framework re-arms the operation is `UNKNOWN`; the callable itself is one-shot.
`CONFIRMED`

### The bound object is `omega::ObjectManagerImpl`

`CONFIRMED` from the constructor `0x1404292E0`:

```asm
14042930F  lea rax, [rip + 0x108d482]     ; -> 0x1414B6798
140429316  mov qword ptr [rcx], rax       ; install vtable
14042930B  mov qword ptr [rcx + 8], rdx   ; +0x08 = owner/app back-pointer
```

`0x1414B6798 - 8` is a COL with signature 1, `moffset 0`, whose type descriptor
reads:

```text
.?AVObjectManagerImpl@omega@@
```

```text
bound object class = omega::ObjectManagerImpl     CONFIRMED (COL 0x141702418)
allocation site    = 0x140405F20 (0x360 bytes), constructor 0x1404292E0
```

This supersedes "ClientApplicationImpl-related". The earlier assumption that the
5 ms registration's bound object was the application object was wrong; the
constructor at `0x1404292E0` also zeroes `+0x220`/`+0x228`/`+0x238`/`+0x248` and
sets `+0x258 = 1`, which is why the two were conflated.

### The list at `boundobj+0x260` is a lock-free deferred-retirement stack

**Terminology (corrected).** This section previously called `+0x260` a
"deferred-destruction stack" holding "objects awaiting destruction". That label
was stronger than the evidence. What the bytes prove is a lock-free intrusive
LIFO whose elements are handed to a deferred processing step. At the time of the
correction none of the following had been resolved:

```text
0x14043B5D0 semantics             UNKNOWN
element vtable+0x28 target        UNKNOWN
element vtable+0x30 target        UNKNOWN
element class                     UNKNOWN
```

so the queue is described as a **deferred-retirement** / **deferred-reclamation**
stack. "Destruction stack" and "objects awaiting destruction" are used only where
a destruction semantic has actually been resolved.

`CONFIRMED`. The producer is `0x140406530`:

```asm
140406540  mov  rdi, qword ptr [rcx + 8]      ; rdi = ObjectManagerImpl
140406547  mov  rax, qword ptr [rax + 0x28]   ; virtual call on [rdx]
14040654B  call qword ptr [rip + 0xf6476f]
140406551  add  rbx, 0x30                     ; rbx = node->link (link at +0x30)
140406555  prefetchw byte ptr [rdi + 0x260]
140406560  mov  rcx, qword ptr [rdi + 0x260]  ; <-- CAS retry label
140406567  mov  qword ptr [rbx], rcx          ; node->next = head
14040656A  mov  rax, rcx
14040656D  lock cmpxchg qword ptr [rdi + 0x260], rbx   ; push
140406576  jne  0x140406560
14040657D  test rcx, rcx
140406580  sete al                           ; returns (old_head == NULL)
140406588  ret
```

The consumer in `0x140430800` is the exact mirror: it atomically exchanges the
head with `NULL` and walks the list via `element+0x30`. So `boundobj+0x260` is a
**lock-free LIFO stack of objects queued for deferred retirement, with the
intrusive link embedded at object offset `0x30`**.

Key consequences:

```text
element base      = stored node pointer - 0x30
link offset       = element + 0x30
push              = CAS loop, node->next = head; head = node
pop-all           = one lock cmpxchg head -> NULL
producer returns  = (old head == NULL), i.e. "was the stack empty before me?"
```

The return value `(old head == NULL)` is `CONFIRMED` as a value. The earlier
claim that it is the arming signal — "the caller uses 'I pushed onto an empty
stack' to decide whether a drain must be scheduled" — is `RETRACTED`: neither
caller reads `al`. It is **not** evidence of timer arming.

A second, structurally similar `+0x260` CAS loop exists at `0x14043A390`
(fn `0x14043A390 - 0x14043A79B`). It is **not** a second *manager instance*:
resolving vtable `0x1414B69A8` yields `omega::PacketSocket`, so that `+0x260` is a
different queue on a different class that merely shares the offset number.
`CONFIRMED` that the lock-free LIFO idiom is reused across the `omega`
socket/manager family; `UNKNOWN` how many instances share it.

### Correction: `0x14043B5D0` is a real image function, and the "one call per element" label was premature

`0x14043B5D0` has a full prologue (`push rbp/rbx/rsi/rdi/r12-r15`, `sub rsp,
0x808`) and takes a critical section at `[rcx+0x80]+0x10`; it is an ordinary
image function, not a thunk. Its complete semantics are **UNKNOWN** — only its
head was read. The earlier label "per-element teardown" remains `HYPOTHESIS`.

Likewise `element vtable+0x30` is **`HYPOTHESIS`, not proven to be a
destructor**. What is established is only that `0x14043A390` calls the same
`vtable+0x30` slot on objects it is retiring, and that `0x14043A390` also calls
`vtable+0x28` (retain/release-shaped) and `vtable+0x00` (per-object work)
elsewhere. Resolving `vtable+0x00/+0x28/+0x30` against a concrete element class
is the next required step.

### The 5 ms timer is a coalescing drain deadline

`0x140430800` performs no polling at all: it steals and retires. The 5 ms period
therefore reads as **a coalescing window**: retirements accumulate on the stack
and one drain pass collects the batch. `0x140430800` does not rearm itself
(`CONFIRMED`).

```text
5 ms operation = deferred-retirement drain deadline (coalescing)
```

`HYPOTHESIS` for the coalescing reading. Note it is **not** supported by the
producer's `sete al`: that return value is discarded by both callers. The
`CONFIRMED` parts are only that the callable drains without polling and never
rearms itself.

### The operation object produced by the factory, byte-for-byte

`0x1404595E0` allocates **`0x78`** bytes and constructs the operation
(`CONFIRMED`):

```asm
140459613  mov  ecx, 0x78
14045961B  call mm_alloc
14045967A  mov  dword ptr [rdi + 0x28], ebp   ; +0x28 = timeout  (r9d)
140459685  mov  byte ptr  [rdi + 0x2c], al    ; +0x2C = flag     ([rsp+0x20])
140459688  mov  byte ptr  [rdi + 0x2d], 0     ; +0x2D = FINISHED := 0
14045968C  lea  rbx, [rdi + 0x30]             ; +0x30 = callable slot
1404596C0  call 0x1402CB8D0                   ; build the callable
1404596C5  mov  qword ptr [rbx], rax          ; +0x30 = callable
```

This settles what the previously measured runtime values are:

```text
object+0x28 = timeout in ms         (5 for this operation)   CONFIRMED
object+0x2C = the registration flag (1 here)                 CONFIRMED
object+0x2D = FINISHED, starts 0                             CONFIRMED
object+0x30 = the callable                                   CONFIRMED
object+0x38 = the callable's context                         CONFIRMED
```

**Correction:** `+0x2C` is therefore not an emergent "wait-mode selector"; it is
the registration's own flag argument. Both `0x14042F960` registrations pass
`[rsp+0x20] = 1` at `0x14042FA23` and `0x14042FAFA`, and that value lands at
`+0x2C`. The branch in `0x140423DD0` that tests it is testing a
**registration-time flag** whose meaning is `HYPOTHESIS`, not a runtime mode
switch. `CONFIRMED` for the dataflow; semantics still `HYPOTHESIS`.

### Closure bodies are heap-materialised, so pointer scans cannot find them

Runtime observation recorded `[operation + 0x00] = 0x1414B6761`. That value does
not exist anywhere in the retail image. Whole-image scans for the 8-byte values
of `0x140430800`, `0x1404305D0`, `0x14042FD80`, `0x1404245F0` and `0x140423DD0`
all return **zero** hits, and so does a scan for `0x1414B6781`. `CONFIRMED`

The table at `0x1414B6760` in the file holds `0x140433C90`, `0x1403C1B20`,
`0x140433D20`, `0x140433DB0` — ordinary image functions, not the contents the
runtime table showed. The operation's dispatch table is copied into heap storage
at runtime.

**Method consequence:** a raw 8-byte pointer scan can never locate a closure's
registration site in this binary. Registration sites must be found by locating
the `lea rax, [rip+...]` that materialises the address into a stack slot
immediately before a `0x140423B50` call. That is the method used above and it is
the only one that worked.

### `0x140430620` is the application tick, and its cancel branch targets `app+0x248`

Complete semantic pseudocode, recovered from the full function body
(`CONFIRMED`; field offsets and branch addresses are exact):

```text
0x140430620(this /*app*/):
  EnterCriticalSection(app + 0x28)
  if app->[0x258] == 0:                    # 0x140430660 / je 0x140430757
      goto SHUTDOWN_BRANCH
  if app->[0x248] != 0:                    # 0x14043066D
      goto DONE                            # already scheduled -> do nothing
  op = app->[0x220]                        # 0x14043067A  registered operation
  closure = { fn = 0x1404305D0, arg = app }        # 0x140430681 materialises it
  new_op = schedule(op, closure, timeout = 0x3E8)  # 0x1404306F4 -> 0x140423B50
  app->[0x248] = new_op                            # 0x140430704 -> 0x1400C67E0
                                                   #   (shared_ptr assign, the
                                                   #    old value's refcount drops)
  goto DONE

SHUTDOWN_BRANCH:                            # 0x140430757
  if app->[0x248] == 0:                   # 0x140430757/75E
      goto DONE
  op = app->[0x220]                       # 0x140430763
  tmp = app->[0x248]                      # 0x140430772, refcount bumped at
                                          #   0x14043078B (lock xadd dword +8)
  cancel(tmp)                             # 0x140430798 -> 0x1403FC050
  app->[0x248] = 0                        # 0x1404307B0
  app->[0x250] = 0                        # 0x1404307B7
  goto DONE

DONE:                                       # 0x1404307D3
  LeaveCriticalSection(app + 0x28)
  return
```

So `0x140430620` is a **tick that does one of two mutually exclusive things**:
when `app+0x258` is non-zero it may **arm** the 1000 ms operation; when
`app+0x258` is zero it **cancels** the outstanding one. It never does both in
one call. `CONFIRMED`

Answering the phase questions directly:

```text
input object                 = the ClientApplicationImpl instance
app field offsets used       = +0x28 mutex, +0x220 operation identity,
                               +0x248/+0x250 cancellable slot,
                               +0x258 mode byte
operation/shared_ptr slots   = +0x220 (read), +0x248/+0x250 (read+write)
calls to 0x1403FC050         = exactly one, at 0x140430798
rearms operations            = YES, but only on the app+0x258 != 0 path,
                               and only when +0x248 is empty
replaces +0x228 / +0x238     = NO; it never touches those slots
is it a scheduler callback   = YES; it is the application tick body
```

(For the record: `0x14042F960` did store `+0x228`/`+0x238`, but in the poller's
program the `+0x238` slot ends up zero — see the `app+0x248` note below.)

### Phase 2 — the exact slot cancelled at `0x140430798`

Traced from pointer provenance, not proximity (`CONFIRMED`):

```asm
140430757  mov  rax, qword ptr [rdi + 0x248]   ; rax = the slot value
14043075e  test rax, rax
140430761  je   0x1404307d3                    ; nothing outstanding -> skip
140430763  mov  rcx, qword ptr [rdi + 0x220]   ; rcx = operation identity
140430772  mov  qword ptr [rbp - 0x19], rax    ; build shared_ptr{ptr=slot}
140430776  mov  rax, qword ptr [rdi + 0x250]   ; its control block
140430781  test rax, rax
14043078b  lock xadd dword ptr [rax + 8], esi  ; retain
140430798  call 0x1403fc050                    ; rdx = &shared_ptr (rsp-based)
```

```text
0x140430798 cancels:  app+0x248 / app+0x250
                      (the 1000 ms operation armed by this same function)
```

The argument is a stack-local `shared_ptr` constructed from
`app+0x248`/`app+0x250` — not from `+0x220`, `+0x228` or `+0x238`. `rcx` is
loaded from `app+0x220` but is overwritten before the call and does not reach
`0x1403FC050`. `CONFIRMED`

**Branch that causes the cancellation** (`CONFIRMED`):

```text
branch address: 0x140430667  je 0x140430757
tested field:   byte ptr [app + 0x258]
expected value: 0
actual semantic consequence: application-tick mode == 0 (stop/shutdown mode)
which operation is cancelled: the 1000 ms operation in app+0x248, whose closure
                               body is 0x1404305D0
```

So the cancelling decision is **not** about a string lookup, a timeout, or a
connection state. It is the single byte `app+0x258`, which the
`ClientApplicationImpl` constructor (`0x1404292E0` at `0x140429614`) initialises
to **1**. Its only other writer found in the image is `0x140120FC0`, which also
calls `0x140430620` at `0x140121182` and writes `[rsi+0x258]`. `CONFIRMED` for
the initialisation and the writer set; the semantic name of the mode is
`HYPOTHESIS`.

### Which application object this is

`app+0x08` is a `boost::shared_ptr` to the real `ClientApplicationImpl`, and
`app+0x248` is written **only** inside `0x14042F960`, `0x14042FBA0` and
`0x140430620` — all three in the `ClientApplicationImpl` tile. The runtime
poller's `arg1` (`0x14B3DA0`) is that instance. `CONFIRMED`

Consequence worth recording because it contradicts a natural assumption: the
`0x14042F960` call that registers the 5 ms operation in `+0x238` also registers
the 500 ms closure in `+0x228`, but in the poller's program only one of those
registrations takes effect — the `+0x248` slot is the one this tick arms, and
the runtime `[app+0x248]` lifetime is governed by the `app+0x258` branch above.
The `+0x238` 5 ms operation observed reaching `0x140423DD0` is therefore **not**
the operation this tick cancels. `CONFIRMED`

### Phase 3 — `0x1403FC050` passes no status

Full body (`CONFIRMED`):

```text
0x1403FC050(rcx = operation context, rdx = shared_ptr to the callable):
  rcx = *rcx                       ; 0x1403FC063 dereference the context
  tmp = *rdx                       ; 0x1403FC070 the callable
  ctl = *(rdx + 8)                 ; 0x1403FC078
  if ctl: lock xadd [ctl+8], 1     ; 0x1403FC08E retain (build a real shared_ptr)
  call 0x140423A70(rcx, &tmp)      ; 0x1403FC098
  release ctl                      ; 0x1403FC09E -> 0x1400B79F0
  return
```

```text
argument layout   = (callable_context, shared_ptr<callable>)
refcount ops      = one retain before the call, one release after
special result    = NONE
cancel vs timeout = NOT differentiated; no status value is supplied
context passed to 0x140423A70 = identical in shape to the timed path
```

Third argument (`r8`) is not used at all, and `0x140423A70` never reads a status
register before publishing. **`0x140423A70` therefore cannot distinguish
cancellation from ordinary completion**, exactly as the convergence note says —
and that is now proven from the callee's own operand use, not inferred.
`CONFIRMED`


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
