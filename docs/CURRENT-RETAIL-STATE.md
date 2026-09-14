# Current Retail State

**This file is authoritative for the current reverse-engineering model.**
`docs/retail-protocol-evidence.md` is a chronological lab notebook that
deliberately preserves superseded hypotheses; when the two conflict, **this file
wins**. Every claim below was re-checked against static evidence or a captured
runtime witness at the checkpoint recorded at the bottom.

## `+0x260` deferred PacketSocket service queue — current verdict

**Causality answer (this pass).** The `+0x260` / 5 ms / `0x14043B5D0` mechanism is
**downstream transport servicing, not the cause of any failure.** It carries an
already-produced message. The confirmed Close verb `0x1404123D0` serializes its
`0x43DB3479` envelope and then calls the same `0x14043B460` service function that
IntroduceConnection and both ID-signature messages use, so the 5 ms path delivers
a Close that has already been decided. It is removed from the causal failure
boundary; the decision point is upstream, at whatever decides to invoke
`0x1404123D0`.

```text
ObjectManagerImpl+0x260 = lock-free intrusive LIFO                     CONFIRMED
queue element class = omega::PacketSocket                              CONFIRMED
0x140430800 drains the whole stack, once per pass                      CONFIRMED
element primary vtable 0x1414B6968, COL 0x141702F08                    CONFIRMED
element vtable+0x28 -> 0x14043DB20  (release/detach gate)              CONFIRMED
element vtable+0x30 -> 0x14043DBF0  (node-list detach/clear)           CONFIRMED
0x14043B5D0 this-operand = the PacketSocket element, NOT the manager   CONFIRMED
0x14043B5D0 = PacketSocket transmit/flush, NOT teardown/cleanup        CONFIRMED
drain path reaches 0x140452360 (transmit hand-off)                     CONFIRMED
drain path frees the PacketSocket                                      DISPROVEN
producer 0x140406530 returns (old_head == NULL)                        CONFIRMED
any caller branches on that AL                                         DISPROVEN
AL=1 schedules the 5 ms drain                                          DISPROVEN
"0x1414B69A8 is a second manager family"                               RETRACTED
5 ms coalescing window                                                 HYPOTHESIS
literal destruction/retirement of the element in the drain             DISPROVEN
Close verb 0x1404123D0 uses this same service path                     CONFIRMED
other message types use the same service path                          CONFIRMED
PacketSocket state field semantics (4, 7, ...)                         UNKNOWN
transitive path to 0x1404245F0 / 0x140434430                           UNKNOWN
-- ConnectionOpen causal chain (this pass) --
event class = omega::ObjectSurrogateEventConnectionOpen (size 0x38)    CONFIRMED
event+0x18 = the connection, event+0x20 = the routed-peer object       CONFIRMED
listener = [[event+0x18]+0x100], class omega::Object, vt 0x1414B5C10   CONFIRMED
listener vtable+0x28 -> 0x14040A970 (releases payload, returns 0)      CONFIRMED
listener vtable+0x70 -> 0x14040AEC0 (THE DECIDER)                      CONFIRMED
0x140434430 -> 0x14040AEC0 = direct virtual dispatch (always taken)    CONFIRMED
0x14040AEEB = ATOMIC NULL-PROBE / CURRENT-PEER LOAD                  CONFIRMED
              (zero-to-zero compare-exchange; see the operand note below)
0x14040AEEB mutates conn+0x88                                          NEVER
the +0x40 test reads the CAS DESTINATION operand, i.e. the peer
  currently attached at conn+0x88, NOT the ConnectionOpen payload peer CONFIRMED
skip-Close condition = current_peer+0x40 is exactly the string "*"     CONFIRMED
peer+0x40 writer = the peer ctor 0x140412907 (parameter p5, single writer)
                                                                       CONFIRMED
peer+0x40 source = p5 of 0x140412820, which at BOTH live call sites is the
                   same argument-expression as p2 (+0x00): the first qword of
                   the route/endpoint record's StrRef                  CONFIRMED
new_peer+0x00     = that same name string, i.e. real name text, never a
                   structural pointer and never a vtable                 CONFIRMED
peer+0x20 = derived composite "p3:p2", NOT a constructor argument      CONFIRMED
why peer+0x40 is "" on the failing path                              UNKNOWN
  (the previous pass blamed an empty p2; that provenance is retracted, and the
   recorded witness cannot separate an empty p2 from peer A not being the
   predecessor of peer B)
peer+0x40 semantic role = the routed peer's name string, tested for the
                           exact wildcard "*"                          CONFIRMED
"*" is a real client-side wildcard name value, not a sentinel          CONFIRMED
endpoint-wildcard experiment suppresses Close                          DISPROVEN
server controls peer+0x40                                              UNKNOWN
indirect server influence over peer+0x40                               HYPOTHESIS
exact wire field supplying the upstream value                          UNKNOWN
D4                                                                     UNKNOWN
```

### The decision input, stated exactly (this pass)

```text
0x14040AEC0 tests  [peer_attached_at_conn+0x88] + 0x40
not                [ConnectionOpen event payload peer] + 0x40
```

The `cmovne` at `0x14040AF04` executes **only in the CAS-failure arm**, so the
pointer whose `+0x40` is inspected is `RAX`, which after a failed
`lock cmpxchg` is the destination operand `[rdx+0x88]`. When the CAS *succeeds*
the field was already NULL and the tested string is the empty-string singleton
`0x14156BD60` — in that arm no peer is inspected at all. Both operands of the CAS
are zero (`xor ecx,ecx` / `xor eax,eax`), so the instruction can never change a
non-NULL `conn+0x88`, and can never change a NULL one either.

```text
instruction class   = ATOMIC NULL-PROBE / CURRENT-PEER LOAD
field mutation      = NONE
runtime witness     = ZF=0, RAX <- peer B, conn+0x88 unchanged   CONFIRMED

raw mechanics       = lock cmpxchg [rdx+0x88], rcx   with RAX=0, RCX=0
                      if [mem] == 0: [mem] = 0 ; ZF=1
                      else:          RAX = [mem] ; [mem] unchanged ; ZF=0
                      Both arms leave the logical value of conn+0x88
                      exactly as it was, so the instruction can never
                      detach, clear, or remove anything.

"unconditional detach"                             SUPERSEDED
"conditional detach"                               SUPERSEDED
"compare-and-clear"                                SUPERSEDED -- mechanically it
   is a zero-to-zero compare-exchange, so describing it as a "clear" implies a
   mutation that provably cannot happen. Label it ATOMIC NULL-PROBE /
   CURRENT-PEER LOAD instead, and keep the CMPXCHG mechanics as raw detail.
```

---

## The `0x1404245F0` path — newly recovered (this pass)

```text
0x1404245F0 = per-owner deferred element drain (destroys list elements)
              materialised ONLY at 0x1403FC11A inside 0x1403FC0B0
              registered through 0x140423B50 with r9d = 0 (no timeout)
              bound object = the owner                                      CONFIRMED
0x140434430 = vtable+0x08 of omega::ObjectSurrogateEventConnectionOpen,
              a notifier over [[this+0x18]+0x100]                           CONFIRMED identity
0x140434430 -> 0x14040AEC0 dispatch                                   CONFIRMED
              (direct virtual dispatch, listener vtable+0x70)
first non-cleanup decision that starts this teardown                        UNKNOWN
primary failure decision vs secondary cleanup                    the Close
              DECISION is 0x14040AEC0; whether reaching it is itself the
              primary failure is still UNKNOWN
```

---

The causal boundary remains upstream and was pushed back one layer this pass.
`0x1404245F0` is now identified concretely.

```text
0x1404245F0 = per-owner deferred EVENT queue drain                CONFIRMED
               (all 12 producers queue omega::ObjectSurrogateEvent-derived
                objects; the queue is homogeneous, not a generic element list)
its single materialisation is 0x1403FC11A, inside 0x1403FC0B0     CONFIRMED
it is registered through 0x140423B50 with r9d = 0 (no timeout)    CONFIRMED
the registration site is the same function that ADDS to the list  CONFIRMED
```

### What `0x1404245F0` does

**Terminology (`CONFIRMED`).** All 12 call sites of `0x1403FC0B0` queue an
`omega::ObjectSurrogateEvent`-derived object. The queue is therefore
**homogeneous**, and the drain is described as a **per-owner deferred event queue
drain** rather than a generic "element drain". Every producer and its event type:

```text
fn 0x140435CE0   omega::ObjectSurrogateEventConnectionOpen
fn 0x1404360A0   omega::ObjectSurrogateEventConnectionPDU
fn 0x1404362A0   omega::ObjectSurrogateEventConnectionClose
fn 0x140436590   omega::ObjectSurrogateEventConnectionFailure
fn 0x140436890   omega::ObjectSurrogateEventConnectionLimitExceeded
fn 0x140436A70   omega::ObjectSurrogateEventConnectionPing
fn 0x140436C80   (no vtable install on this path; producer not classified)
fn 0x140436DC0   omega::ObjectSurrogateEventNegotiationSocketClose
fn 0x140437700   omega::ObjectSurrogateEventConnectionStatus   (3 sites)
```

So the old "collection teardown" wording is `SUPERSEDED`: this is normal deferred
event delivery, and `ObjectSurrogateEventConnectionOpen` is simply one event kind
among eight.

Function extent `0x1404245F0 - 0x140424749` (0x159 bytes, single `.pdata` record,
no chained unwind entries), 71 instructions.

```c
// rcx = owner.  Returns void.  Lock is at owner+0xC0, list sentinel at owner+0xF0.
void Owner::drain_pending() {
    EnterCriticalSection(&owner->[0xC0]);
    owner->[0x100] = NULL;            // clear the registered-operation handle
    owner->[0x108] = NULL;
    destroy_shared(owner->[0x100]);   // 0x1400B79F0 on the old handle

    int n = 0;                        // count elements in the circular list
    Node* s = &owner->[0xF0];
    for (Node* p = s->next; p != s; p = p->next) n++;

    LeaveCriticalSection(&owner->[0xC0]);

    while (n != 0) {
        // 0x1404246A8 is the gate; 0x1404246D0..0x14042470C is the jiffies read
        if (now_ms() < 0) return;                 // abort the drain

        Node* e = pop_front(&owner->[0xF0]);      // 0x140424550
        if (e) {
            Node* o = e - 8;                      // container_of
            (*o)[0x08](o);                        // vtable+0x08
            (*o)[0x00](o, 1);                     // vtable+0x00 with edx=1
        }
        n--;
    }
}
```

`0x140424550` (the pop helper, `0x140424550 - 0x1404245E1`) takes the same owner
lock, unlinks the first real node of the circular list at `owner+0xF0`, drops the
lock, and returns `node - 8`.

```text
list             circular doubly-linked, sentinel at owner+0xF0
                 node->next at node+0x00, node->prev at node+0x08
element          node - 8; destroyed via its own vtable
lock             owner+0xC0, taken and released inside both functions
registered slot  owner+0x100 (two-pointer shared_ptr)
```

So `0x1404245F0` is a **bounded drain that pops every element off a per-owner
circular list and destroys each one**, aborting early via a jiffies comparison.
It is a teardown of *pending elements*, not of the owner itself.

### The insertion / registration function `0x1403FC0B0`

Extent `0x1403FC0B0 - 0x1403FC204`. It does both halves of the producer contract:

```c
// rcx = &owner, rdx = new node
void Owner::add_element(Node* node) {
    Owner* owner = *rcx;                     // rsi = [rcx]
    EnterCriticalSection(&owner->[0xC0]);

    // link `node` into the circular list at owner+0xF0
    Node* s = &owner->[0xF0];
    node->[0x10] = s->prev;
    node->[0x08] = s;
    s->prev->next = &node->[0x08];
    s->prev = &node->[0x08];

    if (owner->[0x100] == NULL) {            // register the drain if not armed
        LEA 0x1404245F0 -> [rsp+0x40];       // 0x1403FC11A  <-- the only site
        [rsp+0x48] = owner;                  // bound object
        [rsp+0x50] = NULL;
        validate_closure(0x1400C37B0);        // may set the +1 "bound method" tag
        op = 0x140423B50(owner, closure, flag=0, r9d=0);   // 0x140423B50
        shared_ptr_move(&owner->[0x100], op);              // 0x1400C67E0
    }
    LeaveCriticalSection(&owner->[0xC0]);
}
```

The materialisation instruction is exactly one site:

```asm
1403fc11a  lea  rax, [rip + 0x284cf]      ; -> 0x1404245F0
1403fc121  mov  [rsp + 0x40], rax         ; callable slot 0
1403fc126  mov  [rsp + 0x48], rsi         ; bound object = the owner
```

and there is **no** 8-byte raw pointer to `0x1404245F0` anywhere in the image
(`xref_le64` returns 0), which is why the older raw-pointer scan could not find
it. Registration is through the **same** `0x140423B50` operation factory used by
the timer registrations, here with `r9d = 0` (no timeout).

`0x1403FC0B0` has 12 callers, all inside `0x140435CE0`-`0x1404385D0`, and every
one of them is an "add one element, then arm the drain if idle" site.

### The inbound dispatcher, and where this list is fed from

`0x14042B990 - 0x14042BB20` is the inbound opcode dispatcher. Its complete branch
set, read from the `cmp r9d, <opcode>` chain (`CONFIRMED` this pass, corrected):

```text
opcode        handler                  message
0xA609E6A7    0x14042BCA0              RequestIDSignature   (`call` at 0x14042B9F2)
0x6731C5AF    0x14042C300              ReplyIDSignature     (`call` at 0x14042BA70)
0x8B0D492F    0x14042C910              IntroduceConnection  (`call` at 0x14042BAB2)
0x43DB3479    0x14042BAC5 edx=1 r8d=0  Close        -> 0x1404123D0(conn,1,0)
0x598D9A7     0x14042BAD5 edx=0 r8d=0  RequestClose -> 0x1404123D0(conn,0,0)
```

```text
0x14042C300 is the ReplyIDSignature handler (dispatcher arm 0x6731C5AF)   CONFIRMED
0x14042C300 is the RequestIDSignature handler (arm 0xA609E6A7)            DISPROVEN
```

This reproduces the previously recorded fact that an inbound *Close* is routed
with `arg2 = 1` (no reply envelope) while inbound *RequestClose* is routed with
`arg2 = 0`.

Both `0x14042C300` and `0x14042C910` reach `0x140412180`, which is the function
that attaches a routed peer and feeds the element list:

```asm
14042c754  lock cmpxchg qword ptr [rdx + 0x88], rdi   ; PROBE, not an attach
                                                      ; (rdi = 0, eax = 0)
```

That instruction is an **atomic null-probe used as a current-peer load**, not
an attach: `rcx`/`rdi` is 0 for the whole function, so the compare-exchange can
never mutate `conn+0x88`. The attach is at
`0x140412A4F` inside `0x140412820`, reached from the `0x140412180` call at
`0x14042c782` that immediately follows.

so the element list is fed from the **inbound ReplyIDSignature and
IntroduceConnection paths**, and the same `0x140412180` is what calls
`0x140435CE0` → `0x1403FC0B0` (add + arm).

### The ConnectionOpen event's payload peer is the *new* peer

`0x140412180` builds the event at its tail (`0x140412396` copies `rdi` = the
connection into the wrapper, then calls `0x140435CE0`), and its sixth argument is
`[[connection+0x88]+0x00]`. Because `0x140412820` has already stored the new peer
at `connection+0x88` by then, the payload peer and the attach destination agree:
the event payload is the **newly created** peer, whose `+0x40` is
`[previous peer +0x00]`.

```text
ConnectionOpen payload peer  = the peer created by this 0x140412180 call
conn+0x88 at that moment     = the same peer (0x140412A4F already ran)
tested peer+0x40             = that same peer's +0x40
                             = [the PREVIOUS peer's +0x00]
```

Note the consequence: the wildcard test at `0x14040AEC0` inspects the **previous**
peer's name, because that is what the new peer copied into `+0x40`. It does
**not** inspect the new peer's own name field (`+0x00`/`+0x10`). This is the
non-obvious part of the whole chain and it is `CONFIRMED` both statically
(`cmovne r8, rax` at `0x14042c75d`, `mov [rsp+0x40], rax` at `0x14042b6e9`) and at
runtime (`peerB+0x40` == `peerA+0x00` == `0x14156BD60`).

### `0x140434430` is a vtable slot of `omega::ObjectSurrogateEventConnectionOpen`

It materialises in a **different shape** from `0x1404245F0`, which matters for
how it must be searched:

```text
xref_indexed(0x140434430) = []            no lea, no direct call
xref_le64(0x140434430)    = [0x1414B6940] one raw pointer, and it is in a vtable
```

The containing table resolves cleanly (`CONFIRMED`):

```text
COL              0x1417029F8   signature 1, self-pointer verified
vtable base      0x1414B6938   (COL sits at vtable-0x08, same convention as the
                                proven PacketSocket vtable 0x1414B6968)
class            omega::ObjectSurrogateEventConnectionOpen
slot             vtable+0x00 = 0x1404344F0 (scalar deleting destructor, size 0x28)
                 vtable+0x08 = 0x140434430  <-- our function
```

Base-class list of that class (from its Class Hierarchy Descriptor):

```text
.?AVObjectSurrogateEventConnectionOpen@omega@@
.?AVObjectSurrogateEvent@omega@@
.?AVApartmentEvent@omega@@
.?AUintrusive_list_node@eastl@@          (mdisp 0, pdisp 8)
```

`0x140434430` reads `[this+0x18]` and `[this+0x20]`, takes the object at
`[[this+0x18]+0x100]`, and notifies it twice, each time passing a copy of the
`[this+0x20]` intrusive pointer:

```text
1. (*obj)->vtable[0x28](obj, &copy_of_[this+0x20])
   if that returns non-zero -> skip step 2
2. (*obj)->vtable[0x70](obj, &copy_of_[this+0x20])
```

Its sibling `0x1404344F0` is the scalar deleting destructor: it releases
`[this+0x20]` and `[this+0x18]` through their `vtable+0x30`, installs the vtable,
and calls `operator delete` with `edx = 0x28`.

```text
0x140434430 identity   a virtual method of
                       omega::ObjectSurrogateEventConnectionOpen that notifies
                       the listener at [[this+0x18]+0x100] with the captured
                       value at [this+0x20]                          CONFIRMED
semantics of the two notified slots (vtable+0x28, vtable+0x70)      UNKNOWN
dispatch relationship 0x140434430 -> 0x14040AEC0                    UNKNOWN
```

It is an **event/notification object** whose class also derives from
`eastl::intrusive_list_node`, so instances can live in an intrusive collection —
but it is not itself the owner of the `0x1404245F0` collection.

### What this changes about the boundary

```text
0x1404245F0      = per-owner deferred element drain (destroys list elements)
                   CONFIRMED
0x140434430      = vtable+0x08 of omega::ObjectSurrogateEventConnectionOpen,
                   a notifier that calls [[this+0x18]+0x100] via vtable+0x28
                   then vtable+0x70                                CONFIRMED identity
0x14040AEC0      = routed-peer classifier that can call 0x1404123D0
0x140434430 -> 0x14040AEC0 dispatch                              CONFIRMED
primary failure decision   the Close decision itself is 0x14040AEC0, whose
                           input is now fully traced; what makes the
                           ConnectionOpen event fire at this point is UNKNOWN
primary failure vs secondary cleanup                               UNKNOWN
```

The old label "collection teardown" for `0x1404245F0` is **narrowed**: it is the
drain of a *pending-element* list, whose element type is not yet named.

## The ConnectionOpen subscriber chain — recovered (this pass)

This pass closed the causal question from `ObjectSurrogateEventConnectionOpen`
through to the Close verb. The chain is now complete and **direct**:

```text
omega::ObjectSurrogateEventConnectionOpen  (a queued event, one of 8 kinds)
  event+0x18 = the connection object        (intrusive_ptr)
  event+0x20 = the routed-peer object       (intrusive_ptr)
        |
        v  0x140434430 = vtable+0x08, the event's notification method
  listener = [ [event+0x18] + 0x100 ]       (an omega::Object)
        |
        +-- listener->vtable+0x28  ->  0x14040A970   returns 0, so...
        +-- listener->vtable+0x70  ->  0x14040AEC0   <-- THE DECIDER
                    |
                    +-- lock cmpxchg [conn+0x88], 0  (CONDITIONAL clear:
                    |      expected RAX=0, replacement RCX=0; only a NULL
                    |      field matches, so this is a no-op on the failing
                    |      path -- conn+0x88 is NOT changed here)
                    +-- IF the CAS failed: rcx = [RAX+0x40]  (the attached peer)
                    +-- IF peer name == "*" exactly:  skip
                    +-- else:  0x1404123D0([arg2] payload peer, 0, 0)  <-- Close
```

**`0x14040AEC0` runs no detach.** The header sentence
```
0x14040AEC0 detaches conn+0x88 unconditionally
```
is `SUPERSEDED`. See the CMPXCHG section below.

### The event and its two payloads

`0x140435CE0` (`0x140435CE0 - 0x14043609F`) builds
`omega::ObjectSurrogateEventConnectionOpen`:

```asm
140435e64  mov  rax,[rip+..] / mov ecx,0x38 / call .. ; mm_alloc(0x38)
140435f8e  mov  rcx, rbx                              ; rbx = the 0x38-byte object
140435f91  call 0x140434110        ; base ctor -> installs 0x1414B6950 then 0x1414B68F0
140435f97  lea  rax,[rip+..]       ; 0x1414B6938
140435f9e  mov  [rbx], rax         ; install ObjectSurrogateEventConnectionOpen vtable
140435fa1  mov  rcx,[rbp+0x7f]
140435fa5  mov  [rbx+0x20], rcx    ; event+0x20 = the captured object
...
140435fea  mov  rdx, rbx
140435fed  mov  rcx, rsi           ; rsi = the queue owner
140435ff0  call 0x1403FC0B0        ; enqueue the event
```

```text
event size            0x38                                          CONFIRMED
event vtable          0x1414B6938, COL 0x1417029F8                  CONFIRMED
class                 omega::ObjectSurrogateEventConnectionOpen    CONFIRMED
event+0x18            the connection object (intrusive_ptr to it)   CONFIRMED
event+0x20            the routed-peer object (intrusive_ptr to it)  CONFIRMED
queue owner           the object at [connection+0x68]               CONFIRMED
```

The two payloads come from the peer-attach path `0x140412180`, called by the
**ReplyIDSignature** handler (`0x14042C300`, dispatcher arm `0x6731C5AF`):

```asm
14042c754  lock cmpxchg qword ptr [rdx + 0x88], rdi   ; atomic probe (rdi = 0)
14042c77f  mov  rcx, r10                              ; the connection
14042c782  call 0x140412180                           ; -> 0x140435CE0 -> 0x1403FC0B0
```

The actual attach is not at `0x14042c754`; it is `0x140412A4F` inside
`0x140412820`, which the `0x140412180` call at `0x14042c782` performs.

### The listener object and the two dispatched slots

`[connection+0x100]` is the listener, and it is an **`omega::Object`** — the same
object that `0x14040A9A0` and `0x14040AB60` install:

```text
listener class   omega::Object                 CONFIRMED
listener vtable  0x1414B5C10, COL 0x141700940  CONFIRMED
  vtable+0x28 -> 0x14040A970    CONFIRMED
  vtable+0x70 -> 0x14040AEC0    CONFIRMED   <-- the decider
```

`0x140434430` dispatches with the payload **by pointer**:

```asm
14043444c  mov  rax,[rcx+0x18]        ; event+0x18 = the connection
140434450  mov  rbx,[rax+0x100]       ; listener
140434460  mov  rax,[rbx]             ; listener vtable
140434463  mov  rsi,[rax+0x28]        ; slot +0x28
140434471  mov  rcx,[rcx+0x20]        ; event+0x20 = the peer
140434475  mov  [rsp+0x40], rcx       ; a one-word ref wrapper {ptr, NULL}
140434492  mov  rcx, rbx
140434498  call rsi                   ; listener->vtable+0x28(listener, &wrapper)
14043449e  test al, al
1404344a0  jne  0x1404344e0           ; non-zero would suppress the next call
1404344a5  mov  rsi,[rax+0x70]        ; else slot +0x70
1404344da  call rsi                   ; listener->vtable+0x70(listener, &wrapper)
```

**Which branch runs for ConnectionOpen (`CONFIRMED`):** `+0x28` is `0x14040A970`,
whose whole body is 12 instructions and always returns `al = 0`:

```asm
14040a970  mov  [rsp+0x10], rdx
14040a982  mov  rcx, [rdx]            ; the wrapped pointer
14040a988  je   0x14040a997           ; NULL -> skip
14040a98a  mov  rax,[rcx] / mov rax,[rax+0x30] / call rax   ; release
14040a997  xor  al, al                ; <-- always 0
14040a99d  ret
```

```text
listener vtable+0x28 = 0x14040A970 = a release/drop of the wrapper payload,
                                     returning 0 unconditionally  CONFIRMED
=> the +0x70 branch ALWAYS executes for ConnectionOpen            CONFIRMED
listener vtable+0x70 = 0x14040AEC0 = the decider                   CONFIRMED
```

So `0x140434430 → 0x14040AEC0` is one **direct virtual dispatch**:
`ObjectSurrogateEventConnectionOpen` notification → `listener->vtable+0x70`.
The old "(0x1404245F0 → 0x140434430) is collection teardown" phrasing is
`SUPERSEDED`: it is generic deferred event delivery followed by event dispatch.

### `0x14040AEC0` — the decider, byte-for-byte

Full body, re-read from the image this pass (`0x14040AEC0 - 0x14040AF87`, 0xC7
bytes). `CONFIRMED`.

```asm
; rcx = listener (omega::Object), rdx -> ref-wrapper { [0]=peer, [8]=control }
14040aec0  mov  [rsp+0x10], rdx
14040aed5  mov  rbx, rdx              ; rbx = the wrapper
14040aed8  mov  rdi, rcx              ; rdi = the listener
14040aedb  mov  rdx, [rdx]            ; rdx = wrapper[0]  = the payload peer
14040aede  test rdx, rdx
14040aee1  je   0x14040af6a           ; NULL payload -> no Close, just release
14040aee7  xor  ecx, ecx              ; RCX = REPLACEMENT = 0
14040aee9  xor  eax, eax              ; RAX = EXPECTED    = 0
14040aeeb  lock cmpxchg [rdx+0x88], rcx
14040aef4  lea  rcx, [rip+0x1160e65]  ; rcx = 0x14156BD60 = the EMPTY string
14040aefb  je   0x14040af08           ; CAS SUCCEEDED -> rcx stays the empty string
14040aefd  mov  rax, [rax+0x40]       ; CAS FAILED -> RAX = [rdx+0x88] = old peer
14040af01  test rax, rax
14040af04  cmovne rcx, rax            ; if that peer name is non-NULL, use it
14040af08  movzx eax, byte ptr [rcx]
14040af0b  cmp  al, byte ptr [rip+0x11633bf]   ; 0x14156E2D0 = '*'
14040af11  jne  0x14040af1f
14040af13  movzx eax, byte ptr [rcx+1]
14040af17  cmp  al, byte ptr [rip+0x11633b4]   ; 0x14156E2D1 = 0
14040af1d  je   0x14040af6a           ; exact "*" -> SKIP the Close
14040af1f  xor  r8d, r8d
14040af22  xor  edx, edx
14040af24  mov  rcx, [rbx]            ; arg1 = the PAYLOAD peer (wrapper[0])
14040af27  call 0x1404123d0           ; Close(conn = payload peer, 0, 0)
...
14040af6a  mov  rcx, [rbx]
14040af72  mov  rax, [rcx] / [rax+0x30] / call ....   ; release the wrapper peer
```

Semantics, with the x86-64 CMPXCHG rule spelled out:

```text
if [mem] == RAX:
    [mem] = RCX
    ZF = 1
else:
    RAX = [mem]
    [mem] unchanged
    ZF = 0
```

```c
// rcx = listener (omega::Object), rdx -> wrapper holding the event payload peer
void Object::on_connection_open(Wrapper* w) {
    Peer* payload_peer = w->[0];               // event+0x20 payload
    if (!payload_peer) goto release_only;

    // A. ONE-SHOT TAKEDOWN OF conn+0x88 -- conditional, and a no-op here
    //    expected = 0, replacement = 0  =>  clears ONLY an already-NULL field,
    //    which is why the field is byte-identical before and after.
    long prev = 0;
    lock cmpxchg(&payload_peer->[0x88], /*repl*/ 0);   // RAX=0

    // B. NAME TEST -- only reached with RAX = the ATTACHED peer
    const char* name = "";                     // 0x14156BD60
    if (ZF == 0) {                             // i.e. [payload_peer+0x88] != NULL
        Peer* attached = (Peer*) rax;          // RAX <- destination operand
        if (attached->[0x40] != NULL) name = attached->[0x40];
    }
    if (name[0] == '*' && name[1] == '\0')     // exact 2-byte string "*"
        goto release_only;                     //   -> SKIP the Close

    // C. otherwise send the Close envelope, TO THE PAYLOAD PEER
    0x1404123D0(/*conn*/ payload_peer, /*arg2*/ 0, /*arg3*/ 0);

release_only:
    release w->[0] via vtable+0x30;
}
```

Pointer provenance at `0x14040AEEB` (`CONFIRMED`):

```text
RDX = the object holding +0x88
      = [rdx_entry] = the ConnectionOpen event's payload peer
      = the object carried by the ref-wrapper the listener was handed
      (survives the CAS: x86-64 cmpxchg never writes the destination operand)
RAX = expected value  = 0   at 0x14040AEE9 (xor eax,eax), no earlier writer
RCX = replacement     = 0   at 0x14040AEE7 (xor ecx,ecx), no earlier writer
```

Two facts worth stating precisely:

```text
the wildcard test is a full two-byte string equality with "*"
    name[0]=='*' && name[1]=='\0'                    CONFIRMED
    (the compared bytes are 0x14156E2D0='*' and 0x14156E2D1=0)

conn+0x88 is NOT modified by this handler
    expected == replacement == 0, so the store commits only when the field is
    already NULL -- the value cannot change either way    CONFIRMED
    runtime: ZF=0, RAX <- peer B, conn+0x88 byte-identical  CONFIRMED

the tested +0x40 belongs to the ATTACHED peer, never to the payload peer
    the load at 0x14040AEFD is guarded by `je 0x14040AF08` at 0x14040AEFB,
    i.e. it executes only in the CAS-failure arm, and its base is RAX  CONFIRMED

the Close is addressed to the PAYLOAD peer, not to the attached peer
    `mov rcx, [rbx]` at 0x14040AF24 with rbx = the wrapper   CONFIRMED

three different pointers are live in this function
    payload peer (wrapper[0])   -> CAS destination AND Close argument
    attached peer ([rdx+0x88])  -> the +0x40 name source
    listener ([event+0x18]+0x100) -> the receiver (`rdi`)     CONFIRMED distinct
```

So a wildcard name on the attached peer suppresses the **Close envelope**
entirely; nothing was ever detached, so there is no "detach" to suppress.

### The routed-peer object and `peer+0x40`

The rendered peer is built by `0x140412820` (`0x140412820 - 0x140412B1B`).
The object is **0x88 bytes** and is a plain metadata record with **no vtable**:
`r13 = 0x14156BD60` is a *data* pointer to the empty string, not a class vtable.

```asm
14041285d  mov  ecx, 0x88 / call ..    ; mm_alloc(0x88)
14041287c  lea  r13, [rip + 0x11594dd] ; r13 = 0x14156BD60 = the EMPTY string
140412883  mov  [rax], r13             ; peer+0x00 = ""
140412888  mov  [rax+0x08], ecx(=0)    ; peer+0x08 = 0
14041288b  mov  [rax+0x10], r13        ; peer+0x10 = ""
14041288f  mov  [rax+0x18], ecx        ; peer+0x18 = 0
140412892  mov  [rax+0x20], r13        ; peer+0x20 = ""
140412896  mov  [rax+0x28], ecx        ; peer+0x28 = 0
140412899  mov  [rax+0x30], r13        ; peer+0x30 = ""
14041289d  mov  [rax+0x38], ecx        ; peer+0x38 = 0
1404128a0  mov  [rax+0x40], r13        ; peer+0x40 = ""   <-- the tested field
1404128a4  mov  [rax+0x48], ecx        ; peer+0x48 = 0
```

`CONFIRMED`. The constructor's **own** empty default covers *five* string slots,
while the constructor takes only **four** string parameters. That is the
`+0x20` discrepancy, and it is resolved below: `+0x20` is **derived**, not
assigned from a parameter.

### Byte-accurate routed-peer layout

```text
offset  size  content                                        source
------  ----  ---------------------------------------------  --------------------
+0x00   0x10  StrRef { char* ptr; u32 len; u32 cap }         ctor arg p2
+0x10   0x10  StrRef                                          ctor arg p3
+0x20   0x10  StrRef  DERIVED composite "p4" ':' "p3"         built in-ctor
+0x30   0x10  StrRef                                          ctor arg p4
+0x40   0x10  StrRef                                          ctor arg p5
+0x50   0x38  sub-object:
              +0x00  0x08  char*        (from route+[0x00])
              +0x08  0x10  StrRef       (from route+[0x08])
              +0x18  0x10  StrRef       (from route+[0x18])
              +0x28  0x08  qword        (from route+[0x28])
              +0x30  0x08  qword (0)
+0x80   0x01  byte   (ctor arg p7, `[rbp+0xf0]`)
+0x81   0x07  padding
+0x88         end of allocation
```

```text
peer size                 0x88                                  CONFIRMED
StrRef                    16 bytes: {char* at +0, u32 len at +8,
                           u32 capacity at +0xC}                CONFIRMED
string fields             FIVE, at +0x00 +0x10 +0x20 +0x30 +0x40 CONFIRMED
"four strings at +00/+10/+30/+40"                    SUPERSEDED
```

The five initial `mov [rax+N], r13` stores are `CONFIRMED`, and so are the four
`call 0x14012D260` assignments. The earlier sentence that listed only four string
fields while separately calling `peer+0x20` a string was describing the same
object with an incomplete list; the record has five StrRef slots.

### What `+0x20` actually is — the `"p4:p3"` composite

`+0x20` is **not** a constructor parameter. It is built inside the constructor by
the local string-builder object created at `+0x50` of the *stack frame* (a
`0x28`-byte-plus-inline-buffer object whose first field is the `omega::Frame`
vtable `0x141480E08`, installed by `0x1400B7840` at `0x140412942`):

```asm
14041293d  lea  rcx, [rsp+0x50] / call 0x1400b7840  ; init the local builder
140412948  mov  rax, [rbp+0xd0] / mov rax,[rax]     ; rax = p2
140412952  mov  rdx, r13                            ; default = ""
140412958  cmovne rdx, rax                          ; rdx = p2 ? p2 : ""
140412961  lea  rcx, [rsp+0x50] / call 0x1403fab90  ; append(p2)
140412966  mov  edx, [rsp+0x60] / add edx,2         ; len += 2
14041296d  lea  rcx, [rsp+0x50] / call 0x1403fae70  ; reserve(len+2)
140412977..14041299c                                ; append the literal ':'
                                                     ;   0x14156E658 = ":"
1404129c2  mov  rax,[rbp+0xc8] / mov rax,[rax]      ; rax = p3
1404129cf  cmovne r13, rax                          ; r13 = p3 ? p3 : ""
1404129d3  mov  rdx, r13
1404129db  lea  rcx, [rsp+0x50] / call 0x1403fab90  ; append(p3)
1404129e0  mov  rdx, [rsp+0x68]                     ; the builder's buffer
1404129e5  lea  rcx, [r15+0x20] / call 0x14012d1f0  ; peer+0x20 = the buffer
1404129ee  lea  rcx, [r15+0x20] / call 0x140403f80  ; normalise
```

```text
peer+0x20 = p3 || ":" || p2
```

and nothing else reads the local builder, so this is its only purpose.
The runtime witness agrees exactly:

```text
peerB+0x20 str = ":castlehilltest"
peerB+0x30 str = "localhost:7979"
```

`":castlehilltest"` is `"" + ":" + "castlehilltest"`, i.e. `p2=""` and
`p3="castlehilltest"`. `CONFIRMED` by construction plus runtime.

So the correct reading of the constructor is:

```text
+0x00 = p2   +0x10 = p3   +0x30 = p4   +0x40 = p5    (four parameters)
+0x20 = p2 + ":" + p3                                (derived, no parameter)
```

The `peer+0x40` writer remains a single writer: `0x140412907`, the **fourth**
`call 0x14012D260`, taking the constructor's **fifth** formal argument (p5).

### Where the fifth argument (the `+0x40` value) comes from

The peer constructor assigns its four string parameters positionally:

```asm
1404128d7  rcx = new_peer          rdx = [rbp+0xc8] = p2  -> peer+0x00
1404128e7  rcx = new_peer + 0x10   rdx = [rbp+0xd0] = p3  -> peer+0x10
1404128f7  rcx = new_peer + 0x30   rdx = [rbp+0xd8] = p4  -> peer+0x30
140412907  rcx = new_peer + 0x40   rdx = [rbp+0xe0] = p5  -> peer+0x40  <-- p5
```

`CONFIRMED`. p5 is the constructor's **fifth formal argument**.

`0x140412820` has exactly **two** call sites image-wide:

```text
0x140412040   in fn 0x140411d30   (omega::Connection open/accept path)
0x140412247   in fn 0x140412180   (the routed-peer attach path)
```

`0x140412180` in turn has exactly two callers, and both reach the same
constructor call:

```text
0x14042c782   ReplyIDSignature handler   0x14042C300
0x14042d15a   IntroduceConnection handler 0x14042C910
```

At **both** `0x140412180` sites the sixth argument (`[stack+0x28]`) resolves to
the object `[[connection+0x88]+0x00]`:

```asm
; ReplyID site, 0x14042c74a/0x14042c75d
14042c74a  mov  rdx, [rsp+0x128]      ; the omega::Connection
14042c74f-. lock cmpxchg [rdx+0x88], rdi   ; probe (rdi = 0)
14042c75d  cmovne r8, rax             ; r8 = [old_peer+0x00]
...
14042c775  lea  r9,  [rsp+0x48]
14042c77f  mov  rcx, r10              ; r10 = the Connection
14042c782  call 0x140412180           ; arg6 = r8 = [old_peer+0x00]
```

and inside `0x140412180` that sixth argument (`[rsp+0xc0]` of its own frame at
entry) is what feeds the constructor's p5:

```asm
1404121e8  mov  rdx, [rsp+0xc0]       ; the sixth argument
1404121f0  mov  rcx, [rdx+8]          ; old record's StrRef ptr
140412220  mov  [rsp+0x30], al        ; flags
140412224  mov  [rsp+0x28], rdx       ; seventh ctor arg
140412229  mov  rax, [rsp+0xb8]       ; (stack arg) -> sixth ctor arg
140412231  mov  [rsp+0x20], rax
140412236  mov  r9,  [rsp+0xb0]       ; fifth ctor arg  = [sixth argument]
14041223e  mov  r8,  rsi
140412241  mov  rdx, rbp
140412244  mov  rcx, rdi
140412247  call 0x140412820
```

```text
new_peer+0x40 = p5
              = [sixth argument of 0x140412180]
              = [ [connection+0x88] + 0x00 ]
              = the StrRef pointer at +0x00 of the peer that was attached
                at connection+0x88 when the attach ran
```

This is proven twice over: statically from the `cmovne r8, rax` provenance above,
and independently by the runtime witness, where `peerB+0x40` held the same
singleton as `peerA+0x00` (`0x14156BD60`).

The IntroduceConnection handler also derives a peer-name string of its own, and
falls back to the empty string when the override is absent:

```asm
14042b62d  lea  rdx,[rip+..]           ; 0x14157C690 = "localhost"
14042b63b  call 0x1411C8EF0            ; compare the name argument
14042b683  lea  r14,[rip+..]           ; 0x14156BD60 = ""
14042b68a  mov  [rsp+0x60], r14        ; the name argument becomes ""
```

That path supplies `p3` (via `[rbp-0x78]`), **not** p5, so it populates
`peer+0x10` and (through the composite) `peer+0x20` — not `peer+0x40`.

```text
peer+0x40 writer       = the peer ctor 0x140412907 (parameter p5), after the
                         constructor's own empty default at 0x1404128A0  CONFIRMED
peer+0x40 source       = p5 of 0x140412820 = [sixth arg of 0x140412180]
                         = [[connection+0x88]+0x00]                      CONFIRMED
failing value          = "" (the empty-string singleton)             CONFIRMED observed
required-to-skip value = the exact two-byte string "*"               CONFIRMED in code
why it is empty        = [old_peer+0x00] was "" on the observed path CONFIRMED
```

### Correct classification of the old wildcard experiment

```text
"changing the endpoint/shard to localhost:7979:* prevents the Close"
                                                            DISPROVEN (as before)
"peer+0x40 == '*' is irrelevant"
                                                            NOT CLAIMED — the
    code proves peer+0x40 == "*" is exactly the skip condition, so this field is
    causally live; the earlier experiment simply never wrote it              CONFIRMED
```

The experiment changed the endpoint/shard identity surfaced elsewhere on the peer
(`peer+0x20`/`peer+0x30`), which is the `"localhost:7979"` composite, not
`peer+0x40`. The two are distinct fields, which is why the experiment failed to
suppress the Close while the code path still expects `"*"`.

### Classification of the Close decision

```text
0x1404245F0       per-owner deferred event drain (generic delivery)   CONFIRMED
0x140434430       ObjectSurrogateEventConnectionOpen notification      CONFIRMED
0x14040A970       listener vtable+0x28, releases the payload, ret 0    CONFIRMED
0x14040AEC0       listener vtable+0x70, THE DECIDER                    CONFIRMED
Close verb usage  NORMAL ConnectionOpen handling with a metadata test,
                  not a dedicated failure path                         HYPOTHESIS
primary failure vs secondary cleanup: the Close *decision* is here, and its
                  input is now fully traced. The decision is a PRIMARY
                  DECISION POINT whose input is the previous routed peer's
                  name field, which is empty on this path.              CONFIRMED
peer+0x40 semantic role   = the routed peer's name string, tested for the exact
                            wildcard "*"                               CONFIRMED
"*" semantic role         = "this routed peer's name is the wildcard", i.e. a
                            real client-side name value; the Close is skipped
                            for wildcard-named peers                     CONFIRMED
server controls peer+0x40 UNKNOWN (indirect influence HYPOTHESIS)
D4                                                                     UNKNOWN
```

### `"*"` is a real wildcard name, not a bespoke sentinel

`CONFIRMED`. The client itself materialises the literal `"*"` as a string
*value* and resolves names against it:

```text
lea r9,[rip+0x1167245] -> 0x14156E2D0 "*"    at 0x140407084 and 0x1404070CC
   inside 0x140407000, a name/route resolution routine that
   strlen's "*", appends it through the local string object at [rsp+0x60],
   and compares a name argument against it
0x140407000 is called from 0x140435B50, inside the IntroduceConnection outbound
   path 0x140435AE0 -> 0x140435C30 -> 0x14042B3D0
the '*' address 0x14156E2D0 has 113 image-wide references, all as the 2-byte
   string "*"
```

So `"*"` is one of the values the client's own name machinery produces and
recognises. A peer named `"*"` is a wildcard-named peer — the natural reading of
`peer+0x40 == "*"` is "this peer's name is the wildcard", and the client declines
to Close such a peer.

```text
"*" semantic role = wildcard peer name                      HYPOTHESIS (best reading)
"*" semantic role = no-close sentinel with no other meaning  DISPROVEN
    (the same literal is a real name value elsewhere in the same subsystem)
```

---

## Inbound message field-to-object mapping (partial, honest)

The task asks for a per-field map from the ReplyIDSignature and
IntroduceConnection payloads into peer/object fields. Only the parts below are
proven. The rest is explicitly `UNKNOWN` and must **not** be assumed.

`omega::Connection` is the object at `[rsp+0x128]` in both handlers
(`CONFIRMED`: the class string `"omega::Connection"` is at `0x14157EB28`, emitted
by `0x140411880`, a method of the class whose vtable is installed at
`0x140411AB1`).

### ReplyIDSignature (`0x14042C300`, dispatched from `0x6731C5AF`)

Parsed shape, from the consume order:

```text
[0x14042c36e]  u16  read first, bounds-checked against 2
[0x14042c3fd]  u64  read next, bounds-checked against 8
then three 0x400-byte string reads (0x1403FB300) at 0x14042c3a9/0x14042c3c2/
0x14042c3d8
then the u16 and the u64 are re-read from the 32-bit words of the top-level
command object and the connection is resolved with
0x14042D320(r13, &conn, &selector)   @ 0x14042c437
```

`0x14042D320` walks the circular list at `[arg+0x130]` under the lock at
`[arg+0x28]`, matches `node->[0x10] == selector`, unlinks the node, decrements
`[arg+0x140]`, and returns `node->[0x10]`'s peer record. So the `u16` selects the
connection.

```text
ReplyID field   immediate parsed destination                 later use
--------------  -------------------------------------------  -----------------
u16 object id   [rsp+0x40]; selector arg of 0x14042D320      selects the routed peer record
u64 correlation r14 / [rsp+0xc0], then the shared_ptr at      retained for the reply; refcount
                [rbp-0x48] of the peer-create path            bumped (`lock inc [rax+8]`)
string #1       [rsp+0x68] (a 16-byte StrRef)                 UNKNOWN downstream
string #2       [rsp+0x58] (a 16-byte StrRef)                 UNKNOWN downstream
string #3       [rsp+0x48] (a 16-byte StrRef)                 UNKNOWN downstream
```

**Which of the three strings becomes `peer+0x40`?** None of them, directly. On
this path `peer+0x40` receives `[[connection+0x88]+0x00]`, which is the
*previously attached* peer's name — see the provenance chain above. The direct
mapping of the three strings into peer/object fields is `UNKNOWN`; the code
retains all three in local StrRefs and the reachable path exercised at bootstrap
does not store any of them into a peer record's `+0x00`.

### IntroduceConnection (`0x14042C910`, dispatched from `0x8B0D492F`)

Parsed shape (`CONFIRMED` from the consume order and bounds checks):

```text
0x14042c99f  u16  @ [rsp+0x88] / [rsp+0x428]
0x14042c9f6  u16  @ [rsp+0x8c]   (r13d)
0x14042ca40  0x400-byte string -> [rsp+0x78]
0x14042ca56  0x400-byte string -> [rsp+0x60]
0x14042ca6c  0x400-byte string -> [rsp+0x50]
0x14042ccab  0x14042A950(r15, &outgoing)   -- map lookup on name [rsp+0x60]
0x14042ce6d  0x14042D470(r15, &found, <name>, <key>)  -- match against the list
              at [connection+0x130]
```

```text
Introduce field     immediate parsed destination            later use
------------------  --------------------------------------  ----------------------
u16 #1 (client obj) [rsp+0x88], then [rsp+0x428]            the introduce route's id
u16 #2 (server obj) [rsp+0x8c] (r13d)                       arg of 0x14042A950 /
                                                            0x14042D470
string #1           StrRef at [rsp+0x78]                    passed to 0x14042B63B,
                                                            compared with "localhost"
string #2           StrRef at [rsp+0x60]                    map-lookup key, and the
                                                            name compared at 0x14042CB49
string #3           StrRef at [rsp+0x50]                    UNKNOWN downstream
```

On the Introduce path the attach's sixth argument resolves through
`0x1404117E0(connection)` into `[rsp+0xd8]`, so the peer record p5 is taken from
is a *connection-derived name*, not from one of these three parsed strings
directly:

```asm
14042d0fc  mov  rcx, [r12]          ; the Connection
14042d100  call 0x1404117e0         ; returns "closed" (0x14157EDE4) when
                                    ;   [connection+0x38] == NULL, else a name
                                    ;   obtained from the socket
14042d10f  mov  [rsp+0xd8], rax
14042d15a  call 0x140412180         ; arg6 = that name-derived peer record
```

```text
IntroduceConnection field -> peer+0x40   NOT PROVEN
```

```text
ReplyID field -> peer+0x40              NOT PROVEN (none of the three strings)
IntroduceConnection field -> peer+0x40  NOT PROVEN
```

### What this means for "*"

Because `peer+0x40` is `old_peer+0x00`, and no inbound field is proven to write a
peer record's `+0x00`, **the server cannot be shown to control the tested value
through any single message field.** Only the indirect two-hop path stands.

---

## The exact `peer+0x40` provenance chain (this pass)

The three preceding sections establish the ends of the chain. Assembling them:

```text
0x14040AEC0  test base  = [connection+0x88]           (CAS destination operand)
                                        ^
                                        | written by 0x140412A4F inside 0x140412820
                                        |
0x140412820  peer+0x40 := p5 (fifth formal argument)  @ 0x140412907
                                        ^
0x140412180  fifth ctor arg = [sixth argument]        @ 0x140412236/0x140412247
                                        ^
call sites   0x14042c782 (ReplyIDSignature 0x14042C300)
             0x14042d15a (IntroduceConnection 0x14042C910)
             both pass  [[connection+0x88]+0x00]
                                        ^
0x140412820  peer+0x00 := p2 (second formal argument) @ 0x1404128D7
                                        ^
             the peer record the attach was handed
```

Compressed:

```text
new_peer+0x40 = old_peer+0x00
```

```text
new_peer+0x40 == previous routed peer's +0x00 field            CONFIRMED
```

### Every field of the two historical peers

**VALUE versus PROVENANCE must be kept apart.** The observed *values* below are
runtime facts. The *provenance* of the first peer's `+0x00` is `UNKNOWN`: the
old table asserted it was `[connection+0x88]+0x00`, and that assertion is
`SUPERSEDED`. Nothing about the observed emptiness may be used to infer its
cause.

```text
field   peer A                              peer B
------  ----------------------------------  ----------------------------------
+0x00   = [connection+0x50] StrRef           = [connection+0x50] StrRef
        static prediction: "castlehilltest"   static prediction: "castlehilltest"
        NOT captured at runtime               (runtime witness unrecorded)
+0x10   p3 (route record string)             p3 (route record string)
+0x20   p3 ":" p2                           ":castlehilltest"  value CONFIRMED
+0x30   p4 (route record string)             "localhost:7979"  value CONFIRMED
+0x40   p5                                  ""                value CONFIRMED
```

```text
Peer B +0x40 == Peer A +0x00                                CONFIRMED
Peer B +0x20 == p3 ":" p2 == ":castlehilltest"              CONFIRMED
  therefore for peer B:  p3 == "" and p2 == "castlehilltest" CONFIRMED
Peer B +0x40 == ""                                          CONFIRMED value
  therefore Peer A +0x00 == ""  ... OR peer A was not the previous
  peer of peer B. The two readings cannot be separated from the
  recorded witness alone, because Peer A's own strings were never
  captured.
```

**Static model (this pass).** `p2` and `p5` of `0x140412820` are the same
argument-expression at the two live call sites: the first qword of the peer
record the attach was handed.

```text
p2 == p5 == [the record pointer]
          = the record's StrRef ptr at +0x00
```

At the ReplyID call site (`0x14042c782`) that record is the **7th** argument of
`0x140412180`, and its provenance is now traced:

```asm
14042c677  mov  [rsp+0x98], r15          ; commit the Ref route record
...
14042c6a0  mov  [rsp+0x20], rcx
14042c6a5  movzx r8d, word [rsp+0x40]
14042c6ab  movzx edx, word [rax+0x28]
14042c6af  lea  rcx, [rsp+0x88]
14042c6b7  call 0x14045b620              ; build the reply envelope
14042c7ff  push r15 / push rdx           ; stack args 6 and 7
14042c782  call 0x140412180
```

```text
arg7 = r15
     = [[connection+0x88] + 0x00]   at the time of this call
     = that record's StrRef ptr at +0x00
```

and the connection's `+0x50` field is the writer's destination in the
IntroduceConnection peer-creation path (`0x140411dfc`: `lea rcx,[rdi+0x50]`
followed by `call 0x14012d260`), i.e. a real name string, not a structural
pointer. **Consequence: `new_peer+0x00` receives a name string, never a
"neighbour object" and never a vtable pointer.**

```text
p2 is the first qword of the route/endpoint record's StrRef at +0x00   HYPOTHESIS
that record is real name text, from [connection+0x50] on the introduce
   path                                                                 CONFIRMED
Peer A +0x00 static prediction = "castlehilltest"                       HYPOTHESIS
Peer A +0x00 == [connection+0x88]+0x00                                  SUPERSEDED
Peer B +0x40 == Peer A +0x00                                            CONFIRMED
```

**This conflicts with the previously published `Peer A +0x00 == ""`.** That
claim rested on reading the argument as a whole record and on the assumption that
the first attach had no predecessor. Both are now retracted; the value should be
re-measured rather than assumed.

### Which peer is which

```text
ConnectionOpen event payload peer   = the peer the attach just created
                                      (peer A at the first attach, peer B later)
conn+0x88 at the decision           = the same peer (the attach wins the race
                                      against the CAS, which cannot clear it)
peer whose +0x40 is tested          = that same peer
operator argument to Close          = that same peer
```

So in the captured failing run all three coincide — but the `+0x40` **value**
originates one peer earlier, in `old_peer+0x00`.

### CORRECTION: the `+0x20` composite is `p3 ":" p2`, and the p2 source is a copy

Two errors from the previous pass, corrected here.

**(1) The composite operand order was transposed.** Re-reading the constructor's
local string build with exact instruction addresses:

```asm
140412948  mov  rax, [rbp+0xd0]   ; p3  (the +0x10 argument)
140412958  cmovne rdx, rax
140412961  call 0x1403fab90       ; builder.append(p3)
14041296a  add  edx, 2
140412972  call 0x1403fae70       ; builder.reserve(len + 2)
140412980  lea  rcx, [0x14156E658] ; the literal ":"
140412990..14041299c              ; builder.append(":")
1404129c2  mov  rax, [rbp+0xc8]   ; p2  (the +0x00 argument)
1404129cf  cmovne r13, rax
1404129db  call 0x1403fab90       ; builder.append(p2)
1404129e5  lea  rcx, [r15+0x20]
1404129e9  call 0x14012d1f0       ; peer+0x20 = the builder buffer
```

```text
peer+0x20 = p3 || ":" || p2
```

The previous statement `peer+0x20 = p2 ":" p3` was **wrong** and is
`SUPERSEDED`. The runtime witness is the discriminator, and it selects the new
formula unambiguously:

```text
peerB+0x20 observed = ":castlehilltest"
p3 || ":" || p2  with p3 = ""  and p2 = "castlehilltest"  ->  ":castlehilltest"  MATCH
p2 || ":" || p3  with p3 = ""  and p2 = "castlehilltest"  ->  "castlehilltest:"  NO MATCH
```

So **p3 is the empty string and p2 is `"castlehilltest"`** in the witness. The old
formula could not reproduce the witness, so it is retracted rather than reworded.

**(2) p2 is not the previous peer's `+0x00` directly — it is a copy of a name
carried by the route record.** `0x140411D30` is the function that seeds it:

```asm
; rcx = connection (destination), rdx = r13 = the introduce/receive route record
140411dbc  lea  rcx, [rdi + 0x70]   ; <- destination address
140411dc0  mov  r8,  r13
140411dc3  lea  rdx, [rbp - 0x78]
140411dc7  call 0x1404143d0         ; acquire the route/endpoint record
...
140411e21  mov  rax, [rdi + 8]      ; the socket manager
140411e25  mov  rcx, [rax + 0xd8]   ; the socket
140411e2c  mov  rax, [rcx + 8]
140411e30  mov  rcx, [rax + 0x10]   ; the route's name  (char*)
140411e3b  mov  rdx, rbx            ; default = the empty-string singleton
140411e41  cmovne rdx, rcx
140411e49  call 0x1403fab90         ; builder.append(the route's name)
...
140411ea5  mov  rdx, rbx            ; (p3-side value)
140411ea8  call 0x1403fab90         ; builder.append(...)
140411eb1  mov  rdx, [rbp - 0x48]
140411eb5  lea  rcx, [rdi + 0x40]
140411eb9  call 0x14012d1f0         ; peer+0x40 = the builder buffer
```

The destination offsets used by `0x140411D30` (`+0x28`, `+0x30`, `+0x50`,
`+0x00`, `+0x40`, `+0x20`) are byte-verified and coincide with the constructor
`0x140412820`'s offsets. **Offset coincidence is not identity.** The object at
`rdi` in `0x140411D30` has not been classified, so calling it "the connection's
own routed-peer record" is withdrawn (`UNKNOWN`).

```text
the p2 of a routed peer is a copy of a name field obtained from a
route/endpoint record                                                    HYPOTHESIS
the copy's immediate source object is NOT the wire and NOT a constant    CONFIRMED
```

### CALL-CHAIN CORRECTION (explicitly recorded)

An earlier pass wrote that `0x140412180` reaches `0x140411D30`. **That is false.**

```text
0x140412180 -> 0x140411D30                                       FALSE
0x140412180    has its own direct call to 0x140412820
                at 0x140412247                                   CONFIRMED
0x140411D30    is NOT called by 0x140412180                       CONFIRMED
0x140411D30    callers are exactly 0x14042B721 (in 0x14042B3D0)
               and 0x14042CF88 (in 0x14042C910)                  CONFIRMED
```

Enumerating every `call` instruction inside `0x140412180`
(`0x140412180 - 0x1404123CD`) yields exactly these targets:

```text
1404121b3  0x140414250       140412247  0x140412820   <-- the peer constructor
1404121d6  0x140414cb0       140412258  [iat]        1404122c3  [iat]
1404122f3  [iat]             140412302  0x14043d380  140412317  0x1404123d0
140412332  [iat]             14041235f  0x140414cb0  14041236d  0x140414250
140412396  [iat]             1404123a5  0x140435ce0  1404123c1  [iat]
```

So the two attach paths are **independent**, and the peer inheritance chain
(`new_peer+0x40 = previous peer's +0x00`) and the `0x140411D30` route-name copy
are **separate mechanisms** until proven otherwise.

What remains `UNKNOWN` is the producer of *that* name field, i.e. the wire or
client-local origin of the first name. That is the single remaining hop, and it
is why the server-control classification above is `UNKNOWN`.

---

## Can the server supply the value? — classification

```text
SERVER CONTROL of peer+0x40            UNKNOWN
indirect server influence              HYPOTHESIS
exact wire field                       UNKNOWN
```

**`INDIRECT` is withdrawn as a confirmed classification.** It is not usable until
a complete, proven chain exists from a specific wire field all the way to the p2
of the peer that seeds the name. That chain does not exist yet, so the honest
classification is `UNKNOWN`, with indirect influence no stronger than a
`HYPOTHESIS`.

What is actually proven about the upstream value:

```text
direct   wire field -> peer+0x40                                NO
peer-to-peer inheritance  new_peer+0x40 = previous peer's +0x00 CONFIRMED
the previous peer's +0x00 (p2) is itself a copy                 CONFIRMED
the copy's origin is a route/endpoint record's name field        HYPOTHESIS
```

The p2 source, stated without shorthand:

```text
p2 of 0x140412820
  <- the third argument of 0x140411d30, copied by
     `mov qword ptr [rdi+0x70], rdx`   at 0x140411dbc
  <- which on the reply path is  [[connection+0x88] + 0x00]
     (`cmovne r13, rax` at 0x14042c75d, rax = the attach probe's old value)
  <- i.e. a routed-peer record the client built
```

So calling it "the neighbour object" or "a peer" is still shorthand: the
**proven** object is a routed-peer record reached through the introduce route
record, and the wire field that populates *its* name field is `UNKNOWN`.

```text
exact message id controlling peer+0x40                     NOT PROVEN
exact field controlling peer+0x40                          NOT PROVEN
wire -> client-local-route-metadata boundary               NOT CROSSED
```

### Consequence for the experiment gate

The task's rule is explicit: an experiment is permitted only once **one exact
server field** is proven to control the value tested at `peer+0x40`. That
condition is **not met**.

```text
EXPERIMENT PERFORMED: NO
REASON: no single server field was proven to control peer+0x40. The chain is
        proven to a two-hop indirection through a client-built peer record, and
        the inbound producer of that record's +0x00 was not identified. Changing
        ReplyID string #N to "*" would therefore have been a guess about which
        of several candidate fields lands in that slot, which the task forbids.
```

### What would close it

The single highest-value remaining static target is the **first** attach for a
connection: the object at `[connection+0x88]` when `0x140412A4F` first wins its
CAS with `old == NULL`. That object's `+0x00` is the root. Concretely:

```text
1. find every writer of a peer record's +0x00 other than 0x1404128D7  (none found
   so far => the record is always built by 0x140412820)
2. therefore find the FIRST 0x140412180 call for the connection and identify the
   record passed as its sixth argument, then that record's own +0x00 producer
3. that producer's input is the field the server would have to set
```

`omega::Connection+0x50` is the field that holds the route name the peer
constructor reads as `p4` (`peer A +0x30` = `"localhost:7979"` in the witness),
and `omega::Connection+0x78` is its lock — those are the connection-side name
slots worth tracing next, but `+0x00` (not `+0x50`) is what `peer+0x40` needs.

---

## D4

```text
D4 classification: UNKNOWN
```

Nothing in this pass links D4 to `peer+0x40` or to the ConnectionOpen decision.
D4 was not sent, and the provenance analysis specifically does **not** relate it
to the source field. It remains `UNKNOWN`, not `DISPROVEN`.

## Runtime instrumention this pass

```text
runtime witness taken this pass: NONE
```

All findings above are static re-derivation plus the previously captured
witnesses in `docs/retail-protocol-evidence.md`. The task's preferred one-shot
locations (the two peer constructor call sites, `0x14040AEC0` entry) were not
needed: the static provenance is unambiguous because the CAS destination operand
survives the instruction by the x86-64 specification, and the `cmovne` at
`0x14040AF04` is reachable only in the CAS-failure arm. No transport or timer
path was instrumented.

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
* `0x14040AEC0` is **not** a peer-removal primitive. Its
  `lock cmpxchg [rdx+0x88], rcx` at `0x14040AEEB` has **expected = 0 and
  replacement = 0**, so it clears the field only when the field is already NULL
  — it *cannot* change a non-NULL `conn+0x88`, and it *cannot* change a NULL one
  either. The instruction is an **atomic null-probe used as a current-peer load**
  (`field mutation = NONE`).
  The function then classifies the routed peer thus read by its `+0x40` string
  against `"*"` and terminates the routed connection.
  `CONFIRMED` (`"unconditional detach"`, `"conditional detach"` and
  `"conditional compare-and-clear"` are all `SUPERSEDED` — see "The decider,
  byte-for-byte")
* At `0x14040AF6A` it releases `[arg2]` — the **connection smart pointer in the
  argument struct**, which is a different lifetime from the peer. `CONFIRMED`
* **Local contract inside `0x14040AEC0`:** its Close call is skipped when the
  classified peer string is exactly the wildcard `"*"`; otherwise that path calls
  Close. The string it classifies belongs to the peer **attached at
  `conn+0x88`** (the CAS destination operand), while the Close is addressed to
  the **event payload peer** — two different operands of the same function.
  In the observed run the compared string was `""`, taken from
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

### The list at `boundobj+0x260` is a lock-free deferred PacketSocket service stack

**Terminology (corrected).** This section previously called `+0x260` a
"deferred-destruction stack" holding "objects awaiting destruction". That label
was stronger than the evidence. What the bytes prove is a lock-free intrusive
LIFO whose elements are handed to a deferred processing step. At the time of the
correction neither of the two calls made per drained element had been resolved:

```text
0x14043B5D0 semantics             UNKNOWN
element vtable+0x28 target        UNKNOWN
element vtable+0x30 target        UNKNOWN
element class                     UNKNOWN
```

so the queue was described as a **deferred-retirement** stack.

**Further correction (supersedes that one).** The drain was then fully resolved
and the retirement reading is now itself `SUPERSEDED`. The elements are
`omega::PacketSocket` sockets; the drain hands each one to a **transmit** path and
never frees it. The queue is a **deferred PacketSocket service queue**: a work
list of sockets with outstanding deferred work to service. Neither "retirement",
"reclamation" nor "destruction" describes it.

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
**lock-free LIFO stack of `omega::PacketSocket` objects queued for deferred
service, with the intrusive link embedded at object offset `0x30`**.

Key consequences:

```text
element base      = stored node pointer - 0x30
link offset       = element + 0x30
push              = CAS loop, node->next = head; head = node
pop-all           = one lock cmpxchg head -> NULL
producer returns  = (old head == NULL), i.e. "was the stack empty before me?"
```

**RETRACTED:** "That return value is the arming signal: the caller uses 'I pushed
onto an empty stack' to decide whether a drain must be scheduled." Both callers
of the producer discard `al` outright (see "the producer's AL is discarded"
below). The `sete al` is real, but no caller reads it, so it is **not** evidence
of timer arming. `CONFIRMED` discarded.

A second, structurally similar `+0x260` CAS loop exists at `0x14043A390`
(fn `0x14043A390 - 0x14043A79B`). It is **not** a second `ObjectManagerImpl`:
`0x14043A390` is `omega::PacketSocket`'s cleanup routine, reached from that
class's scalar deleting destructor `0x14043FA70`, and its `+0x260` is a
*`PacketSocket` field* — a different queue that happens to share the offset
number. See "Second family: `0x1414B69A8` is a `PacketSocket`" in
`docs/retail-protocol-evidence.md`. `CONFIRMED` that the lock-free LIFO idiom is
reused across the `omega` socket/manager family; the previous claim "at least two
*manager instances*" is retracted.

### RESOLVED: `0x14043B5D0` is an `omega::PacketSocket` flush, and it is not the per-element teardown

The earlier note that `0x14043B5D0` was "a real image function whose semantics
are UNKNOWN" is superseded. `0x14043B5D0` is a method of `omega::PacketSocket`:

```text
this                      = omega::PacketSocket
[rcx+0x80]+0x10           = PacketSocket's own critical section
[this+0x164]              = a 0/1 outstanding-work gate. 0x14043B460 sets it
                            0 -> 1 with `lock cmpxchg` and treats the successful
                            transition as "this is the first outstanding pass";
                            0x14043B5D0 with mode 0 resets it 1 -> 0. LIFECYCLE
                            CONFIRMED; the earlier label "retire-once" is
                            replaced by "outstanding-work / service-pending
                            gate" because nothing here retires anything
[this+0x168]              = PacketSocket's OWN lock-free stack of 0x20-byte
                            recording nodes (steal-all, same CAS idiom)
[this+0x98] / +0x180      = PacketSocket state fields
```

It is **not** a per-element teardown.

**Correction to the previous report.** That report said `0x14043B5D0` is called
"with the manager as `this`". That is **wrong**. The drain passes the *element*:

```asm
14043082d  add   rdi, -0x30        ; rdi = element base = the PacketSocket
140430847  mov   rcx, rdi          ; rcx = element   <-- receiver
14043084a  call  0x14043b5d0       ; 0x14043B5D0(element, r8b = 0)
140430852  mov   rcx, rdi          ; rcx = same element
140430859  call  [rax + 0x30]      ; element->vtable+0x30(element)
```

Both lifecycle calls in the drain loop use the queue element as their receiver:

```text
0x14043B5D0 this = omega::PacketSocket     CONFIRMED (contradicts earlier report)
```

It remains a per-*pass* call (once per drain pass), not a per-element operation,
and it is a transmit/flush, not a destroy. The producer `0x140406530` and
`0x14043B5D0` are **not** a release/finalize pair; they are unrelated
neighbouring members of the `omega` socket object family that happen to live in
the same address neighbourhood.

`vtable+0x28` and `vtable+0x30` are now resolved against a concrete class — see
the next section.

### The 5 ms timer is a coalescing drain deadline

`0x140430800` performs no polling at all: it steals the whole list and services
it. Combined with the drain being registered exactly once per object-manager
initialisation, the 5 ms period reads as **a coalescing window**: sockets with
deferred work accumulate on the stack and one drain pass services the batch.
`0x140430800` does not rearm itself (`CONFIRMED`).

```text
5 ms operation = deferred PacketSocket service deadline (coalescing)
```

`HYPOTHESIS` for the coalescing reading. It is **not** proven by the producer's
`sete al` — that return is discarded by both callers. The coalescing reading now
rests on (a) the callable only draining and never polling, and (b) the drain
being registered once at manager init rather than per enqueue.

### The 5 ms drain is a deferred PacketSocket service pass, not teardown

This is the substantive result of this pass. `0x14043B5D0` was fully reversed and
it is a **transmit/flush** operation on the `PacketSocket`, not cleanup:

```text
0x14043B5D0(this = PacketSocket, r8b = mode)  classification = SEND/FLUSH
```

Structure (fn `0x14043B5D0 - 0x14043BB68`, 349 instructions reached):

```text
1. EnterCriticalSection([this+0x80] + 0x10)
2. if (mode == 0) lock cmpxchg dword ptr [this+0x164], 0   ; clear pending flag
3. if (this[0x180] != 1) goto epilogue                     ; service only if enabled
4. build a 0x100-byte scratch buffer + vector header
5. if (this[0x98] == 1) 0x14043C780(this, &scratch)        ; append extra record
6. steal this[0x168] whole (CAS head -> NULL)              ; the record stack
7. if (records == NULL && !extra) goto epilogue
8. if (0x140414BD0(this) != 4) goto epilogue               ; socket state gate
9. if (this[0x38] == NULL) goto epilogue
10. per record: count++, lock xadd [this+0x170], -recordlen ; drain byte total
11. allocate recordptrs[]/recordlens[] (heap if count > 0x64, else stack)
12. per record accumulate bytes and bump [this+0x178] and
    [[this+8][0xd8]+0x2c8] at +0x4c/+0x50/+0x54 (bytes/records/calls)
13. bulk transmit: 0x140452360(this[0x38], recordptrs, count, total_bytes)
14. free heap arrays if used
15. LeaveCriticalSection
```

The bulk call `0x140452360` is itself a transmit hand-off:

```text
- EnterCriticalSection([rcx+0xc8]+0x10)
- 0x140414BD0(rcx) must == 4                    ; same state gate
- 0x140452A80(rcx, total_bytes)                 ; byte-quota / backpressure check;
                                                 ; running total at [rcx+0xd0],
                                                 ; limit at [[rcx+0x38]+0x34]
- per record: 0x140453370(&rcx[0x70], &recordptr)  ; push into a deque-like
                                                    ; container (grow path inside)
- success path: (*[[rcx+0x68]]->vtable[0x90])([rcx+0x68], &records)
                                                 ; hand the batch upward
- failure path: per record, (*record)->vtable[0](record, 1)   ; release
```

**No free occurs anywhere on this path.** The drain's whole 33-byte body calls
exactly two things per element: `0x14043B5D0` and `element->vtable+0x30`. It never
calls the scalar deleting destructor `0x14043FA70` and never reaches `mm_free`.
The socket's real deletion is the separate `vtable+0x00` path.

### The four PacketSocket service fields, from the constructor

The `PacketSocket` constructor `0x140439FE0` initialises them all to zero, which
is what makes the working set self-evident:

```asm
14043a1f2  mov  dword ptr [rdi + 0x160], ebp     ; 0
14043a1f8  mov  dword ptr [rdi + 0x164], ebp     ; 0   outstanding-work gate
14043a1fe  mov  qword ptr [rdi + 0x168], rbp     ; NULL record stack head
14043a205  mov  dword ptr [rdi + 0x170], ebp     ; 0   queued byte total
14043a20b  mov  dword ptr [rdi + 0x174], ebp     ; 0
14043a211  mov  qword ptr [rdi + 0x178], rbp     ; NULL stats object
14043a218  mov  dword ptr [rdi + 0x180], ebp     ; 0   service-enabled flag
14043a21e  mov  qword ptr [rdi + 0x188], rbp     ; NULL
14043a225  mov  dword ptr [rdi + 0x190], ebp     ; 0
```

```text
+0x164  outstanding-work gate            CONFIRMED LIFECYCLE
        0 -> 1  lock cmpxchg at 0x14043B525 (0x14043B460) and 0x14043E02C (0x14043DE10)
                in both cases only after the +0x168 push reported an empty stack,
                i.e. "this socket now has deferred work outstanding"
        1 -> 0  lock cmpxchg at 0x14043B62A (0x14043B5D0, mode 0) - the service
                pass clears it
        ctor zeroes it; 0x14043A3C7 and 0x140443DFE also touch it

+0x168  record stack head (lock-free LIFO)   CONFIRMED
        push  in 0x14043B460 / 0x14043DE10 (CAS loop)
        steal in 0x14043B5D0 (`lock cmpxchg ... , 0`)
        records are 0x20 bytes; link at record+0x00

+0x170  queued byte accumulator              CONFIRMED
        `lock xadd dword ptr [rbx+0x170], eax` in 0x14043B460 adds
        `[arg3+0x10]` (the record's length)         @ 0x14043B545
        `lock xadd dword ptr [rsi+0x170], ecx` in 0x14043B5D0 subtracts each
        record's length (ecx = -len)                @ 0x14043B6FC
        -> it is drained on service, so it counts queued bytes, not lifetime bytes.
        The 0x100000 threshold below is a 1 MiB backlog threshold.

+0x180  service-enabled flag                 CONFIRMED readers/writers
        0x14043B460 requires == 1 before the immediate flush  @ 0x14043B554
        0x14043B5D0 requires == 1 before servicing at all     @ 0x14043B638
        set to 1 by 0x14043AD60 @ 0x14043ADA7, 0x14043BEA0 @ 0x14043C246 and
        0x14043E3A0 @ 0x14043E7E2; set to 3 by 0x14043E2D0 @ 0x14043E31F
```

So the producer path is: build a 0x20-byte record, push it on `+0x168`, add its
length to `+0x170`, and (on the first outstanding pass) flag `+0x164` and enqueue
the socket for service. Flushing then happens either immediately when the queued
byte total crosses 1 MiB *and* the socket is service-enabled, or later in the
5 ms pass. `+0x180` gates both.

### The 0x20-byte record is a reference-counted `omega::Frame` + size

`0x14043F9F0(rec, ctx, arg3, arg4)` builds the record; `0x1403FA990` builds the
object it points at, and that object's vtable resolves the whole picture:

```c
// 0x14043F9F0
Record* build(Record* rec, Ctx* ctx, A3* arg3, uint32_t arg4) {
    rec->[0x00] = NULL;                       // intrusive-list next
    rec->[0x08] = ctx->[0x00];                // move an intrusive ref out of ctx
    if (rec->[0x08]) rec->[0x08]->vtable[0x28]();   // addref
    rec->[0x10] = omega_Frame_copy(arg3);     // 0x1403FA990 -> a new omega::Frame
    rec->[0x18] = arg4;                       // uint32 payload (the size)
    if (ctx->[0x00]) ctx->[0x00]->vtable[0x30]();   // release the original ref
    return rec;                               // ctx->[0x00] now NULL (move)
}

// 0x1403FA990(arg3)  -- arg3 is the PacketSocket's frame at [socket+0x38]
Frame* omega_Frame_copy(Source* src) {
    Frame* f = mm_alloc(0x28);
    f->[0x00] = &omega::Frame_vtable;         // 0x141480E08
    f->[0x08] = src->[0x10];                  // length/count
    f->[0x0c] = f->[0x18] = 0;
    f->[0x20] = 5; f->[0x24] = 0x101; f->[0x26] = 0;
    f->[0x18] = mm_alloc(f->[0x08]);          // data buffer, sized from src
    f->[0x20] = src->[0x20]; f->[0x22] = src->[0x22];   // capacity/state words
    ...
}
```

The vtable installed at `0x141480E08` resolves by RTTI to:

```text
omega::Frame        vtable 0x141480E08      CONFIRMED
```

So the record is not a raw buffer or a scatter/gather segment: it is a
**reference-counted `omega::Frame` plus a 32-bit size**.

The `Frame` layout, taken from `0x1403FA990`:

```text
omega::Frame  (size 0x28, mm_alloc'd, vtable 0x141480E08)
  +0x00  vtable pointer
  +0x08  uint32 length          (copied from src+0x10 on construction)
  +0x0c  uint32 (0)
  +0x10  uint32 size/read cursor -- this is what 0x140452360 reads as `size`
  +0x18  void*  buffer          (mm_alloc(length); this is the `buffer` argument)
  +0x20  uint16 copied from src+0x20
  +0x22  uint16 copied from src+0x22
  +0x24  flags (0x101)
```

Note that `0x1403FA990` reads its *source* with the same `+0x10` / `+0x18` pair
(`0x1403FAA0E` / `0x1403FAA12`) that `0x140452360` later reads from the copy,
which independently confirms that `+0x10` is a size and `+0x18` a buffer pointer
for this class.

Consumers of the record:

```text
0x14043B5D0   walks the queue records via record+0x00, and for each one reads
              [record+0x10] (the Frame), then [Frame+0x10] as the length, and
              subtracts it from socket+0x170                 @ 0x14043B6F3-0x14043B6FC
0x140452360   does NOT see the record. It receives a flat ARRAY OF FRAME POINTERS.
              For each element it reads [frames[i]+0x10] as the size and
              [frames[i]+0x18] as the buffer                     @ 0x1404523FF-0x140452406
```

**Correction (supersedes an earlier contradictory pair of lines).** This section
previously stated both that `record+0x10` is an `omega::Frame*` and `record+0x18`
a `uint32` size, *and* that `0x140452360` "reads `[record+0x10]` as a size and
`[record+0x18]` as a pointer". Both statements were describing **different
objects** and the second was mislabelled:

```text
record+0x10        omega::Frame*                     (the 0x20-byte queue record)
record+0x18        uint32 size / payload type        (the 0x20-byte queue record)

Frame+0x10         uint32 size                       (the omega::Frame object)
Frame+0x18         void*  buffer                     (the omega::Frame object)
```

So `0x140452360`'s `[+0x10]` / `[+0x18]` reads are fields of the **Frame**, reached
through the pointer array it is handed — not fields of the queue record. There is
no contradiction in the code, only in the earlier prose.

Answering the four possibilities directly: **(1) is correct** — `0x14043B5D0`
converts each queue record into a separate pointer array *and* a parallel length
array before calling `0x140452360`; the layout labels were also partly mislabelled,
which is what made the two lines look irreconcilable. There is **no** second
intermediate structure.

The conversion, in full:

```asm
; 0x14043B70C..0x14043B785  choose the two arrays
14043b71e  lea   r8,  [rbp + 0xc0]        ; inline frame-pointer array (0x100 bytes)
14043b725  mov   [rbp + 0x768], r8        ;   -> [rbp+0x768] slot holds its base
14043b72c  lea   r15, [rbp + 0x3e0]       ; inline length array
14043b738  cmp   r13d, 0x64
14043b73c  jle   0x14043b785              ; <= 100 records: use the inline arrays
14043b741  mov   eax, 8 / mul rbx         ; else allocate two heap arrays
14043b757  call  0x14008ce30              ;   frames = mm_alloc(8 * count)  -> r15
14043b773  call  0x14008ce30              ;   lens   = mm_alloc(8 * count)

; 0x14043B7D5..0x14043B7F3  the extra record (this[0x98] == 1) is appended
14043b7d5  movsxd rcx, ebx
14043b7d8  lea   rdx, [rcx*8]
14043b7e0  mov   r8,  [rbp + 0x768]
14043b7e7  mov   [rdx + r8], rax          ; lens[idx]  = record   (the 0x20-byte record)
14043b7eb  mov   rcx, [rax + 0x10]        ; rcx = frame           (MOVED OUT)
14043b7ef  mov   qword ptr [rax + 0x10], 0 ; record+0x10 := NULL
14043b7f3  mov   [rdx + r15], rcx         ; frames[idx] = frame

; 0x14043B810..0x14043B826  the stolen queue records, in reverse order
14043b817  mov   [r8 + rdx], rdi          ; lens[i]   = record
14043b81b  mov   rax, [rdi + 0x10]        ; rax = frame           (MOVED OUT)
14043b81f  mov   qword ptr [rdi + 0x10], 0 ; record+0x10 := NULL
14043b823  mov   [rdx], rax               ; frames[i] = frame

; 0x14043BA05..0x14043BA1B  the hand-off
14043ba05  mov   r9d, r12d                ; arg4 = accumulated total bytes
14043ba08  mov   r8d, [rbp + 0x758]       ; arg3 = record count
14043ba0f  mov   rbx, [rsp + 0x20]        ; arg2 = frame-pointer array (r15)
14043ba17  mov   rcx, [rsi + 0x38]        ; arg1 = PacketSocket's frame/sink object
14043ba1b  call  0x140452360
```

So the two arrays are distinct, with different element meanings:

```text
frames[i]  omega::Frame*            (r15; element size 8)  -- read as [x+0x10]/[x+0x18]
lens[i]    the 0x20-byte record*    (the other array)       -- only used for cleanup
```

`lens[]` is not passed to `0x140452360` at all; it exists so the epilogue can
release and `mm_free(rec, 0x20)` each record (`0x14043B9D9`, `0x14043BB1B`).

The NULLing of `record+0x10` is a **move**, not a transformation: the Frame
pointer is transferred into `frames[]` and the record's slot cleared so the
record's own cleanup does not release it twice.

### Record -> write chain

```text
logical queued object   omega::PacketSocket
queue record           0x20 bytes: { +0x00 next, +0x08 ctx ref,
                                      +0x10 omega::Frame*, +0x18 uint32 size }
queue                  PacketSocket+0x168 (lock-free LIFO)
byte accounting        PacketSocket+0x170 (added on queue, subtracted on service)
service trigger        PacketSocket+0x164 gate -> ObjectManagerImpl+0x260 ->
                       the 5 ms callable 0x140430800
flush                  0x14043B5D0 (mode 0); mode 1 on the >= 1 MiB threshold
conversion             the flush MOVES omega::Frame* out of each record into a
                       flat frames[] array (plus a parallel lens[] it keeps only
                       for cleanup), NULLing record+0x10 as it goes
hand-off               0x140452360(socket+0x38, frames[], count, total_bytes)
per-frame dispatch     for each frames[i]:
                         size   = [frames[i] + 0x10]        (Frame length)
                         buffer = [frames[i] + 0x18]        (Frame data)
                         [[socket+0xd8]]->vtable[8](buffer, size)
                                                           <-- write entry
```

The final hop is a virtual write on the object at `PacketSocket+0xd8`; the real
Winsock boundary in this image is `0x140A82CB0` (`WSASend` twice in a
partial-write loop, returns -1 on failure). The exact hop from
`[[socket+0xd8]]->vtable[8]` to `0x140A82CB0` was not resolved this pass, so the
chain is proven down to a write-dispatch virtual and `UNKNOWN` for that one hop.

### The service path is generic, and the Close verb uses it

`0x14043B460` (which builds the 0x20-byte record, pushes it onto
`PacketSocket+0x168`, and enqueues the socket onto `ObjectManagerImpl+0x260`) has
**six** call sites image-wide, all with one shape:

```text
rcx = the socket        rdx = a context record
r8  = a second context  r9d = a 32-bit message id
```

| call site | containing fn | `r9d` message id | message |
| --------- | ------------- | ---------------- | ------- |
| 0x140412667 | 0x1404123D0 | `0x43DB3479` | **Close** |
| 0x140412BDF | 0x140412B20 | `edi` (param) | sibling Close-family verb |
| 0x14043CE37 | 0x14043C900 | 0 | socket-cluster internal |
| 0x14045B992 | 0x14045B620 | `0x8B0D492F` | IntroduceConnection |
| 0x14045BC70 | 0x14045BA00 | `0xA609E6A7` | RequestIDSignature |
| 0x14045BF91 | 0x14045BCD0 | `0x6731C5AF` | ReplyIDSignature |

One function serializes Close, IntroduceConnection, RequestIDSignature and
ReplyIDSignature identically, so the machinery is **generic outbound message
transport**, not close-time cleanup.

Which Close invocations take the path: `0x1404123D0(conn, arg2, arg3)` writes the
`0x43DB3479` envelope only when `arg2 == 0` (the build block is entered by
fallthrough at `0x1404124F4`; nothing branches to the call at `0x140412667`). The
wire-observed producers do pass 0:

```text
0x14040AEC0  routed-peer Close        arg2 = 0   TAKES the deferred path
0x140468D40  TimeRequester teardown   arg2 = 0   TAKES the deferred path
```

Counter-case: the inbound dispatcher `0x14042B990` routes an inbound Close
(`0x43DB3479`) with `arg2 = 1`, which **skips** `0x14043B460`, while inbound
RequestClose (`0x598D9A7`) is routed with `arg2 = 0` and **takes** it.

### The PacketSocket state machine: getter, CAS, and what 4 vs 7 mean

Two distinct helpers, now both fully resolved:

```text
0x140414BD0(x)                       state GETTER
    returns [x+0x18] unchanged. 9 is a transient spin-lock marker: the accessor
    xchg's 9 in, reads the old value, restores it; if it observes 9 it falls back
    to a QueryPerformanceCounter-timed wait loop.

0x140414CB0(x, newState, allowedMask, warnMask)   state COMPARE-AND-SWAP
    if (1 << oldState) & allowedMask: store newState, return oldState
    else:                            restore oldState, return 0xA (== 10)
```

Verified by emulating the real bytes for every input (after fixing two emulator
bugs: a register-id map that aliased `rcx` onto `rbx`, and 32-bit writes such as
`mov eax, 1` being stored under a key separate from `rax`, which made every
32-bit return read back as 0):

```text
0x140414BD0 with [x+0x18] = 0..8  ->  returns 0..8 exactly, field unchanged
```

The Close verb `0x1404123D0` uses both:

```asm
14041240a  mov   edx, 7              ; newState
14041240f  mov   r9d, 0x180          ; warnMask
140412415  lea   r8d, [rdx + 0x78]   ; allowedMask = 0x7F  (states 0..6)
140412419  call  0x140414cb0         ; CAS
14041241e  mov   r14d, eax           ; r14d = OLD state
140412421  cmp   eax, 0xa
140412424  jne   ...                 ; 0xA -> denied, return false
1404124e1  cmp   r14d, 4 / jne ...   ; GATE 1: the PRE-transition state was 4
...
140412604  call  0x140414bd0         ; GATE: current state is 4 or 7
140412609  cmp   eax, 4 / je  ...
140412611  call  0x140414bd0
140412616  cmp   eax, 7 / jne ...    ; not 4 and not 7 -> do not send
140412667  call  0x14043b460         ; serialize + queue Close
```

So the sequence is: the connection is in state **4**; the CAS moves it
**4 -> 7**, permitted because `1 << 4` is inside the `0x7F` allowed mask; the
send gate then accepts state 7. `0x14043B460`'s own gate
(`0x140414BD0(this) == 4`) is evaluated on the socket's state.

```text
state getter 0x140414BD0                      CONFIRMED  returns [arg+0x18]
state CAS    0x140414CB0(x,new,mask,warn)     CONFIRMED  returns old state, 0xA if denied
state 4       admitted by 0x14043B460 (queue) and by the Close gate  UNKNOWN name
state 7       admitted by the Close gate; produced by the 0x140414CB0 CAS
              (newState = 7, allowedMask = 0x7F, warnMask = 0x180)   UNKNOWN name
state 0xA     "transition denied" sentinel                            CONFIRMED
```

Because `0x14043B460` queues records only when the state is 4, and the Close verb
sends only when it is 4 or 7, state 4 cannot mean "closed". The enum values are
deliberately left unnamed until the writers are recovered.

### Deferred-service pass — element class, virtuals, and producer callers

This pass resolved the element type and both virtual slots, which retires the
"deferred-destruction" label in favour of a proved claim. Method and evidence
are recorded in `docs/retail-protocol-evidence.md`; the conclusions are:

```text
queue element class                = omega::PacketSocket            CONFIRMED
element primary vtable             = 0x1414B6968                   CONFIRMED
element COL                        = 0x141702F08                   CONFIRMED
element type descriptor            = 0x141B65D70                   CONFIRMED
element allocation                 = 0x1F8 bytes, freed via mm_free CONFIRMED
element vtable+0x28 target         = 0x14043DB20                   CONFIRMED
element vtable+0x30 target         = 0x14043DBF0                   CONFIRMED
producer 0x140406530 callers       = exactly 2 (image-wide)         CONFIRMED
producer AL consumed by a caller   = never                          CONFIRMED
second family vtable 0x1414B69A8   = Component sub-vtable INSIDE a
                                     PacketSocket, not a 2nd manager CONFIRMED
```

The element identity is forced by the object's own base-class list: the RTTI
Chain Hierarchy Descriptor for `omega::PacketSocket` is

```text
.?AVPacketSocket@omega@@
.?AVComponent@omega@@
.?AVComponentConsumer@omega@@
.?AVBufferedSocketObserver@omega@@
.?AVInterface@omega@@
.?AV?$LocklessListNode@VPacketSocket@omega@@@omega@@
.?AVLocklessListNodeImpl@detail@omega@@
```

`LocklessListNode<PacketSocket>` embeds its link at class offset `0x30`, which is
exactly the intrusive link offset the producer writes (`add rbx, 0x30`) and the
consumer walks. `LocklessListNode<PacketSocket>` is the **only** instantiation of
that template in the image, so a class-agnostic "some list node at +0x30" reading
is not available.

Corrections this pass makes to the previous checkpoint:

```text
"0x1414B69A8 is a second manager family instance"      WRONG -> it is a PacketSocket
element vtable+0x30 slot of 0x1414B69A8 is _purecall   that vtable is the
                                                        Component sub-vtable
"producer's sete al is the arming signal"              WRONG -> both callers
                                                        discard al
```

### The producer's `AL` is discarded by both callers

`0x140406530` really does `sete al` on `(old_head == NULL)`. It is nevertheless
**not** an arming signal, because neither call site reads it:

```asm
; caller A  0x14043B460, at 0x14043B53D
14043B52F  mov  rcx, qword ptr [rax + 0xD8]
14043B533  mov  rdx, rbx
14043B536  ...                                   ; rcx = [rcx+8] inside producer
14043B53D  call 0x140406530
14043B542  mov  eax, dword ptr [rbp + 0x10]      ; <-- eax immediately clobbered
```

```asm
; caller B  0x14043DE10, at 0x14043E045
14043E037  mov  rax, qword ptr [rdi + 8]
14043E03E  mov  rcx, qword ptr [rax + 0xD8]
14043E045  call 0x140406530
14043E04A  mov  rcx, qword ptr [rdi + 0x40]      ; no flag/test/jcc on al
```

So `producer returns (old_head == NULL)` is `CONFIRMED` as a value, and
`AL actually schedules the 5 ms drain` is `DISPROVEN` for both callers.

The coalescing gate that callers *do* implement is a per-object retire-once flag
written with `lock cmpxchg dword ptr [obj+0x164], 1` (0 -> 1), guarded by the
push onto the object's own stack at `+0x168`; `0x14043B5D0` resets it. The
function that registers the 5 ms drain is `0x14042F960`, called exactly once,
from the object-manager initialisation path at `0x1404465A7`, with `r9d = 5` at
`0x14042FAFF` and `fn = 0x140430800` loaded at `0x14042FA9D`.

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

## The two Close producers, and which one the observed Close came from

`0x1404123D0` is called from two different places in this subsystem. They are
separate mechanisms and must not be merged.

```text
Path A   route-registration-failure Close                       CONFIRMED
         0x140412180 @ 0x140412317 -> 0x1404123D0(conn, 2, 1)
         taken only when 0x14043D380 reports failure
         emits NO ConnectionOpen event
         returns with the peer still attached at conn+0x88

Path B   ConnectionOpen-handler Close                           CONFIRMED
         ObjectSurrogateEventConnectionOpen -> 0x140434430
           -> listener vtable+0x28 (0x14040A970, returns 0)
           -> listener vtable+0x70 (0x14040AEC0)
           -> 0x1404123D0 @ 0x14040AF27
```

```text
historical first-Close witness returned to 0x14040AF2C
  = the instruction after the call at 0x14040AF27
  => the recorded Close is Path B                             CONFIRMED
0x140412317 failure arm = an ALTERNATE Close path,
                          NOT the recorded first Close       CONFIRMED
```

Neither path is labelled the root cause.

### The three pointers at the decider, and why they differ

```text
event payload peer  = wrapper[0]        = rdx entry value   -> CAS destination
                                                             AND Close argument
current peer        = [conn+0x88]       = the CAS result    -> the +0x40 test
listener            = [event+0x18]+0x100= rcx               -> the receiver
```

The ConnectionOpen event captures its payload **at queue time**:

```asm
140435fa1  mov rcx, [rbp + 0x7f]     ; the constructor's peer argument
140435fa5  mov [rbx + 0x20], rcx     ; event+0x20 = that peer (+ intrusive retain)
140435ff0  call 0x1403fc0b0          ; enqueue
```

so `event+0x20` is a captured reference, **not** a live read of `conn+0x88`.

### Discriminator: can event A dispatch after peer B replaces A?

```text
EVENT A CAN BE DISPATCHED AFTER PEER B REPLACES A:  YES   CONFIRMED
```

Static ordering inside one `0x140412180` invocation:

```text
0x140412247  create + attach the new peer at conn+0x88
0x140412302  register the receive route (0x14043d380)
0x1404123a5  queue the ConnectionOpen event, capturing that peer
```

Nothing serialises the deferred queue against a later invocation, and the
recorded ordering puts the replacement **before** the dispatch:

```text
T0  thread 2   NULL   -> peer A   (0x140412A4F)
T2  thread 58  peer A -> peer B   (0x140412A4F)
T3  thread 2   0x140423DD0 -> 0x1404245F0 -> 0x140434430 -> 0x14040AEC0
```

```text
the dispatched event is the one queued at T0 (the T2 attach queued none)
its payload peer is the peer that T2 already replaced
the +0x40 test therefore reads the REPLACEMENT peer
the Close is addressed to the STALE payload peer
```

```text
stale-event / replacement explanation for the captured Close   HYPOTHESIS
    (strong static + ordering evidence; NOT a captured identity)
captured Close is a CURRENT-peer rejection                     HYPOTHESIS
    (same caveat -- not DISPROVEN, because the event payload pointer
     was never captured)
```

**Label narrowed this pass.** The distinction that must be kept:

```text
payload/current-peer pointer relationship, statically possible/probable  YES
captured historical event payload identity                               NOT CAPTURED
```

The static and ordering evidence is strong: the event captures its peer at queue
time, the peer is attached before the event is queued, and the recorded ordering
replaces the peer before the deferred dispatch. But "the dispatched event is
stale" is an inference from that ordering, not a measured fact, so it is a
`HYPOTHESIS` until a witness records the event payload pointer.

Unchanged and still `CONFIRMED`:

```text
captured Close = Path B (call at 0x14040AF27, returns to 0x14040AF2C)  CONFIRMED
Path A at 0x140412317 = an alternate Close path                        CONFIRMED
```

### What is still open

```text
event payload peer != conn+0x88 in the captured run            NOT yet captured
    (the notebook recorded conn+0x88 = peer B at dispatch but never
     recorded the event payload pointer; the static analysis above requires
     them to differ given the recorded ordering)
0x14043D380 return contract (what AL==0 vs AL!=0 mean)         UNKNOWN
which invocation's attach queued the dispatched event           INFERRED from timing
Connection+0x50 name producer                                   UNKNOWN
```

---

## Current failure boundary

> **The Close at `0x14040AEC0` is decided by one field: the `+0x40` string of the
> peer attached at `conn+0x88`, which equals the `+0x00` of the peer attached
> before it. That value is `""` on the observed path, and only the exact 2-byte
> string `"*"` skips the Close. What is still `UNKNOWN` is what fires the
> ConnectionOpen event at this point, not what the handler tests.**

Everything is in place except the ConnectionOpen event's own trigger:

```text
event trigger (why ConnectionOpen fires now)         UNKNOWN
listener dispatch -> 0x14040AEC0                     CONFIRMED
CAS operand provenance at 0x14040AEEB                CONFIRMED
tested field = [conn+0x88]+0x40                      CONFIRMED
that value = the previously attached peer's +0x00    CONFIRMED
skip condition = exact "*"                           CONFIRMED
Close argument = the event payload peer              CONFIRMED
server control of the tested field                   UNKNOWN
```

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
* Semantic meaning of `peer+0x40`. It is a real **string-valued field holding the
  routed peer's name**; it is written once by the constructor from p5, and p5 is
  `[[connection+0x88]+0x00]` — the previously attached peer's name. It held `""`
  in the observed run because that previous peer's `+0x00` was `""`.
* The concrete producer of a peer record's `+0x00` on the **first** attach for a
  connection. That root field is the only remaining gap between the wire and
  `peer+0x40`; see "The exact `peer+0x40` provenance chain".
* Whether any inbound message field on the bootstrap path ever populates a peer
  record's `+0x00` with a non-empty value. No such writer was found; the
  constructor `0x1404128D7` is the only writer of `+0x00`.
* Whether `peer+0x40` can ever hold `"*"` in practice. `"*"` is `CONFIRMED` to be
  a real name value the client produces (`0x140407084`, `0x1404070CC`) and the
  skip condition is `CONFIRMED`, but no runtime instance of a `"*"`-named peer
  has been observed.
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
| `0x14040AEC0` detaches `conn+0x88` unconditionally | `DISPROVEN` | Operand provenance: `RAX` (expected) and `RCX` (replacement) are **both 0** (`xor eax,eax` at `0x14040AEE9`, `xor ecx,ecx` at `0x14040AEE7`). A zero-to-zero CAS clears only an already-NULL field, so the instruction is an **atomic null-probe / current-peer load** with `field mutation = NONE`. |
| The wildcard test inspects the event payload peer's `+0x40` | `DISPROVEN` | The load at `0x14040AEFD` is guarded by `je 0x14040AF08`, so it runs **only in the CAS-failure arm**, where `RAX` is the CAS *destination* operand `[rdx+0x88]`. The tested peer is the attached peer; the payload peer is only the Close argument (`mov rcx,[rbx]` at `0x14040AF24`). |
| `0x14040AEC0` "probes and classifies" without a store | `SUPERSEDED` (label only) | The earlier wording stated the effect correctly but was then replaced by "conditional compare-and-clear", which wrongly implies a mutation. Current label: **atomic null-probe / current-peer load**, `field mutation = NONE`. |
| `0x14040AEC0` **conditionally detaches** `conn+0x88` | `DISPROVEN` | A zero-to-zero compare-exchange cannot clear a non-NULL field either, because the replacement equals the expected value. `NULL -> NULL` and `peer -> peer`; no arm removes a peer. |
| `0x14042C300` is the RequestIDSignature handler | `DISPROVEN` | The dispatcher `0x14042B990` calls `0x14042BCA0` for `0xA609E6A7` (RequestIDSignature) and `0x14042C300` for `0x6731C5AF` (ReplyIDSignature). Pre-existing typo in this document, corrected. |
| The routed peer has "four strings at +00/+10/+30/+40" | `SUPERSEDED` | Five StrRef slots are initialised (`+0x00 +0x10 +0x20 +0x30 +0x40`); only four come from parameters. `+0x20` is the derived composite `p3 ":" p2`. |
| `peer+0x40` = "the 4th argument object of `0x14042B3D0`, i.e. the neighbour object" | `SUPERSEDED` | `p5` is the **qword at `[fourth_argument]`**, and the fourth argument is a *receive-route record* whose `+0x00` is a StrRef, not a whole neighbouring peer. The precise statement is `new_peer+0x40 = old_peer+0x00`. |
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
* Phase 0 correction checkpoint (CMPXCHG class + ReplyID opcode + peer layout):
  see the `Phase 0` commit in the log; `docs/retail-protocol-evidence.md` gains a
  matching section at its end. Two static-analysis tools were added for it:
  `tools/reachprov.py` (reachability-aware register provenance inside one
  function — `provenance.py` follows the fallthrough path only and silently
  misses anything behind a conditional branch) and `tools/branches.py` (direct
  branch map of a `.pdata` function).
* Evidence notebook: `docs/retail-protocol-evidence.md` (chronological; may
  contain superseded conclusions — always cross-check here).
