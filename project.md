## Unified Implementation Plan: Rust Smart-Card Middleware (Modern + Non-Blocking Linux UX)

### Objective

Build a **Rust-based smart-card platform** that:

1. Replaces legacy C middleware with a clean, modular architecture
2. Guarantees **non-blocking behavior**, especially on Linux (no browser/network freezes)

---

# Core Strategy (single direction)

> Build a **PC/SC-backed Rust core**, implement **PIV first**, and expose a **non-blocking PKCS#11 layer** using async workers, caching, and strict timeouts.

This merges both goals:

* Modernization → Rust core + modular design
* Linux reliability → async isolation + fail-fast behavior

---

# Architecture Overview

```text
[ Applications / Browsers ]
        ↓
   PKCS#11 (non-blocking)
        ↓
  Async Worker Layer (core logic)
        ↓
 Smartcard Core (APDU + profiles)
        ↓
 Transport (PC/SC via pcsc crate)
```

---

# Implementation Layers

## 1. Transport Layer (foundation)

* Wrap PC/SC using Rust (`pcsc` crate initially)
* Provide:

  * reader discovery
  * connect/reconnect
  * APDU transmit
* Add **timeouts around every call**

Key rule:

> No direct PC/SC calls outside this layer

---

## 2. Core Runtime (critical layer)

This is the heart of the system.

Responsibilities:

* APDU encoding/decoding (ISO 7816)
* transaction management
* error normalization
* card state tracking

Add:

* strict timeout enforcement
* retry + reconnect logic
* per-reader state machine:

  * Healthy → Slow → Unresponsive → Resetting

---

## 3. Worker Isolation Layer (Linux fix)

Every card gets a dedicated worker.

```text
PKCS#11 → queue → worker thread → PC/SC
```

Responsibilities:

* serialize card access
* enforce timeouts
* recover from hangs
* isolate failures

Guarantee:

> PKCS#11 never directly blocks on hardware

---

## 4. Caching Layer (browser stability)

Cache aggressively:

* certificates
* key metadata
* token info

Behavior:

* load once on insertion
* serve instantly to callers
* refresh asynchronously

Result:

> Browsers rarely touch hardware → no stalls

---

## 5. Card/Profile Layer

Start with:

* **PIV (primary target)**
* CAC (later, via compatibility)

Responsibilities:

* applet selection
* PIN handling
* signing/decryption
* cert enumeration

Keep:

* clean separation from transport

---

## 6. PKCS#11 Provider (user-facing)

Expose functionality to:

* browsers
* SSH
* VPN
* signing tools

Design constraints:

* fully non-blocking
* bounded execution time
* returns errors instead of hanging

Behavior:

* fast responses from cache
* async delegation to worker when needed
* fail fast on timeout

---

# Key Design Guarantees

## 1. Never block the caller

Every operation:

* runs in worker
* has timeout
* returns within fixed time

## 2. Fail fast

On issues:

* return `DEVICE_ERROR` / `TOKEN_NOT_PRESENT`
* never retry indefinitely

## 3. Isolate failures

* one bad reader ≠ system failure
* per-reader workers

## 4. Treat hardware as unreliable

* expect hangs
* expect disconnects
* recover automatically

---

# Development Phases

## Phase 0 — Foundation (1–2 weeks)

* PC/SC wrapper
* CLI tool:

  * list readers
  * connect
  * send APDU
  * print ATR
* basic timeout wrapper

---

## Phase 1 — Core + Worker Model (2–3 weeks)

* implement core runtime
* worker threads per reader
* health state machine
* reconnect logic

Deliverable:

* stable APDU engine with recovery

---

## Phase 2 — PIV Support (2–4 weeks)

* applet select
* PIN verify
* cert enumeration
* sign operation

Add:

* caching layer

Deliverable:

* usable CLI for PIV operations

---

## Phase 3 — PKCS#11 (non-blocking) (3–5 weeks)

* minimal PKCS#11 implementation
* map calls → worker
* cache-backed responses

Test with:

* Mozilla Firefox
* Google Chrome

Goal:

> no browser freezes under any condition

---

## Phase 4 — Hardening (ongoing)

* failure injection:

  * kill pcscd
  * unplug reader mid-op
  * simulate hangs
* fuzz APDU parsing
* performance tuning

---

# Minimal Crate Structure

```text
smartcard-rs/
  smartcard-core/
  smartcard-pcsc/
  smartcard-apdu/
  smartcard-piv/
  smartcard-worker/
  smartcard-pkcs11/
  smartcard-cli/
```

---

# Success Criteria

You are done when:

* inserting/removing card never freezes apps
* browser requests always complete (even on failure)
* card hangs are automatically recovered
* PIV operations work reliably
* PKCS#11 is stable under concurrency

---

# The Plan in One Line

> Build a Rust smart-card core with **worker-isolated PC/SC access, aggressive caching, and strict timeouts**, then expose it through a **non-blocking PKCS#11 interface with PIV as the first-class target**.

---

If needed, next step can be:

* exact PKCS#11 function mapping design
* worker thread API + message protocol
* or a minimal working prototype skeleton in Rust
