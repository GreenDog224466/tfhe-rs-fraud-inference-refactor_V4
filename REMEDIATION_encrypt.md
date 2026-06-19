# Remediation — client_encrypt

**Component:** the encrypting client.
**Versions:** V1 (monolith) → V2 (separated pipeline, **baseline**) → V3 (hardened: ZK/CRS/types) → V4 (real-data).
**Baseline for all diffs:** V2 — the first refactor that split encrypt / compute / decrypt into distinct binaries, before any hardening.
**Provenance:** V2 → V3 was hardened in two passes, both by four-model LLM consensus (Gemini 3.1 Pro base; Grok, DeepSeek, Claude reviewers). Round 1 was a 5-vector architectural/security audit; it was executed. Round 2 re-audited the executed result **and** added further hardening items it found necessary; it was executed. V3 → V4 changed the *data source* (synthetic → real) but left the encrypt logic essentially unchanged.

---

## Lineage at a glance

| Dimension | V1 (monolith) | V2 (baseline) | V3 (hardened) | V4 (real-data) |
|---|---|---|---|---|
| Ciphertext type | FheUint64 | FheInt64 | FheInt32 | FheInt32 |
| Key generation | local, in client | local, in client | moved to `network_genesis` | same |
| Feature data | synthetic | synthetic | synthetic | real (train.parquet + bridge) |
| Feature scaling | n/a | inline ×16384 path (unexercised) | path removed | ×1000 in Python bridge |
| ZK proof | none | none | ProvenCompactCiphertextList | same |
| Column guard | — | width `<` | width `!=` | same |
| Memory hygiene | none | none | zeroize | zeroize (+ comment) |

> **V1 note:** in V1 the dot product lived **inside** the encryption file — encrypt and compute were not separated. The V1 → V2 refactor split them into distinct binaries. (Confirmed against the V1 encryption file, which contains both the encryption helper and the dot-product function.)

> **Scaling note:** the V2 encrypt code carried a `Float → value × 16384` path, but the synthetic data feeding it emitted small raw `int64`s that never hit the float arms — so the ×16384 path was present but never exercised. Real feature scaling (×1000) first happens in V4, in the Python bridge, not the client. The client never scales; it only bounds-checks.

---

## Round 1 — 5-vector architectural / security audit (V2 → V3)

The audit covered the whole system. Three of its five vectors are primarily server/coprocessor concerns and are remediated in the server document; they are noted here only to record where they were raised.

### E1 — Remove local key generation (Vectors 3, 5)
**Baseline (V2):** the client generates keys locally and writes both the client key and server key itself.
**Change:** key generation removed entirely; keys come from `network_genesis`. The client only *loads* the public key.
**Reason:** local keygen puts the secret key in one party's hands, destroying the Web3 trust model. A client that also generates and ships the ~131 MB server key is the OOM/trust failure of Vector 3. The client should hold no secret and generate no evaluation key — in production it fetches the network public key produced by DKG.

### E2 — Add ZK Proof of Ciphertext Knowledge + metadata binding (Vector 5)
**Baseline (V2):** plain per-feature encryption, serialized as a raw `Vec<Vec<FheInt64>>`. No proof, no binding.
**Change:** features pushed into a `ProvenCompactCiphertextList` builder; the build emits a proof bound to 44-byte metadata (sender 20B + nonce + chain_id + block_expiry, big-endian). A CRS is generated, its public params compressed and written to `crs.bin`.
**Reason:** TFHE is IND-CPA-secure; being homomorphic, it is malleable by design — without a binding proof, a mempool adversary can add encrypted deltas to the request (`Enc(x) + Enc(δ)`). The ZK-PoCK asserts well-formedness, the ±8192 bound, and plaintext knowledge, and binds them to the transaction context. (The metadata must be reconstructed byte-for-byte server-side — see server S15.)

### E3 — Ciphertext type change (Vector 2) — *prescription later superseded*
**Baseline (V2):** features encrypted as `FheInt64` (16 radix blocks).
**Round-1 prescription:** downcast the *scale* to 8192 and use `FheInt16` (4 blocks) for a ~75% HCU reduction.
**What shipped:** `FheInt32` (8 blocks), pushed as `i32`. **i16 was rejected.**
**Reason / supersession:** see "Where the audits were superseded" below. In short, i16 silently wraps (8192 × 75 = 614,400 > i16's 32,767 ceiling), so the Round-1 i16 prescription was wrong; the correct type was settled server-side (S2) and propagated back to the client.

### Server-side vectors (raised here, remediated in server doc)
- **Vector 1 (compute half) — silent noise overflow** on a naive serial accumulation loop; the client half (the bounds check) is E4 below.
- **Vector 2 (batch_bootstrap)** — HCU amortization at the coprocessor.
- **Vector 3 (OnceLock + worker pool)** — server-key caching and concurrency.
- **Vector 4 (CMUX / branchless)** — encrypted conditionals downstream.

These are recorded in the server remediation; several were deliberately *not* implemented (see that doc's "items deliberately not executed").

### E4 — Hard bounds check ±8192 (Vector 1, client half)
**Baseline (V2):** the integer arm carried the comment "Assume Python already quantized it" — no enforcement.
**Change:** reject out-of-range values (`< −8192 || > 8192`) with a `Result::Err` before encryption.
**Reason:** FHE does not panic on overflow — an unscaled value silently exceeds the message modulus and produces a valid ciphertext over corrupt data ("silent errors"). The bound also enforces the normalized input range the ZK proof attests to.

> **Note — the bound is enforced twice, by design.** The Python bridge *clamps* values to ±8192 (it conditions the data); this client check *rejects* anything outside ±8192 (it refuses to trust upstream). After the bridge clamps, this check always passes in the current pipeline — but it is the cryptographic guard that catches any data that did not pass through the bridge. Producer-clamps, boundary-rejects: defense in depth, not redundancy.

---

## Round 2 — 7-point hardening audit (V2 → V3)

Round 2 re-audited Round 1's executed code and added robustness items. E5 refines the Round-1 type decision; E6–E11 are net-new defensive checks.

### E5 — Signed cast, not unsigned — *the two's-complement trap*
**Baseline:** the bounded value was cast directly with `as u64`.
**Change:** cast through a signed type first (`as i16` at the time; later `as i32` — see supersession).
**Reason:** casting a negative directly to `u64` wraps it (e.g. −5 → 18,446,744,073,709,551,611), pushing ~1.8×10¹⁹ into the ZK builder and silently corrupting the ciphertext. The signed cast preserves the sign. (The *width* changed later to i32; the signed-cast lesson is what this item established.)

### E6 — Cryptographic zeroization
**Baseline:** plaintexts left to `drop`.
**Change:** zeroize the plaintext buffer after the proof is built.
**Reason:** `drop` releases memory without erasing it; a heap dump moments later exposes raw financial plaintext. zeroize overwrites with zeros first.

### E7 — Single-row enforcement
**Baseline:** the first row of any file was used silently.
**Change:** slice to row 0, then reject if the row count is not exactly 1.
**Reason:** an FHE inference is heavy; batching many rows into one transaction blows the gas/HCU ceiling and reverts, burning fees. One transaction per block (Web3 atomicity), and no silent dropping of rows.

### E8 — Exact column equality
**Baseline:** `width <` EXPECTED_FEATURES.
**Change:** `width !=` EXPECTED_FEATURES.
**Reason:** `<` passes a 435-column file still carrying ID/label columns, broadcasting PII or the fraud label to a public chain. Exact equality guarantees no leakage.

### E9 — Graceful null handling
**Baseline:** `.unwrap()` on cell extraction.
**Change:** `.ok_or_else(...)?` returning a clean error.
**Reason:** a single null panics the whole client. Converting to `Result::Err` lets a wallet frontend halt cleanly.

### E10 — Explicit flush
**Baseline:** the buffered writer was left to drop naturally.
**Change:** explicitly flush the data and CRS writers.
**Reason:** a crash after serialize but before the buffer drains leaves a truncated `request.bin`. Flushing forces atomic completion.

### E11 — Time-based replay protection (`block_expiry`)
**Baseline:** bound metadata covered only sender / nonce / chain_id.
**Change:** added `block_expiry` to the bound metadata.
**Reason:** nonce alone doesn't stop a held transaction from being submitted later when conditions have changed, or replayed on a parallel testnet. Binding the proof to an expiry lets the contract reject a stale submission.

---

## Where the audits were superseded

The interview-relevant part: three places where the shipped code does **not** follow the audit as written, and why.

### Supersession 1 — FheInt16 → FheInt32 (both rounds said i16)
Both Round 1 (Vector 2) and Round 2 pointed at `FheInt16` with a scale of 8192. **That was wrong.** Sizing must be against *accumulation* width, not input width: 8192 × 75 = 614,400 for a single term — already past i16's 32,767 ceiling, before summing 433 terms. i16 would silently wrap. The correct type was established in the server type analysis (S2): FheInt32 (8 blocks) is the honest minimum — i16 wraps, i64 is ~2× the HCU for no benefit. Because the ciphertext type must match on both sides, that server-side decision propagated back to the client (push `i32`). The two's-complement *lesson* from Round 2 survives; only the width changed.

### Supersession 2 — "IND-CCA2" dropped from the malleability framing
Round 1 (Vector 5) labelled the malleability issue "IND-CCA2 Malleability." That term is misapplied. TFHE is IND-CPA-secure (and always was); being homomorphic, it is malleable by design. IND-CCA2 is the *stronger* model the scheme does not claim — there was no IND-CCA2 property to lose. The ZK proof does not upgrade the encryption to IND-CCA2; it adds a separate INT-CTXT-style integrity layer. Framing corrected to say exactly that.

### Supersession 3 — 8192 is the clip *bound*, not the *scale*
The audits treated 8192 as the quantization scale (Vectors 2, 4). In the shipped pipeline the scale is ×1000 (matching weight quantization) and 8192 is the cryptographic *clip bound* — two different numbers doing different jobs. Scaling lives once in the V4 Python bridge (scale 1000, bound 8192, measured clip rate ~1.7%); the client only enforces the bound. V2/V3 never scaled real features at all — they ran on synthetic small-integer data.

---

## V3 → V4 changes

**Code (cosmetic):**
- Encrypt file renamed to its production name; `Cargo.toml [[bin]]` path updated.
- Zeroize comment extended: in this mock zeroization isn't strictly necessary (key and parquet persist on disk anyway) but is kept as production hygiene against core dumps, swapped pages, and freed-memory reads.

**Data (substantive):**
- Feature source switched from synthetic (raw random ints) to **real** `train.parquet` (IEEE-CIS) via the bridge (×1000 scale, ±8192 clip).

The encrypt logic did not change at V4; the data it consumes did. This is the change that made the verified 45.81% result a real-transaction score rather than a synthetic one.
