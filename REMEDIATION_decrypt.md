# Remediation — client_decrypt

**Component:** the decrypting client (logit recovery + sigmoid).
**Versions:** V1 (monolith) → V2 (separated pipeline, **baseline**) → V3 (hardened) → V4 (real-data).
**Baseline for all diffs:** V2 — the first refactor that split encrypt / compute / decrypt into distinct binaries, before any hardening.
**Provenance:** decrypt was hardened differently from the other two components. It was audited by a **two-model pairwise loop — Opus 4.8 and DeepSeek, back and forth until consensus, with no base model.** This is distinct from the encrypt four-model LLM consensus (which has a base model plus three reviewers) and from the server audit-of-the-audit. There is no enumerated written audit document for decrypt; the items below are reconstructed from the code diffs and that audit loop.

---

## Lineage at a glance

| Dimension | V1 (monolith) | V2 (baseline) | V3 (hardened) | V4 (real-data) |
|---|---|---|---|---|
| Location | inline (no separate file) | separate `client_decrypt` | same | same |
| Ciphertext type | n/a | FheInt64 | FheInt32 | FheInt32 |
| FEATURE_SCALE | n/a | 16384 | 16384 | 1000 |
| WEIGHT_SCALE | n/a | 16384 | 1000 | 1000 |
| OUTPUT_SCALE | n/a | 268,435,456 | 16,384,000 | 1,000,000 |
| Trust-model comment | none | none | DKG / TKMS block | same |
| Bias comment | n/a | false (pre-scaled claim) | false (retained) | corrected |

> **V1 note:** in V1 there was no separate decrypt file — decryption was inline, not split into its own binary. The separate `client_decrypt` first appears at V2.

> **Scale reading:** OUTPUT_SCALE = FEATURE_SCALE × WEIGHT_SCALE. The divisor that turns the decrypted raw integer back into a logit is the single most important invariant in this file. It was only fully correct at V4.

---

## D1 — Ciphertext type: FheInt64 → FheInt32 (V2 → V3)
**Baseline (V2):** reads `Vec<FheInt64>`, decrypts to `i64`.
**Change:** reads `Vec<FheInt32>`, decrypts to `i32` (three edits: the import, the deserialization type, the decrypted-variable type).
**Reason:** the type must match the server's output (server S2). The server changed its output to `FheInt32`; a decrypt still reading `FheInt64` would read the wrong bytes and produce garbage. The `FheInt64` was leftover drift from the old convention.

## D2 — WEIGHT_SCALE: 16384 → 1000 (V2 → V3)
**Baseline (V2):** `WEIGHT_SCALE = 16384`.
**Change:** `WEIGHT_SCALE = 1000`.
**Reason:** the weights are quantized at scale 1000 (by the weight-extraction script), so decrypt must use 1000 to reverse the weight scaling correctly. At V3, however, FEATURE_SCALE was still 16384, so OUTPUT_SCALE was 16384 × 1000 = 16,384,000 — still wrong overall (see D3).

## D3 — FEATURE_SCALE: 16384 → 1000 (V3 → V4) — the caught bug
**Baseline (V3):** `FEATURE_SCALE = 16384`, `WEIGHT_SCALE = 1000` → OUTPUT_SCALE = 16,384,000.
**Change:** `FEATURE_SCALE = 1000` → OUTPUT_SCALE = 1000 × 1000 = 1,000,000.
**Reason:** features arrive scaled ×1000 from the V4 Python bridge and weights are quantized ×1000, so the dot-product terms accumulate at exactly 1,000,000 — not 16,384,000. The V3 FEATURE_SCALE was a stale constant left over from the V2 ×16384 quantization scheme; WEIGHT_SCALE had already been corrected (D2) but FEATURE_SCALE had not. Dividing by 16,384,000 instead of 1,000,000 produces a logit roughly 16× too small and a wrong probability. This was the single surviving stale constant, and correcting it is what made the round trip validate.

## D4 — Trust-model comment + bias comment fix
**Baseline (V2/V3):** loads `client_key.bin` and decrypts directly, no trust framing; the bias comment falsely claimed the server bias was pre-scaled in Python by FEATURE_SCALE × WEIGHT_SCALE.
**Change:** added a comment block stating that in production no full secret key exists anywhere — genesis runs DKG producing key shares, and decryption is a threshold protocol (Zama TKMS) combining partial shares without reconstructing the secret; the single-key decrypt stands in for that flow. Separately, the bias comment was corrected to state the truth: the bias was quantized at ×1000, not ×1,000,000, so it is ~1000× too small relative to the terms; the effect is negligible (true bias ≈ −0.002), and a correct version would scale bias by FEATURE_SCALE × WEIGHT_SCALE.
**Reason:** the direct single-key decrypt is the mock's largest deviation from a real fhEVM, so it is documented to pre-empt the obvious "who holds the key?" challenge. The old bias comment was a false claim about the code; the code is left as-is (the error is negligible) and only the comment is corrected — a known, documented limitation rather than a churned fix.

---

## The 50.01% diagnostic — what surfaced the synthetic data

While running the decrypt output during the pairwise audit, the result came back at **50.01%** fraud probability (logit 0.0004).

A fraud model returning 50.01% means a logit of 0.0004 — effectively zero, a coin flip on every transaction. That is the fingerprint of meaningless input, not a real score. The 50.01% was therefore not a *result* but a *diagnostic signal*: it revealed that the pipeline was running on **synthetic data** (raw random integers from the test-data generator), not real transactions.

That discovery triggered the V4 real-data switch: the bridge `prepare_features_for_he_encryption.py` was created (scale ×1000, clip ±8192), real `train.parquet` (IEEE-CIS) was pulled in, and the pipeline was re-run on real data — yielding the verified 45.81% result.

Like the CRS-sharing find in the server component, this was a symptom read back to a root cause, not an item handed over by an audit.

---

## Round-trip parity check (V4, real data)

The final pipeline was validated by mirroring the encrypted computation in plaintext:

- FHE-decrypted logit: **−0.1680**
- Plaintext dot product: **−167,970**
- −167,970 ÷ 1,000,000 = **−0.16797** → exact match → **45.81%** both ways.

Exact parity confirms two things at once: the homomorphic dot product equals the plaintext dot product (the FHE computation is correct), and the OUTPUT_SCALE divisor (D3) is right. This is a correctness proof of the cryptographic computation — not a claim about the model's predictive quality (see the spurious-feature limitation in the README).

---

## V3 → V4 changes (decrypt-specific)

- **FEATURE_SCALE 16384 → 1000** (D3) — the only behavioral change, correcting OUTPUT_SCALE to 1,000,000.
- **Bias comment corrected** (part of D4).

The decrypt file is short by design: recover the logit, reverse the scale, apply the sigmoid locally (non-linear functions are inefficient in FHE). Its remediation is small but consequential — a single stale constant silently breaks the entire result, and tracing the wrong-magnitude logit back to that constant was the work that closed the pipeline.
