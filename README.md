# FHE Fraud Inference — Privacy-Preserving Logistic Regression on Encrypted Transactions

A mock fhEVM-style coprocessor that scores a credit-card transaction for fraud
**without ever decrypting it**. Built on tfhe-rs 0.8.7 (high-level API).

> **What this demonstrates:** a study of where privacy-preserving ML inference
> actually breaks in practice — ciphertext sizing, ZK integrity, CRS sharing,
> scale alignment, and the gap between a working prototype and a production
> fhEVM coprocessor. It is a rigorous learning artifact, not a product, and it
> is candid about its limitations.

## What it does

A client encrypts one IEEE-CIS transaction (433 features) under TFHE, attaches a
zero-knowledge proof of well-formedness, and publishes it. A blind coprocessor
computes an encrypted logistic-regression dot product against quantized weights
and returns an encrypted logit. Only the key-holder can decrypt and apply the
sigmoid.

## Verified result

A real transaction scored end-to-end under encryption:

- FHE-decrypted logit **−0.1680** → **45.81%**
- Plaintext mirror: dot product **−167,972**; −167,972 / 1,000,000 = −0.1680.
  Exact match.

**This validates the homomorphic computation — that the encrypted dot product
equals the plaintext dot product exactly — not the model's predictive quality.**
The two are separate axes. The example model deliberately retains a spurious
feature (see Limitations), so 45.81% is a proof of *cryptographic correctness*,
not a trustworthy fraud-risk score.

## Architecture — four binaries

Run in order; each consumes the previous step's artifacts:

1. **`network_genesis`** — mock DKG. Generates the client, public, and server
   keys on `PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64`.
2. **`client_encrypt`** — encrypts 433 features, builds a ZK proof bound to
   transaction metadata, writes `request.bin` and the shared `crs.bin`.
3. **`server_compute`** — verifies and expands the request, computes the
   encrypted dot product against the quantized weights, writes `response.bin`.
4. **`client_decrypt`** — decrypts the logit, reverses the output scale, applies
   the sigmoid locally.

## Security model

- **Confidentiality:** TFHE under TUniform 2M64 — **≥136-bit lattice security**
  (lattice-estimator: minimum attack `dual_hybrid` ≈136.2 bits; n=887,
  TUniform(46), q=2⁶⁴). See `SECURITY_lattice_estimate.md`.
- **Integrity / malleability:** TFHE is IND-CPA-secure; being homomorphic, it is
  also malleable by design — a public-mempool adversary could homomorphically
  add deltas to a ciphertext. The `ProvenCompactCiphertextList` ZK proof (Proof
  of Ciphertext Knowledge) binds well-formedness, the ±8192 bound, and plaintext
  knowledge to fixed metadata (sender, nonce, chain_id, block_expiry), closing
  that gap.
- **Trust model (mocked):** a single `ClientKey` stands in for production DKG +
  threshold decryption (Zama TKMS). In a real deployment the secret never exists
  in one place; this mock holds it to stay self-contained.
- **Known production gap:** 2M64 gives PBS failure ≤ 2⁻⁶⁴, below the 2⁻¹²⁸ that
  production fhEVM needs to align correctness with the security level and reach
  IND-CPA^D against decryption-oracle attacks. 2M128 requires tfhe-rs 1.x —
  scoped as an isolated future migration because of API and key-format churn.

## Known limitations

- **Bias scale (known, negligible, left documented):** the bias is quantized in
  Python at ×1000, not ×1,000,000, so it is ~1000× too small relative to the
  dot-product terms. The effect is negligible — true bias ≈ −0.002, contributing
  ~−2,000 against a raw logit in the hundreds of thousands — so it is documented
  rather than churned. A correct version scales bias by FEATURE_SCALE ×
  WEIGHT_SCALE.
- **Spurious TransactionID feature:** it carries weight 37, clips to 8192, and
  contributes 303,104 to the raw logit. Because it was trained raw while other
  features were normalized, its magnitude effect cannot be cleanly estimated and
  no reliable risk adjustment is possible — which is why the result is a
  correctness proof, not a risk score.
- **Single-row:** the client encrypts one transaction per run (Web3 atomicity);
  batching is rejected at the client.

## Methodology — how this was hardened

The pipeline was iteratively audited and remediated across four versions, each
change recorded baseline → change → reason in per-component documents
(`REMEDIATION_encrypt.md`, `REMEDIATION_server_compute.md`,
`REMEDIATION_decrypt.md`). Every change is traceable to an audit, not an ad-hoc
edit. Each component was hardened by a distinct method: a four-model LLM
consensus (Gemini 3.1 Pro base; Grok, DeepSeek, Claude reviewers) for encrypt;
an audit-of-the-audit (Opus 4.7 reviewing the consensus plan) for server; and a
pairwise model consensus (Opus 4.8 ↔ DeepSeek) for decrypt.

## Stack

tfhe-rs 0.8.7 · Polars (parquet I/O) · zeroize · serde/bincode · Python
(scikit-learn training, quantization, feature-prep bridge).
