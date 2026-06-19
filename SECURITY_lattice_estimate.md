# Security — Lattice Estimate

**Parameter set:** `PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64` (tfhe-rs 0.8.7).
**Source:** `shortint/parameters/classic/tuniform/p_fail_2_minus_64/ks_pbs.rs`.
**Tool:** Albrecht et al. lattice-estimator (SageMath), script `fhe_proof_tuniform.sage`.

## Parameters tested
- LWE dimension n = 887
- Ciphertext modulus q = 2⁶⁴ (native 64-bit)
- Secret: binary (UniformMod 2)
- Noise: TUniform(46), modelled by its standard deviation (~2^45.21) as a
  discrete Gaussian for the estimate.

## Results (log₂ of attack cost, in bits)

| Attack | Security (bits) |
|---|---|
| arora-gb | ∞ |
| bkw | 208.84 |
| usvp | 143.12 |
| bdd | 140.65 |
| bdd_hybrid | 140.68 |
| bdd_mitm_hybrid | 170.91 |
| dual | 147.14 |
| **dual_hybrid** | **136.20** |

## Verdict
Security is the cost of the **cheapest** attack: **dual_hybrid at ≈136 bits**.
The parameter set therefore provides **≥136-bit security**, exceeding the
128-bit target. This is the lattice (confidentiality) axis only — independent of
the PBS failure probability (2⁻⁶⁴ for this set), which is the separate
correctness axis discussed in the server remediation.

## Note on TUniform modelling
The estimate approximates the bounded TUniform(46) distribution by a discrete
Gaussian of equal standard deviation. This is the standard estimator approach;
the bounded distribution's true tails are thinner, so the Gaussian model is a
conservative (lower-bound-leaning) proxy for security.
