import pandas as pd
import numpy as np

# ---------------------------------------------------------------------------
# BRIDGE: plaintext features  ->  HE-ready integer features
#
# This script converts the cleaned, normalised plaintext dataset into the
# bounded-integer format the FHE encrypt client requires.
#
# Three steps:
#   1. SCALE   - multiply normalised floats by S (matches WEIGHT_SCALE)
#   2. CLIP    - clamp to the cryptographic bound +/- BOUND so the encrypt
#                file's bounds check passes and FheInt32 accumulation cannot
#                overflow
#   3. CONVERT - cast to int64 so the Rust encrypt client can read every
#                column with .i64()
#
# NOTE ON CLIPPING: clipping is a data-owner (client-side) decision. Here it
# stands in for that preprocessing step. Measured clip rate on the full IEEE
# dataset is ~1.7% of values (drops to ~1.5% if TransactionID is excluded).
# The data owner should keep the clip rate low and verify clipped values are
# not in predictively meaningful features.
# ---------------------------------------------------------------------------

S = 1000        # scale factor (must equal WEIGHT_SCALE used in weight quantisation)
BOUND = 8192    # cryptographic bound enforced by the encrypt client

INPUT_PATH = "data/processed/train.parquet"
OUTPUT_PATH = "data/processed/scaled_features.parquet"

# 1. Load the cleaned plaintext dataset
df = pd.read_parquet(INPUT_PATH)
print(f"Loaded {INPUT_PATH}: {df.shape[0]} rows, {df.shape[1]} columns")

# 2. Drop the target column (HE only needs features, never the label)
if "isFraud" in df.columns:
    df = df.drop(columns=["isFraud"])
    print("Dropped label column 'isFraud'")

# 3. SCALE: multiply every value by S
df = df * S

# 4. CLIP: clamp to +/- BOUND
total = df.size
n_clipped = int((df.values > BOUND).sum() + (df.values < -BOUND).sum())
df = df.clip(lower=-BOUND, upper=BOUND)
print(f"Clipped {n_clipped:,} of {total:,} values ({100 * n_clipped / total:.3f}%) to +/-{BOUND}")

# 5. CONVERT: cast every column to int64 for the Rust encrypt client
df = df.astype(np.int64)

# 6. Save HE-ready dataset
df.to_parquet(OUTPUT_PATH)
print(f"Saved HE-ready features to {OUTPUT_PATH}: {df.shape[0]} rows, {df.shape[1]} columns")
print(f"min: {df.values.min()}  max: {df.values.max()}")
