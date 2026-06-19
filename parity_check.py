import pandas as pd, json
df = pd.read_parquet("data/processed/scaled_features.parquet")
row = df.iloc[0]
w = json.load(open("data/LR_weights_quantized.json"))
weights = w["weights"]
raw = sum(int(row[i]) * int(weights[i]) for i in range(len(weights)))
print("plaintext dot product (raw):", raw)
print("logit:", raw / 1_000_000)
