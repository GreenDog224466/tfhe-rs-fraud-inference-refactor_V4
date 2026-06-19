import os
import glob
import joblib
import json
import numpy as np
from sklearn.pipeline import Pipeline

# Config
SCALE_FACTOR = 1000
base_dir = "/mnt/pv/artifacts/LR-PLTT/fine/"
output_path = "/mnt/pv/data/LR_weights_quantized.json"  # <--- SPECIFIC NAME

def get_latest_model_path(base_dir):
    subdirs = [d for d in glob.glob(os.path.join(base_dir, "*")) if os.path.isdir(d)]
    if not subdirs: return None
    latest_dir = sorted(subdirs)[-1]
    return os.path.join(latest_dir, "LR_best.joblib")

def unwrap_model(model):
    print(f"[INFO] Loaded object type: {type(model).__name__}")
    if hasattr(model, "best_estimator_"):
        model = model.best_estimator_
    if hasattr(model, "steps"):
        model = model.steps[-1][1]
    return model

def main():
    model_path = get_latest_model_path(base_dir)
    if not model_path:
        print("ERROR: No model found.")
        exit(1)

    print(f"[INFO] Loading {model_path}...")
    wrapper = joblib.load(model_path)
    model = unwrap_model(wrapper)

    if not hasattr(model, "coef_"):
        print(f"ERROR: Model {type(model).__name__} has no .coef_")
        exit(1)

    print("[INFO] Quantizing weights...")
    weights = model.coef_.flatten()
    bias = model.intercept_[0]
    
    q_weights = [int(w * SCALE_FACTOR) for w in weights]
    q_bias = int(bias * SCALE_FACTOR)

    output = {
        "model_type": "LogisticRegression",
        "scale_factor": SCALE_FACTOR,
        "bias": q_bias,
        "weights": q_weights,
        "feature_count": len(q_weights)
    }

    with open(output_path, 'w') as f:
        json.dump(output, f)

    print(f"[SUCCESS] Saved to {output_path}")

if __name__ == "__main__":
    main()
