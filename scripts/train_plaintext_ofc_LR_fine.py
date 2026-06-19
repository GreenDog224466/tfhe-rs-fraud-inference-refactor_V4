import argparse
import pandas as pd
import numpy as np
import time
import os
import json
import joblib
from datetime import datetime

from sklearn.linear_model import LogisticRegression
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.model_selection import GridSearchCV, StratifiedKFold, train_test_split
from sklearn.metrics import (
    average_precision_score, roc_auc_score, precision_recall_curve
)

# ------------------------------------------------------------------------------
# 1. CONFIGURATION
# ------------------------------------------------------------------------------
def parse_args():
    parser = argparse.ArgumentParser(description="LR Fine-Tuning Script")
    parser.add_argument("--data_path", type=str, default="/mnt/pv/data/train.parquet")
    parser.add_argument("--output_base", type=str, default="/mnt/pv/artifacts/LR-PLTT/fine")
    return parser.parse_args()

def load_data(path):
    print(f"[INFO] Loading data from {path}...")
    df = pd.read_parquet(path)
    if 'isFraud' not in df.columns:
        raise ValueError("Column 'isFraud' not found.")
    X = df.drop(columns=['isFraud'])
    y = df['isFraud']
    print(f"[INFO] Full Data Shape: {X.shape}, Target Distribution:\n{y.value_counts(normalize=True)}")
    return X, y

def create_pipeline(random_state=42):
    # LR is sensitive to scale, so we MUST scale the transaction amount
    preprocessor = ColumnTransformer(
        transformers=[
            ('scale_amount', StandardScaler(), ['TransactionAmt'])
        ],
        remainder='passthrough'
    )
    # Based on coarse run, lbfgs with l2 penalty is the winner.
    # We increase max_iter for safety during fine-tuning.
    clf = LogisticRegression(
        solver='lbfgs',
        penalty='l2',
        random_state=random_state,
        max_iter=2000,
        n_jobs=1
    )

    pipeline = Pipeline([
        ('pre', preprocessor),
        ('clf', clf)
    ])
    return pipeline

def main():
    args = parse_args()
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    output_dir = os.path.join(args.output_base, timestamp)
    os.makedirs(output_dir, exist_ok=True)

    X, y = load_data(args.data_path)

    # --- Create a hold-out test set for final evaluation ---
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"[INFO] Split data: Train={X_train.shape}, Test={X_test.shape}")

    pipeline = create_pipeline()

    # --------------------------------------------------------------------------
    # FINE-TUNING GRID (Grid Search)
    # --------------------------------------------------------------------------
    # Coarse search found C=10 and class_weight=None were best.
    # We now search in a tight grid around C=10.
    param_grid = {
        'clf__C': [5, 8, 10, 12, 15, 20],
        'clf__class_weight': [None] # Coarse run preferred None
    }

    # Use more CV folds for robust fine-tuning
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

    # 64-Core Optimization: GridSearchCV benefits greatly from n_jobs
    search = GridSearchCV(
        estimator=pipeline,
        param_grid=param_grid,
        scoring='average_precision',
        cv=cv,
        verbose=2,
        n_jobs=60, # AGGRESSIVE PARALLELISM
    )

    print(f"[INFO] Starting Grid Search (Fine-Tuning) on 64 Cores...")
    start_time = time.time()
    search.fit(X_train, y_train)
    elapsed = time.time() - start_time

    print(f"\n[INFO] Search complete in {elapsed:.2f} seconds.")
    print(f"[INFO] Best Params: {search.best_params_}")

    # --------------------------------------------------------------------------
    # SAVING ARTIFACTS
    # --------------------------------------------------------------------------
    best_model = search.best_estimator_

    # --- Final Evaluation on Hold-Out Test Set ---
    y_prob = best_model.predict_proba(X_test)[:, 1]
    pr_auc = average_precision_score(y_test, y_prob)
    roc_auc = roc_auc_score(y_test, y_prob)

    metrics = {
        "run_id": timestamp,
        "mode": "fine",
        "model": "LogisticRegression",
        "PR-AUC": pr_auc,
        "ROC-AUC": roc_auc,
        "best_params": search.best_params_,
        "training_time_sec": elapsed
    }

    with open(os.path.join(output_dir, "LR_metrics.json"), "w") as f:
        json.dump(metrics, f, indent=2)

    pd.DataFrame(search.cv_results_).to_csv(os.path.join(output_dir, "LR_cv_results.csv"), index=False)
    joblib.dump(best_model, os.path.join(output_dir, "LR_best.joblib"))

    # --- FHE Export: Weights & Bias (CRITICAL) ---
    lr_model = best_model.named_steps['clf']
    preprocessor = best_model.named_steps['pre']
    
    # Get feature names in the correct order after ColumnTransformer
    feature_names = preprocessor.get_feature_names_out()

    weights_df = pd.DataFrame(lr_model.coef_, columns=feature_names)
    weights_df.to_csv(os.path.join(output_dir, "weights.csv"), index=False)

    bias_df = pd.DataFrame(lr_model.intercept_, columns=["bias"])
    bias_df.to_csv(os.path.join(output_dir, "bias.csv"), index=False)

    print(f"\n[SUCCESS] All artifacts, including weights.csv and bias.csv, saved to {output_dir}")
    print(f"Final PR-AUC on test set: {pr_auc:.4f}")

if __name__ == "__main__":
    main()
