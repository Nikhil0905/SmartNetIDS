# Model trainer module for SmartNetIDS
"""
Train and evaluate an Isolation Forest model for SmartNetIDS.

Usage:
    python src/trainer.py

- Lists available datasets in datasets/.
- Supports optional label column for supervised evaluation.
- Saves model to data/models/isolation_forest.joblib.
"""

import os
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix
from ml_model import save_model


def list_datasets(dataset_dir='datasets'):
    """
    List all CSV files in the datasets directory and subdirectories.
    Returns a list of file paths.
    """
    csv_files = []
    for root, _, files in os.walk(dataset_dir):
        for file in files:
            if file.endswith('.csv'):
                csv_files.append(os.path.join(root, file))
    return csv_files


def load_dataset(csv_path, label_col=None):
    df = pd.read_csv(csv_path)
    if label_col and label_col in df.columns:
        X = df.drop(columns=[label_col])
        y = df[label_col]
    else:
        # Try to auto-detect a label column if any column is non-numeric or has only two unique values
        non_numeric_cols = [col for col in df.columns if not pd.api.types.is_numeric_dtype(df[col])]
        likely_label = None
        for col in non_numeric_cols:
            if df[col].nunique() <= 10:
                likely_label = col
                break
        if likely_label:
            print(f"[WARNING] Excluding likely label column '{likely_label}' from features.")
            X = df.drop(columns=[likely_label])
            y = df[likely_label]
        else:
            X = df.select_dtypes(include=[np.number])
            y = None
    return X, y, X.columns.tolist()


def preprocess_features(X):
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    return X_scaled, scaler


def train_isolation_forest(X, contamination=0.05):
    model = IsolationForest(contamination=contamination, random_state=42)  # type: ignore
    model.fit(X)
    return model


def evaluate_unsupervised(model, X, y_true):
    y_pred = model.predict(X)
    print("Confusion Matrix:")
    print(confusion_matrix(y_true, y_pred))
    print(f"Precision: {precision_score(y_true, y_pred, pos_label=-1):.3f}")
    print(f"Recall: {recall_score(y_true, y_pred, pos_label=-1):.3f}")
    print(f"F1 Score: {f1_score(y_true, y_pred, pos_label=-1):.3f}")


def train_and_save(csv_path, label_col=None, contamination=0.05):
    print(f"Loading dataset from {csv_path}")
    X, y, feature_names = load_dataset(csv_path, label_col)
    X_scaled, scaler = preprocess_features(X)
    model = train_isolation_forest(X_scaled, contamination)
    if y is not None:
        y_eval = y.copy().astype(str).str.strip().str.upper()
        y_eval = y_eval.map(lambda v: 1 if "BENIGN" in v else -1)
        evaluate_unsupervised(model, X_scaled, y_eval)
    save_model(model)
    print("Training complete. Model saved.")


if __name__ == "__main__":
    # Interactive dataset selection
    print("Available datasets in 'datasets/':")
    csv_files = list_datasets()
    if not csv_files:
        print("No CSV files found in datasets/. Please add datasets and try again.")
        exit(1)
    for idx, path in enumerate(csv_files):
        print(f"[{idx}] {path}")
    selected = input(f"Select dataset [0-{len(csv_files)-1}]: ")
    try:
        selected_idx = int(selected)
        assert 0 <= selected_idx < len(csv_files)
    except Exception:
        print("Invalid selection.")
        exit(1)
    csv_path = csv_files[selected_idx]
    # Optionally ask for label column
    label_col = input("Enter label column name (or leave blank for unsupervised): ").strip() or None
    contamination = input("Enter contamination (anomaly proportion, default 0.05): ").strip()
    contamination = float(contamination) if contamination else 0.05
    train_and_save(csv_path, label_col=label_col, contamination=contamination) 