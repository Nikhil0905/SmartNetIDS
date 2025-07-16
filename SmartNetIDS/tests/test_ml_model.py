# Unit tests for ml_model.py
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import numpy as np
from sklearn.ensemble import IsolationForest
from src.ml_model import save_model, load_model, predict
import tempfile


def test_save_load_predict():
    # Create dummy data and model
    X = np.random.normal(0, 1, (10, 4))
    model = IsolationForest(contamination=0.2, random_state=42)  # type: ignore
    model.fit(X)
    # Save model
    with tempfile.NamedTemporaryFile(delete=False, suffix='.joblib') as tmp:
        save_model(model, tmp.name)
        # Load model
        loaded = load_model(tmp.name)
        # Predict
        preds = predict(loaded, X)
        assert len(preds) == X.shape[0]
        assert set(preds).issubset({1, -1})
    os.remove(tmp.name) 