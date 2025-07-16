# ML model module for SmartNetIDS
# Handles loading, saving, and inference for ML models (Isolation Forest)

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
import os

MODEL_PATH = os.path.join('data', 'models', 'isolation_forest.joblib')


def load_model(model_path=MODEL_PATH):
    """
    Load a trained ML model from disk.
    Returns the loaded model, or None if not found.
    """
    try:
        model = joblib.load(model_path)
        print(f"Model loaded from {model_path}")
        return model
    except FileNotFoundError:
        print(f"Model file not found at {model_path}")
        return None


def save_model(model, model_path=MODEL_PATH):
    """
    Save a trained ML model to disk.
    """
    joblib.dump(model, model_path)
    print(f"Model saved to {model_path}")


def predict(model, features):
    """
    Perform inference using the loaded model.
    :param model: Trained Isolation Forest model
    :param features: 1D or 2D array-like of features
    :return: Prediction (1 = normal, -1 = anomaly)
    """
    features = np.array(features)
    if features.ndim == 1:
        features = features.reshape(1, -1)
    return model.predict(features)


if __name__ == "__main__":
    # Test harness: Train a dummy Isolation Forest, save, load, and predict
    print("Testing ML model module with dummy data:")
    X_train = np.random.normal(0, 1, (100, 5))
    X_test = np.random.normal(0, 1, (2, 5))
    # Inject an outlier
    X_test[1] = [10, 10, 10, 10, 10]
    model = IsolationForest(contamination=0.1, random_state=42)  # type: ignore
    model.fit(X_train)
    save_model(model)
    loaded_model = load_model()
    preds = predict(loaded_model, X_test)
    print(f"Test data predictions: {preds}") 