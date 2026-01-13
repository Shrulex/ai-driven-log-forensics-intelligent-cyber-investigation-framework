import pandas as pd
import numpy as np
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sklearn.ensemble import IsolationForest
import joblib
from features import engineer_features
from ingestion import get_timeline

def train_baseline_model():
    timeline = get_timeline()
    features_df = engineer_features(timeline)
    
    feature_cols = ['login_hour', 'events_per_user', 'failed_logins', 
                   'is_suspicious_action', 'ip_change']
    X = features_df[feature_cols].values
    
    model = IsolationForest(contamination=0.1, random_state=42)
    model.fit(X)
    
    joblib.dump(model, "models/baseline_isolation_forest.pkl")
    print("M4: Trained Isolation Forest baseline")
    print(f"Features shape: {X.shape}")
    return model

def score_anomalies(model, features_df):
    """Score new data for anomalies."""
    feature_cols = ['login_hour', 'events_per_user', 'failed_logins', 
                   'is_suspicious_action', 'ip_change']
    X = features_df[feature_cols].values
    anomaly_scores = model.decision_function(X)
    anomaly_labels = model.predict(X)  # -1 = anomaly, 1 = normal
    
    results = features_df.copy()
    results['anomaly_score'] = anomaly_scores
    results['is_anomaly'] = anomaly_labels
    
    return results

if __name__ == "__main__":
    # M4: Train + test
    print("=== M4 BEHAVIORAL BASELINE ===")
    model = train_baseline_model()
    
    # Test on same data
    timeline = get_timeline()
    features_df = engineer_features(timeline)
    scored = score_anomalies(model, features_df)
    
    print("\nAnomaly detection results:")
    print(scored[['user', 'action', 'anomaly_score', 'is_anomaly']].head(10))
    
    # Save scored data
    scored.to_csv("features/scored_anomalies.csv", index=False)
    print("Saved scored_anomalies.csv")
