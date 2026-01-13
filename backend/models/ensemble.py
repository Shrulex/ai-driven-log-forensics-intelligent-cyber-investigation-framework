import pandas as pd
import numpy as np
import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sklearn.ensemble import IsolationForest
import joblib
from features import engineer_features
from ingestion import get_timeline

def rule_based_anomalies(features_df):
    """Simple statistical rules (non-ML)."""
    scores = np.zeros(len(features_df))
    
    # Rule 1: Login after 8PM
    late_logins = (features_df['login_hour'] > 20) & (features_df['action'] == 'login')
    scores[late_logins] += 0.3
    
    # Rule 2: Failed login + suspicious action
    failed_suspicious = (features_df['failed_logins'] > 0) & (features_df['is_suspicious_action'] == 1)
    scores[failed_suspicious] += 0.4
    
    # Rule 3: High event burst (>5 events/hour for user)
    high_burst = features_df['events_per_user'] > 5
    scores[high_burst] += 0.2
    
    return scores

def ensemble_detect():
    """M5: Combine ML + Rules."""
    timeline = get_timeline()
    features_df = engineer_features(timeline)
    
    # ML model
    model = IsolationForest(contamination=0.1, random_state=42)
    feature_cols = ['login_hour', 'events_per_user', 'failed_logins', 'is_suspicious_action', 'ip_change']
    X = features_df[feature_cols].values
    model.fit(X)
    
    ml_scores = model.decision_function(X) * -1  # Invert (higher = more anomalous)
    
    # Rule scores
    rule_scores = rule_based_anomalies(features_df)
    
    # Ensemble: average
    ensemble_scores = (ml_scores + rule_scores) / 2
    
    results = features_df.copy()
    results['ml_score'] = ml_scores
    results['rule_score'] = rule_scores
    results['ensemble_score'] = ensemble_scores
    results['final_risk'] = pd.cut(ensemble_scores, bins=3, labels=['LOW', 'MEDIUM', 'HIGH'])
    
    results.to_csv("features/ensemble_results.csv", index=False)
    
    print("=== M5 ENSEMBLE ANOMALY ===")
    print(results[['user', 'action', 'ml_score', 'rule_score', 'ensemble_score', 'final_risk']])
    print("Saved ensemble_results.csv")
    
    return results

if __name__ == "__main__":
    ensemble_detect()
