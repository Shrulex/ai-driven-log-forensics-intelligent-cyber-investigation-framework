import pandas as pd
import numpy as np

def engineer_features(df):
    """M3: Create AI-ready features from timeline."""
    features = df.copy()
    
    # Feature 1: Hour of day (normal logins are 9-5)
    features['login_hour'] = pd.to_datetime(features['timestamp']).dt.hour
    
    # Feature 2: Event frequency per user (sudden bursts suspicious)
    features['events_per_user'] = features.groupby('user')['user'].transform('count')
    
    # Feature 3: Failed login count per user
    features['failed_logins'] = features.apply(lambda row: 1 if row['action'] == 'login' and row['status'] == 'fail' else 0, axis=1)
    features['failed_logins'] = features.groupby('user')['failed_logins'].transform('cumsum')
    
    # Feature 4: Suspicious actions (1=suspicious, 0=normal)
    suspicious_actions = ['usb_insert', 'privilege_escalation']
    features['is_suspicious_action'] = features['action'].isin(suspicious_actions).astype(int)
    
    # Feature 5: IP change frequency (same user, different IPs = suspicious)
    features['ip_change'] = features.groupby('user')['source_ip'].transform(lambda x: x.ne(x.shift()).cumsum())
    
    return features[['timestamp', 'user', 'action', 'source_ip', 'status', 'login_hour', 'events_per_user', 'failed_logins', 'is_suspicious_action', 'ip_change']]

if __name__ == "__main__":
    # Import from same folder
    from ingestion import get_timeline
    timeline = get_timeline()
    
    features_df = engineer_features(timeline)
    print("=== M3 FEATURES ===")
    print(features_df[['user', 'action', 'login_hour', 'is_suspicious_action', 'ip_change']].head())
    
    # Save
    features_df.to_csv("features/timeline_features.csv", index=False)
    print("Saved features/timeline_features.csv")
