import pandas as pd
import numpy as np
import sys
import os

# Bulletproof path setup
project_root = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..')
sys.path.insert(0, project_root)

# Direct imports (no backend. prefix)
from ingestion import get_timeline
from features import engineer_features

import pickle

# MITRE ATT&CK mapping [file:1]
MITRE_MAP = {
    'login': 'TA0001 - Initial Access',
    'file_access': 'TA0002 - Execution', 
    'usb_insert': 'T1201 - Exploitation for Client Execution',
    'privilege_escalation': 'TA0004 - Privilege Escalation'
}

def calculate_risk_score(timeline):
    """M7: 0-100 risk score from all modules."""
    features_df = engineer_features(timeline)
    
    # Normalize ML anomaly (if exists, else 0)
    ml_score = np.abs(features_df.get('anomaly_score', 0)) / 0.2
    ml_score = np.clip(ml_score, 0, 1)
    
    # Temporal risk (event density)
    temporal_risk = features_df['events_per_user'] / features_df['events_per_user'].max()
    
    # Suspicious action multiplier
    suspicious_mult = 1 + (features_df['is_suspicious_action'] * 0.5)
    
    # Final risk calculation (0-100)
    risk_score = (ml_score * 30 + temporal_risk * 20 + suspicious_mult * 20) * 2
    risk_score = np.clip(risk_score, 0, 100)
    
    results = features_df.copy()
    results['ml_contribution'] = ml_score * 30
    results['temporal_contribution'] = temporal_risk * 20
    results['mitre_multiplier'] = suspicious_mult
    results['mitre_tag'] = results['action'].map(MITRE_MAP).fillna('Recon')
    results['final_risk_score'] = risk_score.round(1)
    results['risk_level'] = pd.cut(results['final_risk_score'], 
                                   bins=[0, 30, 70, 100], 
                                   labels=['LOW', 'MEDIUM', 'HIGH'])
    
    print("=== M7 RISK SCORING ===")
    print(results.nlargest(5, 'final_risk_score')[['user', 'action', 'mitre_tag', 'final_risk_score', 'risk_level']])
    
    results.to_csv("features/risk_assessment.csv", index=False)
    print(f"Saved risk_assessment.csv ({len(results)} events)")
    
    high_risk = results[results['risk_level'] == 'HIGH']
    print(f"\nHIGH risk incidents: {len(high_risk)}")
    
    return results

if __name__ == "__main__":
    timeline = get_timeline()
    results = calculate_risk_score(timeline)
    
    print("\nM7 RISK SCORING ✅")
