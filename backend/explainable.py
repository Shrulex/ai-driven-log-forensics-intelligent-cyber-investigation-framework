import pandas as pd
import numpy as np
import os

# Load prior risk results
risk_df = pd.read_csv('features/risk_assessment.csv')

def explain_incident(row):
    """Simple explainable AI: top reasons for risk using M7 data."""
    explanations = []
    # High risk score
    if row['final_risk_score'] > 80:
        explanations.append(f"Extreme risk score ({row['final_risk_score']:.1f})")
    # Suspicious actions
    if 'usb' in str(row['action']).lower():
        explanations.append("USB insert (MITRE T1201: Exploitation)")
    elif 'login' in str(row['action']).lower():
        explanations.append("Repeated logins flagged")
    # MITRE high-impact
    if 'T1201' in str(row['mitre_tag']):
        explanations.append("Client execution technique")
    # HIGH level
    if row['risk_level'] == 'HIGH':
        explanations.append("Classified as critical incident")
    
    top_reasons = explanations[:3]  # Top 3
    return '; '.join(top_reasons) if top_reasons else "Routine activity"

# Add explanations
risk_df['explanation'] = risk_df.apply(explain_incident, axis=1)
risk_df.to_csv('features/explainable_risk_assessment.csv', index=False)

print("=== M8 EXPLAINABLE AI ===")
high_risks = risk_df[risk_df['risk_level'] == 'HIGH'].head(5)
print(high_risks[['user', 'action', 'final_risk_score', 'risk_level', 'mitre_tag', 'explanation']])
print(f"Saved explainable_risk_assessment.csv ({len(risk_df)} events)")
print("HIGH risk incidents with explanations:", len(high_risks))
print("M8 EXPLAINABLE AI ✅")

if __name__ == "__main__":
    pass
