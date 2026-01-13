import yaml
import pandas as pd
from collections import Counter

# Load MITRE config
with open('docs/mitre_mapping.yml', 'r') as f:
    mitre_map = yaml.safe_load(f)

# Load data
df = pd.read_csv('features/explainable_risk_assessment.csv')

def apply_mitre_enhanced(df):
    """M10: Enhanced MITRE + cross-case pattern boost."""
    # Apply mapping
    df['mitre_tag'] = df['action'].map(mitre_map).fillna('Unknown')
    
    # Cross-case: Boost repeats
    pattern_counts = Counter(df[df['risk_level']=='HIGH']['action'])
    for action, count in pattern_counts.items():
        if count > 2:  # Repeat offender
            df.loc[df['action']==action, 'final_risk_score'] *= 1.2
            df['mitre_tag'] = df['mitre_tag'].where(df['action']!=action, f"{mitre_map.get(action, 'Unknown')} (Repeat x{count})")
    
    df['risk_level'] = pd.cut(df['final_risk_score'], bins=[0,30,70,100], labels=['LOW','MEDIUM','HIGH'])
    df.to_csv('features/m10_mitre_adaptive.csv', index=False)
    
    print("=== M10 MITRE & ADAPTIVE ===")
    print("Pattern boosts:", dict(pattern_counts))
    print(df.nlargest(5, 'final_risk_score')[['user','action','final_risk_score','mitre_tag']])
    print("Saved m10_mitre_adaptive.csv")
    print("M10 ADAPTIVE LEARNING ✅")

if __name__ == "__main__":
    apply_mitre_enhanced(df)
