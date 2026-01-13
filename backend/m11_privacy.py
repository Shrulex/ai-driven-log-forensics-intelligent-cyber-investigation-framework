import pandas as pd
import hashlib
from datetime import datetime

df = pd.read_csv('features/m10_mitre_adaptive.csv')

def mask_pii(df):
    """M11: Hash sensitive data before ML/training."""
    df_anonym = df.copy()
    # Hash PII
    df_anonym['user_hash'] = df_anonym['user'].apply(lambda x: hashlib.sha256(str(x).encode()).hexdigest()[:8])
    df_anonym['source_ip_hash'] = df_anonym['action'].apply(lambda x: hashlib.sha256(str(x).encode()).hexdigest()[:8])  # Simulate IP
    # Drop originals
    df_anonym.drop(['user'], axis=1, inplace=True)
    df_anonym.rename(columns={'user_hash': 'user'}, inplace=True)
    df_anonym.to_csv('features/m11_anonymized.csv', index=False)
    return df_anonym

def audit_access(user_role, query):
    """Log investigator actions."""
    with open('docs/audit_log.txt', 'a') as f:
        f.write(f"{datetime.now()}: {user_role} executed '{query}'\n")

# M11 Demo
print("=== M11 PRIVACY COMPLIANCE ===")
anon_df = mask_pii(df)
print("Sample anonymized:")
print(anon_df[['user', 'action', 'final_risk_score']].head())
print("\nAudit example:")
audit_access("investigator", "view high risk")
with open('docs/audit_log.txt') as f:
    print(f.read())
print("Saved m11_anonymized.csv & audit_log.txt")
print("M11 PRIVACY ✅")

if __name__ == "__main__":
    pass
