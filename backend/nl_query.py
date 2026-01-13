import pandas as pd
import re

# Load explainable data
df = pd.read_csv('features/explainable_risk_assessment.csv')

def nl_query(query):
    """M9: Translate natural language to filters."""
    query_lower = query.lower()
    results = df.copy()
    
    # Keyword filters
    if 'high' in query_lower or 'critical' in query_lower:
        results = results[results['risk_level'] == 'HIGH']
    if 'usb' in query_lower:
        results = results[results['action'].str.contains('usb', case=False, na=False)]
    if any(user in query_lower for user in ['user1', 'user2', 'user3']):
        results = results[results['user'].str.lower().str.contains(re.search(r'user\d', query_lower).group(), na=False)]
    if 'login' in query_lower:
        results = results[results['action'].str.contains('login', case=False, na=False)]
    
    print(f"=== M9 NL QUERY: '{query}' ===")
    print(f"Found {len(results)} matching incidents:")
    print(results[['user', 'action', 'final_risk_score', 'risk_level', 'mitre_tag', 'explanation']].head(10))
    return results

if __name__ == "__main__":
    # Test queries
    nl_query("show high risk USB events")
    print("\n---")
    nl_query("high risk for user1")
    print("\n---")
    nl_query("all logins")
    print("M9 NATURAL LANGUAGE ✅")
