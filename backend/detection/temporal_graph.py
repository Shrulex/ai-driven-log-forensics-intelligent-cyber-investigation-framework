import pandas as pd
import numpy as np
import sys
import os
import networkx as nx

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)

# Import functions
from backend.ingestion import get_timeline
from backend.features import engineer_features

def temporal_patterns(timeline):
    """M6.1: Simple temporal analysis."""
    # Ensure timestamp is datetime
    timeline = timeline.copy()
    timeline['timestamp'] = pd.to_datetime(timeline['timestamp'])
    timeline = timeline.sort_values('timestamp')
    
    # Create 1-hour windows
    timeline['window'] = timeline['timestamp'].dt.floor('1H')
    
    sequences = []
    for (user, window), group in timeline.groupby(['user', 'window']):
        seq = group['action'].tolist()
        sequences.append({
            'user': user,
            'window': window,
            'sequence': ' → '.join(seq),
            'length': len(seq)
        })
    
    # Suspicious sequences
    suspicious = [s for s in sequences if s['length'] >= 2]
    
    print("=== M6.1 TEMPORAL PATTERNS ===")
    for s in suspicious:
        print(f"{s['user']} {s['window']}: {s['sequence']} (len {s['length']})")
    
    return suspicious

def build_event_graph(timeline):
    """M6.2: User-Action-IP graph."""
    G = nx.Graph()
    
    for _, row in timeline.iterrows():
        G.add_node(row['user'], type='user')
        G.add_node(row['action'], type='action')
        G.add_node(row['source_ip'], type='ip')
        G.add_edge(row['user'], row['action'])
        G.add_edge(row['action'], row['source_ip'])
    
    print("\n=== M6.2 GRAPH ANALYSIS ===")
    print(f"Nodes: {G.number_of_nodes()}, Edges: {G.number_of_edges()}")
    
    # Suspicious: high degree centrality
    centrality = nx.degree_centrality(G)
    suspicious = {n: score for n, score in centrality.items() if score > 0.2}
    
    print("High centrality (suspicious):", suspicious)
    
    # Save graph (fixed)
    import pickle
    os.makedirs("models", exist_ok=True)
    with open("models/event_graph.pkl", "wb") as f:
        pickle.dump(G, f)
    print("Graph saved as event_graph.pkl")
    
    return G

if __name__ == "__main__":
    print("=== M6 TEMPORAL + GRAPH ===")
    timeline = get_timeline()
    
    temporal_suspicious = temporal_patterns(timeline)
    graph = build_event_graph(timeline)
    
    print("\nM6 ✅ COMPLETE")
