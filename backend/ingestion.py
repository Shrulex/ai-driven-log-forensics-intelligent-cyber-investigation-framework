import pandas as pd
import sqlite3

def normalize_timestamps(df):
    """Convert timestamp to datetime."""
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    return df

def store_to_sqlite(df, db_path="data/raw_logs.sqlite"):
    """Store normalized logs to SQLite."""
    conn = sqlite3.connect(db_path)
    df.to_sql('raw_logs', conn, if_exists='append', index=False)
    conn.close()
    print(f"Stored to {db_path}")

def load_csv_log(file_path, db_path="data/raw_logs.sqlite"):
    """Full ingestion pipeline."""
    df = pd.read_csv(file_path)
    df = normalize_timestamps(df)
    store_to_sqlite(df, db_path)
    print(f"Loaded and normalized {len(df)} rows from {file_path}")
    return df

def query_raw_logs(db_path="data/raw_logs.sqlite"):
    """Query all stored logs."""
    conn = sqlite3.connect(db_path)
    df = pd.read_sql("SELECT * FROM raw_logs ORDER BY timestamp", conn)
    conn.close()
    return df

def get_timeline(user=None, source_ip=None):
    """M2: Get unified timeline with filters."""
    conn = sqlite3.connect("data/raw_logs.sqlite")
    query = "SELECT * FROM raw_logs WHERE 1=1"
    params = []
    
    if user:
        query += " AND user = ?"
        params.append(user)
    if source_ip:
        query += " AND source_ip = ?"
        params.append(source_ip)
    
    query += " ORDER BY timestamp"
    
    df = pd.read_sql(query, conn, params=params)
    conn.close()
    return df

if __name__ == "__main__":
    sample_path = "data/sample_windows_events.csv"
    try:
        # M1: Ingest
        df = load_csv_log(sample_path)
        print("\nRaw data:")
        print(df.head())
        
        # M1: Query
        print("\nAll logs from SQLite:")
        all_logs = query_raw_logs()
        print(all_logs)
        
        # M2: Timeline examples
        print("\n=== M2 TIMELINE ===")
        print("Full timeline:")
        full_timeline = get_timeline()
        print(full_timeline)
        
        print("\nTimeline for user1:")
        user1_timeline = get_timeline(user="user1")
        print(user1_timeline)
        
        print("\nTimeline for IP 192.168.1.100:")
        ip_timeline = get_timeline(source_ip="192.168.1.100")
        print(ip_timeline)
        
    except FileNotFoundError:
        print("Create data/sample_windows_events.csv first")
    except Exception as e:
        print(f"Error: {e}")


# import pandas as pd
# import sqlite3

# def normalize_timestamps(df):
#     """Convert timestamp to datetime."""
#     df['timestamp'] = pd.to_datetime(df['timestamp'])
#     return df

# def store_to_sqlite(df, db_path="data/raw_logs.sqlite"):
#     """Store normalized logs to SQLite."""
#     conn = sqlite3.connect(db_path)
#     df.to_sql('raw_logs', conn, if_exists='append', index=False)
#     conn.close()
#     print(f"Stored to {db_path}")

# def load_csv_log(file_path, db_path="data/raw_logs.sqlite"):
#     """Full ingestion pipeline."""
#     df = pd.read_csv(file_path)
#     df = normalize_timestamps(df)
#     store_to_sqlite(df, db_path)
#     print(f"Loaded and normalized {len(df)} rows from {file_path}")
#     return df

# def query_raw_logs(db_path="data/raw_logs.sqlite"):
#     """Query stored logs."""
#     conn = sqlite3.connect(db_path)
#     df = pd.read_sql("SELECT * FROM raw_logs ORDER BY timestamp", conn)
#     conn.close()
#     return df

# def get_timeline(user=None, source_ip=None):
#     """Get unified timeline with optional filters."""
#     conn = sqlite3.connect("data/raw_logs.sqlite")
#     query = "SELECT * FROM raw_logs WHERE 1=1"
#     params = []
    
#     if user:
#         query += " AND user = ?"
#         params.append(user)
#     if source_ip:
#         query += " AND source_ip = ?"
#         params.append(source_ip)
    
#     query += " ORDER BY timestamp"
    
#     df = pd.read_sql(query, conn, params=params)
#     conn.close()
#     return df

# if __name__ == "__main__":
#     sample_path = "data/sample_windows_events.csv"
#     try:
#         df = load_csv_log(sample_path)
#         print("\nRaw data:")
#         print(df.head())
        
#         print("\nQuery test from SQLite:")
#         timeline = query_raw_logs()
#         print(timeline)
#     except FileNotFoundError:
#         print("Sample file not found - create data/sample_windows_events.csv")
#     except Exception as e:
#         print(f"Error: {e}")
