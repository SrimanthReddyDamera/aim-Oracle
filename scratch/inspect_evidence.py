import sqlite3
import json

conn = sqlite3.connect("storage/oracle_investigation_fts.db")
cursor = conn.cursor()
cursor.execute("SELECT evidence_id, source_id, source_type, content, metadata FROM evidence_metadata LIMIT 5;")
for r in cursor.fetchall():
    print("--------------------------------------------------")
    print(f"ID: {r[0]}, Source: {r[1]}, Type: {r[2]}")
    print(f"Content: {r[3][:200]}...")
    print(f"Meta: {r[4]}")
