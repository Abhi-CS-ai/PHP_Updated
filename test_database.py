import sqlite3
import os

# Ensure the 'database' folder exists
os.makedirs('database', exist_ok=True)

# Try connecting to the database
try:
    conn = sqlite3.connect('database/scan_results.db')
    c = conn.cursor()
    
    # Create a test table
    c.execute('CREATE TABLE IF NOT EXISTS test (id INTEGER PRIMARY KEY)')
    print("✅ Successfully connected to the database and created table 'test'")
    
    # Optional: Insert data to check write access
    c.execute('INSERT INTO test (id) VALUES (NULL)')
    conn.commit()
    print("🟢 Successfully inserted a test record")

except Exception as e:
    print("❌ Error:", str(e))

finally:
    conn.close()