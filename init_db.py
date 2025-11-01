import sqlite3
import logging

def init_database(db_path='nids.db'):
    """Initialize SQLite database with required tables."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create alerts table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            src_ip TEXT NOT NULL,
            dst_ip TEXT NOT NULL,
            protocol TEXT NOT NULL,
            src_port INTEGER,
            dst_port INTEGER,
            class_label TEXT NOT NULL,
            attack_type TEXT,
            confidence REAL NOT NULL,
            action_taken TEXT,
            UNIQUE(timestamp, src_ip, dst_ip, src_port, dst_port)
        )
    ''')
    
    # Create flows table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS flows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            flow_id TEXT UNIQUE NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            summary_features TEXT,
            raw_pkt BLOB
        )
    ''')
    
    # Create responses table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS responses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id INTEGER NOT NULL,
            response_type TEXT NOT NULL,
            status TEXT NOT NULL,
            initiated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (alert_id) REFERENCES alerts(id)
        )
    ''')
    
    # Create indexes for performance
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_src_ip ON alerts(src_ip)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_class ON alerts(class_label)')
    
    conn.commit()
    conn.close()
    
    logging.info(f"Database initialized at {db_path}")

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    init_database()
    print("Database initialized successfully!")