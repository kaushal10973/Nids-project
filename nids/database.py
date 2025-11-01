
import sqlite3
import logging
import json
from datetime import datetime
from contextlib import contextmanager

logger = logging.getLogger(__name__)

class DatabaseManager:
    """Manage SQLite database operations for NIDS."""
    
    def __init__(self, db_path='nids.db'):
        self.db_path = db_path
        self.init_db()
    
    def init_db(self):
        """Initialize database if it doesn't exist."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = cursor.fetchall()
                if not tables:
                    logger.warning("Database not initialized. Run init_db.py first.")
        except Exception as e:
            logger.error(f"Database initialization check failed: {e}")
    
    @contextmanager
    def get_connection(self):
        """Context manager for database connections."""
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            logger.error(f"Database error: {e}")
            raise
        finally:
            conn.close()
    
    def store_alert(self, src_ip, dst_ip, protocol, src_port, dst_port,
                    class_label, attack_type, confidence, action_taken=None):
        """Store alert in database."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO alerts 
                    (src_ip, dst_ip, protocol, src_port, dst_port, 
                     class_label, attack_type, confidence, action_taken)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (src_ip, dst_ip, protocol, src_port, dst_port,
                      class_label, attack_type, confidence, action_taken))
                
                alert_id = cursor.lastrowid
                logger.debug(f"Stored alert {alert_id}")
                return alert_id
                
        except sqlite3.IntegrityError:
            # Duplicate alert within same timestamp
            logger.debug("Duplicate alert detected, skipping")
            return None
        except Exception as e:
            logger.error(f"Error storing alert: {e}")
            return None
    
    def update_alert_action(self, alert_id, action):
        """Update action taken for an alert."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE alerts SET action_taken = ? WHERE id = ?
                ''', (action, alert_id))
                logger.debug(f"Updated alert {alert_id} with action: {action}")
        except Exception as e:
            logger.error(f"Error updating alert action: {e}")
    
    def store_flow(self, flow_id, summary, raw_pkt):
        """Store flow data."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT OR IGNORE INTO flows (flow_id, summary_features, raw_pkt)
                    VALUES (?, ?, ?)
                ''', (flow_id, summary, raw_pkt))
        except Exception as e:
            logger.error(f"Error storing flow: {e}")
    
    def store_response(self, alert_id, response_type, status):
        """Store response action."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO responses (alert_id, response_type, status)
                    VALUES (?, ?, ?)
                ''', (alert_id, response_type, status))
                return cursor.lastrowid
        except Exception as e:
            logger.error(f"Error storing response: {e}")
            return None
    
    def query_logs(self, filters=None, limit=100, offset=0):
        """Query alert logs with optional filters."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                query = "SELECT * FROM alerts WHERE 1=1"
                params = []
                
                if filters:
                    if filters.get('src_ip'):
                        query += " AND src_ip = ?"
                        params.append(filters['src_ip'])
                    
                    if filters.get('dst_ip'):
                        query += " AND dst_ip = ?"
                        params.append(filters['dst_ip'])
                    
                    if filters.get('class_label'):
                        query += " AND class_label = ?"
                        params.append(filters['class_label'])
                    
                    if filters.get('start_date'):
                        query += " AND timestamp >= ?"
                        params.append(filters['start_date'])
                    
                    if filters.get('end_date'):
                        query += " AND timestamp <= ?"
                        params.append(filters['end_date'])
                    
                    if filters.get('min_confidence'):
                        query += " AND confidence >= ?"
                        params.append(filters['min_confidence'])
                
                query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
                params.extend([limit, offset])
                
                cursor.execute(query, params)
                rows = cursor.fetchall()
                
                return [dict(row) for row in rows]
                
        except Exception as e:
            logger.error(f"Error querying logs: {e}")
            return []
    
    def get_statistics(self):
        """Get summary statistics."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Total alerts
                cursor.execute("SELECT COUNT(*) as total FROM alerts")
                total = cursor.fetchone()['total']
                
                # Alerts by class
                cursor.execute('''
                    SELECT class_label, COUNT(*) as count 
                    FROM alerts 
                    GROUP BY class_label
                ''')
                by_class = {row['class_label']: row['count'] for row in cursor.fetchall()}
                
                # Recent alerts (last hour)
                cursor.execute('''
                    SELECT COUNT(*) as recent 
                    FROM alerts 
                    WHERE timestamp >= datetime('now', '-1 hour')
                ''')
                recent = cursor.fetchone()['recent']
                
                # Top attacking IPs
                cursor.execute('''
                    SELECT src_ip, COUNT(*) as count 
                    FROM alerts 
                    WHERE class_label != 'Normal'
                    GROUP BY src_ip 
                    ORDER BY count DESC 
                    LIMIT 10
                ''')
                top_ips = [dict(row) for row in cursor.fetchall()]
                
                return {
                    'total_alerts': total,
                    'by_class': by_class,
                    'recent_alerts': recent,
                    'top_attacking_ips': top_ips
                }
                
        except Exception as e:
            logger.error(f"Error getting statistics: {e}")
            return {}
    
    def get_recent_alerts(self, limit=50):
        """Get most recent alerts."""
        return self.query_logs(limit=limit)