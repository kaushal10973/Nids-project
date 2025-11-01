import logging
import subprocess
import smtplib
from email.mime.text import MIMEText
from datetime import datetime
from nids.database import DatabaseManager

logger = logging.getLogger(__name__)

class ResponseEngine:
    """Automated threat response engine."""
    
    def __init__(self, config):
        self.config = config
        self.auto_block = config['response']['auto_block']
        self.notification_enabled = config['response']['notification_enabled']
        self.alert_threshold = config['response']['alert_threshold']
        self.email = config['response']['email']
        self.blocked_ips = set()
        self.db = DatabaseManager(config['database']['path'])
    
    def handle_threat(self, alert_id, src_ip, attack_type, confidence):
        """
        Handle detected threat with automated response.
        Returns action taken.
        """
        try:
            actions = []
            
            # Only act if confidence exceeds threshold
            if confidence < self.alert_threshold:
                return "monitored"
            
            # Determine severity
            severity = self.get_severity(attack_type, confidence)
            
            # Block IP for high severity attacks
            if self.auto_block and severity in ['high', 'critical']:
                if self.block_ip(src_ip):
                    actions.append('blocked')
                    logger.warning(f"Blocked IP {src_ip} for {attack_type} attack")
            
            # Send notification
            if self.notification_enabled:
                self.send_notification(src_ip, attack_type, confidence, severity)
                actions.append('notified')
            
            # Log response
            action_str = ','.join(actions) if actions else 'logged'
            self.db.store_response(alert_id, action_str, 'completed')
            
            return action_str
            
        except Exception as e:
            logger.error(f"Error handling threat: {e}")
            return "error"
    
    def get_severity(self, attack_type, confidence):
        """Determine attack severity."""
        severity_map = {
            'DoS': 'high',
            'U2R': 'critical',
            'R2L': 'high',
            'Probe': 'medium'
        }
        
        base_severity = severity_map.get(attack_type, 'low')
        
        # Upgrade severity for high confidence
        if confidence > 0.95:
            if base_severity == 'high':
                return 'critical'
            elif base_severity == 'medium':
                return 'high'
        
        return base_severity
    
    def block_ip(self, ip_address):
        """
        Block IP address using iptables (Linux).
        Note: Requires root privileges.
        """
        try:
            if ip_address in self.blocked_ips:
                logger.debug(f"IP {ip_address} already blocked")
                return True
            
            # Use iptables to block (Linux)
            cmd = ['iptables', '-A', 'INPUT', '-s', ip_address, '-j', 'DROP']
            
            # IMPORTANT: This is pseudocode - actual implementation requires privileges
            # Uncomment for production use with proper permissions
            # result = subprocess.run(cmd, capture_output=True, text=True)
            # if result.returncode == 0:
            #     self.blocked_ips.add(ip_address)
            #     logger.info(f"Successfully blocked IP: {ip_address}")
            #     return True
            
            # For demonstration (without actual blocking)
            self.blocked_ips.add(ip_address)
            logger.info(f"[DEMO] Would block IP: {ip_address}")
            return True
            
        except Exception as e:
            logger.error(f"Error blocking IP {ip_address}: {e}")
            return False
    
    def unblock_ip(self, ip_address):
        """Unblock previously blocked IP."""
        try:
            if ip_address not in self.blocked_ips:
                return True
            
            # cmd = ['iptables', '-D', 'INPUT', '-s', ip_address, '-j', 'DROP']
            # result = subprocess.run(cmd, capture_output=True, text=True)
            
            self.blocked_ips.remove(ip_address)
            logger.info(f"[DEMO] Would unblock IP: {ip_address}")
            return True
            
        except Exception as e:
            logger.error(f"Error unblocking IP {ip_address}: {e}")
            return False
    
    def send_notification(self, src_ip, attack_type, confidence, severity):
        """Send email notification about threat."""
        try:
            subject = f"[NIDS Alert] {severity.upper()}: {attack_type} attack detected"
            body = f"""
Network Intrusion Detection System Alert

Severity: {severity.upper()}
Attack Type: {attack_type}
Source IP: {src_ip}
Confidence: {confidence:.2%}
Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Automated Response: IP blocking {'enabled' if self.auto_block else 'disabled'}

This is an automated alert from your NIDS system.
            """
            
            # For demonstration - actual email sending would require SMTP configuration
            logger.info(f"[NOTIFICATION] {subject}")
            logger.debug(f"Notification body:\n{body}")
            
            # Uncomment for actual email sending:
            # msg = MIMEText(body)
            # msg['Subject'] = subject
            # msg['From'] = 'nids@example.com'
            # msg['To'] = self.email
            # 
            # with smtplib.SMTP('localhost') as server:
            #     server.send_message(msg)
            
            return True
            
        except Exception as e:
            logger.error(f"Error sending notification: {e}")
            return False
    
    def escalate(self, alert_id, reason):
        """Escalate alert for manual review."""
        logger.warning(f"Alert {alert_id} escalated: {reason}")
        self.db.store_response(alert_id, 'escalated', reason)

