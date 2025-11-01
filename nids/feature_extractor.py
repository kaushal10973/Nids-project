import logging
from scapy.all import IP, TCP, UDP, ICMP, Raw
import time
import numpy as np

logger = logging.getLogger(__name__)

class FeatureExtractor:
    """Extract ML features from network packets."""
    
    def __init__(self):
        self.protocol_map = {'TCP': 6, 'UDP': 17, 'ICMP': 1, 'OTHER': 255}
        self.flag_map = {'F': 0x01, 'S': 0x02, 'R': 0x04, 'P': 0x08, 'A': 0x10, 'U': 0x20}
    
    def extract(self, pkt, flow_id, flows_dict):
        """
        Extract features from packet suitable for NSL-KDD trained models.
        Returns feature vector as numpy array.
        """
        try:
            if IP not in pkt:
                return None
            
            features = {}
            
            # Basic features
            features['duration'] = 0  # Will be calculated for flows
            features['protocol_type'] = self.get_protocol_type(pkt)
            features['service'] = self.get_service(pkt)
            features['flag'] = self.get_flags(pkt)
            features['src_bytes'] = len(pkt)
            features['dst_bytes'] = 0  # Need bidirectional tracking
            
            # Content features
            features['land'] = self.check_land(pkt)
            features['wrong_fragment'] = 0
            features['urgent'] = self.get_urgent(pkt)
            
            # Count features (requires flow tracking)
            features['count'] = self.get_count(flow_id, flows_dict)
            features['srv_count'] = self.get_srv_count(pkt, flow_id, flows_dict)
            features['serror_rate'] = 0.0
            features['srv_serror_rate'] = 0.0
            features['rerror_rate'] = 0.0
            features['srv_rerror_rate'] = 0.0
            features['same_srv_rate'] = 1.0
            features['diff_srv_rate'] = 0.0
            features['srv_diff_host_rate'] = 0.0
            
            # Host-based features
            features['dst_host_count'] = self.get_dst_host_count(pkt, flows_dict)
            features['dst_host_srv_count'] = 0
            features['dst_host_same_srv_rate'] = 1.0
            features['dst_host_diff_srv_rate'] = 0.0
            features['dst_host_same_src_port_rate'] = 0.0
            features['dst_host_srv_diff_host_rate'] = 0.0
            features['dst_host_serror_rate'] = 0.0
            features['dst_host_srv_serror_rate'] = 0.0
            features['dst_host_rerror_rate'] = 0.0
            features['dst_host_srv_rerror_rate'] = 0.0
            
            # Update flow tracking
            self.update_flow(pkt, flow_id, flows_dict, features)
            
            # Convert to feature vector (41 features for NSL-KDD)
            feature_vector = self.to_vector(features)
            
            return feature_vector
            
        except Exception as e:
            logger.error(f"Error extracting features: {e}")
            return None
    
    def get_protocol_type(self, pkt):
        """Extract protocol type."""
        if TCP in pkt:
            return 6  # TCP
        elif UDP in pkt:
            return 17  # UDP
        elif ICMP in pkt:
            return 1  # ICMP
        return 0
    
    def get_service(self, pkt):
        """Determine service based on port."""
        if TCP in pkt or UDP in pkt:
            port = pkt[TCP].dport if TCP in pkt else pkt[UDP].dport
            
            # Common services
            service_map = {
                20: 1, 21: 1,  # FTP
                22: 2,  # SSH
                23: 3,  # Telnet
                25: 4,  # SMTP
                53: 5,  # DNS
                80: 6,  # HTTP
                110: 7,  # POP3
                143: 8,  # IMAP
                443: 9,  # HTTPS
                3306: 10,  # MySQL
            }
            return service_map.get(port, 0)
        return 0
    
    def get_flags(self, pkt):
        """Extract TCP flags."""
        if TCP in pkt:
            flags = pkt[TCP].flags
            flag_value = 0
            if 'F' in str(flags): flag_value |= 0x01
            if 'S' in str(flags): flag_value |= 0x02
            if 'R' in str(flags): flag_value |= 0x04
            if 'P' in str(flags): flag_value |= 0x08
            if 'A' in str(flags): flag_value |= 0x10
            if 'U' in str(flags): flag_value |= 0x20
            return flag_value
        return 0
    
    def check_land(self, pkt):
        """Check if source and destination are the same (LAND attack)."""
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            if TCP in pkt:
                return 1 if (src == dst and pkt[TCP].sport == pkt[TCP].dport) else 0
            elif UDP in pkt:
                return 1 if (src == dst and pkt[UDP].sport == pkt[UDP].dport) else 0
        return 0
    
    def get_urgent(self, pkt):
        """Get urgent pointer count."""
        if TCP in pkt:
            return pkt[TCP].urgptr if pkt[TCP].urgptr else 0
        return 0
    
    def get_count(self, flow_id, flows_dict):
        """Get connection count in last 2 seconds."""
        if flow_id in flows_dict:
            return flows_dict[flow_id].get('count', 1)
        return 1
    
    def get_srv_count(self, pkt, flow_id, flows_dict):
        """Get service count."""
        return self.get_count(flow_id, flows_dict)
    
    def get_dst_host_count(self, pkt, flows_dict):
        """Get destination host count."""
        if IP in pkt:
            dst_ip = pkt[IP].dst
            count = sum(1 for fid, fdata in flows_dict.items() 
                       if dst_ip in fid and time.time() - fdata.get('last_seen', 0) < 2)
            return min(count, 255)
        return 0
    
    def update_flow(self, pkt, flow_id, flows_dict, features):
        """Update flow tracking dictionary."""
        current_time = time.time()
        
        if flow_id not in flows_dict:
            flows_dict[flow_id] = {
                'start_time': current_time,
                'last_seen': current_time,
                'count': 1,
                'packets': [],
            }
        else:
            flow = flows_dict[flow_id]
            flow['last_seen'] = current_time
            flow['count'] += 1
            flow['packets'].append(features)
        
        # Clean old flows (older than 5 seconds)
        to_remove = [fid for fid, fdata in flows_dict.items() 
                    if current_time - fdata.get('last_seen', 0) > 5]
        for fid in to_remove:
            del flows_dict[fid]
    
    def to_vector(self, features):
        """Convert feature dict to numpy array (simplified 41-feature vector)."""
        # This is a simplified version - actual NSL-KDD has 41 features
        vector = [
            features.get('duration', 0),
            features.get('protocol_type', 0),
            features.get('service', 0),
            features.get('flag', 0),
            features.get('src_bytes', 0),
            features.get('dst_bytes', 0),
            features.get('land', 0),
            features.get('wrong_fragment', 0),
            features.get('urgent', 0),
            features.get('count', 1),
            features.get('srv_count', 1),
            features.get('serror_rate', 0),
            features.get('srv_serror_rate', 0),
            features.get('rerror_rate', 0),
            features.get('srv_rerror_rate', 0),
            features.get('same_srv_rate', 1),
            features.get('diff_srv_rate', 0),
            features.get('srv_diff_host_rate', 0),
            features.get('dst_host_count', 0),
            features.get('dst_host_srv_count', 0),
            features.get('dst_host_same_srv_rate', 1),
            features.get('dst_host_diff_srv_rate', 0),
            features.get('dst_host_same_src_port_rate', 0),
            features.get('dst_host_srv_diff_host_rate', 0),
            features.get('dst_host_serror_rate', 0),
            features.get('dst_host_srv_serror_rate', 0),
            features.get('dst_host_rerror_rate', 0),
            features.get('dst_host_srv_rerror_rate', 0),
        ]
        
        # Pad to 41 features if needed
        while len(vector) < 41:
            vector.append(0)
        
        return np.array(vector[:41], dtype=np.float32)

