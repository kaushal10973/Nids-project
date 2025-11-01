import logging
from scapy.all import sniff, IP, TCP, UDP, ICMP
from scapy.error import Scapy_Exception
import threading
from nids.feature_extractor import FeatureExtractor
from nids.classifier import ThreatClassifier
from nids.database import DatabaseManager
from nids.response import ResponseEngine

logger = logging.getLogger(__name__)

class PacketSniffer:
    """Network packet sniffer using Scapy."""
    
    def __init__(self, config):
        self.config = config
        self.interface = config['network']['interface']
        self.filter = config['network']['filter']
        self.packet_count = config['network']['packet_count']
        self.running = False
        self.lock = threading.Lock()
        
        # Initialize components
        self.feature_extractor = FeatureExtractor()
        self.classifier = ThreatClassifier(config)
        self.db_manager = DatabaseManager(config['database']['path'])
        self.response_engine = ResponseEngine(config)
        
        # Flow tracking for stateful analysis
        self.flows = {}
        
    def start(self):
        """Start packet capture."""
        self.running = True
        logger.info(f"Starting packet capture on {self.interface} with filter: {self.filter}")
        
        try:
            sniff(
                iface=self.interface,
                prn=self.process_packet,
                filter=self.filter,
                count=self.packet_count,
                store=False,
                stop_filter=lambda x: not self.running
            )
        except Scapy_Exception as e:
            logger.error(f"Scapy error: {e}")
        except PermissionError:
            logger.error("Permission denied. Run with sudo or appropriate privileges.")
        except Exception as e:
            logger.error(f"Unexpected error in packet capture: {e}")
    
    def stop(self):
        """Stop packet capture."""
        self.running = False
        logger.info("Stopping packet capture")
    
    def process_packet(self, pkt):
        """Process each captured packet."""
        try:
            if IP not in pkt:
                return
            
            # Extract basic packet info
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            protocol = pkt[IP].proto
            
            # Determine protocol type
            proto_name = "OTHER"
            src_port = 0
            dst_port = 0
            
            if TCP in pkt:
                proto_name = "TCP"
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
            elif UDP in pkt:
                proto_name = "UDP"
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
            elif ICMP in pkt:
                proto_name = "ICMP"
            
            # Create flow ID
            flow_id = self.create_flow_id(src_ip, dst_ip, src_port, dst_port, proto_name)
            
            # Extract features
            features = self.feature_extractor.extract(pkt, flow_id, self.flows)
            
            if features is None:
                return
            
            # Classify traffic
            prediction = self.classifier.classify(features)
            
            if prediction is None:
                return
            
            class_label = prediction['class']
            attack_type = prediction['attack_type']
            confidence = prediction['confidence']
            
            # Log to database if attack detected or confidence is high
            if class_label != 'Normal' or confidence > 0.9:
                alert_id = self.db_manager.store_alert(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    protocol=proto_name,
                    src_port=src_port,
                    dst_port=dst_port,
                    class_label=class_label,
                    attack_type=attack_type,
                    confidence=confidence
                )
                
                # Trigger automated response for attacks
                if class_label != 'Normal' and alert_id:
                    action = self.response_engine.handle_threat(
                        alert_id=alert_id,
                        src_ip=src_ip,
                        attack_type=attack_type,
                        confidence=confidence
                    )
                    
                    # Update alert with action taken
                    if action:
                        self.db_manager.update_alert_action(alert_id, action)
                
                logger.info(f"Alert: {class_label} ({attack_type}) from {src_ip}:{src_port} "
                           f"to {dst_ip}:{dst_port} [confidence: {confidence:.2f}]")
            
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
    
    def create_flow_id(self, src_ip, dst_ip, src_port, dst_port, protocol):
        """Create unique flow identifier."""
        # Sort IPs and ports for bidirectional flow tracking
        if (src_ip, src_port) < (dst_ip, dst_port):
            return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
        else:
            return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"
    
    def extract_features(self, pkt):
        """Extract features from packet for ML classification."""
        return self.feature_extractor.extract(pkt)
    
    def save_raw(self, pkt, flow_id):
        """Save raw packet data."""
        try:
            raw_data = bytes(pkt)
            self.db_manager.store_flow(flow_id, str(pkt.summary()), raw_data)
        except Exception as e:
            logger.error(f"Error saving raw packet: {e}")