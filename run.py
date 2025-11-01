
import sys
import threading
import logging
import yaml
from nids.sniffer import PacketSniffer
from nids.utils import setup_logging
from dashboard.app import create_app

def load_config(config_path='config.yaml'):
    """Load configuration from YAML file."""
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)

def main():
    # Load configuration
    config = load_config()
    
    # Setup logging
    setup_logging(config['logging']['level'], config['logging']['file'])
    logger = logging.getLogger(__name__)
    
    logger.info("Starting Network Intrusion Detection System...")
    
    # Start packet sniffer in separate thread
    sniffer = PacketSniffer(config)
    sniffer_thread = threading.Thread(target=sniffer.start, daemon=True)
    sniffer_thread.start()
    logger.info("Packet sniffer started")
    
    # Start Flask dashboard
    app = create_app(config)
    logger.info(f"Starting dashboard on {config['dashboard']['host']}:{config['dashboard']['port']}")
    
    try:
        app.run(
            host=config['dashboard']['host'],
            port=config['dashboard']['port'],
            debug=config['dashboard']['debug'],
            threaded=True
        )
    except KeyboardInterrupt:
        logger.info("Shutting down NIDS...")
        sniffer.stop()
        sys.exit(0)

if __name__ == '__main__':
    main()