import os
import time
import threading
import logging
from dotenv import load_dotenv
from monitor import DirectoryMonitor
from entropy import calculate_shannon_entropy
from behavior import BehaviorAnalyzer
from recovery import RecoveryVault
from api_client import APIClient

# Load environment variables
load_dotenv()

def main():
    watch_directory = os.getenv('WATCH_DIRECTORY', '.')
    
    # Ensure the target directory exists
    if not os.path.exists(watch_directory):
        logging.warning(f"Watch directory {watch_directory} does not exist. Creating it.")
        os.makedirs(watch_directory, exist_ok=True)
    
    # Initialize monitor, behavior analyzer, recovery vault, and API client
    monitor = DirectoryMonitor(watch_directory)
    behavior_analyzer = BehaviorAnalyzer(time_window=10, max_modifications=5)
    vault = RecoveryVault()
    api_client = APIClient()
    
    # Register agent with the server
    api_client.register()
    
    # Start background heartbeat thread
    def heartbeat_loop():
        while True:
            time.sleep(60)
            api_client.heartbeat()
            
    threading.Thread(target=heartbeat_loop, daemon=True).start()
    
    try:
        monitor.start()
        
        # Main loop to keep the agent alive
        # Future phases will pull from monitor.event_queue here for analysis
        while True:
            time.sleep(1)
            
            # Process queued events
            while not monitor.event_queue.empty():
                event = monitor.event_queue.get()
                
                entropy_score = 0.0
                
                if event['type'] in ['CREATED', 'MODIFIED']:
                    # Small delay to ensure file write lock is released
                    time.sleep(0.05)
                    entropy_score = calculate_shannon_entropy(event['path'])
                    logging.info(f"Analyzed {event['path']} - Entropy: {entropy_score:.4f}")
                
                # Run behavior analysis on all events
                is_suspicious = behavior_analyzer.analyze_event(event['type'], event['path'])
                
                # Phase 7: Threat Detection Engine
                threat_detected = False
                threat_reasons = []
                
                if is_suspicious:
                    threat_detected = True
                    threat_reasons.append("Behavior anomaly (Mass Modification)")
                    
                if entropy_score >= 7.5:
                    threat_detected = True
                    threat_reasons.append(f"High Entropy ({entropy_score:.2f}) - Possible Encryption")
                    
                if threat_detected:
                    logging.warning(f"THREAT DETECTED on {event['path']} - Reasons: {', '.join(threat_reasons)}")
                    
                    # Trigger Recovery (Phase 6)
                    if event['type'] != 'DELETED':
                        vault.backup_file(event['path'])
                        
                    # Phase 9: Transmit alert to central server
                    alert_type = "MASS_MODIFICATION" if is_suspicious else "HIGH_ENTROPY"
                    if is_suspicious and entropy_score >= 7.5:
                        alert_type = "CRITICAL_RANSOMWARE_BEHAVIOR"
                        
                    api_client.send_alert(
                        alert_type=alert_type,
                        severity="CRITICAL",
                        description=f"Threat detected: {', '.join(threat_reasons)}",
                        file_path=event['path'],
                        entropy=entropy_score
                    )
                
    except KeyboardInterrupt:
        logging.info("Keyboard interrupt received. Shutting down...")
        monitor.stop()

if __name__ == "__main__":
    main()
