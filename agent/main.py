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
from canary import CanaryManager
from mitigation import ActiveMitigation

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
    canary_manager = CanaryManager(watch_directory)
    mitigator = ActiveMitigation(watch_directory)
    
    # Register agent with the server
    api_client.register()
    
    # Deploy canary honeypot files
    canary_manager.deploy_canaries()
    # Maintain local state
    folder_locked = False
    monitor_running = False
    
    # Start background heartbeat thread
    def heartbeat_loop():
        while True:
            time.sleep(60)
            api_client.heartbeat()
            
    threading.Thread(target=heartbeat_loop, daemon=True).start()
    
    # Start background command polling thread
    def command_loop():
        nonlocal folder_locked, watch_directory, monitor, behavior_analyzer, canary_manager, mitigator, monitor_running
        while True:
            time.sleep(5)
            commands, remote_dir = api_client.poll_commands(folder_locked=folder_locked)
            
            # Handle remote directory switch
            if remote_dir and remote_dir != watch_directory:
                logging.info(f"Remote configuration update: Switching watch directory to {remote_dir}")
                
                # Stop current monitor
                if monitor_running:
                    try:
                        monitor.stop()
                    except Exception as e:
                        logging.error(f"Error stopping monitor: {e}")
                
                # Ensure new target directory exists
                if not os.path.exists(remote_dir):
                    try:
                        os.makedirs(remote_dir, exist_ok=True)
                    except Exception as e:
                        logging.error(f"Failed to create new watch directory {remote_dir}: {e}")
                        continue
                        
                # Re-initialize components
                watch_directory = remote_dir
                monitor = DirectoryMonitor(watch_directory)
                canary_manager = CanaryManager(watch_directory)
                mitigator = ActiveMitigation(watch_directory)
                
                canary_manager.deploy_canaries()
                folder_locked = False
                
                try:
                    monitor.start()
                    monitor_running = True
                    logging.info(f"Successfully switched monitoring to {watch_directory}")
                except PermissionError:
                    logging.error(f"Access denied monitoring {watch_directory}. It might be locked down.")
                    monitor_running = False
                
            for cmd in commands:
                if cmd == "unlock":
                    logging.info("Received remote command: UNLOCK")
                    mitigator.unlock_directory()
                    folder_locked = False
                    if not monitor_running:
                        try:
                            monitor.start()
                            monitor_running = True
                            logging.info("Monitor successfully started after unlock.")
                        except Exception as e:
                            logging.error(f"Could not start monitor after unlock: {e}")
                    
    threading.Thread(target=command_loop, daemon=True).start()
    
    try:
        try:
            monitor.start()
            monitor_running = True
        except PermissionError as e:
            logging.error(f"Permission denied starting monitor on {watch_directory}. Is it locked? {e}")
            logging.info("Agent is still running and waiting for remote UNLOCK command.")
            folder_locked = True
        
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
                
                # Phase 7 & 17: Threat Detection Engine
                threat_detected = False
                threat_reasons = []
                
                is_canary_hit = canary_manager.is_canary(event['path'])

                if is_canary_hit:
                    threat_detected = True
                    threat_reasons.append("HONEYPOT TRIGGERED - Canary file modified!")
                
                if is_suspicious:
                    threat_detected = True
                    threat_reasons.append("Behavior anomaly (Mass Modification)")
                    
                if entropy_score >= 7.5:
                    threat_detected = True
                    threat_reasons.append(f"High Entropy ({entropy_score:.2f}) - Possible Encryption")
                    
                if threat_detected:
                    logging.warning(f"THREAT DETECTED on {event['path']} - Reasons: {', '.join(threat_reasons)}")
                    
                    # --- ACTIVE MITIGATION ---
                    # 1. Lockdown the directory IMMEDIATELY
                    locked = mitigator.lockdown_directory()
                    if locked:
                        folder_locked = True
                        threat_reasons.append("Folder locked down (Read-Only via icacls)")

                    # 2. Kill the process touching the file (can be slow/hang on Windows, so run in background)
                    threading.Thread(target=mitigator.kill_suspect_process, args=(event['path'],), daemon=True).start()
                    threat_reasons.append("Initiated suspect process termination")

                    # 3. Trigger Recovery
                    if event['type'] != 'DELETED':
                        vault.backup_file(event['path'])
                        
                    # Phase 9: Transmit alert to central server
                    alert_type = "MASS_MODIFICATION" if is_suspicious else "HIGH_ENTROPY"
                    if is_canary_hit:
                        alert_type = "HONEYPOT_TRIGGERED"
                    elif is_suspicious and entropy_score >= 7.5:
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
