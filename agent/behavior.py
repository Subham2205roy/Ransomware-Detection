import time
import logging

class BehaviorAnalyzer:
    def __init__(self, time_window=10, max_modifications=5):
        """
        time_window: The time window in seconds to track events.
        max_modifications: The threshold of events within the window that triggers a warning.
        """
        self.time_window = time_window
        self.max_modifications = max_modifications
        
        # We will keep a list of timestamps when files were modified/created
        self.event_timestamps = []

    def analyze_event(self, event_type, file_path):
        """
        Called every time a file event occurs.
        Returns True if the behavior is suspicious (rapid modifications), False otherwise.
        """
        current_time = time.time()
        
        # Track all meaningful file system actions to detect a mass-encryption or deletion wave
        if event_type in ['MODIFIED', 'CREATED', 'RENAMED', 'DELETED']:
            self.event_timestamps.append(current_time)

        # Remove timestamps older than the time_window
        self._clean_old_events(current_time)

        # Check if the number of events exceeds the threshold
        if len(self.event_timestamps) >= self.max_modifications:
            logging.warning(f"BEHAVIOR ALERT: Detected {len(self.event_timestamps)} file actions within {self.time_window} seconds! Possible ransomware mass-modification.")
            return True
            
        return False

    def _clean_old_events(self, current_time):
        """Removes timestamps outside the current sliding window."""
        self.event_timestamps = [t for t in self.event_timestamps if (current_time - t) <= self.time_window]
