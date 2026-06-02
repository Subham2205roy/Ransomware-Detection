import time
import queue
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class RansomwareEventHandler(FileSystemEventHandler):
    def __init__(self, event_queue):
        super().__init__()
        self.event_queue = event_queue

    def _queue_event(self, event_type, file_path):
        # We only care about files, not directories
        event_data = {
            'type': event_type,
            'path': file_path,
            'timestamp': time.time()
        }
        self.event_queue.put(event_data)
        logging.info(f"Event: {event_type} | File: {file_path}")

    def on_created(self, event):
        if not event.is_directory:
            self._queue_event('CREATED', event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._queue_event('MODIFIED', event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self._queue_event('DELETED', event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self._queue_event('RENAMED', event.dest_path)


class DirectoryMonitor:
    def __init__(self, target_directory):
        self.target_directory = target_directory
        # In-memory queue to pass events to the behavior/entropy engines
        self.event_queue = queue.Queue()
        self.observer = Observer()
        self.event_handler = RansomwareEventHandler(self.event_queue)

    def start(self):
        logging.info(f"Starting monitor on directory: {self.target_directory}")
        self.observer.schedule(self.event_handler, self.target_directory, recursive=True)
        self.observer.start()

    def stop(self):
        self.observer.stop()
        self.observer.join()
        logging.info("Monitor stopped.")
