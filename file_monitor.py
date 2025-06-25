import os
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import logging
from logger import setup_logger
import threading

# Setup logger after importing
logger = setup_logger(__name__)

class FileEventHandler(FileSystemEventHandler):
    def __init__(self, callback, allowed_extensions=None):
        self.callback = callback
        # Define allowed file extensions to monitor
        self.allowed_extensions = allowed_extensions or {
            # Documents
            '.pdf', '.docx', '.doc', '.pptx', '.ppt', '.txt', '.csv',
            # Executables and Scripts
            '.exe', '.dll', '.bat', '.ps1', '.vbs', '.js', '.py',
            # Images
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp',
            '.ico', '.svg'
        }
        # Define directories to ignore
        self.ignored_dirs = {'.git', '__pycache__', 'venv', 'env', 'node_modules'}

    def _should_process_file(self, filepath):
        """Check if the file should be processed based on extension and path."""
        # Check if file is in an ignored directory
        path_parts = os.path.normpath(filepath).split(os.sep)
        if any(ignored in path_parts for ignored in self.ignored_dirs):
            print(f"DEBUG: File {filepath} ignored due to directory")  # Debug print
            return False
        
        # Check file extension
        ext = os.path.splitext(filepath)[1].lower()
        should_process = ext in self.allowed_extensions
        print(f"DEBUG: File {filepath} extension {ext} {'allowed' if should_process else 'not allowed'}")  # Debug print
        return should_process

    def on_created(self, event):
        if not event.is_directory and self._should_process_file(event.src_path):
            logger.info(f"New file detected: {event.src_path}")
            print(f"DEBUG: FileEventHandler.on_created called for: {event.src_path}")  # Debug print
            self.callback(event.src_path)

    def on_modified(self, event):
        if not event.is_directory and self._should_process_file(event.src_path):
            logger.info(f"File modified: {event.src_path}")
            print(f"DEBUG: FileEventHandler.on_modified called for: {event.src_path}")  # Debug print
            self.callback(event.src_path)

class FileMonitor:
    def __init__(self, path, callback, allowed_extensions=None):
        self.path = path
        self.callback = callback
        self.observer = Observer()
        self.event_handler = FileEventHandler(callback, allowed_extensions)
        self.observer.schedule(self.event_handler, path, recursive=True)
        self.running = False
        self.thread = None

    def _scan_existing_files(self):
        """Scan existing files in the directory, excluding ignored paths."""
        logger.info(f"Scanning existing files in: {self.path}")
        for root, dirs, files in os.walk(self.path):
            # Remove ignored directories from dirs to prevent walking into them
            dirs[:] = [d for d in dirs if d not in self.event_handler.ignored_dirs]
            
            for file in files:
                filepath = os.path.join(root, file)
                if self.event_handler._should_process_file(filepath):
                    logger.info(f"Scanning existing file: {filepath}")
                    self.callback(filepath)

    def start(self):
        if self.running:
            return
        # First scan existing files
        self._scan_existing_files()
        # Then start monitoring for new/modified files
        self.running = True
        self.thread = threading.Thread(target=self.observer.start, daemon=True)
        self.thread.start()
        logger.info(f"Started monitoring: {self.path}")

    def stop(self):
        if self.observer and self.running:
            self.observer.stop()
            self.observer.join()
            self.running = False
            logger.info(f"Stopped monitoring: {self.path}") 