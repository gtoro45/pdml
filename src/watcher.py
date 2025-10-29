import os
import time
from collections import deque, defaultdict
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

print(f"Running as user: {os.geteuid()}", flush=True)
# === CONFIGURATION ===
WATCH_DIRECTORIES = [
    "/home/capstone/Desktop/cluster/daemon-logs",
    "/home/capstone/Desktop/cluster/zeek-logs-camera",
    "/home/capstone/Desktop/cluster/zeek-logs-lidar",
    "/home/capstone/Desktop/cluster/zeek-logs-nginx"
]
LOG_FILENAME = "conn.log"
BUFFER_SIZE = 500

# === DATA STRUCTURE ===
# Dictionary to store buffers for each log source (directory name)
log_buffers = defaultdict(lambda: deque(maxlen=BUFFER_SIZE))

# === FILE EVENT HANDLER ===
class ConnLogHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if not event.is_directory and event.src_path.endswith(LOG_FILENAME):
            self.read_new_lines(event.src_path)

    def read_new_lines(self, filepath):
        # Extract log source name from parent directory
        log_dir = os.path.basename(os.path.dirname(filepath))
        buffer = log_buffers[log_dir]

        # Track file offset (in-memory only)
        if not hasattr(self, 'offsets'):
            self.offsets = {}

        offset = self.offsets.get(filepath, 0)

        try:
            with open(filepath, 'r') as f:
                f.seek(offset)
                new_lines = f.readlines()
                for line in new_lines:
                    cleaned = line.strip()
                    if cleaned:
                        entry = f"[{log_dir}] {cleaned}"
                        buffer.append(entry)
                        print(entry, flush=True)  # ✅ Print each new entry immediately
                self.offsets[filepath] = f.tell()
        except Exception as e:
            print(f"Error reading {filepath}: {e}", flush=True)

# === SETUP WATCHDOG ===
if __name__ == "__main__":
    event_handler = ConnLogHandler()
    observer = Observer()

    for directory in WATCH_DIRECTORIES:
        if os.path.exists(directory):
            observer.schedule(event_handler, path=directory, recursive=False)
            print(f"Watching directory: {directory}", flush=True)
        else:
            print(f"Warning: Directory not found: {directory}", flush=True)

    observer.start()
    print("Watching for conn.log updates...", flush=True)

    try:
        while True:
            time.sleep(5)
            # Optional: print buffer sizes for monitoring
            for source, buffer in log_buffers.items():
                print(f"{source}: {len(buffer)} entries", flush=True)
    except KeyboardInterrupt:
        print("Stopping log watcher...", flush=True)
        observer.stop()
    observer.join()