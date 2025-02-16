# this program is used to update the admin monitor automatically when it is saved.

import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import os
import subprocess

class Watcher:
    DIRECTORY_TO_WATCH = "."

    def __init__(self):
        self.observer = Observer()

    def run(self):
        event_handler = Handler()
        self.observer.schedule(event_handler, self.DIRECTORY_TO_WATCH, recursive=True)
        self.observer.start()
        try:
            while True:
                time.sleep(5)
        except:
            self.observer.stop()
            print("Observer Stopped")

        self.observer.join()

class Handler(FileSystemEventHandler):

    @staticmethod
    def on_modified(event):
        if event.src_path.endswith(".py"):
            print(f'{event.src_path} has been modified')
            build_executable()

def build_executable():
    try:
        subprocess.run(["pyinstaller", "--onefile", "--windowed", "admin_monitor.py"], check=True)
        print("Executable has been built")
    except subprocess.CalledProcessError as e:
        print(f"Error occurred while building executable: {e}")

if __name__ == '__main__':
    w = Watcher()
    w.run()