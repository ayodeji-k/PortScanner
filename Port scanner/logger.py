from datetime import datetime
from typing import List

class Logger:
    def __init__(self):
        self.logs: List[str] = []

    def log(self, message: str):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] {message}"
        self.logs.append(log_entry)
        print(log_entry)

    def save_to_file(self, filename: str):
        with open(filename, 'w') as f:
            f.write('\n'.join(self.logs)) 