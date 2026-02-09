from base_reader import BaseReader

class LinuxReader(BaseReader):
    def __init__(self, path="/var/log/syslog"):
        self.path = path

    def read_events(self):
        try:
            with open(self.path, "r", errors="ignore") as f:
                for line in f:
                    yield {
                        "LogType": "Linux",
                        "Severity": "ERROR" if "error" in line.lower() else "INFO",
                        "Message": [line.strip()]
                    }
        except Exception as e:
            print(f"[LinuxReader ERROR] {e}")
