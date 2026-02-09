from base_reader import BaseReader

class FileReader(BaseReader):
    def __init__(self, path):
        self.path = path

    def read_events(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    yield {
                        "LogType": "File",
                        "Severity": "ERROR" if "error" in line.lower() else "INFO",
                        "Message": [line]
                    }
        except Exception as e:
            print(f"[FileReader ERROR] {e}")
