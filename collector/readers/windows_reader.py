from base_reader import BaseReader
import win32evtlog
import platform
from datetime import datetime

class WindowsReader(BaseReader):
    def __init__(self, server="localhost", channels=None):
        self.server = server
        self.channels = channels or ["Application", "System", "Security"]

    def read_events(self):
        for logtype in self.channels:
            try:
                handle = win32evtlog.OpenEventLog(self.server, logtype)
                flags = win32evtlog.EVENTLOG_SEQUENTIAL_READ | win32evtlog.EVENTLOG_BACKWARDS_READ
                events = win32evtlog.ReadEventLog(handle, flags, 0)
            except Exception as e:
                print(f"[WindowsReader] Cannot read {logtype}: {e}")
                continue

            if not events:
                continue

            for event in events:
                inserts = event.StringInserts if event.StringInserts else []
                
                yield {
                    "LogType": logtype,
                    "EventID": event.EventID,
                    "Severity": event.EventType,
                    "Source": event.SourceName,
                    "GeneratedTimeUTC": event.TimeGenerated.strftime("%Y-%m-%d %H:%M:%S"),
                    "WrittenTimeUTC": event.TimeWritten.strftime("%Y-%m-%d %H:%M:%S"),
                    "Message": inserts,
                    "MachineName": platform.node(),
                }
