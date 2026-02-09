import time
import win32evtlog  # from pywin32
import pywintypes
from datetime import datetime,timedelta,timezone,UTC
import json
import os
import csv
import requests
from requests.exceptions import ConnectionError as RequestsConnectionError, RequestException
import ctypes
import platform
from bs4 import BeautifulSoup

import queue
import threading
import socket

import sys

from dotenv import load_dotenv
import importlib
import importlib.util

load_dotenv("mails.env")
#load_dotenv(".env")

SENDER_EMAIL = os.getenv("ALERT_EMAIL")
SENDER_PASSWORD = os.getenv("ALERT_PASSWORD")
RECEIVER_EMAIL = os.getenv("ALERT_TO")
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 465

last_email_sent = {}
last_alert_signature = {}

LOGSTASH_URL = os.environ.get("LOGSTASH_URL", "http://localhost:5044")
MAX_RETRIES = int(os.environ.get("MAX_RETRIES", "5"))
RETRY_DELAY = int(os.environ.get("RETRY_DELAY", "5"))
FALLBACK_FILE = os.environ.get("FALLBACK_FILE", "failed_logs.jsonl")

log_queue = queue.Queue()

stop_event = threading.Event()
stop_cleanup_event = threading.Event()

DEBUG = False

import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_email_alert(log_obj):
    global last_email_sent, last_alert_signature

    # now = datetime.utcnow()
    now = datetime.now(timezone.utc)
    log_type = log_obj.get("LogType", "GENERAL")

    # Build a unique signature for deduplication (EventID + Source + Message)
    signature = (
        log_obj.get("EventID"),
        log_obj.get("Source"),
        # log_obj.get("Message")
    )

    # ----- Deduplication -----
    if log_type in last_alert_signature and last_alert_signature[log_type] == signature:
        print(f"[SKIP EMAIL] Duplicate CRITICAL log for {log_type}")
        return

    # ----- Rate limit (cooldown per log type) -----
    cooldown = timedelta(seconds=30)  # change if you want
    if log_type in last_email_sent and now - last_email_sent[log_type] < cooldown:
        print(f"[SKIP EMAIL] Cooldown active for {log_type}")
        return

    # Update trackers
    last_email_sent[log_type] = now
    last_alert_signature[log_type] = signature

    # ----- Actual email send -----
    
    try:
        subject = f"[ALERT] Critical log detected - {log_type}"
        body = (
            f"LogType: {log_type}\n"
            f"EventID: {log_obj.get('EventID')}\n"
            f"Severity: {log_obj.get('Severity')}\n"
            f"Source: {log_obj.get('Source')}\n"
            f"Time: {log_obj.get('GeneratedTimeUTC')}\n"
            f"Description: {log_obj.get('Description')}\n"
            f"Message: {log_obj.get('LogMessages') or log_obj.get('Message')}\n"
        )

        msg = MIMEMultipart()
        msg["From"] = SENDER_EMAIL
        msg["To"] = RECEIVER_EMAIL
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, context=context) as server:
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())

        print(f"Email alert SENT for {log_type}")

    except Exception as e:
        print(f"[ERROR] Failed to send email: {e}")

def send_system_offline_email():
    """Send an alert when the monitoring system goes offline."""
    try:
        subject = "[ALERT] Windows Log Monitoring - System OFFLINE "
        timestamp_now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        body = (
            "This is an automated alert.\n\n"
            "The Windows Log Monitoring system has stopped running.\n"
            "No logs are currently being monitored or sent.\n\n"
            f"Timestamp: {timestamp_now}"
        )

        msg = MIMEMultipart()
        msg["From"] = SENDER_EMAIL
        msg["To"] = RECEIVER_EMAIL
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, context=context) as server:
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())

        print("[ALERT] System offline email sent.")
    except Exception as e:
        print(f"[ERROR] Failed to send system offline email: {e}")


def send_logs_worker():
    import requests as _requests
    while not stop_event.is_set():
        try:
            log_event = log_queue.get(timeout=1)  
        except queue.Empty:
            continue

        sent = False
        for attempt in range(MAX_RETRIES):
            if stop_event.is_set():
                break
            try:
                resp = _requests.post(LOGSTASH_URL, json=log_event, timeout=5)
                if resp.status_code in (200, 201):
                    sent = True
                    break
                else:
                    print(f"[WARN] Logstash responded {resp.status_code}: {resp.text}")
            except Exception as _e:
                # Print the raw error for debugging
                print(f"[ERROR] Cannot send log to Logstash: {_e}")

            time.sleep(RETRY_DELAY * (attempt + 1))

        if not sent:
            append_to_fallback(log_event)

        log_queue.task_done()

def process_and_send_log(event_dict):
    
    event_dict.setdefault("host", socket.gethostname())
    event_dict.setdefault("@timestamp", time.strftime("%Y-%m-%dT%H:%M:%S"))
    try:
        log_queue.put(event_dict)

    except Exception as _e:
        try:
            with open(FALLBACK_FILE, "a", encoding="utf-8") as _f:
                _f.write(json.dumps(event_dict) + "\n")
        except Exception:
            pass

for _ in range(3):
    threading.Thread(target=send_logs_worker, daemon=True).start()

# CONFIG

CHECK_INTERVAL = 2  # seconds1
EVENT_FILE = "windows_event_ids.txt"
EVENT_CSV = "AllEventIDs_HumanReadable_Refined.csv"
OUTPUT_FILE = "logs.json"
STATE_FILE = "last_record.json"
ES_URL = "http://localhost:9200/windows-logs/_doc/"
ES_INDEX_URL = "http://localhost:9200/windows-logs"

ES_AUTH = (
    os.getenv("ES_USER"),
    os.getenv("ES_PASSWORD")
)

CRITICAL_LEVELS = ["ERROR", "AUDIT_FAILURE"]
CLEANUP_INTERVAL_HOURS = 24 

# EVENT LEVEL MAPPING

EVENT_TYPE_MAP = {
    1: "ERROR",
    2: "WARNING",
    4: "INFORMATION",
    8: "AUDIT_SUCCESS",
    16: "AUDIT_FAILURE"
}

def get_event_level(event):
    level = EVENT_TYPE_MAP.get(event.EventType, "UNKNOWN")
    if level in CRITICAL_LEVELS:
        return "CRITICAL"
    return level

# LOAD EVENT DESCRIPTIONS

def load_event_descriptions_txt(file_path):
    descriptions = {}
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if "|" in line:
                    event_id, desc = line.split("|", 1)
                    try:
                        descriptions[int(event_id)] = desc.strip()
                    except ValueError:
                        continue
    except Exception as e:
        print(f"[ERROR] Could not load TXT event descriptions ({e})")
    return descriptions

def load_event_descriptions_csv(file_path):
    descriptions = {}
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    event_id = int(row["Id"])
                    desc = row.get("Description", "").strip()
                    if desc:
                        descriptions[event_id] = desc
                except (ValueError, KeyError):
                    continue
    except Exception as e:
        print(f"[ERROR] Could not load CSV event descriptions ({e})")
    return descriptions

EVENT_DESCRIPTIONS_TXT = load_event_descriptions_txt(EVENT_FILE)
EVENT_DESCRIPTIONS_CSV = load_event_descriptions_csv(EVENT_CSV)

# ENRICHMENT FUNCTIONS

def fetch_description_from_microsoft(event_id: int) -> str:
    url = f"https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-{event_id}"
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200 and "Event" in resp.text:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(resp.text, "html.parser")
            title = soup.find("h1")
            if title:
                return title.get_text(strip=True)
    except Exception:
        pass
    return None

def decode_hresult(hr: int) -> str:
    FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000
    buffer = ctypes.create_unicode_buffer(1024)
    length = ctypes.windll.kernel32.FormatMessageW(
        FORMAT_MESSAGE_FROM_SYSTEM,
        None,
        ctypes.c_uint32(hr & 0xFFFFFFFF),
        0,
        buffer,
        len(buffer),
        None
    )
    msg = buffer.value.strip()
    return msg if length else None

def get_event_description(event_id: int, logtype: str) -> str:
    if event_id in EVENT_DESCRIPTIONS_TXT:
        return EVENT_DESCRIPTIONS_TXT[event_id]
    if event_id in EVENT_DESCRIPTIONS_CSV:
        return EVENT_DESCRIPTIONS_CSV[event_id]
    if logtype == "Security":
        msg = fetch_description_from_microsoft(event_id)
        if msg:
            return msg
    msg = decode_hresult(event_id)
    if msg:
        return msg
    return "Unknown Event (no description available)"



def substitute_placeholders(template: str, inserts: list) -> str:
    if not template:
        return template
    if not inserts:
        return template
    desc = template
    for i in range(1, 50):
        placeholder = f"%{i}"
        if placeholder in desc:
            if i <= len(inserts):
                desc = desc.replace(placeholder, str(inserts[i - 1]))
    return desc


MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
MAX_FALLBACK_SIZE = 50 * 1024 * 1024  # 50 MB

def append_to_fallback(log_event):
    try:
        if os.path.exists(FALLBACK_FILE) and os.path.getsize(FALLBACK_FILE) > MAX_FALLBACK_SIZE:
            os.rename(FALLBACK_FILE, FALLBACK_FILE + ".old")  # rotate
        with open(FALLBACK_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(log_event, ensure_ascii=False) + "\n")
    except Exception as e:
        print(f"[ERROR] Could not write to fallback: {e}")

def get_log_file():
    """Return current daily log file, rotated by size if needed"""
    today_str = datetime.now().strftime("%Y-%m-%d")
    base_file = f"logs_{today_str}.json"
    
    # If file doesn't exist yet, just return it
    if not os.path.exists(base_file):
        return base_file

    # Check current file size
    if os.path.getsize(base_file) < MAX_FILE_SIZE:
        return base_file

    # Rotate file by adding a numeric suffix
    i = 1
    while True:
        rotated_file = f"logs_{today_str}_{i}.json"
        if not os.path.exists(rotated_file):
            return rotated_file
        elif os.path.getsize(rotated_file) < MAX_FILE_SIZE:
            return rotated_file
        i += 1

# ALERT / LOG OUTPUT

def send_alert(log_obj, output_file=OUTPUT_FILE):
    log_line = json.dumps(log_obj, default=str, ensure_ascii=False, indent=4)
    print(f"[LOG]\n{log_line}")

    try:
        if "GeneratedTimeUTC" in log_obj:
            dt = datetime.strptime(log_obj["GeneratedTimeUTC"], "%Y-%m-%d %H:%M:%S")
            log_obj["GeneratedTimeUTC"] = dt.strftime("%Y-%m-%dT%H:%M:%S")
        if "WrittenTimeUTC" in log_obj:
            dt = datetime.strptime(log_obj["WrittenTimeUTC"], "%Y-%m-%d %H:%M:%S")
            log_obj["WrittenTimeUTC"] = dt.strftime("%Y-%m-%dT%H:%M:%S")
        if "@timestamp" in log_obj:
            dt = datetime.strptime(log_obj["@timestamp"], "%Y-%m-%dT%H:%M:%S")
            log_obj["@timestamp"] = dt.strftime("%Y-%m-%dT%H:%M:%S")
    except Exception:
        pass
    
    try:
        resp = requests.post(ES_URL, json=log_obj, auth=ES_AUTH)
        if resp.status_code not in (200, 201):
            print(f"[ERROR] Failed to send to Elasticsearch: {resp.text}")
    except Exception as e:
        print(f"[ERROR] Elasticsearch connection failed: {e}")
    
    try:
        log_file = get_log_file()
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(log_line + "\n")
    except Exception as e:
        print(f"[ERROR] Could not write log to file: {e}")

    # Normalize Message field before sending to ES
    if "Message" in log_obj:
        inserts = log_obj.pop("Message")  # take the original inserts list
        if inserts:
            # Keep raw list for Logstash / file
            log_obj["LogMessages"] = [str(m) for m in inserts if m is not None]
            # Create a clean string for ES
            log_obj["Message"] = " | ".join(str(m) for m in inserts if m is not None)
        else:
            log_obj["LogMessages"] = []
            log_obj["Message"] = ""

    try:
        process_and_send_log(log_obj)
    except Exception as _e:
        print(f"[ERROR] Could not enqueue log for Logstash: {_e}")

    if log_obj["LogLevel"] == "CRITICAL":
        send_email_alert(log_obj)


# STATE MANAGEMENT

def load_state():
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_state(state):
    if not state:
        state = {"Application": 0, "System": 0, "Security": 0}
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f)

# DEDUPLICATION CACHE

recent_events = []
CACHE_LIMIT = 200

def is_duplicate(log_obj):
    key = (log_obj["EventID"], log_obj["Source"], tuple(log_obj.get("Message") or []))
    if key in recent_events:
        return True
    recent_events.append(key)
    if len(recent_events) > CACHE_LIMIT:
        recent_events.pop(0)
    return False


# ------------------ Plugin loader & generic monitor ------------------
def load_reader(name: str):
    """Load a reader class from the `readers` plugin folder.
    Tries standard import `readers.<name>_reader` first, then falls back
    to loading the file `readers/<name>_reader.py` relative to this file.
    The reader class is expected to be named `<Name>Reader` (capitalized).
    """
    mod_name = f"readers.{name}_reader"
    class_name = name.capitalize() + "Reader"
    try:
        module = importlib.import_module(mod_name)
        return getattr(module, class_name)
    except Exception:
        # Try loading from plugin folder path
        readers_dir = os.path.join(os.path.dirname(__file__), "readers")
        candidate = os.path.join(readers_dir, f"{name}_reader.py")
        if os.path.exists(candidate):
            spec = importlib.util.spec_from_file_location(mod_name, candidate)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return getattr(module, class_name)
        raise ImportError(f"Could not import reader '{name}' from plugins or package")


def monitor_with_reader(reader, output_file=OUTPUT_FILE):
    """Generic monitor loop for plugin readers. The reader must implement
    `read_events()` that yields log dictionaries compatible with `send_alert()`.
    """
    print(f"[INFO] Starting generic monitor with reader: {reader.__class__.__name__}")
    try:
        while not stop_event.is_set():
            events_found = False
            for event in reader.read_events():
                events_found = True
                if not isinstance(event, dict):
                    if DEBUG:
                        print("[DEBUG] reader yielded non-dict, skipping:", event)
                    continue
                try:
                    print("[EVENT]", json.dumps(event, default=str, ensure_ascii=False))
                except Exception:
                    print("[EVENT] (non-serializable)", event)
                try:
                    if not is_duplicate(event):
                        send_alert(event, output_file)
                except Exception as e:
                    print(f"[ERROR] processing event from reader: {e}")
                if stop_event.is_set():
                    break
            if not events_found:
                time.sleep(CHECK_INTERVAL)
    except KeyboardInterrupt:
        raise
    except Exception as e:
        print(f"[FATAL] Generic monitor exception: {e}")

# MONITOR

def monitor_windows_event_logs(start_date=None, query_mode=False, newest_first=False):
    server = "localhost"
    log_channels = ["Application", "System", "Security"]

    output_file = OUTPUT_FILE if not query_mode else f"query_logs_{start_date.strftime('%Y-%m-%d') if start_date else 'all'}.json"

    handles = {}
    last_record = load_state() if not query_mode else {}

    for logtype in log_channels:
        last_record.setdefault(logtype, 0)
        try:
            handles[logtype] = win32evtlog.OpenEventLog(server, logtype)
            if DEBUG:
                print(f"[DEBUG] OpenEventLog succeeded for '{logtype}'")

            try:
                back_flags = win32evtlog.EVENTLOG_SEQUENTIAL_READ | win32evtlog.EVENTLOG_BACKWARDS_READ
                try:
                    recent_events = win32evtlog.ReadEventLog(handles[logtype], back_flags, 0)
                    if recent_events:
                        latest_rec = recent_events[0].RecordNumber
                        if DEBUG:
                            print(f"[DEBUG] {logtype} latest RecordNumber: {latest_rec}")
                        if last_record[logtype] == 0:
                            last_record[logtype] = latest_rec
                        elif last_record[logtype] > latest_rec:
                            if DEBUG:
                                print(f"[DEBUG] saved last_record for {logtype} ({last_record[logtype]}) > latest ({latest_rec}); clamping to {latest_rec}")
                            last_record[logtype] = latest_rec
                    else:
                        # No events returned from backwards read; fall back to count
                        info = win32evtlog.GetNumberOfEventLogRecords(handles[logtype])
                        if DEBUG:
                            print(f"[DEBUG] {logtype} event count fallback: {info}")
                        if last_record[logtype] == 0:
                            last_record[logtype] = info
                except pywintypes.error:
                    # If backwards read is not permitted (Security etc), fall back to count
                    info = win32evtlog.GetNumberOfEventLogRecords(handles[logtype])
                    if DEBUG:
                        print(f"[DEBUG] {logtype} GetNumberOfEventLogRecords fallback: {info}")
                    if last_record[logtype] == 0:
                        last_record[logtype] = info
            except Exception as _e:
                if DEBUG:
                    print(f"[DEBUG] Could not determine latest record for {logtype}: {_e}")
        except pywintypes.error as e:
            print(f"[WARNING] Could not open {logtype} log ({e}). Skipping...")
            if DEBUG:
                print(f"[DEBUG] pywintypes.error while opening {logtype}: {e}")
    while True:
        no_new_events = True
        for logtype, hand in handles.items():
            try:
                if newest_first:
                    flags = win32evtlog.EVENTLOG_SEQUENTIAL_READ | win32evtlog.EVENTLOG_BACKWARDS_READ
                    start_record = 0
                else:

                    flags = win32evtlog.EVENTLOG_SEQUENTIAL_READ | win32evtlog.EVENTLOG_FORWARDS_READ
                    start_record = 0
                if DEBUG:
                    print(f"[DEBUG] Reading {logtype}: flags={flags} start_record={start_record}")
                try:
                    events = win32evtlog.ReadEventLog(hand, flags, start_record)
                except pywintypes.error as _read_e:
                    if DEBUG:
                        print(f"[DEBUG] ReadEventLog raised for {logtype}: {_read_e}")
                    continue
            except pywintypes.error:
                continue

            if events:
                no_new_events = False
                for event in events:
                    event_id = event.EventID
                    desc = get_event_description(event_id, logtype)
                    time_str = event.TimeGenerated.strftime("%Y-%m-%d %H:%M:%S")
                    inserts = event.StringInserts if event.StringInserts else []
                    desc = substitute_placeholders(desc, inserts)
                    raw_level = EVENT_TYPE_MAP.get(event.EventType, "UNKNOWN")
                    log_obj = {
                        "LogType": logtype,
                        "EventID": event_id,
                        "Severity": raw_level,  
                        "LogLevel": get_event_level(event),
                        "Description": desc,
                        "Source": event.SourceName,
                        "Time": time_str,
                        "GeneratedTimeUTC": event.TimeGenerated.strftime("%Y-%m-%d %H:%M:%S"),
                        "WrittenTimeUTC": event.TimeWritten.strftime("%Y-%m-%d %H:%M:%S"),
                        "Message": inserts,
                        "RecordNumber": event.RecordNumber,
                        "Category": getattr(event, "EventCategory", None),
                        "MachineName": platform.node(),
                        "User": getattr(event, "UserName", None)
                    }

                    # Filter out events we've already processed using RecordNumber
                    if last_record.get(logtype, 0) and event.RecordNumber <= last_record[logtype]:
                        # skip already processed
                        continue

                    if not query_mode or (not start_date) or (event.TimeGenerated >= start_date):
                        if not is_duplicate(log_obj):
                            send_alert(log_obj, output_file)

                    last_record[logtype] = event.RecordNumber

                if not query_mode and not newest_first:
                    save_state(last_record)
            else:
                if DEBUG:
                    print(f"[DEBUG] ReadEventLog returned no events for {logtype} (start_record={start_record})")

        if query_mode and no_new_events:
            print("Query complete. Saving state and exiting.")
            save_state(last_record)
            return

        if newest_first and no_new_events:
            print("Newest-first backfill complete. Saving state.")
            save_state(last_record)
            return

        save_state(last_record)

        if not query_mode:
            if no_new_events:
                time.sleep(CHECK_INTERVAL)
            else:
                time.sleep(0.1)

# --- CLEANUP ---
def cleanup_elasticsearch_logs(days_old=60, es_index_url=ES_INDEX_URL, es_auth=ES_AUTH):
    cutoff = datetime.now() - timedelta(days=days_old)
    cutoff_iso = cutoff.strftime("%Y-%m-%dT%H:%M:%S")
    query = {"query": {"range": {"GeneratedTimeUTC": {"lt": cutoff_iso}}}}
    try:
        resp = requests.post(f"{es_index_url}/_delete_by_query", json=query, auth=es_auth)
        if resp.status_code in (200, 201):
            deleted = resp.json().get("deleted", 0)
            print(f"\n[INFO] Deleted {deleted} logs older than {days_old} days from Elasticsearch")
        else:
            print(f"\n[ERROR] ES cleanup failed: {resp.status_code} - {resp.text}")
    except Exception as e:
        print(f"[ERROR] Elasticsearch cleanup exception: {e}")

def schedule_cleanup(interval_hours=24, days_old=60):
    while not stop_cleanup_event.is_set():
        # File cleanup
        try:
            cutoff = datetime.now() - timedelta(days=days_old)
            if os.path.exists(OUTPUT_FILE):
                with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
                    for line in lines:
                        try:
                            log = json.loads(line)
                            log_time_str = log.get("GeneratedTimeUTC") or log.get("Time")
                            if log_time_str:
                                log_time = datetime.strptime(log_time_str, "%Y-%m-%d %H:%M:%S")
                                if log_time >= cutoff:
                                    f.write(line)
                        except Exception:
                            f.write(line)
        except Exception as e:
            print(f"[ERROR] File cleanup failed: {e}")
        # Elasticsearch cleanup
        try:
            cleanup_elasticsearch_logs(days_old=days_old)
        except Exception as e:
            print(f"[ERROR] Elasticsearch cleanup failed: {e}")
        time.sleep(interval_hours * 3600)

# --- STOP FLAG LISTENER ---
def listen_for_stop_file(flag_file, stop_event_obj, name="Thread"):
    while not stop_event_obj.is_set():
        if os.path.exists(flag_file):
            stop_event_obj.set()
            print(f"[INFO] {name} stopped via flag file: {flag_file}")
            try:
                os.remove(flag_file)
            except Exception:
                pass
            break
        time.sleep(1)

if __name__ == "__main__":
    
    try:

        def test_security_access():
            try:
                hand = win32evtlog.OpenEventLog("localhost", "Security")
                print("[TEST] OpenEventLog('Security') succeeded")
                try:
                    cnt = win32evtlog.GetNumberOfEventLogRecords(hand)
                    print(f"[TEST] Number of records: {cnt}")
                except Exception as e:
                    print(f"[TEST] Could not get record count: {e}")
            except pywintypes.error as e:
                print(f"[TEST] pywintypes.error opening Security log: {e}")
            except Exception as e:
                print(f"[TEST] Unexpected error opening Security log: {e}")

        if "--test-security" in sys.argv:
            test_security_access()
            sys.exit(0)
        # Set DEBUG global if requested
        if "--debug" in sys.argv:
            DEBUG = True

        threading.Thread(target=listen_for_stop_file,
                         args=("stop_cleanup.flag", stop_cleanup_event, "Cleanup Scheduler"),
                         daemon=True).start()
        threading.Thread(target=listen_for_stop_file,
                         args=("stop_monitor.flag", stop_event, "Monitor"),
                         daemon=True).start()
        threading.Thread(target=schedule_cleanup,
                         args=(CLEANUP_INTERVAL_HOURS,),
                         daemon=True).start()

        SELECT_READER = "windows"  # <-- change this line to monitor another reader
        SELECT_PATH = None  # e.g. "C:/path/to/logfile.log" for file/json readers 

        # Load plugin reader (except Windows which uses built-in function)
        if SELECT_READER.lower() == "windows":
            last_state = load_state()
            if last_state:
                print("Resuming from last saved state...")
                monitor_windows_event_logs()
            else:
                print("No saved state found, fetching newest logs first...")
                monitor_windows_event_logs(newest_first=False)
                print("Switching to forward monitoring...")
                monitor_windows_event_logs()
        else:
            try:
                ReaderClass = load_reader(SELECT_READER)

                # If file/json reader → require path
                if SELECT_READER.lower() in ("file", "json"):
                    if not SELECT_PATH:
                        raise ValueError(
                            f"Reader '{SELECT_READER}' requires SELECT_PATH to be set!"
                        )
                    reader = ReaderClass(SELECT_PATH)
                else:
                    # linux or other custom readers
                    reader = ReaderClass()

                monitor_with_reader(reader)

            except Exception as e:
                print(f"[FATAL] Could not load or run reader '{SELECT_READER}': {e}")
                raise


    except KeyboardInterrupt:
        print("\n[STOPPED] Monitoring stopped by user.")
        send_system_offline_email() 
        stop_event.set()   # signal workers to stop
        try:
            log_queue.join()
        except Exception:
            pass
        print("All threads stopped. Exiting cleanly.")

    except Exception as e:
        print(f"[FATAL] Unhandled exception: {e}")
        send_system_offline_email()



