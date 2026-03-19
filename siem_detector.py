"""
SIEM-style simple detection engine (Python)

Features:
 - Parses raw log lines (generic/SSH/HTTP-like examples supported by regex)
 - Normalizes events to: timestamp (datetime), src_ip, user, outcome (success/fail), service
 - Tracks events per-IP and per-user using sliding time windows
 - Detects:
     1) IP-based brute force: >= IP_FAILURE_THRESHOLD fails from same IP within IP_WINDOW seconds
     2) Account brute force: >= USER_FAILURE_THRESHOLD fails for same user within USER_WINDOW seconds
     3) Password spray: same IP fails against >= SPRAY_USER_UNIQUE unique usernames within SPRAY_WINDOW seconds
     4) Successful after multiple failures (COMPROMISE_PATTEN): success within FOLLOWUP_WINDOW after N prior fails
 - Produces a JSON-like summary of findings and sample evidence lines.

Notes:
 - Thresholds/time windows are configurable constants below.
 - Detection logic is intentionally simple but follows common SIEM correlation patterns
   (examples and approaches commonly used in Wazuh/Splunk/Elastic). See references in README.
"""

from collections import defaultdict, deque, Counter
from datetime import datetime, timedelta
import re
import json

# -------- CONFIGURABLE THRESHOLDS ----------
IP_FAILURE_THRESHOLD = 5         
IP_WINDOW = timedelta(seconds=60) 

USER_FAILURE_THRESHOLD = 5
USER_WINDOW = timedelta(minutes=5)
SPRAY_USER_UNIQUE = 5
SPRAY_WINDOW = timedelta(hours=1)  

FOLLOWUP_FAILURES = 4
FOLLOWUP_WINDOW = timedelta(minutes=15) 

# ----------------------------------------------------------------------


TIMESTAMP_FORMATS = [
    "%b %d %H:%M:%S",         
    "%Y-%m-%dT%H:%M:%S",      
    "%Y-%m-%d %H:%M:%S",      


RE_IP = re.compile(r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})")

RE_USER = re.compile(r"(?:user(?:name)?=|'user'?:\s*\"?)(?P<user>[\w@.\-]+)|invalid user (?P<user2>[\w@.\-]+)|for user (?P<user3>[\w@.\-]+)")

RE_FAIL = re.compile(r"(failed|failure|authentication failure|invalid user|password mismatch|authentication failure)", re.I)
RE_SUCCESS = re.compile(r"(accepted|success|logged in|authentication succeeded|session opened)", re.I)

RE_ISO_TS = re.compile(r"(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})")

def try_parse_timestamp(s):
  
    m = RE_ISO_TS.search(s)
    if m:
        try:
            return datetime.fromisoformat(m.group("ts"))
        except Exception:
            pass
 
    for fmt in TIMESTAMP_FORMATS:
        try:
            m = re.search(r"[A-Za-z0-9:\- ]{" + str(len(fmt)+2) + "}", s)
            if m:
                ts_candidate = m.group(0)
         
                if "%Y" not in fmt:
                    ts = datetime.strptime(ts_candidate.strip(), fmt)
                    ts = ts.replace(year=datetime.now().year)
                else:
                    ts = datetime.strptime(ts_candidate.strip(), fmt)
                return ts
        except Exception:
            continue
 
    return datetime.now()

def parse_log_line(line):
    """
    Parse a single raw log line; return normalized event dict or None.
    This parser is heuristic — adapt to your logs for best results.
    """
    raw = line.strip()
    ts = try_parse_timestamp(raw)

    ip_m = RE_IP.search(raw)
    ip = ip_m.group("ip") if ip_m else "unknown"

    user_m = RE_USER.search(raw)
    user = None
    if user_m:
        user = user_m.group("user") or user_m.group("user2") or user_m.group("user3")
    if not user:
       
        m2 = re.search(r"for user (?P<u>[\w@.\-]+)", raw, re.I)
        if m2:
            user = m2.group("u")

    outcome = None
    if RE_FAIL.search(raw):
        outcome = "FAIL"
    elif RE_SUCCESS.search(raw):
        outcome = "SUCCESS"
    else:
       
        mstatus = re.search(r"\bHTTP/\d+\.\d+\"\s*(?P<code>\d{3})", raw)
        if mstatus:
            code = int(mstatus.group("code"))
            if 200 <= code < 400:
                outcome = "SUCCESS"
            else:
                outcome = "FAIL"

    
    service = "generic"
    if "sshd" in raw or "ssh" in raw.lower():
        service = "ssh"
    elif "rdp" in raw.lower() or "mstsc" in raw.lower():
        service = "rdp"
    elif "login" in raw.lower() or "auth" in raw.lower():
        service = "auth"
    elif "HTTP" in raw or "GET " in raw or "POST " in raw:
        service = "http"

    event = {
        "ts": ts,
        "src_ip": ip,
        "user": user if user else "unknown",
        "outcome": outcome if outcome else "UNKNOWN",
        "service": service,
        "raw": raw
    }
    return event

class Detector:
    def __init__(self):
       
        self.ip_fails = defaultdict(deque)
       
        self.user_fails = defaultdict(deque)
        
        self.ip_user_attempts = defaultdict(deque)
       
        self.recent_fail_history = defaultdict(deque)

       
        self.findings = []

    def ingest_event(self, event):
        ts = event["ts"]
        ip = event["src_ip"]
        user = event["user"]
        outcome = event["outcome"]

       
        if outcome == "UNKNOWN":
            return

      
        if outcome == "FAIL":
            
            dq = self.ip_fails[ip]
            dq.append(ts)
            
            while dq and (ts - dq[0]) > IP_WINDOW:
                dq.popleft()
            if len(dq) >= IP_FAILURE_THRESHOLD:
               
                self._raise_finding(
                    kind="IP_BRUTE_FORCE",
                    ts=ts,
                    src_ip=ip,
                    user=user,
                    evidence=f"{len(dq)} failures from {ip} within {IP_WINDOW}"
                )

           
            udq = self.user_fails[user]
            udq.append(ts)
            while udq and (ts - udq[0]) > USER_WINDOW:
                udq.popleft()
            if len(udq) >= USER_FAILURE_THRESHOLD:
                self._raise_finding(
                    kind="ACCOUNT_BRUTE_FORCE",
                    ts=ts,
                    src_ip=ip,
                    user=user,
                    evidence=f"{len(udq)} failures for user {user} within {USER_WINDOW}"
                )

            
            ipdq = self.ip_user_attempts[ip]
            ipdq.append((ts, user))
            
            while ipdq and (ts - ipdq[0][0]) > SPRAY_WINDOW:
                ipdq.popleft()
            unique_users = set(u for _, u in ipdq)
            if len(unique_users) >= SPRAY_USER_UNIQUE:
                self._raise_finding(
                    kind="PASSWORD_SPRAY",
                    ts=ts,
                    src_ip=ip,
                    user=None,
                    evidence=f"{len(unique_users)} distinct usernames tried from {ip} within {SPRAY_WINDOW}"
                )

            
            key = (user, ip)
            h = self.recent_fail_history[key]
            h.append(ts)
           
            while h and (ts - h[0]) > FOLLOWUP_WINDOW:
                h.popleft()

        elif outcome == "SUCCESS":
           
            key = (user, ip)
            h = self.recent_fail_history.get(key, deque())
          
            while h and (event["ts"] - h[0]) > FOLLOWUP_WINDOW:
                h.popleft()
            if len(h) >= FOLLOWUP_FAILURES:
                self._raise_finding(
                    kind="SUCCESS_AFTER_FAILS",
                    ts=ts,
                    src_ip=ip,
                    user=user,
                    evidence=f"Successful login for {user} from {ip} after {len(h)} recent failures within {FOLLOWUP_WINDOW}"
                )
            
            if key in self.recent_fail_history:
                del self.recent_fail_history[key]

    def _raise_finding(self, kind, ts, src_ip, user, evidence):
        f = {
            "kind": kind,
            "time": ts.isoformat(),
            "src_ip": src_ip,
            "user": user,
            "evidence": evidence
        }
       
        if self.findings and self.findings[-1]["kind"] == kind and self.findings[-1]["src_ip"] == src_ip and self.findings[-1]["user"] == user:
            
            return
        self.findings.append(f)

    def summary(self):
        return {"findings": self.findings}


def main():
    detector = Detector()

    sample_logs = [
        127.0.0.1 - - [16/Oct/2025 03:06:27] "GET / HTTP/1.1" 302 -
127.0.0.1 - - [16/Oct/2025 03:06:27] "GET /login HTTP/1.1" 200 -
127.0.0.1 - - [16/Oct/2025 03:06:29] "GET /static/style.css HTTP/1.1" 200 -
127.0.0.1 - - [16/Oct/2025 03:06:29] "GET /favicon.ico HTTP/1.1" 404 -
127.0.0.1 - - [16/Oct/2025 03:09:12] "POST /login HTTP/1.1" 200 -
127.0.0.1 - - [16/Oct/2025 03:09:17] "GET /login HTTP/1.1" 200 -
127.0.0.1 - - [16/Oct/2025 03:09:26] "POST /login HTTP/1.1" 200 -
127.0.0.1 - - [16/Oct/2025 03:09:30] "GET /login HTTP/1.1" 200 -
127.0.0.1 - - [16/Oct/2025 03:09:32] "GET /signup HTTP/1.1" 200 -
127.0.0.1 - - [16/Oct/2025 03:09:33] "GET /static/style.css HTTP/1.1" 304 -
127.0.0.1 - - [16/Oct/2025 03:09:48] "POST /signup HTTP/1.1" 302 -
127.0.0.1 - - [16/Oct/2025 03:09:48] "GET /login HTTP/1.1" 200 -
127.0.0.1 - - [16/Oct/2025 03:09:48] "GET /static/style.css HTTP/1.1" 304 -
127.0.0.1 - - [16/Oct/2025 03:09:59] "POST /login HTTP/1.1" 302 -
127.0.0.1 - - [16/Oct/2025 03:09:59] "GET /home HTTP/1.1" 200 -
127.0.0.1 - - [16/Oct/2025 03:09:59] "GET /static/style.css HTTP/1.1" 304 -
127.0.0.1 - - [16/Oct/2025 03:10:06] "GET /logout HTTP/1.1" 302 -
127.0.0.1 - - [16/Oct/2025 03:10:06] "GET /login HTTP/1.1" 200 -
127.0.0.1 - - [16/Oct/2025 03:10:06] "GET /static/style.css HTTP/1.1" 304 -
127.0.0.1 - - [16/Oct/2025 03:13:58] "POST /login HTTP/1.1" 200 -
127.0.0.1 - - [16/Oct/2025 03:20:19] "GET /login HTTP/1.0" 200 -
127.0.0.1 - - [16/Oct/2025 03:20:19] "GET /login HTTP/1.0" 200 -
127.0.0.1 - - [16/Oct/2025 03:20:19] "GET /login HTTP/1.0" 200 -
127.0.0.1 - - [16/Oct/2025 03:20:19] "GET /login HTTP/1.0" 200 -
127.0.0.1 - - [16/Oct/2025 03:20:19] "GET /login HTTP/1.0" 200 -
127.0.0.1 - - [16/Oct/2025 03:20:19] "GET /login HTTP/1.0" 200 -
127.0.0.1 - - [16/Oct/2025 03:20:19] "GET /login HTTP/1.0" 200 -
127.0.0.1 - - [16/Oct/2025 03:20:19] "GET /login HTTP/1.0" 200 -
127.0.0.1 - - [16/Oct/2025 03:20:19] "GET /login HTTP/1.0" 200 -
127.0.0.1 - - [16/Oct/2025 03:20:19] "GET /login HTTP/1.0" 200 -
127.0.0.1 - - [16/Oct/2025 03:20:19] "GET /login HTTP/1.0" 200 -
127.0.0.1 - - [16/Oct/2025 03:20:19] "GET /login HTTP/1.0" 200 -
127.0.0.1 - - [16/Oct/2025 03:20:19] "GET /login HTTP/1.0" 200 -
127.0.0.1 - - [16/Oct/2025 03:20:19] "GET /login HTTP/1.0" 200 -
127.0.0.1 - - [16/Oct/2025 03:20:19] "GET /login HTTP/1.0" 200 -
127.0.0.1 - - [16/Oct/2025 03:20:19] "GET /login HTTP/1.0" 200 -
127.0.0.1 - - [16/Oct/2025 03:20:19] "POST /login HTTP/1.0" 302 -
127.0.0.1 - - [16/Oct/2025 03:20:19] "POST /login HTTP/1.0" 200 -
127.0.0.1 - - [16/Oct/2025 03:20:19] "POST /login HTTP/1.0" 200 -
127.0.0.1 - - [16/Oct/2025 03:20:19] "POST /login HTTP/1.0" 200 -
127.0.0.1 - - [16/Oct/2025 03:20:19] "POST /login HTTP/1.0" 200 -
127.0.0.1 - - [16/Oct/2025 03:20:19] "POST /login HTTP/1.0" 200 -
127.0.0.1 - - [16/Oct/2025 03:20:19] "POST /login HTTP/1.0" 200 -
127.0.0.1 - - [16/Oct/2025 03:20:19] "POST /login HTTP/1.0" 200 -
127.0.0.1 - - [16/Oct/2025 03:20:19] "POST /login HTTP/1.0" 200 -
127.0.0.1 - - [16/Oct/2025 03:20:19] "POST /login HTTP/1.0" 200 -
127.0.0.1 - - [16/Oct/2025 03:20:19] "POST /login HTTP/1.0" 200 -
127.0.0.1 - - [16/Oct/2025 03:20:19] "POST /login HTTP/1.0" 200 -
127.0.0.1 - - [16/Oct/2025 03:20:19] "POST /login HTTP/1.0" 200 -
127.0.0.1 - - [16/Oct/2025 03:20:19] "GET /home HTTP/1.0" 200 -
127.0.0.1 - - [16/Oct/2025 03:20:19] "POST /login HTTP/1.0" 200 -
127.0.0.1 - - [16/Oct/2025 03:20:19] "POST /login HTTP/1.0" 200 -
127.0.0.1 - - [16/Oct/2025 03:20:19] "POST /login HTTP/1.0" 200 -
127.0.0.1 - - [16/Oct/2025 03:20:20] "GET /login HTTP/1.0" 200 -
127.0.0.1 - - [16/Oct/2025 03:20:20] "GET /login HTTP/1.0" 200 -
127.0.0.1 - - [16/Oct/2025 03:20:20] "GET /login HTTP/1.0" 200 -
127.0.0.1 - - [16/Oct/2025 03:20:20] "GET /login HTTP/1.0" 200 -
127.0.0.1 - - [16/Oct/2025 03:20:20] "GET /login HTTP/1.0" 200 -
127.0.0.1 - - [16/Oct/2025 03:20:20] "GET /login HTTP/1.0" 200 -
127.0.0.1 - - [16/Oct/2025 03:20:20] "GET /login HTTP/1.0" 200 -
127.0.0.1 - - [16/Oct/2025 03:20:20] "GET /login HTTP/1.0" 200 -
127.0.0.1 - - [16/Oct/2025 03:20:20] "GET /login HTTP/1.0" 200 -
127.0.0.1 - - [16/Oct/2025 03:20:20] "GET /login HTTP/1.0" 200 -
127.0.0.1 - - [16/Oct/2025 03:20:20] "GET /login HTTP/1.0" 200 -
127.0.0.1 - - [16/Oct/2025 03:20:20] "GET /login HTTP/1.0" 200 -
127.0.0.1 - - [16/Oct/2025 03:20:20] "GET /login HTTP/1.0" 200 -
127.0.0.1 - - [16/Oct/2025 03:20:20] "POST /login HTTP/1.0" 200 -
127.0.0.1 - - [16/Oct/2025 03:20:20] "GET /login HTTP/1.0" 200 -
127.0.0.1 - - [16/Oct/2025 03:20:20] "POST /login HTTP/1.0" 200 -
127.0.0.1 - - [16/Oct/2025 03:20:20] "POST /login HTTP/1.0" 200 -
127.0.0.1 - - [16/Oct/2025 03:20:20] "POST /login HTTP/1.0" 200 -
127.0.0.1 - - [16/Oct/2025 03:20:20] "POST /login HTTP/1.0" 200 -
127.0.0.1 - - [16/Oct/2025 03:20:20] "GET /login HTTP/1.0" 200 -
127.0.0.1 - - [16/Oct/2025 03:20:20] "POST /login HTTP/1.0" 200 -
127.0.0.1 - - [16/Oct/2025 03:20:20] "POST /login HTTP/1.0" 200 -
127.0.0.1 - - [16/Oct/2025 03:20:20] "POST /login HTTP/1.0" 200 -
127.0.0.1 - - [16/Oct/2025 03:20:20] "POST /login HTTP/1.0" 200 -
127.0.0.1 - - [16/Oct/2025 03:20:20] "POST /login HTTP/1.0" 200 -

    ]

   
    for line in sample_logs:
        evt = parse_log_line(line)
        if evt:
            detector.ingest_event(evt)

    out = detector.summary()
    print(json.dumps(out, indent=2))

if __name__ == "__main__":
    main()
