import re
import pandas as pd
from datetime import timedelta

# ===============================
# LOG PARSING (TXT → EXCEL)
# ===============================

# Updated regex for CLEAN log format
LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) - - \[(?P<time>.*?)\] '
    r'"(?P<method>\S+) (?P<url>.*?) (?P<protocol>HTTP/\d\.\d)" '
    r'(?P<status>\d+) -'
)

def txt_to_excel(log_file, excel_file):
    records = []

    with open(log_file, "r") as f:
        for line in f:
            match = LOG_PATTERN.search(line)
            if match:
                records.append(match.groupdict())

    df = pd.DataFrame(records)

    # Convert timestamp
    df["time"] = pd.to_datetime(df["time"], format="%d/%b/%Y %H:%M:%S")

    df.to_excel(excel_file, index=False)
    print("Logs parsed and stored in Excel:", excel_file)
    return df


# ===============================
# RULE-BASED DETECTIONS
# ===============================

# 1️⃣ Brute Force: repeated /login access
def detect_bruteforce(df):
    alerts = {}

    login_hits = df[df["url"].str.contains("/login", case=False)]

    for ip, group in login_hits.groupby("ip"):
        group = group.sort_values("time")
        for i in range(len(group)):
            window = group.iloc[i:i+5]
            if len(window) == 5 and window["time"].max() - window["time"].min() <= timedelta(minutes=1):
                alerts[ip] = "Brute Force Attack"
                break

    return [(ip, attack) for ip, attack in alerts.items()]


# 2️⃣ SQL Injection
def detect_sql_injection(df):
    sql_regex = re.compile(
        r"(\bor\b\s+['\"]?1['\"]?\s*=\s*['\"]?1|\bunion\b\s+\bselect\b|--)",
        re.IGNORECASE
    )

    alerts = {}

    for _, r in df.iterrows():
        combined = f"{r['url']} {r['protocol']}".lower()
        if sql_regex.search(combined):
            alerts[r["ip"]] = "SQL Injection Attack"

    return [(ip, attack) for ip, attack in alerts.items()]


# 3️⃣ XSS
def detect_xss(df):
    patterns = ["<script", "javascript:", "onerror=", "onload="]
    alerts = {}

    for _, r in df.iterrows():
        if any(p in r["url"].lower() for p in patterns):
            alerts[r["ip"]] = "XSS Attack"

    return [(ip, attack) for ip, attack in alerts.items()]


# 4️⃣ Path Traversal
def detect_path_traversal(df):
    patterns = ["../", "%2e%2e%2f", "..%2f"]
    alerts = {}

    for _, r in df.iterrows():
        if any(p in r["url"].lower() for p in patterns):
            alerts[r["ip"]] = "Path Traversal Attack"

    return [(ip, attack) for ip, attack in alerts.items()]


# 5️⃣ Scanner / Reconnaissance (URL-based)
def detect_scanners(df):
    scan_paths = ["/admin", "/phpinfo", "/config", "/.env"]
    alerts = {}

    for _, r in df.iterrows():
        if any(p in r["url"].lower() for p in scan_paths):
            alerts[r["ip"]] = "Scanner Detected"

    return [(ip, attack) for ip, attack in alerts.items()]


# ===============================
# SIEM RULE ENGINE (PRIORITY)
# ===============================

def run_siem(df):
    alert_map = {}

    for ip, attack in detect_bruteforce(df):
        alert_map[ip] = attack

    for ip, attack in detect_sql_injection(df):
        alert_map[ip] = attack

    for ip, attack in detect_xss(df):
        alert_map[ip] = attack

    for ip, attack in detect_path_traversal(df):
        alert_map[ip] = attack

    # Scanner = lowest priority
    for ip, attack in detect_scanners(df):
        if ip not in alert_map:
            alert_map[ip] = attack

    return [(ip, attack) for ip, attack in alert_map.items()]


# ===============================
# SAVE ALERTS TO EXCEL
# ===============================

def save_alerts_to_excel(alerts, filename="siem_alerts.xlsx"):
    df_alerts = pd.DataFrame(alerts, columns=["IP Address", "Attack Type"])
    df_alerts = df_alerts.drop_duplicates()
    df_alerts.to_excel(filename, index=False)
    print("SIEM alerts stored in Excel:", filename)


# ===============================
# MAIN
# ===============================

if __name__ == "__main__":
    print("Starting SIEM Rule Engine...")

    df = txt_to_excel("web_logs_localhost_style.txt", "web_logs.xlsx")
    #df = txt_to_excel("logs_file_imon.txt", "web_logs.xlsx")

    alerts = run_siem(df)

    save_alerts_to_excel(alerts)

    print("SIEM analysis completed successfully.")