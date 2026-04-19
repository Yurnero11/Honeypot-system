import pandas as pd
import re
from pathlib import Path

LOG_PATTERN = re.compile(
    r"^(\d{4}-\d{2}-\d{2})\s(\d{2}:\d{2}:\d{2},\d{3})\s\[(\w+)\]\s\[([\w-]+)\]\s(.*)$"
)


def parse_log_file(file_path):
    records = []
    service = Path(file_path).stem.upper()
    is_system_log = service == 'SYSTEM'

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                match = LOG_PATTERN.match(line)
                if not match:
                    continue

                date, time, level, logger_name, message = match.groups()

                ip_address = 'N/A'
                event_type = 'Other'
                mitre_techniques = []

                if not is_system_log:
                    ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', message)
                    ip_address = ip_match.group(1) if ip_match else 'N/A'

                    event_match = re.search(r'\[(START|ACCESS|ATTACK|CMD|AUTH SUCCESS|DISCONNECT|ERROR)\]', message)
                    event_type = event_match.group(1) if event_match else 'Other'

                    mitre_match = re.search(r'Detected MITRE techniques: \[(.*?)\]', message)
                    if mitre_match:
                        mitre_techniques = [t.strip() for t in mitre_match.group(1).replace("'", "").split(', ')]

                records.append({
                    'timestamp': f"{date} {time}",
                    'service': service,
                    'level': level,
                    'logger': logger_name,
                    'ip_address': ip_address,
                    'event': event_type,
                    'mitre': mitre_techniques,
                    'full_message': message.strip()
                })
    except FileNotFoundError:
        print(f"[WARNING] Log file not found: {file_path}")
        return []

    return records


def get_all_honeypot_data(log_files=['logs/raw/http.log', 'logs/raw/ssh.log', 'logs/raw/redis.log', 'logs/raw/system.log']):
    all_data = []
    for f in log_files:
        if Path(f).exists():
            all_data.extend(parse_log_file(f))

    df = pd.DataFrame(all_data)

    df = df[~df['event'].isin(['START', 'DISCONNECT'])]

    df['is_ioc'] = df['level'] == 'WARNING'

    return df