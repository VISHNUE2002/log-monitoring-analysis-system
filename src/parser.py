import re
from datetime import datetime

# Regex pattern for: YYYY-MM-DD HH:MM:SS [LEVEL] IP - Message
LOG_REGEX = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \[([A-Z]+)\] (\d{1,3}(?:\.\d{1,3}){3}) - (.*)$")

def parse_line(line):
    line = line.strip()
    if not line:
        return None
    
    match = LOG_REGEX.match(line)
    if not match:
        return None
    
    timestamp_str, level, ip, message = match.groups()
    try:
        dt = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None
        
    return {
        "timestamp": dt,
        "level": level,
        "ip": ip,
        "message": message
    }

def parse_log_file(filepath):
    total = 0
    valid = 0
    invalid = 0
    
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if not line.strip():
                continue
            total += 1
            entry = parse_line(line)
            if entry:
                valid += 1
                yield entry
            else:
                invalid += 1

if __name__ == "__main__":
    count = 0
    for log in parse_log_file("sample.log"):
        count += 1
        print(f"[{log['level']}] {log['ip']} -> {log['message']}")
    print(f"\nTotal valid logs parsed: {count}")