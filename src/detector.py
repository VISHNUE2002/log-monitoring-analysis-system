from collections import defaultdict, deque
from datetime import timedelta


class SecurityDetector:
    def __init__(self, failed_login_limit=3, error_burst_limit=10, error_window_minutes=5):
        self.failed_login_limit = failed_login_limit
        self.error_burst_limit = error_burst_limit
        self.error_window = timedelta(minutes=error_window_minutes)

        self.failed_logins = defaultdict(int)
        self.error_timestamps = deque()
        self.alerts = []
        self._alerted_ips = set()
        self._burst_alerted = False

    def process_entry(self, entry):
        message = entry.get("message", "").lower()
        level = entry.get("level", "")
        ip = entry.get("ip", "")
        timestamp = entry.get("timestamp")

        # 1. Detect failed login attempts
        if "failed login" in message and ip:
            self.failed_logins[ip] += 1
            if self.failed_logins[ip] >= self.failed_login_limit and ip not in self._alerted_ips:
                self.alerts.append({
                    "type": "REPEATED_FAILED_LOGINS",
                    "severity": "HIGH",
                    "ip": ip,
                    "count": self.failed_logins[ip],
                    "message": f"IP {ip} exceeded failed login threshold with {self.failed_logins[ip]} attempts"
                })
                self._alerted_ips.add(ip)

        # 2. Detect error burst (> 10 errors in 5 min)
        if level == "ERROR" and timestamp:
            self.error_timestamps.append(timestamp)

            # Slide window: evict errors older than 5 minutes
            while self.error_timestamps and (timestamp - self.error_timestamps[0]) > self.error_window:
                self.error_timestamps.popleft()

            if len(self.error_timestamps) > self.error_burst_limit and not self._burst_alerted:
                self.alerts.append({
                    "type": "HIGH_ERROR_BURST",
                    "severity": "CRITICAL",
                    "count": len(self.error_timestamps),
                    "window_minutes": int(self.error_window.total_seconds() / 60),
                    "message": f"Exceeded {self.error_burst_limit} errors within {int(self.error_window.total_seconds() / 60)} minutes"
                })
                self._burst_alerted = True

    def get_alerts(self):
        return self.alerts


if __name__ == "__main__":
    from parser import parse_log_file

    detector = SecurityDetector()
    for entry in parse_log_file("sample.log"):
        detector.process_entry(entry)

    print("Detected Security Alerts:")
    for alert in detector.get_alerts():
        print(f"[{alert['severity']}] {alert['type']}: {alert['message']}")