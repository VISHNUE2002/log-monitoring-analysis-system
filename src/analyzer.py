from collections import defaultdict


class LogAnalyzer:
    def __init__(self):
        self.level_counts = defaultdict(int)
        self.ip_errors = defaultdict(int)
        self.total_logs = 0

    def process_entry(self, entry):
        self.total_logs += 1
        
        level = entry.get("level", "UNKNOWN")
        self.level_counts[level] += 1

        if level == "ERROR":
            ip = entry.get("ip")
            if ip:
                self.ip_errors[ip] += 1

    def get_summary(self):
        return {
            "total_logs": self.total_logs,
            "levels": dict(self.level_counts),
            "errors_by_ip": dict(self.ip_errors)
        }


if __name__ == "__main__":
    from parser import parse_log_file

    analyzer = LogAnalyzer()
    for entry in parse_log_file("sample.log"):
        analyzer.process_entry(entry)

    print("Analysis Results:")
    print(analyzer.get_summary())