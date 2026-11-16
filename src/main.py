import argparse
import json
import os

from parser import parse_log_file
from analyzer import LogAnalyzer
from detector import SecurityDetector
from reporter import ReportGenerator


def load_config(config_path="config.json"):
    if os.path.exists(config_path):
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"[WARN] Failed to load config: {e}")
    return {}


def process_logs(input_files, output_file, config):
    thresholds = config.get("security_threshold", config.get("security_thresholds", {}))
    failed_login_limit = thresholds.get("failed_login_threshold", 3)
    burst_threshold = thresholds.get("error_burst_threshold", 10)
    burst_window = thresholds.get("error_burst_window_minutes", 5)

    analyzer = LogAnalyzer()
    detector = SecurityDetector(
        failed_login_limit=failed_login_limit,
        error_burst_limit=burst_threshold,
        error_window_minutes=burst_window
    )

    total_valid = 0

    print("[*] Starting log analysis...")
    for filepath in input_files:
        if not os.path.exists(filepath):
            print(f"[ERROR] File not found: {filepath}")
            continue

        print(f"[*] Reading: {filepath}")
        for entry in parse_log_file(filepath):
            total_valid += 1
            analyzer.process_entry(entry)
            detector.process_entry(entry)

    summary = analyzer.get_summary()
    alerts = detector.get_alerts()

    reporter = ReportGenerator(output_path=output_file)
    report_data = reporter.build_report(
        log_summary=summary,
        alerts=alerts,
        source_files=input_files,
        stats={
            "valid_entries": total_valid,
            "total_offending_ips": len(summary.get("errors_by_ip", {})),
            "alerts_triggered": len(alerts)
        }
    )

    reporter.export_json(report_data)

    print("\n--- Summary ---")
    print(f"Valid log entries processed: {total_valid}")
    print(f"Log level counts: {summary['levels']}")
    print(f"Error count by IP: {summary['errors_by_ip']}")
    print(f"Security alerts: {len(alerts)}")
    for alert in alerts:
        print(f"  [{alert['severity']}] {alert['type']}: {alert['message']}")

    print(f"\nReport written to: {output_file}")


def main():
    parser = argparse.ArgumentParser(description="Log Monitoring & Analysis System")
    parser.add_argument("-i", "--input", nargs="+", default=None, help="Input log file(s)")
    parser.add_argument("-o", "--output", default=None, help="Output JSON file")
    parser.add_argument("-c", "--config", default="config.json", help="Path to config.json")

    args = parser.parse_args()
    config = load_config(args.config)

    input_files = args.input if args.input else [config.get("default_input_file", "sample.log")]
    output_file = args.output or config.get("default_output_file", "output_report.json")

    process_logs(input_files, output_file, config)


if __name__ == "__main__":
    main()