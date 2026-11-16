import json
from datetime import datetime


class ReportGenerator:
    def __init__(self, output_path="output_report.json"):
        self.output_path = output_path

    def build_report(self, log_summary, alerts, source_files, stats=None):
        report = {
            "metadata": {
                "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "source_files": source_files if isinstance(source_files, list) else [source_files],
                "system_status": "ALERTS_DETECTED" if alerts else "HEALTHY"
            },
            "processing_stats": stats or {},
            "log_level_distribution": log_summary.get("levels", {}),
            "errors_by_ip": log_summary.get("errors_by_ip", {}),
            "security_alerts": alerts
        }
        return report

    def export_json(self, report_data):
        with open(self.output_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=4)
        return self.output_path