"""
Report Generation Service
Generates compliance and anomaly detection reports in HTML format
with SHA-256 hash signatures for tamper-proof audit trail
"""
import hashlib
import uuid
from datetime import datetime
from typing import List, Optional, Dict, Any


class ReportGenerator:
    """
    Generates compliance and anomaly detection reports in HTML format.
    Reports are signed with SHA-256 hashing for tamper-proof auditing.
    """

    BRANDING_CSS = """
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 0;
            background: #f4f6f9;
            color: #333;
        }
        .report-container {
            max-width: 900px;
            margin: 30px auto;
            background: #fff;
            border-radius: 8px;
            box-shadow: 0 2px 12px rgba(0,0,0,0.08);
            overflow: hidden;
        }
        .report-header {
            background: linear-gradient(135deg, #1a237e, #283593);
            color: #fff;
            padding: 30px 40px;
        }
        .report-header h1 {
            margin: 0 0 5px 0;
            font-size: 28px;
        }
        .report-header .subtitle {
            opacity: 0.85;
            font-size: 14px;
        }
        .report-meta {
            display: flex;
            justify-content: space-between;
            padding: 15px 40px;
            background: #e8eaf6;
            font-size: 13px;
            color: #555;
        }
        .report-body {
            padding: 30px 40px;
        }
        .section {
            margin-bottom: 30px;
        }
        .section h2 {
            color: #1a237e;
            border-bottom: 2px solid #e8eaf6;
            padding-bottom: 8px;
            font-size: 20px;
        }
        .score-badge {
            display: inline-block;
            padding: 6px 18px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 16px;
            color: #fff;
        }
        .score-high { background: #2e7d32; }
        .score-medium { background: #f57f17; }
        .score-low { background: #c62828; }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }
        th, td {
            text-align: left;
            padding: 10px 12px;
            border-bottom: 1px solid #eee;
        }
        th {
            background: #f5f5f5;
            font-weight: 600;
            font-size: 13px;
            text-transform: uppercase;
            color: #666;
        }
        .status-pass { color: #2e7d32; font-weight: bold; }
        .status-fail { color: #c62828; font-weight: bold; }
        .risk-critical { color: #b71c1c; font-weight: bold; }
        .risk-high { color: #e65100; font-weight: bold; }
        .risk-medium { color: #f57f17; font-weight: bold; }
        .risk-low { color: #2e7d32; font-weight: bold; }
        .signature-block {
            margin-top: 40px;
            padding: 20px;
            background: #f5f5f5;
            border: 1px dashed #ccc;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 12px;
            color: #666;
            word-break: break-all;
        }
        .recommendations {
            background: #fff3e0;
            border-left: 4px solid #ff9800;
            padding: 15px 20px;
            margin-top: 10px;
        }
        .recommendations li {
            margin-bottom: 6px;
        }
        .audit-status {
            padding: 12px 20px;
            border-radius: 6px;
            font-weight: bold;
        }
        .audit-valid { background: #e8f5e9; color: #2e7d32; }
        .audit-invalid { background: #ffebee; color: #c62828; }
    """

    @staticmethod
    def sign_report(report_content: str) -> str:
        """
        Generate SHA-256 hash signature for tamper-proofing.

        Args:
            report_content: The full report content to sign

        Returns:
            SHA-256 hex digest string
        """
        return hashlib.sha256(report_content.encode("utf-8")).hexdigest()

    @staticmethod
    def _score_class(score: float) -> str:
        if score >= 80:
            return "score-high"
        elif score >= 50:
            return "score-medium"
        return "score-low"

    @staticmethod
    def _risk_class(severity: str) -> str:
        return f"risk-{severity.lower()}"

    def _html_skeleton(self, title: str, subtitle: str, report_id: str,
                       timestamp: str, body_html: str) -> str:
        """Build a complete self-contained HTML document."""
        content_for_signing = body_html + timestamp + report_id
        signature = self.sign_report(content_for_signing)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title} - CloudTwin AI</title>
<style>{self.BRANDING_CSS}</style>
</head>
<body>
<div class="report-container">
    <div class="report-header">
        <h1>CloudTwin AI</h1>
        <div class="subtitle">{subtitle}</div>
    </div>
    <div class="report-meta">
        <span><strong>Report ID:</strong> {report_id}</span>
        <span><strong>Generated:</strong> {timestamp}</span>
    </div>
    <div class="report-body">
        {body_html}
        <div class="signature-block">
            <strong>SHA-256 Report Signature (Tamper-Proof Seal)</strong><br><br>
            {signature}
        </div>
    </div>
</div>
</body>
</html>"""

    
    # Compliance Report
    

    def generate_compliance_report(
        self,
        compliance_results: Any,
        format: str = "html",
    ) -> Dict[str, str]:
        """
        Generate a compliance report for one or more resources.

        Args:
            compliance_results: A single ComplianceResult or a list of them,
                                or a dict from the /compliance/ all-buckets endpoint.
            format: 'html' (default)

        Returns:
            dict with keys 'content', 'signature', 'report_id'
        """
        report_id = f"CR-{uuid.uuid4().hex[:12].upper()}"
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

        # Normalise input
        results = self._normalise_compliance(compliance_results)

        body_parts: List[str] = []
        body_parts.append("<div class='section'><h2>Compliance Assessment</h2>")

        if not results:
            body_parts.append("<p>No compliance data available.</p></div>")
        else:
            overall_score = sum(r.get("compliance_score", 0) for r in results) / len(results)
            body_parts.append(
                f"<p>Overall compliance score: "
                f"<span class='score-badge {self._score_class(overall_score)}'>"
                f"{overall_score:.1f}%</span></p>"
            )
            body_parts.append(self._compliance_table(results))
            body_parts.append("</div>")

            # Recommendations
            all_recs = []
            for r in results:
                all_recs.extend(r.get("recommendations", []))
            if all_recs:
                body_parts.append("<div class='section'><h2>Recommendations</h2>")
                body_parts.append("<div class='recommendations'><ul>")
                for rec in all_recs:
                    body_parts.append(f"<li>{rec}</li>")
                body_parts.append("</ul></div></div>")

        body_html = "\n".join(body_parts)
        html = self._html_skeleton(
            "Compliance Report", "Cloud Compliance Assessment Report",
            report_id, timestamp, body_html,
        )
        signature = self.sign_report(body_html + timestamp + report_id)
        return {"content": html, "signature": signature, "report_id": report_id}

    def _compliance_table(self, results: List[Dict]) -> str:
        """Render compliance checks as an HTML table with control references."""
        control_map = {
            "encryption": "ISO 27001 A.10.1 / NIST SC-28",
            "versioning": "ISO 27001 A.12.3 / NIST CP-9",
            "public_access": "ISO 27001 A.13.1 / NIST AC-3",
            "logging": "ISO 27001 A.12.4 / NIST AU-2",
            "lifecycle": "ISO 27001 A.12.1 / NIST SI-12",
        }
        rows: List[str] = []
        for r in results:
            resource = r.get("resource_name", "unknown")
            checks = r.get("checks", {})
            for check_name, check in checks.items():
                if isinstance(check, dict):
                    status = check.get("status", "N/A")
                    message = check.get("message", "")
                    severity = check.get("severity", "medium")
                else:
                    status = check.status
                    message = check.message
                    severity = check.severity
                status_cls = "status-pass" if status == "PASS" else "status-fail"
                control_ref = check.get("control_reference", control_map.get(check_name, "N/A")) if isinstance(check, dict) else control_map.get(check_name, "N/A")
                rows.append(
                    f"<tr>"
                    f"<td>{resource}</td>"
                    f"<td>{check_name}</td>"
                    f"<td class='{status_cls}'>{status}</td>"
                    f"<td>{message}</td>"
                    f"<td class='{self._risk_class(severity)}'>{severity.upper()}</td>"
                    f"<td>{control_ref}</td>"
                    f"</tr>"
                )
        return (
            "<table>"
            "<tr><th>Resource</th><th>Check</th><th>Status</th>"
            "<th>Details</th><th>Severity</th><th>Control Reference</th></tr>"
            + "".join(rows)
            + "</table>"
        )

    @staticmethod
    def _normalise_compliance(data: Any) -> List[Dict]:
        """Accept various shapes of compliance data and return a list of dicts."""
        if isinstance(data, list):
            out = []
            for item in data:
                out.append(item if isinstance(item, dict) else item.dict() if hasattr(item, "dict") else vars(item))
            return out
        if isinstance(data, dict):
            if "results" in data:
                return [
                    r if isinstance(r, dict) else r.dict() if hasattr(r, "dict") else vars(r)
                    for r in data["results"]
                ]
            return [data]
        if hasattr(data, "dict"):
            return [data.dict()]
        return []

    
    # Anomaly Detection Report
    

    def generate_anomaly_report(
        self,
        anomaly_results: Any,
        format: str = "html",
    ) -> Dict[str, str]:
        """
        Generate an anomaly detection report.

        Args:
            anomaly_results: List of AnomalyDetectionResult dicts/objects
            format: 'html' (default)

        Returns:
            dict with keys 'content', 'signature', 'report_id'
        """
        report_id = f"AR-{uuid.uuid4().hex[:12].upper()}"
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

        results = self._normalise_anomaly(anomaly_results)

        body_parts: List[str] = []
        body_parts.append("<div class='section'><h2>Anomaly Detection Summary</h2>")

        if not results:
            body_parts.append(
                "<p>No anomalies detected or anomaly detection data unavailable.</p></div>"
            )
        else:
            total = len(results)
            critical = sum(1 for r in results if r.get("risk_level", "").lower() == "critical")
            high = sum(1 for r in results if r.get("risk_level", "").lower() == "high")
            medium = sum(1 for r in results if r.get("risk_level", "").lower() == "medium")
            low = sum(1 for r in results if r.get("risk_level", "").lower() == "low")

            body_parts.append(
                f"<p>Total anomalies: <strong>{total}</strong> &mdash; "
                f"<span class='risk-critical'>Critical: {critical}</span> | "
                f"<span class='risk-high'>High: {high}</span> | "
                f"<span class='risk-medium'>Medium: {medium}</span> | "
                f"<span class='risk-low'>Low: {low}</span></p>"
            )
            body_parts.append(self._anomaly_table(results))
            body_parts.append("</div>")

        body_html = "\n".join(body_parts)
        html = self._html_skeleton(
            "Anomaly Detection Report",
            "AI-Powered Anomaly Detection Report",
            report_id, timestamp, body_html,
        )
        signature = self.sign_report(body_html + timestamp + report_id)
        return {"content": html, "signature": signature, "report_id": report_id}

    @staticmethod
    def _anomaly_table(results: List[Dict]) -> str:
        rows: List[str] = []
        for r in results:
            risk = r.get("risk_level", "unknown")
            rows.append(
                f"<tr>"
                f"<td>{r.get('anomaly_type', 'N/A')}</td>"
                f"<td>{r.get('resource_name', 'N/A')}</td>"
                f"<td>{r.get('description', '')}</td>"
                f"<td class='risk-{risk.lower()}'>{risk.upper()}</td>"
                f"<td>{r.get('confidence', 'N/A')}</td>"
                f"<td>{r.get('detected_at', 'N/A')}</td>"
                f"</tr>"
            )
        return (
            "<table>"
            "<tr><th>Type</th><th>Resource</th><th>Description</th>"
            "<th>Risk Level</th><th>Confidence</th><th>Detected</th></tr>"
            + "".join(rows)
            + "</table>"
        )

    @staticmethod
    def _normalise_anomaly(data: Any) -> List[Dict]:
        if isinstance(data, list):
            return [
                d if isinstance(d, dict) else d.dict() if hasattr(d, "dict") else vars(d)
                for d in data
            ]
        if isinstance(data, dict):
            return [data]
        if hasattr(data, "dict"):
            return [data.dict()]
        return []

    
    # Full / Comprehensive Report
    
    def generate_full_report(
        self,
        compliance_results: Any,
        anomaly_results: Any,
        audit_trail: Any,
    ) -> Dict[str, str]:
        """
        Generate a comprehensive report combining compliance, anomaly, and audit data.

        Args:
            compliance_results: Compliance assessment data
            anomaly_results: Anomaly detection data
            audit_trail: Blockchain audit trail data

        Returns:
            dict with keys 'content', 'signature', 'report_id'
        """
        report_id = f"FR-{uuid.uuid4().hex[:12].upper()}"
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

        body_parts: List[str] = []

        #  Compliance Section 
        c_results = self._normalise_compliance(compliance_results)
        body_parts.append("<div class='section'><h2>1. Compliance Assessment</h2>")
        if c_results:
            overall_score = sum(r.get("compliance_score", 0) for r in c_results) / len(c_results)
            body_parts.append(
                f"<p>Overall compliance score: "
                f"<span class='score-badge {self._score_class(overall_score)}'>"
                f"{overall_score:.1f}%</span></p>"
            )
            body_parts.append(self._compliance_table(c_results))
        else:
            body_parts.append("<p>No compliance data available.</p>")
        body_parts.append("</div>")

        #  Anomaly Section 
        a_results = self._normalise_anomaly(anomaly_results)
        body_parts.append("<div class='section'><h2>2. Anomaly Detection</h2>")
        if a_results:
            body_parts.append(self._anomaly_table(a_results))
        else:
            body_parts.append("<p>No anomaly data available.</p>")
        body_parts.append("</div>")

        #  Audit Trail Section 
        body_parts.append("<div class='section'><h2>3. Audit Trail Integrity</h2>")
        audit_data = self._normalise_audit(audit_trail)
        if audit_data:
            chain_valid = audit_data.get("chain_valid", False)
            total_blocks = audit_data.get("total_blocks", 0)
            status_cls = "audit-valid" if chain_valid else "audit-invalid"
            status_txt = "VALID - Chain integrity verified" if chain_valid else "INVALID - Chain integrity compromised"
            body_parts.append(
                f"<div class='audit-status {status_cls}'>"
                f"Blockchain Audit Trail: {status_txt}</div>"
                f"<p>Total audit blocks: {total_blocks}</p>"
            )
        else:
            body_parts.append("<p>No audit trail data available.</p>")
        body_parts.append("</div>")

        #  Recommendations 
        all_recs: List[str] = []
        for r in c_results:
            all_recs.extend(r.get("recommendations", []))
        if all_recs:
            body_parts.append("<div class='section'><h2>4. Recommendations</h2>")
            body_parts.append("<div class='recommendations'><ul>")
            for rec in all_recs:
                body_parts.append(f"<li>{rec}</li>")
            body_parts.append("</ul></div></div>")

        body_html = "\n".join(body_parts)
        html = self._html_skeleton(
            "Full Assessment Report",
            "Comprehensive Compliance & Security Assessment Report",
            report_id, timestamp, body_html,
        )
        signature = self.sign_report(body_html + timestamp + report_id)
        return {"content": html, "signature": signature, "report_id": report_id}

    @staticmethod
    def _normalise_audit(data: Any) -> Optional[Dict]:
        if isinstance(data, dict):
            return data
        if hasattr(data, "dict"):
            return data.dict()
        return None
