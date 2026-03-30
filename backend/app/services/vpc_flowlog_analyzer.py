"""
VPC Flow Log Analyzer — pulls real AWS VPC Flow Logs and runs them
through the trained ML anomaly detection models (IF + SVM + Autoencoder).

Maps VPC Flow Log fields to UNSW-NB15 features for model compatibility.
"""
import json
import time
from datetime import datetime, timezone, timedelta
from typing import Optional

import boto3
import pandas as pd
import numpy as np


# VPC Flow Log → UNSW-NB15 feature mapping
# VPC Flow Log fields: version, account-id, interface-id, srcaddr, dstaddr,
# srcport, dstport, protocol, packets, bytes, start, end, action, log-status
# Protocol numbers: 6=TCP, 17=UDP, 1=ICMP

WELL_KNOWN_PORTS = {
    22: "ssh", 53: "dns", 80: "http", 443: "https",
    21: "ftp", 20: "ftp",
}


def pull_vpc_flow_logs(session: boto3.Session, hours: int = 1) -> dict:
    """Pull VPC Flow Logs from CloudWatch Logs and analyze with ML models."""
    ec2 = session.client("ec2")
    logs_client = session.client("logs")

    vpcs = ec2.describe_vpcs().get("Vpcs", [])
    flow_logs = ec2.describe_flow_logs().get("FlowLogs", [])

    if not flow_logs:
        return {
            "status": "no_flow_logs",
            "message": "No VPC Flow Logs enabled. Enable them in AWS Console: VPC → Your VPC → Flow Logs → Create.",
            "setup_instructions": [
                "1. Go to AWS Console → VPC → Your VPCs",
                "2. Select your VPC → Actions → Create flow log",
                "3. Filter: All",
                "4. Destination: CloudWatch Logs",
                "5. Log group: /vpc/flow-logs (create new)",
                "6. IAM role: Create new role (auto)",
                "7. Wait 5-10 minutes for logs to appear",
            ],
            "vpcs_found": len(vpcs),
            "predictions": None,
        }

    cw_flow_logs = [fl for fl in flow_logs if fl.get("LogDestinationType") == "cloud-watch-logs"]
    if not cw_flow_logs:
        return {
            "status": "no_cloudwatch_logs",
            "message": "VPC Flow Logs exist but aren't sent to CloudWatch Logs. ML analysis requires CloudWatch destination.",
            "flow_logs_found": len(flow_logs),
            "predictions": None,
        }

    log_group = cw_flow_logs[0].get("LogGroupName")
    if not log_group:
        # Try to extract from LogDestination ARN
        dest = cw_flow_logs[0].get("LogDestination", "")
        if ":log-group:" in dest:
            log_group = dest.split(":log-group:")[-1].rstrip(":*")

    if not log_group:
        return {
            "status": "error",
            "message": "Could not determine CloudWatch Log Group for flow logs.",
            "predictions": None,
        }

    start_ms = int((datetime.now(timezone.utc) - timedelta(hours=hours)).timestamp() * 1000)
    end_ms = int(datetime.now(timezone.utc).timestamp() * 1000)

    raw_events = []
    try:
        streams_resp = logs_client.describe_log_streams(
            logGroupName=log_group,
            orderBy="LastEventTime",
            descending=True,
            limit=5,
        )
        streams = streams_resp.get("logStreams", [])

        for stream in streams:
            stream_name = stream["logStreamName"]
            try:
                events_resp = logs_client.get_log_events(
                    logGroupName=log_group,
                    logStreamName=stream_name,
                    startTime=start_ms,
                    endTime=end_ms,
                    limit=500,
                )
                for event in events_resp.get("events", []):
                    raw_events.append(event.get("message", ""))
            except Exception:
                continue

    except Exception as e:
        return {
            "status": "error",
            "message": f"Failed to pull CloudWatch logs: {str(e)}",
            "log_group": log_group,
            "predictions": None,
        }

    if not raw_events:
        return {
            "status": "no_events",
            "message": f"No flow log events found in the last {hours} hour(s). Logs may take 5-10 minutes to appear after enabling.",
            "log_group": log_group,
            "predictions": None,
        }

    parsed = []
    for line in raw_events:
        parts = line.strip().split()
        if len(parts) < 14 or parts[0] == "version":
            continue  # header or incomplete
        try:
            parsed.append({
                "version": parts[0],
                "account_id": parts[1],
                "interface_id": parts[2],
                "srcaddr": parts[3],
                "dstaddr": parts[4],
                "srcport": int(parts[5]) if parts[5] != "-" else 0,
                "dstport": int(parts[6]) if parts[6] != "-" else 0,
                "protocol": int(parts[7]) if parts[7] != "-" else 0,
                "packets": int(parts[8]) if parts[8] != "-" else 0,
                "bytes": int(parts[9]) if parts[9] != "-" else 0,
                "start": int(parts[10]) if parts[10] != "-" else 0,
                "end": int(parts[11]) if parts[11] != "-" else 0,
                "action": parts[12],
                "log_status": parts[13],
            })
        except (ValueError, IndexError):
            continue

    if not parsed:
        return {
            "status": "no_parseable_events",
            "message": "Flow log events found but couldn't parse them.",
            "raw_event_count": len(raw_events),
            "predictions": None,
        }

    df = _map_to_model_features(parsed)
    predictions = _run_ml_predictions(df)

    for i, pred in enumerate(predictions.get("anomalous_entries", [])):
        if i < len(parsed):
            idx = pred.get("original_index", i)
            if idx < len(parsed):
                pred["srcaddr"] = parsed[idx]["srcaddr"]
                pred["dstaddr"] = parsed[idx]["dstaddr"]
                pred["srcport"] = parsed[idx]["srcport"]
                pred["dstport"] = parsed[idx]["dstport"]
                pred["action"] = parsed[idx]["action"]

    return {
        "status": "completed",
        "log_group": log_group,
        "analysis_period": f"Last {hours} hour(s)",
        "raw_events": len(raw_events),
        "parsed_events": len(parsed),
        "total_logs": predictions.get("total_samples", len(parsed)),
        "anomalies_detected": predictions.get("anomaly_count", 0),
        "anomaly_percentage": predictions.get("anomaly_percentage", 0),
        "risk_level": predictions.get("risk_level", "Normal"),
        "anomalous_entries": predictions.get("anomalous_entries", []),
        "model_summary": predictions.get("model_summary", {}),
        "traffic_summary": _traffic_summary(parsed),
    }


def _map_to_model_features(parsed: list[dict]) -> pd.DataFrame:
    """Map VPC Flow Log fields to UNSW-NB15 model features."""
    records = []
    for p in parsed:
        proto_num = p["protocol"]
        dstport = p["dstport"]
        duration = max(p["end"] - p["start"], 0)

        # Numeric features
        record = {
            "dur": float(duration),
            "sbytes": float(p["bytes"]),
            "dbytes": 0.0,  # Not available in flow logs
            "sttl": 64.0,  # Default TTL estimate
            "dttl": 64.0,
            "sloss": 0.0,
            "dloss": 0.0,
            "sload": float(p["bytes"]) / max(duration, 1),
            "dload": 0.0,
            "spkts": float(p["packets"]),
            "dpkts": 0.0,
            "sinpkt": float(duration * 1000) / max(p["packets"], 1),  # ms per packet
            "dinpkt": 0.0,
            "sjit": 0.0,
            "djit": 0.0,
            "tcprtt": 0.0,
            "ct_srv_src": 1.0,
            "ct_dst_ltm": 1.0,
            # One-hot: protocol
            "proto_icmp": 1.0 if proto_num == 1 else 0.0,
            "proto_tcp": 1.0 if proto_num == 6 else 0.0,
            "proto_udp": 1.0 if proto_num == 17 else 0.0,
            # One-hot: service (based on destination port)
            "service_-": 0.0,
            "service_dns": 1.0 if dstport == 53 else 0.0,
            "service_ftp": 1.0 if dstport in (20, 21) else 0.0,
            "service_http": 1.0 if dstport == 80 else 0.0,
            "service_https": 1.0 if dstport == 443 else 0.0,
            "service_ssh": 1.0 if dstport == 22 else 0.0,
            # One-hot: state (based on action)
            "state_CON": 1.0 if p["action"] == "ACCEPT" else 0.0,
            "state_FIN": 0.0,
            "state_INT": 0.0,
            "state_REQ": 0.0,
            "state_RST": 1.0 if p["action"] == "REJECT" else 0.0,
        }

        # Set service_- if no known service matched
        if not any(record[f"service_{s}"] for s in ["dns", "ftp", "http", "https", "ssh"]):
            record["service_-"] = 1.0

        records.append(record)

    return pd.DataFrame(records)


def _run_ml_predictions(df: pd.DataFrame) -> dict:
    """Run the mapped features through the trained ML models."""
    try:
        from ai_engine.ml.inference import AnomalyInferenceEngine
        engine = AnomalyInferenceEngine()

        if not engine.models_exist():
            return {
                "error": "ML models not found",
                "total_samples": len(df),
                "anomaly_count": 0,
                "anomaly_percentage": 0,
                "anomalous_entries": [],
            }

        engine.load_models()

        feature_names = engine.feature_names
        # Column order must match training data
        df_aligned = df.reindex(columns=feature_names, fill_value=0.0)
        X_scaled = engine.scaler.transform(df_aligned.values)

        if_preds = engine.models["isolation_forest"].predict(X_scaled)
        svm_preds = engine.models["one_class_svm"].predict(X_scaled)

        import numpy as np
        ae_recon = engine.models["autoencoder"].predict(X_scaled, verbose=0)
        ae_errors = np.mean(np.square(X_scaled - ae_recon), axis=1)
        ae_preds = (ae_errors > engine.ae_threshold).astype(int)

        # sklearn convention: -1 = anomaly; majority vote across 3 models
        if_anomaly = (if_preds == -1).astype(int)
        svm_anomaly = (svm_preds == -1).astype(int)

        votes = if_anomaly + svm_anomaly + ae_preds
        ensemble = (votes >= 2).astype(int)

        anomaly_count = int(ensemble.sum())
        total = len(df)
        pct = round((anomaly_count / total) * 100, 2) if total > 0 else 0

        anomalous = []
        anomaly_indices = np.where(ensemble == 1)[0]
        for idx in anomaly_indices[:100]:  # cap response size
            score = float(ae_errors[idx])
            risk = "Critical" if votes[idx] == 3 else "High" if votes[idx] == 2 else "Medium"
            anomalous.append({
                "index": int(idx),
                "original_index": int(idx),
                "anomaly_score": score,
                "risk_level": risk,
                "model_agreement": {
                    "isolation_forest": bool(if_anomaly[idx]),
                    "one_class_svm": bool(svm_anomaly[idx]),
                    "autoencoder": bool(ae_preds[idx]),
                },
            })

        return {
            "total_samples": total,
            "anomaly_count": anomaly_count,
            "anomaly_percentage": pct,
            "risk_level": (
                "Critical" if pct > 20
                else "High" if pct > 10
                else "Medium" if anomaly_count > 0
                else "Normal"
            ),
            "anomalous_entries": anomalous,
            "model_summary": {
                "isolation_forest_anomalies": int(if_anomaly.sum()),
                "one_class_svm_anomalies": int(svm_anomaly.sum()),
                "autoencoder_anomalies": int(ae_preds.sum()),
                "ensemble_anomalies": anomaly_count,
            },
        }

    except Exception as e:
        return {
            "error": f"ML prediction failed: {str(e)}",
            "total_samples": len(df),
            "anomaly_count": 0,
            "anomaly_percentage": 0,
            "anomalous_entries": [],
        }


def _traffic_summary(parsed: list[dict]) -> dict:
    """Summarize traffic patterns from parsed flow logs."""
    from collections import Counter

    protocols = Counter()
    for p in parsed:
        proto = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(p["protocol"], f"Other({p['protocol']})")
        protocols[proto] += 1

    actions = Counter(p["action"] for p in parsed)
    unique_src = set(p["srcaddr"] for p in parsed)
    unique_dst = set(p["dstaddr"] for p in parsed)
    top_ports = Counter(p["dstport"] for p in parsed if p["dstport"] > 0).most_common(10)
    total_bytes = sum(p["bytes"] for p in parsed)

    return {
        "protocols": dict(protocols),
        "actions": dict(actions),
        "unique_source_ips": len(unique_src),
        "unique_dest_ips": len(unique_dst),
        "top_dest_ports": [{"port": p, "count": c, "service": WELL_KNOWN_PORTS.get(p, "")} for p, c in top_ports],
        "total_bytes": total_bytes,
        "total_packets": sum(p["packets"] for p in parsed),
    }
