import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import StatsCard from "../components/StatsCard";
import ComplianceGauge from "../components/ComplianceGauge";
import { audit, health, awsAccounts, deploy } from "../services/api";
import "./Dashboard.css";

export default function Dashboard() {
  const [auditStats, setAuditStats] = useState(null);
  const [sysHealth, setSysHealth] = useState(null);
  const [accounts, setAccounts] = useState([]);
  const [twinStatus, setTwinStatus] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.allSettled([
      audit.stats(),
      health(),
      awsAccounts.list(),
      deploy.status(),
    ]).then(([a, h, acc, tw]) => {
      if (a.status === "fulfilled") setAuditStats(a.value.data?.blockchain_statistics || a.value.data);
      if (h.status === "fulfilled") setSysHealth(h.value.data);
      if (acc.status === "fulfilled") setAccounts(acc.value.data || []);
      if (tw.status === "fulfilled") setTwinStatus(tw.value.data);
      setLoading(false);
    });
  }, []);

  const activeAccounts = accounts.filter((a) => a.is_active);
  const lastScanned = activeAccounts
    .filter((a) => a.last_scanned_at)
    .sort((a, b) => new Date(b.last_scanned_at) - new Date(a.last_scanned_at))[0];
  const hasLastScanScore = typeof lastScanned?.compliance_score === "number";

  return (
    <div className="page">
      <h1 className="page-title">Dashboard</h1>
      <p className="page-sub">AI-Powered Cloud Security Compliance &amp; Threat Detection</p>

      {loading ? (
        <div className="loading">Loading platform status...</div>
      ) : (
        <>
          <div className="stats-grid">
            <StatsCard
              title="AWS Accounts"
              value={activeAccounts.length}
              sub={activeAccounts.length === 1 ? "1 account connected" : `${activeAccounts.length} accounts connected`}
              color={activeAccounts.length > 0 ? "#3fb950" : "#d29922"}
              icon="☁"
            />
            <StatsCard
              title="Last Scan Score"
              value={lastScanned?.last_scanned_at && hasLastScanScore ? `${Math.round(lastScanned.compliance_score)}%` : "--"}
              sub={lastScanned ? `${lastScanned.account_alias} - ${new Date(lastScanned.last_scanned_at).toLocaleDateString()}` : "No scans yet"}
              color={
                lastScanned?.compliance_score >= 80 ? "#3fb950"
                : lastScanned?.compliance_score >= 50 ? "#d29922"
                : hasLastScanScore ? "#f85149"
                : "#8b949e"
              }
              icon="✔"
            />
            <StatsCard
              title="Digital Twin"
              value={twinStatus?.deployed ? "Deployed" : "Idle"}
              sub={twinStatus?.deployed ? `${twinStatus.resource_count || 0} resources` : "Not deployed"}
              color={twinStatus?.deployed ? "#3fb950" : "#8b949e"}
              icon="⎈"
            />
            <StatsCard
              title="Audit Blocks"
              value={auditStats?.total_blocks ?? "--"}
              sub={auditStats?.chain_valid ? "Chain valid" : auditStats ? "Chain broken" : "Loading..."}
              color={auditStats?.chain_valid ? "#3fb950" : "#f85149"}
              icon="⛓"
            />
          </div>

          {/* Quick actions */}
          <div className="dash-grid">
            <div className="dash-card">
              <h3>Quick Actions</h3>
              <p className="empty" style={{ marginBottom: "1rem" }}>
                Follow the flow: Connect &rarr; Scan &rarr; Clone to Twin &rarr; Fix &rarr; Verify
              </p>
              <div style={{ display: "flex", gap: "0.75rem", flexWrap: "wrap" }}>
                <Link to="/aws" className="btn primary" style={{ textDecoration: "none" }}>
                  {activeAccounts.length > 0 ? "Manage AWS Accounts" : "Connect AWS Account"}
                </Link>
                <Link to="/compliance" className="btn secondary" style={{ textDecoration: "none" }}>
                  View Compliance
                </Link>
                <Link to="/deploy" className="btn secondary" style={{ textDecoration: "none" }}>
                  Digital Twin
                </Link>
                <Link to="/anomaly" className="btn secondary" style={{ textDecoration: "none" }}>
                  Anomaly Detection
                </Link>
              </div>
            </div>

            <div className="dash-card">
              <h3>System Status</h3>
              <table className="status-table">
                <tbody>
                  <tr>
                    <td>Backend</td>
                    <td><span className={`badge ${sysHealth?.status === "healthy" ? "green" : "red"}`}>
                      {sysHealth?.status === "healthy" ? "Healthy" : "Degraded"}
                    </span></td>
                  </tr>
                  <tr>
                    <td>LocalStack (Twin)</td>
                    <td><span className={`badge ${sysHealth?.localstack_connected ? "green" : "gray"}`}>
                      {sysHealth?.localstack_connected ? "Online" : "N/A (Prod)"}
                    </span></td>
                  </tr>
                  <tr>
                    <td>Audit Ledger (SHA-256)</td>
                    <td><span className={`badge ${auditStats?.chain_valid ? "green" : "red"}`}>
                      {auditStats?.chain_valid ? "Verified" : auditStats ? "Invalid" : "--"}
                    </span></td>
                  </tr>
                  <tr>
                    <td>Anomaly Detector</td>
                    <td><span className="badge blue">Ready</span></td>
                  </tr>
                  <tr>
                    <td>ISO 27001 Controls</td>
                    <td><span className="badge blue">Mapped</span></td>
                  </tr>
                  <tr>
                    <td>NIST 800-53 Controls</td>
                    <td><span className="badge blue">Mapped</span></td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

          {/* Connected accounts summary */}
          {activeAccounts.length > 0 && (
            <div className="dash-card" style={{ marginTop: "1.5rem" }}>
              <h3>Connected Accounts</h3>
              <div className="gauge-row">
                {activeAccounts.map((a) => (
                  <div key={a.id} className="gauge-item">
                    <ComplianceGauge score={a.compliance_score || 0} size={110} />
                    <div className="gauge-label">{a.account_alias}</div>
                    <div className="gauge-label" style={{ fontSize: "0.7rem", color: "#8b949e" }}>
                      {a.last_scanned_at ? new Date(a.last_scanned_at).toLocaleDateString() : "Not scanned"}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
