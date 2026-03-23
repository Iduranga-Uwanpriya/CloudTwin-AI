import React, { useEffect, useState } from "react";
import StatsCard from "../components/StatsCard";
import ComplianceGauge from "../components/ComplianceGauge";
import { audit, health, compliance } from "../services/api";
import "./Dashboard.css";

export default function Dashboard() {
  const [auditStats, setAuditStats] = useState(null);
  const [sysHealth, setSysHealth] = useState(null);
  const [scanResult, setScanResult] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.allSettled([
      audit.stats(),
      health(),
      compliance.scanAll(),
    ]).then(([a, h, c]) => {
      if (a.status === "fulfilled") setAuditStats(a.value.data);
      if (h.status === "fulfilled") setSysHealth(h.value.data);
      if (c.status === "fulfilled") setScanResult(c.value.data);
      setLoading(false);
    });
  }, []);

  const avgScore = scanResult?.results?.length
    ? scanResult.results.reduce((s, r) => s + r.compliance_score, 0) / scanResult.results.length
    : 0;

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
              title="Avg Compliance Score"
              value={`${Math.round(avgScore)}%`}
              sub={`${scanResult?.results?.length ?? 0} buckets scanned`}
              color={avgScore >= 80 ? "#3fb950" : avgScore >= 50 ? "#d29922" : "#f85149"}
              icon="✔"
            />
            <StatsCard
              title="Audit Blocks"
              value={auditStats?.total_blocks ?? "—"}
              sub={auditStats?.chain_valid ? "Chain valid" : "Chain broken"}
              color={auditStats?.chain_valid ? "#3fb950" : "#f85149"}
              icon="⛓"
            />
            <StatsCard
              title="LocalStack"
              value={sysHealth?.localstack_connected ? "Online" : "Offline"}
              sub="Digital twin environment"
              color={sysHealth?.localstack_connected ? "#3fb950" : "#f85149"}
              icon="⎈"
            />
            <StatsCard
              title="Backend"
              value={sysHealth?.status === "healthy" ? "Healthy" : "Degraded"}
              sub={`v${sysHealth?.version ?? "—"}`}
              color={sysHealth?.status === "healthy" ? "#3fb950" : "#f85149"}
              icon="⬡"
            />
          </div>

          <div className="dash-grid">
            <div className="dash-card">
              <h3>Compliance Overview</h3>
              {scanResult?.results?.length ? (
                <div className="gauge-row">
                  {scanResult.results.map((r) => (
                    <div key={r.resource_name} className="gauge-item">
                      <ComplianceGauge score={r.compliance_score} size={110} />
                      <div className="gauge-label">{r.resource_name}</div>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="empty">No buckets found. Deploy the digital twin first.</p>
              )}
            </div>

            <div className="dash-card">
              <h3>System Status</h3>
              <table className="status-table">
                <tbody>
                  <tr>
                    <td>Compliance Engine</td>
                    <td><span className="badge green">Active</span></td>
                  </tr>
                  <tr>
                    <td>Anomaly Detector</td>
                    <td><span className="badge blue">Ready</span></td>
                  </tr>
                  <tr>
                    <td>Audit Ledger (SHA-256)</td>
                    <td><span className={`badge ${auditStats?.chain_valid ? "green" : "red"}`}>
                      {auditStats?.chain_valid ? "Verified" : "Invalid"}
                    </span></td>
                  </tr>
                  <tr>
                    <td>Merkle Tree</td>
                    <td><span className="badge green">Enabled</span></td>
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
        </>
      )}
    </div>
  );
}
