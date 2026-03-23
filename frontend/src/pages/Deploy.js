import React, { useState, useEffect } from "react";
import { deploy, reports } from "../services/api";
import "./Deploy.css";

export default function Deploy() {
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(false);
  const [msg, setMsg] = useState(null);
  const [error, setError] = useState(null);

  const loadStatus = async () => {
    try {
      const { data } = await deploy.status();
      setStatus(data);
    } catch {
      setStatus(null);
    }
  };

  useEffect(() => { loadStatus(); }, []);

  const handleDeploy = async () => {
    setLoading(true);
    setError(null);
    setMsg(null);
    try {
      const { data } = await deploy.infrastructure({});
      setMsg(data.message || "Deployed successfully");
      await loadStatus();
    } catch (e) {
      setError(e.response?.data?.detail || "Deployment failed");
    } finally {
      setLoading(false);
    }
  };

  const handleDestroy = async () => {
    if (!window.confirm("Destroy all digital twin infrastructure?")) return;
    setLoading(true);
    setError(null);
    try {
      const { data } = await deploy.destroy();
      setMsg(data.message || "Destroyed");
      await loadStatus();
    } catch (e) {
      setError(e.response?.data?.detail || "Destroy failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="page">
      <h1 className="page-title">Digital Twin</h1>
      <p className="page-sub">
        LocalStack-based AWS digital twin — safely simulate and test misconfiguration scenarios
      </p>

      <div className="arch-grid">
        <div className="arch-card">
          <div className="arch-icon">⎈</div>
          <div className="arch-title">Terraform IaC</div>
          <div className="arch-desc">Infrastructure-as-Code provisions compliant and misconfigured S3 buckets, security groups, and VPCs in LocalStack</div>
        </div>
        <div className="arch-card">
          <div className="arch-icon">⬡</div>
          <div className="arch-title">LocalStack</div>
          <div className="arch-desc">Local AWS cloud emulator — safely replicates S3, EC2, IAM, CloudTrail without touching production</div>
        </div>
        <div className="arch-card">
          <div className="arch-icon">✔</div>
          <div className="arch-title">Compliance Scan</div>
          <div className="arch-desc">Policy-as-Code engine checks each resource against ISO 27001 &amp; NIST 800-53 controls after deployment</div>
        </div>
        <div className="arch-card">
          <div className="arch-icon">⛓</div>
          <div className="arch-title">Audit Ledger</div>
          <div className="arch-desc">Every scan result is committed to the SHA-256 hash chain with Merkle Tree proof for tamper-evident evidence</div>
        </div>
      </div>

      <div className="deploy-section">
        <h3>Infrastructure Control</h3>

        {status && (
          <div className="status-panel">
            <div className={`deploy-status ${status.deployed ? "deployed" : "idle"}`}>
              {status.deployed ? "Infrastructure deployed" : "No infrastructure deployed"}
            </div>
            {status.resources?.length > 0 && (
              <ul className="resource-list">
                {status.resources.map((r) => (
                  <li key={r}>{r}</li>
                ))}
              </ul>
            )}
          </div>
        )}

        <div className="btn-row">
          <button className="btn primary" onClick={handleDeploy} disabled={loading}>
            {loading ? "Working..." : "Deploy Twin"}
          </button>
          <button className="btn danger" onClick={handleDestroy} disabled={loading}>
            Destroy Twin
          </button>
          <button className="btn secondary" onClick={loadStatus}>Refresh Status</button>
        </div>

        {msg && <div className="success-msg">{msg}</div>}
        {error && <div className="error-msg">{error}</div>}
      </div>

      <div className="reports-section">
        <h3>Reports</h3>
        <p className="reports-desc">Signed HTML reports (SHA-256 tamper-proof) are generated after compliance scans.</p>
        <div className="btn-row">
          <a
            className="btn secondary"
            href={reports.full()}
            target="_blank"
            rel="noreferrer"
          >
            Full Compliance Report
          </a>
        </div>
      </div>
    </div>
  );
}
