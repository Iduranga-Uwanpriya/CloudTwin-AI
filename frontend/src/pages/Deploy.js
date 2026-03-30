import React, { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { deploy, compliance, reports, awsAccounts, scanner } from "../services/api";
import "./Deploy.css";

function formatApiError(err, fallback = "Request failed") {
  const detail = err?.response?.data?.detail;
  if (typeof detail === "string" && detail.trim()) return detail;
  if (Array.isArray(detail) && detail.length > 0) {
    const messages = detail.map((item) => item?.msg).filter(Boolean);
    if (messages.length > 0) return messages.join(", ");
  }
  return fallback;
}

export default function Deploy() {
  const [status, setStatus] = useState(null);
  const [accounts, setAccounts] = useState([]);
  const [loading, setLoading] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [msg, setMsg] = useState(null);
  const [error, setError] = useState(null);
  const [complianceResults, setComplianceResults] = useState(null);
  const [tfFile, setTfFile] = useState(null);
  const [tfUploading, setTfUploading] = useState(false);
  const [cloning, setCloning] = useState({});
  const [cloneResults, setCloneResults] = useState({});
  const [initialLoading, setInitialLoading] = useState(true);

  const loadStatus = async () => {
    try {
      const { data } = await deploy.status();
      setStatus(data);
    } catch {
      setStatus(null);
    }
  };

  const loadAccounts = async () => {
    try {
      const { data } = await awsAccounts.list();
      setAccounts((data || []).filter((a) => a.is_active));
    } catch {
      setAccounts([]);
    }
  };

  useEffect(() => {
    Promise.allSettled([loadStatus(), loadAccounts()]).then(() => {
      setInitialLoading(false);
    });
  }, []);

  const handleCloneToTwin = async (accountId) => {
    setCloning((s) => ({ ...s, [accountId]: true }));
    setError(null);
    setMsg(null);
    try {
      const { data } = await scanner.cloneToTwin(accountId);
      setCloneResults((r) => ({ ...r, [accountId]: data }));
      setMsg("Resources cloned to digital twin successfully");
      await loadStatus();
      // Auto-scan after clone
      await handleScanAll();
    } catch (e) {
      setError(formatApiError(e, "Clone to twin failed"));
    } finally {
      setCloning((s) => ({ ...s, [accountId]: false }));
    }
  };

  const handleScanAll = async () => {
    setScanning(true);
    try {
      const { data } = await compliance.scanAll();
      setComplianceResults(data);
    } catch {
      // scan may fail if no buckets
    } finally {
      setScanning(false);
    }
  };

  const handleDestroy = async () => {
    if (!window.confirm("Destroy all digital twin infrastructure?")) return;
    setLoading(true);
    setError(null);
    setComplianceResults(null);
    setCloneResults({});
    try {
      const { data } = await deploy.destroy();
      setMsg(data.message || "Destroyed");
      await loadStatus();
    } catch (e) {
      setError(formatApiError(e, "Destroy failed"));
    } finally {
      setLoading(false);
    }
  };

  const handleDownloadTf = async (accountId) => {
    setError(null);
    try {
      const { data } = await scanner.generateTerraform(accountId);
      const blob = new Blob([data.terraform], { type: "text/plain" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "infrastructure.tf";
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      setError("Failed to generate Terraform file");
    }
  };

  const handleTfUpload = async () => {
    if (!tfFile) return;
    setTfUploading(true);
    setError(null);
    setMsg(null);
    setComplianceResults(null);
    try {
      const { data } = await compliance.scanTerraform(tfFile);
      setComplianceResults({ results: data.results || [data] });
      setMsg("Terraform scanned successfully");
      await loadStatus();
    } catch (e) {
      setError(formatApiError(e, "Terraform upload failed"));
    } finally {
      setTfUploading(false);
    }
  };

  const getScoreColor = (score) => {
    if (score >= 80) return "good";
    if (score >= 50) return "warn";
    return "bad";
  };

  const avgScore = complianceResults?.results
    ? (complianceResults.results.reduce((sum, r) => sum + (r.compliance_score || 0), 0) / complianceResults.results.length).toFixed(0)
    : null;

  if (initialLoading) {
    return (
      <div className="page">
        <h1 className="page-title">Digital Twin</h1>
        <div className="loading">Loading twin status...</div>
      </div>
    );
  }

  return (
    <div className="page">
      <h1 className="page-title">Digital Twin</h1>
      <p className="page-sub">
        Safe AWS simulation — clone, scan, fix, and validate before touching production
      </p>

      {/* Architecture cards */}
      <div className="arch-grid">
        <div className="arch-card">
          <div className="arch-icon">⎈</div>
          <div className="arch-title">Terraform IaC</div>
          <div className="arch-desc">Upload .tf files or clone AWS resources to the twin environment</div>
        </div>
        <div className="arch-card">
          <div className="arch-icon">⬡</div>
          <div className="arch-title">LocalStack</div>
          <div className="arch-desc">Local AWS emulator — S3, EC2, IAM, CloudTrail running safely in Docker</div>
        </div>
        <div className="arch-card">
          <div className="arch-icon">✔</div>
          <div className="arch-title">Auto-Scan</div>
          <div className="arch-desc">Every clone is automatically scanned against ISO 27001 &amp; NIST 800-53</div>
        </div>
        <div className="arch-card">
          <div className="arch-icon">⛓</div>
          <div className="arch-title">Audit Ledger</div>
          <div className="arch-desc">Scan results logged to SHA-256 blockchain with Merkle Tree proof</div>
        </div>
      </div>

      {/* No accounts connected */}
      {accounts.length === 0 ? (
        <div className="deploy-section" style={{ textAlign: "center", padding: "2.5rem 1.5rem" }}>
          <p style={{ color: "#8b949e", fontSize: "1.1rem", marginBottom: "1rem" }}>
            Connect an AWS account first to clone resources into the digital twin.
          </p>
          <Link to="/aws" className="btn primary" style={{ textDecoration: "none" }}>
            Connect AWS Account
          </Link>
        </div>
      ) : (
        <>
          {/* Clone from connected accounts */}
          <div className="deploy-section">
            <h3>Clone from AWS Account</h3>
            <p style={{ color: "#8b949e", fontSize: "0.85rem", marginBottom: "1rem" }}>
              Select an account to clone its resources into the digital twin for safe testing
            </p>
            {accounts.map((a) => (
              <div key={a.id} style={{ display: "flex", alignItems: "center", gap: "0.75rem", marginBottom: "0.75rem", padding: "0.75rem 1rem", background: "#0d1117", borderRadius: "6px", border: "1px solid #30363d" }}>
                <div style={{ flex: 1 }}>
                  <div style={{ color: "#e6edf3", fontWeight: 600 }}>{a.account_alias}</div>
                  <div style={{ color: "#8b949e", fontSize: "0.8rem" }}>{a.role_arn}</div>
                  {a.last_scanned_at && (
                    <div style={{ color: "#8b949e", fontSize: "0.75rem" }}>
                      Last scan: {new Date(a.last_scanned_at).toLocaleString()}
                    </div>
                  )}
                </div>
                <button
                  className="btn primary"
                  onClick={() => handleCloneToTwin(a.id)}
                  disabled={cloning[a.id] || loading}
                >
                  {cloning[a.id] ? "Cloning..." : "Clone to Twin"}
                </button>
                <button
                  className="btn secondary"
                  onClick={() => handleDownloadTf(a.id)}
                >
                  Download .tf
                </button>
              </div>
            ))}

            {/* Clone results */}
            {Object.entries(cloneResults).map(([accountId, result]) => (
              <div key={accountId} style={{ marginTop: "0.75rem" }}>
                {result.error ? (
                  <div className="error-msg">{result.error}</div>
                ) : (
                  <div style={{ background: "#0d1117", border: "1px solid #238636", borderRadius: "6px", padding: "1rem" }}>
                    <div style={{ color: "#3fb950", fontWeight: 600, marginBottom: "0.5rem" }}>
                      Twin Cloned Successfully
                    </div>
                    <div style={{ color: "#8b949e", fontSize: "0.85rem" }}>
                      {result.cloned_resources?.length || 0} resources cloned to LocalStack
                    </div>
                    {result.compliance_preview?.map((r) => (
                      <div key={r.bucket} style={{ color: "#c9d1d9", fontSize: "0.85rem", marginTop: "0.25rem" }}>
                        {r.bucket}: <span style={{ color: r.score >= 80 ? "#3fb950" : "#f85149" }}>{r.score.toFixed(0)}%</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>

          {/* Twin control */}
          <div className="deploy-section">
            <h3>Infrastructure Control</h3>

            {status && (
              <div className="status-panel">
                <div className={`deploy-status ${status.deployed ? "deployed" : "idle"}`}>
                  {status.deployed
                    ? `${status.resource_count} resource${status.resource_count !== 1 ? "s" : ""} deployed`
                    : "No infrastructure deployed"}
                </div>
              </div>
            )}

            <div className="btn-row">
              {status?.deployed && (
                <button className="btn secondary" onClick={handleScanAll} disabled={scanning}>
                  {scanning ? "Scanning..." : "Re-scan"}
                </button>
              )}
              <button className="btn danger" onClick={handleDestroy} disabled={loading || !status?.deployed}>
                Destroy Twin
              </button>
              <button className="btn secondary" onClick={() => { loadStatus(); loadAccounts(); }}>Refresh</button>
            </div>

            {msg && <div className="success-msg">{msg}</div>}
            {error && <div className="error-msg">{error}</div>}
          </div>
        </>
      )}

      {/* Terraform upload section (optional) */}
      <div className="deploy-section">
        <h3>Upload Terraform (optional)</h3>
        <p className="tf-desc">Upload your own .tf file to scan it against compliance rules before deploying to real AWS</p>
        <div className="tf-upload-row">
          <input
            type="file"
            accept=".tf"
            onChange={(e) => setTfFile(e.target.files[0])}
            className="tf-input"
          />
          <button
            className="btn primary"
            onClick={handleTfUpload}
            disabled={!tfFile || tfUploading}
          >
            {tfUploading ? "Scanning..." : "Scan Terraform"}
          </button>
        </div>
      </div>

      {/* Compliance results */}
      {complianceResults?.results && (
        <div className="deploy-section">
          <h3>
            Compliance Results
            {avgScore && (
              <span className={`avg-score ${getScoreColor(avgScore)}`}>
                {avgScore}% average
              </span>
            )}
          </h3>

          <div className="twin-results">
            {complianceResults.results.map((r, i) => (
              <div key={i} className="twin-resource-card">
                <div className="twin-resource-header">
                  <span className="twin-resource-name">{r.resource_name || `Resource ${i + 1}`}</span>
                  <span className={`twin-resource-score ${getScoreColor(r.compliance_score || 0)}`}>
                    {(r.compliance_score || 0).toFixed(0)}%
                  </span>
                </div>
                <div className="twin-resource-summary">{r.summary || ""}</div>

                {r.checks && (
                  <div className="twin-checks">
                    {Object.entries(r.checks).map(([key, check]) => (
                      <div key={key} className={`twin-check ${check.status === "PASS" ? "pass" : "fail"}`}>
                        <span className={`twin-check-badge ${check.status === "PASS" ? "pass" : "fail"}`}>
                          {check.status}
                        </span>
                        <span className="twin-check-msg">{check.message || key}</span>
                      </div>
                    ))}
                  </div>
                )}

                {r.recommendations?.length > 0 && (
                  <div className="twin-remediation">
                    <strong>Remediation:</strong>
                    <ul>
                      {r.recommendations.map((rec, j) => <li key={j}>{rec}</li>)}
                    </ul>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Resource list */}
      {status?.resources?.length > 0 && (
        <div className="deploy-section">
          <h3>Deployed Resources</h3>
          <div className="resource-grid">
            {status.resources.map((r) => (
              <div key={r} className="resource-chip">{r}</div>
            ))}
          </div>
        </div>
      )}

      {/* Reports */}
      <div className="deploy-section">
        <h3>Reports</h3>
        <p className="reports-desc">Signed HTML reports (SHA-256 tamper-proof) generated from scan results.</p>
        <div className="btn-row">
          <a className="btn secondary" href={reports.full()} target="_blank" rel="noreferrer">
            Full Compliance Report
          </a>
        </div>
      </div>
    </div>
  );
}
