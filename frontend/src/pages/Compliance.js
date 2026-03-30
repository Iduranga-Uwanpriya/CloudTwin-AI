import React, { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import ComplianceGauge from "../components/ComplianceGauge";
import { awsAccounts, scanner, compliance } from "../services/api";
import "./Compliance.css";

const SEVERITY_COLOR = { critical: "#f85149", high: "#d29922", medium: "#58a6ff", low: "#3fb950" };
function formatApiError(err, fallback = "Request failed") {
  const detail = err?.response?.data?.detail;
  if (typeof detail === "string" && detail.trim()) return detail;
  if (Array.isArray(detail) && detail.length > 0) {
    const messages = detail.map((item) => item?.msg).filter(Boolean);
    if (messages.length > 0) return messages.join(", ");
  }
  return fallback;
}

export default function Compliance() {
  const [accounts, setAccounts] = useState([]);
  const [selectedAccount, setSelectedAccount] = useState(null);
  const [scanHistory, setScanHistory] = useState([]);
  const [findings, setFindings] = useState(null);
  const [activeScanId, setActiveScanId] = useState(null);
  const [loading, setLoading] = useState(true);
  const [findingsLoading, setFindingsLoading] = useState(false);
  const [error, setError] = useState(null);

  // Terraform upload (optional)
  const [tfFile, setTfFile] = useState(null);
  const [tfResults, setTfResults] = useState(null);
  const [tfLoading, setTfLoading] = useState(false);

  useEffect(() => {
    loadAccounts();
  }, []);

  const loadAccounts = async () => {
    try {
      const { data } = await awsAccounts.list();
      const active = (data || []).filter((a) => a.is_active);
      setAccounts(active);
      if (active.length > 0 && !selectedAccount) {
        selectAccount(active[0]);
      }
    } catch {
      // not connected
    } finally {
      setLoading(false);
    }
  };

  const selectAccount = async (account) => {
    setSelectedAccount(account);
    setFindings(null);
    setActiveScanId(null);
    setError(null);
    try {
      const { data } = await scanner.history(account.id);
      setScanHistory(data.scans || data || []);
    } catch {
      setScanHistory([]);
    }
  };

  const loadFindings = async (scanId) => {
    setFindingsLoading(true);
    setActiveScanId(scanId);
    setError(null);
    try {
      const { data } = await scanner.findings(scanId);
      setFindings(data);
    } catch (e) {
      setError(formatApiError(e, "Failed to load scan findings"));
      setFindings(null);
    } finally {
      setFindingsLoading(false);
    }
  };

  const scanTerraform = async () => {
    if (!tfFile) return;
    setTfLoading(true);
    setError(null);
    try {
      const { data } = await compliance.scanTerraform(tfFile);
      setTfResults(data.results || data);
    } catch (e) {
      setError(formatApiError(e, "Terraform scan failed"));
    } finally {
      setTfLoading(false);
    }
  };

  const getScoreColor = (score) => {
    if (score >= 80) return "#3fb950";
    if (score >= 50) return "#d29922";
    return "#f85149";
  };

  if (loading) {
    return (
      <div className="page">
        <h1 className="page-title">Compliance Scanner</h1>
        <div className="loading">Loading accounts...</div>
      </div>
    );
  }

  return (
    <div className="page">
      <h1 className="page-title">Compliance Scanner</h1>
      <p className="page-sub">Policy-as-Code engine mapped to ISO 27001 &amp; NIST 800-53 controls</p>

      {accounts.length === 0 ? (
        <div className="comp-controls" style={{ textAlign: "center", padding: "3rem 1.5rem" }}>
          <p style={{ color: "#8b949e", fontSize: "1.1rem", marginBottom: "1rem" }}>
            No AWS accounts connected yet. Connect an account and run a scan to see compliance results here.
          </p>
          <Link to="/aws" className="btn primary" style={{ textDecoration: "none" }}>
            Connect AWS Account
          </Link>
        </div>
      ) : (
        <>
          {/* Account selector */}
          <div className="comp-controls">
            <div className="input-row">
              <select
                className="text-input"
                value={selectedAccount?.id || ""}
                onChange={(e) => {
                  const acc = accounts.find((a) => a.id === e.target.value);
                  if (acc) selectAccount(acc);
                }}
              >
                {accounts.map((a) => (
                  <option key={a.id} value={a.id}>
                    {a.account_alias} {a.last_scanned_at ? `(last scan: ${new Date(a.last_scanned_at).toLocaleDateString()})` : "(not scanned)"}
                  </option>
                ))}
              </select>
            </div>
          </div>

          {/* Scan history */}
          {scanHistory.length === 0 ? (
            <div className="comp-controls" style={{ textAlign: "center", padding: "2rem 1.5rem" }}>
              <p style={{ color: "#8b949e" }}>
                No scans found for this account. Go to{" "}
                <Link to="/aws" style={{ color: "#58a6ff" }}>Connect AWS</Link> and run a scan first.
              </p>
            </div>
          ) : (
            <div className="result-wrap">
              <h3>Scan History</h3>
              <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
                {scanHistory.map((s) => (
                  <div
                    key={s.scan_id || s.id}
                    className={`scan-history-card${activeScanId === (s.scan_id || s.id) ? " active-scan" : ""}`}
                    onClick={() => loadFindings(s.scan_id || s.id)}
                  >
                    <div className="scan-history-top">
                      <span className="scan-history-date">
                        {s.created_at ? new Date(s.created_at).toLocaleString() : s.scan_id || s.id}
                      </span>
                      <span className="scan-history-meta">
                        {s.resources_scanned ?? "--"} resources | {s.total_checks ?? "--"} checks
                      </span>
                      <span
                        className="scan-history-score"
                        style={{ color: getScoreColor(s.overall_score || s.score || 0) }}
                      >
                        {Math.round(s.overall_score || s.score || 0)}%
                      </span>
                    </div>
                    {s.resources && s.resources.length > 0 && (
                      <div className="scan-history-resources">
                        {s.resources.map((r, i) => (
                          <span key={i} className={`resource-tag rt-${r.type}`}>
                            <span className="resource-tag-type">{r.type}</span> {r.id}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Findings detail */}
          {findingsLoading && <div className="loading">Loading findings...</div>}

          {findings && !findingsLoading && (
            <div className="result-wrap">
              <div className="result-header">
                <div>
                  <div className="result-name">Scan Results</div>
                  <div className="result-summary">
                    {findings.resources_scanned ?? "--"} resources scanned |{" "}
                    {findings.passed_checks ?? "--"} passed |{" "}
                    {findings.failed_checks ?? "--"} failed
                  </div>
                </div>
                <ComplianceGauge score={findings.overall_score || findings.compliance_score || 0} size={120} />
              </div>

              {/* Live scan findings */}
              {findings.findings && findings.findings.length > 0 && (
                <div className="checks-grid">
                  {findings.findings.map((f, i) => (
                    <div
                      key={i}
                      className={`check-card ${f.status === "PASS" ? "pass" : f.status === "FAIL" ? "fail" : "skip"}`}
                    >
                      <div className="check-status">{f.status}</div>
                      <div className="check-key">{f.rule_title}</div>
                      <div className="check-msg">
                        <span className="check-resource-type">{f.resource_type}</span>{" "}
                        <span className="check-resource-id">{f.resource_id}</span>
                      </div>
                      {f.status === "FAIL" && f.remediation && (
                        <div className="check-rem">{f.remediation}</div>
                      )}
                      <div className="check-footer">
                        <span
                          className="check-sev"
                          style={{ color: SEVERITY_COLOR[f.severity] }}
                        >
                          {f.severity}
                        </span>
                        {f.iso_control && <span className="check-fw">ISO {f.iso_control}</span>}
                        {f.nist_control && <span className="check-fw">NIST {f.nist_control}</span>}
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {/* Legacy LocalStack results */}
              {findings.results && (
                <div className="checks-grid">
                  {(Array.isArray(findings.results) ? findings.results : [findings.results]).map((r, idx) => (
                    <React.Fragment key={idx}>
                      {r.checks && Object.entries(r.checks).map(([key, check]) => (
                        <div
                          key={key}
                          className={`check-card ${check.status === "PASS" ? "pass" : check.status === "FAIL" ? "fail" : "skip"}`}
                        >
                          <div className="check-status">{check.status}</div>
                          <div className="check-key">{key.replace(/_/g, " ")}</div>
                          <div className="check-msg">{check.message}</div>
                          {check.remediation && (
                            <div className="check-rem">{check.remediation}</div>
                          )}
                          {check.severity && (
                            <div
                              className="check-sev"
                              style={{ color: SEVERITY_COLOR[check.severity] }}
                            >
                              {check.severity}
                            </div>
                          )}
                        </div>
                      ))}
                    </React.Fragment>
                  ))}
                </div>
              )}
            </div>
          )}
        </>
      )}

      {error && <div className="error-msg">{error}</div>}

      {/* Terraform upload (optional) */}
      <div className="comp-controls" style={{ marginTop: "2rem" }}>
        <h3 style={{ color: "#e6edf3", marginBottom: "0.75rem" }}>Upload Terraform (optional)</h3>
        <p style={{ color: "#8b949e", fontSize: "0.85rem", marginBottom: "0.75rem" }}>
          Upload a .tf file to scan it against compliance rules before deploying to real AWS
        </p>
        <div className="input-row">
          <input
            type="file"
            accept=".tf,.json"
            className="file-input"
            onChange={(e) => setTfFile(e.target.files[0])}
          />
          <button className="btn secondary" onClick={scanTerraform} disabled={tfLoading || !tfFile}>
            {tfLoading ? "Scanning..." : "Scan Terraform"}
          </button>
        </div>
      </div>

      {tfResults && (
        <div className="result-wrap">
          <h3>Terraform Scan Results ({Array.isArray(tfResults) ? tfResults.length : 1} resources)</h3>
          {(Array.isArray(tfResults) ? tfResults : [tfResults]).map((r) => (
            <div key={r.resource_name} className="tf-row">
              <span className="tf-name">{r.resource_name}</span>
              <span className="tf-type">{r.resource_type}</span>
              <span
                className="tf-score"
                style={{ color: r.compliance_score >= 80 ? "#3fb950" : r.compliance_score >= 50 ? "#d29922" : "#f85149" }}
              >
                {Math.round(r.compliance_score)}%
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
