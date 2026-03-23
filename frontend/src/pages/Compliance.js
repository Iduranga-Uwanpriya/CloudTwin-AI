import React, { useState } from "react";
import ComplianceGauge from "../components/ComplianceGauge";
import { compliance } from "../services/api";
import "./Compliance.css";

const SEVERITY_COLOR = { critical: "#f85149", high: "#d29922", medium: "#58a6ff", low: "#3fb950" };

export default function Compliance() {
  const [bucket, setBucket] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [tfFile, setTfFile] = useState(null);
  const [tfResults, setTfResults] = useState(null);

  const scan = async () => {
    if (!bucket.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const { data } = await compliance.scan(bucket.trim());
      setResult(data);
    } catch (e) {
      setError(e.response?.data?.detail || "Scan failed");
    } finally {
      setLoading(false);
    }
  };

  const scanAll = async () => {
    setLoading(true);
    setError(null);
    try {
      const { data } = await compliance.scanAll();
      if (data.results?.length) setResult(data.results[0]);
    } catch (e) {
      setError(e.response?.data?.detail || "Scan failed");
    } finally {
      setLoading(false);
    }
  };

  const scanTerraform = async () => {
    if (!tfFile) return;
    setLoading(true);
    setError(null);
    try {
      const { data } = await compliance.scanTerraform(tfFile);
      setTfResults(data.results || data);
    } catch (e) {
      setError(e.response?.data?.detail || "Terraform scan failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="page">
      <h1 className="page-title">Compliance Scanner</h1>
      <p className="page-sub">Policy-as-Code engine mapped to ISO 27001 &amp; NIST 800-53 controls</p>

      <div className="comp-controls">
        <div className="input-row">
          <input
            className="text-input"
            placeholder="S3 bucket name"
            value={bucket}
            onChange={(e) => setBucket(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && scan()}
          />
          <button className="btn primary" onClick={scan} disabled={loading}>
            {loading ? "Scanning..." : "Scan Bucket"}
          </button>
          <button className="btn secondary" onClick={scanAll} disabled={loading}>
            Scan All
          </button>
        </div>

        <div className="input-row">
          <input
            type="file"
            accept=".tf,.json"
            className="file-input"
            onChange={(e) => setTfFile(e.target.files[0])}
          />
          <button className="btn secondary" onClick={scanTerraform} disabled={loading || !tfFile}>
            Scan Terraform
          </button>
        </div>
      </div>

      {error && <div className="error-msg">{error}</div>}

      {result && (
        <div className="result-wrap">
          <div className="result-header">
            <div>
              <div className="result-name">{result.resource_name}</div>
              <div className="result-summary">{result.summary}</div>
            </div>
            <ComplianceGauge score={result.compliance_score} size={120} />
          </div>

          <div className="checks-grid">
            {Object.entries(result.checks).map(([key, check]) => (
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
                <div
                  className="check-sev"
                  style={{ color: SEVERITY_COLOR[check.severity] }}
                >
                  {check.severity}
                </div>
              </div>
            ))}
          </div>

          {result.recommendations?.length > 0 && (
            <div className="recommendations">
              <h4>Recommendations</h4>
              <ul>
                {result.recommendations.map((r, i) => <li key={i}>{r}</li>)}
              </ul>
            </div>
          )}
        </div>
      )}

      {tfResults && (
        <div className="result-wrap">
          <h3>Terraform Scan Results ({tfResults.length} resources)</h3>
          {tfResults.map((r) => (
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
