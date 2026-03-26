import React, { useEffect, useState } from "react";
import { audit } from "../services/api";
import "./AuditTrail.css";

export default function AuditTrail() {
  const [trail, setTrail] = useState(null);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [expanded, setExpanded] = useState(null);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const [t, s] = await Promise.all([audit.trail(), audit.stats()]);
      setTrail(t.data);
      setStats(s.data?.blockchain_statistics || s.data);
    } catch (e) {
      setError("Failed to load audit trail");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  return (
    <div className="page">
      <h1 className="page-title">Audit Trail</h1>
      <p className="page-sub">Tamper-evident blockchain log — SHA-256 hash chain with Merkle Tree verification</p>

      {stats && (
        <div className="audit-stats">
          <div className="a-stat-item">
            <span className="a-stat-val">{stats.total_blocks}</span>
            <span className="a-stat-label">Total Blocks</span>
          </div>
          <div className="a-stat-item">
            <span className="a-stat-val" style={{ color: stats.chain_valid ? "#3fb950" : "#f85149" }}>
              {stats.chain_valid ? "Valid" : "Broken"}
            </span>
            <span className="a-stat-label">Chain Integrity</span>
          </div>
          {stats.merkle_root_hash && (
            <div className="a-stat-item merkle">
              <span className="a-stat-val mono">{stats.merkle_root_hash.substring(0, 16)}...</span>
              <span className="a-stat-label">Merkle Root</span>
            </div>
          )}
          <div className="a-stat-item">
            <span className="a-stat-val">{(stats.average_compliance ?? stats.avg_compliance_score)?.toFixed(1) ?? "—"}%</span>
            <span className="a-stat-label">Avg Compliance</span>
          </div>
        </div>
      )}

      <div className="refresh-row">
        <button className="btn secondary" onClick={load} disabled={loading}>
          {loading ? "Loading..." : "Refresh"}
        </button>
        {trail && (
          <span className={`chain-badge ${trail.chain_valid ? "valid" : "invalid"}`}>
            {trail.chain_valid ? "Chain verified" : "Chain integrity failure"}
          </span>
        )}
      </div>

      {error && <div className="error-msg">{error}</div>}

      {trail?.blocks?.length > 0 && (
        <div className="blocks-list">
          {[...trail.blocks].reverse().map((block) => (
            <div
              key={block.id}
              className={`block-card ${expanded === block.id ? "open" : ""}`}
              onClick={() => setExpanded(expanded === block.id ? null : block.id)}
            >
              <div className="block-row">
                <span className="block-id">#{block.id}</span>
                <span className="block-resource">{block.resource_name}</span>
                <span
                  className="block-score"
                  style={{
                    color: block.compliance_score >= 80 ? "#3fb950"
                         : block.compliance_score >= 50 ? "#d29922"
                         : "#f85149"
                  }}
                >
                  {Math.round(block.compliance_score)}%
                </span>
                <span className="block-checks">{block.checks_passed}/{block.checks_total} checks</span>
                <span className="block-time">{new Date(block.timestamp).toLocaleString()}</span>
                <span className="block-chevron">{expanded === block.id ? "▲" : "▼"}</span>
              </div>

              {expanded === block.id && (
                <div className="block-detail">
                  <div className="hash-row">
                    <span className="hash-label">Current Hash</span>
                    <span className="hash-val mono">{block.current_hash}</span>
                  </div>
                  <div className="hash-row">
                    <span className="hash-label">Previous Hash</span>
                    <span className="hash-val mono">{block.previous_hash}</span>
                  </div>
                  {block.merkle_root && (
                    <div className="hash-row">
                      <span className="hash-label">Merkle Root</span>
                      <span className="hash-val mono">{block.merkle_root}</span>
                    </div>
                  )}
                  {block.check_details && Object.keys(block.check_details).length > 0 && (
                    <div className="check-detail-grid">
                      {Object.entries(block.check_details).map(([k, v]) => (
                        <div key={k} className={`mini-check ${v.status === "PASS" ? "pass" : "fail"}`}>
                          <span>{k.replace(/_/g, " ")}</span>
                          <span>{v.status}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {!loading && !trail?.blocks?.length && (
        <div className="empty-state">
          No audit blocks yet. Run compliance scans to populate the ledger.
        </div>
      )}
    </div>
  );
}
