import React, { useState, useEffect } from "react";
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell
} from "recharts";
import { anomaly, awsAccounts, scanner } from "../services/api";
import "./AnomalyDetection.css";

const RISK_COLOR = { critical: "#f85149", high: "#d29922", medium: "#58a6ff", low: "#3fb950" };

export default function AnomalyDetection() {
  const [file, setFile] = useState(null);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [modelStatus, setModelStatus] = useState(null);
  const [evaluation, setEvaluation] = useState(null);

  // CloudTrail state
  const [accounts, setAccounts] = useState([]);
  const [selectedAccount, setSelectedAccount] = useState(null);
  const [ctLoading, setCtLoading] = useState(false);
  const [ctResults, setCtResults] = useState(null);
  const [ctError, setCtError] = useState(null);

  // VPC Flow Log + ML state
  const [vpcLoading, setVpcLoading] = useState(false);
  const [vpcResults, setVpcResults] = useState(null);
  const [vpcError, setVpcError] = useState(null);
  const [vpcHours, setVpcHours] = useState(1);

  useEffect(() => {
    anomaly.status().then((r) => setModelStatus(r.data)).catch(() => {});
    anomaly.evaluation().then((r) => setEvaluation(r.data)).catch(() => {});
    awsAccounts.list().then((r) => {
      const active = (r.data || []).filter((a) => a.is_active);
      setAccounts(active);
      if (active.length > 0) setSelectedAccount(active[0]);
    }).catch(() => {});
  }, []);

  const detect = async () => {
    if (!file) return;
    setLoading(true);
    setError(null);
    try {
      const { data } = await anomaly.detect(file);
      setResult(data);
    } catch (e) {
      setError(e.response?.data?.detail || "Detection failed");
    } finally {
      setLoading(false);
    }
  };

  const analyzeCloudTrail = async () => {
    if (!selectedAccount) return;
    setCtLoading(true);
    setCtError(null);
    try {
      const { data } = await scanner.cloudtrailThreats(selectedAccount.id);
      setCtResults(data);
    } catch (e) {
      setCtError(e.response?.data?.detail || "CloudTrail analysis failed");
    } finally {
      setCtLoading(false);
    }
  };

  const anomalies = result?.anomalous_entries || result?.anomalies || [];
  const chartData = anomalies.length
    ? ["Critical", "High", "Medium", "Low"].map((level) => ({
        name: level.toLowerCase(),
        count: anomalies.filter((a) => a.risk_level === level).length,
      }))
    : [];

  const ctChartData = ctResults ? [
    { name: "critical", count: ctResults.severity_summary?.critical || 0 },
    { name: "high", count: ctResults.severity_summary?.high || 0 },
    { name: "medium", count: ctResults.severity_summary?.medium || 0 },
    { name: "low", count: ctResults.severity_summary?.low || 0 },
  ] : [];

  return (
    <div className="page">
      <h1 className="page-title">Threat Detection</h1>
      <p className="page-sub">
        CloudTrail threat analysis + ML-based network anomaly detection
      </p>

      {/* ── CloudTrail Threat Analysis ─────────────────────── */}
      <div className="section-divider">
        <h2 className="section-title">CloudTrail Threat Analysis</h2>
        <p className="section-sub">Real-time detection of suspicious AWS API activity</p>
      </div>

      {accounts.length === 0 ? (
        <div className="result-wrap" style={{ textAlign: "center", padding: "2rem" }}>
          <p style={{ color: "#8b949e" }}>Connect an AWS account first to analyze CloudTrail events.</p>
        </div>
      ) : (
        <>
          <div className="ct-controls">
            <select
              className="ct-select"
              value={selectedAccount?.id || ""}
              onChange={(e) => {
                const acc = accounts.find((a) => a.id === e.target.value);
                if (acc) setSelectedAccount(acc);
              }}
            >
              {accounts.map((a) => (
                <option key={a.id} value={a.id}>{a.account_alias}</option>
              ))}
            </select>
            <button
              className="btn primary"
              onClick={analyzeCloudTrail}
              disabled={ctLoading}
            >
              {ctLoading ? "Analyzing..." : "Analyze Threats (Last 24h)"}
            </button>
          </div>

          {ctError && <div className="error-msg">{ctError}</div>}

          {ctResults && (
            <div className="result-wrap">
              <div className="ct-summary">
                <div className="ct-stat">
                  <div className="ct-stat-val">{ctResults.total_events}</div>
                  <div className="ct-stat-label">Events Analyzed</div>
                </div>
                <div className="ct-stat">
                  <div className="ct-stat-val" style={{
                    color: ctResults.total_threats > 0 ? "#f85149" : "#3fb950"
                  }}>
                    {ctResults.total_threats}
                  </div>
                  <div className="ct-stat-label">Threats Found</div>
                </div>
                <div className="ct-stat">
                  <div className="ct-stat-val" style={{ color: "#f85149" }}>
                    {ctResults.severity_summary?.critical || 0}
                  </div>
                  <div className="ct-stat-label">Critical</div>
                </div>
                <div className="ct-stat">
                  <div className="ct-stat-val" style={{ color: "#d29922" }}>
                    {ctResults.severity_summary?.high || 0}
                  </div>
                  <div className="ct-stat-label">High</div>
                </div>
                <div className="ct-stat">
                  <div className="ct-stat-val" style={{ color: "#58a6ff" }}>
                    {ctResults.severity_summary?.medium || 0}
                  </div>
                  <div className="ct-stat-label">Medium</div>
                </div>
              </div>

              {ctChartData.some((d) => d.count > 0) && (
                <div className="chart-wrap">
                  <h4>Threats by Severity</h4>
                  <ResponsiveContainer width="100%" height={180}>
                    <BarChart data={ctChartData} margin={{ top: 5, right: 20, left: 0, bottom: 5 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#21262d" />
                      <XAxis dataKey="name" stroke="#484f58" tick={{ fill: "#8b949e", fontSize: 12 }} />
                      <YAxis stroke="#484f58" tick={{ fill: "#8b949e", fontSize: 12 }} />
                      <Tooltip contentStyle={{ background: "#161b22", border: "1px solid #21262d", color: "#c9d1d9" }} />
                      <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                        {ctChartData.map((d) => (
                          <Cell key={d.name} fill={RISK_COLOR[d.name]} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              )}

              {ctResults.threats && ctResults.threats.length > 0 && (
                <div className="anomaly-table-wrap">
                  <h4>Detected Threats ({ctResults.threats.length})</h4>
                  <table className="anomaly-table">
                    <thead>
                      <tr>
                        <th>Severity</th>
                        <th>Threat</th>
                        <th>Event</th>
                        <th>User</th>
                        <th>Source IP</th>
                        <th>Time</th>
                      </tr>
                    </thead>
                    <tbody>
                      {ctResults.threats.map((t, i) => (
                        <tr key={i}>
                          <td>
                            <span className="risk-badge" style={{
                              color: RISK_COLOR[t.severity],
                              background: (RISK_COLOR[t.severity] || "#8b949e") + "22"
                            }}>
                              {t.severity}
                            </span>
                          </td>
                          <td>
                            <div className="threat-title">{t.title}</div>
                            <div className="threat-desc">{t.description}</div>
                          </td>
                          <td className="mono">{t.event_name}</td>
                          <td>{t.username || "\u2014"}</td>
                          <td className="mono">{t.source_ip || "\u2014"}</td>
                          <td className="time-cell">{t.event_time ? new Date(t.event_time).toLocaleString() : "\u2014"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

              {ctResults.threats && ctResults.threats.length === 0 && (
                <div className="no-threats">
                  <span className="no-threats-icon">&#x2714;</span>
                  No threats detected in the last {ctResults.analysis_period || "24 hours"}
                </div>
              )}

              {ctResults.activity_summary && (
                <div className="activity-summary">
                  <h4>Activity Summary</h4>
                  <div className="activity-grid">
                    <div className="activity-item">
                      <span className="activity-label">Unique IPs</span>
                      <span className="activity-val">{ctResults.activity_summary.unique_ips?.length || 0}</span>
                    </div>
                    <div className="activity-item">
                      <span className="activity-label">Unique Users</span>
                      <span className="activity-val">{ctResults.activity_summary.unique_users?.length || 0}</span>
                    </div>
                    <div className="activity-item">
                      <span className="activity-label">Total API Calls</span>
                      <span className="activity-val">{ctResults.activity_summary.event_count || 0}</span>
                    </div>
                  </div>
                  {ctResults.activity_summary.top_events?.length > 0 && (
                    <div className="top-events">
                      <h5>Top API Calls</h5>
                      {ctResults.activity_summary.top_events.map(([name, count]) => (
                        <div key={name} className="top-event-row">
                          <span className="mono">{name}</span>
                          <span className="event-count">{count}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </>
      )}

      {/* ── ML Network Anomaly Detection (Live VPC Flow Logs) ──── */}
      <div className="section-divider" style={{ marginTop: "2.5rem" }}>
        <h2 className="section-title">ML Network Anomaly Detection</h2>
        <p className="section-sub">
          Isolation Forest + One-Class SVM + Autoencoder ensemble on live VPC Flow Logs
        </p>
      </div>

      <div className="model-status-row">
        <div className={`model-badge ${modelStatus?.status === "ready" ? "trained" : "untrained"}`}>
          {modelStatus?.status === "ready" ? "Models ready" : "Models not trained \u2014 run trainer first"}
        </div>
      </div>

      {accounts.length === 0 ? (
        <div className="result-wrap" style={{ textAlign: "center", padding: "2rem" }}>
          <p style={{ color: "#8b949e" }}>Connect an AWS account first to analyze VPC Flow Logs.</p>
        </div>
      ) : (
        <>
          <div className="ct-controls">
            <select
              className="ct-select"
              value={selectedAccount?.id || ""}
              onChange={(e) => {
                const acc = accounts.find((a) => a.id === e.target.value);
                if (acc) setSelectedAccount(acc);
              }}
            >
              {accounts.map((a) => (
                <option key={a.id} value={a.id}>{a.account_alias}</option>
              ))}
            </select>
            <select
              className="ct-select"
              style={{ minWidth: 120 }}
              value={vpcHours}
              onChange={(e) => setVpcHours(Number(e.target.value))}
            >
              <option value={1}>Last 1 hour</option>
              <option value={3}>Last 3 hours</option>
              <option value={6}>Last 6 hours</option>
              <option value={12}>Last 12 hours</option>
              <option value={24}>Last 24 hours</option>
            </select>
            <button
              className="btn primary"
              onClick={async () => {
                if (!selectedAccount) return;
                setVpcLoading(true);
                setVpcError(null);
                try {
                  const { data } = await scanner.vpcFlowLogAnalysis(selectedAccount.id, vpcHours);
                  setVpcResults(data);
                } catch (e) {
                  setVpcError(e.response?.data?.detail || "VPC Flow Log analysis failed");
                } finally {
                  setVpcLoading(false);
                }
              }}
              disabled={vpcLoading}
            >
              {vpcLoading ? "Analyzing..." : "Analyze VPC Traffic"}
            </button>
          </div>

          {vpcError && <div className="error-msg">{vpcError}</div>}

          {vpcResults && vpcResults.status === "no_flow_logs" && (
            <div className="result-wrap">
              <h4 style={{ color: "#d29922" }}>VPC Flow Logs Not Enabled</h4>
              <p style={{ color: "#8b949e", marginBottom: 12 }}>{vpcResults.message}</p>
              <div style={{ background: "#0d1117", borderRadius: 6, padding: 16 }}>
                <p style={{ color: "#e6edf3", fontWeight: 600, marginBottom: 8 }}>Setup Instructions:</p>
                {vpcResults.setup_instructions?.map((step, i) => (
                  <p key={i} style={{ color: "#8b949e", fontSize: "0.85rem", margin: "4px 0" }}>{step}</p>
                ))}
              </div>
            </div>
          )}

          {vpcResults && vpcResults.status === "no_events" && (
            <div className="result-wrap" style={{ textAlign: "center", padding: "2rem" }}>
              <p style={{ color: "#d29922" }}>{vpcResults.message}</p>
            </div>
          )}

          {vpcResults && vpcResults.status === "completed" && (
            <div className="result-wrap">
              <div className="anomaly-stats">
                <div className="a-stat">
                  <div className="a-val">{vpcResults.parsed_events}</div>
                  <div className="a-label">Flow Logs Analyzed</div>
                </div>
                <div className="a-stat">
                  <div className="a-val" style={{
                    color: vpcResults.risk_level === "Critical" ? "#f85149"
                      : vpcResults.risk_level === "High" ? "#d29922"
                      : vpcResults.risk_level === "Medium" ? "#58a6ff"
                      : "#3fb950"
                  }}>
                    {vpcResults.anomalies_detected}
                  </div>
                  <div className="a-label">Anomalies</div>
                </div>
                <div className="a-stat">
                  <div className="a-val" style={{ color: vpcResults.anomaly_percentage > 10 ? "#f85149" : "#3fb950" }}>
                    {vpcResults.anomaly_percentage}%
                  </div>
                  <div className="a-label">Anomaly Rate</div>
                </div>
                <div className="a-stat">
                  <div className="a-val" style={{
                    color: vpcResults.risk_level === "Critical" ? "#f85149"
                      : vpcResults.risk_level === "High" ? "#d29922"
                      : vpcResults.risk_level === "Medium" ? "#58a6ff"
                      : "#3fb950"
                  }}>
                    {vpcResults.risk_level}
                  </div>
                  <div className="a-label">Risk Level</div>
                </div>
              </div>

              {/* Model Agreement Summary */}
              {vpcResults.model_summary && (
                <div className="eval-grid" style={{ marginBottom: 20 }}>
                  {Object.entries(vpcResults.model_summary).map(([model, count]) => (
                    <div key={model} className="eval-card">
                      <div className="eval-model">{model.replace(/_/g, " ")}</div>
                      <div className="eval-row">
                        <span>flagged</span>
                        <span>{count}</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {/* Traffic Summary */}
              {vpcResults.traffic_summary && (
                <div style={{ marginBottom: 20 }}>
                  <h4>Traffic Summary</h4>
                  <div className="activity-grid">
                    <div className="activity-item">
                      <span className="activity-label">Unique Source IPs</span>
                      <span className="activity-val">{vpcResults.traffic_summary.unique_source_ips}</span>
                    </div>
                    <div className="activity-item">
                      <span className="activity-label">Unique Dest IPs</span>
                      <span className="activity-val">{vpcResults.traffic_summary.unique_dest_ips}</span>
                    </div>
                    <div className="activity-item">
                      <span className="activity-label">Total Bytes</span>
                      <span className="activity-val">{(vpcResults.traffic_summary.total_bytes / 1024).toFixed(1)} KB</span>
                    </div>
                    <div className="activity-item">
                      <span className="activity-label">Total Packets</span>
                      <span className="activity-val">{vpcResults.traffic_summary.total_packets}</span>
                    </div>
                  </div>
                  {vpcResults.traffic_summary.protocols && (
                    <div style={{ marginTop: 12 }}>
                      <h5 style={{ color: "#8b949e", fontSize: "0.8rem", marginBottom: 6 }}>Protocols</h5>
                      <div style={{ display: "flex", gap: 16 }}>
                        {Object.entries(vpcResults.traffic_summary.protocols).map(([proto, count]) => (
                          <span key={proto} style={{ color: "#58a6ff", fontSize: "0.85rem" }}>
                            {proto}: <span style={{ color: "#c9d1d9" }}>{count}</span>
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                  {vpcResults.traffic_summary.top_dest_ports?.length > 0 && (
                    <div className="top-events" style={{ marginTop: 12 }}>
                      <h5>Top Destination Ports</h5>
                      {vpcResults.traffic_summary.top_dest_ports.map((p) => (
                        <div key={p.port} className="top-event-row">
                          <span className="mono">{p.port} {p.service && `(${p.service})`}</span>
                          <span className="event-count">{p.count}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Anomalous Entries Table */}
              {vpcResults.anomalous_entries?.length > 0 && (
                <div className="anomaly-table-wrap">
                  <h4>Anomalous Traffic ({vpcResults.anomalous_entries.length})</h4>
                  <table className="anomaly-table">
                    <thead>
                      <tr>
                        <th>Risk</th>
                        <th>Source</th>
                        <th>Destination</th>
                        <th>Port</th>
                        <th>Action</th>
                        <th>Score</th>
                        <th>IF</th>
                        <th>SVM</th>
                        <th>AE</th>
                      </tr>
                    </thead>
                    <tbody>
                      {vpcResults.anomalous_entries.slice(0, 50).map((a, i) => (
                        <tr key={i}>
                          <td>
                            <span className="risk-badge" style={{
                              color: RISK_COLOR[a.risk_level?.toLowerCase()],
                              background: (RISK_COLOR[a.risk_level?.toLowerCase()] || "#8b949e") + "22"
                            }}>
                              {a.risk_level}
                            </span>
                          </td>
                          <td className="mono">{a.srcaddr || "\u2014"}</td>
                          <td className="mono">{a.dstaddr || "\u2014"}</td>
                          <td>{a.dstport || "\u2014"}</td>
                          <td>
                            <span style={{ color: a.action === "REJECT" ? "#f85149" : "#3fb950" }}>
                              {a.action || "\u2014"}
                            </span>
                          </td>
                          <td>{a.anomaly_score?.toFixed(4)}</td>
                          <td>{a.model_agreement?.isolation_forest ? "!" : "ok"}</td>
                          <td>{a.model_agreement?.one_class_svm ? "!" : "ok"}</td>
                          <td>{a.model_agreement?.autoencoder ? "!" : "ok"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

              {vpcResults.anomalous_entries?.length === 0 && (
                <div className="no-threats">
                  <span className="no-threats-icon">&#x2714;</span>
                  No anomalous network traffic detected in the last {vpcHours} hour(s)
                </div>
              )}
            </div>
          )}
        </>
      )}

      {/* ── CSV Upload (Manual) ────────────────────────────────── */}
      <div className="section-divider" style={{ marginTop: "2.5rem" }}>
        <h2 className="section-title">Manual CSV Analysis</h2>
        <p className="section-sub">Upload UNSW-NB15 format CSV for offline anomaly detection</p>
      </div>

      <div className="upload-section">
        <div className="input-row">
          <input
            type="file"
            accept=".csv"
            className="file-input"
            onChange={(e) => setFile(e.target.files[0])}
          />
          <button className="btn primary" onClick={detect} disabled={loading || !file}>
            {loading ? "Detecting..." : "Detect Anomalies"}
          </button>
        </div>
      </div>

      {error && <div className="error-msg">{error}</div>}

      {result && (
        <div className="result-wrap">
          <div className="anomaly-stats">
            <div className="a-stat">
              <div className="a-val">{result.total_logs ?? "\u2014"}</div>
              <div className="a-label">Total Records</div>
            </div>
            <div className="a-stat">
              <div className="a-val" style={{ color: "#f85149" }}>{result.anomalies_detected ?? anomalies.length ?? "\u2014"}</div>
              <div className="a-label">Anomalies</div>
            </div>
            <div className="a-stat">
              <div className="a-val" style={{ color: "#3fb950" }}>{result.anomaly_percentage != null ? result.anomaly_percentage + "%" : "\u2014"}</div>
              <div className="a-label">Anomaly Rate</div>
            </div>
          </div>

          {chartData.some((d) => d.count > 0) && (
            <div className="chart-wrap">
              <h4>Anomalies by Risk Level</h4>
              <ResponsiveContainer width="100%" height={180}>
                <BarChart data={chartData} margin={{ top: 5, right: 20, left: 0, bottom: 5 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#21262d" />
                  <XAxis dataKey="name" stroke="#484f58" tick={{ fill: "#8b949e", fontSize: 12 }} />
                  <YAxis stroke="#484f58" tick={{ fill: "#8b949e", fontSize: 12 }} />
                  <Tooltip contentStyle={{ background: "#161b22", border: "1px solid #21262d", color: "#c9d1d9" }} />
                  <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                    {chartData.map((d) => (
                      <Cell key={d.name} fill={RISK_COLOR[d.name]} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}

          {anomalies.length > 0 && (
            <div className="anomaly-table-wrap">
              <h4>Detected Anomalies ({anomalies.length})</h4>
              <table className="anomaly-table">
                <thead>
                  <tr>
                    <th>#</th>
                    <th>Risk</th>
                    <th>Score</th>
                    <th>IF</th>
                    <th>SVM</th>
                    <th>AE</th>
                    <th>Attack</th>
                  </tr>
                </thead>
                <tbody>
                  {anomalies.slice(0, 50).map((a, i) => (
                    <tr key={i}>
                      <td>{a.index}</td>
                      <td>
                        <span className="risk-badge" style={{ color: RISK_COLOR[a.risk_level?.toLowerCase()], background: (RISK_COLOR[a.risk_level?.toLowerCase()] || "#8b949e") + "22" }}>
                          {a.risk_level}
                        </span>
                      </td>
                      <td>{a.anomaly_score?.toFixed(4)}</td>
                      <td>{a.model_agreement?.isolation_forest ? "!" : "ok"}</td>
                      <td>{a.model_agreement?.one_class_svm ? "!" : "ok"}</td>
                      <td>{a.model_agreement?.autoencoder ? "!" : "ok"}</td>
                      <td>{a.attack_category || "\u2014"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {evaluation && (
        <div className="result-wrap">
          <h4>Model Evaluation Metrics</h4>
          {evaluation.dataset && (
            <p style={{ color: "#8b949e", fontSize: 13, marginBottom: 12 }}>
              Dataset: {evaluation.dataset} | Training: {evaluation.training_samples?.toLocaleString()} | Test: {evaluation.test_samples?.toLocaleString()}
            </p>
          )}
          <div className="eval-grid">
            {Object.entries(evaluation.models || evaluation).map(([model, metrics]) => (
              typeof metrics === "object" && metrics !== null && (
                <div key={model} className="eval-card">
                  <div className="eval-model">{model.replace(/_/g, " ")}</div>
                  {Object.entries(metrics).map(([k, v]) => (
                    <div key={k} className="eval-row">
                      <span>{k.replace(/_/g, " ")}</span>
                      <span>{typeof v === "number" ? v.toFixed(3) : String(v)}</span>
                    </div>
                  ))}
                </div>
              )
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
