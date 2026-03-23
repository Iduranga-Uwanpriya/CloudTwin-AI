import React, { useState, useEffect } from "react";
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell
} from "recharts";
import { anomaly } from "../services/api";
import "./AnomalyDetection.css";

const RISK_COLOR = { critical: "#f85149", high: "#d29922", medium: "#58a6ff", low: "#3fb950" };

export default function AnomalyDetection() {
  const [file, setFile] = useState(null);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [modelStatus, setModelStatus] = useState(null);
  const [evaluation, setEvaluation] = useState(null);

  useEffect(() => {
    anomaly.status().then((r) => setModelStatus(r.data)).catch(() => {});
    anomaly.evaluation().then((r) => setEvaluation(r.data)).catch(() => {});
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

  const anomalies = result?.anomalous_entries || result?.anomalies || [];
  const chartData = anomalies.length
    ? ["Critical", "High", "Medium", "Low"].map((level) => ({
        name: level.toLowerCase(),
        count: anomalies.filter((a) => a.risk_level === level).length,
      }))
    : [];

  return (
    <div className="page">
      <h1 className="page-title">Anomaly Detection</h1>
      <p className="page-sub">
        Isolation Forest · One-Class SVM · Autoencoder ensemble on CloudTrail &amp; VPC Flow logs
      </p>

      <div className="model-status-row">
        <div className={`model-badge ${modelStatus?.status === "ready" ? "trained" : "untrained"}`}>
          {modelStatus?.status === "ready" ? "Models ready" : "Models not trained — run trainer first"}
        </div>
      </div>

      <div className="upload-section">
        <label className="upload-label">
          Upload log CSV (CloudTrail / VPC Flow)
        </label>
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
              <div className="a-val">{result.total_logs ?? "—"}</div>
              <div className="a-label">Total Records</div>
            </div>
            <div className="a-stat">
              <div className="a-val" style={{ color: "#f85149" }}>{result.anomalies_detected ?? anomalies.length ?? "—"}</div>
              <div className="a-label">Anomalies</div>
            </div>
            <div className="a-stat">
              <div className="a-val" style={{ color: "#3fb950" }}>{result.anomaly_percentage != null ? result.anomaly_percentage + "%" : "—"}</div>
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
                      <td>{a.attack_category || "—"}</td>
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
          <div className="eval-grid">
            {Object.entries(evaluation).map(([model, metrics]) => (
              <div key={model} className="eval-card">
                <div className="eval-model">{model}</div>
                {typeof metrics === "object" && Object.entries(metrics).map(([k, v]) => (
                  <div key={k} className="eval-row">
                    <span>{k}</span>
                    <span>{typeof v === "number" ? v.toFixed(3) : String(v)}</span>
                  </div>
                ))}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
