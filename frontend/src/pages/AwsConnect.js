import React, { useState, useEffect } from "react";
import { awsAccounts, scanner } from "../services/api";
import "./AwsConnect.css";

export default function AwsConnect() {
  const [accounts, setAccounts] = useState([]);
  const [alias, setAlias] = useState("");
  const [roleArn, setRoleArn] = useState("");
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(null);
  const [connecting, setConnecting] = useState(false);
  const [scanning, setScanning] = useState({});
  const [scanResults, setScanResults] = useState({});

  useEffect(() => {
    loadAccounts();
  }, []);

  const loadAccounts = async () => {
    try {
      const { data } = await awsAccounts.list();
      setAccounts(data);
    } catch {
      // not connected yet
    }
  };

  const downloadTemplate = async () => {
    try {
      const { data } = await awsAccounts.cfnTemplate();
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "cloudtwin-readonly-role.template.json";
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      setError("Failed to download template");
    }
  };

  const handleConnect = async (e) => {
    e.preventDefault();
    setConnecting(true);
    setError(null);
    setSuccess(null);
    try {
      const { data } = await awsAccounts.connect({ account_alias: alias, role_arn: roleArn });
      setSuccess(data);
      setAlias("");
      setRoleArn("");
      loadAccounts();
    } catch (e) {
      setError(e.response?.data?.detail || "Failed to connect");
    } finally {
      setConnecting(false);
    }
  };

  const handleScan = async (accountId) => {
    setScanning((s) => ({ ...s, [accountId]: true }));
    try {
      const { data } = await scanner.scan(accountId);
      setScanResults((r) => ({ ...r, [accountId]: data }));
      loadAccounts();
    } catch (e) {
      setScanResults((r) => ({
        ...r,
        [accountId]: { error: e.response?.data?.detail || "Scan failed" },
      }));
    } finally {
      setScanning((s) => ({ ...s, [accountId]: false }));
    }
  };

  const handleDisconnect = async (id) => {
    if (!window.confirm("Disconnect this AWS account?")) return;
    await awsAccounts.disconnect(id);
    loadAccounts();
  };

  return (
    <div className="page">
      <h1 className="page-title">Connect AWS Account</h1>
      <p className="page-sub">
        Securely connect your AWS account using a read-only cross-account IAM role
      </p>

      {/* Setup instructions */}
      <div className="setup-box">
        <h3>Setup Instructions</h3>
        <ol>
          <li>Download the CloudFormation template below</li>
          <li>Go to your AWS Console &rarr; CloudFormation &rarr; Create Stack</li>
          <li>Upload the template file</li>
          <li>Set the <strong>ExternalId</strong> parameter (provided after connecting below)</li>
          <li>Wait for stack to complete — it creates a read-only IAM role</li>
          <li>Copy the <strong>Role ARN</strong> from the stack outputs</li>
          <li>Paste it below and click Connect</li>
        </ol>
        <button className="btn download-btn" onClick={downloadTemplate}>
          Download CloudFormation Template
        </button>
      </div>

      {/* Connect form */}
      <form className="connect-form" onSubmit={handleConnect}>
        <div className="form-row">
          <input
            placeholder="Account Name (e.g. Production)"
            value={alias}
            onChange={(e) => setAlias(e.target.value)}
            required
          />
          <input
            placeholder="Role ARN (arn:aws:iam::123456789012:role/CloudTwinAI-ReadOnly)"
            value={roleArn}
            onChange={(e) => setRoleArn(e.target.value)}
            required
            className="arn-input"
          />
          <button type="submit" className="btn primary" disabled={connecting}>
            {connecting ? "Connecting..." : "Connect"}
          </button>
        </div>
      </form>

      {error && <div className="error-msg">{error}</div>}

      {success && (
        <div className="success-msg">
          <strong>Account connected!</strong>
          <br />
          ExternalId: <code>{success.account.external_id}</code>
          <br />
          <small>Use this ExternalId in your CloudFormation stack parameters.</small>
        </div>
      )}

      {/* Connected accounts */}
      {accounts.length > 0 && (
        <div className="accounts-section">
          <h3>Connected Accounts</h3>
          {accounts.filter((a) => a.is_active).map((a) => (
            <div key={a.id} className="account-card">
              <div className="account-info">
                <div className="account-alias">{a.account_alias}</div>
                <div className="account-arn">{a.role_arn}</div>
                <div className="account-meta">
                  ExternalId: <code>{a.external_id}</code>
                  {a.last_scanned_at && (
                    <span> | Last scan: {new Date(a.last_scanned_at).toLocaleString()}</span>
                  )}
                </div>
              </div>
              <div className="account-actions">
                <button
                  className="btn primary"
                  onClick={() => handleScan(a.id)}
                  disabled={scanning[a.id]}
                >
                  {scanning[a.id] ? "Scanning..." : "Scan Now"}
                </button>
                <button className="btn danger" onClick={() => handleDisconnect(a.id)}>
                  Disconnect
                </button>
              </div>

              {scanResults[a.id] && (
                <div className={`scan-result ${scanResults[a.id].error ? "scan-error" : ""}`}>
                  {scanResults[a.id].error ? (
                    <div className="error-msg">{scanResults[a.id].error}</div>
                  ) : (
                    <div className="scan-summary">
                      <div className="scan-score">
                        <span className={`score ${scanResults[a.id].overall_score >= 80 ? "good" : scanResults[a.id].overall_score >= 50 ? "warn" : "bad"}`}>
                          {scanResults[a.id].overall_score}%
                        </span>
                        <span className="score-label">Compliance Score</span>
                      </div>
                      <div className="scan-stats">
                        <div><strong>{scanResults[a.id].resources_scanned}</strong> resources</div>
                        <div><strong>{scanResults[a.id].total_checks}</strong> checks</div>
                        <div className="pass">{scanResults[a.id].passed_checks} passed</div>
                        <div className="fail">{scanResults[a.id].failed_checks} failed</div>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
