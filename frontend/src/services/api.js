import axios from "axios";

const BASE = "/api/v1";

const api = axios.create({ baseURL: BASE });

// ── Auth interceptor: attach JWT to every request ──────────
api.interceptors.request.use((config) => {
  const token = localStorage.getItem("token");
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

// ── Auth ────────────────────────────────────────────────────
export const auth = {
  signup: (data) => api.post("/auth/signup", data),
  login: (email, password) => {
    const fd = new URLSearchParams();
    fd.append("username", email);
    fd.append("password", password);
    return api.post("/auth/login", fd, {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
    });
  },
  me: () => api.get("/auth/me"),
};

// ── AWS Accounts ────────────────────────────────────────────
export const awsAccounts = {
  connect: (data) => api.post("/aws-accounts/connect", data),
  list: () => api.get("/aws-accounts/"),
  disconnect: (id) => api.delete(`/aws-accounts/${id}`),
  cfnTemplate: () => api.get("/aws-accounts/cloudformation-template"),
};

// ── Live Scanner ────────────────────────────────────────────
export const scanner = {
  scan: (accountId) => api.post(`/scanner/${accountId}/scan`),
  history: (accountId) => api.get(`/scanner/${accountId}/history`),
  findings: (scanId) => api.get(`/scanner/results/${scanId}`),
};

// ── Compliance (Terraform / LocalStack) ─────────────────────
export const compliance = {
  scan: (bucket) => api.get(`/compliance/scan/${bucket}`),
  scanAll: () => api.get("/compliance/scan-all"),
  scanTerraform: (file) => {
    const fd = new FormData();
    fd.append("file", file);
    return api.post("/compliance/terraform", fd);
  },
};

// ── Anomaly Detection ───────────────────────────────────────
export const anomaly = {
  detect: (file) => {
    const fd = new FormData();
    fd.append("file", file);
    return api.post("/anomaly/detect", fd);
  },
  status: () => api.get("/anomaly/status"),
  evaluation: () => api.get("/anomaly/evaluation"),
};

// ── Audit Trail ─────────────────────────────────────────────
export const audit = {
  trail: () => api.get("/audit/blockchain"),
  stats: () => api.get("/audit/stats"),
};

// ── Deploy (Digital Twin) ───────────────────────────────────
export const deploy = {
  infrastructure: (config) => api.post("/deploy/infrastructure", config),
  destroy: () => api.post("/deploy/destroy"),
  status: () => api.get("/deploy/status"),
};

// ── Reports ─────────────────────────────────────────────────
export const reports = {
  compliance: (bucket) => `/api/v1/reports/compliance/${bucket}`,
  full: () => `/api/v1/reports/full`,
};

// ── Health ──────────────────────────────────────────────────
export const health = () => api.get("/health");
