import React, { useState, useEffect } from "react";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import Sidebar from "./components/Sidebar";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import AwsConnect from "./pages/AwsConnect";
import Compliance from "./pages/Compliance";
import AnomalyDetection from "./pages/AnomalyDetection";
import AuditTrail from "./pages/AuditTrail";
import Deploy from "./pages/Deploy";
import { auth } from "./services/api";
import "./App.css";

export default function App() {
  const [user, setUser] = useState(null);
  const [checking, setChecking] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem("token");
    if (token) {
      auth.me()
        .then((r) => setUser(r.data))
        .catch(() => localStorage.removeItem("token"))
        .finally(() => setChecking(false));
    } else {
      setChecking(false);
    }
  }, []);

  const handleLogin = (data) => {
    setUser({ email: data.email, id: data.user_id });
  };

  const handleLogout = () => {
    localStorage.removeItem("token");
    localStorage.removeItem("user_email");
    setUser(null);
  };

  if (checking) return null;

  if (!user) return <Login onLogin={handleLogin} />;

  return (
    <BrowserRouter>
      <div className="app-layout">
        <Sidebar user={user} onLogout={handleLogout} />
        <main className="app-main">
          <Routes>
            <Route path="/"           element={<Dashboard />} />
            <Route path="/aws"        element={<AwsConnect />} />
            <Route path="/compliance" element={<Compliance />} />
            <Route path="/deploy"     element={<Deploy />} />
            <Route path="/anomaly"    element={<AnomalyDetection />} />
            <Route path="/audit"      element={<AuditTrail />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}
