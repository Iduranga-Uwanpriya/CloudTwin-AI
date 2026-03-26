import React from "react";
import { NavLink } from "react-router-dom";
import "./Sidebar.css";

const links = [
  { to: "/", label: "Dashboard", icon: "⬡" },
  { to: "/aws", label: "Connect AWS", icon: "☁" },
  { to: "/compliance", label: "Compliance", icon: "✔" },
  { to: "/deploy", label: "Digital Twin", icon: "⎈" },
  { to: "/anomaly", label: "Anomaly Detection", icon: "⚠" },
  { to: "/audit", label: "Audit Trail", icon: "⛓" },
];

export default function Sidebar({ user, onLogout }) {
  return (
    <nav className="sidebar">
      <div className="sidebar-brand">
        <span className="brand-icon">⬡</span>
        <span className="brand-name">CloudTwin AI</span>
      </div>
      <ul className="sidebar-nav">
        {links.map(({ to, label, icon }) => (
          <li key={to}>
            <NavLink
              to={to}
              end={to === "/"}
              className={({ isActive }) => "nav-link" + (isActive ? " active" : "")}
            >
              <span className="nav-icon">{icon}</span>
              <span>{label}</span>
            </NavLink>
          </li>
        ))}
      </ul>
      <div className="sidebar-footer">
        {user && (
          <div className="user-section">
            <span className="user-email">{user.email}</span>
            <button className="logout-btn" onClick={onLogout}>Logout</button>
          </div>
        )}
        <span>ISO 27001 · NIST 800-53</span>
      </div>
    </nav>
  );
}
