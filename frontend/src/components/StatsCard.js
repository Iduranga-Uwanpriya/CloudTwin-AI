import React from "react";
import "./StatsCard.css";

export default function StatsCard({ title, value, sub, color = "#58a6ff", icon }) {
  return (
    <div className="stats-card">
      <div className="stats-header">
        <span className="stats-title">{title}</span>
        {icon && <span className="stats-icon">{icon}</span>}
      </div>
      <div className="stats-value" style={{ color }}>{value}</div>
      {sub && <div className="stats-sub">{sub}</div>}
    </div>
  );
}
