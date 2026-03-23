import React from "react";
import { RadialBarChart, RadialBar, PolarAngleAxis } from "recharts";

export default function ComplianceGauge({ score = 0, size = 140 }) {
  const color = score >= 80 ? "#3fb950" : score >= 50 ? "#d29922" : "#f85149";
  const data = [{ value: score, fill: color }];

  return (
    <div style={{ display: "inline-block", textAlign: "center", position: "relative" }}>
      <RadialBarChart
        width={size}
        height={size}
        cx={size / 2}
        cy={size / 2}
        innerRadius={size * 0.35}
        outerRadius={size * 0.48}
        data={data}
        startAngle={90}
        endAngle={-270}
      >
        <PolarAngleAxis type="number" domain={[0, 100]} tick={false} />
        <RadialBar dataKey="value" cornerRadius={4} background={{ fill: "#21262d" }} />
      </RadialBarChart>
      <div style={{
        position: "absolute",
        top: "50%",
        left: "50%",
        transform: "translate(-50%, -50%)",
        color,
        fontWeight: 700,
        fontSize: size * 0.16,
      }}>
        {Math.round(score)}%
      </div>
    </div>
  );
}
