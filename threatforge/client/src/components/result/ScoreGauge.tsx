import React from "react";

interface ScoreGaugeProps {
  score: number; // 0.0 to 1.0
  verdict: string;
  threatLevel: string;
}

export const ScoreGauge: React.FC<ScoreGaugeProps> = ({ score, verdict, threatLevel }) => {
  const percentage = Math.round(score * 100);
  const radius = 80;
  const strokeWidth = 14;
  const circumference = 2 * Math.PI * radius;
  // Use 240 degrees arc (approx 0.66 of circle)
  const arcLength = circumference * 0.75;
  const strokeDashoffset = arcLength - (arcLength * percentage) / 100;

  const getScoreColor = () => {
    if (verdict === "UNKNOWN") return "var(--text-muted)";
    if (percentage < 35) return "#94d2bd"; // pearl-aqua
    if (percentage < 65) return "#ee9b00"; // golden-orange
    if (percentage < 85) return "#bb3e03"; // rusty-spice
    return "#ae2012"; // oxidized-iron
  };

  const scoreColor = getScoreColor();

  return (
    <div className="flex flex-col items-center justify-center p-6 rounded-3xl border border-[var(--border-theme)] bg-[var(--bg-surface-1)] shadow-xl relative overflow-hidden">
      <div className="relative w-52 h-52 flex items-center justify-center">
        <svg className="w-full h-full -rotate-135 transform" viewBox="0 0 200 200">
          <defs>
            <linearGradient id="gaugeGradient" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#94d2bd" />
              <stop offset="35%" stopColor="#ee9b00" />
              <stop offset="70%" stopColor="#bb3e03" />
              <stop offset="100%" stopColor="#ae2012" />
            </linearGradient>
          </defs>

          {/* Background Track */}
          <circle
            cx="100"
            cy="100"
            r={radius}
            fill="transparent"
            stroke="var(--bg-surface-3)"
            strokeWidth={strokeWidth}
            strokeDasharray={`${arcLength} ${circumference}`}
            strokeLinecap="round"
          />

          {/* Progress Arc */}
          <circle
            cx="100"
            cy="100"
            r={radius}
            fill="transparent"
            stroke="url(#gaugeGradient)"
            strokeWidth={strokeWidth}
            strokeDasharray={`${arcLength} ${circumference}`}
            strokeDashoffset={verdict === "UNKNOWN" ? arcLength : strokeDashoffset}
            strokeLinecap="round"
            className="transition-all duration-1000 ease-out"
          />
        </svg>

        {/* Center Content */}
        <div className="absolute inset-0 flex flex-col items-center justify-center text-center select-none">
          <span className="text-[11px] font-mono uppercase text-[var(--text-muted)] tracking-wider">
            Model Score
          </span>
          <span
            className="text-4xl font-extrabold font-mono tracking-tight my-0.5"
            style={{ color: scoreColor }}
          >
            {verdict === "UNKNOWN" ? "N/A" : `${percentage}%`}
          </span>
          <div
            className="text-[10px] font-mono px-2 py-0.5 rounded-full font-bold uppercase tracking-wider mt-1 border"
            style={{
              borderColor: scoreColor,
              backgroundColor: `${scoreColor}22`,
              color: scoreColor,
            }}
          >
            {threatLevel} Threat
          </div>
        </div>
      </div>

      <div className="mt-2 text-center">
        <span className="text-[11px] text-[var(--text-muted)] font-mono">
          Random Forest Output Confidence
        </span>
      </div>
    </div>
  );
};
