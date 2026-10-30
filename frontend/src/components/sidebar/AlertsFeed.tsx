import React, { useMemo } from 'react';
import {
  AlertTriangle, ShieldCheck, Flame, Crosshair, Key,
  UploadCloud, Activity, Clock
} from 'lucide-react';
import { FlowResult } from '../../types/network';
import { timeAgo } from '../../utils/network';

interface AlertsFeedProps {
  flows: FlowResult[];
  onSelectFlow: (flow: FlowResult) => void;
  onSelectNode: (ip: string) => void;
}

function getAttackIcon(scenario?: string) {
  if (!scenario) return <AlertTriangle className="w-3.5 h-3.5 text-medium" />;
  const s = scenario.toLowerCase();
  if (s.includes('scan')) return <Crosshair className="w-3.5 h-3.5 text-yellow-400" />;
  if (s.includes('flood') || s.includes('syn')) return <Flame className="w-3.5 h-3.5 text-high" />;
  if (s.includes('login') || s.includes('auth')) return <Key className="w-3.5 h-3.5 text-amber-400" />;
  if (s.includes('exfiltration') || s.includes('large')) return <UploadCloud className="w-3.5 h-3.5 text-purple-400" />;
  return <Activity className="w-3.5 h-3.5 text-primary" />;
}

export function AlertsFeed({ flows, onSelectFlow, onSelectNode }: AlertsFeedProps) {
  // Filter for medium and high risk flows
  const alerts = useMemo(
    () => flows.filter(f => f.fusion.risk_level !== 'LOW'),
    [flows]
  );

  // Group alerts by Source IP
  const groupedAlerts = useMemo(() => {
    const map = new Map<string, { count: number; highCount: number; flows: FlowResult[] }>();
    alerts.forEach(a => {
      const src = a.source_ip;
      if (!map.has(src)) {
        map.set(src, { count: 0, highCount: 0, flows: [] });
      }
      const entry = map.get(src)!;
      entry.count += 1;
      if (a.fusion.risk_level === 'HIGH') entry.highCount += 1;
      entry.flows.push(a);
    });
    return Array.from(map.entries()).sort((a, b) => b[1].count - a[1].count);
  }, [alerts]);

  return (
    <div className="flex-1 flex flex-col p-4 min-h-0 select-auto">
      {/* Header with counter */}
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-high flex-shrink-0 animate-pulse" />
          <h2 className="font-bold text-xs uppercase tracking-wider text-gray-300">
            Live Threat Stream
          </h2>
        </div>
        {alerts.length > 0 && (
          <span className="text-[10px] font-mono px-2 py-0.5 rounded font-bold bg-high/20 text-high border border-high/40 shadow-glow-high">
            {alerts.length} threats
          </span>
        )}
      </div>

      {/* Top Attackers Summary Ribbon */}
      {groupedAlerts.length > 0 && (
        <div className="mb-3 p-2 bg-background/80 rounded-lg border border-border/80 text-[11px]">
          <div className="text-[10px] font-semibold text-gray-400 uppercase tracking-wider mb-1">
            Top Aggressors
          </div>
          <div className="flex flex-wrap gap-1.5">
            {groupedAlerts.slice(0, 4).map(([ip, data]) => (
              <button
                key={ip}
                onClick={() => onSelectNode(ip)}
                className={`px-2 py-0.5 rounded font-mono text-[10px] border flex items-center gap-1 transition-all hover:border-primary ${
                  data.highCount > 0
                    ? 'bg-high/15 border-high/40 text-high font-bold'
                    : 'bg-medium/15 border-medium/40 text-medium'
                }`}
              >
                <span>{ip}</span>
                <span className="opacity-70">({data.count})</span>
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Alerts Feed List */}
      <div className="flex-1 overflow-y-auto space-y-2 pr-1">
        {alerts.slice(0, 40).map((f, i) => {
          const isNewest = i === 0;
          const isHigh = f.fusion.risk_level === 'HIGH';

          return (
            <div
              key={i}
              onClick={() => onSelectFlow(f)}
              className={`p-2.5 rounded-lg border cursor-pointer transition-all hover:scale-[1.01] ${
                isHigh
                  ? 'bg-high/10 border-high/50 hover:bg-high/15'
                  : 'bg-medium/10 border-medium/50 hover:bg-medium/15'
              } ${isNewest ? 'animate-pulse ring-1 ring-high shadow-glow-high' : ''}`}
            >
              <div className="flex items-center justify-between mb-1">
                <div className="flex items-center gap-1.5">
                  {getAttackIcon(f.demo_scenario)}
                  <span
                    className={`text-[9px] font-bold font-mono px-1.5 py-0.2 rounded uppercase ${
                      isHigh ? 'bg-high/30 text-high' : 'bg-medium/30 text-medium'
                    }`}
                  >
                    {f.fusion.risk_level}
                  </span>
                  {f.demo_scenario && (
                    <span className="text-[10px] font-mono text-gray-300 font-semibold truncate max-w-[110px]">
                      {f.demo_scenario.replace(/_/g, ' ')}
                    </span>
                  )}
                </div>

                <div className="flex items-center gap-1 text-[10px] text-gray-500 font-mono">
                  <Clock className="w-2.5 h-2.5" />
                  <span>{timeAgo(f.timestamp || Date.now() / 1000)}</span>
                </div>
              </div>

              <div className="font-mono text-xs text-gray-200 truncate flex items-center gap-1">
                <span className="hover:underline">{f.source_ip}</span>
                <span className="text-gray-500">→</span>
                <span className="hover:underline">{f.destination_ip}</span>
                <span className="text-gray-500 text-[10px]">:{f.destination_port}</span>
              </div>

              <div className="flex items-center justify-between text-[10px] text-gray-400 mt-1.5 pt-1 border-t border-border/40 font-mono">
                <span>IF: {f.isolation_forest.is_anomaly ? 'ANOMALY' : 'normal'}</span>
                <span>GAT Score: {f.gat.attack_score.toFixed(3)}</span>
                <span className="text-gray-500">{f.protocol}</span>
              </div>
            </div>
          );
        })}

        {alerts.length === 0 && (
          <div className="flex flex-col items-center justify-center py-12 text-gray-500">
            <ShieldCheck className="w-10 h-10 mb-2 text-low/50" />
            <span className="text-xs font-semibold text-gray-400">Zero Anomalies Detected</span>
            <span className="text-[11px] text-gray-600 mt-1 text-center max-w-[200px]">
              The dual AI models report clean network communication patterns.
            </span>
          </div>
        )}
      </div>
    </div>
  );
}
