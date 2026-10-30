import React from 'react';
import { X, ArrowRight, ShieldAlert, Cpu, Network, CheckCircle, AlertTriangle } from 'lucide-react';
import { FlowResult } from '../../types/network';
import { formatBytes } from '../../utils/network';

interface FlowDetailsProps {
  flow: FlowResult;
  onClose: () => void;
  onSelectNode: (ip: string) => void;
}

export function FlowDetails({ flow, onClose, onSelectNode }: FlowDetailsProps) {
  const { isolation_forest: ifResult, gat: gatResult, fusion } = flow;

  // GAT Attack Score Bar calculation: 0.0 to 1.0, threshold at 0.8
  const gatScore = Math.max(0, Math.min(1, gatResult.attack_score || 0));
  const gatThreshold = gatResult.threshold || 0.8;
  const gatPct = Math.round(gatScore * 100);
  const gatThresholdPct = Math.round(gatThreshold * 100);

  // Isolation Forest Score: decision_function is typically around -0.5 to +0.5.
  // < 0 is anomaly, > 0 is normal. Normalize visually to 0-100% scale where 50% is 0.0 threshold.
  const ifScore = ifResult.decision_score;
  const ifNormalized = Math.max(0, Math.min(100, Math.round((ifScore + 0.5) * 100)));

  // Model Agreement:
  const ifAnomaly = ifResult.is_anomaly;
  const gatAnomaly = gatResult.is_anomaly;
  const modelsAgree = ifAnomaly === gatAnomaly;

  return (
    <div className="p-4 border-b border-border/80 text-xs">
      {/* Header */}
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-1.5 font-bold uppercase tracking-wider text-gray-300">
          <Network className="w-4 h-4 text-primary" />
          <span>Flow Inspection</span>
        </div>
        <button
          onClick={onClose}
          className="text-gray-500 hover:text-white p-1 rounded hover:bg-border/40 transition-colors"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Endpoints & Protocol */}
      <div className="bg-background/90 p-3 rounded-lg border border-border/80 mb-3 space-y-2">
        <div className="flex items-center justify-between gap-1 text-xs font-mono">
          <span
            onClick={() => onSelectNode(flow.source_ip)}
            className="text-primary hover:underline cursor-pointer truncate max-w-[120px] select-all font-bold"
            title="Click to focus Source Node"
          >
            {flow.source_ip}
          </span>
          <span className="text-gray-500">:{flow.source_port}</span>
          <ArrowRight className="w-3.5 h-3.5 text-gray-500 flex-shrink-0" />
          <span
            onClick={() => onSelectNode(flow.destination_ip)}
            className="text-cyan-400 hover:underline cursor-pointer truncate max-w-[120px] select-all font-bold"
            title="Click to focus Destination Node"
          >
            {flow.destination_ip}
          </span>
          <span className="text-gray-500">:{flow.destination_port}</span>
        </div>

        <div className="flex items-center justify-between text-[11px] pt-1 border-t border-border/50">
          <span className="text-gray-400">Protocol: <strong className="text-white">{flow.protocol}</strong></span>
          {flow.demo_scenario && (
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-medium/20 text-yellow-300 border border-medium/40 font-semibold uppercase">
              {flow.demo_scenario.replace(/_/g, ' ')}
            </span>
          )}
        </div>
      </div>

      {/* Flow Statistics */}
      <div className="grid grid-cols-2 gap-2 mb-3">
        <div className="bg-background/60 p-2 rounded border border-border/50">
          <span className="text-[10px] text-gray-500 uppercase">Packets</span>
          <div className="text-sm font-bold font-mono text-white">{(flow.packet_count || 0).toLocaleString()}</div>
        </div>
        <div className="bg-background/60 p-2 rounded border border-border/50">
          <span className="text-[10px] text-gray-500 uppercase">Bytes</span>
          <div className="text-sm font-bold font-mono text-white">{formatBytes(flow.byte_count || 0)}</div>
        </div>
      </div>

      {/* ── AI MODEL CONSENSUS DISPLAY ────────────────────────────────────── */}
      <div className="bg-background/80 p-3 rounded-lg border border-border/70 mb-3 space-y-3">
        <div className="flex items-center justify-between">
          <span className="font-semibold text-gray-300 text-[11px] flex items-center gap-1">
            <Cpu className="w-3.5 h-3.5 text-primary" /> Model Consensus
          </span>
          <span
            className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold border flex items-center gap-1 ${
              modelsAgree
                ? 'bg-low/20 text-low border-low/40'
                : 'bg-medium/20 text-medium border-medium/40'
            }`}
          >
            {modelsAgree ? <CheckCircle className="w-3 h-3" /> : <AlertTriangle className="w-3 h-3" />}
            {modelsAgree ? 'Models Agree' : 'Disagreement'}
          </span>
        </div>

        {/* Indicator Dots */}
        <div className="flex items-center justify-around py-1.5 px-2 bg-panel/50 rounded border border-border/50">
          <div className="flex items-center gap-2">
            <span
              className={`w-2.5 h-2.5 rounded-full ${
                ifAnomaly ? 'bg-high shadow-glow-high' : 'bg-low'
              }`}
            />
            <span className="text-[11px] font-mono text-gray-300">
              IsoForest: <strong className={ifAnomaly ? 'text-high' : 'text-low'}>{ifAnomaly ? 'ANOMALY' : 'NORMAL'}</strong>
            </span>
          </div>

          <div className="w-[1px] h-4 bg-border/80" />

          <div className="flex items-center gap-2">
            <span
              className={`w-2.5 h-2.5 rounded-full ${
                gatAnomaly ? 'bg-high shadow-glow-high' : 'bg-low'
              }`}
            />
            <span className="text-[11px] font-mono text-gray-300">
              GAT: <strong className={gatAnomaly ? 'text-high' : 'text-low'}>{gatAnomaly ? 'ANOMALY' : 'NORMAL'}</strong>
            </span>
          </div>
        </div>

        {/* 1. GAT Attack Score Gauge */}
        <div>
          <div className="flex justify-between items-center text-[11px] mb-1">
            <span className="text-gray-400">GAT Attack Score</span>
            <span className="font-mono font-bold text-gray-200">
              {gatScore.toFixed(4)}{' '}
              <span className="text-gray-500 font-normal">/ {gatThreshold.toFixed(2)} th</span>
            </span>
          </div>

          {/* Progress bar with threshold marker */}
          <div className="relative w-full h-3 bg-panel rounded-full overflow-visible border border-border">
            {/* Fill bar */}
            <div
              className={`h-full rounded-full transition-all duration-300 ${
                gatAnomaly ? 'bg-high' : 'bg-primary'
              }`}
              style={{ width: `${gatPct}%` }}
            />
            {/* Threshold line marker */}
            <div
              className="absolute top-[-3px] bottom-[-3px] w-[2px] bg-yellow-400 shadow-[0_0_6px_#EAB308] z-10"
              style={{ left: `${gatThresholdPct}%` }}
              title={`Threshold: ${gatThreshold.toFixed(2)}`}
            />
          </div>
          <div className="flex justify-between text-[9px] text-gray-500 mt-1 font-mono">
            <span>0.0 Normal</span>
            <span className="text-yellow-400 font-bold">▲ 0.80 Alert Threshold</span>
            <span>1.0 Attack</span>
          </div>
        </div>

        {/* 2. Isolation Forest Decision Score Gauge */}
        <div>
          <div className="flex justify-between items-center text-[11px] mb-1">
            <span className="text-gray-400">Isolation Forest Score</span>
            <span className="font-mono font-bold text-gray-200">{ifScore.toFixed(4)}</span>
          </div>

          <div className="relative w-full h-3 bg-panel rounded-full overflow-hidden border border-border">
            <div
              className={`h-full rounded-full transition-all duration-300 ${
                ifAnomaly ? 'bg-high' : 'bg-low'
              }`}
              style={{ width: `${ifNormalized}%` }}
            />
            {/* Zero point marker (where score < 0 is anomaly) */}
            <div
              className="absolute top-0 bottom-0 w-[1px] bg-white opacity-40"
              style={{ left: '50%' }}
            />
          </div>
          <div className="flex justify-between text-[9px] text-gray-500 mt-1 font-mono">
            <span className="text-high">Anomaly (&lt;0)</span>
            <span>0.0</span>
            <span className="text-low">Normal (&gt;0)</span>
          </div>
        </div>

        {/* Final Fused Risk Level */}
        <div
          className={`p-2.5 rounded-lg border text-center font-bold tracking-wider uppercase text-xs flex items-center justify-center gap-2 ${
            fusion.risk_level === 'HIGH'
              ? 'bg-high/20 text-high border-high/50 shadow-glow-high'
              : fusion.risk_level === 'MEDIUM'
              ? 'bg-medium/20 text-medium border-medium/50'
              : 'bg-low/20 text-low border-low/50'
          }`}
        >
          <ShieldAlert className="w-4 h-4" />
          <span>FUSED RISK: {fusion.risk_level}</span>
        </div>
      </div>
    </div>
  );
}
