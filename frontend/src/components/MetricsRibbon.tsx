import React, { useMemo } from 'react';
import { NetworkUpdate, ChartEntry } from '../types/network';
import { formatBytes } from '../utils/network';

interface MetricsRibbonProps {
  lastUpdate: NetworkUpdate | null;
  activeIPs: number;
  activeConnections: number;
  chartData: ChartEntry[];
}

function MiniSparkline({
  data,
  color = '#3B82F6',
  width = 60,
  height = 20,
}: {
  data: number[];
  color?: string;
  width?: number;
  height?: number;
}) {
  if (!data || data.length < 2) {
    return (
      <svg width={width} height={height} className="opacity-30">
        <line x1="0" y1={height / 2} x2={width} y2={height / 2} stroke={color} strokeWidth="1" strokeDasharray="2,2" />
      </svg>
    );
  }

  const min = Math.min(...data);
  const max = Math.max(...data);
  const range = max - min || 1;

  const points = data.map((val, idx) => {
    const x = (idx / (data.length - 1)) * width;
    const y = height - ((val - min) / range) * (height - 4) - 2;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  });

  const pathD = `M ${points.join(' L ')}`;

  return (
    <svg width={width} height={height} className="overflow-visible">
      <path d={pathD} fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function DeltaBadge({ current, previous }: { current: number; previous?: number }) {
  if (previous === undefined || previous === 0 && current === 0) {
    return <span className="text-[10px] text-gray-500 font-mono">-</span>;
  }

  const diff = current - previous;
  if (diff === 0) {
    return <span className="text-[10px] text-gray-500 font-mono">0%</span>;
  }

  const pct = previous > 0 ? Math.round((diff / previous) * 100) : (diff > 0 ? 100 : -100);
  const isUp = diff > 0;

  return (
    <span className={`text-[10px] font-mono flex items-center font-semibold ${isUp ? 'text-high' : 'text-low'}`}>
      {isUp ? '▲' : '▼'} {Math.abs(pct)}%
    </span>
  );
}

interface MetricCardProps {
  title: string;
  value: string | number;
  valueColor?: string;
  delta?: { current: number; previous?: number };
  sparkData?: number[];
  sparkColor?: string;
  glow?: boolean;
}

function MetricCard({
  title,
  value,
  valueColor = 'text-gray-100',
  delta,
  sparkData = [],
  sparkColor = '#2472f4',
  glow = false,
}: MetricCardProps) {
  return (
    <div
      className={`glass-panel p-2.5 rounded-lg border border-border/70 flex flex-col justify-between transition-all hover:border-primary/40 ${
        glow ? 'shadow-glow-high border-high/40 bg-high/5' : ''
      }`}
    >
      <div className="flex items-center justify-between gap-1 mb-1">
        <span className="text-[10px] text-gray-400 uppercase tracking-wider font-semibold truncate">
          {title}
        </span>
        {delta && <DeltaBadge current={delta.current} previous={delta.previous} />}
      </div>

      <div className="flex items-baseline justify-between gap-2 mt-0.5">
        <div className={`text-xl font-bold font-mono tracking-tight ${valueColor}`}>
          {value}
        </div>
        <MiniSparkline data={sparkData} color={sparkColor} width={48} height={18} />
      </div>
    </div>
  );
}

export function MetricsRibbon({
  lastUpdate,
  activeIPs,
  activeConnections,
  chartData,
}: MetricsRibbonProps) {
  // Extract sparkline history series from rolling chartData
  const packetsHistory = useMemo(() => chartData.map(c => c.packetsPerSec), [chartData]);
  const bytesHistory = useMemo(() => chartData.map(c => c.bytesPerSec || 0), [chartData]);
  const flowsHistory = useMemo(() => chartData.map(c => c.totalFlows), [chartData]);
  const anomaliesHistory = useMemo(() => chartData.map(c => c.anomalies), [chartData]);
  const mediumRiskHistory = useMemo(() => chartData.map(c => c.mediumRisk), [chartData]);
  const highRiskHistory = useMemo(() => chartData.map(c => c.highRisk), [chartData]);

  // Previous window comparisons for deltas
  const prevEntry = chartData.length >= 2 ? chartData[chartData.length - 2] : undefined;
  const currEntry = chartData.length >= 1 ? chartData[chartData.length - 1] : undefined;

  const windowDur = lastUpdate?.window_duration || 5;

  // Real Bytes calculation
  const rawBytes = lastUpdate?.bytes_captured ?? (lastUpdate ? lastUpdate.packets_captured * 64 : 0);
  const bytesPerSec = lastUpdate ? Math.round(rawBytes / windowDur) : 0;
  const formattedBytesSec = lastUpdate ? `${formatBytes(bytesPerSec)}/s` : '—';

  const packetsPerSec = lastUpdate ? Math.round(lastUpdate.packets_captured / windowDur) : 0;

  return (
    <div className="flex-shrink-0 grid grid-cols-2 sm:grid-cols-4 xl:grid-cols-8 gap-2.5 px-4 py-2.5 bg-background/90 border-b border-border/80 select-auto">
      <MetricCard
        title="Packets / Sec"
        value={lastUpdate ? packetsPerSec.toLocaleString() : '—'}
        sparkData={packetsHistory}
        sparkColor="#3B82F6"
        delta={currEntry ? { current: currEntry.packetsPerSec, previous: prevEntry?.packetsPerSec } : undefined}
      />

      <MetricCard
        title="Real Bytes / Sec"
        value={formattedBytesSec}
        sparkData={bytesHistory}
        sparkColor="#06B6D4"
        delta={currEntry ? { current: currEntry.bytesPerSec, previous: prevEntry?.bytesPerSec } : undefined}
      />

      <MetricCard
        title="Active IPs"
        value={activeIPs}
        sparkData={useMemo(() => chartData.map(() => activeIPs), [chartData, activeIPs])}
        sparkColor="#8B5CF6"
      />

      <MetricCard
        title="Active Links"
        value={activeConnections}
        sparkData={useMemo(() => chartData.map(() => activeConnections), [chartData, activeConnections])}
        sparkColor="#6366F1"
      />

      <MetricCard
        title="Flows Analysed"
        value={lastUpdate ? lastUpdate.total_flows.toLocaleString() : '—'}
        sparkData={flowsHistory}
        sparkColor="#10B981"
        delta={currEntry ? { current: currEntry.totalFlows, previous: prevEntry?.totalFlows } : undefined}
      />

      <MetricCard
        title="Anomalies"
        value={lastUpdate?.anomalies ?? '—'}
        valueColor="text-high"
        sparkData={anomaliesHistory}
        sparkColor="#EF4444"
        glow={(lastUpdate?.anomalies || 0) > 0}
        delta={currEntry ? { current: currEntry.anomalies, previous: prevEntry?.anomalies } : undefined}
      />

      <MetricCard
        title="Medium Risk"
        value={lastUpdate?.risk_counts?.MEDIUM ?? '—'}
        valueColor="text-medium"
        sparkData={mediumRiskHistory}
        sparkColor="#F59E0B"
        delta={currEntry ? { current: currEntry.mediumRisk, previous: prevEntry?.mediumRisk } : undefined}
      />

      <MetricCard
        title="High Risk"
        value={lastUpdate?.risk_counts?.HIGH ?? '—'}
        valueColor="text-high"
        sparkData={highRiskHistory}
        sparkColor="#EF4444"
        glow={(lastUpdate?.risk_counts?.HIGH || 0) > 0}
        delta={currEntry ? { current: currEntry.highRisk, previous: prevEntry?.highRisk } : undefined}
      />
    </div>
  );
}
