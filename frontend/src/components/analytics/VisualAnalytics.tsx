import React, { useMemo } from 'react';
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, BarChart, Bar
} from 'recharts';
import { ChartEntry, FlowResult } from '../../types/network';
import { formatBytes } from '../../utils/network';

interface VisualAnalyticsProps {
  chartData: ChartEntry[];
  flows: FlowResult[];
}

const RISK_COLORS = {
  high: '#EF4444',
  medium: '#F59E0B',
  low: '#10B981',
};

const PROTO_COLORS: Record<string, string> = {
  TCP: '#3B82F6',
  UDP: '#06B6D4',
  ICMP: '#8B5CF6',
  OTHER: '#6B7280',
};

export function VisualAnalytics({ chartData, flows }: VisualAnalyticsProps) {
  // Protocol Breakdown for Donut Chart
  const protocolData = useMemo(() => {
    const counts: Record<string, number> = { TCP: 0, UDP: 0, ICMP: 0, OTHER: 0 };
    flows.forEach(f => {
      const p = (f.protocol || 'OTHER').toUpperCase();
      if (counts[p] !== undefined) counts[p] += 1;
      else counts.OTHER += 1;
    });

    return Object.entries(counts)
      .filter(([_, val]) => val > 0)
      .map(([name, value]) => ({ name, value }));
  }, [flows]);

  // Top Talkers (Hosts sending the most bytes)
  const topTalkers = useMemo(() => {
    const bytesMap = new Map<string, number>();
    flows.forEach(f => {
      const src = f.source_ip;
      bytesMap.set(src, (bytesMap.get(src) || 0) + (f.byte_count || 0));
    });

    return Array.from(bytesMap.entries())
      .map(([ip, bytes]) => ({ ip, bytes, label: ip }))
      .sort((a, b) => b.bytes - a.bytes)
      .slice(0, 5);
  }, [flows]);

  // Top Destination Ports
  const topPorts = useMemo(() => {
    const portsMap = new Map<number, number>();
    flows.forEach(f => {
      if (f.destination_port) {
        portsMap.set(f.destination_port, (portsMap.get(f.destination_port) || 0) + (f.packet_count || 1));
      }
    });

    return Array.from(portsMap.entries())
      .map(([port, count]) => ({ port: `Port ${port}`, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);
  }, [flows]);

  return (
    <div className="flex-1 p-5 overflow-y-auto space-y-5 bg-background select-auto">
      {/* ── 1. MAIN STACKED AREA CHART (LOW / MEDIUM / HIGH TRAFFIC OVER TIME) ── */}
      <div className="glass-panel p-4 rounded-xl border border-border/80">
        <div className="flex items-center justify-between mb-3">
          <div>
            <h2 className="text-sm font-bold text-white tracking-tight">Threat Severity Timeline</h2>
            <p className="text-[11px] text-gray-400">Rolling volume of Low, Medium, and High risk traffic flows</p>
          </div>
          <div className="flex items-center gap-3 text-xs font-mono">
            <span className="flex items-center gap-1.5 text-gray-300">
              <span className="w-2.5 h-2.5 rounded-full bg-high" /> High Risk
            </span>
            <span className="flex items-center gap-1.5 text-gray-300">
              <span className="w-2.5 h-2.5 rounded-full bg-medium" /> Medium Risk
            </span>
            <span className="flex items-center gap-1.5 text-gray-300">
              <span className="w-2.5 h-2.5 rounded-full bg-low" /> Low (Normal)
            </span>
          </div>
        </div>

        <div className="h-56 w-full">
          {chartData.length === 0 ? (
            <div className="h-full flex items-center justify-center text-xs text-gray-600">
              Awaiting window metrics to generate timeline...
            </div>
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="gradHigh" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor={RISK_COLORS.high} stopOpacity={0.7} />
                    <stop offset="95%" stopColor={RISK_COLORS.high} stopOpacity={0.05} />
                  </linearGradient>
                  <linearGradient id="gradMed" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor={RISK_COLORS.medium} stopOpacity={0.7} />
                    <stop offset="95%" stopColor={RISK_COLORS.medium} stopOpacity={0.05} />
                  </linearGradient>
                  <linearGradient id="gradLow" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor={RISK_COLORS.low} stopOpacity={0.5} />
                    <stop offset="95%" stopColor={RISK_COLORS.low} stopOpacity={0.02} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="time" stroke="#4B5563" tick={{ fontSize: 9, fill: '#9CA3AF' }} tickLine={false} />
                <YAxis stroke="#4B5563" tick={{ fontSize: 9, fill: '#9CA3AF' }} tickLine={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#151C2C',
                    borderColor: '#2A3655',
                    borderRadius: 8,
                    fontSize: 11,
                    color: '#E5E7EB',
                  }}
                />
                <Area type="monotone" dataKey="highRisk" stackId="1" stroke={RISK_COLORS.high} fill="url(#gradHigh)" name="High Risk" />
                <Area type="monotone" dataKey="mediumRisk" stackId="1" stroke={RISK_COLORS.medium} fill="url(#gradMed)" name="Medium Risk" />
                <Area type="monotone" dataKey="lowRisk" stackId="1" stroke={RISK_COLORS.low} fill="url(#gradLow)" name="Low Risk" />
              </AreaChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* ── 2. THREE-PANEL ANALYTICS ROW ───────────────────────────────────── */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        {/* Protocol Donut Chart */}
        <div className="glass-panel p-4 rounded-xl border border-border/80 flex flex-col justify-between">
          <div>
            <h3 className="text-xs font-bold text-white uppercase tracking-wider mb-1">Protocol Distribution</h3>
            <p className="text-[10px] text-gray-400 mb-2">Transport protocol usage across active flows</p>
          </div>

          <div className="h-44 flex items-center justify-center">
            {protocolData.length === 0 ? (
              <span className="text-xs text-gray-600">No protocol data</span>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={protocolData}
                    cx="50%"
                    cy="50%"
                    innerRadius={45}
                    outerRadius={68}
                    paddingAngle={4}
                    dataKey="value"
                  >
                    {protocolData.map((entry) => (
                      <Cell key={entry.name} fill={PROTO_COLORS[entry.name] || '#6B7280'} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#151C2C',
                      borderColor: '#2A3655',
                      borderRadius: 8,
                      fontSize: 11,
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            )}
          </div>

          <div className="flex justify-center gap-3 text-[11px] font-mono mt-1">
            {protocolData.map((d) => (
              <span key={d.name} className="flex items-center gap-1 text-gray-300">
                <span className="w-2 h-2 rounded-full" style={{ backgroundColor: PROTO_COLORS[d.name] || '#6B7280' }} />
                {d.name} ({d.value})
              </span>
            ))}
          </div>
        </div>

        {/* Top Talkers by Bytes */}
        <div className="glass-panel p-4 rounded-xl border border-border/80 flex flex-col justify-between">
          <div>
            <h3 className="text-xs font-bold text-white uppercase tracking-wider mb-1">Top Talkers (Bandwidth)</h3>
            <p className="text-[10px] text-gray-400 mb-2">Hosts responsible for the highest byte volume</p>
          </div>

          <div className="h-44">
            {topTalkers.length === 0 ? (
              <div className="h-full flex items-center justify-center text-xs text-gray-600">No talkers yet</div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={topTalkers} layout="vertical" margin={{ top: 5, right: 10, left: 15, bottom: 0 }}>
                  <XAxis type="number" hide />
                  <YAxis dataKey="ip" type="category" stroke="#9CA3AF" tick={{ fontSize: 9, fill: '#E5E7EB' }} tickLine={false} width={80} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#151C2C', borderColor: '#2A3655', borderRadius: 8, fontSize: 11 }}
                    formatter={(val: any) => [formatBytes(val), 'Volume']}
                  />
                  <Bar dataKey="bytes" fill="#3B82F6" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>

          <div className="text-[10px] text-gray-500 font-mono text-center">
            Bandwidth aggregated across all recorded flows
          </div>
        </div>

        {/* Top Destination Ports */}
        <div className="glass-panel p-4 rounded-xl border border-border/80 flex flex-col justify-between">
          <div>
            <h3 className="text-xs font-bold text-white uppercase tracking-wider mb-1">Targeted Ports</h3>
            <p className="text-[10px] text-gray-400 mb-2">Most queried destination service ports</p>
          </div>

          <div className="h-44">
            {topPorts.length === 0 ? (
              <div className="h-full flex items-center justify-center text-xs text-gray-600">No port traffic</div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={topPorts} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
                  <XAxis dataKey="port" stroke="#9CA3AF" tick={{ fontSize: 9, fill: '#E5E7EB' }} tickLine={false} />
                  <YAxis stroke="#4B5563" tick={{ fontSize: 9 }} tickLine={false} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#151C2C', borderColor: '#2A3655', borderRadius: 8, fontSize: 11 }}
                    formatter={(val: any) => [val.toLocaleString(), 'Packets']}
                  />
                  <Bar dataKey="count" fill="#06B6D4" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>

          <div className="text-[10px] text-gray-500 font-mono text-center">
            High count on uncommon ports can indicate a port scan
          </div>
        </div>
      </div>
    </div>
  );
}
