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
  TCP: '#3B82F6',   // Electric Blue
  UDP: '#06B6D4',   // Bright Cyan
  ICMP: '#A855F7',  // Vibrant Purple
  OTHER: '#94A3B8', // High-contrast Light Slate
};

const COMMON_PORTS: Record<number, string> = {
  80: 'HTTP',
  443: 'HTTPS',
  53: 'DNS',
  22: 'SSH',
  21: 'FTP',
  25: 'SMTP',
  123: 'NTP',
  8080: 'HTTP-Alt',
  8443: 'HTTPS-Alt',
  3389: 'RDP',
  3306: 'MySQL',
  5432: 'PostgreSQL',
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

  const totalProtoFlows = useMemo(
    () => protocolData.reduce((acc, curr) => acc + curr.value, 0),
    [protocolData]
  );

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
      .map(([portNum, count]) => {
        const service = COMMON_PORTS[portNum] ? ` (${COMMON_PORTS[portNum]})` : '';
        return {
          portNum,
          port: `Port ${portNum}${service}`,
          shortPort: `${portNum}`,
          count,
        };
      })
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);
  }, [flows]);

  return (
    <div className="flex-1 p-5 overflow-y-auto space-y-5 bg-background select-auto font-sans">
      {/* ── 1. MAIN STACKED AREA CHART (LOW / MEDIUM / HIGH TRAFFIC OVER TIME) ── */}
      <div className="glass-panel p-4 rounded-xl border border-border/80 shadow-lg">
        <div className="flex items-center justify-between mb-3">
          <div>
            <h2 className="text-sm font-bold text-white tracking-tight flex items-center gap-2">
              <span>Threat Severity Timeline</span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-panel border border-border text-gray-300">
                Live Window Trends
              </span>
            </h2>
            <p className="text-[11px] text-gray-400">Rolling volume of Low, Medium, and High risk traffic flows</p>
          </div>
          <div className="flex items-center gap-3 text-xs font-mono">
            <span className="flex items-center gap-1.5 text-gray-300">
              <span className="w-2.5 h-2.5 rounded-full bg-high shadow-[0_0_8px_rgba(239,68,68,0.6)]" /> High Risk
            </span>
            <span className="flex items-center gap-1.5 text-gray-300">
              <span className="w-2.5 h-2.5 rounded-full bg-medium shadow-[0_0_8px_rgba(245,158,11,0.6)]" /> Medium Risk
            </span>
            <span className="flex items-center gap-1.5 text-gray-300">
              <span className="w-2.5 h-2.5 rounded-full bg-low shadow-[0_0_8px_rgba(16,185,129,0.6)]" /> Low (Normal)
            </span>
          </div>
        </div>

        <div className="h-56 w-full">
          {chartData.length === 0 ? (
            <div className="h-full flex items-center justify-center text-xs text-gray-500 font-mono">
              Awaiting window metrics to generate timeline...
            </div>
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="gradHigh" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor={RISK_COLORS.high} stopOpacity={0.75} />
                    <stop offset="95%" stopColor={RISK_COLORS.high} stopOpacity={0.05} />
                  </linearGradient>
                  <linearGradient id="gradMed" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor={RISK_COLORS.medium} stopOpacity={0.75} />
                    <stop offset="95%" stopColor={RISK_COLORS.medium} stopOpacity={0.05} />
                  </linearGradient>
                  <linearGradient id="gradLow" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor={RISK_COLORS.low} stopOpacity={0.6} />
                    <stop offset="95%" stopColor={RISK_COLORS.low} stopOpacity={0.05} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="time" stroke="#4B5563" tick={{ fontSize: 9, fill: '#9CA3AF' }} tickLine={false} />
                <YAxis stroke="#4B5563" tick={{ fontSize: 9, fill: '#9CA3AF' }} tickLine={false} />
                <Tooltip
                  content={({ active, payload, label }) => {
                    if (active && payload && payload.length) {
                      return (
                        <div className="bg-[#0B1120]/95 border border-primary/50 shadow-[0_8px_30px_rgba(0,0,0,0.7)] rounded-lg p-3 text-xs backdrop-blur-md font-mono min-w-[170px]">
                          <div className="text-[11px] font-bold text-gray-300 pb-1.5 mb-2 border-b border-border/80 flex items-center justify-between">
                            <span>Time: {label}</span>
                            <span className="text-[10px] text-primary">FLOWS</span>
                          </div>
                          <div className="space-y-1.5">
                            {payload.map((entry: any) => (
                              <div key={entry.name} className="flex items-center justify-between gap-4">
                                <span className="flex items-center gap-1.5 text-gray-300">
                                  <span className="w-2 h-2 rounded-full" style={{ backgroundColor: entry.stroke || entry.color }} />
                                  <span className="font-sans text-[11px]">{entry.name}:</span>
                                </span>
                                <span className="font-bold text-white text-[12px]">{Number(entry.value).toLocaleString()}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      );
                    }
                    return null;
                  }}
                />
                <Area type="monotone" dataKey="highRisk" stackId="1" stroke={RISK_COLORS.high} strokeWidth={2} fill="url(#gradHigh)" name="High Risk" />
                <Area type="monotone" dataKey="mediumRisk" stackId="1" stroke={RISK_COLORS.medium} strokeWidth={2} fill="url(#gradMed)" name="Medium Risk" />
                <Area type="monotone" dataKey="lowRisk" stackId="1" stroke={RISK_COLORS.low} strokeWidth={2} fill="url(#gradLow)" name="Low Risk" />
              </AreaChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* ── 2. THREE-PANEL ANALYTICS ROW ───────────────────────────────────── */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        {/* Protocol Donut Chart */}
        <div className="glass-panel p-4 rounded-xl border border-border/80 flex flex-col justify-between shadow-lg">
          <div>
            <h3 className="text-xs font-bold text-white uppercase tracking-wider mb-1 flex items-center justify-between">
              <span>Protocol Distribution</span>
              <span className="text-[10px] font-mono text-cyan-400 font-normal">
                {totalProtoFlows} Flows
              </span>
            </h3>
            <p className="text-[10px] text-gray-400 mb-2">Transport protocol usage across active flows</p>
          </div>

          <div className="h-44 flex items-center justify-center relative">
            {protocolData.length === 0 ? (
              <span className="text-xs text-gray-500 font-mono">No protocol data</span>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={protocolData}
                    cx="50%"
                    cy="50%"
                    innerRadius={46}
                    outerRadius={70}
                    paddingAngle={4}
                    dataKey="value"
                    stroke="#0B0F19"
                    strokeWidth={2}
                  >
                    {protocolData.map((entry) => (
                      <Cell
                        key={entry.name}
                        fill={PROTO_COLORS[entry.name] || '#94A3B8'}
                        className="transition-all hover:opacity-90"
                      />
                    ))}
                  </Pie>
                  <Tooltip
                    content={({ active, payload }) => {
                      if (active && payload && payload.length) {
                        const data = payload[0];
                        const name = data.name as string;
                        const color = PROTO_COLORS[name] || '#94A3B8';
                        const count = Number(data.value);
                        const percent = totalProtoFlows > 0 ? ((count / totalProtoFlows) * 100).toFixed(1) : '0';

                        return (
                          <div className="bg-[#0B1120]/95 border border-primary/50 shadow-[0_8px_25px_rgba(0,0,0,0.8)] rounded-lg p-2.5 text-xs backdrop-blur-md font-mono min-w-[150px]">
                            <div className="flex items-center gap-2 mb-1.5 pb-1 border-b border-border/70">
                              <span className="w-2.5 h-2.5 rounded-full shadow-[0_0_6px_currentColor]" style={{ backgroundColor: color, color }} />
                              <span className="font-bold text-white text-sm">{name}</span>
                            </div>
                            <div className="flex items-center justify-between text-gray-300">
                              <span className="text-gray-400">Active Flows:</span>
                              <span className="font-bold text-white">{count.toLocaleString()}</span>
                            </div>
                            <div className="flex items-center justify-between text-gray-300 mt-1">
                              <span className="text-gray-400">Share:</span>
                              <span className="font-bold text-cyan-300">{percent}%</span>
                            </div>
                          </div>
                        );
                      }
                      return null;
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            )}
          </div>

          <div className="flex justify-center flex-wrap gap-2 text-[11px] font-mono mt-2 pt-2 border-t border-border/50">
            {protocolData.map((d) => (
              <span key={d.name} className="flex items-center gap-1.5 px-2 py-0.5 rounded bg-background/60 border border-border/60 text-gray-200">
                <span className="w-2 h-2 rounded-full shadow-[0_0_4px_currentColor]" style={{ backgroundColor: PROTO_COLORS[d.name] || '#94A3B8', color: PROTO_COLORS[d.name] || '#94A3B8' }} />
                <span className="font-semibold">{d.name}</span>
                <span className="text-gray-400">({d.value})</span>
              </span>
            ))}
          </div>
        </div>

        {/* Top Talkers by Bytes */}
        <div className="glass-panel p-4 rounded-xl border border-border/80 flex flex-col justify-between shadow-lg">
          <div>
            <h3 className="text-xs font-bold text-white uppercase tracking-wider mb-1 flex items-center justify-between">
              <span>Top Talkers</span>
              <span className="text-[10px] font-mono text-primary font-normal">Bandwidth</span>
            </h3>
            <p className="text-[10px] text-gray-400 mb-2">Hosts responsible for the highest byte volume</p>
          </div>

          <div className="h-44">
            {topTalkers.length === 0 ? (
              <div className="h-full flex items-center justify-center text-xs text-gray-500 font-mono">No talkers yet</div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={topTalkers} layout="vertical" margin={{ top: 5, right: 15, left: 15, bottom: 0 }}>
                  <XAxis type="number" hide />
                  <YAxis dataKey="ip" type="category" stroke="#9CA3AF" tick={{ fontSize: 9, fill: '#E5E7EB', fontFamily: 'monospace' }} tickLine={false} width={85} />
                  <Tooltip
                    content={({ active, payload }) => {
                      if (active && payload && payload.length) {
                        const data = payload[0].payload;
                        return (
                          <div className="bg-[#0B1120]/95 border border-primary/50 shadow-[0_8px_25px_rgba(0,0,0,0.8)] rounded-lg p-2.5 text-xs backdrop-blur-md font-mono min-w-[160px]">
                            <div className="text-[10px] text-gray-400 mb-1">Host IP Address</div>
                            <div className="font-bold text-white text-sm pb-1 mb-1.5 border-b border-border/70 truncate">{data.ip}</div>
                            <div className="flex items-center justify-between text-gray-300">
                              <span className="text-gray-400">Total Volume:</span>
                              <span className="font-bold text-primary">{formatBytes(data.bytes)}</span>
                            </div>
                          </div>
                        );
                      }
                      return null;
                    }}
                  />
                  <Bar dataKey="bytes" fill="#3B82F6" radius={[0, 4, 4, 0]} className="hover:opacity-90" />
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>

          <div className="text-[10px] text-gray-400 font-mono text-center pt-2 border-t border-border/50">
            Bandwidth aggregated across all recorded flows
          </div>
        </div>

        {/* Top Destination Ports */}
        <div className="glass-panel p-4 rounded-xl border border-border/80 flex flex-col justify-between shadow-lg">
          <div>
            <h3 className="text-xs font-bold text-white uppercase tracking-wider mb-1 flex items-center justify-between">
              <span>Targeted Ports</span>
              <span className="text-[10px] font-mono text-cyan-400 font-normal">Packets</span>
            </h3>
            <p className="text-[10px] text-gray-400 mb-2">Most queried destination service ports</p>
          </div>

          <div className="h-44">
            {topPorts.length === 0 ? (
              <div className="h-full flex items-center justify-center text-xs text-gray-500 font-mono">No port traffic</div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={topPorts} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
                  <XAxis dataKey="shortPort" stroke="#9CA3AF" tick={{ fontSize: 9, fill: '#E5E7EB', fontFamily: 'monospace' }} tickLine={false} />
                  <YAxis stroke="#4B5563" tick={{ fontSize: 9, fill: '#9CA3AF' }} tickLine={false} />
                  <Tooltip
                    content={({ active, payload }) => {
                      if (active && payload && payload.length) {
                        const data = payload[0].payload;
                        return (
                          <div className="bg-[#0B1120]/95 border border-cyan-400/50 shadow-[0_8px_25px_rgba(0,0,0,0.8)] rounded-lg p-2.5 text-xs backdrop-blur-md font-mono min-w-[160px]">
                            <div className="flex items-center justify-between mb-1.5 pb-1 border-b border-border/70">
                              <span className="font-bold text-white text-sm">{data.port}</span>
                            </div>
                            <div className="flex items-center justify-between text-gray-300">
                              <span className="text-gray-400">Total Packets:</span>
                              <span className="font-bold text-cyan-300">{Number(data.count).toLocaleString()}</span>
                            </div>
                          </div>
                        );
                      }
                      return null;
                    }}
                  />
                  <Bar dataKey="count" fill="#06B6D4" radius={[4, 4, 0, 0]} className="hover:opacity-90" />
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>

          <div className="text-[10px] text-gray-400 font-mono text-center pt-2 border-t border-border/50">
            Concentration on abnormal ports highlights scan activity
          </div>
        </div>
      </div>
    </div>
  );
}
