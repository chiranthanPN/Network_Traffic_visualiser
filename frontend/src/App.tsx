import React, { useState, useEffect, useMemo, useRef, useCallback } from 'react';
import ForceGraph2D from 'react-force-graph-2d';
import { Shield, Play, Square, AlertTriangle, ShieldCheck, Wifi, WifiOff } from 'lucide-react';
import { useNetworkWebSocket } from './hooks/useNetworkWebSocket';
import { getHealth, startMonitor, stopMonitor } from './services/api';
import { HealthStatus, FlowResult } from './types/network';
import { TrafficChart } from './components/TrafficChart';

// ─────────────────────────────────────────────────────────────────────────────
// HELPER – MetricCard
// ─────────────────────────────────────────────────────────────────────────────
function MetricCard({
  title,
  value,
  valueColor = 'text-gray-100',
  sub,
}: {
  title: string;
  value: string | number;
  valueColor?: string;
  sub?: string;
}) {
  return (
    <div className="bg-panel p-4 rounded-lg border border-border shadow-sm flex flex-col">
      <div className="text-[10px] text-gray-500 mb-1 uppercase tracking-widest font-semibold">
        {title}
      </div>
      <div className={`text-2xl font-bold font-mono ${valueColor}`}>{value}</div>
      {sub && <div className="text-[10px] text-gray-500 mt-1">{sub}</div>}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// HELPER – StatusDot
// ─────────────────────────────────────────────────────────────────────────────
function StatusDot({ ok, label }: { ok: boolean | undefined; label: string }) {
  return (
    <span
      className={`text-xs font-medium flex items-center gap-1 ${
        ok === undefined ? 'text-gray-500' : ok ? 'text-low' : 'text-high'
      }`}
    >
      <span
        className={`inline-block w-2 h-2 rounded-full ${
          ok === undefined ? 'bg-gray-600' : ok ? 'bg-low' : 'bg-high'
        }`}
      />
      {label}
    </span>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// MAIN APP
// ─────────────────────────────────────────────────────────────────────────────
export default function App() {
  const { isConnected, lastUpdate, flows, chartData, error: wsError, clearHistory } =
    useNetworkWebSocket('ws://localhost:8000/api/ws');

  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [backendUp, setBackendUp] = useState<boolean | null>(null);
  const [isMonitoring, setIsMonitoring] = useState(false);
  const [isStarting, setIsStarting] = useState(false);

  const [selectedNode, setSelectedNode] = useState<string | null>(null);
  const [selectedEdge, setSelectedEdge] = useState<FlowResult | null>(null);

  // Table filters
  const [searchTerm, setSearchTerm] = useState('');
  const [filterRisk, setFilterRisk] = useState<string>('ALL');

  const graphRef = useRef<any>(null);

  // ── Health polling ────────────────────────────────────────────────────────
  useEffect(() => {
    const poll = async () => {
      try {
        const h = await getHealth();
        setHealth(h);
        setBackendUp(true);
        setIsMonitoring(h.capture);
      } catch {
        setBackendUp(false);
        setHealth(null);
      }
    };
    poll();
    const iv = setInterval(poll, 5000);
    return () => clearInterval(iv);
  }, []);

  // ── Controls ──────────────────────────────────────────────────────────────
  const handleStart = async () => {
    setIsStarting(true);
    try {
      await startMonitor();
      setIsMonitoring(true);
    } finally {
      setIsStarting(false);
    }
  };

  const handleStop = async () => {
    await stopMonitor();
    setIsMonitoring(false);
  };

  const handleReset = () => {
    clearHistory();
    setSelectedNode(null);
    setSelectedEdge(null);
  };

  // ── Derived live status ───────────────────────────────────────────────────
  const liveStatus = (() => {
    if (backendUp === false) return { label: 'BACKEND DOWN', cls: 'bg-high/20 text-high border-high/40' };
    if (!isConnected && backendUp) return { label: 'CONNECTING…', cls: 'bg-medium/20 text-medium border-medium/40' };
    if (isMonitoring && isConnected) return { label: '● LIVE', cls: 'bg-low/20 text-low border-low/40' };
    if (isConnected && !isMonitoring) return { label: '○ STOPPED', cls: 'bg-gray-700/40 text-gray-300 border-border' };
    return { label: '● DISCONNECTED', cls: 'bg-high/20 text-high border-high/40' };
  })();

  // ── Graph data ────────────────────────────────────────────────────────────
  const graphData = useMemo(() => {
    const nodes = new Map<string, { id: string; risk: string; flows: number }>();
    const links: any[] = [];

    const currentFlows = lastUpdate?.flows ?? [];

    currentFlows.forEach((f) => {
      const { source_ip, destination_ip, fusion } = f;
      const risk = fusion.risk_level;

      if (!nodes.has(source_ip)) nodes.set(source_ip, { id: source_ip, risk: 'LOW', flows: 0 });
      if (!nodes.has(destination_ip)) nodes.set(destination_ip, { id: destination_ip, risk: 'LOW', flows: 0 });

      const upgradeRisk = (cur: string, next: string) => {
        const levels = ['LOW', 'MEDIUM', 'HIGH'];
        return levels.indexOf(next) > levels.indexOf(cur) ? next : cur;
      };
      nodes.get(source_ip)!.risk = upgradeRisk(nodes.get(source_ip)!.risk, risk);
      nodes.get(destination_ip)!.risk = upgradeRisk(nodes.get(destination_ip)!.risk, risk);
      nodes.get(source_ip)!.flows += 1;

      links.push({ source: source_ip, target: destination_ip, risk, flow: f });
    });

    return { nodes: Array.from(nodes.values()), links };
  }, [lastUpdate]);

  const getNodeColor = useCallback(
    (node: any) => {
      if (node.id === selectedNode) return '#ffffff';
      if (node.risk === 'HIGH') return '#ef4444';
      if (node.risk === 'MEDIUM') return '#f59e0b';
      return '#3b82f6';
    },
    [selectedNode]
  );

  const getNodeBorderColor = useCallback(
    (node: any) => {
      if (node.id === selectedNode) return '#ffffff';
      if (node.risk === 'HIGH') return '#b91c1c';
      return 'transparent';
    },
    [selectedNode]
  );

  const getLinkColor = useCallback((link: any) => {
    if (link.risk === 'HIGH') return 'rgba(239,68,68,0.85)';
    if (link.risk === 'MEDIUM') return 'rgba(245,158,11,0.6)';
    return 'rgba(59,130,246,0.3)';
  }, []);

  // Derived summary metrics
  const activeIPs = graphData.nodes.length;
  const activeConnections = graphData.links.length;
  const packetsPerSec = lastUpdate
    ? (lastUpdate.packets_captured / (lastUpdate.window_duration || 5)).toFixed(1)
    : '—';

  const alerts = flows.filter((f) => f.fusion.risk_level !== 'LOW');

  // ── Render ────────────────────────────────────────────────────────────────
  return (
    <div className="h-screen flex flex-col font-sans overflow-hidden select-none">
      {/* ══ HEADER ══════════════════════════════════════════════════════════ */}
      <header className="flex-shrink-0 bg-panel border-b border-border px-5 py-3 flex items-center justify-between gap-4">
        {/* Left: branding + status */}
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <Shield className="w-5 h-5 text-primary flex-shrink-0" />
            <span className="text-base font-bold tracking-tight whitespace-nowrap">
              Network Traffic Analyser
            </span>
          </div>
          <div className={`px-2.5 py-1 rounded text-xs font-bold border ${liveStatus.cls} whitespace-nowrap`}>
            {liveStatus.label}
          </div>
          {isConnected ? (
            <Wifi className="w-4 h-4 text-low" title="WebSocket connected" />
          ) : (
            <WifiOff className="w-4 h-4 text-high" title="WebSocket disconnected" />
          )}
        </div>

        {/* Centre: model/service status */}
        <div className="flex items-center gap-5 text-xs text-gray-400">
          <StatusDot ok={backendUp ?? undefined} label="API" />
          <StatusDot ok={health?.isolation_forest} label="Isolation Forest" />
          <StatusDot ok={health?.gat} label="GAT" />
          <StatusDot ok={isMonitoring} label="Capture" />
        </div>

        {/* Right: controls */}
        <div className="flex items-center gap-2">
          {!isMonitoring ? (
            <button
              onClick={handleStart}
              disabled={isStarting || backendUp === false}
              className="flex items-center gap-2 bg-primary hover:bg-primary/80 disabled:opacity-40 px-4 py-1.5 rounded text-white text-sm font-medium transition-colors"
            >
              <Play className="w-3.5 h-3.5" />
              {isStarting ? 'Starting…' : 'Start Monitoring'}
            </button>
          ) : (
            <button
              onClick={handleStop}
              className="flex items-center gap-2 bg-high hover:bg-high/80 px-4 py-1.5 rounded text-white text-sm font-medium transition-colors"
            >
              <Square className="w-3.5 h-3.5" /> Stop Monitoring
            </button>
          )}
          <button
            onClick={handleReset}
            className="px-3 py-1.5 text-xs text-gray-400 hover:text-white border border-border rounded hover:border-gray-400 transition-colors"
          >
            Reset
          </button>
        </div>
      </header>

      {/* ══ ERROR BANNER ════════════════════════════════════════════════════ */}
      {(wsError || backendUp === false) && (
        <div className="flex-shrink-0 bg-high/10 border-b border-high/40 px-5 py-2 text-xs text-high flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 flex-shrink-0" />
          {wsError || 'Cannot reach backend at http://localhost:8000. Is the server running?'}
        </div>
      )}

      {/* ══ METRICS RIBBON ══════════════════════════════════════════════════ */}
      <div className="flex-shrink-0 grid grid-cols-8 gap-3 px-5 py-3 bg-background border-b border-border">
        <MetricCard title="Packets/s" value={packetsPerSec} />
        <MetricCard title="Bytes/s" value={lastUpdate ? Math.round(lastUpdate.packets_captured * 64).toLocaleString() : '—'} sub="approx" />
        <MetricCard title="Active IPs" value={activeIPs} />
        <MetricCard title="Connections" value={activeConnections} />
        <MetricCard title="Flows Analysed" value={lastUpdate?.total_flows ?? '—'} />
        <MetricCard title="Anomalies" value={lastUpdate?.anomalies ?? '—'} valueColor="text-high" />
        <MetricCard title="Medium Risk" value={lastUpdate?.risk_counts.MEDIUM ?? '—'} valueColor="text-medium" />
        <MetricCard title="High Risk" value={lastUpdate?.risk_counts.HIGH ?? '—'} valueColor="text-high" />
      </div>

      {/* ══ MAIN BODY ═══════════════════════════════════════════════════════ */}
      <div className="flex-1 flex gap-0 overflow-hidden">

        {/* ── GRAPH ─────────────────────────────────────────────────────── */}
        <div className="flex-[3] relative bg-background overflow-hidden">

          {/* Monitoring badge */}
          <div className="absolute top-3 left-3 z-10">
            <div className={`px-3 py-1 rounded text-xs font-mono border shadow-sm ${
              isMonitoring
                ? 'bg-background/80 text-low border-low/30'
                : 'bg-background/80 text-gray-500 border-border'
            }`}>
              {isMonitoring ? '● LIVE MONITORING' : '○ STOPPED'}
            </div>
          </div>

          {/* Window info */}
          {lastUpdate && (
            <div className="absolute top-3 right-3 z-10 text-[10px] font-mono text-gray-500 bg-background/80 px-2 py-1 rounded border border-border">
              Window: {lastUpdate.window_duration}s &nbsp;|&nbsp; {new Date(lastUpdate.timestamp * 1000).toLocaleTimeString()}
            </div>
          )}

          {/* Legend */}
          <div className="absolute bottom-4 left-3 z-10 bg-background/90 p-3 rounded-lg border border-border shadow-lg text-xs flex flex-col gap-1.5">
            <div className="font-bold text-gray-400 uppercase tracking-wider mb-1 text-[10px]">Legend</div>
            {[
              { color: 'bg-low', label: 'Low Risk' },
              { color: 'bg-medium', label: 'Medium Risk' },
              { color: 'bg-high', label: 'High Risk' },
              { color: 'bg-white', label: 'Selected' },
            ].map(({ color, label }) => (
              <div key={label} className="flex items-center gap-2 text-gray-300">
                <div className={`w-2.5 h-2.5 rounded-full flex-shrink-0 ${color}`} />
                {label}
              </div>
            ))}
            <div className="border-t border-border mt-1 pt-1 text-gray-500 text-[10px]">
              Animated dots = active traffic
            </div>
          </div>

          {/* Empty state */}
          {graphData.nodes.length === 0 && (
            <div className="absolute inset-0 flex items-center justify-center flex-col gap-3 text-gray-600 pointer-events-none">
              <Shield className="w-12 h-12 opacity-20" />
              <span className="text-sm">
                {isMonitoring
                  ? 'Waiting for network traffic…'
                  : 'Click Start Monitoring to begin capture'}
              </span>
            </div>
          )}

          <ForceGraph2D
            ref={graphRef}
            graphData={graphData}
            nodeLabel={(node: any) => `${node.id}\nFlows: ${node.flows}`}
            nodeColor={getNodeColor}
            nodeRelSize={6}
            nodeCanvasObjectMode={() => 'after'}
            nodeCanvasObject={(node: any, ctx, globalScale) => {
              // Draw IP label when zoomed in enough
              if (globalScale < 2) return;
              const label = node.id as string;
              const fontSize = 10 / globalScale;
              ctx.font = `${fontSize}px monospace`;
              ctx.fillStyle = 'rgba(255,255,255,0.7)';
              ctx.textAlign = 'center';
              ctx.fillText(label, node.x, node.y + 12 / globalScale);
            }}
            linkColor={getLinkColor}
            linkWidth={(link: any) => (link.risk === 'HIGH' ? 2.5 : 1)}
            linkDirectionalParticles={(link: any) =>
              link.risk === 'HIGH' ? 4 : link.risk === 'MEDIUM' ? 2 : 1
            }
            linkDirectionalParticleWidth={(link: any) =>
              link.risk === 'HIGH' ? 3 : 1.5
            }
            linkDirectionalParticleColor={getLinkColor}
            onNodeClick={(node: any) => {
              setSelectedNode(node.id);
              setSelectedEdge(null);
            }}
            onLinkClick={(link: any) => {
              setSelectedEdge((link as any).flow);
              setSelectedNode(null);
            }}
            onBackgroundClick={() => {
              setSelectedNode(null);
              setSelectedEdge(null);
            }}
            backgroundColor="#0B0F19"
            width={undefined}
            height={undefined}
          />
        </div>

        {/* ── SIDEBAR ───────────────────────────────────────────────────── */}
        <div className="w-80 flex-shrink-0 flex flex-col border-l border-border bg-panel overflow-y-auto">

          {/* Node Details */}
          {selectedNode && (
            <section className="border-b border-border p-4">
              <div className="flex items-center justify-between mb-3">
                <h2 className="font-bold text-sm uppercase tracking-wider text-gray-300">Node Details</h2>
                <button onClick={() => setSelectedNode(null)} className="text-gray-600 hover:text-white text-lg leading-none">×</button>
              </div>
              <div className="font-mono text-primary text-base mb-4 bg-background rounded px-3 py-2 border border-border">
                {selectedNode}
              </div>
              {(() => {
                const nf = flows.filter(f => f.source_ip === selectedNode || f.destination_ip === selectedNode);
                const inb = nf.filter(f => f.destination_ip === selectedNode);
                const out = nf.filter(f => f.source_ip === selectedNode);
                const totalPkts = nf.reduce((s, f) => s + f.packet_count, 0);
                const totalBytes = nf.reduce((s, f) => s + f.byte_count, 0);
                return (
                  <>
                    <div className="grid grid-cols-2 gap-2 text-xs mb-4">
                      {[
                        ['Total Flows', nf.length],
                        ['Inbound', inb.length],
                        ['Outbound', out.length],
                        ['Total Packets', totalPkts.toLocaleString()],
                        ['Total Bytes', totalBytes.toLocaleString()],
                        ['Unique Peers', new Set([...nf.map(f => f.source_ip), ...nf.map(f => f.destination_ip)]).size - 1],
                      ].map(([k, v]) => (
                        <div key={String(k)} className="bg-background p-2 rounded">
                          <div className="text-gray-500">{k}</div>
                          <div className="font-bold text-gray-100">{v}</div>
                        </div>
                      ))}
                    </div>
                    <p className="text-xs text-gray-500 mb-2">Recent Communications</p>
                    <div className="space-y-1 max-h-40 overflow-y-auto">
                      {nf.slice(0, 8).map((f, i) => {
                        const isOut = f.source_ip === selectedNode;
                        const peer = isOut ? f.destination_ip : f.source_ip;
                        return (
                          <div
                            key={i}
                            className="flex justify-between items-center text-xs px-2 py-1.5 bg-background rounded hover:border-border border border-transparent cursor-pointer"
                            onClick={() => { setSelectedEdge(f); setSelectedNode(null); }}
                          >
                            <span className="text-gray-500">{isOut ? '→' : '←'}</span>
                            <span className="font-mono text-gray-200 flex-1 mx-2 truncate">{peer}</span>
                            <span className={`font-bold text-[10px] px-1.5 py-0.5 rounded ${
                              f.fusion.risk_level === 'HIGH' ? 'bg-high/20 text-high' :
                              f.fusion.risk_level === 'MEDIUM' ? 'bg-medium/20 text-medium' :
                              'bg-low/20 text-low'
                            }`}>{f.fusion.risk_level}</span>
                          </div>
                        );
                      })}
                    </div>
                  </>
                );
              })()}
            </section>
          )}

          {/* Edge / Flow Details */}
          {selectedEdge && (
            <section className="border-b border-border p-4">
              <div className="flex items-center justify-between mb-3">
                <h2 className="font-bold text-sm uppercase tracking-wider text-gray-300">Flow Details</h2>
                <button onClick={() => setSelectedEdge(null)} className="text-gray-600 hover:text-white text-lg leading-none">×</button>
              </div>

              {/* Addresses */}
              <div className="space-y-1 mb-4 text-xs font-mono">
                {[
                  { label: 'SRC', ip: selectedEdge.source_ip, port: selectedEdge.source_port },
                  { label: 'DST', ip: selectedEdge.destination_ip, port: selectedEdge.destination_port },
                ].map(({ label, ip, port }) => (
                  <div key={label} className="flex justify-between items-center bg-background px-3 py-2 rounded">
                    <span className="text-gray-500 w-8">{label}</span>
                    <span
                      className="text-primary hover:underline cursor-pointer flex-1 mx-2"
                      onClick={() => { setSelectedNode(ip); setSelectedEdge(null); }}
                    >
                      {ip}
                    </span>
                    <span className="text-gray-500">:{port}</span>
                  </div>
                ))}
                <div className="flex justify-between items-center bg-background px-3 py-2 rounded">
                  <span className="text-gray-500 w-8">PROTO</span>
                  <span className="text-gray-200 font-bold">{selectedEdge.protocol}</span>
                </div>
              </div>

              {/* Stats */}
              <div className="grid grid-cols-2 gap-2 text-xs mb-4">
                {[
                  ['Packets', selectedEdge.packet_count.toLocaleString()],
                  ['Bytes', selectedEdge.byte_count.toLocaleString()],
                ].map(([k, v]) => (
                  <div key={String(k)} className="bg-background p-2 rounded">
                    <div className="text-gray-500">{k}</div>
                    <div className="font-bold">{v}</div>
                  </div>
                ))}
              </div>

              {/* Model results */}
              <div className="space-y-2 text-xs">
                <div className="bg-background p-3 rounded border border-border">
                  <div className="font-bold text-gray-300 mb-2">Isolation Forest</div>
                  <div className="flex justify-between mb-1">
                    <span className="text-gray-500">Anomaly</span>
                    <span className={selectedEdge.isolation_forest.is_anomaly ? 'text-high font-bold' : 'text-low'}>
                      {selectedEdge.isolation_forest.is_anomaly ? 'ANOMALY' : 'NORMAL'}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-500">Decision Score</span>
                    <span className="font-mono">{selectedEdge.isolation_forest.decision_score.toFixed(4)}</span>
                  </div>
                  <div className="text-[10px] text-gray-600 mt-1">Higher = more normal. Not a probability.</div>
                </div>

                <div className="bg-background p-3 rounded border border-border">
                  <div className="font-bold text-gray-300 mb-2">GAT Model</div>
                  <div className="flex justify-between mb-1">
                    <span className="text-gray-500">Anomaly</span>
                    <span className={selectedEdge.gat.is_anomaly ? 'text-high font-bold' : 'text-low'}>
                      {selectedEdge.gat.is_anomaly ? 'ANOMALY' : 'NORMAL'}
                    </span>
                  </div>
                  <div className="flex justify-between mb-1">
                    <span className="text-gray-500">Attack Score</span>
                    <span className="font-mono">{selectedEdge.gat.attack_score.toFixed(4)}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-500">Threshold</span>
                    <span className="font-mono">{selectedEdge.gat.threshold.toFixed(4)}</span>
                  </div>
                  <div className="text-[10px] text-gray-600 mt-1">Score vs threshold – not a calibrated probability.</div>
                </div>

                <div className={`p-2.5 rounded font-bold text-center text-sm tracking-widest border ${
                  selectedEdge.fusion.risk_level === 'HIGH'
                    ? 'bg-high/15 text-high border-high/50'
                    : selectedEdge.fusion.risk_level === 'MEDIUM'
                    ? 'bg-medium/15 text-medium border-medium/50'
                    : 'bg-low/15 text-low border-low/50'
                }`}>
                  FUSION: {selectedEdge.fusion.risk_level}
                </div>
                <div className="text-[10px] text-gray-600">
                  IF:{' '}
                  <span className={selectedEdge.fusion.isolation_forest_anomaly ? 'text-high' : 'text-low'}>
                    {selectedEdge.fusion.isolation_forest_anomaly ? 'anomaly' : 'normal'}
                  </span>{' '}
                  &nbsp;GAT:{' '}
                  <span className={selectedEdge.fusion.gat_anomaly ? 'text-high' : 'text-low'}>
                    {selectedEdge.fusion.gat_anomaly ? 'anomaly' : 'normal'}
                  </span>
                </div>
              </div>
            </section>
          )}

          {/* Alerts Feed */}
          <section className="flex-1 flex flex-col p-4 min-h-0">
            <div className="flex items-center gap-2 mb-3">
              <AlertTriangle className="w-4 h-4 text-medium flex-shrink-0" />
              <h2 className="font-bold text-sm uppercase tracking-wider text-gray-300">
                Live Alerts
              </h2>
              {alerts.length > 0 && (
                <span className="ml-auto text-xs bg-high/20 text-high px-2 py-0.5 rounded font-bold">
                  {alerts.length}
                </span>
              )}
            </div>

            <div className="flex-1 overflow-y-auto space-y-2 pr-1">
              {alerts.slice(0, 30).map((f, i) => (
                <div
                  key={i}
                  className={`p-2.5 rounded border-l-4 cursor-pointer hover:brightness-110 transition-all ${
                    f.fusion.risk_level === 'HIGH'
                      ? 'bg-high/10 border-high'
                      : 'bg-medium/10 border-medium'
                  }`}
                  onClick={() => { setSelectedEdge(f); setSelectedNode(null); }}
                >
                  <div className="flex justify-between items-center mb-1">
                    <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${
                      f.fusion.risk_level === 'HIGH' ? 'bg-high/30 text-high' : 'bg-medium/30 text-medium'
                    }`}>
                      {f.fusion.risk_level}
                    </span>
                    <span className="text-[10px] text-gray-500">{f.protocol}</span>
                  </div>
                  <div className="font-mono text-xs text-gray-200 truncate">
                    {f.source_ip} → {f.destination_ip}
                  </div>
                  <div className="text-[10px] text-gray-500 mt-1">
                    {f.isolation_forest.is_anomaly && 'IF:anomaly '}
                    {f.gat.is_anomaly && `GAT:${f.gat.attack_score.toFixed(3)}`}
                  </div>
                </div>
              ))}

              {alerts.length === 0 && (
                <div className="flex flex-col items-center justify-center py-10 text-gray-600">
                  <ShieldCheck className="w-8 h-8 mb-2 opacity-30" />
                  <span className="text-xs">No anomalies detected</span>
                </div>
              )}
            </div>
          </section>

          {/* Traffic Chart */}
          <div className="flex-shrink-0 border-t border-border">
            <TrafficChart data={chartData} />
          </div>
        </div>
      </div>

      {/* ══ FLOW TABLE ══════════════════════════════════════════════════════ */}
      <div className="flex-shrink-0 h-56 bg-panel border-t border-border flex flex-col">
        <div className="flex items-center justify-between px-4 py-2 border-b border-border flex-shrink-0">
          <h2 className="font-bold text-sm uppercase tracking-wider text-gray-300">
            Flow History
            <span className="ml-2 text-gray-600 font-normal text-xs normal-case">
              ({flows.length} total)
            </span>
          </h2>
          <div className="flex gap-2">
            <input
              type="text"
              placeholder="Search IP or protocol…"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="bg-background border border-border rounded px-3 py-1 text-xs text-gray-200 outline-none focus:border-primary w-52"
            />
            <select
              value={filterRisk}
              onChange={(e) => setFilterRisk(e.target.value)}
              className="bg-background border border-border rounded px-2 py-1 text-xs text-gray-200 outline-none focus:border-primary"
            >
              <option value="ALL">All Risks</option>
              <option value="HIGH">High Risk</option>
              <option value="MEDIUM">Medium Risk</option>
              <option value="LOW">Low Risk</option>
            </select>
          </div>
        </div>

        <div className="flex-1 overflow-auto">
          <table className="w-full text-xs text-left">
            <thead className="text-[10px] text-gray-500 uppercase bg-background sticky top-0 z-10">
              <tr>
                {['Source', 'Destination', 'Proto', 'Packets', 'Bytes', 'IF Anomaly', 'IF Score', 'GAT Score', 'Risk'].map(
                  (h) => (
                    <th key={h} className="px-3 py-2 font-semibold tracking-wider whitespace-nowrap">
                      {h}
                    </th>
                  )
                )}
              </tr>
            </thead>
            <tbody>
              {flows
                .filter((f) => filterRisk === 'ALL' || f.fusion.risk_level === filterRisk)
                .filter(
                  (f) =>
                    !searchTerm ||
                    f.source_ip.includes(searchTerm) ||
                    f.destination_ip.includes(searchTerm) ||
                    f.protocol.toLowerCase().includes(searchTerm.toLowerCase())
                )
                .slice(0, 200)
                .map((f, i) => (
                  <tr
                    key={i}
                    className={`border-b border-border/50 hover:bg-border/30 cursor-pointer transition-colors ${
                      selectedEdge === f ? 'bg-primary/10' : ''
                    }`}
                    onClick={() => { setSelectedEdge(f); setSelectedNode(null); }}
                  >
                    <td className="px-3 py-1.5 font-mono whitespace-nowrap">
                      {f.source_ip}
                      <span className="text-gray-600">:{f.source_port}</span>
                    </td>
                    <td className="px-3 py-1.5 font-mono whitespace-nowrap">
                      {f.destination_ip}
                      <span className="text-gray-600">:{f.destination_port}</span>
                    </td>
                    <td className="px-3 py-1.5">{f.protocol}</td>
                    <td className="px-3 py-1.5 text-right font-mono">{f.packet_count.toLocaleString()}</td>
                    <td className="px-3 py-1.5 text-right font-mono">{f.byte_count.toLocaleString()}</td>
                    <td className="px-3 py-1.5">
                      <span className={f.isolation_forest.is_anomaly ? 'text-high font-bold' : 'text-gray-500'}>
                        {f.isolation_forest.is_anomaly ? 'YES' : 'NO'}
                      </span>
                    </td>
                    <td className="px-3 py-1.5 font-mono">
                      {f.isolation_forest.decision_score.toFixed(3)}
                    </td>
                    <td className="px-3 py-1.5 font-mono">{f.gat.attack_score.toFixed(3)}</td>
                    <td
                      className={`px-3 py-1.5 font-bold ${
                        f.fusion.risk_level === 'HIGH'
                          ? 'text-high'
                          : f.fusion.risk_level === 'MEDIUM'
                          ? 'text-medium'
                          : 'text-low'
                      }`}
                    >
                      {f.fusion.risk_level}
                    </td>
                  </tr>
                ))}
            </tbody>
          </table>

          {flows.length === 0 && !isMonitoring && (
            <div className="flex items-center justify-center h-24 text-gray-600 text-xs">
              Start monitoring to see flows here.
            </div>
          )}
          {flows.length === 0 && isMonitoring && (
            <div className="flex items-center justify-center h-24 text-gray-600 text-xs">
              Waiting for network traffic…
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
