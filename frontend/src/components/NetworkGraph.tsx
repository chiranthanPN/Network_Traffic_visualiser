import React, { useRef, useEffect, useState, useMemo, useCallback } from 'react';
import ForceGraph2D from 'react-force-graph-2d';
import ForceGraph3D from 'react-force-graph-3d';
import {
  Maximize2, Minimize2, Pause, Play, Target, Filter,
  Shield, AlertTriangle
} from 'lucide-react';
import { FlowResult, NetworkUpdate, GraphNode, GraphLink } from '../types/network';
import { isPrivateIP } from '../utils/network';

interface NetworkGraphProps {
  lastUpdate: NetworkUpdate | null;
  selectedNode: string | null;
  selectedEdge: FlowResult | null;
  is3D: boolean;
  onSelectNode: (ip: string | null) => void;
  onSelectEdge: (flow: FlowResult | null) => void;
  isMonitoring: boolean;
}

const INACTIVITY_TTL_MS = 35000; // 35 seconds persistent retention

export function NetworkGraph({
  lastUpdate,
  selectedNode,
  selectedEdge,
  is3D,
  onSelectNode,
  onSelectEdge,
  isMonitoring,
}: NetworkGraphProps) {
  const graph2dRef = useRef<any>(null);
  const graph3dRef = useRef<any>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  // Graph state preserved across 5-second updates to eliminate layout jitter
  const persistentNodesRef = useRef<Map<string, GraphNode>>(new Map());
  const persistentLinksRef = useRef<Map<string, GraphLink>>(new Map());
  const [graphData, setGraphData] = useState<{ nodes: GraphNode[]; links: GraphLink[] }>({
    nodes: [],
    links: [],
  });

  const [isPaused, setIsPaused] = useState(false);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [riskFilter, setRiskFilter] = useState<'ALL' | 'ANOMALIES' | 'HIGH'>('ALL');

  // Animation frame tracker for radar sweep and pulsing rings
  const animTimeRef = useRef(0);
  useEffect(() => {
    let frameId: number;
    const loop = (t: number) => {
      animTimeRef.current = t;
      frameId = requestAnimationFrame(loop);
    };
    frameId = requestAnimationFrame(loop);
    return () => cancelAnimationFrame(frameId);
  }, []);

  // ── MERGE UPDATE INTO PERSISTENT GRAPH (Prevents layout reshuffle) ───────────
  useEffect(() => {
    if (!lastUpdate || !lastUpdate.flows) return;

    const now = Date.now();
    const currentNodes = persistentNodesRef.current;
    const currentLinks = persistentLinksRef.current;

    const upgradeRisk = (cur: string, next: string): 'LOW' | 'MEDIUM' | 'HIGH' => {
      const levels = ['LOW', 'MEDIUM', 'HIGH'];
      return levels.indexOf(next) > levels.indexOf(cur) ? (next as any) : (cur as any);
    };

    // Process new flows
    lastUpdate.flows.forEach((f) => {
      const src = f.source_ip;
      const dst = f.destination_ip;
      const risk = f.fusion.risk_level;

      // Update or insert Source Node
      const srcNode = currentNodes.get(src);
      if (srcNode) {
        srcNode.risk = upgradeRisk(srcNode.risk, risk);
        srcNode.flows += 1;
        srcNode.packetCount += f.packet_count || 1;
        srcNode.byteCount += f.byte_count || 64;
        srcNode.lastSeen = now;
        srcNode.isHighPulsing = srcNode.risk === 'HIGH';
      } else {
        currentNodes.set(src, {
          id: src,
          risk,
          isInternal: isPrivateIP(src),
          flows: 1,
          packetCount: f.packet_count || 1,
          byteCount: f.byte_count || 64,
          lastSeen: now,
          isHighPulsing: risk === 'HIGH',
        });
      }

      // Update or insert Destination Node
      const dstNode = currentNodes.get(dst);
      if (dstNode) {
        dstNode.risk = upgradeRisk(dstNode.risk, risk);
        dstNode.flows += 1;
        dstNode.packetCount += f.packet_count || 1;
        dstNode.byteCount += f.byte_count || 64;
        dstNode.lastSeen = now;
        dstNode.isHighPulsing = dstNode.risk === 'HIGH';
      } else {
        currentNodes.set(dst, {
          id: dst,
          risk,
          isInternal: isPrivateIP(dst),
          flows: 1,
          packetCount: f.packet_count || 1,
          byteCount: f.byte_count || 64,
          lastSeen: now,
          isHighPulsing: risk === 'HIGH',
        });
      }

      // Update or insert Link
      const linkKey = `${src}->${dst}`;
      const revKey = `${dst}->${src}`;
      const isBidirectional = currentLinks.has(revKey);

      currentLinks.set(linkKey, {
        source: src,
        target: dst,
        risk,
        flow: f,
        byteCount: f.byte_count || 64,
        packetCount: f.packet_count || 1,
        curvature: isBidirectional ? 0.25 : 0,
        lastSeen: now,
      });
    });

    // Prune stale nodes/links older than INACTIVITY_TTL_MS
    for (const [id, node] of currentNodes.entries()) {
      if (now - node.lastSeen > INACTIVITY_TTL_MS) {
        currentNodes.delete(id);
      }
    }
    for (const [key, link] of currentLinks.entries()) {
      if (now - link.lastSeen > INACTIVITY_TTL_MS) {
        currentLinks.delete(key);
      }
    }

    setGraphData({
      nodes: Array.from(currentNodes.values()),
      links: Array.from(currentLinks.values()),
    });
  }, [lastUpdate]);

  // ── FILTERED DATA VIEW ──────────────────────────────────────────────────────
  const filteredData = useMemo(() => {
    let nodes = graphData.nodes;
    let links = graphData.links;

    if (riskFilter === 'HIGH') {
      const highNodeIds = new Set(nodes.filter(n => n.risk === 'HIGH').map(n => n.id));
      nodes = nodes.filter(n => n.risk === 'HIGH');
      links = links.filter(l => {
        const s = typeof l.source === 'object' ? (l.source as any).id : l.source;
        const t = typeof l.target === 'object' ? (l.target as any).id : l.target;
        return highNodeIds.has(s) && highNodeIds.has(t);
      });
    } else if (riskFilter === 'ANOMALIES') {
      const anomalyNodeIds = new Set(nodes.filter(n => n.risk !== 'LOW').map(n => n.id));
      nodes = nodes.filter(n => n.risk !== 'LOW');
      links = links.filter(l => {
        const s = typeof l.source === 'object' ? (l.source as any).id : l.source;
        const t = typeof l.target === 'object' ? (l.target as any).id : l.target;
        return anomalyNodeIds.has(s) && anomalyNodeIds.has(t);
      });
    }

    return { nodes, links };
  }, [graphData, riskFilter]);

  // Calculate top talkers by bytes to always display their labels
  const topTalkerIds = useMemo(() => {
    const sorted = [...filteredData.nodes].sort((a, b) => b.byteCount - a.byteCount);
    return new Set(sorted.slice(0, 5).map(n => n.id));
  }, [filteredData.nodes]);

  // ── NODE DRAWING & ENCODING ─────────────────────────────────────────────────
  const drawNodeCanvas = useCallback(
    (node: any, ctx: CanvasRenderingContext2D, globalScale: number) => {
      const isSelected = node.id === selectedNode;
      const isHigh = node.risk === 'HIGH';
      const isMedium = node.risk === 'MEDIUM';

      // Base radius scaled logarithmically by packet count
      const baseRadius = Math.max(4, Math.min(16, 4 + Math.log2((node.packetCount || 1) + 1) * 1.5));
      const radius = isSelected ? baseRadius + 3 : baseRadius;

      const t = animTimeRef.current * 0.003;

      // 1. Radar / Pulsing Ring around HIGH nodes
      if (isHigh) {
        const pulse = (Math.sin(t * 3) + 1) / 2;
        ctx.beginPath();
        ctx.arc(node.x, node.y, radius + 4 + pulse * 6, 0, 2 * Math.PI);
        ctx.strokeStyle = `rgba(239, 68, 68, ${0.3 + pulse * 0.4})`;
        ctx.lineWidth = 1.8 / globalScale;
        ctx.stroke();

        ctx.beginPath();
        ctx.arc(node.x, node.y, radius + 10 + pulse * 10, 0, 2 * Math.PI);
        ctx.strokeStyle = `rgba(239, 68, 68, ${0.15 * (1 - pulse)})`;
        ctx.lineWidth = 1 / globalScale;
        ctx.stroke();
      }

      // 2. Selection halo
      if (isSelected) {
        ctx.beginPath();
        ctx.arc(node.x, node.y, radius + 5, 0, 2 * Math.PI);
        ctx.strokeStyle = '#FFFFFF';
        ctx.lineWidth = 2 / globalScale;
        ctx.stroke();
      }

      // 3. Draw Node Shape: Internal (Diamond / Shield) vs External (Circle)
      ctx.beginPath();
      if (node.isInternal) {
        // Diamond for internal/private hosts
        const d = radius * 1.25;
        ctx.moveTo(node.x, node.y - d);
        ctx.lineTo(node.x + d, node.y);
        ctx.lineTo(node.x, node.y + d);
        ctx.lineTo(node.x - d, node.y);
        ctx.closePath();
      } else {
        // Circle for external hosts
        ctx.arc(node.x, node.y, radius, 0, 2 * Math.PI);
      }

      // Fill color based on risk
      if (isSelected) {
        ctx.fillStyle = '#FFFFFF';
      } else if (isHigh) {
        ctx.fillStyle = '#EF4444';
      } else if (isMedium) {
        ctx.fillStyle = '#F59E0B';
      } else {
        ctx.fillStyle = node.isInternal ? '#3B82F6' : '#06B6D4';
      }
      ctx.fill();

      // Border stroke
      ctx.lineWidth = 1.2 / globalScale;
      ctx.strokeStyle = isSelected ? '#FFFFFF' : isHigh ? '#B91C1C' : isMedium ? '#D97706' : '#1D4ED8';
      ctx.stroke();

      // 4. Node Label: Always show for HIGH risk, selected, or top talkers; otherwise show when zoomed in
      const shouldShowLabel = isHigh || isSelected || topTalkerIds.has(node.id) || globalScale >= 1.6;

      if (shouldShowLabel) {
        const label = node.id as string;
        const fontSize = Math.max(8, 11 / Math.sqrt(globalScale));
        ctx.font = `bold ${fontSize}px "JetBrains Mono", monospace`;
        ctx.textAlign = 'center';

        // Background tag for readability
        const textWidth = ctx.measureText(label).width;
        ctx.fillStyle = isHigh ? 'rgba(239, 68, 68, 0.85)' : 'rgba(11, 15, 25, 0.85)';
        ctx.fillRect(
          node.x - textWidth / 2 - 3,
          node.y + radius + 3,
          textWidth + 6,
          fontSize + 4
        );

        ctx.fillStyle = isHigh ? '#FFFFFF' : '#E5E7EB';
        ctx.fillText(label, node.x, node.y + radius + fontSize + 2);
      }
    },
    [selectedNode, topTalkerIds]
  );

  // ── BACKGROUND RADAR GRID ──────────────────────────────────────────────────
  const drawCanvasBackground = useCallback(
    (ctx: CanvasRenderingContext2D, globalScale: number) => {
      const width = ctx.canvas.width;
      const height = ctx.canvas.height;

      // Subtle radar concentric circles
      const centerX = width / 2;
      const centerY = height / 2;
      ctx.save();
      ctx.strokeStyle = 'rgba(42, 54, 85, 0.25)';
      ctx.lineWidth = 1;

      for (let r = 80; r < Math.max(width, height); r += 120) {
        ctx.beginPath();
        ctx.arc(centerX, centerY, r, 0, 2 * Math.PI);
        ctx.stroke();
      }

      // Crosshairs
      ctx.beginPath();
      ctx.moveTo(centerX, 0);
      ctx.lineTo(centerX, height);
      ctx.moveTo(0, centerY);
      ctx.lineTo(width, centerY);
      ctx.stroke();

      // Faint sweeping radar beam
      const t = animTimeRef.current * 0.001;
      const beamLength = Math.max(width, height);
      const angle = t % (2 * Math.PI);
      const beamX = centerX + Math.cos(angle) * beamLength;
      const beamY = centerY + Math.sin(angle) * beamLength;

      const grad = ctx.createRadialGradient(centerX, centerY, 0, centerX, centerY, beamLength);
      grad.addColorStop(0, 'rgba(59, 130, 246, 0.04)');
      grad.addColorStop(1, 'rgba(59, 130, 246, 0)');

      ctx.fillStyle = grad;
      ctx.beginPath();
      ctx.moveTo(centerX, centerY);
      ctx.arc(centerX, centerY, beamLength, angle - 0.2, angle);
      ctx.closePath();
      ctx.fill();

      ctx.restore();
    },
    []
  );

  // ── CONTROLS ──────────────────────────────────────────────────────────────
  const handleFit = () => {
    if (graph2dRef.current) graph2dRef.current.zoomToFit(400, 30);
    if (graph3dRef.current) graph3dRef.current.zoomToFit(400, 30);
  };

  const handleTogglePause = () => {
    setIsPaused(!isPaused);
    if (graph2dRef.current) {
      if (!isPaused) graph2dRef.current.pauseAnimation();
      else graph2dRef.current.resumeAnimation();
    }
  };

  const handleToggleFullscreen = () => {
    if (!containerRef.current) return;
    if (!document.fullscreenElement) {
      containerRef.current.requestFullscreen().then(() => setIsFullscreen(true));
    } else {
      document.exitFullscreen().then(() => setIsFullscreen(false));
    }
  };

  return (
    <div ref={containerRef} className="relative w-full h-full bg-background overflow-hidden flex flex-col select-auto">
      {/* ── TOP GRAPH TOOLBAR ───────────────────────────────────────────────── */}
      <div className="absolute top-3 left-3 z-20 flex items-center gap-2">
        {/* Risk filter */}
        <div className="flex items-center gap-1 bg-panel/90 backdrop-blur-md px-2.5 py-1 rounded-lg border border-border text-xs text-gray-300">
          <Filter className="w-3.5 h-3.5 text-gray-400" />
          <select
            value={riskFilter}
            onChange={(e) => setRiskFilter(e.target.value as any)}
            className="bg-transparent outline-none font-medium text-xs cursor-pointer text-gray-200"
          >
            <option value="ALL" className="bg-panel">All Traffic</option>
            <option value="ANOMALIES" className="bg-panel">Anomalies Only</option>
            <option value="HIGH" className="bg-panel">High Risk Only</option>
          </select>
        </div>

        {/* Fit to Screen */}
        <button
          onClick={handleFit}
          title="Fit view to all nodes"
          className="bg-panel/90 backdrop-blur-md p-1.5 rounded-lg border border-border text-gray-300 hover:text-white hover:border-primary/50 transition-colors"
        >
          <Target className="w-4 h-4" />
        </button>

        {/* Pause Simulation */}
        <button
          onClick={handleTogglePause}
          title={isPaused ? 'Resume physics simulation' : 'Pause physics simulation'}
          className={`bg-panel/90 backdrop-blur-md p-1.5 rounded-lg border transition-colors ${
            isPaused ? 'text-medium border-medium/50' : 'border-border text-gray-300 hover:text-white'
          }`}
        >
          {isPaused ? <Play className="w-4 h-4" /> : <Pause className="w-4 h-4" />}
        </button>

        {/* Fullscreen */}
        <button
          onClick={handleToggleFullscreen}
          title={isFullscreen ? 'Exit Fullscreen' : 'Enter Fullscreen'}
          className="bg-panel/90 backdrop-blur-md p-1.5 rounded-lg border border-border text-gray-300 hover:text-white hover:border-primary/50 transition-colors"
        >
          {isFullscreen ? <Minimize2 className="w-4 h-4" /> : <Maximize2 className="w-4 h-4" />}
        </button>
      </div>

      {/* ── TOP RIGHT WINDOW STATS ─────────────────────────────────────────── */}
      {lastUpdate && (
        <div className="absolute top-3 right-3 z-20 text-[10px] font-mono text-gray-400 bg-panel/80 backdrop-blur-md px-3 py-1.5 rounded-lg border border-border flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-low animate-pulse" />
          <span>TTL: 35s retain</span>
          <span className="text-border">|</span>
          <span>Window: {lastUpdate.window_duration}s</span>
          <span className="text-border">|</span>
          <span>Nodes: {filteredData.nodes.length}</span>
        </div>
      )}

      {/* ── BOTTOM LEFT LEGEND ─────────────────────────────────────────────── */}
      <div className="absolute bottom-4 left-3 z-20 bg-panel/85 backdrop-blur-md p-3 rounded-lg border border-border shadow-xl text-xs flex flex-col gap-1.5">
        <div className="font-bold text-gray-400 uppercase tracking-wider text-[10px] mb-0.5">
          Map Legend
        </div>
        <div className="grid grid-cols-2 gap-x-4 gap-y-1">
          <div className="flex items-center gap-1.5 text-gray-300">
            <span className="w-2.5 h-2.5 rounded-full bg-low" />
            <span className="text-[11px]">Low Risk</span>
          </div>
          <div className="flex items-center gap-1.5 text-gray-300">
            <span className="w-2.5 h-2.5 rounded-full bg-medium" />
            <span className="text-[11px]">Medium Risk</span>
          </div>
          <div className="flex items-center gap-1.5 text-gray-300">
            <span className="w-2.5 h-2.5 rounded-full bg-high shadow-[0_0_6px_#EF4444]" />
            <span className="text-[11px] font-semibold text-high">High Alert</span>
          </div>
          <div className="flex items-center gap-1.5 text-gray-300">
            <span className="w-2.5 h-2.5 rounded-full bg-white border border-gray-400" />
            <span className="text-[11px]">Selected</span>
          </div>
        </div>

        <div className="border-t border-border/80 mt-1 pt-1 flex flex-col gap-1 text-[10px] text-gray-400">
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 rotate-45 border border-primary bg-primary/40 inline-block" />
            <span>Internal RFC1918 Host</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full border border-cyan-400 bg-cyan-400/40 inline-block" />
            <span>External Internet Host</span>
          </div>
          <div className="text-gray-500">
            Particles = packet rate | Width = bytes
          </div>
        </div>
      </div>

      {/* ── EMPTY STATE WHEN NO TRAFFIC ────────────────────────────────────── */}
      {filteredData.nodes.length === 0 && (
        <div className="absolute inset-0 z-10 flex items-center justify-center flex-col gap-3 text-gray-500 pointer-events-none">
          <div className="relative">
            <div className="w-16 h-16 rounded-full border border-primary/20 flex items-center justify-center animate-ping" />
            <Shield className="w-8 h-8 text-primary/40 absolute inset-0 m-auto" />
          </div>
          <span className="text-sm font-medium text-gray-400">
            {isMonitoring
              ? 'Listening on network interface for traffic...'
              : 'Click "Start Monitoring" or "Replay Sample" to begin'}
          </span>
          <span className="text-xs text-gray-600">
            Packets will group into flows and generate the real-time GAT graph
          </span>
        </div>
      )}

      {/* ── FORCE GRAPH RENDERER (2D or 3D) ─────────────────────────────────── */}
      {is3D ? (
        <ForceGraph3D
          ref={graph3dRef}
          graphData={filteredData}
          nodeLabel={(n: any) => `${n.id} (${n.risk})`}
          nodeColor={(n: any) =>
            n.id === selectedNode ? '#FFFFFF' : n.risk === 'HIGH' ? '#EF4444' : n.risk === 'MEDIUM' ? '#F59E0B' : '#3B82F6'
          }
          nodeVal={(n: any) => Math.max(3, Math.log2((n.packetCount || 1) + 1) * 3)}
          linkColor={(l: any) =>
            l.risk === 'HIGH' ? 'rgba(239,68,68,0.8)' : l.risk === 'MEDIUM' ? 'rgba(245,158,11,0.6)' : 'rgba(59,130,246,0.3)'
          }
          linkWidth={(l: any) => (l.risk === 'HIGH' ? 2.5 : 1)}
          linkDirectionalParticles={2}
          linkDirectionalParticleWidth={1.5}
          linkCurvature="curvature"
          backgroundColor="#0B0F19"
          onNodeClick={(node: any) => {
            onSelectNode(node.id);
            onSelectEdge(null);
          }}
          onLinkClick={(link: any) => {
            onSelectEdge((link as any).flow);
            onSelectNode(null);
          }}
          onBackgroundClick={() => {
            onSelectNode(null);
            onSelectEdge(null);
          }}
        />
      ) : (
        <ForceGraph2D
          ref={graph2dRef}
          graphData={filteredData}
          nodeCanvasObjectMode={() => 'replace'}
          nodeCanvasObject={drawNodeCanvas}
          nodePointerAreaPaint={(node: any, color, ctx) => {
            const r = Math.max(6, 4 + Math.log2((node.packetCount || 1) + 1) * 2);
            ctx.fillStyle = color;
            ctx.beginPath();
            ctx.arc(node.x, node.y, r + 4, 0, 2 * Math.PI);
            ctx.fill();
          }}
          linkColor={(link: any) =>
            link.risk === 'HIGH'
              ? 'rgba(239,68,68,0.85)'
              : link.risk === 'MEDIUM'
              ? 'rgba(245,158,11,0.65)'
              : 'rgba(59,130,246,0.35)'
          }
          linkWidth={(link: any) => {
            const bytes = link.byteCount || 64;
            return link.risk === 'HIGH' ? Math.max(2.5, Math.min(6, Math.log10(bytes))) : Math.max(1, Math.min(4, Math.log10(bytes) * 0.7));
          }}
          linkCurvature="curvature"
          linkDirectionalParticles={(link: any) => {
            const pps = link.packetCount || 1;
            return link.risk === 'HIGH' ? 4 : pps > 50 ? 3 : 1;
          }}
          linkDirectionalParticleSpeed={(link: any) => {
            const pps = link.packetCount || 1;
            return Math.min(0.03, 0.005 + pps * 0.0002);
          }}
          linkDirectionalParticleWidth={(link: any) => (link.risk === 'HIGH' ? 3 : 1.8)}
          linkDirectionalParticleColor={(link: any) =>
            link.risk === 'HIGH' ? '#EF4444' : link.risk === 'MEDIUM' ? '#F59E0B' : '#60A5FA'
          }
          onRenderFramePre={drawCanvasBackground}
          onNodeClick={(node: any) => {
            onSelectNode(node.id);
            onSelectEdge(null);
          }}
          onLinkClick={(link: any) => {
            onSelectEdge((link as any).flow);
            onSelectNode(null);
          }}
          onBackgroundClick={() => {
            onSelectNode(null);
            onSelectEdge(null);
          }}
          backgroundColor="#0B0F19"
          d3AlphaDecay={0.03}
          d3VelocityDecay={0.3}
          cooldownTicks={120}
        />
      )}
    </div>
  );
}
