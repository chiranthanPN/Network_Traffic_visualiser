import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { Toaster, toast } from 'sonner';
import { AlertTriangle } from 'lucide-react';
import { useNetworkWebSocket } from './hooks/useNetworkWebSocket';
import { getHealth, startDemo, startMonitor, stopMonitor } from './services/api';
import { HealthStatus, FlowResult } from './types/network';
import { soundManager } from './utils/audio';

import { Header } from './components/Header';
import { MetricsRibbon } from './components/MetricsRibbon';
import { NetworkGraph } from './components/NetworkGraph';
import { NodeDetails } from './components/sidebar/NodeDetails';
import { FlowDetails } from './components/sidebar/FlowDetails';
import { AlertsFeed } from './components/sidebar/AlertsFeed';
import { VisualAnalytics } from './components/analytics/VisualAnalytics';
import { FlowTable } from './components/FlowTable';

export default function App() {
  const [soundEnabled, setSoundEnabled] = useState(true);
  const [is3D, setIs3D] = useState(false);
  const [activeTab, setActiveTab] = useState<'graph' | 'analytics' | 'table'>('graph');

  // Trigger Sonner toast and audio on new HIGH alert
  const handleHighAlert = useCallback((flow: FlowResult) => {
    soundManager.playAlertSound();
    toast.error(`HIGH THREAT DETECTED`, {
      description: `${flow.source_ip} → ${flow.destination_ip} (${flow.protocol}) | Scenario: ${
        flow.demo_scenario ? flow.demo_scenario.replace(/_/g, ' ') : 'Graph Attack Anomaly'
      }`,
      duration: 5000,
    });
  }, []);

  const { isConnected, lastUpdate, flows, chartData, error: wsError, clearHistory } =
    useNetworkWebSocket('ws://localhost:8000/api/ws', {
      onHighAlert: handleHighAlert,
    });

  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [backendUp, setBackendUp] = useState<boolean | null>(null);
  const [isMonitoring, setIsMonitoring] = useState(false);
  const [isStarting, setIsStarting] = useState(false);

  const [selectedNode, setSelectedNode] = useState<string | null>(null);
  const [selectedEdge, setSelectedEdge] = useState<FlowResult | null>(null);

  // Table filters
  const [searchTerm, setSearchTerm] = useState('');
  const [filterRisk, setFilterRisk] = useState<string>('ALL');

  // ── Health Polling ──────────────────────────────────────────────────────────
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

  // ── Keyboard Shortcuts (Space, /, Esc) ──────────────────────────────────────
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      const activeEl = document.activeElement;
      const isInput = activeEl?.tagName === 'INPUT' || activeEl?.tagName === 'TEXTAREA';

      // 'Space' toggles monitoring when not typing in an input
      if (e.code === 'Space' && !isInput) {
        e.preventDefault();
        if (isMonitoring) {
          handleStop();
        } else {
          handleStart();
        }
      }

      // '/' focuses search
      if (e.key === '/' && !isInput) {
        e.preventDefault();
        const searchInput = document.querySelector('input[type="text"]') as HTMLInputElement;
        if (searchInput) searchInput.focus();
      }

      // 'Esc' deselects active node/edge
      if (e.key === 'Escape') {
        setSelectedNode(null);
        setSelectedEdge(null);
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isMonitoring]);

  // ── Handlers ────────────────────────────────────────────────────────────────
  const handleStart = async () => {
    setIsStarting(true);
    try {
      await startMonitor();
      setIsMonitoring(true);
      toast.success('Packet capture started on all interfaces');
    } catch {
      toast.error('Failed to start monitoring');
    } finally {
      setIsStarting(false);
    }
  };

  const handleStop = async () => {
    await stopMonitor();
    setIsMonitoring(false);
    toast.info('Monitoring stopped');
  };

  const handleDemo = async () => {
    setIsStarting(true);
    try {
      await startDemo();
      setIsMonitoring(true);
      toast.info('Streaming synthetic threat dataset');
    } catch {
      toast.error('Failed to start demo replay');
    } finally {
      setIsStarting(false);
    }
  };

  const handleReset = () => {
    clearHistory();
    setSelectedNode(null);
    setSelectedEdge(null);
    toast('History and graph reset');
  };

  const handleToggleSound = () => {
    const next = soundManager.toggle();
    setSoundEnabled(next);
    toast(next ? 'Alert sound enabled' : 'Alert sound muted');
  };

  const handleToggle3D = () => {
    setIs3D(!is3D);
  };

  // Active IPs & links count
  const activeIPs = useMemo(() => {
    const set = new Set<string>();
    (lastUpdate?.flows || []).forEach(f => {
      set.add(f.source_ip);
      set.add(f.destination_ip);
    });
    return set.size;
  }, [lastUpdate]);

  const activeConnections = lastUpdate?.flows?.length || 0;

  return (
    <div className="h-screen w-screen flex flex-col font-sans bg-background text-gray-200 overflow-hidden select-auto">
      {/* Toast Notification Container */}
      <Toaster position="top-right" theme="dark" richColors />

      {/* ══ 1. TOP HEADER ═════════════════════════════════════════════════════ */}
      <Header
        backendUp={backendUp}
        isConnected={isConnected}
        isMonitoring={isMonitoring}
        isStarting={isStarting}
        isDemoMode={lastUpdate?.mode === 'demo'}
        health={health}
        soundEnabled={soundEnabled}
        is3D={is3D}
        activeTab={activeTab}
        onToggleSound={handleToggleSound}
        onToggle3D={handleToggle3D}
        onTabChange={setActiveTab}
        onStart={handleStart}
        onStop={handleStop}
        onDemo={handleDemo}
        onReset={handleReset}
      />

      {/* ══ 2. BACKEND / WS ERROR BANNER ══════════════════════════════════════ */}
      {(wsError || backendUp === false) && (
        <div className="flex-shrink-0 bg-high/15 border-b border-high/40 px-4 py-2 text-xs text-high flex items-center gap-2 select-text font-mono">
          <AlertTriangle className="w-4 h-4 flex-shrink-0 animate-pulse" />
          <span>
            {wsError ||
              'Cannot reach backend at http://localhost:8000. Run "python run.py" or check Administrator privileges for Scapy.'}
          </span>
        </div>
      )}

      {/* ══ 3. ENRICHED METRICS RIBBON (Responsive grid, real bytes, sparklines) ═ */}
      <MetricsRibbon
        lastUpdate={lastUpdate}
        activeIPs={activeIPs}
        activeConnections={activeConnections}
        chartData={chartData}
      />

      {/* ══ 4. MAIN WORKSPACE CONTENT ═════════════════════════════════════════ */}
      <div className="flex-1 flex overflow-hidden">
        {/* TAB A: LIVE GRAPH + SIDEBAR + BOTTOM TABLE */}
        {activeTab === 'graph' && (
          <div className="flex-1 flex overflow-hidden">
            {/* Left: Graph Area + Collapsible Bottom Flow Table */}
            <div className="flex-1 flex flex-col overflow-hidden relative">
              {/* Force Graph (occupies primary space) */}
              <div className="flex-1 relative overflow-hidden">
                <NetworkGraph
                  lastUpdate={lastUpdate}
                  selectedNode={selectedNode}
                  selectedEdge={selectedEdge}
                  is3D={is3D}
                  onSelectNode={(ip) => {
                    setSelectedNode(ip);
                    setSelectedEdge(null);
                  }}
                  onSelectEdge={(flow) => {
                    setSelectedEdge(flow);
                    setSelectedNode(null);
                  }}
                  isMonitoring={isMonitoring}
                />
              </div>

              {/* Bottom Quick Flow Table (height 180px) */}
              <div className="h-48 flex-shrink-0 border-t border-border/80 flex flex-col bg-panel">
                <FlowTable
                  flows={flows}
                  selectedEdge={selectedEdge}
                  onSelectFlow={(flow) => {
                    setSelectedEdge(flow);
                    setSelectedNode(null);
                  }}
                  isMonitoring={isMonitoring}
                  searchTerm={searchTerm}
                  onSearchChange={setSearchTerm}
                  filterRisk={filterRisk}
                  onFilterRiskChange={setFilterRisk}
                />
              </div>
            </div>

            {/* Right: Inspection Sidebar (Fixed 340px) */}
            <div className="w-80 lg:w-88 flex-shrink-0 flex flex-col border-l border-border/80 bg-panel/95 backdrop-blur-md overflow-hidden">
              {/* If a node is selected, show Node Details */}
              {selectedNode && (
                <NodeDetails
                  nodeId={selectedNode}
                  flows={flows}
                  onClose={() => setSelectedNode(null)}
                  onSelectFlow={(f) => {
                    setSelectedEdge(f);
                    setSelectedNode(null);
                  }}
                />
              )}

              {/* If an edge/flow is selected, show Flow Details */}
              {selectedEdge && (
                <FlowDetails
                  flow={selectedEdge}
                  onClose={() => setSelectedEdge(null)}
                  onSelectNode={(ip) => {
                    setSelectedNode(ip);
                    setSelectedEdge(null);
                  }}
                />
              )}

              {/* Threat Alert Stream Feed */}
              <AlertsFeed
                flows={flows}
                onSelectFlow={(f) => {
                  setSelectedEdge(f);
                  setSelectedNode(null);
                }}
                onSelectNode={(ip) => {
                  setSelectedNode(ip);
                  setSelectedEdge(null);
                }}
              />
            </div>
          </div>
        )}

        {/* TAB B: EXPANDED VISUAL ANALYTICS */}
        {activeTab === 'analytics' && (
          <VisualAnalytics chartData={chartData} flows={flows} />
        )}

        {/* TAB C: FULLSCREEN FLOW TABLE */}
        {activeTab === 'table' && (
          <div className="flex-1 flex flex-col overflow-hidden bg-panel">
            <FlowTable
              flows={flows}
              selectedEdge={selectedEdge}
              onSelectFlow={(flow) => {
                setSelectedEdge(flow);
                setActiveTab('graph'); // jump to graph inspector
              }}
              isMonitoring={isMonitoring}
              searchTerm={searchTerm}
              onSearchChange={setSearchTerm}
              filterRisk={filterRisk}
              onFilterRiskChange={setFilterRisk}
            />
          </div>
        )}
      </div>
    </div>
  );
}
