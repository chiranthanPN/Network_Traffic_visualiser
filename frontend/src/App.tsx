import React, { useState, useEffect, useMemo, useCallback, useRef } from 'react';
import { Toaster, toast } from 'sonner';
import { AlertTriangle, Info } from 'lucide-react';
import { useNetworkWebSocket } from './hooks/useNetworkWebSocket';
import { getHealth, getDatasets, startDemo, startMonitor, stopMonitor, simulateFakeSite } from './services/api';
import { HealthStatus, FlowResult, DatasetOption, FakeWebsiteAlert } from './types/network';
import { soundManager } from './utils/audio';

import { Header } from './components/Header';
import { MetricsRibbon } from './components/MetricsRibbon';
import { NetworkGraph } from './components/NetworkGraph';
import { NodeDetails } from './components/sidebar/NodeDetails';
import { FlowDetails } from './components/sidebar/FlowDetails';
import { AlertsFeed } from './components/sidebar/AlertsFeed';
import { VisualAnalytics } from './components/analytics/VisualAnalytics';
import { FlowTable } from './components/FlowTable';
import { FakeWebsiteAlertModal } from './components/FakeWebsiteAlertModal';

export default function App() {
  const [soundEnabled, setSoundEnabled] = useState(true);
  const [is3D, setIs3D] = useState(false);
  const [activeTab, setActiveTab] = useState<'graph' | 'analytics' | 'table'>('graph');

  // Datasets for sample replay
  const [datasets, setDatasets] = useState<DatasetOption[]>([]);
  const [selectedDataset, setSelectedDataset] = useState<string>('demo_anomaly_flows.csv');

  // Pop-up Alert state for Fake Websites
  const [activeFakeAlert, setActiveFakeAlert] = useState<FakeWebsiteAlert | null>(null);
  const snoozedDomainsRef = useRef<Map<string, number>>(new Map());

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

  // Pop-up Alert warning for Fake Online Shopping / Demo Websites
  const handleFakeWebsiteAlert = useCallback((alert: FakeWebsiteAlert) => {
    const domain = alert.fake_website.domain;
    const now = Date.now();
    const snoozedUntil = snoozedDomainsRef.current.get(domain) || 0;

    // Sonner notification toast
    toast.warning(`FAKE WEBSITE DETECTED: ${alert.fake_website.site_name}`, {
      description: `${domain} (${alert.fake_website.category}) — Insecure simulated environment!`,
      duration: 6000,
    });

    // If snoozed recently, skip center modal popup
    if (now < snoozedUntil) {
      return;
    }

    // Play urgent sound alert
    soundManager.playFakeSiteAlertSound();

    // Trigger Pop-up Alert Warning Modal
    setActiveFakeAlert(alert);
  }, []);

  const handleSnoozeDomain = useCallback((domain: string) => {
    snoozedDomainsRef.current.set(domain, Date.now() + 60000);
    toast.info(`Snoozed popups for ${domain} for 60s`);
  }, []);

  const { isConnected, lastUpdate, flows, chartData, error: wsError, infoNotice, clearHistory } =
    useNetworkWebSocket('ws://localhost:8000/api/ws', {
      onHighAlert: handleHighAlert,
      onFakeWebsiteAlert: handleFakeWebsiteAlert,
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

  // ── Dataset Options Fetching ─────────────────────────────────────────────────
  useEffect(() => {
    getDatasets()
      .then((data) => {
        if (data && data.length > 0) {
          setDatasets(data);
          setSelectedDataset(data[0].id);
        }
      })
      .catch((err) => {
        console.error('Failed to load datasets:', err);
      });
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
      const chosen = datasets.find(d => d.id === selectedDataset);
      await startDemo(selectedDataset);
      setIsMonitoring(true);
      toast.info(`Streaming ${chosen ? chosen.name : selectedDataset}`);
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

  const handleSimulateFakeSite = async (siteId: string) => {
    try {
      toast.info(`Injecting live test traffic for ${siteId}...`);
      const res = await simulateFakeSite(siteId);
      toast.success(`Generated live test connection for ${res.site} (${res.domain})`);
    } catch {
      toast.error('Simulation request failed');
    }
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

  // Active dataset display label
  const activeDatasetDisplayName = useMemo(() => {
    const targetId = lastUpdate?.dataset_name || selectedDataset;
    const match = datasets.find(d => d.id === targetId);
    return match ? match.name : targetId;
  }, [lastUpdate?.dataset_name, selectedDataset, datasets]);

  return (
    <div className="h-screen w-screen flex flex-col font-sans bg-background text-gray-200 overflow-hidden select-auto">
      {/* Toast Notification Container */}
      <Toaster position="top-right" theme="dark" richColors />

      {/* ══ POP-UP ALERT WARNING MODAL FOR FAKE WEBSITES ══════════════════════ */}
      <FakeWebsiteAlertModal
        alert={activeFakeAlert}
        onClose={() => {
          if (activeFakeAlert) {
            snoozedDomainsRef.current.set(activeFakeAlert.fake_website.domain, Date.now() + 15000);
          }
          setActiveFakeAlert(null);
        }}
        onInspect={(flow) => {
          if (activeFakeAlert) {
            snoozedDomainsRef.current.set(activeFakeAlert.fake_website.domain, Date.now() + 30000);
          }
          setSelectedEdge(flow);
          setSelectedNode(null);
          setActiveTab('graph');
        }}
        onSnooze={handleSnoozeDomain}
      />

      {/* ══ 1. TOP HEADER ═════════════════════════════════════════════════════ */}
      <Header
        backendUp={backendUp}
        isConnected={isConnected}
        isMonitoring={isMonitoring}
        isStarting={isStarting}
        isDemoMode={lastUpdate?.mode === 'demo'}
        captureMode={lastUpdate?.capture_mode || health?.capture_mode}
        health={health}
        soundEnabled={soundEnabled}
        is3D={is3D}
        activeTab={activeTab}
        datasets={datasets}
        selectedDataset={selectedDataset}
        activeDatasetName={activeDatasetDisplayName}
        onSelectDataset={setSelectedDataset}
        onToggleSound={handleToggleSound}
        onToggle3D={handleToggle3D}
        onTabChange={setActiveTab}
        onStart={handleStart}
        onStop={handleStop}
        onDemo={handleDemo}
        onReset={handleReset}
        onSimulateFakeSite={handleSimulateFakeSite}
      />

      {/* ══ 2. BACKEND / WS ERROR BANNER ══════════════════════════════════════ */}
      {(wsError || backendUp === false) && (
        <div className="flex-shrink-0 bg-high/15 border-b border-high/40 px-4 py-2 text-xs text-high flex items-center gap-2 select-text font-mono">
          <AlertTriangle className="w-4 h-4 flex-shrink-0 animate-pulse" />
          <span>
            {wsError ||
              'Cannot reach backend at http://localhost:8000. Run "python run.py".'}
          </span>
        </div>
      )}

      {/* Informational / Capture Mode Notice */}
      {infoNotice && !wsError && (
        <div className="flex-shrink-0 bg-primary/10 border-b border-primary/30 px-4 py-1 text-xs text-cyan-300 flex items-center gap-2 select-text font-mono">
          <Info className="w-3.5 h-3.5 flex-shrink-0 text-primary" />
          <span>{infoNotice}</span>
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
