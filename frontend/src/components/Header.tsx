import React from 'react';
import {
  Shield, Play, Square, Wifi, WifiOff, Volume2, VolumeX,
  RotateCcw, Box, Eye
} from 'lucide-react';
import { HealthStatus } from '../types/network';

interface HeaderProps {
  backendUp: boolean | null;
  isConnected: boolean;
  isMonitoring: boolean;
  isStarting: boolean;
  isDemoMode: boolean;
  health: HealthStatus | null;
  soundEnabled: boolean;
  is3D: boolean;
  activeTab: 'graph' | 'analytics' | 'table';
  onToggleSound: () => void;
  onToggle3D: () => void;
  onTabChange: (tab: 'graph' | 'analytics' | 'table') => void;
  onStart: () => void;
  onStop: () => void;
  onDemo: () => void;
  onReset: () => void;
}

function StatusDot({ ok, label }: { ok: boolean | undefined; label: string }) {
  return (
    <span
      className={`text-xs font-medium flex items-center gap-1.5 ${
        ok === undefined ? 'text-gray-500' : ok ? 'text-low' : 'text-high'
      }`}
    >
      <span
        className={`inline-block w-2 h-2 rounded-full transition-all ${
          ok === undefined
            ? 'bg-gray-600'
            : ok
            ? 'bg-low shadow-[0_0_6px_rgba(16,185,129,0.5)]'
            : 'bg-high shadow-[0_0_6px_rgba(239,68,68,0.5)]'
        }`}
      />
      {label}
    </span>
  );
}

export function Header({
  backendUp,
  isConnected,
  isMonitoring,
  isStarting,
  isDemoMode,
  health,
  soundEnabled,
  is3D,
  activeTab,
  onToggleSound,
  onToggle3D,
  onTabChange,
  onStart,
  onStop,
  onDemo,
  onReset,
}: HeaderProps) {
  const liveStatus = (() => {
    if (backendUp === false) {
      return { label: 'BACKEND DOWN', cls: 'bg-high/20 text-high border-high/50 shadow-glow-high' };
    }
    if (!isConnected && backendUp) {
      return { label: 'CONNECTING...', cls: 'bg-medium/20 text-medium border-medium/50' };
    }
    if (isMonitoring && isConnected) {
      return {
        label: isDemoMode ? '● DEMO REPLAY' : '● LIVE MONITORING',
        cls: 'bg-low/20 text-low border-low/50 shadow-[0_0_8px_rgba(16,185,129,0.35)]',
      };
    }
    if (isConnected && !isMonitoring) {
      return { label: '○ READY', cls: 'bg-gray-800 text-gray-300 border-border' };
    }
    return { label: '● DISCONNECTED', cls: 'bg-high/20 text-high border-high/50' };
  })();

  return (
    <header className="flex-shrink-0 glass-header px-4 py-2.5 flex items-center justify-between gap-3 select-auto">
      {/* Brand & Connection State */}
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2">
          <div className="p-1.5 bg-primary/10 rounded-lg border border-primary/30">
            <Shield className="w-5 h-5 text-primary" />
          </div>
          <div>
            <h1 className="text-sm font-bold tracking-tight text-white flex items-center gap-1.5">
              Network Traffic Analyser
              <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-primary/20 text-primary border border-primary/30 font-normal">
                GAT + IF
              </span>
            </h1>
          </div>
        </div>

        <div className={`px-2.5 py-0.5 rounded text-xs font-mono font-bold border transition-all ${liveStatus.cls}`}>
          {liveStatus.label}
        </div>

        {isConnected ? (
          <span title="WebSocket Connected" className="flex items-center gap-1 text-[11px] text-low">
            <Wifi className="w-3.5 h-3.5 text-low" />
            <span className="hidden lg:inline text-gray-400 font-mono text-[10px]">WS LIVE</span>
          </span>
        ) : (
          <span title="WebSocket Disconnected" className="flex items-center gap-1 text-[11px] text-high">
            <WifiOff className="w-3.5 h-3.5 text-high" />
            <span className="hidden lg:inline text-gray-400 font-mono text-[10px]">WS OFF</span>
          </span>
        )}
      </div>

      {/* Navigation Tabs */}
      <div className="flex items-center gap-1 bg-background/70 p-1 rounded-lg border border-border/80">
        <button
          onClick={() => onTabChange('graph')}
          className={`flex items-center gap-1.5 px-3 py-1 rounded text-xs font-medium transition-all ${
            activeTab === 'graph'
              ? 'bg-primary text-white shadow-sm'
              : 'text-gray-400 hover:text-white hover:bg-panel'
          }`}
        >
          <Eye className="w-3.5 h-3.5" />
          <span>Live Graph</span>
        </button>

        <button
          onClick={() => onTabChange('analytics')}
          className={`flex items-center gap-1.5 px-3 py-1 rounded text-xs font-medium transition-all ${
            activeTab === 'analytics'
              ? 'bg-primary text-white shadow-sm'
              : 'text-gray-400 hover:text-white hover:bg-panel'
          }`}
        >
          <span>Analytics</span>
        </button>

        <button
          onClick={() => onTabChange('table')}
          className={`flex items-center gap-1.5 px-3 py-1 rounded text-xs font-medium transition-all ${
            activeTab === 'table'
              ? 'bg-primary text-white shadow-sm'
              : 'text-gray-400 hover:text-white hover:bg-panel'
          }`}
        >
          <span>Flow History</span>
        </button>
      </div>

      {/* Model & System Health Badges */}
      <div className="hidden xl:flex items-center gap-4 text-xs bg-background/50 px-3 py-1 rounded-md border border-border/50">
        <StatusDot ok={backendUp ?? undefined} label="API" />
        <StatusDot ok={health?.isolation_forest} label="IsoForest" />
        <StatusDot ok={health?.gat} label="GAT Model" />
        <StatusDot ok={isMonitoring} label="Capture" />
      </div>

      {/* Action Controls */}
      <div className="flex items-center gap-2">
        {/* Sound toggle */}
        <button
          onClick={onToggleSound}
          title={soundEnabled ? 'Alert Audio Enabled (Click to Mute)' : 'Alert Audio Muted (Click to Enable)'}
          className={`p-1.5 rounded border transition-colors ${
            soundEnabled
              ? 'border-primary/50 text-primary bg-primary/10'
              : 'border-border text-gray-500 hover:text-gray-300'
          }`}
        >
          {soundEnabled ? <Volume2 className="w-4 h-4" /> : <VolumeX className="w-4 h-4" />}
        </button>

        {/* 2D / 3D Toggle */}
        <button
          onClick={onToggle3D}
          title={is3D ? 'Switch to 2D Graph' : 'Switch to 3D Force Graph'}
          className={`flex items-center gap-1 px-2.5 py-1 rounded text-xs font-mono font-medium border transition-colors ${
            is3D
              ? 'bg-primary/20 text-primary border-primary/50 shadow-glow-primary'
              : 'border-border text-gray-400 hover:text-white hover:bg-panel'
          }`}
        >
          <Box className="w-3.5 h-3.5" />
          <span>{is3D ? '3D' : '2D'}</span>
        </button>

        {!isMonitoring ? (
          <>
            <button
              onClick={onDemo}
              disabled={isStarting || backendUp === false}
              className="flex items-center gap-1.5 border border-border/90 hover:border-primary/80 disabled:opacity-40 px-3 py-1.5 rounded text-gray-200 text-xs font-medium transition-colors bg-panel/50 hover:bg-panel"
            >
              <Play className="w-3 h-3 text-medium" /> Replay Sample
            </button>

            <button
              onClick={onStart}
              disabled={isStarting || backendUp === false}
              className="flex items-center gap-1.5 bg-primary hover:bg-primary/90 disabled:opacity-40 px-3.5 py-1.5 rounded text-white text-xs font-medium transition-all shadow-[0_0_12px_rgba(59,130,246,0.35)]"
            >
              <Play className="w-3 h-3 fill-current" />
              {isStarting ? 'Starting...' : 'Start Monitoring'}
            </button>
          </>
        ) : (
          <button
            onClick={onStop}
            className="flex items-center gap-1.5 bg-high hover:bg-high/90 px-3.5 py-1.5 rounded text-white text-xs font-medium transition-all shadow-glow-high"
          >
            <Square className="w-3 h-3 fill-current" /> Stop Monitoring
          </button>
        )}

        <button
          onClick={onReset}
          title="Reset graph and flow history"
          className="p-1.5 text-gray-400 hover:text-white border border-border rounded hover:border-gray-500 transition-colors"
        >
          <RotateCcw className="w-3.5 h-3.5" />
        </button>
      </div>
    </header>
  );
}
