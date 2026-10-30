import React from 'react';
import { X, Network, ArrowUpRight, ArrowDownLeft, Shield, Globe } from 'lucide-react';
import { FlowResult } from '../../types/network';
import { isPrivateIP, formatBytes } from '../../utils/network';

interface NodeDetailsProps {
  nodeId: string;
  flows: FlowResult[];
  onClose: () => void;
  onSelectFlow: (flow: FlowResult) => void;
}

export function NodeDetails({ nodeId, flows, onClose, onSelectFlow }: NodeDetailsProps) {
  const isInternal = isPrivateIP(nodeId);

  // Filter flows involving this node
  const nodeFlows = flows.filter(f => f.source_ip === nodeId || f.destination_ip === nodeId);
  const inboundFlows = nodeFlows.filter(f => f.destination_ip === nodeId);
  const outboundFlows = nodeFlows.filter(f => f.source_ip === nodeId);

  const totalPkts = nodeFlows.reduce((sum, f) => sum + (f.packet_count || 0), 0);
  const totalBytes = nodeFlows.reduce((sum, f) => sum + (f.byte_count || 0), 0);

  const uniquePeers = Array.from(
    new Set(nodeFlows.map(f => (f.source_ip === nodeId ? f.destination_ip : f.source_ip)))
  );

  const highAlerts = nodeFlows.filter(f => f.fusion.risk_level === 'HIGH');
  const mediumAlerts = nodeFlows.filter(f => f.fusion.risk_level === 'MEDIUM');

  return (
    <div className="p-4 border-b border-border/80 text-xs">
      {/* Header */}
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-1.5 font-bold uppercase tracking-wider text-gray-300">
          <Network className="w-4 h-4 text-primary" />
          <span>Host Details</span>
        </div>
        <button
          onClick={onClose}
          className="text-gray-500 hover:text-white p-1 rounded hover:bg-border/40 transition-colors"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* IP Badge & Classification */}
      <div className="bg-background/90 p-3 rounded-lg border border-border/80 mb-3.5">
        <div className="flex items-center justify-between gap-2 mb-1">
          <span className="font-mono text-sm font-bold text-white select-all">
            {nodeId}
          </span>
          <span
            className={`text-[10px] font-mono px-2 py-0.5 rounded border flex items-center gap-1 ${
              isInternal
                ? 'bg-primary/20 text-primary border-primary/40'
                : 'bg-cyan-500/20 text-cyan-400 border-cyan-500/40'
            }`}
          >
            {isInternal ? <Shield className="w-3 h-3" /> : <Globe className="w-3 h-3" />}
            {isInternal ? 'Internal (RFC1918)' : 'External IP'}
          </span>
        </div>

        {/* Risk summary tags */}
        <div className="flex gap-2 mt-2">
          {highAlerts.length > 0 && (
            <span className="text-[10px] px-2 py-0.5 rounded bg-high/20 text-high border border-high/40 font-bold shadow-glow-high">
              {highAlerts.length} High Risk Flows
            </span>
          )}
          {mediumAlerts.length > 0 && (
            <span className="text-[10px] px-2 py-0.5 rounded bg-medium/20 text-medium border border-medium/40 font-bold">
              {mediumAlerts.length} Medium Risk
            </span>
          )}
          {highAlerts.length === 0 && mediumAlerts.length === 0 && (
            <span className="text-[10px] px-2 py-0.5 rounded bg-low/20 text-low border border-low/40">
              Clean Traffic
            </span>
          )}
        </div>
      </div>

      {/* Metrics Grid */}
      <div className="grid grid-cols-2 gap-2 mb-4">
        <div className="bg-background/60 p-2 rounded border border-border/50">
          <div className="text-[10px] text-gray-500 uppercase">Total Flows</div>
          <div className="text-sm font-bold font-mono text-white">{nodeFlows.length}</div>
        </div>

        <div className="bg-background/60 p-2 rounded border border-border/50">
          <div className="text-[10px] text-gray-500 uppercase">Unique Peers</div>
          <div className="text-sm font-bold font-mono text-white">{uniquePeers.length}</div>
        </div>

        <div className="bg-background/60 p-2 rounded border border-border/50">
          <div className="text-[10px] text-gray-500 uppercase flex items-center gap-1">
            <ArrowDownLeft className="w-3 h-3 text-cyan-400" /> Inbound
          </div>
          <div className="text-xs font-mono text-gray-200">{inboundFlows.length} flows</div>
        </div>

        <div className="bg-background/60 p-2 rounded border border-border/50">
          <div className="text-[10px] text-gray-500 uppercase flex items-center gap-1">
            <ArrowUpRight className="w-3 h-3 text-primary" /> Outbound
          </div>
          <div className="text-xs font-mono text-gray-200">{outboundFlows.length} flows</div>
        </div>

        <div className="bg-background/60 p-2 rounded border border-border/50">
          <div className="text-[10px] text-gray-500 uppercase">Total Packets</div>
          <div className="text-xs font-mono text-gray-200">{totalPkts.toLocaleString()}</div>
        </div>

        <div className="bg-background/60 p-2 rounded border border-border/50">
          <div className="text-[10px] text-gray-500 uppercase">Total Bytes</div>
          <div className="text-xs font-mono text-gray-200">{formatBytes(totalBytes)}</div>
        </div>
      </div>

      {/* Active Peers List */}
      <div>
        <div className="text-[11px] font-semibold text-gray-400 uppercase tracking-wider mb-2">
          Connected Peers ({uniquePeers.length})
        </div>
        <div className="space-y-1.5 max-h-48 overflow-y-auto pr-1">
          {nodeFlows.slice(0, 10).map((f, idx) => {
            const isOut = f.source_ip === nodeId;
            const peer = isOut ? f.destination_ip : f.source_ip;
            const risk = f.fusion.risk_level;

            return (
              <div
                key={idx}
                onClick={() => onSelectFlow(f)}
                className="flex items-center justify-between p-2 rounded bg-background/50 hover:bg-background border border-border/40 hover:border-primary/50 cursor-pointer transition-colors"
              >
                <div className="flex items-center gap-1.5 truncate">
                  <span className="text-gray-500 text-[10px] font-mono">{isOut ? '→' : '←'}</span>
                  <span className="font-mono text-xs text-gray-200 truncate select-all">{peer}</span>
                </div>
                <div className="flex items-center gap-1.5 flex-shrink-0">
                  <span className="text-[10px] text-gray-500 font-mono">{f.protocol}</span>
                  <span
                    className={`text-[9px] font-bold px-1.5 py-0.2 rounded ${
                      risk === 'HIGH'
                        ? 'bg-high/20 text-high'
                        : risk === 'MEDIUM'
                        ? 'bg-medium/20 text-medium'
                        : 'bg-low/20 text-low'
                    }`}
                  >
                    {risk}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
