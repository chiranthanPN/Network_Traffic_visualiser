import React, { useState, useMemo, useRef } from 'react';
import { useVirtualizer } from '@tanstack/react-virtual';
import { Search, ArrowUpDown, Shield, AlertTriangle, ShieldAlert } from 'lucide-react';
import { FlowResult } from '../types/network';
import { formatBytes } from '../utils/network';

interface FlowTableProps {
  flows: FlowResult[];
  selectedEdge: FlowResult | null;
  onSelectFlow: (flow: FlowResult) => void;
  isMonitoring: boolean;
  searchTerm: string;
  onSearchChange: (val: string) => void;
  filterRisk: string;
  onFilterRiskChange: (val: string) => void;
}

type SortField = 'source_ip' | 'destination_ip' | 'protocol' | 'packet_count' | 'byte_count' | 'if_score' | 'gat_score' | 'risk';

export function FlowTable({
  flows,
  selectedEdge,
  onSelectFlow,
  isMonitoring,
  searchTerm,
  onSearchChange,
  filterRisk,
  onFilterRiskChange,
}: FlowTableProps) {
  const [sortField, setSortField] = useState<SortField>('byte_count');
  const [sortAsc, setSortAsc] = useState<boolean>(false);

  // Filter flows
  const filteredFlows = useMemo(() => {
    return flows
      .filter((f) => filterRisk === 'ALL' || f.fusion.risk_level === filterRisk)
      .filter(
        (f) =>
          !searchTerm ||
          f.source_ip.includes(searchTerm) ||
          f.destination_ip.includes(searchTerm) ||
          f.protocol.toLowerCase().includes(searchTerm.toLowerCase())
      );
  }, [flows, filterRisk, searchTerm]);

  // Sort flows
  const sortedFlows = useMemo(() => {
    return [...filteredFlows].sort((a, b) => {
      let valA: any;
      let valB: any;

      switch (sortField) {
        case 'source_ip':
          valA = a.source_ip;
          valB = b.source_ip;
          break;
        case 'destination_ip':
          valA = a.destination_ip;
          valB = b.destination_ip;
          break;
        case 'protocol':
          valA = a.protocol;
          valB = b.protocol;
          break;
        case 'packet_count':
          valA = a.packet_count || 0;
          valB = b.packet_count || 0;
          break;
        case 'byte_count':
          valA = a.byte_count || 0;
          valB = b.byte_count || 0;
          break;
        case 'if_score':
          valA = a.isolation_forest.decision_score;
          valB = b.isolation_forest.decision_score;
          break;
        case 'gat_score':
          valA = a.gat.attack_score;
          valB = b.gat.attack_score;
          break;
        case 'risk':
          const order = { LOW: 1, MEDIUM: 2, HIGH: 3 };
          valA = order[a.fusion.risk_level] || 0;
          valB = order[b.fusion.risk_level] || 0;
          break;
        default:
          valA = 0;
          valB = 0;
      }

      if (valA < valB) return sortAsc ? -1 : 1;
      if (valA > valB) return sortAsc ? 1 : -1;
      return 0;
    });
  }, [filteredFlows, sortField, sortAsc]);

  const handleHeaderClick = (field: SortField) => {
    if (sortField === field) {
      setSortAsc(!sortAsc);
    } else {
      setSortField(field);
      setSortAsc(false); // default descending for new field
    }
  };

  // Virtualizer for smooth rendering of 200+ rows
  const parentRef = useRef<HTMLDivElement>(null);
  const rowVirtualizer = useVirtualizer({
    count: sortedFlows.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 36,
    overscan: 10,
  });

  return (
    <div className="flex-1 flex flex-col bg-panel/90 border-t border-border/80 select-auto overflow-hidden">
      {/* Table Toolbar */}
      <div className="flex items-center justify-between px-4 py-2 border-b border-border/80 flex-shrink-0 bg-background/50">
        <div className="flex items-center gap-3">
          <h2 className="font-bold text-xs uppercase tracking-wider text-gray-300 flex items-center gap-2">
            <span>Flow History</span>
            <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-panel text-gray-400 border border-border">
              {sortedFlows.length} shown / {flows.length} total
            </span>
          </h2>
        </div>

        <div className="flex items-center gap-2">
          {/* Search */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-gray-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search IP, protocol... (Press /)"
              value={searchTerm}
              onChange={(e) => onSearchChange(e.target.value)}
              className="bg-background border border-border rounded-lg pl-8 pr-3 py-1 text-xs text-gray-200 outline-none focus:border-primary w-56 font-mono"
            />
          </div>

          {/* Risk Filter */}
          <select
            value={filterRisk}
            onChange={(e) => onFilterRiskChange(e.target.value)}
            className="bg-background border border-border rounded-lg px-2.5 py-1 text-xs text-gray-200 outline-none focus:border-primary font-medium"
          >
            <option value="ALL">All Risk Levels</option>
            <option value="HIGH">High Risk Only</option>
            <option value="MEDIUM">Medium Risk Only</option>
            <option value="LOW">Low Risk Only</option>
          </select>
        </div>
      </div>

      {/* Virtual Table Container */}
      <div ref={parentRef} className="flex-1 overflow-auto">
        <table className="w-full text-xs text-left">
          <thead className="text-[10px] text-gray-400 uppercase bg-background/95 sticky top-0 z-10 border-b border-border">
            <tr>
              <th onClick={() => handleHeaderClick('source_ip')} className="px-3 py-2 cursor-pointer hover:text-white">
                <span className="flex items-center gap-1">Source Host <ArrowUpDown className="w-3 h-3" /></span>
              </th>
              <th onClick={() => handleHeaderClick('destination_ip')} className="px-3 py-2 cursor-pointer hover:text-white">
                <span className="flex items-center gap-1">Destination <ArrowUpDown className="w-3 h-3" /></span>
              </th>
              <th onClick={() => handleHeaderClick('protocol')} className="px-3 py-2 cursor-pointer hover:text-white">
                <span className="flex items-center gap-1">Proto <ArrowUpDown className="w-3 h-3" /></span>
              </th>
              <th onClick={() => handleHeaderClick('packet_count')} className="px-3 py-2 text-right cursor-pointer hover:text-white">
                <span className="flex items-center justify-end gap-1">Packets <ArrowUpDown className="w-3 h-3" /></span>
              </th>
              <th onClick={() => handleHeaderClick('byte_count')} className="px-3 py-2 text-right cursor-pointer hover:text-white">
                <span className="flex items-center justify-end gap-1">Volume <ArrowUpDown className="w-3 h-3" /></span>
              </th>
              <th onClick={() => handleHeaderClick('if_score')} className="px-3 py-2 cursor-pointer hover:text-white">
                <span className="flex items-center gap-1">IsoForest Score <ArrowUpDown className="w-3 h-3" /></span>
              </th>
              <th onClick={() => handleHeaderClick('gat_score')} className="px-3 py-2 cursor-pointer hover:text-white">
                <span className="flex items-center gap-1">GAT Score <ArrowUpDown className="w-3 h-3" /></span>
              </th>
              <th onClick={() => handleHeaderClick('risk')} className="px-3 py-2 cursor-pointer hover:text-white">
                <span className="flex items-center gap-1">Fused Risk <ArrowUpDown className="w-3 h-3" /></span>
              </th>
            </tr>
          </thead>

          <tbody
            style={{
              height: `${rowVirtualizer.getTotalSize()}px`,
              position: 'relative',
              width: '100%',
            }}
          >
            {rowVirtualizer.getVirtualItems().map((virtualRow) => {
              const f = sortedFlows[virtualRow.index];
              const isSelected = selectedEdge === f;
              const isHigh = f.fusion.risk_level === 'HIGH';
              const isMed = f.fusion.risk_level === 'MEDIUM';

              return (
                <tr
                  key={virtualRow.index}
                  onClick={() => onSelectFlow(f)}
                  className={`border-b border-border/40 hover:bg-border/30 cursor-pointer transition-colors ${
                    isSelected ? 'bg-primary/15 border-primary/50' : ''
                  }`}
                  style={{
                    position: 'absolute',
                    top: 0,
                    left: 0,
                    width: '100%',
                    height: `${virtualRow.size}px`,
                    transform: `translateY(${virtualRow.start}px)`,
                  }}
                >
                  <td className="px-3 py-2 font-mono whitespace-nowrap select-all">
                    {f.source_ip}
                    <span className="text-gray-500">:{f.source_port}</span>
                  </td>

                  <td className="px-3 py-2 font-mono whitespace-nowrap select-all">
                    {f.destination_ip}
                    <span className="text-gray-500">:{f.destination_port}</span>
                  </td>

                  <td className="px-3 py-2 font-mono text-gray-300">{f.protocol}</td>

                  <td className="px-3 py-2 text-right font-mono text-gray-200">
                    {(f.packet_count || 0).toLocaleString()}
                  </td>

                  <td className="px-3 py-2 text-right font-mono text-gray-200">
                    {formatBytes(f.byte_count || 0)}
                  </td>

                  <td className="px-3 py-2 font-mono">
                    <span className={f.isolation_forest.is_anomaly ? 'text-high font-bold' : 'text-gray-400'}>
                      {f.isolation_forest.decision_score.toFixed(3)}
                    </span>
                  </td>

                  <td className="px-3 py-2 font-mono">
                    <span className={f.gat.is_anomaly ? 'text-high font-bold' : 'text-gray-400'}>
                      {f.gat.attack_score.toFixed(3)}
                    </span>
                  </td>

                  {/* Accessible Color-Blind Friendly Risk Chip */}
                  <td className="px-3 py-2 whitespace-nowrap">
                    <span
                      className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase font-mono ${
                        isHigh
                          ? 'bg-high/20 text-high border border-high/50 shadow-glow-high'
                          : isMed
                          ? 'bg-medium/20 text-medium border border-medium/40'
                          : 'bg-low/20 text-low border border-low/40'
                      }`}
                    >
                      {isHigh ? (
                        <>
                          <ShieldAlert className="w-3 h-3 text-high" /> ✖ HIGH
                        </>
                      ) : isMed ? (
                        <>
                          <AlertTriangle className="w-3 h-3 text-medium" /> ▲ MED
                        </>
                      ) : (
                        <>
                          <Shield className="w-3 h-3 text-low" /> ● LOW
                        </>
                      )}
                    </span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>

        {sortedFlows.length === 0 && (
          <div className="flex flex-col items-center justify-center h-36 text-gray-500 text-xs gap-1">
            <span>No flows match your search or filter.</span>
            {flows.length === 0 && !isMonitoring && (
              <span className="text-gray-600">Start monitoring or replay sample data to view live flow records.</span>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
