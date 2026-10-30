// ─── Per-flow ML results ─────────────────────────────────────────────────────

export interface IsolationForestResult {
  is_anomaly: boolean;
  /** Higher = more normal. Lower = more anomalous. NOT a probability. */
  decision_score: number;
}

export interface GATResult {
  is_anomaly: boolean;
  /** Raw graph-attention score. Compared to threshold — not a calibrated probability. */
  attack_score: number;
  threshold: number;
}

export interface FusionResult {
  isolation_forest_anomaly: boolean;
  gat_anomaly: boolean;
  risk_level: 'LOW' | 'MEDIUM' | 'HIGH';
}

export interface FlowResult {
  source_ip: string;
  destination_ip: string;
  source_port: number | null;
  destination_port: number | null;
  protocol: string;
  packet_count: number;
  byte_count: number;
  duration?: number;
  packets_per_second?: number;
  bytes_per_second?: number;
  average_packet_size?: number;
  tcp_syn_count?: number;
  tcp_rst_count?: number;
  isolation_forest: IsolationForestResult;
  gat: GATResult;
  fusion: FusionResult;
  demo_scenario?: string;
  expected_label?: 'NORMAL' | 'SYNTHETIC_ANOMALY';
  timestamp?: number;
}

// ─── Window-level snapshot (one WebSocket message) ───────────────────────────

export interface RiskCounts {
  LOW: number;
  MEDIUM: number;
  HIGH: number;
}

export interface NetworkUpdate {
  type: 'network_update';
  mode?: 'live' | 'demo';
  /** Unix timestamp (seconds) */
  timestamp: number;
  /** Seconds for this analysis window */
  window_duration: number;
  packets_captured: number;
  bytes_captured?: number;
  total_flows: number;
  anomalies: number;
  risk_counts: RiskCounts;
  flows: FlowResult[];
}

// ─── Backend health / status ─────────────────────────────────────────────────

export interface HealthStatus {
  api: boolean;
  capture: boolean;
  isolation_forest: boolean;
  gat: boolean;
}

// ─── Chart history entry for multi-series analytics ──────────────────────────

export interface ChartEntry {
  time: string;
  packetsPerSec: number;
  bytesPerSec: number;
  totalFlows: number;
  anomalies: number;
  lowRisk: number;
  mediumRisk: number;
  highRisk: number;
}

// ─── Persistent Graph Types ──────────────────────────────────────────────────

export interface GraphNode {
  id: string;
  risk: 'LOW' | 'MEDIUM' | 'HIGH';
  isInternal: boolean;
  flows: number;
  packetCount: number;
  byteCount: number;
  lastSeen: number; // timestamp ms
  isHighPulsing?: boolean;
  isNewAlert?: boolean;
  x?: number;
  y?: number;
  vx?: number;
  vy?: number;
}

export interface GraphLink {
  source: string | GraphNode;
  target: string | GraphNode;
  risk: 'LOW' | 'MEDIUM' | 'HIGH';
  flow: FlowResult;
  byteCount: number;
  packetCount: number;
  curvature?: number;
  lastSeen: number;
}
