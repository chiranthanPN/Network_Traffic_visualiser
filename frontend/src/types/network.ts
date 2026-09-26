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
  isolation_forest: IsolationForestResult;
  gat: GATResult;
  fusion: FusionResult;
}

// ─── Window-level snapshot (one WebSocket message) ───────────────────────────

export interface RiskCounts {
  LOW: number;
  MEDIUM: number;
  HIGH: number;
}

export interface NetworkUpdate {
  type: 'network_update';
  /** Unix timestamp (seconds) */
  timestamp: number;
  /** Seconds for this analysis window */
  window_duration: number;
  packets_captured: number;
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

// ─── Chart history entry ─────────────────────────────────────────────────────

export interface ChartEntry {
  time: string;
  packetsPerSec: number;
  totalFlows: number;
  anomalies: number;
}
