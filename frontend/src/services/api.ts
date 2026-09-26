import { HealthStatus } from '../types/network';

const API_BASE = 'http://localhost:8000/api';

export async function getHealth(): Promise<HealthStatus> {
  const res = await fetch(`${API_BASE}/health`);
  return res.json();
}

export async function startMonitor(): Promise<{status: string}> {
  const res = await fetch(`${API_BASE}/monitor/start`, { method: 'POST' });
  return res.json();
}

export async function stopMonitor(): Promise<{status: string}> {
  const res = await fetch(`${API_BASE}/monitor/stop`, { method: 'POST' });
  return res.json();
}
