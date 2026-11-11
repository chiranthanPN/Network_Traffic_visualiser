import { HealthStatus, DatasetOption } from '../types/network';

const API_BASE = 'http://localhost:8000/api';

export async function getHealth(): Promise<HealthStatus> {
  const res = await fetch(`${API_BASE}/health`);
  return res.json();
}

export async function getDatasets(): Promise<DatasetOption[]> {
  const res = await fetch(`${API_BASE}/datasets`);
  return res.json();
}

export async function startMonitor(): Promise<{status: string}> {
  const res = await fetch(`${API_BASE}/monitor/start`, { method: 'POST' });
  return res.json();
}

export async function startDemo(datasetId?: string): Promise<{status: string; dataset?: string}> {
  const url = datasetId
    ? `${API_BASE}/monitor/demo?dataset=${encodeURIComponent(datasetId)}`
    : `${API_BASE}/monitor/demo`;
  const res = await fetch(url, { method: 'POST' });
  return res.json();
}

export async function stopMonitor(): Promise<{status: string}> {
  const res = await fetch(`${API_BASE}/monitor/stop`, { method: 'POST' });
  return res.json();
}

export async function simulateFakeSite(siteId: string = 'saucedemo'): Promise<{status: string; site: string; domain: string}> {
  const res = await fetch(`${API_BASE}/monitor/simulate-fake-site?site_id=${siteId}`, { method: 'POST' });
  return res.json();
}

export async function getFakeSites(): Promise<any[]> {
  const res = await fetch(`${API_BASE}/fake-sites`);
  return res.json();
}
