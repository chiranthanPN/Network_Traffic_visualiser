import { useState, useEffect, useCallback, useRef } from 'react';
import { NetworkUpdate, FlowResult, ChartEntry } from '../types/network';

interface WebSocketHookOptions {
  onHighAlert?: (alertFlow: FlowResult) => void;
  onFakeWebsiteAlert?: (alert: { flow: FlowResult; fake_website: any }) => void;
  onInfoNotice?: (msg: string) => void;
}

export function useNetworkWebSocket(url: string, options?: WebSocketHookOptions) {
  const [isConnected, setIsConnected] = useState(false);
  const [lastUpdate, setLastUpdate] = useState<NetworkUpdate | null>(null);
  const [flows, setFlows] = useState<FlowResult[]>([]);
  const [chartData, setChartData] = useState<ChartEntry[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [infoNotice, setInfoNotice] = useState<string | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const backoffRef = useRef(1000);
  const onHighAlertRef = useRef(options?.onHighAlert);
  const onFakeWebsiteAlertRef = useRef(options?.onFakeWebsiteAlert);
  const onInfoNoticeRef = useRef(options?.onInfoNotice);

  useEffect(() => {
    onHighAlertRef.current = options?.onHighAlert;
    onFakeWebsiteAlertRef.current = options?.onFakeWebsiteAlert;
    onInfoNoticeRef.current = options?.onInfoNotice;
  }, [options?.onHighAlert, options?.onFakeWebsiteAlert, options?.onInfoNotice]);

  const connect = useCallback(() => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.CONNECTING) return;

    const ws = new WebSocket(url);
    wsRef.current = ws;

    ws.onopen = () => {
      setIsConnected(true);
      setError(null);
      backoffRef.current = 1000;
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);

        if (data.type === 'error') {
          setError(data.message as string);
          return;
        }

        if (data.type === 'info' || data.type === 'capture_mode_info') {
          setInfoNotice(data.message as string);
          onInfoNoticeRef.current?.(data.message as string);
          return;
        }

        if (data.type === 'network_update') {
          const update = data as NetworkUpdate;
          setLastUpdate(update);
          setError(null);

          // Tag flows with timestamp
          const taggedFlows = update.flows.map(f => ({
            ...f,
            timestamp: f.timestamp || update.timestamp,
          }));

          // Check for fake website alerts
          if (update.fake_website_alerts && update.fake_website_alerts.length > 0) {
            update.fake_website_alerts.forEach(fwa => {
              onFakeWebsiteAlertRef.current?.(fwa);
            });
          } else {
            // Fallback: check individual flows
            taggedFlows.forEach(f => {
              if (f.fake_website && f.fake_website.is_fake) {
                onFakeWebsiteAlertRef.current?.({
                  flow: f,
                  fake_website: f.fake_website
                });
              }
            });
          }

          // Fire toast / alert callback for any new HIGH risk flows in this window (excluding fake websites if already handled)
          if (onHighAlertRef.current) {
            const highFlows = taggedFlows.filter(f => f.fusion.risk_level === 'HIGH' && !f.fake_website);
            highFlows.forEach(hf => {
              onHighAlertRef.current?.(hf);
            });
          }

          setFlows((prev) => {
            const merged = [...taggedFlows, ...prev];
            return merged.slice(0, 1000);
          });

          setChartData((prev) => {
            const now = new Date(update.timestamp * 1000);
            const pad = (n: number) => n.toString().padStart(2, '0');
            const timeStr = `${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;
            const windowDur = update.window_duration || 5;

            const packetsPerSec = Math.round(update.packets_captured / windowDur);
            const bytesPerSec = update.bytes_captured !== undefined
              ? Math.round(update.bytes_captured / windowDur)
              : Math.round(update.packets_captured * 64 / windowDur);

            const entry: ChartEntry = {
              time: timeStr,
              packetsPerSec,
              bytesPerSec,
              totalFlows: update.total_flows,
              anomalies: update.anomalies,
              lowRisk: update.risk_counts?.LOW || 0,
              mediumRisk: update.risk_counts?.MEDIUM || 0,
              highRisk: update.risk_counts?.HIGH || 0,
            };

            return [...prev, entry].slice(-40); // rolling 40 windows
          });
        }
      } catch (err) {
        console.error('WS parse error:', err);
      }
    };

    ws.onclose = () => {
      setIsConnected(false);
      const delay = Math.min(backoffRef.current, 16000);
      backoffRef.current = delay * 2;
      reconnectTimer.current = setTimeout(connect, delay);
    };

    ws.onerror = () => {
      // handled by onclose
    };
  }, [url]);

  useEffect(() => {
    connect();
    return () => {
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current);
      if (wsRef.current) {
        wsRef.current.onclose = null;
        wsRef.current.close();
      }
    };
  }, [connect]);

  const clearHistory = useCallback(() => {
    setFlows([]);
    setLastUpdate(null);
    setChartData([]);
    setError(null);
  }, []);

  return { isConnected, lastUpdate, flows, chartData, error, infoNotice, clearHistory };
}
