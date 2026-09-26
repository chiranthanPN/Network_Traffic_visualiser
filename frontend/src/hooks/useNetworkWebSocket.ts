import { useState, useEffect, useCallback, useRef } from 'react';
import { NetworkUpdate, FlowResult } from '../types/network';

export function useNetworkWebSocket(url: string) {
  const [isConnected, setIsConnected] = useState(false);
  const [lastUpdate, setLastUpdate] = useState<NetworkUpdate | null>(null);
  const [flows, setFlows] = useState<FlowResult[]>([]);
  const [chartData, setChartData] = useState<any[]>([]);
  const [error, setError] = useState<string | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const backoffRef = useRef(1000);

  const connect = useCallback(() => {
    // Don't double-connect
    if (wsRef.current && wsRef.current.readyState === WebSocket.CONNECTING) return;

    const ws = new WebSocket(url);
    wsRef.current = ws;

    ws.onopen = () => {
      setIsConnected(true);
      setError(null);
      backoffRef.current = 1000; // reset backoff
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);

        if (data.type === 'error') {
          setError(data.message as string);
          return;
        }

        if (data.type === 'network_update') {
          const update = data as NetworkUpdate;
          setLastUpdate(update);
          setError(null);

          setFlows((prev) => {
            const merged = [...update.flows, ...prev];
            return merged.slice(0, 1000);
          });

          setChartData((prev) => {
            const now = new Date();
            const pad = (n: number) => n.toString().padStart(2, '0');
            const timeStr = `${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;
            const entry = {
              time: timeStr,
              packetsPerSec: Math.round(update.packets_captured / (update.window_duration || 5)),
              totalFlows: update.total_flows,
              anomalies: update.anomalies,
            };
            return [...prev, entry].slice(-30); // rolling 30 windows
          });
        }
      } catch (err) {
        console.error('WS parse error:', err);
      }
    };

    ws.onclose = () => {
      setIsConnected(false);
      // Exponential back-off: 1s → 2s → 4s → … cap 16s
      const delay = Math.min(backoffRef.current, 16000);
      backoffRef.current = delay * 2;
      reconnectTimer.current = setTimeout(connect, delay);
    };

    ws.onerror = () => {
      // onclose fires after onerror automatically
    };
  }, [url]);

  useEffect(() => {
    connect();
    return () => {
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current);
      if (wsRef.current) {
        // Prevent reconnect loop on unmount
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

  return { isConnected, lastUpdate, flows, chartData, error, clearHistory };
}
