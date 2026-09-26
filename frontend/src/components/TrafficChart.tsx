import React, { useState } from 'react';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from 'recharts';
import { ChartEntry } from '../types/network';

const METRICS: { key: keyof ChartEntry; label: string; color: string }[] = [
  { key: 'packetsPerSec', label: 'Packets/s', color: '#3b82f6' },
  { key: 'totalFlows',    label: 'Flows',     color: '#10b981' },
  { key: 'anomalies',     label: 'Anomalies', color: '#ef4444' },
];

interface Props {
  data: ChartEntry[];
}

export function TrafficChart({ data }: Props) {
  const [active, setActive] = useState<keyof ChartEntry>('packetsPerSec');

  return (
    <div className="p-4 pb-2">
      {/* Metric selector */}
      <div className="flex gap-1 mb-3">
        {METRICS.map((m) => (
          <button
            key={String(m.key)}
            onClick={() => setActive(m.key)}
            className={`text-[10px] px-2 py-0.5 rounded transition-colors ${
              active === m.key
                ? 'font-bold text-white'
                : 'text-gray-500 hover:text-gray-300'
            }`}
            style={active === m.key ? { backgroundColor: m.color + '30', borderColor: m.color, color: m.color } : {}}
          >
            {m.label}
          </button>
        ))}
      </div>

      <div style={{ height: 100 }}>
        {data.length === 0 ? (
          <div className="h-full flex items-center justify-center text-[10px] text-gray-600">
            No data yet
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={data} margin={{ top: 2, right: 4, left: -20, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#2A3655" strokeOpacity={0.5} />
              <XAxis
                dataKey="time"
                stroke="#4B5563"
                tick={{ fontSize: 8, fill: '#6B7280' }}
                tickLine={false}
                interval="preserveStartEnd"
              />
              <YAxis
                stroke="#4B5563"
                tick={{ fontSize: 8, fill: '#6B7280' }}
                tickLine={false}
              />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#151C2C',
                  borderColor: '#2A3655',
                  borderRadius: 4,
                  fontSize: 11,
                  color: '#E5E7EB',
                }}
                labelStyle={{ color: '#9CA3AF', fontSize: 10 }}
              />
              {METRICS.filter((m) => m.key === active).map((m) => (
                <Line
                  key={String(m.key)}
                  type="monotone"
                  dataKey={m.key}
                  stroke={m.color}
                  strokeWidth={2}
                  dot={false}
                  isAnimationActive={false}
                  name={m.label}
                />
              ))}
            </LineChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  );
}
