import React from 'react';
import {
  ShieldAlert, ShoppingBag, ExternalLink, Eye, BellOff, X,
  AlertTriangle, ArrowRight, ShieldCheck, Cpu
} from 'lucide-react';
import { FlowResult, FakeWebsiteInfo } from '../types/network';

interface FakeWebsiteAlertModalProps {
  alert: {
    flow: FlowResult;
    fake_website: FakeWebsiteInfo;
  } | null;
  onClose: () => void;
  onInspect: (flow: FlowResult) => void;
  onSnooze: (domain: string) => void;
}

export function FakeWebsiteAlertModal({
  alert,
  onClose,
  onInspect,
  onSnooze,
}: FakeWebsiteAlertModalProps) {
  if (!alert) return null;

  const { flow, fake_website } = alert;

  const handleInspect = () => {
    onInspect(flow);
    onClose();
  };

  const handleSnooze = () => {
    onSnooze(fake_website.domain);
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-in fade-in duration-200">
      <div className="relative w-full max-w-lg overflow-hidden rounded-2xl bg-panel border-2 border-amber-500/80 shadow-[0_0_50px_rgba(245,158,11,0.35)] text-gray-100">
        {/* Animated Top Hazard Stripe */}
        <div className="h-2 w-full bg-gradient-to-r from-amber-500 via-red-500 to-amber-500 animate-pulse" />

        {/* Modal Header */}
        <div className="p-5 pb-3 flex items-start justify-between gap-3 border-b border-border/80">
          <div className="flex items-center gap-3">
            <div className="relative p-2.5 rounded-xl bg-amber-500/20 text-amber-400 border border-amber-500/40 flex-shrink-0">
              <ShieldAlert className="w-7 h-7 animate-bounce" />
              <span className="absolute -top-1 -right-1 flex h-3 w-3">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-amber-400 opacity-75" />
                <span className="relative inline-flex rounded-full h-3 w-3 bg-amber-500" />
              </span>
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase tracking-wider bg-amber-500/20 text-amber-300 border border-amber-500/40">
                  Live Traffic Threat
                </span>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase tracking-wider bg-high/20 text-high border border-high/40">
                  HIGH RISK
                </span>
              </div>
              <h2 className="text-lg font-bold text-white tracking-tight mt-1 flex items-center gap-1.5">
                Fake Website Detected!
              </h2>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 text-gray-400 hover:text-white rounded-lg hover:bg-border/60 transition-colors"
            title="Dismiss popup"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-5 space-y-4">
          {/* Target Website Showcase Card */}
          <div className="bg-background/90 p-4 rounded-xl border border-amber-500/30 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <ShoppingBag className="w-5 h-5 text-amber-400 flex-shrink-0" />
                <div>
                  <h3 className="text-base font-extrabold text-white tracking-tight">
                    {fake_website.site_name}
                  </h3>
                  <span className="text-xs text-amber-300/90 font-medium">
                    {fake_website.category}
                  </span>
                </div>
              </div>

              <a
                href={`https://${fake_website.domain}`}
                target="_blank"
                rel="noreferrer"
                className="flex items-center gap-1 px-2.5 py-1 rounded text-xs font-mono bg-border/40 hover:bg-border text-gray-300 hover:text-white transition-colors"
                title="Open domain in external tab"
              >
                <span>{fake_website.domain}</span>
                <ExternalLink className="w-3 h-3" />
              </a>
            </div>

            <p className="text-xs text-gray-300 leading-relaxed">
              {fake_website.description}
            </p>
          </div>

          {/* Connection Details Grid */}
          <div className="grid grid-cols-2 gap-2 text-xs font-mono">
            <div className="p-2.5 rounded-lg bg-background/60 border border-border/60">
              <div className="text-[10px] text-gray-400 font-sans uppercase">Destination IP</div>
              <div className="text-white font-bold truncate mt-0.5">
                {flow.destination_ip}:{flow.destination_port || 443}
              </div>
            </div>

            <div className="p-2.5 rounded-lg bg-background/60 border border-border/60">
              <div className="text-[10px] text-gray-400 font-sans uppercase">Source / Process</div>
              <div className="text-white font-bold truncate mt-0.5">
                {flow.process || 'Web Browser'} ({flow.protocol})
              </div>
            </div>
          </div>

          {/* Advisory Warning Callout */}
          <div className="flex items-start gap-2.5 p-3 rounded-lg bg-high/10 border border-high/30 text-high text-xs">
            <AlertTriangle className="w-4 h-4 flex-shrink-0 mt-0.5" />
            <div className="text-gray-200 leading-snug">
              <strong className="text-high font-semibold">Security Warning: </strong>
              {fake_website.warning}
            </div>
          </div>
        </div>

        {/* Modal Footer Actions */}
        <div className="p-4 bg-background/80 border-t border-border/80 flex items-center justify-between gap-2">
          <button
            onClick={handleSnooze}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-gray-400 hover:text-white hover:bg-border/60 transition-colors"
            title="Silence repeated popups for this website for 60 seconds"
          >
            <BellOff className="w-3.5 h-3.5" />
            <span>Snooze (60s)</span>
          </button>

          <div className="flex items-center gap-2">
            <button
              onClick={onClose}
              className="px-3.5 py-1.5 rounded-lg text-xs font-medium border border-border hover:bg-border/60 text-gray-300 hover:text-white transition-colors"
            >
              Dismiss
            </button>

            <button
              onClick={handleInspect}
              className="flex items-center gap-1.5 px-4 py-1.5 rounded-lg text-xs font-medium bg-amber-500 hover:bg-amber-600 text-black font-bold shadow-[0_0_15px_rgba(245,158,11,0.4)] transition-all"
            >
              <Eye className="w-3.5 h-3.5" />
              <span>Inspect Flow</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
