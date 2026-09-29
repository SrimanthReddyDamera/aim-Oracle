import React, { useState } from 'react';
import { TopologyNode, TopologyEdge } from '../../types/oracle';
import { 
  Server, 
  Database, 
  Layers, 
  Globe, 
  Cloud, 
  CheckCircle2, 
  AlertTriangle, 
  XCircle, 
  ArrowRight,
  ExternalLink,
  GitCommit,
  Radio,
  Zap,
  Info,
  ShieldAlert
} from 'lucide-react';
import { JiraBadge, PRBadge, BlastRadiusBadge } from './Badges';

interface TopologyGraphProps {
  nodes?: TopologyNode[];
  edges?: TopologyEdge[];
  blastRadius?: string;
  jiraKey?: string;
  pullRequest?: string;
  upstreamCaller?: string;
  downstreamDependency?: string;
  title?: string;
  className?: string;
}

export function TopologyGraph({
  nodes = [],
  edges = [],
  blastRadius,
  jiraKey,
  pullRequest,
  upstreamCaller,
  downstreamDependency,
  title = 'Service Dependency & Failure Propagation Topology',
  className = '',
}: TopologyGraphProps) {
  const [selectedNode, setSelectedNode] = useState<TopologyNode | null>(
    nodes.find((n) => n.status === 'FAILED') || nodes.find((n) => n.status === 'DEGRADED') || nodes[0] || null
  );

  // Fallback default topology if none provided
  const activeNodes: TopologyNode[] = nodes.length > 0 ? nodes : [
    { id: 'gw', label: upstreamCaller || 'edge-ingress-envoy (AWS eu-west-1)', type: 'GATEWAY', status: 'HEALTHY' },
    { id: 'svc', label: 'payment-gateway (v2.14.2)', type: 'SERVICE', status: 'HEALTHY' },
    { id: 'cache', label: downstreamDependency || 'redis-cluster-shard-01 (v5.4)', type: 'CACHE', status: 'FAILED' },
    { id: 'db', label: 'aurora-pg-primary', type: 'DATABASE', status: 'HEALTHY' },
  ];

  const getNodeIcon = (type: TopologyNode['type']) => {
    switch (type) {
      case 'GATEWAY':
        return <Globe size={18} className="text-sky-600 dark:text-sky-400" />;
      case 'SERVICE':
        return <Server size={18} className="text-indigo-600 dark:text-indigo-400" />;
      case 'CACHE':
        return <Zap size={18} className="text-amber-600 dark:text-amber-400" />;
      case 'DATABASE':
        return <Database size={18} className="text-emerald-600 dark:text-emerald-400" />;
      case 'THIRD_PARTY':
        return <Cloud size={18} className="text-purple-600 dark:text-purple-400" />;
    }
  };

  const getNodeStatusBadge = (status: TopologyNode['status']) => {
    switch (status) {
      case 'HEALTHY':
        return (
          <span className="inline-flex items-center gap-1 text-[10px] font-medium px-2 py-0.5 rounded-full bg-emerald-50 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800/60">
            <CheckCircle2 size={10} /> HEALTHY
          </span>
        );
      case 'DEGRADED':
        return (
          <span className="inline-flex items-center gap-1 text-[10px] font-medium px-2 py-0.5 rounded-full bg-amber-50 dark:bg-amber-950/40 text-amber-700 dark:text-amber-300 border border-amber-200 dark:border-amber-800/60">
            <AlertTriangle size={10} /> DEGRADED
          </span>
        );
      case 'FAILED':
        return (
          <span className="inline-flex items-center gap-1 text-[10px] font-medium px-2 py-0.5 rounded-full bg-rose-50 dark:bg-rose-950/40 text-rose-700 dark:text-rose-300 border border-rose-200 dark:border-rose-900/60">
            <XCircle size={10} className="animate-pulse" /> FAILED
          </span>
        );
    }
  };

  const getNodeBorder = (status: TopologyNode['status'], isSelected: boolean) => {
    if (isSelected) {
      return 'ring-2 ring-indigo-500 border-indigo-500 dark:border-indigo-400 shadow-md';
    }
    switch (status) {
      case 'FAILED':
        return 'border-rose-300 dark:border-rose-800 bg-rose-50/40 dark:bg-rose-950/20 hover:border-rose-400';
      case 'DEGRADED':
        return 'border-amber-300 dark:border-amber-800 bg-amber-50/40 dark:bg-amber-950/20 hover:border-amber-400';
      default:
        return 'border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 hover:border-slate-300 dark:hover:border-slate-700';
    }
  };

  return (
    <div className={`border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 rounded-xl overflow-hidden shadow-2xs ${className}`}>
      {/* Header with Title and Enterprise Incident Linkages */}
      <div className="p-4 border-b border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-800/40 flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <Radio size={14} className="text-indigo-600 dark:text-indigo-400 animate-pulse" />
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-900 dark:text-white">
              {title}
            </h3>
          </div>
          <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">
            Real-time causal graph mapping inbound request path, degraded microservices, and downstream fault origins.
          </p>
        </div>

        {/* Action pills: Jira & PR */}
        <div className="flex flex-wrap items-center gap-2 shrink-0">
          {jiraKey && <JiraBadge ticket={jiraKey} />}
          {pullRequest && <PRBadge pr={pullRequest} />}
        </div>
      </div>

      {/* Blast Radius Alert Banner */}
      {blastRadius && (
        <div className="px-4 py-2.5 bg-rose-50/70 dark:bg-rose-950/30 border-b border-rose-200/60 dark:border-rose-900/40 flex flex-wrap items-center justify-between gap-2 text-xs">
          <div className="flex items-center gap-2 text-rose-800 dark:text-rose-200">
            <ShieldAlert size={14} className="text-rose-600 dark:text-rose-400 shrink-0" />
            <span className="font-semibold">Blast Radius:</span>
            <span className="font-medium text-rose-700 dark:text-rose-300">{blastRadius}</span>
          </div>
          <div className="flex items-center gap-3 text-[11px] text-rose-600 dark:text-rose-400">
            {upstreamCaller && (
              <span>Caller: <strong className="font-mono text-rose-700 dark:text-rose-300">{upstreamCaller}</strong></span>
            )}
            {downstreamDependency && (
              <span>Target: <strong className="font-mono text-rose-700 dark:text-rose-300">{downstreamDependency}</strong></span>
            )}
          </div>
        </div>
      )}

      {/* Topology Canvas */}
      <div className="p-6 bg-slate-50/50 dark:bg-slate-950/50">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 relative">
          {activeNodes.map((node, index) => {
            const isSelected = selectedNode?.id === node.id;
            return (
              <div key={node.id} className="relative group">
                <div
                  onClick={() => setSelectedNode(node)}
                  className={`p-4 rounded-xl border transition-all cursor-pointer ${getNodeBorder(node.status, isSelected)}`}
                >
                  <div className="flex items-center justify-between mb-3">
                    <div className="p-2 rounded-lg bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700">
                      {getNodeIcon(node.type)}
                    </div>
                    {getNodeStatusBadge(node.status)}
                  </div>

                  <div className="space-y-1">
                    <div className="text-[10px] uppercase font-mono tracking-wider font-semibold text-slate-400 dark:text-slate-500">
                      {node.type}
                    </div>
                    <div className="text-xs font-bold text-slate-900 dark:text-white truncate font-mono" title={node.label}>
                      {node.label}
                    </div>
                  </div>

                  <div className="mt-3 pt-2.5 border-t border-slate-100 dark:border-slate-800 flex items-center justify-between text-[10px] text-slate-400">
                    <span>Node #{index + 1}</span>
                    <span className="group-hover:text-indigo-600 dark:group-hover:text-indigo-400 transition-colors font-medium">
                      Inspect Telemetry →
                    </span>
                  </div>
                </div>

                {/* Flow Connector Arrow between adjacent nodes (desktop) */}
                {index < activeNodes.length - 1 && (
                  <div className="hidden lg:flex absolute -right-3 top-1/2 -translate-y-1/2 z-10 w-6 h-6 items-center justify-center rounded-full bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 shadow-2xs text-slate-400">
                    <ArrowRight size={11} />
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {/* Selected Node Telemetry Drawer */}
        {selectedNode && (
          <div className="mt-5 p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-xs">
            <div className="flex flex-col sm:flex-row justify-between sm:items-center gap-2 pb-3 border-b border-slate-100 dark:border-slate-800">
              <div className="flex items-center gap-2">
                <span className="p-1.5 rounded-md bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700">
                  {getNodeIcon(selectedNode.type)}
                </span>
                <div>
                  <h4 className="text-xs font-bold font-mono text-slate-900 dark:text-white">
                    {selectedNode.label}
                  </h4>
                  <span className="text-[10px] text-slate-400 uppercase font-mono">
                    Architecture Role: {selectedNode.type}
                  </span>
                </div>
              </div>
              <div className="flex items-center gap-2">
                {getNodeStatusBadge(selectedNode.status)}
              </div>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-3 text-xs">
              <div>
                <span className="text-[10px] font-medium text-slate-400 block">Health Verdict</span>
                <span className={`font-semibold font-mono ${
                  selectedNode.status === 'FAILED' 
                    ? 'text-rose-600 dark:text-rose-400' 
                    : selectedNode.status === 'DEGRADED' 
                    ? 'text-amber-600 dark:text-amber-400' 
                    : 'text-emerald-600 dark:text-emerald-400'
                }`}>
                  {selectedNode.status === 'FAILED' ? 'CRITICAL_FAULT' : selectedNode.status === 'DEGRADED' ? 'LATENCY_SPIKE' : 'ONLINE_HEALTHY'}
                </span>
              </div>
              <div>
                <span className="text-[10px] font-medium text-slate-400 block">Protocol / Port</span>
                <span className="font-mono text-slate-700 dark:text-slate-300">
                  {selectedNode.type === 'GATEWAY' ? 'HTTPS :443 (HTTP/2)' : selectedNode.type === 'CACHE' ? 'mTLS 1.3 :6379' : selectedNode.type === 'DATABASE' ? 'TCP :5432 (TLS)' : 'gRPC :8080'}
                </span>
              </div>
              <div>
                <span className="text-[10px] font-medium text-slate-400 block">Observed Latency</span>
                <span className="font-mono text-slate-700 dark:text-slate-300">
                  {selectedNode.status === 'FAILED' ? '5,000ms (TIMEOUT)' : selectedNode.status === 'DEGRADED' ? '4,820ms' : '1.2ms'}
                </span>
              </div>
              <div>
                <span className="text-[10px] font-medium text-slate-400 block">Causal Fault Attribution</span>
                <span className="font-medium text-slate-700 dark:text-slate-300 truncate block">
                  {selectedNode.status === 'FAILED' ? 'Primary Root Cause Origin' : selectedNode.status === 'DEGRADED' ? 'Upstream Cascading Contention' : 'Unaffected Dependency'}
                </span>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
