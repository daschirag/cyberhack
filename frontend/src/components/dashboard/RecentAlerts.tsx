import React, { useState } from 'react';
import { format, formatDistanceToNow } from 'date-fns';
import { AlertTriangle, Shield, FileText, Network, Clock, Eye, MoreHorizontal } from 'lucide-react';

interface Anomaly {
  id: string;
  type: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  explanation: string;
  risk_score: number;
  timestamp: string;
  status?: 'new' | 'investigating' | 'resolved';
  source_ip?: string;
  user_agent?: string;
}

interface RecentAlertsProps {
  anomalies: Anomaly[];
  onViewAll?: () => void;
  onAlertClick?: (anomaly: Anomaly) => void;
}

const RecentAlerts: React.FC<RecentAlertsProps> = ({ anomalies, onViewAll, onAlertClick }) => {
  const [expandedAlert, setExpandedAlert] = useState<string | null>(null);
  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'CRITICAL':
        return 'text-red-400 bg-red-500/10 border-red-500/20 animate-pulse';
      case 'HIGH':
        return 'text-orange-400 bg-orange-500/10 border-orange-500/20';
      case 'MEDIUM':
        return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20';
      case 'LOW':
        return 'text-blue-400 bg-blue-500/10 border-blue-500/20';
      default:
        return 'text-gray-400 bg-gray-500/10 border-gray-500/20';
    }
  };

  const getStatusColor = (status?: string) => {
    switch (status) {
      case 'new':
        return 'bg-green-500';
      case 'investigating':
        return 'bg-yellow-500';
      case 'resolved':
        return 'bg-gray-500';
      default:
        return 'bg-blue-500';
    }
  };

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'login':
        return <Shield size={16} className="text-blue-400" />;
      case 'network':
        return <Network size={16} className="text-green-400" />;
      case 'file_transfer':
        return <FileText size={16} className="text-purple-400" />;
      case 'malware':
        return <AlertTriangle size={16} className="text-red-400" />;
      case 'ddos':
        return <Network size={16} className="text-orange-400" />;
      default:
        return <AlertTriangle size={16} className="text-gray-400" />;
    }
  };

  const getTypeLabel = (type: string) => {
    switch (type) {
      case 'login':
        return 'Login Anomaly';
      case 'network':
        return 'Network Threat';
      case 'file_transfer':
        return 'File Transfer';
      case 'malware':
        return 'Malware Detection';
      case 'ddos':
        return 'DDoS Attack';
      default:
        return 'Security Alert';
    }
  };

  const toggleExpanded = (alertId: string) => {
    setExpandedAlert(expandedAlert === alertId ? null : alertId);
  };

  const handleAlertClick = (anomaly: Anomaly) => {
    if (onAlertClick) {
      onAlertClick(anomaly);
    } else {
      toggleExpanded(anomaly.id);
    }
  };

  return (
    <div className="bg-slate-800 rounded-lg border border-slate-700 overflow-hidden">
      <div className="p-6 border-b border-slate-700">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-xl font-semibold text-white">Recent Alerts</h2>
            <p className="text-slate-400 text-sm mt-1">Latest security anomalies detected</p>
          </div>
          <div className="flex items-center space-x-2">
            <div className="flex items-center space-x-1 text-xs text-slate-400">
              <Clock size={12} />
              <span>Live</span>
            </div>
            <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
          </div>
        </div>
      </div>
      
      <div className="max-h-96 overflow-y-auto">
        {anomalies.length === 0 ? (
          <div className="p-8 text-center text-slate-400">
            <Shield size={48} className="mx-auto mb-4 text-slate-600" />
            <p className="font-medium">No recent alerts</p>
            <p className="text-sm mt-1">System is operating normally</p>
          </div>
        ) : (
          <div className="divide-y divide-slate-700/50">
            {anomalies.slice(0, 10).map((anomaly) => (
              <div 
                key={anomaly.id} 
                className="p-4 hover:bg-slate-700/30 transition-all duration-200 cursor-pointer group"
                onClick={() => handleAlertClick(anomaly)}
              >
                <div className="flex items-start justify-between">
                  <div className="flex items-start space-x-3 flex-1">
                    <div className="flex-shrink-0 mt-1 relative">
                      {getTypeIcon(anomaly.type)}
                      {anomaly.status && (
                        <div className={`absolute -top-1 -right-1 w-2 h-2 rounded-full ${getStatusColor(anomaly.status)}`}></div>
                      )}
                    </div>
                    
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center space-x-2 mb-1">
                        <span className="text-sm font-medium text-white group-hover:text-blue-300 transition-colors">
                          {getTypeLabel(anomaly.type)}
                        </span>
                        <span className={`px-2 py-1 text-xs font-medium rounded-full border ${getSeverityColor(anomaly.severity)}`}>
                          {anomaly.severity}
                        </span>
                      </div>
                      
                      <p className="text-sm text-slate-300 mb-2 line-clamp-2">
                        {anomaly.explanation || 'Security anomaly detected'}
                      </p>
                      
                      <div className="flex items-center space-x-4 text-xs text-slate-400">
                        <span className="flex items-center space-x-1">
                          <span>Risk:</span>
                          <span className={`font-medium ${anomaly.risk_score > 0.7 ? 'text-red-400' : anomaly.risk_score > 0.4 ? 'text-yellow-400' : 'text-green-400'}`}>
                            {Math.round(anomaly.risk_score * 100)}%
                          </span>
                        </span>
                        <span>•</span>
                        <span className="flex items-center space-x-1">
                          <Clock size={10} />
                          <span>{formatDistanceToNow(new Date(anomaly.timestamp), { addSuffix: true })}</span>
                        </span>
                      </div>

                      {/* Expanded details */}
                      {expandedAlert === anomaly.id && (
                        <div className="mt-3 pt-3 border-t border-slate-700/50 space-y-3">
                          <div className="bg-slate-700/30 rounded-lg p-3">
                            <div className="text-xs font-medium text-slate-300 mb-2">Full Explanation:</div>
                            <p className="text-sm text-slate-200 leading-relaxed">
                              {anomaly.explanation || 'No detailed explanation available for this security anomaly.'}
                            </p>
                          </div>
                          
                          <div className="grid grid-cols-1 gap-2">
                            {anomaly.source_ip && (
                              <div className="text-xs text-slate-400">
                                <span className="font-medium">Source IP:</span> {anomaly.source_ip}
                              </div>
                            )}
                            {anomaly.user_agent && (
                              <div className="text-xs text-slate-400">
                                <span className="font-medium">User Agent:</span> {anomaly.user_agent}
                              </div>
                            )}
                            <div className="text-xs text-slate-400">
                              <span className="font-medium">Timestamp:</span> {format(new Date(anomaly.timestamp), 'PPpp')}
                            </div>
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                  
                  <div className="flex items-center space-x-2 flex-shrink-0">
                    <div className="flex flex-col items-end space-y-1">
                      <div className={`w-3 h-3 rounded-full ${anomaly.severity === 'CRITICAL' ? 'bg-red-500 animate-pulse' : anomaly.severity === 'HIGH' ? 'bg-orange-500' : anomaly.severity === 'MEDIUM' ? 'bg-yellow-500' : 'bg-blue-500'}`}></div>
                      <MoreHorizontal size={12} className="text-slate-500 opacity-0 group-hover:opacity-100 transition-opacity" />
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
      
      {anomalies.length > 0 && (
        <div className="p-4 border-t border-slate-700 bg-slate-800/50">
          <button 
            onClick={onViewAll}
            className="w-full text-sm text-blue-400 hover:text-blue-300 transition-colors flex items-center justify-center space-x-2"
          >
            <Eye size={14} />
            <span>View All Alerts ({anomalies.length})</span>
          </button>
        </div>
      )}
    </div>
  );
};

export default RecentAlerts;
