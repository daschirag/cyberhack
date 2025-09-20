import React from 'react';
import { format } from 'date-fns';
import { AlertTriangle, Shield, FileText, Network } from 'lucide-react';
import { RecentAlertsProps, Anomaly } from '../../types';

const RecentAlerts: React.FC<RecentAlertsProps> = ({ anomalies }) => {
  const getSeverityColor = (severity: string): string => {
    switch (severity) {
      case 'CRITICAL':
        return 'text-red-400 bg-red-500/10 border-red-500/20';
      case 'HIGH':
        return 'text-orange-400 bg-orange-500/10 border-orange-500/20';
      case 'MEDIUM':
        return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20';
      default:
        return 'text-blue-400 bg-blue-500/10 border-blue-500/20';
    }
  };

  const getTypeIcon = (type: string): React.ReactElement => {
    switch (type) {
      case 'login':
        return <Shield size={16} className="text-blue-400" />;
      case 'network':
        return <Network size={16} className="text-green-400" />;
      case 'file_transfer':
        return <FileText size={16} className="text-purple-400" />;
      default:
        return <AlertTriangle size={16} className="text-gray-400" />;
    }
  };

  const getTypeLabel = (type: string): string => {
    switch (type) {
      case 'login':
        return 'Login Anomaly';
      case 'network':
        return 'Network Threat';
      case 'file_transfer':
        return 'File Transfer';
      default:
        return 'Unknown';
    }
  };

  return (
    <div className="bg-slate-800 rounded-lg border border-slate-700">
      <div className="p-6 border-b border-slate-700">
        <h2 className="text-xl font-semibold text-white">Recent Alerts</h2>
        <p className="text-slate-400 text-sm mt-1">Latest security anomalies detected</p>
      </div>
      
      <div className="divide-y divide-slate-700">
        {anomalies.length === 0 ? (
          <div className="p-6 text-center text-slate-400">
            <Shield size={48} className="mx-auto mb-4 text-slate-600" />
            <p>No recent alerts</p>
            <p className="text-sm">System is operating normally</p>
          </div>
        ) : (
          anomalies.map((anomaly: Anomaly, index: number) => (
            <div key={index} className="p-4 hover:bg-slate-700/50 transition-colors">
              <div className="flex items-start justify-between">
                <div className="flex items-start space-x-3">
                  <div className="flex-shrink-0 mt-1">
                    {getTypeIcon(anomaly.type)}
                  </div>
                  
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center space-x-2 mb-1">
                      <span className="text-sm font-medium text-white">
                        {getTypeLabel(anomaly.type)}
                      </span>
                      <span className={`px-2 py-1 text-xs font-medium rounded-full border ${getSeverityColor(anomaly.severity)}`}>
                        {anomaly.severity}
                      </span>
                    </div>
                    
                    <p className="text-sm text-slate-300 mb-2">
                      {anomaly.explanation || 'Security anomaly detected'}
                    </p>
                    
                    <div className="flex items-center space-x-4 text-xs text-slate-400">
                      <span>Risk: {Math.round(anomaly.risk_score * 100)}%</span>
                      <span>•</span>
                      <span>
                        {format(new Date(anomaly.timestamp), 'MMM dd, HH:mm')}
                      </span>
                    </div>
                  </div>
                </div>
                
                <div className="flex-shrink-0">
                  <div className="w-3 h-3 bg-red-500 rounded-full animate-pulse"></div>
                </div>
              </div>
            </div>
          ))
        )}
      </div>
      
      {anomalies.length > 0 && (
        <div className="p-4 border-t border-slate-700">
          <button className="w-full text-sm text-blue-400 hover:text-blue-300 transition-colors">
            View All Alerts →
          </button>
        </div>
      )}
    </div>
  );
};

export default RecentAlerts;
