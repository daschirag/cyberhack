import React from 'react';
import { format } from 'date-fns';
import { AlertTriangle, Shield, FileText, Network } from 'lucide-react';

const ActivityTimeline = ({ anomalies }) => {
  const getTypeIcon = (type) => {
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

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'CRITICAL':
        return 'bg-red-500';
      case 'HIGH':
        return 'bg-orange-500';
      case 'MEDIUM':
        return 'bg-yellow-500';
      default:
        return 'bg-blue-500';
    }
  };

  return (
    <div className="bg-slate-800 rounded-lg border border-slate-700 p-6">
      <h2 className="text-xl font-semibold text-white mb-6">Activity Timeline</h2>
      
      <div className="space-y-4">
        {anomalies.length === 0 ? (
          <div className="text-center text-slate-400 py-8">
            <Shield size={32} className="mx-auto mb-2 text-slate-600" />
            <p className="text-sm">No recent activity</p>
          </div>
        ) : (
          anomalies.map((anomaly, index) => (
            <div key={index} className="flex items-start space-x-3">
              <div className="flex-shrink-0">
                <div className={`w-3 h-3 rounded-full ${getSeverityColor(anomaly.severity)}`}></div>
                {index < anomalies.length - 1 && (
                  <div className="w-px h-8 bg-slate-600 ml-1.5 mt-1"></div>
                )}
              </div>
              
              <div className="flex-1 min-w-0">
                <div className="flex items-center space-x-2 mb-1">
                  {getTypeIcon(anomaly.type)}
                  <span className="text-sm font-medium text-white">
                    {anomaly.type.replace('_', ' ').toUpperCase()}
                  </span>
                  <span className="text-xs text-slate-400">
                    {format(new Date(anomaly.timestamp), 'HH:mm')}
                  </span>
                </div>
                
                <p className="text-xs text-slate-300 truncate">
                  {anomaly.explanation || 'Security event detected'}
                </p>
                
                <div className="flex items-center space-x-2 mt-1">
                  <span className="text-xs text-slate-400">
                    Risk: {Math.round(anomaly.risk_score * 100)}%
                  </span>
                  <span className="text-xs text-slate-500">•</span>
                  <span className="text-xs text-slate-400">
                    {anomaly.severity}
                  </span>
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};

export default ActivityTimeline;
