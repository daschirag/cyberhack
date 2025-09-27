import React, { useState } from 'react';
import { useAnomalies } from '../context/AnomalyContext';
import { format } from 'date-fns';
import { AlertTriangle, Shield, FileText, Network, Filter, Search } from 'lucide-react';

const Alerts = () => {
  const { anomalies, handleAlertAction } = useAnomalies();
  const [filter, setFilter] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');

  const filteredAnomalies = anomalies.filter(anomaly => {
    const matchesFilter = filter === 'all' || anomaly.severity === filter.toUpperCase();
    const matchesSearch = anomaly.explanation?.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         anomaly.type?.toLowerCase().includes(searchTerm.toLowerCase());
    return matchesFilter && matchesSearch;
  });

  const getSeverityColor = (severity) => {
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

  const getTypeIcon = (type) => {
    switch (type) {
      case 'login':
        return <Shield size={20} className="text-blue-400" />;
      case 'network':
        return <Network size={20} className="text-green-400" />;
      case 'file_transfer':
        return <FileText size={20} className="text-purple-400" />;
      default:
        return <AlertTriangle size={20} className="text-gray-400" />;
    }
  };

  const handleAction = async (anomalyId, action) => {
    await handleAlertAction(anomalyId, action);
  };

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white">Security Alerts</h1>
          <p className="text-slate-400 mt-1">Monitor and manage security threats</p>
        </div>
        <div className="text-sm text-slate-400">
          {filteredAnomalies.length} of {anomalies.length} alerts
        </div>
      </div>

      {/* Filters and Search */}
      <div className="flex flex-col sm:flex-row gap-4">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-slate-400" size={20} />
          <input
            type="text"
            placeholder="Search alerts..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-10 pr-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
        
        <div className="flex items-center space-x-2">
          <Filter className="text-slate-400" size={20} />
          <select
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            className="px-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
      </div>

      {/* Alerts List */}
      <div className="space-y-4">
        {filteredAnomalies.length === 0 ? (
          <div className="text-center py-12">
            <Shield size={64} className="mx-auto mb-4 text-slate-600" />
            <h3 className="text-xl font-semibold text-slate-300 mb-2">No alerts found</h3>
            <p className="text-slate-400">No security alerts match your current filters.</p>
          </div>
        ) : (
          filteredAnomalies.map((anomaly, index) => (
            <div key={index} className="bg-slate-800 rounded-lg border border-slate-700 p-6 hover:border-slate-600 transition-colors">
              <div className="flex items-start justify-between">
                <div className="flex items-start space-x-4">
                  <div className="flex-shrink-0">
                    {getTypeIcon(anomaly.type)}
                  </div>
                  
                  <div className="flex-1">
                    <div className="flex items-center space-x-3 mb-2">
                      <h3 className="text-lg font-semibold text-white">
                        {anomaly.type?.replace('_', ' ').toUpperCase() || 'Unknown'}
                      </h3>
                      <span className={`px-3 py-1 text-sm font-medium rounded-full border ${getSeverityColor(anomaly.severity)}`}>
                        {anomaly.severity}
                      </span>
                    </div>
                    
                    <p className="text-slate-300 mb-3">
                      {anomaly.explanation || 'Security anomaly detected'}
                    </p>
                    
                    <div className="flex items-center space-x-6 text-sm text-slate-400">
                      <span>Risk Score: {Math.round(anomaly.risk_score * 100)}%</span>
                      <span>•</span>
                      <span>{format(new Date(anomaly.timestamp), 'MMM dd, yyyy HH:mm:ss')}</span>
                    </div>
                  </div>
                </div>
                
                <div className="flex items-center space-x-2">
                  <button
                    onClick={() => handleAction(anomaly.timestamp, 'acknowledge')}
                    className="px-3 py-1 text-xs bg-blue-600 text-white rounded hover:bg-blue-700 transition-colors"
                  >
                    Acknowledge
                  </button>
                  <button
                    onClick={() => handleAction(anomaly.timestamp, 'investigate')}
                    className="px-3 py-1 text-xs bg-orange-600 text-white rounded hover:bg-orange-700 transition-colors"
                  >
                    Investigate
                  </button>
                  <button
                    onClick={() => handleAction(anomaly.timestamp, 'resolve')}
                    className="px-3 py-1 text-xs bg-green-600 text-white rounded hover:bg-green-700 transition-colors"
                  >
                    Resolve
                  </button>
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};

export default Alerts;
