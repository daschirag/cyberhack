import React, { useState, useEffect } from 'react';
import { useAnomalies } from '../context/AnomalyContext';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, LineChart, Line } from 'recharts';
import { ChartData, TimeSeriesData } from '../types';

const Analytics: React.FC = () => {
  const { getAnomalyTypes, getSeverityBreakdown, anomalies } = useAnomalies();
  const [anomalyTypes, setAnomalyTypes] = useState<Record<string, number>>({});
  const [severityBreakdown, setSeverityBreakdown] = useState<Record<string, number>>({});
  const [timeSeriesData, setTimeSeriesData] = useState<TimeSeriesData[]>([]);

  useEffect(() => {
    const fetchData = async (): Promise<void> => {
      const [types, severity] = await Promise.all([
        getAnomalyTypes(),
        getSeverityBreakdown()
      ]);
      setAnomalyTypes(types);
      setSeverityBreakdown(severity);
    };

    fetchData();
  }, [getAnomalyTypes, getSeverityBreakdown]);

  useEffect(() => {
    // Generate time series data from anomalies
    const hourlyData: Record<number, number> = {};
    anomalies.forEach(anomaly => {
      const hour = new Date(anomaly.timestamp).getHours();
      hourlyData[hour] = (hourlyData[hour] || 0) + 1;
    });

    const timeData: TimeSeriesData[] = Array.from({ length: 24 }, (_, i) => ({
      hour: `${i}:00`,
      count: hourlyData[i] || 0
    }));

    setTimeSeriesData(timeData);
  }, [anomalies]);

  const COLORS = ['#ef4444', '#f97316', '#eab308', '#22c55e', '#3b82f6'];

  const anomalyTypeData: ChartData[] = Object.entries(anomalyTypes).map(([type, count]) => ({
    name: type.replace('_', ' ').toUpperCase(),
    value: count
  }));

  const severityData: ChartData[] = Object.entries(severityBreakdown).map(([severity, count]) => ({
    name: severity,
    value: count
  }));

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-white">Analytics</h1>
        <p className="text-slate-400 mt-1">Security insights and threat analysis</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Anomaly Types Chart */}
        <div className="bg-slate-800 rounded-lg border border-slate-700 p-6">
          <h2 className="text-xl font-semibold text-white mb-4">Anomaly Types</h2>
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={anomalyTypeData}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                outerRadius={80}
                fill="#8884d8"
                dataKey="value"
              >
                {anomalyTypeData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* Severity Breakdown */}
        <div className="bg-slate-800 rounded-lg border border-slate-700 p-6">
          <h2 className="text-xl font-semibold text-white mb-4">Severity Distribution</h2>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={severityData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
              <XAxis dataKey="name" stroke="#9ca3af" />
              <YAxis stroke="#9ca3af" />
              <Tooltip 
                contentStyle={{ 
                  backgroundColor: '#1e293b', 
                  border: '1px solid #374151',
                  borderRadius: '8px',
                  color: '#f8fafc'
                }}
              />
              <Bar dataKey="value" fill="#3b82f6" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Time Series Chart */}
      <div className="bg-slate-800 rounded-lg border border-slate-700 p-6">
        <h2 className="text-xl font-semibold text-white mb-4">Anomalies by Hour</h2>
        <ResponsiveContainer width="100%" height={400}>
          <LineChart data={timeSeriesData}>
            <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
            <XAxis dataKey="hour" stroke="#9ca3af" />
            <YAxis stroke="#9ca3af" />
            <Tooltip 
              contentStyle={{ 
                backgroundColor: '#1e293b', 
                border: '1px solid #374151',
                borderRadius: '8px',
                color: '#f8fafc'
              }}
            />
            <Line 
              type="monotone" 
              dataKey="count" 
              stroke="#ef4444" 
              strokeWidth={2}
              dot={{ fill: '#ef4444', strokeWidth: 2, r: 4 }}
            />
          </LineChart>
        </ResponsiveContainer>
      </div>

      {/* Summary Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="bg-slate-800 rounded-lg border border-slate-700 p-6">
          <h3 className="text-lg font-semibold text-white mb-2">Total Anomalies</h3>
          <p className="text-3xl font-bold text-red-400">{anomalies.length}</p>
          <p className="text-sm text-slate-400 mt-1">All time</p>
        </div>
        
        <div className="bg-slate-800 rounded-lg border border-slate-700 p-6">
          <h3 className="text-lg font-semibold text-white mb-2">Critical Alerts</h3>
          <p className="text-3xl font-bold text-red-500">{severityBreakdown.CRITICAL || 0}</p>
          <p className="text-sm text-slate-400 mt-1">Require immediate attention</p>
        </div>
        
        <div className="bg-slate-800 rounded-lg border border-slate-700 p-6">
          <h3 className="text-lg font-semibold text-white mb-2">Detection Rate</h3>
          <p className="text-3xl font-bold text-green-400">99.8%</p>
          <p className="text-sm text-slate-400 mt-1">Accuracy</p>
        </div>
      </div>
    </div>
  );
};

export default Analytics;
