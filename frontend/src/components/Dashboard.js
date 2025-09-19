import React from 'react';
import { useAnomalies } from '../context/AnomalyContext';
import StatsCards from './dashboard/StatsCards';
import RecentAlerts from './dashboard/RecentAlerts';
import ThreatLevel from './dashboard/ThreatLevel';
import SystemHealth from './dashboard/SystemHealth';
import ActivityTimeline from './dashboard/ActivityTimeline';

const Dashboard = () => {
  const { stats, anomalies, loading } = useAnomalies();

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white">Security Dashboard</h1>
          <p className="text-slate-400 mt-1">Real-time threat monitoring and analysis</p>
        </div>
        <div className="text-right">
          <div className="text-sm text-slate-400">Last Updated</div>
          <div className="text-white font-medium">
            {new Date(stats.last_updated).toLocaleTimeString()}
          </div>
        </div>
      </div>

      {/* Stats Cards */}
      <StatsCards stats={stats} />

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column */}
        <div className="lg:col-span-2 space-y-6">
          {/* Threat Level */}
          <ThreatLevel stats={stats} />
          
          {/* Recent Alerts */}
          <RecentAlerts anomalies={anomalies.slice(0, 10)} />
        </div>

        {/* Right Column */}
        <div className="space-y-6">
          {/* System Health */}
          <SystemHealth stats={stats} />
          
          {/* Activity Timeline */}
          <ActivityTimeline anomalies={anomalies.slice(0, 5)} />
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
