import React from 'react';
import { Activity, Cpu, HardDrive, Wifi, LucideIcon } from 'lucide-react';
import { SystemHealthProps } from '../../types';

interface HealthMetric {
  name: string;
  value: string;
  status: 'good' | 'warning' | 'critical';
  icon: LucideIcon;
  color: string;
}

const SystemHealth: React.FC<SystemHealthProps> = ({ stats }) => {
  const healthMetrics: HealthMetric[] = [
    {
      name: 'CPU Usage',
      value: '23%',
      status: 'good',
      icon: Cpu,
      color: 'text-green-400',
    },
    {
      name: 'Memory',
      value: '67%',
      status: 'warning',
      icon: HardDrive,
      color: 'text-yellow-400',
    },
    {
      name: 'Network',
      value: '45%',
      status: 'good',
      icon: Wifi,
      color: 'text-green-400',
    },
    {
      name: 'Processing',
      value: '89%',
      status: 'good',
      icon: Activity,
      color: 'text-green-400',
    },
  ];

  const getStatusColor = (status: string): string => {
    switch (status) {
      case 'good':
        return 'bg-green-500';
      case 'warning':
        return 'bg-yellow-500';
      case 'critical':
        return 'bg-red-500';
      default:
        return 'bg-gray-500';
    }
  };

  return (
    <div className="bg-slate-800 rounded-lg border border-slate-700 p-6">
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-xl font-semibold text-white">System Health</h2>
        <div className="flex items-center space-x-1">
          <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
          <span className="text-sm text-green-400">Healthy</span>
        </div>
      </div>

      <div className="space-y-4">
        {healthMetrics.map((metric, index) => {
          const Icon = metric.icon;
          return (
            <div key={index} className="flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <Icon size={20} className={metric.color} />
                <span className="text-sm text-slate-300">{metric.name}</span>
              </div>
              
              <div className="flex items-center space-x-3">
                <div className="w-16 bg-slate-700 rounded-full h-2">
                  <div 
                    className={`h-2 rounded-full ${getStatusColor(metric.status)}`}
                    style={{ 
                      width: metric.value.replace('%', '') + '%' 
                    }}
                  ></div>
                </div>
                <span className="text-sm font-medium text-white w-10 text-right">
                  {metric.value}
                </span>
              </div>
            </div>
          );
        })}
      </div>

      <div className="mt-6 pt-4 border-t border-slate-700">
        <div className="flex items-center justify-between text-sm">
          <span className="text-slate-400">Overall Status</span>
          <span className="text-green-400 font-medium">Optimal</span>
        </div>
      </div>
    </div>
  );
};

export default SystemHealth;
