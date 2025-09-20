import React from 'react';
import { AlertTriangle, Shield, Activity, Clock, LucideIcon } from 'lucide-react';
import { StatsCardsProps } from '../../types';

interface StatCard {
  title: string;
  value: string | number;
  icon: LucideIcon;
  color: string;
  bgColor: string;
  borderColor: string;
}

const StatsCards: React.FC<StatsCardsProps> = ({ stats }) => {
  const cards: StatCard[] = [
    {
      title: 'Total Anomalies',
      value: stats.total_anomalies,
      icon: AlertTriangle,
      color: 'text-red-400',
      bgColor: 'bg-red-500/10',
      borderColor: 'border-red-500/20',
    },
    {
      title: 'Critical Alerts',
      value: stats.critical_count,
      icon: Shield,
      color: 'text-red-500',
      bgColor: 'bg-red-500/10',
      borderColor: 'border-red-500/20',
    },
    {
      title: 'High Priority',
      value: stats.high_count,
      icon: Activity,
      color: 'text-orange-400',
      bgColor: 'bg-orange-500/10',
      borderColor: 'border-orange-500/20',
    },
    {
      title: 'System Uptime',
      value: stats.system_uptime,
      icon: Clock,
      color: 'text-green-400',
      bgColor: 'bg-green-500/10',
      borderColor: 'border-green-500/20',
    },
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
      {cards.map((card, index) => {
        const Icon = card.icon;
        return (
          <div
            key={index}
            className={`${card.bgColor} ${card.borderColor} border rounded-lg p-6 hover:scale-105 transition-transform duration-200`}
          >
            <div className="flex items-center justify-between">
              <div>
                <p className="text-slate-400 text-sm font-medium">{card.title}</p>
                <p className="text-2xl font-bold text-white mt-2">{card.value}</p>
              </div>
              <div className={`${card.color} ${card.bgColor} p-3 rounded-lg`}>
                <Icon size={24} />
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
};

export default StatsCards;
