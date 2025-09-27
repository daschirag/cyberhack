import React from 'react';
import { AlertTriangle, Shield, CheckCircle } from 'lucide-react';

const ThreatLevel = ({ stats }) => {
  const getThreatLevel = () => {
    const critical = stats.critical_count;
    const high = stats.high_count;
    
    if (critical > 0) return { level: 'CRITICAL', color: 'text-red-500', bgColor: 'bg-red-500/10' };
    if (high > 2) return { level: 'HIGH', color: 'text-orange-500', bgColor: 'bg-orange-500/10' };
    if (high > 0) return { level: 'MEDIUM', color: 'text-yellow-500', bgColor: 'bg-yellow-500/10' };
    return { level: 'LOW', color: 'text-green-500', bgColor: 'bg-green-500/10' };
  };

  const threat = getThreatLevel();

  const getIcon = () => {
    switch (threat.level) {
      case 'CRITICAL':
        return <AlertTriangle className="text-red-500" size={32} />;
      case 'HIGH':
        return <AlertTriangle className="text-orange-500" size={32} />;
      case 'MEDIUM':
        return <Shield className="text-yellow-500" size={32} />;
      default:
        return <CheckCircle className="text-green-500" size={32} />;
    }
  };

  return (
    <div className="bg-slate-800 rounded-lg p-6 border border-slate-700">
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-xl font-semibold text-white">Threat Level</h2>
        <div className={`${threat.color} ${threat.bgColor} px-3 py-1 rounded-full text-sm font-medium`}>
          {threat.level}
        </div>
      </div>

      <div className="flex items-center space-x-6">
        <div className="flex-shrink-0">
          {getIcon()}
        </div>
        
        <div className="flex-1">
          <div className="mb-4">
            <div className="flex justify-between text-sm text-slate-400 mb-2">
              <span>Security Status</span>
              <span>{threat.level}</span>
            </div>
            <div className="w-full bg-slate-700 rounded-full h-2">
              <div 
                className={`h-2 rounded-full transition-all duration-500 ${
                  threat.level === 'CRITICAL' ? 'bg-red-500' :
                  threat.level === 'HIGH' ? 'bg-orange-500' :
                  threat.level === 'MEDIUM' ? 'bg-yellow-500' : 'bg-green-500'
                }`}
                style={{
                  width: threat.level === 'CRITICAL' ? '100%' :
                         threat.level === 'HIGH' ? '75%' :
                         threat.level === 'MEDIUM' ? '50%' : '25%'
                }}
              ></div>
            </div>
          </div>
          
          <div className="text-sm text-slate-300">
            {threat.level === 'CRITICAL' && 'Immediate action required. Critical threats detected.'}
            {threat.level === 'HIGH' && 'High priority threats require attention.'}
            {threat.level === 'MEDIUM' && 'Moderate security concerns detected.'}
            {threat.level === 'LOW' && 'System operating within normal parameters.'}
          </div>
        </div>
      </div>
    </div>
  );
};

export default ThreatLevel;
