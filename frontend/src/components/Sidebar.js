import React from 'react';
import { NavLink } from 'react-router-dom';
import { 
  LayoutDashboard, 
  AlertTriangle, 
  BarChart3, 
  Settings, 
  Shield,
  X
} from 'lucide-react';

const Sidebar = ({ isOpen, setIsOpen }) => {
  const navigation = [
    { name: 'Dashboard', href: '/', icon: LayoutDashboard },
    { name: 'Alerts', href: '/alerts', icon: AlertTriangle },
    { name: 'Analytics', href: '/analytics', icon: BarChart3 },
    { name: 'Settings', href: '/settings', icon: Settings },
  ];

  return (
    <>
      {/* Mobile backdrop */}
      {isOpen && (
        <div 
          className="fixed inset-0 bg-black bg-opacity-50 z-40 lg:hidden"
          onClick={() => setIsOpen(false)}
        />
      )}

      {/* Sidebar */}
      <div className={`
        fixed inset-y-0 left-0 z-50 w-64 bg-slate-800 border-r border-slate-700 transform transition-transform duration-300 ease-in-out
        ${isOpen ? 'translate-x-0' : '-translate-x-full'}
        lg:translate-x-0 lg:static lg:inset-0
      `}>
        <div className="flex items-center justify-between h-16 px-4 border-b border-slate-700">
          <div className="flex items-center space-x-2">
            <Shield className="text-blue-400" size={24} />
            <span className="text-lg font-bold text-white">CyberShield</span>
          </div>
          <button
            onClick={() => setIsOpen(false)}
            className="lg:hidden p-1 rounded-md text-slate-400 hover:text-white hover:bg-slate-700"
          >
            <X size={20} />
          </button>
        </div>

        <nav className="mt-8 px-4">
          <div className="space-y-2">
            {navigation.map((item) => {
              const Icon = item.icon;
              return (
                <NavLink
                  key={item.name}
                  to={item.href}
                  className={({ isActive }) =>
                    `flex items-center px-3 py-2 text-sm font-medium rounded-md transition-colors ${
                      isActive
                        ? 'bg-blue-600 text-white'
                        : 'text-slate-300 hover:bg-slate-700 hover:text-white'
                    }`
                  }
                  onClick={() => setIsOpen(false)}
                >
                  <Icon size={20} className="mr-3" />
                  {item.name}
                </NavLink>
              );
            })}
          </div>
        </nav>

        {/* System Status */}
        <div className="absolute bottom-4 left-4 right-4">
          <div className="bg-slate-700 rounded-lg p-3">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-medium text-slate-300">System Status</span>
              <div className="flex items-center space-x-1">
                <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
                <span className="text-xs text-green-400">Online</span>
              </div>
            </div>
            <div className="text-xs text-slate-400">
              <div>Uptime: 2h 34m</div>
              <div>Last Update: Just now</div>
            </div>
          </div>
        </div>
      </div>
    </>
  );
};

export default Sidebar;
