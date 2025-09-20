import React from 'react';
import { Menu, Bell, Shield, Wifi } from 'lucide-react';
import { HeaderProps } from '../types';

const Header: React.FC<HeaderProps> = ({ onMenuClick }) => {
  return (
    <header className="bg-slate-800 border-b border-slate-700 px-4 py-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-4">
          <button
            onClick={onMenuClick}
            className="p-2 rounded-md text-slate-400 hover:text-white hover:bg-slate-700 transition-colors"
          >
            <Menu size={20} />
          </button>
          
          <div className="flex items-center space-x-2">
            <Shield className="text-blue-400" size={24} />
            <h1 className="text-xl font-bold text-white">CyberShield</h1>
          </div>
        </div>

        <div className="flex items-center space-x-4">
          {/* Connection Status */}
          <div className="flex items-center space-x-2">
            <Wifi className="text-green-400" size={16} />
            <span className="text-sm text-slate-300">Live</span>
          </div>

          {/* Notifications */}
          <button className="relative p-2 rounded-md text-slate-400 hover:text-white hover:bg-slate-700 transition-colors">
            <Bell size={20} />
            <span className="absolute -top-1 -right-1 bg-red-500 text-white text-xs rounded-full h-5 w-5 flex items-center justify-center">
              3
            </span>
          </button>

          {/* User Profile */}
          <div className="flex items-center space-x-2">
            <div className="w-8 h-8 bg-gradient-to-r from-blue-500 to-purple-600 rounded-full flex items-center justify-center">
              <span className="text-white text-sm font-medium">A</span>
            </div>
            <span className="text-sm text-slate-300">Admin</span>
          </div>
        </div>
      </div>
    </header>
  );
};

export default Header;
