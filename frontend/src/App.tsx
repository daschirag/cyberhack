import React, { useState } from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { Toaster } from 'react-hot-toast';
import Dashboard from './components/Dashboard';
import Alerts from './components/Alerts';
import Analytics from './components/Analytics';
import Settings from './components/Settings';
import Sidebar from './components/Sidebar';
import Header from './components/Header';
import { AnomalyProvider } from './context/AnomalyContext';
import './index.css';

const App: React.FC = () => {
  const [sidebarOpen, setSidebarOpen] = useState<boolean>(false);

  return (
    <AnomalyProvider>
      <Router>
        <div className="flex h-screen bg-slate-900">
          <Sidebar isOpen={sidebarOpen} setIsOpen={setSidebarOpen} />
          
          <div className="flex-1 flex flex-col overflow-hidden">
            <Header onMenuClick={() => setSidebarOpen(!sidebarOpen)} />
            
            <main className="flex-1 overflow-x-hidden overflow-y-auto bg-slate-900">
              <Routes>
                <Route path="/" element={<Dashboard />} />
                <Route path="/alerts" element={<Alerts />} />
                <Route path="/analytics" element={<Analytics />} />
                <Route path="/settings" element={<Settings />} />
              </Routes>
            </main>
          </div>
        </div>
        
        <Toaster
          position="top-right"
          containerStyle={{
            top: 20,
            right: 20,
            zIndex: 9999,
          }}
          toastOptions={{
            duration: 4000,
            style: {
              background: '#1e293b',
              color: '#f8fafc',
              border: '1px solid #334155',
              borderRadius: '8px',
              fontSize: '14px',
              fontWeight: '500',
              zIndex: 9999,
            },
            success: {
              iconTheme: {
                primary: '#22c55e',
                secondary: '#f8fafc',
              },
            },
            error: {
              iconTheme: {
                primary: '#ef4444',
                secondary: '#f8fafc',
              },
            },
          }}
        />
      </Router>
    </AnomalyProvider>
  );
};

export default App;
