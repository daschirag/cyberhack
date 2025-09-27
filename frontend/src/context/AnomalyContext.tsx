import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import axios from 'axios';
import toast from 'react-hot-toast';
import { Anomaly, Stats, AnomalyContextType } from '../types/index.ts';

const AnomalyContext = createContext<AnomalyContextType | undefined>(undefined);

export const useAnomalies = (): AnomalyContextType => {
  const context = useContext(AnomalyContext);
  if (!context) {
    throw new Error('useAnomalies must be used within an AnomalyProvider');
  }
  return context;
};

interface AnomalyProviderProps {
  children: ReactNode;
}

export const AnomalyProvider: React.FC<AnomalyProviderProps> = ({ children }) => {
  const [anomalies, setAnomalies] = useState<Anomaly[]>([]);
  const [stats, setStats] = useState<Stats>({
    total_anomalies: 0,
    critical_count: 0,
    high_count: 0,
    medium_count: 0,
    low_count: 0,
    last_updated: '',
    system_uptime: ''
  });
  const [loading, setLoading] = useState<boolean>(true);
  const [wsConnection, setWsConnection] = useState<WebSocket | null>(null);

  const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000';

  // WebSocket connection for real-time updates
  useEffect(() => {
    const connectWebSocket = () => {
      const ws = new WebSocket(`${import.meta.env.VITE_WS_URL || 'ws://localhost:8000'}/ws`);
      
      ws.onopen = () => {
        console.log('WebSocket connected');
        setWsConnection(ws);
      };

      ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        
        if (data.type === 'new_anomaly') {
          setAnomalies(prev => [data.data, ...prev]);
          toast.error(`New ${data.data.severity} anomaly detected!`, {
            duration: 5000,
          });
        } else if (data.type === 'stats_update') {
          setStats(data.data);
        } else if (data.type === 'alert_action') {
          toast.success(`Alert ${data.action} applied`, {
            duration: 3000,
          });
        }
      };

      ws.onclose = () => {
        console.log('WebSocket disconnected');
        setWsConnection(null);
        // Reconnect after 5 seconds
        setTimeout(connectWebSocket, 5000);
      };

      ws.onerror = (error) => {
        console.error('WebSocket error:', error);
      };
    };

    connectWebSocket();

    return () => {
      if (wsConnection) {
        wsConnection.close();
      }
    };
  }, []);

  // Fetch initial data
  useEffect(() => {
    const fetchData = async () => {
      try {
        setLoading(true);
        const [anomaliesResponse, statsResponse] = await Promise.all([
          axios.get(`${API_BASE}/api/anomalies?limit=100`),
          axios.get(`${API_BASE}/api/stats`)
        ]);
        
        setAnomalies(anomaliesResponse.data);
        setStats(statsResponse.data);
      } catch (error) {
        console.error('Error fetching data:', error);
        toast.error('Failed to fetch data from server');
      } finally {
        setLoading(false);
      }
    };

    fetchData();
    
    // Refresh data every 30 seconds
    const interval = setInterval(fetchData, 30000);
    return () => clearInterval(interval);
  }, [API_BASE]);

  const fetchAnomalies = async (params = {}) => {
    try {
      const response = await axios.get(`${API_BASE}/api/anomalies`, { params });
      return response.data;
    } catch (error) {
      console.error('Error fetching anomalies:', error);
      toast.error('Failed to fetch anomalies');
      return [];
    }
  };

  const handleAlertAction = async (anomalyId: string, action: string, notes: string = '') => {
    try {
      await axios.post(`${API_BASE}/api/alerts/${anomalyId}/action`, {
        anomaly_id: anomalyId,
        action,
        notes
      });
      toast.success(`Alert ${action} successfully`);
    } catch (error) {
      console.error('Error handling alert action:', error);
      toast.error('Failed to apply alert action');
    }
  };

  const getAnomalyTypes = async () => {
    try {
      const response = await axios.get(`${API_BASE}/api/anomalies/types`);
      return response.data;
    } catch (error) {
      console.error('Error fetching anomaly types:', error);
      return {};
    }
  };

  const getSeverityBreakdown = async () => {
    try {
      const response = await axios.get(`${API_BASE}/api/anomalies/severity`);
      return response.data;
    } catch (error) {
      console.error('Error fetching severity breakdown:', error);
      return {};
    }
  };

  const value = {
    anomalies,
    stats,
    loading,
    wsConnection,
    fetchAnomalies,
    handleAlertAction,
    getAnomalyTypes,
    getSeverityBreakdown,
    setAnomalies,
    setStats
  };

  return (
    <AnomalyContext.Provider value={value}>
      {children}
    </AnomalyContext.Provider>
  );
};
