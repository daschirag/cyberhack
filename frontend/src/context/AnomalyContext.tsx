import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import axios from 'axios';
import toast from 'react-hot-toast';
import { Anomaly, Stats, AnomalyContextType, WebSocketMessage } from '../types';

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

  const API_BASE = import.meta.env.VITE_API_URL || '';

  // WebSocket connection for real-time updates
  useEffect(() => {
    let reconnectTimeout: NodeJS.Timeout;
    
    const connectWebSocket = () => {
      try {
        const ws = new WebSocket(`${import.meta.env.VITE_WS_URL || 'ws://localhost:5173'}/ws`);
        
        ws.onopen = () => {
          console.log('WebSocket connected');
          setWsConnection(ws);
        };

        ws.onmessage = (event: MessageEvent) => {
          const data: WebSocketMessage = JSON.parse(event.data);
          
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
          // Reconnect after 10 seconds (longer delay to avoid spam)
          reconnectTimeout = setTimeout(connectWebSocket, 10000);
        };

        ws.onerror = (error: Event) => {
          console.error('WebSocket error:', error);
          console.log('WebSocket connection failed - running in demo mode');
        };
      } catch (error) {
        console.error('Failed to create WebSocket connection:', error);
        console.log('Running in demo mode without real-time updates');
      }
    };

    // Try to connect, but don't spam if it fails
    connectWebSocket();

    return () => {
      if (reconnectTimeout) {
        clearTimeout(reconnectTimeout);
      }
      if (wsConnection) {
        wsConnection.close();
      }
    };
  }, []);

  // Fetch initial data
  useEffect(() => {
    const fetchData = async (): Promise<void> => {
      try {
        setLoading(true);
        const [anomaliesResponse, statsResponse] = await Promise.all([
          axios.get<Anomaly[]>(`${API_BASE}/api/anomalies?limit=100`),
          axios.get<Stats>(`${API_BASE}/api/stats`)
        ]);
        
        setAnomalies(anomaliesResponse.data);
        setStats(statsResponse.data);
      } catch (error) {
        console.error('Error fetching data:', error);
        console.log('Backend not available, using mock data');
        
        // Use mock data when backend is not available
        const mockAnomalies: Anomaly[] = [
          {
            id: '1',
            timestamp: new Date().toISOString(),
            type: 'Suspicious Login',
            severity: 'HIGH',
            explanation: 'Multiple failed login attempts from the same IP address within a short time frame',
            risk_score: 85,
            source_ip: '192.168.1.100',
            description: 'Multiple failed login attempts detected',
            status: 'active',
            confidence: 0.85
          },
          {
            id: '2',
            timestamp: new Date(Date.now() - 300000).toISOString(),
            type: 'Data Exfiltration',
            severity: 'CRITICAL',
            explanation: 'Large volume of sensitive data being transferred to external IP addresses',
            risk_score: 95,
            source_ip: '10.0.0.50',
            description: 'Large data transfer to external IP',
            status: 'active',
            confidence: 0.92
          },
          {
            id: '3',
            timestamp: new Date(Date.now() - 600000).toISOString(),
            type: 'Malware Detection',
            severity: 'MEDIUM',
            explanation: 'Suspicious file behavior patterns detected, possible malware activity',
            risk_score: 65,
            source_ip: '172.16.0.25',
            description: 'Suspicious file behavior detected',
            status: 'investigating',
            confidence: 0.78
          },
          {
            id: '4',
            timestamp: new Date(Date.now() - 900000).toISOString(),
            type: 'Network Anomaly',
            severity: 'LOW',
            explanation: 'Unusual network traffic pattern detected during off-hours',
            risk_score: 35,
            source_ip: '203.0.113.42',
            description: 'Unusual network activity detected',
            status: 'resolved',
            confidence: 0.45
          }
        ];

        const mockStats: Stats = {
          total_anomalies: mockAnomalies.length,
          critical_count: 1,
          high_count: 1,
          medium_count: 1,
          low_count: 1,
          last_updated: new Date().toISOString(),
          system_uptime: '2 days, 14 hours'
        };

        setAnomalies(mockAnomalies);
        setStats(mockStats);

        toast('Running in demo mode - backend not connected', {
          duration: 5000,
        });

        // Test toast to verify toast system is working
        setTimeout(() => {
          toast.success('Demo mode activated successfully!', {
            duration: 3000,
          });
        }, 1000);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
    
    // Refresh data every 30 seconds (only if backend is available)
    const interval = setInterval(() => {
      // Only try to fetch if we have a WebSocket connection
      if (wsConnection) {
        fetchData();
      }
    }, 30000);
    return () => clearInterval(interval);
  }, [API_BASE, wsConnection]);

  const fetchAnomalies = async (params: Record<string, any> = {}): Promise<Anomaly[]> => {
    try {
      const response = await axios.get<Anomaly[]>(`${API_BASE}/api/anomalies`, { params });
      return response.data;
    } catch (error) {
      console.error('Error fetching anomalies:', error);
      toast.error('Failed to fetch anomalies');
      return [];
    }
  };

  const handleAlertAction = async (anomalyId: string, action: string, notes: string = ''): Promise<void> => {
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

  const getAnomalyTypes = async (): Promise<Record<string, number>> => {
    try {
      const response = await axios.get<Record<string, number>>(`${API_BASE}/api/anomalies/types`);
      return response.data;
    } catch (error) {
      console.error('Error fetching anomaly types:', error);
      return {};
    }
  };

  const getSeverityBreakdown = async (): Promise<Record<string, number>> => {
    try {
      const response = await axios.get<Record<string, number>>(`${API_BASE}/api/anomalies/severity`);
      return response.data;
    } catch (error) {
      console.error('Error fetching severity breakdown:', error);
      return {};
    }
  };

  const value: AnomalyContextType = {
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
