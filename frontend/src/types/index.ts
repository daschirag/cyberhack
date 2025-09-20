// Anomaly types
export interface Anomaly {
  timestamp: string;
  type: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  explanation?: string;
  risk_score: number;
}

// Stats types
export interface Stats {
  total_anomalies: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  last_updated: string;
  system_uptime: string;
}

// Context types
export interface AnomalyContextType {
  anomalies: Anomaly[];
  stats: Stats;
  loading: boolean;
  wsConnection: WebSocket | null;
  fetchAnomalies: (params?: Record<string, any>) => Promise<Anomaly[]>;
  handleAlertAction: (anomalyId: string, action: string, notes?: string) => Promise<void>;
  getAnomalyTypes: () => Promise<Record<string, number>>;
  getSeverityBreakdown: () => Promise<Record<string, number>>;
  setAnomalies: React.Dispatch<React.SetStateAction<Anomaly[]>>;
  setStats: React.Dispatch<React.SetStateAction<Stats>>;
}

// Component prop types
export interface StatsCardsProps {
  stats: Stats;
}

export interface RecentAlertsProps {
  anomalies: Anomaly[];
}

export interface ThreatLevelProps {
  stats: Stats;
}

export interface SystemHealthProps {
  stats: Stats;
}

export interface ActivityTimelineProps {
  anomalies: Anomaly[];
}

export interface HeaderProps {
  onMenuClick: () => void;
}

export interface SidebarProps {
  isOpen: boolean;
  setIsOpen: React.Dispatch<React.SetStateAction<boolean>>;
}

// Settings types
export interface NotificationSettings {
  email: boolean;
  slack: boolean;
  discord: boolean;
  criticalOnly: boolean;
}

export interface DetectionSettings {
  sensitivity: 'low' | 'medium' | 'high';
  autoResolve: boolean;
  retentionDays: number;
}

export interface ApiSettings {
  openaiKey: string;
  slackWebhook: string;
  discordWebhook: string;
}

export interface AppSettings {
  notifications: NotificationSettings;
  detection: DetectionSettings;
  api: ApiSettings;
}

// WebSocket message types
export interface WebSocketMessage {
  type: 'new_anomaly' | 'stats_update' | 'alert_action';
  data: any;
  action?: string;
}

// Chart data types
export interface ChartData {
  name: string;
  value: number;
}

export interface TimeSeriesData {
  hour: string;
  count: number;
}
