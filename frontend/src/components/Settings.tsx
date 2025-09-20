import React, { useState } from 'react';
import { Shield, Bell, Database, Key, Save } from 'lucide-react';
import { AppSettings } from '../types';

const Settings: React.FC = () => {
  const [settings, setSettings] = useState<AppSettings>({
    notifications: {
      email: true,
      slack: false,
      discord: false,
      criticalOnly: false
    },
    detection: {
      sensitivity: 'medium',
      autoResolve: false,
      retentionDays: 30
    },
    api: {
      openaiKey: '',
      slackWebhook: '',
      discordWebhook: ''
    }
  });

  const handleSave = (): void => {
    // In a real app, this would save to backend
    console.log('Settings saved:', settings);
  };

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-white">Settings</h1>
        <p className="text-slate-400 mt-1">Configure your security monitoring system</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Notifications */}
        <div className="bg-slate-800 rounded-lg border border-slate-700 p-6">
          <div className="flex items-center space-x-2 mb-6">
            <Bell className="text-blue-400" size={24} />
            <h2 className="text-xl font-semibold text-white">Notifications</h2>
          </div>
          
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <label className="text-white font-medium">Email Alerts</label>
                <p className="text-sm text-slate-400">Receive alerts via email</p>
              </div>
              <input
                type="checkbox"
                checked={settings.notifications.email}
                onChange={(e) => setSettings({
                  ...settings,
                  notifications: { ...settings.notifications, email: e.target.checked }
                })}
                className="w-4 h-4 text-blue-600 bg-slate-700 border-slate-600 rounded focus:ring-blue-500"
              />
            </div>
            
            <div className="flex items-center justify-between">
              <div>
                <label className="text-white font-medium">Slack Integration</label>
                <p className="text-sm text-slate-400">Send alerts to Slack channel</p>
              </div>
              <input
                type="checkbox"
                checked={settings.notifications.slack}
                onChange={(e) => setSettings({
                  ...settings,
                  notifications: { ...settings.notifications, slack: e.target.checked }
                })}
                className="w-4 h-4 text-blue-600 bg-slate-700 border-slate-600 rounded focus:ring-blue-500"
              />
            </div>
            
            <div className="flex items-center justify-between">
              <div>
                <label className="text-white font-medium">Critical Only</label>
                <p className="text-sm text-slate-400">Only notify for critical alerts</p>
              </div>
              <input
                type="checkbox"
                checked={settings.notifications.criticalOnly}
                onChange={(e) => setSettings({
                  ...settings,
                  notifications: { ...settings.notifications, criticalOnly: e.target.checked }
                })}
                className="w-4 h-4 text-blue-600 bg-slate-700 border-slate-600 rounded focus:ring-blue-500"
              />
            </div>
          </div>
        </div>

        {/* Detection Settings */}
        <div className="bg-slate-800 rounded-lg border border-slate-700 p-6">
          <div className="flex items-center space-x-2 mb-6">
            <Shield className="text-green-400" size={24} />
            <h2 className="text-xl font-semibold text-white">Detection</h2>
          </div>
          
          <div className="space-y-4">
            <div>
              <label className="text-white font-medium block mb-2">Sensitivity Level</label>
              <select
                value={settings.detection.sensitivity}
                onChange={(e) => setSettings({
                  ...settings,
                  detection: { ...settings.detection, sensitivity: e.target.value as 'low' | 'medium' | 'high' }
                })}
                className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
              </select>
            </div>
            
            <div className="flex items-center justify-between">
              <div>
                <label className="text-white font-medium">Auto-Resolve</label>
                <p className="text-sm text-slate-400">Automatically resolve low-risk alerts</p>
              </div>
              <input
                type="checkbox"
                checked={settings.detection.autoResolve}
                onChange={(e) => setSettings({
                  ...settings,
                  detection: { ...settings.detection, autoResolve: e.target.checked }
                })}
                className="w-4 h-4 text-blue-600 bg-slate-700 border-slate-600 rounded focus:ring-blue-500"
              />
            </div>
            
            <div>
              <label className="text-white font-medium block mb-2">Data Retention (Days)</label>
              <input
                type="number"
                value={settings.detection.retentionDays}
                onChange={(e) => setSettings({
                  ...settings,
                  detection: { ...settings.detection, retentionDays: parseInt(e.target.value) }
                })}
                className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>
          </div>
        </div>

        {/* API Configuration
        <div className="bg-slate-800 rounded-lg border border-slate-700 p-6 lg:col-span-2">
          <div className="flex items-center space-x-2 mb-6">
            <Key className="text-purple-400" size={24} />
            <h2 className="text-xl font-semibold text-white">API Configuration</h2>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <label className="text-white font-medium block mb-2">OpenAI API Key</label>
              <input
                type="password"
                value={settings.api.openaiKey}
                onChange={(e) => setSettings({
                  ...settings,
                  api: { ...settings.api, openaiKey: e.target.value }
                })}
                placeholder="sk-..."
                className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>
            
            <div>
              <label className="text-white font-medium block mb-2">Slack Webhook URL</label>
              <input
                type="url"
                value={settings.api.slackWebhook}
                onChange={(e) => setSettings({
                  ...settings,
                  api: { ...settings.api, slackWebhook: e.target.value }
                })}
                placeholder="https://hooks.slack.com/..."
                className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>
          </div>
        </div> */}
      </div>

      {/* Save Button */}
      <div className="flex justify-end">
        <button
          onClick={handleSave}
          className="flex items-center space-x-2 px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
        >
          <Save size={20} />
          <span>Save Settings</span>
        </button>
      </div>
    </div>
  );
};

export default Settings;
