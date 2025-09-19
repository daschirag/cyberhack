# 🏆 CyberShield - Hackathon Setup Guide

## 🎯 Quick Start (5 Minutes)

### 1. Install Dependencies
```bash
# Install Python dependencies
pip install -r requirements.txt
pip install -r backend/requirements.txt

# Install Node.js dependencies
cd frontend
npm install
cd ..
```

### 2. Start the Demo
```bash
# One-command startup
python start_hackathon_demo.py
```

### 3. Access Your Dashboard
- **Frontend Dashboard**: http://localhost:3000
- **Backend API**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs

## 🚀 What You Get

### Real-Time Security Dashboard
- **Live Threat Monitoring**: Real-time anomaly detection
- **Beautiful UI**: Modern, professional cybersecurity interface
- **Interactive Charts**: Visual analytics and threat trends
- **Alert Management**: Acknowledge, investigate, and resolve threats

### Advanced Features
- **Multi-Vector Detection**: Login, network, and file transfer anomalies
- **Risk Scoring**: AI-powered threat assessment
- **WebSocket Updates**: Real-time notifications
- **Responsive Design**: Works on desktop and mobile

## 🎮 Demo Scenarios

### Scenario 1: Normal Operations
```bash
# Start with normal traffic
python data_generator.py --mode stream --anomaly-rate 0.05
```

### Scenario 2: Attack Simulation
```bash
# Simulate coordinated attack
python data_generator.py --mode attack
```

### Scenario 3: High Threat Environment
```bash
# High anomaly rate for dramatic effect
python data_generator.py --mode stream --anomaly-rate 0.3
```

## 🏗️ Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Data Sources  │───▶│  Detection Engine│───▶│   Dashboard     │
│                 │    │                  │    │                 │
│ • Login Events  │    │ • Real-time      │    │ • React UI      │
│ • Network Data  │    │   Processing     │    │ • FastAPI       │
│ • File Transfers│    │ • Anomaly        │    │ • WebSockets    │
└─────────────────┘    │   Detection      │    └─────────────────┘
                       └──────────────────┘
```

## 🎨 Frontend Features

### Dashboard
- **Threat Level Indicator**: Real-time security status
- **Statistics Cards**: Total anomalies, critical alerts, system health
- **Recent Alerts**: Latest security events with details
- **Activity Timeline**: Chronological view of events

### Analytics
- **Anomaly Type Distribution**: Pie charts and bar graphs
- **Severity Breakdown**: Risk level analysis
- **Time Series**: Hourly anomaly patterns
- **Performance Metrics**: Detection accuracy and system stats

### Alert Management
- **Filter & Search**: Find specific threats
- **Action Buttons**: Acknowledge, investigate, resolve
- **Real-time Updates**: Live notifications via WebSocket
- **Severity Indicators**: Color-coded threat levels

## 🔧 Backend API

### Key Endpoints
- `GET /api/anomalies` - Get all anomalies
- `GET /api/stats` - System statistics
- `GET /api/anomalies/recent` - Recent threats
- `POST /api/alerts/{id}/action` - Handle alert actions
- `WebSocket /ws` - Real-time updates

### Data Format
```json
{
  "timestamp": "2024-01-15T10:15:00",
  "type": "login",
  "severity": "HIGH",
  "risk_score": 0.85,
  "explanation": "Login from suspicious country",
  "details": { ... }
}
```

## 🎯 Hackathon Presentation Tips

### 1. Start Clean
- Begin with normal traffic to show baseline
- Demonstrate the clean, professional interface

### 2. Build Suspense
- Gradually introduce suspicious activities
- Show real-time updates and notifications

### 3. Show Impact
- Trigger coordinated attacks
- Demonstrate multi-vector threat detection
- Highlight the speed of detection and response

### 4. Highlight Features
- **Real-time Processing**: Show live updates
- **AI-Powered Analysis**: Explain risk scoring
- **Professional UI**: Emphasize production-ready design
- **Scalability**: Mention enterprise deployment

### 5. Technical Depth
- Show the API documentation
- Demonstrate WebSocket real-time updates
- Explain the anomaly detection algorithms
- Discuss the modular architecture

## 🏆 Winning Features

### Technical Excellence
- **Real-time Processing**: Sub-second threat detection
- **Modern Stack**: React, FastAPI, WebSockets
- **Production Ready**: Error handling, logging, monitoring
- **Scalable Architecture**: Microservices design

### User Experience
- **Intuitive Interface**: Easy to understand and use
- **Responsive Design**: Works on all devices
- **Real-time Updates**: Live notifications and alerts
- **Professional Look**: Enterprise-grade appearance

### Innovation
- **Multi-Vector Detection**: Comprehensive threat monitoring
- **AI Integration**: Smart risk assessment
- **Real-time Analytics**: Live threat intelligence
- **Actionable Insights**: Clear next steps for security teams

## 🚨 Troubleshooting

### Common Issues
1. **Port Conflicts**: Change ports in configuration files
2. **Missing Dependencies**: Run `pip install -r requirements.txt`
3. **Node Modules**: Run `npm install` in frontend directory
4. **Permission Errors**: Check file permissions on output directories

### Performance Tips
- Use `--anomaly-rate 0.1` for smooth demo
- Close unnecessary applications
- Ensure stable internet connection for WebSocket

## 📱 Mobile Demo
The dashboard is fully responsive and works great on tablets and phones for mobile demos.

## 🎉 Good Luck!

Your CyberShield system is now ready to impress the judges! The combination of real-time threat detection, beautiful UI, and professional architecture makes this a winning hackathon project.

**Remember**: Focus on the real-time aspects, the professional UI, and the comprehensive threat detection capabilities. This system demonstrates both technical skill and practical cybersecurity knowledge.
