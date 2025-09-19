# 🛡️ CyberShield - Real-Time Cybersecurity Anomaly Detection System

A production-ready cybersecurity anomaly detection system with a modern web dashboard for real-time threat monitoring and analysis.

## ✨ Features

- **🔍 Real-Time Detection**: Processes security events as they arrive with minimal latency
- **🎨 Modern Dashboard**: Beautiful React-based UI with real-time updates
- **📊 Advanced Analytics**: Interactive charts and threat intelligence
- **🚨 Smart Alerting**: AI-powered risk scoring and alert management
- **🧠 Knowledge Base**: RAG-powered context for enhanced LLM explanations
- **🔒 Privacy-First**: Automatic PII masking and data protection
- **🌐 REST API**: Complete FastAPI backend with WebSocket support
- **📱 Responsive Design**: Works on desktop, tablet, and mobile devices
- **🔍 Vector Search**: Optional semantic similarity search for anomaly patterns

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

## 🚀 Quick Start

### Prerequisites

- **Python 3.8+**
- **Node.js 16+**
- **npm or yarn**

### 1. Clone the Repository

```bash
git clone <your-repo-url>
cd anomaly-detection-system
```

### 2. Install Dependencies

#### Backend Dependencies
```bash
# Install Python dependencies
pip install -r requirements.txt
pip install -r backend/requirements.txt
```

#### Frontend Dependencies
```bash
# Install Node.js dependencies
cd frontend
npm install
cd ..
```

### 3. Environment Setup

#### Backend Environment
```bash
# Copy environment template
cp env_config.txt .env

# Edit .env with your API keys (optional)
# OPENAI_API_KEY=your_openai_api_key_here
# USE_LLM=true
```

#### Frontend Environment
```bash
# Copy frontend environment template
cp frontend/env.example frontend/.env

# Edit frontend/.env if needed
# REACT_APP_API_URL=http://localhost:8000
```

### 4. Run the System

#### Option A: One-Command Startup (Recommended)
```bash
python start_hackathon_demo.py
```

#### Option B: Manual Startup
```bash
# Terminal 1: Start Backend
cd backend
python main.py

# Terminal 2: Start Frontend
cd frontend
npm start

# Terminal 3: Start Anomaly Detection
python anomaly_detection.py

# Terminal 4: Start Data Generator (for demo)
python data_generator.py --mode stream --anomaly-rate 0.1
```

### 5. Access the Application

- **🌐 Frontend Dashboard**: http://localhost:3000
- **🔧 Backend API**: http://localhost:8000
- **📚 API Documentation**: http://localhost:8000/docs
- **🔌 WebSocket**: ws://localhost:8000/ws

## 🐧 Ubuntu/Linux Users

For detailed Ubuntu setup instructions, see [UBUNTU_SETUP.md](UBUNTU_SETUP.md)

### Quick Ubuntu Commands:
```bash
# Install system dependencies
sudo apt update && sudo apt install python3 python3-pip python3-venv nodejs npm curl -y

# Clone and setup
git clone <your-repo-url>
cd anomaly-detection-system
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cd frontend && npm install && cd ..

# Run the system
python start_hackathon_demo.py
```

## 📦 Dependencies

### Backend Dependencies (`requirements.txt`)
```
# Core Framework
pathway>=0.12.0
fastapi>=0.104.1
uvicorn[standard]>=0.24.0

# Data Processing
pandas>=2.0.0
numpy>=1.24.0
python-dateutil>=2.8.0

# Web & API
websockets>=12.0
python-multipart>=0.0.6
pydantic>=2.5.0

# Environment & Configuration
python-dotenv>=1.0.0

# AI & ML (Optional)
openai>=1.0.0

# Development
pytest>=7.4.0
black>=23.0.0
flake8>=6.0.0
```

### Backend API Dependencies (`backend/requirements.txt`)
```
fastapi==0.104.1
uvicorn[standard]==0.24.0
websockets==12.0
python-multipart==0.0.6
pydantic==2.5.0
python-dotenv==1.0.0
```

### Frontend Dependencies (`frontend/package.json`)
```json
{
  "dependencies": {
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-router-dom": "^6.8.0",
    "recharts": "^2.8.0",
    "lucide-react": "^0.294.0",
    "tailwindcss": "^3.3.0",
    "axios": "^1.6.0",
    "date-fns": "^2.30.0",
    "react-hot-toast": "^2.4.1",
    "framer-motion": "^10.16.0"
  }
}
```

## 🎮 Demo Scenarios

### Normal Operations
```bash
python data_generator.py --mode stream --anomaly-rate 0.05
```

### Attack Simulation
```bash
python data_generator.py --mode attack
```

### High Threat Environment
```bash
python data_generator.py --mode stream --anomaly-rate 0.3
```

## 🔧 API Endpoints

### Core Endpoints
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

## 🎨 Frontend Features

### Dashboard
- **Threat Level Indicator**: Real-time security status
- **Statistics Cards**: Total anomalies, critical alerts, system health
- **Recent Alerts**: Latest security events with details
- **Activity Timeline**: Chronological view of events

### Analytics
- **Anomaly Type Distribution**: Interactive pie charts
- **Severity Breakdown**: Risk level analysis
- **Time Series**: Hourly anomaly patterns
- **Performance Metrics**: Detection accuracy and system stats

### Alert Management
- **Filter & Search**: Find specific threats
- **Action Buttons**: Acknowledge, investigate, resolve
- **Real-time Updates**: Live notifications via WebSocket
- **Severity Indicators**: Color-coded threat levels

## 🛡️ Detection Capabilities

### Login Anomaly Detection
- Suspicious countries and locations
- Unusual login times
- New IP addresses
- Risk scoring based on multiple factors

### Network Traffic Monitoring
- Traffic spike detection (DDoS-like attacks)
- Baseline learning and adaptation
- Statistical anomaly detection
- Real-time threshold monitoring

### File Transfer Analysis
- Large file transfer detection
- Suspicious file types and patterns
- User behavior profiling
- Data exfiltration attempts

### Knowledge Base & RAG
- **User Behavior Learning**: Tracks normal patterns (login times, locations, file sizes)
- **Anomaly History**: Stores and indexes past anomalies for pattern recognition
- **RAG Context**: Provides historical context to LLM for smarter explanations
- **Privacy Protection**: Automatic masking of usernames, IPs, and sensitive data
- **Vector Search**: Optional semantic similarity search for related anomalies
- **Bounded Memory**: Efficient storage with automatic cleanup (20 logins, 10 files, 500 anomalies)

## 🚨 Troubleshooting

### Common Issues

1. **Port Conflicts**
   ```bash
   # Change ports in configuration files
   # Backend: backend/main.py (port 8000)
   # Frontend: frontend/package.json (port 3000)
   ```

2. **Missing Dependencies**
   ```bash
   # Reinstall all dependencies
   pip install -r requirements.txt
   pip install -r backend/requirements.txt
   cd frontend && npm install
   ```

3. **Permission Errors**
   ```bash
   # Ensure output directories exist
   mkdir -p ./output ./data/login_stream ./data/network_stream ./data/file_stream
   ```

4. **WebSocket Connection Issues**
   - Check firewall settings
   - Ensure ports 8000 and 3000 are available
   - Verify backend is running before frontend

### Performance Tips
- Use `--anomaly-rate 0.1` for smooth demo
- Close unnecessary applications
- Ensure stable internet connection for WebSocket

## 📁 Project Structure

```
anomaly-detection-system/
├── backend/                 # FastAPI backend
│   ├── main.py             # Main API server
│   └── requirements.txt    # Backend dependencies
├── frontend/               # React frontend
│   ├── src/               # Source code
│   │   ├── components/    # React components
│   │   ├── context/       # React context
│   │   └── App.js         # Main app component
│   ├── public/            # Static files
│   └── package.json       # Frontend dependencies
├── data/                  # Data streams
│   ├── login_stream/      # Login event data
│   ├── network_stream/    # Network traffic data
│   └── file_stream/       # File transfer data
├── output/                # Anomaly outputs
├── anomaly_detection.py   # Main detection engine
├── data_generator.py      # Demo data generator
├── start_hackathon_demo.py # One-command startup
├── requirements.txt       # Main dependencies
└── README.md             # This file
```

## 🏆 Hackathon Features

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

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🎯 Demo Tips

### For Presentations
1. **Start Clean**: Begin with normal traffic to show baseline
2. **Build Suspense**: Gradually introduce suspicious activities
3. **Show Impact**: Trigger coordinated attacks to demonstrate detection
4. **Highlight Speed**: Emphasize real-time processing capabilities
5. **Explain Value**: Connect technical features to business benefits

---

**Built for cybersecurity education and real-time threat detection**

*Demonstrating the power of real-time data processing for security applications*