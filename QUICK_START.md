# 🚀 Quick Start Guide - CyberShield

## 📋 Prerequisites Check

Before running, ensure you have:
- ✅ Python 3.8+ installed
- ✅ Node.js 16+ installed
- ✅ Git repository cloned

## ⚡ 5-Minute Setup

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

### 2. Start the System

```bash
# One command to start everything
python start_hackathon_demo.py
```

### 3. Access Your Dashboard

- **🌐 Frontend**: http://localhost:3000
- **🔧 Backend API**: http://localhost:8000
- **📚 API Docs**: http://localhost:8000/docs

## 🎮 Test the System

### Check if Backend is Working
```bash
curl http://localhost:8000/api/health
```
Should return: `{"status": "healthy", "timestamp": "..."}`

### Check if Frontend is Working
Open http://localhost:3000 in your browser
You should see the CyberShield dashboard

### Generate Test Data
```bash
# In a new terminal
python data_generator.py --mode stream --anomaly-rate 0.2
```

## 🚨 Troubleshooting

### Port Already in Use
```bash
# Kill processes on ports 3000 and 8000
# Windows:
netstat -ano | findstr :3000
netstat -ano | findstr :8000
taskkill /PID <PID_NUMBER> /F

# Linux/Mac:
lsof -ti:3000 | xargs kill -9
lsof -ti:8000 | xargs kill -9
```

### Missing Dependencies
```bash
# Reinstall everything
pip install --upgrade pip
pip install -r requirements.txt
pip install -r backend/requirements.txt
cd frontend && npm install && cd ..
```

### Permission Errors
```bash
# Create necessary directories
mkdir -p ./output ./data/login_stream ./data/network_stream ./data/file_stream
```

## ✅ Success Indicators

You'll know everything is working when:
- ✅ Backend shows "Application startup complete"
- ✅ Frontend opens in browser without errors
- ✅ Dashboard shows real-time data
- ✅ WebSocket connection is established
- ✅ Anomalies appear in the dashboard

## 🎯 Demo Commands

```bash
# Normal traffic
python data_generator.py --mode stream --anomaly-rate 0.05

# Attack simulation
python data_generator.py --mode attack

# High threat environment
python data_generator.py --mode stream --anomaly-rate 0.3
```

## 📱 Mobile Testing

The dashboard is responsive and works on mobile devices. Test by:
1. Opening http://localhost:3000 on your phone
2. Using browser dev tools to simulate mobile
3. Checking the responsive design

---

**🎉 You're ready for your hackathon presentation!**
