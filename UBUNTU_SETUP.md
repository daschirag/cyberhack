# 🐧 Ubuntu Setup Guide - CyberShield Cybersecurity System

## 🚀 Quick Start (Ubuntu Terminal Commands)

### 1. Clone the Repository
```bash
# Clone the repository
git clone <your-repo-url>
cd anomaly-detection-system

# Verify you're in the right directory
ls -la
```

### 2. Install System Dependencies
```bash
# Update package list
sudo apt update

# Install Python 3.8+ and pip
sudo apt install python3 python3-pip python3-venv -y

# Install Node.js 16+ (for frontend)
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs

# Install build tools (for some Python packages)
sudo apt install build-essential python3-dev -y

# Install curl (for health checks)
sudo apt install curl -y
```

### 3. Create Virtual Environment
```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Verify activation (you should see (venv) in prompt)
which python
```

### 4. Install Python Dependencies
```bash
# Upgrade pip
pip install --upgrade pip

# Install all dependencies
pip install -r requirements.txt
pip install -r backend/requirements.txt

# Verify installation
pip list | grep -E "(pathway|fastapi|pandas|numpy)"
```

### 5. Install Frontend Dependencies
```bash
# Install Node.js dependencies
cd frontend
npm install
cd ..

# Verify Node.js installation
node --version
npm --version
```

### 6. Environment Setup
```bash
# Copy environment template
cp env_config.txt .env

# Edit environment file (optional - system works with defaults)
nano .env
# Press Ctrl+X, then Y, then Enter to save and exit
```

### 7. Run the Complete System
```bash
# One command to start everything
python start_hackathon_demo.py
```

### 8. Access Your Dashboard
- **Frontend Dashboard**: http://localhost:3000
- **Backend API**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs

## 🎮 Demo Commands

### Test the System
```bash
# Test backend health
curl http://localhost:8000/api/health

# Generate demo data
python data_generator.py --mode stream --anomaly-rate 0.2

# Run Knowledge Base demo
python demo_kb_flow.py

# Run tests
python -m pytest tests/ -v
```

### Different Demo Scenarios
```bash
# Normal traffic
python data_generator.py --mode stream --anomaly-rate 0.05

# Attack simulation
python data_generator.py --mode attack

# High threat environment
python data_generator.py --mode stream --anomaly-rate 0.3
```

## 🚨 Troubleshooting Commands

### Port Conflicts
```bash
# Check what's using ports 3000 and 8000
sudo netstat -tulpn | grep :3000
sudo netstat -tulpn | grep :8000

# Kill processes on specific ports
sudo fuser -k 3000/tcp
sudo fuser -k 8000/tcp

# Alternative: Find and kill by PID
sudo lsof -ti:3000 | xargs kill -9
sudo lsof -ti:8000 | xargs kill -9
```

### Permission Issues
```bash
# Fix file permissions
chmod +x start_hackathon_demo.py
chmod +x demo_kb_flow.py

# Create necessary directories
mkdir -p ./output ./data/login_stream ./data/network_stream ./data/file_stream

# Fix ownership if needed
sudo chown -R $USER:$USER .
```

### Python Environment Issues
```bash
# Deactivate and recreate virtual environment
deactivate
rm -rf venv
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### Node.js Issues
```bash
# Clear npm cache
npm cache clean --force

# Remove node_modules and reinstall
cd frontend
rm -rf node_modules package-lock.json
npm install
cd ..
```

### Missing Dependencies
```bash
# Install missing system packages
sudo apt install python3-dev libffi-dev libssl-dev -y

# Reinstall Python packages
pip install --force-reinstall -r requirements.txt

# For ChromaDB issues
pip install --upgrade chromadb
```

### Memory Issues
```bash
# Check system resources
free -h
df -h

# Increase swap if needed
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

## 🔧 Manual Component Startup

If the one-command startup fails, start components manually:

### Terminal 1: Backend
```bash
source venv/bin/activate
cd backend
python main.py
```

### Terminal 2: Frontend
```bash
cd frontend
npm start
```

### Terminal 3: Anomaly Detection
```bash
source venv/bin/activate
python anomaly_detection.py
```

### Terminal 4: Data Generator
```bash
source venv/bin/activate
python data_generator.py --mode stream --anomaly-rate 0.1
```

## 📊 System Requirements

### Minimum Requirements
- **OS**: Ubuntu 18.04+ (or any Linux distribution)
- **RAM**: 4GB minimum, 8GB recommended
- **Storage**: 2GB free space
- **Python**: 3.8+
- **Node.js**: 16+

### Recommended Requirements
- **RAM**: 8GB+
- **CPU**: 4+ cores
- **Storage**: 5GB+ free space
- **Network**: Stable internet connection

## 🎯 Verification Commands

### Check System Status
```bash
# Check Python version
python3 --version

# Check Node.js version
node --version
npm --version

# Check if ports are available
netstat -tulpn | grep -E ":(3000|8000)"

# Check virtual environment
echo $VIRTUAL_ENV

# Check installed packages
pip list | wc -l
```

### Test Individual Components
```bash
# Test Python imports
python3 -c "import pathway, fastapi, pandas, numpy; print('All imports successful')"

# Test Node.js
cd frontend && npm test && cd ..

# Test API endpoint
curl -f http://localhost:8000/api/health || echo "Backend not running"

# Test frontend
curl -f http://localhost:3000 || echo "Frontend not running"
```

## 🏆 Success Indicators

You'll know everything is working when:

✅ **Backend**: Shows "Application startup complete"  
✅ **Frontend**: Opens in browser without errors  
✅ **Dashboard**: Shows real-time data and charts  
✅ **WebSocket**: Connection established (check browser console)  
✅ **Anomalies**: Appear in dashboard when data generator runs  
✅ **API**: http://localhost:8000/docs shows API documentation  

## 🆘 Emergency Commands

### Complete Reset
```bash
# Stop all processes
pkill -f "python.*anomaly_detection"
pkill -f "python.*main.py"
pkill -f "npm.*start"

# Clean everything
rm -rf venv
rm -rf frontend/node_modules
rm -rf frontend/package-lock.json
rm -rf ./output/*
rm -rf ./data/*/*

# Start fresh
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
cd frontend && npm install && cd ..
python start_hackathon_demo.py
```

### Get Help
```bash
# Check system logs
journalctl -f

# Check Python errors
python start_hackathon_demo.py 2>&1 | tee error.log

# Check Node.js errors
cd frontend && npm start 2>&1 | tee frontend-error.log
```

## 📱 Mobile Testing

The dashboard is responsive and works on mobile devices:

```bash
# Find your local IP
hostname -I

# Access from mobile device
# http://YOUR_LOCAL_IP:3000
# Example: http://192.168.1.100:3000
```

---

## 🎉 You're Ready!

Your CyberShield system is now running with:
- ✅ Real-time anomaly detection
- ✅ Modern React dashboard
- ✅ FastAPI backend with WebSocket
- ✅ Knowledge Base with RAG capabilities
- ✅ AI-powered alert explanations
- ✅ Vector database integration
- ✅ Complete test suite

**Perfect for your hackathon presentation!** 🏆
