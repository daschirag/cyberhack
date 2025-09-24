#!/usr/bin/env python3
"""
Hackathon Demo Starter Script
Frontend (React) on port 3000, Backend (FastAPI) on port 8000
"""

import subprocess
import sys
import time
import os
import signal
import threading
import requests
from pathlib import Path
import logging
from rag.rag_pipeline import get_rag_pipeline

class HackathonDemo:
    def __init__(self):
        self.processes = []
        self.running = True
        self.health_check_interval = 10
        
    def wait_for_backend(self, max_attempts=500):
        """Wait for backend to be ready"""
        print("⏳ Waiting for backend to be ready...")
        for attempt in range(max_attempts):
            try:
                response = requests.get("http://localhost:8000/api/health", timeout=2)
                if response.status_code == 200:
                    print("✅ Backend is ready!")
                    return True
            except Exception as e:
                if attempt == 0:
                    print(f"   Connection error: {str(e)[:50]}...")
            time.sleep(1)
            if attempt % 5 == 0:
                print(f"   Still waiting... ({attempt}/{max_attempts})")
        
        print("❌ Backend failed to start in time")
        return False
    
    def wait_for_frontend(self, max_attempts=60):
        """Wait for frontend to be ready"""
        print("⏳ Waiting for frontend to be ready...")
        for attempt in range(max_attempts):
            try:
                response = requests.get("http://localhost:3000", timeout=2)
                if response.status_code == 200:
                    print("✅ Frontend is ready!")
                    return True
            except Exception as e:
                pass
            time.sleep(2)
            if attempt % 10 == 0 and attempt > 0:
                print(f"   Still waiting... ({attempt}/{max_attempts})")
        
        print("⚠️ Frontend may still be loading (this is normal)")
        return True  # Continue anyway since React takes time to compile
        
    def check_directory_structure(self):
        """Ensure all required directories exist"""
        directories = [
            "./output",
            "./data/login_stream", 
            "./data/network_stream",
            "./data/file_stream",
            "./logs",
            # ADD THESE RAG DIRECTORIES
            "./chroma_db",           # For vector database
            "./rag/knowledge_base"   # For knowledge base files
        ]
        
        print("📁 Setting up directory structure...")
        for directory in directories:
            os.makedirs(directory, exist_ok=True)
            os.chmod(directory, 0o755)
        print("✅ Directory structure ready")

    def initialize_rag_pipeline(self):
        """Initialize RAG pipeline before starting services"""
        print("🧠 Initializing RAG pipeline...")
        try:
            # Initialize RAG
            rag = get_rag_pipeline()
            status = rag.get_pipeline_status()
            
            print(f"   RAG Enabled: {status.get('rag_enabled', False)}")
            print(f"   Knowledge Base Documents: {status.get('knowledge_base_documents', 0)}")
            print(f"   Vector Store Documents: {status.get('vector_store_info', {}).get('document_count', 0)}")
            print(f"   OpenAI Model: {status.get('openai_model', 'Not configured')}")
            
            if status.get('initialized', False):
                print("✅ RAG pipeline initialized successfully")
                return True
            else:
                print("⚠️ RAG pipeline not fully initialized")
                return False
                
        except Exception as e:
            print(f"❌ RAG initialization failed: {e}")
            print("   System will run without RAG enhancement")
            return False
    
    def start_backend(self):
        """Start the FastAPI backend on port 8000"""
        print("🚀 Starting FastAPI backend...")
        try:
            backend_dir = Path("backend")
            if not backend_dir.exists():
                print("❌ Backend directory not found!")
                return None
                
            # Start the backend with logs
            log_file = open("./logs/backend.log", "w")
            process = subprocess.Popen(
                [sys.executable, "main.py"],
                cwd=backend_dir,
                stdout=log_file,
                stderr=subprocess.STDOUT
            )
            print("🔄 Backend starting... (logs in ./logs/backend.log)")
            return process
        except Exception as e:
            print(f"❌ Failed to start backend: {e}")
            return None
    
    def start_frontend(self):
        """Start the React frontend on port 3000"""
        print("🎨 Starting React frontend...")
        try:
            # Look for existing frontend directory
            frontend_paths = ["frontend", "../frontend", "./frontend"]
            frontend_dir = None
            
            for path in frontend_paths:
                if Path(path).exists() and (Path(path) / "package.json").exists():
                    frontend_dir = Path(path)
                    break
            
            if not frontend_dir:
                print("❌ Frontend directory with package.json not found!")
                print("   Looked in: frontend, ../frontend, ./frontend")
                return None
            
            print(f"   Found React app in: {frontend_dir}")
            
            # Check if node_modules exists
            node_modules = frontend_dir / "node_modules"
            if not node_modules.exists():
                print("📦 Installing frontend dependencies...")
                install_result = subprocess.run(
                    ["npm", "install"], 
                    cwd=frontend_dir, 
                    capture_output=True, 
                    text=True
                )
                if install_result.returncode != 0:
                    print(f"❌ npm install failed: {install_result.stderr}")
                    print("   Trying to continue anyway...")
                else:
                    print("✅ Dependencies installed successfully")
            
            # Start the frontend development server
            print("🚀 Starting React development server...")
            log_file = open("./logs/frontend.log", "w")
            
            # Set environment variables for the frontend
            frontend_env = {
                **os.environ, 
                "BROWSER": "none", 
                "PORT": "3000",
                "REACT_APP_API_URL": "http://localhost:8000",
                "CI": "false"  # Prevents treating warnings as errors
            }
            
            process = subprocess.Popen(
                ["npm", "start"],
                cwd=frontend_dir,
                stdout=log_file,
                stderr=subprocess.STDOUT,
                env=frontend_env
            )
            print("✅ Frontend started on http://localhost:3000 (logs in ./logs/frontend.log)")
            return process
            
        except Exception as e:
            print(f"❌ Failed to start frontend: {e}")
            return None
    
    def start_anomaly_detection(self):
        """Start the anomaly detection system"""
        print("🛡️ Starting anomaly detection system...")
        try:
            log_file = open("./logs/anomaly_detection.log", "w")
            process = subprocess.Popen(
                [sys.executable, "anomaly_detection.py"],
                stdout=log_file,
                stderr=subprocess.STDOUT
            )
            print("✅ Anomaly detection system started (logs in ./logs/anomaly_detection.log)")
            return process
        except Exception as e:
            print(f"❌ Failed to start anomaly detection: {e}")
            return None

    def start_data_generator(self):
        """Start the data generator for demo"""
        print("📊 Starting data generator...")
        try:
            log_file = open("./logs/data_generator.log", "w")
            process = subprocess.Popen(
                [sys.executable, "data_generator.py", "--mode", "stream", "--anomaly-rate", "0.3"],
                stdout=log_file,
                stderr=subprocess.STDOUT
            )
            print("✅ Data generator started (logs in ./logs/data_generator.log)")
            return process
        except Exception as e:
            print(f"❌ Failed to start data generator: {e}")
            return None
    
    def monitor_processes(self):
        """Monitor all processes with health checks"""
        while self.running:
            time.sleep(self.health_check_interval)
            
            # Check process health
            dead_processes = []
            for i, process in enumerate(self.processes):
                if process and process.poll() is not None:
                    print(f"⚠️ Process {i} stopped unexpectedly (exit code: {process.returncode})")
                    dead_processes.append(i)
            
            if dead_processes and self.running:
                print("🔄 Some processes died, consider restarting the demo")
    
    def check_services_health(self):
        """Check if services are responding"""
        services = [
            ("Backend API", "http://localhost:8000/api/health"),
            ("Frontend", "http://localhost:3000"),
        ]
        
        print("\n🏥 Health Check Results:")
        for service_name, url in services:
            try:
                response = requests.get(url, timeout=3)
                if response.status_code == 200:
                    print(f"   ✅ {service_name} is healthy")
                else:
                    print(f"   ⚠️ {service_name} responded with status {response.status_code}")
            except Exception as e:
                print(f"   ❌ {service_name} health check failed: {str(e)[:50]}...")
    
    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        print("\n🛑 Shutting down hackathon demo...")
        self.running = False
        self.cleanup()
        sys.exit(0)
    
    def cleanup(self):
        """Clean up all processes"""
        print("🧹 Cleaning up processes...")
        for i, process in enumerate(self.processes):
            if process and process.poll() is None:
                print(f"   Stopping process {i}...")
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    print(f"   Force killing process {i}...")
                    process.kill()
        print("✅ All processes stopped")
    
    def run(self):
        """Run the complete hackathon demo"""
        print("🎯 Starting CyberShield Hackathon Demo")
        print("=" * 60)
        
        # Set up signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        # Setup directories
        self.check_directory_structure()
        
        # ADD RAG INITIALIZATION HERE (before backend)
        print("\n" + "="*30 + " RAG SETUP " + "="*30)
        rag_ready = self.initialize_rag_pipeline()

        # Start backend first
        print("\n" + "="*30 + " BACKEND " + "="*30)
        backend_process = self.start_backend()
        if backend_process:
            self.processes.append(backend_process)
            
            # Wait for backend to be ready
            if not self.wait_for_backend():
                print("❌ Cannot continue without backend")
                self.cleanup()
                return
        else:
            print("❌ Cannot continue without backend")
            return
        
        # Start anomaly detection
        print("\n" + "="*25 + " ANOMALY DETECTION " + "="*25)
        anomaly_process = self.start_anomaly_detection()
        if anomaly_process:
            self.processes.append(anomaly_process)
            time.sleep(3)
        
        # Start data generator
        print("\n" + "="*26 + " DATA GENERATOR " + "="*26)
        data_process = self.start_data_generator()
        if data_process:
            self.processes.append(data_process)
            time.sleep(2)
        
        # Start frontend last (so backend is ready for API calls)
        print("\n" + "="*30 + " FRONTEND " + "="*30)
        frontend_process = self.start_frontend()
        if frontend_process:
            self.processes.append(frontend_process)
            
            # Wait for frontend to be ready (but don't fail if it takes time)
            self.wait_for_frontend()
        
        print("\n🎉 Hackathon Demo is running!")
        print("=" * 60)
        print("🎨 Frontend Dashboard: http://localhost:3000")
        print("🔧 Backend API: http://localhost:8000")
        print("📊 API Documentation: http://localhost:8000/docs")
        print("🔍 Debug Endpoint: http://localhost:8000/api/debug/files")
        print("🧠 RAG Status: http://localhost:8000/api/rag/status")
        print("💡 RAG Explanation: http://localhost:8000/api/rag/explain")
        print("🛡️ Anomaly Detection: Running")
        print("📈 Data Generator: Running (30% anomaly rate)")
        print("\n📁 Log Files:")
        print("   Frontend: ./logs/frontend.log")
        print("   Backend: ./logs/backend.log")
        print("   Anomaly Detection: ./logs/anomaly_detection.log")
        print("   Data Generator: ./logs/data_generator.log")
        print("\n📂 Output Files:")
        print("   Login Anomalies: ./output/login_anomalies.jsonl")
        print("   Network Anomalies: ./output/network_anomalies.jsonl")
        print("   File Anomalies: ./output/file_anomalies.jsonl")
        print("\n🔧 Useful Commands:")
        print("   Check backend health: curl http://localhost:8000/api/health")
        print("   Check anomalies: curl http://localhost:8000/api/anomalies")
        print("   Debug files: curl http://localhost:8000/api/debug/files")
        print("   Check RAG status: curl http://localhost:8000/api/rag/status")
        print("   Test RAG explain: curl -X POST http://localhost:8000/api/rag/explain -H 'Content-Type: application/json' -d '{\"type\":\"login_anomaly\"}'")
        print("   View logs: tail -f ./logs/backend.log")
        print("\nPress Ctrl+C to stop all services")
        print("=" * 60)
        
        # Initial health check after a short delay
        time.sleep(5)
        self.check_services_health()
        
        # Start monitoring thread
        monitor_thread = threading.Thread(target=self.monitor_processes, daemon=True)
        monitor_thread.start()
        
        print(f"\n🔄 System monitoring active (checking every {self.health_check_interval}s)")
        print("💡 If frontend takes time to load, that's normal - React needs to compile")
        
        try:
            # Keep main thread alive
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.signal_handler(signal.SIGINT, None)

if __name__ == "__main__":
    # Check prerequisites
    print("🔍 Checking prerequisites...")
    
    # Check Python
    print(f"   Python: {sys.version.split()[0]} ✅")
    
    # Check Node.js
    try:
        node_version = subprocess.check_output(["node", "--version"], text=True).strip()
        print(f"   Node.js: {node_version} ✅")
    except:
        print("   Node.js: Not found ❌")
        print("   Please install Node.js: sudo apt install nodejs npm")
        sys.exit(1)
    
    # Check npm
    try:
        npm_version = subprocess.check_output(["npm", "--version"], text=True).strip()
        print(f"   npm: {npm_version} ✅")
    except:
        print("   npm: Not found ❌")
        print("   Please install npm: sudo apt install npm")
        sys.exit(1)
    
    print("✅ Prerequisites check passed!")
    print()
    
    # Run the demo
    demo = HackathonDemo()
    demo.run()
